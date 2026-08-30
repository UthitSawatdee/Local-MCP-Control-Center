"""Bounded deterministic workspace snapshot and context ranking services."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .code_intelligence import WorkspaceIndexService, is_indexable
from .errors import PolicyError
from .filesystem import SafeFilesystem, redact_text


_TOKEN_RE = re.compile(r"[A-Za-z0-9_$][A-Za-z0-9_$.-]{1,63}")
_TEST_PATTERNS = ("test_*.py", "*_test.py", "*.spec.ts", "*.spec.tsx", "*.test.ts", "*.test.tsx", "*.test.js", "*.test.jsx")


class WorkspaceContextService:
    """Compose bounded local context; never decides authorization."""

    def __init__(self, filesystem: SafeFilesystem, index: WorkspaceIndexService):
        self.filesystem = filesystem
        self.index = index

    def snapshot(
        self,
        root: Path,
        *,
        max_items: int,
        git_result: dict[str, Any] | None,
        profiles: list[dict[str, Any]],
        processes: list[dict[str, Any]],
        recent_errors: list[dict[str, Any]],
    ) -> dict[str, Any]:
        entries = self.filesystem.list_entries(root, root, max_items=max_items + 1)
        file_tree_truncated = len(entries) > max_items
        entries = entries[:max_items]
        tests: list[str] = []
        tests_truncated = False
        for pattern in _TEST_PATTERNS:
            matches, truncated = self.filesystem.find_files(root, root, pattern, max_results=max_items)
            tests_truncated = tests_truncated or truncated
            tests.extend(str(item["relative_path"]) for item in matches if item.get("kind") == "file")
        tests = sorted(set(tests))[:max_items]
        changed = self.changed_paths((git_result or {}).get("stdout", ""))
        return {
            "workspace": {"name": root.name, "kind": "project", "file_tree_truncated": file_tree_truncated},
            "top_level": entries,
            "git": {
                "status": git_result,
                "changed_files": changed,
            },
            "test_structure": {"files": tests, "truncated": tests_truncated},
            "profiles": [self.public_profile(item, root) for item in profiles],
            "managed_processes": processes,
            "recent_errors": recent_errors[:max_items],
        }

    def context(
        self,
        root: Path,
        target: Path,
        query: str,
        *,
        intent: str,
        max_files: int,
        max_bytes: int,
        changed_files: set[str] | None = None,
        indexed_symbols: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if not query or len(query) > 500:
            raise PolicyError("INVALID_INPUT", "query must contain 1-500 characters")
        max_files = max(1, min(int(max_files), 100))
        max_bytes = max(1, min(int(max_bytes), 2_000_000))
        changed_files = changed_files or set()
        query_folded = query.casefold()
        query_tokens = {token.casefold() for token in _TOKEN_RE.findall(query)}
        candidates, discovery_truncated = self.filesystem.find_files(
            root,
            target,
            "*",
            max_results=2_000,
            include_ignored=False,
        )
        indexed_by_path = {
            str(item.get("relative_path")): item
            for item in (indexed_symbols or [])
            if isinstance(item, dict)
        }
        ranked: list[tuple[float, dict[str, Any]]] = []
        for item in candidates:
            if item.get("kind") != "file":
                continue
            relative = str(item["relative_path"])
            path = root / relative
            if not is_indexable(path) or path.is_symlink():
                continue
            score = 0.0
            reasons: list[str] = []
            relative_folded = relative.casefold()
            name_folded = path.name.casefold()
            if relative in changed_files:
                score += 100
                reasons.append("git_changed")
            if query_folded in relative_folded:
                score += 55
                reasons.append("path_match")
            matching_tokens = sum(1 for token in query_tokens if token in relative_folded)
            if matching_tokens:
                score += 15 * matching_tokens
                reasons.append("filename_tokens")
            if name_folded.startswith("test") or ".test." in name_folded or ".spec." in name_folded:
                if intent in {"debug", "implement", "review"}:
                    score += 8
                    reasons.append("test_candidate")
            indexed = indexed_by_path.get(relative)
            if indexed:
                score += 5
                reasons.append("indexed")
            # Prefer shallow source files when all other signals are equal.
            score -= relative.count("/") * 0.1
            ranked.append((score, {"relative_path": relative, "path": path, "reasons": reasons}))

        # Text scoring is intentionally bounded to a small prefix of candidates
        # so context discovery cannot turn into an unbounded repository scan.
        for _, candidate in sorted(ranked, key=lambda pair: (-pair[0], pair[1]["relative_path"]))[:200]:
            path = candidate["path"]
            try:
                content, digest = self.filesystem.read_text(path, max_bytes=min(128_000, max_bytes))
            except PolicyError:
                continue
            content_folded = content.casefold()
            occurrences = content_folded.count(query_folded)
            token_hits = sum(content_folded.count(token) for token in query_tokens)
            if occurrences or token_hits:
                candidate["score"] = candidate.get("score", 0.0) + min(40, occurrences * 12 + token_hits)
                candidate["reasons"].append("text_match")
                candidate["matches"] = occurrences
                candidate["content_hash"] = digest
                candidate["content"] = content

        ranked.sort(key=lambda pair: (-float(pair[1].get("score", pair[0])), pair[1]["relative_path"]))
        files: list[dict[str, Any]] = []
        used_bytes = 0
        for base_score, candidate in ranked:
            content = candidate.pop("content", None)
            if content is None and not candidate["reasons"]:
                continue
            if content is not None:
                content_bytes = len(content.encode("utf-8"))
                if used_bytes + content_bytes > max_bytes:
                    candidate["content_omitted"] = True
                    candidate.pop("content_hash", None)
                else:
                    candidate["snippets"] = self.snippets(content, query, max_bytes=min(16_000, max_bytes - used_bytes))
                    used_bytes += content_bytes
            candidate["score"] = round(float(candidate.get("score", base_score)), 3)
            candidate.pop("path", None)
            files.append(candidate)
            if len(files) >= max_files:
                break

        truncated = discovery_truncated or len(files) >= max_files or any(item.get("content_omitted") for item in files)
        return {
            "status": "ok",
            "query": query,
            "intent": intent,
            "files": files,
            "file_count": len(files),
            "bytes": used_bytes,
            "truncated": truncated,
            "has_more": truncated,
            "ranking": "deterministic-local-v1",
        }

    @staticmethod
    def snippets(content: str, query: str, *, max_bytes: int) -> list[dict[str, Any]]:
        lines = content.splitlines()
        query_folded = query.casefold()
        result: list[dict[str, Any]] = []
        used = 0
        for number, line in enumerate(lines, start=1):
            if query_folded not in line.casefold() and not any(
                token.casefold() in line.casefold() for token in _TOKEN_RE.findall(query)
            ):
                continue
            text = redact_text(line)[:1000]
            size = len(text.encode("utf-8"))
            if result and used + size > max_bytes:
                break
            result.append({"line": number, "text": text})
            used += size
            if used >= max_bytes:
                break
        return result

    @staticmethod
    def changed_paths(status_text: str) -> set[str]:
        changed: set[str] = set()
        for line in str(status_text or "").splitlines():
            if not line or line.startswith("##"):
                continue
            if len(line) < 4:
                continue
            path = line[3:].strip()
            if " -> " in path:
                path = path.split(" -> ", 1)[-1]
            if path and not path.startswith("/"):
                changed.add(path)
        return changed

    @staticmethod
    def public_profile(profile: dict[str, Any], root: Path) -> dict[str, Any]:
        value = dict(profile)
        working = value.get("working_directory")
        if isinstance(working, str):
            try:
                value["working_directory"] = Path(working).resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                value["working_directory"] = "."
        value.pop("executable", None)
        return value
