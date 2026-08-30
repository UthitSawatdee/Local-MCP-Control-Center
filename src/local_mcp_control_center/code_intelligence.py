"""Small deterministic code-index and symbol adapters.

This module deliberately stays below a language-server's complexity.  It
indexes metadata and lightweight declarations only; authorization remains in
the broker and source text is never persisted in the index.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Any, Iterable

from .errors import PolicyError
from .filesystem import SafeFilesystem, TEXT_SUFFIXES, is_protected_relative, redact_text
from .storage import Store


CODE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".go", ".rs", ".java", ".kt", ".rb", ".php", ".c", ".h", ".cpp", ".cc",
    ".cs", ".swift", ".sql",
}
INDEXABLE_SUFFIXES = CODE_SUFFIXES | {suffix for suffix in TEXT_SUFFIXES if suffix not in {".csv", ".svg"}}

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.-]{0,127}$")
_JS_DECLARATIONS = (
    ("function", re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)")),
    ("class", re.compile(r"^\s*(?:export\s+)?(?:default\s+)?class\s+([A-Za-z_$][\w$]*)")),
    ("interface", re.compile(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)")),
    ("type", re.compile(r"^\s*(?:export\s+)?type\s+([A-Za-z_$][\w$]*)\s*=")),
    ("enum", re.compile(r"^\s*(?:export\s+)?enum\s+([A-Za-z_$][\w$]*)")),
    ("variable", re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^\n]*\)|[A-Za-z_$][\w$]*)\s*=>")),
)


def language_for(path: Path) -> str | None:
    suffix = path.suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".vue": "vue",
        ".svelte": "svelte",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".kt": "kotlin",
        ".rb": "ruby",
        ".php": "php",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cs": "csharp",
        ".swift": "swift",
        ".sql": "sql",
    }.get(suffix)


def is_indexable(path: Path) -> bool:
    return path.suffix.lower() in INDEXABLE_SUFFIXES


def _python_symbols(path: Path, text: str) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(text, filename=str(path))
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    result: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            line = int(getattr(node, "lineno", 1))
            end_line = int(getattr(node, "end_lineno", line))
            signature = lines[line - 1].strip()[:500] if 0 < line <= len(lines) else node.name
            result.append(
                {
                    "name": node.name,
                    "symbol_kind": "class" if isinstance(node, ast.ClassDef) else "function",
                    "line": line,
                    "end_line": end_line,
                    "signature": redact_text(signature),
                }
            )
    return result


def _text_symbols(path: Path, text: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in _JS_DECLARATIONS:
            match = pattern.match(line)
            if match:
                result.append(
                    {
                        "name": match.group(1),
                        "symbol_kind": kind,
                        "line": line_number,
                        "end_line": line_number,
                        "signature": redact_text(line.strip())[:500],
                    }
                )
                break
    return result


def extract_symbols(path: Path, text: str) -> list[dict[str, Any]]:
    if language_for(path) == "python":
        return sorted(_python_symbols(path, text), key=lambda item: (item["line"], item["name"]))
    return sorted(_text_symbols(path, text), key=lambda item: (item["line"], item["name"]))


def validate_symbol(symbol: str) -> str:
    if not isinstance(symbol, str) or not _IDENTIFIER_RE.fullmatch(symbol):
        raise PolicyError("INVALID_INPUT", "symbol must be a bounded identifier")
    return symbol


class WorkspaceIndexService:
    """Build and query a metadata-only persistent workspace index."""

    def __init__(self, store: Store, filesystem: SafeFilesystem):
        self.store = store
        self.filesystem = filesystem

    def build(
        self,
        scope_id: str,
        root: Path,
        *,
        max_files: int = 10_000,
        include_ignored: bool = False,
    ) -> dict[str, Any]:
        matches, truncated = self.filesystem.find_files(
            root, root, "*", max_results=max(1, min(int(max_files), 10_000)), include_ignored=include_ignored
        )
        files: list[dict[str, Any]] = []
        symbols: list[dict[str, Any]] = []
        for item in matches:
            if item.get("kind") != "file":
                continue
            relative = str(item["relative_path"])
            path = root / relative
            if not is_indexable(path) or path.is_symlink() or is_protected_relative(relative):
                continue
            try:
                stat = path.stat()
                if stat.st_size > 5_000_000:
                    continue
                raw = path.read_bytes()
                text = raw.decode("utf-8-sig")
            except (OSError, UnicodeDecodeError):
                continue
            files.append(
                {
                    "relative_path": relative,
                    "kind": "file",
                    "language": language_for(path),
                    "size": stat.st_size,
                    "modified_ns": stat.st_mtime_ns,
                    "content_hash": self._hash(raw),
                }
            )
            for symbol in extract_symbols(path, text):
                symbols.append({"relative_path": relative, **symbol})
        self.store.replace_workspace_index(scope_id, files, symbols, truncated=truncated)
        return {
            "state": "partial" if truncated else "ready",
            "file_count": len(files),
            "symbol_count": len(symbols),
            "truncated": truncated,
        }

    def status(self, scope_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.workspace_index_status(scope_id)

    def symbols(
        self,
        root: Path,
        target: Path,
        symbol: str,
        *,
        max_results: int = 100,
        definitions_only: bool = True,
    ) -> tuple[list[dict[str, Any]], bool]:
        symbol = validate_symbol(symbol)
        candidates = self._candidate_files(root, target, max_files=10_000)
        results: list[dict[str, Any]] = []
        for path in candidates:
            if not is_indexable(path) or is_protected_relative(path.relative_to(root).as_posix()):
                continue
            try:
                raw = path.read_bytes()
                if len(raw) > 5_000_000:
                    continue
                text = raw.decode("utf-8-sig")
            except (OSError, UnicodeDecodeError):
                continue
            definitions = extract_symbols(path, text)
            if definitions_only:
                selected = [item for item in definitions if item["name"] == symbol]
            else:
                selected = [item for item in definitions if item["name"] == symbol]
            relative = path.relative_to(root).as_posix()
            for item in selected:
                line = self._line(text, int(item["line"]))
                results.append({"relative_path": relative, **item, "text": redact_text(line)[:500]})
                if len(results) >= max_results:
                    return results, True
        return results, False

    def references(
        self,
        root: Path,
        target: Path,
        symbol: str,
        *,
        max_results: int = 100,
    ) -> tuple[list[dict[str, Any]], bool]:
        symbol = validate_symbol(symbol)
        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        results: list[dict[str, Any]] = []
        for path in self._candidate_files(root, target, max_files=10_000):
            if not is_indexable(path) or is_protected_relative(path.relative_to(root).as_posix()):
                continue
            try:
                raw = path.read_bytes()
                if len(raw) > 5_000_000:
                    continue
                text = raw.decode("utf-8-sig")
            except (OSError, UnicodeDecodeError):
                continue
            relative = path.relative_to(root).as_posix()
            for line_number, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    results.append({"relative_path": relative, "line": line_number, "text": redact_text(line)[:500]})
                    if len(results) >= max_results:
                        return results, True
        return results, False

    @staticmethod
    def _candidate_files(root: Path, target: Path, *, max_files: int) -> Iterable[Path]:
        if target.is_file():
            return [target]
        if not target.is_dir():
            raise PolicyError("NOT_A_DIRECTORY", "code search target must be a file or directory")
        result: list[Path] = []
        for current, directory_names, file_names in os.walk(target, topdown=True, followlinks=False):
            current_path = Path(current)
            directory_names[:] = sorted(
                name for name in directory_names
                if not (current_path / name).is_symlink()
                and name not in {".git", ".venv", "venv", "node_modules", "__pycache__", ".next", "dist", "build", "coverage", "target", "vendor", ".pytest_cache"}
            )
            for filename in sorted(file_names):
                path = current_path / filename
                if path.is_symlink():
                    continue
                result.append(path)
                if len(result) >= max_files:
                    return result
        return result

    @staticmethod
    def _line(text: str, line_number: int) -> str:
        lines = text.splitlines()
        return lines[line_number - 1] if 0 < line_number <= len(lines) else ""

    @staticmethod
    def _hash(raw: bytes) -> str:
        import hashlib

        return "sha256:" + hashlib.sha256(raw).hexdigest()
