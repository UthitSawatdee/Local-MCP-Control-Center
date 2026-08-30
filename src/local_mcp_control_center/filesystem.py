from __future__ import annotations

import errno
import fnmatch
import hashlib
import json
import os
import re
import shutil
import select
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable

from .errors import PolicyError


MAX_READ_BYTES = 1_048_576
TEXT_SUFFIXES = {
    ".txt", ".md", ".markdown", ".py", ".js", ".jsx", ".ts", ".tsx", ".json",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".html", ".css", ".scss",
    ".sql", ".sh", ".zsh", ".env.example", ".csv", ".xml", ".svg",
}
PROTECTED_COMPONENTS = {
    ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker", ".npmrc", ".pypirc",
    "keychains", "login.keychain-db", "browser", "cookies", "passwords",
}
PROTECTED_FILENAMES = {
    ".env", ".env.local", ".env.development", ".env.production", ".env.test",
    "credentials", "credentials.json", "id_rsa", "id_ed25519", "id_ecdsa",
}
PROTECTED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")
DEFAULT_IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".next", "dist",
    "build", "coverage", "target", "vendor", ".pytest_cache",
}
SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{16,}"),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def redact_text(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def is_protected_relative(relative_path: str) -> bool:
    components = [part for part in relative_path.replace("\\", "/").split("/") if part]
    lower_components = {part.lower() for part in components}
    if lower_components & PROTECTED_COMPONENTS:
        return True
    for component in components:
        lower = component.lower()
        if lower in PROTECTED_FILENAMES:
            return True
        if lower.endswith(PROTECTED_SUFFIXES):
            return True
    if ".git" in lower_components:
        return True
    return False


def validate_relative_path(relative_path: str) -> list[str]:
    if not isinstance(relative_path, str) or not relative_path:
        raise PolicyError("INVALID_INPUT", "relative_path must be a non-empty string")
    if "\x00" in relative_path:
        raise PolicyError("PATH_NULL_BYTE", "path contains a null byte")
    if relative_path.startswith("/") or relative_path.startswith("~"):
        raise PolicyError("PATH_ABSOLUTE", "absolute paths are not accepted")
    if "\\" in relative_path:
        raise PolicyError("PATH_SEPARATOR", "use POSIX-style relative paths")
    parts = [part for part in relative_path.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise PolicyError("PATH_TRAVERSAL", "parent traversal is not accepted")
    if any("\x00" in part for part in parts):
        raise PolicyError("PATH_NULL_BYTE", "path contains a null byte")
    return parts


class SafeFilesystem:
    """Filesystem adapter that requires already-authorized, canonical paths."""

    def resolve_under(self, root: Path, relative_path: str, *, must_exist: bool = False) -> Path:
        parts = validate_relative_path(relative_path)
        candidate = root.joinpath(*parts) if parts else root
        if must_exist and not candidate.exists():
            raise PolicyError("TARGET_NOT_FOUND", f"target does not exist: {relative_path}")

        current = root
        for part in parts:
            current = current / part
            if current.is_symlink():
                raise PolicyError("SYMLINK_NOT_ALLOWED", "symlink path components are not allowed")

        if candidate.exists() or candidate.is_symlink():
            resolved = candidate.resolve(strict=True)
            if resolved != root and root not in resolved.parents:
                raise PolicyError("PATH_ESCAPE", "resolved target is outside the allowed scope")
            if candidate.is_symlink():
                raise PolicyError("SYMLINK_NOT_ALLOWED", "symlink targets are not allowed")
            return resolved

        parent = candidate.parent.resolve(strict=True)
        if parent != root and root not in parent.parents:
            raise PolicyError("PATH_ESCAPE", "resolved parent is outside the allowed scope")
        return parent / candidate.name

    def read_text(self, target: Path, *, max_bytes: int = MAX_READ_BYTES) -> tuple[str, str]:
        text, digest = self.read_text_raw(target, max_bytes=max_bytes)
        return redact_text(text), digest

    def read_text_raw(self, target: Path, *, max_bytes: int = MAX_READ_BYTES) -> tuple[str, str]:
        """Read a validated UTF-8 text file without redacting the in-process value.

        This is only for exact local transformations such as patch application;
        callers must never place the returned raw text in an MCP response or
        audit event.
        """
        if target.is_symlink():
            raise PolicyError("SYMLINK_NOT_ALLOWED", "symlink targets are not readable")
        if not target.is_file():
            raise PolicyError("NOT_A_FILE", "target is not a regular file")
        size = target.stat().st_size
        if size > max_bytes:
            raise PolicyError("QUOTA_EXCEEDED", f"file exceeds {max_bytes} byte read limit")
        raw = target.read_bytes()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PolicyError("BINARY_NOT_SUPPORTED", "file is not UTF-8 text; use a format tool") from exc
        return text, sha256_bytes(raw)

    def list_entries(self, target: Path, root: Path, *, max_items: int = 100) -> list[dict[str, object]]:
        if not target.is_dir():
            raise PolicyError("NOT_A_DIRECTORY", "target is not a directory")
        result: list[dict[str, object]] = []
        for item in sorted(target.iterdir(), key=lambda value: value.name.lower()):
            relative = item.relative_to(root).as_posix()
            if is_protected_relative(relative):
                continue
            try:
                if item.is_symlink():
                    result.append({"name": item.name, "relative_path": relative, "kind": "symlink_blocked", "size": None})
                    if len(result) >= max_items:
                        break
                    continue
                stat = item.stat()
                result.append({
                    "name": item.name,
                    "relative_path": relative,
                    "kind": "directory" if item.is_dir() else "file",
                    "size": stat.st_size if item.is_file() else None,
                })
            except OSError:
                result.append({"name": item.name, "relative_path": relative, "kind": "unreadable"})
            if len(result) >= max_items:
                break
        return result

    def search_text(
        self,
        root: Path,
        target: Path,
        query: str,
        *,
        max_results: int = 100,
        max_file_bytes: int = 512_000,
    ) -> list[dict[str, object]]:
        if not query or len(query) > 200:
            raise PolicyError("INVALID_INPUT", "query must contain 1-200 characters")
        if not target.is_dir():
            raise PolicyError("NOT_A_DIRECTORY", "search target is not a directory")
        results: list[dict[str, object]] = []
        for current, directory_names, file_names in os.walk(target, topdown=True, followlinks=False):
            current_path = Path(current)
            directory_names[:] = [
                name for name in directory_names
                if name not in DEFAULT_IGNORED_DIRS
                and not is_protected_relative((current_path / name).relative_to(root).as_posix())
            ]
            for filename in sorted(file_names):
                path = current_path / filename
                relative = path.relative_to(root).as_posix()
                if path.is_symlink() or is_protected_relative(relative) or path.suffix.lower() not in TEXT_SUFFIXES:
                    continue
                try:
                    if path.stat().st_size > max_file_bytes:
                        continue
                    content = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                for line_number, line in enumerate(content.splitlines(), start=1):
                    if query.casefold() in line.casefold():
                        results.append({"relative_path": relative, "line": line_number, "text": redact_text(line)[:500]})
                        if len(results) >= max_results:
                            return results
        return results

    def find_files(
        self,
        root: Path,
        target: Path,
        pattern: str,
        *,
        max_results: int = 100,
        include_ignored: bool = False,
    ) -> tuple[list[dict[str, object]], bool]:
        """Find files by a relative path or basename pattern.

        Ignored directories are an automatic discovery optimization only.  The
        broker still authorizes every explicit path independently.
        """
        if not pattern or len(pattern) > 256:
            raise PolicyError("INVALID_INPUT", "pattern must contain 1-256 characters")
        if not target.exists():
            raise PolicyError("TARGET_NOT_FOUND", "search target does not exist")
        max_results = max(1, min(int(max_results), 1000))
        results: list[dict[str, object]] = []

        def add(path: Path) -> bool:
            if path.is_symlink():
                return False
            relative = path.relative_to(root).as_posix()
            if is_protected_relative(relative):
                return False
            if not (fnmatch.fnmatchcase(relative, pattern) or fnmatch.fnmatchcase(path.name, pattern)):
                return False
            try:
                stat = path.stat()
            except OSError:
                return False
            results.append({
                "relative_path": relative,
                "name": path.name,
                "kind": "directory" if path.is_dir() else "file",
                "size": stat.st_size if path.is_file() else None,
            })
            return len(results) > max_results

        if target.is_file():
            truncated = add(target)
            return results[:max_results], truncated
        if not target.is_dir():
            raise PolicyError("NOT_A_DIRECTORY", "find target is not a directory")

        for current, directory_names, file_names in os.walk(target, topdown=True, followlinks=False):
            current_path = Path(current)
            directory_names[:] = sorted(
                name for name in directory_names
                if not Path(current_path / name).is_symlink()
                and (include_ignored or name not in DEFAULT_IGNORED_DIRS)
                and not is_protected_relative((current_path / name).relative_to(root).as_posix())
            )
            for filename in sorted(file_names):
                if add(current_path / filename):
                    return results[:max_results], True
        return results, False

    def search_regex(
        self,
        root: Path,
        target: Path,
        pattern: str,
        *,
        max_results: int = 100,
        ignore_case: bool = False,
        max_file_bytes: int = 512_000,
        timeout_ms: int = 5_000,
    ) -> tuple[list[dict[str, object]], bool]:
        """Search with a direct ``rg`` process and a bounded fallback.

        The pattern is passed as one argv element; it is never interpreted by a
        shell.  ``select`` lets the adapter enforce a deadline while consuming
        bounded JSON lines from ripgrep.
        """
        if not pattern or len(pattern) > 500:
            raise PolicyError("INVALID_INPUT", "pattern must contain 1-500 characters")
        try:
            re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error as exc:
            raise PolicyError("INVALID_INPUT", f"invalid regular expression: {exc}") from exc
        max_results = max(1, min(int(max_results), 1000))
        timeout_ms = max(1, min(int(timeout_ms), 60_000))
        rg = next(
            (
                candidate for candidate in ("/opt/homebrew/bin/rg", "/usr/local/bin/rg", "/usr/bin/rg")
                if Path(candidate).is_file() and os.access(candidate, os.X_OK)
            ),
            None,
        )
        if rg is None:
            return self._search_regex_python(
                root, target, pattern, max_results=max_results, ignore_case=ignore_case,
                max_file_bytes=max_file_bytes, timeout_ms=timeout_ms,
            )

        if not target.exists():
            raise PolicyError("TARGET_NOT_FOUND", "search target does not exist")
        argv = [
            rg, "--json", "--no-messages", "--color", "never", "--hidden",
            "--max-columns", "500", "--max-columns-preview", "--max-filesize", str(max_file_bytes),
        ]
        for ignored in sorted(DEFAULT_IGNORED_DIRS):
            argv.extend(("--glob", f"!{ignored}/**", "--glob", f"!**/{ignored}/**"))
        if ignore_case:
            argv.append("--ignore-case")
        argv.extend(("--", pattern, str(target)))
        try:
            process = subprocess.Popen(
                argv,
                cwd=str(root),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                text=False,
            )
        except OSError as exc:
            raise PolicyError("SEARCH_UNAVAILABLE", "unable to start the local regex search adapter") from exc

        results: list[dict[str, object]] = []
        deadline = time.monotonic() + timeout_ms / 1000
        timed_out = False
        limit_reached = False
        try:
            assert process.stdout is not None
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                ready, _, _ = select.select([process.stdout], [], [], min(remaining, 0.1))
                if not ready:
                    if process.poll() is not None:
                        break
                    continue
                raw_line = process.stdout.readline()
                if not raw_line:
                    break
                try:
                    event = json.loads(raw_line.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    continue
                if event.get("type") != "match":
                    continue
                data = event.get("data") or {}
                path_data = data.get("path") or {}
                raw_path = path_data.get("text")
                line_number = data.get("line_number")
                line_data = data.get("lines") or {}
                line_text = line_data.get("text", "")
                if not isinstance(raw_path, str) or not isinstance(line_number, int):
                    continue
                path = Path(raw_path)
                if not path.is_absolute():
                    path = root / path
                try:
                    relative = path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
                except (FileNotFoundError, ValueError):
                    continue
                if is_protected_relative(relative) or path.is_symlink():
                    continue
                results.append({
                    "relative_path": relative,
                    "line": line_number,
                    "text": redact_text(str(line_text).rstrip("\r\n"))[:500],
                })
                if len(results) > max_results:
                    limit_reached = True
                    break
        finally:
            if timed_out or process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        if timed_out:
            raise PolicyError("SEARCH_TIMEOUT", "regex search exceeded its time limit")
        if process.returncode not in (0, 1) and not limit_reached:
            raise PolicyError("SEARCH_FAILED", "regex search adapter failed")
        return results[:max_results], len(results) > max_results

    def _search_regex_python(
        self,
        root: Path,
        target: Path,
        pattern: str,
        *,
        max_results: int,
        ignore_case: bool,
        max_file_bytes: int,
        timeout_ms: int,
    ) -> tuple[list[dict[str, object]], bool]:
        try:
            compiled = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error as exc:
            raise PolicyError("INVALID_INPUT", f"invalid regular expression: {exc}") from exc
        if target.is_file():
            files = [target]
        elif target.is_dir():
            files = []
            for current, directory_names, file_names in os.walk(target, topdown=True, followlinks=False):
                current_path = Path(current)
                directory_names[:] = [name for name in directory_names if name not in DEFAULT_IGNORED_DIRS]
                files.extend(current_path / name for name in sorted(file_names))
        else:
            raise PolicyError("NOT_A_DIRECTORY", "search target is not a file or directory")
        deadline = time.monotonic() + timeout_ms / 1000
        results: list[dict[str, object]] = []
        for path in files:
            if time.monotonic() > deadline:
                raise PolicyError("SEARCH_TIMEOUT", "regex search exceeded its time limit")
            if path.is_symlink() or is_protected_relative(path.relative_to(root).as_posix()):
                continue
            try:
                if path.stat().st_size > max_file_bytes:
                    continue
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for line_number, line in enumerate(content.splitlines(), start=1):
                if time.monotonic() > deadline:
                    raise PolicyError("SEARCH_TIMEOUT", "regex search exceeded its time limit")
                if compiled.search(line):
                    results.append({
                        "relative_path": path.relative_to(root).as_posix(),
                        "line": line_number,
                        "text": redact_text(line)[:500],
                    })
                    if len(results) > max_results:
                        return results[:max_results], True
        return results[:max_results], False

    def read_text_page(
        self,
        target: Path,
        *,
        start_line: int = 1,
        max_lines: int = 200,
        max_bytes: int = MAX_READ_BYTES,
        max_file_bytes: int = 50_000_000,
    ) -> tuple[str, str, int, int, bool]:
        """Read exact line boundaries without silently truncating a file."""
        if target.is_symlink():
            raise PolicyError("SYMLINK_NOT_ALLOWED", "symlink targets are not readable")
        if not target.is_file():
            raise PolicyError("NOT_A_FILE", "target is not a regular file")
        if not isinstance(start_line, int) or start_line < 1:
            raise PolicyError("INVALID_INPUT", "start_line must be a positive integer")
        max_lines = max(1, min(int(max_lines), 1000))
        max_bytes = max(1, min(int(max_bytes), MAX_READ_BYTES))
        if target.stat().st_size > max_file_bytes:
            raise PolicyError("QUOTA_EXCEEDED", "file exceeds the paged-read safety limit")
        raw = target.read_bytes()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PolicyError("BINARY_NOT_SUPPORTED", "file is not UTF-8 text") from exc
        lines = text.splitlines(keepends=True)
        if start_line > len(lines) + 1:
            raise PolicyError("INVALID_INPUT", "start_line is beyond the end of the file")
        selected: list[str] = []
        used_bytes = 0
        index = start_line - 1
        while index < len(lines) and len(selected) < max_lines:
            line = lines[index]
            line_bytes = len(line.encode("utf-8"))
            if not selected and line_bytes > max_bytes:
                raise PolicyError("PAGE_LIMIT_TOO_SMALL", "one source line exceeds the requested page size")
            if selected and used_bytes + line_bytes > max_bytes:
                break
            selected.append(line)
            used_bytes += line_bytes
            index += 1
        end_line = start_line + len(selected) - 1 if selected else start_line - 1
        return redact_text("".join(selected)), sha256_bytes(raw), start_line, end_line, index < len(lines)

    def backup(self, target: Path, snapshot_root: Path, snapshot_id: str) -> Path:
        snapshot_dir = snapshot_root / snapshot_id
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(snapshot_dir, 0o700)
        destination = snapshot_dir / target.name
        shutil.copy2(target, destination)
        os.chmod(destination, 0o600)
        return destination

    def atomic_write(self, target: Path, data: bytes, *, preserve_mode: bool = True) -> None:
        if target.exists() and not target.is_file():
            raise PolicyError("NOT_A_FILE", "target is not a regular file")
        target.parent.mkdir(parents=False, exist_ok=True)
        original_mode = target.stat().st_mode if target.exists() else None
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if preserve_mode and original_mode is not None:
                os.chmod(temporary, original_mode & 0o777)
            os.replace(temporary, target)
            try:
                directory_fd = os.open(target.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        finally:
            if temporary.exists():
                temporary.unlink(missing_ok=True)

    def move_file_no_replace(self, source: Path, destination: Path) -> None:
        """Move one regular file without replacing an existing destination.

        macOS rename semantics can replace a destination if it appears after a
        preflight check. A hard-link followed by unlink provides no-replace
        behavior for this regular-file operation. It intentionally requires
        both paths to be on the same filesystem.
        """
        try:
            os.link(source, destination, follow_symlinks=False)
        except FileExistsError as exc:
            raise PolicyError("TARGET_EXISTS", "destination appeared before move") from exc
        except OSError as exc:
            if exc.errno == errno.EXDEV:
                raise PolicyError(
                    "CROSS_DEVICE_MOVE_UNSUPPORTED",
                    "bulk move requires source and destination on the same filesystem",
                ) from exc
            raise

        try:
            source.unlink()
        except OSError:
            try:
                destination.unlink()
            except OSError:
                pass
            raise
