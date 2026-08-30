"""Bounded, deterministic dependency/import graph extraction.

This module is intentionally a small read-only seam for developer tooling.  It
does not execute code, persist an index, or attempt to be a language server.
Python imports are collected with :mod:`ast`; JavaScript and TypeScript use a
small comment/string-aware scanner for static import, export-from, require,
and literal dynamic-import forms.

The public interface returns JSON-safe metadata only.  Source text is held in
local variables while a file is parsed and is never included in a result.
Callers should treat ``diagnostics`` and ``unresolved`` as informational,
untrusted parser output rather than authorization decisions.
"""

from __future__ import annotations

import ast
import json
import os
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable

from .errors import PolicyError


DEFAULT_MAX_FILES = 1_000
DEFAULT_MAX_EDGES = 5_000
DEFAULT_MAX_FILE_BYTES = 1_048_576
DEFAULT_MAX_OUTPUT_BYTES = 2_000_000
DEFAULT_MAX_SPECIFIER_LENGTH = 256

MAX_FILES = 10_000
MAX_EDGES = 50_000
MAX_FILE_BYTES = 5_000_000
MAX_OUTPUT_BYTES = 10_000_000
MAX_SPECIFIER_LENGTH = 4_096
MIN_OUTPUT_BYTES = 512

IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".next",
        "dist",
        "build",
        "coverage",
        "target",
        "vendor",
        ".pytest_cache",
    }
)
PROTECTED_COMPONENTS = frozenset(
    {
        ".ssh",
        ".aws",
        ".azure",
        ".gnupg",
        ".kube",
        ".docker",
        ".npmrc",
        ".pypirc",
        "keychains",
        "login.keychain-db",
        "browser",
        "cookies",
        "passwords",
    }
)
PROTECTED_FILENAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.test",
        "credentials",
        "credentials.json",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
    }
)
PROTECTED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
}
PYTHON_SUFFIXES = frozenset({".py"})
JAVASCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs"})
TYPESCRIPT_SUFFIXES = frozenset({".ts", ".tsx", ".mts", ".cts"})
SOURCE_SUFFIXES = frozenset(LANGUAGE_BY_SUFFIX)

_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


class DependencyGraphError(PolicyError):
    """A graph request was rejected before any source file was read."""


@dataclass(frozen=True, slots=True)
class GraphLimits:
    """Hard bounds applied to one graph build.

    The limits are deliberately finite and validated before scanning.  The
    optional keyword overrides on :func:`build_dependency_graph` are useful to
    adapters that already expose individual numeric settings.
    """

    max_files: int = DEFAULT_MAX_FILES
    max_edges: int = DEFAULT_MAX_EDGES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    max_specifier_length: int = DEFAULT_MAX_SPECIFIER_LENGTH


@dataclass(frozen=True, slots=True)
class _Candidate:
    relative_path: str
    path: Path
    language: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class _ImportRecord:
    specifier: str
    kind: str
    position: int
    names: tuple[str, ...] = ()
    python_level: int = 0
    python_module: str | None = None
    specifier_truncated: bool = False


@dataclass(frozen=True, slots=True)
class _Resolution:
    relative_path: str | None
    reason: str | None


def build_dependency_graph(
    root: str | os.PathLike[str],
    files: Iterable[str | os.PathLike[str]] | None = None,
    *,
    limits: GraphLimits | None = None,
    max_files: int | None = None,
    max_edges: int | None = None,
    max_file_bytes: int | None = None,
    max_output_bytes: int | None = None,
    max_specifier_length: int | None = None,
    include_ignored: bool = False,
) -> dict[str, Any]:
    """Build a bounded dependency graph for ``root``.

    ``root`` must be an existing, canonicalizable directory.  ``files`` is an
    optional iterable of POSIX-style paths relative to that root; when it is
    omitted, the directory is discovered deterministically.  In both modes
    only supported Python/JavaScript/TypeScript source files are nodes, and an
    import resolves only to a selected node inside the same root.  A target
    that exists but was excluded by ``files`` or a file limit is reported as
    ``not_scanned`` rather than being read implicitly.

    The return value contains only relative paths, language/kind metadata,
    bounded import specifiers, safe diagnostics, and truncation metadata.  It
    is safe to JSON-encode and contains no source contents.

    Raises:
        DependencyGraphError: if the root, file set, or limits are malformed.
    """

    effective_limits = _effective_limits(
        limits,
        max_files=max_files,
        max_edges=max_edges,
        max_file_bytes=max_file_bytes,
        max_output_bytes=max_output_bytes,
        max_specifier_length=max_specifier_length,
    )
    _validate_bool("include_ignored", include_ignored)
    canonical_root = _canonical_root(root, include_ignored=include_ignored)

    if files is None:
        candidates, file_limited = _discover_candidates(
            canonical_root,
            max_files=effective_limits.max_files,
            include_ignored=include_ignored,
        )
    else:
        candidates, file_limited = _explicit_candidates(
            canonical_root,
            files,
            max_files=effective_limits.max_files,
            include_ignored=include_ignored,
        )

    candidates.sort(key=lambda item: _path_sort_key(item.relative_path))
    selected_paths = {item.relative_path for item in candidates}
    nodes: list[dict[str, Any]] = [
        {
            "relative_path": item.relative_path,
            "language": item.language,
            "kind": "file",
            "size_bytes": item.size_bytes,
        }
        for item in candidates
    ]
    diagnostics: list[dict[str, Any]] = []
    import_records: list[tuple[str, _ImportRecord]] = []
    file_size_limited = False

    for candidate in candidates:
        if candidate.size_bytes > effective_limits.max_file_bytes:
            file_size_limited = True
            diagnostics.append(
                _diagnostic(
                    candidate.relative_path,
                    "file_too_large",
                    "source file exceeds the configured read limit",
                    limit=effective_limits.max_file_bytes,
                )
            )
            continue

        try:
            raw = _read_bounded(candidate.path, effective_limits.max_file_bytes)
        except _FileTooLarge:
            file_size_limited = True
            diagnostics.append(
                _diagnostic(
                    candidate.relative_path,
                    "file_too_large",
                    "source file exceeds the configured read limit",
                    limit=effective_limits.max_file_bytes,
                )
            )
            continue
        except (OSError, ValueError):
            diagnostics.append(
                _diagnostic(
                    candidate.relative_path,
                    "read_error",
                    "source file could not be read",
                )
            )
            continue

        try:
            source = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            diagnostics.append(
                _diagnostic(
                    candidate.relative_path,
                    "encoding_error",
                    "source file is not valid UTF-8 text",
                )
            )
            continue

        records, parse_diagnostic = _parse_imports(
            candidate,
            source,
            max_specifier_length=effective_limits.max_specifier_length,
        )
        if parse_diagnostic is not None:
            diagnostics.append(parse_diagnostic)
        import_records.extend((candidate.relative_path, record) for record in records)

    import_records.sort(key=_import_sort_key)
    edges: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    edge_limited = False
    specifier_limited = any(record.specifier_truncated for _, record in import_records)

    for relationship_number, (source_path, record) in enumerate(import_records):
        if relationship_number >= effective_limits.max_edges:
            edge_limited = True
            break
        resolution = _resolve_import(
            canonical_root,
            source_path,
            candidate_language=_language_for_relative(source_path),
            record=record,
            selected_paths=selected_paths,
            include_ignored=include_ignored,
        )
        relationship = {
            "source": source_path,
            "specifier": _bounded_specifier(record.specifier, effective_limits.max_specifier_length),
            "kind": record.kind,
        }
        if resolution.relative_path is not None:
            edges.append({**relationship, "target": resolution.relative_path})
        else:
            unresolved.append({**relationship, "reason": resolution.reason or "unresolved"})

    edges.sort(key=lambda item: _path_sort_key(str(item["source"])) + (
        _path_sort_key(str(item["target"])),
        str(item["specifier"]),
        str(item["kind"]),
    ))
    unresolved.sort(key=lambda item: _path_sort_key(str(item["source"])) + (
        str(item["specifier"]),
        str(item["kind"]),
        str(item["reason"]),
    ))
    diagnostics.sort(key=_diagnostic_sort_key)

    base_reasons: list[str] = []
    if file_limited:
        base_reasons.append("file_limit")
    if file_size_limited:
        base_reasons.append("file_size_limit")
    if edge_limited:
        base_reasons.append("edge_limit")
    if specifier_limited:
        base_reasons.append("specifier_limit")

    payload = _make_payload(
        nodes,
        edges,
        unresolved,
        diagnostics,
        file_limited=file_limited,
        file_size_limited=file_size_limited,
        edge_limited=edge_limited,
        specifier_limited=specifier_limited,
        output_limited=False,
        reasons=base_reasons,
    )
    if _serialized_size(payload) > effective_limits.max_output_bytes:
        payload = _fit_output(
            nodes,
            edges,
            unresolved,
            diagnostics,
            max_output_bytes=effective_limits.max_output_bytes,
            file_limited=file_limited,
            file_size_limited=file_size_limited,
            edge_limited=edge_limited,
            specifier_limited=specifier_limited,
            base_reasons=base_reasons,
        )
    return payload


def scan_dependency_graph(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Compatibility alias for callers that name the operation ``scan``."""

    return build_dependency_graph(*args, **kwargs)


def _effective_limits(
    limits: GraphLimits | None,
    *,
    max_files: int | None,
    max_edges: int | None,
    max_file_bytes: int | None,
    max_output_bytes: int | None,
    max_specifier_length: int | None,
) -> GraphLimits:
    if limits is None:
        effective = GraphLimits()
    elif isinstance(limits, GraphLimits):
        effective = limits
    else:
        raise DependencyGraphError("INVALID_LIMIT", "limits must be a GraphLimits value")
    overrides = {
        "max_files": max_files,
        "max_edges": max_edges,
        "max_file_bytes": max_file_bytes,
        "max_output_bytes": max_output_bytes,
        "max_specifier_length": max_specifier_length,
    }
    for name, value in overrides.items():
        if value is not None:
            effective = replace(effective, **{name: value})
    _validate_limit("max_files", effective.max_files, 1, MAX_FILES)
    _validate_limit("max_edges", effective.max_edges, 1, MAX_EDGES)
    _validate_limit("max_file_bytes", effective.max_file_bytes, 1, MAX_FILE_BYTES)
    _validate_limit("max_output_bytes", effective.max_output_bytes, MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES)
    _validate_limit("max_specifier_length", effective.max_specifier_length, 1, MAX_SPECIFIER_LENGTH)
    return effective


def _validate_limit(name: str, value: Any, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DependencyGraphError(
            "INVALID_LIMIT",
            f"{name} must be an integer from {minimum} to {maximum}",
        )


def _validate_bool(name: str, value: Any) -> None:
    if type(value) is not bool:
        raise DependencyGraphError("INVALID_INPUT", f"{name} must be boolean")


def _canonical_root(root: str | os.PathLike[str], *, include_ignored: bool) -> Path:
    try:
        raw_root = os.fspath(root)
    except TypeError as exc:
        raise DependencyGraphError("INVALID_ROOT", "root must be a path-like directory") from exc
    if isinstance(raw_root, bytes):
        raise DependencyGraphError("INVALID_ROOT", "root must be a text path")
    if not raw_root or "\x00" in raw_root:
        raise DependencyGraphError("INVALID_ROOT", "root must be a non-empty path")

    lexical = Path(os.path.abspath(raw_root))
    _reject_symlink_components(lexical)
    try:
        if not lexical.exists():
            raise DependencyGraphError("ROOT_NOT_FOUND", "root directory does not exist")
        if not lexical.is_dir():
            raise DependencyGraphError("ROOT_NOT_DIRECTORY", "root must be a directory")
        canonical = lexical.resolve(strict=True)
    except DependencyGraphError:
        raise
    except (OSError, RuntimeError) as exc:
        raise DependencyGraphError("INVALID_ROOT", "root could not be canonicalized") from exc

    if not canonical.is_dir():
        raise DependencyGraphError("ROOT_NOT_DIRECTORY", "root must be a directory")
    if _is_protected_relative(canonical.name) or (
        canonical.name.casefold() in IGNORED_DIRECTORIES and not include_ignored
    ):
        raise DependencyGraphError("PROTECTED_ROOT", "protected or ignored roots are not graph scopes")
    return canonical


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            if current.is_symlink():
                raise DependencyGraphError("SYMLINK_NOT_ALLOWED", "root contains a symlink path component")
        except OSError as exc:
            raise DependencyGraphError("INVALID_ROOT", "root path could not be inspected") from exc


def _discover_candidates(
    root: Path,
    *,
    max_files: int,
    include_ignored: bool,
) -> tuple[list[_Candidate], bool]:
    candidates: list[_Candidate] = []
    pending = [root]
    truncated = False
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        entries.sort(key=lambda entry: _path_sort_key(entry.name))
        directories: list[os.DirEntry[str]] = []
        for entry in entries:
            relative = _relative_path(root, Path(entry.path))
            if entry.is_symlink():
                continue
            if _is_protected_relative(relative):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if not include_ignored and entry.name.casefold() in IGNORED_DIRECTORIES:
                        continue
                    directories.append(entry)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            language = _language_for_relative(relative)
            if language is None:
                continue
            try:
                size_bytes = entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            if len(candidates) >= max_files:
                truncated = True
                break
            candidates.append(_Candidate(relative, Path(entry.path), language, int(size_bytes)))
        if truncated:
            break
        for directory in reversed(directories):
            pending.append(Path(directory.path))
    return candidates, truncated


def _explicit_candidates(
    root: Path,
    files: Iterable[str | os.PathLike[str]],
    *,
    max_files: int,
    include_ignored: bool,
) -> tuple[list[_Candidate], bool]:
    if isinstance(files, (str, bytes, os.PathLike)):
        raise DependencyGraphError("INVALID_FILE_SET", "files must be an iterable of relative file paths")

    normalized: list[str] = []
    seen: set[str] = set()
    truncated = False
    try:
        iterator = iter(files)
        for index, item in enumerate(iterator):
            if index >= max_files:
                truncated = True
                break
            relative = _validate_relative_path(item)
            if relative in seen:
                continue
            seen.add(relative)
            normalized.append(relative)
    except (TypeError, ValueError) as exc:
        raise DependencyGraphError("INVALID_FILE_SET", "files must contain text relative paths") from exc

    candidates: list[_Candidate] = []
    for relative in sorted(normalized, key=_path_sort_key):
        if relative == "." or _is_protected_relative(relative):
            continue
        if not include_ignored and _has_ignored_component(relative):
            continue
        safe_path = _safe_workspace_path(root, relative)
        if safe_path is None:
            continue
        try:
            if not safe_path.is_file() or safe_path.is_symlink():
                continue
            size_bytes = safe_path.stat().st_size
        except OSError:
            continue
        language = _language_for_relative(relative)
        if language is None:
            continue
        candidates.append(_Candidate(relative, safe_path, language, int(size_bytes)))
    return candidates, truncated


def _validate_relative_path(value: str | os.PathLike[str]) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise DependencyGraphError("INVALID_FILE_SET", "file paths must be text relative paths") from exc
    if isinstance(raw, bytes) or not raw or "\x00" in raw:
        raise DependencyGraphError("INVALID_FILE_SET", "file paths must be non-empty text paths")
    if raw.startswith(("/", "~")) or _WINDOWS_ABSOLUTE_RE.match(raw):
        raise DependencyGraphError("PATH_ABSOLUTE", "file paths must be relative to root")
    if "\\" in raw:
        raise DependencyGraphError("PATH_SEPARATOR", "file paths must use POSIX separators")
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise DependencyGraphError("PATH_TRAVERSAL", "parent traversal is not accepted in file paths")
    if not parts:
        return "."
    return "/".join(parts)


def _safe_workspace_path(root: Path, relative: str) -> Path | None:
    parts = relative.split("/") if relative != "." else []
    candidate = root.joinpath(*parts)
    current = root
    for part in parts:
        current /= part
        try:
            if current.is_symlink():
                return None
        except OSError:
            return None
    try:
        if candidate.is_symlink():
            return None
        if not candidate.exists():
            return None
        if root != candidate and root not in candidate.parents:
            return None
    except OSError:
        return None
    return candidate


def _relative_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _language_for_relative(relative_path: str) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(Path(relative_path).suffix.casefold())


def _is_protected_relative(relative_path: str) -> bool:
    components = [part for part in relative_path.replace("\\", "/").split("/") if part]
    lower_components = {part.casefold() for part in components}
    if lower_components & PROTECTED_COMPONENTS:
        return True
    for component in components:
        lower = component.casefold()
        if lower in PROTECTED_FILENAMES or lower.endswith(PROTECTED_SUFFIXES):
            return True
    return ".git" in lower_components


def _has_ignored_component(relative_path: str) -> bool:
    return any(part.casefold() in IGNORED_DIRECTORIES for part in relative_path.split("/"))


def _read_bounded(path: Path, max_file_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(path), flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("source path is not a regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(max_file_bytes + 1)
    except OSError:
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > max_file_bytes:
        raise _FileTooLarge
    return data


class _FileTooLarge(Exception):
    pass


def _parse_imports(
    candidate: _Candidate,
    source: str,
    *,
    max_specifier_length: int,
) -> tuple[list[_ImportRecord], dict[str, Any] | None]:
    if candidate.language == "python":
        try:
            tree = ast.parse(source, filename="<workspace>")
        except (SyntaxError, ValueError, RecursionError):
            return [], _diagnostic(
                candidate.relative_path,
                "syntax_error",
                "Python source could not be parsed",
            )
        records: list[_ImportRecord] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    records.append(
                        _ImportRecord(
                            specifier=alias.name,
                            kind="import",
                            position=int(getattr(node, "lineno", 0)),
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module
                prefix = "." * int(node.level) + (module or "")
                names = tuple(
                    alias.name
                    for alias in node.names
                    if alias.name and alias.name != "*"
                )
                specifier = prefix
                if module is None and names:
                    specifier = "." * int(node.level) + names[0]
                records.append(
                    _ImportRecord(
                        specifier=specifier,
                        kind="from_import",
                        position=int(getattr(node, "lineno", 0)),
                        names=names,
                        python_level=int(node.level),
                        python_module=module,
                    )
                )
        return _bound_records(records, max_specifier_length), None

    records, unclosed = _javascript_imports(source, max_specifier_length=max_specifier_length)
    if unclosed:
        return records, _diagnostic(
            candidate.relative_path,
            "syntax_notice",
            "JavaScript/TypeScript scanner reached an unterminated literal or comment",
        )
    return records, None


def _bound_records(records: list[_ImportRecord], max_specifier_length: int) -> list[_ImportRecord]:
    return [
        replace(
            record,
            specifier=_bounded_specifier(record.specifier, max_specifier_length),
            specifier_truncated=(
                record.specifier_truncated or len(record.specifier) > max_specifier_length
            ),
        )
        for record in records
        if record.specifier
    ]


def _javascript_imports(
    source: str,
    *,
    max_specifier_length: int,
) -> tuple[list[_ImportRecord], bool]:
    records: list[_ImportRecord] = []
    length = len(source)
    position = 0
    unclosed = False
    while position < length:
        character = source[position]
        if character.isspace():
            position += 1
            continue
        if source.startswith("//", position):
            newline = source.find("\n", position + 2)
            position = length if newline < 0 else newline + 1
            continue
        if source.startswith("/*", position):
            end = source.find("*/", position + 2)
            if end < 0:
                unclosed = True
                break
            position = end + 2
            continue
        if character in "'\"`":
            _, end = _read_js_string(source, position)
            if end is None:
                unclosed = True
                break
            position = end
            continue
        match = _IDENTIFIER_RE.match(source, position)
        if match is None:
            position += 1
            continue
        token = match.group(0)
        token_position = position
        position = match.end()
        if token == "require":
            literal = _literal_after_call(source, position)
            if literal is not None:
                specifier, end = literal
                records.append(
                    _ImportRecord(
                        specifier=specifier,
                        kind="require",
                        position=token_position,
                    )
                )
                position = end
        elif token == "import":
            after = _skip_js_trivia(source, position)
            if after < length and source[after] == "(":
                literal = _literal_after_call(source, after)
                if literal is not None:
                    specifier, end = literal
                    records.append(
                        _ImportRecord(
                            specifier=specifier,
                            kind="dynamic_import",
                            position=token_position,
                        )
                    )
                    position = end
            else:
                literal = _literal_in_import_declaration(source, after)
                if literal is not None:
                    specifier, end = literal
                    records.append(
                        _ImportRecord(
                            specifier=specifier,
                            kind="import",
                            position=token_position,
                        )
                    )
                    position = max(position, end)
        elif token == "export":
            literal = _literal_in_export_declaration(source, position)
            if literal is not None:
                specifier, end = literal
                records.append(
                    _ImportRecord(
                        specifier=specifier,
                        kind="export_from",
                        position=token_position,
                    )
                )
                position = max(position, end)
    return _bound_records(records, max_specifier_length), unclosed


def _skip_js_trivia(source: str, position: int) -> int:
    length = len(source)
    while position < length:
        if source[position].isspace():
            position += 1
        elif source.startswith("//", position):
            newline = source.find("\n", position + 2)
            position = length if newline < 0 else newline + 1
        elif source.startswith("/*", position):
            end = source.find("*/", position + 2)
            position = length if end < 0 else end + 2
        else:
            break
    return position


def _read_js_string(source: str, position: int) -> tuple[str, int | None]:
    if position >= len(source) or source[position] not in "'\"`":
        return "", None
    quote = source[position]
    result: list[str] = []
    position += 1
    while position < len(source):
        character = source[position]
        if character == quote:
            return "".join(result), position + 1
        if character in "\r\n":
            return "", None
        if character == "\\":
            if position + 1 >= len(source):
                return "", None
            escaped = source[position + 1]
            if escaped == "\n":
                position += 2
                continue
            result.append(escaped)
            position += 2
            continue
        result.append(character)
        position += 1
    return "", None


def _literal_after_call(source: str, position: int) -> tuple[str, int] | None:
    position = _skip_js_trivia(source, position)
    if position >= len(source) or source[position] != "(":
        return None
    position = _skip_js_trivia(source, position + 1)
    if position >= len(source) or source[position] not in "'\"`":
        return None
    specifier, end = _read_js_string(source, position)
    if end is None:
        return None
    return specifier, end


def _literal_in_import_declaration(source: str, position: int) -> tuple[str, int] | None:
    position = _skip_js_trivia(source, position)
    if position >= len(source):
        return None
    if source[position] in "'\"`":
        literal = _read_js_string(source, position)
        return literal if literal[1] is not None else None
    return _find_first_literal_before_statement_end(source, position)


def _literal_in_export_declaration(source: str, position: int) -> tuple[str, int] | None:
    position = _skip_js_trivia(source, position)
    length = len(source)
    saw_from = False
    while position < length:
        if source.startswith("//", position):
            newline = source.find("\n", position + 2)
            return None
        if source.startswith("/*", position):
            end = source.find("*/", position + 2)
            if end < 0:
                return None
            position = end + 2
            continue
        if source[position] in "'\"`":
            literal = _read_js_string(source, position)
            if literal[1] is None:
                return None
            if saw_from:
                return literal
            position = literal[1]
            continue
        if source[position] in ";\n" and not saw_from:
            return None
        match = _IDENTIFIER_RE.match(source, position)
        if match:
            if match.group(0) == "from":
                saw_from = True
            position = match.end()
        else:
            position += 1
    return None


def _find_first_literal_before_statement_end(source: str, position: int) -> tuple[str, int] | None:
    length = len(source)
    brace_depth = 0
    while position < length:
        if source.startswith("//", position):
            newline = source.find("\n", position + 2)
            if newline < 0:
                return None
            position = newline + 1
            continue
        if source.startswith("/*", position):
            end = source.find("*/", position + 2)
            if end < 0:
                return None
            position = end + 2
            continue
        character = source[position]
        if character in "'\"`":
            literal = _read_js_string(source, position)
            if literal[1] is None:
                return None
            return literal
        if character == "{":
            brace_depth += 1
        elif character == "}" and brace_depth:
            brace_depth -= 1
        elif character in ";\n" and brace_depth == 0:
            return None
        position += 1
    return None


def _resolve_import(
    root: Path,
    source_relative: str,
    *,
    candidate_language: str | None,
    record: _ImportRecord,
    selected_paths: set[str],
    include_ignored: bool,
) -> _Resolution:
    specifier = record.specifier
    if not specifier:
        return _Resolution(None, "invalid_specifier")
    if record.specifier_truncated or len(specifier) > MAX_SPECIFIER_LENGTH:
        return _Resolution(None, "specifier_too_long")
    if "\x00" in specifier or "\\" in specifier:
        return _Resolution(None, "unsafe_path")
    if _WINDOWS_ABSOLUTE_RE.match(specifier) or specifier.startswith(("/", "~")):
        return _Resolution(None, "unsafe_path")

    if candidate_language == "python":
        return _resolve_python_import(
            root,
            source_relative,
            record,
            selected_paths=selected_paths,
            include_ignored=include_ignored,
        )
    if not _is_relative_import_specifier(specifier):
        return _Resolution(None, "external")
    if "://" in specifier or "?" in specifier or "#" in specifier:
        return _Resolution(None, "external")
    normalized = _normalize_relative_import(source_relative, specifier)
    if normalized is None:
        return _Resolution(None, "unsafe_path")
    return _resolve_workspace_module(
        root,
        normalized,
        language=candidate_language,
        selected_paths=selected_paths,
        include_ignored=include_ignored,
    )


def _resolve_python_import(
    root: Path,
    source_relative: str,
    record: _ImportRecord,
    *,
    selected_paths: set[str],
    include_ignored: bool,
) -> _Resolution:
    module = record.python_module or ""
    module_parts = [part for part in module.split(".") if part]
    source_parent = list(Path(source_relative).parent.parts)
    if record.python_level:
        base_parts = source_parent
        for _ in range(record.python_level - 1):
            if not base_parts:
                return _Resolution(None, "unsafe_path")
            base_parts.pop()
    else:
        base_parts = []

    if record.kind == "import":
        module_parts = [part for part in record.specifier.split(".") if part]
        names: tuple[str, ...] = ()
    else:
        names = record.names

    if any(part in {".", ".."} or not part for part in module_parts):
        return _Resolution(None, "unsafe_path")
    module_relative = "/".join([*base_parts, *module_parts])
    options: list[str] = []
    if names and module_relative:
        for name in names:
            if _safe_import_component(name):
                options.append(f"{module_relative}/{name}")
    if module_relative:
        options.append(module_relative)
    elif names:
        for name in names:
            if _safe_import_component(name):
                options.append("/".join([*base_parts, name]))
    if not options:
        options.append("/".join(base_parts))

    module_present = False
    if module_relative:
        module_resolution = _resolve_workspace_module(
            root,
            module_relative,
            language="python",
            selected_paths=selected_paths,
            include_ignored=include_ignored,
        )
        module_present = (
            module_resolution.relative_path is not None
            or module_resolution.reason == "not_scanned"
        )
    for option in options:
        resolution = _resolve_workspace_module(
            root,
            option,
            language="python",
            selected_paths=selected_paths,
            include_ignored=include_ignored,
        )
        if resolution.relative_path is not None or resolution.reason in {
            "not_scanned",
            "ignored",
            "protected",
        }:
            return resolution

    if record.python_level:
        return _Resolution(None, "missing")
    # A top-level Python module without a workspace candidate is normally an
    # installed dependency.  If a package/module directory existed but did
    # not contain the requested child, preserve a useful missing distinction.
    if module_present:
        return _Resolution(None, "missing")
    return _Resolution(None, "external")


def _safe_import_component(component: str) -> bool:
    return bool(component) and component not in {".", ".."} and "/" not in component and "\\" not in component


def _is_relative_import_specifier(specifier: str) -> bool:
    return specifier in {".", ".."} or specifier.startswith(("./", "../"))


def _normalize_relative_import(source_relative: str, specifier: str) -> str | None:
    base = list(Path(source_relative).parent.parts)
    result = base
    for component in specifier.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not result:
                return None
            result.pop()
        else:
            if component in {".", ".."} or "\x00" in component:
                return None
            result.append(component)
    return "/".join(result) if result else "."


def _resolve_workspace_module(
    root: Path,
    base_relative: str,
    *,
    language: str | None,
    selected_paths: set[str],
    include_ignored: bool,
) -> _Resolution:
    if base_relative == ".":
        return _Resolution(None, "missing")
    if _is_protected_relative(base_relative):
        return _Resolution(None, "protected")
    if not include_ignored and _has_ignored_component(base_relative):
        return _Resolution(None, "ignored")
    if any(part == ".." for part in base_relative.split("/")):
        return _Resolution(None, "unsafe_path")

    suffixes = _resolution_suffixes(language, base_relative)
    variants = _module_variants(base_relative, suffixes)
    saw_existing_unsafe = False
    for variant in variants:
        if _is_protected_relative(variant):
            saw_existing_unsafe = True
            continue
        if not include_ignored and _has_ignored_component(variant):
            saw_existing_unsafe = True
            continue
        candidate = _safe_workspace_path(root, variant)
        if candidate is None:
            continue
        try:
            if not candidate.is_file() or candidate.is_symlink():
                continue
        except OSError:
            continue
        if variant in selected_paths:
            return _Resolution(variant, None)
        return _Resolution(None, "not_scanned")
    if saw_existing_unsafe:
        return _Resolution(None, "protected" if _is_protected_relative(base_relative) else "ignored")
    return _Resolution(None, "missing")


def _resolution_suffixes(language: str | None, base_relative: str) -> tuple[str, ...]:
    suffix = Path(base_relative).suffix.casefold()
    if language == "python":
        return ("", ".py") if suffix != ".py" else ("",)
    if language == "typescript":
        preferred = ("", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
    else:
        preferred = ("", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
    if suffix in SOURCE_SUFFIXES:
        return ("",) + tuple(ext for ext in preferred[1:] if ext != suffix)
    return preferred


def _module_variants(base_relative: str, suffixes: tuple[str, ...]) -> list[str]:
    variants: list[str] = []
    base_path = Path(base_relative)
    for suffix in suffixes:
        variants.append(base_relative if not suffix else f"{base_relative}{suffix}")
    for suffix in suffixes:
        variants.append(f"{base_relative}/__init__{suffix or '.py'}" if suffix else f"{base_relative}/index")
    # JS/TS package directories use index.<ext>; Python uses __init__.py.
    if suffixes and suffixes[0] == "":
        for suffix in suffixes[1:]:
            variants.append(f"{base_relative}/index{suffix}")
    if base_path.suffix.casefold() in SOURCE_SUFFIXES:
        variants.insert(0, base_relative)
    return list(dict.fromkeys(variants))


def _bounded_specifier(specifier: str, maximum: int) -> str:
    return specifier[:maximum]


def _diagnostic(
    relative_path: str,
    kind: str,
    message: str,
    *,
    limit: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "relative_path": relative_path,
        "kind": kind,
        "message": message,
    }
    if limit is not None:
        result["limit"] = limit
    return result


def _path_sort_key(value: str) -> tuple[str, str]:
    return value.casefold(), value


def _import_sort_key(item: tuple[str, _ImportRecord]) -> tuple[Any, ...]:
    source, record = item
    return _path_sort_key(source) + (record.position, record.kind, record.specifier)


def _diagnostic_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return _path_sort_key(str(item.get("relative_path", ""))) + (
        str(item.get("kind", "")),
        str(item.get("message", "")),
    )


def _make_payload(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    unresolved: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
    *,
    file_limited: bool,
    file_size_limited: bool,
    edge_limited: bool,
    specifier_limited: bool,
    output_limited: bool,
    reasons: list[str],
) -> dict[str, Any]:
    truncated = bool(
        file_limited
        or file_size_limited
        or edge_limited
        or specifier_limited
        or output_limited
    )
    return {
        "state": "partial" if truncated else "ready",
        "nodes": list(nodes),
        "edges": list(edges),
        "unresolved": list(unresolved),
        "diagnostics": list(diagnostics),
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "unresolved": len(unresolved),
            "diagnostics": len(diagnostics),
        },
        "truncated": truncated,
        "truncation": {
            "files": file_limited,
            "file_size": file_size_limited,
            "edges": edge_limited,
            "specifiers": specifier_limited,
            "output": output_limited,
            "reasons": sorted(set(reasons)),
        },
    }


def _serialized_size(payload: dict[str, Any]) -> int:
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return len(encoded)


def _fit_output(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    unresolved: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
    *,
    max_output_bytes: int,
    file_limited: bool,
    file_size_limited: bool,
    edge_limited: bool,
    specifier_limited: bool,
    base_reasons: list[str],
) -> dict[str, Any]:
    groups: list[tuple[str, list[dict[str, Any]]]] = [
        ("diagnostics", diagnostics),
        ("unresolved", unresolved),
        ("edges", edges),
        ("nodes", nodes),
    ]
    original_lengths = {name: len(items) for name, items in groups}
    retained = {name: list(items) for name, items in groups}

    def payload() -> dict[str, Any]:
        result = _make_payload(
            retained["nodes"],
            retained["edges"],
            retained["unresolved"],
            retained["diagnostics"],
            file_limited=file_limited,
            file_size_limited=file_size_limited,
            edge_limited=edge_limited,
            specifier_limited=specifier_limited,
            output_limited=True,
            reasons=[*base_reasons, "output_limit"],
        )
        omitted = {
            name: original_lengths[name] - len(retained[name])
            for name in original_lengths
            if original_lengths[name] != len(retained[name])
        }
        if omitted:
            result["truncation"]["omitted"] = omitted
        return result

    for name, _items in groups:
        if _serialized_size(payload()) <= max_output_bytes:
            break
        current = retained[name]
        low = 0
        high = len(current)
        while low < high:
            remove = (low + high) // 2
            if remove == 0:
                remove = 1
            retained[name] = current[: len(current) - remove]
            if _serialized_size(payload()) <= max_output_bytes:
                high = remove
            else:
                low = remove + 1
        retained[name] = current[: len(current) - low]

    result = payload()
    # The minimum output limit is validated up front; this final guard keeps
    # the contract fail-closed if the metadata shape changes later.
    if _serialized_size(result) > max_output_bytes:
        result["nodes"] = []
        result["edges"] = []
        result["unresolved"] = []
        result["diagnostics"] = []
        result["counts"] = {"nodes": 0, "edges": 0, "unresolved": 0, "diagnostics": 0}
    return result


__all__ = [
    "DEFAULT_MAX_EDGES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_MAX_SPECIFIER_LENGTH",
    "DependencyGraphError",
    "GraphLimits",
    "build_dependency_graph",
    "scan_dependency_graph",
]
