from __future__ import annotations

import json
from pathlib import Path

import pytest

from local_mcp_control_center.dependency_graph import (
    DependencyGraphError,
    GraphLimits,
    build_dependency_graph,
)


def _edge(graph: dict[str, object], source: str, target: str) -> dict[str, object]:
    return next(
        item
        for item in graph["edges"]  # type: ignore[index]
        if item["source"] == source and item["target"] == target  # type: ignore[index]
    )


def test_python_and_javascript_typescript_imports_resolve_deterministically(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "pkg").mkdir()
    (root / "pkg" / "__init__.py").write_text("from .util import helper\n", encoding="utf-8")
    (root / "pkg" / "util.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
    (root / "main.py").write_text(
        "import pkg.util\nfrom pkg import util\nimport requests\nfrom .missing import value\n",
        encoding="utf-8",
    )
    (root / "ui.ts").write_text(
        'import { value } from "./lib";\n'
        'const helper = require("./helper");\n'
        'export { value } from "./lib";\n'
        'import("external-package");\n',
        encoding="utf-8",
    )
    (root / "lib.ts").write_text("export const value = 1;\n", encoding="utf-8")
    (root / "helper.js").write_text("module.exports = {};\n", encoding="utf-8")

    first = build_dependency_graph(root)
    second = build_dependency_graph(root)

    assert first == second
    assert [node["relative_path"] for node in first["nodes"]] == sorted(
        node["relative_path"] for node in first["nodes"]
    )
    assert any(
        item["source"] == "main.py"
        and item["target"] == "pkg/util.py"
        and item["specifier"] == "pkg.util"
        for item in first["edges"]
    )
    assert _edge(first, "ui.ts", "helper.js")["kind"] == "require"
    assert _edge(first, "ui.ts", "lib.ts")["kind"] == "export_from"
    unresolved = {(item["source"], item["specifier"], item["reason"]) for item in first["unresolved"]}
    assert ("main.py", "requests", "external") in unresolved
    assert ("main.py", ".missing", "missing") in unresolved
    assert ("ui.ts", "external-package", "external") in unresolved
    assert all("content" not in node for node in first["nodes"])
    assert "return 1" not in json.dumps(first)


def test_relative_resolution_stays_inside_root_and_reports_unsafe_import(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    (root / "src").mkdir(parents=True)
    (root / "shared").mkdir()
    (root / "src" / "app.ts").write_text(
        'import "../shared/util";\nimport "../../outside";\nimport "/etc/passwd";\n',
        encoding="utf-8",
    )
    (root / "shared" / "util.ts").write_text("export const ok = true;\n", encoding="utf-8")

    graph = build_dependency_graph(root)

    assert _edge(graph, "src/app.ts", "shared/util.ts")["specifier"] == "../shared/util"
    unsafe = {(item["specifier"], item["reason"]) for item in graph["unresolved"]}
    assert ("../../outside", "unsafe_path") in unsafe
    assert ("/etc/passwd", "unsafe_path") in unsafe


def test_ignored_protected_and_symlink_trees_are_not_read(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.py").write_text(
        "import node_modules.dep\nfrom . import secret\n",
        encoding="utf-8",
    )
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dep.py").write_text("token = 'secret'\n", encoding="utf-8")
    (root / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("password = 'secret'\n", encoding="utf-8")
    link = root / "linked.py"
    try:
        link.symlink_to(outside / "secret.py")
    except OSError:
        pytest.skip("symlinks are unavailable in this environment")

    graph = build_dependency_graph(root)

    paths = {node["relative_path"] for node in graph["nodes"]}
    assert paths == {"app.py"}
    assert all("node_modules" not in path for path in paths)
    assert all("secret" not in json.dumps(item) for item in graph["nodes"])
    assert {item["reason"] for item in graph["unresolved"]} >= {"ignored", "missing"}


def test_explicit_file_set_is_bounded_and_does_not_expand_to_import_targets(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "a.py").write_text("from . import b\n", encoding="utf-8")
    (root / "b.py").write_text("value = 1\n", encoding="utf-8")

    graph = build_dependency_graph(root, files=["a.py"])

    assert [node["relative_path"] for node in graph["nodes"]] == ["a.py"]
    assert graph["unresolved"] == [
        {"source": "a.py", "specifier": ".b", "kind": "from_import", "reason": "not_scanned"}
    ]


def test_syntax_encoding_and_file_size_diagnostics_are_safe(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    (root / "binary.py").write_bytes(b"\xff\xfe")
    (root / "large.py").write_text("import x\n" + ("#" * 100), encoding="utf-8")

    graph = build_dependency_graph(root, max_file_bytes=16)

    diagnostics = {(item["relative_path"], item["kind"]) for item in graph["diagnostics"]}
    assert ("bad.py", "syntax_error") in diagnostics
    assert ("binary.py", "encoding_error") in diagnostics
    assert ("large.py", "file_too_large") in diagnostics
    assert graph["truncated"] is True
    assert graph["truncation"]["file_size"] is True  # type: ignore[index]
    assert "broken" not in json.dumps(graph)
    assert "\ufffd" not in json.dumps(graph)


def test_file_and_edge_limits_are_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    for name in ("a.py", "b.py", "c.py"):
        (root / name).write_text("import external_one\nimport external_two\n", encoding="utf-8")

    graph = build_dependency_graph(root, max_files=2, max_edges=1)

    assert [node["relative_path"] for node in graph["nodes"]] == ["a.py", "b.py"]
    assert len(graph["unresolved"]) + len(graph["edges"]) == 1
    assert graph["truncation"]["files"] is True  # type: ignore[index]
    assert graph["truncation"]["edges"] is True  # type: ignore[index]
    assert graph["truncation"]["reasons"] == ["edge_limit", "file_limit"]  # type: ignore[index]


def test_output_limit_truncates_metadata_without_exceeding_bound(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    for index in range(12):
        (root / f"module_{index:02d}.py").write_text(
            "import " + ("external_dependency_" + str(index) * 20) + "\n",
            encoding="utf-8",
        )

    graph = build_dependency_graph(root, max_output_bytes=900)
    encoded = json.dumps(graph, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()

    assert graph["truncated"] is True
    assert graph["truncation"]["output"] is True  # type: ignore[index]
    assert len(encoded) <= 900
    assert all(len(item["specifier"]) <= 256 for item in graph["unresolved"])  # type: ignore[index]


def test_import_specifier_limit_is_bounded_and_not_resolved(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "main.js").write_text('import "./' + ("x" * 40) + '";\n', encoding="utf-8")

    graph = build_dependency_graph(root, max_specifier_length=8)

    assert graph["edges"] == []
    assert graph["unresolved"][0]["reason"] == "specifier_too_long"  # type: ignore[index]
    assert len(graph["unresolved"][0]["specifier"]) == 8  # type: ignore[index]
    assert graph["truncation"]["specifiers"] is True  # type: ignore[index]
    assert graph["truncation"]["reasons"] == ["specifier_limit"]  # type: ignore[index]


def test_malformed_root_limits_and_paths_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()

    with pytest.raises(DependencyGraphError) as missing:
        build_dependency_graph(root / "missing")
    assert missing.value.code == "ROOT_NOT_FOUND"

    with pytest.raises(DependencyGraphError) as invalid_limit:
        build_dependency_graph(root, max_files=0)
    assert invalid_limit.value.code == "INVALID_LIMIT"

    with pytest.raises(DependencyGraphError) as absolute:
        build_dependency_graph(root, files=[str(root / "a.py")])
    assert absolute.value.code == "PATH_ABSOLUTE"

    with pytest.raises(DependencyGraphError) as traversal:
        build_dependency_graph(root, files=["../outside.py"])
    assert traversal.value.code == "PATH_TRAVERSAL"


def test_graph_limits_value_and_scan_alias_are_supported(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "main.js").write_text('require("./dep");\n', encoding="utf-8")
    (root / "dep.js").write_text("module.exports = 1;\n", encoding="utf-8")

    graph = build_dependency_graph(root, limits=GraphLimits(max_files=2, max_edges=2))

    assert _edge(graph, "main.js", "dep.js")["kind"] == "require"
