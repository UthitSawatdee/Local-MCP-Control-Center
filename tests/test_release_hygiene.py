"""Release-hygiene regression tests using only synthetic paths in a temp repo.

These tests do not scan real credentials, the application data directory, or
this checkout's Git index/history. Full release scans are a separate gate.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _ignored_paths(tmp_path: Path, paths: list[str]) -> set[str]:
    git = shutil.which("git")
    if git is None:
        pytest.fail("Git is required to verify release ignore rules")
    repo = tmp_path / "synthetic-repository"
    repo.mkdir()
    home = tmp_path / "isolated-home"
    home.mkdir()
    (repo / ".gitignore").write_text(
        (ROOT / ".gitignore").read_text(encoding="utf-8"), encoding="utf-8"
    )
    # Do not inherit real Git configuration, credentials, or GIT_DIR overrides.
    environment = {
        "PATH": os.defpath,
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    prefix = [
        git, "-c", "core.fsmonitor=false",
        "-c", f"core.excludesFile={os.devnull}",
    ]
    subprocess.run(
        [*prefix, "init", "--quiet"], cwd=repo, env=environment,
        check=True, capture_output=True, timeout=15, shell=False,
    )
    result = subprocess.run(
        [*prefix, "check-ignore", "--no-index", "--stdin", "-z"],
        cwd=repo, env=environment,
        input="\0".join(paths) + "\0", text=True,
        capture_output=True, check=False, timeout=15, shell=False,
    )
    assert result.returncode in {0, 1}, result.stderr
    return {path for path in result.stdout.split("\0") if path}


def test_secret_and_runtime_paths_are_ignored(tmp_path: Path) -> None:
    paths = [
        ".env", ".env.production", "nested/.env", "nested/.env.local",
        ".envrc", ".mcp.json", "config/tunnel.local.json",
        "config/agent.local.toml", "config/agent.local.yaml",
        "config/agent.local.yml", "keys/server.pem", "keys/server.key",
        "keys/server.p8", "keys/server.p12", "keys/server.pfx",
        "keys/server.jks", "keys/server.keystore", "keys/id_rsa",
        "keys/id_dsa", "keys/id_ecdsa", "keys/id_ed25519",
        ".ssh/config", ".aws/config", ".gnupg/private-material",
        ".codex/sessions/session.jsonl", "credentials.json",
        "config/credentials.prod.json", "config/client_secret_demo.json",
        "config/service-account-demo.json", "config/service_account_demo.json",
        "secrets.json", "config/secrets.prod.json", "token.json",
        "tokens.json", "auth.json", "accounts.json", "cookies.json",
        "browser/storage-state.json", "browser/storage_state.json",
        "control.sqlite3", "control.sqlite3-wal", "state/app.sqlite-shm",
        "state/app.db", "state/app.db-wal", "backup.dump", "backup.sql.gz",
        "logs/session.txt", "snapshots/source.txt", "run/process.json",
        "backups/source.py", ".agents/runtime/session.yml", "debug.log",
        "server.pid", ".DS_Store", "docs/.DS_Store", "docs/._README.md",
        "dist/package.whl", "Local MCP Control Center.app/Contents/Info.plist",
        ".venv/lib/local.py", "build/generated.py", "__pycache__/demo.pyc",
        "src/demo.egg-info/PKG-INFO", ".coverage", ".coverage.worker",
        "htmlcov/index.html", ".pytest_cache/state", ".mypy_cache/state",
        ".ruff_cache/state", ".tox/state", ".nox/state", "README.md~",
    ]
    assert _ignored_paths(tmp_path, paths) == set(paths)


def test_source_tests_and_placeholder_examples_remain_trackable(tmp_path: Path) -> None:
    paths = [
        ".gitignore", "pyproject.toml", "README.md", "ARCHITECTURE.md",
        "CONTEXT.md", "config/README.md", ".env.example",
        "config/.env.example", "config/agent.example.json",
        "src/local_mcp_control_center/broker.py",
        "src/local_mcp_control_center/codex_threads.py",
        "src/local_mcp_control_center/motion_erp.py",
        "tests/test_context_ledger.py", "tests/test_release_hygiene.py",
        "scripts/build_macos_app.py", "docs/RELEASE_CHECKLIST.md",
        ".agents/skills/example/SKILL.md", "migrations/001_schema.sql",
        "tests/fixtures/public-certificate.crt", "keys/id_ed25519.pub",
    ]
    assert _ignored_paths(tmp_path, paths) == set()


def test_public_onboarding_has_no_personal_home_paths() -> None:
    personal_home = re.compile(r"(?:/Users/[^/\s]+|/home/[^/\s]+)/")
    for relative_path in ("README.md", "ARCHITECTURE.md", "config/README.md"):
        content = (ROOT / relative_path).read_text(encoding="utf-8")
        assert personal_home.search(content) is None, relative_path
