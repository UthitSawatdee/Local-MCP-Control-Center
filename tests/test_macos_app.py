from __future__ import annotations

import os
import plistlib
from pathlib import Path

from scripts.build_macos_app import APP_BUNDLE_NAME, build_app


def test_build_app_creates_clickable_bundle(tmp_path: Path) -> None:
    project = tmp_path / "project"
    python = project / ".venv" / "bin" / "python"
    init = project / "src" / "local_mcp_control_center" / "__init__.py"
    python.parent.mkdir(parents=True)
    init.parent.mkdir(parents=True)
    python.write_text("#!/bin/zsh\n", encoding="utf-8")
    python.chmod(0o755)
    init.write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    icon = tmp_path / "icon.icns"
    icon.write_bytes(b"test-icon")

    destination = build_app(
        project,
        destination=tmp_path / APP_BUNDLE_NAME,
        icon_source=icon,
    )

    launcher = destination / "Contents" / "MacOS" / "LocalMCPControlCenter"
    resources = destination / "Contents" / "Resources"
    with (destination / "Contents" / "Info.plist").open("rb") as handle:
        info = plistlib.load(handle)

    assert destination.is_dir()
    assert launcher.is_file()
    assert os.access(launcher, os.X_OK)
    assert resources.joinpath("project-root.txt").read_text(encoding="utf-8").strip() == str(project)
    assert resources.joinpath("python-path.txt").read_text(encoding="utf-8").strip() == str(python.absolute())
    assert resources.joinpath("python-arch.txt").read_text(encoding="utf-8").strip() in {"arm64", "x86_64"}
    assert resources.joinpath("AppIcon.icns").read_bytes() == b"test-icon"
    assert info["CFBundleDisplayName"] == "Local MCP Control Center"
    assert info["CFBundleExecutable"] == "LocalMCPControlCenter"
    assert info["CFBundleShortVersionString"] == "9.9.9"
    assert info["CFBundleIconFile"] == "AppIcon.icns"
    assert " local_mcp_control_center" in launcher.read_text(encoding="utf-8")
