"""Build a clickable macOS application bundle for the local GUI.

The bundle is a small launcher, not a second copy of the application.  It
points at this checkout's virtual environment and source tree so the normal
CLI, MCP bridge, SQLite state, and tunnel configuration remain the same.
"""

from __future__ import annotations

import argparse
import os
import platform
import plistlib
import re
import shutil
import stat
from pathlib import Path


APP_NAME = "Local MCP Control Center"
APP_BUNDLE_NAME = f"{APP_NAME}.app"
BUNDLE_IDENTIFIER = "com.local-mcp-control-center"
DEFAULT_DESTINATION = Path.home() / "Applications" / APP_BUNDLE_NAME
DEFAULT_ICON_SOURCE = Path(
    "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/"
    "GenericApplicationIcon.icns"
)
VERSION_PATTERN = re.compile(r'__version__\s*=\s*["\']([^"\']+)["\']')


LAUNCHER = r'''#!/bin/zsh
set -u

CONTENTS_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd)"
PROJECT_ROOT_FILE="$CONTENTS_DIR/Resources/project-root.txt"
PYTHON_FILE="$CONTENTS_DIR/Resources/python-path.txt"
PYTHON_ARCH_FILE="$CONTENTS_DIR/Resources/python-arch.txt"

show_error() {
  /usr/bin/osascript <<'APPLESCRIPT'
display dialog "Local MCP Control Center cannot start. Check the installation and try again." buttons {"OK"} with title "Local MCP Control Center"
APPLESCRIPT
}

if [[ ! -f "$PROJECT_ROOT_FILE" || ! -f "$PYTHON_FILE" ]]; then
  show_error
  exit 1
fi

PROJECT_ROOT="$(< "$PROJECT_ROOT_FILE")"
PYTHON="$(< "$PYTHON_FILE")"
PYTHON_ARCH=""
if [[ -f "$PYTHON_ARCH_FILE" ]]; then
  PYTHON_ARCH="$(< "$PYTHON_ARCH_FILE")"
fi

if [[ ! -d "$PROJECT_ROOT" || ! -x "$PYTHON" ]]; then
  show_error
  exit 1
fi

DATA_DIR="${HOME}/Library/Application Support/LocalMCPControlCenter"
LOG_DIR="$DATA_DIR/logs"
LOG_PATH="$LOG_DIR/gui-launcher.log"
if ! /bin/mkdir -p "$LOG_DIR"; then
  show_error
  exit 1
fi

cd -- "$PROJECT_ROOT" || {
  show_error
  exit 1
}

export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin${PATH:+:$PATH}"
RUNNER=( "$PYTHON" )
if [[ "$PYTHON_ARCH" == "arm64" || "$PYTHON_ARCH" == "x86_64" ]]; then
  RUNNER=( /usr/bin/arch "-$PYTHON_ARCH" "$PYTHON" )
fi
exec "${RUNNER[@]}" -m local_mcp_control_center \
  --data-dir "$DATA_DIR" gui >>"$LOG_PATH" 2>&1
'''


def _project_version(project_root: Path) -> str:
    version_file = project_root / "src" / "local_mcp_control_center" / "__init__.py"
    match = VERSION_PATTERN.search(version_file.read_text(encoding="utf-8"))
    if match is None:
        raise RuntimeError(f"Could not read application version from {version_file}")
    return match.group(1)


def _required_executable(path: Path, label: str) -> Path:
    path = path.expanduser().absolute()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"{label} is missing or not executable: {path}")
    return path


def _runtime_architecture() -> str:
    value = platform.machine().lower()
    aliases = {"aarch64": "arm64", "amd64": "x86_64"}
    return aliases.get(value, value)


def _write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def _install_icon(resources_dir: Path, icon_source: Path | None) -> bool:
    source = icon_source.expanduser().absolute() if icon_source else DEFAULT_ICON_SOURCE
    if not source.is_file():
        return False
    target = resources_dir / "AppIcon.icns"
    # System .icns files can carry macOS flags that are not transferable to a
    # user-created bundle.  Copy the bytes only, then apply normal app modes.
    shutil.copyfile(source, target)
    target.chmod(0o644)
    return True


def build_app(
    project_root: Path | str,
    *,
    destination: Path | str = DEFAULT_DESTINATION,
    python_path: Path | str | None = None,
    icon_source: Path | str | None = None,
) -> Path:
    """Build and return one exact, user-clickable application bundle."""

    project_root = Path(project_root).expanduser().absolute().resolve(strict=True)
    if not project_root.is_dir():
        raise RuntimeError(f"Project root is not a directory: {project_root}")

    python = _required_executable(
        Path(python_path) if python_path else project_root / ".venv" / "bin" / "python",
        "Project Python",
    )
    destination = Path(destination).expanduser().absolute()
    if destination.suffix != ".app" or destination.name != APP_BUNDLE_NAME:
        raise RuntimeError(f"Destination must be named {APP_BUNDLE_NAME}: {destination}")
    if destination == Path.home() or destination == Path("/"):
        raise RuntimeError("Refusing to replace a broad directory with an app bundle")
    if destination.is_symlink():
        raise RuntimeError(f"Refusing to replace a symlink: {destination}")
    if destination.exists():
        if not destination.is_dir():
            raise RuntimeError(f"Destination exists and is not a directory: {destination}")
        shutil.rmtree(destination)

    contents = destination / "Contents"
    macos = contents / "MacOS"
    resources = contents / "Resources"
    macos.mkdir(parents=True)
    resources.mkdir()

    launcher = macos / "LocalMCPControlCenter"
    _write_text(launcher, LAUNCHER)
    launcher.chmod(
        launcher.stat().st_mode
        | stat.S_IXUSR
        | stat.S_IXGRP
        | stat.S_IXOTH
    )
    _write_text(resources / "project-root.txt", f"{project_root}\n")
    _write_text(resources / "python-path.txt", f"{python}\n")
    python_arch = _runtime_architecture()
    if python_arch in {"arm64", "x86_64"}:
        _write_text(resources / "python-arch.txt", f"{python_arch}\n")

    has_icon = _install_icon(
        resources,
        Path(icon_source) if icon_source else None,
    )
    version = _project_version(project_root)
    info = {
        "CFBundleDisplayName": APP_NAME,
        "CFBundleExecutable": launcher.name,
        "CFBundleIdentifier": BUNDLE_IDENTIFIER,
        "CFBundleIconFile": "AppIcon.icns" if has_icon else "",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": APP_NAME,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleSignature": "????",
        "CFBundleVersion": version,
        "LSMinimumSystemVersion": "13.0",
        "LSArchitecturePriority": [python_arch] if python_arch in {"arm64", "x86_64"} else [],
        "LSMultipleInstancesProhibited": True,
        "NSHighResolutionCapable": True,
    }
    with (contents / "Info.plist").open("wb") as handle:
        plistlib.dump(info, handle, fmt=plistlib.FMT_XML, sort_keys=False)
    (contents / "Info.plist").chmod(0o644)
    return destination


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the clickable macOS app bundle")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository checkout used by the launcher",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        default=DEFAULT_DESTINATION,
        help=f"app bundle destination (default: {DEFAULT_DESTINATION})",
    )
    parser.add_argument(
        "--python",
        type=Path,
        default=None,
        help="Python executable; defaults to <project-root>/.venv/bin/python",
    )
    parser.add_argument(
        "--icon",
        type=Path,
        default=None,
        help="optional .icns file; macOS GenericApplicationIcon is the default",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    app_path = build_app(
        args.project_root,
        destination=args.destination,
        python_path=args.python,
        icon_source=args.icon,
    )
    print(f"Created {app_path}")
    print("Double-click it in Applications or drag it to the Dock.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
