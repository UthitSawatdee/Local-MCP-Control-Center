from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PolicyError
from .filesystem import redact_text, validate_relative_path


TRUSTED_BIN_DIRS = tuple(
    path for path in (
        Path("/usr/bin"),
        Path("/bin"),
        Path("/usr/local/bin"),
        Path("/opt/homebrew/bin"),
        Path("/opt/local/bin"),
        Path.home() / ".local" / "bin",
    )
    if path.is_dir()
)


@dataclass(frozen=True, slots=True)
class CommandResult:
    profile: str
    argv_display: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "argv": self.argv_display,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "duration_ms": self.duration_ms,
        }


def display_argv(argv: list[str]) -> str:
    """Return a bounded, redacted diagnostic command without local root paths."""
    if not argv:
        return ""
    return redact_text(" ".join([Path(argv[0]).name, *argv[1:]]))[:2_000]


@dataclass(frozen=True, slots=True)
class ProjectProfile:
    """A locally detected project command profile.

    Commands are stored as executable plus argument arrays.  A client may pick
    a profile and a validated test path, but cannot provide a command string or
    arbitrary flags.
    """

    name: str
    project_type: str
    working_directory: Path
    executable: str
    args: tuple[str, ...]
    timeout_ms: int = 600_000
    source: str = "detected"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "project_type": self.project_type,
            "working_directory": str(self.working_directory),
            "executable": self.executable,
            "args": list(self.args),
            "timeout_ms": self.timeout_ms,
            "source": self.source,
        }


class ProjectProfileRegistry:
    """Detect a small, explicit set of development profiles from project files."""

    def detect(self, project_root: Path) -> dict[str, ProjectProfile]:
        if not project_root.is_dir():
            raise PolicyError("TARGET_NOT_FOUND", "project root is not a directory")
        profiles: dict[str, ProjectProfile] = {}
        backend = project_root / "backend"
        frontend = project_root / "frontend"
        if backend.is_dir():
            executable = self._project_python(project_root, backend)
            profiles["backend_pytest"] = ProjectProfile(
                "backend_pytest", "python", backend, executable, ("-m", "pytest", "-q")
            )
            ruff = self._project_optional(backend, "ruff")
            if ruff:
                profiles["backend_lint"] = ProjectProfile(
                    "backend_lint", "python", backend, ruff, ("check", ".")
                )
            mypy = self._project_optional(backend, "mypy")
            if mypy:
                profiles["backend_typecheck"] = ProjectProfile(
                    "backend_typecheck", "python", backend, mypy, (".",)
                )
        if frontend.is_dir():
            npm = self._trusted_optional("npm")
            scripts = self._package_scripts(frontend / "package.json")
            if npm:
                profiles["frontend_test"] = ProjectProfile(
                    "frontend_test", "node", frontend, npm, ("test", "--", "--run")
                )
                if "lint" in scripts:
                    profiles["frontend_lint"] = ProjectProfile(
                        "frontend_lint", "node", frontend, npm, ("run", "lint")
                    )
                if "typecheck" in scripts or "type-check" in scripts:
                    script = "typecheck" if "typecheck" in scripts else "type-check"
                    profiles["frontend_typecheck"] = ProjectProfile(
                        "frontend_typecheck", "node", frontend, npm, ("run", script)
                    )
                if "build" in scripts:
                    profiles["frontend_build"] = ProjectProfile(
                        "frontend_build", "node", frontend, npm, ("run", "build")
                    )
                if "dev" in scripts or "start" in scripts:
                    script = "dev" if "dev" in scripts else "start"
                    profiles["frontend_dev"] = ProjectProfile(
                        "frontend_dev", "node", frontend, npm, ("run", script), timeout_ms=3_600_000
                    )
        if not profiles and (project_root / "pyproject.toml").is_file():
            python = self._project_python(project_root, project_root)
            profiles["backend_pytest"] = ProjectProfile(
                "backend_pytest", "python", project_root, python, ("-m", "pytest", "-q")
            )
            ruff = self._project_optional(project_root, "ruff")
            if ruff:
                profiles["backend_lint"] = ProjectProfile(
                    "backend_lint", "python", project_root, ruff, ("check", ".")
                )
            mypy = self._project_optional(project_root, "mypy")
            if mypy:
                profiles["backend_typecheck"] = ProjectProfile(
                    "backend_typecheck", "python", project_root, mypy, (".",)
                )
        return profiles

    @staticmethod
    def _package_scripts(path: Path) -> dict[str, str]:
        if not path.is_file():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        scripts = value.get("scripts") if isinstance(value, dict) else None
        return {str(key): str(item) for key, item in scripts.items()} if isinstance(scripts, dict) else {}

    @staticmethod
    def _trusted_optional(executable: str) -> str | None:
        try:
            return ProjectProfileRegistry._trusted_executable(executable)
        except PolicyError:
            return None

    @staticmethod
    def _project_optional(project_directory: Path, executable: str) -> str | None:
        local = project_directory / ".venv" / "bin" / executable
        if local.is_file() and os.access(local, os.X_OK):
            return str(local)
        return ProjectProfileRegistry._trusted_optional(executable)

    @classmethod
    def _project_python(cls, project_root: Path, working_directory: Path) -> str:
        for directory in (working_directory, project_root):
            candidate = directory / ".venv" / "bin" / "python"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return cls._trusted_executable("python3")

    @staticmethod
    def _trusted_executable(executable: str) -> str:
        if Path(executable).name != executable or not executable:
            raise PolicyError("PROFILE_NOT_ALLOWED", f"invalid executable name: {executable}")
        for directory in TRUSTED_BIN_DIRS:
            candidate = directory / executable
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        raise PolicyError("PROFILE_NOT_ALLOWED", f"required executable is unavailable: {executable}")


class FixedRunner:
    """Executes only named, fixed command profiles; it never invokes a shell."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.runtime_home = data_dir / "runtime-home"
        self.runtime_tmp = data_dir / "runtime-tmp"
        self.runtime_home.mkdir(parents=True, exist_ok=True)
        self.runtime_tmp.mkdir(parents=True, exist_ok=True)
        self.profile_registry = ProjectProfileRegistry()

    def run(self, profile: str, project_root: Path, *, output_limit: int = 65_536, timeout_seconds: int = 600) -> CommandResult:
        output_limit = max(1, min(int(output_limit), 1_048_576))
        timeout_seconds = max(1, min(int(timeout_seconds), 3_600))
        argv, cwd = self._profile(profile, project_root)
        return self._run_argv(profile, argv, cwd, output_limit=output_limit, timeout_seconds=timeout_seconds)

    def run_project_profile(
        self,
        profile: str,
        project_root: Path,
        *,
        target: str | None = None,
        test_path: str | None = None,
        output_limit: int = 65_536,
        timeout_seconds: int | None = None,
    ) -> CommandResult:
        """Run a detected profile with only a validated test-path extension."""
        selected = self._resolve_project_profile(profile, project_root, target=target, test_path=test_path)
        timeout = selected.timeout_ms // 1000 if timeout_seconds is None else timeout_seconds
        return self._run_argv(
            selected.name,
            [selected.executable, *selected.args],
            selected.working_directory,
            output_limit=output_limit,
            timeout_seconds=max(1, min(int(timeout), 3_600)),
        )

    def available_profiles(self, project_root: Path) -> list[dict[str, Any]]:
        return [profile.to_dict() for profile in self.profile_registry.detect(project_root).values()]

    def inspect_runtime_versions(self, project_root: Path) -> dict[str, dict[str, Any]]:
        """Probe only fixed runtime ``--version`` commands.

        This is intentionally separate from project command profiles.  The
        WorkspaceEngine may observe local runtime drift, but callers cannot
        provide an executable, arguments, environment, or shell command.
        """
        executables: dict[str, str] = {}
        for name, executable_name in (
            ("python", "python3"),
            ("node", "node"),
            ("npm", "npm"),
            ("git", "git"),
            ("postgres", "psql"),
        ):
            try:
                executables[name] = self._trusted_executable(executable_name)
            except PolicyError:
                continue
        result: dict[str, dict[str, Any]] = {}
        for name, executable in executables.items():
            command = self._run_argv(
                f"runtime_version:{name}",
                [executable, "--version"],
                self.runtime_home,
                output_limit=256,
                timeout_seconds=10,
            )
            version = (command.stdout or command.stderr).splitlines()[0][:120] if (command.stdout or command.stderr) else None
            result[name] = {
                "state": "available" if command.exit_code == 0 and not command.timed_out else "unavailable",
                "version": version,
                "exit_code": command.exit_code,
                "timed_out": command.timed_out,
            }
        return result

    def tracked_paths(self, project_root: Path) -> list[str]:
        """Return bounded tracked filenames only; never reads file contents."""
        command = self._run_argv(
            "git_tracked_paths",
            self._git(["ls-files", "-z", "--cached"]),
            project_root,
            output_limit=1_048_576,
            timeout_seconds=30,
        )
        if command.stdout_truncated or command.stderr_truncated:
            raise PolicyError("GIT_OUTPUT_TRUNCATED", "tracked path inventory was truncated")
        if command.exit_code != 0 or command.timed_out:
            return []
        if command.stdout and not command.stdout.endswith("\x00"):
            raise PolicyError("GIT_OUTPUT_TRUNCATED", "tracked path inventory was incomplete")
        paths = [item for item in command.stdout.split("\x00") if item and not item.startswith("/")]
        unique_paths = sorted(set(paths))
        if len(unique_paths) > 10_000:
            raise PolicyError("GIT_OUTPUT_TRUNCATED", "tracked path inventory exceeds the metadata limit")
        return unique_paths

    def _run_argv(
        self,
        profile: str,
        argv: list[str],
        cwd: Path,
        *,
        output_limit: int,
        timeout_seconds: int,
    ) -> CommandResult:
        safe_path = os.pathsep.join(str(path) for path in TRUSTED_BIN_DIRS)
        environment = {
            "PATH": safe_path,
            "HOME": str(self.runtime_home),
            "TMPDIR": str(self.runtime_tmp),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "CI": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "PAGER": "cat",
            "NO_COLOR": "1",
        }
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
                shell=False,
                text=False,
                start_new_session=True,
            )
            stdout_raw = completed.stdout or b""
            stderr_raw = completed.stderr or b""
            stdout_truncated = len(stdout_raw) > output_limit
            stderr_truncated = len(stderr_raw) > output_limit
            stdout = stdout_raw[:output_limit].decode("utf-8", errors="replace")
            stderr = stderr_raw[:output_limit].decode("utf-8", errors="replace")
            return CommandResult(
                profile,
                display_argv(argv),
                completed.returncode,
                stdout,
                stderr,
                False,
                stdout_truncated,
                stderr_truncated,
                int((time.monotonic() - started) * 1000),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"")[:output_limit]
            stderr = (exc.stderr or b"")[:output_limit]
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            return CommandResult(
                profile,
                display_argv(argv),
                -1,
                stdout,
                stderr,
                True,
                len(exc.stdout or b"") > output_limit,
                len(exc.stderr or b"") > output_limit,
                int((time.monotonic() - started) * 1000),
            )
        except OSError as exc:
            raise PolicyError("PROFILE_NOT_ALLOWED", f"unable to start fixed profile: {exc}") from exc

    def _resolve_project_profile(
        self,
        profile: str,
        project_root: Path,
        *,
        target: str | None,
        test_path: str | None,
    ) -> ProjectProfile:
        profiles = self.profile_registry.detect(project_root)
        if target is not None and target not in {"backend", "frontend", "auto"}:
            raise PolicyError("INVALID_INPUT", "target must be backend, frontend, or auto")
        if profile == "run_targeted_test":
            if target == "backend":
                selected_name = "backend_pytest"
            elif target == "frontend":
                selected_name = "frontend_test"
            else:
                selected_name = "backend_pytest" if "backend_pytest" in profiles else "frontend_test"
        elif profile in {"run_lint", "lint"}:
            selected_name = self._quality_name(profiles, "lint", target)
        elif profile in {"run_typecheck", "typecheck"}:
            selected_name = self._quality_name(profiles, "typecheck", target)
        elif profile in {"run_build", "build"}:
            selected_name = "frontend_build" if target in {None, "auto", "frontend"} else "backend_build"
        else:
            selected_name = profile
        selected = profiles.get(selected_name)
        if selected is None:
            raise PolicyError("PROFILE_NOT_ALLOWED", f"project profile is unavailable: {selected_name}")
        if test_path is not None:
            if selected_name not in {"backend_pytest", "frontend_test"}:
                raise PolicyError("INVALID_INPUT", "test_path is only valid for a test profile")
            parts = validate_relative_path(test_path)
            candidate = selected.working_directory.joinpath(*parts)
            if not candidate.is_file() or candidate.is_symlink():
                raise PolicyError("TARGET_NOT_FOUND", "test_path must identify an existing regular file")
            selected = ProjectProfile(
                selected.name,
                selected.project_type,
                selected.working_directory,
                selected.executable,
                (*selected.args, test_path),
                selected.timeout_ms,
                selected.source,
            )
        return selected

    @staticmethod
    def _quality_name(profiles: dict[str, ProjectProfile], quality: str, target: str | None) -> str:
        candidates = []
        if target in {None, "auto", "backend"}:
            candidates.append(f"backend_{quality}")
        if target in {None, "auto", "frontend"}:
            candidates.append(f"frontend_{quality}")
        for name in candidates:
            if name in profiles:
                return name
        raise PolicyError("PROFILE_NOT_ALLOWED", f"project profile is unavailable: {quality}")

    def _profile(self, profile: str, project_root: Path) -> tuple[list[str], Path]:
        if not project_root.is_dir():
            raise PolicyError("TARGET_NOT_FOUND", "project root is not a directory")
        if profile == "git_status":
            return self._git(["status", "--short", "--branch", "--untracked-files=normal"]), project_root
        if profile == "git_diff":
            return self._git(
                [
                    "diff",
                    "--no-ext-diff",
                    "--no-color",
                    "--",
                    ".",
                    ":(exclude)**/.env",
                    ":(exclude)**/.env.*",
                    ":(exclude)**/*.pem",
                    ":(exclude)**/*.key",
                    ":(exclude)**/*.p12",
                    ":(exclude)**/*.pfx",
                ]
            ), project_root
        if profile == "git_log":
            return self._git(["log", "-n", "50", "--oneline", "--decorate"]), project_root
        if profile == "backend_pytest":
            backend = project_root / "backend"
            if not backend.is_dir():
                raise PolicyError("TARGET_NOT_FOUND", "backend directory is not present")
            executable = self.profile_registry._project_python(project_root, backend)
            return [executable, "-m", "pytest", "-q"], backend
        if profile == "frontend_test":
            frontend = project_root / "frontend"
            if not frontend.is_dir():
                raise PolicyError("TARGET_NOT_FOUND", "frontend directory is not present")
            return [self._which_or_fail("npm"), "test", "--", "--run"], frontend
        if profile == "frontend_build":
            frontend = project_root / "frontend"
            if not frontend.is_dir():
                raise PolicyError("TARGET_NOT_FOUND", "frontend directory is not present")
            return [self._which_or_fail("npm"), "run", "build"], frontend
        raise PolicyError("PROFILE_NOT_ALLOWED", f"unknown fixed profile: {profile}")

    @staticmethod
    def _git(args: list[str]) -> list[str]:
        git = FixedRunner._trusted_executable("git")
        return [git, "-c", "core.fsmonitor=false", "--no-pager", "--no-optional-locks", *args]

    @staticmethod
    def _which_or_fail(executable: str) -> str:
        return FixedRunner._trusted_executable(executable)

    @staticmethod
    def _trusted_executable(executable: str) -> str:
        if Path(executable).name != executable or not executable:
            raise PolicyError("PROFILE_NOT_ALLOWED", f"invalid executable name: {executable}")
        for directory in TRUSTED_BIN_DIRS:
            candidate = directory / executable
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        raise PolicyError("PROFILE_NOT_ALLOWED", f"required executable is unavailable: {executable}")
