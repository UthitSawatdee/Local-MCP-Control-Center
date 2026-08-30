"""Argument-array Git adapter for the controlled project lifecycle."""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .errors import PolicyError
from .filesystem import redact_text, validate_relative_path
from .runner import CommandResult, FixedRunner, TRUSTED_BIN_DIRS, display_argv


BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$")
REMOTE_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
ALLOWED_OPERATIONS = {
    "current_branch": "branch",
    "create_branch": "switch",
    "stage": "add",
    "stage_for_commit": "add",
    "commit": "commit",
    "restore": "restore",
    "push": "push",
}


class GitAdapter:
    """Run a small allowlisted Git vocabulary without shell parsing."""

    def __init__(self, runner: FixedRunner):
        self.runner = runner

    def run(
        self,
        operation: str,
        project_root: Path,
        args: list[str],
        *,
        output_limit: int = 65_536,
        timeout_seconds: int = 300,
    ) -> CommandResult:
        if not project_root.is_dir():
            raise PolicyError("TARGET_NOT_FOUND", "project root is not a directory")
        if any(not isinstance(item, str) or not item for item in args):
            raise PolicyError("INVALID_INPUT", "Git arguments must be non-empty strings")
        expected_command = ALLOWED_OPERATIONS.get(operation)
        if expected_command is None or not args or args[0] != expected_command:
            raise PolicyError("GIT_OPERATION_NOT_ALLOWED", "Git operation is not in the controlled vocabulary")
        forbidden = {"clean", "reset", "checkout", "rebase", "-f", "--force", "--force-with-lease"}
        if any(item in forbidden or item.startswith("--force") for item in args):
            raise PolicyError("GIT_OPERATION_NOT_ALLOWED", "destructive or force Git arguments are unavailable")
        if operation == "push" and len(args) != 3:
            raise PolicyError("INVALID_INPUT", "controlled push requires exactly remote and branch")
        self._validate_operation_args(operation, args)
        argv = FixedRunner._git(args)
        output_limit = max(1, min(int(output_limit), 1_048_576))
        timeout_seconds = max(1, min(int(timeout_seconds), 3_600))
        environment = {
            "PATH": os.pathsep.join(str(path) for path in TRUSTED_BIN_DIRS),
            "HOME": str(self.runner.runtime_home),
            "TMPDIR": str(self.runner.runtime_tmp),
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
                cwd=str(project_root),
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
            return CommandResult(
                f"git_{operation}",
                display_argv(argv),
                completed.returncode,
                redact_text(stdout_raw[:output_limit].decode("utf-8", errors="replace")),
                redact_text(stderr_raw[:output_limit].decode("utf-8", errors="replace")),
                False,
                len(stdout_raw) > output_limit,
                len(stderr_raw) > output_limit,
                int((time.monotonic() - started) * 1000),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            if isinstance(stdout, bytes):
                stdout = stdout[:output_limit].decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr[:output_limit].decode("utf-8", errors="replace")
            return CommandResult(
                f"git_{operation}",
                display_argv(argv),
                -1,
                redact_text(str(stdout)),
                redact_text(str(stderr)),
                True,
                False,
                False,
                int((time.monotonic() - started) * 1000),
            )
        except OSError as exc:
            raise PolicyError("GIT_UNAVAILABLE", "unable to start the fixed Git adapter") from exc

    @staticmethod
    def validate_branch(branch: str) -> str:
        if not isinstance(branch, str) or not BRANCH_RE.fullmatch(branch):
            raise PolicyError("INVALID_INPUT", "branch must be a safe local Git branch name")
        if branch.endswith("/") or branch.endswith(".") or ".." in branch or "@{" in branch:
            raise PolicyError("INVALID_INPUT", "branch name contains unsafe Git syntax")
        if branch.startswith("-") or branch.startswith("/") or "/." in branch:
            raise PolicyError("INVALID_INPUT", "branch name contains unsafe Git syntax")
        return branch

    @staticmethod
    def validate_remote(remote: str) -> str:
        if not isinstance(remote, str) or not REMOTE_RE.fullmatch(remote):
            raise PolicyError("INVALID_INPUT", "remote must be a simple configured Git remote name")
        return remote

    @staticmethod
    def validate_paths(paths: Any) -> list[str]:
        if not isinstance(paths, list) or not paths or len(paths) > 100:
            raise PolicyError("INVALID_INPUT", "paths must be a non-empty list of at most 100 items")
        if any(not isinstance(path, str) or not path for path in paths):
            raise PolicyError("INVALID_INPUT", "Git paths must be non-empty text")
        if len(set(paths)) != len(paths):
            raise PolicyError("INVALID_INPUT", "Git paths must not contain duplicates")
        return paths

    @staticmethod
    def commit_message(message: str) -> str:
        if not isinstance(message, str) or not message.strip() or len(message) > 200:
            raise PolicyError("INVALID_INPUT", "commit message must contain 1-200 characters")
        return message.strip()

    @classmethod
    def _validate_operation_args(cls, operation: str, args: list[str]) -> None:
        if operation == "current_branch":
            if args != ["branch", "--show-current"]:
                raise PolicyError("GIT_OPERATION_NOT_ALLOWED", "current branch arguments are fixed")
            return
        if operation == "create_branch":
            if len(args) != 3 or args[1] != "-c":
                raise PolicyError("GIT_OPERATION_NOT_ALLOWED", "branch creation arguments are fixed")
            cls.validate_branch(args[2])
            return
        if operation in {"stage", "stage_for_commit"}:
            if len(args) < 3 or args[1] != "--":
                raise PolicyError("GIT_OPERATION_NOT_ALLOWED", "staging arguments are fixed")
            cls.validate_paths(args[2:])
            for path in args[2:]:
                if not validate_relative_path(path):
                    raise PolicyError("INVALID_INPUT", "Git paths must identify a file")
            return
        if operation == "commit":
            if len(args) < 6 or args[1:3] != ["--only", "-m"] or "--" not in args[4:]:
                raise PolicyError("GIT_OPERATION_NOT_ALLOWED", "commit arguments are fixed")
            separator = args.index("--", 4)
            cls.commit_message(args[3])
            cls.validate_paths(args[separator + 1:])
            return
        if operation == "restore":
            if len(args) != 3 or args[1] != "--" or not validate_relative_path(args[2]):
                raise PolicyError("GIT_OPERATION_NOT_ALLOWED", "restore arguments are fixed")
            return
        if operation == "push":
            cls.validate_remote(args[1])
            cls.validate_branch(args[2])

    @staticmethod
    def current_branch(result: CommandResult) -> str | None:
        if result.exit_code != 0:
            return None
        value = result.stdout.strip()
        return value or None
