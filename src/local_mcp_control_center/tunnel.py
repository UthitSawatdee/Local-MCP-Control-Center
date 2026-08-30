from __future__ import annotations

import hashlib
import ctypes
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence
from urllib.parse import urlparse
from urllib.request import urlopen

from .errors import TunnelError
from .filesystem import redact_text
from .models import utc_now
from .storage import Store


TUNNEL_ID_RE = re.compile(r"^tunnel_[0-9a-f]{32}$")
PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
KEYCHAIN_SERVICE = "com.local-mcp-control-center.tunnel"
MAX_CLIENT_OUTPUT = 2_000
METRIC_NUMBER_RE = r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"


class SecretStore(Protocol):
    """Small seam for a platform secret store."""

    def set(self, secret: str) -> None:
        ...

    def get(self) -> str | None:
        ...

    def has(self) -> bool:
        ...

    def delete(self) -> bool:
        ...


class MacOSKeychain:
    """Store the tunnel runtime key in the user's macOS login Keychain."""

    def __init__(self, service: str, account: str):
        self.service = service
        self.account = account

    @staticmethod
    def _frameworks() -> tuple[Any, Any]:
        if sys.platform != "darwin":
            raise TunnelError("KEYCHAIN_UNAVAILABLE", "macOS Keychain is available only on macOS")
        try:
            security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
            core_foundation = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        except OSError as exc:
            raise TunnelError("KEYCHAIN_UNAVAILABLE", "macOS Keychain framework was not available") from exc
        security.SecKeychainAddGenericPassword.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p,
            ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ]
        security.SecKeychainFindGenericPassword.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ]
        security.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        security.SecKeychainItemDelete.argtypes = [ctypes.c_void_p]
        core_foundation.CFRelease.argtypes = [ctypes.c_void_p]
        return security, core_foundation

    def _find_item(self, security: Any) -> tuple[int, Any]:
        service, account = self.service.encode("utf-8"), self.account.encode("utf-8")
        item = ctypes.c_void_p()
        status = security.SecKeychainFindGenericPassword(
            None, len(service), service, len(account), account, None, None, ctypes.byref(item)
        )
        return status, item

    def set(self, secret: str) -> None:
        if not secret:
            raise TunnelError("TUNNEL_API_KEY_MISSING", "runtime API key cannot be empty")
        security, core_foundation = self._frameworks()
        self.delete()
        service, account, secret_bytes = self.service.encode("utf-8"), self.account.encode("utf-8"), secret.encode("utf-8")
        secret_buffer = ctypes.create_string_buffer(secret_bytes)
        try:
            status = security.SecKeychainAddGenericPassword(
                None, len(service), service, len(account), account,
                len(secret_bytes), ctypes.cast(secret_buffer, ctypes.c_void_p), None,
            )
        finally:
            ctypes.memset(secret_buffer, 0, len(secret_buffer))
        if status != 0:
            raise TunnelError("KEYCHAIN_WRITE_FAILED", "macOS Keychain rejected the runtime API key")

    def get(self) -> str | None:
        if sys.platform != "darwin":
            raise TunnelError("KEYCHAIN_UNAVAILABLE", "macOS Keychain is available only on macOS")
        try:
            result = subprocess.run(
                ["/usr/bin/security", "find-generic-password", "-a", self.account, "-s", self.service, "-w"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TunnelError("KEYCHAIN_READ_FAILED", "macOS Keychain could not read the runtime API key") from exc
        if result.returncode == 44:  # errSecItemNotFound
            return None
        if result.returncode != 0:
            raise TunnelError("KEYCHAIN_READ_FAILED", "macOS Keychain could not read the runtime API key")
        value = result.stdout.strip()
        return value or None

    def has(self) -> bool:
        return self.get() is not None

    def delete(self) -> bool:
        if sys.platform != "darwin":
            raise TunnelError("KEYCHAIN_UNAVAILABLE", "macOS Keychain is available only on macOS")
        try:
            result = subprocess.run(
                ["/usr/bin/security", "delete-generic-password", "-a", self.account, "-s", self.service],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TunnelError("KEYCHAIN_DELETE_FAILED", "macOS Keychain could not remove the runtime API key") from exc
        if result.returncode == 44:  # errSecItemNotFound
            return False
        if result.returncode != 0:
            raise TunnelError("KEYCHAIN_DELETE_FAILED", "macOS Keychain could not remove the runtime API key")
        return True


@dataclass(frozen=True, slots=True)
class TunnelConfig:
    client_path: str
    profile: str
    tunnel_id: str
    updated_at: str

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "TunnelConfig":
        if not isinstance(value, dict):
            raise TunnelError("TUNNEL_CONFIG_INVALID", "tunnel configuration must be an object")
        client_path = value.get("client_path", "tunnel-client")
        profile = value.get("profile", "local-mcp-control-center")
        tunnel_id = value.get("tunnel_id", "")
        updated_at = value.get("updated_at", "")
        validate_tunnel_settings(client_path, profile, tunnel_id)
        return cls(
            client_path=client_path,
            profile=profile,
            tunnel_id=tunnel_id,
            updated_at=updated_at or utc_now(),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "client_path": self.client_path,
            "profile": self.profile,
            "tunnel_id": self.tunnel_id,
            "updated_at": self.updated_at,
        }


def validate_tunnel_settings(client_path: Any, profile: Any, tunnel_id: Any) -> None:
    if not isinstance(client_path, str) or not client_path.strip():
        raise TunnelError("TUNNEL_CONFIG_INVALID", "tunnel-client path is required")
    client_name = Path(client_path.strip()).name
    if client_name != "tunnel-client":
        raise TunnelError("TUNNEL_CONFIG_INVALID", "the executable must be the official tunnel-client binary")
    if not isinstance(profile, str) or not PROFILE_RE.fullmatch(profile):
        raise TunnelError(
            "TUNNEL_CONFIG_INVALID",
            "profile must be 1-64 characters using letters, numbers, dot, underscore, or hyphen",
        )
    if not isinstance(tunnel_id, str) or not TUNNEL_ID_RE.fullmatch(tunnel_id):
        raise TunnelError(
            "TUNNEL_CONFIG_INVALID",
            "tunnel ID must be tunnel_ followed by 32 lowercase hexadecimal characters",
        )


def keychain_account(data_dir: Path, profile: str) -> str:
    digest = hashlib.sha256(str(data_dir).encode("utf-8")).hexdigest()[:20]
    return f"{digest}:{profile}"


class TunnelClientAdapter:
    """Fixed, testable adapter around the official tunnel-client CLI."""

    def __init__(
        self,
        store: Store,
        *,
        secret_store_factory: Callable[[str], SecretStore] | None = None,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        popen: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
        which: Callable[[str], str | None] = shutil.which,
    ):
        self.store = store
        self.data_dir = store.data_dir
        self.profile_dir = self.data_dir / "tunnel-profiles"
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.profile_dir, 0o700)
        self.run = run
        self.popen = popen
        self.which = which
        self._secret_store_factory = secret_store_factory

    def get_config(self) -> TunnelConfig | None:
        raw = self.store.get_tunnel_config()
        return TunnelConfig.from_mapping(raw) if raw else None

    def public_status(self) -> dict[str, Any]:
        try:
            config = self.get_config()
        except TunnelError as exc:
            return {
                "configured": False,
                "state": "invalid_configuration",
                "client_path": None,
                "client_available": False,
                "profile": None,
                "tunnel_id": None,
                "api_key": "unknown",
                "profile_dir": str(self.profile_dir),
                "error_code": exc.code,
                "message": exc.message,
            }
        if not config:
            return {
                "configured": False,
                "state": "not_configured",
                "client_path": None,
                "client_available": False,
                "profile": None,
                "tunnel_id": None,
                "api_key": "missing",
                "profile_dir": str(self.profile_dir),
            }
        client = self.resolve_client(config.client_path, raise_error=False)
        secret_store = self._secret_store(config.profile)
        try:
            secret = secret_store.get()
            key_status = "keychain" if secret else "environment" if os.environ.get("CONTROL_PLANE_API_KEY") else "missing"
        except TunnelError:
            secret = None
            key_status = "environment" if os.environ.get("CONTROL_PLANE_API_KEY") else "unavailable"
        return {
            "configured": True,
            "state": "configured_stopped",
            "client_path": config.client_path,
            "client_available": client is not None,
            "profile": config.profile,
            "tunnel_id": config.tunnel_id,
            "api_key": key_status,
            "api_key_suffix": self._key_suffix(secret),
            "profile_dir": str(self.profile_dir),
        }

    def clear_stored_key(self) -> dict[str, Any]:
        config = self._require_config()
        removed = self._secret_store(config.profile).delete()
        return {
            "status": "ok",
            "removed": removed,
            "message": "Saved runtime API key was removed from macOS Keychain." if removed else "No saved runtime API key was found in macOS Keychain.",
        }

    def configure(self, *, client_path: str, profile: str, tunnel_id: str, api_key: str | None) -> dict[str, Any]:
        validate_tunnel_settings(client_path, profile, tunnel_id)
        config = TunnelConfig(client_path, profile, tunnel_id, utc_now())
        client = self.resolve_client(config.client_path)
        secret_store = self._secret_store(config.profile)
        if api_key is not None and api_key != "":
            secret_store.set(api_key)
        secret = self._runtime_key(secret_store)
        try:
            result = self.run(
                self._init_argv(client, config),
                cwd=str(self.data_dir),
                env=self._environment(config, secret),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TunnelError("TUNNEL_PROFILE_INIT_TIMEOUT", "tunnel-client profile initialization timed out") from exc
        except OSError as exc:
            raise TunnelError("TUNNEL_PROFILE_INIT_FAILED", "could not execute tunnel-client profile initialization") from exc
        if result.returncode != 0:
            raise TunnelError(
                "TUNNEL_PROFILE_INIT_FAILED",
                self._failure_message("tunnel-client profile initialization failed", result, secret),
            )
        self.store.set_tunnel_config(config.to_dict())
        return {
            "status": "ok",
            "state": "configured",
            "profile": config.profile,
            "tunnel_id": config.tunnel_id,
            "client_path": client,
            "profile_dir": str(self.profile_dir),
            "api_key_suffix": self._key_suffix(secret),
            "message": "Tunnel profile initialized and saved. You can now start the tunnel.",
        }

    def doctor(self) -> dict[str, Any]:
        config = self._require_config()
        client = self.resolve_client(config.client_path)
        secret = self._runtime_key(self._secret_store(config.profile))
        try:
            result = self.run(
                self._doctor_argv(client, config),
                cwd=str(self.data_dir),
                env=self._environment(config, secret),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TunnelError("TUNNEL_DOCTOR_TIMEOUT", "tunnel-client doctor timed out") from exc
        except OSError as exc:
            raise TunnelError("TUNNEL_DOCTOR_FAILED", "could not execute tunnel-client doctor") from exc
        output = self._combined_output(result, secret)
        if result.returncode != 0:
            raise TunnelError("TUNNEL_DOCTOR_FAILED", self._failure_message("tunnel-client doctor failed", result, secret))
        return {"status": "ok", "state": "ready", "profile": config.profile, "output": output}

    def launch(self, log_path: Path) -> tuple[subprocess.Popen[Any], Path]:
        config = self._require_config()
        client = self.resolve_client(config.client_path)
        secret = self._runtime_key(self._secret_store(config.profile))
        run_dir = self.data_dir / "run"
        run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(run_dir, 0o700)
        health_url_file = run_dir / f"tunnel-health-{config.profile}.url"
        health_url_file.unlink(missing_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(log_path.parent, 0o700)
        handle = log_path.open("ab")
        command = self._run_argv(client, config, health_url_file)
        try:
            process = self.popen(
                command,
                cwd=str(self.data_dir),
                env=self._environment(config, secret),
                stdin=subprocess.DEVNULL,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
        except FileNotFoundError as exc:
            handle.close()
            raise TunnelError("TUNNEL_CLIENT_NOT_FOUND", "tunnel-client executable was not found") from exc
        except OSError as exc:
            handle.close()
            raise TunnelError("TUNNEL_START_FAILED", "could not start tunnel-client") from exc
        handle.close()
        return process, health_url_file

    def health(self, health_url_file: Path | None = None) -> dict[str, Any]:
        config = self.get_config()
        if not config:
            return {"state": "not_configured", "healthy": False, "ready": False, "health_url": None}
        url_file = health_url_file or self.data_dir / "run" / f"tunnel-health-{config.profile}.url"
        try:
            health_url = url_file.read_text(encoding="utf-8").strip()
        except (FileNotFoundError, OSError):
            return {"state": "starting", "healthy": False, "ready": False, "health_url": None}
        if not self._is_loopback_http_url(health_url):
            return {"state": "invalid_health_url", "healthy": False, "ready": False, "health_url": None}
        health_ok = self._probe(health_url.rstrip("/") + "/healthz")
        ready_ok = self._probe(health_url.rstrip("/") + "/readyz")
        state = "ready" if ready_ok else "healthy" if health_ok else "unhealthy"
        return {"state": state, "healthy": health_ok, "ready": ready_ok, "health_url": health_url}

    def control_plane_status(
        self,
        log_path: str | Path | None,
        *,
        since: str | None = None,
        health_url: str | None = None,
    ) -> dict[str, str]:
        """Return a conservative, secret-free control-plane signal.

        The tunnel client's local health endpoint can be live/ready while its
        control-plane poller is unauthorized. Prefer current metrics when
        available, and use the log as a bounded fallback. ``since`` prevents a
        previous run's 401 from contaminating the current run's status.
        """
        metrics_status = self._control_plane_metrics_status(health_url)
        if metrics_status:
            return metrics_status
        if not log_path:
            return {"state": "unknown", "message": "No tunnel-client log is available yet."}
        try:
            with Path(log_path).open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                handle.seek(max(0, handle.tell() - 64_000), os.SEEK_SET)
                text = handle.read().decode("utf-8", errors="replace")
        except OSError:
            return {"state": "unknown", "message": "Tunnel-client log is not available yet."}
        for line in reversed(text.splitlines()):
            if since and not self._log_line_is_since(line, since):
                continue
            if "401 Unauthorized" in line or '"status_code":401' in line:
                return {
                    "state": "unauthorized",
                    "message": "OpenAI rejected the runtime API key (401 Unauthorized).",
                }
        return {
            "state": "unverified",
            "message": "Local health is available; OpenAI authentication has not been confirmed by this status check.",
        }

    def wait_for_control_plane(
        self,
        log_path: str | Path,
        *,
        since: str | None = None,
        health_url_file: Path | None = None,
        timeout: float = 3.0,
    ) -> dict[str, str]:
        """Wait briefly for the first control-plane result after a launch."""
        path = Path(log_path)
        if not path.exists():
            return {"state": "unknown", "message": "Tunnel-client log is not available yet."}
        deadline = time.monotonic() + max(0.0, timeout)
        status: dict[str, str] = {"state": "unverified", "message": ""}
        while True:
            health = self.health(health_url_file)
            status = self.control_plane_status(
                path,
                since=since,
                health_url=health.get("health_url"),
            )
            if status["state"] in {"authenticated", "unauthorized", "error"}:
                return status
            if time.monotonic() >= deadline:
                return status
            time.sleep(0.1)

    def _control_plane_metrics_status(self, health_url: str | None) -> dict[str, str] | None:
        if not health_url or not self._is_loopback_http_url(health_url):
            return None
        try:
            with urlopen(health_url.rstrip("/") + "/metrics", timeout=0.5) as response:
                metrics = response.read(256_000).decode("utf-8", errors="replace")
        except Exception:
            return None
        for line in metrics.splitlines():
            if 'http_response_status_code="401"' not in line:
                continue
            try:
                if float(line.rsplit(None, 1)[-1]) > 0:
                    return {
                        "state": "unauthorized",
                        "message": "OpenAI rejected the runtime API key (401 Unauthorized).",
                    }
            except (ValueError, IndexError):
                continue
        successful = re.search(
            rf"^commands_poll_last_successful_timestamp_seconds\{{[^}}]*\}}\s+({METRIC_NUMBER_RE})\s*$",
            metrics,
            re.MULTILINE,
        )
        if successful and float(successful.group(1)) > 0:
            return {
                "state": "authenticated",
                "message": "OpenAI control-plane authentication and polling are working.",
            }
        errors = re.search(
            rf"^commands_poll_errors_total\{{[^}}]*\}}\s+({METRIC_NUMBER_RE})\s*$",
            metrics,
            re.MULTILINE,
        )
        if errors and float(errors.group(1)) > 0:
            return {
                "state": "error",
                "message": "Tunnel-client is running but control-plane polling has not succeeded.",
            }
        return None

    @staticmethod
    def _key_suffix(secret: str | None) -> str | None:
        return f"…{secret[-4:]}" if secret else None

    @staticmethod
    def _log_line_is_since(line: str, since: str) -> bool:
        try:
            event = json.loads(line)
            event_time = event.get("time") if isinstance(event, dict) else None
            if not isinstance(event_time, str):
                return True
            return datetime.fromisoformat(event_time) >= datetime.fromisoformat(since)
        except (TypeError, ValueError, json.JSONDecodeError):
            return True

    def resolve_client(self, client_path: str, *, raise_error: bool = True) -> str | None:
        candidate = client_path.strip()
        if "/" in candidate:
            path = Path(candidate).expanduser().absolute()
            resolved = str(path) if path.is_file() and os.access(path, os.X_OK) else None
        else:
            resolved = self.which(candidate)
        if resolved:
            return resolved
        if raise_error:
            raise TunnelError(
                "TUNNEL_CLIENT_NOT_FOUND",
                "tunnel-client was not found. Install the official client with "
                "`brew tap openai/tools && brew install openai/tools/tunnel-client`, "
                "or choose its executable path in Configure tunnel.",
            )
        return None

    def _require_config(self) -> TunnelConfig:
        config = self.get_config()
        if not config:
            raise TunnelError("TUNNEL_NOT_CONFIGURED", "Configure a tunnel ID, runtime API key, and client before starting the tunnel.")
        return config

    def _secret_store(self, profile: str) -> SecretStore:
        if self._secret_store_factory:
            return self._secret_store_factory(profile)
        return MacOSKeychain(KEYCHAIN_SERVICE, keychain_account(self.data_dir, profile))

    @staticmethod
    def _runtime_key(secret_store: SecretStore) -> str:
        try:
            secret = secret_store.get()
        except TunnelError:
            secret = None
        if secret:
            return secret
        environment_secret = os.environ.get("CONTROL_PLANE_API_KEY")
        if environment_secret:
            return environment_secret
        raise TunnelError(
            "TUNNEL_API_KEY_MISSING",
            "No runtime API key found. Enter it in Configure tunnel; it is saved only in macOS Keychain.",
        )

    def _environment(self, config: TunnelConfig, secret: str) -> dict[str, str]:
        environment = os.environ.copy()
        environment["CONTROL_PLANE_API_KEY"] = secret
        environment["CONTROL_PLANE_TUNNEL_ID"] = config.tunnel_id
        package_root = Path(__file__).resolve().parents[1]
        current_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = os.pathsep.join(
            value for value in (str(package_root), current_pythonpath) if value
        )
        return environment

    def _init_argv(self, client: str, config: TunnelConfig) -> list[str]:
        return [
            client,
            "init",
            "--sample",
            "sample_mcp_stdio_local",
            "--profile-dir",
            str(self.profile_dir),
            "--profile",
            config.profile,
            "--force",
            "--tunnel-id",
            config.tunnel_id,
            "--mcp-command",
            shlex.join(self._mcp_argv()),
        ]

    def _doctor_argv(self, client: str, config: TunnelConfig) -> list[str]:
        return [
            client,
            "doctor",
            "--profile-dir",
            str(self.profile_dir),
            "--profile",
            config.profile,
            "--explain",
        ]

    def _run_argv(self, client: str, config: TunnelConfig, health_url_file: Path) -> list[str]:
        return [
            client,
            "run",
            "--profile-dir",
            str(self.profile_dir),
            "--profile",
            config.profile,
            "--health.listen-addr",
            "127.0.0.1:0",
            "--health.url-file",
            str(health_url_file),
        ]

    def _mcp_argv(self) -> list[str]:
        return [
            sys.executable,
            "-m",
            "local_mcp_control_center",
            "--data-dir",
            str(self.data_dir),
            "mcp",
        ]

    @staticmethod
    def _combined_output(result: subprocess.CompletedProcess[str], secret: str) -> str:
        return redact_text((result.stdout or "") + (result.stderr or "")).replace(secret, "<redacted>")[:MAX_CLIENT_OUTPUT]

    def _failure_message(self, prefix: str, result: subprocess.CompletedProcess[str], secret: str) -> str:
        output = self._combined_output(result, secret)
        return f"{prefix} (exit {result.returncode}). {output or 'See the tunnel-client log for details.'}"

    @staticmethod
    def _is_loopback_http_url(value: str) -> bool:
        try:
            parsed = urlparse(value)
            port = parsed.port
        except ValueError:
            return False
        return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"} and bool(port)

    @staticmethod
    def _probe(url: str) -> bool:
        try:
            with urlopen(url, timeout=0.5) as response:
                return 200 <= response.status < 300
        except Exception:
            return False


class MemorySecretStore:
    """Test adapter; never used by the production GUI."""

    def __init__(self, value: str | None = None):
        self.value = value

    def set(self, secret: str) -> None:
        self.value = secret

    def get(self) -> str | None:
        return self.value

    def has(self) -> bool:
        return bool(self.value)

    def delete(self) -> bool:
        had_value = bool(self.value)
        self.value = None
        return had_value
