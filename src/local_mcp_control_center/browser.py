"""Policy-controlled Playwright browser runtime.

This module owns Playwright and Chromium.  Callers can select only a named
profile and a snapshot reference; they cannot provide a browser executable,
process ID, selector, JavaScript, shell command, or browser context state.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .errors import PolicyError
from .filesystem import redact_text


MAX_BROWSER_SESSIONS = 4
MAX_PAGES_PER_SESSION = 4
MAX_SNAPSHOT_BYTES = 65_536
MAX_TABLE_ROWS = 100
MAX_TABLE_COLUMNS = 50
MAX_FIELD_BYTES = 65_536
MAX_OPERATION_TIMEOUT_MS = 60_000
DEFAULT_IDLE_TIMEOUT_SECONDS = 30 * 60
DEFAULT_OPERATION_TIMEOUT_MS = 30_000
_REF_RE = re.compile(r"^e[1-9][0-9]{0,5}$")
_SENSITIVE_URL_PARTS = {
    "access_token",
    "apikey",
    "auth",
    "authorization",
    "code",
    "csrf",
    "key",
    "password",
    "secret",
    "session",
    "token",
}
_DESTRUCTIVE_WORDS = re.compile(r"(?i)\b(delete|remove|destroy|archive|discard|void)\b")


@dataclass(frozen=True, slots=True)
class BrowserProfilePolicy:
    name: str
    allowed_origins: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.name or not self.allowed_origins:
            raise ValueError("browser profile needs a name and allowed origin")
        normalized = tuple(_normalize_origin(origin) for origin in self.allowed_origins)
        if any(origin is None for origin in normalized):
            raise ValueError("browser profile origins must be absolute http(s) origins")
        object.__setattr__(self, "allowed_origins", normalized)


@dataclass(slots=True)
class BrowserSession:
    session_id: str
    profile: BrowserProfilePolicy
    context: Any
    page: Any
    created_at: float
    last_activity: float
    current_url: str = "about:blank"
    current_origin: str | None = None
    snapshot_token: str | None = None
    refs: dict[str, str] = field(default_factory=dict)
    domain_violation: bool = False


def _normalize_origin(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname.lower().rstrip(".")
    default_port = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    suffix = "" if default_port else f":{port}"
    return f"{parsed.scheme.lower()}://{host}{suffix}"


def _origin_for_url(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    return _normalize_origin(urlunsplit((parsed.scheme, parsed.netloc, "", "", "")))


BROWSER_PROFILES: Mapping[str, BrowserProfilePolicy] = {
    "motion-erp": BrowserProfilePolicy(
        name="motion-erp",
        allowed_origins=("https://dynamics-motion.asia.motionerpcloud.com",),
    ),
}


def safe_url(value: str) -> str:
    """Return URL useful for diagnostics without secret-bearing parameters."""
    if not isinstance(value, str) or not value:
        return ""
    if value == "about:blank":
        return value
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        return parsed.scheme + "://" if parsed.scheme else "about:blank"
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key.lower().replace("-", "_") in _SENSITIVE_URL_PARTS for key, _ in query_items):
        query = ""
    else:
        query = urlencode(query_items[:30])[:1_000]
    fragment = parsed.fragment
    if any(part in fragment.lower().replace("-", "_") for part in _SENSITIVE_URL_PARTS):
        fragment = ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path[:2_000], query, fragment[:1_000]))


def _truncate_utf8(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, False
    suffix = "\n[TRUNCATED]"
    if max_bytes <= len(suffix.encode("utf-8")):
        return encoded[:max_bytes].decode("utf-8", errors="ignore"), True
    budget = max(0, max_bytes - len(suffix.encode("utf-8")))
    return encoded[:budget].decode("utf-8", errors="ignore") + suffix, True


class BrowserManager:
    """Own persistent Playwright contexts and enforce profile boundaries."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        profiles: Mapping[str, BrowserProfilePolicy] | None = None,
        headless: bool = False,
        idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
        operation_timeout_ms: int = DEFAULT_OPERATION_TIMEOUT_MS,
        clock: Callable[[], float] | None = None,
    ):
        self.data_dir = Path(data_dir).expanduser().absolute()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.data_dir, 0o700)
        self.profiles = dict(profiles or BROWSER_PROFILES)
        self.headless = bool(headless)
        self.idle_timeout_seconds = max(1.0, float(idle_timeout_seconds))
        self.operation_timeout_ms = max(1, min(int(operation_timeout_ms), MAX_OPERATION_TIMEOUT_MS))
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        self._sessions: dict[str, BrowserSession] = {}
        self._playwright: Any = None

    def open(self, profile_name: str) -> dict[str, Any]:
        with self._lock:
            self.cleanup_idle()
            profile = self._profile(profile_name)
            for session in self._sessions.values():
                if session.profile.name == profile.name:
                    self._touch(session)
                    self._assert_pages_allowed(session)
                    return self._session_result(session)
            if len(self._sessions) >= MAX_BROWSER_SESSIONS:
                raise PolicyError("BROWSER_SESSION_LIMIT", "maximum browser session count reached")
            profile_dir = self.data_dir / profile.name
            if profile_dir.is_symlink():
                raise PolicyError("BROWSER_PROFILE_INVALID", "browser profile directory cannot be a symlink")
            profile_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(profile_dir, 0o700)
            try:
                playwright = self._ensure_playwright()
                context = playwright.chromium.launch_persistent_context(
                    user_data_dir=str(profile_dir),
                    headless=self.headless,
                    timeout=self.operation_timeout_ms,
                )
            except PolicyError:
                raise
            except Exception as exc:
                self._stop_playwright_if_unused()
                code = "BROWSER_PROFILE_IN_USE" if "already" in str(exc).lower() and "use" in str(exc).lower() else "BROWSER_LAUNCH_FAILED"
                raise PolicyError(code, "unable to start the owned Chromium profile") from exc
            session = BrowserSession(
                session_id="br_" + secrets.token_urlsafe(12),
                profile=profile,
                context=context,
                page=None,
                created_at=self._clock(),
                last_activity=self._clock(),
            )
            try:
                context.route("**/*", lambda route: self._route_request(route, session))
                context.on("page", lambda page: self._on_new_page(session, page))
                context.on("response", lambda response: self._on_response(session, response))
                pages = list(context.pages)
                session.page = pages[0] if pages else context.new_page()
                for page in pages or [session.page]:
                    self._configure_page(session, page)
                self._trim_pages(session)
                self._sessions[session.session_id] = session
                self._assert_pages_allowed(session)
                return self._session_result(session)
            except PolicyError:
                try:
                    context.close()
                finally:
                    self._stop_playwright_if_unused()
                raise
            except Exception as exc:
                try:
                    context.close()
                finally:
                    self._stop_playwright_if_unused()
                raise PolicyError("BROWSER_LAUNCH_FAILED", "unable to configure owned Chromium profile") from exc

    def snapshot(self, session_id: str, *, max_bytes: int = MAX_SNAPSHOT_BYTES) -> dict[str, Any]:
        with self._lock:
            session = self._session(session_id)
            page = self._page(session)
            self._touch(session)
            token = "s" + secrets.token_urlsafe(10)
            try:
                descriptors = page.evaluate(_SNAPSHOT_SCRIPT, {"token": token, "max_items": 500})
                title = page.title()
                table_data: list[dict[str, Any]] = []
                for item in descriptors.get("tables", []):
                    ref = item.get("ref")
                    if isinstance(ref, str):
                        table = page.locator(f'[data-local-mcp-ref="{ref}"]')
                        table_data.append({"ref": ref, **self._extract_table(table)})
            except PolicyError:
                raise
            except Exception as exc:
                raise self._operation_error(session, exc) from exc
            session.snapshot_token = token
            session.refs = {
                str(item["ref"]): str(item.get("kind", "element"))
                for item in [*descriptors.get("elements", []), *descriptors.get("texts", []), *descriptors.get("tables", [])]
                if isinstance(item, dict) and _REF_RE.fullmatch(str(item.get("ref", "")))
            }
            lines = [f"page title: {redact_text(str(title))[:200]}"]
            for item in descriptors.get("elements", []):
                if not isinstance(item, dict):
                    continue
                ref = item.get("ref")
                role = redact_text(str(item.get("role") or "element"))[:60]
                name = redact_text(str(item.get("name") or ""))[:180]
                label = f' [ref={ref}] {role}'
                if name:
                    label += f' "{name}"'
                lines.append(label)
            for item in descriptors.get("texts", []):
                if not isinstance(item, dict):
                    continue
                text_value = redact_text(str(item.get("text") or ""))[:240]
                if text_value:
                    lines.append(f'[ref={item.get("ref")}] text "{text_value}"')
            for table in table_data:
                lines.append(f'[ref={table["ref"]}] table')
                columns = table.get("columns", [])
                if columns:
                    lines.append("  columns: " + " | ".join(f'"{redact_text(str(value))[:160]}"' for value in columns))
                for index, row in enumerate(table.get("rows", []), start=1):
                    values = " | ".join(redact_text(str(value))[:160] for value in row)
                    lines.append(f"  row {index}: {values}")
            rendered, truncated = _truncate_utf8("\n".join(lines), max(512, min(int(max_bytes), MAX_SNAPSHOT_BYTES)))
            return {
                "status": "ok",
                "browser_session_id": session.session_id,
                "current_url": safe_url(session.current_url),
                "origin": session.current_origin,
                "snapshot": rendered,
                "truncated": truncated,
                "element_count": len(session.refs),
                "table_count": len(table_data),
            }

    def execute(
        self,
        session_id: str,
        action: str,
        *,
        target: Mapping[str, Any] | None = None,
        url: str | None = None,
        value: str | None = None,
        key: str | None = None,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            session = self._session(session_id)
            page = self._page(session)
            timeout = self._timeout(timeout_ms)
            self._touch(session)
            try:
                if action == "navigate":
                    self._navigate(session, page, url, timeout)
                    result: dict[str, Any] = {"status": "ok"}
                elif action == "click":
                    locator = self._target_locator(session, page, target)
                    self._reject_destructive(locator)
                    locator.click(timeout=timeout)
                    self._settle(page, timeout)
                    result = {"status": "ok"}
                elif action == "fill":
                    locator = self._target_locator(session, page, target)
                    self._reject_sensitive_field(locator)
                    self._reject_destructive(locator)
                    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_FIELD_BYTES:
                        raise PolicyError("QUOTA_EXCEEDED", "field value exceeds browser input limit")
                    locator.fill(value, timeout=timeout)
                    result = {"status": "ok", "value_bytes": len(value.encode("utf-8"))}
                elif action == "select":
                    locator = self._target_locator(session, page, target)
                    self._reject_destructive(locator)
                    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_FIELD_BYTES:
                        raise PolicyError("QUOTA_EXCEEDED", "select value exceeds browser input limit")
                    self._select_value(page, locator, value, timeout)
                    result = {"status": "ok"}
                elif action == "press":
                    locator = self._target_locator(session, page, target)
                    self._reject_destructive(locator)
                    if not isinstance(key, str) or not key or len(key) > 64:
                        raise PolicyError("INVALID_INPUT", "press requires one bounded keyboard key")
                    locator.press(key, timeout=timeout)
                    self._settle(page, timeout)
                    result = {"status": "ok"}
                elif action == "wait":
                    timed_out = False
                    try:
                        page.wait_for_load_state("networkidle", timeout=timeout)
                    except Exception as exc:
                        if type(exc).__name__ == "TimeoutError":
                            timed_out = True
                        else:
                            raise
                    result = {"status": "ok", "timed_out": timed_out}
                elif action == "read_text":
                    locator = self._target_locator(session, page, target)
                    text = redact_text(locator.inner_text(timeout=timeout))
                    rendered, truncated = _truncate_utf8(text, MAX_SNAPSHOT_BYTES)
                    result = {"status": "ok", "text": rendered, "truncated": truncated}
                elif action == "read_table":
                    locator = self._target_locator(session, page, target)
                    result = {"status": "ok", **self._extract_table(locator)}
                elif action == "submit":
                    locator = self._target_locator(session, page, target)
                    self._reject_destructive(locator)
                    tag = str(locator.evaluate("element => element.tagName.toLowerCase()"))
                    if tag == "form":
                        locator.evaluate("element => element.requestSubmit()")
                    else:
                        locator.click(timeout=timeout)
                    self._settle(page, timeout)
                    result = {"status": "ok"}
                else:
                    raise PolicyError("INVALID_INPUT", f"unsupported browser action: {action}")
                self._assert_pages_allowed(session)
            except PolicyError:
                raise
            except Exception as exc:
                raise self._operation_error(session, exc) from exc
            if action in {"navigate", "click", "fill", "select", "press", "submit"}:
                self._invalidate_refs(session)
            session.current_url = page.url
            session.current_origin = _origin_for_url(page.url)
            result.update(
                {
                    "browser_session_id": session.session_id,
                    "current_url": safe_url(session.current_url),
                    "origin": session.current_origin,
                }
            )
            return result

    def close(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                raise PolicyError("BROWSER_SESSION_NOT_FOUND", "browser session does not exist")
            try:
                session.context.close()
            except Exception as exc:
                if not self._is_closed_error(exc):
                    raise PolicyError("BROWSER_CLOSE_FAILED", "owned browser session could not be closed") from exc
            finally:
                self._stop_playwright_if_unused()
            return {"status": "ok", "browser_session_id": session_id, "closed": True}

    def close_profile(self, profile_name: str) -> int:
        with self._lock:
            profile = self._profile(profile_name)
            session_ids = [sid for sid, item in self._sessions.items() if item.profile.name == profile.name]
            for session_id in session_ids:
                self.close(session_id)
            return len(session_ids)

    def cleanup_idle(self) -> int:
        with self._lock:
            now = self._clock()
            expired = [
                session_id
                for session_id, session in self._sessions.items()
                if now - session.last_activity >= self.idle_timeout_seconds
            ]
            for session_id in expired:
                try:
                    self.close(session_id)
                except PolicyError:
                    self._sessions.pop(session_id, None)
            return len(expired)

    def status(self) -> dict[str, Any]:
        with self._lock:
            self.cleanup_idle()
            sessions = [self._session_result(session) for session in self._sessions.values()]
            return {
                "status": "ok",
                "profiles": [
                    {
                        "profile": profile.name,
                        "allowed_origins": list(profile.allowed_origins),
                        "active_session_count": sum(item.profile.name == profile.name for item in self._sessions.values()),
                    }
                    for profile in self.profiles.values()
                ],
                "sessions": sessions,
                "max_sessions": MAX_BROWSER_SESSIONS,
                "idle_timeout_seconds": self.idle_timeout_seconds,
            }

    def close_all(self) -> None:
        with self._lock:
            for session_id in list(self._sessions):
                try:
                    self.close(session_id)
                except PolicyError:
                    self._sessions.pop(session_id, None)
            self._stop_playwright_if_unused()

    def _profile(self, profile_name: str) -> BrowserProfilePolicy:
        profile = self.profiles.get(profile_name)
        if profile is None:
            raise PolicyError("BROWSER_PROFILE_NOT_ALLOWED", f"browser profile is not allowed: {profile_name}")
        return profile

    def _session(self, session_id: str) -> BrowserSession:
        if not isinstance(session_id, str) or not session_id:
            raise PolicyError("INVALID_INPUT", "browser_session_id is required")
        session = self._sessions.get(session_id)
        if session is None:
            raise PolicyError("BROWSER_SESSION_NOT_FOUND", "browser session does not exist")
        return session

    def _ensure_playwright(self) -> Any:
        if self._playwright is not None:
            return self._playwright
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise PolicyError("BROWSER_DEPENDENCY_MISSING", "Playwright is not installed in the Control Center environment") from exc
        self._playwright = sync_playwright().start()
        return self._playwright

    def _stop_playwright_if_unused(self) -> None:
        if self._sessions or self._playwright is None:
            return
        try:
            self._playwright.stop()
        except Exception:
            pass
        self._playwright = None

    def _route_request(self, route: Any, session: BrowserSession) -> None:
        url = route.request.url
        if self._url_allowed(session.profile, url, allow_blank=True) or url.startswith(("data:", "blob:")):
            route.continue_()
            return
        # Static third-party assets are denied without poisoning the page. A
        # document/frame navigation outside the profile is a boundary escape
        # and is surfaced to the caller as DOMAIN_NOT_ALLOWED.
        if route.request.is_navigation_request():
            session.domain_violation = True
        route.abort()

    def _on_new_page(self, session: BrowserSession, page: Any) -> None:
        with self._lock:
            self._configure_page(session, page)
            session.page = page
            if not self._url_allowed(session.profile, page.url, allow_blank=True):
                session.domain_violation = True
                try:
                    page.close()
                except Exception:
                    pass

    def _on_response(self, session: BrowserSession, response: Any) -> None:
        with self._lock:
            status = response.status
            if not 300 <= status < 400:
                return
            location = response.headers.get("location")
            if isinstance(location, str) and not self._url_allowed(
                session.profile, urljoin(response.url, location)
            ):
                session.domain_violation = True

    def _configure_page(self, session: BrowserSession, page: Any) -> None:
        page.set_default_timeout(self.operation_timeout_ms)
        page.on("framenavigated", lambda frame: self._on_frame_navigated(session, frame))

    def _on_frame_navigated(self, session: BrowserSession, frame: Any) -> None:
        with self._lock:
            self._invalidate_refs(session)
            url = frame.url
            if not self._url_allowed(session.profile, url, allow_blank=True):
                session.domain_violation = True

    def _trim_pages(self, session: BrowserSession) -> None:
        pages = list(session.context.pages)
        for page in pages[:-MAX_PAGES_PER_SESSION]:
            if page is session.page:
                continue
            try:
                page.close()
            except Exception:
                pass
        if len([page for page in session.context.pages if not page.is_closed()]) > MAX_PAGES_PER_SESSION:
            raise PolicyError("BROWSER_PAGE_LIMIT", "maximum page count reached for browser session")

    def _assert_pages_allowed(self, session: BrowserSession) -> None:
        if session.domain_violation:
            session.domain_violation = False
            self._invalidate_refs(session)
            self._drop_session(session.session_id)
            raise PolicyError("DOMAIN_NOT_ALLOWED", "browser navigation or popup left the profile allowlist")
        for page in list(session.context.pages):
            if self._url_allowed(session.profile, page.url, allow_blank=True):
                continue
            try:
                page.close()
            except Exception:
                pass
            if page is session.page:
                self._drop_session(session.session_id)
            raise PolicyError("DOMAIN_NOT_ALLOWED", "browser navigation or popup left the profile allowlist")
        self._trim_pages(session)

    def _navigate(self, session: BrowserSession, page: Any, url: str | None, timeout: int) -> None:
        if not isinstance(url, str) or not url:
            raise PolicyError("INVALID_INPUT", "navigate requires url")
        if not self._url_allowed(session.profile, url):
            raise PolicyError("DOMAIN_NOT_ALLOWED", "navigation target is outside browser profile allowlist")
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        except Exception as exc:
            if session.domain_violation:
                session.domain_violation = False
                self._invalidate_refs(session)
                self._drop_session(session.session_id)
                raise PolicyError("DOMAIN_NOT_ALLOWED", "redirect left browser profile allowlist") from exc
            if not self._url_allowed(session.profile, page.url, allow_blank=True):
                raise PolicyError("DOMAIN_NOT_ALLOWED", "redirect left browser profile allowlist") from exc
            raise
        self._assert_pages_allowed(session)

    def _page(self, session: BrowserSession) -> Any:
        try:
            pages = [page for page in session.context.pages if not page.is_closed()]
        except Exception as exc:
            self._drop_session(session.session_id)
            raise PolicyError("BROWSER_CRASHED", "owned browser session is no longer available") from exc
        if not pages:
            self._drop_session(session.session_id)
            raise PolicyError("BROWSER_CRASHED", "owned browser session has no live page")
        if session.page is None or session.page.is_closed():
            session.page = pages[-1]
        return session.page

    def _target_locator(self, session: BrowserSession, page: Any, target: Mapping[str, Any] | None) -> Any:
        if not isinstance(target, Mapping) or set(target) != {"ref"} or not isinstance(target.get("ref"), str):
            raise PolicyError("INVALID_INPUT", "browser target must contain only one snapshot ref")
        ref = target["ref"]
        if not _REF_RE.fullmatch(ref) or ref not in session.refs or session.snapshot_token is None:
            raise PolicyError("STALE_BROWSER_REF", "snapshot ref is stale; call browser_snapshot again")
        locator = page.locator(f'[data-local-mcp-ref="{ref}"]')
        try:
            if (
                locator.count() != 1
                or locator.get_attribute("data-local-mcp-snapshot") != session.snapshot_token
                or not locator.is_visible()
            ):
                raise PolicyError("STALE_BROWSER_REF", "snapshot ref is no longer attached; call browser_snapshot again")
        except PolicyError:
            raise
        except Exception as exc:
            raise self._operation_error(session, exc) from exc
        return locator

    def _extract_table(self, locator: Any) -> dict[str, Any]:
        data = locator.evaluate(_TABLE_SCRIPT, {"max_rows": MAX_TABLE_ROWS, "max_columns": MAX_TABLE_COLUMNS})
        rows = data.get("rows", []) if isinstance(data, dict) else []
        rows = [[redact_text(str(value))[:500] for value in row[:MAX_TABLE_COLUMNS]] for row in rows if isinstance(row, list)]
        columns = [redact_text(str(value))[:500] for value in (data.get("columns", []) if isinstance(data, dict) else [])[:MAX_TABLE_COLUMNS]]
        result = {"columns": columns, "rows": rows, "truncated": bool(data.get("truncated")) if isinstance(data, dict) else False}
        while len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_SNAPSHOT_BYTES:
            if len(result["rows"]) > 1:
                result["rows"].pop()
                result["truncated"] = True
            elif len(result["columns"]) > 8:
                result["columns"] = result["columns"][:8]
                result["truncated"] = True
            else:
                result["columns"] = [str(value)[:200] for value in result["columns"]]
                result["rows"] = [[str(value)[:200] for value in row[:8]] for row in result["rows"]]
                result["truncated"] = True
                break
        return result

    def _reject_sensitive_field(self, locator: Any) -> None:
        field_type = str(locator.get_attribute("type") or "").lower()
        if field_type == "password":
            raise PolicyError("SENSITIVE_FIELD_BLOCKED", "password fields cannot be filled through browser MCP")

    def _select_value(self, page: Any, locator: Any, value: str, timeout: int) -> None:
        tag = str(locator.evaluate("element => element.tagName.toLowerCase()"))
        if tag == "select":
            try:
                locator.select_option(value=value, timeout=timeout)
            except Exception:
                locator.select_option(label=value, timeout=timeout)
            return
        role = str(locator.get_attribute("role") or "")
        if role != "combobox":
            raise PolicyError("BROWSER_SELECT_UNSUPPORTED", "select requires a native select or combobox target")
        locator.click(timeout=timeout)
        if tag in {"input", "textarea"} or str(locator.get_attribute("contenteditable") or "").lower() == "true":
            self._reject_sensitive_field(locator)
            locator.fill(value, timeout=timeout)
        options = page.get_by_role("option", name=value, exact=True)
        visible_options = page.locator('[role="option"]:visible')
        try:
            visible_options.first.wait_for(state="visible", timeout=timeout)
        except Exception as exc:
            if type(exc).__name__ == "TimeoutError":
                raise PolicyError("BROWSER_OPTION_NOT_FOUND", "combobox option is not available") from exc
            raise
        for index in range(options.count()):
            option = options.nth(index)
            if option.is_visible():
                option.click(timeout=timeout)
                return
        raise PolicyError("BROWSER_OPTION_NOT_FOUND", "combobox option is not available")

    def _reject_destructive(self, locator: Any) -> None:
        summary = " ".join(
            str(value or "")
            for value in (
                locator.get_attribute("aria-label"),
                locator.get_attribute("title"),
                locator.get_attribute("name"),
                locator.inner_text(timeout=500),
            )
        )
        if _DESTRUCTIVE_WORDS.search(summary):
            raise PolicyError("BROWSER_DESTRUCTIVE_BLOCKED", "destructive browser actions are blocked in V1")

    def _settle(self, page: Any, timeout: int) -> None:
        try:
            page.wait_for_load_state("domcontentloaded", timeout=min(timeout, 2_000))
        except Exception as exc:
            if type(exc).__name__ != "TimeoutError":
                raise

    def _timeout(self, value: int | None) -> int:
        if value is None:
            return self.operation_timeout_ms
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise PolicyError("INVALID_INPUT", "timeout_ms must be a positive integer")
        return min(value, self.operation_timeout_ms, MAX_OPERATION_TIMEOUT_MS)

    def _url_allowed(self, profile: BrowserProfilePolicy, url: str, *, allow_blank: bool = False) -> bool:
        if allow_blank and url in {"", "about:blank"}:
            return True
        origin = _origin_for_url(url)
        return origin in profile.allowed_origins

    def _touch(self, session: BrowserSession) -> None:
        session.last_activity = self._clock()
        try:
            session.current_url = session.page.url if session.page is not None else "about:blank"
            session.current_origin = _origin_for_url(session.current_url)
        except Exception:
            pass

    @staticmethod
    def _invalidate_refs(session: BrowserSession) -> None:
        session.snapshot_token = None
        session.refs.clear()

    def _session_result(self, session: BrowserSession, *, include_auth: bool = True) -> dict[str, Any]:
        self._touch(session)
        result = {
            "browser_session_id": session.session_id,
            "profile": session.profile.name,
            "current_url": safe_url(session.current_url),
            "origin": session.current_origin,
        }
        if include_auth:
            result["authenticated"] = self._authentication_state(session)
        return {"status": "ok", **result}

    def _authentication_state(self, session: BrowserSession) -> bool | None:
        try:
            page = self._page(session)
            if urlsplit(page.url).path.rstrip("/") == "/web/login":
                return False
            if page.locator('input[type="password"]').count() > 0:
                return False
            if session.profile.name == "motion-erp" and page.locator(".o_web_client").count() > 0:
                return True
        except Exception:
            return None
        return None

    def _operation_error(self, session: BrowserSession, exc: Exception) -> PolicyError:
        if self._is_closed_error(exc):
            self._drop_session(session.session_id)
            return PolicyError("BROWSER_CRASHED", "owned browser process is no longer available")
        return PolicyError("BROWSER_OPERATION_FAILED", "browser operation failed")

    @staticmethod
    def _is_closed_error(exc: Exception) -> bool:
        name = type(exc).__name__.lower()
        message = str(exc).lower()
        return any(value in name or value in message for value in ("targetclosed", "browserclosed", "browser disconnected", "closed"))

    def _drop_session(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is not None:
            try:
                session.context.close()
            except Exception:
                pass
        self._stop_playwright_if_unused()


_SNAPSHOT_SCRIPT = r"""
({token, max_items}) => {
  const interactive = 'button, a[href], input:not([type="hidden"]), textarea, select, [contenteditable="true"], [tabindex]:not([tabindex="-1"]), [role]:not([role="table"]):not([role="grid"]):not([role="row"]):not([role="cell"])';
  const visible = (el) => {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
  };
  const text = (el) => (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 180);
  const containsPasswordControl = (el) => Boolean(el.querySelector(
    'input[type="password"], input[name*="password" i], input[autocomplete="current-password"], input[autocomplete="new-password"]'
  ));
  const name = (el) => {
    const label = el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('placeholder');
    if (label) return label;
    if (el.labels && el.labels.length) return text(el.labels[0]);
    return text(el);
  };
  const role = (el) => {
    if (el.getAttribute('role')) return el.getAttribute('role');
    if (el.tagName === 'A') return 'link';
    if (el.tagName === 'BUTTON') return 'button';
    if (el.tagName === 'TEXTAREA') return 'textbox';
    if (el.tagName === 'SELECT') return 'combobox';
    if (el.tagName === 'INPUT') {
      const type = (el.getAttribute('type') || 'text').toLowerCase();
      if (type === 'checkbox') return 'checkbox';
      if (type === 'radio') return 'radio';
      return 'textbox';
    }
    return 'element';
  };
  for (const old of document.querySelectorAll('[data-local-mcp-ref]')) old.removeAttribute('data-local-mcp-ref');
  for (const old of document.querySelectorAll('[data-local-mcp-snapshot]')) old.removeAttribute('data-local-mcp-snapshot');
  const elements = [];
  const texts = [];
  let counter = 1;
  for (const el of document.querySelectorAll(interactive)) {
    if (!visible(el) || containsPasswordControl(el) || (el.tagName === 'INPUT' && (el.getAttribute('type') || '').toLowerCase() === 'password')) continue;
    const ref = `e${counter++}`;
    el.setAttribute('data-local-mcp-ref', ref);
    el.setAttribute('data-local-mcp-snapshot', token);
    elements.push({ref, kind: 'element', role: role(el), name: name(el)});
    if (elements.length >= max_items) break;
  }
  for (const el of document.querySelectorAll('h1, h2, h3, p, [role="alert"], [role="status"], li')) {
    if (!visible(el) || containsPasswordControl(el) || el.closest('button, a, label')) continue;
    const textValue = text(el);
    if (!textValue) continue;
    const ref = `e${counter++}`;
    el.setAttribute('data-local-mcp-ref', ref);
    el.setAttribute('data-local-mcp-snapshot', token);
    texts.push({ref, kind: 'text', text: textValue});
    if (elements.length + texts.length >= max_items) break;
  }
  const tables = [];
  for (const el of document.querySelectorAll('table, [role="table"], [role="grid"]')) {
    if (!visible(el) || el.getAttribute('data-local-mcp-ref')) continue;
    const ref = `e${counter++}`;
    el.setAttribute('data-local-mcp-ref', ref);
    el.setAttribute('data-local-mcp-snapshot', token);
    tables.push({ref, kind: 'table'});
    if (tables.length + elements.length >= max_items) break;
  }
  return {elements, texts, tables};
}
"""


_TABLE_SCRIPT = r"""
(element, {max_rows, max_columns}) => {
  const clean = (value) => (value || '').replace(/\s+/g, ' ').trim();
  let rows = Array.from(element.querySelectorAll('tr'));
  if (!rows.length) rows = Array.from(element.querySelectorAll('[role="row"]'));
  const values = rows.slice(0, max_rows + 1).map(row => {
    let cells = Array.from(row.querySelectorAll(':scope > th, :scope > td'));
    if (!cells.length) cells = Array.from(row.querySelectorAll('[role="columnheader"], [role="gridcell"], [role="cell"]'));
    return cells.slice(0, max_columns).map(cell => clean(cell.innerText || cell.textContent));
  });
  const header = values.length && rows[0].querySelector('th, [role="columnheader"]') ? values.shift() : [];
  return {columns: header || [], rows: values.slice(0, max_rows), truncated: values.length > max_rows};
}
"""
