# Browser Automation V1

Local MCP Control Center exposes browser automation only through the existing
MCP path:

```text
ChatGPT -> secure tunnel -> local MCP bridge -> ToolRegistry -> schema validation
-> PolicyEngine/Broker -> BrowserManager -> Playwright -> owned Chromium context
```

There is no separate browser MCP server, shell bridge, arbitrary selector,
JavaScript evaluator, or caller-controlled browser process.

## Installation

Install the Python dependency in the Control Center environment and install
the owned Chromium browser once:

```text
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m playwright install chromium
```

The default persistent profile root on macOS is the application's private
data directory:

```text
~/Library/Application Support/LocalMCPControlCenter/browser/
```

Profile directories are created with mode `0700`. Authentication remains in
Chromium's local profile and is never returned through MCP or audit metadata.

## Motion ERP profile

V1 contains one exact profile:

```text
profile: motion-erp
allowed origin: https://dynamics-motion.asia.motionerpcloud.com
```

Direct navigation, redirects, popups, and frame requests outside this origin
are blocked with `DOMAIN_NOT_ALLOWED`. Wildcard internet browsing is not
enabled.

The first login is manual in the owned Chromium window. `browser_open` reports
`authenticated: true` only when the Motion/Odoo application marker is present;
otherwise it returns `false` for a visible login state or `null` when the state
cannot be confirmed.

## Public tools

All four tools are opt-in in Tools policy and route through `Broker.invoke`:

- `browser_open(profile)` opens or reuses the persistent `motion-erp` context.
- `browser_snapshot(browser_session_id)` returns bounded structured DOM and ARIA-derived role/name lines plus bounded table rows. It omits hidden inputs and password fields.
- `browser_run_command(...)` accepts only `navigate`, `click`, `fill`, `select`, `press`, `wait`, `read_text`, `read_table`, and `submit`. Targets are current snapshot refs such as `e42`; CSS, XPath, JavaScript, shell, raw Playwright expressions, and arbitrary endpoint fetches are not accepted.
- `browser_close(browser_session_id)` closes only a session owned by Control Center.

Mutation actions invalidate snapshot refs. Call `browser_snapshot` again after
navigation or click/fill/select/press/submit before using another target. A ref
from an older page state returns `STALE_BROWSER_REF`.

V1 blocks destructive-looking browser targets (`delete`, `remove`, `destroy`,
`archive`, `discard`, `void`) and never provides a browser delete capability.

## Safe Motion ERP verification

Use the Calendar and Timesheet URLs from the task only after opening the
profile and confirming the snapshot. Read-only verification can inspect the
Calendar, existing Timesheet rows, and the edit form. Do not create or modify
production Timesheet data without an explicitly selected safe test record and
the user's approval for that external side effect.

Every operation records actor, tool, profile/session digest, action, origin,
target ref summary, request/trace IDs, decision, and timing in the existing
redacted hash-chain audit. Passwords, cookies, authorization/session/CSRF
tokens, local storage, full HTML, and secret-bearing URL parameters are not
logged.

After enabling browser tools in the GUI, restart the MCP bridge or tunnel-managed
bridge. The GUI Runtime/Browser status distinguishes registry policy from the
live `tools/list` snapshot; a stale bridge requires restart.
