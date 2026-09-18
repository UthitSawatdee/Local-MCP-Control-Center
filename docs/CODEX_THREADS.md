# Codex Thread Reader — Local MCP

Implemented: 2026-09-16. This is an optional stored-history adapter, not an agent execution backend.

## Status and scope

The repository now includes a Codex App Server stdio adapter, broker handlers, MCP tools, a local GUI configuration dialog, CLI commands and automated tests. Enabling the adapter in the user's real Control Center configuration and reading the real target thread still require a local setup/smoke test. Automated tests use temporary databases, synthetic transcripts and fixture subprocesses; they do not read the user's actual Codex history.

The adapter is separate from the existing provider-backed AgentRuntime. Reading history does not create an agent task or require changing its model profiles.

## One-time activation — GUI

1. Close and reopen the Local MCP Control Center GUI so that it loads the updated Python source. Preserve the existing application data directory and tunnel configuration.
2. Open **Tools → Configure Codex**. Select the installed Codex executable and the **CODEX_HOME used by the Codex instance containing the thread**. The dialog proposes the existing setting, local CODEX_HOME environment value or `~/.codex`; confirm that it is the correct directory. An executable found through the local PATH is only a suggestion until Save is pressed. For a different installed runtime, use Browse; do not select an unrelated executable.
3. Select **Allow MCP to read my local Codex thread history**, then Save. This is a history-wide local grant, not authorization for only one thread. It enables the list/read tools. No generic filesystem scope for CODEX_HOME is created.
4. Open **Runtime → Restart bridge** and refresh the connector's tool list in the client. The GUI and bridge are separate running Python processes; updating source does not reload either automatically. An already-open conversation may retain old tool schemas until its connector tools are refreshed.
5. Run `codex_status(probe=true)`, then read one small page of the target thread. A successful initialization probe proves connection to the chosen runtime, not that a particular thread exists or that every paginated API is supported.

To revoke access, clear the checkbox and Save. New reads are denied immediately by the configuration check; an in-flight read rechecks the configuration before returning content. Restart/refresh the bridge to remove disabled tools from the advertised tool list as well.

## Optional local CLI

Run these commands from this repository with its virtual environment. They are local-user commands, not MCP actions. Use the same `--data-dir` as the GUI when a custom data directory is configured.

```sh
# Only use this discovery route when the intended Codex CLI is on PATH.
CODEX_BIN="$(command -v codex)"
[ -n "$CODEX_BIN" ] || { echo "Select the installed Codex executable in the GUI."; exit 1; }
.venv/bin/local-mcp configure-codex \
  --executable "$CODEX_BIN" \
  --codex-home "${CODEX_HOME:-$HOME/.codex}"

.venv/bin/local-mcp codex-status --probe
.venv/bin/local-mcp read-codex-thread \
  'codex://threads/01a0a5ab-3817-7f92-9a01-a65bf69edecb' --limit 1

# Revoke the local grant.
.venv/bin/local-mcp configure-codex --disable
```

Do not copy the whole block to activate and test unless also intending to revoke access at the final command.

## MCP tools

| Tool | Purpose | Defaults |
| --- | --- | --- |
| `codex_status` | Safe configuration status; `probe=true` performs initialization only | Advertised by default; no history returned |
| `codex_list_threads` | One page of stored thread metadata; `query` searches titles, not message bodies | Disabled until local opt-in; limit 20, maximum 50 |
| `codex_read_thread` | One page of visible user/assistant history and selected tool metadata, addressed by UUID or exact deep link | Disabled until local opt-in; limit 3 turns, maximum 20; oldest first |

Example first read:

```json
{
  "thread_id": "codex://threads/01a0a5ab-3817-7f92-9a01-a65bf69edecb",
  "limit": 3,
  "sort_direction": "asc",
  "include_tool_results": false
}
```

Pass the returned `next_cursor` unchanged as `cursor` with the same thread/direction for subsequent pages. A non-null cursor means more stored history remains. Never describe a partial page as the complete chat. Use `sort_direction="desc"` for the newest stored turns first.

`include_tool_results=true` additionally returns redacted command text and bounded command output where available. It does not expose arbitrary MCP tool argument/result dictionaries, file diffs or every possible tool payload. A command output is capped at 8,000 characters and reports `output_truncated` when applicable. Non-text user content is counted, not returned as image bytes or local files.

For a handoff, summarize the retrieved visible messages into goals, latest decisions, completed work, claimed versus verified results, unresolved issues and next actions. Repository state mentioned in old messages is historical evidence, not a fresh Git or database verification.

## Protocol and safety boundaries

Each request owns a short-lived child process running the fixed command `codex app-server --listen stdio://`. The adapter communicates through newline-delimited JSON-RPC. It permits only `initialize`, the `initialized` notification, `thread/list`, `thread/read` and `thread/turns/list`. Reading metadata uses `includeTurns=false`; reading turns uses `itemsView="full"` followed by an explicit visible-content projection. Listing uses `useStateDbOnly=true` to avoid requesting scan-and-repair of JSONL metadata.

There are no MCP parameters for executable, filesystem path, environment, provider URL, arbitrary RPC or shell. Configuration is available only through the local GUI/CLI. No `turn/start`, resume, fork, archive, deletion or configuration/account read RPC is used. Unexpected server requests for actions cause the reader to fail closed. Shutdown targets only the reader's owned subprocess, not the user's Codex application.

Read-only describes the exposed operations: the selected Codex executable remains a trusted local program and may perform its own startup, logging or storage maintenance. This is not an operating-system sandbox or a guarantee that Codex writes zero filesystem bytes. The adapter does not itself parse auth files or export them. Codex can still internally load its own configuration/authentication. API-key and tunnel-secret environment variables are not forwarded; only HOME, CODEX_HOME, LANG and filtered absolute local PATH entries are passed.

Only allowlisted visible message fields and metadata reach MCP. Reasoning/internal/system items and unknown types are omitted. Recognized credential patterns are redacted before truncation, but no pattern-based filter can guarantee detection of every secret pasted into an ordinary conversation. Audit events record counts, IDs and status, not transcript bodies. Read results are not persisted to a transcript cache by this adapter.

Concurrency is limited to two readers per broker, wire input to 4 MiB per request, response content to at most 60,000 UTF-8 bytes (or the lower tool-policy allowance), and request time to at most 20 seconds plus bounded process cleanup. Oversized visible pages fail explicitly instead of silently skipping messages. Decrease the turn limit or omit command results. A single extremely large turn can still exceed the limit; item-level continuation is not implemented in this version.

## Limitations and diagnostics

- Only stored history available to the selected local Codex runtime is read. Cloud-only, another device's, another CODEX_HOME's, unsaved or ephemeral history is not automatically fetched.
- Paginated history APIs are experimental. A selected older/incompatible runtime can initialize successfully but reject `thread/turns/list`. The adapter returns `CODEX_METHOD_UNSUPPORTED`; it does not attempt resume or an unbounded history fallback.
- `CODEX_NOT_CONFIGURED`: use the local configuration dialog; enabling the tool policy alone does not grant history access.
- `CODEX_THREAD_NOT_FOUND`: check the selected local runtime/home and exact thread ID. Do not infer that the original conversation never existed.
- `CODEX_OUTPUT_TOO_LARGE`: request fewer turns, omit command results, or note the single-turn size limitation.
- `CODEX_TIMEOUT` / `CODEX_DISCONNECTED`: verify the selected executable can start its App Server under the Control Center's local environment.
- `CODEX_CONFIG_CHANGED`: reselect paths locally after moving or replacing the selected installation/home.

## Verification and implementation map

Run the project's `backend_pytest` profile, or run `.venv/bin/python -m pytest -q` locally. Tests cover default denial, UUID/deep-link validation, forbidden controls, Unicode, redaction, hidden-item filtering, cursor forwarding, malformed/oversized pages, concurrent access, revocation, CLI registration, audit privacy and real stdio fixture subprocess cleanup/timeouts.

Core files: `codex_threads.py` (protocol and projection), `codex_thread_integration.py` (broker/MCP adapter), `codex_thread_gui.py` (local configuration), plus integration changes in `registry.py`, `storage.py`, `broker.py`, `mcp_server.py`, `gui_ux.py` and `cli.py`. Tests are `tests/test_codex_threads.py` and `tests/test_codex_thread_hardening.py`.

Protocol reference reviewed on 2026-09-16: OpenAI Codex App Server documentation, `https://developers.openai.com/codex/app-server/`, especially initialization, read stored thread, list thread turns and list-thread filters. Compatibility with the actual installed runtime must be established by the live smoke test, not inferred from fixture tests.
