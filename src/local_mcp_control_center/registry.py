from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .browser import LOCAL_BROWSER_PROFILE_NAME
from .models import ApprovalMode, PermissionClass


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    group: str
    description: str
    risk: str
    default_enabled: bool
    default_approval: str
    permission_class: str | None = None
    read_only: bool | None = None
    destructive: bool = False
    parallel_safe: bool | None = None
    category: str | None = None
    live_execution_supported: bool = True
    live_block_reason: str | None = None
    live_approval_required: bool | None = None
    live_approval_available: bool = True

    def __post_init__(self) -> None:
        permission = self.permission_class
        if permission is None:
            if self.name in {
                "write_file", "create_file", "create_directory", "rename_file",
                "move_file", "bulk_move_files", "csv_transform", "xlsx_edit", "docx_edit",
                "apply_patch",
            }:
                permission = PermissionClass.WRITE
            elif self.name in {
                "run_backend_test", "run_frontend_test", "run_targeted_test", "run_lint",
                "run_typecheck", "run_build", "process_start_profile", "process_stop",
                "git_create_branch", "git_stage_paths", "git_commit",
            }:
                permission = PermissionClass.EXECUTE
            elif self.name in {"delete_file", "git_restore_file", "git_push", "apply_approved_action"}:
                permission = PermissionClass.DANGEROUS
            else:
                permission = PermissionClass.READ
            object.__setattr__(self, "permission_class", str(permission))
        if self.read_only is None:
            object.__setattr__(self, "read_only", permission == PermissionClass.READ)
        if not self.destructive and self.name in {"delete_file", "git_restore_file", "git_push", "apply_approved_action"}:
            object.__setattr__(self, "destructive", True)
        if self.parallel_safe is None:
            object.__setattr__(self, "parallel_safe", bool(self.read_only) and not self.destructive)
        if self.category is None:
            object.__setattr__(self, "category", self.group)

    @property
    def schema(self) -> dict[str, Any]:
        return TOOL_SCHEMAS.get(self.name, {})

    def to_metadata(self) -> dict[str, Any]:
        metadata = {
            "name": self.name,
            "category": self.category or self.group,
            "group": self.group,
            "description": self.description,
            "risk": self.risk,
            "permission_class": self.permission_class,
            "read_only": bool(self.read_only),
            "destructive": self.destructive,
            "parallel_safe": bool(self.parallel_safe),
            "default_enabled": self.default_enabled,
            "default_approval": self.default_approval,
            "schema": self.schema,
        }
        if not self.live_execution_supported or self.live_block_reason:
            metadata.update(
                {
                    "live_execution_supported": self.live_execution_supported,
                    "live_block_reason": self.live_block_reason,
                    "live_approval_required": self.live_approval_required,
                    "live_approval_available": self.live_approval_available,
                }
            )
        return metadata


TOOL_DEFINITIONS: tuple[ToolDefinition, ...] = (
    ToolDefinition("list_scopes", "scope", "Read-only discovery. Use first to see MCP-visible scope IDs and capabilities; returns no absolute root to ChatGPT.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("list_files", "filesystem", "List entries under one approved scope-relative directory. Use POSIX relative_path such as '.' or 'src'; returns bounded names, kinds, relative paths and sizes.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("read_file", "filesystem", "Read one bounded UTF-8 text file under an approved scope. Use only scope_id plus relative_path such as 'README.md'; protected targets, binary files, absolute paths and '..' traversal are rejected; obvious secret patterns are redacted.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("search_text", "filesystem", "Search UTF-8 text files under one approved scope-relative directory. Use a literal query of 1-200 characters; .git, virtual environments, credentials and protected targets are skipped; returns bounded file/line matches.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("write_file", "filesystem", "Overwrite exactly one existing UTF-8 text file under an approved scope. The target is hash-checked and the replacement is atomic with a backup; no wildcard or arbitrary path is accepted.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("create_file", "filesystem", "Create exactly one new UTF-8 text file in an existing approved directory. It never overwrites; relative_path must not escape the scope or target a protected file.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("create_directory", "filesystem", "Create exactly one new directory under an approved scope-relative parent. The parent must already exist; it never overwrites, creates nested parents, follows symlinks, or escapes the scope. Use the scope's create capability.", "high", True, ApprovalMode.NEVER),
    ToolDefinition("rename_file", "filesystem", "Rename exactly one regular file within one approved scope. new_name must be a single filename, destination must be absent, and the exact source hash is rechecked before execution.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("move_file", "filesystem", "Move exactly one regular file between approved scopes. The source needs move permission and the destination needs create permission; destination overwrite, traversal, symlinks and wildcard moves are rejected.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("bulk_move_files", "filesystem", "Move an explicit list of regular files from one approved scope to one existing destination directory, preserving each filename. Use for a reviewed batch; source_relative_paths accepts POSIX relative paths only (no wildcards), the batch is bounded by scope max_items, every source hash and destination is preflight-checked before any move, and destinations are never overwritten. Returns source-to-destination mappings; no file is deleted.", "high", True, ApprovalMode.NEVER),
    ToolDefinition("delete_file", "filesystem", "Delete exactly one regular file after exact one-time approval. It never recursively deletes directories, creates a backup first, and rechecks the source hash before applying.", "critical", False, ApprovalMode.ALWAYS),
    ToolDefinition("csv_transform", "documents", "Apply one allowlisted CSV operation: append_rows, update_cells, sort_rows or rename_columns. Values are scalar and formula-like prefixes are neutralized unless explicitly allowed; replacement is atomic with a backup.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("xlsx_edit", "documents", "Apply one allowlisted XLSX/XLSM operation: update_cells, append_rows, rename_sheet or add_sheet. No macros or formulas are evaluated; formula-like values are neutralized by default; replacement is atomic with a backup.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("docx_edit", "documents", "Apply one allowlisted DOCX operation: replace_text, append_paragraph or update_table_cell. It does not execute embedded content; the document is precondition-checked and backed up before atomic replacement.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("git_status", "project", "Read Git status for the explicitly selected MCP-visible project. Required input: scope_id (for example, 'project-atm-coperation'); no path or command string is accepted, output is bounded, and obvious secret patterns are redacted. If scope_id is missing or invalid, call list_scopes and retry with one project scope ID.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("git_diff", "project", "Read a bounded working-tree diff for the explicitly selected MCP-visible project. Required input: scope_id; fixed read-only Git arguments are used and commit, reset, checkout, push, and arbitrary flags are unavailable. If scope_id is missing or invalid, call list_scopes and retry with one project scope ID.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("git_log", "project", "Read at most 50 recent commits for the explicitly selected MCP-visible project. Required input: scope_id; fixed read-only Git arguments are used and repository history cannot be mutated. If scope_id is missing or invalid, call list_scopes and retry with one project scope ID.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("run_backend_test", "project", "Run the fixed backend pytest profile for the explicitly selected MCP-visible project. Required input: scope_id; only the repository backend test entrypoint runs with bounded time/output and policy checks. If scope_id is missing or invalid, call list_scopes and retry with one project scope ID.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("run_frontend_test", "project", "Run the fixed frontend npm test profile for the explicitly selected MCP-visible project. Required input: scope_id; no command string or extra flags are accepted, and bounded time/output and policy checks apply. If scope_id is missing or invalid, call list_scopes and retry with one project scope ID.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("run_build", "project", "Run the fixed build profile for the explicitly selected MCP-visible project. Required input: scope_id; no command string or extra flags are accepted, and bounded time/output and policy checks apply. If scope_id is missing or invalid, call list_scopes and retry with one project scope ID.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("runtime_status", "control", "Read local Control Center readiness, policy version, managed runtime records and the non-authoritative tunnel/ChatGPT path state. It does not claim an active ChatGPT conversation from a heartbeat.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("apply_approved_action", "control", "Apply one exact action that the user approved in the GUI. Provide only approval_id; the broker rechecks expiry, policy version, payload digest, action hash, scope and file preconditions, then consumes the approval once.", "high", True, ApprovalMode.NEVER),
)


# New entries are append-only so clients that already know the original MVP
# tools continue to work.  Read-only discovery is visible by default; writes,
# execution, and dangerous operations still require an explicit GUI tool-policy
# enablement and (where applicable) scope permission/approval.
TOOL_DEFINITIONS = TOOL_DEFINITIONS + (
    ToolDefinition("apply_patch", "filesystem", "Apply an exact unified patch to one existing UTF-8 source file. The patch is hash-preconditioned, rejects fuzzy/ambiguous context, creates a private checkpoint, replaces atomically, and reports changed line ranges.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("read_many_files", "filesystem", "Read a bounded ordered list of scope-relative UTF-8 files in parallel. Each item retains its own result or stable error and may request a line range.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("read_csv", "documents", "Read one approved scope-relative .csv file as bounded structured row arrays. Use when the user asks to inspect or query CSV data. Required: scope_id and relative_path (example: read_csv(scope_id='project-atm-coperation', relative_path='data/items.csv')). Optional defaults: start_row=1, max_rows=200 (maximum 1000), max_columns=50 (maximum 200), delimiter=',' (also ';', tab, or '|'). Supports UTF-8/UTF-8 BOM; secret-like cell values are redacted. Returns row_count, column_count, the requested rows, content_hash, and truncation flags; it never writes the file. If scope_id is unknown, call list_scopes; if the file is not UTF-8 .csv, correct the path or encoding; if quota is exceeded, request a smaller bounded read.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("find_files", "filesystem", "Find scope-relative files by deterministic path/name pattern with noisy generated/vendor trees skipped by default. Results are bounded and explicit reads remain governed by scope policy.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("search_regex", "filesystem", "Search approved UTF-8 files with a bounded regular expression through a direct non-shell adapter. Results include relative paths and line numbers; binary and protected paths are skipped.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("read_file_page", "filesystem", "Read one deterministic bounded line page from an approved UTF-8 file and return an exact continuation token when more data remains.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("read_file_page_continue", "filesystem", "Continue a prior read_file_page from its exact next line after rechecking the file hash, scope, and actor policy.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("run_targeted_test", "project", "Run one safe backend or frontend test target in the explicitly selected MCP-visible project. Required input: scope_id plus an optional relative test path; the local ProjectProfile supplies the command, never a shell command from the client. If scope_id is missing or invalid, call list_scopes and retry with one project scope ID.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("run_lint", "project", "Run the locally detected or configured lint ProjectProfile in the explicitly selected MCP-visible project. Required input: scope_id; arbitrary commands and flags are unavailable. If scope_id is missing or invalid, call list_scopes and retry with one project scope ID.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("run_typecheck", "project", "Run the locally detected or configured typecheck ProjectProfile in the explicitly selected MCP-visible project. Required input: scope_id; arbitrary commands and flags are unavailable. If scope_id is missing or invalid, call list_scopes and retry with one project scope ID.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("process_start_profile", "runtime", "Start one allowlisted project process profile with an argument array, owned process group, bounded logs, timeout, and scope execution policy.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("process_status", "runtime", "Inspect status of owned or previously registered managed processes without exposing arbitrary host processes.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("process_logs", "runtime", "Read bounded tail or incremental logs for one owned managed process. Secrets are redacted and output never includes an environment dump.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("process_stop", "runtime", "Stop one process group previously started and owned by this Control Center. Arbitrary PIDs and broad process-name kills are rejected.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("git_create_branch", "git", "Create one validated local Git branch in the explicitly selected MCP-visible project. Required input: scope_id and branch; invocation uses fixed argument-array Git and never a shell.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("git_stage_paths", "git", "Stage only an explicit bounded list of approved project-relative paths in the explicitly selected project. Required input: scope_id and paths; unrelated dirty files are not selected implicitly.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("git_commit", "git", "Commit only explicitly selected project-relative paths in the explicitly selected project with a bounded message. Required input: scope_id, paths, and message; status/preconditions are checked and unrelated files are not selected implicitly.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("git_restore_file", "git", "Restore one explicitly selected tracked file in the explicitly selected project through an approval-required Git operation. Required input: scope_id and path; reset, clean, checkout, and broad restoration remain unavailable.", "critical", False, ApprovalMode.ALWAYS),
    ToolDefinition("git_push", "git", "Push one explicitly selected branch from the explicitly selected project to a named remote through an approval-required non-force Git operation. Required input: scope_id; remote and branch are bounded values.", "critical", False, ApprovalMode.ALWAYS),
    ToolDefinition("workspace_snapshot", "context", "Return bounded project metadata, top-level tree, Git summary, test structure, managed services, and recent local errors without source contents by default.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_context", "context", "Rank deterministic filename, text, symbol, changed-file, and test context for a query without an LLM call or authorization bypass.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_index", "context", "Build or refresh a metadata-only persistent workspace index outside the project source tree, retaining hashes, languages, tests, and lightweight symbols.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_index_status", "context", "Read persistent workspace-index status and counts without returning raw source or secrets.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_observe", "context", "Observe one registered project through the WorkspaceEngine. Returns bounded Git, fixed runtime, service-port, filesystem, capsule-drift, environment-warning and unfinished-run metadata; never returns secret contents.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_prepare", "context", "Prepare one bounded WorkPackage for a registered project, goal, mode and relative allowed scope. Persists only safe workspace metadata and does not edit source files or execute commands.", "low", True, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("workspace_run_status", "context", "Read one WorkspaceEngine WorkRun, WorkPackage, append-only evidence list and optional handoff after scope visibility checks.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_finish", "context", "Finish one prepared WorkRun and generate a bounded handoff with changed files, verification split, decisions, risks, remaining work and publication readiness; no source mutation or push occurs.", "low", True, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("workspace_action_proposals", "context", "List exact pending or approved dangerous actions represented by the existing Control Center approval seam. This tool never applies an action.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_propose_action", "control", "Create one exact approval-gated proposal for an allowlisted WorkspaceEngine controlled action. The proposal call never executes the action; Apply approved remains the only execution seam.", "critical", False, ApprovalMode.NEVER, permission_class="EXECUTE", read_only=False, parallel_safe=False),
    ToolDefinition("symbol_search", "code", "Find deterministic definitions and declarations for a symbol across supported project source files.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("find_definition", "code", "Find deterministic symbol definitions across supported project source files with bounded source context.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("find_references", "code", "Find bounded word-boundary references to a symbol across supported project source files.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("dry_run", "control", "Preview a registered action's permission class, scope/target summary, preconditions, expected effect, and approval requirement without executing it.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("tool_batch", "control", "Run a bounded ordered batch of explicitly allowlisted READ-only tools. Each child independently passes schema, scope, capability and audit checks; writes, execution and dangerous operations are never fanned out.", "low", True, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("dependency_graph", "code", "Build a bounded deterministic Python/JavaScript/TypeScript dependency graph for one approved scope-relative directory. Results contain metadata, edges, unresolved imports and diagnostics, never source contents; ignored/protected trees and symlink escapes remain excluded.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_status", "agent", "List configured compatibility-agent and provider/model profile metadata plus bounded task status. No executable, environment, credential or prompt data is exposed.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_task_status", "agent", "Read one owned delegated-agent task status after the broker rechecks the task's approved scope visibility.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_task_logs", "agent", "Read bounded redacted logs for one owned delegated-agent task after scope visibility checks. Prompts and environments are never returned.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_result", "agent", "Read the bounded redacted result of one terminal owned delegated-agent task after scope visibility checks; a task claim is not independent verification.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_run", "agent", "Start one bounded task using an explicitly configured local agent profile and one approved project scope. The caller may provide only a prompt and bounded timeout; executable, argv, environment and cwd are configuration-only.", "critical", False, ApprovalMode.NEVER, permission_class="EXECUTE", read_only=False, parallel_safe=False),
    ToolDefinition("agent_cancel", "agent", "Cancel one owned delegated-agent task through its task ID after the broker rechecks the approved scope's execution capability. Arbitrary PIDs and process names are unavailable.", "critical", False, ApprovalMode.NEVER, permission_class="EXECUTE", read_only=False, parallel_safe=False),
    ToolDefinition("create_agent_task", "agent", "Create one explicit bounded worker task for explorer, implementer, reviewer, or tester. Use only a role, task description, approved project scope ID, and configured model profile; optional parent_task_id/base_ref are validated locally. The server derives system instructions, permissions, provider, worktree and limits. Raw system prompts, commands, executables, environment values and provider URLs are not accepted.", "critical", False, ApprovalMode.NEVER, permission_class="EXECUTE", read_only=False, parallel_safe=False),
    ToolDefinition("get_agent_task", "agent", "Read one persisted provider-backed worker task by task_id. Returns only bounded lifecycle metadata, role, scope, provider/model, capability context, worktree/base metadata and error state; task text and credentials are never returned.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("get_agent_result", "agent", "Read the structured result of one terminal provider-backed worker task. Returns summary, actual changed files, verification, tests, worktree/base commit, provider/model, warnings and errors. A non-terminal task returns RESULT_NOT_READY.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("list_agent_tasks", "agent", "List bounded recent persisted provider-backed worker tasks, optionally filtered by approved scope or finite lifecycle status. Results are metadata-only and visibility is rechecked per scope.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("cancel_agent_task", "agent", "Cancel one active provider-backed worker task by task_id. Only the owned worker is signalled, partial metadata is preserved, the state transition is atomic, and an audit event is written; arbitrary PIDs, commands and process names are unavailable.", "critical", False, ApprovalMode.NEVER, permission_class="EXECUTE", read_only=False, parallel_safe=False),
)

# Browser automation is enabled by default so the new tools are immediately
# available. All four tools still execute only through Broker and the named
# profile's network policy.
TOOL_DEFINITIONS = TOOL_DEFINITIONS + (
    ToolDefinition("browser_open", "browser", "Open or reuse one persistent, policy-controlled browser profile. The caller can select only a configured profile; credentials, cookies, tokens, executable paths and process IDs are unavailable.", "high", True, ApprovalMode.NEVER, permission_class="EXECUTE", read_only=False, parallel_safe=False),
    ToolDefinition("browser_snapshot", "browser", "Return a bounded structured accessibility/DOM snapshot with short-lived element refs. Password fields, cookies, tokens, hidden inputs and raw HTML are excluded.", "low", True, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("browser_run_command", "browser", "Run one bounded declarative browser action against a current snapshot ref. Only navigate, click, fill, select, press, wait, read_text, read_table and submit are accepted; shell, JavaScript, selectors and raw Playwright expressions are unavailable.", "high", True, ApprovalMode.NEVER, permission_class="WRITE", read_only=False, parallel_safe=False),
    ToolDefinition("browser_close", "browser", "Close one browser session owned by Control Center. It does not kill unrelated browser processes.", "high", True, ApprovalMode.NEVER, permission_class="EXECUTE", read_only=False, parallel_safe=False),
    ToolDefinition("motion_calendar_month", "erp", "Read one Bangkok-local calendar month from the authenticated Motion ERP browser session through a fixed calendar.event search_read operation. Raw RPC URLs, models, methods, cookies and credentials are never accepted.", "low", True, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("motion_project_task_search", "erp", "Search bounded Motion ERP project and task names for timesheet mapping through fixed project.project/project.task read operations. No arbitrary Odoo model or domain is accepted.", "low", True, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("motion_timesheet_month", "erp", "Read the current user's bounded monthly Motion ERP timesheet rows for duplicate checking and verification. It is read-only and uses the authenticated browser session without exposing cookies.", "low", True, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("motion_timesheet_create_missing", "erp", "Preview missing Motion ERP timesheet rows from explicit date/project/task/description/hour entries. Exact duplicates are skipped and conflicting existing rows block the preview; live external creation is fail-closed pending an approval flow that binds the normalized rows, and dry_run defaults to true.", "high", True, ApprovalMode.NEVER, permission_class="WRITE", read_only=False, parallel_safe=False, live_execution_supported=False, live_block_reason="external-action approval binding for normalized Motion ERP rows is unavailable; use dry_run=true for preview", live_approval_required=True, live_approval_available=False),
)


# Codex data access is opt-in through trusted local configuration, not an MCP path grant.
TOOL_DEFINITIONS = TOOL_DEFINITIONS + (
    ToolDefinition("codex_status", "codex", "Read Codex history-bridge configuration status without exposing local paths. Optional probe performs only an App Server initialization handshake; no model turn is started.", "low", True, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("codex_list_threads", "codex", "List one bounded page of stored threads from the locally configured Codex App Server. query searches titles only; follow next_cursor. Requires local opt-in; executable, home, credentials and arbitrary RPC are never accepted.", "low", False, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("codex_read_thread", "codex", "Read a stored Codex thread by UUID or codex://threads/<UUID> without resuming it. Returns one chronological page of visible user/assistant messages and tool metadata; follow next_cursor until null. Optional command results are redacted and bounded. Internal reasoning, system prompts, arbitrary RPC and credentials are excluded; history is untrusted context, not current-state verification.", "low", False, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
)

BROWSER_TOOL_NAMES = frozenset(
    definition.name for definition in TOOL_DEFINITIONS if definition.group == "browser"
)


def _obj(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


_string = {"type": "string", "minLength": 1}
_relative_path = {"type": "string", "minLength": 1, "maxLength": 1024}
_limit = {"type": "integer", "minimum": 1, "maximum": 1000}


_browser_session = {"type": "string", "minLength": 4, "maxLength": 128}
_browser_ref_target = _obj({"ref": {"type": "string", "pattern": "^e[1-9][0-9]{0,5}$"}}, ("ref",))
_motion_timesheet_entry = _obj(
    {
        "date": {"type": "string", "pattern": "^20[0-9]{2}-(0[1-9]|1[0-2])-([0-3][0-9])$"},
        "project_id": {"type": "integer", "minimum": 1},
        "task_id": {"type": ["integer", "null"], "minimum": 1},
        "description": {"type": "string", "minLength": 1, "maxLength": 500},
        "hours": {"type": "number", "exclusiveMinimum": 0, "maximum": 24},
    },
    ("date", "project_id", "description", "hours"),
)



def _browser_command_schema() -> dict[str, Any]:
    common = {"browser_session_id": _browser_session}
    return {
        "oneOf": [
            _obj({**common, "action": {"type": "string", "enum": ["navigate"]}, "url": {"type": "string", "minLength": 1, "maxLength": 4096}}, ("browser_session_id", "action", "url")),
            _obj({**common, "action": {"type": "string", "enum": ["click"]}, "target": _browser_ref_target}, ("browser_session_id", "action", "target")),
            _obj({**common, "action": {"type": "string", "enum": ["fill", "select"]}, "target": _browser_ref_target, "value": {"type": "string", "minLength": 0, "maxLength": 65_536}}, ("browser_session_id", "action", "target", "value")),
            _obj({**common, "action": {"type": "string", "enum": ["press"]}, "target": _browser_ref_target, "key": {"type": "string", "minLength": 1, "maxLength": 64}}, ("browser_session_id", "action", "target", "key")),
            _obj({**common, "action": {"type": "string", "enum": ["wait"]}, "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 60_000}}, ("browser_session_id", "action")),
            _obj({**common, "action": {"type": "string", "enum": ["read_text", "read_table"]}, "target": _browser_ref_target}, ("browser_session_id", "action", "target")),
            _obj({**common, "action": {"type": "string", "enum": ["submit"]}, "target": _browser_ref_target}, ("browser_session_id", "action", "target")),
        ]
    }


TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_scopes": _obj({}),
    "list_files": _obj({"scope_id": _string, "relative_path": _relative_path, "max_items": _limit}, ("scope_id",)),
    "read_file": _obj({"scope_id": _string, "relative_path": _relative_path}, ("scope_id", "relative_path")),
    "read_csv": _obj(
        {
            "scope_id": _string,
            "relative_path": _relative_path,
            "start_row": {"type": "integer", "minimum": 1, "maximum": 50_000_000},
            "max_rows": {"type": "integer", "minimum": 1, "maximum": 1_000},
            "max_columns": {"type": "integer", "minimum": 1, "maximum": 200},
            "delimiter": {"type": "string", "enum": [",", ";", "\t", "|"]},
        },
        ("scope_id", "relative_path"),
    ),
    "search_text": _obj({"scope_id": _string, "query": {"type": "string", "minLength": 1, "maxLength": 200}, "relative_path": _relative_path, "max_results": _limit}, ("scope_id", "query")),
    "write_file": _obj({"scope_id": _string, "relative_path": _relative_path, "content": {"type": "string", "maxLength": 1_048_576}}, ("scope_id", "relative_path", "content")),
    "create_file": _obj({"scope_id": _string, "relative_path": _relative_path, "content": {"type": "string", "maxLength": 1_048_576}}, ("scope_id", "relative_path")),
    "create_directory": _obj({"scope_id": _string, "relative_path": _relative_path}, ("scope_id", "relative_path")),
    "rename_file": _obj({"scope_id": _string, "relative_path": _relative_path, "new_name": _string}, ("scope_id", "relative_path", "new_name")),
    "move_file": _obj({"source_scope_id": _string, "source_relative_path": _relative_path, "destination_scope_id": _string, "destination_relative_path": _relative_path}, ("source_scope_id", "source_relative_path", "destination_scope_id", "destination_relative_path")),
    "bulk_move_files": _obj({"source_scope_id": _string, "source_relative_paths": {"type": "array", "items": _relative_path, "minItems": 1, "maxItems": 100}, "destination_scope_id": _string, "destination_relative_directory": _relative_path}, ("source_scope_id", "source_relative_paths", "destination_scope_id")),
    "delete_file": _obj({"scope_id": _string, "relative_path": _relative_path}, ("scope_id", "relative_path")),
    "csv_transform": _obj({"scope_id": _string, "relative_path": _relative_path, "operation": _string, "rows": {"type": "array"}, "updates": {"type": "array"}, "column": {"type": "integer", "minimum": 1}, "descending": {"type": "boolean"}, "header": {"type": "boolean"}, "mapping": {"type": "object"}, "allow_formulas": {"type": "boolean"}}, ("scope_id", "relative_path", "operation")),
    "xlsx_edit": _obj({"scope_id": _string, "relative_path": _relative_path, "operation": _string, "sheet": _string, "cell": _string, "value": {}, "updates": {"type": "array"}, "rows": {"type": "array"}, "old_name": _string, "new_name": _string, "name": _string, "allow_formulas": {"type": "boolean"}}, ("scope_id", "relative_path", "operation")),
    "docx_edit": _obj({"scope_id": _string, "relative_path": _relative_path, "operation": _string, "old": _string, "new": _string, "text": _string, "table": {"type": "integer", "minimum": 0}, "row": {"type": "integer", "minimum": 0}, "column": {"type": "integer", "minimum": 0}}, ("scope_id", "relative_path", "operation")),
    "git_status": _obj({"scope_id": _string}, ("scope_id",)),
    "git_diff": _obj({"scope_id": _string}, ("scope_id",)),
    "git_log": _obj({"scope_id": _string}, ("scope_id",)),
    "run_backend_test": _obj({"scope_id": _string}, ("scope_id",)),
    "run_frontend_test": _obj({"scope_id": _string}, ("scope_id",)),
    "runtime_status": _obj({}),
    "run_targeted_test": _obj({"scope_id": _string, "target": {"type": "string", "enum": ["backend", "frontend", "auto"]}, "test_path": _relative_path, "test_file": _relative_path}, ("scope_id", "target")),
    "apply_patch": _obj({"scope_id": _string, "relative_path": _relative_path, "patch": {"type": "string", "minLength": 1, "maxLength": 1_048_576}, "expected_hash": {"type": ["string", "null"]}}, ("scope_id", "relative_path", "patch")),
    "read_many_files": _obj({"scope_id": _string, "files": {"type": "array", "minItems": 1, "maxItems": 32, "items": {**_obj({"path": _relative_path, "relative_path": _relative_path, "start_line": {"type": "integer", "minimum": 1}, "end_line": {"type": "integer", "minimum": 1}}), "oneOf": [{"required": ["path"], "not": {"required": ["relative_path"]}}, {"required": ["relative_path"], "not": {"required": ["path"]}}]}}}, ("scope_id", "files")),
    "find_files": _obj({"scope_id": _string, "pattern": {"type": "string", "minLength": 1, "maxLength": 256}, "relative_path": _relative_path, "include_ignored": {"type": "boolean"}, "max_results": _limit}, ("scope_id",)),
    "search_regex": _obj({"scope_id": _string, "pattern": {"type": "string", "minLength": 1, "maxLength": 500}, "relative_path": _relative_path, "max_results": _limit, "ignore_case": {"type": "boolean"}, "max_file_bytes": {"type": "integer", "minimum": 1, "maximum": 50_000_000}, "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 60_000}}, ("scope_id", "pattern")),
    "read_file_page": _obj({"scope_id": _string, "relative_path": _relative_path, "start_line": {"type": "integer", "minimum": 1}, "max_lines": {"type": "integer", "minimum": 1, "maximum": 1000}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1_048_576}}, ("scope_id", "relative_path")),
    "read_file_page_continue": _obj({"continuation_token": _string}, ("continuation_token",)),
    "run_lint": _obj({"scope_id": _string, "target": {"type": "string", "enum": ["backend", "frontend", "auto"]}}, ("scope_id",)),
    "run_typecheck": _obj({"scope_id": _string, "target": {"type": "string", "enum": ["backend", "frontend", "auto"]}}, ("scope_id",)),
    "run_build": _obj({"scope_id": _string, "target": {"type": "string", "enum": ["backend", "frontend", "auto"]}}, ("scope_id",)),
    "process_start_profile": _obj({"scope_id": _string, "profile": _string, "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600}}, ("scope_id", "profile")),
    "process_status": _obj({"process_id": _string}, ()),
    "process_logs": _obj({"process_id": _string, "tail_lines": {"type": "integer", "minimum": 1, "maximum": 500}, "since_sequence": {"type": "integer", "minimum": 1}}, ("process_id",)),
    "process_stop": _obj({"process_id": _string}, ("process_id",)),
    "git_create_branch": _obj({"scope_id": _string, "branch": _string}, ("scope_id", "branch")),
    "git_stage_paths": _obj({"scope_id": _string, "paths": {"type": "array", "items": _relative_path, "minItems": 1, "maxItems": 100}}, ("scope_id", "paths")),
    "git_commit": _obj({"scope_id": _string, "paths": {"type": "array", "items": _relative_path, "minItems": 1, "maxItems": 100}, "message": {"type": "string", "minLength": 1, "maxLength": 200}}, ("scope_id", "paths", "message")),
    "git_restore_file": _obj({"scope_id": _string, "path": _relative_path, "expected_hash": {"type": ["string", "null"]}}, ("scope_id", "path")),
    "git_push": _obj({"scope_id": _string, "remote": {"type": "string", "minLength": 1, "maxLength": 100}, "branch": {"type": _string}}, ("scope_id",)),
    "workspace_snapshot": _obj({"scope_id": _string, "max_items": _limit}, ()),
    "workspace_context": _obj({"query": {"type": "string", "minLength": 1, "maxLength": 500}, "scope_id": _string, "path": _relative_path, "intent": {"type": "string", "enum": ["debug", "implement", "review", "trace", "explore"]}, "max_files": {"type": "integer", "minimum": 1, "maximum": 100}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 2_000_000}, "delivery_key": {"type": "string", "minLength": 1, "maxLength": 256}}, ("query",)),
    "workspace_index": _obj({"scope_id": _string, "refresh": {"type": "boolean"}, "include_ignored": {"type": "boolean"}, "max_files": {"type": "integer", "minimum": 1, "maximum": 10000}}, ("scope_id",)),
    "workspace_index_status": _obj({"scope_id": _string}, ()),
    "workspace_observe": _obj({"project_id": _string, "max_items": _limit}, ("project_id",)),
    "workspace_prepare": _obj(
        {
            "project_id": _string,
            "goal": {"type": "string", "minLength": 1, "maxLength": 4000},
            "mode": {"type": "string", "enum": ["diagnose", "implement", "review"]},
            "allowed_scope": {"type": "array", "items": _relative_path, "minItems": 1, "maxItems": 100},
        },
        ("project_id", "goal"),
    ),
    "workspace_run_status": _obj({"run_id": _string}, ("run_id",)),
    "workspace_finish": _obj({"run_id": _string}, ("run_id",)),
    "workspace_action_proposals": _obj({"project_id": _string}, ()),
    "workspace_propose_action": _obj(
        {
            "run_id": _string,
            "action": {"type": "string", "enum": ["owned_service_start", "owned_service_stop", "targeted_verification", "commit", "push"]},
            "parameters": {"type": "object", "maxProperties": 10},
        },
        ("run_id", "action"),
    ),
    "symbol_search": _obj({"scope_id": _string, "symbol": _string, "relative_path": _relative_path, "max_results": _limit}, ("scope_id", "symbol")),
    "find_definition": _obj({"scope_id": _string, "symbol": _string, "relative_path": _relative_path, "max_results": _limit}, ("scope_id", "symbol")),
    "find_references": _obj({"scope_id": _string, "symbol": _string, "relative_path": _relative_path, "max_results": _limit}, ("scope_id", "symbol")),
    "dry_run": _obj({"tool": _string, "arguments": {"type": "object"}}, ("tool", "arguments")),
    "apply_approved_action": _obj({"approval_id": _string}, ("approval_id",)),
    "tool_batch": _obj(
        {
            "scope_id": _string,
            "operations": {
                "type": "array",
                "minItems": 1,
                "maxItems": 20,
                "items": _obj(
                    {
                        "operation": {"type": "string", "minLength": 1, "maxLength": 128},
                        "arguments": {"type": "object"},
                    },
                    ("operation",),
                ),
            },
        },
        ("scope_id", "operations"),
    ),
    "dependency_graph": _obj(
        {
            "scope_id": _string,
            "path": _relative_path,
            "files": {"type": "array", "items": _relative_path, "maxItems": 10_000},
            "max_files": {"type": "integer", "minimum": 1, "maximum": 10_000},
            "max_edges": {"type": "integer", "minimum": 1, "maximum": 50_000},
            "max_file_bytes": {"type": "integer", "minimum": 1, "maximum": 5_000_000},
            "max_output_bytes": {"type": "integer", "minimum": 512, "maximum": 10_000_000},
            "max_specifier_length": {"type": "integer", "minimum": 1, "maximum": 4_096},
            "include_ignored": {"type": "boolean"},
        },
        ("scope_id",),
    ),
    "agent_status": _obj({}),
    "agent_task_status": _obj({"task_id": _string}, ("task_id",)),
    "agent_task_logs": _obj(
        {
            "task_id": _string,
            "tail_lines": {"type": "integer", "minimum": 1, "maximum": 500},
            "since_sequence": {"type": "integer", "minimum": 0},
            "stream": {"type": "string", "enum": ["combined", "stdout", "stderr"]},
        },
        ("task_id",),
    ),
    "agent_result": _obj({"task_id": _string}, ("task_id",)),
    "agent_run": _obj(
        {
            "scope_id": _string,
            "profile": _string,
            "prompt": {"type": "string", "minLength": 1, "maxLength": 32_768},
            "timeout_seconds": {"type": "number", "minimum": 0.001, "maximum": 3_600},
        },
        ("scope_id", "profile", "prompt"),
    ),
    "agent_cancel": _obj({"task_id": _string}, ("task_id",)),
    "create_agent_task": _obj(
        {
            "role": {"type": "string", "enum": ["explorer", "implementer", "reviewer", "tester"]},
            "task": {"type": "string", "minLength": 1, "maxLength": 16_384},
            "scope_id": _string,
            "model_profile": {"type": "string", "minLength": 1, "maxLength": 64},
            "parent_task_id": {"type": ["string", "null"], "minLength": 1, "maxLength": 64},
            "base_ref": {"type": ["string", "null"], "minLength": 1, "maxLength": 200},
        },
        ("role", "task", "scope_id", "model_profile"),
    ),
    "get_agent_task": _obj({"task_id": _string}, ("task_id",)),
    "get_agent_result": _obj({"task_id": _string}, ("task_id",)),
    "list_agent_tasks": _obj(
        {
            "scope_id": _string,
            "status": {"type": "string", "enum": ["queued", "starting", "running", "completed", "failed", "cancelled"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        },
    ),
    "cancel_agent_task": _obj({"task_id": _string}, ("task_id",)),
    "codex_status": _obj({"probe": {"type": "boolean"}}),
    "codex_list_threads": _obj(
        {
            "query": {"type": "string", "maxLength": 200},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            "cursor": {"type": "string", "minLength": 1, "maxLength": 4096},
            "archived": {"type": "boolean"},
        },
    ),
    "codex_read_thread": _obj(
        {
            "thread_id": {"type": "string", "minLength": 36, "maxLength": 52,
                "pattern": "^(?:codex://threads/)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 20},
            "cursor": {"type": "string", "minLength": 1, "maxLength": 4096},
            "sort_direction": {"type": "string", "enum": ["asc", "desc"]},
            "include_tool_results": {"type": "boolean"},
        },
        ("thread_id",),
    ),
    "browser_open": _obj({"profile": {"type": "string", "enum": [LOCAL_BROWSER_PROFILE_NAME]}}, ("profile",)),
    "browser_snapshot": _obj({"browser_session_id": _browser_session, "max_bytes": {"type": "integer", "minimum": 512, "maximum": 65_536}}, ("browser_session_id",)),
    "browser_run_command": _browser_command_schema(),
    "browser_close": _obj({"browser_session_id": _browser_session}, ("browser_session_id",)),
    "motion_calendar_month": _obj(
        {
            "browser_session_id": _browser_session,
            "month": {"type": "string", "pattern": "^20[0-9]{2}-(0[1-9]|1[0-2])$"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        ("browser_session_id", "month"),
    ),
    "motion_project_task_search": _obj(
        {
            "browser_session_id": _browser_session,
            "query": {"type": "string", "minLength": 1, "maxLength": 200},
            "project_id": {"type": ["integer", "null"], "minimum": 1},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        },
        ("browser_session_id", "query"),
    ),
    "motion_timesheet_month": _obj(
        {
            "browser_session_id": _browser_session,
            "month": {"type": "string", "pattern": "^20[0-9]{2}-(0[1-9]|1[0-2])$"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        ("browser_session_id", "month"),
    ),
    "motion_timesheet_create_missing": _obj(
        {
            "browser_session_id": _browser_session,
            "entries": {"type": "array", "items": _motion_timesheet_entry, "minItems": 1, "maxItems": 100},
            "dry_run": {"type": "boolean"},
        },
        ("browser_session_id", "entries"),
    ),
}


TOOL_BY_NAME = {definition.name: definition for definition in TOOL_DEFINITIONS}


class ToolRegistry:
    """Deterministic catalog shared by policy, broker, and MCP transport."""

    def __init__(self, definitions: tuple[ToolDefinition, ...] = TOOL_DEFINITIONS):
        self._definitions = tuple(definitions)
        self._by_name = {definition.name: definition for definition in self._definitions}

    def get(self, name: str) -> ToolDefinition | None:
        return self._by_name.get(name)

    def all(self) -> tuple[ToolDefinition, ...]:
        return self._definitions

    def enabled(self, name: str, policies: dict[str, Any]) -> bool:
        definition = self.get(name)
        policy = policies.get(name)
        return bool(definition and policy and policy.enabled)

    def metadata(self) -> list[dict[str, Any]]:
        return [definition.to_metadata() for definition in self._definitions]


DEFAULT_REGISTRY = ToolRegistry()
