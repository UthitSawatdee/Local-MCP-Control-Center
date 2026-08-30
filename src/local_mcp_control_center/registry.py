from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
        return {
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
    ToolDefinition("git_status", "project", "Read the status of the single MCP-visible project scope using a fixed non-shell git profile. No path or command string is accepted; output is bounded and obvious secret patterns are redacted.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("git_diff", "project", "Read a bounded working-tree diff for the single MCP-visible project scope using fixed read-only git arguments. It cannot commit, reset, checkout, push or accept arbitrary flags.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("git_log", "project", "Read at most 50 recent commits for the single MCP-visible project scope using fixed read-only git arguments. It cannot mutate repository history.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("run_backend_test", "project", "Run the fixed backend pytest profile for the single MCP-visible project. It runs only the repository backend test entrypoint with bounded time/output and policy checks.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("run_frontend_test", "project", "Run the fixed frontend npm test profile for the single MCP-visible project. No command string or extra flags are accepted; bounded time/output and policy checks apply.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("run_build", "project", "Run the fixed frontend npm build profile for the single MCP-visible project. No command string or extra flags are accepted; bounded time/output and policy checks apply.", "critical", False, ApprovalMode.NEVER),
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
    ToolDefinition("find_files", "filesystem", "Find scope-relative files by deterministic path/name pattern with noisy generated/vendor trees skipped by default. Results are bounded and explicit reads remain governed by scope policy.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("search_regex", "filesystem", "Search approved UTF-8 files with a bounded regular expression through a direct non-shell adapter. Results include relative paths and line numbers; binary and protected paths are skipped.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("read_file_page", "filesystem", "Read one deterministic bounded line page from an approved UTF-8 file and return an exact continuation token when more data remains.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("read_file_page_continue", "filesystem", "Continue a prior read_file_page from its exact next line after rechecking the file hash, scope, and actor policy.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("run_targeted_test", "project", "Run one safe backend or frontend test target selected by the local ProjectProfile. The client supplies a relative test path, never a shell command.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("run_lint", "project", "Run the locally detected or configured lint ProjectProfile without accepting arbitrary commands or flags.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("run_typecheck", "project", "Run the locally detected or configured typecheck ProjectProfile without accepting arbitrary commands or flags.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("process_start_profile", "runtime", "Start one allowlisted project process profile with an argument array, owned process group, bounded logs, timeout, and scope execution policy.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("process_status", "runtime", "Inspect status of owned or previously registered managed processes without exposing arbitrary host processes.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("process_logs", "runtime", "Read bounded tail or incremental logs for one owned managed process. Secrets are redacted and output never includes an environment dump.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("process_stop", "runtime", "Stop one process group previously started and owned by this Control Center. Arbitrary PIDs and broad process-name kills are rejected.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("git_create_branch", "git", "Create one validated local Git branch in the approved project using fixed argument-array Git invocation.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("git_stage_paths", "git", "Stage only an explicit bounded list of approved project-relative paths; unrelated dirty files are not selected implicitly.", "high", False, ApprovalMode.NEVER),
    ToolDefinition("git_commit", "git", "Commit only explicitly selected project-relative paths with a bounded message after reporting status and staged diff summary.", "critical", False, ApprovalMode.NEVER),
    ToolDefinition("git_restore_file", "git", "Restore one explicitly selected tracked file through an approval-required Git operation. Reset, clean, checkout, and broad restoration remain unavailable.", "critical", False, ApprovalMode.ALWAYS),
    ToolDefinition("git_push", "git", "Push one explicitly selected branch to a named remote through an approval-required non-force Git operation.", "critical", False, ApprovalMode.ALWAYS),
    ToolDefinition("workspace_snapshot", "context", "Return bounded project metadata, top-level tree, Git summary, test structure, managed services, and recent local errors without source contents by default.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_context", "context", "Rank deterministic filename, text, symbol, changed-file, and test context for a query without an LLM call or authorization bypass.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_index", "context", "Build or refresh a metadata-only persistent workspace index outside the project source tree, retaining hashes, languages, tests, and lightweight symbols.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("workspace_index_status", "context", "Read persistent workspace-index status and counts without returning raw source or secrets.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("symbol_search", "code", "Find deterministic definitions and declarations for a symbol across supported project source files.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("find_definition", "code", "Find deterministic symbol definitions across supported project source files with bounded source context.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("find_references", "code", "Find bounded word-boundary references to a symbol across supported project source files.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("dry_run", "control", "Preview a registered action's permission class, scope/target summary, preconditions, expected effect, and approval requirement without executing it.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("tool_batch", "control", "Run a bounded ordered batch of explicitly allowlisted READ-only tools. Each child independently passes schema, scope, capability and audit checks; writes, execution and dangerous operations are never fanned out.", "low", True, ApprovalMode.NEVER, permission_class="READ", read_only=True, parallel_safe=False),
    ToolDefinition("dependency_graph", "code", "Build a bounded deterministic Python/JavaScript/TypeScript dependency graph for one approved scope-relative directory. Results contain metadata, edges, unresolved imports and diagnostics, never source contents; ignored/protected trees and symlink escapes remain excluded.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_status", "agent", "List configured local agent profile names and bounded task status. No executable, environment, credential or prompt data is exposed.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_task_status", "agent", "Read one owned delegated-agent task status after the broker rechecks the task's approved scope visibility.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_task_logs", "agent", "Read bounded redacted logs for one owned delegated-agent task after scope visibility checks. Prompts and environments are never returned.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_result", "agent", "Read the bounded redacted result of one terminal owned delegated-agent task after scope visibility checks; a task claim is not independent verification.", "low", True, ApprovalMode.NEVER),
    ToolDefinition("agent_run", "agent", "Start one bounded task using an explicitly configured local agent profile and one approved project scope. The caller may provide only a prompt and bounded timeout; executable, argv, environment and cwd are configuration-only.", "critical", False, ApprovalMode.NEVER, permission_class="EXECUTE", read_only=False, parallel_safe=False),
    ToolDefinition("agent_cancel", "agent", "Cancel one owned delegated-agent task through its task ID after the broker rechecks the approved scope's execution capability. Arbitrary PIDs and process names are unavailable.", "critical", False, ApprovalMode.NEVER, permission_class="EXECUTE", read_only=False, parallel_safe=False),
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


TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_scopes": _obj({}),
    "list_files": _obj({"scope_id": _string, "relative_path": _relative_path, "max_items": _limit}, ("scope_id",)),
    "read_file": _obj({"scope_id": _string, "relative_path": _relative_path}, ("scope_id", "relative_path")),
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
    "git_status": _obj({}),
    "git_diff": _obj({}),
    "git_log": _obj({}),
    "run_backend_test": _obj({}),
    "run_frontend_test": _obj({}),
    "runtime_status": _obj({}),
    "run_targeted_test": _obj({"target": {"type": "string", "enum": ["backend", "frontend", "auto"]}, "test_path": _relative_path, "test_file": _relative_path}, ("target",)),
    "apply_patch": _obj({"scope_id": _string, "relative_path": _relative_path, "patch": {"type": "string", "minLength": 1, "maxLength": 1_048_576}, "expected_hash": {"type": ["string", "null"]}}, ("scope_id", "relative_path", "patch")),
    "read_many_files": _obj({"scope_id": _string, "files": {"type": "array", "minItems": 1, "maxItems": 32, "items": {**_obj({"path": _relative_path, "relative_path": _relative_path, "start_line": {"type": "integer", "minimum": 1}, "end_line": {"type": "integer", "minimum": 1}}), "oneOf": [{"required": ["path"], "not": {"required": ["relative_path"]}}, {"required": ["relative_path"], "not": {"required": ["path"]}}]}}}, ("scope_id", "files")),
    "find_files": _obj({"scope_id": _string, "pattern": {"type": "string", "minLength": 1, "maxLength": 256}, "relative_path": _relative_path, "include_ignored": {"type": "boolean"}, "max_results": _limit}, ("scope_id",)),
    "search_regex": _obj({"scope_id": _string, "pattern": {"type": "string", "minLength": 1, "maxLength": 500}, "relative_path": _relative_path, "max_results": _limit, "ignore_case": {"type": "boolean"}, "max_file_bytes": {"type": "integer", "minimum": 1, "maximum": 50_000_000}, "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 60_000}}, ("scope_id", "pattern")),
    "read_file_page": _obj({"scope_id": _string, "relative_path": _relative_path, "start_line": {"type": "integer", "minimum": 1}, "max_lines": {"type": "integer", "minimum": 1, "maximum": 1000}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1_048_576}}, ("scope_id", "relative_path")),
    "read_file_page_continue": _obj({"continuation_token": _string}, ("continuation_token",)),
    "run_lint": _obj({"target": {"type": "string", "enum": ["backend", "frontend", "auto"]}}, ()),
    "run_typecheck": _obj({"target": {"type": "string", "enum": ["backend", "frontend", "auto"]}}, ()),
    "run_build": _obj({"target": {"type": "string", "enum": ["backend", "frontend", "auto"]}}, ()),
    "process_start_profile": _obj({"scope_id": _string, "profile": _string, "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600}}, ("scope_id", "profile")),
    "process_status": _obj({"process_id": _string}, ()),
    "process_logs": _obj({"process_id": _string, "tail_lines": {"type": "integer", "minimum": 1, "maximum": 500}, "since_sequence": {"type": "integer", "minimum": 1}}, ("process_id",)),
    "process_stop": _obj({"process_id": _string}, ("process_id",)),
    "git_create_branch": _obj({"branch": _string}, ("branch",)),
    "git_stage_paths": _obj({"paths": {"type": "array", "items": _relative_path, "minItems": 1, "maxItems": 100}}, ("paths",)),
    "git_commit": _obj({"message": {"type": "string", "minLength": 1, "maxLength": 200}, "paths": {"type": "array", "items": _relative_path, "minItems": 1, "maxItems": 100}}, ("message", "paths")),
    "git_restore_file": _obj({"path": _relative_path, "expected_hash": {"type": ["string", "null"]}}, ("path",)),
    "git_push": _obj({"remote": {"type": "string", "minLength": 1, "maxLength": 100}, "branch": {"type": _string}}, ()),
    "workspace_snapshot": _obj({"scope_id": _string, "max_items": _limit}, ()),
    "workspace_context": _obj({"query": {"type": "string", "minLength": 1, "maxLength": 500}, "scope_id": _string, "path": _relative_path, "intent": {"type": "string", "enum": ["debug", "implement", "review", "trace", "explore"]}, "max_files": {"type": "integer", "minimum": 1, "maximum": 100}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 2_000_000}, "delivery_key": {"type": "string", "minLength": 1, "maxLength": 256}}, ("query",)),
    "workspace_index": _obj({"scope_id": _string, "refresh": {"type": "boolean"}, "include_ignored": {"type": "boolean"}, "max_files": {"type": "integer", "minimum": 1, "maximum": 10000}}, ("scope_id",)),
    "workspace_index_status": _obj({"scope_id": _string}, ()),
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
