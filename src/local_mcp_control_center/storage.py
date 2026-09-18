from __future__ import annotations

import json
import hashlib
import os
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any, Iterable

from .errors import StorageError
from .models import ApprovalMode, ApprovalRequest, Scope, ToolPolicy, utc_now
from .registry import BROWSER_TOOL_NAMES, TOOL_DEFINITIONS


CAPABILITIES = ("read", "execute", "write", "create", "rename", "move", "delete")
APPROVAL_MODES = {str(mode) for mode in ApprovalMode}
DELETE_TOOL = "delete_file"
DELETE_CAPABILITY = "delete"
DANGEROUS_TOOLS = {DELETE_TOOL, "git_restore_file", "git_push"}
MCP_BRIDGE_SNAPSHOT_KEY = "mcp_bridge_snapshot"
BROWSER_DEFAULTS_MIGRATION_KEY = "browser_tools_default_enabled_v1"


def _workspace_payload_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _workspace_evidence_hash(run_id: str, sequence: int, event_type: str, payload: dict[str, Any]) -> str:
    return _workspace_payload_hash(
        {"run_id": run_id, "sequence": sequence, "event_type": event_type, "payload": payload}
    )


class Store:
    """Small SQLite adapter for policy, approvals, runtime state, and audit metadata."""

    def __init__(self, db_path: str | Path, data_dir: str | Path | None = None):
        self.db_path = Path(db_path).expanduser().absolute()
        self.data_dir = Path(data_dir).expanduser().absolute() if data_dir else self.db_path.parent
        self.data_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.data_dir, 0o700)
        self._lock = RLock()
        try:
            self._conn = sqlite3.connect(
                self.db_path,
                timeout=30,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            os.chmod(self.db_path, 0o600)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._initialize()
        except sqlite3.Error as exc:
            raise StorageError(str(exc)) from exc

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scopes (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            kind TEXT NOT NULL,
            root TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            expose_to_mcp INTEGER NOT NULL DEFAULT 0,
            policy_version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scope_permissions (
            scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            capability TEXT NOT NULL,
            allowed INTEGER NOT NULL DEFAULT 0,
            approval_mode TEXT NOT NULL DEFAULT 'never',
            max_bytes INTEGER NOT NULL DEFAULT 1048576,
            max_items INTEGER NOT NULL DEFAULT 100,
            PRIMARY KEY(scope_id, capability)
        );
        CREATE TABLE IF NOT EXISTS tool_policies (
            tool_name TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL,
            approval_mode TEXT NOT NULL,
            max_duration_ms INTEGER NOT NULL DEFAULT 30000,
            output_limit_bytes INTEGER NOT NULL DEFAULT 65536,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS approval_requests (
            id TEXT PRIMARY KEY,
            action_hash TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            intent_json TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            policy_version INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            decision_reason TEXT,
            decided_at TEXT,
            consumed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            occurred_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            session_id TEXT,
            request_id TEXT,
            tool TEXT NOT NULL,
            operation TEXT NOT NULL,
            scope_id TEXT,
            target_display TEXT NOT NULL,
            decision TEXT NOT NULL,
            approval_id TEXT,
            pre_hash TEXT,
            post_hash TEXT,
            result_code TEXT,
            error_code TEXT,
            metadata_json TEXT NOT NULL,
            prev_hash TEXT,
            event_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS runtime_processes (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            profile TEXT NOT NULL,
            pid INTEGER,
            pgid INTEGER,
            state TEXT NOT NULL,
            started_at TEXT,
            stopped_at TEXT,
            log_path TEXT,
            timeout_ms INTEGER,
            exit_code INTEGER,
            owner_session_id TEXT,
            updated_at TEXT,
            command_digest TEXT,
            argv_json TEXT
        );
        CREATE TABLE IF NOT EXISTS agent_tasks (
            task_id TEXT PRIMARY KEY,
            parent_task_id TEXT,
            root_task_id TEXT NOT NULL,
            role TEXT NOT NULL,
            task_text TEXT NOT NULL,
            scope_id TEXT NOT NULL REFERENCES scopes(id),
            effective_scope_id TEXT NOT NULL REFERENCES scopes(id),
            model_profile TEXT NOT NULL,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            status TEXT NOT NULL,
            base_ref TEXT,
            base_commit TEXT,
            worktree_path TEXT,
            source_dirty INTEGER,
            source_head_commit TEXT,
            capability_json TEXT NOT NULL,
            owner_actor TEXT NOT NULL,
            owner_session_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            updated_at TEXT NOT NULL,
            error_code TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_agent_tasks_status_created
            ON agent_tasks(status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_agent_tasks_root
            ON agent_tasks(root_task_id, created_at);
        CREATE TABLE IF NOT EXISTS agent_results (
            task_id TEXT PRIMARY KEY REFERENCES agent_tasks(task_id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            summary TEXT NOT NULL,
            changed_files_json TEXT NOT NULL,
            verification_json TEXT NOT NULL,
            tests_json TEXT NOT NULL,
            worktree_json TEXT,
            provider TEXT,
            model TEXT,
            warnings_json TEXT NOT NULL,
            errors_json TEXT NOT NULL,
            tool_calls INTEGER NOT NULL DEFAULT 0,
            started_at TEXT,
            completed_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_profiles (
            scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            profile TEXT NOT NULL,
            project_type TEXT NOT NULL,
            working_directory TEXT NOT NULL,
            executable TEXT NOT NULL,
            args_json TEXT NOT NULL,
            timeout_ms INTEGER NOT NULL DEFAULT 600000,
            enabled INTEGER NOT NULL DEFAULT 1,
            source TEXT NOT NULL DEFAULT 'detected',
            updated_at TEXT NOT NULL,
            PRIMARY KEY(scope_id, profile)
        );
        CREATE TABLE IF NOT EXISTS workspace_files (
            scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            relative_path TEXT NOT NULL,
            kind TEXT NOT NULL,
            language TEXT,
            size INTEGER NOT NULL,
            modified_ns INTEGER NOT NULL,
            content_hash TEXT,
            is_ignored INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(scope_id, relative_path)
        );
        CREATE TABLE IF NOT EXISTS workspace_symbols (
            scope_id TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            name TEXT NOT NULL,
            symbol_kind TEXT NOT NULL,
            line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            signature TEXT NOT NULL,
            FOREIGN KEY(scope_id, relative_path) REFERENCES workspace_files(scope_id, relative_path) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS workspace_index_runs (
            scope_id TEXT PRIMARY KEY REFERENCES scopes(id) ON DELETE CASCADE,
            state TEXT NOT NULL,
            file_count INTEGER NOT NULL DEFAULT 0,
            symbol_count INTEGER NOT NULL DEFAULT 0,
            truncated INTEGER NOT NULL DEFAULT 0,
            error_code TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workspace_capsules (
            scope_id TEXT PRIMARY KEY REFERENCES scopes(id) ON DELETE CASCADE,
            capsule_json TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            source TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workspace_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            snapshot_json TEXT NOT NULL,
            environment_fingerprint TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_workspace_snapshots_scope_created
            ON workspace_snapshots(scope_id, created_at DESC);
        CREATE TABLE IF NOT EXISTS workspace_runs (
            run_id TEXT PRIMARY KEY,
            scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            goal TEXT NOT NULL,
            mode TEXT NOT NULL,
            status TEXT NOT NULL,
            work_package_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            updated_at TEXT NOT NULL,
            last_error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_workspace_runs_scope_created
            ON workspace_runs(scope_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_workspace_runs_status_updated
            ON workspace_runs(status, updated_at DESC);
        CREATE TABLE IF NOT EXISTS workspace_evidence (
            evidence_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES workspace_runs(run_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
            sequence INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE(run_id, sequence)
        );
        CREATE INDEX IF NOT EXISTS idx_workspace_evidence_run_sequence
            ON workspace_evidence(run_id, sequence);
        CREATE TABLE IF NOT EXISTS workspace_handoffs (
            run_id TEXT PRIMARY KEY REFERENCES workspace_runs(run_id) ON DELETE CASCADE,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
        with self._lock:
            self._conn.executescript(schema)
            self._ensure_columns(
                "runtime_processes",
                {
            "timeout_ms": "INTEGER",
            "exit_code": "INTEGER",
            "scope_id": "TEXT",
            "owner_session_id": "TEXT",
                    "updated_at": "TEXT",
                    "command_digest": "TEXT",
                    "argv_json": "TEXT",
                },
            )
            self._ensure_columns(
                "audit_events",
                {"trace_id": "TEXT", "duration_ms": "INTEGER", "process_id": "TEXT"},
            )
            self._ensure_columns(
                "agent_tasks",
                {"source_dirty": "INTEGER", "source_head_commit": "TEXT"},
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('policy_version', '1')"
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('agent_runtime_schema', '1')"
            )
            now = utc_now()
            for definition in TOOL_DEFINITIONS:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO tool_policies
                    (tool_name, enabled, approval_mode, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        definition.name,
                        int(definition.default_enabled),
                        definition.default_approval,
                        now,
                    ),
                )
            self._ensure_capability_rows()
            self._normalize_approval_policy(now)
            self._conn.commit()

    def _ensure_columns(self, table: str, columns: dict[str, str]) -> None:
        existing = {
            row["name"]
            for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for name, declaration in columns.items():
            if name not in existing:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    def _ensure_capability_rows(self) -> None:
        scopes = self._conn.execute("SELECT id FROM scopes").fetchall()
        for scope in scopes:
            for capability in CAPABILITIES:
                self._conn.execute(
                    "INSERT OR IGNORE INTO scope_permissions"
                    "(scope_id, capability, allowed, approval_mode, max_bytes, max_items)"
                    " VALUES (?, ?, 0, ?, 1048576, 100)",
                    (
                        scope["id"],
                        capability,
                        "always" if capability == DELETE_CAPABILITY else "never",
                    ),
                )

    def _normalize_approval_policy(self, now: str) -> None:
        """Migrate older settings to the dangerous-operation approval boundary.

        Older versions required approval for every mutation and could leave the
        Control Center's apply tool disabled.  Keep the policy migration in the
        storage layer so an existing installation behaves consistently even when
        it is started from the CLI or MCP bridge instead of the GUI.
        """
        changed = 0
        browser_defaults_migrated = self._conn.execute(
            "SELECT value FROM meta WHERE key=?",
            (BROWSER_DEFAULTS_MIGRATION_KEY,),
        ).fetchone()
        if not browser_defaults_migrated:
            placeholders = ",".join("?" for _ in BROWSER_TOOL_NAMES)
            cursor = self._conn.execute(
                f"UPDATE tool_policies SET enabled=1, updated_at=? "
                f"WHERE tool_name IN ({placeholders}) AND enabled=0",
                (now, *sorted(BROWSER_TOOL_NAMES)),
            )
            changed += max(cursor.rowcount, 0)
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?)",
                (BROWSER_DEFAULTS_MIGRATION_KEY, "1"),
            )

        placeholders = ",".join("?" for _ in DANGEROUS_TOOLS)
        cursor = self._conn.execute(
            f"""
            UPDATE tool_policies
            SET approval_mode = CASE WHEN tool_name IN ({placeholders}) THEN 'always' ELSE 'never' END,
                updated_at = ?
            WHERE approval_mode != CASE WHEN tool_name IN ({placeholders}) THEN 'always' ELSE 'never' END
            """,
            (*sorted(DANGEROUS_TOOLS), now, *sorted(DANGEROUS_TOOLS)),
        )
        changed += max(cursor.rowcount, 0)

        # Applying a user-approved delete is a required control-center action.
        cursor = self._conn.execute(
            "UPDATE tool_policies SET enabled=1, updated_at=? "
            "WHERE tool_name='apply_approved_action' AND enabled=0",
            (now,),
        )
        changed += max(cursor.rowcount, 0)

        cursor = self._conn.execute(
            """
            UPDATE scope_permissions
            SET approval_mode = CASE WHEN capability = ? THEN 'always' ELSE 'never' END
            WHERE approval_mode != CASE WHEN capability = ? THEN 'always' ELSE 'never' END
            """,
            (DELETE_CAPABILITY, DELETE_CAPABILITY),
        )
        changed += max(cursor.rowcount, 0)

        # Never leave obsolete non-delete approvals actionable after the policy
        # changes.  The records remain in SQLite for auditability.
        rows = self._conn.execute(
            "SELECT id, intent_json FROM approval_requests WHERE status IN ('pending', 'approved')"
        ).fetchall()
        for row in rows:
            try:
                intent = json.loads(row["intent_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(intent, dict) and intent.get("tool") in DANGEROUS_TOOLS:
                continue
            cursor = self._conn.execute(
                """
                UPDATE approval_requests
                SET status='expired', decision_reason=?, decided_at=?
                WHERE id=? AND status IN ('pending', 'approved')
                """,
                ("policy migrated: approval is required for dangerous operations", now, row["id"]),
            )
            changed += max(cursor.rowcount, 0)

        if changed:
            row = self._conn.execute("SELECT value FROM meta WHERE key='policy_version'").fetchone()
            current = int(row["value"]) if row else 1
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('policy_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(current + 1),),
            )

    def _fetchone(self, query: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(query, tuple(params)).fetchone()

    def _fetchall(self, query: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(query, tuple(params)).fetchall())

    def policy_version(self) -> int:
        row = self._fetchone("SELECT value FROM meta WHERE key='policy_version'")
        return int(row["value"]) if row else 1

    def get_mcp_bridge_snapshot(self) -> dict[str, Any] | None:
        row = self._fetchone("SELECT value FROM meta WHERE key=?", (MCP_BRIDGE_SNAPSHOT_KEY,))
        if not row:
            return None
        try:
            value = json.loads(row["value"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError("MCP bridge snapshot is corrupted") from exc
        if not isinstance(value, dict):
            raise StorageError("MCP bridge snapshot must be an object")
        return value

    def set_mcp_bridge_snapshot(self, snapshot: dict[str, Any]) -> None:
        required = {"pid", "tool_count", "policy_version", "started_at"}
        if set(snapshot) != required:
            raise StorageError("MCP bridge snapshot has unsupported or missing fields")
        for field in ("pid", "tool_count", "policy_version"):
            value = snapshot[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise StorageError(f"MCP bridge snapshot field {field} must be a non-negative integer")
        if not isinstance(snapshot["started_at"], str) or not snapshot["started_at"]:
            raise StorageError("MCP bridge snapshot started_at must be text")
        encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (MCP_BRIDGE_SNAPSHOT_KEY, encoded),
            )
            self._conn.commit()

    def clear_mcp_bridge_snapshot(self, *, pid: int | None = None) -> None:
        with self._lock:
            if pid is not None:
                row = self._conn.execute(
                    "SELECT value FROM meta WHERE key=?",
                    (MCP_BRIDGE_SNAPSHOT_KEY,),
                ).fetchone()
                if not row:
                    return
                try:
                    snapshot = json.loads(row["value"])
                except (TypeError, json.JSONDecodeError):
                    return
                if not isinstance(snapshot, dict) or snapshot.get("pid") != pid:
                    return
            self._conn.execute("DELETE FROM meta WHERE key=?", (MCP_BRIDGE_SNAPSHOT_KEY,))
            self._conn.commit()

    def get_codex_thread_config(self) -> dict[str, Any] | None:
        """Local-only path grant; no Codex auth or transcript data is stored here."""
        row = self._fetchone("SELECT value FROM meta WHERE key='codex_thread_config'")
        if not row:
            return None
        try:
            value = json.loads(row["value"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError("Codex configuration is corrupted") from exc
        if not isinstance(value, dict):
            raise StorageError("Codex configuration must be an object")
        return value

    def set_codex_thread_config(self, config: dict[str, Any]) -> None:
        if set(config) not in ({"enabled"}, {"enabled", "executable", "codex_home"}) or type(config.get("enabled")) is not bool:
            raise StorageError("Codex configuration contains unsupported fields")
        encoded = json.dumps(config, ensure_ascii=False, sort_keys=True)
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('codex_thread_config', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (encoded,),
            )
            self._conn.commit()

    def get_tunnel_config(self) -> dict[str, Any] | None:
        """Return non-secret tunnel settings; the API key never lives in SQLite."""
        row = self._fetchone("SELECT value FROM meta WHERE key='tunnel_config'")
        if not row:
            return None
        try:
            value = json.loads(row["value"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError("tunnel configuration is corrupted") from exc
        if not isinstance(value, dict):
            raise StorageError("tunnel configuration must be an object")
        return value

    def set_tunnel_config(self, config: dict[str, Any]) -> None:
        """Persist only validated, non-secret tunnel settings."""
        if not isinstance(config, dict):
            raise StorageError("tunnel configuration must be an object")
        if "api_key" in config or "CONTROL_PLANE_API_KEY" in config:
            raise StorageError("tunnel API keys must be stored in macOS Keychain")
        encoded = json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('tunnel_config', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (encoded,),
            )
            self._conn.commit()

    def clear_tunnel_config(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM meta WHERE key='tunnel_config'")
            self._conn.commit()

    def bump_policy_version(self) -> int:
        with self._lock:
            current = self.policy_version() + 1
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('policy_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(current),),
            )
            self._conn.commit()
            return current

    def add_scope(self, scope: Scope, permissions: dict[str, dict[str, Any]] | None = None) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO scopes
                    (id, label, kind, root, enabled, expose_to_mcp, policy_version, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scope.id,
                        scope.label,
                        scope.kind,
                        scope.root,
                        int(scope.enabled),
                        int(scope.expose_to_mcp),
                        scope.policy_version,
                        scope.created_at,
                        scope.updated_at,
                    ),
                )
                permission_map = permissions or {"read": {"allowed": True, "approval_mode": "never"}}
                if not isinstance(permission_map, dict):
                    raise StorageError("permissions must be an object")
                for capability in CAPABILITIES:
                    raw = permission_map.get(capability, {})
                    if not isinstance(raw, dict):
                        raise StorageError(f"permission for {capability} must be an object")
                    approval_mode, max_bytes, max_items = self._validated_permission(raw)
                    approval_mode = "always" if capability == DELETE_CAPABILITY else "never"
                    self._conn.execute(
                        """
                        INSERT INTO scope_permissions
                        (scope_id, capability, allowed, approval_mode, max_bytes, max_items)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scope.id,
                            capability,
                            int(bool(raw.get("allowed", False))),
                            approval_mode,
                            max_bytes,
                            max_items,
                        ),
                    )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise StorageError(str(exc)) from exc

    def get_scope(self, scope_id: str) -> Scope | None:
        row = self._fetchone("SELECT * FROM scopes WHERE id=?", (scope_id,))
        return self._scope_from_row(row) if row else None

    def list_scopes(self, include_disabled: bool = True) -> list[Scope]:
        query = "SELECT * FROM scopes"
        params: tuple[Any, ...] = ()
        if not include_disabled:
            query += " WHERE enabled=1"
        query += " ORDER BY label COLLATE NOCASE"
        return [self._scope_from_row(row) for row in self._fetchall(query, params)]

    @staticmethod
    def _scope_from_row(row: sqlite3.Row) -> Scope:
        return Scope(
            id=row["id"],
            label=row["label"],
            kind=row["kind"],
            root=row["root"],
            enabled=bool(row["enabled"]),
            expose_to_mcp=bool(row["expose_to_mcp"]),
            policy_version=int(row["policy_version"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def update_scope(self, scope_id: str, **changes: Any) -> Scope:
        allowed = {"label", "enabled", "expose_to_mcp"}
        unknown = set(changes) - allowed
        if unknown:
            raise StorageError(f"Unsupported scope fields: {sorted(unknown)}")
        scope = self.get_scope(scope_id)
        if not scope:
            raise StorageError(f"Scope not found: {scope_id}")
        changes["updated_at"] = utc_now()
        fields = ", ".join(f"{key}=?" for key in changes)
        params = [int(value) if isinstance(value, bool) else value for value in changes.values()]
        params.append(scope_id)
        with self._lock:
            self._conn.execute(f"UPDATE scopes SET {fields} WHERE id=?", params)
            self._conn.commit()
        return self.get_scope(scope_id)  # type: ignore[return-value]

    def delete_scope(self, scope_id: str) -> None:
        with self._lock:
            try:
                # Explicit cleanup keeps scope removal compatible with
                # databases created before these tables used cascading FKs.
                self._conn.execute(
                    "DELETE FROM workspace_handoffs WHERE run_id IN "
                    "(SELECT run_id FROM workspace_runs WHERE scope_id=?)",
                    (scope_id,),
                )
                self._conn.execute(
                    "DELETE FROM workspace_evidence WHERE run_id IN "
                    "(SELECT run_id FROM workspace_runs WHERE scope_id=?)",
                    (scope_id,),
                )
                self._conn.execute("DELETE FROM workspace_runs WHERE scope_id=?", (scope_id,))
                self._conn.execute("DELETE FROM workspace_snapshots WHERE scope_id=?", (scope_id,))
                self._conn.execute("DELETE FROM workspace_capsules WHERE scope_id=?", (scope_id,))
                self._conn.execute("DELETE FROM scopes WHERE id=?", (scope_id,))
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise StorageError("scope is referenced by persisted runtime state") from exc

    def permissions(self, scope_id: str) -> dict[str, dict[str, Any]]:
        rows = self._fetchall(
            "SELECT capability, allowed, approval_mode, max_bytes, max_items FROM scope_permissions WHERE scope_id=?",
            (scope_id,),
        )
        return {
            row["capability"]: {
                "allowed": bool(row["allowed"]),
                "approval_mode": row["approval_mode"],
                "max_bytes": int(row["max_bytes"]),
                "max_items": int(row["max_items"]),
            }
            for row in rows
        }

    def set_permission(
        self,
        scope_id: str,
        capability: str,
        *,
        allowed: bool,
        approval_mode: str | None = None,
        max_bytes: int = 1_048_576,
        max_items: int = 100,
    ) -> None:
        if capability not in CAPABILITIES:
            raise StorageError(f"Unknown capability: {capability}")
        requested_approval_mode = approval_mode or (
            "always" if capability == DELETE_CAPABILITY else "never"
        )
        approval_mode, max_bytes, max_items = self._validated_permission(
            {
                "approval_mode": requested_approval_mode,
                "max_bytes": max_bytes,
                "max_items": max_items,
            }
        )
        approval_mode = "always" if capability == DELETE_CAPABILITY else "never"
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scope_permissions(scope_id, capability, allowed, approval_mode, max_bytes, max_items)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope_id, capability) DO UPDATE SET
                  allowed=excluded.allowed,
                  approval_mode=excluded.approval_mode,
                  max_bytes=excluded.max_bytes,
                  max_items=excluded.max_items
                """,
                (scope_id, capability, int(allowed), approval_mode, max_bytes, max_items),
            )
            self._conn.commit()

    @staticmethod
    def _validated_permission(raw: dict[str, Any]) -> tuple[str, int, int]:
        approval_mode = str(raw.get("approval_mode", "never"))
        if approval_mode not in APPROVAL_MODES:
            raise StorageError(f"Unknown approval mode: {approval_mode}")
        try:
            max_bytes = int(raw.get("max_bytes", 1_048_576))
            max_items = int(raw.get("max_items", 100))
        except (TypeError, ValueError) as exc:
            raise StorageError("Permission quotas must be integers") from exc
        if not 1 <= max_bytes <= 100 * 1024 * 1024:
            raise StorageError("max_bytes must be between 1 and 104857600")
        if not 1 <= max_items <= 100_000:
            raise StorageError("max_items must be between 1 and 100000")
        return approval_mode, max_bytes, max_items

    def get_tool_policy(self, tool_name: str) -> ToolPolicy | None:
        row = self._fetchone("SELECT * FROM tool_policies WHERE tool_name=?", (tool_name,))
        if not row:
            return None
        return ToolPolicy(
            tool_name=row["tool_name"],
            enabled=bool(row["enabled"]),
            approval_mode=row["approval_mode"],
            max_duration_ms=int(row["max_duration_ms"]),
            output_limit_bytes=int(row["output_limit_bytes"]),
            updated_at=row["updated_at"],
        )

    def list_tool_policies(self) -> list[ToolPolicy]:
        return [
            self.get_tool_policy(row["tool_name"])  # type: ignore[misc]
            for row in self._fetchall("SELECT tool_name FROM tool_policies ORDER BY tool_name")
        ]

    def set_tool_policy(
        self,
        tool_name: str,
        *,
        enabled: bool,
        approval_mode: str,
        max_duration_ms: int | None = None,
        output_limit_bytes: int | None = None,
    ) -> ToolPolicy:
        if not self.get_tool_policy(tool_name):
            raise StorageError(f"Unknown tool: {tool_name}")
        current = self.get_tool_policy(tool_name)
        assert current is not None
        if approval_mode not in APPROVAL_MODES:
            raise StorageError(f"Unknown approval mode: {approval_mode}")
        effective_approval_mode = "always" if tool_name in DANGEROUS_TOOLS else "never"
        duration = current.max_duration_ms if max_duration_ms is None else int(max_duration_ms)
        output_limit = current.output_limit_bytes if output_limit_bytes is None else int(output_limit_bytes)
        if not 1 <= duration <= 3_600_000:
            raise StorageError("max_duration_ms must be between 1 and 3600000")
        if not 1 <= output_limit <= 1_048_576:
            raise StorageError("output_limit_bytes must be between 1 and 1048576")
        with self._lock:
            self._conn.execute(
                """
                UPDATE tool_policies
                SET enabled=?, approval_mode=?, max_duration_ms=?, output_limit_bytes=?, updated_at=?
                WHERE tool_name=?
                """,
                (
                    int(enabled),
                    effective_approval_mode,
                    duration,
                    output_limit,
                    utc_now(),
                    tool_name,
                ),
            )
            self._conn.commit()
        return self.get_tool_policy(tool_name)  # type: ignore[return-value]

    def create_approval(self, request: ApprovalRequest) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO approval_requests
                (id, action_hash, status, intent_json, payload_json, policy_version, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.id,
                    request.action_hash,
                    request.status,
                    json.dumps(request.intent, sort_keys=True, separators=(",", ":")),
                    json.dumps(request.payload, sort_keys=True, separators=(",", ":")),
                    request.policy_version,
                    request.expires_at,
                ),
            )
            self._conn.commit()

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        row = self._fetchone("SELECT * FROM approval_requests WHERE id=?", (approval_id,))
        return self._approval_from_row(row) if row else None

    def list_approvals(self, statuses: tuple[str, ...] = ("pending",)) -> list[ApprovalRequest]:
        placeholders = ",".join("?" for _ in statuses)
        rows = self._fetchall(
            f"SELECT * FROM approval_requests WHERE status IN ({placeholders}) ORDER BY expires_at",
            statuses,
        )
        return [self._approval_from_row(row) for row in rows]

    @staticmethod
    def _approval_from_row(row: sqlite3.Row) -> ApprovalRequest:
        return ApprovalRequest(
            id=row["id"],
            action_hash=row["action_hash"],
            status=row["status"],
            intent=json.loads(row["intent_json"]),
            payload=json.loads(row["payload_json"]),
            policy_version=int(row["policy_version"]),
            expires_at=row["expires_at"],
            decision_reason=row["decision_reason"],
            decided_at=row["decided_at"],
            consumed_at=row["consumed_at"],
        )

    def decide_approval(
        self,
        approval_id: str,
        status: str,
        reason: str | None = None,
        *,
        expected_status: str | None = None,
    ) -> bool:
        with self._lock:
            query = "UPDATE approval_requests SET status=?, decision_reason=?, decided_at=? WHERE id=?"
            params: list[Any] = [status, reason, utc_now(), approval_id]
            if expected_status is not None:
                query += " AND status=?"
                params.append(expected_status)
            cursor = self._conn.execute(query, params)
            self._conn.commit()
            return cursor.rowcount == 1

    def consume_approval(self, approval_id: str) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE approval_requests SET status='consumed', consumed_at=? "
                "WHERE id=? AND status='approved'",
                (utc_now(), approval_id),
            )
            self._conn.commit()
            return cursor.rowcount == 1

    def upsert_runtime(self, data: dict[str, Any]) -> None:
        fields = {
            "id", "kind", "profile", "pid", "pgid", "state", "started_at", "stopped_at", "log_path",
            "timeout_ms", "exit_code", "scope_id", "owner_session_id", "updated_at", "command_digest", "argv_json",
        }
        if set(data) - fields:
            raise StorageError("Unsupported runtime fields")
        columns = ", ".join(data)
        placeholders = ", ".join("?" for _ in data)
        updates = ", ".join(f"{key}=excluded.{key}" for key in data if key != "id")
        with self._lock:
            self._conn.execute(
                f"INSERT INTO runtime_processes ({columns}) VALUES ({placeholders}) "
                f"ON CONFLICT(id) DO UPDATE SET {updates}",
                tuple(data.values()),
            )
            self._conn.commit()

    def list_runtime(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._fetchall("SELECT * FROM runtime_processes ORDER BY kind")]

    # ---- DevOS workspace engine -------------------------------------------

    def upsert_workspace_capsule(
        self,
        scope_id: str,
        capsule: dict[str, Any],
        *,
        content_hash: str,
        source: str = "control-plane",
    ) -> None:
        encoded = json.dumps(capsule, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 262_144:
            raise StorageError("workspace capsule exceeds 256 KiB")
        if not isinstance(content_hash, str) or not content_hash:
            raise StorageError("workspace capsule content hash is required")
        if not isinstance(source, str) or not source or len(source) > 120:
            raise StorageError("workspace capsule source is invalid")
        with self._lock:
            self._conn.execute(
                "INSERT INTO workspace_capsules(scope_id, capsule_json, content_hash, source, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(scope_id) DO UPDATE SET capsule_json=excluded.capsule_json, "
                "content_hash=excluded.content_hash, source=excluded.source, updated_at=excluded.updated_at",
                (scope_id, encoded, content_hash, source, utc_now()),
            )
            self._conn.commit()

    def get_workspace_capsule(self, scope_id: str) -> dict[str, Any] | None:
        row = self._fetchone(
            "SELECT capsule_json, content_hash, source, updated_at FROM workspace_capsules WHERE scope_id=?",
            (scope_id,),
        )
        if not row:
            return None
        try:
            capsule = json.loads(row["capsule_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError("workspace capsule is corrupted") from exc
        if not isinstance(capsule, dict):
            raise StorageError("workspace capsule must be an object")
        return {
            "capsule": capsule,
            "content_hash": row["content_hash"],
            "source": row["source"],
            "updated_at": row["updated_at"],
        }

    def save_workspace_snapshot(
        self,
        snapshot_id: str,
        scope_id: str,
        snapshot: dict[str, Any],
        *,
        environment_fingerprint: str,
        created_at: str | None = None,
    ) -> None:
        encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 2_000_000:
            raise StorageError("workspace snapshot exceeds 2 MiB")
        if not snapshot_id or not scope_id or not environment_fingerprint:
            raise StorageError("workspace snapshot identity is incomplete")
        with self._lock:
            self._conn.execute(
                "INSERT INTO workspace_snapshots"
                "(snapshot_id, scope_id, snapshot_json, environment_fingerprint, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (snapshot_id, scope_id, encoded, environment_fingerprint, created_at or utc_now()),
            )
            self._conn.commit()

    def get_workspace_snapshot(self, snapshot_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM workspace_snapshots WHERE snapshot_id=?", (snapshot_id,))
        return self._decode_workspace_snapshot(row) if row else None

    def latest_workspace_snapshot(self, scope_id: str) -> dict[str, Any] | None:
        row = self._fetchone(
            "SELECT * FROM workspace_snapshots WHERE scope_id=? ORDER BY created_at DESC LIMIT 1",
            (scope_id,),
        )
        return self._decode_workspace_snapshot(row) if row else None

    @staticmethod
    def _decode_workspace_snapshot(row: sqlite3.Row) -> dict[str, Any]:
        try:
            snapshot = json.loads(row["snapshot_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError("workspace snapshot is corrupted") from exc
        if not isinstance(snapshot, dict):
            raise StorageError("workspace snapshot must be an object")
        return {
            "snapshot_id": row["snapshot_id"],
            "scope_id": row["scope_id"],
            "snapshot": snapshot,
            "environment_fingerprint": row["environment_fingerprint"],
            "created_at": row["created_at"],
        }

    def create_workspace_run(self, data: dict[str, Any]) -> None:
        fields = {
            "run_id", "scope_id", "goal", "mode", "status", "work_package_json",
            "created_at", "started_at", "completed_at", "updated_at", "last_error",
        }
        required = fields - {"started_at", "completed_at", "last_error"}
        if set(data) - fields or not required.issubset(data):
            raise StorageError("unsupported or incomplete workspace run fields")
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO workspace_runs"
                    "(run_id, scope_id, goal, mode, status, work_package_json, created_at, started_at, completed_at, updated_at, last_error)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    tuple(data.get(key) for key in (
                        "run_id", "scope_id", "goal", "mode", "status", "work_package_json",
                        "created_at", "started_at", "completed_at", "updated_at", "last_error",
                    )),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise StorageError(str(exc)) from exc

    def get_workspace_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM workspace_runs WHERE run_id=?", (run_id,))
        return dict(row) if row else None

    def list_workspace_runs(
        self,
        *,
        scope_id: str | None = None,
        statuses: tuple[str, ...] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if scope_id is not None:
            clauses.append("scope_id=?")
            params.append(scope_id)
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(statuses)
        query = "SELECT * FROM workspace_runs"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 100)))
        return [dict(row) for row in self._fetchall(query, params)]

    def update_workspace_run(self, run_id: str, **changes: Any) -> None:
        allowed = {"status", "work_package_json", "started_at", "completed_at", "updated_at", "last_error"}
        unknown = set(changes) - allowed
        if unknown:
            raise StorageError(f"unsupported workspace run fields: {sorted(unknown)}")
        if not changes:
            return
        changes.setdefault("updated_at", utc_now())
        fields = ", ".join(f"{key}=?" for key in changes)
        with self._lock:
            self._conn.execute(
                f"UPDATE workspace_runs SET {fields} WHERE run_id=?",
                (*changes.values(), run_id),
            )
            self._conn.commit()

    def append_workspace_evidence(self, data: dict[str, Any]) -> dict[str, Any]:
        fields = {"evidence_id", "run_id", "event_type", "payload_json", "payload_hash", "recorded_at"}
        if set(data) != fields:
            raise StorageError("unsupported or incomplete workspace evidence fields")
        if len(str(data["payload_json"]).encode("utf-8")) > 256_000:
            raise StorageError("workspace evidence payload exceeds 256 KiB")
        with self._lock:
            run = self._conn.execute(
                "SELECT status FROM workspace_runs WHERE run_id=?",
                (data["run_id"],),
            ).fetchone()
            if run is None:
                raise StorageError("workspace run was not found")
            if run["status"] == "completed":
                raise StorageError("completed workspace runs are immutable")
            row = self._conn.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM workspace_evidence WHERE run_id=?",
                (data["run_id"],),
            ).fetchone()
            sequence = int(row["next_sequence"])
            try:
                payload = json.loads(data["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise StorageError("workspace evidence payload must be valid JSON") from exc
            if not isinstance(payload, dict):
                raise StorageError("workspace evidence payload must be an object")
            payload_hash = _workspace_evidence_hash(
                str(data["run_id"]), sequence, str(data["event_type"]), payload
            )
            self._conn.execute(
                "INSERT INTO workspace_evidence"
                "(evidence_id, run_id, sequence, event_type, payload_json, payload_hash, recorded_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    data["evidence_id"], data["run_id"], sequence, data["event_type"],
                    data["payload_json"], payload_hash, data["recorded_at"],
                ),
            )
            self._conn.commit()
        return {**data, "sequence": sequence, "payload_hash": payload_hash}

    def workspace_evidence(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._fetchall(
            "SELECT * FROM workspace_evidence WHERE run_id=? ORDER BY sequence",
            (run_id,),
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise StorageError("workspace evidence is corrupted") from exc
            if not isinstance(payload, dict):
                raise StorageError("workspace evidence payload must be an object")
            expected_hash = _workspace_evidence_hash(
                str(row["run_id"]), int(row["sequence"]), str(row["event_type"]), payload
            )
            if row["payload_hash"] != expected_hash:
                raise StorageError("workspace evidence hash mismatch")
            result.append({
                "evidence_id": row["evidence_id"],
                "run_id": row["run_id"],
                "sequence": int(row["sequence"]),
                "event_type": row["event_type"],
                "payload": payload,
                "payload_hash": row["payload_hash"],
                "recorded_at": row["recorded_at"],
            })
        return result

    def save_workspace_handoff(
        self,
        run_id: str,
        report: dict[str, Any],
        *,
        created_at: str | None = None,
    ) -> None:
        encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 1_000_000:
            raise StorageError("workspace handoff exceeds 1 MiB")
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO workspace_handoffs(run_id, report_json, created_at) VALUES (?, ?, ?)",
                    (run_id, encoded, created_at or utc_now()),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise StorageError(str(exc)) from exc

    def get_workspace_handoff(self, run_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM workspace_handoffs WHERE run_id=?", (run_id,))
        if not row:
            return None
        try:
            report = json.loads(row["report_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError("workspace handoff is corrupted") from exc
        if not isinstance(report, dict):
            raise StorageError("workspace handoff must be an object")
        return {"run_id": row["run_id"], "report": report, "created_at": row["created_at"]}

    # ---- provider-backed agent runtime ------------------------------------

    def create_agent_task(self, data: dict[str, Any]) -> None:
        fields = {
            "task_id", "parent_task_id", "root_task_id", "role", "task_text", "scope_id",
            "effective_scope_id", "model_profile", "provider", "model", "status", "base_ref",
            "base_commit", "worktree_path", "source_dirty", "source_head_commit", "capability_json", "owner_actor", "owner_session_id",
            "created_at", "started_at", "completed_at", "updated_at", "error_code",
        }
        required = fields - {"parent_task_id", "base_ref", "base_commit", "worktree_path", "source_dirty", "source_head_commit", "started_at", "completed_at", "error_code"}
        if set(data) - fields or not required.issubset(data):
            raise StorageError("Unsupported or incomplete agent task fields")
        columns = ", ".join(data)
        placeholders = ", ".join("?" for _ in data)
        with self._lock:
            try:
                self._conn.execute(
                    f"INSERT INTO agent_tasks ({columns}) VALUES ({placeholders})",
                    tuple(data.values()),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise StorageError(str(exc)) from exc

    def get_agent_task(self, task_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM agent_tasks WHERE task_id=?", (task_id,))
        return dict(row) if row else None

    def list_agent_tasks(
        self,
        *,
        scope_id: str | None = None,
        status: str | None = None,
        statuses: tuple[str, ...] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 1000))
        clauses: list[str] = []
        params: list[Any] = []
        if scope_id is not None:
            clauses.append("scope_id=?")
            params.append(scope_id)
        selected_statuses = statuses
        if status is not None:
            selected_statuses = (status,)
        if selected_statuses:
            placeholders = ",".join("?" for _ in selected_statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(selected_statuses)
        query = "SELECT * FROM agent_tasks"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(bounded_limit)
        return [dict(row) for row in self._fetchall(query, params)]

    def count_agent_tasks(
        self,
        *,
        root_task_id: str | None = None,
        statuses: tuple[str, ...] | None = None,
    ) -> int:
        clauses: list[str] = []
        params: list[Any] = []
        if root_task_id is not None:
            clauses.append("root_task_id=?")
            params.append(root_task_id)
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(statuses)
        query = "SELECT COUNT(*) AS count FROM agent_tasks"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        row = self._fetchone(query, params)
        return int(row["count"]) if row else 0

    def update_agent_task(self, task_id: str, **changes: Any) -> None:
        allowed = {
            "parent_task_id", "root_task_id", "role", "task_text", "scope_id", "effective_scope_id",
            "model_profile", "provider", "model", "status", "base_ref", "base_commit",
            "worktree_path", "source_dirty", "source_head_commit", "capability_json", "owner_actor", "owner_session_id", "created_at",
            "started_at", "completed_at", "updated_at", "error_code",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise StorageError(f"Unsupported agent task fields: {sorted(unknown)}")
        if not changes:
            return
        changes.setdefault("updated_at", utc_now())
        fields = ", ".join(f"{key}=?" for key in changes)
        params = list(changes.values()) + [task_id]
        with self._lock:
            self._conn.execute(f"UPDATE agent_tasks SET {fields} WHERE task_id=?", params)
            self._conn.commit()

    def transition_agent_task(
        self,
        task_id: str,
        *,
        expected_statuses: tuple[str, ...],
        status: str,
        **changes: Any,
    ) -> bool:
        if not expected_statuses:
            raise StorageError("agent task transition requires an expected status")
        allowed = {"status", "started_at", "completed_at", "updated_at", "error_code"}
        if set(changes) - allowed:
            raise StorageError("Unsupported agent task transition fields")
        changes = {"status": status, **changes}
        changes.setdefault("updated_at", utc_now())
        fields = ", ".join(f"{key}=?" for key in changes)
        placeholders = ",".join("?" for _ in expected_statuses)
        params = list(changes.values()) + [task_id, *expected_statuses]
        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE agent_tasks SET {fields} WHERE task_id=? AND status IN ({placeholders})",
                params,
            )
            self._conn.commit()
            return cursor.rowcount == 1

    def save_agent_result(self, task_id: str, data: dict[str, Any]) -> None:
        fields = {
            "status", "summary", "changed_files_json", "verification_json", "tests_json",
            "worktree_json", "provider", "model", "warnings_json", "errors_json", "tool_calls",
            "started_at", "completed_at",
        }
        required = fields - {"worktree_json", "provider", "model", "started_at"}
        if set(data) - fields or not required.issubset(data):
            raise StorageError("Unsupported or incomplete agent result fields")
        values = {"task_id": task_id, "updated_at": utc_now(), **data}
        with self._lock:
            self._conn.execute(
                "INSERT INTO agent_results"
                " (task_id, status, summary, changed_files_json, verification_json, tests_json, worktree_json, provider, model, warnings_json, errors_json, tool_calls, started_at, completed_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(task_id) DO UPDATE SET"
                " status=excluded.status, summary=excluded.summary, changed_files_json=excluded.changed_files_json,"
                " verification_json=excluded.verification_json, tests_json=excluded.tests_json, worktree_json=excluded.worktree_json,"
                " provider=excluded.provider, model=excluded.model, warnings_json=excluded.warnings_json, errors_json=excluded.errors_json,"
                " tool_calls=excluded.tool_calls, started_at=excluded.started_at, completed_at=excluded.completed_at, updated_at=excluded.updated_at",
                tuple(values[key] for key in (
                    "task_id", "status", "summary", "changed_files_json", "verification_json", "tests_json",
                    "worktree_json", "provider", "model", "warnings_json", "errors_json", "tool_calls",
                    "started_at", "completed_at", "updated_at",
                )),
            )
            self._conn.commit()

    def get_agent_result(self, task_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM agent_results WHERE task_id=?", (task_id,))
        if not row:
            return None

        def decode(name: str, default: Any) -> Any:
            value = row[name]
            if value is None:
                return default
            try:
                return json.loads(value)
            except (TypeError, json.JSONDecodeError):
                return default

        return {
            "task_id": task_id,
            "status": row["status"],
            "summary": row["summary"],
            "changed_files": decode("changed_files_json", []),
            "verification": decode("verification_json", []),
            "tests": decode("tests_json", []),
            "worktree": decode("worktree_json", None),
            "base_commit": None,
            "provider": row["provider"],
            "model": row["model"],
            "warnings": decode("warnings_json", []),
            "errors": decode("errors_json", []),
            "tool_calls": int(row["tool_calls"]),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }

    def get_runtime(self, kind: str) -> dict[str, Any] | None:
        row = self._fetchone(
            "SELECT * FROM runtime_processes WHERE kind=? ORDER BY id LIMIT 1",
            (kind,),
        )
        return dict(row) if row else None

    def get_runtime_by_id(self, process_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM runtime_processes WHERE id=?", (process_id,))
        return dict(row) if row else None

    def update_runtime_state(self, kind: str, state: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runtime_processes SET state=? WHERE kind=?",
                (state, kind),
            )
            self._conn.commit()

    def update_runtime(self, process_id: str, **changes: Any) -> None:
        allowed = {
            "kind", "profile", "pid", "pgid", "state", "started_at", "stopped_at", "log_path",
            "timeout_ms", "exit_code", "owner_session_id", "updated_at", "command_digest", "argv_json",
            "scope_id",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise StorageError(f"Unsupported runtime fields: {sorted(unknown)}")
        if not changes:
            return
        changes.setdefault("updated_at", utc_now())
        fields = ", ".join(f"{key}=?" for key in changes)
        params = list(changes.values()) + [process_id]
        with self._lock:
            self._conn.execute(f"UPDATE runtime_processes SET {fields} WHERE id=?", params)
            self._conn.commit()

    def upsert_project_profile(self, data: dict[str, Any]) -> None:
        fields = {
            "scope_id", "profile", "project_type", "working_directory", "executable", "args_json",
            "timeout_ms", "enabled", "source", "updated_at",
        }
        required = {"scope_id", "profile", "project_type", "working_directory", "executable", "args_json"}
        if set(data) - fields or not required.issubset(data):
            raise StorageError("Unsupported project profile fields")
        values = {"timeout_ms": 600_000, "enabled": 1, "source": "detected", "updated_at": utc_now(), **data}
        with self._lock:
            self._conn.execute(
                "INSERT INTO project_profiles"
                "(scope_id, profile, project_type, working_directory, executable, args_json, timeout_ms, enabled, source, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(scope_id, profile) DO UPDATE SET"
                " project_type=excluded.project_type, working_directory=excluded.working_directory,"
                " executable=excluded.executable, args_json=excluded.args_json, timeout_ms=excluded.timeout_ms,"
                " enabled=excluded.enabled, source=excluded.source, updated_at=excluded.updated_at",
                tuple(values[key] for key in (
                    "scope_id", "profile", "project_type", "working_directory", "executable",
                    "args_json", "timeout_ms", "enabled", "source", "updated_at",
                )),
            )
            self._conn.commit()

    def list_project_profiles(self, scope_id: str | None = None) -> list[dict[str, Any]]:
        if scope_id is None:
            rows = self._fetchall("SELECT * FROM project_profiles ORDER BY scope_id, profile")
        else:
            rows = self._fetchall(
                "SELECT * FROM project_profiles WHERE scope_id=? ORDER BY profile",
                (scope_id,),
            )
        return [dict(row) for row in rows]

    def delete_project_profiles(self, scope_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM project_profiles WHERE scope_id=?", (scope_id,))
            self._conn.commit()

    def replace_workspace_index(
        self,
        scope_id: str,
        files: list[dict[str, Any]],
        symbols: list[dict[str, Any]],
        *,
        truncated: bool = False,
        error_code: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM workspace_symbols WHERE scope_id=?", (scope_id,))
            self._conn.execute("DELETE FROM workspace_files WHERE scope_id=?", (scope_id,))
            for item in files:
                self._conn.execute(
                    "INSERT INTO workspace_files"
                    "(scope_id, relative_path, kind, language, size, modified_ns, content_hash, is_ignored, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        scope_id, item["relative_path"], item["kind"], item.get("language"), item["size"],
                        item["modified_ns"], item.get("content_hash"), int(bool(item.get("is_ignored", False))), utc_now(),
                    ),
                )
            for item in symbols:
                self._conn.execute(
                    "INSERT INTO workspace_symbols"
                    "(scope_id, relative_path, name, symbol_kind, line, end_line, signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        scope_id, item["relative_path"], item["name"], item["symbol_kind"],
                        item["line"], item.get("end_line", item["line"]), item.get("signature", ""),
                    ),
                )
            self._conn.execute(
                "INSERT INTO workspace_index_runs"
                "(scope_id, state, file_count, symbol_count, truncated, error_code, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(scope_id) DO UPDATE SET"
                " state=excluded.state, file_count=excluded.file_count, symbol_count=excluded.symbol_count,"
                " truncated=excluded.truncated, error_code=excluded.error_code, updated_at=excluded.updated_at",
                (
                    scope_id,
                    "partial" if truncated else "ready",
                    len(files),
                    len(symbols),
                    int(truncated),
                    error_code,
                    utc_now(),
                ),
            )
            self._conn.commit()

    def workspace_index_rows(self, scope_id: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self._fetchall(
                "SELECT * FROM workspace_files WHERE scope_id=? ORDER BY relative_path",
                (scope_id,),
            )
        ]

    def workspace_symbol_rows(self, scope_id: str, *, name: str | None = None) -> list[dict[str, Any]]:
        if name is None:
            rows = self._fetchall(
                "SELECT * FROM workspace_symbols WHERE scope_id=? ORDER BY relative_path, line, name",
                (scope_id,),
            )
        else:
            rows = self._fetchall(
                "SELECT * FROM workspace_symbols WHERE scope_id=? AND name=? ORDER BY relative_path, line",
                (scope_id, name),
            )
        return [dict(row) for row in rows]

    def workspace_index_status(self, scope_id: str | None = None) -> list[dict[str, Any]]:
        query = (
            "SELECT r.scope_id, r.state, r.file_count, r.symbol_count, r.truncated, r.error_code, r.updated_at, "
            "COALESCE(SUM(CASE WHEN f.kind='file' THEN 1 ELSE 0 END), 0) AS regular_file_count "
            "FROM workspace_index_runs r LEFT JOIN workspace_files f ON f.scope_id=r.scope_id"
        )
        params: tuple[Any, ...] = ()
        if scope_id is not None:
            query += " WHERE r.scope_id=?"
            params = (scope_id,)
        query += " GROUP BY r.scope_id, r.state, r.file_count, r.symbol_count, r.truncated, r.error_code, r.updated_at ORDER BY r.scope_id"
        return [dict(row) for row in self._fetchall(query, params)]

    def audit_rows(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._fetchall(
            "SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?",
            (max(1, min(limit, 1000)),),
        )
        return [dict(row) for row in rows]
