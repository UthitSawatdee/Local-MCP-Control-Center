# OVERNIGHT STATUS

`PARTIAL`

Foundation through P4-T02 approval integration is implemented. Controlled operations remain opt-in and approval-gated; P4-T03 through P4-T06 user-facing service/verification/commit/push flows remain deferred.

## COMPLETED

- Phase 0: repository reconciliation, scope/safety rules, plan, and resumable checkpoint.
- Phase 1: Project Registry reuse, validated Capsule persistence, bounded Snapshot observer, Broker/MCP/CLI adapters, and read-only health UI.
- Phase 2: bounded impact/dependency metadata, WorkPackage, scope boundary, test mapping, and persisted WorkRun.
- Phase 3: append-only Flight Recorder, normalized evidence, fixed-runner provenance guard, handoff report, CLI/MCP status surface.
- P4-T01: read-only ActionProposal view backed by existing approval records.
- P4-T02: opt-in approval integration for exact owned-service, targeted-verification, commit, and push proposals through the existing Broker approval/apply seam.

## IMPLEMENTED

- `WorkspaceEngine.observe/prepare/record/finish` with persisted snapshots, runs, evidence, and handoffs.
- Existing `scopes` remain the canonical Project Registry; no duplicate project subsystem was added.
- Capsule input is bounded and rejects unknown, credential-shaped, unsafe branch/path, and non-local health configuration.
- Git/runtime/service/process/filesystem metadata is bounded and secret-content-free. Runtime version probes use trusted host binaries only.
- Baseline, in-scope, out-of-scope, protected, and attribution-uncertain changes are reported separately.
- Evidence payloads are normalized, hashed with run/sequence/event identity, and fail closed on tampering. Plain caller-supplied test status cannot mark a handoff verified.
- Public MCP tools: `workspace_observe`, `workspace_prepare`, `workspace_run_status`, `workspace_finish`, `workspace_action_proposals`, plus opt-in `workspace_propose_action`.
- CLI commands: `doctor`, `observe`, `prepare`, `run-status`, `finish`, `action-proposals`, and `propose-action`.

## ARCHITECTURE

The engine composes the existing Store, Policy/Broker, SafeFilesystem, FixedRunner, dependency graph, and AuditLog. Adapters remain thin. P4-T02 exposes no generic executor: `workspace_propose_action` only creates exact approval records, while `apply_approved_action` remains the sole execution seam and FixedRunner results remain the only source of verified execution evidence.

## VERIFIED

- Baseline before this implementation: `110 passed`.
- Pre-P4-T02 targeted suite: `tests/test_workspace_engine.py tests/test_gui_ux.py` — `19 passed`.
- Pre-P4-T02 full suite — `128 passed`.
- Pre-P4-T02 `compileall` — pass.
- Pre-P4-T02 `git diff --check` — pass.
- P4-T02 current full suite through the managed `backend_pytest` project profile — `136 passed`, exit code `0`.
- P4-T02 current source/test trailing-whitespace scan (`[ \\t]+$`) — no findings.

Live external MCP, tunnel, Portal timeline, and user-project runtime validation were not run.

## FILES CHANGED

DevOS core: `src/local_mcp_control_center/workspace_engine.py`, `storage.py`, `runner.py`, `git_adapter.py`, `registry.py`, `broker.py`, `mcp_server.py`, `cli.py`.

UI/docs/tests: `gui.py`, `README.md`, `ARCHITECTURE.md`, `.agents/runtime/devos-20260901.yml`, `docs/DEVOS_IMPLEMENTATION_PLAN.md`, `docs/bug-log.md`, this report, `tests/test_workspace_engine.py`, `tests/test_workspace_controlled_actions.py`, `tests/test_workspace_controlled_adapters.py`, and additive health coverage in `tests/test_gui_ux.py`.

Pre-existing dirty changes were preserved, including provider-backed agent runtime, supervisor/tunnel/UI tests, scripts, and untracked UI/test files. Mixed files retain their unrelated changes.

## DATABASE / MIGRATION

No external migration was added. Store initialization additively creates Workspace Capsule, Snapshot, WorkRun, Evidence, and Handoff tables with foreign-key cleanup; scope removal explicitly cleans dependent metadata for compatibility.

## SECURITY / SAFETY

Read-only is the default. Broker/PolicyEngine remains the authorization seam. `workspace_propose_action` is disabled by default and cannot execute directly; every controlled proposal forces exact approval, rechecks the low-level tool and execute capability before proposal and apply, binds WorkRun/action/scope/payload/preconditions/policy version, excludes pre-existing dirty commit paths, records verification only from FixedRunner results, and binds push to exact branch + HEAD. No secret access, arbitrary shell, force push, cleanup, merge, automatic commit/push, or policy weakening was added.

## BUGS DISCOVERED

See [docs/bug-log.md](bug-log.md). No open bug remains from this bounded implementation; the log records the repaired safety and attribution cases.

## PENDING APPROVAL

No commit or push was performed. Any commit, push, controlled service/test action, or policy change requires a separate explicit approval.

## REMAINING WORK

- P4-T03 Owned Service Controls on top of the P4-T02 approval seam.
- P4-T04 Targeted Verification selection/status UX on top of the fixed-profile proposal seam.
- P4-T05 Commit Proposal review/selection for WorkRun-owned paths only.
- P4-T06 Push Proposal publication UX for completed verified WorkRuns only.
- Portal timeline/start-work adapter, if the Portal surface is still required.
- Live MCP/tunnel/user-project integration validation.

## CURRENT CHECKPOINT

`run_id=devos-20260901`, `phase=4`, `last_completed=P4-T02`, `next=P4-T03`, `last_verified_commit=c04a9db`, `working_tree=dirty_preexisting_changes_preserved`.

## COMMITS

None.

## RECOMMENDED NEXT ACTION

Start P4-T03 as a separate task/session. Reuse `workspace_propose_action` + `apply_approved_action`; do not add a second execution path or weaken approval policy.
