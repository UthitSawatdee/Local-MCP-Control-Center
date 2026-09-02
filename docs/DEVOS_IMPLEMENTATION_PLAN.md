# DevOS Implementation Plan

สถานะ: `PARTIAL` — Foundation, work intelligence, evidence, handoff และ proposal read surface เสร็จ; controlled operations ยัง deferred

เอกสารนี้แยก target architecture ของ Local Engineering Control Plane ออกจาก implementation ที่มีจริงใน checkout และแบ่งงานเป็น atomic tasks ที่ resume ได้จาก checkpoint

## Reconciliation

ที่มีอยู่และต้อง reuse:

- `Store` เป็น SQLite adapter สำหรับ scopes, policies, approvals, runtime, agent tasks และ metadata index
- `PolicyEngine` เป็น deep module สำหรับ canonical scope, capabilities, protected targets และ quotas
- `FixedRunner`, `GitAdapter`, `SafeFilesystem`, `ManagedProcessManager` เป็น adapters ที่มี allowlist และ bounded execution อยู่แล้ว
- `WorkspaceContextService`, `WorkspaceIndexService` และ `dependency_graph` มี context/index/impact primitives แบบ read-only อยู่แล้ว
- `AuditLog` เป็น append-only hash chain ที่ redact metadata ก่อน persist
- `Broker` เป็นจุด authorize/dispatch เดียว; `mcp_server.py`, CLI และ Tkinter GUI เป็น adapters

ข้อสังเกตจาก baseline: working tree มี changes จากงานก่อนหน้าเกี่ยวกับ bridge/UI และ provider-backed agent runtime; ต้อง preserve ทั้งหมด. Baseline ณ 2026-09-01: `110 passed`.

## Contract

`WorkspaceEngine` เป็น deep module กลาง มี public interface หลัก:

```text
observe(scope) -> WorkspaceSnapshot
prepare(request) -> WorkPackage
record(event) -> EvidenceReceipt
finish(run_id) -> HandoffReport
```

MCP/CLI/Portal เรียก interface นี้ผ่าน Broker หรือ adapter ที่บางที่สุด. Engine ไม่ตัดสิน authorization เอง; ทุก data-plane call ยังต้องผ่าน Broker/PolicyEngine.

## Tasks

### Phase 0 — Reconcile and checkpoint

- `P0-T01` Inspect repository, conventions, policy seam, storage, adapters, tests, Git state. Dependency: none. Verification: baseline pytest, status/diff inspection. Status: complete.
- `P0-T02` Freeze WorkspaceEngine contract, task sequence, safety notes, and resumable checkpoint. Dependency: P0-T01. Verification: path/link/whitespace checks. Status: complete.

### Phase 1 — Foundation

- `P1-T01` Project Registry and Capsule model. Reuse existing `scopes` as canonical project registry; add validated safe capsule persistence without reading secret files. Verification: model/parser/store tests. Status: complete.
- `P1-T02` Workspace Observer and normalized Snapshot. Cover Git, fixed runtime probes, service ports, filesystem/tracked-environment warnings, capsule drift, unfinished runs, and environment fingerprint. Verification: fixture-based observer tests; no live user project required. Status: complete.
- `P1-T03` Broker/MCP/CLI adapters for `workspace_observe`, `workspace_run_status`, and `workspace_action_proposals`; CLI `doctor`. Verification: broker policy/schema tests and CLI smoke. Status: complete.
- `P1-T04` Read-only Portal health view. Reuse current Tkinter UX; compact status labels, explicit warnings, no duplicate mutation controls. Verification: formatter/UI unit tests. Status: complete.

### Phase 2 — Work Intelligence

- `P2-T01` Impact map from changed files, bounded dependency metadata, workflows, and risk. Reuse `dependency_graph`; persist only metadata. Status: complete.
- `P2-T02` WorkPackage/context pack for project, goal, mode, and allowed scope. Include protected scope, recommended files, required verification, escalation conditions, and known issues. Status: complete.
- `P2-T03` Test mapping with nearest/feature/escalation verification levels. Status: complete.
- `P2-T04` `workspace_prepare` MCP/CLI adapters creating a persisted WorkRun and WorkPackage. Status: complete.

### Phase 3 — Evidence and Handoff

- `P3-T01` WorkRun lifecycle and append-only Flight Recorder evidence. Status: complete.
- `P3-T02` Normalize verification evidence; never persist uncontrolled terminal dumps. Plain caller-supplied test results remain unverified; an internal fixed-runner hook is the only source that can mark execution evidence verified. Status: complete.
- `P3-T03` `workspace_finish` handoff generator with verified/unverified split, risks, remaining work, changelog draft, and commit proposal. Status: complete.
- `P3-T04` Portal/CLI run status and handoff display. Status: complete for CLI/MCP; Portal timeline remains deferred.

### Phase 4 — Controlled Operations

- `P4-T01` Represent action proposals by reusing existing approval records; no new execution path. Status: complete.
- `P4-T02` Approval integration. Add opt-in `workspace_propose_action` for exact owned-service/test/commit/push proposals. Every proposal is approval-gated, binds WorkRun/action/scope/payload/preconditions/policy version, reuses `apply_approved_action`, rechecks the underlying tool/capability at proposal and apply time, records fixed-runner verification provenance, and binds push approval to the exact HEAD commit. The proposal call never executes the action. Status: complete.
- `P4-T03` Owned Service Controls. Build the user-facing WorkRun service start/stop flow on the P4-T02 approval seam; do not add another executor. Status: pending.
- `P4-T04` Targeted Verification. Build WorkRun verification selection/status UX on the P4-T02 fixed-profile proposal seam. Status: pending.
- `P4-T05` Commit Proposal. Build review/selection UX for explicit WorkRun-owned paths only; pre-existing dirty paths remain excluded. Status: pending.
- `P4-T06` Push Proposal. Build publication UX only for completed, verified, ready-for-review WorkRuns; exact branch + HEAD approval remains mandatory. Status: pending.

## Scope and safety

- Allowed implementation scope: new WorkspaceEngine module, additive Store schema/methods, registry schemas, Broker adapters, CLI/Portal read-only surfaces, tests, docs, checkpoint.
- Protected: existing policy/audit/worktree/agent runtime contracts, unrelated dirty changes, user project repositories, secrets, `.env*`, credentials, private keys, production databases.
- Out of scope: MRP business code, new infrastructure, arbitrary shell, child MCP/browser/desktop automation, automatic merge/push, OS-level sandbox claims.

## Verification ladder

1. Static import/compile and `git diff --check`.
2. New WorkspaceEngine tests.
3. Existing context/index/policy/MCP/CLI/GUI tests.
4. Full local suite at phase boundary or shared-contract changes.

## Suggested logical commits

- `feat: add DevOS workspace engine foundation`
- `feat: add DevOS work intelligence and evidence`
- `docs: add DevOS overnight handoff`

Commits and push remain pending unless separately authorized.
