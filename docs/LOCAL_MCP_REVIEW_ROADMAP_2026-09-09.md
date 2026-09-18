# Local MCP Control Center — Review Roadmap

วันที่: 2026-09-09  
สถานะ: review/roadmap; เอกสารนี้ไม่ใช่หลักฐานว่า live bridge, OpenAI API หรือ Motion ERP UAT ผ่านแล้ว

## ขอบเขตและหลักฐานปัจจุบัน

- ตรวจแบบ read-only ที่ `HEAD=f57a353`; worktree มี dirty changes และไฟล์ Motion ERP/test ใหม่ จึงแยก “source ใน dirty tree” ออกจาก “implemented/released”. Backend worker baseline/owned paths ถูกตรวจเทียบกับ `/tmp/local-mcp-backend-review-20260909` แล้ว.
- Architecture ที่ยืนยันจาก source: `MCPServer/ToolRegistry → Broker/PolicyEngine → adapter → audit`; มี `scope_id`, relative path, protected-target checks, quotas, approvals, redacted hash-chain audit และ owned process bounds.
- `mcp_server.py` ใช้ `structured_output=True`; source export และ focused schema check ผ่านสำหรับ Motion tools แต่ยังต้องตรวจทุก result branch และ live `tools/list` หลัง restart ก่อนสรุป runtime parity.
- Motion read adapters และ `motion_timesheet_create_missing` มี fixed models/methods, bounded input, `dry_run=true` default, exact duplicate skip, conflicting-hours block และ worker เพิ่ม duplicate-business-key rejection กับ broker fail-closed guard สำหรับ `dry_run=false`. External-target/payload approval ยังไม่เสร็จ.
- GUI `expose_to_mcp=True` เป็นการเปลี่ยนแปลงที่มีอยู่ใน baseline dirty tree ก่อน worker delta; จัดเป็น review recommendation เรื่อง explicit consent/least privilege ไม่ใช่ P0 security defect ที่พิสูจน์แล้วจากหลักฐานรอบนี้.
- Backend worker รายงาน targeted 43 passed; refined metadata patch หลังตรวจซ้ำ `tests/test_motion_erp.py tests/test_runner_and_mcp.py` ด้วย `PYTHONPATH=src` ได้ 14 passed และตรวจ `ToolDefinition`, registry rows, generic preview และ MCP output schema เพิ่มแล้ว. Final full suite ผ่าน 172 tests (18.53s), compileall และ diff check ผ่าน. ยังไม่มีหลักฐานจาก live bridge, API key-backed provider, browser session หรือ ERP จริง; source tests ไม่แทน live/UAT evidence.

## Version evidence และข้อควรระวัง

- MCP `2026-07-28` เป็น specification ปัจจุบันจากหน้าทางการ และใช้ stateless, self-contained requests/per-request capability negotiation: <https://modelcontextprotocol.io/specification/2026-07-28>.
- Transport แยก stdio กับ Streamable HTTP; cancellation ผูกกับ transport และ legacy clients ต้องมี backward-compatibility path: <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports>.
- HTTP authorization ใช้ OAuth metadata/audience/least privilege; stdio ไม่ควรใช้ MCP HTTP authorization flow และควรรับ credential จาก environment: <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>.
- Checkout ระบุ `mcp>=2.1,<2.2`; installed package คือ `mcp 2.1.1`. Package version นี้ไม่ใช่หลักฐาน wire revision หรือ live compatibility; ต้องยืนยันผ่าน version negotiation และ restarted `tools/list`.
- Tool schemas, structured output, error classes, deterministic discovery, limits และ audit guidance: <https://modelcontextprotocol.io/specification/2026-07-28/server/tools>. Security threat model เพิ่มเติม: <https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html>.

## Priority roadmap

### P0 — Close proven safety gaps

1. `motion_timesheet_create_missing`: worker guard now fail-closes `dry_run=false` with `MOTION_ERP_WRITE_REQUIRES_APPROVAL`; approval that binds exact external target, normalized payload, browser session/profile, expiry and policy version is still pending. `dry_run=true` must remain preview-only; no ERP record creation during preview.
2. Duplicate contract: worker normalizes and rejects repeated business keys within one request; existing exact key + same hours = skip; existing key + different hours = reject whole write batch. Unit evidence exists; no live write claim.

### P1 — Reliability, lifecycle, schema, diagnostics

- Per-tool typed input/output schemas, bounded arrays/bytes/timeouts, `structuredContent` validation and text compatibility mirror.
- Protocol errors แยกจาก actionable tool execution errors (`isError=true`); ทุก denial/approval/exception ต้องมี stable error code และ redacted trace ID.
- `dry_run` metadata fix verified: Motion registry metadata now reports `live_execution_supported=false`, `live_approval_required=true`, `live_approval_available=false`, and a stable block reason; generic tools retain their ordinary preview fields. Approval UX still waits for exact external-target/payload binding.
- Future apply flow must fail closed when a `company_id` field exists but current ERP company cannot be resolved; otherwise duplicate lookup is not company-scoped. This is a pending hardening check, not live evidence.
- Propagate cancellation/deadline เข้า owned process/browser adapter; enforce concurrency, output limits, cleanup and terminal state. Tasks เป็น optional extension ไม่ใช่เหตุผลให้ขยาย tool surface.
- เพิ่ม diagnostics ที่แยก `registry`, SQLite policy, running bridge, tunnel/process identity และ client cache; acceptance ต้องมี restarted live `tools/list` evidence.
- Audit event ต้องระบุ actor/tool/scope/approval/decision/result/duration/bytes โดยไม่เก็บ secret, prompt หรือ raw external response; chain verify หลัง restart และ tamper fixture.

### P2 — Discovery และ token efficiency

- `tools/list` deterministic order, pagination, catalog revision/hash, cache invalidation/list-change signal และ collision-safe namespacing.
- วัด catalog/result bytes หรือ token estimate ต่อ profile; ใช้ small explicit tool profiles และ bounded read/context tools. ห้ามเพิ่ม generic shell/RPC/child-MCP surface เพื่อแก้ token cost.
- Acceptance: stable list hash เมื่อ policy ไม่เปลี่ยน, changed policy ทำให้ revision เปลี่ยน, p95 catalog/result size อยู่ใน declared budget, และ no live tool hidden from registry/policy explanation.

### UI workflow

- Native Tk/ttk UI wave complete in scoped evidence: compact Overview, Tools/Audit search with stable row IDs, preview-only live metadata, human-readable states, fetch-before-replace preservation, and visible per-area polling errors/recovery that do not mask unrelated failures. Final UI suite: 20 passed; parent visually inspected final Overview/Tools at 1200x760. Evidence used native UI temporary sample data; it does not prove the installed live app/bridge or a restart. Scope exposure remains explicit-consent acceptance work.

## Core MCP กับ product capability

- Core/protocol: JSON-RPC, transport/version negotiation, tool schemas, structured results, error classes, cancellation/progress, pagination/discovery.
- Product/control-plane: path scopes, approvals, catalog hashes, redaction/audit, tool profiles, token budgets, GUI consent, Motion business adapters.
- Out of scope สำหรับ roadmap นี้: arbitrary shell, arbitrary Odoo RPC, automatic external write, automatic push/merge, hostile-code sandbox claim.

## Acceptance gate

ก่อนเรียกว่า ready ต้องมี: scoped targeted tests ผ่าน, `git diff --check`, schema/tool inventory parity, restart แล้วตรวจ live `tools/list`, approval replay/precondition tests, cancellation/timeout/cleanup evidence, redaction/chain verification และ explicit report แยก `implemented`, `tested`, `live verified`, `UAT`, `pending`.

## Execution note

งานนี้วางแผน/ควบคุมโดย Astra และมอบหมาย worker ด้วย Luna max ตาม assignment; speed toggle ใช้งานไม่ได้ จึงไม่มีการอ้าง token savings ที่วัดแล้ว.
