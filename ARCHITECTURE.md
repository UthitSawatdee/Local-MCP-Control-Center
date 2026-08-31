# Local MCP Control Center — Implementation Blueprint

สถานะ: blueprint + runnable Python/Tkinter implementation 0.2.0 พร้อม provider-backed Agent Runtime V1 (ยังไม่รวม UDS/Tauri/Rust และ macOS packaging ของ hardening)

วันที่: 2026-08-29

หมายเหตุ implementation: checkout นี้มี runnable Python/Tkinter reference implementation ที่พิสูจน์ policy, approval, audit, document adapter, fixed/project profiles, managed processes, controlled Git lifecycle, code discovery/index/context, MCP stdio contract และการเรียก `tunnel-client init/doctor/run` ผ่าน profile ที่แยกของแอป ก่อนย้าย trusted broker ไป Rust/Tauri, เพิ่ม UDS/security-scoped bookmark และทำ macOS packaging ใน phase hardening ถัดไป รายละเอียด actual runtime อยู่ในหัวข้อ 17; หัวข้อก่อนหน้ายังคงเป็น blueprint/roadmap

## 1. ข้อสรุปการออกแบบ

สร้าง Local MCP Control Center เป็น macOS desktop application แยก repository จาก `Project-ATM-Coperation` โดยให้มี policy broker เป็นจุดเดียวที่ตัดสินและทำ filesystem/process operation ทุกชนิด

สแตกที่แนะนำ:

- GUI: Tauri 2 + React/TypeScript เพื่อ reuse ความถนัดจาก frontend ของ MRP และได้แอปที่เบากว่า Electron
- Trusted local module: Rust policy broker, audit writer และ process supervisor ฝั่ง Tauri
- MCP bridge: Python 3.12 sidecar ใช้ MCP SDK และ document adapters เพราะ ecosystem สำหรับ `xlsx`, `csv` และ `docx` เหมาะกับงานนี้
- State: SQLite สำหรับ policy, pending approvals, runtime state และ audit metadata
- Secrets: macOS Keychain เท่านั้นสำหรับ tunnel identity/credential; ไม่ใส่ secret ใน repository หรือ SQLite แบบ plaintext
- IPC: Unix domain socket ใน Application Support, mode `0600`, ตรวจ peer credentials และ request nonce
- Connection: OpenAI Secure MCP Tunnel แบบ outbound-only โดย tunnel client เรียก MCP bridge ผ่าน stdio

หลักการสำคัญคือ MCP bridge ไม่เป็นเจ้าของสิทธิ์ไฟล์เอง แต่ส่ง `ActionIntent` ไปยัง policy broker เท่านั้น หากต้องการ OS-level containment เพิ่มเติมในระยะ hardening ให้ย้าย broker/adapter ไปอยู่ใน sandboxed helper หรือ VM แยก ไม่ยกระดับเป็น root

OpenAI ระบุว่า Secure MCP Tunnel ใช้สำหรับ MCP server ที่อยู่หลัง firewall/private network โดย `tunnel-client` สร้าง outbound HTTPS path ไปยัง OpenAI และ forward งานมายัง server ภายใน โดยไม่ต้องเปิด inbound firewall port ให้เครื่อง ([official OpenAI documentation](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)) การใช้ MCP ใน API ยังรองรับการจำกัด allowed tools และกำหนด approval policy ได้ ([MCP and Connectors](https://developers.openai.com/api/docs/guides/tools-connectors-mcp))

## 2. สิ่งที่ระบบต้องทำและไม่ทำ

### In scope

- ลงทะเบียน project directory และ file directories ที่ผู้ใช้เลือกเอง
- Permission แยก `read`, `execute`, `write`, `create`, `rename`, `move`, `delete`
- Tool permission class แยก `READ`, `WRITE`, `EXECUTE`, `DANGEROUS` จาก scope capability
- เปิด/ปิด Tool และกำหนด approval mode ต่อ Tool
- อ่าน/ค้นหาไฟล์ด้วย `scope_id` + `relative_path` เท่านั้น
- เขียนไฟล์แบบ atomic พร้อมตรวจ precondition และเก็บ backup เมื่อ overwrite
- จัดการ CSV และแก้ไข `.xlsx`/`.xlsm` อย่างมีขอบเขต
- แก้ไข `.docx` ในระดับ paragraph/table ที่กำหนด
- Git read operations ใน Project Scope
- Test/build ผ่าน command profiles ที่ fix ไว้ล่วงหน้าและต้องมี scope `execute`
- `apply_patch`, bounded multi-file/paged reads, filename/regex discovery
- ProjectProfile สำหรับ targeted test/lint/typecheck/build และ managed process/log lifecycle
- Controlled Git branch/stage/commit พร้อม approval-gated restore/push
- Workspace snapshot/context, persistent metadata index และ lightweight symbol/reference search
- Bounded in-memory context ledger ที่เก็บ digest/preview แบบ redacted, compound READ batch, deterministic Python/JS/TS dependency graph และ delegated-agent task manager สำหรับ profile ที่ configure ไว้ล่วงหน้า
- GUI สำหรับ policy, approvals, audit และ lifecycle ของ MCP/tunnel
- Audit ทั้งคำขอ การอนุญาต การปฏิเสธ การอนุมัติ และผลลัพธ์

### Out of scope สำหรับ MVP

- `run_shell(command)` หรือ command ที่รับ string แล้วส่งให้ shell
- `sudo`, `curl | sh`, การติดตั้ง package แบบอัตโนมัติจาก MCP/GUI และคำสั่งที่รับ arbitrary flags
- `git reset`, `git clean`, `checkout`, `rebase`, force push และ arbitrary Git arguments
- การเข้าถึง Docker socket หรือการควบคุม Docker daemon
- การลบ directory แบบ recursive
- การเขียน legacy `.xls` และ `.doc`; ให้ read-only หรือแปลงโดยผู้ใช้ก่อน
- การอ่าน Keychain อื่นนอกเหนือจาก item ของ tunnel นี้, browser profile, SSH keys, cloud credentials และ `.env`
- การอ้างว่า ChatGPT กำลังเชื่อมต่ออยู่เมื่อเห็นเพียง tunnel heartbeat

## 3. Architecture

```text
┌─────────────────────────────┐
│ ChatGPT custom MCP app       │
└──────────────┬──────────────┘
               │ MCP request
               ▼
┌─────────────────────────────┐
│ OpenAI Secure MCP Tunnel     │
│ private endpoint             │
└──────────────┬──────────────┘
               │ outbound HTTPS
               ▼
┌─────────────────────────────┐
│ tunnel-client (Control Center)│
│ fixed profile, no user shell  │
└──────────────┬──────────────┘
               │ stdio
               ▼
┌─────────────────────────────┐
│ MCP bridge (Python)          │
│ protocol + schema only       │
│ no direct business authority │
└──────────────┬──────────────┘
               │ UDS 0600
               ▼
┌─────────────────────────────────────────────┐
│ Policy broker (Rust, trusted local module)   │
│ canonical path → policy → approval → action  │
├───────────────┬───────────────┬─────────────┤
│ SQLite policy │ Keychain       │ supervisor  │
│ + audit       │ tunnel key     │ + profiles  │
└──────┬────────┴───────────────┴──────┬──────┘
       │                                │
       ▼                                ▼
┌───────────────┐                ┌──────────────┐
│ File adapters  │                │ Fixed runner │
│ CSV/XLSX/DOCX  │                │ git/test     │
└───────────────┘                │ build only   │
                                 └──────────────┘

┌─────────────────────────────┐
│ Tauri GUI                    │
│ path / tool / approval / log │
│ talks to broker locally      │
└─────────────────────────────┘
```

### Runtime ownership

Control Center เป็นเจ้าของ process ที่มัน start เท่านั้น โดยเก็บ PID/PGID, start token และ log path ของแต่ละ process ห้ามหยุด process ด้วยชื่อกว้าง ๆ เช่น `killall node` หรือ `pkill`. เมื่อปิด GUI ใน MVP ให้หยุด bridge และ tunnel ที่ Control Center เป็นเจ้าของ (ถ้ามี); ระยะถัดไปค่อยเพิ่ม headless LaunchAgent ที่ใช้ policy เดียวกัน

### Connection status ที่แสดงใน GUI

แยกสถานะให้ชัดเจน:

1. `Control Center`: แอปพร้อม/ไม่พร้อม
2. `Policy broker`: database และ policy พร้อมหรือไม่
3. `MCP bridge`: initialize/list-tools handshake ผ่านหรือไม่
4. `Tunnel`: tunnel-client เชื่อม OpenAI endpoint อยู่หรือไม่
5. `ChatGPT path`: พร้อมให้ ChatGPT เรียกผ่าน endpoint หรือไม่

อย่าแสดง `ChatGPT connected` จาก heartbeat เพียงอย่างเดียว เพราะ tunnel ไม่ได้ยืนยันว่ามีบทสนทนาที่กำลังเรียก Tool อยู่

## 4. Deep modules และ interface

ใช้ seam ที่เล็กและทดสอบได้ โดยให้ความซับซ้อนอยู่หลัง policy broker interface

### Policy broker interface

```text
authorize(intent: ActionIntent) ->
    Allow(plan)
  | RequireApproval(approval_request)
  | Deny(policy_error)

execute(approval_id or plan_id) -> ExecutionResult

read_audit(filter) -> AuditPage
```

`ActionIntent` ต้องมีอย่างน้อย:

```json
{
  "request_id": "uuid",
  "session_id": "uuid",
  "actor": "chatgpt",
  "tool": "file_write",
  "operation": "overwrite",
  "scope_id": "atm-project",
  "targets": ["frontend/src/app/page.tsx"],
  "input_digest": "sha256:...",
  "expected_preconditions": {
    "frontend/src/app/page.tsx": "sha256:..."
  },
  "policy_version": 12
}
```

Broker ต้องสร้าง `action_hash` จาก canonical JSON ของ intent และ target ที่ canonical แล้ว ไม่ใช้ข้อความอธิบายจาก ChatGPT เป็นหลักฐานการอนุมัติ

### MCP bridge interface

MCP bridge เปิดเฉพาะ Tool ที่อยู่ใน registry และแปลง input เป็น `ActionIntent` ไม่รับ path absolute จาก model และไม่รับ command string

แนะนำ Tool set:

| กลุ่ม | Tool | ค่าเริ่มต้น | หมายเหตุ |
|---|---|---:|---|
| scope | `list_scopes` | เปิด | คืนชื่อ scope และ capability ที่เปิด ไม่คืน root เต็มโดยไม่จำเป็น |
| filesystem | `list_files` | เปิด | `scope_id`, `relative_path`, จำกัดจำนวนรายการ |
| filesystem | `read_file` | เปิด | text only, size limit, redaction |
| filesystem | `search_text` | เปิด | ค้นเฉพาะ scope, จำกัด pattern/result |
| filesystem | `write_file` | ปิดจนผู้ใช้เปิด | overwrite existing; approval ตาม policy |
| filesystem | `create_file` | ปิดจนผู้ใช้เปิด | ห้ามใช้แทน arbitrary write |
| filesystem | `rename_file` | ปิด | same scope, no directory tree rename ใน MVP |
| filesystem | `move_file` | ปิด | ต้องผ่าน source/destination checks |
| filesystem | `delete_file` | ปิด | ไม่ recursive; approval เสมอ |
| documents | `csv_transform` | ปิด | operation enum ไม่รับ Python/expression |
| documents | `xlsx_edit` | ปิด | sheet/range/cell operation enum |
| documents | `docx_edit` | ปิด | paragraph/table operation enum |
| project | `git_status` | เปิด | read-only |
| project | `git_diff` | เปิด | read-only, path relative |
| project | `git_log` | เปิด | จำกัดจำนวน commit |
| project | `run_backend_test` | ปิด | fixed profile, approval เสมอใน MVP |
| project | `run_frontend_test` | ปิด | fixed profile, approval เสมอใน MVP |
| project | `run_build` | ปิด | fixed profile, approval เสมอใน MVP |
| control | `runtime_status` | เปิด | สถานะเท่านั้น ไม่มี start/stop จาก ChatGPT |
| control | `apply_approved_action` | เปิดแบบจำกัด | ใช้ได้เฉพาะ approval ที่ GUI อนุมัติและยัง valid |

ไม่มี Tool ชื่อ `shell`, `exec`, `run_command`, `python`, `node_eval` หรือ `docker` ใน registry

### Approval flow

```text
MCP mutation request
        │
        ▼
broker canonicalize + policy check
        │
        ├── Deny → audit → return DENIED
        ├── Allow → execute → audit → return result
        └── RequireApproval
                │
                ▼
          pending approval
                │
                ▼
         GUI shows exact diff/targets
                │
          user deny / approve once
                │
                ▼
        apply_approved_action(id)
                │
        recheck policy + hashes + expiry
                │
          execute once or fail closed
```

Approval ควรมี TTL สั้น เช่น 5 นาที, ใช้ได้ครั้งเดียว, ผูกกับ `action_hash`, `policy_version`, expected precondition และ target list แบบ exact ไม่อนุญาต wildcard หรือ “อนุมัติทุกการเขียนใน session” สำหรับ dangerous delete/Git restore/push actions; execute profiles ใช้ scope `execute` และ fixed profile policy

## 5. Data model

SQLite เป็น state store ของ Control Center ไม่ใช่ที่เก็บเนื้อหาไฟล์หลัก

### Entity relationship

```text
Scope 1 ──── * ScopePermission
ToolPolicy 1 ──── * ApprovalRequest
ApprovalRequest 1 ──── * AuditEvent
RuntimeProcess ──── * AuditEvent
Settings  ──── * AuditEvent
```

### Tables

#### `scopes`

| Column | Type | ความหมาย |
|---|---|---|
| `id` | TEXT PK | stable scope id |
| `label` | TEXT | ชื่อที่แสดงใน GUI |
| `kind` | TEXT | `project`, `directory`, `file` |
| `canonical_root` | TEXT | path ที่ตรวจแล้ว; ไม่ส่งให้ model โดยตรง |
| `bookmark_ref` | TEXT | reference ไปยัง Keychain/security-scoped bookmark |
| `enabled` | INTEGER | เปิด/ปิด scope |
| `expose_to_mcp` | INTEGER | อนุญาตให้ MCP เห็น scope หรือไม่ |
| `policy_version` | INTEGER | version ล่าสุด |
| `created_at`, `updated_at` | TEXT | UTC timestamp |

#### `scope_permissions`

| Column | Type | ความหมาย |
|---|---|---|
| `scope_id` | TEXT FK | scope ที่เกี่ยวข้อง |
| `capability` | TEXT | `read`, `execute`, `write`, `create`, `rename`, `move`, `delete` |
| `decision` | TEXT | `allow`, `deny` |
| `approval_mode` | TEXT | `never`, `always`, `on_risk` |
| `max_bytes` | INTEGER | quota ต่อ action |
| `max_items` | INTEGER | quota ต่อ action |

#### `tool_policies`

| Column | Type | ความหมาย |
|---|---|---|
| `tool_name` | TEXT PK | ชื่อใน MCP registry |
| `enabled` | INTEGER | เปิด/ปิด |
| `approval_mode` | TEXT | `never`, `always`, `on_risk` |
| `max_duration_ms` | INTEGER | timeout |
| `output_limit_bytes` | INTEGER | จำกัด output |
| `updated_at` | TEXT | UTC timestamp |

#### `approval_requests`

| Column | Type | ความหมาย |
|---|---|---|
| `id` | TEXT PK | approval id |
| `action_hash` | TEXT UNIQUE | hash ของ action แบบ canonical |
| `status` | TEXT | `pending`, `approved`, `denied`, `expired`, `consumed` |
| `intent_json` | TEXT | canonical, redacted intent |
| `policy_version` | INTEGER | policy ตอนสร้าง request |
| `expires_at` | TEXT | TTL |
| `decision_reason` | TEXT | เหตุผลของผู้ใช้/ระบบ |
| `decided_at` | TEXT | เวลาตัดสินใจ |
| `consumed_at` | TEXT | เวลาที่ใช้สำเร็จ |

#### `audit_events`

| Column | Type | ความหมาย |
|---|---|---|
| `seq` | INTEGER PK | ลำดับเพิ่มขึ้นเรื่อย ๆ |
| `event_id` | TEXT UNIQUE | event UUID |
| `occurred_at` | TEXT | UTC timestamp |
| `actor` | TEXT | `user`, `chatgpt`, `control-center`, `system` |
| `session_id`, `request_id` | TEXT | correlation |
| `tool`, `operation` | TEXT | สิ่งที่เกิดขึ้น |
| `scope_id` | TEXT | scope ที่เกี่ยวข้อง |
| `target_display` | TEXT | scope-relative/redacted target |
| `decision` | TEXT | `allowed`, `denied`, `approval_required`, `approved`, `executed`, `failed` |
| `approval_id` | TEXT | ถ้ามี |
| `pre_hash`, `post_hash` | TEXT | hash ก่อน/หลัง |
| `result_code`, `error_code` | TEXT | ผลแบบ machine-readable |
| `metadata_json` | TEXT | ข้อมูลที่ redacted แล้ว |
| `prev_hash`, `event_hash` | TEXT | hash chain |

#### `runtime_processes`

| Column | Type | ความหมาย |
|---|---|---|
| `id` | TEXT PK | process record |
| `kind` | TEXT | `mcp_bridge`, `tunnel_client` |
| `profile` | TEXT | ชื่อ profile ที่ allowlist |
| `pid`, `pgid` | INTEGER | process ownership |
| `state` | TEXT | `starting`, `running`, `stopped`, `failed` |
| `started_at`, `stopped_at` | TEXT | lifecycle |
| `log_path` | TEXT | app-owned log path |

#### `settings`

ใช้เก็บ non-secret settings เช่น language, audit retention และ launch-at-login ตัว secret ใช้ Keychain และเก็บเพียง reference ใน SQLite

### Storage layout บน macOS

```text
~/Library/Application Support/LocalMCPControlCenter/
├── control.sqlite3          # mode 0600
├── logs/
├── snapshots/               # backups ที่ผูกกับ approval/action
├── run/
│   └── broker.sock          # mode 0600
└── tunnel-profiles/         # non-secret config, directory mode 0700
```

ชื่อ path ข้างต้นเป็นตำแหน่งเชิงออกแบบ ให้ implementation ใช้ Foundation URL และ Application Support directory ที่ระบบคืนมา ไม่ต่อ string จาก `HOME` เอง

## 6. Security model

### Trust zones

| Zone | ถือว่าเชื่อถือได้แค่ไหน | กฎ |
|---|---|---|
| ผู้ใช้หน้า GUI | ผู้อนุมัติ | เป็นผู้เดียวที่เปลี่ยน policy และ approve sensitive action |
| Policy broker | trusted local module | เป็นผู้ตัดสินและทำ operation |
| MCP bridge | untrusted adapter | validate schema, ไม่ถือ policy, ไม่ทำ file operation เอง |
| ChatGPT/model | untrusted caller | input และข้อความจากไฟล์ถือเป็นข้อมูล ไม่ใช่คำสั่งระบบ |
| tunnel-client | transport | ส่งต่อข้อมูล ไม่ได้รับสิทธิ์เพิ่ม |
| repository contents | untrusted data | ห้ามให้ข้อความในไฟล์ขยาย capability |

### Path authorization algorithm

ทุก request จาก MCP ต้องใช้ `scope_id` และ `relative_path`:

```text
1. ตรวจ schema, length, NUL และ encoding
2. ปฏิเสธ absolute path และ path ที่มี ..
3. canonicalize root และ target
4. สำหรับ target ใหม่ ให้ canonicalize nearest existing parent
5. ปฏิเสธ symlink ที่พาออกนอก root; MVP ปฏิเสธ symlink path ทั้งหมด
6. หา scope ที่ตรง; MVP ปฏิเสธ overlapping scopes เพื่อให้ผล deterministic
7. ตรวจ protected-target rules; deny มี precedence
8. ตรวจ scope enabled + expose_to_mcp
9. ตรวจ Tool enabled
10. ตรวจ capability และ quota
11. คำนวณ action_hash และตรวจ approval หากจำเป็น
12. recheck target และ precondition ก่อน mutate
```

ไม่รับ absolute path จาก ChatGPT เพราะ scope-relative identifier ลด path confusion, ลดการรั่วไหลของ username และทำให้ policy review เข้าใจง่าย

### Protected targets ที่ deny เป็นค่าเริ่มต้น

- `.ssh`, `.aws`, `.gnupg`, `.config` ที่มี credential
- `.env`, `.env.*` ยกเว้น `.env.example` ที่ผู้ใช้เปิดเองได้แบบ explicit
- `*.pem`, `*.key`, `*.p12`, `*.pfx`, private key และ token files
- browser profile, password store, Keychain export และ cloud credential files
- `/`, home root, `System`, `Library`, `Applications` และ directory ของผู้ใช้อื่นเป็น root scope
- `.git/objects`, `.git/config` และ hook directories เมื่อ Tool ไม่จำเป็น

นอกจากชื่อไฟล์ ให้ใช้ secret-pattern scanner ก่อนส่ง text กลับ MCP และแทนค่าด้วย `[REDACTED]` การ scanner เป็น defense-in-depth ไม่ใช่เหตุผลให้ยกเลิก path policy

### Permission semantics

- `read`: อ่าน content/metadata ภายใน scope
- `write`: overwrite ไฟล์ที่มีอยู่แล้ว; ไม่รวม create
- `create`: สร้างไฟล์หรือ directory ใหม่; parent ต้องอยู่ใน scope
- `rename`: เปลี่ยนชื่อใน parent เดิม; directory rename ปิดใน MVP
- `move`: ย้าย source ไป destination; ต้องผ่านทั้ง source และ destination policy
- `delete`: ลบไฟล์เดียว; directory และ recursive delete ปิดใน MVP
- `execute`: เรียกเฉพาะ ProjectProfile หรือ owned process profile; ไม่ใช่ arbitrary shell
- `DANGEROUS`: เป็น Tool classification สำหรับ delete/Git restore/push และไม่ grant scope capability เอง

`move` ต้องมี `move` บน source และ `create` หรือ `write` บน destination ตามกรณี overwrite การ overwrite destination ต้อง approval เสมอ

### Approval rules ที่แนะนำ

| Action | ค่าเริ่มต้น |
|---|---|
| read/search/list | allow ถ้า policy อนุญาต; audit ทุกครั้ง |
| overwrite existing | immediate เมื่อเปิด write และ precondition ผ่าน |
| create text file | immediate เมื่อเปิด create และ quota ผ่าน |
| rename/move | immediate เมื่อ capability และ precondition ผ่าน |
| delete | approval เสมอ; no recursive |
| CSV/XLSX/DOCX edit | immediate เมื่อเปิด write และ format validation ผ่าน |
| test/build/process start | ต้องเปิด execute และ fixed ProjectProfile; bounded timeout/output |
| git status/diff/log | auto allow ถ้าเปิด Tool |
| git branch/stage/commit | ต้องเปิด execute; explicit branch/path/message เท่านั้น |
| git restore/push | approval เสมอ; no reset/clean/force |
| policy/tool changes | ต้องทำจาก GUI และ audit |

### Atomic mutation และ TOCTOU

สำหรับ text/CSV/document:

1. อ่าน precondition hash และ metadata
2. สร้าง temp file ใน directory เดียวกัน
3. เขียนและ fsync temp file
4. ตรวจ output format/semantic validation
5. backup เป้าหมายเดิมภายใต้ app-owned snapshot store
6. rename temp ไป target แบบ atomic
7. fsync parent เมื่อ platform adapter รองรับ
8. คำนวณ post-hash และเขียน audit

ถ้า precondition hash เปลี่ยนหลัง approval ให้คืน `STALE_APPROVAL` และไม่ retry อัตโนมัติ ระยะ hardening ให้ใช้ fd-relative operations (`openat`/`renameat`/`unlinkat` ตามความเหมาะสม) เพื่อลด race ระหว่างตรวจและ mutate

### Process execution

Test/build ไม่ใช่ arbitrary shell แต่ยังเป็น code execution จาก repository จึงต้องมี:

- profile id enum เช่น `backend_pytest`, `frontend_test`, `frontend_build`
- executable absolute path ที่ resolve และตรวจตอน start
- argv array ที่ประกอบจาก enum/parameter ที่ validate แล้ว; ไม่ใช้ `shell=True`
- fixed working directory ภายใน project scope
- clean environment และไม่มี API keys/credentials
- timeout, output cap, CPU/memory policy เท่าที่ platform ทำได้
- no package install, no network-dependent bootstrap และ no Docker socket ใน MVP
- เก็บ command profile id, exit code, duration และ output digest ใน audit; ไม่เก็บ secret output

การเปิด test/build ไม่ควรถูกตีความว่า repository ปลอดภัย หากต้องรันโค้ดที่ไม่ trusted จริง ให้ใช้ VM/CI sandbox แยกเป็น policy ต่อไป

### macOS-specific controls

- ใช้ Keychain Services เก็บ tunnel identity/credential และทำให้ item เข้าถึงได้เฉพาะ application ที่ลงนาม
- ใช้ native folder chooser และ security-scoped bookmark สำหรับ user-selected folders เมื่อ packaging แบบ sandboxed
- ไม่ขอ Full Disk Access เป็นค่าเริ่มต้น; ถ้า path ต้องใช้ TCC permission ให้แสดงเหตุผลและขอเฉพาะตอนผู้ใช้เลือก
- ใช้ hardened runtime, code signing และ notarization ใน release
- GUI ↔ broker ใช้ UDS 0600; ไม่มี unauthenticated admin HTTP endpoint บน loopback
- ถ้าใช้ LaunchAgent ให้ label และ pid file เฉพาะของแอป และหยุดเฉพาะ process group ที่แอปเป็นเจ้าของ
- ไม่รันเป็น root และไม่ใช้ privileged helper ใน MVP

ข้อจำกัดที่ต้องสื่อสารตรง ๆ: application-level allowlist ป้องกัน model/tool misuse ได้ดี แต่ไม่ใช่ OS sandbox เต็มรูปแบบ หาก process เดียวกันถูก compromise และทำงานด้วย user เดียวกัน มันอาจยังใช้สิทธิ์ของ user ได้ ดังนั้นงานที่ไม่ trusted ต้องเลื่อนไป sandbox/VM

## 7. Document adapters

### CSV

- operations: inspect, select rows, append rows, update cells, sort by declared columns, rename columns
- รองรับ UTF-8/BOM และ encoding ที่ระบุชัด
- preserve delimiter/newline เมื่อทำได้; รายงานเมื่อ format เปลี่ยน
- ป้องกัน CSV formula injection โดย neutralize ค่าเริ่มต้นที่ขึ้นต้นด้วย `=`, `+`, `-`, `@`; การเขียนสูตรต้องเป็น option explicit + approval
- แสดง row/cell diff ก่อน overwrite

### Excel

- MVP: `.xlsx`; `.xlsm` เปิดได้เมื่อใช้ `keep_vba`/macro-preservation path ที่ทดสอบแล้ว
- `.xls` ให้ read-only ใน MVP
- operations: inspect workbook/sheets, read range, update cells/range, append rows, rename sheet, add sheet
- ไม่ execute macro, external link, formula หรือ embedded object
- ไม่ส่ง workbook ทั้งไฟล์ให้ model เป็นค่าเริ่มต้น; ให้ read range ตาม request และ quota
- validate open/reload หลังเขียน และเก็บ pre/post hash
- ถ้า workbook มี feature ที่ adapter ไม่รับรอง ให้ deny หรือขอผู้ใช้ export copy ก่อน

### Word

- MVP: `.docx`; `.doc` ให้ read-only
- operations: inspect paragraphs, replace exact text, append paragraph, update declared table cells
- แสดง diff ระดับ paragraph/table ไม่ส่งเอกสารทั้งฉบับโดยไม่จำเป็น
- ไม่ execute field, macro, embedded OLE หรือ external relationship
- backup ก่อน rewrite เพราะ library อาจไม่ preserve feature ที่ไม่รู้จัก

Document adapter ทุกตัวต้องอยู่หลัง broker; ห้ามรับ path absolute หรือเปิด API ที่รับ script/expression จาก model

## 8. GUI Control Center

### Overview

- cards: Control Center, Policy broker, MCP bridge, Tunnel, ChatGPT path
- ปุ่ม Start/Stop ของ MCP และ tunnel แยกกัน
- pending approvals count
- warning ถ้ามี dirty project worktree หรือ policy เปลี่ยนแต่ runtime ยังใช้ version เก่า

### Allowed Paths

แต่ละ row แสดง:

```text
Label | Kind | Exposed to MCP | Read | Write | Create | Rename | Move | Delete | Status
```

การเพิ่ม path ใช้ native chooser, canonicalize ทันที, ปฏิเสธ broad/protected root และตั้งค่าเริ่มต้นเป็น read-only + `expose_to_mcp = false` จนผู้ใช้ยืนยัน

### Tools

จัดกลุ่ม Files, Documents, Project, Runtime พร้อมคำอธิบายภาษาไทย/อังกฤษ, risk level, enabled toggle, approval mode และ quota ห้ามมี toggle ชื่อ Shell หรือ “Full access”

### Approval Inbox

แสดงข้อมูลที่ทำให้ผู้ใช้ตัดสินใจได้จริง:

- Tool/operation และเหตุผลที่ต้อง approval
- scope label + relative target
- before/after hash และ semantic diff
- จำนวนไฟล์/bytes และผลกระทบเรื่อง overwrite/move/delete
- policy version, expiry และ session
- ปุ่ม `Deny` และ `Allow Once`

ไม่มีปุ่ม `Allow Everything` ใน MVP

### Audit Log

ค้น/กรองตาม time, actor, tool, operation, scope, decision, request id และ approval id ดูรายละเอียด event chain และ export เป็น redacted JSONL ได้ โดยไม่มีเนื้อหาไฟล์เป็นค่าเริ่มต้น

### Settings

- tunnel profile reference และ connection test
- launch at login
- default approval policy
- data redaction/retention
- language และ notification preference
- export/import policy แบบไม่รวม secret

## 9. Folder structure ของ repository ใหม่

ไม่ควรวางโค้ดนี้ใน MRP repo เพราะ Control Center เป็น security boundary และมี lifecycle แยก

```text
local-mcp-control-center/
├── apps/
│   └── control-center/
│       ├── src/                    # React UI
│       ├── src-tauri/
│       │   ├── src/main.rs
│       │   ├── commands.rs         # thin GUI commands
│       │   ├── supervisor.rs
│       │   └── macos.rs            # Keychain/bookmarks/LaunchAgent
│       └── capabilities/
├── crates/
│   ├── policy-core/
│   │   ├── src/path.rs
│   │   ├── src/permissions.rs
│   │   ├── src/approval.rs
│   │   ├── src/action_hash.rs
│   │   └── src/errors.rs
│   ├── audit-store/
│   │   ├── src/schema.rs
│   │   ├── src/hash_chain.rs
│   │   └── src/redaction.rs
│   └── process-supervisor/
│       ├── src/profiles.rs
│       └── src/ownership.rs
├── services/
│   ├── mcp-bridge/
│   │   ├── pyproject.toml
│   │   ├── src/mcp_bridge/server.py
│   │   ├── src/mcp_bridge/contracts.py
│   │   ├── src/mcp_bridge/broker_client.py
│   │   └── tests/
│   └── document-adapters/
│       ├── csv_adapter.py
│       ├── xlsx_adapter.py
│       ├── docx_adapter.py
│       └── tests/
├── config/
│   ├── tool-registry.json
│   ├── execution-profiles.json
│   └── protected-targets.json
├── migrations/
├── tests/
│   ├── policy/
│   ├── approval-replay/
│   ├── integration/
│   └── fixtures/
├── packaging/macos/
│   ├── entitlements.plist
│   ├── launch-agent.plist.template
│   └── notarization.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT-MODEL.md
│   └── RUNBOOK.md
└── CONTEXT.md
```

## 10. ATM project bootstrap profile

เมื่อผู้ใช้เปิด GUI และเลือก directory ปัจจุบัน ให้เสนอ profile นี้เป็น draft เท่านั้น:

```json
{
  "id": "atm-project",
  "label": "Project ATM Coperation",
  "kind": "project",
  "root": "/Users/indierockbadgirl/Desktop/for-work/Project/Project-ATM-Coperation",
  "expose_to_mcp": true,
  "permissions": {
    "read": "allow",
    "write": "allow_with_approval",
    "create": "allow_with_approval",
    "rename": "deny",
    "move": "deny",
    "delete": "deny"
  },
  "tools": {
    "git_status": "allow",
    "git_diff": "allow",
    "git_log": "allow",
    "run_backend_test": "execute + fixed profile",
    "run_frontend_test": "execute + fixed profile",
    "run_build": "execute + fixed profile"
  }
}
```

ข้อควรระวัง:

- path ข้างต้นเป็นค่าที่ตรวจพบจากเครื่องนี้ ไม่ควร hard-code ใน release; ให้ native chooser เป็นผู้ยืนยัน root จริง
- ตอน register ให้ scan และแสดง dirty worktree แต่ห้าม reset, clean, stash หรือ overwrite งานเดิมอัตโนมัติ
- default ไม่ expose `.env`, credentials, `.git/config`, `.git/objects`, virtualenv, `node_modules` และ binary ขนาดใหญ่
- `write` ใน profile หมายถึง broker ตรวจ capability, hash และ atomic mutation; dangerous operations เท่านั้นที่ขอ approval ใน runtime 0.2.0
- Git mutation เปิดเฉพาะ branch/stage/commit ที่ระบุ path และ `execute` อนุญาต; restore/push ต้อง approval. Docker, service restart และ package install ยังไม่เปิด

สำหรับ allowed file directories อื่น เช่น `Documents/Accounting` ให้เริ่มเป็น `read=true`, `write/create/rename/move/delete=false`, `expose_to_mcp=false` แล้วให้ผู้ใช้เปิดเป็นราย capability หลังตรวจ path

## 11. MVP phases

### Phase 0 — Contract and threat model

ผลลัพธ์:

- glossary และ threat model
- Tool registry แบบ enum
- ActionIntent/Approval/ExecutionResult schema
- protected-target rules และ path semantics

เกณฑ์ผ่าน: ทุก Tool มี input/output/error/approval behavior ระบุได้ และไม่มี arbitrary shell surface

### Phase 1 — Policy core แบบยังไม่มี MCP

ผลลัพธ์:

- scope registration
- canonical path resolver
- permission evaluator
- action hash
- SQLite migrations
- audit append/hash chain

เกณฑ์ผ่าน: policy tests ครอบคลุม traversal, symlink, overlap, protected path, stale hash, quota และ permission matrix

### Phase 2 — Read-only bridge + GUI พื้นฐาน

ผลลัพธ์:

- `list_scopes`, `list_files`, `read_file`, `search_text`
- GUI Overview, Allowed Paths, Tools, Audit
- UDS broker protocol
- redaction/size limits

เกณฑ์ผ่าน: MCP initialize/list-tools และ read-only calls ทำงานได้ใน temp fixture; ทุก call มี audit; path นอก scope ถูก deny

### Phase 3 — Controlled mutations and approval

ผลลัพธ์:

- write/create/rename/move/delete ที่จำกัด
- Approval Inbox
- exact action hash + TTL + one-time consume
- atomic write, backup, pre/post hash

เกณฑ์ผ่าน: approve action A ไม่สามารถนำไปใช้กับ target/input B; policy เปลี่ยนแล้ว approval เก่าถูก invalidate; failed validation ไม่ mutate

### Phase 4 — CSV/XLSX/DOCX adapters

ผลลัพธ์:

- semantic edit tools
- diff preview
- format-specific safety rules
- round-trip validation fixtures

เกณฑ์ผ่าน: supported formats แก้ไขและ reopen ได้, unsupported features fail closed, formula/macro/external-link rules ผ่านการทดสอบ

### Phase 5 — ATM Git/test/build profiles

ผลลัพธ์:

- git read tools
- fixed backend/frontend test profiles
- build profile
- clean environment, output limits, timeout
- dirty-worktree warning

เกณฑ์ผ่าน: รันได้เฉพาะ enum profile; extra command/flag/working directory ถูก reject; test/build ต้องมี execute policy และ audit

### Phase 6 — Tunnel and macOS lifecycle

ผลลัพธ์:

- tunnel-client supervisor — ทำแล้วใน Python reference MVP
- Keychain credential reference — ทำแล้วสำหรับ runtime API key ของ tunnel
- start/stop/status/diagnostics — ทำแล้วผ่าน GUI
- LaunchAgent option — ยังไม่ทำ
- signed/notarized packaging — ยังไม่ทำ

เกณฑ์ที่ผ่านใน reference MVP: ไม่มี inbound listener จาก Control Center เอง, ใช้ `tunnel-client` แบบ outbound, process ownership ตรวจได้, restart เฉพาะ process ของแอป, MCP path แสดงเป็นพร้อม/ไม่พร้อมตาม health โดยไม่รายงาน ChatGPT connected เกินหลักฐาน

### Phase 7 — Hardening

ผลลัพธ์:

- sandboxed helper/XPC หรือ VM path สำหรับ untrusted execution
- fuzz path/action parser
- crash recovery และ audit integrity check
- policy export/import review
- security review/red-team prompt injection fixtures

เกณฑ์ผ่าน: compromise ของ MCP bridge ไม่สามารถข้าม broker policy ใน threat model ที่ประกาศ และ recovery ไม่ทำให้ pending approval กลายเป็น valid โดยอัตโนมัติ

## 12. Implementation order ที่แนะนำ

1. Freeze contracts และ error codes ก่อนทำ GUI
2. ทำ `policy-core` เป็น pure Rust module ที่รับ dependency ผ่าน interface; ทดสอบด้วย in-memory adapter
3. ทำ audit store และ redaction ก่อนเปิด write tool
4. ทำ broker UDS protocol ที่ request ทุกตัวมี correlation id และ nonce
5. ทำ read-only MCP bridge และใช้ MCP Inspector/official protocol client ตรวจ handshake
6. ทำ GUI ให้แก้ policy ผ่าน broker interface เดียวกับที่ test ใช้; ห้ามให้ UI เขียน SQLite ตรง
7. เพิ่ม approval state machine และ replay/stale tests
8. เพิ่ม file operations ทั่วไป แล้วค่อย document adapters
9. เพิ่ม project command profiles หลัง policy/file layers stable
10. เพิ่ม tunnel supervisor เป็นขั้นท้าย เพราะ transport ไม่ควรถูกใช้กลบ policy defect
11. package/sign/notarize หลัง integration tests ผ่าน

### Error codes ที่ควร freeze ตั้งแต่ต้น

```text
INVALID_INPUT
SCOPE_NOT_FOUND
SCOPE_DISABLED
MCP_EXPOSURE_DISABLED
PATH_ABSOLUTE
PATH_TRAVERSAL
SYMLINK_NOT_ALLOWED
PROTECTED_TARGET
TOOL_DISABLED
CAPABILITY_DENIED
QUOTA_EXCEEDED
APPROVAL_REQUIRED
APPROVAL_NOT_FOUND
APPROVAL_EXPIRED
APPROVAL_ALREADY_USED
STALE_APPROVAL
PRECONDITION_CHANGED
FORMAT_UNSUPPORTED
FORMAT_VALIDATION_FAILED
PROFILE_NOT_ALLOWED
PROCESS_TIMEOUT
PROCESS_OUTPUT_LIMIT
RUNTIME_NOT_READY
```

## 13. Verification plan

### Policy tests

- `../secret.txt`, absolute path, encoded traversal และ NUL
- root เป็น symlink, child เป็น symlink, symlink เปลี่ยนหลัง preflight
- overlap ของ scopes และ protected path precedence
- read ไม่ grant write; create ไม่ grant overwrite
- move ต้องผ่าน source/destination ทั้งคู่
- delete directory/recursive ถูกปฏิเสธ
- quota files/bytes และ output truncation

### Approval tests

- action hash เปลี่ยนเมื่อ target, content หรือ precondition เปลี่ยน
- approve once ใช้ซ้ำไม่ได้
- expiry/policy version mismatch fail closed
- ผู้ใช้ deny แล้ว model เรียก apply ซ้ำไม่ได้
- broker crash/restart ไม่เปลี่ยน pending เป็น approved

### Document tests

- CSV encoding/newline/formula injection
- XLSX formulas, styles, merged cells, workbook reopen
- XLSM macro bytes preservation policy
- DOCX paragraph/table replacement และ unsupported relationship warning
- backup/restore และ post-hash

### Process tests

- profile enum เท่านั้น; arbitrary arg rejected
- `shell=True`/command string static check
- fixed cwd และ environment scrub
- timeout, output cap, process ownership
- Docker/socket/sudo/package install not reachable

### Integration and release tests

- MCP initialize → list tools → read → pending approval → GUI approve → apply → audit
- tunnel disconnected/reconnected state
- app stop does not kill unrelated process
- launch at login uses current policy version
- signed app cannot read protected target through GUI or MCP

## 14. Open decisions ที่ควรล็อกก่อนเริ่มเขียนโค้ด

1. minimum macOS version: แนะนำ macOS 14+ เพื่อใช้ API/security behavior ที่สม่ำเสมอ
2. distribution: internal signed/notarized DMG ก่อน; Mac App Store sandbox เป็นตัวเลือกภายหลัง
3. initial Python packaging: developer mode ใช้ bundled/managed runtime; release ใช้ sidecar ที่ pin dependencies และ hash artifacts
4. `.xls`/`.doc` policy: read-only ใน MVP หรือมี explicit conversion workflow แยก
5. ChatGPT plan/workspace: ทดสอบว่า account มี custom MCP/developer mode และ write actions ตามสิทธิ์ของ workspace ก่อนผูก tunnel จริง
6. retention: audit metadata เก็บกี่วัน และ snapshot backup เก็บกี่รุ่น โดยไม่ลบ audit หลักแบบเงียบ ๆ

## 15. Definition of Done สำหรับ initial release

- มี GUI ที่ลงทะเบียน scope และแก้ permission ได้
- มี read-only MCP path ที่ผ่าน tunnel โดยไม่มี inbound port
- มี write tools ที่ปิดเป็นค่าเริ่มต้น และ dangerous actions มี exact approval flow
- มี document operations ตาม supported-format matrix
- มี ProjectProfile สำหรับ targeted test/lint/typecheck/build และ managed process lifecycle
- ไม่มี arbitrary shell หรือ Docker socket
- ทุก request และ policy change มี redacted audit event พร้อม hash chain
- มี tests สำหรับ traversal, symlink, stale approval, atomic write และ process allowlist
- package เป็น signed/notarized macOS app และมี recovery/diagnostics runbook

## 16. เอกสารอ้างอิง

- [OpenAI — MCP and Connectors](https://developers.openai.com/api/docs/guides/tools-connectors-mcp)
- [OpenAI — Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)

## 17. Actual Developer Agent Runtime V1

หัวข้อนี้เป็น contract ที่มีอยู่จริงใน checkout นี้ ไม่ใช่ target architecture ที่ยังไม่ implement. Runtime ไม่มี Codex dependency:

```text
ChatGPT Lead / MCP client
          │ stdio / tunnel
          ▼
 MCPServer + ToolRegistry
      schema validation
          ▼
      Policy Broker
 scope + capability + audit
          │
          ▼
 Provider-backed Agent Task API
          │ create/get/list/result/cancel
          ▼
 AgentRuntimeService
 role profiles + limits + SQLite lifecycle
          │
   ┌──────┼──────────┐
   ▼      ▼          ▼
 Provider Tool Facade WorktreeManager
 adapter  → Broker   fixed Git only
```

### MCP Agent Task API

| Tool | Input summary | Output/behavior |
|---|---|---|
| `create_agent_task` | `role`, bounded `task`, approved `scope_id`, configured `model_profile`; optional `parent_task_id`, `base_ref` | Creates one persisted task; role/system instructions/capabilities are server-derived. |
| `get_agent_task` | `task_id` | Returns finite lifecycle state, role/scope, provider/model, capability context and worktree/base metadata. |
| `get_agent_result` | `task_id` | Returns terminal structured result: summary, actual changed files, verification, tests, worktree/base commit, provider/model, warnings/errors and timestamps. |
| `list_agent_tasks` | optional approved `scope_id`, finite `status`, limit ≤ 100 | Returns bounded recent persisted metadata with per-scope visibility checks. |
| `cancel_agent_task` | `task_id` | Signals only the owned worker, atomically marks it cancelled when active, preserves result metadata and audits the action. |

The only task states are `queued`, `starting`, `running`, `completed`, `failed` and `cancelled`. Mutation/execute task tools are policy-disabled by default; they must be enabled in Control Center before appearing in MCP `tools/list`. Read-only task inspection is independently policy-controlled.

### Role capability contract

| Role | Allowed | Explicitly denied |
|---|---|---|
| Explorer | scoped read/search/list, Git reads, context/code discovery | write/create/delete, test execution, Git mutation, shell, worker spawn |
| Implementer | scoped read/search, write/create in its isolated worktree, Git diff, targeted test profile | delete, rename/move, Git mutation/push/reset/clean, shell, worker spawn |
| Reviewer | scoped read/search, Git reads/diff and context/code discovery; may inspect a parent Implementer worktree | all writes/creates/deletes, test execution, Git mutation, shell, worker spawn |
| Tester | scoped read/search, Git reads, targeted test profile | source/test writes, create/delete, Git mutation, shell, worker spawn |

The role profile is persisted as an `AgentCapabilityContext`. The provider receives that context and a role-derived system instruction, but the `AgentToolFacade` remains authoritative and checks the role allowlist, current tool policy, effective scope capability, path policy, preconditions and cancellation before every operation. Workers cannot call the MCP task API or receive a child-agent tool.

### Provider and runtime boundary

`AgentModelProvider` exposes only `run_agent(...)` and `cancel(...)`. The runtime ships a fixed-endpoint `OpenAIChatProvider` adapter that reads `OPENAI_API_KEY` from local process configuration and uses `LOCAL_MCP_AGENT_MODEL` (default `gpt-5.6-luna`); `FakeModelProvider` supplies deterministic tests. Additional providers can be registered through the trusted local `AgentModelProfile` control-plane seam. MCP task input can select only a configured profile name; it cannot provide credentials, endpoint, executable, argv, environment, cwd or raw system prompt.

`AgentRuntimeService` owns task threads, cancellation events, provider invocation, result normalization, restart recovery and runtime limits. SQLite tables `agent_tasks` and `agent_results` are additive to the existing Store and persist state across MCP request boundaries. Incomplete tasks found at startup become `failed` with `RUNTIME_RESTARTED`; the runtime does not silently retry.

Defaults are explicit and hard-bounded: four concurrent workers, six workers per root task, 80 tool calls per worker, 1 MiB result, 1 MiB tool output and 15 minutes runtime. Configuration may lower these values, never raise the module hard caps.

### Worktree and security boundary

Implementers require a project scope with `read`, `write`, `create` and `execute`. For a Git repository root, `WorktreeManager` resolves a validated `base_ref` (default `HEAD`), records `base_commit` and source dirty state, then creates a server-generated detached worktree below the private application data directory. It never accepts a model-selected path, overwrites a collision, resets/cleans the main working tree, or automatically removes review evidence. Reviewers with an Implementer `parent_task_id` reuse that worktree through the hidden read-only effective scope.

Every lifecycle transition and worktree creation is written to the existing redacted audit hash chain. Forbidden worker operations produce `TOOL_NOT_ALLOWED`/policy errors and an audit row. Existing Broker operations enforce canonical scope-relative paths, symlink/traversal/protected-target rules, exact write preconditions and fixed test/Git adapters. No arbitrary shell, unrestricted subprocess, recursive delete, force Git operation, credential access or recursive worker spawn is reachable from the Agent Task API.

### Existing compatibility and deferred scope

The original MCP tools and the earlier fixed-profile delegated-agent compatibility path remain registered; the provider-backed API is additive. The runtime uses local threads and fixed/scrubbed adapters, not an OS-level hostile-code sandbox. Automatic merge/push, autonomous planning, child MCP/browser/desktop automation, distributed workers, queue infrastructure and unrelated MRP changes remain out of scope for V1.
