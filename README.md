# Local MCP Control Center

macOS-first local control center สำหรับ MCP แบบ least privilege ตาม blueprint ของโปรเจกต์นี้ โดยรุ่นปัจจุบันมี tunnel-client integration สำหรับ Secure MCP Tunnel แล้ว

รุ่นนี้ตั้งใจให้ runnable และตรวจสอบได้บน Python/Tkinter ก่อน โดยแยกชั้นสำคัญไว้ชัดเจน:

- `PolicyEngine` ตรวจ scope, canonical path, capability, quota และ protected targets
- `Broker` เป็นจุดเดียวที่รับคำขอ MCP และทำ approval/execution
- `Store` เก็บ policy, approval, runtime state และ audit metadata ใน SQLite
- `DocumentAdapter` รองรับ CSV, `.xlsx`/`.xlsm` และ `.docx` ด้วย operation ที่กำหนดไว้ล่วงหน้า
- `FixedRunner` รองรับ git read, backward-compatible test/build profiles และ ProjectProfile ที่ตรวจจากโครงสร้างโปรเจกต์สำหรับ targeted test/lint/typecheck/dev
- `WorkspaceIndexService` และ `WorkspaceContextService` ให้ metadata index, symbol/reference search และ deterministic context ranking โดยไม่เก็บ source content ลง SQLite; `ContextLedger` ช่วย deduplicate การส่ง context แบบ bounded และ in-memory
- `CompoundReadExecutor` ทำ batch เฉพาะ READ tools ที่ allowlist ไว้; `dependency_graph` วิเคราะห์ import metadata แบบ read-only; `AgentTaskManager` รองรับ delegated task เฉพาะ profile ที่ configure ไว้ล่วงหน้า
- `MCPServer` เปิดเฉพาะ tools ที่ผู้ใช้เปิดใน Control Center
- `TunnelClientAdapter` เรียก `tunnel-client init`, `doctor` และ `run` ด้วย profile directory ของแอป และไม่รับ shell command จากผู้ใช้
- macOS Keychain เก็บ runtime API key; SQLite เก็บเฉพาะ tunnel ID, profile และ executable path
- Tkinter GUI จัดการ allowed paths, permissions, tools, approvals, audit และ runtime/tunnel lifecycle

รุ่นนี้ไม่มี `shell`, `exec`, `run_command`, `python`, `node_eval` หรือ Docker tool

## ติดตั้ง

```text
cd /path/to/local-mcp-control-center
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

ถ้าใช้ checkout นี้โดยตรง ให้ใช้ path เต็มของโฟลเดอร์:

```text
/Users/indierockbadgirl/Documents/Codex/2026-08-29/referenced-chatgpt-conversation-this-is-an/outputs/local-mcp-control-center
```

## วิธีใช้งานจริง

Control Center ไม่ใช่ช่องแชต และไม่ใช่ terminal สำหรับพิมพ์คำสั่งธรรมชาติ หน้าที่ของมันคือกำหนดว่า ChatGPT มีสิทธิ์ทำอะไรบนเครื่องได้บ้าง แล้วเป็นคนดูแล MCP bridge/tunnel ให้ทำงานอยู่

ลำดับการใช้งานคือ:

1. เปิด GUI ด้วยคำสั่งด้านล่าง
2. ใน `Allowed Paths` เพิ่มโฟลเดอร์ `Project-ATM-Coperation` และเปิด `read` ก่อน
3. ใน `Tools` เปิดเฉพาะเครื่องมือที่ต้องใช้
4. กด `Configure tunnel` ใส่ `tunnel_id`, runtime API key และกด `Save & initialize profile`
5. กด `Run tunnel doctor` ให้ผ่าน แล้วกด `Start tunnel`
6. ไปที่ ChatGPT สร้าง developer-mode app เลือก `Tunnel` แล้วเลือก/ใส่ tunnel ID
7. หลังจากนั้นจึงพิมพ์คำสั่งธรรมชาติในบทสนทนา ChatGPT ที่ผูก app นั้น เช่น “ดูไฟล์ใน scope โปรเจกต์และสรุป git diff”

ในแท็บ `Runtime` ให้ตรวจสองค่าคู่กันก่อนสร้าง app:

- `Health: ready` หมายถึง process local ตอบ health check ได้เท่านั้น
- `OpenAI connection: authenticated` หมายถึง control plane รับรอง key และมีการ poll สำเร็จ
- ถ้าเห็น `unauthorized` หรือ `401 Unauthorized` ให้เปิด Configure tunnel แล้วใส่ key ที่ Platform ยังเป็น `Active` ใหม่อีกครั้ง โดยดูท้าย key ให้ตรงกัน เช่น `…8WgA`; อย่าปล่อยช่อง key ว่าง เพราะจะนำ key เดิมใน Keychain กลับมาใช้
- ถ้า key suffix ตรงกับ Platform แล้วยังได้ 401 ให้ตรวจว่าเป็น runtime API key ของ Platform organization เดียวกับ tunnel และมี `Tunnels Read + Use`

การสร้างและเลือก tunnel ต้องใช้สิทธิ์ของ Platform organization และ ChatGPT workspace แยกกัน ดูรายละเอียดใน [Secure MCP Tunnel ของ OpenAI](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)

## Developer Agent Runtime

รุ่นนี้เพิ่ม developer workflow แบบ additive โดยทุก MCP call ยังผ่าน `ToolRegistry → schema validation → PolicyEngine/Broker → adapter → audit` เส้นทางเดียว:

```text
MCP client
  → Tool Registry + schema
  → Policy Broker (scope / capability / approval / precondition)
  → filesystem | ProjectProfile | GitAdapter | owned process
  → bounded structured result + trace audit
```

เครื่องมือที่เพิ่ม/เปิดใช้ได้เมื่อผู้ใช้เปิด policy:

- Discovery/files: `find_files`, `search_regex`, `read_many_files`, `read_file_page`, `read_file_page_continue`
- Editing: `apply_patch` แบบ exact unified hunk พร้อม hash, backup และ changed line ranges
- Verification: `run_targeted_test`, `run_lint`, `run_typecheck`; `run_backend_test`, `run_frontend_test`, `run_build` ยังคงเป็น compatibility tools
- Runtime: `process_start_profile`, `process_status`, `process_logs`, `process_stop`
- Git: `git_create_branch`, `git_stage_paths`, `git_commit`, `git_restore_file`, `git_push`
- Context/code: `workspace_snapshot`, `workspace_context`, `workspace_index`, `workspace_index_status`, `symbol_search`, `find_definition`, `find_references`, `dependency_graph`
- Batch/control: `tool_batch` (READ-only children เท่านั้น), `dry_run`
- Delegated agent: `agent_status`, `agent_task_status`, `agent_task_logs`, `agent_result`, `agent_run`, `agent_cancel`; ต้อง configure `AgentProfile` จาก control plane ก่อนจึงจะ run ได้

Permission class มี `READ`, `WRITE`, `EXECUTE`, `DANGEROUS` และแยกจาก scope capabilities (`read`, `execute`, `write`, `create`, `rename`, `move`, `delete`) อย่างชัดเจน การเปิด tool ไม่ได้ grant สิทธิ์ scope เพิ่มเอง

ตัวอย่าง workflow:

1. เปิด `read` แล้วเรียก `list_scopes`, `workspace_snapshot`, `git_status`, `search_regex`, `read_many_files`
2. เรียก `symbol_search`/`find_references` และ `dry_run` ก่อนแก้ไข
3. เปิด `write` + `apply_patch`, ส่ง `expected_hash` เมื่อมี hash จากการอ่าน และตรวจ `git_diff`
4. เปิด `execute` แล้วเรียก targeted test, lint, typecheck หรือ build ตาม ProjectProfile ที่ตรวจได้
5. ใช้ `git_stage_paths`/`git_commit` กับ path ที่ระบุชัดเจนเท่านั้น
6. ใช้ `git_restore_file`, `git_push` หรือ `delete_file` ได้เฉพาะหลัง `Approve once → Apply approved`

`apply_patch` ไม่ใช้ fuzzy matching; หาก context/hash เปลี่ยนจะคืน `PRECONDITION_CHANGED` หรือ `PATCH_CONTEXT_MISMATCH` และไม่เขียนทับเวอร์ชันใหม่. Paged read ใช้ continuation token ที่ผูกกับ actor, scope, path และ content hash. Context/index เป็นตัวช่วยจัดลำดับความเกี่ยวข้อง ไม่ใช่ตัวตัดสิน authorization

Process ใช้เฉพาะ executable/argument array จาก ProjectProfile หรือ explicit `AgentProfile`, `shell=False`, isolated runtime environment, process group ที่ Control Center เป็นเจ้าของ และ log สูงสุด 1 MiB พร้อม redaction. Git ไม่มี generic `git(args[])`; `reset`, `clean`, force push, recursive delete, credential access, desktop/browser automation และ child-MCP forwarding ยังไม่เปิดใช้งาน

`tool_batch` มี parent scope เป็น anchor แต่ child ทุกตัวเรียกผ่าน Broker ใหม่และต้องผ่าน schema, tool policy, capability, path policy และ audit ของตัวเอง. `workspace_context` รับ `delivery_key` แบบ optional เพื่อเก็บเพียง digest ใน in-memory ledger; เมื่อ context เดิมไม่เปลี่ยนจะละเว้น snippets ซ้ำ. `dependency_graph` คืนเฉพาะ relative metadata/edges/diagnostics และมี bounds ของ files, edges, bytes และ output.

Delegated agent compatibility path ใช้เฉพาะ profile ที่ผู้ใช้ configure จาก control plane (`Broker.configure_agent_profile`); MCP caller ส่งได้เพียง `scope_id`, profile name, bounded prompt และ timeout. manager ไม่อ่าน credentials, ไม่รับ executable/argv/env/cwd/PID จาก MCP, ไม่ persist prompt และไม่ถือว่า agent claim เป็นผล verification.

### Provider-backed Agent Task API V1

นี่คือ orchestration path หลักสำหรับ worker แบบ `explorer`, `implementer`, `reviewer` และ `tester` โดย ChatGPT เป็น Lead ที่ตัดสินใจว่าจะ delegate เมื่อใด ส่วน MCP เป็น control plane ที่ validate, authorize, start, cancel, persist และ audit งาน เครื่องมือทั้งห้าคือ:

```text
create_agent_task  →  get_agent_task / get_agent_result
                   →  list_agent_tasks / cancel_agent_task
```

`create_agent_task` รับเฉพาะ `role`, bounded `task`, approved `scope_id`, trusted `model_profile` และ optional `parent_task_id`/`base_ref`; ไม่มี raw system prompt, command, executable, environment, provider URL หรือ filesystem path ให้ caller/model เลือกเอง ระบบสร้าง capability context และ system instructions จาก role ฝั่ง server

Provider ถูกลงทะเบียนจาก trusted local configuration ผ่าน `Broker.configure_agent_model_profile` หรือ `OPENAI_API_KEY` สำหรับ profile `openai-default` (endpoint ถูกกำหนดในโค้ด; model ใช้ `LOCAL_MCP_AGENT_MODEL` หรือค่าเริ่มต้น `gpt-5.6-luna`) และเลือกผ่านชื่อ profile เท่านั้น ไม่เก็บ key ใน SQLite หรือ audit การทดสอบใช้ `FakeModelProvider` แบบ deterministic ได้โดยไม่ต้องมี credential

สถานะที่ persist มีเพียงชุดจำกัด `queued`, `starting`, `running`, `completed`, `failed`, `cancelled` ผลลัพธ์ประกอบด้วย summary, actual changed files, verification, tests, worktree/base commit, provider/model, warnings/errors และ timestamps. `get_agent_result` จะตอบ `RESULT_NOT_READY` จนกว่างานจะ terminal

สิทธิ์ของ role ถูก enforce ที่ `AgentToolFacade` และ Broker อีกชั้นหนึ่ง: Explorer/Reviewer อ่านอย่างเดียว, Tester อ่านและรันเฉพาะ targeted-test profile, Implementer เขียน/สร้างได้เฉพาะ isolated Git worktree และรัน targeted test ได้ แต่ไม่มี delete, Git mutation, push, shell หรือ worker spawn. ทุก tool call ยังผ่าน path/protected-target/hash/precondition/audit ของ Broker เดิม

Implementer ใช้ worktree ที่สร้างจาก `base_ref` (default `HEAD`) และบันทึก `base_commit`, source dirty state และ path ที่ระบบสร้างเอง; main working tree ไม่ถูก reset/clean/overwrite และ evidence ไม่ถูกลบอัตโนมัติ. Reviewer ที่ระบุ `parent_task_id` ของ Implementer จะอ่าน diff จาก worktree เดิมแบบ read-only

ค่าเริ่มต้นที่ enforce: concurrent workers 4, workers ต่อ root 6, tool calls ต่อ worker 80, result 1 MiB และ runtime 15 นาที (ทุกค่ามี hard cap และลดได้จาก configuration). Worker ไม่สามารถเรียก `create_agent_task` หรือเปิด child MCP ได้ จึงไม่มี recursive self-orchestration ใน V1

สร้าง/ยกเลิก tool เป็น mutation/execute policy จึงต้องเปิดใน Control Center ก่อนให้ปรากฏใน MCP `tools/list`; `get`, `result` และ `list` เป็น read-only discovery ที่เปิดได้ตาม policy. เมื่อปิด MCP แล้ว runtime ยังเป็น Python local service ที่ใช้ provider adapter ปกติ ไม่มี Codex API, Codex thread, Codex binary หรือ Codex session state เป็น runtime dependency

### Migration notes

เครื่องมือเดิมและชื่อเดิมยังอยู่ใน registry; client เดิมที่เรียก `list_scopes`, filesystem primitives, document tools, `git_status`/`git_diff`/`git_log`, test/build และ `runtime_status` ไม่ต้องเปลี่ยน contract. Client ใหม่ควรใช้ `run_targeted_test` แทนการประกอบ command เอง และใช้ `apply_patch` แทนการเขียน source ทั้งไฟล์เมื่อแก้เฉพาะจุด

### เปิด GUI

```text
cd /path/to/local-mcp-control-center
.venv/bin/local-mcp --data-dir "$HOME/Library/Application Support/LocalMCPControlCenter" gui
```

ในรุ่นนี้ยังเป็น Tkinter reference app จึงยังไม่มี `.app` สำหรับดับเบิลคลิกจาก Applications

## เริ่มใช้งานกับ Project-ATM-Coperation

เพิ่ม scope แบบ read-only และยังไม่ expose ให้ MCP:

```text
.venv/bin/local-mcp --data-dir '/Users/indierockbadgirl/Library/Application Support/LocalMCPControlCenter' add-scope \
  --scope-id atm-project \
  --label 'Project ATM Coperation' \
  --kind project \
  --root '/Users/indierockbadgirl/Desktop/for-work/Project/Project-ATM-Coperation'
```

ถ้าต้องการให้ ChatGPT เห็น scope นี้ตั้งแต่ต้น ให้เพิ่ม `--expose` หลังจากตรวจ path แล้ว:

```text
.venv/bin/local-mcp --data-dir '/Users/indierockbadgirl/Library/Application Support/LocalMCPControlCenter' add-scope \
  --scope-id atm-project \
  --label 'Project ATM Coperation' \
  --kind project \
  --root '/Users/indierockbadgirl/Desktop/for-work/Project/Project-ATM-Coperation' \
  --expose
```

เปิด GUI:

```text
.venv/bin/local-mcp --data-dir '/Users/indierockbadgirl/Library/Application Support/LocalMCPControlCenter' gui
```

ใน GUI ให้เลือก scope แล้วเปิด capability ทีละรายการตามงานจริง โดย policy ของรุ่นนี้คือ:

- `read`: เปิดได้สำหรับ scope ที่ต้องให้ MCP สำรวจ
- `write`, `create`, `rename`, `move`: เมื่อเปิดแล้วทำงานทันทีภายใต้ path/quota/precondition ที่กำหนด
- `create_directory`: สร้างโฟลเดอร์ใหม่ได้ครั้งละหนึ่งโฟลเดอร์ใต้ parent ที่มีอยู่แล้ว โดยใช้ capability `create`; ไม่สร้าง parent ซ้อนอัตโนมัติและไม่เขียนทับเป้าหมายเดิม
- `bulk_move_files`: ย้ายไฟล์หลายไฟล์ในคำขอเดียวได้ โดยต้องส่งรายการ `source_relative_paths` ที่ระบุชื่อไฟล์ชัดเจนและส่งปลายทางเป็น directory เดียวกัน; ระบบจะตรวจและ hash ทุกไฟล์ก่อนเริ่ม, ไม่รับ wildcard, ไม่เขียนทับปลายทาง และคืน mapping ของทุกไฟล์
- `delete`: เมื่อเปิดแล้วจึงลบได้ แต่ทุกคำขอต้องกด `Approve once` และ `Apply approved`
- `Expose to MCP`: เปิดเฉพาะ scope ที่ต้องการให้ ChatGPT เห็น
- CSV/Excel/Word, test และ build: ทำงานทันทีเมื่อเปิด tool และ capability ที่เกี่ยวข้อง

ในแท็บ Allowed Paths สามารถเลือกได้ทั้ง folder scope และ file scope; file scope จะเห็นได้เฉพาะไฟล์ที่เลือกและใช้ relative path เป็น `.`

เมื่อ ChatGPT ขอแก้ไข/สร้าง/เปลี่ยนชื่อ/ย้ายไฟล์ หรือแก้ CSV/Excel/Word MCP จะตอบ `status: ok` และ `executed: true` หลังตรวจ policy แล้วลงมือทำทันที พร้อม backup สำหรับงานที่เขียนทับไฟล์ ส่วน `delete_file`, `git_restore_file` และ `git_push` จะตอบ `approval_required` และ `executed: false`; ให้เปิดแท็บ `Approvals` แล้วทำตามลำดับ `Approve once` → เลือกรายการที่มีสถานะ `approved` → `Apply approved` ภายในเวลาที่กำหนด

สำหรับการจัดไฟล์เป็นหมวด ให้สร้าง directory ปลายทางก่อนด้วย `create_directory` แล้วเรียก `bulk_move_files` โดยส่งรายการไฟล์ที่ตรวจแล้ว เช่น `TA_2026.pdf`, `ASS09_BIT07.pdf` และ `BIT-01.pdf` ไปยัง `01_University_BIT` ในคำขอเดียว การย้ายชุดนี้ไม่ต้อง approval ใน Control Center และไม่ใช่การลบ แต่ ChatGPT อาจแสดงการยืนยันตามนโยบายของแอปเอง หาก preflight พบไฟล์หาย, แฮชเปลี่ยน, symlink, path ไม่ปลอดภัย หรือปลายทางซ้ำ ระบบจะหยุดก่อนย้ายทุกไฟล์; หากเกิด filesystem error หลังเริ่ม ระบบจะพยายาม rollback ไฟล์ที่ย้ายไปแล้วและรายงาน mapping ที่ยังคงค้างอย่างชัดเจน

แท็บ `Approvals` จะแสดงคำขออันตรายที่รออนุมัติ ได้แก่ การลบไฟล์, Git restore และ Git push หากไม่มีรายการ แปลว่ายังไม่มีคำขออันตรายที่รออนุมัติ ไม่ใช่ระบบเสียหาย ปุ่ม `Open Approvals` ในหน้า Overview ใช้เปิดแท็บนี้ได้โดยตรง

การเพิ่ม scope ไม่ได้แก้ไขไฟล์ใน Project-ATM-Coperation และการลบ scope ก็ไม่ลบไฟล์จริง

เพื่อให้ approval อยู่รอดระหว่างการ refresh GUI รุ่น MVP เก็บ payload ของ pending action ไว้ใน SQLite ที่ directory mode `0700` และ database mode `0600`; runtime API key ของ tunnel ไม่เก็บใน SQLite แต่เก็บใน macOS Keychain

## คำสั่งตรวจสอบแบบไม่เปิด GUI

```text
.venv/bin/local-mcp --data-dir '/Users/indierockbadgirl/Library/Application Support/LocalMCPControlCenter' list-scopes
.venv/bin/local-mcp --data-dir '/Users/indierockbadgirl/Library/Application Support/LocalMCPControlCenter' list-tools
.venv/bin/local-mcp --data-dir '/Users/indierockbadgirl/Library/Application Support/LocalMCPControlCenter' pending-approvals
.venv/bin/local-mcp --data-dir '/Users/indierockbadgirl/Library/Application Support/LocalMCPControlCenter' verify-audit
```

## MCP/tunnel lifecycle

คำสั่ง `mcp` เปิด MCP bridge ผ่าน stdio สำหรับให้ tunnel client ที่ถูกตั้งค่าไว้เป็นผู้ถือ stdio connection:

```text
.venv/bin/local-mcp --data-dir '/Users/indierockbadgirl/Library/Application Support/LocalMCPControlCenter' mcp
```

GUI มีปุ่ม `Configure tunnel`, `Run tunnel doctor`, `Start tunnel` และ `Stop tunnel` แล้ว

`Start tunnel` จะตรวจ profile ด้วย `tunnel-client doctor` ก่อน แล้วเปิดคำสั่ง `tunnel-client run --profile ...` พร้อม health URL แบบ loopback และ log ที่อยู่ใน application data directory ส่วน MCP command ที่ tunnel-client เรียกถูกสร้างโดยโปรแกรมเองเป็น:

```text
python -m local_mcp_control_center --data-dir <private-data-dir> mcp
```

ไม่ควรกด `Start MCP bridge` พร้อมกับ `Start tunnel` เพราะ tunnel-client จะ start MCP bridge ของ profile ให้เองอยู่แล้ว ปุ่ม `Start MCP bridge` มีไว้สำหรับตรวจ MCP แบบ standalone เท่านั้น

ถ้า Start tunnel พบ 401 ระหว่างเริ่มต้น โปรแกรมจะหยุด client ที่ authenticate ไม่ผ่านให้เอง เพื่อไม่ให้ process วน retry และแสดงขั้นตอนให้เปลี่ยน key ก่อนเริ่มใหม่

ถ้าไม่มี `tunnel-client` GUI จะแจ้งให้ติดตั้ง client ทางการด้วย Homebrew:

```text
brew tap openai/tools
brew install openai/tools/tunnel-client
```

ปุ่ม Start จะไม่สร้าง tunnel ID หรือ API key ให้อัตโนมัติ ผู้ใช้ต้องสร้าง/ได้รับค่าจาก Platform ก่อน และไม่ควรส่ง API key ในแชตหรือเก็บไว้ใน repository

## ทดสอบ

```text
.venv/bin/python -m pytest
```

ชุดทดสอบครอบคลุม path traversal/symlink/protected target, capability และ tool policy, approval hash/expiry/precondition, audit chain, atomic write/backup, fixed/project profiles, exact patch/paged reads, regex/discovery, managed process ownership/timeout/log redaction, controlled Git mutation, CSV/XLSX/DOCX adapters, context ledger bounds/redaction, compound READ dispatch, dependency graph limits, delegated-agent compatibility และ provider-backed agent task lifecycle/role policy/cancellation/worktree/MCP schema

## ขอบเขตของ MVP นี้

นี่เป็น reference implementation ฝั่ง Python/Tkinter เพื่อเดินระบบ policy และ contract ให้ตรวจได้ก่อน ยังไม่ใช่การอ้างว่ามี Tauri 2/Rust helper หรือ security-scoped bookmark ครบแล้ว ขั้น hardening ถัดไปควรย้าย trusted broker ไป Rust/Tauri helper และเพิ่ม UDS/security-scoped bookmark โดยยังรักษา contract ของ broker ชุดนี้

Tunnel integration ในรุ่นนี้ใช้งานจริงผ่าน binary `tunnel-client` และ macOS Keychain แล้ว แต่ยังต้องให้ผู้ใช้สร้าง tunnel/permissions ใน Platform และผูก app ใน ChatGPT เอง เพราะเป็นขั้นตอน account/workspace ที่โปรแกรมไม่ควรทำแทนโดยเดา credential

Developer runtime นี้มี context ledger แบบ in-memory bounded, dependency/import graph, delegated-agent compatibility manager และ provider-backed Agent Task runtime แบบ persisted แล้ว แต่ยังไม่รวม file watcher, arbitrary child MCP bridge, browser automation, desktop/UI automation, automatic merge/push หรือ OS-level sandbox. P3 เหล่านี้ต้องผ่าน security review แยกก่อนเพิ่มขอบเขต; worker provider ปัจจุบันใช้ local thread และ fixed/scrubbed adapters จึงไม่อ้างว่าเป็น hostile-code sandbox
