# Local MCP Control Center — Domain Context

เอกสารนี้เป็น glossary ของโดเมน ไม่ใช่รายละเอียดการติดตั้งหรือ implementation

## คำศัพท์หลัก

### Scope

ขอบเขตไฟล์หรือ directory ที่ผู้ใช้ลงทะเบียนและอนุญาตให้ระบบพิจารณาการเข้าถึงได้ Scope มีชื่อที่ผู้ใช้เข้าใจได้ และอาจเปิดหรือปิดการส่งข้อมูลผ่าน MCP แยกจากสิทธิ์การใช้งานใน Control Center

### Permission

ความสามารถที่อนุญาตบน Scope เช่น read, execute, write, create, rename, move และ delete Permission เป็นราย capability ไม่ใช่สิทธิ์รวมแบบ all-or-nothing โดย `execute` แยกจากการเขียนไฟล์และใช้กับ ProjectProfile/process

### Permission Class

การจัดประเภทผลกระทบของ Tool ได้แก่ `READ`, `WRITE`, `EXECUTE` และ `DANGEROUS` ซึ่ง registry ใช้เป็น metadata และ broker ใช้ประกอบ policy; Permission Class ไม่แทน scope capability และไม่ override approval

### Tool

การกระทำที่ MCP เปิดให้ ChatGPT เรียกใช้ เช่น อ่านไฟล์ ค้นหา ดู git diff หรือแก้ไข workbook Tool อาจถูกปิดได้ และ Tool หนึ่งตัวต้องไม่แอบขยายไปทำการกระทำอื่น

### Tool Registry

catalog กลางที่เก็บชื่อ, schema, category, permission class, read-only/destructive hint และ parallel-safety ของ Tool ทุกตัว MCP, broker และ GUI ใช้ registry เดียวกัน

### Action

คำขอหนึ่งรายการที่มี operation, tool, scope, target, input และเงื่อนไขก่อนทำงานที่ระบุแน่นอน Action คือหน่วยที่ใช้ตรวจสิทธิ์ ขอ approval และบันทึกผล

### Approval

การตัดสินใจของผู้ใช้ต่อ Action ที่ระบุแน่นอน Approval ไม่ใช่ใบอนุญาตถาวร และไม่ครอบคลุม target หรือ input ที่เปลี่ยนไป

### Audit Event

บันทึกเหตุการณ์ที่ตรวจสอบย้อนหลังได้ เช่น request, policy decision, approval, execution result และการเปลี่ยน configuration Audit Event ต้องอธิบายได้ว่าใคร ขออะไร ระบบตัดสินใจอย่างไร และผลเป็นอย่างไร โดยไม่เก็บเนื้อหาไฟล์หรือ secret โดยไม่จำเป็น

### Session

ช่วงเวลาของการเชื่อมต่อ MCP/tunnel หนึ่งชุด Session เป็นบริบททางเทคนิคของ request ไม่ใช่การอนุมัติให้ทำทุกอย่างในบทสนทนา ChatGPT

### Actor

ผู้ริเริ่มเหตุการณ์ ได้แก่ user, chatgpt, control-center หรือ system การระบุ Actor ต้องไม่อนุมานว่า ChatGPT มีสิทธิ์เท่ากับผู้ใช้เครื่อง

### Project Scope

Scope ที่ชี้ไปยัง repository และมีชุด Tool สำหรับ repository เช่น git status, git diff, test และ build Project Scope ยังอยู่ภายใต้ Permission และ Approval เช่นเดียวกับ file scope

### ProjectProfile

ชุดคำสั่งที่ตรวจพบหรือกำหนดไว้ล่วงหน้าสำหรับ project เช่น test, lint, typecheck, build และ dev โดยเก็บ executable กับ argv เป็น array ไม่รับ shell command จาก MCP client

### Managed Process

process ที่ Control Center เป็นผู้ start ผ่าน ProjectProfile และเป็นเจ้าของด้วย PID/PGID, command digest, scope, timeout และ bounded log เท่านั้น จึงไม่เท่ากับสิทธิ์ kill process ทั้งเครื่อง

### Protected Target

ไฟล์หรือ directory ที่ห้ามเข้าถึงเป็นค่าเริ่มต้น เช่น credential store, private key, browser profile, .env และ metadata ที่อาจเปิดทางไปยัง secret Protected Target มี precedence เหนือ Scope ที่กว้างกว่า

### Policy Version

หมายเลขรุ่นของกฎที่ใช้ตัดสิน Action ณ เวลานั้น การเปลี่ยน Scope, Permission หรือ Tool policy ต้องทำให้ version เปลี่ยน เพื่อให้ approval เก่าหมดความน่าเชื่อถือ

### Trace ID

รหัส correlation ของ MCP request ที่เชื่อม policy decision, adapter result และ audit event ภายใน workflow เดียวกัน โดยไม่ใช้แทน approval หรือ session permission

### Capability Grant

ผลของการอนุญาต capability บน target ที่ตรวจ canonical แล้ว Capability Grant ไม่ใช่สิทธิ์ของ process ทั้งเครื่อง และไม่อนุญาตให้เรียก arbitrary shell
