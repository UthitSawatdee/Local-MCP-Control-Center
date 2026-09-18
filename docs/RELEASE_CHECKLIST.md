# Release checklist — Local MCP Control Center

ใช้ก่อน commit, push หรือแชร์ checkout ให้ผู้ใช้รายอื่น การผ่าน unit tests หรือการเพิ่ม `.gitignore` เพียงอย่างเดียวไม่ใช่การรับรองว่าไม่มี secret ใน Git history

## ขอบเขตการเตรียมรอบ 2026-09-18

- ทำงานบน `local-mcp-control-center`, branch `main`; ไม่แก้โปรเจกต์ ATM
- รักษางาน modified/untracked ที่มีอยู่ก่อนหน้า ไม่ลบไฟล์ runtime, credentials, backups หรือประวัติ Git
- เพิ่ม ignore rules สำหรับ private keys, environment/local configuration, session files, runtime databases/logs, build output และ OS metadata โดยไม่ ignore source/tests ทั้ง directory
- ปรับ README และตัวอย่าง path ใน ARCHITECTURE ให้ไม่ผูกกับ home directory ของผู้พัฒนา พร้อมอัปเดตคำแนะนำ config สำหรับเครื่องใหม่
- เพิ่ม `tests/test_release_hygiene.py` เพื่อทดสอบ ignore rules ด้วยชื่อไฟล์จำลองใน temporary Git repository และตรวจ path ส่วนตัวในเอกสาร onboarding
- การค้นหารูปแบบ key/token ในไฟล์ข้อความที่ MCP อนุญาตให้เข้าถึงพบข้อมูลจำลองใน security tests; ไม่ได้ยืนยันทุกชนิดของ secret และไม่ได้อ่าน protected credential files
- ยังไม่ stage, commit หรือ push ในรอบเตรียมนี้

## ผล verification รอบนี้

- ชุดทดสอบเต็มก่อนแก้ไข: `backend_pytest`, exit code 0, process `7fb1ecb1-18e4-44dc-a132-50c47cd80715`
- ชุดทดสอบเต็มหลังเพิ่ม release-hygiene tests: `backend_pytest`, exit code 0, process `58fb94c1-caa0-42a2-8b73-564f5e2a2e9d`
- ค้นซ้ำไม่พบ personal home paths ตามรูปแบบที่ตรวจในไฟล์ข้อความที่ MCP อนุญาต; key/token matches ยังคงอยู่ใน test fixtures ไม่เพิ่ม blanket allowlist
- `.DS_Store` ยังอยู่บน disk แต่ไม่ปรากฏใน Git untracked list แล้ว งานเดิมที่ modified/untracked ยังอยู่
- ผลข้างต้นไม่รวม full Git history scan, dependency audit, clean installation หรือ remote verification

## 1. ยืนยัน repository และตรวจรายการที่จะเผยแพร่

รันจาก checkout ที่ต้องการเผยแพร่ โดยอ่านผลบนเครื่องเจ้าของและไม่ส่ง raw diff ที่อาจมี secret เข้าแชต:

```sh
git status --short --branch
git diff --stat
git diff --check
git diff --cached --stat
git diff --cached --check
git ls-files --cached --ignored --exclude-standard
```

คำสั่งสุดท้ายแสดง tracked files ที่ตรงกับ ignore rules แล้ว หากมีผลลัพธ์ ต้องทบทวนเป็นรายไฟล์ก่อน commit; การเพิ่ม `.gitignore` ไม่ทำให้ Git หยุด track ไฟล์เดิมและไม่ลบข้อมูลจาก commit เก่า [1]

ตรวจ `.agents/runtime/`, logs, snapshots, databases, private config และไฟล์สำรองเป็นพิเศษ ห้ามเอาไฟล์ที่ยังไม่แน่ใจออกจาก index หรือทิ้งงานโดยอัตโนมัติ แยกการหยุด track ออกจากการลบไฟล์จริงและขออนุมัติสำหรับการเปลี่ยนที่เสี่ยง

ยืนยันชื่อ remote, repository owner, branch และ visibility ใน Git client ก่อน push อย่าเผยแพร่ URL ที่ฝัง credential ถ้ามีการตั้งค่าแบบนั้นอยู่ ห้ามเปลี่ยน repository เป็น public อัตโนมัติ

## 2. ตรวจ secrets ทั้งไฟล์ปัจจุบันและ Git history

ต้องมีการสแกนสองส่วนแยกกัน: release candidate ปัจจุบัน และทุก branch/tag/ref ที่จะเผยแพร่ ห้ามสรุปว่า history สะอาดจากการค้นหา working tree อย่างเดียว

ตัวอย่าง Gitleaks สำหรับให้เจ้าของเครื่องรันในเครื่อง โดยใช้ full redaction [3]:

```sh
gitleaks version
gitleaks dir --redact=100 .
gitleaks git --redact=100 --log-opts="--all" .
```

ยังไม่ได้ติดตั้งหรือรัน Gitleaks ผ่าน MCP ในรอบนี้ ผลการค้นหาแบบ regex ไม่ทดแทนผล Gitleaks คำสั่ง history ตรวจ refs ที่มีอยู่ใน local clone เท่านั้น ต้องยืนยันว่ามี branch/tag ที่จะเผยแพร่ครบ รวมถึงยืนยันว่า clone ไม่ใช่ shallow clone ก่อนถือว่าตรวจประวัติครบ

การสแกน directory อาจพบ secret ที่เก็บเป็น local-only อยู่แล้ว ต้องเทียบกับ Git index และรายการ release จริง ไม่ลบ credential หรือ revoke key เพียงเพราะพบใน directory ที่ไม่ถูกเผยแพร่ อย่าอัปโหลด raw report, credential หรือ private key เพื่อขอให้ผู้อื่นตรวจ

ไฟล์ทดสอบ redaction มี fake key/token ที่ตั้งใจสร้างขึ้น ให้ทบทวนผลรายรายการและบันทึกเหตุผลของ false positive ห้าม ignore ทั้ง `tests/`, ปิด generic rules ทั้งหมด หรือสร้าง baseline เพื่อละเว้นทุกผลการตรวจโดยไม่ทบทวน

ถ้าพบ key/token จริงที่เคย commit หรือ push ให้หยุดเผยแพร่และ revoke/rotate key ที่ได้รับผลกระทบก่อน การลบไฟล์ใน commit ใหม่อย่างเดียวไม่ทำให้ key ที่รั่วใช้การไม่ได้ การ rewrite history ต้องแยกแผนและประสานผู้ร่วมงาน ไม่ทำ force push อัตโนมัติ [2]

## 3. ทดสอบ release candidate

รันจาก checkout ที่ตรวจแล้ว:

```sh
.venv/bin/python -m pytest
.venv/bin/python -m pip check
```

ชุด regression ใหม่ทดสอบเฉพาะ ignore rules ใน temporary repository และไฟล์เอกสารที่ระบุ ไม่อ่าน index/history ของ checkout จริงหรือ protected credentials จึงยังต้องทำ gate 1–2 แยกต่างหาก

ต้องทดสอบติดตั้งจาก clean checkout/release candidate ใน virtual environment ใหม่ด้วย Python 3.12 ขึ้นไป และทดสอบ GUI บน macOS ที่มี Tkinter; การผ่าน tests บน development environment เดิมไม่ยืนยัน dependency resolution หรือการติดตั้งบนเครื่องใหม่

`python scripts/build_macos_app.py` สร้าง launcher ที่อ้างถึง checkout และ Python บนเครื่องที่สร้าง ไม่ใช่ standalone installer สำหรับแจก `.app` เดิมให้ทุกคน ผู้ใช้แต่ละคนต้องติดตั้งและสร้าง launcher ของตัวเองตาม README

ไม่คัดลอก `.venv`, application data directory, Keychain entries, browser profiles/cookies, tunnel profiles หรือฐานข้อมูล approvals/audit ไปให้ผู้ใช้รายอื่น

## 4. ทบทวน optional integrations และสิทธิ์

ผู้ใช้แต่ละคนต้องลงทะเบียน scope ของตนเอง เริ่มจาก read-only และเปิดเฉพาะ tools/capabilities ที่ต้องใช้ ไม่แจก profile ที่ให้สิทธิ์เข้าถึง home directory ทั้งหมด

Motion ERP adapter ปัจจุบันมี instance origin แบบเฉพาะใน `browser.py` และ `motion_erp.py`; ไม่ใช่ connector ทั่วไปสำหรับทุก ERP instance ต้องทบทวนว่าต้องการแจก integration นี้ด้วยหรือไม่ โดยไม่ขยาย origin allowlist หรือเปลี่ยน endpoint ของผู้ใช้เดิมอัตโนมัติ

Codex reader, provider-backed agents และ tunnel ต้องมี local configuration/authorization ของผู้ใช้แต่ละคน ห้ามส่งต่อ session หรือ key ของผู้พัฒนาเพื่อให้ onboarding สั้นลง

## 5. Stage, commit, push หลังผ่านการตรวจ

เลือก stage เป็นรายไฟล์หลังตรวจ diff แล้วเท่านั้น ไม่ใช้ `git add .` หรือ `git add -A` เพื่อเก็บงานทั้งหมดแบบไม่แยกประเภท ตรวจ staged diff อีกครั้งและ rerun verification เมื่อ release candidate เปลี่ยน

ผ่านครบจึง commit เป็นชุดที่อธิบายได้ และ push branch/remote ที่ยืนยันแล้วแบบ non-force ผ่าน approval ของ Control Center หลัง push ตรวจว่า commit บน GitHub ตรงกับ local HEAD และไม่มี local-only files หลุดขึ้นไป

ก่อนเปิดเป็น public ให้เจ้าของ repository ตัดสินใจเรื่องสิทธิ์แจกจ่าย/license เอง ไม่เพิ่ม license หรือเปลี่ยน visibility แทนเจ้าของโดยอัตโนมัติ พิจารณาเปิด secret scanning/push protection ที่ repository รองรับ [2]

## ข้อจำกัดของ MCP ที่พบในรอบตรวจนี้

`git_diff` ที่แชตเห็นมี schema แบบไม่รับ `scope_id` แต่ runtime ต้องการ `scope_id` จึงถูกปฏิเสธด้วย `scope_id Field required` ส่วน Git tools ไม่อยู่ใน read-only allowlist ของ `tool_batch` จึงไม่ใช้ batch เพื่อข้ามข้อจำกัดนี้

ใช้ `workspace_snapshot(scope_id=...)` ตรวจสถานะ และ `process_start_profile(scope_id=..., profile="backend_pytest")` รัน tests ได้ แต่ยังไม่ได้ยืนยัน full Git diff/index, ประวัติ secrets ทั้งหมด, remote identity/HEAD, clean-install หรือ dependency audit ผ่าน MCP

ต้อง refresh/reconnect tool schema ให้ตรงกับ bridge ที่รันอยู่และตรวจว่า Git tools รับ `scope_id` ได้จริงก่อนทำ Git gate ต่อ ไม่จำเป็นต้องลด policy, เปิด arbitrary shell หรือเปิด protected credentials เพื่อแก้ปัญหานี้

## อ้างอิง

[1] Git: gitignore — https://git-scm.com/docs/gitignore

[2] GitHub: Removing sensitive data from a repository — https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

[3] Gitleaks: usage, redaction and Git history options — https://github.com/gitleaks/gitleaks
