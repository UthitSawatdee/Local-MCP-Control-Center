# DevOS Bug Log

สถานะ: ไม่มี bug ค้างจากงานรอบนี้

รายการที่พบและแก้พร้อม regression test:

- Protected-only Git changes เคยถูกมองว่า clean; ตอนนี้ยังแสดง dirty และ warning โดยไม่อ่านเนื้อหาไฟล์ลับ
- Capsule ที่ persist แล้วมี `source` ทำให้ round-trip parser ล้มเหลว; ตอนนี้แยก source เป็น metadata และตรวจ content hash
- Workspace metadata เคยขัดขวางการลบ scope; ตอนนี้ลบ metadata ลูกก่อน และ schema ใหม่ใช้ cascading foreign keys
- Evidence ที่ payload ถูกแก้ไขโดยไม่แก้ hash เคยถูกอ่านได้; ตอนนี้ Store fail closed เมื่อ hash mismatch
- Handoff เคยรวม pre-existing หรือ out-of-scope changes; ตอนนี้ WorkPackage บันทึก baseline และรายงานแยกตาม scope
- Runtime probe เคยเลือก interpreter จาก `.venv` ของ project; ตอนนี้ใช้ trusted host binaries และ runtime-home ที่แยกไว้
- Git status/tracked-path output ที่ถูกตัดอาจทำให้ inventory ไม่ครบ; ตอนนี้ fail closed และแสดง warning
- Capsule branch/source และ custom protected paths เคยเปิดช่องให้ metadata/path หลุดขอบเขต; ตอนนี้ validate และ sanitize ก่อนเผยแพร่
- Filesystem metadata walk และ WorkRun terminal lifecycle เคยไม่มี budget/serialization guard; ตอนนี้มี directory/time budget และ engine lifecycle lock
- Caller-supplied `test_result` ที่มี status/profile/exit code เคย forge verified handoff ได้; ตอนนี้ต้องมาจาก internal fixed-runner provenance เท่านั้น
