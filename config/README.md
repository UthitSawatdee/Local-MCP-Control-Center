# Runtime configuration

เก็บเฉพาะ configuration ที่ไม่มี secret ใน repository นี้

ผู้ใช้แต่ละคนต้องตั้งค่า scopes, permissions, tunnel และ optional agent/browser profiles ของตนเองผ่าน Control Center ไม่คัดลอกการตั้งค่าที่มี session หรือ credential ของผู้พัฒนาไปใช้ร่วมกัน

Runtime API key ของ tunnel เก็บใน macOS Keychain ส่วน policy, approvals และ runtime metadata เก็บใน application data directory ที่แอปจัดการ ไม่ควรแนบ directory นี้ไปกับ repository หรือไฟล์แจกจ่าย

ไฟล์ตัวอย่างต้องใช้ placeholder เท่านั้น ห้ามเก็บ access token, private key, cookie, session, tunnel identity หรือ credential จริงใน repository, SQLite action payload หรือ chat log

`.gitignore` กัน local configuration และไฟล์ลับที่ยังไม่ถูก track เท่านั้น ไม่ลบไฟล์จริงและไม่ลบข้อมูลจาก Git history ดูขั้นตอนตรวจ tracked files และประวัติทั้งหมดใน [Release checklist](../docs/RELEASE_CHECKLIST.md)
