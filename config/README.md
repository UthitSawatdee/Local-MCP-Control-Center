# Runtime configuration

เก็บเฉพาะ configuration ที่ไม่มี secret ใน repository นี้

สำหรับ Secure MCP Tunnel ให้ผู้ใช้สร้างและตรวจ profile จากเอกสาร/เครื่องมือทางการก่อน แล้วค่อยเพิ่ม integration ที่ระบุ executable, arguments, endpoint และ credential reference อย่างชัดเจน

ห้ามเก็บ access token, private key, cookie, tunnel identity หรือ credential ในไฟล์นี้, SQLite payload หรือ chat log โดยตรง รุ่น MVP จึงตอบ `TUNNEL_NOT_CONFIGURED` และไม่เปิด process ที่ไม่สามารถระบุ ownership กับ profile ได้
