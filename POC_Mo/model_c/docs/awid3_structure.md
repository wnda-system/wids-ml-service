# ข้อ 2.3 — โครงสร้างไฟล์ AWID3 ที่ได้จริง (ตรวจ 2026-10-13)

ที่อยู่: `~/CSV/<n>.<Class>/<Class>_<i>.csv` — 13 โฟลเดอร์, 747 ไฟล์, 44 GB, **มีแต่ CSV ไม่มี pcap**
ตรวจละเอียดเฉพาะ 8 คลาสชั้น MAC (+SSDP) ด้วย `profile_awid3.py` → `awid3_profile.json`

- ทุกไฟล์ 254 คอลัมน์ ชื่อตรงกัน (ต่างแค่ CRLF/LF ท้ายบรรทัด); label = คอลัมน์สุดท้าย `Label`
- แต่ละคลาส = capture ต่อเนื่อง 1 ครั้ง ~10 นาที (Evil_Twin ~15 นาที) แบ่งเป็นไฟล์ละ ~50,000 แถว
  `frame.number` นับต่อเนื่องข้ามไฟล์ (_0 เริ่ม 1, ไฟล์ถัดไปต่อจากไฟล์ก่อน) → 1 คลาส = 1 pcap ต้นฉบับ
- รูปแบบเวลา: ~7 นาทีแรก Normal ล้วน, ~3 นาทีท้ายมีการโจมตีปนกับ Normal
- frame หายจาก CSV เป็นจุดๆ (frame.number กระโดด 1 ค่า) 3–284 จุดต่อคลาส; มีแถวเสีย (ทุกคอลัมน์ NaN) 0–135 แถว
- ~~เวลาข้ามรอยต่อไฟล์ย้อนได้ถึง ~0.5 s~~ → **ไม่จริง**: `frame.time_epoch` ใน CSV ถูกปัดเป็นวินาทีเต็ม (round) ใน 60–97% ของแถว (ทั้งไฟล์)
  ส่วน `frame.time` (สตริง ns, "GTB Standard Time" = UTC+2) ยังละเอียดครบ → ใช้ `frame.time` ตรวจเวลา
- label สะกดไม่สม่ำเสมอ: `Kr00k`/`Kr00K`, `SSDP`/`SDDP`, `Label` เป็น NaN 276 แถวใน SSDP
- Krack: frame โจมตีทั้งหมดอยู่ 2417 MHz, Normal ทั้งหมด 2472 MHz (label รั่วผ่านช่องสัญญาณ); คลาสอื่น 5180 MHz
- encap 23 (radiotap) ทุกไฟล์

## อัปเดตหลังได้ pcap (AWID3_Dataset.zip, 12.9 GB, ~/AWID3_raw)

- zip มี `pcaps/` 13 ไฟล์ (pcap คลาสสิก, radiotap, µs) + `radius_decrypted_keys/` + `sslkeys/` + `Read_me.txt`
- pcap เป็น **capture ดิบที่ยังเข้ารหัส** (ต้องใส่ key ใน Wireshark ถึงถอดได้) — ตรงกับสิ่งที่ sensor เห็น
- **เลขลำดับ pcap ≠ เลขโฟลเดอร์ CSV**: pcap 7 = Evil_Twin (CSV 12), pcap 12 = Botnet (CSV 8), pcap 2 ชื่อ `Disass` → map ด้วยชื่อ
- Deauth: pcap 1,626,472 frame; CSV 1,626,469 แถว; จับคู่ด้วย `frame.number` ได้ทุกแถว, เวลา (`frame.time`) ต่างกัน ≤ 2.4e-7 s
  frame ใน pcap ที่ไม่มีใน CSV = 3 (424717, 465324, 468044): ทั้ง 3 เป็น QoS data เข้ารหัสจาก AP ตัวจริง (0c:9d:92:54:fe:34)
  seq ต่อเนื่องกับ frame ข้างเคียง, อยู่ช่วงก่อนการโจมตี → น่าจะถูก tshark ทิ้งตอนถอดรหัส ไม่ใช่ frame โจมตี
- Read_me: Krack โจมตีบน `wlan_radio.channel == 2`; มี filter ช่วงเลข frame ของการโจมตีแต่ละแบบ
