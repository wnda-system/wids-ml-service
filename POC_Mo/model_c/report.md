# Model C (awid3-mac-v1) — รายงานผลการเทรน

เครื่องเทรน: `br1.paas.ku.ac.th` (SLURM, ขั้น extract รันบน `dgx-03`) · 2026-10-13
โค้ดทั้งหมดอยู่ที่ `experiment_1/model_c_build/` (ไม่ได้ส่งมาใน `model_c/` — ขอได้ถ้าต้องการรันซ้ำ)

## สรุป

| เกณฑ์ (ข้อ 5.5) | ผล | ผ่าน |
|---|---|:---:|
| recall ≥ 0.9 หลังใช้ threshold: Deauth / Disas / (Re)Assoc / RogueAP | 1.000 / 0.979 / 0.957 / 1.000 | ✅ |
| recall ≥ 0.9 หลังใช้ threshold: **Evil_Twin** | **0.000** (ปิดไว้, threshold 1.01) | ❌ |
| แจ้งผิดบนข้อมูลของเรา ครึ่งหลัง ≤ 1 เหตุการณ์/ชม. | **0.041** (2 เหตุการณ์ใน 48.8 ชม.) | ✅ |
| Kr00k / Krack / SSDP (ไม่บังคับ) | 0.875 / 0 (ปิด) / 0 (ปิด) | — |

- **Evil_Twin ไม่ผ่านเพราะ `known_pairs` ของเครื่อง sensor ขาด AP จริงของมหาวิทยาลัย 21 คู่** ไม่ใช่เพราะโมเดล
  (บน AWID3 โมเดลจับได้ 0.977 แบบ argmax) — ทดลองแล้ว: ถ้า Approve AP ชุดนี้ Evil_Twin ผ่านเกณฑ์ (หัวข้อ 6)
- Krack และ SSDP ปิดไว้ (threshold 1.01): ฟีเจอร์ที่ใช้ได้ทำให้แจ้งผิดบนข้อมูลของเรา 49–63 และ 8–11 เหตุการณ์/ชม.
- **สิ่งที่เครื่อง sensor ต้องทำ:** หัวข้อ 8

## 1. สิ่งที่พบในข้อ 2.3 — โครงสร้าง AWID3

- ไฟล์ที่ได้: CSV 13 คลาส (`~/CSV/<n>.<Class>/<Class>_<i>.csv`, 747 ไฟล์, 44 GB) + `AWID3_Dataset.zip` (12.9 GB)
  ซึ่งมี `pcaps/` 13 ไฟล์ (pcap คลาสสิก, radiotap, µs), `radius_decrypted_keys/`, `sslkeys/`, `Read_me.txt`
- **pcap เป็น capture ดิบที่ยังเข้ารหัส** (ถอดได้เมื่อใส่ key ใน Wireshark) → ตรงกับสิ่งที่เครื่อง sensor เห็น
- แต่ละคลาส = capture ต่อเนื่อง 1 ครั้ง ~10 นาที (Evil_Twin ~15 นาที): ~7 นาทีแรก normal ล้วน, ~3 นาทีท้ายมีการโจมตีปน
  CSV ของคลาสหนึ่งถูกหั่นเป็นไฟล์ละ ~50,000 แถว โดย `frame.number` นับต่อเนื่องข้ามไฟล์ = 1 pcap
- **เลขลำดับ pcap ≠ เลขโฟลเดอร์ CSV**: pcap 7 = Evil_Twin (CSV 12), pcap 12 = Botnet (CSV 8), pcap 2 ชื่อ `Disass` → จับคู่ด้วยชื่อ
- CSV ทุกไฟล์ 254 คอลัมน์ชื่อเดียวกัน, label = คอลัมน์ `Label` (สุดท้าย)
- **`frame.time_epoch` ใน CSV ถูกปัดเป็นวินาทีเต็มใน 60–97% ของแถว** → ตรวจเวลาด้วย `frame.time` (สตริง ns,
  "GTB Standard Time" = UTC+2 — ตรวจ offset จากแถวที่ไม่ถูกปัด)
- label สะกดไม่สม่ำเสมอ: `Kr00k`/`Kr00K`, `SSDP`/`SDDP` → รวมเป็นชื่อเดียว
- มีแถวเสีย (ทุกคอลัมน์ว่าง) 0–276 แถว/คลาส และ frame ใน pcap ที่ไม่มีแถวใน CSV เป็นจุดๆ (ตารางข้อ 2)
- Krack: frame โจมตีทั้งหมดอยู่ 2417 MHz (ช่อง 2), normal ทั้งหมดอยู่ 2472 MHz; คลาสอื่น 5180 MHz
  (ฟีเจอร์ที่ใช้ไม่มีช่องสัญญาณ จึงไม่รั่ว แต่ capture ของ Krack คนละ AP/ย่านกับคลาสอื่น)
- ไม่ได้ใช้: Botnet, Malware, SSH, SQL_Injection, Website_spoofing (ต้องถอดรหัส payload)

## 2. ข้อ 3 — pcap → ฟีเจอร์รายวินาที + label

- อ่าน pcap ด้วย scapy `PcapReader` เรียก `extract_fields(pkt, n, first_time, prev_time, state, llc_snap_dispatch=True)` ต่อ frame
  แล้ว `add_derived_columns()` และเขียน `.csv.gz` (163 คอลัมน์) — เหมือน `CaptureSession.run()`
  แบ่ง pcap เป็น chunk ~50k frame (ขอบ chunk อยู่ที่ต้นวินาทีพอดี) รันขนาน: ผลตรงกับการรันเรียงทีละ frame **ทุกช่อง** (ทดสอบ 6,000 frame × 163 คอลัมน์)
  ข้อต่าง 1 จุด: `seen_tcp_seqs` เริ่มใหม่ทุก chunk → กระทบเฉพาะ `tcp.analysis.retransmission` ซึ่ง `windows()` ไม่ใช้
- label: จับคู่ด้วย `frame.number`, ตรวจเวลาซ้ำด้วย `frame.time` (คลาด ≤ 2e-6 s) และ `frame.time_epoch` (คลาด ≤ 0.5 s เพราะถูกปัด)
- **กติกา frame ที่ไม่มี label (ตกลงกันแล้ว):** frame ใน pcap ที่ไม่มีแถวใน CSV ยังใช้คำนวณฟีเจอร์ แต่ไม่มี label;
  ถ้าเกิน 0.01% ของคลาส → หยุด; วินาที normal ภายในช่วงโจมตีที่มี frame ไม่มี label → ทิ้ง
  ทุกคลาสต่ำกว่าเกณฑ์ (สูงสุด 1.9e-5) — ตัวอย่างที่ตรวจ (Deauth 3 frame): data frame เข้ารหัสจาก AP จริง seq ต่อเนื่องกับข้างเคียง อยู่ก่อนการโจมตีหลายนาที
- `windows(df, 1, known_pairs, arp_seed)` ทีละ capture, ตัดวินาทีแรก/สุดท้าย; label รายวินาทีตามข้อ 3.4
- `known_pairs`/`arp_seed` จากช่วง normal ของแต่ละ capture เท่านั้น โดยมี 2 ข้อเพิ่มจาก `anomaly_detect.py`:
  - baseline จบ **30 วินาทีก่อน** frame โจมตีแรก — AWID3 ติด label beacon ชุดแรกของ evil twin (`0c:9d:92:54:fe:35`, 8 วินาทีก่อน) เป็น normal
    (และอีก 143 beacon ช่วงกลางการโจมตี) ทำให้ BSSID ผู้โจมตีหลุดเข้า `known_pairs`
  - คู่ (SSID, BSSID) ต้องปรากฏ ≥ 50% ของวินาที baseline (SSID ต้อง ≥ 90% เหมือนเดิม)
  - `arp_seed` ว่างทุกคลาส (ARP อยู่ใน frame ที่เข้ารหัส)

| class     |   pcap frames |   attack frames | unlabeled frames   |   AWID3 broken rows |   epoch rounded rows |   time max diff (s) |   seconds |   attack s |   dropped s | known_pairs               |
|:----------|--------------:|----------------:|:-------------------|--------------------:|---------------------:|--------------------:|----------:|-----------:|------------:|:--------------------------|
| (Re)Assoc |     1,843,939 |           5,502 | 7 (3.8e-06)        |                   6 |            1,293,933 |             2.4e-07 |       607 |        182 |           0 | ASUS_5G/0c:9d:92:54:fe:34 |
| Deauth    |     1,626,472 |          38,942 | 3 (1.8e-06)        |                   0 |            1,026,469 |             2.4e-07 |       601 |        178 |           0 | ASUS_5G/0c:9d:92:54:fe:34 |
| Disas     |     2,013,719 |          75,131 | 3 (1.5e-06)        |                   0 |            1,163,717 |             2.4e-07 |       602 |        182 |           0 | ASUS_5G/0c:9d:92:54:fe:34 |
| Evil_Twin |     3,778,728 |         104,827 | 49 (1.3e-05)       |                  27 |            3,478,681 |             2.4e-07 |       900 |        444 |           1 | ASUS_5G/0c:9d:92:54:fe:34 |
| Kr00k     |     2,900,458 |         191,803 | 18 (6.2e-06)       |                   0 |            2,550,441 |             2.4e-07 |       602 |        184 |           0 | ASUS_5G/0c:9d:92:54:fe:34 |
| Krack     |     1,438,493 |          49,990 | 5 (3.5e-06)        |                   0 |            1,238,490 |             2.4e-07 |       629 |        178 |           0 | ASUS/0c:9d:92:54:fe:30    |
| RogueAP   |     1,973,193 |           1,310 | 8 (4.1e-06)        |                   0 |            1,273,185 |             2.4e-07 |       603 |        174 |           0 | ASUS_5G/0c:9d:92:54:fe:34 |
| SSDP      |     8,141,523 |       5,499,851 | 155 (1.9e-05)      |                 276 |            7,941,368 |             2.4e-07 |       632 |        193 |           9 | ASUS_5G/0c:9d:92:54:fe:34 |

ข้อสังเกตเรื่อง label ของ AWID3 (มีผลกับการตีความ):
- **RogueAP**: ช่วงโจมตีมี deauth flood (median 229 frame/วินาที) ที่ AWID3 ติด label เป็น normal — มีแค่ beacon ของ rogue AP ที่เป็น RogueAP
- **Evil_Twin**: beacon ของ evil twin บางส่วนติด label normal (ดูด้านบน)

## 3. ข้อ 4 — ฟีเจอร์

เปรียบเทียบการกระจายตัววินาที normal ของ AWID3 (ช่วงก่อนโจมตี 3,377 วินาที) กับ `ours/features.csv` (97.5 ชม.) —
ตารางเต็มอยู่บนเครื่องเทรนที่ `experiment_1/notes/step4_feature_compare.md`; ใช้ 14 ตัว:

`deauth, disassoc, auth, assoc_req, deauth_to_one_client_10s, deauth_seq_out_of_order, tsf_offset_switches,
new_bssid_known_ssid, bssid_beacon_rate, deauth_per_mgmt, beacon_per_mgmt, probe_req_per_mgmt, rts_per_ctrl, cts_per_ctrl`

| ตัดออก | เหตุผล |
|---|---|
| `arp_ip_mac_flips_10s`, `arp_ips_per_mac_60s`, `arp_reply_ratio` | เป็น 0 ตลอดใน AWID3 (ARP เข้ารหัส) แต่ไม่เป็น 0 ใน 10–17% ของวินาทีของเรา → เรียนไม่ได้ |
| `mgmt_frac`, `ctrl_frac`, `data_frac`, `protected_ratio`, `retry_ratio` | แม้เป็นสัดส่วนแล้ว median ยังต่างกัน 3–127 เท่า |
| `max_bssid_per_ssid` | ปกติ = 1 ใน AWID3 แต่ = 3 ของเรา (SSID องค์กรหลาย AP) ขณะที่ evil twin ใน AWID3 = 2 |

ฟีเจอร์ใหม่ใน `model_c_features.py` คำนวณจากผลของ `windows()` เท่านั้น (สัดส่วน 5 ตัว) — ไม่ต้องใช้ frame 163 คอลัมน์

## 4. ข้อ 5 — เทรนและประเมินผล

- โมเดล: `HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, class_weight="balanced")` ใน `Pipeline`
  (เทียบกับ `RandomForestClassifier` แล้ว HGB ดีกว่าทั้ง recall และความสมเหตุสมผลของฟีเจอร์ — RF ใช้ `rts_per_ctrl` เป็นหลักสำหรับ Disas)
- **แบ่งข้อมูลตามเวลา**: AWID3 มีแค่ 1 capture ต่อคลาส จึงแบ่งตามเวลาภายใน capture — ช่วง normal ก่อนโจมตีและช่วงโจมตี
  แต่ละช่วง 70% แรก = train, 30% หลัง = test, ทิ้ง 10 วินาทีรอบรอยต่อ (ฟีเจอร์ย้อนหลัง 10 วินาที) และ 10 วินาทีก่อนเริ่มโจมตี
- ข้อมูลของเรา **ไม่ได้ใช้เทรน** — ใช้ตั้ง threshold (ครึ่งแรก) และวัดผล (ครึ่งหลัง) เท่านั้น

จำนวนวินาที (หลังแบ่ง):

|           |   test |   train |
|:----------|-------:|--------:|
| (Re)Assoc |     47 |     125 |
| Deauth    |     49 |     119 |
| Disas     |     48 |     124 |
| Evil_Twin |    132 |     302 |
| Kr00k     |     48 |     126 |
| Krack     |     50 |     118 |
| RogueAP   |     52 |     112 |
| SSDP      |     50 |     134 |
| normal    |    922 |    2378 |

### 4.1 AWID3 held-out

|           |   support |   P argmax |   R argmax |   F1 argmax |   P threshold |   R threshold |   F1 threshold |   recall drop |   threshold |
|:----------|----------:|-----------:|-----------:|------------:|--------------:|--------------:|---------------:|--------------:|------------:|
| (Re)Assoc |        47 |      1     |      0.957 |       0.978 |         1     |         0.957 |          0.978 |         0     |        0.5  |
| Deauth    |        49 |      1     |      1     |       1     |         1     |         1     |          1     |         0     |        0.5  |
| Disas     |        48 |      0.922 |      0.979 |       0.949 |         0.922 |         0.979 |          0.949 |         0     |        0.5  |
| Evil_Twin |       132 |      1     |      0.977 |       0.989 |         0     |         0     |          0     |         0.977 |        1.01 |
| Kr00k     |        48 |      0.977 |      0.875 |       0.923 |         0.977 |         0.875 |          0.923 |         0     |        0.5  |
| Krack     |        50 |      0.979 |      0.94  |       0.959 |         0     |         0     |          0     |         0.94  |        1.01 |
| RogueAP   |        52 |      0.929 |      1     |       0.963 |         0.929 |         1     |          0.963 |         0     |        0.5  |
| SSDP      |        50 |      0.288 |      0.46  |       0.354 |         0     |         0     |          0     |         0.46  |        1.01 |
| normal    |       922 |      0.963 |      0.937 |       0.95  |         0.799 |         1     |          0.888 |        -0.063 |             |

("threshold" = threshold ที่ส่งไปใน `meta.json`; precision ของ normal ลดลงเพราะการโจมตีของคลาสที่ปิดไว้ถูกทายเป็น normal)

Confusion matrix — argmax:

|                |   (Re)Assoc |   Deauth |   Disas |   Evil_Twin |   Kr00k |   Krack |   RogueAP |   SSDP |   normal |
|:---------------|------------:|---------:|--------:|------------:|--------:|--------:|----------:|-------:|---------:|
| true (Re)Assoc |          45 |        0 |       0 |           0 |       0 |       0 |         1 |      0 |        1 |
| true Deauth    |           0 |       49 |       0 |           0 |       0 |       0 |         0 |      0 |        0 |
| true Disas     |           0 |        0 |      47 |           0 |       1 |       0 |         0 |      0 |        0 |
| true Evil_Twin |           0 |        0 |       0 |         129 |       0 |       0 |         0 |      0 |        3 |
| true Kr00k     |           0 |        0 |       4 |           0 |      42 |       0 |         0 |      0 |        2 |
| true Krack     |           0 |        0 |       0 |           0 |       0 |      47 |         3 |      0 |        0 |
| true RogueAP   |           0 |        0 |       0 |           0 |       0 |       0 |        52 |      0 |        0 |
| true SSDP      |           0 |        0 |       0 |           0 |       0 |       0 |         0 |     23 |       27 |
| true normal    |           0 |        0 |       0 |           0 |       0 |       1 |         0 |     57 |      864 |

Confusion matrix — ใช้ threshold:

|                |   (Re)Assoc |   Deauth |   Disas |   Evil_Twin |   Kr00k |   Krack |   RogueAP |   SSDP |   normal |
|:---------------|------------:|---------:|--------:|------------:|--------:|--------:|----------:|-------:|---------:|
| true (Re)Assoc |          45 |        0 |       0 |           0 |       0 |       0 |         1 |      0 |        1 |
| true Deauth    |           0 |       49 |       0 |           0 |       0 |       0 |         0 |      0 |        0 |
| true Disas     |           0 |        0 |      47 |           0 |       1 |       0 |         0 |      0 |        0 |
| true Evil_Twin |           0 |        0 |       0 |           0 |       0 |       0 |         0 |      0 |      132 |
| true Kr00k     |           0 |        0 |       4 |           0 |      42 |       0 |         0 |      0 |        2 |
| true Krack     |           0 |        0 |       0 |           0 |       0 |       0 |         3 |      0 |       47 |
| true RogueAP   |           0 |        0 |       0 |           0 |       0 |       0 |        52 |      0 |        0 |
| true SSDP      |           0 |        0 |       0 |           0 |       0 |       0 |         0 |      0 |       50 |
| true normal    |           0 |        0 |       0 |           0 |       0 |       0 |         0 |      0 |      922 |

### 4.2 ข้อมูลปกติของเรา (`ours/features.csv`)

ทุกวินาทีเป็น normal; เหตุการณ์ = วินาทีที่แจ้งซึ่งห่างกัน ≤ 3 วินาทีนับเป็น 1; ชั่วโมง = จำนวนวินาทีที่มีข้อมูล / 3600 (เวลาไทย)

| half                   |   hours | from                | to                  |   FA/h argmax | argmax by class                                                                                                                       |   FA/h shipped thr | shipped by class                       |   events |
|:-----------------------|--------:|:--------------------|:--------------------|--------------:|:--------------------------------------------------------------------------------------------------------------------------------------|-------------------:|:---------------------------------------|---------:|
| calibration (1st half) |    48.8 | 2026-10-08 13:03:51 | 2026-10-11 12:10:13 |        125.43 | {'(Re)Assoc': 0.02, 'Evil_Twin': 80.41, 'Krack': 49.23, 'SSDP': 8.34}                             |              0.021 | {'(Re)Assoc': 0.021}                   |        1 |
| evaluation (2nd half)  |    48.8 | 2026-10-11 12:10:14 | 2026-10-13 12:58:02 |        166.99 | {'(Re)Assoc': 0.02, 'Evil_Twin': 125.45, 'Krack': 62.51, 'RogueAP': 0.02, 'SSDP': 10.78} |              0.041 | {'(Re)Assoc': 0.021, 'RogueAP': 0.021} |        2 |

แจ้งผิดตามช่วงเวลาของวัน (ครึ่งหลัง, เหตุการณ์/ชม., ชั่วโมงเวลาไทย):

|         |       0 |       1 |     2 |     3 |   4 |      5 |       6 |       7 |       8 |       9 |    10 |      11 |     12 |     13 |    14 |      15 |   16 |    17 |      18 |   19 |     20 |      21 |    22 |      23 |
|:--------|--------:|--------:|------:|------:|----:|-------:|--------:|--------:|--------:|--------:|------:|--------:|-------:|-------:|------:|--------:|-----:|------:|--------:|-----:|-------:|--------:|------:|--------:|
| argmax  | 150.521 | 156.543 | 193.5 | 181.5 | 115 | 82.011 | 146.622 | 159.522 | 214.649 | 164.569 | 187   | 199.528 | 223.05 | 246.74 | 210.5 | 156.522 |  195 | 184.5 | 143.259 |  120 | 145.04 | 142.579 | 138.5 | 132.537 |
| shipped |   0     |   0     |   0.5 |   0   |   0 |  0     |   0     |   0     |   0     |   0     |   0.5 |   0     |   0    |   0    |   0   |   0     |    0 |   0   |   0     |    0 |   0    |   0     |   0   |   0     |

### 4.3 Threshold

- ตั้งบนครึ่งแรกของข้อมูลเรา (48.8 ชม.) ต่อคลาส: ค่าต่ำสุด (≥ 0.5) ที่ทำให้คลาสนั้นแจ้งผิด ≤ 0.5/8 เหตุการณ์/ชม.
  (รวมทุกคลาส ≤ 0.5/ชม. เผื่อ margin จากเกณฑ์ 1/ชม.) แล้ววัดบนครึ่งหลังเท่านั้น
- คลาสที่ threshold ถูกดันไป ≥ 0.999 (Evil_Twin, Krack, SSDP) **ตั้งเป็น 1.01 = ปิด** (ทางเลือก ก ที่ตกลงกันแล้ว)
- recall บน AWID3 ที่ลดลงหลังใช้ threshold: ดูคอลัมน์ "recall drop" ในข้อ 4.1 — คลาสที่เปิดไว้ไม่ลดเลย

### 4.4 Feature importance (permutation บน AWID3 test: recall ของคลาสนั้นลดลงเท่าไหร่เมื่อสลับฟีเจอร์)

|           | top-3 (recall drop when shuffled)                                                        |
|:----------|:-----------------------------------------------------------------------------------------|
| (Re)Assoc | assoc_req (0.94), new_bssid_known_ssid (0.08), disassoc (0.00)                           |
| Deauth    | deauth_per_mgmt (0.94), tsf_offset_switches (0.15), new_bssid_known_ssid (0.05)          |
| Disas     | disassoc (0.93), rts_per_ctrl (0.33), deauth_seq_out_of_order (0.18)                     |
| Evil_Twin | new_bssid_known_ssid (0.87), deauth_per_mgmt (0.03), tsf_offset_switches (0.02)          |
| Kr00k     | disassoc (0.82), deauth_to_one_client_10s (0.31), beacon_per_mgmt (0.27)                 |
| Krack     | tsf_offset_switches (0.78), deauth_to_one_client_10s (0.21), new_bssid_known_ssid (0.05) |
| RogueAP   | tsf_offset_switches (0.91), deauth_to_one_client_10s (0.79), new_bssid_known_ssid (0.01) |
| SSDP      | rts_per_ctrl (0.39), cts_per_ctrl (0.34), beacon_per_mgmt (0.08)                         |
| normal    | tsf_offset_switches (0.10), new_bssid_known_ssid (0.08), deauth_per_mgmt (0.05)          |

- สมเหตุสมผล: (Re)Assoc → `assoc_req`, Deauth → `deauth_per_mgmt`, Disas/Kr00k → `disassoc`, Evil_Twin → `new_bssid_known_ssid`,
  RogueAP/Krack → `tsf_offset_switches` (AP ปลอมที่ใช้ BSSID เดียวกับของจริง → นาฬิกา TSF สองชุด)
- **น่าสงสัย (อาจเรียนสภาพแวดล้อม):** Disas → `rts_per_ctrl` (อันดับ 2), Kr00k → `beacon_per_mgmt`, SSDP → `rts_per_ctrl`/`cts_per_ctrl` (SSDP ปิดอยู่แล้ว)
- RogueAP → `deauth_to_one_client_10s` อันดับ 2 เพราะ capture RogueAP มี deauth flood (หัวข้อ 2) — โมเดลอาจแจ้ง deauth flood บางแบบเป็น RogueAP
  (ใน test ไม่สับสนกับ Deauth: RogueAP 52/52, Deauth 49/49)

## 5. ความเร็ว

`model_features()` ~10 ms + `predict_proba()` ~25 ms ต่อ 10 แถว **เมื่อจำกัด OpenMP 1–2 thread** (เครื่องเทรน)
ถ้าไม่จำกัด HGB จะเปิด thread เท่าจำนวน core: บนเครื่องเทรน 64 core ช้าลงเป็น ~200 ms (บน Celeron 2 core ไม่น่ามีปัญหา
แต่แนะนำ `OMP_NUM_THREADS=1` หรือ `threadpoolctl.threadpool_limits(1)` ใน monitor)

## 6. การทดลอง ข — แก้ `known_pairs` แล้ว Evil_Twin ผ่านไหม

ต้นเหตุ: `new_bssid_known_ssid` ไม่เป็น 0 ใน ~12–15% ของวินาทีปกติของเรา เพราะ `context.json → pairs` (19 คู่ใน SSID ที่ป้องกัน) ขาด AP จริงที่สัญญาณอ่อน (~-82 dBm)
ซึ่งตรงกับที่ `detection_rules.md` 1.5 บันทึกไว้ (`a4:6c:2a…`, `cc:16:7e…`) — AP เหล่านี้ไม่ได้ถูก Approve

วิธี: คำนวณฟีเจอร์ใหม่จาก `ours/raw` (287 ไฟล์ × 5 นาที, 24.5 ชม.) ด้วย `windows()` ตัวเดิม 2 แบบ
- `orig` = `known_pairs` ของเครื่อง sensor (ตรวจแล้วได้ผลตรงกับ `features.csv`: `{'common_seconds': 88159, 'share_equal': {'frames': 1.0, 'deauth': 1.0, 'new_bssid_known_ssid': 1.0, 'max_bssid_per_ssid': 1.0, 'tsf_offset_switches': 0.9949296158078018}}`)
- `approved` = `orig` + ทุก (SSID ที่ป้องกัน, BSSID ที่เป็น MAC ผู้ผลิต) ที่ beacon ใน **ครึ่งแรก** ของ raw = จำลองการกด Approve
แล้วตั้ง threshold บนครึ่งแรก วัดบนครึ่งหลัง แบบเดียวกับข้อ 4

| known_pairs   |   calib h |   eval h | new_bssid>0 share   |   Evil_Twin thr |   Evil_Twin recall AWID3 |   FA/h argmax (Evil_Twin) |   FA/h thr total |
|:--------------|----------:|---------:|:--------------------|----------------:|-------------------------:|--------------------------:|-----------------:|
| orig          |      12.4 |     12.1 | 11.6%               |            1.01 |                   0      |                     70.52 |            0     |
| approved      |      12.4 |     12.1 | 0.0%                |            0.5  |                   0.9773 |                      0.08 |            0.083 |

AP ที่ต้อง Approve (21 คู่ — ควรให้ฝ่าย IT ยืนยันก่อน):
- `AIS SMART Login` / `a4:6c:2a:6c:c8:fb`
- `AIS SMART Login` / `a4:6c:2a:88:30:5b`
- `AIS SMART Login` / `a4:6c:2a:a8:11:4e`
- `AIS SMART Login` / `a4:6c:2a:c0:70:4b`
- `.@ AIS SUPER WiFi` / `a4:6c:2a:6c:c8:fd`
- `.@ AIS SUPER WiFi` / `a4:6c:2a:a8:11:4f`
- `.@ AIS SUPER WiFi` / `cc:16:7e:b5:e9:ad`
- `KUWIN` / `a4:6c:2a:6c:c8:fe`
- `KUWIN` / `a4:6c:2a:88:30:5e`
- `KUWIN` / `a4:6c:2a:a8:11:4c`
- `KUWIN` / `cc:16:7e:8b:f2:be`
- `KUWIN` / `cc:16:7e:b5:e9:ae`
- `KUWIN-IOT` / `a4:6c:2a:6c:c8:ff`
- `KUWIN-IOT` / `a4:6c:2a:88:30:5f`
- `KUWIN-IOT` / `a4:6c:2a:a8:11:4d`
- `KUWIN-IOT` / `cc:16:7e:8b:f2:bf`
- `eduroam` / `a4:6c:2a:6c:c8:fc`
- `eduroam` / `a4:6c:2a:88:30:5c`
- `eduroam` / `a4:6c:2a:a8:11:4b`
- `eduroam` / `a4:6c:2a:c0:70:4c`
- `eduroam` / `cc:16:7e:8b:f2:bc`

**สรุป:** หลัง Approve ฟีเจอร์ไม่เป็น 0 เหลือ 0.0% ของวินาที (รวมครึ่งหลังที่ไม่ได้ใช้สร้างรายการ), threshold Evil_Twin ลงเป็น 0.5,
recall Evil_Twin บน AWID3 = 0.977 และแจ้งผิด 0.083 เหตุการณ์/ชม. → ผ่านเกณฑ์
ข้อจำกัด: วัดบน 12 ชม. (ข้อมูล raw มีแค่ 24.5 ชม.) และ AP ใหม่ที่ไม่ได้ Approve ในอนาคตจะทำให้ Model C แจ้ง Evil_Twin ทุกวินาทีที่ได้ยิน AP นั้น

## 7. ข้อจำกัด

- **ข้อมูลโจมตีน้อยและมาจากที่เดียว:** 1 capture ต่อคลาส (~3 นาทีโจมตี), test ~50 วินาทีต่อคลาส (Evil_Twin 132) —
  recall 0.957 ของ (Re)Assoc = พลาด 2 จาก 47 วินาที; การโจมตีด้วยเครื่องมือ/อัตราอื่นอาจหน้าตาต่างไป
- **normal ของ AWID3 น้อย** (0.66 ชม. สำหรับเทรน) และเป็นเครือข่ายทดลองที่มี AP เดียว (ASUS) ต่างจากมหาวิทยาลัยมาก — threshold จึงมาจากข้อมูลของเราทั้งหมด
- ข้อมูลของเราช่วงบ่ายวันที่ 8 (พฤหัสฯ) ถึงเที่ยงวันที่ 13 ต.ค. (อังคาร) (รวมวันหยุดสุดสัปดาห์ 10–11 ต.ค.) — ยังไม่ครอบคลุมเหตุการณ์อย่างคนหนาแน่นมาก
- label ของ AWID3 มีความไม่สม่ำเสมอ (RogueAP deauth, beacon evil twin) — ใช้ label รายวินาที "มี frame โจมตี ≥ 1" ตามแผน
- Kr00k ใช้ disassoc flood เหมือน Disas → สับสนกันบ้าง (Kr00k → Disas 4/48)
- สถานะงาน SLURM: ระบบไฟล์ของโหนด `dgx-03` ให้ I/O error 3 ครั้ง (ไฟล์ผลลัพธ์ตรวจแล้วไม่เสีย, ขั้น label/windows รันบน login node)

## 8. สิ่งที่เครื่อง sensor ต้องทำ (แผน v2: โมเดลรันเป็น service บนเครื่องเทรน)

1. รับ token จากผู้ใช้ทางช่องทางอื่น (ไม่อยู่ใน report/git) แล้วยิง `test_vectors/request_*.json` → ต้องได้ผลตรงกับ `response_*.json` (หัวข้อ 10.4)
2. **Approve AP 21 คู่ในหัวข้อ 6** (หลังฝ่าย IT ยืนยัน) — `windows()` บน sensor เป็นคนคำนวณ `new_bssid_known_ssid` ด้วย `known_pairs` ของ sensor
   จากนั้นตั้ง threshold Evil_Twin ใหม่จากข้อมูล shadow mode (จากการทดลองคาดว่า ~0.5) แล้วแจ้งกลับมาแก้ `meta.json` — จนกว่าจะทำ Evil_Twin คง 1.01
3. Shadow mode ≥ 3 วันตามข้อ 8 ของแผน v2

## 9. ไฟล์ใน `model_c/`

| ไฟล์ | |
|---|---|
| `model/model.joblib` | `Pipeline([("clf", HistGradientBoostingClassifier)])`, classes ตาม `meta.json` |
| `model/meta.json` | รูปแบบตามแผน v1 ข้อ 6 + `versions` ครบทุก library (python 3.12.12, numpy, pandas, scikit-learn, scipy, joblib, threadpoolctl) |
| `model/model_c_features.py` | `model_features(win_df)` — numpy/pandas ล้วน, ไม่อ่านไฟล์, ไม่มี state |
| `model/sample_windows.csv`, `model/expected_proba.csv`, `model/test_model_c.py` | ตรวจว่าโหลดโมเดลแล้วได้ผลเดิม (ละเอียด 1e-9) |
| `service/` | โค้ด service, systemd unit, ตัวทดสอบ — หัวข้อ 10 |
| `test_vectors/` | request/response 4 คู่ — หัวข้อ 10.4 |

ย้ายไฟล์โมเดลจาก `model_c/` ไป `model_c/model/` ตามโครงของแผน v2 ข้อ 7 (ไฟล์เหมือนเดิม; `meta.json` เพิ่มเวอร์ชัน library)

## 10. Service

### 10.1 สถานะ: **โค้ดพร้อมและทดสอบแล้ว แต่ยังไม่ได้เปิดถาวร / ยังเข้าจากนอก cluster ไม่ได้**

ตรวจแล้วติด 2 เรื่องที่ต้องให้ผู้ดูแล cluster ตัดสิน (ไม่ได้หาทางเลี่ยง):

1. **firewall ปิดพอร์ต 8500:** <hpc-host> อยู่บน `ens34` = zone `net` ของ Shorewall ซึ่ง default `REJECT`
   (`/etc/shorewall/policy`: `all all REJECT`) และ `/etc/shorewall/rules` เปิดให้ `net` เฉพาะ TCP 22, 80, 443, 636, 8000 (JupyterHub), 8001, 8081,
   8888–8890, 9443, 10443, 30080, 30443 — ไม่มี 8500 การเพิ่ม rule ต้องใช้ root
   พอร์ตที่เปิดอยู่แต่ไม่มีอะไรฟัง (8001, 8888, 8889, 8890) **ไม่ได้เลือกใช้เอง** เพราะเป็นพอร์ตที่ผู้ดูแลเปิดไว้เพื่องานอื่น — ต้องถามก่อน
2. **นโยบายรัน service ค้างบน `br1`:** ไม่พบเอกสารนโยบายบนเครื่อง (motd, `/etc/profile.d`, `/cm/shared/docs`)
   `br1` เป็น head node ของ cluster (Bright Base Command Manager 10, มี JupyterHub/Kubernetes ingress) และไม่มีผู้ใช้คนไหนเปิด linger
   (`/var/lib/systemd/linger/` ว่าง, ของเรา `Linger=no`) — การรัน service ถาวรต้องใช้ `loginctl enable-linger` → **ยังไม่ได้เปิด รอผู้ดูแลอนุญาต**

ทดสอบจากเครื่องอื่นยังทำไม่ได้: compute node (`dgx-03`) เข้ามาทาง zone `nat` (ACCEPT ทุกพอร์ต) จึงไม่ได้พิสูจน์อะไรเรื่อง firewall ฝั่ง `net`
และไม่มีเครื่องนอก cluster ให้ทดสอบจาก session นี้ — ผลในหัวข้อ 10.3–10.4 เป็นการยิงที่ `127.0.0.1` เท่านั้น

### 10.2 การใช้งาน

- URL (เมื่อเปิดแล้ว): `http://<hpc-host>:8500` — `GET /v1/info`, `POST /v1/predict`, `GET /v1/health`
- ทุก endpoint ต้องมี `Authorization: Bearer <token>`; ไม่มี/ผิด → 401; token อยู่ที่ `service/model_c.token` (chmod 600, 64 ตัวอักษร)
- `context_seconds` = 10 ตามที่กำหนด (โมเดลจริงใช้แค่ 36 คอลัมน์ของวินาทีนั้น — ฟีเจอร์ย้อนหลังยาวสุดที่ใช้ `deauth_to_one_client_10s` sensor คำนวณมาให้แล้วใน `windows()`)
- วินาทีที่ขาดระหว่าง `win` ต่ำสุด–สูงสุดของ request เติม 0 แล้ว **ตอบผลของวินาทีนั้นด้วย** (ทุกวินาที `>= predict_from`) — ดู `test_vectors/*gap*`
- คอลัมน์เกินจาก 36 ตัวถูกเมิน, ขาดตัวใด → 400; `feature_version` ≠ 2 → 409; request ครอบคลุมเกิน 3600 วินาที หรือ body > 4 MB → 413
- ไม่มี state ข้าม request; log 1 บรรทัดต่อ request (IP, path, status, เวลา, sensor_id, จำนวน window/alert) — ไม่บันทึก header/token

เปิด/ปิด:
- ทดสอบชั่วคราว: `cd ~/experiment_1/model_c/service && OMP_NUM_THREADS=2 ~/experiment_1/.venv/bin/python model_c_service.py --host 127.0.0.1 --port 8500`
- ถาวร (หลังได้รับอนุญาต + เปิด firewall + `loginctl enable-linger`): ติดตั้ง `service/model_c.service` ตามคำสั่งในไฟล์ แล้ว
  `systemctl --user start|stop|status model_c.service`, log: `journalctl --user -u model_c.service`
  unit ตั้ง `OMP_NUM_THREADS=2`, `Restart=on-failure`, `MemoryMax=2G`, `CPUQuota=200%`, `Nice=5` และ service เองจำกัด thread ด้วย `threadpoolctl`

### 10.3 ผลทดสอบ (`service/check_service.py`, ยิงที่ `127.0.0.1:8500`, 2026-10-13)

- ผ่านทั้งหมด (19 ข้อในโหมด record, 23 ข้อในโหมดเทียบกับ `response_*.json`): health/info ครบ field, ไม่มี token/token ผิด → 401 ทั้ง 3 endpoint, `feature_version` 1 → 409,
  ขาดฟีเจอร์ → 400, JSON เสีย → 400, path ผิด → 404, `GET /v1/predict` → 405, `predict_from` เกินวินาทีสุดท้าย → ผลว่าง
- ผลจาก service ตรงกับการเรียกโมเดลโดยตรงทุกค่า (ต่าง 0) และตรงกับ `response_*.json` เมื่อยิงซ้ำ
- **เวลาตอบ** request 70 วินาที (ตอบ 5): median 53 ms, สูงสุด 54 ms จาก 20 ครั้ง (เกณฑ์ < 1 วินาที); request 15 วินาที ~53–95 ms
- log ไม่มี token (ตรวจแล้ว)

### 10.4 Test vectors (`test_vectors/`, response ได้จาก service จริง)

| คู่ | ที่มา | window | ผล |
|---|---|---|---|
| `normal_ours` | `ours/features.csv` 2026-10-12 14:00 (เวลาไทย) | 10 context + 5 | normal ×5, ไม่แจ้ง |
| `attack_deauth_awid3` | AWID3 Deauth (test split) | 10 + 5 | Deauth ×5, แจ้ง |
| `attack_evil_twin_awid3` | AWID3 Evil_Twin (test split) | 10 + 5 | proba Evil_Twin 0.97–1.0 แต่ **ไม่แจ้ง** (threshold 1.01) → predicted normal |
| `gap_ours` | `ours/features.csv` ช่วงที่ขาดจริง 2 วินาที | 22 วินาทีที่มี (ช่วง 24 วินาที) | ตอบ 14 วินาที รวม 2 วินาทีที่เติม 0, normal ทั้งหมด |
