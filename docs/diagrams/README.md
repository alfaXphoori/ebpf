# 🖼️ แผนภาพของหลักสูตร (Course Diagrams)

แผนภาพ flowchart ทุกภาพในหลักสูตรเป็นไฟล์ SVG สไตล์การ์ด (กล่องมุมโค้ง สีพาสเทล เงาบาง ป้ายหัวกลุ่มสีทึบ) ที่ render จากต้นฉบับ Mermaid ในโฟลเดอร์ [`src/`](src/) ส่วน Sequence Diagram 4 ภาพ (W08, W20, W21, W22) ยังเป็นบล็อก Mermaid ใน README ตามเดิม

## แก้ไขแผนภาพ

1. แก้ไฟล์ `src/<ชื่อ>.mmd` (ไวยากรณ์ Mermaid flowchart ปกติ)
2. รัน `make diagrams` ที่ root ของ repo หรือ `scripts/render_diagrams.sh <ชื่อ>` เพื่อ render เฉพาะภาพนั้น
3. เปิดไฟล์ `docs/diagrams/<ชื่อ>.svg` ดูผล แล้ว commit ทั้ง `.mmd` และ `.svg`

อย่าแก้ไฟล์ `.svg` ด้วยมือ เพราะจะถูกเขียนทับในการ render ครั้งถัดไป

## สิ่งที่ต้องมีในเครื่อง

- `docker` กับ image `minlag/mermaid-cli:11.4.2` (เปลี่ยนได้ด้วยตัวแปร `MMDC_IMAGE`)
- `python3` และ `libharfbuzz-subset0` (ใช้ตัดฟอนต์ให้เหลือเฉพาะตัวอักษรที่ใช้)
- `fonts-noto-core` และ `fonts-dejavu-core`

## ขั้นตอนภายใน

```
src/<ชื่อ>.mmd ──mmdc (ธีม mermaid-config.json)──▶ raw SVG ──diagram_postprocess.py──▶ <ชื่อ>.svg
```

- [`mermaid-config.json`](mermaid-config.json): ธีม `base` ฟอนต์ Noto Sans / Noto Sans Thai เส้นหนา 2px
- [`../../scripts/diagram_postprocess.py`](../../scripts/diagram_postprocess.py): ทำมุมโค้ง ใส่เงา ทำป้ายหัวกลุ่ม (สีเลือกจาก id ของ subgraph เช่น `KERNEL` แดง, `USER` น้ำเงิน, `TEST` เขียว) ใส่พื้นหลังการ์ดสีขาว และฝังฟอนต์แบบ subset เพื่อให้ภาษาไทยแสดงเหมือนกันทุกเครื่อง

## สีของ class (ใช้ใน `classDef`)

| class | ความหมาย | fill / stroke |
|---|---|---|
| `kern`, `hook`, `sec` | โค้ดหรือ hook ฝั่งเคอร์เนล | `#ffe4e6` / `#e11d48` |
| `user`, `week`, `core` | โปรแกรม user space / สัปดาห์ | `#dbeafe` / `#2563eb` |
| `map`, `perf` | BPF map | `#fef3c7` / `#d97706` |
| `net`, `test` | netns, veth, แพ็กเก็ต / การทดสอบ | `#dcfce7` / `#16a34a` |
| `trig` | คำสั่งทดสอบหรือ CLI flag | `#f1f5f9` / `#64748b` |
| `doc` | เอกสาร / เครื่องมือ | `#ffedd5` / `#ea580c` |
| `file` | ไฟล์ในแล็บ | `#f8fafc` / `#94a3b8` |
| `phase` | เฟส | `#ede9fe` / `#7c3aed` |
| `root` | รากของต้นไม้ | `#1e293b` / `#0f172a` (ตัวอักษรขาว) |

## ชื่อไฟล์

| ไฟล์ | ใช้ใน |
|---|---|
| `course-flow`, `prerequisite-map` | `README.md` |
| `content-tree-overview`, `content-tree-phase01` … `phase11` | `docs/CONTENT_TREE.md` |
| `guide-ch01` … `guide-ch11` | `docs/MASTER_STUDY_GUIDE.md` |
| `week01-overview` … `week26-overview` | `README.md` ของแต่ละสัปดาห์ |
