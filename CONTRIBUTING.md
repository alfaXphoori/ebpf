# แนวทางการแก้โค้ดและเพิ่มแล็บ

เอกสารนี้สรุปโครงสร้างโฟลเดอร์ กฎความปลอดภัย สไตล์โค้ด และคำสั่งเช็กความเรียบร้อยของ **eBPF Zero to Hero** เผื่อเวลาต้องการแก้แล็บเดิม เพิ่มโจทย์ หรือเพิ่มแล็บใหม่

---

## 1. โครงสร้างของแต่ละสัปดาห์

แต่ละแล็บจะอยู่ใน `phaseXX-<ชื่อเฟส>/weekYY-<ชื่อหัวข้อ>/` โดยแล็บที่ใช้ C + Go จะจัดไฟล์แบบนี้:

```text
weekYY-<topic>/
├── README.md        # อธิบายหลักการทำงาน, ไล่โค้ดทีละบรรทัด, วิธีรัน, ตัวอย่าง output,
│                    # ข้อจำกัด, Checklist, แก้ปัญหาที่พบบ่อย และโจทย์ฝึกมือ 3 ระดับ
├── Makefile         # target: all, generate, build, run, test, clean
├── go.mod / go.sum  # Go module แยกต่อสัปดาห์ (ห้ามชี้ path ออกนอก repo)
├── *.c              # โค้ด eBPF ฝั่งเคอร์เนล (GPL-2.0-only, build ผ่าน //go:generate + bpf2go)
├── main.go          # โปรแกรม Go ฝั่ง User Space (โหลด BPF, แสดงผล, CLI)
└── main_test.go     # Unit tests (BPF_PROG_TEST_RUN หรือทดสอบ load/attach จริง)
```

---

## 2. กฎความปลอดภัยที่ต้องทำตาม

1. **ห้ามแก้ไขระบบโฮสต์ค้างไว้**
   - แล็บเครือข่ายทั้งหมด (`week01`, `week02`, `week07`, `week08`, `week11`, `week12`, `week13`, `week21`, `week25`) ต้องรันใน Network Namespace ที่ขึ้นต้นด้วย `wXX-` (เช่น `w08-lb`, `w21-rx`) เท่านั้น ห้ามแก้ routing table หรือ `sysctl` ของเครื่องหลัก
   - แล็บ cgroup (`week14`, `week20`) ต้องสร้าง sub-cgroup เฉพาะของตัวเอง (เช่น `/sys/fs/cgroup/w14-*`, `/sys/fs/cgroup/w20-*`) **ห้าม** ผูกตัวบล็อกเข้ากับ root cgroup `/sys/fs/cgroup` เด็ดขาด
2. **ล้างระบบทุกครั้งหลังจบ (`SWITCH_PARTIAL` และ Cleanup):** ปิดแล็บหรือจบเทสต์แล้ว ต้องลบ namespace / cgroup / tc / xdp และคืนค่า sysctl ที่แตะไว้ให้หมด
3. **จำกัดวงของ Policy ทดสอบ**
   - แล็บคุมไฟล์/โปรเซส (`week10`, `week26`) ต้องชี้ path ทดสอบไว้ใต้ `lab-files/` เท่านั้น เลี่ยงกฎที่ไปโดนไฟล์ระบบ (เช่น `-block-all` ใน `week10` หรือกฎบล็อกที่ไม่จำกัดชื่อไฟล์ binary ใน `week26`)
   - โค้ดตัวอย่างที่เปิดหรือเชื่อม socket ให้ใช้เฉพาะ loopback (`127.0.0.1` / `::1`) หรือ IP ใน `wXX-*` namespace เท่านั้น
4. **ไม่เอา `vmlinux.h` และไฟล์ที่คอมไพล์แล้วขึ้น Git**
   - `vmlinux.h`, `*_bpfel.go`, `*_bpfeb.go`, `*.o` และ `bin/` ถูก ignore ไว้ใน `.gitignore` แล้ว ให้ใช้ `make vmlinux` / `make` สร้างเอาเอง

---

## 3. แนวทางเขียนโค้ด

### ฝั่ง Kernel C (eBPF)
- **เน้น CO-RE:** งานที่อ่านโครงสร้างภายในเคอร์เนล (`task_struct`, `sk_buff`, tracepoint raw structs, `fentry`/`fexit`, `lsm`, `kfuncs`) ให้ `#include "../../vmlinux.h"` คู่กับ `<bpf/bpf_helpers.h>`, `<bpf/bpf_core_read.h>`, `<bpf/bpf_tracing.h>` และอ่านด้วย `BPF_CORE_READ()`
- **ใช้ UAPI สำหรับ XDP/TC:** งานแกะแพ็กเก็ต (`week07`, `week08`, `week11`, `week12`, `week21`) ใช้ header มาตรฐาน (`<linux/bpf.h>`, `<linux/if_ether.h>`, `<linux/ip.h>`, `<linux/tcp.h>`) เพื่อลดการพึ่ง BTF ที่ไม่จำเป็น
- **เช็กขอบเขต Pointer เสมอ:** ทุกครั้งที่อ่านข้อมูลจาก `data`/`data_end` หรือ buffer ต้องเช็ก bounds ให้ BPF Verifier มั่นใจก่อนเสมอ
- **ระวัง Byte Order สลับกัน:**
  - ใน `sk_ops` (`week20`): `local_port` เป็น Host byte order ส่วน `remote_port` เป็น Network byte order
  - ใน `xdp_md` / `__sk_buff`: IP และ Port ใน header เป็น Network byte order — เช็ก `bpf_htons()` / `bpf_htonl()` ให้ตรงกับฝั่ง Go
- **ใส่ License:** ไฟล์ `.c` ที่เรียก helper/kfunc ของเคอร์เนลต้องมี `char LICENSE[] SEC("license") = "GPL";` (ดูรายละเอียดใน [LICENSE](LICENSE))

### ฝั่ง Go และ Python
- **จัดหน้าโค้ดและตรวจ static check:** โค้ด Go ทุกไฟล์ต้องผ่าน `gofmt` (`make fmt-check`) และ `go vet ./...` (`make vet`)
- **เขียนเทสต์อัตโนมัติ:** แล็บ Go+eBPF ทุกตัวควรมี `main_test.go` และ `test:` ใน `Makefile` ที่เรียก `go test -exec sudo -v ./...` โดยใช้ `BPF_PROG_TEST_RUN` หรือ load/attach สั้นๆ ที่จบในไม่กี่วินาทีและไม่พึ่งเน็ตนอกเครื่อง
- **เทสต์และ syntax ของ Python:** สคริปต์ Python ที่มี logic สำคัญ (`week01`, `week18`, `week26`) ควรมี `test_*.py` (`unittest`) ที่รันได้โดยไม่ต้องใช้ root (`make py-test`)
- **ตั้งสิทธิ์รันให้สคริปต์:** สคริปต์ที่มี `#!` ด้านบน ต้องทำ `chmod +x` ไว้เสมอ (`scripts/check_docs.py` ช่วยเช็กให้อัตโนมัติ)

---

## 4. แผนภาพและเอกสาร

- ต้นฉบับแผนภาพอยู่ใน `docs/diagrams/src/*.mmd` แปลงเป็น SVG ลง `docs/diagrams/out/*.svg` ด้วย:
  ```bash
  make diagrams
  ```
  รายละเอียดเพิ่มเติมดูใน [docs/diagrams/README.md](docs/diagrams/README.md)
- เวลาเพิ่มหรือแก้ไฟล์ Markdown หรือแผนภาพ ให้เช็กลิงก์ด้วย:
  ```bash
  make docs-check
  ```
  (`scripts/check_docs.py` จะเช็กลิงก์ทั้งหมด, คู่ `.mmd`/`.svg`, SVG ที่ไม่ได้ใช้ และสิทธิ์ `+x` ของสคริปต์)

---

## 5. เช็กให้ครบก่อน Push

รันคำสั่งเดียวจาก root ของ repo:

```bash
make check
```

คำสั่งนี้จะไล่เช็กให้ครบทุกขั้น:
1. `all`: สร้าง `vmlinux.h` (ถ้ายังไม่มี) แล้ว `go generate` + `go build` ทุกแล็บ
2. `test`: รัน `go test -exec sudo -v ./...` ในทุกสัปดาห์ที่มีชุดทดสอบ
3. `vet`: รัน `go vet ./...` ครบทุก Go module
4. `fmt-check`: ตรวจ `gofmt -l` บนไฟล์ `.go` ทั้งหมด (ยกเว้น `*_bpf*.go` ที่ generate)
5. `docs-check`: รัน `python3 scripts/check_docs.py`
6. `py-test`: รัน Python `unittest` (`week01`, `week18`, `week26`)
7. ตรวจ syntax ของสคริปต์ทั้งหมดด้วย `bash -n` และ `python3 -m py_compile`

> หมายเหตุ: ถ้าแก้โค้ด CO-RE ที่อ่าน struct ภายในเคอร์เนล (เช่น tracepoints, `task_struct`, `sk_buff`, `sched_ext_ops`) แนะนำให้ลองรันบน Ubuntu 24.04 VM (Kernel 6.8) เพิ่มด้วยตามที่บอกไว้ใน [README.md](README.md)

---

## 6. สัญญาอนุญาต (License)

- โค้ด Kernel-space eBPF C: **GPL-2.0-only** ([LICENSES/GPL-2.0.txt](LICENSES/GPL-2.0.txt))
- โค้ด User-space (Go, Python), สคริปต์ และเอกสาร: **MIT** ([LICENSES/MIT.txt](LICENSES/MIT.txt))
- รายละเอียดเต็มดูใน [LICENSE](LICENSE)
