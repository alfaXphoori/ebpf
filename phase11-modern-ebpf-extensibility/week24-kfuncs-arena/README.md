# สัปดาห์ที่ 24: kfuncs และ BPF Arena — เรียกฟังก์ชันเคอร์เนลอย่างปลอดภัย และแชร์หน่วยความจำกับ User Space

ยินดีต้อนรับสู่ **Week 24** ของหลักสูตร eBPF Zero to Hero!

สัปดาห์นี้เป็นสัปดาห์แรกของ **Phase 11: Modern eBPF Extensibility** ตลอด 23 สัปดาห์ที่ผ่านมา โปรแกรม eBPF ของเราคุยกับเคอร์เนลผ่าน **BPF helpers** (`bpf_map_lookup_elem`, `bpf_probe_read_kernel`, ...) และคุยกับ user space ผ่าน **map** (lookup/update ทีละ key ด้วย syscall `bpf()`) สัปดาห์นี้เราจะรู้จักกลไกรุ่นใหม่สองอย่างที่ eBPF สมัยใหม่ (เช่น `sched_ext` ใน Week 25) พึ่งพาอย่างมาก:

1. **kfuncs** — ฟังก์ชันในเคอร์เนลที่ "เปิดให้ BPF เรียก" ผ่าน BTF พร้อมกฎความปลอดภัยที่ verifier บังคับ เช่น ทุก reference ที่ได้จาก `bpf_task_from_pid()` ต้องคืนด้วย `bpf_task_release()` เสมอ
2. **BPF Arena** (`BPF_MAP_TYPE_ARENA`) — พื้นที่หน่วยความจำ (สูงสุด 4 GiB) ที่ BPF และ user space **`mmap` ร่วมกัน** BPF สร้างโครงสร้างข้อมูลที่มี pointer จริง (เช่น linked list) แล้วโปรแกรม Go เดินตาม pointer เดียวกันได้โดยไม่ต้อง lookup map เลย

ทุกตัวเลขและข้อความ error ในบทนี้มาจากการรันจริงบน Linux 7.0 (หัวข้อ 4)

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 Helper vs kfunc

| | BPF helper | kfunc |
|---|---|---|
| ตัวอย่าง | `bpf_map_lookup_elem()`, `bpf_probe_read_kernel()` | `bpf_task_from_pid()`, `bpf_cpumask_create()`, `bpf_arena_alloc_pages()` |
| การอ้างถึงใน bytecode | `call <หมายเลข helper>` ตาม enum ใน UAPI (`bpf_func_id`) | `call` แบบ `BPF_PSEUDO_KFUNC_CALL` + **BTF ID** ของฟังก์ชันใน kernel BTF |
| ประกาศใน C | `bpf_helper_defs.h` (pointer to function คงที่) | `extern ... __ksym;` (vmlinux.h ของ bpftool 7.x มีให้แล้ว) |
| ความเสถียร | เป็น UAPI: เพิ่มได้ ห้ามเปลี่ยน/ลบ | **ไม่มี stable ABI** — คล้าย `EXPORT_SYMBOL_GPL` อาจเปลี่ยนชื่อ/signature/ถูกลบได้ในเคอร์เนลรุ่นถัดไป |
| ใครเพิ่มได้ | ต้องแก้ core BPF + UAPI | subsystem ใดก็ได้ (รวมถึง kernel module) ลงทะเบียนด้วย `register_btf_kfunc_id_set()` |
| อนุญาตให้ใครเรียก | กำหนดใน `get_func_proto` ของแต่ละ program type | ลงทะเบียน **ต่อ program type** (เช่น TRACING, SYSCALL, SCHED_CLS, STRUCT_OPS) |

ชุมชน BPF ตัดสินใจราวปี 2022–2023 ว่าจะไม่เพิ่ม helper ใหม่อีก ฟีเจอร์ใหม่เกือบทั้งหมดจึงมาในรูป kfunc (อ้างอิง: เอกสาร `Documentation/bpf/kfuncs.rst` ในซอร์สเคอร์เนล — ควรอ่านฉบับที่ตรงกับเคอร์เนลที่ใช้)

### 1.2 kfunc ถูก resolve อย่างไร (`__ksym`, `__weak`, `bpf_ksym_exists`)

```
task_kfunc.c                         cilium/ebpf (loader)                    Kernel
-----------------------              ---------------------------------       ---------------------------
extern ... bpf_task_from_pid(...)    อ่าน .ksyms ใน ELF                       /sys/kernel/btf/vmlinux
    __weak __ksym;          -------> หา FUNC 'bpf_task_from_pid' ใน    ----> [99570] FUNC 'bpf_task_from_pid'
call bpf_task_from_pid               kernel BTF แล้วเขียน BTF ID ลง imm      [98316] DECL_TAG 'bpf_kfunc' type_id=99570
                                     ของคำสั่ง call                           verifier: อนุญาตกับ prog type นี้ไหม?
                                                                                       เช็ก flag KF_* และชนิดอาร์กิวเมนต์
```

- **`__ksym`** (= `section(".ksyms")`) บอก loader ว่าสัญลักษณ์นี้ต้องหาใน kernel BTF ไม่ใช่ใน ELF
- **`__weak`** ถ้าหาไม่เจอ loader จะไม่ล้ม: ที่อยู่ของสัญลักษณ์ = 0 และคำสั่ง `call` ถูก "poison" (cilium/ebpf ใช้ค่าคงที่ `0xdedc0de` + ...)
- **`bpf_ksym_exists(sym)`** (จาก `bpf_helpers.h`) = `!!sym` บังคับว่า `sym` ต้องเป็น `__weak` เมื่อ kfunc ไม่มีอยู่ ค่าเป็น 0 แบบคงที่ verifier จึงรู้ว่า branch ที่เรียก kfunc นั้น **ไม่มีทางเกิดขึ้น** และตัดทิ้ง (dead code) โปรแกรมเดียวกันจึงโหลดได้ทั้งบนเคอร์เนลที่มีและไม่มี kfunc นั้น — ในแล็บเราพิสูจน์ด้วย kfunc ปลอม `bpf_week24_no_such_kfunc` (ผลจริง: `bpf_ksym_exists(...) = 0` และโปรแกรมโหลดผ่าน)

### 1.3 กฎ reference ของ kfunc: flag `KF_*`

แต่ละ kfunc ถูกประกาศในซอร์สเคอร์เนลด้วย `BTF_ID_FLAGS(func, <name>, <flags>)` (เช่นใน `kernel/bpf/helpers.c`, `kernel/bpf/cpumask.c`) flag เหล่านี้ **ไม่ได้อยู่ใน BTF** ต้องเปิดดูจากซอร์สของเคอร์เนลรุ่นที่ใช้ flag หลัก ๆ:

| Flag | ความหมายที่ verifier บังคับ | ตัวอย่างในแล็บ |
|---|---|---|
| `KF_ACQUIRE` | ค่าที่คืนคือ **reference** (refcount +1) — โปรแกรมต้องส่งต่อให้ kfunc ที่เป็น `KF_RELEASE` ก่อนจบทุกเส้นทาง ไม่งั้นได้ `Unreleased reference` | `bpf_task_from_pid`, `bpf_cpumask_create` |
| `KF_RET_NULL` | ค่าที่คืนอาจเป็น NULL — ต้องเช็กก่อน dereference (ชนิดใน log คือ `trusted_ptr_or_null_`) | `bpf_task_from_pid`, `bpf_cpumask_create` |
| `KF_RELEASE` | รับ reference ไปคืน หลังเรียกแล้ว pointer เดิม (และสำเนาทุกตัว) ใช้ไม่ได้อีก | `bpf_task_release`, `bpf_cpumask_release` |
| `KF_RCU` | รับอาร์กิวเมนต์ที่เป็น trusted **หรือ** RCU-protected pointer | `bpf_cpumask_copy`, `bpf_task_acquire` |
| `KF_TRUSTED_ARGS` | อาร์กิวเมนต์ pointer ต้อง "trusted" (มาจาก ctx/acquire โดยตรง ไม่ใช่เดินผ่าน pointer ที่ไม่น่าเชื่อถือ) | — |
| `KF_SLEEPABLE` | เรียกได้เฉพาะในโปรแกรม sleepable | — |

> [!NOTE]
> ชุด flag และ flag ที่เป็นค่าเริ่มต้นเปลี่ยนไปตามรุ่นเคอร์เนล (มีงาน upstream ที่ปรับให้พฤติกรรมแบบ trusted args เป็นค่าเริ่มต้น) ตารางนี้คือแนวคิด ไม่ใช่สัญญา — ให้ยึด error ของ verifier บนเครื่องจริงเป็นหลัก ซึ่งแล็บนี้ทดสอบไว้ใน `TestBrokenProgramsRejected`

**trusted vs RCU pointer:** `t` ที่ได้จาก `bpf_task_from_pid()` เป็น *trusted* (เรามี reference) แต่ field อย่าง `t->real_parent` หรือ `t->cpus_ptr` ถูกมองเป็น pointer ที่ปลอดภัยเฉพาะภายใต้ RCU ในโปรแกรม **sleepable** (เช่น `SEC("syscall")`) จึงต้องครอบด้วย `bpf_rcu_read_lock()` / `bpf_rcu_read_unlock()` (ซึ่งก็เป็น kfunc) ตอนพัฒนาแล็บนี้ เราเรียก `bpf_cpumask_copy(mask, t->cpus_ptr)` นอก lock แล้วได้ error จริงว่า `R2 must be a rcu pointer`

### 1.4 kfunc ลงทะเบียนแยกตาม program type

kfunc ชุดเดียวกันอาจใช้ได้ใน `tp_btf`/`fentry` (TRACING) และ `SEC("syscall")` แต่ใช้ไม่ได้ใน socket filter ถ้าเรียกผิดชนิด verifier ตอบว่า `calling kernel function bpf_task_from_pid is not allowed` (โปรแกรม `wrong_prog_type` ในแล็บ) — เวลาจะใช้ kfunc ตัวไหน ต้องดูว่า subsystem นั้นเรียก `register_btf_kfunc_id_set(BPF_PROG_TYPE_..., ...)` กับชนิดใดบ้าง

ในแล็บนี้เลือก **`SEC("syscall")` (`BPF_PROG_TYPE_SYSCALL`)** เพราะ: (1) kfunc ทั้ง task, cpumask และ arena ใช้ได้ (2) ไม่ต้อง attach กับ hook ใด เรียกด้วย `BPF_PROG_TEST_RUN` ได้โดยตรง พร้อมส่ง struct เข้า-ออกผ่าน `ctx` จึงทดสอบแบบ deterministic ได้ (3) เป็น sleepable ทำให้ได้เห็นกฎ RCU ข้างบน

### 1.5 ค้นหา kfunc บนเครื่องที่รันอยู่

kfunc ที่ "export" ให้ BPF จะมี BTF **decl tag `bpf_kfunc`** ผูกกับ FUNC (ต้องใช้ pahole รุ่นใหม่ตอน build เคอร์เนล — Ubuntu 26.04 มีแล้ว) วิธีที่ใช้ได้จริงบน 7.0:

```bash
# 1) นับจำนวน kfunc ใน vmlinux (ได้ 272 บนเครื่องทดสอบ)
bpftool btf dump file /sys/kernel/btf/vmlinux | grep -c "DECL_TAG 'bpf_kfunc'"

# 2) ดู prototype แบบ C — bpftool 7.x สร้างบล็อก "/* BPF kfuncs */" จาก decl tag ให้
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -E '__ksym;$' | grep bpf_task_

# 3) รายชื่อล้วน (จับคู่ DECL_TAG -> FUNC id)
bpftool btf dump file /sys/kernel/btf/vmlinux | awk '
  $2=="FUNC"{id=substr($1,2,length($1)-2); fn[id]=$3}
  $2=="DECL_TAG" && $3=="'"'"'bpf_kfunc'"'"'"{split($4,a,"="); k[a[2]]=1}
  END{for(i in k) print fn[i]}' | tr -d "'" | sort

# 4) kfunc จาก kernel module (มี BTF แยกไฟล์)
for m in /sys/kernel/btf/*; do n=$(bpftool btf dump file $m 2>/dev/null | grep -c "DECL_TAG 'bpf_kfunc'"); [ "$n" -gt 0 ] && echo "$(basename $m) $n"; done
```

> [!WARNING]
> คำสั่งยอดนิยม `bpftool btf dump ... format c | grep bpf_kfunc` **ใช้ไม่ได้** — output แบบ C ไม่มีชื่อ decl tag ให้ grep (ที่เจอ 13 บรรทัดบน 7.0 คือ struct ภายในอย่าง `bpf_kfunc_desc` ไม่ใช่ kfunc) และ flag `KF_*` ไม่อยู่ใน BTF เลย ต้องดูจากซอร์สเคอร์เนล

### 1.6 BPF Arena คืออะไร

map แบบเดิมเก็บ "ค่า" ขนาดคงที่ต่อ key เวลา BPF อยากได้โครงสร้างข้อมูลแบบ linked list/tree ต้องจำลองด้วย index และ user space ต้อง lookup ทีละ key (1 syscall ต่อ key หรือ batch) **Arena** (Linux 6.9+, x86-64 เป็นสถาปัตยกรรมแรก) แก้ปัญหานี้ด้วยแนวคิด "heap ที่แชร์กัน":

```
              user space (Go)                                kernel (BPF program)
   ┌──────────────────────────────────────┐        ┌──────────────────────────────────────┐
   │ mmap(arena fd)  user_vm_start         │        │ kern_vm_start (เคอร์เนลจองให้ 4 GiB+guard)│
   │ 0x7a23c2b3e000 ┌────────┬────────┐   │        │                ┌────────┬────────┐  │
   │                │ page 0 │ page 1 │…  │ <====> │                │ page 0 │ page 1 │… │
   │                └────────┴────────┘   │ same   │                └────────┴────────┘  │
   └──────────────────────────────────────┘ pages  └──────────────────────────────────────┘
     pointer ที่เก็บใน arena = user address (64 บิต)      JIT ใช้ kern_vm_start + (32 บิตล่างของ pointer)
```

- สร้างด้วย `BPF_MAP_TYPE_ARENA` + **`BPF_F_MMAPABLE` (บังคับ)**; `max_entries` คือ **จำนวนหน้า** (สูงสุด 2^20 หน้า = 4 GiB บนหน้า 4 KiB — วัดจริงในหัวข้อ 4) `key_size`/`value_size` = 0
- หน่วยความจำจริงยัง **ไม่ถูกจอง** ตอนสร้าง map (sparse) หน้าจะมีจริงเมื่อ (ก) BPF เรียก kfunc `bpf_arena_alloc_pages()` หรือ (ข) user space แตะหน้านั้น (page fault ฝั่ง user → เคอร์เนลจองหน้าให้) ถ้าสร้าง map ด้วย `BPF_F_SEGV_ON_FAULT` การแตะหน้าที่ยังไม่จองจะได้ SIGSEGV แทน — ทดลองกับ `Memory.ReadAt` ใน Go แล้ว process ตายทันทีด้วย `unexpected fault address ... fatal error: fault`
- kfunc ที่เกี่ยวข้องบน 7.0: `bpf_arena_alloc_pages`, `bpf_arena_free_pages` และ `bpf_arena_reserve_pages` (ตัวหลังเป็นของใหม่กว่า — เจอใน BTF ของ 7.0 ไม่ได้ใช้ในแล็บ)

### 1.7 Address space 1 และการ cast pointer

ใน C ฝั่ง BPF เราประกาศ pointer ที่ชี้เข้า arena เป็น `__attribute__((address_space(1)))` (ตั้งชื่อ macro ว่า `__arena`) ค่า pointer ที่ **เก็บ** ในหน่วยความจำ arena เป็นรูปแบบ **user address** (64 บิตเต็ม) เพื่อให้ user space เดินตามได้ ส่วนเวลา BPF จะ **dereference** ต้องแปลงเป็นที่อยู่ฝั่งเคอร์เนล:

| ทิศทาง | คำสั่ง BPF | ใครแทรก |
|---|---|---|
| as(1) → as(0) "cast_kern" (ก่อน load/store) | `rX = addr_space_cast(rY, 0x0, 0x1)` | clang ≥ 19 แทรกอัตโนมัติเมื่อมี `__BPF_FEATURE_ADDR_SPACE_CAST` (ในแล็บนับได้ 12 คำสั่งใน `arena_bpfel.o`) |
| as(0) → as(1) "cast_user" | `addr_space_cast(rY, 0x1, 0x0)` | clang/verifier |

JIT แปลง load/store ผ่าน pointer ของ arena เป็นแบบ `PROBE_MEM32`: ใช้ 32 บิตล่างของ pointer บวก `kern_vm_start` และมี exception table รองรับ ผลคือ:
- **BPF แตะหน้าที่ยังไม่ได้จอง → เคอร์เนลไม่ crash**: load ได้ 0, store ถูกทิ้งเงียบ ๆ (พิสูจน์ในหัวข้อ 4.2)
- **ไม่ต้อง bounds check** แบบ map value — verifier ไม่รู้ว่า pointer ชี้หน้าไหน และไม่จำเป็นต้องรู้

### 1.8 ลำดับชีวิตของ arena: ต้อง `mmap()` ก่อนโหลดโปรแกรม

verifier/JIT ต้องรู้ `user_vm_start` (ใช้สร้าง 32 บิตบนของ user pointer) **ตอน `BPF_PROG_LOAD`** ซึ่งได้มาจาก `map_extra` ตอนสร้าง map หรือจากการ `mmap()` ครั้งแรก ถ้าโหลดโปรแกรมก่อน จะได้ error จริง:
```
load program: invalid argument: arena's user address must be set via map_extra or mmap()
```
ใน cilium/ebpf v0.22 จึงต้องแยกขั้นตอน: `ebpf.NewMap(spec.Maps["arena"])` → `m.Memory()` (= `mmap(fd, PROT_READ|PROT_WRITE, MAP_SHARED)`) → `spec.LoadAndAssign(..., MapReplacements{"arena": m})` (`loadArenaObjects()` ที่ bpf2go สร้างให้ ใช้ตรง ๆ ไม่ได้) และเพราะ cilium/ebpf `mmap` ด้วย address = NULL เราจึงใช้ `map_extra` (บังคับ address คงที่) กับ `Map.Memory()` ไม่ได้ — ทดลองจริงด้วย `MapExtra: 1 << 44` ได้ `creating new Memory: setting up memory-mapped region: invalid argument` (เคอร์เนลบังคับให้ `mmap` ที่ address ตาม `map_extra` เท่านั้น)

**หา "ฐาน" ใน Go:** `ebpf.Memory` ให้แค่ `ReadAt`/`WriteAt` ตาม offset ไม่บอก address ของ mapping แต่ pointer ใน arena เป็น user address — เราจึงให้ BPF จอง header เป็นการจองแรก (ได้หน้า 0 = offset 0) แล้วเขียน `hdr->self = (u64)hdr` ไว้ Go อ่าน header ที่ offset 0 ได้ฐานแล้วแปลงทุก pointer เป็น `offset = ptr - base` (test ตรวจซ้ำว่าฐานนี้คือบรรทัด `anon_inode:bpf-map` ใน `/proc/self/maps` ของ process เราเอง)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `task_kfunc.c` (kfunc ที่ใช้ถูกต้อง)

- **บรรทัด 7-21:** kfunc ทั้งหมดที่ใช้มี prototype อยู่ใน `vmlinux.h` แล้ว (bpftool 7.7 สร้างให้ภายใต้ `#ifndef BPF_NO_KFUNC_PROTOTYPES`) ไฟล์นี้ประกาศเพิ่มเฉพาะ `bpf_week24_no_such_kfunc` ซึ่งไม่มีจริง เพื่อสาธิต `__weak`
- **บรรทัด 23-33:** `struct task_query` คือ ctx ของโปรแกรม syscall — Go ส่ง `pid` เข้า และได้ผลลัพธ์กลับใน struct เดียวกัน (bpf2go สร้าง Go type `kfuncTaskQuery` ให้ด้วย `-type task_query`)
- **บรรทัด 40-41:** `SEC("syscall")` cilium/ebpf ตั้งโปรแกรมเป็น `BPF_PROG_TYPE_SYSCALL` + sleepable
- **บรรทัด 48-51:** `bpf_ksym_exists()` ของ kfunc ที่มีจริง (`bpf_task_from_vpid`) ได้ 1 ของปลอมได้ 0 และการเรียกของปลอมใน `if` ถูก verifier ตัดทิ้ง
- **บรรทัด 54-58:** `bpf_task_from_pid()` (KF_ACQUIRE | KF_RET_NULL) ใช้ PID ใน **init pid namespace** (ถ้าต้องการ PID ตาม namespace ของ caller ใช้ `bpf_task_from_vpid`) และต้องเช็ก NULL
- **บรรทัด 61-64:** อ่าน field ของ trusted pointer ได้ตรง ๆ (`t->tgid`) แต่ helper เขียนลง ctx ของ syscall program ไม่ได้ (`R1 type=ctx expected=fp, ...`) จึงอ่าน `comm` ลง stack ก่อนแล้ว `memcpy`
- **บรรทัด 66-81:** คู่ acquire/release ที่สอง: `bpf_cpumask_create()` แล้ว `bpf_cpumask_copy(mask, t->cpus_ptr)` **ภายใน** `bpf_rcu_read_lock()` (เหตุผลตามหัวข้อ 1.3) พร้อมอ่าน `real_parent->tgid`
- **บรรทัด 83-89:** `bpf_cpumask_weight()` นับ CPU แล้วคืน reference ทั้งสองตัว (`bpf_cpumask_release`, `bpf_task_release`) — verifier ตรวจทุกเส้นทางของโปรแกรมว่าไม่มี reference ค้าง

### 2.2 ไฟล์ `task_kfunc_broken.c` (ตั้งใจให้ verifier ปฏิเสธ)

clang คอมไพล์ผ่านทุกโปรแกรม (กฎของ kfunc อยู่ที่ verifier ไม่ใช่ compiler):

| โปรแกรม | ความผิด | ข้อความจริงจาก verifier (Linux 7.0) |
|---|---|---|
| `leak_task` | ไม่เรียก `bpf_task_release` | `Unreleased reference id=2 alloc_insn=2` |
| `no_null_check` | ใช้ `t->tgid` ก่อนเช็ก NULL | `R0 invalid mem access 'trusted_ptr_or_null_'` |
| `use_after_release` | อ่าน `t->tgid` หลัง release | `R7 invalid mem access 'scalar'` |
| `wrong_prog_type` | เรียก kfunc ใน `SEC("socket")` | `calling kernel function bpf_task_from_pid is not allowed` |

สังเกต `alloc_insn=2` ชี้กลับไปที่คำสั่งที่ 2 (`call bpf_task_from_pid`) ใน log ช่วยให้หาว่า reference ไหนรั่ว และ `use_after_release` แสดงว่าหลัง `KF_RELEASE` ชนิดของ register เปลี่ยนจาก `trusted_ptr_task_struct` เป็น `scalar` ทันที

### 2.3 ไฟล์ `arena_list.c`

- **บรรทัด 12-15:** `#error` ถ้า clang ไม่รองรับ `__BPF_FEATURE_ADDR_SPACE_CAST` แล้วนิยาม `__arena`
- **บรรทัด 26-30:** arena 16 หน้า (64 KiB) `max_entries` เป็นหน่วยหน้า
- **บรรทัด 33-48:** `struct arena_node` (ชื่อ `node` เฉย ๆ ชนกับ type ใน `vmlinux.h`) มี `next` เป็น pointer จริงใน arena; `struct arena_hdr` อยู่ offset 0 เก็บ `self`, `head` และสถิติ
- **บรรทัด 67-69:** ตัวแปร global `hdr`, `cur_page` อยู่ใน `.bss` ธรรมดา แต่ "ชี้เข้า" arena (pointer ใน as(1) ที่เก็บนอก arena)
- **บรรทัด 72-90 (`bump_alloc`):** ขอหน้าใหม่ทีละหน้าด้วย `bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0)` (addr hint = NULL ให้เคอร์เนลเลือกหน้าว่างแรก) แล้วตัดแบ่งทีละ `size` ไบต์ ไม่มี free
- **บรรทัด 98-111:** การเรียกครั้งแรกสร้าง header และเก็บ `h->self = (__u64)h` — ค่านี้คือ address ใน process ของ Go
- **บรรทัด 114-127:** เดิน list ด้วย `n = n->next` เหมือน C ปกติ clang แทรก `addr_space_cast` ก่อนทุก dereference (ดู disassembly ในหัวข้อ 4.5) ลูปมีเพดาน `MAX_WALK` ให้ verifier พิสูจน์ว่าจบ ถ้า list ยาวเกินคืน `-E2BIG`
- **บรรทัด 129-141:** จอง node ใหม่และ push-front
- **บรรทัด 148-170 (`arena_peek`):** อ่าน-เขียน-อ่าน ที่ offset ที่ Go ระบุ เพื่อสาธิต page fault ข้อสังเกตสองจุดที่เจอระหว่างพัฒนา:
  - `asm volatile("" : : "r"(&arena))` — โปรแกรมนี้ไม่ได้เรียก kfunc ที่รับ `&arena` จึงไม่ได้ "ผูก" กับ arena ไม่งั้นได้ `addr_space_cast insn can only be used in a program that has an associated arena`
  - `volatile` — เวอร์ชันแรกไม่มี clang ยุบ `*p = 0xC0FFEE; after = *p;` เป็นค่าคงที่ ทำให้ดูเหมือน store ไปหน้าที่ไม่ได้จองสำเร็จ (ผลผิด `after=0xc0ffee`)

### 2.4 ไฟล์ `main.go`

- **`//go:generate` 3 บรรทัด:** สร้าง binding 3 ชุด `kfunc`, `broken`, `arena` (`-type upsert_args -type peek_args` ให้ได้ Go struct ตรง layout) — bpf2go **ไม่สร้าง type ที่มี pointer field** (`field 2: type *btf.Pointer: not supported`) จึงเขียน `arenaHdr`/`arenaNode` เอง โดย pointer = `uint64`
- **`queryTask()`:** `prog.Run(&ebpf.RunOptions{Context: &q, ContextOut: &q})` = `BPF_PROG_TEST_RUN` ของโปรแกรม syscall
- **`loadBrokenProgram()` / `verifierTail()`:** โหลดโปรแกรมพังทีละตัวด้วย `ebpf.NewProgram` แล้วดึงท้าย `VerifierError.Log`
- **`newArenaLab()`:** ลำดับ NewMap → `Memory()` → `LoadAndAssign` + `MapReplacements` (หัวข้อ 1.8) หมายเหตุ: cilium/ebpf **Clone** map ที่ส่งไปใน `MapReplacements` (dup fd) เราจึงเก็บ `m` ตัวเดิมที่ `mmap` แล้วไว้ใช้/ปิดเอง
- **`readAt()`:** `binary.Read(io.NewSectionReader(mem, off, size), binary.NativeEndian, v)` — เป็นการ copy จาก mapping ล้วน ๆ **ไม่มี syscall ไม่มี map lookup**
- **`walk()`:** เริ่มจาก `h.Head` แล้ว `p = n.Next` ไปเรื่อย ๆ แปลงเป็น offset ด้วย `p - h.Self` มีเพดาน `NrNodes` กัน list วน
- **`main()` ส่วน page fault:** BPF peek หน้า 0 (จองแล้ว, offset `0xff8` ซึ่งเป็น 8 ไบต์ท้ายหน้าที่ไม่มี node ใช้) → BPF peek หน้า 8 (ยังไม่จอง) → Go อ่านหน้า 8 → BPF peek หน้า 8 อีกครั้ง

### 2.5 `Makefile`, `go.mod` และ patch ของ cilium/ebpf v0.22.0

ตอนโหลดโปรแกรม arena ครั้งแรกด้วย cilium/ebpf v0.22.0 (รุ่นล่าสุด ณ เวลาที่เขียน) verifier ตอบว่า:
```
load program: invalid argument: BPF_MOV uses reserved fields
...
34: (bf) r1 = r1
```
ทั้งที่ `llvm-objdump` แสดง `r1 = addr_space_cast(r1, 0x0, 0x1)` สาเหตุ: `asm.Instruction.Marshal` ใน v0.22.0 เขียน `ins.Offset = 0` ให้ **ทุก** คำสั่ง ALU ที่ไม่ใช่ SDiv/SMod/MovSX ทำให้ field `off=1` ของ `addr_space_cast` หาย upstream แก้แล้วใน commit [`cc4947e`](https://github.com/cilium/ebpf/commit/cc4947e88a916cf69b368982cfd524451f50eccd) ("asm: conditionally set ins.Offset when marshaling Movs") แต่ยังไม่อยู่ใน release ใด

แล็บนี้ยังคง `require github.com/cilium/ebpf v0.22.0` แล้ว:
1. `go.mod` มี `tool github.com/cilium/ebpf/cmd/bpf2go` (Go 1.24+) เพื่อให้ `go mod vendor` vendor bpf2go ด้วย และ `go generate` ใช้ได้ทั้งตอนมี/ไม่มี `vendor/`
2. target `$(VENDOR_STAMP)` รัน `go mod vendor` แล้ว `patch -p1` ด้วย `patches/cilium-ebpf-v0.22.0-addr-space-cast.patch` (เฉพาะ hunk ของ commit ข้างบน) `go build`/`go test` จะใช้ `vendor/` อัตโนมัติ
3. ไม่แตะ module cache (Go ห้าม `-overlay` ไฟล์ใน `GOMODCACHE` อยู่แล้ว: `Files beneath GOMODCACHE ... must not be replaced`) และ `vendor/` อยู่ใน `.gitignore`

เมื่อ cilium/ebpf ออก release ที่มี fix ให้ bump `go.mod` แล้วลบ `patches/` + target vendor ทิ้ง ส่วน kfunc (Part 1) ไม่ได้รับผลกระทบจากบั๊กนี้

### 2.6 ไฟล์ `main_test.go`

| Test | ตรวจอะไร |
|---|---|
| `TestQueryTaskSelf` | PID ของ test เอง: tgid/ppid ตรง `os.Getpid()/Getppid()`, comm ตรง `/proc/self/comm`, `bpf_ksym_exists` = 1/0 |
| `TestQueryTaskThreadAffinity` | ส่ง **TID** ของ thread ที่ถูก `sched_setaffinity` ให้เหลือ CPU 0 → `nr_cpus_allowed == 1`; main thread ต้องเท่ากับ `sched_getaffinity` |
| `TestQueryTaskMissing` | PID ที่ไม่มีจริง → `found == 0` (ทางเส้น NULL) |
| `TestBrokenProgramsRejected` | ทั้ง 4 โปรแกรมต้องถูกปฏิเสธด้วยข้อความตามตาราง 2.2 |
| `TestArenaUpsertAndWalk` | 1000 upsert / 8 key → count/sum ทุก node ถูก และ pointer ที่ BPF คืน = pointer ที่ Go เดินเจอ |
| `TestArenaPointersAreUserAddresses` | `hdr.self` คือจุดเริ่มของ mapping `anon_inode:bpf-map` ใน `/proc/self/maps` |
| `TestArenaPageFaults` | หน้าที่จองแล้ว BPF เขียน Go เห็น; หน้าที่ไม่จอง load=0/store หาย; หลัง Go แตะหน้า BPF เขียนได้ |
| `TestArenaUserFaultConsumesPage` | ถ้า Go แตะหน้า 1 ก่อน node ที่ 127 จะไปอยู่หน้า 2 แทนหน้า 1 |
| `TestArenaWalkLimit` | list โตเกิน `MAX_WALK` → `E2BIG` ที่ 513 node |
| `TestArenaRequiresMmapBeforeLoad` | `loadArenaObjects()` ตรง ๆ ต้องล้มด้วยข้อความ `arena's user address must be set ...` |
| `TestArenaCreateLimits` | 2^20 หน้าสร้างได้, 2^20+1 หน้า → `argument list too long` (E2BIG), ไม่มี `BPF_F_MMAPABLE` → `invalid argument` |

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจความพร้อมของเครื่อง
```bash
uname -r                                          # ต้อง >= 6.9 สำหรับ arena (แล็บนี้ทดสอบบน 7.0)
clang --version | head -1                          # ต้อง >= 19 สำหรับ addr_space_cast
bpftool btf dump file /sys/kernel/btf/vmlinux | grep -c "DECL_TAG 'bpf_kfunc'"
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -E '__ksym;$' | grep -E 'bpf_(task_from_pid|task_release|arena_alloc_pages)\('
cat /proc/sys/net/core/bpf_jit_enable             # arena ต้องใช้ JIT (ค่า 1)
```

### ขั้นตอนที่ 2: คอมไพล์และรันเทสต์
```bash
cd phase11-modern-ebpf-extensibility/week24-kfuncs-arena
make all           # generate + vendor/patch + build
make test          # = go test -exec sudo -v ./...
# หรือจาก root ของ repo:  make week24 && make week24-test
```

### ขั้นตอนที่ 3: รันโปรแกรม
```bash
sudo ./bin/kfunc-arena                      # PID 1 + ตัวเอง, 1000 upsert / 8 key
sudo ./bin/kfunc-arena -pid $$ -n 5000 -keys 300
```

### ขั้นตอนที่ 4: ดู verifier log เต็มของโปรแกรมที่พัง
```bash
go test -exec sudo -run 'TestBrokenProgramsRejected/leak_task' -v .   # ผ่าน = ถูกปฏิเสธจริง
```
หรือแก้ `verifierTail(err, 2)` ใน `main.go` เป็นค่าที่มากขึ้น แล้ว `make run`

### ขั้นตอนที่ 5: ดู `addr_space_cast` ที่ clang แทรกให้
```bash
llvm-objdump -S --no-show-raw-insn arena_bpfel.o | grep -B2 -A2 addr_space_cast | head -30
```

### ขั้นตอนที่ 6 (ทางเลือก): พิสูจน์บั๊กของ cilium/ebpf v0.22.0 ด้วยตัวเอง
```bash
go build -mod=mod -o /tmp/unpatched . && sudo /tmp/unpatched   # -mod=mod = ไม่ใช้ vendor/ ที่ patch แล้ว
```
Part 1 ต้องผ่านปกติ ส่วน Part 2 ต้องล้มด้วย `BPF_MOV uses reserved fields`

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`), Intel Core i3-12100 (8 CPUs), clang 21.1.8, Go 1.26, bpftool v7.7.0 (libbpf v1.7), cilium/ebpf v0.22.0 + patch ในหัวข้อ 2.5

### 4.1 `make test`
```text
=== RUN   TestQueryTaskSelf
    main_test.go:80: pid 80738: tgid=80738 ppid=80736 comm="week24-kfuncs-a" cpus=8
--- PASS: TestQueryTaskSelf (0.03s)
=== RUN   TestQueryTaskThreadAffinity
--- PASS: TestQueryTaskThreadAffinity (0.03s)
=== RUN   TestQueryTaskMissing
--- PASS: TestQueryTaskMissing (0.03s)
=== RUN   TestBrokenProgramsRejected
=== RUN   TestBrokenProgramsRejected/leak_task
=== RUN   TestBrokenProgramsRejected/no_null_check
=== RUN   TestBrokenProgramsRejected/use_after_release
=== RUN   TestBrokenProgramsRejected/wrong_prog_type
--- PASS: TestBrokenProgramsRejected (0.09s)
    --- PASS: TestBrokenProgramsRejected/leak_task (0.03s)
    --- PASS: TestBrokenProgramsRejected/no_null_check (0.03s)
    --- PASS: TestBrokenProgramsRejected/use_after_release (0.03s)
    --- PASS: TestBrokenProgramsRejected/wrong_prog_type (0.02s)
=== RUN   TestArenaUpsertAndWalk
--- PASS: TestArenaUpsertAndWalk (0.02s)
=== RUN   TestArenaPointersAreUserAddresses
    main_test.go:222: 756b5c018000-756b5c028000 rw-s 00000000 00:11 1062                       anon_inode:bpf-map
--- PASS: TestArenaPointersAreUserAddresses (0.02s)
=== RUN   TestArenaPageFaults
--- PASS: TestArenaPageFaults (0.02s)
=== RUN   TestArenaUserFaultConsumesPage
=== RUN   TestArenaUserFaultConsumesPage/no_user_fault
=== RUN   TestArenaUserFaultConsumesPage/go_touched_page_1
--- PASS: TestArenaUserFaultConsumesPage (0.04s)
    --- PASS: TestArenaUserFaultConsumesPage/no_user_fault (0.02s)
    --- PASS: TestArenaUserFaultConsumesPage/go_touched_page_1 (0.02s)
=== RUN   TestArenaWalkLimit
--- PASS: TestArenaWalkLimit (0.02s)
=== RUN   TestArenaRequiresMmapBeforeLoad
--- PASS: TestArenaRequiresMmapBeforeLoad (0.00s)
=== RUN   TestArenaCreateLimits
=== RUN   TestArenaCreateLimits/4GiB_(1<<20_pages)_ok
=== RUN   TestArenaCreateLimits/4GiB_+_1_page
    main_test.go:349: creating map: map create: argument list too long
=== RUN   TestArenaCreateLimits/without_BPF_F_MMAPABLE
    main_test.go:349: creating map: map create: invalid argument
--- PASS: TestArenaCreateLimits (0.00s)
    --- PASS: TestArenaCreateLimits/4GiB_(1<<20_pages)_ok (0.00s)
    --- PASS: TestArenaCreateLimits/4GiB_+_1_page (0.00s)
    --- PASS: TestArenaCreateLimits/without_BPF_F_MMAPABLE (0.00s)
PASS
ok  	ebpf-noob-to-hero/phase11-modern-ebpf-extensibility/week24-kfuncs-arena	0.301s
```
(comm ของ test binary ถูกตัดเหลือ 15 ตัวอักษร `week24-kfuncs-a` เพราะ `TASK_COMM_LEN` = 16 รวม NUL)

### 4.2 `sudo ./bin/kfunc-arena`
```text
======================================================================
 Week 24 Part 1: kfuncs (bpf_task_from_pid / bpf_task_release / bpf_cpumask_*)
======================================================================
PID      FOUND  TGID     PPID     CPUS   COMM            
80458    yes    80458    80453    8      kfunc-arena     
1        yes    1        0        8      systemd         
1073741823 no     (bpf_task_from_pid คืน NULL)
bpf_ksym_exists(bpf_task_from_vpid)       = 1
bpf_ksym_exists(bpf_week24_no_such_kfunc) = 0

--- Verifier vs. broken kfunc usage (task_kfunc_broken.c) ---
[leak_task] rejected:
    Unreleased reference id=2 alloc_insn=2
    BPF_EXIT instruction in main prog would lead to reference leak
[no_null_check] rejected:
    3: (61) r1 = *(u32 *)(r0 +2804)
    R0 invalid mem access 'trusted_ptr_or_null_'
[use_after_release] rejected:
    7: (61) r1 = *(u32 *)(r7 +2804)
    R7 invalid mem access 'scalar'
[wrong_prog_type] rejected:
    1: (85) call bpf_task_from_pid#99570
    calling kernel function bpf_task_from_pid is not allowed

======================================================================
 Week 24 Part 2: BPF Arena (BPF_MAP_TYPE_ARENA + mmap ใน Go)
======================================================================
arena: max 16 pages, mmap 65536 bytes (ReadOnly=false)
header @ offset 0: base(self)=0x7a23c2b3e000 nr_nodes=8 pages=1 bytes_used=304
/proc/self/maps : 7a23c2b3e000-7a23c2b4e000 rw-s 00000000 00:11 1062                       anon_inode:bpf-map
1000 upserts with 8 keys -> Go walked 8 nodes by following arena pointers:
  KEY  COUNT   SUM       NODE PTR         OFFSET  CHECK
  0    125     62000     0x7a23c2b3e030   0x30    ok
  1    125     62125     0x7a23c2b3e050   0x50    ok
  2    125     62250     0x7a23c2b3e070   0x70    ok
  3    125     62375     0x7a23c2b3e090   0x90    ok
  4    125     62500     0x7a23c2b3e0b0   0xb0    ok
  5    125     62625     0x7a23c2b3e0d0   0xd0    ok
  6    125     62750     0x7a23c2b3e0f0   0xf0    ok
  7    125     62875     0x7a23c2b3e110   0x110   ok

--- Page faults: BPF access ไปยังหน้าที่ยังไม่ได้จอง ---
BPF  peek off=0xff8  (allocated page)   before=0x0 after=0xc0ffee | Go reads 0xc0ffee
BPF  peek off=0x8000 (unallocated page) before=0x0 after=0x0 (store dropped)
Go   read off=0x8000 -> 0x0 (user-space fault ทำให้เคอร์เนลจองหน้านี้ให้)
BPF  peek off=0x8000 again              before=0x0 after=0xc0ffee (หน้าถูกจองแล้ว)
```

**การตีความ:**
- `NODE PTR` (เช่น `0x7a23c2b3e030`) เป็นค่าที่ **โปรแกรม BPF เขียน** ลง `next`/`head` แต่เป็น address ในช่วง mapping ของ process Go เอง (`7a23c2b3e000-7a23c2b4e000` = 64 KiB = 16 หน้า) Go จึงลบฐานแล้วอ่านได้เลย
- header 48 ไบต์ (`0x30`) + 8 node × 32 ไบต์ = `bytes_used=304` ใช้หน้าเดียว node แรก (key 0) อยู่ offset `0x30` ต่อจาก header พอดี
- ทุก node ผ่านการตรวจกับค่าที่ Go คำนวณเอง (count = 125, sum = ผลรวมของ i ที่ `i % 8 == key`)
- PPID 0 ของ systemd คือพฤติกรรมปกติ (`real_parent` ของ init ชี้ไปที่ idle task ซึ่งมี tgid 0)
- ตำแหน่ง address และ PID เปลี่ยนทุกครั้งที่รัน (ASLR)

รันเพิ่มด้วย `-n 5000 -keys 300` สองรอบ (ตัดเฉพาะบรรทัดสรุป): ได้ `nr_nodes=300 pages=3 bytes_used=9648` และ Go เดินครบ 300 node ทั้งสองรอบ ไม่มี `MISMATCH`

### 4.3 Verifier log เต็มของ `leak_task`
```text
load program: invalid argument:
	0: R1=ctx() R10=fp0
	; int leak_task(struct task_query *q) @ task_kfunc_broken.c:19
	0: (bf) r6 = r1                       ; R1=ctx() R6=ctx()
	; struct task_struct *t = bpf_task_from_pid(q->pid); @ task_kfunc_broken.c:21
	1: (61) r1 = *(u32 *)(r6 +0)          ; R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6=ctx()
	2: (85) call bpf_task_from_pid#99570          ; R0=trusted_ptr_or_null_task_struct(id=2,ref_obj_id=2) refs=2
	; if (!t) @ task_kfunc_broken.c:23
	3: (15) if r0 == 0x0 goto pc+2        ; R0=trusted_ptr_task_struct(ref_obj_id=2) refs=2
	; q->tgid = t->tgid; @ task_kfunc_broken.c:25
	4: (61) r1 = *(u32 *)(r0 +2804)       ; R0=trusted_ptr_task_struct(ref_obj_id=2) R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) refs=2
	5: (63) *(u32 *)(r6 +4) = r1          ; R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6=ctx() refs=2
	; } @ task_kfunc_broken.c:27
	6: (b7) r0 = 0                        ; R0=0 refs=2
	7: (95) exit
	Unreleased reference id=2 alloc_insn=2
	BPF_EXIT instruction in main prog would lead to reference leak
	processed 8 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
อ่าน log ได้ดังนี้: หลัง `call bpf_task_from_pid#99570` (99570 คือ BTF ID เดียวกับในหัวข้อ 4.4) R0 มีชนิด `trusted_ptr_or_null_task_struct` และสถานะ `refs=2`; หลัง `if r0 == 0` ในเส้นทางที่ไม่ใช่ NULL ชนิดกลายเป็น `trusted_ptr_task_struct`; ที่ `exit` ยังมี `refs=2` ค้าง จึงถูกปฏิเสธ (เส้นทาง NULL ไม่มีปัญหาเพราะ reference ถูกยกเลิกไปแล้ว)

### 4.4 ค้นหา kfunc บนเครื่องทดสอบ
```text
$ bpftool btf dump file /sys/kernel/btf/vmlinux | grep -c "DECL_TAG 'bpf_kfunc'"
272
$ bpftool btf dump file /sys/kernel/btf/vmlinux | grep -E "FUNC 'bpf_task_from_pid'|type_id=99570 "
[98316] DECL_TAG 'bpf_kfunc' type_id=99570 component_idx=-1
[99570] FUNC 'bpf_task_from_pid' type_id=59304 linkage=static
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -E '^extern .*\bbpf_(task_from_pid|task_release|task_acquire|cpumask_create|cpumask_copy|arena_alloc_pages)\('
extern void __attribute__((address_space(1))) *bpf_arena_alloc_pages(void *p__map, void __attribute__((address_space(1))) *addr__ign, u32 page_cnt, int node_id, u64 flags) __weak __ksym;
extern void bpf_cpumask_copy(struct bpf_cpumask *dst, const struct cpumask *src) __weak __ksym;
extern struct bpf_cpumask *bpf_cpumask_create(void) __weak __ksym;
extern struct task_struct *bpf_task_acquire(struct task_struct *p) __weak __ksym;
extern struct task_struct *bpf_task_from_pid(s32 pid) __weak __ksym;
extern void bpf_task_release(struct task_struct *p) __weak __ksym;
$ for m in /sys/kernel/btf/*; do ...; done        # kfunc ที่มาจาก module
nf_conntrack 10
nf_nat 1
vmlinux 272
```
(ใน 272 ตัวนี้มี `scx_*` ของ sched_ext 51 ตัว — ใช้ใน Week 25) สังเกตว่าชื่อพารามิเตอร์มี suffix อย่าง `p__map`, `addr__ign`: เป็นข้อตกลงของ kfunc ที่บอก verifier ว่าอาร์กิวเมนต์นั้นเป็น map pointer หรือให้ข้ามการตรวจชนิด

### 4.5 `addr_space_cast` ใน object ที่คอมไพล์แล้ว (`llvm-objdump -S --no-show-raw-insn arena_bpfel.o`, ตัดมาบางส่วน)
```text
      28:	if r0 == 0x0 goto +0x64 <arena_upsert+0x408>
      29:	r1 = addr_space_cast(r0, 0x0, 0x1)
; 		if (hdr)
      30:	r2 = 0x0 ll
      32:	r2 = *(u64 *)(r2 + 0x0)
      33:	if r2 == 0x0 goto +0x7 <arena_upsert+0x148>
      34:	r2 = addr_space_cast(r2, 0x0, 0x1)
; 			hdr->pages++;
      35:	r3 = *(u64 *)(r2 + 0x20)
      36:	r3 += 0x1
```
ทั้งไฟล์มี `addr_space_cast` 12 คำสั่ง — ทุกครั้งก่อน dereference pointer ของ arena ตามหัวข้อ 1.7

---

## 5. ข้อจำกัด (Limitations)

1. **kfunc ไม่มี stable ABI:** โปรแกรมนี้อาจโหลดไม่ผ่านบนเคอร์เนลรุ่นอื่นถ้าชื่อ/signature/flag ของ kfunc เปลี่ยน `__weak` + `bpf_ksym_exists()` ช่วยได้เฉพาะกรณี "ไม่มี kfunc" ไม่ช่วยกรณี signature เปลี่ยน
2. **บั๊กของ toolchain:** arena ใน Go ตอนนี้ต้องพึ่ง patch ใน `vendor/` (หัวข้อ 2.5) ถ้ารัน `go run .` / `go test` บนเครื่องที่ยังไม่ได้ `make` จะใช้ cilium/ebpf v0.22.0 ตัวเดิมและ Part 2 ล้ม
3. **ไม่มี concurrency control:** `arena_upsert` ไม่ใช้ lock/atomic ถ้าหลาย CPU เรียกพร้อมกัน (เช่นเปลี่ยนไป attach กับ tracepoint) จะเกิด lost update และ node ซ้ำ ในแล็บ Go เรียกทีละครั้งผ่าน `BPF_PROG_TEST_RUN` จึงไม่เจอ (`bpf_spin_lock` ใช้ในหน่วยความจำ arena ไม่ได้ ต้องใช้ atomic หรือ lock ที่สร้างบน atomic เอง)
4. **Allocator ง่ายที่สุด:** bump allocator ไม่มี free, ทิ้งเศษท้ายหน้า และ lookup แบบ O(n) ผ่าน linked list ที่จำกัด 513 node (`MAX_WALK` + 1)
5. **สมมติหน้า 4 KiB และ header อยู่หน้า 0:** `ARENA_PAGE_SIZE` hard-code เป็น 4096 และการหาฐานพึ่งว่าการจองครั้งแรกของ arena ว่าง ๆ ได้หน้า 0 (ตรวจด้วย magic; ถ้า Go แตะหน้า 0 ก่อน BPF ข้อสมมตินี้จะผิด)
6. **Arena:** ต้องการเคอร์เนล 6.9+ และ JIT ที่รองรับ arena (x86-64 ตั้งแต่ 6.9; arm64 และสถาปัตยกรรมอื่นตามมาในรุ่นหลัง — ตรวจสอบกับเคอร์เนลที่ใช้) ขนาดสูงสุด 4 GiB ต่อ arena (`2^20+1` หน้า → `E2BIG`)
7. **`ebpf.Memory.Size()` คืน `uint32`:** arena ขนาดเต็ม 4 GiB (2^20 หน้า) `mmap` ได้แต่ `Size()` รายงาน `0` (วัดจริงระหว่างพัฒนา) โค้ดที่ตรวจ bounds ด้วย `Size()` จะผิดในกรณีนี้
8. **6.8 (Ubuntu 24.04):** ไม่มี arena และ kfunc บางตัว (Part 1 น่าจะโหลดได้แต่ยังไม่ได้ทดสอบบน 6.8) และ bpftool รุ่นเก่าอาจไม่สร้าง prototype kfunc ใน `vmlinux.h` ต้องประกาศ `extern ... __ksym;` เอง
9. ต้องใช้ root (`CAP_BPF` + `CAP_PERFMON`/`CAP_SYS_ADMIN`) ทั้งการโหลดและ `BPF_PROG_TEST_RUN`

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

ข้อความทั้งหมดในตารางนี้เจอจริงระหว่างพัฒนาแล็บบน Linux 7.0

| อาการ | สาเหตุ / วิธีแก้ |
|---|---|
| `load program: invalid argument: BPF_MOV uses reserved fields` และใน log เห็น `(bf) r1 = r1` | cilium/ebpf v0.22.0 ทำ `addr_space_cast` เสีย — build ผ่าน `make` (patch `vendor/`) หรือใช้ release ที่มี commit `cc4947e` |
| `arena's user address must be set via map_extra or mmap()` | โหลดโปรแกรมก่อน `mmap` arena — ใช้ลำดับ NewMap → `Memory()` → `LoadAndAssign` + `MapReplacements` |
| `addr_space_cast insn can only be used in a program that has an associated arena` | โปรแกรมนั้นไม่ได้อ้างถึง arena map เลย — อ้าง `&arena` (เช่น `asm volatile("" : : "r"(&arena))`) หรือเรียก kfunc ที่รับ `&arena` |
| `Unreleased reference id=N alloc_insn=M` | ลืม `*_release()` ในบางเส้นทาง ดูคำสั่งที่ `M` ใน log ว่า acquire จากไหน |
| `R0 invalid mem access 'trusted_ptr_or_null_'` | kfunc เป็น `KF_RET_NULL` ต้อง `if (!t) return 0;` ก่อนใช้ |
| `R7 invalid mem access 'scalar'` หลัง release | ใช้ pointer หลัง `KF_RELEASE` — ย้ายการอ่าน field ไปก่อน release |
| `calling kernel function bpf_task_from_pid is not allowed` | kfunc ไม่ได้ลงทะเบียนให้ program type นี้ — เปลี่ยน `SEC()` (เช่น `syscall`, `tp_btf/...`, `fentry/...`) |
| `call bpf_cpumask_copy#...: R2 must be a rcu pointer` | ส่ง pointer ที่เดินจาก trusted pointer ในโปรแกรม sleepable นอก RCU — ครอบด้วย `bpf_rcu_read_lock()/unlock()` |
| `call bpf_probe_read_kernel_str#115: R1 type=ctx expected=fp, pkt, ...` | helper เขียนลง ctx ของ `SEC("syscall")` ตรง ๆ ไม่ได้ — อ่านลง buffer บน stack แล้ว copy |
| `error: redefinition of 'node'` ตอน `make generate` | ชื่อ struct ชนกับ type ใน `vmlinux.h` — ตั้งชื่อเฉพาะ เช่น `arena_node` |
| `generating arenaArenaHdr: ... type *btf.Pointer: not supported` | bpf2go `-type` ไม่รองรับ struct ที่มี pointer — เขียน Go struct เองโดยใช้ `uint64` แทน pointer |
| BPF เขียนหน้าที่ไม่ได้จองแล้ว "อ่านกลับได้ค่าที่เขียน" | clang ทำ store-to-load forwarding — ใช้ `volatile` เมื่อทดลองพฤติกรรมของหน่วยความจำ |
| `creating new Memory: setting up memory-mapped region: invalid argument` | arena สร้างด้วย `map_extra` แต่ `Map.Memory()` ของ cilium/ebpf `mmap` ที่ address = NULL — เอา `map_extra` ออก (ให้ `mmap` ครั้งแรกกำหนด address) |
| Go ตายด้วย `unexpected fault address ...` / `fatal error: fault` | arena มี `BPF_F_SEGV_ON_FAULT` แล้ว Go อ่าน/เขียนหน้าที่ยังไม่ได้จอง — ให้ BPF จองก่อน หรือเอา flag ออก |
| คำเตือน `vmlinux.h:...: warning: declaration does not declare anything` | มาจาก `vmlinux.h` ของ 7.0 กับ clang 21 ไม่กระทบผลลัพธ์ |

---

## 7. Milestone Checklist

- [x] อธิบายความต่างของ helper กับ kfunc (BTF ID, ไม่มี stable ABI, ลงทะเบียนต่อ program type)
- [x] ค้นหา kfunc บนเครื่องจริงด้วย BTF decl tag `bpf_kfunc` และอ่าน prototype จาก `vmlinux.h`
- [x] ใช้คู่ `KF_ACQUIRE`/`KF_RELEASE` (`bpf_task_from_pid`/`bpf_task_release`, `bpf_cpumask_create`/`bpf_cpumask_release`) ถูกต้องทุกเส้นทาง
- [x] ใช้ `__weak` + `bpf_ksym_exists()` ทำ kfunc แบบ optional
- [x] อ่าน verifier log ของ reference leak, NULL, use-after-release และ program type ผิดได้
- [x] สร้าง `BPF_MAP_TYPE_ARENA`, `mmap` ใน Go ด้วย `Map.Memory()` ก่อนโหลดโปรแกรม
- [x] สร้าง linked list ด้วย `bpf_arena_alloc_pages` ใน BPF แล้วเดินตาม pointer เดียวกันใน Go โดยไม่มี map lookup
- [x] อธิบาย address space 1, `addr_space_cast` และพฤติกรรม page fault ของทั้งสองฝั่ง
- [x] วินิจฉัยบั๊กของ toolchain (cilium/ebpf) จากหลักฐานใน verifier log + disassembly และแก้ด้วย patch ที่ทำซ้ำได้
- [x] ตรวจทุกอย่างด้วย `BPF_PROG_TEST_RUN` (`make test`)

---

## 8. แบบฝึกหัดท้ายบท (Exercises)

ทุกข้อให้เพิ่ม test ใน `main_test.go` แล้วรัน `make test` เป็นหลักฐาน

### ระดับพื้นฐาน
1. **`bpf_task_from_vpid` vs `bpf_task_from_pid`:** เพิ่มฟิลด์ `vpid_tgid` ใน `task_query` ที่ได้จาก `bpf_task_from_vpid()` (ใช้ `bpf_ksym_exists` ครอบ) แล้วรันโปรแกรมใน PID namespace ใหม่
   - **ตรวจสอบ:** `sudo unshare -fp --mount-proc ./bin/kfunc-arena` — PID ของตัวเองใน namespace ใหม่ (เช่น 1) หาเจอด้วย `bpf_task_from_vpid` แต่ `bpf_task_from_pid(1)` ต้องได้ systemd ของ host
2. **ทำให้ verifier ปฏิเสธเพิ่มอีกแบบ:** เพิ่มโปรแกรม `double_release` ใน `task_kfunc_broken.c` ที่เรียก `bpf_task_release(t)` สองครั้ง
   - **ตรวจสอบ:** เพิ่ม entry ใน map `want` ของ `TestBrokenProgramsRejected` ด้วยข้อความจริงที่ได้ (ห้ามเดา — คัดจาก log)

### ระดับปานกลาง
1. **นับ CPU ที่ task ทุกตัวใช้ร่วมกัน:** ใช้ `bpf_cpumask_and()` สะสม intersection ของ `cpus_ptr` ของ PID หลายตัว (Go ส่ง array ของ PID ใน ctx) แล้วคืน weight
   - **ตรวจสอบ:** สร้าง 2 thread ใน test ที่ affinity `{0,1}` และ `{1,2}` แล้วผลต้องเป็น 1
2. **Arena hash table:** เปลี่ยน linked list เดียวเป็น array ของ bucket head 64 ช่องใน header (`head[key % 64]`) เพื่อให้ lookup สั้นลงและรองรับ key มากกว่า 513
   - **ตรวจสอบ:** 2,000 key ที่ไม่ซ้ำกันต้องไม่ได้ `E2BIG` และ Go เดินทุก bucket แล้วได้ 2,000 node ที่ count/sum ถูกต้อง (ระวังขีด 16 หน้า: 2,000 × 32 B ≈ 16 หน้าพอดี ต้องเพิ่ม `ARENA_PAGES`)

### ระดับท้าทาย
1. **Arena + tracepoint จริง ไม่ใช่ test_run:** เพิ่มโปรแกรม `tp_btf/sched_process_exec` (หรือ `fentry`) ที่ upsert node ต่อ `comm` ลง arena เดียวกัน ทำให้ปลอดภัยเมื่อหลาย CPU ทำงานพร้อมกันด้วย `__sync_fetch_and_add` สำหรับ counter และ CAS (`__sync_val_compare_and_swap`) สำหรับ push-front
   - **ตรวจสอบ:** ใน test สั่ง `exec` `/bin/true` 200 ครั้งจากหลาย goroutine แล้ว count ของ `true` ใน arena ต้อง ≥ 200 และ `nr_nodes` ต้องเท่ากับจำนวน comm ที่ไม่ซ้ำ (ไม่มี node ซ้ำ)
2. **Free-list allocator:** เพิ่มโปรแกรม `arena_delete(key)` ที่ถอด node ออกจาก list แล้วใส่ free list ใน header ให้ `bump_alloc` ใช้ซ้ำก่อนขอหน้าใหม่ และเมื่อหน้าว่างทั้งหน้าให้คืนด้วย `bpf_arena_free_pages`
   - **ตรวจสอบ:** insert 1,000 → delete ทั้งหมด → insert 1,000 ใหม่ แล้ว `hdr->pages` ต้องไม่เพิ่มจากรอบแรก; หลัง free หน้าแล้ว BPF peek หน้านั้นต้องได้ `after=0` (store ถูกทิ้ง) อีกครั้ง
