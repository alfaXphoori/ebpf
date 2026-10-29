//go:build ignore
// +build ignore

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Week 25: struct_ops + sched_ext - CPU scheduler ขนาดเล็กที่เขียนด้วย BPF
 *
 * โครงสร้างคล้าย scx_simple ของ upstream (tools/sched_ext/scx_simple.bpf.c) แต่ตัดให้เหลือสั้นที่สุด:
 *   - โหมด FIFO  : ทุก task ต่อคิวเดียวกัน (SHARED_DSQ) ตามลำดับที่มาถึง
 *   - โหมด vtime : คิวเดียวกันแต่เรียงตาม virtual time (ใครใช้ CPU น้อย/weight สูงได้ไปก่อน)
 *   - fail_mode  : จงใจทำให้พัง เพื่อสาธิต safety net ของ sched_ext (watchdog / scx_bpf_error)
 *
 * SAFETY: .flags = SCX_OPS_SWITCH_PARTIAL -> scheduler นี้คุมเฉพาะ task ที่ตั้ง policy เป็น
 * SCHED_EXT (7) เองเท่านั้น task อื่นทั้งเครื่องยังอยู่กับ EEVDF/CFS ตามปกติ
 */
#include "vmlinux.h"
#include "scx_mini.h"

char _license[] SEC("license") = "GPL"; /* sched_ext kfuncs ต้องการ GPL */

/* DSQ id ที่เราสร้างเอง (ต้องไม่ชนกับ built-in: SCX_DSQ_GLOBAL/SCX_DSQ_LOCAL ใช้บิต 63) */
#define SHARED_DSQ 0

/* fail_mode: 0 = ปกติ, 1 = stall (dispatch ไม่ดึงงาน -> watchdog), 2 = เรียก scx_bpf_error() ใน ops.running */
#define FAIL_NONE  0
#define FAIL_STALL 1
#define FAIL_ERROR 2

/* ค่าคงที่ตอนโหลด (อยู่ใน .rodata) ฝั่ง Go ตั้งค่าผ่าน CollectionSpec.Variables ก่อน load */
const volatile bool vtime_mode = false;
const volatile u32 fail_mode = FAIL_NONE;

/* ตัวนับสถิติ: PERCPU_ARRAY -> แต่ละ CPU มีช่องของตัวเอง ไม่ต้องใช้ atomic */
enum stat_idx {
	STAT_LOCAL,    /* select_cpu เจอ CPU ว่าง -> insert ตรงเข้า local DSQ (ข้าม enqueue) */
	STAT_ENQ,      /* ops.enqueue ถูกเรียก -> ใส่ SHARED_DSQ */
	STAT_DISPATCH, /* ops.dispatch ย้ายงานจาก SHARED_DSQ มา local DSQ ของ CPU นี้สำเร็จ */
	STAT_RUNNING,  /* ops.running: task ของเราได้ขึ้น CPU นี้จริง */
	W25_NR_STATS,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, W25_NR_STATS);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

static __always_inline void stat_inc(u32 idx)
{
	u64 *cnt = bpf_map_lookup_elem(&stats, &idx);
	if (cnt)
		(*cnt)++;
}

/* vtime ปัจจุบันของระบบ = vtime ของ task ล่าสุดที่ได้รัน (ใช้กัน task ที่หลับนานสะสมเครดิตเกิน) */
static u64 vtime_now;
/* ใช้นับรวมเพื่อสาธิต FAIL_ERROR */
static u64 nr_running_total;

/* ฝั่ง Go อ่านตัวแปรนี้เพื่อรู้ว่า scheduler จบเพราะอะไร (ดู scx_mini.h) */
struct w25_exit_info exit_info;

/*
 * ops.select_cpu: เรียกตอน task ตื่น (wakeup) เพื่อเลือก CPU
 * ใช้ตัวช่วยของเคอร์เนล scx_bpf_select_cpu_dfl() ซึ่งหา CPU ว่างให้ (idle tracking ในตัว)
 * ถ้าเจอ CPU ว่าง เราใส่ task ลง SCX_DSQ_LOCAL ทันที = "direct dispatch" -> ops.enqueue จะไม่ถูกเรียก
 */
s32 BPF_STRUCT_OPS(w25_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle && fail_mode != FAIL_STALL) {
		stat_inc(STAT_LOCAL);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}
	return cpu;
}

/*
 * ops.enqueue: task พร้อมรันแต่ยังไม่มีที่ลง -> เราตัดสินใจว่าจะใส่ DSQ ไหน
 * FIFO : scx_bpf_dsq_insert()       ต่อท้ายคิว
 * vtime: scx_bpf_dsq_insert_vtime() คิวเรียงตาม vtime (priority queue)
 * (ห้ามผสม FIFO กับ vtime ใน DSQ เดียวกัน เคอร์เนลจะ error; ที่นี่เลือกโหมดตอนโหลดครั้งเดียว)
 */
void BPF_STRUCT_OPS(w25_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(STAT_ENQ);

	if (vtime_mode) {
		u64 vtime = p->scx.dsq_vtime;

		/* จำกัดเครดิต: task ที่หลับนานได้ล้ำหน้าไม่เกิน 1 slice (เหมือน scx_simple) */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
	} else {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	}
}

/*
 * ops.dispatch: CPU นี้ว่าง (local DSQ หมด) -> ดึงงานจาก SHARED_DSQ มาใส่ local DSQ ของ CPU นี้
 * ชื่อ kfunc ในเคอร์เนลนี้คือ scx_bpf_dsq_move_to_local() (ชื่อเก่า: scx_bpf_consume)
 *
 * ข้อสังเกต: ตอน slice ของ prev หมด เคอร์เนลเรียก ops.dispatch "ก่อน" จะเรียก ops.enqueue(prev)
 * prev จึงยังไม่อยู่ใน SHARED_DSQ ให้เทียบ vtime -> ถ้ามีแค่ 2 task บน CPU เดียว จะสลับกันรันเสมอ
 * scheduler จริงจึงตัดสินใจเรื่อง prev เองใน dispatch (ดูแบบฝึกหัดระดับท้าทายใน README)
 */
void BPF_STRUCT_OPS(w25_dispatch, s32 cpu, struct task_struct *prev)
{
	if (fail_mode == FAIL_STALL)
		return; /* จงใจไม่ดึงงาน: task ค้างใน SHARED_DSQ จน watchdog ตัดสินว่า stall */

	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		stat_inc(STAT_DISPATCH);
}

/* ops.running: task เริ่มรันบน CPU -> เลื่อน vtime_now ตาม */
void BPF_STRUCT_OPS(w25_running, struct task_struct *p)
{
	u64 n;

	stat_inc(STAT_RUNNING);

	if (fail_mode == FAIL_ERROR) {
		/* -mcpu=v1 (ค่า default ของ bpf2go) มี atomic add แต่ห้ามใช้ค่าที่คืนกลับ จึงอ่านแยก */
		__sync_fetch_and_add(&nr_running_total, 1);
		n = nr_running_total;
		if (n >= 1000) {
			/* เคอร์เนลจะ disable scheduler นี้ แล้วคืน task ทั้งหมดให้ fair class */
			scx_bpf_error("w25: deliberate scx_bpf_error after %llu running events", n);
			return;
		}
	}
	if (vtime_mode && vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/*
 * ops.stopping: task ลง CPU -> คิดค่าใช้ CPU เป็น vtime
 * p->scx.slice คือ slice ที่ "เหลือ" ดังนั้น (SCX_SLICE_DFL - slice) = เวลาที่ใช้ไปจริง (ns)
 * หารด้วย weight (nice 0 = 100) -> task ที่ weight สูง vtime โตช้ากว่า = ได้ CPU มากกว่า
 */
void BPF_STRUCT_OPS(w25_stopping, struct task_struct *p, bool runnable)
{
	if (!vtime_mode)
		return;
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

/* ops.enable: task เข้ามาอยู่ใต้ scheduler เรา -> เริ่ม vtime ที่ "ปัจจุบัน" */
void BPF_STRUCT_OPS(w25_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

/* ops.init (sleepable): สร้าง DSQ ของเราเอง; -1 = ไม่ผูก NUMA node */
s32 BPF_STRUCT_OPS_SLEEPABLE(w25_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

/* ops.exit: ถูกเรียกเสมอเมื่อ scheduler ถูกถอด (ปกติหรือถูก eject) */
void BPF_STRUCT_OPS(w25_exit, struct scx_exit_info *ei)
{
	RECORD_EXIT_INFO(exit_info, ei);
}

/*
 * ตาราง ops: SEC(".struct_ops.link") = struct_ops map ที่ attach ผ่าน BPF link
 * (ปิด link / โปรเซสตาย -> scheduler ถูกถอดอัตโนมัติ)
 * ชื่อ type ต้องตรงกับ struct ในเคอร์เนล (sched_ext_ops) loader จะหา bpf_struct_ops_sched_ext_ops ใน BTF
 */
SEC(".struct_ops.link")
struct sched_ext_ops w25_ops = {
	.select_cpu = (void *)w25_select_cpu,
	.enqueue    = (void *)w25_enqueue,
	.dispatch   = (void *)w25_dispatch,
	.running    = (void *)w25_running,
	.stopping   = (void *)w25_stopping,
	.enable     = (void *)w25_enable,
	.init       = (void *)w25_init,
	.exit       = (void *)w25_exit,
	/* SAFETY: คุมเฉพาะ task ที่เป็น SCHED_EXT เท่านั้น (ไม่ switch ทั้งเครื่อง) */
	.flags      = SCX_OPS_SWITCH_PARTIAL,
	/* watchdog: task ที่ runnable แต่ไม่ได้รันนานเกินนี้ -> eject (Go ปรับค่าได้ด้วย -timeout) */
	.timeout_ms = 5000,
	.name       = "w25_minimal",
};
