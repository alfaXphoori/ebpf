//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * kfunc ที่ใช้ในไฟล์นี้ถูกประกาศไว้แล้วใน vmlinux.h (bpftool 7.x สร้างบล็อก "BPF kfuncs"
 * จาก BTF decl tag 'bpf_kfunc') ในรูปแบบ:
 *
 *   extern struct task_struct *bpf_task_from_pid(s32 pid) __weak __ksym;
 *   extern void bpf_task_release(struct task_struct *p) __weak __ksym;
 *   extern struct bpf_cpumask *bpf_cpumask_create(void) __weak __ksym;
 *   ...
 *
 * __ksym  = ให้ loader (cilium/ebpf) หา BTF ID ของฟังก์ชันนี้ใน kernel BTF ตอนโหลด
 * __weak  = ถ้าเคอร์เนลไม่มี kfunc นี้ ให้โหลดต่อได้ (ที่อยู่ = 0) แทนที่จะล้มเหลว
 *
 * kfunc ด้านล่างนี้ "ไม่มีจริง" ในเคอร์เนลใด ๆ — ใช้สาธิต bpf_ksym_exists()
 */
extern int bpf_week24_no_such_kfunc(void) __ksym __weak;

struct task_query {
	__s32 pid;              /* in : PID/TID ใน init pid namespace */
	__s32 found;            /* out: 1 = พบ task */
	__s32 tgid;             /* out */
	__s32 ppid;             /* out: tgid ของ real_parent (อ่านภายใต้ RCU) */
	__u32 nr_cpus_allowed;  /* out: จำนวน CPU ใน affinity mask (ผ่าน bpf_cpumask_*) */
	__u32 has_vpid_kfunc;   /* out: bpf_ksym_exists(bpf_task_from_vpid) */
	__u32 has_fake_kfunc;   /* out: bpf_ksym_exists(bpf_week24_no_such_kfunc) */
	__u32 _pad;
	char comm[16];          /* out */
};

/*
 * SEC("syscall") = BPF_PROG_TYPE_SYSCALL: ไม่ attach กับ hook ใด ถูกเรียกด้วย
 * BPF_PROG_TEST_RUN เท่านั้น ctx คือ buffer ที่ user space ส่งเข้ามา (และได้คืนกลับ)
 * โปรแกรมชนิดนี้เป็น sleepable และ kfunc ทั้งหมดในไฟล์นี้ลงทะเบียนให้ใช้ได้กับ SYSCALL
 */
SEC("syscall")
int query_task(struct task_query *q)
{
	struct task_struct *t, *parent;
	struct bpf_cpumask *mask;
	char comm[16] = {};

	/* kfunc แบบ optional: ตรวจก่อนเรียก (verifier ตัด branch ที่เป็นไปไม่ได้ทิ้ง) */
	q->has_vpid_kfunc = bpf_ksym_exists(bpf_task_from_vpid);
	q->has_fake_kfunc = bpf_ksym_exists(bpf_week24_no_such_kfunc);
	if (bpf_ksym_exists(bpf_week24_no_such_kfunc))
		bpf_week24_no_such_kfunc();

	/* KF_ACQUIRE | KF_RET_NULL: ได้ reference (refcount +1) หรือ NULL */
	t = bpf_task_from_pid(q->pid);
	if (!t) {
		q->found = 0;
		return 0;
	}

	q->found = 1;
	q->tgid = t->tgid; /* t เป็น trusted pointer: อ่าน field ตรง ๆ ได้ */
	/* helper เขียนลง ctx ของ syscall program ตรง ๆ ไม่ได้ (R1 type=ctx) จึงพักไว้บน stack ก่อน */
	bpf_probe_read_kernel_str(comm, sizeof(comm), t->comm);
	__builtin_memcpy(q->comm, comm, sizeof(comm));

	/* อีกคู่ acquire/release: cpumask ที่ BPF จองเอง */
	mask = bpf_cpumask_create(); /* KF_ACQUIRE | KF_RET_NULL */

	/*
	 * โปรแกรม syscall เป็น sleepable: pointer ที่ "เดินต่อ" จาก trusted pointer
	 * (t->real_parent, t->cpus_ptr) ถูก verifier มองเป็น MEM_RCU ใช้ได้เฉพาะใน
	 * RCU read-side critical section — ถ้าย้าย bpf_cpumask_copy ออกไปนอก lock
	 * จะได้ "R2 must be a rcu pointer"
	 */
	bpf_rcu_read_lock();
	parent = t->real_parent;
	if (parent)
		q->ppid = parent->tgid;
	if (mask) /* bpf_cpumask_copy มี flag KF_RCU: อาร์กิวเมนต์ต้องเป็น trusted หรือ RCU pointer */
		bpf_cpumask_copy(mask, t->cpus_ptr);
	bpf_rcu_read_unlock();

	if (mask) {
		q->nr_cpus_allowed = bpf_cpumask_weight((const struct cpumask *)mask);
		bpf_cpumask_release(mask); /* KF_RELEASE */
	}

	bpf_task_release(t); /* KF_RELEASE: ถ้าลืมบรรทัดนี้ verifier ปฏิเสธทั้งโปรแกรม */
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
