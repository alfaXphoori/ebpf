//go:build ignore
// +build ignore

/*
 * โปรแกรม "พังโดยตั้งใจ" — คอมไพล์ผ่าน (clang ไม่รู้กฎของ kfunc) แต่ verifier ต้องปฏิเสธตอนโหลด
 * main.go และ main_test.go โหลดทีละโปรแกรมแล้วแสดง/ตรวจข้อความ error จริงจากเคอร์เนล
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct task_query {
	__s32 pid;
	__s32 tgid;
};

/* 1) ลืม release: reference ที่ได้จาก KF_ACQUIRE รั่วเมื่อโปรแกรมจบ */
SEC("syscall")
int leak_task(struct task_query *q)
{
	struct task_struct *t = bpf_task_from_pid(q->pid);

	if (!t)
		return 0;
	q->tgid = t->tgid;
	return 0; /* <-- ไม่มี bpf_task_release(t) */
}

/* 2) ลืมเช็ก NULL: KF_RET_NULL ทำให้ค่าที่คืนเป็น "ptr_or_null" */
SEC("syscall")
int no_null_check(struct task_query *q)
{
	struct task_struct *t = bpf_task_from_pid(q->pid);

	q->tgid = t->tgid; /* <-- t อาจเป็น NULL */
	bpf_task_release(t);
	return 0;
}

/* 3) ใช้หลัง release: reference ถูกคืนไปแล้ว pointer จึงหมดสิทธิ์ใช้ */
SEC("syscall")
int use_after_release(struct task_query *q)
{
	struct task_struct *t = bpf_task_from_pid(q->pid);

	if (!t)
		return 0;
	bpf_task_release(t);
	q->tgid = t->tgid; /* <-- ใช้หลังคืน */
	return 0;
}

/* 4) kfunc ลงทะเบียนแยกตามชนิดโปรแกรม: socket filter ไม่ได้รับอนุญาตให้ใช้ bpf_task_from_pid */
SEC("socket")
int wrong_prog_type(struct __sk_buff *skb)
{
	struct task_struct *t = bpf_task_from_pid(1);

	if (t)
		bpf_task_release(t);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
