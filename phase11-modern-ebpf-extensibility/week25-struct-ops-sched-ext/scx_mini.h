/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_mini.h - helper macros ขั้นต่ำสำหรับเขียน sched_ext scheduler ด้วย BPF
 *
 * ไฟล์นี้ "เขียนใหม่ให้เล็กที่สุด" จากแนวคิดใน upstream:
 *   linux/tools/sched_ext/include/scx/common.bpf.h   (BPF_STRUCT_OPS, scx_bpf_error)
 *   linux/tools/sched_ext/include/scx/user_exit_info.h (การเก็บเหตุผลที่ scheduler ถูก eject)
 * เราไม่ vendor ทั้ง repo sched-ext/scx เพราะต้องการให้นักศึกษาเห็นว่า "ของที่จำเป็นจริง" มีแค่นี้
 *
 * ประกาศ kfunc (scx_bpf_dsq_insert, scx_bpf_dsq_move_to_local, ...) ไม่ต้องเขียนเอง
 * เพราะ bpftool 7.x ใส่ prototype ของ kfunc ไว้ใน vmlinux.h แล้ว (ส่วน #ifndef BPF_NO_KFUNC_PROTOTYPES)
 * ส่วน enum/struct (SCX_DSQ_LOCAL, SCX_SLICE_DFL, struct sched_ext_ops ...) ก็มาจาก BTF ของเคอร์เนล
 */
#ifndef __SCX_MINI_H
#define __SCX_MINI_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * BPF_STRUCT_OPS: ประกาศ callback 1 ตัวของ struct_ops
 *   - SEC("struct_ops/<name>") บอก loader ว่าเป็นโปรแกรมชนิด BPF_PROG_TYPE_STRUCT_OPS
 *   - BPF_PROG() แปลง ctx (u64 array) ให้เป็นอาร์กิวเมนต์ที่มีชนิดตามที่เราประกาศ
 * BPF_STRUCT_OPS_SLEEPABLE ใช้ "struct_ops.s/" สำหรับ callback ที่หลับได้ เช่น ops.init
 * (scx_bpf_create_dsq() เรียกได้เฉพาะในบริบทที่ sleep ได้)
 */
#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name) BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name) BPF_PROG(name, ##args)

/*
 * scx_bpf_error(fmt, args...): สั่งให้เคอร์เนล "ปลด" BPF scheduler ทิ้งพร้อมข้อความ
 * kfunc จริงคือ scx_bpf_error_bstr(fmt, u64 data[], size) แบบเดียวกับ bpf_seq_printf
 * มาโครนี้แพ็กอาร์กิวเมนต์ลง array ด้วย ___bpf_fill จาก libbpf (ย่อจาก common.bpf.h)
 */
#define scx_bpf_error(fmt, args...)                                         \
	({                                                                  \
		static char ___fmt[] = fmt;                                 \
		unsigned long long ___param[___bpf_narg(args)];             \
		_Pragma("GCC diagnostic push")                              \
		_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")      \
		___bpf_fill(___param, args);                                \
		_Pragma("GCC diagnostic pop")                               \
		scx_bpf_error_bstr(___fmt, ___param, sizeof(___param));     \
	})

/* เปรียบเทียบเวลา/vtime แบบทนต่อ u64 wrap-around (เหมือน time_before() ในเคอร์เนล) */
static __always_inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

/*
 * exit_info: ย่อจาก user_exit_info.h ของ upstream
 * ops.exit() คัดลอก kind / exit_code / reason / msg จาก struct scx_exit_info (หน่วยความจำเคอร์เนล)
 * มาไว้ในตัวแปร global (.bss) ให้ฝั่ง Go อ่านได้หลัง detach หรือหลังถูก watchdog eject
 */
#define EXIT_REASON_LEN 128
#define EXIT_MSG_LEN    256

struct w25_exit_info {
	s32 kind;     /* enum scx_exit_kind: 64 = UNREG, 1024+ = error */
	s32 _pad;
	s64 exit_code;
	char reason[EXIT_REASON_LEN];
	char msg[EXIT_MSG_LEN];
};

#define RECORD_EXIT_INFO(dst, ei)                                                    \
	({                                                                           \
		/* ei เป็น trusted BTF pointer จึงอ่าน field ตรง ๆ ได้ */            \
		/* แต่ reason/msg ชี้ไปหน่วยความจำอื่นต้อง probe_read */              \
		bpf_probe_read_kernel_str((dst).reason, sizeof((dst).reason),        \
					  (ei)->reason);                             \
		bpf_probe_read_kernel_str((dst).msg, sizeof((dst).msg), (ei)->msg);  \
		(dst).exit_code = (ei)->exit_code;                                   \
		/* เขียน kind เป็นอันสุดท้าย: Go ใช้ kind != 0 เป็นสัญญาณว่า "จบแล้ว" */ \
		/* (bpf2go คอมไพล์ด้วย -mcpu=v1 จึงไม่ใช้ cmpxchg; ใช้ barrier แทน) */  \
		asm volatile("" ::: "memory");                                       \
		(dst).kind = (ei)->kind;                                             \
	})

#endif /* __SCX_MINI_H */
