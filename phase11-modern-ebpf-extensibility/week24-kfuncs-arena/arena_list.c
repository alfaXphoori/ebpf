//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * __arena = address space 1 ของ LLVM
 * clang >= 19 (มี __BPF_FEATURE_ADDR_SPACE_CAST) จะแทรกคำสั่ง addr_space_cast ให้อัตโนมัติ
 * ทุกครั้งที่ dereference pointer ใน address space 1 จึงเขียนโค้ดเหมือน C ปกติได้
 */
#ifndef __BPF_FEATURE_ADDR_SPACE_CAST
#error "ต้องใช้ clang/LLVM ที่รองรับ BPF addr_space_cast (clang 19 ขึ้นไป)"
#endif
#define __arena __attribute__((address_space(1)))

#define NUMA_NO_NODE (-1)
#define ARENA_PAGES 16          /* ขนาด arena = 16 หน้า = 64 KiB (หน้า 4 KiB) */
#define ARENA_PAGE_SIZE 4096    /* x86_64 / arm64 แบบหน้า 4 KiB */
#define MAX_WALK 512            /* เพดานลูปเดิน list (verifier ต้องเห็นว่าลูปจบ) */
#define ARENA_MAGIC 0x3432454e45524121ULL /* "!ARENE24" */

#define E2BIG 7
#define ENOMEM 12

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);   /* บังคับสำหรับ arena */
	__uint(max_entries, ARENA_PAGES);    /* หน่วยเป็น "หน้า" ไม่ใช่จำนวน element */
} arena SEC(".maps");

/* ชื่อ struct node ชนกับ type ในเคอร์เนล (vmlinux.h) จึงใช้ arena_node */
struct arena_node {
	struct arena_node __arena *next; /* pointer จริง ใช้ได้ทั้งใน BPF และ user space */
	__u64 key;
	__u64 count;
	__u64 sum;
};

/* อยู่ที่หน้าแรกของ arena (offset 0) ให้ user space หาเจอ */
struct arena_hdr {
	__u64 magic;
	__u64 self;                       /* user address ของ header = ฐานของ arena ใน process */
	struct arena_node __arena *head;
	__u64 nr_nodes;
	__u64 pages;                      /* จำนวนหน้าที่โปรแกรมนี้ขอด้วย bpf_arena_alloc_pages */
	__u64 bytes_used;
};

struct upsert_args {
	__u64 key;       /* in */
	__u64 value;     /* in */
	__u64 node_addr; /* out: pointer ของ node (มุมมอง user space) */
	__s32 err;       /* out: 0 หรือ -errno */
	__u32 _pad;
};

struct peek_args {
	__u64 off;       /* in : offset จากฐาน arena */
	__u64 before;    /* out: ค่าที่อ่านได้ก่อนเขียน */
	__u64 after;     /* out: ค่าที่อ่านได้หลังเขียน 0xC0FFEE */
	__s32 err;
	__u32 _pad;
};

/* ตัวแปร global ธรรมดา (อยู่ใน .bss ไม่ได้อยู่ใน arena) ที่ "เก็บ pointer ชี้เข้า arena" */
struct arena_hdr __arena *hdr;
void __arena *cur_page;
__u32 cur_off;

/* bump allocator: ขอหน้าใหม่จาก arena ทีละ 1 หน้าเมื่อหน้าเดิมเต็ม (ไม่มี free) */
static void __arena *bump_alloc(__u32 size)
{
	void __arena *p;

	if (!cur_page || cur_off + size > ARENA_PAGE_SIZE) {
		/* kfunc: (map, addr hint, page_cnt, node_id, flags) -> user address หรือ NULL */
		cur_page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
		if (!cur_page)
			return NULL;
		cur_off = 0;
		if (hdr)
			hdr->pages++;
	}
	p = cur_page + cur_off;
	cur_off += size;
	if (hdr)
		hdr->bytes_used += size;
	return p;
}

SEC("syscall")
int arena_upsert(struct upsert_args *args)
{
	struct arena_node __arena *n;
	int i;

	if (!hdr) {
		/* การจองครั้งแรกของ arena ที่ว่างได้หน้า 0 (offset 0) */
		struct arena_hdr __arena *h = bump_alloc(sizeof(*h));

		if (!h) {
			args->err = -ENOMEM;
			return 0;
		}
		h->magic = ARENA_MAGIC;
		h->self = (__u64)h;   /* ค่าของ pointer = address ใน user space ของ process ที่ mmap */
		h->pages = 1;
		h->bytes_used = sizeof(*h);
		hdr = h;
	}

	/* เดิน linked list ใน arena: โหลดผ่าน pointer ได้เลย ไม่ต้อง bpf_probe_read / map lookup */
	n = hdr->head;
	for (i = 0; i < MAX_WALK && n; i++) {
		if (n->key == args->key) {
			n->count++;
			n->sum += args->value;
			args->node_addr = (__u64)n;
			return 0;
		}
		n = n->next;
	}
	if (n) {                 /* เดินครบ MAX_WALK แล้วยังไม่จบ list */
		args->err = -E2BIG;
		return 0;
	}

	n = bump_alloc(sizeof(*n));
	if (!n) {
		args->err = -ENOMEM; /* arena เต็ม (ครบ ARENA_PAGES หน้า) */
		return 0;
	}
	n->key = args->key;
	n->count = 1;
	n->sum = args->value;
	n->next = hdr->head;     /* push-front */
	hdr->head = n;
	hdr->nr_nodes++;
	args->node_addr = (__u64)n;
	return 0;
}

/*
 * สาธิตการเข้าถึงหน้าที่ยังไม่ได้จอง: JIT แปลง load/store ของ arena เป็นแบบ PROBE_MEM32
 * ถ้าเกิด page fault เคอร์เนลจะไม่ oops — load ได้ 0 และ store ถูกทิ้งเงียบ ๆ
 */
SEC("syscall")
int arena_peek(struct peek_args *args)
{
	volatile __u64 __arena *p; /* volatile: กัน clang ยุบ store+load เป็นค่าคงที่ */

	/*
	 * โปรแกรมที่ใช้ addr_space_cast ต้อง "ผูก" กับ arena map: เคอร์เนลผูกให้เมื่อโปรแกรม
	 * อ้างถึง map ด้วยคำสั่ง ld_imm64 ฟังก์ชันนี้ไม่ได้เรียก kfunc ที่รับ &arena
	 * จึงต้องอ้างถึงเอง ไม่งั้นได้ "addr_space_cast insn can only be used in a program
	 * that has an associated arena"
	 */
	asm volatile("" : : "r"(&arena));

	if (!hdr || args->off > (__u64)ARENA_PAGES * ARENA_PAGE_SIZE - sizeof(__u64)) {
		args->err = -E2BIG;
		return 0;
	}
	p = (volatile __u64 __arena *)(hdr->self + args->off);
	args->before = *p;
	*p = 0xC0FFEE;
	args->after = *p;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
