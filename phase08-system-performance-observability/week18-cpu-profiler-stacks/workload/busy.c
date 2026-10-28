// busy.c - CPU workload ที่รู้ "คำตอบ" ล่วงหน้า ใช้ตรวจความถูกต้องของ Profiler
//
// โครงสร้างการเรียก:  main -> run_workload -> hot_path_a  (งาน 2 ส่วน)
//                                         -> hot_path_b  (งาน 1 ส่วน)
// ดังนั้นใน Flame Graph ควรเห็น hot_path_a กว้างประมาณ 2 เท่าของ hot_path_b
//
// คอมไพล์ด้วย -fno-omit-frame-pointer เพื่อให้ bpf_get_stackid() เดิน
// frame pointer chain ของ user stack ได้ครบ
//
//   cc -O1 -g -fno-omit-frame-pointer -o bin/busy workload/busy.c
//   ./bin/busy 10      # รัน 10 วินาที

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static volatile unsigned long sink;

__attribute__((noinline)) static void spin(unsigned long iters)
{
    for (unsigned long i = 0; i < iters; i++)
        sink += i * 2654435761UL;
}

/*
 * barrier() หลัง spin() กันไม่ให้คอมไพเลอร์แปลงเป็น tail call (jmp spin)
 * ถ้าเกิด tail call เฟรมของ hot_path_a/b จะหายไปจาก stack และ flame graph
 */
#define barrier() __asm__ __volatile__("" ::: "memory")

__attribute__((noinline)) void hot_path_a(void) { spin(2000000); barrier(); }
__attribute__((noinline)) void hot_path_b(void) { spin(1000000); barrier(); }

__attribute__((noinline)) void run_workload(int seconds)
{
    time_t end = time(NULL) + seconds;
    while (time(NULL) < end) {
        hot_path_a();
        hot_path_b();
    }
}

int main(int argc, char **argv)
{
    int seconds = argc > 1 ? atoi(argv[1]) : 10;
    printf("busy: pid=%d, burning one CPU for %d s (hot_path_a:hot_path_b = 2:1)\n",
           (int)getpid(), seconds);
    run_workload(seconds);
    return 0;
}
