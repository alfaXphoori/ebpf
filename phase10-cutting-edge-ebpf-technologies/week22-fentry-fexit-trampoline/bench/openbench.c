// openbench.c - Load generator สำหรับวัด overhead ของ probe บน do_sys_openat2
//
// วนเรียก openat("/dev/null") + close() จำนวน N รอบ แล้วรายงานเวลาเฉลี่ยต่อรอบ (ns/op)
// ใช้เปรียบเทียบ: ไม่มี probe  vs  kprobe  vs  fentry  vs  kretprobe  vs  fexit
//
// Build: gcc -O2 -o openbench openbench.c
// Usage: ./openbench [iterations]   (default 1000000)
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
    long n = argc > 1 ? atol(argv[1]) : 1000000;

    /* warm-up: ให้ dentry cache / branch predictor อุ่นก่อนเริ่มจับเวลา */
    for (long i = 0; i < 10000; i++)
        close(openat(AT_FDCWD, "/dev/null", O_RDONLY));

    long long t0 = now_ns();
    for (long i = 0; i < n; i++) {
        int fd = openat(AT_FDCWD, "/dev/null", O_RDONLY);
        if (fd < 0) {
            perror("openat");
            return 1;
        }
        close(fd);
    }
    long long t1 = now_ns();

    printf("%.1f\n", (double)(t1 - t0) / n);
    return 0;
}
