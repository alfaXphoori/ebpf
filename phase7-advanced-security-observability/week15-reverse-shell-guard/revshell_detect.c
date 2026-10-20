//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/*
 * Security Alert Struct streamed over BPF Ring Buffer
 */
struct threat_alert {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8 is_suspicious_parent;
    char pad[3];
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
};

/*
 * BPF Ring Buffer for instant security event dispatch
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4MB */
} threat_events SEC(".maps");

/*
 * Helper string comparison for shell binary names
 */
static __always_inline int is_shell(const char *name)
{
    /* "bash" */
    if (name[0] == 'b' && name[1] == 'a' && name[2] == 's' && name[3] == 'h') return 1;
    /* "sh" */
    if (name[0] == 's' && name[1] == 'h' && name[2] == '\0') return 1;
    /* "dash" */
    if (name[0] == 'd' && name[1] == 'a' && name[2] == 's' && name[3] == 'h') return 1;
    /* "nc" */
    if (name[0] == 'n' && name[1] == 'c') return 1;
    /* "zsh" */
    if (name[0] == 'z' && name[1] == 's' && name[2] == 'h') return 1;
    return 0;
}

/*
 * Detect if parent process is a typical daemon/web service that should NOT spawn shells
 */
static __always_inline int is_daemon_parent(const char *pname)
{
    /* "ngin" (nginx) */
    if (pname[0] == 'n' && pname[1] == 'g' && pname[2] == 'i' && pname[3] == 'n') return 1;
    /* "apac" (apache) */
    if (pname[0] == 'a' && pname[1] == 'p' && pname[2] == 'a' && pname[3] == 'c') return 1;
    /* "node" */
    if (pname[0] == 'n' && pname[1] == 'o' && pname[2] == 'd' && pname[3] == 'e') return 1;
    /* "pyth" (python web service / daemon) */
    if (pname[0] == 'p' && pname[1] == 'y' && pname[2] == 't' && pname[3] == 'h') return 1;
    /* "redi" (redis) */
    if (pname[0] == 'r' && pname[1] == 'e' && pname[2] == 'd' && pname[3] == 'i') return 1;
    return 0;
}

struct trace_sched_exec_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    unsigned int filename_loc;
    int pid;
    int old_pid;
};

/*
 * Minimal task_struct representation for CO-RE parent inspection
 */
struct task_struct___core {
    struct task_struct___core *real_parent;
    char comm[TASK_COMM_LEN];
    int tgid;
};

SEC("tracepoint/sched/sched_process_exec")
int trace_exec_threat(struct trace_sched_exec_args *ctx)
{
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    /* Check if target binary being launched is an interactive shell or netcat */
    if (!is_shell(comm)) {
        return 0;
    }

    struct task_struct___core *task = (struct task_struct___core *)bpf_get_current_task();
    struct task_struct___core *parent = BPF_CORE_READ(task, real_parent);

    char pcomm[TASK_COMM_LEN] = {};
    int ppid = 0;
    if (parent) {
        bpf_core_read_str(&pcomm, sizeof(pcomm), &parent->comm);
        ppid = BPF_CORE_READ(parent, tgid);
    }

    int is_suspicious = is_daemon_parent(pcomm);

    struct threat_alert *alert = bpf_ringbuf_reserve(&threat_events, sizeof(*alert), 0);
    if (!alert) {
        return 0;
    }

    alert->pid = bpf_get_current_pid_tgid() >> 32;
    alert->ppid = ppid;
    alert->uid = bpf_get_current_uid_gid();
    alert->ts_ns = bpf_ktime_get_ns();
    alert->is_suspicious_parent = is_suspicious ? 1 : 0;
    __builtin_memcpy(alert->comm, comm, sizeof(alert->comm));
    __builtin_memcpy(alert->pcomm, pcomm, sizeof(alert->pcomm));

    bpf_ringbuf_submit(alert, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
