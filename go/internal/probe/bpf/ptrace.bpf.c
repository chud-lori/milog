// SPDX-License-Identifier: GPL-2.0
//
// MiLog ptrace anti-injection probe — captures cross-process ptrace
// attach attempts. The classic post-exploit code injection vector:
// attacker gets RCE in a low-privilege worker, then ptrace-attaches
// to a long-running root process and POKEDATAs in shellcode. Hijacks
// privilege without spawning a new process — invisible to exec-based
// detection (which exec.bpf.c handles).
//
// Filter scope
// -------------
//
// We only fire on the *attach-class* requests: PTRACE_TRACEME (0),
// PTRACE_ATTACH (16), PTRACE_SEIZE (0x4206). Other request values
// (PEEKDATA, POKEDATA, GETREGS, CONT, DETACH, …) are operations
// performed on an already-attached target, so emitting them would
// multiply the per-debug-session event rate by ~100x without adding
// security signal. The attach event is enough — once we know who
// attached to whom, the comm allowlist tells us if it's gdb/strace
// (legit) or sshd-fork doing something it absolutely shouldn't.
//
// The userspace allowlist (which COMMs are allowed to ptrace-attach)
// is enforced in Go for the same maintainability reasons as the file
// probe — teaching BPF a comm allowlist needs bpf_strncmp (kernel
// 6.0+) or hand-rolled byte loops (verifier pain). We accept a few
// more events through the ringbuf in exchange for portability.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define COMM_LEN 16

// Userspace mirrors this layout exactly. Keep field order + sizes in
// sync with go/internal/probe/ptrace_linux.go's `ptraceRawEvent`.
struct ptrace_event {
    __u32 pid;
    __u32 uid;
    __u32 target_pid;
    __u32 request;
    char  comm[COMM_LEN];
};

const struct ptrace_event *ptrace_event_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} ptrace_events SEC(".maps");

// Generic syscall tracepoint context — same layout file.bpf.c uses
// for openat. args[0] is the ptrace request, args[1] is the target
// PID. Stable since 4.7.
struct trace_event_raw_sys_enter_min {
    char  _common[8];
    long  __syscall_nr;
    long  args[6];
};

// PTRACE_TRACEME = child requests trace by parent (debugger-startup
// pattern). PTRACE_ATTACH = classic attach to running process.
// PTRACE_SEIZE = modern attach (no SIGSTOP). The three cover every
// way one process can begin tracing another.
#define PTRACE_TRACEME 0
#define PTRACE_ATTACH  16
#define PTRACE_SEIZE   0x4206

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter_min *ctx)
{
    long request = ctx->args[0];
    long target_pid = ctx->args[1];

    if (request != PTRACE_ATTACH &&
        request != PTRACE_SEIZE &&
        request != PTRACE_TRACEME) {
        return 0;
    }

    struct ptrace_event *e = bpf_ringbuf_reserve(&ptrace_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->uid        = bpf_get_current_uid_gid() & 0xffffffff;
    e->target_pid = (__u32)target_pid;
    e->request    = (__u32)request;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
