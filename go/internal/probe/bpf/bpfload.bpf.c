// SPDX-License-Identifier: GPL-2.0
//
// MiLog BPF-program-load probe — captures `bpf(BPF_PROG_LOAD, ...)`
// syscalls. On most production hosts no userspace process loads BPF
// programs after boot finishes (systemd / dockerd / cni do their
// loads during init); a fresh load post-boot is one of the strongest
// rootkit / persistence signals available — anti-detection rootkits
// of the bpftrace-clone family install their own BPF programs to
// hide processes / files / network connections from /proc and
// netstat.
//
// We filter at BPF time to cmd == BPF_PROG_LOAD (=5) only — libbpf
// userspace runtime makes constant `bpf()` calls for map operations
// (BPF_MAP_LOOKUP_ELEM / BPF_MAP_UPDATE_ELEM are 1 / 2) that would
// drown the userspace consumer if every cmd was emitted. The other
// program-installation cmds (PROG_ATTACH, BTF_LOAD, etc.) almost
// always pair with a PROG_LOAD on the same process, so PROG_LOAD
// alone catches the load event.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define COMM_LEN 16

// `enum bpf_cmd` from linux/bpf.h — BPF_PROG_LOAD is the load-a-new-
// program cmd. Values are stable kernel ABI.
#define BPF_CMD_PROG_LOAD 5

// Userspace mirrors this layout. Keep in sync with
// go/internal/probe/bpfload_linux.go's `bpfLoadRawEvent`.
struct bpfload_event {
    __u32 pid;
    __u32 uid;
    __u32 cmd; // bpf() command — always BPF_CMD_PROG_LOAD here, but kept
               // as a field so future filter relaxations don't require
               // a struct change.
    char  comm[COMM_LEN];
};

const struct bpfload_event *bpfload_event_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} bpfload_events SEC(".maps");

// sys_enter_bpf tracepoint: args[0] = cmd, args[1] = attr pointer
// (userspace), args[2] = size. We only need cmd. Stable since 4.7.
struct trace_event_raw_sys_enter_min {
    char  _common[8];
    long  __syscall_nr;
    long  args[6];
};

SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_bpf_enter(struct trace_event_raw_sys_enter_min *ctx)
{
    long cmd = ctx->args[0];
    if (cmd != BPF_CMD_PROG_LOAD) {
        return 0;
    }

    struct bpfload_event *e = bpf_ringbuf_reserve(&bpfload_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->cmd = (__u32)cmd;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
