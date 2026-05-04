// SPDX-License-Identifier: GPL-2.0
//
// MiLog exec probe — captures every sched_process_exec tracepoint and
// pushes a per-event record into a BPF ring buffer for the userspace
// loader to consume.
//
// Design notes
// ------------
//
// We deliberately avoid vmlinux.h / struct task_struct here. The full
// CO-RE chain read (`task->real_parent->tgid`) needs vmlinux.h shape
// which adds another build prereq (kernel BTF dump) and complicates
// non-CO-RE distros. The fields we need from this tracepoint are
// stable across all kernels with sched_process_exec (Linux 4.x+), so
// we declare a minimal context struct ourselves and read PPID + parent
// comm in userspace from /proc/<pid>/status.
//
// The tracepoint format file (read from
// /sys/kernel/debug/tracing/events/sched/sched_process_exec/format)
// shows __data_loc_filename at a stable offset; the lower 16 bits of
// that field are the offset from the tracepoint event base where the
// filename string actually lives. This is the canonical execsnoop-style
// trick — see libbpf-tools/execsnoop.bpf.c for the reference.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_FILENAME_LEN 256
#define COMM_LEN 16

// Userspace mirrors this layout exactly. Keep field order + sizes in
// sync with go/internal/probe/exec_linux.go's `event` struct.
struct exec_event {
    __u32 pid;
    __u32 uid;
    char  comm[COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
};

// Force libbpf to emit the type into the BTF section so userspace can
// resolve it by name if we ever switch to bpf2go's typed wrapper.
const struct exec_event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Minimal substitute for `struct trace_event_raw_sched_process_exec`.
// Only the fields we read are declared; the rest stays opaque. Layout
// taken from the kernel's tracepoint format definition — stable since
// Linux 4.x, no CO-RE relocation needed.
struct trace_event_raw_sched_process_exec_min {
    char  _common[8];
    __u32 __data_loc_filename;
    __s32 pid;
    __s32 old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec_min *ctx)
{
    struct exec_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;   // ring full — userspace fell behind. Drop this event.
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // __data_loc_filename packs `(length << 16) | offset`. Mask off the
    // top 16 bits to get the offset of the filename string within the
    // event buffer; bpf_probe_read_kernel_str then walks until NUL.
    __u32 fname_off = ctx->__data_loc_filename & 0xffff;
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                              (char *)ctx + fname_off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
