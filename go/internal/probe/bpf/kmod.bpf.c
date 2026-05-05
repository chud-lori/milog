// SPDX-License-Identifier: GPL-2.0
//
// MiLog kernel-module load probe — fires once per kernel module
// loaded, regardless of which syscall delivered it (init_module(2)
// or finit_module(2)). Kernel module loading is one of the strongest
// rootkit / persistence signals available: almost no legitimate
// post-boot software loads modules at runtime, and most production
// hosts can be operated with module loading disabled entirely
// (kernel.modules_disabled=1 after boot finishes).
//
// Why module:module_load instead of two syscall tracepoints
// ----------------------------------------------------------
//
// Both init_module and finit_module ultimately call kernel
// load_module(), which fires tracepoint module:module_load with the
// loaded module's name as a __data_loc string field. One attach
// covers both syscall paths AND we get the module name "for free"
// without having to readlink /proc/<pid>/fd/<fd> userspace-side for
// the finit_module case (where the only argument is a fd).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define COMM_LEN 16
#define NAME_LEN 64

// Userspace mirrors this layout exactly. Keep field order + sizes in
// sync with go/internal/probe/kmod_linux.go's `kmodRawEvent`.
struct kmod_event {
    __u32 pid;
    __u32 uid;
    char  comm[COMM_LEN];
    char  name[NAME_LEN];
};

const struct kmod_event *kmod_event_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} kmod_events SEC(".maps");

// module:module_load tracepoint format (stable kernel ABI):
//   field:unsigned short common_type;          offset:0;  size:2;
//   ...common header (8 bytes total)...
//   field:int            taints;               offset:8;  size:4;
//   field:__data_loc char[] name;              offset:12; size:4;
//
// __data_loc is a packed (offset, length) compound: bottom 16 bits
// = byte offset from the start of the trace event header to where
// the variable-length string lives in the trailing payload area;
// top 16 bits = length. We extract the offset and let
// bpf_probe_read_kernel_str walk the bytes (NUL-terminated, bounded
// by the buffer size).
struct trace_event_raw_module_load_min {
    char _common[8];
    int  taints;
    int  data_loc_name;
};

SEC("tracepoint/module/module_load")
int handle_module_load(struct trace_event_raw_module_load_min *ctx)
{
    struct kmod_event *e = bpf_ringbuf_reserve(&kmod_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Decode __data_loc and read the module name. Standard libbpf
    // pattern; the verifier accepts ctx-pointer arithmetic when the
    // result is consumed by a bpf_probe_read_* helper that does its
    // own bounded fault-tolerant read.
    __u32 name_off = (__u32)ctx->data_loc_name & 0xffff;
    bpf_probe_read_kernel_str(&e->name, sizeof(e->name),
                              (void *)ctx + name_off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
