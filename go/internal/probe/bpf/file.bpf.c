// SPDX-License-Identifier: GPL-2.0
//
// MiLog file-audit probe — captures `openat()` syscalls on
// security-sensitive paths and pushes one ring-buffer event per match.
//
// Why a coarse BPF-side prefix filter
// -----------------------------------
//
// `sys_enter_openat` fires on every file open on the system —
// dynamic-linker probing libc, JS files in node_modules, every
// locale file, etc. Sending all of those through the ringbuf would
// drown the userspace consumer and the precision-match work duplicates
// what the audit FIM module already does.
//
// Instead we keep a four-prefix allowlist (`/etc/`, `/root`, `/home`,
// `/var/`) baked into the program. Anything outside those trees is
// dropped at BPF time. The userspace consumer applies the precise
// per-path match against the configurable sensitive list. The four
// prefixes cover the post-compromise re-entry surface that the audit
// FIM defaults already hash, plus webroot data under /var/www.
//
// The userspace allowlist (which COMMs are allowed to read sensitive
// paths) is enforced in Go, not BPF — we want sshd reading
// authorized_keys to be common-cheap path of (BPF emit → Go fast-skip
// because comm == "sshd"), since teaching BPF a comm allowlist needs
// either bpf_strncmp (kernel 6.0+) or a manual byte loop (verifier
// pain). Trade-off: a few more events through the ringbuf in exchange
// for portability + maintainability.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define COMM_LEN     16
#define FILENAME_LEN 256

// Userspace mirrors this layout exactly. Keep field order + sizes in
// sync with go/internal/probe/file_linux.go's `fileRawEvent` struct.
struct file_event {
    __u32 pid;
    __u32 uid;
    __u32 flags;     // openat flags (O_RDONLY etc.)
    char  comm[COMM_LEN];
    char  filename[FILENAME_LEN];
};

const struct file_event *file_event_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// Generic syscall tracepoint context. The first arg is the syscall
// number; args[1] for openat is the user-space `const char *filename`,
// args[2] is the open flags. Layout has been stable since 4.7.
struct trace_event_raw_sys_enter_min {
    char  _common[8];
    long  __syscall_nr;
    long  args[6];
};

// is_interesting_prefix returns 1 when the first 5 bytes of `head`
// look like one of the four sensitive-tree roots. Open-coded for
// clarity (and verifier ease) — a generic loop over a const string
// table would need bounded iteration tricks.
static __always_inline int is_interesting_prefix(const char head[5])
{
    if (head[0] != '/') return 0;
    if (head[1] == 'e' && head[2] == 't' && head[3] == 'c'  && head[4] == '/') return 1;
    if (head[1] == 'r' && head[2] == 'o' && head[3] == 'o'  && head[4] == 't') return 1;
    if (head[1] == 'h' && head[2] == 'o' && head[3] == 'm'  && head[4] == 'e') return 1;
    if (head[1] == 'v' && head[2] == 'a' && head[3] == 'r'  && head[4] == '/') return 1;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter_min *ctx)
{
    const char *filename_user = (const char *)ctx->args[1];

    // Cheap prefix check — read the first 8 bytes only. ~99% of
    // opens land outside our four sensitive trees and bail here
    // without touching the ringbuf.
    char head[8] = {};
    long hn = bpf_probe_read_user_str(&head, sizeof(head), filename_user);
    if (hn < 5 || !is_interesting_prefix(head)) {
        return 0;
    }

    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e) {
        return 0;   // ring full — userspace fell behind, drop.
    }

    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->uid   = bpf_get_current_uid_gid() & 0xffffffff;
    e->flags = (__u32)ctx->args[2];
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Re-read the full filename now that we know it's interesting.
    // The two-read pattern is the standard execsnoop trick — cheaper
    // overall than always reading 256 bytes.
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_user);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
