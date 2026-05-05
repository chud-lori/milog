// SPDX-License-Identifier: GPL-2.0
//
// MiLog tcp connect probe — captures outbound TCP connect attempts via
// the sock:inet_sock_set_state tracepoint and pushes a per-event record
// into a BPF ring buffer.
//
// Why tracepoint, not kprobe
// --------------------------
//
// kprobe on `tcp_v4_connect` is the classic execsnoop-style approach,
// but it needs vmlinux.h / CO-RE chain reads to dereference struct sock
// safely across kernels — heavy build prereqs we'd rather not pull in.
// `inet_sock_set_state` is a documented-stable tracepoint with explicit
// IP + port fields baked into its event format, fires on every socket
// state transition, and its layout has been stable since 4.16. Filter
// for TCP_CLOSE → TCP_SYN_SENT to capture the "connect()" moment.
//
// One probe handles both AF_INET and AF_INET6; the v6-or-v4 selector
// lives in the userspace consumer (Go side reads `family` and picks
// saddr/daddr vs saddr_v6/daddr_v6 accordingly).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define COMM_LEN 16

// Mirrored on the Go side as `tcpRawEvent`. Field order + sizes must
// stay byte-for-byte identical — the userspace consumer does a single
// binary.Read into the struct.
struct tcp_event {
    __u32 pid;
    __u32 uid;
    __u32 family;        // AF_INET / AF_INET6 (4-byte for natural alignment in the event)
    __u32 dport;         // remote port (kernel emits BE in tracepoint; we expose host order to userspace)
    __u8  daddr_v4[4];   // valid when family == AF_INET
    __u8  daddr_v6[16];  // valid when family == AF_INET6
    char  comm[COMM_LEN];
};

// Force libbpf to emit the type into BTF so the userspace side can
// resolve it by name if we later switch to bpf2go's typed wrapper.
const struct tcp_event *tcp_event_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tcp_events SEC(".maps");

// Minimal mirror of struct trace_event_raw_inet_sock_set_state_template.
// Only the fields we actually read are declared; the rest stays opaque
// behind explicit padding so offsets line up. Layout stable since
// kernel 4.16 — confirmed against the format file at
// /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format.
struct trace_event_raw_inet_sock_set_state_min {
    char  _common[8];
    __u64 skaddr;            // pointer field — opaque to us
    __s32 oldstate;
    __s32 newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
};

// TCP states — values from include/net/tcp_states.h, stable forever.
#define TCP_CLOSE     7
#define TCP_SYN_SENT  2

// IP family — values from include/linux/socket.h, stable forever.
#define AF_INET       2
#define AF_INET6     10

// IP protocol — value from include/uapi/linux/in.h.
#define IPPROTO_TCP   6

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state_min *ctx)
{
    // Only TCP. The tracepoint also fires for SCTP / DCCP transitions;
    // we'd see those as IPPROTO_SCTP / IPPROTO_DCCP and want to skip.
    if (ctx->protocol != IPPROTO_TCP) {
        return 0;
    }
    // Connect-moment filter: socket transitioning out of TCP_CLOSE into
    // TCP_SYN_SENT is exactly the "connect()" instant for outbound flows.
    // Inbound listeners go CLOSE → LISTEN; established peers go through
    // SYN_RECV/ESTABLISHED. Filtering here keeps the ring buffer small.
    if (ctx->oldstate != TCP_CLOSE || ctx->newstate != TCP_SYN_SENT) {
        return 0;
    }
    // Family guard — only handle v4 / v6. Anything else is exotic
    // (Bluetooth, AX.25, …) and not what milog cares about.
    if (ctx->family != AF_INET && ctx->family != AF_INET6) {
        return 0;
    }

    struct tcp_event *e = bpf_ringbuf_reserve(&tcp_events, sizeof(*e), 0);
    if (!e) {
        return 0;   // ring full — userspace fell behind. Drop this event.
    }

    e->pid    = bpf_get_current_pid_tgid() >> 32;
    e->uid    = bpf_get_current_uid_gid() & 0xffffffff;
    e->family = ctx->family;
    // The tracepoint dport field is already in HOST byte order — see
    // the kernel's TP_fast_assign in include/trace/events/sock.h:
    //   __entry->dport = ntohs(inet->inet_dport);
    // No bswap needed here.
    e->dport = ctx->dport;

    if (ctx->family == AF_INET) {
        __builtin_memcpy(&e->daddr_v4, &ctx->daddr, 4);
    } else {
        __builtin_memcpy(&e->daddr_v6, &ctx->daddr_v6, 16);
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
