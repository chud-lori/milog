// SPDX-License-Identifier: GPL-2.0
//
// MiLog TCP retransmit observability probe — counts retransmissions
// per destination (daddr, dport, family) into a LRU_HASH map. The
// userspace consumer polls the map periodically, computes deltas
// from the last sample, and emits a RetransEvent when a destination
// crosses the configured threshold within the window.
//
// Why no per-process attribution
// -------------------------------
//
// tcp_retransmit_skb fires from softirq context — bpf_get_current_pid_tgid
// and bpf_get_current_comm return whatever was unfortunate enough
// to be running on this CPU when the timer expired, NOT the process
// that originally sent the data. Per-comm tracking would be
// confidently wrong, so we don't attempt it; per-(daddr, dport)
// is what's actually useful for an operator anyway ("flow to
// 1.2.3.4:443 is degraded" beats "your kworker thread is").
//
// Why LRU_HASH and not a streaming ringbuf
// -----------------------------------------
//
// Retransmits on a flaky link can be hundreds per second; pushing
// every event through a ringbuf would burn CPU on the userspace
// side without adding signal. Aggregation in BPF + periodic poll
// is the standard pattern for high-volume counters (see also
// libbpf-tools/tcpconnlat). LRU eviction caps the tracked-flow
// count at max_entries so a host with thousands of distinct
// destinations doesn't OOM the map.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define AF_INET  2
#define AF_INET6 10

// retrans_key indexes the count map. daddr is 16 bytes — for IPv4
// flows we store the v4 address in the first 4 bytes and zero-fill
// the rest, so a single key shape covers both families. dport +
// family pack into a 4-byte tail, total 20 bytes per key.
//
// Userspace mirrors this layout; struct alignment is the natural
// 1-byte (u8 array) followed by 2-byte (u16) which needs no padding.
struct retrans_key {
    __u8  daddr[16];
    __u16 dport;
    __u16 family;
};

const struct retrans_key *retrans_key_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct retrans_key);
    __type(value, __u64);
} retrans_counts SEC(".maps");

// tcp_retransmit_skb tracepoint format (stable since ~4.16):
//   field:unsigned short common_type;        offset:0;  size:2;
//   ...common header (8 bytes)...
//   field:const void *  skbaddr;             offset:8;  size:8;
//   field:const void *  skaddr;              offset:16; size:8;
//   field:int           state;               offset:24; size:4;
//   field:__u16         sport;               offset:28; size:2;
//   field:__u16         dport;               offset:30; size:2;
//   field:__u16         family;              offset:32; size:2;
//   field:__u8          saddr[4];            offset:34; size:4;
//   field:__u8          daddr[4];            offset:38; size:4;
//   field:__u8          saddr_v6[16];        offset:42; size:16;
//   field:__u8          daddr_v6[16];        offset:58; size:16;
//
// The C struct alignment matches the kernel format byte-for-byte
// (no compiler-inserted padding given the field types and order).
struct trace_event_raw_tcp_retrans_min {
    char  _common[8];
    void *skbaddr;
    void *skaddr;
    int   state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
};

SEC("tracepoint/tcp/tcp_retransmit_skb")
int handle_retransmit(struct trace_event_raw_tcp_retrans_min *ctx)
{
    struct retrans_key k = {};
    k.family = ctx->family;
    k.dport  = ctx->dport;

    if (k.family == AF_INET) {
        // v4 sits in the first 4 bytes of the 16-byte key buffer;
        // remaining 12 bytes were zeroed by the {} initializer above.
        __builtin_memcpy(k.daddr, ctx->daddr, 4);
    } else if (k.family == AF_INET6) {
        __builtin_memcpy(k.daddr, ctx->daddr_v6, 16);
    } else {
        return 0;
    }

    // Atomic increment if the entry already exists; lazy insert
    // otherwise. BPF_NOEXIST avoids racing inserts when two CPUs
    // see a missing entry simultaneously — the second one will fail
    // the BPF_NOEXIST check and we fall through with the count
    // having been initialised by the first CPU's update_elem.
    __u64 *count = bpf_map_lookup_elem(&retrans_counts, &k);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&retrans_counts, &k, &init, BPF_NOEXIST);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
