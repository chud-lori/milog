// SPDX-License-Identifier: GPL-2.0
//
// MiLog per-PID syscall rate counter — feeds the rate-anomaly rule.
// Increments a counter for each PID on every syscall entry; userspace
// samples the map periodically and detects per-process rate spikes
// vs a Welford-tracked baseline.
//
// Why raw_tracepoint not tracepoint
// ----------------------------------
//
// `raw_tracepoint/sys_enter` skips the kernel's per-event arg
// formatting that the structured `tracepoint:raw_syscalls:sys_enter`
// performs. We don't need the syscall number or args — we just need
// to know "syscall happened, attribute it to this PID". Skipping the
// formatting saves a measurable percentage of CPU on syscall-heavy
// hosts (databases, web servers under load), at the cost of needing
// kernel 4.17+. Older kernels surface as a load failure; milog-probe
// logs "syscall-rate coverage degraded" and other probes keep running.
//
// Why PERCPU_HASH not HASH
// -------------------------
//
// On a host with N cores doing M syscalls/sec, regular HASH would
// see N-way atomic contention on every map update — `__sync_fetch_and_add`
// becomes the bottleneck. `LRU_PERCPU_HASH` gives each CPU its own
// counter slot, so increments are local writes with zero atomic
// overhead. Userspace iterates and sums across CPUs at sample time
// — cheap, since sampling happens once per minute.
//
// LRU caps the tracked-PID set at max_entries; rare PIDs evict
// before the userspace age-out kicks in.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   // tgid (process-level PID, what /proc/<pid> shows)
    __type(value, __u64); // running syscall count
} syscall_counts SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Skip pid 0: the idle task / kernel-thread root. It's not a
    // userspace process and would otherwise dominate the counters
    // on a busy host.
    if (pid == 0) {
        return 0;
    }

    __u64 *cnt = bpf_map_lookup_elem(&syscall_counts, &pid);
    if (cnt) {
        // Per-CPU map: this is OUR cpu's slot. No atomic needed,
        // a simple non-volatile increment is correct because every
        // other CPU writes to its own slot.
        (*cnt)++;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&syscall_counts, &pid, &init, BPF_NOEXIST);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
