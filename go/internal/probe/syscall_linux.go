//go:build linux

// syscall_linux.go — userspace loader for the per-PID syscall rate
// probe. Same shape as retrans_linux.go (sample-and-tick rather than
// stream), but adds Welford σ state per tracked PID for anomaly
// detection vs. the rolling baseline.
//
// Memory bound is N_pids × (Welford{24B} + bookkeeping ~24B) ≈ 50 B
// per tracked PID. With LRU cap at 16384 PIDs, worst case ~800 KB
// of Go-side state — fits in any real system's RAM, no concern.

package probe

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/syscall.bpf.o
var syscallBpfObj []byte

// syscallBaseline tracks the per-PID Welford state plus the fields
// needed for delta computation and age-out. We carry the Welford
// directly (not a pointer) since the map lookup already gives us a
// reference, and updates happen through the map's value pointer.
type syscallBaseline struct {
	w             Welford
	last          uint64    // last total count seen via the BPF map (for delta)
	lastSampledAt time.Time // for age-out of departed PIDs
	firstSeenAt   time.Time // for partial-first-window suppression
}

// defaultSyscallWindow — sample interval. Same default as retrans
// (60s) so the two probes' tick alignment doesn't matter (each runs
// its own goroutine anyway).
const defaultSyscallWindow = 60 * time.Second

// defaultSyscallMaxAge — how long a PID can go unsampled before we
// drop its baseline. Mostly relevant for short-lived processes that
// briefly cross the LRU map and then exit. Long-lived legitimate
// processes never trip this.
const defaultSyscallMaxAge = 30 * time.Minute

func envSyscallWindow() time.Duration {
	v := os.Getenv("MILOG_PROBE_SYSCALL_WINDOW")
	if v == "" {
		return defaultSyscallWindow
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return defaultSyscallWindow
	}
	return d
}

// RunSyscallRate loads the syscall counter probe, attaches the
// raw_tracepoint:sys_enter, and ticks every window emitting
// RateAnomalyEvents. Threshold logic (3σ + floor + burn-in) lives
// in matchSyscallBurst — the loader emits events for ALL active
// PIDs and the rule decides whether to fire.
//
// Per-CPU map iteration: cilium/ebpf returns a []uint64 of length
// runtime.NumCPU() per key. We sum to get the total count for that
// PID. Per-CPU eliminates atomic contention in BPF (huge win on
// 16+ core boxes); the cost is this O(NumCPUs × NumPIDs) sum at
// sample time, which is trivial relative to the per-syscall hot
// path.
func RunSyscallRate(ctx context.Context, out chan<- RateAnomalyEvent) error {
	if len(syscallBpfObj) == 0 {
		return errors.New("probe: bpf/syscall.bpf.o is empty — rebuild with clang available (apt install clang llvm libbpf-dev)")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("probe: remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallBpfObj))
	if err != nil {
		return fmt.Errorf("probe: load syscall BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("probe: instantiate syscall BPF collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_sys_enter"]
	if prog == nil {
		return errors.New("probe: BPF program 'handle_sys_enter' missing from object")
	}

	// AttachRawTracepoint requires kernel 4.17+; older kernels
	// surface as an attach error and we bubble up to milog-probe
	// which logs "syscall-rate coverage degraded".
	rawTP, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("probe: attach raw_tracepoint sys_enter: %w", err)
	}
	defer rawTP.Close()

	countsMap := coll.Maps["syscall_counts"]
	if countsMap == nil {
		return errors.New("probe: BPF map 'syscall_counts' missing from object")
	}

	window := envSyscallWindow()
	baselines := make(map[uint32]*syscallBaseline, 256)

	ticker := time.NewTicker(window)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case tickAt := <-ticker.C:
			if err := emitSyscallRateAnomalies(ctx, countsMap, baselines, window, tickAt, out); err != nil {
				return fmt.Errorf("probe: syscall-rate tick: %w", err)
			}
		}
	}
}

// emitSyscallRateAnomalies walks the BPF per-CPU count map once,
// computes the per-PID delta vs the previous sample, folds it into
// the Welford baseline, and emits a RateAnomalyEvent. The rule (in
// matchSyscallBurst) gates whether the alert ultimately fires —
// this loader emits unconditionally so all-PIDs JSON debugging
// (`milog-probe --json`) shows the full state.
func emitSyscallRateAnomalies(
	ctx context.Context,
	m *ebpf.Map,
	baselines map[uint32]*syscallBaseline,
	window time.Duration,
	tickAt time.Time,
	out chan<- RateAnomalyEvent,
) error {
	seen := make(map[uint32]struct{}, len(baselines))

	iter := m.Iterate()
	var pid uint32
	var perCPU []uint64
	for iter.Next(&pid, &perCPU) {
		if pid == 0 {
			continue // BPF already filtered, defensive
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		seen[pid] = struct{}{}

		b := baselines[pid]
		if b == nil {
			// First observation: record the count but skip Welford
			// update — the count likely covers a partial window
			// (process started mid-tick) and would skew the mean
			// downward. Next tick onward we have a full window's
			// data.
			baselines[pid] = &syscallBaseline{
				last:          total,
				lastSampledAt: tickAt,
				firstSeenAt:   tickAt,
			}
			continue
		}

		// Same wraparound guard as retrans: counter "shrinking"
		// implies LRU re-insertion or kernel-side reset; treat as
		// "reset baseline" rather than emit a wraparound event.
		if total < b.last {
			b.last = total
			b.lastSampledAt = tickAt
			continue
		}
		delta := total - b.last
		b.last = total
		b.lastSampledAt = tickAt

		// Update Welford BEFORE emitting — the event carries the
		// post-update mean/stddev. This matches the spec: "what
		// does the baseline look like INCLUDING this sample" so
		// the rule's "is THIS sample anomalous?" question is
		// well-formed.
		b.w.Update(float64(delta))

		comm, parentComm, ppid, uid := lookupProcMeta(pid)

		ev := RateAnomalyEvent{
			PID:        pid,
			PPID:       ppid,
			UID:        uid,
			Comm:       comm,
			ParentComm: parentComm,
			Count:      delta,
			Mean:       b.w.Mean,
			Stddev:     b.w.Stddev(),
			Window:     window,
			Samples:    b.w.N,
		}

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("syscall map iterate: %w", err)
	}

	// Age-out: drop baselines whose PIDs disappeared from the BPF
	// map and haven't been re-seen for maxAge. Prevents the local
	// state from growing unbounded over a long-running probe.
	maxAge := defaultSyscallMaxAge
	for pid, b := range baselines {
		if _, ok := seen[pid]; ok {
			continue
		}
		if tickAt.Sub(b.lastSampledAt) > maxAge {
			delete(baselines, pid)
		}
	}
	return nil
}

// lookupProcMeta reads /proc/<pid>/{status,comm} once per sample
// per PID. Same race-acceptance as lookupParent in exec_linux.go:
// if the PID exited between the BPF map sample and the lookup,
// we get empty strings and the alert body just lacks parent
// context. Better than blocking on stale state.
func lookupProcMeta(pid uint32) (comm, parentComm string, ppid, uid uint32) {
	commPath := "/proc/" + uitoa(pid) + "/comm"
	if b, err := os.ReadFile(commPath); err == nil {
		comm = string(bytes.TrimSpace(b))
	}
	statusPath := "/proc/" + uitoa(pid) + "/status"
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return comm, "", 0, 0
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		switch {
		case bytes.HasPrefix(line, []byte("PPid:")):
			fields := bytes.Fields(line)
			if len(fields) >= 2 {
				if v, err := parseUint32(fields[1]); err == nil {
					ppid = v
				}
			}
		case bytes.HasPrefix(line, []byte("Uid:")):
			fields := bytes.Fields(line)
			// Uid line format: "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
			// Effective UID is index 2 (the one our alerts care about).
			if len(fields) >= 3 {
				if v, err := parseUint32(fields[2]); err == nil {
					uid = v
				}
			}
		}
	}
	if ppid != 0 {
		ppCommPath := "/proc/" + uitoa(ppid) + "/comm"
		if b, err := os.ReadFile(ppCommPath); err == nil {
			parentComm = string(bytes.TrimSpace(b))
		}
	}
	return comm, parentComm, ppid, uid
}

// parseUint32 parses a uint32 from a numeric byte slice. strconv
// would do the same job from a string; this avoids the alloc on the
// hot path (lookupProcMeta runs per active PID per tick).
func parseUint32(b []byte) (uint32, error) {
	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + uint64(c-'0')
		if n > 0xffffffff {
			return 0, errors.New("uint32 overflow")
		}
	}
	return uint32(n), nil
}

