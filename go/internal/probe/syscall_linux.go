//go:build linux

// Loader for the per-PID syscall-rate probe: samples a per-CPU count map
// each window and keeps a Welford baseline per PID (about 50 B each, so
// roughly 800 KB at the 16384-PID LRU cap).

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

// syscallBaseline is one PID's Welford state plus what delta and age-out need.
type syscallBaseline struct {
	w             Welford
	last          uint64    // last total count seen via the BPF map (for delta)
	lastSampledAt time.Time // for age-out of departed PIDs
	firstSeenAt   time.Time // for partial-first-window suppression
}

// defaultSyscallWindow is the sample interval.
const defaultSyscallWindow = 60 * time.Second

// defaultSyscallMaxAge drops baselines of PIDs unseen this long.
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

// RunSyscallRate attaches raw_tracepoint:sys_enter and emits a
// RateAnomalyEvent per active PID every window; matchSyscallBurst decides
// whether to alert. The map is per-CPU to avoid atomics in BPF, so counts
// are summed across CPUs here.
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

	// Raw tracepoints need kernel 4.17+.
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

// emitSyscallRateAnomalies emits every PID, not just anomalies, so
// --json shows the full state.
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
			// The first count likely covers a partial window, so
			// record it without updating the baseline.
			baselines[pid] = &syscallBaseline{
				last:          total,
				lastSampledAt: tickAt,
				firstSeenAt:   tickAt,
			}
			continue
		}

		// A shrinking counter means LRU re-insertion or a reset;
		// restart from the new value.
		if total < b.last {
			b.last = total
			b.lastSampledAt = tickAt
			continue
		}
		delta := total - b.last
		b.last = total
		b.lastSampledAt = tickAt

		// The event's mean and stddev include this sample.
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

	// Drop baselines for PIDs gone from the map longer than maxAge.
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

// lookupProcMeta returns empty values if the PID has already exited.
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
			// "Uid:\t<real>\t<effective>\t<saved>\t<fs>"; take effective.
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

// parseUint32 avoids a string allocation per PID per tick.
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

