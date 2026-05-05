//go:build linux

// retrans_linux.go — userspace loader for the TCP retransmit
// observability probe. Differs from the streaming probes (exec /
// tcp connect / file / ptrace / kmod): there's no ringbuf, just a
// LRU_HASH counter map that BPF increments and Go reads on a tick.
//
// The tick window + delta computation pattern keeps event rate
// bounded by destination cardinality (max 4096 entries via LRU)
// rather than by per-packet retransmit volume — a flaky link
// produces hundreds of retransmits per second but only one
// RetransEvent per (daddr, dport) per window.

package probe

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/retrans.bpf.o
var retransBpfObj []byte

// retransKey mirrors `struct retrans_key` in retrans.bpf.c byte-for-
// byte. 16 bytes for daddr (v4 in first 4 bytes, v6 full 16) +
// 2 bytes dport + 2 bytes family = 20 bytes total, no padding.
type retransKey struct {
	Daddr  [16]byte
	DPort  uint16
	Family uint16
}

// defaultRetransWindow is the BPF-map sample interval. Picked at 60s
// because it's the smallest window that keeps single-packet
// retransmits from spiking into the alert path while still being
// short enough to surface a developing problem before the operator
// notices via end-user complaints.
const defaultRetransWindow = 60 * time.Second

// envRetransWindow returns the operator-configured window or the
// default. Parse failure → default; we don't want a malformed env
// var to silently make the probe never tick.
func envRetransWindow() time.Duration {
	v := os.Getenv("MILOG_PROBE_RETRANS_WINDOW")
	if v == "" {
		return defaultRetransWindow
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return defaultRetransWindow
	}
	return d
}

// RunRetrans loads the retransmit probe, attaches
// tracepoint:tcp:tcp_retransmit_skb, and ticks every window emitting
// RetransEvents for any (daddr, dport) pair whose count grew since
// the last sample. Threshold filtering happens in MatchRetrans —
// the loader emits all non-zero deltas.
//
// The tracepoint is non-fatal-but-useful — older kernels (<4.16)
// don't have it. attach failure surfaces as the goroutine error
// and milog-probe logs "retransmit coverage degraded".
func RunRetrans(ctx context.Context, out chan<- RetransEvent) error {
	if len(retransBpfObj) == 0 {
		return errors.New("probe: bpf/retrans.bpf.o is empty — rebuild with clang available (apt install clang llvm libbpf-dev)")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("probe: remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(retransBpfObj))
	if err != nil {
		return fmt.Errorf("probe: load retrans BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("probe: instantiate retrans BPF collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_retransmit"]
	if prog == nil {
		return errors.New("probe: BPF program 'handle_retransmit' missing from object")
	}

	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", prog, nil)
	if err != nil {
		return fmt.Errorf("probe: attach tracepoint tcp/tcp_retransmit_skb: %w", err)
	}
	defer tp.Close()

	countsMap := coll.Maps["retrans_counts"]
	if countsMap == nil {
		return errors.New("probe: BPF map 'retrans_counts' missing from object")
	}

	window := envRetransWindow()
	// lastSeen caches the previous sample's count per key so we can
	// emit deltas rather than absolute totals. A new key (not in the
	// map) implies last=0, so the first observation registers as a
	// delta equal to the count itself — which is correct: that's
	// how many retransmits happened in the most recent window.
	lastSeen := make(map[retransKey]uint64, 64)

	ticker := time.NewTicker(window)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := emitRetransDeltas(ctx, countsMap, lastSeen, window, out); err != nil {
				return fmt.Errorf("probe: retrans tick: %w", err)
			}
		}
	}
}

// emitRetransDeltas walks the BPF count map once, computes the
// delta vs the previous sample for each key, and pushes a
// RetransEvent for any non-zero delta. LRU eviction can drop keys
// out from under us — we lazily age out lastSeen entries that
// disappeared from the BPF map to keep the cache from growing
// unbounded over a long-running probe.
func emitRetransDeltas(
	ctx context.Context,
	m *ebpf.Map,
	lastSeen map[retransKey]uint64,
	window time.Duration,
	out chan<- RetransEvent,
) error {
	seen := make(map[retransKey]struct{}, len(lastSeen))

	iter := m.Iterate()
	var key retransKey
	var count uint64
	for iter.Next(&key, &count) {
		seen[key] = struct{}{}
		prev := lastSeen[key]
		// Counter wraparound on uint64 is theoretical (2^64 events
		// at 1ns each = 584 years) — but a kernel-side reset, key
		// re-insertion after LRU eviction, or sample skip during
		// userspace shutdown could produce count < prev. Treat that
		// as "no delta" rather than emitting a wraparound event.
		if count < prev {
			lastSeen[key] = count
			continue
		}
		delta := count - prev
		lastSeen[key] = count
		if delta == 0 {
			continue
		}

		ev := RetransEvent{
			DPort:  key.DPort,
			Count:  delta,
			Window: window,
		}
		switch key.Family {
		case afInet:
			ev.DAddr = net.IP(key.Daddr[:4]).String()
			ev.IsIPv6 = false
		case afInet6:
			ev.DAddr = net.IP(key.Daddr[:]).String()
			ev.IsIPv6 = true
		default:
			// BPF-side already filters AF_INET / AF_INET6 — getting
			// here means a kernel bug or layout drift; skip rather
			// than emit garbage.
			continue
		}

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("retrans map iterate: %w", err)
	}

	// Age-out: anything in lastSeen that's NOT in seen disappeared
	// from the BPF map (LRU evicted, or we picked it up during a
	// rare empty interval and the key was reused). Drop it from
	// our cache so memory doesn't grow.
	for k := range lastSeen {
		if _, ok := seen[k]; !ok {
			delete(lastSeen, k)
		}
	}
	return nil
}

