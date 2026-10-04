//go:build linux

// Loader for the TCP retransmit probe. No ring buffer: BPF increments an
// LRU hash of per-destination counts (4096 entries) that Go samples each
// window, so event volume scales with destinations, not packets.

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

// retransKey must match struct retrans_key in retrans.bpf.c: 16-byte daddr
// (v4 in the first 4), 2-byte dport, 2-byte family, no padding.
type retransKey struct {
	Daddr  [16]byte
	DPort  uint16
	Family uint16
}

// defaultRetransWindow is the sample interval.
const defaultRetransWindow = 60 * time.Second

// envRetransWindow falls back to the default on a bad value so the probe
// keeps ticking.
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

// RunRetrans attaches tcp:tcp_retransmit_skb (kernel 4.16+) and emits a
// RetransEvent per destination whose count grew; MatchRetrans applies the
// threshold.
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
	// Previous count per key; a new key counts from 0.
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

// emitRetransDeltas emits non-zero deltas and forgets keys the LRU evicted.
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
		// A shrinking count means a reset or LRU re-insertion, not
		// wraparound; treat it as no delta.
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
			// BPF already filters other families; this means layout drift.
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

	for k := range lastSeen {
		if _, ok := seen[k]; !ok {
			delete(lastSeen, k)
		}
	}
	return nil
}

