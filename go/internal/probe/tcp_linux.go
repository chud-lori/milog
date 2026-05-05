//go:build linux

// tcp_linux.go — userspace loader for the tcp connect probe.
//
// Mirrors the structure of exec_linux.go: load embedded BPF object,
// attach a tracepoint, stream events into a Go channel until the ctx
// is cancelled. Lives in a separate file (and uses a separate ring
// buffer + map name) so a verifier-reject on one program doesn't block
// the other from loading.

package probe

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/tcp.bpf.o
var tcpBpfObj []byte

// tcpRawEvent is the binary layout written by the BPF program. Field
// order, sizes, and padding match `struct tcp_event` in tcp.bpf.c. A
// drift between the two is silent corruption — the probe would emit
// alerts with the wrong port, comm, or destination IP.
//
// The 4-byte ints (Family, DPort) are wider than they need to be on
// the wire (Family is u16-equivalent, DPort is u16) — bumped to u32
// so the struct is naturally 4-byte aligned and we don't need explicit
// padding bytes. The C side declares them the same way for symmetry.
type tcpRawEvent struct {
	PID     uint32
	UID     uint32
	Family  uint32
	DPort   uint32
	DaddrV4 [4]byte
	DaddrV6 [16]byte
	Comm    [commLen]byte
}

// AF_INET / AF_INET6 — same constants the kernel uses. Hardcoded
// rather than imported from `golang.org/x/sys/unix` to keep the probe
// dependency-light (cilium/ebpf is the only non-stdlib import here
// that actually pulls in foreign code). Left UNTYPED so they
// implicit-convert against either uint32 (tcp probe) or uint16
// (retrans probe, which packs Family into a 16-bit hash-key field).
const (
	afInet  = 2
	afInet6 = 10
)

// RunNet loads the tcp connect probe, attaches the
// sock:inet_sock_set_state tracepoint, and streams matched NetEvents
// into `out` until ctx is cancelled. Errors out on a verifier reject
// or rlimit failure — milog-probe surfaces the error and lets systemd
// restart it.
//
// Designed to run alongside Run() in a separate goroutine; both
// programs live in independent collections so a load failure on one
// doesn't take down the other.
func RunNet(ctx context.Context, out chan<- NetEvent) error {
	if len(tcpBpfObj) == 0 {
		return errors.New("probe: bpf/tcp.bpf.o is empty — rebuild with clang available (apt install clang llvm libbpf-dev)")
	}

	// rlimit.RemoveMemlock is idempotent — calling it again from
	// RunNet after Run already did is harmless. Cheaper than
	// requiring callers to coordinate.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("probe: remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tcpBpfObj))
	if err != nil {
		return fmt.Errorf("probe: load tcp BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("probe: instantiate tcp BPF collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_inet_sock_set_state"]
	if prog == nil {
		return errors.New("probe: BPF program 'handle_inet_sock_set_state' missing from object")
	}

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", prog, nil)
	if err != nil {
		return fmt.Errorf("probe: attach tracepoint sock/inet_sock_set_state: %w", err)
	}
	defer tp.Close()

	rb, err := ringbuf.NewReader(coll.Maps["tcp_events"])
	if err != nil {
		return fmt.Errorf("probe: open tcp ring buffer: %w", err)
	}
	defer rb.Close()

	go func() {
		<-ctx.Done()
		_ = rb.Close()
	}()

	for {
		rec, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("probe: tcp ringbuf read: %w", err)
		}
		if len(rec.RawSample) < binary.Size(tcpRawEvent{}) {
			continue
		}
		var raw tcpRawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		ev := NetEvent{
			PID:   raw.PID,
			UID:   raw.UID,
			DPort: uint16(raw.DPort),
			Comm:  trimNul(raw.Comm[:]),
		}
		switch raw.Family {
		case afInet:
			ev.DAddr = net.IP(raw.DaddrV4[:]).String()
			ev.IsIPv6 = false
		case afInet6:
			ev.DAddr = net.IP(raw.DaddrV6[:]).String()
			ev.IsIPv6 = true
		default:
			// BPF side already filters AF_INET / AF_INET6 — getting
			// here means a kernel-side bug or a layout drift. Skip
			// rather than emit a garbage event.
			continue
		}
		// /proc lookup for ParentComm — same userspace-cheap pattern
		// as the exec probe. Useful in alert bodies for "which web
		// worker spawned this connect?" forensics.
		ev.PPID, ev.ParentComm = lookupParent(raw.PID)

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}
