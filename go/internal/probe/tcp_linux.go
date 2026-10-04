//go:build linux

// Loader for the tcp connect probe, in its own collection and ring buffer so
// a verifier reject doesn't affect the other probes.

package probe

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/tcp.bpf.o
var tcpBpfObj []byte

// tcpRawEvent must match struct tcp_event in tcp.bpf.c; a mismatch silently
// garbles ports and addresses. Family and DPort are u32 on both sides for
// natural alignment.
type tcpRawEvent struct {
	PID     uint32
	UID     uint32
	Family  uint32
	DPort   uint32
	DaddrV4 [4]byte
	DaddrV6 [16]byte
	Comm    [commLen]byte
}

// Untyped so they compare against both uint32 (tcp) and uint16 (retrans)
// fields; hardcoded to avoid pulling in x/sys/unix.
const (
	afInet  = 2
	afInet6 = 10
)

// RunNet attaches sock:inet_sock_set_state and sends a NetEvent per outbound
// connect until ctx is cancelled; load and attach failures are returned.
func RunNet(ctx context.Context, out chan<- NetEvent) error {
	if len(tcpBpfObj) == 0 {
		return errors.New("probe: bpf/tcp.bpf.o is empty — rebuild with clang available (apt install clang llvm libbpf-dev)")
	}

	// RemoveMemlock is idempotent, so each loader can call it.
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
			// BPF already filters other families; this means layout drift.
			continue
		}
		ev.PPID, ev.ParentComm = lookupParent(raw.PID)
		ev.Exe, ev.Cgroup = lookupExeCgroup(raw.PID)

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// lookupExeCgroup returns ("", "") for whatever is gone, which
// isMilogDelivery treats as not milog's.
func lookupExeCgroup(pid uint32) (exe, cgroup string) {
	dir := "/proc/" + strconv.FormatUint(uint64(pid), 10)
	exe, _ = os.Readlink(dir + "/exe")
	if data, err := os.ReadFile(dir + "/cgroup"); err == nil {
		cgroup = cgroupPath(string(data))
	}
	return exe, cgroup
}
