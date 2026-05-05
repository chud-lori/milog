//go:build linux

// bpfload_linux.go — userspace loader for the BPF-program-load probe.
// Streaming shape (ringbuf), same as ptrace / kmod — load events are
// rare on a healthy host so per-event delivery is cheap.

package probe

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/bpfload.bpf.o
var bpfLoadBpfObj []byte

// bpfLoadRawEvent mirrors `struct bpfload_event` in bpfload.bpf.c
// byte-for-byte.
type bpfLoadRawEvent struct {
	PID  uint32
	UID  uint32
	Cmd  uint32
	Comm [commLen]byte
}

// RunBpfLoad loads the bpf-load probe, attaches sys_enter_bpf, and
// streams BpfLoadEvents into `out` until ctx is cancelled.
func RunBpfLoad(ctx context.Context, out chan<- BpfLoadEvent) error {
	if len(bpfLoadBpfObj) == 0 {
		return errors.New("probe: bpf/bpfload.bpf.o is empty — rebuild with clang available (apt install clang llvm libbpf-dev)")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("probe: remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfLoadBpfObj))
	if err != nil {
		return fmt.Errorf("probe: load bpfload BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("probe: instantiate bpfload BPF collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_bpf_enter"]
	if prog == nil {
		return errors.New("probe: BPF program 'handle_bpf_enter' missing from object")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_bpf", prog, nil)
	if err != nil {
		return fmt.Errorf("probe: attach tracepoint syscalls/sys_enter_bpf: %w", err)
	}
	defer tp.Close()

	rb, err := ringbuf.NewReader(coll.Maps["bpfload_events"])
	if err != nil {
		return fmt.Errorf("probe: open bpfload ring buffer: %w", err)
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
			return fmt.Errorf("probe: bpfload ringbuf read: %w", err)
		}
		if len(rec.RawSample) < binary.Size(bpfLoadRawEvent{}) {
			continue
		}
		var raw bpfLoadRawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		ev := BpfLoadEvent{
			PID:  raw.PID,
			UID:  raw.UID,
			Cmd:  raw.Cmd,
			Comm: trimNul(raw.Comm[:]),
		}
		ev.PPID, ev.ParentComm = lookupParent(raw.PID)

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}
