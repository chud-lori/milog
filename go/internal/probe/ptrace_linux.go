//go:build linux

// ptrace_linux.go — userspace loader for the ptrace anti-injection
// probe. Same shape as file_linux.go: load embedded bpf/ptrace.bpf.o,
// attach the sys_enter_ptrace tracepoint, stream `PtraceEvent`s into a
// Go channel.
//
// Independent collection so a verifier reject on this probe doesn't
// take down exec / tcp / file coverage.

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

//go:embed bpf/ptrace.bpf.o
var ptraceBpfObj []byte

// ptraceRawEvent mirrors `struct ptrace_event` in ptrace.bpf.c byte-
// for-byte. Drift here = silently misattributed alerts (wrong target
// pid, wrong request code).
type ptraceRawEvent struct {
	PID       uint32
	UID       uint32
	TargetPID uint32
	Request   uint32
	Comm      [commLen]byte
}

// RunPtrace loads the ptrace probe, attaches sys_enter_ptrace, and
// streams matched PtraceEvents into `out` until ctx is cancelled.
// Same signature shape as Run / RunNet / RunFile — milog-probe
// supervises via a fourth independent goroutine.
func RunPtrace(ctx context.Context, out chan<- PtraceEvent) error {
	if len(ptraceBpfObj) == 0 {
		return errors.New("probe: bpf/ptrace.bpf.o is empty — rebuild with clang available (apt install clang llvm libbpf-dev)")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("probe: remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ptraceBpfObj))
	if err != nil {
		return fmt.Errorf("probe: load ptrace BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("probe: instantiate ptrace BPF collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_ptrace"]
	if prog == nil {
		return errors.New("probe: BPF program 'handle_ptrace' missing from object")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_ptrace", prog, nil)
	if err != nil {
		return fmt.Errorf("probe: attach tracepoint syscalls/sys_enter_ptrace: %w", err)
	}
	defer tp.Close()

	rb, err := ringbuf.NewReader(coll.Maps["ptrace_events"])
	if err != nil {
		return fmt.Errorf("probe: open ptrace ring buffer: %w", err)
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
			return fmt.Errorf("probe: ptrace ringbuf read: %w", err)
		}
		if len(rec.RawSample) < binary.Size(ptraceRawEvent{}) {
			continue
		}
		var raw ptraceRawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		ev := PtraceEvent{
			PID:       raw.PID,
			UID:       raw.UID,
			TargetPID: raw.TargetPID,
			Request:   raw.Request,
			Comm:      trimNul(raw.Comm[:]),
		}
		ev.PPID, ev.ParentComm = lookupParent(raw.PID)

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}
