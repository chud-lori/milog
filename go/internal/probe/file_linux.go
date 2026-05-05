//go:build linux

// file_linux.go — userspace loader for the file-audit probe.
//
// Mirrors tcp_linux.go: load embedded bpf/file.bpf.o, attach the
// sys_enter_openat tracepoint, stream `FileEvent`s into a Go channel.
// Coarse prefix filter lives BPF-side (see file.bpf.c); precise
// per-path matching against the configurable sensitive list happens
// in rules.go's MatchFile.
//
// Independent collection so a verifier reject on the file probe doesn't
// take down exec or tcp coverage.

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

//go:embed bpf/file.bpf.o
var fileBpfObj []byte

// fileRawEvent is the binary layout written by handle_openat. Field
// order, sizes, padding match `struct file_event` in file.bpf.c —
// drift here is silent corruption (mis-attributed paths in alerts).
type fileRawEvent struct {
	PID      uint32
	UID      uint32
	Flags    uint32
	Comm     [commLen]byte
	Filename [filenameLen]byte
}

// RunFile loads the file-audit probe, attaches sys_enter_openat, and
// streams matched FileEvents into `out` until ctx is cancelled. Same
// shape as Run / RunNet — three independent goroutines in milog-probe.
func RunFile(ctx context.Context, out chan<- FileEvent) error {
	if len(fileBpfObj) == 0 {
		return errors.New("probe: bpf/file.bpf.o is empty — rebuild with clang available (apt install clang llvm libbpf-dev)")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("probe: remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(fileBpfObj))
	if err != nil {
		return fmt.Errorf("probe: load file BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("probe: instantiate file BPF collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_openat"]
	if prog == nil {
		return errors.New("probe: BPF program 'handle_openat' missing from object")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
	if err != nil {
		return fmt.Errorf("probe: attach tracepoint syscalls/sys_enter_openat: %w", err)
	}
	defer tp.Close()

	rb, err := ringbuf.NewReader(coll.Maps["file_events"])
	if err != nil {
		return fmt.Errorf("probe: open file ring buffer: %w", err)
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
			return fmt.Errorf("probe: file ringbuf read: %w", err)
		}
		if len(rec.RawSample) < binary.Size(fileRawEvent{}) {
			continue
		}
		var raw fileRawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		ev := FileEvent{
			PID:      raw.PID,
			UID:      raw.UID,
			Flags:    raw.Flags,
			Comm:     trimNul(raw.Comm[:]),
			Filename: trimNul(raw.Filename[:]),
		}
		ev.PPID, ev.ParentComm = lookupParent(raw.PID)

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}
