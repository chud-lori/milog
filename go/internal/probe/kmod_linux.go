//go:build linux

// Loader for the kernel-module load probe (module:module_load).

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

//go:embed bpf/kmod.bpf.o
var kmodBpfObj []byte

// kmodNameLen matches NAME_LEN in kmod.bpf.c. The kernel's MODULE_NAME_LEN
// is 64 - sizeof(unsigned long), so 64 bytes always fits.
const kmodNameLen = 64

// kmodRawEvent mirrors `struct kmod_event` in kmod.bpf.c.
type kmodRawEvent struct {
	PID  uint32
	UID  uint32
	Comm [commLen]byte
	Name [kmodNameLen]byte
}

// RunKmod attaches module:module_load and sends KmodEvents until ctx is cancelled.
func RunKmod(ctx context.Context, out chan<- KmodEvent) error {
	if len(kmodBpfObj) == 0 {
		return errors.New("probe: bpf/kmod.bpf.o is empty — rebuild with clang available (apt install clang llvm libbpf-dev)")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("probe: remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(kmodBpfObj))
	if err != nil {
		return fmt.Errorf("probe: load kmod BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("probe: instantiate kmod BPF collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_module_load"]
	if prog == nil {
		return errors.New("probe: BPF program 'handle_module_load' missing from object")
	}

	tp, err := link.Tracepoint("module", "module_load", prog, nil)
	if err != nil {
		return fmt.Errorf("probe: attach tracepoint module/module_load: %w", err)
	}
	defer tp.Close()

	rb, err := ringbuf.NewReader(coll.Maps["kmod_events"])
	if err != nil {
		return fmt.Errorf("probe: open kmod ring buffer: %w", err)
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
			return fmt.Errorf("probe: kmod ringbuf read: %w", err)
		}
		if len(rec.RawSample) < binary.Size(kmodRawEvent{}) {
			continue
		}
		var raw kmodRawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		ev := KmodEvent{
			PID:    raw.PID,
			UID:    raw.UID,
			Comm:   trimNul(raw.Comm[:]),
			Module: trimNul(raw.Name[:]),
		}
		ev.PPID, ev.ParentComm = lookupParent(raw.PID)

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}
