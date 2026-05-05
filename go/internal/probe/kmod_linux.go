//go:build linux

// kmod_linux.go — userspace loader for the kernel-module load probe.
// Same shape as the other Run* loaders: load embedded
// bpf/kmod.bpf.o, attach module:module_load, stream `KmodEvent`s
// into a Go channel.

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

// kmodNameLen mirrors NAME_LEN in kmod.bpf.c. Linux module names are
// capped at MODULE_NAME_LEN = 64 (`#define MODULE_NAME_LEN (64-sizeof(unsigned long))`
// in include/linux/module.h on most arches; we round up to 64 for
// alignment, the trailing NULs trim cleanly).
const kmodNameLen = 64

// kmodRawEvent mirrors `struct kmod_event` in kmod.bpf.c.
type kmodRawEvent struct {
	PID  uint32
	UID  uint32
	Comm [commLen]byte
	Name [kmodNameLen]byte
}

// RunKmod loads the kmod probe, attaches module:module_load, and
// streams KmodEvents into `out` until ctx is cancelled. Module load
// is rare on production hosts — this goroutine is mostly idle, ring
// buffer pressure is essentially zero. We still budget 64 KiB for
// it to handle module-storm corner cases (initramfs unpacking on
// custom kernels, dkms rebuilds).
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
