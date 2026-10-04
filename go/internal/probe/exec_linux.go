//go:build linux

// Linux loader for the exec probe. bpf/exec.bpf.o is embedded at build time;
// build.sh compiles it with clang and skips milog-probe when clang is missing.

package probe

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/exec.bpf.o
var execBpfObj []byte

// commLen and filenameLen must match struct exec_event in bpf/exec.bpf.c.
const (
	commLen     = 16
	filenameLen = 256
)

// rawEvent matches struct exec_event byte for byte; strings are cut at the first NUL.
type rawEvent struct {
	PID      uint32
	UID      uint32
	Comm     [commLen]byte
	Filename [filenameLen]byte
}

// Run attaches sched_process_exec and sends an Event per exec on out until
// ctx is cancelled. Sends block, so a slow consumer backs up the ring buffer
// and the kernel drops events once it is full. Load or attach failures
// (missing CAP_BPF/CAP_PERFMON, no tracepoint) are returned.
func Run(ctx context.Context, out chan<- Event) error {
	if len(execBpfObj) == 0 {
		// The object is empty when clang didn't run before go build.
		return errors.New("probe: bpf/exec.bpf.o is empty — rebuild with clang available (apt install clang llvm)")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("probe: remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(execBpfObj))
	if err != nil {
		return fmt.Errorf("probe: load BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("probe: instantiate BPF collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_exec"]
	if prog == nil {
		return errors.New("probe: BPF program 'handle_exec' missing from object")
	}

	tp, err := link.Tracepoint("sched", "sched_process_exec", prog, nil)
	if err != nil {
		return fmt.Errorf("probe: attach tracepoint sched/sched_process_exec: %w", err)
	}
	defer tp.Close()

	rb, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("probe: open ring buffer: %w", err)
	}
	defer rb.Close()

	// Closing the reader on cancel unblocks Read with ErrClosed.
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
			return fmt.Errorf("probe: ringbuf read: %w", err)
		}
		if len(rec.RawSample) < int(binary.Size(rawEvent{})) {
			// Truncated record; skip rather than panic.
			continue
		}
		var raw rawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		ev := Event{
			PID:      raw.PID,
			UID:      raw.UID,
			Comm:     trimNul(raw.Comm[:]),
			Filename: trimNul(raw.Filename[:]),
		}
		// Parent info comes from /proc here instead of CO-RE reads in
		// BPF; a slow read delays only this event.
		ev.PPID, ev.ParentComm = lookupParent(raw.PID)
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// trimNul cuts a fixed-size kernel string at its first NUL.
func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// lookupParent returns the PPid and parent comm from /proc, or (0, "") if
// either is gone; parent-based rules then don't match. The parent may
// already have exited, leaving ppid 1, which only costs alert context.
func lookupParent(pid uint32) (uint32, string) {
	statusPath := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/status"
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, ""
	}
	var ppid uint32
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		v, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			break
		}
		ppid = uint32(v)
		break
	}
	if ppid == 0 {
		return 0, ""
	}
	commPath := "/proc/" + strconv.FormatUint(uint64(ppid), 10) + "/comm"
	commBytes, err := os.ReadFile(commPath)
	if err != nil {
		return ppid, ""
	}
	return ppid, strings.TrimSpace(string(commBytes))
}
