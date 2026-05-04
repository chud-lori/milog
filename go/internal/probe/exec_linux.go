//go:build linux

// Linux-only BPF loader for the exec probe. Compiled into the
// `milog-probe` binary on linux/amd64 + linux/arm64; non-Linux builds
// pick up the stub in exec_other.go.
//
// The compiled BPF object (bpf/exec.bpf.o) is embedded at build time
// via go:embed. build.sh invokes clang to produce it from
// bpf/exec.bpf.c — which means a Linux build host needs `clang` with
// BPF target support (Debian/Ubuntu: `apt install clang llvm`,
// Fedora/Rocky: `dnf install clang llvm`).
//
// On a clean clone before clang has run, exec.bpf.o doesn't exist
// yet; embed will fail at compile time. build.sh handles that by
// running clang first when it's available, and by SKIPPING the probe
// build entirely when it isn't.

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

// commLen / filenameLen mirror the C-side struct exec_event. Keep in
// sync with bpf/exec.bpf.c — a mismatch means we'd misread the ring
// buffer payload and emit garbage filenames into alert bodies.
const (
	commLen     = 16
	filenameLen = 256
)

// rawEvent is the binary layout written by the BPF program into the
// ring buffer. Field order + packing matches struct exec_event in
// bpf/exec.bpf.c byte-for-byte. binary.LittleEndian.Uint32 for the
// pid/uid; the byte arrays come through as-is and we trim at the
// first NUL.
type rawEvent struct {
	PID      uint32
	UID      uint32
	Comm     [commLen]byte
	Filename [filenameLen]byte
}

// Run loads the BPF program, attaches the tracepoint, and streams
// matched Hits into `out` until ctx is cancelled. Caller is expected
// to consume the channel concurrently — a slow consumer will only
// drop in-Go events; the kernel ring buffer auto-recycles when the
// userspace side falls behind.
//
// Errors:
//   - rlimit / map/program load failures (CAP_BPF / CAP_PERFMON missing)
//   - tracepoint attachment failure (kernel without sched_process_exec)
//
// Both surface as "I can't do my job" — milog-probe exits non-zero,
// systemd restarts it, the daemon notices and logs the gap.
func Run(ctx context.Context, out chan<- Event) error {
	if len(execBpfObj) == 0 {
		// Build-time placeholder — clang didn't run before go build.
		// Fail fast with an actionable message rather than emitting
		// nothing forever.
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

	// Cancellation: ring buffer Read() blocks; closing the reader on
	// ctx.Done unblocks it with ErrClosed. Single goroutine to keep
	// shutdown ordering simple.
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
			// Truncated — should never happen with our fixed-size
			// struct, but sanity-check rather than panic on a
			// kernel-side bug.
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
		// PPID + parent comm are cheaper to read in userspace than
		// to add CO-RE chain reads to the BPF program. /proc reads
		// happen on the consumer goroutine, not the BPF hot path —
		// a slow /proc read just delays this one event, doesn't
		// block the kernel ringbuf producer.
		ev.PPID, ev.ParentComm = lookupParent(raw.PID)
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// trimNul slices off the trailing NUL bytes from a fixed-size kernel
// string. bpf_get_current_comm + bpf_probe_read_kernel_str both
// guarantee NUL termination; we trim everything from the first NUL on.
func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// lookupParent reads /proc/<pid>/status for PPid + /proc/<ppid>/comm.
// Returns (0, "") when the child has already exited or the parent
// can't be read — both are fine, the rule engine treats unknown parent
// as "not allowlisted, not a web worker" → matches no rules.
//
// We accept the inherent race: by the time the userspace consumer
// sees the event, the parent might have died and PPID rolled to 1
// (init). For our security-monitoring use case that just means the
// alert occasionally lacks parent context — a worse failure mode would
// be holding state in the BPF program for every running process.
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
