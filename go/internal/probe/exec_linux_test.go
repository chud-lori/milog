//go:build linux

// Smoke tests for the embedded BPF exec probe. Two tiers, deliberate:
//
//   - TestExecBpfObject_Spec — parses the embedded .bpf.o without
//     touching the kernel. Catches structural regressions (renamed
//     program, missing map, wrong section, dropped license) on every
//     PR. Runs as the non-root CI user; no privileges required.
//
//   - TestExecBpfObject_KernelLoad — actually loads the program into
//     the runner's kernel via cilium/ebpf. Catches "compiles clean
//     but the verifier rejects on this kernel" — the regression class
//     that makes BPF painful in production. Skips when EUID != 0
//     because BPF program loading needs CAP_BPF; CI invokes this test
//     in a separate `sudo go test ...` step (see ci.yml) so the
//     non-sudo run stays green for everyone.
//
// Together they keep iteration on the BPF C side honest without
// requiring the user's Linux box in the loop for every change.

package probe

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestExecBpfObject_Spec(t *testing.T) {
	if len(execBpfObj) == 0 {
		t.Fatal("execBpfObj is empty — build.sh didn't produce bpf/exec.bpf.o " +
			"(install clang + libbpf-dev and re-run `bash build.sh`)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(execBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader: %v", err)
	}

	// Program shape — name + type. Both are load-bearing for the
	// userspace attach call (link.Tracepoint(prog, …)) and for the
	// audit alert path; renaming either silently breaks production.
	prog, ok := spec.Programs["handle_exec"]
	if !ok {
		t.Fatalf("expected program 'handle_exec', got: %v", programNames(spec))
	}
	if prog.Type != ebpf.TracePoint {
		t.Errorf("handle_exec.Type = %v, want TracePoint", prog.Type)
	}

	// Map shape — name, type, capacity floor. The 64 KiB floor is a
	// loose guard: the C side declares 256 KiB; if a future tweak
	// drops below, the userspace ring reader will start dropping
	// events under sustained exec storms long before anyone notices.
	m, ok := spec.Maps["events"]
	if !ok {
		t.Fatalf("expected map 'events', got: %v", mapNames(spec))
	}
	if m.Type != ebpf.RingBuf {
		t.Errorf("events.Type = %v, want RingBuf", m.Type)
	}
	if m.MaxEntries < 64*1024 {
		t.Errorf("events.MaxEntries = %d, want >= 65536", m.MaxEntries)
	}
}

func TestExecBpfObject_KernelLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF) — see ci.yml's sudo step")
	}
	// Removing the locked-memory rlimit is the same prep the production
	// loader does. Without it, BPF map allocation fails with EPERM on
	// older kernels; on recent ones the limit is unlimited by default
	// for root, but stay defensive.
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(execBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// Surface verifier errors verbatim — they're the most useful
		// signal when iterating on the BPF C side. Other errors get
		// the standard %v.
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("BPF verifier rejected handle_exec on kernel %s:\n%+v", uname(), verr)
		}
		t.Fatalf("NewCollection on kernel %s: %v", uname(), err)
	}
	defer coll.Close()

	// Sanity-check that the loaded collection still has handle_exec.
	// This catches a different bug class than the spec test: the spec
	// said "handle_exec exists" but loading silently dropped it (very
	// unlikely with current cilium/ebpf, but free to assert).
	if _, ok := coll.Programs["handle_exec"]; !ok {
		t.Errorf("loaded collection missing program 'handle_exec'")
	}
}

// uname returns "uname -r" output for verifier-error context, falling
// back to a marker string when the file isn't readable. Only used in
// failure messages, so a missing read is non-fatal.
func uname() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return string(bytes.TrimSpace(b))
}

func programNames(spec *ebpf.CollectionSpec) []string {
	out := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		out = append(out, n)
	}
	return out
}

func mapNames(spec *ebpf.CollectionSpec) []string {
	out := make([]string, 0, len(spec.Maps))
	for n := range spec.Maps {
		out = append(out, n)
	}
	return out
}

// =============================================================================
// tcp connect probe — same two-tier shape as the exec probe above.
// =============================================================================

func TestTcpBpfObject_Spec(t *testing.T) {
	if len(tcpBpfObj) == 0 {
		t.Fatal("tcpBpfObj is empty — build.sh didn't produce bpf/tcp.bpf.o " +
			"(install clang + libbpf-dev and re-run `bash build.sh`)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tcpBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (tcp): %v", err)
	}

	prog, ok := spec.Programs["handle_inet_sock_set_state"]
	if !ok {
		t.Fatalf("expected program 'handle_inet_sock_set_state', got: %v", programNames(spec))
	}
	if prog.Type != ebpf.TracePoint {
		t.Errorf("handle_inet_sock_set_state.Type = %v, want TracePoint", prog.Type)
	}

	m, ok := spec.Maps["tcp_events"]
	if !ok {
		t.Fatalf("expected map 'tcp_events', got: %v", mapNames(spec))
	}
	if m.Type != ebpf.RingBuf {
		t.Errorf("tcp_events.Type = %v, want RingBuf", m.Type)
	}
	if m.MaxEntries < 64*1024 {
		t.Errorf("tcp_events.MaxEntries = %d, want >= 65536", m.MaxEntries)
	}
}

func TestTcpBpfObject_KernelLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF) — see ci.yml's sudo step")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tcpBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (tcp): %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("BPF verifier rejected handle_inet_sock_set_state on kernel %s:\n%+v", uname(), verr)
		}
		t.Fatalf("NewCollection (tcp) on kernel %s: %v", uname(), err)
	}
	defer coll.Close()
	if _, ok := coll.Programs["handle_inet_sock_set_state"]; !ok {
		t.Errorf("loaded collection missing program 'handle_inet_sock_set_state'")
	}
}

// =============================================================================
// file audit probe — same two-tier shape.
// =============================================================================

func TestFileBpfObject_Spec(t *testing.T) {
	if len(fileBpfObj) == 0 {
		t.Fatal("fileBpfObj is empty — build.sh didn't produce bpf/file.bpf.o " +
			"(install clang + libbpf-dev and re-run `bash build.sh`)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(fileBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (file): %v", err)
	}

	prog, ok := spec.Programs["handle_openat"]
	if !ok {
		t.Fatalf("expected program 'handle_openat', got: %v", programNames(spec))
	}
	if prog.Type != ebpf.TracePoint {
		t.Errorf("handle_openat.Type = %v, want TracePoint", prog.Type)
	}

	m, ok := spec.Maps["file_events"]
	if !ok {
		t.Fatalf("expected map 'file_events', got: %v", mapNames(spec))
	}
	if m.Type != ebpf.RingBuf {
		t.Errorf("file_events.Type = %v, want RingBuf", m.Type)
	}
	if m.MaxEntries < 64*1024 {
		t.Errorf("file_events.MaxEntries = %d, want >= 65536", m.MaxEntries)
	}
}

func TestFileBpfObject_KernelLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF) — see ci.yml's sudo step")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(fileBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (file): %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("BPF verifier rejected handle_openat on kernel %s:\n%+v", uname(), verr)
		}
		t.Fatalf("NewCollection (file) on kernel %s: %v", uname(), err)
	}
	defer coll.Close()
	if _, ok := coll.Programs["handle_openat"]; !ok {
		t.Errorf("loaded collection missing program 'handle_openat'")
	}
}

// =============================================================================
// ptrace anti-injection probe — same two-tier shape.
// =============================================================================

func TestPtraceBpfObject_Spec(t *testing.T) {
	if len(ptraceBpfObj) == 0 {
		t.Fatal("ptraceBpfObj is empty — build.sh didn't produce bpf/ptrace.bpf.o " +
			"(install clang + libbpf-dev and re-run `bash build.sh`)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ptraceBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (ptrace): %v", err)
	}

	prog, ok := spec.Programs["handle_ptrace"]
	if !ok {
		t.Fatalf("expected program 'handle_ptrace', got: %v", programNames(spec))
	}
	if prog.Type != ebpf.TracePoint {
		t.Errorf("handle_ptrace.Type = %v, want TracePoint", prog.Type)
	}

	m, ok := spec.Maps["ptrace_events"]
	if !ok {
		t.Fatalf("expected map 'ptrace_events', got: %v", mapNames(spec))
	}
	if m.Type != ebpf.RingBuf {
		t.Errorf("ptrace_events.Type = %v, want RingBuf", m.Type)
	}
	if m.MaxEntries < 16*1024 {
		t.Errorf("ptrace_events.MaxEntries = %d, want >= 16384", m.MaxEntries)
	}
}

func TestPtraceBpfObject_KernelLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF) — see ci.yml's sudo step")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ptraceBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (ptrace): %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("BPF verifier rejected handle_ptrace on kernel %s:\n%+v", uname(), verr)
		}
		t.Fatalf("NewCollection (ptrace) on kernel %s: %v", uname(), err)
	}
	defer coll.Close()
	if _, ok := coll.Programs["handle_ptrace"]; !ok {
		t.Errorf("loaded collection missing program 'handle_ptrace'")
	}
}

// =============================================================================
// Kernel module load probe — same two-tier shape.
// =============================================================================

func TestKmodBpfObject_Spec(t *testing.T) {
	if len(kmodBpfObj) == 0 {
		t.Fatal("kmodBpfObj is empty — build.sh didn't produce bpf/kmod.bpf.o " +
			"(install clang + libbpf-dev and re-run `bash build.sh`)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(kmodBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (kmod): %v", err)
	}

	prog, ok := spec.Programs["handle_module_load"]
	if !ok {
		t.Fatalf("expected program 'handle_module_load', got: %v", programNames(spec))
	}
	if prog.Type != ebpf.TracePoint {
		t.Errorf("handle_module_load.Type = %v, want TracePoint", prog.Type)
	}

	m, ok := spec.Maps["kmod_events"]
	if !ok {
		t.Fatalf("expected map 'kmod_events', got: %v", mapNames(spec))
	}
	if m.Type != ebpf.RingBuf {
		t.Errorf("kmod_events.Type = %v, want RingBuf", m.Type)
	}
	if m.MaxEntries < 16*1024 {
		t.Errorf("kmod_events.MaxEntries = %d, want >= 16384", m.MaxEntries)
	}
}

func TestKmodBpfObject_KernelLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF) — see ci.yml's sudo step")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(kmodBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (kmod): %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("BPF verifier rejected handle_module_load on kernel %s:\n%+v", uname(), verr)
		}
		t.Fatalf("NewCollection (kmod) on kernel %s: %v", uname(), err)
	}
	defer coll.Close()
	if _, ok := coll.Programs["handle_module_load"]; !ok {
		t.Errorf("loaded collection missing program 'handle_module_load'")
	}
}

// =============================================================================
// TCP retransmit observability probe — same two-tier shape, but the
// map is LRU_HASH instead of RingBuf since this probe samples rather
// than streams.
// =============================================================================

func TestRetransBpfObject_Spec(t *testing.T) {
	if len(retransBpfObj) == 0 {
		t.Fatal("retransBpfObj is empty — build.sh didn't produce bpf/retrans.bpf.o " +
			"(install clang + libbpf-dev and re-run `bash build.sh`)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(retransBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (retrans): %v", err)
	}

	prog, ok := spec.Programs["handle_retransmit"]
	if !ok {
		t.Fatalf("expected program 'handle_retransmit', got: %v", programNames(spec))
	}
	if prog.Type != ebpf.TracePoint {
		t.Errorf("handle_retransmit.Type = %v, want TracePoint", prog.Type)
	}

	m, ok := spec.Maps["retrans_counts"]
	if !ok {
		t.Fatalf("expected map 'retrans_counts', got: %v", mapNames(spec))
	}
	if m.Type != ebpf.LRUHash {
		t.Errorf("retrans_counts.Type = %v, want LRUHash", m.Type)
	}
	// 1024-entry floor — well below the BPF-side 4096 declaration so
	// regressions that drop the cap (e.g. someone tightens it during
	// memory tuning) still leave reasonable headroom.
	if m.MaxEntries < 1024 {
		t.Errorf("retrans_counts.MaxEntries = %d, want >= 1024", m.MaxEntries)
	}
}

func TestRetransBpfObject_KernelLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF) — see ci.yml's sudo step")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(retransBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (retrans): %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("BPF verifier rejected handle_retransmit on kernel %s:\n%+v", uname(), verr)
		}
		t.Fatalf("NewCollection (retrans) on kernel %s: %v", uname(), err)
	}
	defer coll.Close()
	if _, ok := coll.Programs["handle_retransmit"]; !ok {
		t.Errorf("loaded collection missing program 'handle_retransmit'")
	}
}
