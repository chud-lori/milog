//go:build linux

// BPF object tests. *_Spec parses the embedded .bpf.o without the kernel
// and runs as any user; *_KernelLoad loads it to catch verifier rejects,
// skips without root, and runs under sudo in a separate CI step.

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

	// The attach call depends on the program name and type.
	prog, ok := spec.Programs["handle_exec"]
	if !ok {
		t.Fatalf("expected program 'handle_exec', got: %v", programNames(spec))
	}
	if prog.Type != ebpf.TracePoint {
		t.Errorf("handle_exec.Type = %v, want TracePoint", prog.Type)
	}

	// Loose 64 KiB floor (C declares 256 KiB); smaller drops events in exec storms.
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
	// Older kernels need the memlock rlimit removed to allocate maps.
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(execBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// Print verifier logs verbatim; they're the useful part.
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("BPF verifier rejected handle_exec on kernel %s:\n%+v", uname(), verr)
		}
		t.Fatalf("NewCollection on kernel %s: %v", uname(), err)
	}
	defer coll.Close()

	if _, ok := coll.Programs["handle_exec"]; !ok {
		t.Errorf("loaded collection missing program 'handle_exec'")
	}
}

// uname returns the kernel release for verifier-error messages.
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
	// 1024-entry floor, well under the declared 4096.
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

func TestSyscallBpfObject_Spec(t *testing.T) {
	if len(syscallBpfObj) == 0 {
		t.Fatal("syscallBpfObj is empty — build.sh didn't produce bpf/syscall.bpf.o " +
			"(install clang + libbpf-dev and re-run `bash build.sh`)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (syscall): %v", err)
	}

	prog, ok := spec.Programs["handle_sys_enter"]
	if !ok {
		t.Fatalf("expected program 'handle_sys_enter', got: %v", programNames(spec))
	}
	// A raw tracepoint, not tracepoint/raw_syscalls/sys_enter, avoids
	// per-event argument formatting cost.
	if prog.Type != ebpf.RawTracepoint {
		t.Errorf("handle_sys_enter.Type = %v, want RawTracepoint", prog.Type)
	}

	m, ok := spec.Maps["syscall_counts"]
	if !ok {
		t.Fatalf("expected map 'syscall_counts', got: %v", mapNames(spec))
	}
	if m.Type != ebpf.LRUCPUHash {
		t.Errorf("syscall_counts.Type = %v, want LRUCPUHash", m.Type)
	}
	if m.MaxEntries < 4096 {
		t.Errorf("syscall_counts.MaxEntries = %d, want >= 4096", m.MaxEntries)
	}
}

func TestSyscallBpfObject_KernelLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF) — see ci.yml's sudo step")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (syscall): %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("BPF verifier rejected handle_sys_enter on kernel %s:\n%+v", uname(), verr)
		}
		t.Fatalf("NewCollection (syscall) on kernel %s: %v", uname(), err)
	}
	defer coll.Close()
	if _, ok := coll.Programs["handle_sys_enter"]; !ok {
		t.Errorf("loaded collection missing program 'handle_sys_enter'")
	}
}

func TestBpfLoadBpfObject_Spec(t *testing.T) {
	if len(bpfLoadBpfObj) == 0 {
		t.Fatal("bpfLoadBpfObj is empty — build.sh didn't produce bpf/bpfload.bpf.o " +
			"(install clang + libbpf-dev and re-run `bash build.sh`)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfLoadBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (bpfload): %v", err)
	}

	prog, ok := spec.Programs["handle_bpf_enter"]
	if !ok {
		t.Fatalf("expected program 'handle_bpf_enter', got: %v", programNames(spec))
	}
	if prog.Type != ebpf.TracePoint {
		t.Errorf("handle_bpf_enter.Type = %v, want TracePoint", prog.Type)
	}

	m, ok := spec.Maps["bpfload_events"]
	if !ok {
		t.Fatalf("expected map 'bpfload_events', got: %v", mapNames(spec))
	}
	if m.Type != ebpf.RingBuf {
		t.Errorf("bpfload_events.Type = %v, want RingBuf", m.Type)
	}
	if m.MaxEntries < 16*1024 {
		t.Errorf("bpfload_events.MaxEntries = %d, want >= 16384", m.MaxEntries)
	}
}

func TestBpfLoadBpfObject_KernelLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF) — see ci.yml's sudo step")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfLoadBpfObj))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader (bpfload): %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("BPF verifier rejected handle_bpf_enter on kernel %s:\n%+v", uname(), verr)
		}
		t.Fatalf("NewCollection (bpfload) on kernel %s: %v", uname(), err)
	}
	defer coll.Close()
	if _, ok := coll.Programs["handle_bpf_enter"]; !ok {
		t.Errorf("loaded collection missing program 'handle_bpf_enter'")
	}
}
