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
