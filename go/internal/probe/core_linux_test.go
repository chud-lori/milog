package probe

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// The probe loads on kernels without /sys/kernel/btf/vmlinux only while no object needs CO-RE relocation.
func TestBpfObjects_NoCORERelocations(t *testing.T) {
	objs := map[string][]byte{
		"exec": execBpfObj, "tcp": tcpBpfObj, "file": fileBpfObj, "ptrace": ptraceBpfObj,
		"kmod": kmodBpfObj, "retrans": retransBpfObj, "syscall": syscallBpfObj, "bpfload": bpfLoadBpfObj,
	}
	for name, obj := range objs {
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for prog, p := range spec.Programs {
			for i := range p.Instructions {
				if btf.CORERelocationMetadata(&p.Instructions[i]) != nil {
					t.Errorf("%s/%s needs CO-RE relocation; update docs/probe.md and the doctor BTF line", name, prog)
				}
			}
		}
	}
}
