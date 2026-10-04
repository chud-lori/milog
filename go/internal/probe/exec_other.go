//go:build !linux

// Non-Linux stubs so the rule engine still builds and tests on macOS.

package probe

import (
	"context"
	"errors"
)

// ErrUnsupported is returned by Run on non-Linux hosts.
var ErrUnsupported = errors.New("probe: eBPF requires Linux (kernel 4.18+ with BTF)")

func Run(ctx context.Context, out chan<- Event) error {
	return ErrUnsupported
}

// RunNet returns ErrUnsupported.
func RunNet(ctx context.Context, out chan<- NetEvent) error {
	return ErrUnsupported
}

// RunFile returns ErrUnsupported.
func RunFile(ctx context.Context, out chan<- FileEvent) error {
	return ErrUnsupported
}

// RunPtrace returns ErrUnsupported.
func RunPtrace(ctx context.Context, out chan<- PtraceEvent) error {
	return ErrUnsupported
}

// RunKmod returns ErrUnsupported.
func RunKmod(ctx context.Context, out chan<- KmodEvent) error {
	return ErrUnsupported
}

// RunRetrans returns ErrUnsupported.
func RunRetrans(ctx context.Context, out chan<- RetransEvent) error {
	return ErrUnsupported
}

// RunSyscallRate returns ErrUnsupported.
func RunSyscallRate(ctx context.Context, out chan<- RateAnomalyEvent) error {
	return ErrUnsupported
}

// RunBpfLoad returns ErrUnsupported.
func RunBpfLoad(ctx context.Context, out chan<- BpfLoadEvent) error {
	return ErrUnsupported
}
