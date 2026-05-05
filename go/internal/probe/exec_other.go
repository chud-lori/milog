//go:build !linux

// Stub for non-Linux builds. eBPF is Linux-only — milog-probe on
// macOS / BSD compiles, but `Run` returns ErrUnsupported immediately.
// The macOS path exists so contributor laptops can still compile + run
// `go test ./...` against the OS-independent rule engine.

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

// RunNet stub mirrors Run — non-Linux builds compile but never stream
// network events. Same ErrUnsupported sentinel keeps the cmd/main side
// uniform.
func RunNet(ctx context.Context, out chan<- NetEvent) error {
	return ErrUnsupported
}
