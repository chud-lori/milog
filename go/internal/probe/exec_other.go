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
