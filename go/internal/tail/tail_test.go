package tail

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Faster interval for tests — 30 ms is snappy enough without being
// flaky on loaded CI runners.
func fastOpts() Options { return Options{Interval: 30 * time.Millisecond} }

func writeAppend(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, lines <-chan string, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case got, ok := <-lines:
			if !ok {
				t.Fatalf("channel closed before seeing %q", want)
			}
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("timeout waiting for %q", want)
		}
	}
}

func TestTail_AppendedLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.log")
	if err := os.WriteFile(p, []byte("ignored-existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tl, err := Open(ctx, p, fastOpts())
	if err != nil {
		t.Fatal(err)
	}
	// Give the tailer a moment to stat + seek to EOF.
	time.Sleep(60 * time.Millisecond)

	writeAppend(t, p, "first new line\n")
	waitFor(t, tl.Lines(), "first new line", time.Second)

	writeAppend(t, p, "second\nthird\n")
	waitFor(t, tl.Lines(), "second", time.Second)
	waitFor(t, tl.Lines(), "third", time.Second)
}

func TestTail_PartialLineJoinsOnNextWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b.log")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tl, err := Open(ctx, p, fastOpts())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)

	// Write half a line, wait, then complete it.
	writeAppend(t, p, "half-")
	time.Sleep(80 * time.Millisecond)
	writeAppend(t, p, "line\n")
	waitFor(t, tl.Lines(), "half-line", time.Second)
}

func TestTail_RotationResumesOnNewFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.log")
	if err := os.WriteFile(p, []byte("ancient\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tl, err := Open(ctx, p, fastOpts())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)

	// Simulate logrotate: move the current file, create a new one at
	// the same path.
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("fresh after rotate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, tl.Lines(), "fresh after rotate", time.Second)
}

func TestTail_ContextCancelClosesChannel(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d.log")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tl, err := Open(ctx, p, fastOpts())
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	// Channel must close within a couple of intervals.
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case _, ok := <-tl.Lines():
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("channel did not close after cancel")
		}
	}
}
