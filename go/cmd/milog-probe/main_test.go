package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/chud-lori/milog/internal/probe"
)

// captureStdout swaps os.Stdout for a pipe so we can assert on what
// emitJSON writes without hitting the real terminal.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.Bytes()
	}()

	fn()
	_ = w.Close()
	return string(<-done)
}

func TestEmitJSON_includesEventAndHits(t *testing.T) {
	ev := probe.Event{
		PID: 1234, PPID: 1000, UID: 33,
		Comm: "bash", ParentComm: "nginx", Filename: "/bin/bash",
	}
	hits := probe.Match(ev)
	out := captureStdout(t, func() { emitJSON(ev, hits) })

	var got struct {
		Event probe.Event `json:"event"`
		Hits  []probe.Hit `json:"hits"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput=%q", err, out)
	}
	if got.Event.PID != 1234 {
		t.Fatalf("PID round-trip failed: got %d", got.Event.PID)
	}
	if len(got.Hits) == 0 {
		t.Fatal("expected at least one hit (nginx → bash)")
	}
}

func TestHandleEvent_dryRunFiresNothing(t *testing.T) {
	// dry-run should NOT exec milog. We can't easily assert "didn't
	// exec" without process introspection, so use a milogBin path that
	// would fail if invoked — and rely on dry-run to skip it.
	ev := probe.Event{
		Comm: "bash", ParentComm: "nginx", Filename: "/bin/bash",
		PID: 100, UID: 0,
	}
	// No panic, no exec attempt → test passes by completion.
	handleEvent(ev, false, true, "/nonexistent/milog")
}

func TestHandleEvent_jsonModeAlwaysEmits(t *testing.T) {
	// Even a "no rule matched" event prints in JSON mode (debugging
	// affordance). Verifies we don't shortcut on len(hits)==0.
	ev := probe.Event{
		Comm: "ls", ParentComm: "bash", Filename: "/bin/ls",
		PID: 100, UID: 1000,
	}
	out := captureStdout(t, func() {
		handleEvent(ev, true, false, "/nonexistent/milog")
	})
	if !strings.Contains(out, `"event"`) {
		t.Fatalf("expected event JSON in stdout, got %q", out)
	}
	if !strings.Contains(out, `"hits":null`) && !strings.Contains(out, `"hits":[]`) {
		t.Fatalf("expected empty hits array, got %q", out)
	}
}
