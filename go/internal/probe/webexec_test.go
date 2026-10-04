package probe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chud-lori/milog/internal/alertlog"
)

func TestMatchWebTriggeredExec(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	window := 30 * time.Second
	ev := Event{PID: 42, PPID: 7, UID: 33, Comm: "sh", ParentComm: "php-fpm8.2", Filename: "/bin/sh"}
	row := func(age int64, rule, body string) alertlog.Row {
		return alertlog.Row{TS: at.Unix() - age, Rule: rule, Body: body}
	}

	cases := []struct {
		name     string
		rows     []alertlog.Row
		wantRule string // "" means no hit
	}{
		{"no rows", nil, ""},
		{"exploit 10s before", []alertlog.Row{row(10, "exploit:api:sqli", "GET /?id=1 union select")}, "exploit:api:sqli"},
		{"5xx 29s before", []alertlog.Row{row(29, "5xx:api", "12 5xx responses")}, "5xx:api"},
		{"exploit 31s before is outside the window", []alertlog.Row{row(31, "exploit:api:sqli", "x")}, ""},
		{"exploit logged 2s after the exec", []alertlog.Row{row(-2, "exploit:api:rce", "x")}, "exploit:api:rce"},
		{"exploit logged 10s after the exec", []alertlog.Row{row(-10, "exploit:api:rce", "x")}, ""},
		{"other rule keys are ignored", []alertlog.Row{row(5, "4xx:api", "x"), row(5, "probe:api", "x"), row(5, "cpu", "x")}, ""},
		{"newest preceding row wins", []alertlog.Row{row(20, "5xx:api", "old"), row(3, "exploit:api:lfi", "new"), row(15, "exploit:web:xss", "mid")}, "exploit:api:lfi"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, ok := matchWebTriggeredExec(ev, c.rows, at, window)
			if c.wantRule == "" {
				if ok {
					t.Fatalf("unexpected hit %+v", h)
				}
				return
			}
			if !ok {
				t.Fatalf("no hit, want one after %s", c.wantRule)
			}
			if h.RuleKey != "process:web_triggered_exec:php-fpm8.2:sh" {
				t.Errorf("rule key %q", h.RuleKey)
			}
			if !strings.Contains(h.Body, "preceding "+c.wantRule) {
				t.Errorf("body %q missing %s", h.Body, c.wantRule)
			}
		})
	}
}

func TestMatchWebTriggeredExecSanitisesRequest(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	rows := []alertlog.Row{{
		TS:   at.Unix() - 1,
		Rule: "exploit:api```\x1b:rce",
		Body: "```GET /?c=\x1b[31mid``` \x07HTTP/1.1```",
	}}
	h, ok := matchWebTriggeredExec(Event{Comm: "sh", ParentComm: "nginx"}, rows, at, 30*time.Second)
	if !ok {
		t.Fatal("no hit")
	}
	if !strings.HasSuffix(h.Title, "after exploit:api:rce") {
		t.Fatalf("rule key not sanitised in title: %q", h.Title)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(h.Body, "```"), "```")
	if strings.Contains(inner, "`") || strings.ContainsAny(inner, "\x1b\x07") {
		t.Fatalf("body not sanitised: %q", h.Body)
	}
	if !strings.Contains(inner, "GET /?c=[31mid HTTP/1.1") {
		t.Fatalf("request line lost: %q", h.Body)
	}
}

func TestWebTriggeredExec(t *testing.T) {
	at := time.Now()
	log := filepath.Join(t.TempDir(), "alerts.log")
	data := fmt.Sprintf("%d\texploit:api:rce\t15158332\tExploit attempt: api / rce\t```GET /?cmd=id```\n", at.Unix()-5)
	if err := os.WriteFile(log, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, ok := WebTriggeredExec(Event{Comm: "sh", ParentComm: "sshd"}, log, at); ok {
		t.Error("non-web parent fired")
	}
	if _, ok := WebTriggeredExec(Event{Comm: "sh", ParentComm: "nginx"}, filepath.Join(t.TempDir(), "missing"), at); ok {
		t.Error("missing alerts.log fired")
	}
	h, ok := WebTriggeredExec(Event{Comm: "curl", ParentComm: "nginx"}, log, at)
	if !ok || !strings.Contains(h.Body, "GET /?cmd=id") {
		t.Fatalf("got %+v ok=%v", h, ok)
	}

	old := at.Add(-time.Minute)
	if err := os.Chtimes(log, old, old); err != nil {
		t.Fatal(err)
	}
	if _, ok := WebTriggeredExec(Event{Comm: "curl", ParentComm: "nginx"}, log, at); ok {
		t.Error("alerts.log untouched for a minute still fired")
	}
}

func TestReadAlertsTailRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Unix()
	real := filepath.Join(dir, "real.log")
	if err := os.WriteFile(real, []byte(fmt.Sprintf("%d\texploit:api:rce\t0\tt\tb\n", now)), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.log")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.log")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(alertsLogMaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if rows, ok := readAlertsTail(real, now-30); !ok || len(rows) != 1 {
		t.Fatalf("regular file: rows=%v ok=%v", rows, ok)
	}
	for _, p := range []string{link, fifo, big} {
		done := make(chan bool)
		go func() { _, ok := readAlertsTail(p, now-30); done <- ok }()
		select {
		case ok := <-done:
			if ok {
				t.Errorf("%s was read", filepath.Base(p))
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s blocked", filepath.Base(p))
		}
	}
}

func TestReadAlertsTailReadsOnlyTheTail(t *testing.T) {
	now := time.Now().Unix()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d\texploit:api:old\t0\tt\tb\n", now))
	for sb.Len() < 2*alertsTailBytes {
		sb.WriteString(fmt.Sprintf("%d\tcpu\t0\tt\tpadding padding padding\n", now))
	}
	sb.WriteString(fmt.Sprintf("%d\texploit:api:new\t0\tt\tb\n", now))
	path := filepath.Join(t.TempDir(), "alerts.log")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, ok := readAlertsTail(path, now-30)
	if !ok || rows[len(rows)-1].Rule != "exploit:api:new" {
		t.Fatalf("ok=%v last=%+v", ok, rows[len(rows)-1])
	}
	for _, r := range rows {
		if r.Rule == "exploit:api:old" || r.Rule == "" {
			t.Fatalf("read past the tail or kept a partial row: %+v", r)
		}
	}
}

func TestWebExecWindow(t *testing.T) {
	cases := map[string]time.Duration{"": 30 * time.Second, "0": 30 * time.Second, "x": 30 * time.Second, "90": 90 * time.Second}
	for env, want := range cases {
		t.Setenv("MILOG_PROBE_WEB_EXEC_WINDOW", env)
		if got := webExecWindow(); got != want {
			t.Errorf("%q: got %v want %v", env, got, want)
		}
	}
}
