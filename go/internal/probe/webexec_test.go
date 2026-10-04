package probe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
		Rule: "exploit:api:rce",
		Body: "```GET /?c=\x1b[31mid``` \x07HTTP/1.1```",
	}}
	h, ok := matchWebTriggeredExec(Event{Comm: "sh", ParentComm: "nginx"}, rows, at, 30*time.Second)
	if !ok {
		t.Fatal("no hit")
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

func TestWebExecWindow(t *testing.T) {
	cases := map[string]time.Duration{"": 30 * time.Second, "0": 30 * time.Second, "x": 30 * time.Second, "90": 90 * time.Second}
	for env, want := range cases {
		t.Setenv("MILOG_PROBE_WEB_EXEC_WINDOW", env)
		if got := webExecWindow(); got != want {
			t.Errorf("%q: got %v want %v", env, got, want)
		}
	}
}
