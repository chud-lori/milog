package alertlog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSeverity(t *testing.T) {
	cases := map[int64]string{
		15158332: "crit", 16711680: "crit",
		16753920: "warn", 15844367: "warn",
		3447003: "info", 0: "info", 999: "info",
	}
	for in, want := range cases {
		if got := Severity(in); got != want {
			t.Errorf("Severity(%d): got %q want %q", in, got, want)
		}
	}
}

func TestWindowToCutoff(t *testing.T) {
	// Fixed reference time so "today" is deterministic.
	ref := time.Date(2026, 4, 24, 15, 30, 0, 0, time.UTC)
	refU := ref.Unix()

	cases := map[string]int64{
		"all":       0,
		"today":     refU - (refU % 86400),
		"yesterday": refU - (refU % 86400) - 86400,
	}
	for w, want := range cases {
		got, err := WindowToCutoff(w, ref)
		if err != nil {
			t.Errorf("WindowToCutoff(%q): %v", w, err)
			continue
		}
		if got != want {
			t.Errorf("WindowToCutoff(%q): got %d want %d", w, got, want)
		}
	}

	// N<h/d/w> — tolerate uppercase and relative-to-real-now (no strict
	// equality — just ensure cutoff < now).
	for _, w := range []string{"1h", "24h", "7D", "2w"} {
		got, err := WindowToCutoff(w, time.Now())
		if err != nil {
			t.Errorf("%s: %v", w, err)
		}
		if got >= time.Now().Unix() {
			t.Errorf("%s: cutoff should be in the past, got %d", w, got)
		}
	}

	// Invalid
	for _, w := range []string{"bogus", "3x", "-5h"} {
		if _, err := WindowToCutoff(w, ref); err == nil {
			t.Errorf("%s: expected error", w)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "alerts.log")
	now := time.Now().Unix()
	data := fmt.Sprintf(
		"%d\t5xx:api\t15158332\t5xx spike\t12 5xx in last min\n"+
			"%d\t4xx:api\t16753920\t4xx spike\t55 4xx\n"+
			"%d\talert:test\t3447003\tMiLog test\tmanual\n"+
			"%d\tmem\t15158332\tMemory critical\tMEM 97%%\n"+
			"not-a-valid-row-no-tabs\n",
		now-3600,  // included
		now-1800,  // included
		now-600,   // included
		now-25*3600, // excluded at 24h
	)
	if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	// 24h window → 3 rows
	cutoff, _ := WindowToCutoff("24h", time.Now())
	rows, err := Load(file, cutoff, 100)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("24h: got %d rows want 3", len(rows))
	}

	// Severity derivation
	if rows[0].Sev != "crit" || rows[1].Sev != "warn" || rows[2].Sev != "info" {
		t.Errorf("sev mapping: got %q %q %q", rows[0].Sev, rows[1].Sev, rows[2].Sev)
	}

	// all → 4 rows (includes 25h-old)
	rows, err = Load(file, 0, 100)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("all: got %d want 4", len(rows))
	}

	// maxRows cap keeps the latest
	rows, err = Load(file, 0, 2)
	if err != nil {
		t.Fatalf("cap: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("cap: got %d want 2", len(rows))
	}
	if rows[0].Rule != "alert:test" || rows[1].Rule != "mem" {
		t.Errorf("cap kept wrong rows: got %q %q", rows[0].Rule, rows[1].Rule)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	rows, err := Load("/does/not/exist", 0, 100)
	if err != nil {
		t.Errorf("missing: got err %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("missing: got %d rows", len(rows))
	}
}
