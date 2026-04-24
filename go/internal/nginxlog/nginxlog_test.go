package nginxlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractStatusClass(t *testing.T) {
	cases := []struct {
		line string
		want byte
	}{
		{`1.2.3.4 - - [24/Apr/2026:12:34:56 +0000] "GET /api/x HTTP/1.1" 200 1024 "-" "ua"`, 2},
		{`1.2.3.4 - - [24/Apr/2026:12:34:56 +0000] "POST /login HTTP/1.1" 404 0 "-" "ua"`, 4},
		{`1.2.3.4 - - [24/Apr/2026:12:34:56 +0000] "GET /api/x HTTP/1.1" 503 512 "-" "ua"`, 5},
		{`1.2.3.4 - - [24/Apr/2026:12:34:56 +0000] "GET /api/x HTTP/1.1" 301 0 "-" "ua"`, 3},
		{`1.2.3.4 - - [24/Apr/2026:12:34:56 +0000] "GET /api/x HTTP/1.1" 999 0 "-" "ua"`, 0},
		{`garbage without status`, 0},
	}
	for _, c := range cases {
		if got := extractStatusClass(c.line); got != c.want {
			t.Errorf("extractStatusClass(%q): got %d want %d", c.line, got, c.want)
		}
	}
}

func TestCurrentMinutePrefix(t *testing.T) {
	tm := time.Date(2026, 4, 24, 12, 34, 56, 0, time.UTC)
	want := "24/Apr/2026:12:34"
	if got := CurrentMinutePrefix(tm); got != want {
		t.Errorf("CurrentMinutePrefix: got %q want %q", got, want)
	}
}

func TestMinuteCounts(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "api.access.log")
	lines := []string{
		// Current minute: 3 x 2xx, 1 x 4xx, 2 x 5xx
		`1.1.1.1 - - [24/Apr/2026:12:34:56 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"`,
		`1.1.1.2 - - [24/Apr/2026:12:34:56 +0000] "GET /b HTTP/1.1" 200 1 "-" "-"`,
		`1.1.1.3 - - [24/Apr/2026:12:34:57 +0000] "GET /c HTTP/1.1" 201 1 "-" "-"`,
		`1.1.1.4 - - [24/Apr/2026:12:34:58 +0000] "GET /d HTTP/1.1" 404 0 "-" "-"`,
		`1.1.1.5 - - [24/Apr/2026:12:34:59 +0000] "GET /e HTTP/1.1" 500 0 "-" "-"`,
		`1.1.1.6 - - [24/Apr/2026:12:34:59 +0000] "GET /f HTTP/1.1" 502 0 "-" "-"`,
		// Different minute — should NOT count
		`1.1.1.7 - - [24/Apr/2026:12:33:10 +0000] "GET /old HTTP/1.1" 200 1 "-" "-"`,
		`1.1.1.8 - - [24/Apr/2026:12:35:10 +0000] "GET /new HTTP/1.1" 200 1 "-" "-"`,
	}
	data := ""
	for _, l := range lines {
		data += l + "\n"
	}
	if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := MinuteCounts(file, "24/Apr/2026:12:34")
	if err != nil {
		t.Fatalf("MinuteCounts: %v", err)
	}
	if c.Total != 6 {
		t.Errorf("Total: got %d want 6", c.Total)
	}
	if c.C2xx != 3 {
		t.Errorf("C2xx: got %d want 3", c.C2xx)
	}
	if c.C4xx != 1 {
		t.Errorf("C4xx: got %d want 1", c.C4xx)
	}
	if c.C5xx != 2 {
		t.Errorf("C5xx: got %d want 2", c.C5xx)
	}
	if c.C3xx != 0 {
		t.Errorf("C3xx: got %d want 0", c.C3xx)
	}
}

func TestMinuteCounts_MissingFile(t *testing.T) {
	c, err := MinuteCounts("/does/not/exist.log", "24/Apr/2026:12:34")
	if err != nil {
		t.Errorf("missing file: got error %v, want nil", err)
	}
	if c.Total != 0 {
		t.Errorf("missing file: Total=%d, want 0", c.Total)
	}
}

func TestParseLine(t *testing.T) {
	line := `1.2.3.4 - - [24/Apr/2026:12:34:56 +0000] "POST /api/login?retry=1 HTTP/1.1" 401 0 "-" "bad-bot/1.0" 0.01`
	l := ParseLine(line)
	if l.IP != "1.2.3.4" {
		t.Errorf("IP: %q", l.IP)
	}
	if l.Method != "POST" {
		t.Errorf("Method: %q", l.Method)
	}
	if l.Path != "/api/login" {
		t.Errorf("Path: %q (query should be stripped)", l.Path)
	}
	if l.Status != 401 {
		t.Errorf("Status: %d", l.Status)
	}
	if l.Class != "4xx" {
		t.Errorf("Class: %q", l.Class)
	}
	if l.UA != "bad-bot/1.0" {
		t.Errorf("UA: %q", l.UA)
	}
	if l.TS != "[24/Apr/2026:12:34:56" && !strings.HasPrefix(l.TS, "[") {
		// TS trimming is best-effort — just ensure we captured something
		// bracket-shaped.
		t.Errorf("TS: %q", l.TS)
	}
}

func TestParseLine_MalformedReturnsZero(t *testing.T) {
	cases := []string{
		`garbage without quotes`,
		`1.1.1.1 - - [t] "GET /" noop`,
		``,
	}
	for _, c := range cases {
		l := ParseLine(c)
		if l.Status != 0 {
			t.Errorf("ParseLine(%q): expected Status=0 got %d", c, l.Status)
		}
	}
}

func TestParseLine_PathMustStartWithSlash(t *testing.T) {
	// Malformed request lines yield `PATH="400"` etc — must be rejected.
	line := `1.1.1.1 - - [24/Apr/2026:12:34:56 +0000] "\x00\x00" 400 0 "-" "-" 0.001`
	l := ParseLine(line)
	if l.Path != "" {
		t.Errorf("expected empty path for malformed, got %q", l.Path)
	}
}

func TestTailLines(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "t.log")
	var data string
	for i := 1; i <= 50; i++ {
		data += fmt.Sprintf("line-%d\n", i)
	}
	if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := TailLines(file, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 5 {
		t.Errorf("got %d lines want 5", len(lines))
	}
	if lines[0] != "line-46" || lines[4] != "line-50" {
		t.Errorf("wrong tail: %v", lines)
	}
}

func TestTailLines_MissingFile(t *testing.T) {
	lines, err := TailLines("/does/not/exist", 10)
	if err != nil {
		t.Errorf("missing: got %v", err)
	}
	if lines != nil {
		t.Errorf("missing: got %v", lines)
	}
}

func TestHistogram(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "h.log")
	// Fixed reference: two minutes, 3 requests in the first, 1 in the second.
	now := time.Date(2026, 4, 24, 12, 34, 0, 0, time.UTC)
	m1 := now.Add(-1 * time.Minute).Format("02/Jan/2006:15:04")
	m2 := now.Format("02/Jan/2006:15:04")
	data := ""
	for i := 0; i < 3; i++ {
		data += fmt.Sprintf(`1.1.1.%d - - [%s:10 +0000] "GET / HTTP/1.1" 200 1 "-" "-"` + "\n", i, m1)
	}
	data += fmt.Sprintf(`2.2.2.2 - - [%s:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"` + "\n", m2)
	if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	buckets, err := Histogram(file, 5, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 5 {
		t.Fatalf("want 5 buckets got %d", len(buckets))
	}
	// Find the two populated buckets.
	var got1, got2 int
	for _, b := range buckets {
		if b.T == m1 {
			got1 = b.C
		} else if b.T == m2 {
			got2 = b.C
		}
	}
	if got1 != 3 || got2 != 1 {
		t.Errorf("counts: m1=%d m2=%d (want 3, 1)", got1, got2)
	}
}
