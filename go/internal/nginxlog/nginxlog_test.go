package nginxlog

import (
	"os"
	"path/filepath"
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
