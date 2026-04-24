package main

import (
	"strings"
	"testing"

	"github.com/chud-lori/milog/internal/config"
)

func TestRenderSparkline_Empty(t *testing.T) {
	got := renderSparkline(nil, 10)
	if len(got) != 10 || strings.TrimSpace(got) != "" {
		t.Errorf("empty sparkline: got %q (len %d)", got, len(got))
	}
}

func TestRenderSparkline_ScalesToMax(t *testing.T) {
	// All zero except one peak — peak should render as the tallest glyph.
	buf := []int{0, 0, 0, 0, 10}
	got := renderSparkline(buf, 5)
	runes := []rune(got)
	if len(runes) != 5 {
		t.Fatalf("want 5 runes got %d (%q)", len(runes), got)
	}
	if runes[4] != sparkChars[len(sparkChars)-1] {
		t.Errorf("peak should be tallest glyph, got %q", string(runes[4]))
	}
	if runes[0] != sparkChars[0] {
		t.Errorf("zero should be shortest glyph, got %q", string(runes[0]))
	}
}

func TestRenderSparkline_LeftPadsWhenBufferShort(t *testing.T) {
	buf := []int{5, 10}
	got := renderSparkline(buf, 6)
	if !strings.HasPrefix(got, "    ") {
		t.Errorf("expected 4-char left-pad, got %q", got)
	}
	runes := []rune(got)
	if len(runes) != 6 {
		t.Errorf("want width 6, got %d (%q)", len(runes), got)
	}
}

func TestRenderSparkline_Truncates(t *testing.T) {
	buf := make([]int, 100)
	for i := range buf {
		buf[i] = i
	}
	got := renderSparkline(buf, 10)
	if len([]rune(got)) != 10 {
		t.Errorf("want 10 runes got %d (%q)", len([]rune(got)), got)
	}
}

func TestView_RendersHeaderAndTable(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api", "web"}, Refresh: 5},
		width:      120,
		height:     30,
		refreshSec: 5,
		sys:        sysSample{cpu: 42, memPct: 60, dskPct: 30, memUsed: 1024, memTot: 2048, dskUsed: 50, dskTot: 100},
		apps: []appSample{
			{name: "api", count: 12, c2xx: 10, c3xx: 0, c4xx: 1, c5xx: 1},
			{name: "web", count: 0, c2xx: 0, c3xx: 0, c4xx: 0, c5xx: 0},
		},
		history: map[string][]int{
			"api": {1, 2, 3, 4, 12},
			"web": {},
		},
	}
	view := m.View()
	// ANSI-tolerant substring checks.
	for _, s := range []string{"MiLog TUI", "CPU", "MEM", "DISK", "api", "web", "q:quit"} {
		if !strings.Contains(view, s) {
			t.Errorf("View missing %q; got:\n%s", s, view)
		}
	}
}

func TestView_ShowsPausedBadge(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      80,
		refreshSec: 5,
		paused:     true,
		apps:       []appSample{{name: "api", count: 5}},
		history:    map[string][]int{"api": {5}},
	}
	view := m.View()
	if !strings.Contains(view, "PAUSED") {
		t.Errorf("paused view missing PAUSED badge; got:\n%s", view)
	}
}
