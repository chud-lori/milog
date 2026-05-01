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

func TestRuleMentionsApp(t *testing.T) {
	cases := []struct {
		rule, app string
		want      bool
	}{
		{"app:api:panic_go", "api", true},
		{"web:5xx_burst:api", "api", true},
		{"exploit:api:sqli", "api", true},
		{"probe:api", "api", true},
		{"app:worker:panic_go", "api", false},
		{"sys:cpu_high", "api", false},
		{"", "api", false},
		{"app:api:foo", "", false},
		// Substring guard: 'api-v2' app shouldn't match a rule about 'api'.
		{"app:api:foo", "api-v2", false},
	}
	for _, c := range cases {
		if got := ruleMentionsApp(c.rule, c.app); got != c.want {
			t.Errorf("ruleMentionsApp(%q, %q) = %v, want %v", c.rule, c.app, got, c.want)
		}
	}
}

func TestTopN_SortsByCountDescThenKeyAsc(t *testing.T) {
	in := map[string]int{"/a": 1, "/b": 5, "/c": 5, "/d": 3}
	got := topN(in, 3)
	if len(got) != 3 {
		t.Fatalf("want 3 rows, got %d", len(got))
	}
	if got[0].count != 5 || got[0].key != "/b" {
		t.Errorf("rank 1: want (/b, 5), got (%s, %d)", got[0].key, got[0].count)
	}
	if got[1].count != 5 || got[1].key != "/c" {
		t.Errorf("rank 2 (tie-break by key asc): want (/c, 5), got (%s, %d)", got[1].key, got[1].count)
	}
	if got[2].count != 3 || got[2].key != "/d" {
		t.Errorf("rank 3: want (/d, 3), got (%s, %d)", got[2].key, got[2].count)
	}
}

func TestApps_CursorRendered(t *testing.T) {
	m := model{
		cfg:         &config.Config{Apps: []string{"api", "web"}},
		width:       120,
		refreshSec:  5,
		selectedIdx: 1,
		apps: []appSample{
			{name: "api", count: 1},
			{name: "web", count: 2},
		},
		history: map[string][]int{"api": {1}, "web": {2}},
	}
	view := m.View()
	// Cursor glyph from renderApps: `›` precedes the highlighted row.
	if !strings.Contains(view, "›") {
		t.Errorf("expected cursor glyph in view when selectedIdx=1; got:\n%s", view)
	}
}

func TestRenderDrilldown_RendersAllPanes(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewDrilldown,
		apps:       []appSample{{name: "api"}},
		drill: drilldownData{
			app:        "api",
			totalLines: 2000,
			topPaths:   []kv{{key: "/v1/users", count: 42}, {key: "/v1/orders", count: 7}},
			topIPs:     []kv{{key: "1.2.3.4", count: 12}},
		},
	}
	view := m.View()
	for _, want := range []string{"APP", "api", "TOP PATHS", "/v1/users", "TOP IPs", "1.2.3.4", "RECENT ALERTS"} {
		if !strings.Contains(view, want) {
			t.Errorf("drill-down view missing %q; got:\n%s", want, view)
		}
	}
	if !strings.Contains(view, "esc:back") {
		t.Errorf("drill-down footer missing back hint; got:\n%s", view)
	}
}

func TestRenderDrilldown_EmptyShowsHelpfulMessages(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewDrilldown,
		apps:       []appSample{{name: "api"}},
		drill: drilldownData{
			app:        "api",
			totalLines: 0,
			// no paths / IPs / alerts
		},
	}
	view := m.View()
	if !strings.Contains(view, "no data") {
		t.Errorf("empty top-paths/ips should show 'no data'; got:\n%s", view)
	}
	if !strings.Contains(view, "RECENT ALERTS") || !strings.Contains(view, "none") {
		t.Errorf("empty alerts should show 'none'; got:\n%s", view)
	}
}
