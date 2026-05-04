package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/chud-lori/milog/internal/alertlog"
	"github.com/chud-lori/milog/internal/config"
	"github.com/chud-lori/milog/internal/history"
)

// keyMsg builds a tea.KeyMsg for tests. Special names ("esc", "enter",
// "up" ...) map to their KeyType counterparts; anything else is treated
// as a single-rune Runes key. Only the names this TUI actually uses
// are mapped — the table grows when a new keybind needs testing.
func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

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

func TestRenderAlertsView_RendersRowsLatestFirst(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewAlerts,
		alerts: alertsData{
			total: 2,
			// alertsSampleCmd reverses to newest-first before storing,
			// so we feed pre-reversed rows here.
			rows: []alertlog.Row{
				{TS: 1714000200, Sev: "crit", Rule: "process:exec_from_tmp:dropper",
					Title: "Exec from tmp", Body: "```/tmp/x```"},
				{TS: 1714000100, Sev: "warn", Rule: "audit:fim:MODIFIED:/etc/passwd",
					Title: "FIM drift", Body: "```diff…```"},
			},
		},
	}
	view := m.View()
	for _, want := range []string{
		"ALERTS (last 24h)",
		"2 total in window",
		"process:exec_from_tmp:dropper",
		"audit:fim:MODIFIED:/etc/passwd",
		"esc:back",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("alerts view missing %q; got:\n%s", want, view)
		}
	}
	// Newest-first ordering: process:exec... must appear before audit:fim...
	idxExec := strings.Index(view, "process:exec_from_tmp")
	idxFim := strings.Index(view, "audit:fim:MODIFIED")
	if idxExec < 0 || idxFim < 0 || idxExec >= idxFim {
		t.Errorf("expected process:exec... before audit:fim... (newest first); got idxExec=%d idxFim=%d", idxExec, idxFim)
	}
}

func TestRenderAlertsView_CapNotice(t *testing.T) {
	// total > rows means we hit the cap. View should say so explicitly.
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewAlerts,
		alerts: alertsData{
			total: 200,
			rows: []alertlog.Row{
				{TS: 1714000000, Sev: "crit", Rule: "x", Title: "y", Body: "z"},
			},
		},
	}
	view := m.View()
	if !strings.Contains(view, "showing latest 1 of 200") {
		t.Errorf("expected cap notice; got:\n%s", view)
	}
}

func TestRenderAlertsView_EmptyState(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewAlerts,
		alerts:     alertsData{total: 0},
	}
	view := m.View()
	if !strings.Contains(view, "no alerts in the last 24h") {
		t.Errorf("expected empty-state message; got:\n%s", view)
	}
}

func TestRenderAlertsView_LoadError(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewAlerts,
		alerts:     alertsData{err: errors.New("permission denied")},
	}
	view := m.View()
	if !strings.Contains(view, "error reading alerts.log") || !strings.Contains(view, "permission denied") {
		t.Errorf("expected error message in view; got:\n%s", view)
	}
}

func TestUpdate_AKeyOpensAlertsViewFromOverview(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewOverview,
		apps:       []appSample{{name: "api"}},
		history:    map[string][]int{"api": {1}},
	}
	updated, _ := m.Update(keyMsg("a"))
	got := updated.(model)
	if got.view != viewAlerts {
		t.Errorf("after 'a' from overview, view=%v want viewAlerts", got.view)
	}
}

func TestUpdate_EscFromAlertsReturnsToOverview(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewAlerts,
		alerts:     alertsData{total: 5, rows: []alertlog.Row{{Rule: "x"}}},
	}
	updated, _ := m.Update(keyMsg("esc"))
	got := updated.(model)
	if got.view != viewOverview {
		t.Errorf("after 'esc' from alerts, view=%v want viewOverview", got.view)
	}
	if got.alerts.total != 0 {
		t.Errorf("alerts payload should be cleared on back; got total=%d", got.alerts.total)
	}
}

func TestUpdate_AKeyDoesNothingFromDrilldown(t *testing.T) {
	// `a` is overview-only; pressing it from drill-down must NOT switch.
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewDrilldown,
		apps:       []appSample{{name: "api"}},
	}
	updated, _ := m.Update(keyMsg("a"))
	if updated.(model).view != viewDrilldown {
		t.Errorf("drilldown should ignore 'a'; got view=%v", updated.(model).view)
	}
}

func TestRenderAlertRow_FormatsSeverity(t *testing.T) {
	row := alertlog.Row{TS: 1714000000, Sev: "crit", Rule: "audit:yara:milog_php_eval_obfuscation",
		Title: "YARA hit", Body: "```yara hit: rule=… path=/var/www/x.php```"}
	got := renderAlertRow(row)
	if !strings.Contains(got, "audit:yara:milog_php_eval_obf…") {
		t.Errorf("rule should truncate to 29 chars + ellipsis; got %q", got)
	}
	if !strings.Contains(got, "[crit]") {
		t.Errorf("expected sev tag in row; got %q", got)
	}
	// Body backticks should be stripped for readability.
	if strings.Contains(got, "```") {
		t.Errorf("body backticks should be trimmed; got %q", got)
	}
}

func TestRenderPathsView_RendersRowsWithBreakdown(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api", "web"}},
		width:      120,
		refreshSec: 5,
		view:       viewPaths,
		paths: pathsData{
			appsSampled: []string{"api", "web"},
			totalLines:  2000,
			rows: []pathRow{
				{path: "/wp-login.php", total: 50, byApp: []kv{
					{key: "api", count: 30}, {key: "web", count: 20},
				}},
				{path: "/v1/users", total: 12, byApp: []kv{
					{key: "api", count: 12},
				}},
			},
		},
	}
	view := m.View()
	for _, want := range []string{
		"TOP PATHS",
		"across 2 app(s)",
		"/wp-login.php",
		"50",
		"api:30",
		"web:20",
		"/v1/users",
		"esc:back",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("paths view missing %q; got:\n%s", want, view)
		}
	}
}

func TestRenderPathsView_SingleAppRowHasEmptyBreakdown(t *testing.T) {
	// A path that only appeared on one app gets no per-app breakdown
	// rendered — visual signal that it isn't cross-app scan traffic.
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewPaths,
		paths: pathsData{
			appsSampled: []string{"api"},
			totalLines:  100,
			rows: []pathRow{
				{path: "/v1/internal", total: 7, byApp: []kv{{key: "api", count: 7}}},
			},
		},
	}
	view := m.View()
	if !strings.Contains(view, "/v1/internal") {
		t.Fatalf("expected path in view; got:\n%s", view)
	}
	// A breakdown like `api:7` would be rendered for cross-app rows.
	// For a one-app row there should be no `api:` segment because the
	// total column already conveys it.
	if strings.Contains(view, "api:7") {
		t.Errorf("expected NO breakdown for single-app row; got:\n%s", view)
	}
}

func TestRenderPathsView_NoAppsSampledMessage(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewPaths,
		paths:      pathsData{}, // nothing sampled
	}
	view := m.View()
	if !strings.Contains(view, "no apps sampled") {
		t.Errorf("expected config-help message when nothing sampled; got:\n%s", view)
	}
}

func TestRenderPathsView_QuietAppsMessage(t *testing.T) {
	// Apps were sampled but produced zero parsed paths (e.g. clean
	// startup before any traffic). Distinct from "config broken".
	m := model{
		cfg:        &config.Config{Apps: []string{"api", "web"}},
		width:      120,
		refreshSec: 5,
		view:       viewPaths,
		paths: pathsData{
			appsSampled: []string{"api", "web"},
			totalLines:  0,
		},
	}
	view := m.View()
	if !strings.Contains(view, "no path data yet") {
		t.Errorf("expected quiet-host message; got:\n%s", view)
	}
}

func TestRenderPathsView_ErroredAppsSurfaced(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api", "web"}},
		width:      120,
		refreshSec: 5,
		view:       viewPaths,
		paths: pathsData{
			appsSampled: []string{"api"},
			appsErrored: []string{"web"},
			totalLines:  10,
			rows:        []pathRow{{path: "/x", total: 1, byApp: []kv{{key: "api", count: 1}}}},
		},
	}
	view := m.View()
	if !strings.Contains(view, "unreadable: web") {
		t.Errorf("expected unreadable-apps note; got:\n%s", view)
	}
}

func TestFormatPathsBreakdown_CapsAtWidth(t *testing.T) {
	rows := []kv{
		{key: "api", count: 100}, {key: "web", count: 50},
		{key: "auth", count: 25}, {key: "billing", count: 10},
	}
	got := formatPathsBreakdown(rows, 20)
	if len(got) > 22 { // width + " …" tail
		t.Errorf("breakdown should be capped near width=20; got %q (len=%d)", got, len(got))
	}
	if !strings.Contains(got, "…") {
		t.Errorf("expected ellipsis tail when capped; got %q", got)
	}
}

func TestFormatPathsBreakdown_SingleRowReturnsEmpty(t *testing.T) {
	got := formatPathsBreakdown([]kv{{key: "api", count: 12}}, 30)
	if got != "" {
		t.Errorf("single-app row should return empty breakdown; got %q", got)
	}
}

func TestUpdate_PCapitalOpensPathsViewFromOverview(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewOverview,
		apps:       []appSample{{name: "api"}},
		history:    map[string][]int{"api": {1}},
	}
	updated, _ := m.Update(keyMsg("P"))
	got := updated.(model)
	if got.view != viewPaths {
		t.Errorf("after 'P' from overview, view=%v want viewPaths", got.view)
	}
}

func TestUpdate_LowercasePStillPausesNotPaths(t *testing.T) {
	// Regression guard: lowercase 'p' must keep its existing pause
	// semantics. Capital P is the paths-view binding.
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewOverview,
		apps:       []appSample{{name: "api"}},
		history:    map[string][]int{"api": {1}},
	}
	updated, _ := m.Update(keyMsg("p"))
	got := updated.(model)
	if got.view != viewOverview {
		t.Errorf("lowercase 'p' must NOT switch view; got %v", got.view)
	}
	if !got.paused {
		t.Errorf("lowercase 'p' must toggle pause; paused=%v", got.paused)
	}
}

func TestUpdate_EscFromPathsReturnsToOverview(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewPaths,
		paths: pathsData{
			appsSampled: []string{"api"},
			totalLines:  10,
			rows:        []pathRow{{path: "/x", total: 1}},
		},
	}
	updated, _ := m.Update(keyMsg("esc"))
	got := updated.(model)
	if got.view != viewOverview {
		t.Errorf("after 'esc' from paths, view=%v want viewOverview", got.view)
	}
	if got.paths.totalLines != 0 {
		t.Errorf("paths payload should be cleared on back; got totalLines=%d", got.paths.totalLines)
	}
}

func TestUpdate_PCapitalDoesNothingFromDrilldown(t *testing.T) {
	// `P` is overview-only; pressing it from drill-down must NOT switch.
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewDrilldown,
		apps:       []appSample{{name: "api"}},
	}
	updated, _ := m.Update(keyMsg("P"))
	if updated.(model).view != viewDrilldown {
		t.Errorf("drilldown should ignore 'P'; got view=%v", updated.(model).view)
	}
}

func TestParseAppRule(t *testing.T) {
	cases := []struct {
		rule              string
		wantSrc, wantPat  string
		wantOK            bool
	}{
		{"app:api:panic_go", "api", "panic_go", true},
		{"app:web:py_traceback", "web", "py_traceback", true},
		// Pattern with embedded colon — split exactly twice.
		{"app:api:db:timeout", "api", "db:timeout", true},
		// Wrong prefix — not a pattern fire.
		{"audit:fim:MODIFIED:/etc/passwd", "", "", false},
		{"web:5xx_burst:api", "", "", false},
		{"process:exec_from_tmp:dropper", "", "", false},
		// Malformed.
		{"app:", "", "", false},
		{"app:onlysource", "", "", false},
		{"app:onlysource:", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		gotSrc, gotPat, gotOK := parseAppRule(c.rule)
		if gotOK != c.wantOK || gotSrc != c.wantSrc || gotPat != c.wantPat {
			t.Errorf("parseAppRule(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.rule, gotSrc, gotPat, gotOK, c.wantSrc, c.wantPat, c.wantOK)
		}
	}
}

func TestRenderErrorsView_AggregatesAcrossSources(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api", "web"}},
		width:      120,
		refreshSec: 5,
		view:       viewErrors,
		errors: errorsData{
			totalFires:  8,
			sourcesSeen: []string{"api", "web"},
			rows: []errorRow{
				{pattern: "panic_go", total: 5, bySource: []kv{
					{key: "api", count: 3}, {key: "web", count: 2},
				}},
				{pattern: "oom_kill", total: 3, bySource: []kv{
					{key: "api", count: 3},
				}},
			},
		},
	}
	view := m.View()
	for _, want := range []string{
		"PATTERN FIRES",
		"last 24h",
		"2 sources active",
		"8 total fires across 2 distinct patterns",
		"panic_go",
		"api:3",
		"web:2",
		"oom_kill",
		"esc:back",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("errors view missing %q; got:\n%s", want, view)
		}
	}
	// panic_go (count 5) must appear before oom_kill (count 3).
	idxPanic := strings.Index(view, "panic_go")
	idxOom := strings.Index(view, "oom_kill")
	if idxPanic < 0 || idxOom < 0 || idxPanic >= idxOom {
		t.Errorf("expected panic_go before oom_kill (count desc); got idxPanic=%d idxOom=%d", idxPanic, idxOom)
	}
}

func TestRenderErrorsView_SingleSourceRowHasEmptyBreakdown(t *testing.T) {
	// A pattern that only fires on one source gets no breakdown column —
	// same convention as the paths view, signalling "concentrated, not
	// cross-source". The renderAlertRow truncation rules differ from
	// renderErrorsView: errors-row truncates pattern at the patW
	// budget, never at 32.
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewErrors,
		errors: errorsData{
			totalFires:  4,
			sourcesSeen: []string{"api"},
			rows: []errorRow{
				{pattern: "panic_go", total: 4, bySource: []kv{{key: "api", count: 4}}},
			},
		},
	}
	view := m.View()
	if !strings.Contains(view, "panic_go") {
		t.Fatalf("expected pattern in view; got:\n%s", view)
	}
	if strings.Contains(view, "api:4") {
		t.Errorf("expected NO breakdown for single-source row; got:\n%s", view)
	}
}

func TestRenderErrorsView_NoFiresMessage(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewErrors,
		errors:     errorsData{}, // no fires
	}
	view := m.View()
	if !strings.Contains(view, "no app:* fires in the last 24h") {
		t.Errorf("expected empty-state message; got:\n%s", view)
	}
	if !strings.Contains(view, "PATTERNS_ENABLED=0") {
		t.Errorf("expected diagnostic hint about PATTERNS_ENABLED; got:\n%s", view)
	}
}

func TestRenderErrorsView_LoadError(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewErrors,
		errors:     errorsData{err: errors.New("permission denied")},
	}
	view := m.View()
	if !strings.Contains(view, "error reading alerts.log") || !strings.Contains(view, "permission denied") {
		t.Errorf("expected error message; got:\n%s", view)
	}
}

func TestUpdate_EKeyOpensErrorsViewFromOverview(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewOverview,
		apps:       []appSample{{name: "api"}},
		history:    map[string][]int{"api": {1}},
	}
	updated, _ := m.Update(keyMsg("e"))
	got := updated.(model)
	if got.view != viewErrors {
		t.Errorf("after 'e' from overview, view=%v want viewErrors", got.view)
	}
}

func TestUpdate_EscFromErrorsReturnsToOverview(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewErrors,
		errors: errorsData{
			totalFires: 2,
			rows:       []errorRow{{pattern: "panic_go", total: 2}},
		},
	}
	updated, _ := m.Update(keyMsg("esc"))
	got := updated.(model)
	if got.view != viewOverview {
		t.Errorf("after 'esc' from errors, view=%v want viewOverview", got.view)
	}
	if got.errors.totalFires != 0 {
		t.Errorf("errors payload should be cleared on back; got totalFires=%d", got.errors.totalFires)
	}
}

func TestUpdate_EKeyDoesNothingFromDrilldown(t *testing.T) {
	// `e` is overview-only.
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewDrilldown,
		apps:       []appSample{{name: "api"}},
	}
	updated, _ := m.Update(keyMsg("e"))
	if updated.(model).view != viewDrilldown {
		t.Errorf("drilldown should ignore 'e'; got view=%v", updated.(model).view)
	}
}

func TestRenderTrendView_RendersRowWithSparklineAndStats(t *testing.T) {
	mins := make([]int, trendWindowMinutes)
	for i := range mins {
		mins[i] = i // climbing trend
	}
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewTrend,
		trend: trendData{
			rows: []trendRow{
				{app: "api", mins: mins, cur: trendWindowMinutes - 1, peak: trendWindowMinutes - 1, sum: 1770},
			},
		},
	}
	view := m.View()
	for _, want := range []string{
		"REQUEST TREND",
		fmt.Sprintf("last %d min", trendWindowMinutes),
		"api",
		"cur=" + fmt.Sprintf("%-4d", trendWindowMinutes-1),
		"1h=1770",
		"peak=" + fmt.Sprintf("%-4d", trendWindowMinutes-1),
		"esc:back",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("trend view missing %q; got:\n%s", want, view)
		}
	}
}

func TestRenderTrendView_NoRowsMessage(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewTrend,
		trend:      trendData{}, // no rows, no err
	}
	view := m.View()
	if !strings.Contains(view, "no data in window") {
		t.Errorf("expected empty-state message; got:\n%s", view)
	}
}

func TestRenderTrendView_NotConfiguredHint(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewTrend,
		trend:      trendData{loadErr: history.ErrNotConfigured},
	}
	view := m.View()
	if !strings.Contains(view, "DB not present") {
		t.Errorf("expected ErrNotConfigured message; got:\n%s", view)
	}
	if !strings.Contains(view, "milog install history") {
		t.Errorf("expected fix-it hint pointing at milog install history; got:\n%s", view)
	}
}

func TestRenderTrendView_NoBinaryHint(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewTrend,
		trend:      trendData{loadErr: history.ErrNoBinary},
	}
	view := m.View()
	if !strings.Contains(view, "sqlite3") {
		t.Errorf("expected sqlite3 mention in error; got:\n%s", view)
	}
	if !strings.Contains(view, "milog install history") {
		t.Errorf("expected install hint; got:\n%s", view)
	}
}

func TestRenderTrendView_GenericLoadErrorRenders(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}},
		width:      120,
		refreshSec: 5,
		view:       viewTrend,
		trend:      trendData{loadErr: errors.New("disk full")},
	}
	view := m.View()
	if !strings.Contains(view, "disk full") {
		t.Errorf("expected verbatim error in view; got:\n%s", view)
	}
}

func TestUpdate_TKeyOpensTrendViewFromOverview(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewOverview,
		apps:       []appSample{{name: "api"}},
		history:    map[string][]int{"api": {1}},
	}
	updated, _ := m.Update(keyMsg("t"))
	got := updated.(model)
	if got.view != viewTrend {
		t.Errorf("after 't' from overview, view=%v want viewTrend", got.view)
	}
}

func TestUpdate_EscFromTrendReturnsToOverview(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewTrend,
		trend: trendData{
			rows: []trendRow{{app: "api", cur: 5, peak: 10, sum: 100}},
		},
	}
	updated, _ := m.Update(keyMsg("esc"))
	got := updated.(model)
	if got.view != viewOverview {
		t.Errorf("after 'esc' from trend, view=%v want viewOverview", got.view)
	}
	if len(got.trend.rows) != 0 {
		t.Errorf("trend payload should be cleared on back; got %d rows", len(got.trend.rows))
	}
}

func TestUpdate_TKeyDoesNothingFromDrilldown(t *testing.T) {
	m := model{
		cfg:        &config.Config{Apps: []string{"api"}, AlertStateDir: t.TempDir()},
		width:      120,
		refreshSec: 5,
		view:       viewDrilldown,
		apps:       []appSample{{name: "api"}},
	}
	updated, _ := m.Update(keyMsg("t"))
	if updated.(model).view != viewDrilldown {
		t.Errorf("drilldown should ignore 't'; got view=%v", updated.(model).view)
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
