// milog-tui — bubbletea TUI for MiLog.
//
// Reuses the same internal/* data packages the Go web daemon uses, so
// numbers between `milog tui` and the web dashboard can never drift.
// Bash `milog monitor` stays — this is an additional option, not a
// replacement.
//
// Six views:
//
//	overview    header + system bars + per-app table (default)
//	drilldown   one app: top paths, top IPs, recent alerts
//	alerts      global last-24h alert log, latest first
//	paths       top paths summed across every configured app
//	errors      pattern-fire aggregation (app:* rule keys) with per-source breakdown
//	trend       per-app request-rate sparklines over the last hour from the SQLite history DB
//
// Key bindings:
//
//	q / Ctrl+C  quit (anywhere)
//	p           pause sampling (freezes sparklines + numbers)
//	r           refresh now
//	+ / -       decrease / increase refresh interval
//	?           toggle help
//	↑/k ↓/j     move row selection (overview)
//	enter / l   drill into the highlighted app
//	a           open the global alerts view
//	P           open the paths-cross-app view (capital P; lowercase p is pause)
//	e           open the errors aggregation view
//	t           open the trend view
//	esc / h     leave drill-down / alerts / paths / errors / trend → overview
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/chud-lori/milog/internal/alertlog"
	"github.com/chud-lori/milog/internal/config"
	"github.com/chud-lori/milog/internal/history"
	"github.com/chud-lori/milog/internal/nginxlog"
	"github.com/chud-lori/milog/internal/sysinfo"
	"github.com/chud-lori/milog/internal/sysstat"
)

// buildVersion is overridden at link time via -ldflags.
var buildVersion = "unknown"

// sparkChars match the bash `milog monitor` palette so side-by-side
// viewers see the same glyphs.
var sparkChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

const (
	sparkLen        = 30                    // samples kept per app
	minRefreshSec   = 1
	maxRefreshSec   = 60
	defaultRefreshS = 5

	// Drill-down sampling caps. Larger N = more accurate top-paths/top-IPs
	// at the cost of one extra parse pass per refresh. ~2k lines covers a
	// few minutes of a busy app on a single host without breaking a sweat.
	drilldownTailLines = 2000
	drilldownTopN      = 8 // rows shown in each top-paths / top-IPs pane
	drilldownAlertsCap = 8 // rows shown in the recent-alerts pane
)

type viewMode int

const (
	viewOverview viewMode = iota
	viewDrilldown
	viewAlerts
	viewPaths
	viewErrors
	viewTrend
)

// alertsViewCap caps the global alerts view at a sensible row budget.
// At ~24 chars per row that's about 80 rows of viewport on a 100x40
// terminal; bigger histories get truncated with a count footer rather
// than scrolling, since the TUI today is screen-fitting (no scroll).
const (
	alertsViewWindow = "24h"
	alertsViewCap    = 50

	// pathsViewTailLines: per-app tail depth for the paths view sample.
	// Smaller than drilldownTailLines because we read every app, not
	// one — the multiplication makes total work meaningful.
	// 1k × ~10 apps ≈ 10k lines parsed per refresh, ~20ms on a busy host.
	pathsViewTailLines = 1000
	pathsViewCap       = 12 // top-N rows shown

	// Errors view caps. Same window as alerts view (24h) so operators
	// build a consistent mental model; row cap matches paths view.
	errorsViewWindow = "24h"
	errorsViewCap    = 12

	// Trend view: 60-minute window, 1 char per minute → 60-char-wide
	// sparkline. Fits a 100-col terminal alongside ~30 chars of stats
	// column. The bash daemon writes one row per minute, so 60 rows
	// is the natural upper bound and there's nothing to bucket.
	trendWindowMinutes = 60
)

// ---- Styles -----------------------------------------------------------

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("7")).Bold(true)
	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))
	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))
	okStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("2"))
	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("3"))
	critStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("1"))
	pausedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("0")).Background(lipgloss.Color("3")).Padding(0, 1)
)

// ---- Model ------------------------------------------------------------

// appSample is one per-app snapshot produced by a sampler tick.
type appSample struct {
	name  string
	count int
	c2xx  int
	c3xx  int
	c4xx  int
	c5xx  int
}

// sysSample is a system snapshot at the same instant as appSample.
type sysSample struct {
	cpu     int
	memPct  int
	memUsed int64
	memTot  int64
	dskPct  int
	dskUsed int64
	dskTot  int64
}

// kv is a name+count pair for top-N tables. Used for both top-paths and
// top-IPs in the drill-down view.
type kv struct {
	key   string
	count int
}

// drilldownData is the focused-app payload computed off the UI thread by
// drilldownSampleCmd. Kept compact — every field is what the renderer
// actually shows; nothing is recomputed on each frame.
type drilldownData struct {
	app        string
	topPaths   []kv
	topIPs     []kv
	totalLines int
	alerts     []alertlog.Row
	err        error
}

// tickMsg triggers a fresh sample pass. Sent via tea.Every.
type tickMsg time.Time

// sampleMsg carries the result of a sample pass (ran off the UI thread).
type sampleMsg struct {
	sys  sysSample
	apps []appSample
	err  error
}

// drilldownMsg carries the result of a drill-down sample pass.
type drilldownMsg struct {
	data drilldownData
}

// alertsData is the global-alerts payload computed off the UI thread.
type alertsData struct {
	rows  []alertlog.Row // newest first, capped at alertsViewCap
	total int            // total rows within window before capping
	err   error
}

// alertsMsg carries the result of an alerts sample pass.
type alertsMsg struct {
	data alertsData
}

// pathRow is one row in the cross-app paths view: the path, its total
// hit count summed across apps, and a per-app breakdown for the right
// column. byApp is sorted (by count desc) at sample time so the
// renderer doesn't pay the cost.
type pathRow struct {
	path   string
	total  int
	byApp  []kv // {app: count}, sorted count-desc
}

// pathsData is the cross-app paths payload computed off the UI thread.
type pathsData struct {
	rows         []pathRow
	totalLines   int      // total parsed lines across every app
	appsSampled  []string // apps that produced at least one parsed line
	appsErrored  []string // apps whose log couldn't be tailed (missing, perm)
}

type pathsMsg struct {
	data pathsData
}

// errorRow aggregates one pattern across every source it fired on.
// `pattern` is the trailing segment of the rule key (the bit after
// `app:<source>:`). bySource carries the (source, count) pairs sorted
// count-desc; total is the sum.
type errorRow struct {
	pattern  string
	total    int
	bySource []kv
}

type errorsData struct {
	rows         []errorRow
	totalFires   int      // total app:* rule fires within window
	sourcesSeen  []string // distinct sources that had at least one fire
	err          error    // alertlog read failure (rare)
}

type errorsMsg struct {
	data errorsData
}

// trendRow is one app's hour of per-minute request counts plus the
// stats we render. cur is the most-recent minute; peak is the max
// over the window; sum is total requests in the window.
type trendRow struct {
	app  string
	mins []int // length up to trendWindowMinutes, oldest → newest
	cur  int
	peak int
	sum  int
}

type trendData struct {
	rows []trendRow
	// State of the underlying data source: ErrNotConfigured (HISTORY
	// off / file missing), ErrNoBinary (no sqlite3), or any other
	// error from the LoadMinutes call. Nil means "data loaded fine,
	// even if rows is empty (quiet host)".
	loadErr error
}

type trendMsg struct {
	data trendData
}

type model struct {
	cfg        *config.Config
	width      int
	height     int
	paused     bool
	refreshSec int
	lastAt     time.Time

	sys     sysSample
	apps    []appSample
	history map[string][]int // rolling per-app request counts
	status  string           // last error, if any

	showHelp bool

	view        viewMode
	selectedIdx int           // highlighted row in overview
	drill       drilldownData // current drill-down payload (empty when in overview)
	alerts      alertsData    // current alerts-view payload (empty when not in viewAlerts)
	paths       pathsData     // current paths-view payload (empty when not in viewPaths)
	errors      errorsData    // current errors-view payload (empty when not in viewErrors)
	trend       trendData     // current trend-view payload (empty when not in viewTrend)
}

// ---- Commands ---------------------------------------------------------

// sampleCmd runs the blocking sampling work off the UI goroutine. The
// Msg returned becomes the next Update() call.
func sampleCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var s sampleMsg
		cpu, err := sysstat.CPU()
		if err != nil {
			s.err = err
		}
		mem, _ := sysstat.Mem()
		disk, _ := sysstat.DiskAt("/")
		s.sys = sysSample{
			cpu:     cpu,
			memPct:  mem.Pct,
			memUsed: mem.UsedMB,
			memTot:  mem.TotalMB,
			dskPct:  disk.Pct,
			dskUsed: disk.UsedGB,
			dskTot:  disk.TotalGB,
		}
		minute := nginxlog.CurrentMinutePrefix(time.Now())
		for _, a := range cfg.Apps {
			path := filepath.Join(cfg.LogDir, a+".access.log")
			c, _ := nginxlog.MinuteCounts(path, minute)
			s.apps = append(s.apps, appSample{
				name: a, count: c.Total,
				c2xx: c.C2xx, c3xx: c.C3xx, c4xx: c.C4xx, c5xx: c.C5xx,
			})
		}
		return s
	}
}

// tickCmd schedules the next tick at the current refresh cadence.
func tickCmd(sec int) tea.Cmd {
	return tea.Tick(time.Duration(sec)*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// drilldownSampleCmd reads the last drilldownTailLines of the focused
// app's nginx access log, computes top paths + top IPs, and pulls recent
// alerts whose rule key references the app. Runs off the UI thread.
//
// "References the app" means any colon-separated segment of the rule
// matches the app name exactly — so `web:5xx_burst:api`,
// `app:api:panic_go`, `exploit:api:sqli`, `probe:api` all match `api`.
// Substring matching would false-positive on overlapping app names.
func drilldownSampleCmd(cfg *config.Config, app string) tea.Cmd {
	return func() tea.Msg {
		var d drilldownData
		d.app = app

		path := filepath.Join(cfg.LogDir, app+".access.log")
		lines, err := nginxlog.TailLines(path, drilldownTailLines)
		if err != nil {
			d.err = err
		}
		d.totalLines = len(lines)

		paths := map[string]int{}
		ips := map[string]int{}
		for _, raw := range lines {
			ln := nginxlog.ParseLine(raw)
			if ln.Path != "" {
				paths[ln.Path]++
			}
			if ln.IP != "" {
				ips[ln.IP]++
			}
		}
		d.topPaths = topN(paths, drilldownTopN)
		d.topIPs = topN(ips, drilldownTopN)

		// Recent alerts referencing this app — last 24h, capped at the
		// view's row budget. Missing alerts.log is silent.
		cutoff, _ := alertlog.WindowToCutoff("24h", time.Now())
		rows, _ := alertlog.Load(filepath.Join(cfg.AlertStateDir, "alerts.log"), cutoff, 0)
		var hits []alertlog.Row
		for _, r := range rows {
			if ruleMentionsApp(r.Rule, app) {
				hits = append(hits, r)
			}
		}
		// Latest first, capped to the alerts pane.
		if len(hits) > drilldownAlertsCap {
			hits = hits[len(hits)-drilldownAlertsCap:]
		}
		// Reverse so newest is on top.
		for i, j := 0, len(hits)-1; i < j; i, j = i+1, j-1 {
			hits[i], hits[j] = hits[j], hits[i]
		}
		d.alerts = hits

		return drilldownMsg{data: d}
	}
}

// alertsSampleCmd loads the last alertsViewWindow of alerts from disk
// and trims to alertsViewCap with newest first. Runs off the UI thread
// so a slow disk read can't stutter the TUI redraw.
//
// Unlike the drill-down's filtered-by-app pane, this view is global —
// every rule key, every app. Operators land here when they want to see
// "what's been firing across the host" at a glance, without first
// picking an app.
func alertsSampleCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var d alertsData
		cutoff, _ := alertlog.WindowToCutoff(alertsViewWindow, time.Now())
		rows, err := alertlog.Load(filepath.Join(cfg.AlertStateDir, "alerts.log"), cutoff, 0)
		if err != nil {
			d.err = err
			return alertsMsg{data: d}
		}
		d.total = len(rows)
		// alertlog.Load returns oldest-first by file order; we want
		// newest-first for the at-a-glance read. Cap THEN reverse so
		// the cap takes the most recent N rows.
		if len(rows) > alertsViewCap {
			rows = rows[len(rows)-alertsViewCap:]
		}
		// Reverse in place — newest first.
		for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
			rows[i], rows[j] = rows[j], rows[i]
		}
		d.rows = rows
		return alertsMsg{data: d}
	}
}

// trendSampleCmd loads the last trendWindowMinutes of per-minute
// request counts from the SQLite history DB, bucketed by app. The
// bash daemon already writes per-minute rows so we don't need to
// re-bucket — just align timestamps to fixed minute slots so apps
// with different first-write timestamps still line up visually.
//
// Errors are passed through to the renderer rather than stuffed in
// model.status because the trend view has its own diagnostic real
// estate. ErrNotConfigured / ErrNoBinary get a friendly hint pointing
// at `milog install history`; other errors render verbatim.
func trendSampleCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var d trendData
		// 60-minute lookback. We add 60s of slack at the front edge
		// because the daemon writes the *previous* completed minute,
		// so "now - 1h" might miss the row that just landed seconds
		// ago. Cheap insurance against a confusing "rate=0 cur" in
		// the right column.
		since := time.Now().Add(-time.Duration(trendWindowMinutes+1)*time.Minute).Unix()
		raw, err := history.LoadMinutes(cfg.HistoryDB, since)
		if err != nil {
			d.loadErr = err
			return trendMsg{data: d}
		}

		// Stable order: configured-app order first, then any extra
		// apps from the DB that aren't in cfg.Apps (host changed
		// configs since last write). Both branches preserve insertion
		// order so the rendered rows don't flicker on tick.
		seen := map[string]bool{}
		ordered := make([]string, 0, len(raw))
		for _, a := range cfg.Apps {
			if _, ok := raw[a]; ok {
				ordered = append(ordered, a)
				seen[a] = true
			}
		}
		for a := range raw {
			if !seen[a] {
				ordered = append(ordered, a)
			}
		}

		nowMin := time.Now().Unix() / 60
		for _, app := range ordered {
			rows := raw[app]
			if len(rows) == 0 {
				continue
			}
			// Bucket into a fixed-size slot array indexed by
			// `(rowMin - oldestSlot)` where slot 0 is the oldest
			// minute in the window. Missing minutes (server idle)
			// stay at zero — the sparkline glyph for zero is the
			// flattest one, which reads as "nothing happened" at
			// a glance. Right-edge of the slot array is `now`.
			slots := make([]int, trendWindowMinutes)
			oldestSlot := nowMin - int64(trendWindowMinutes-1)
			for _, r := range rows {
				rowMin := r.TS / 60
				idx := int(rowMin - oldestSlot)
				if idx < 0 || idx >= trendWindowMinutes {
					continue
				}
				slots[idx] += r.Req
			}
			tr := trendRow{app: app, mins: slots}
			for _, v := range slots {
				tr.sum += v
				if v > tr.peak {
					tr.peak = v
				}
			}
			tr.cur = slots[len(slots)-1]
			d.rows = append(d.rows, tr)
		}
		return trendMsg{data: d}
	}
}

// parseAppRule splits an `app:<source>:<pattern>` rule key into its
// (source, pattern) components. Returns ("", "", false) for keys that
// don't have the `app:` prefix or fewer than two trailing segments —
// callers use that as the filter for "is this a pattern-fire alert?".
//
// The pattern segment can itself contain colons (e.g. user-defined
// `APP_PATTERN_db:timeout='…'`), so we split exactly twice rather
// than calling strings.Split — keeps the pattern intact when it has
// colons in the name.
func parseAppRule(rule string) (source, pattern string, ok bool) {
	const prefix = "app:"
	if !strings.HasPrefix(rule, prefix) {
		return "", "", false
	}
	rest := rule[len(prefix):]
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 || colon == len(rest)-1 {
		return "", "", false
	}
	return rest[:colon], rest[colon+1:], true
}

// errorsSampleCmd loads the last errorsViewWindow of alerts, filters to
// `app:*` rule keys (pattern-fire alerts from the patterns module),
// and aggregates by pattern → source → count. Returns the top
// errorsViewCap patterns by total count.
//
// Caller renders rows like `<count>  <pattern>  <src1:N1 src2:N2 …>` —
// same shape as the paths view, swapping path-cross-app for
// pattern-cross-source. When one pattern is firing across every
// source, that's the "everything's broken at once" signature
// (e.g. shared-library OOM panic showing in api + web + worker).
func errorsSampleCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var d errorsData
		cutoff, _ := alertlog.WindowToCutoff(errorsViewWindow, time.Now())
		rows, err := alertlog.Load(filepath.Join(cfg.AlertStateDir, "alerts.log"), cutoff, 0)
		if err != nil {
			d.err = err
			return errorsMsg{data: d}
		}
		// pattern → source → count. Tracking sources at accumulation
		// avoids a second pass and lets us emit a deduped sourcesSeen
		// for the header at zero cost.
		byPattern := map[string]map[string]int{}
		sources := map[string]struct{}{}
		for _, r := range rows {
			source, pattern, ok := parseAppRule(r.Rule)
			if !ok {
				continue
			}
			d.totalFires++
			sources[source] = struct{}{}
			inner := byPattern[pattern]
			if inner == nil {
				inner = map[string]int{}
				byPattern[pattern] = inner
			}
			inner[source]++
		}
		for s := range sources {
			d.sourcesSeen = append(d.sourcesSeen, s)
		}
		sort.Strings(d.sourcesSeen)

		out := make([]errorRow, 0, len(byPattern))
		for p, inner := range byPattern {
			total := 0
			for _, c := range inner {
				total += c
			}
			out = append(out, errorRow{
				pattern:  p,
				total:    total,
				bySource: topN(inner, len(inner)),
			})
		}
		// Same total-desc + tiebreak-asc order as paths view — keeps
		// the row layout stable across ticks when counts are equal.
		sort.Slice(out, func(i, j int) bool {
			if out[i].total != out[j].total {
				return out[i].total > out[j].total
			}
			return out[i].pattern < out[j].pattern
		})
		if len(out) > errorsViewCap {
			out = out[:errorsViewCap]
		}
		d.rows = out
		return errorsMsg{data: d}
	}
}

// pathsSampleCmd tails the last pathsViewTailLines of every configured
// app's nginx log, sums path counts globally, and returns the top
// pathsViewCap entries. Each row carries a per-app breakdown so the
// operator can see whether a path's hits are concentrated on one app
// or spread across the host (the latter being the scan-probe signature
// this view exists to surface).
//
// Tail-failure semantics: an app whose log can't be read (missing
// file, permission denied) is recorded in appsErrored but does NOT
// fail the whole sample — the view still shows whatever the readable
// apps produced. Empty appsSampled + non-empty appsErrored is the
// signal "everything's broken, fix LOG_DIR".
func pathsSampleCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var d pathsData
		// path → app → count. Tracking per-app at accumulation time
		// avoids a second pass when building the breakdown column.
		byPath := map[string]map[string]int{}

		for _, a := range cfg.Apps {
			path := filepath.Join(cfg.LogDir, a+".access.log")
			lines, err := nginxlog.TailLines(path, pathsViewTailLines)
			if err != nil || len(lines) == 0 {
				if err != nil {
					d.appsErrored = append(d.appsErrored, a)
				}
				continue
			}
			d.appsSampled = append(d.appsSampled, a)
			d.totalLines += len(lines)
			for _, raw := range lines {
				ln := nginxlog.ParseLine(raw)
				if ln.Path == "" {
					continue
				}
				inner := byPath[ln.Path]
				if inner == nil {
					inner = map[string]int{}
					byPath[ln.Path] = inner
				}
				inner[a]++
			}
		}

		rows := make([]pathRow, 0, len(byPath))
		for p, inner := range byPath {
			total := 0
			for _, c := range inner {
				total += c
			}
			rows = append(rows, pathRow{
				path:  p,
				total: total,
				byApp: topN(inner, len(inner)), // keep all, already small
			})
		}
		// Sort by total desc, path asc as tie-break (stable + deterministic
		// across ticks even when counts are identical, so the list doesn't
		// flicker between renders).
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].total != rows[j].total {
				return rows[i].total > rows[j].total
			}
			return rows[i].path < rows[j].path
		})
		if len(rows) > pathsViewCap {
			rows = rows[:pathsViewCap]
		}
		d.rows = rows
		return pathsMsg{data: d}
	}
}

// topN sorts the (key, count) map and keeps the highest n by count.
func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, c := range m {
		out = append(out, kv{key: k, count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].key < out[j].key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ruleMentionsApp returns true when any colon-separated segment of the
// rule equals app. See drilldownSampleCmd's docstring.
func ruleMentionsApp(rule, app string) bool {
	if rule == "" || app == "" {
		return false
	}
	for _, seg := range strings.Split(rule, ":") {
		if seg == app {
			return true
		}
	}
	return false
}

// ---- Init / Update ----------------------------------------------------

func (m model) Init() tea.Cmd {
	// Kick off with an immediate sample + the first tick.
	return tea.Batch(sampleCmd(m.cfg), tickCmd(m.refreshSec))
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		// Global keys — same behaviour in both views.
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "p":
			m.paused = !m.paused
			return m, nil
		case "+", "=":
			// `=` is the unshifted `+` on US layouts — accept both so
			// users don't have to hold Shift.
			if m.refreshSec > minRefreshSec {
				m.refreshSec--
			}
			return m, nil
		case "-", "_":
			if m.refreshSec < maxRefreshSec {
				m.refreshSec++
			}
			return m, nil
		case "?":
			m.showHelp = !m.showHelp
			return m, nil
		}
		// View-specific keys.
		switch m.view {
		case viewOverview:
			switch msg.String() {
			case "r":
				return m, sampleCmd(m.cfg)
			case "up", "k":
				if m.selectedIdx > 0 {
					m.selectedIdx--
				}
				return m, nil
			case "down", "j":
				if m.selectedIdx < len(m.apps)-1 {
					m.selectedIdx++
				}
				return m, nil
			case "enter", "l", "right":
				if len(m.apps) == 0 {
					return m, nil
				}
				if m.selectedIdx >= len(m.apps) {
					m.selectedIdx = len(m.apps) - 1
				}
				m.view = viewDrilldown
				return m, drilldownSampleCmd(m.cfg, m.apps[m.selectedIdx].name)
			case "a":
				m.view = viewAlerts
				return m, alertsSampleCmd(m.cfg)
			case "P":
				// Capital P (shift+p) — `p` on its own is the global
				// pause toggle, kept that way for muscle memory. The
				// paths view is reachable from overview only, so the
				// capital binding lives here in the per-view branch.
				m.view = viewPaths
				return m, pathsSampleCmd(m.cfg)
			case "e":
				m.view = viewErrors
				return m, errorsSampleCmd(m.cfg)
			case "t":
				m.view = viewTrend
				return m, trendSampleCmd(m.cfg)
			}
		case viewDrilldown:
			switch msg.String() {
			case "esc", "h", "left", "backspace":
				m.view = viewOverview
				m.drill = drilldownData{}
				return m, nil
			case "r":
				if m.selectedIdx < len(m.apps) {
					return m, drilldownSampleCmd(m.cfg, m.apps[m.selectedIdx].name)
				}
				return m, nil
			}
		case viewAlerts:
			switch msg.String() {
			case "esc", "h", "left", "backspace":
				m.view = viewOverview
				m.alerts = alertsData{}
				return m, nil
			case "r":
				return m, alertsSampleCmd(m.cfg)
			}
		case viewPaths:
			switch msg.String() {
			case "esc", "h", "left", "backspace":
				m.view = viewOverview
				m.paths = pathsData{}
				return m, nil
			case "r":
				return m, pathsSampleCmd(m.cfg)
			}
		case viewErrors:
			switch msg.String() {
			case "esc", "h", "left", "backspace":
				m.view = viewOverview
				m.errors = errorsData{}
				return m, nil
			case "r":
				return m, errorsSampleCmd(m.cfg)
			}
		case viewTrend:
			switch msg.String() {
			case "esc", "h", "left", "backspace":
				m.view = viewOverview
				m.trend = trendData{}
				return m, nil
			case "r":
				return m, trendSampleCmd(m.cfg)
			}
		}

	case tickMsg:
		// Re-schedule regardless of pause (so the UI stays responsive
		// and unpausing picks up quickly), but only sample when not paused.
		next := tickCmd(m.refreshSec)
		if m.paused {
			return m, next
		}
		// Refresh the current view's data on every tick.
		batch := []tea.Cmd{sampleCmd(m.cfg), next}
		switch m.view {
		case viewDrilldown:
			if m.selectedIdx < len(m.apps) {
				batch = append(batch, drilldownSampleCmd(m.cfg, m.apps[m.selectedIdx].name))
			}
		case viewAlerts:
			batch = append(batch, alertsSampleCmd(m.cfg))
		case viewPaths:
			batch = append(batch, pathsSampleCmd(m.cfg))
		case viewErrors:
			batch = append(batch, errorsSampleCmd(m.cfg))
		case viewTrend:
			batch = append(batch, trendSampleCmd(m.cfg))
		}
		return m, tea.Batch(batch...)

	case sampleMsg:
		if msg.err != nil {
			m.status = "sample: " + msg.err.Error()
		} else {
			m.status = ""
		}
		m.sys = msg.sys
		m.apps = msg.apps
		m.lastAt = time.Now()
		// Clamp selection if app list shrank since last sample.
		if m.selectedIdx >= len(m.apps) {
			m.selectedIdx = len(m.apps) - 1
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
		}
		// Push current counts into the per-app history ring (skip when
		// paused so unpause doesn't drop in a backdated jump).
		if !m.paused {
			if m.history == nil {
				m.history = map[string][]int{}
			}
			for _, a := range m.apps {
				buf := append(m.history[a.name], a.count)
				if len(buf) > sparkLen {
					buf = buf[len(buf)-sparkLen:]
				}
				m.history[a.name] = buf
			}
		}

	case drilldownMsg:
		m.drill = msg.data
		if msg.data.err != nil {
			m.status = "drill: " + msg.data.err.Error()
		}

	case alertsMsg:
		m.alerts = msg.data
		if msg.data.err != nil {
			m.status = "alerts: " + msg.data.err.Error()
		}

	case pathsMsg:
		m.paths = msg.data

	case errorsMsg:
		m.errors = msg.data
		if msg.data.err != nil {
			m.status = "errors: " + msg.data.err.Error()
		}

	case trendMsg:
		m.trend = msg.data
		// Don't set m.status — the trend view renders its own
		// loadErr inline so the operator sees the diagnostic in
		// context rather than as a generic footer status.
	}
	return m, nil
}

// ---- View -------------------------------------------------------------

func (m model) View() string {
	var b strings.Builder

	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")
	switch m.view {
	case viewDrilldown:
		b.WriteString(m.renderDrilldown())
	case viewAlerts:
		b.WriteString(m.renderAlertsView())
	case viewPaths:
		b.WriteString(m.renderPathsView())
	case viewErrors:
		b.WriteString(m.renderErrorsView())
	case viewTrend:
		b.WriteString(m.renderTrendView())
	default:
		b.WriteString(m.renderSystem())
		b.WriteString("\n\n")
		b.WriteString(m.renderApps())
	}
	b.WriteString("\n")
	b.WriteString(m.renderFooter())
	if m.showHelp {
		b.WriteString("\n\n")
		b.WriteString(m.renderHelp())
	}
	return b.String()
}

func (m model) renderHeader() string {
	title := titleStyle.Render("MiLog TUI")
	host := dimStyle.Render(sysinfo.Hostname())
	version := dimStyle.Render("v" + buildVersion)
	ts := dimStyle.Render(m.lastAt.Format("15:04:05"))
	right := lipgloss.JoinHorizontal(lipgloss.Right, ts, " · ", host, " · ", version)
	left := title
	if m.paused {
		left = lipgloss.JoinHorizontal(lipgloss.Left, title, " ", pausedStyle.Render("PAUSED"))
	}
	// Pad between left and right to fill width.
	pad := 0
	if m.width > lipgloss.Width(left)+lipgloss.Width(right) {
		pad = m.width - lipgloss.Width(left) - lipgloss.Width(right)
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, left, strings.Repeat(" ", pad), right)
}

// renderSystem renders three horizontal percentage bars (CPU/MEM/DISK).
// Each bar's width adapts to the terminal so it stays on one line.
func (m model) renderSystem() string {
	cpu := m.sys.cpu
	memPct := m.sys.memPct
	dskPct := m.sys.dskPct
	barW := m.width - 32
	if barW < 10 {
		barW = 10
	}
	row := func(label string, pct int, right string) string {
		color := okStyle
		if pct >= 75 {
			color = warnStyle
		}
		if pct >= 90 {
			color = critStyle
		}
		filled := pct * barW / 100
		if filled > barW {
			filled = barW
		}
		if filled < 0 {
			filled = 0
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("·", barW-filled)
		pctStr := fmt.Sprintf("%3d%%", pct)
		return fmt.Sprintf("  %-6s %s %s %s",
			labelStyle.Render(label), color.Render(bar), color.Render(pctStr), dimStyle.Render(right))
	}
	memRight := fmt.Sprintf("%dM / %dM", m.sys.memUsed, m.sys.memTot)
	dskRight := fmt.Sprintf("%dG / %dG", m.sys.dskUsed, m.sys.dskTot)
	return strings.Join([]string{
		row("CPU", cpu, ""),
		row("MEM", memPct, memRight),
		row("DISK", dskPct, dskRight),
	}, "\n")
}

func (m model) renderApps() string {
	if len(m.apps) == 0 {
		return dimStyle.Render("  no apps configured (set MILOG_APPS)")
	}
	// Compute column widths.
	nameW := 8
	for _, a := range m.apps {
		if len(a.name) > nameW {
			nameW = len(a.name)
		}
	}
	if nameW > 16 {
		nameW = 16
	}
	sparkW := m.width - (nameW + 2 + 7 + 7 + 7 + 7 + 7 + 5*2)
	if sparkW < 10 {
		sparkW = 10
	}

	// Header.
	var lines []string
	hdr := fmt.Sprintf("  %-*s  %7s  %7s  %7s  %7s  %7s  %s",
		nameW, "APP", "REQ", "2xx", "3xx", "4xx", "5xx", "SPARK")
	lines = append(lines, labelStyle.Render(hdr))

	for i, a := range m.apps {
		spark := renderSparkline(m.history[a.name], sparkW)
		sparkStyled := okStyle.Render(spark)
		if a.count == 0 {
			sparkStyled = dimStyle.Render(spark)
		} else if a.count > 40 {
			sparkStyled = critStyle.Render(spark)
		} else if a.count > 15 {
			sparkStyled = warnStyle.Render(spark)
		}
		errColor := labelStyle
		if a.c5xx > 0 {
			errColor = critStyle
		} else if a.c4xx > 20 {
			errColor = warnStyle
		}
		displayName := a.name
		if len(displayName) > nameW {
			displayName = displayName[:nameW-1] + "…"
		}
		// Cursor marker on the highlighted row — replaces leading spaces.
		// `›` (single-char arrow) keeps alignment with the header indent.
		cursor := "  "
		if i == m.selectedIdx {
			cursor = warnStyle.Render("› ")
		}
		lines = append(lines, fmt.Sprintf("%s%-*s  %7d  %7d  %7d  %s  %s  %s",
			cursor, nameW, displayName,
			a.count, a.c2xx, a.c3xx,
			errColor.Render(fmt.Sprintf("%7d", a.c4xx)),
			errColor.Render(fmt.Sprintf("%7d", a.c5xx)),
			sparkStyled))
	}
	return strings.Join(lines, "\n")
}

// renderDrilldown renders the focused-app view: top paths, top IPs,
// recent alerts. Empty payload (e.g. drill into an idle app) shows
// helpful placeholders rather than blank panes.
func (m model) renderDrilldown() string {
	d := m.drill
	if d.app == "" {
		// Drill-down keypress hit but no sample landed yet.
		return dimStyle.Render("  loading drill-down…")
	}
	var b strings.Builder

	// Sub-header: which app, sample size, back hint.
	subhead := fmt.Sprintf("  %s %s   %s",
		labelStyle.Render("APP"),
		titleStyle.Render(d.app),
		dimStyle.Render(fmt.Sprintf("(scanned %d recent lines)", d.totalLines)))
	b.WriteString(subhead)
	b.WriteString("\n\n")

	// Two-column top-paths / top-IPs row. Width-adaptive: each pane gets
	// half the screen minus margins. Column widths inside each pane keep
	// the count column right-aligned at 6 chars.
	colW := (m.width - 6) / 2
	if colW < 24 {
		colW = 24
	}
	pathPane := renderTopPane("TOP PATHS", d.topPaths, colW)
	ipPane := renderTopPane("TOP IPs", d.topIPs, colW)
	b.WriteString(joinPanesHorizontal(pathPane, ipPane))
	b.WriteString("\n")

	// Recent alerts pane — full width, latest first.
	b.WriteString("\n")
	b.WriteString("  ")
	b.WriteString(labelStyle.Render("RECENT ALERTS (24h)"))
	b.WriteString("\n")
	if len(d.alerts) == 0 {
		b.WriteString("  ")
		b.WriteString(dimStyle.Render("none"))
		return b.String()
	}
	for _, r := range d.alerts {
		b.WriteString(renderAlertRow(r))
	}
	return b.String()
}

// renderAlertRow formats one alertlog row for the recent-alerts panes
// (used by drill-down and the global alerts view). One line per row,
// 2-space indent: `<HH:MM> [<sev>] <rule>  <body excerpt>`. Body is
// trimmed of its enclosing backticks (alert_fire wraps in ``` for
// Discord) and capped at 60 chars so the line fits a typical 100-col
// terminal alongside time + sev + rule.
func renderAlertRow(r alertlog.Row) string {
	when := time.Unix(r.TS, 0).Format("15:04")
	sevStyle := labelStyle
	switch r.Sev {
	case "crit":
		sevStyle = critStyle
	case "warn":
		sevStyle = warnStyle
	}
	ruleShort := r.Rule
	if len(ruleShort) > 32 {
		ruleShort = ruleShort[:29] + "…"
	}
	body := strings.TrimSpace(strings.Trim(r.Body, "`"))
	if len(body) > 60 {
		body = body[:57] + "…"
	}
	return fmt.Sprintf("  %s %s %s %s\n",
		dimStyle.Render(when),
		sevStyle.Render(fmt.Sprintf("[%s]", r.Sev)),
		ruleShort,
		dimStyle.Render(body))
}

// renderAlertsView is the global alerts screen — every rule, every app,
// last alertsViewWindow. Header shows total count + window + cap; one
// row per alertlog entry below, newest first. Empty state distinguishes
// "no alerts in window" from "couldn't load file" so the operator
// knows whether the silence is good news or a config problem.
func (m model) renderAlertsView() string {
	d := m.alerts
	var b strings.Builder

	b.WriteString("  ")
	b.WriteString(labelStyle.Render(fmt.Sprintf("ALERTS (last %s)", alertsViewWindow)))
	b.WriteString("\n")

	if d.err != nil {
		b.WriteString("  ")
		b.WriteString(critStyle.Render("error reading alerts.log: " + d.err.Error()))
		b.WriteString("\n")
		return b.String()
	}

	if d.total == 0 {
		b.WriteString("  ")
		b.WriteString(dimStyle.Render("no alerts in the last " + alertsViewWindow))
		b.WriteString("\n")
		b.WriteString("  ")
		b.WriteString(dimStyle.Render("(quiet host, or alerts.log not yet populated)"))
		return b.String()
	}

	// Counter line so an operator knows whether the cap kicked in.
	if d.total > len(d.rows) {
		b.WriteString("  ")
		b.WriteString(dimStyle.Render(fmt.Sprintf(
			"showing latest %d of %d in window",
			len(d.rows), d.total,
		)))
		b.WriteString("\n")
	} else {
		b.WriteString("  ")
		b.WriteString(dimStyle.Render(fmt.Sprintf("%d total in window", d.total)))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	for _, r := range d.rows {
		b.WriteString(renderAlertRow(r))
	}
	return b.String()
}

// renderPathsView is the global top-paths-cross-app screen. Each row
// shows the path total + per-app breakdown. The breakdown is the
// value-add over `milog top-paths` (per-app) — when one path appears
// at the top with hits across every app, that's the scan-probe
// signature this view exists to surface (`/wp-login.php`, `.git/config`,
// `xmlrpc.php`, etc.).
func (m model) renderPathsView() string {
	d := m.paths
	var b strings.Builder

	b.WriteString("  ")
	b.WriteString(labelStyle.Render(fmt.Sprintf(
		"TOP PATHS — across %d app(s), last %d lines/app",
		len(d.appsSampled), pathsViewTailLines,
	)))
	b.WriteString("\n")

	// Errored apps surfaced as an inline note so an unreadable log
	// doesn't silently rot — the same pattern the audit-status output
	// uses for missing paths.
	if len(d.appsErrored) > 0 {
		b.WriteString("  ")
		b.WriteString(warnStyle.Render(
			"unreadable: " + strings.Join(d.appsErrored, ", "),
		))
		b.WriteString("\n")
	}

	if len(d.rows) == 0 {
		b.WriteString("  ")
		if len(d.appsSampled) == 0 {
			b.WriteString(dimStyle.Render(
				"no apps sampled — check MILOG_LOG_DIR / MILOG_APPS",
			))
		} else {
			b.WriteString(dimStyle.Render(
				"no path data yet (quiet apps or fresh start)",
			))
		}
		b.WriteString("\n")
		return b.String()
	}

	b.WriteString("  ")
	b.WriteString(dimStyle.Render(fmt.Sprintf(
		"%d total req parsed across %d distinct paths",
		d.totalLines, len(d.rows),
	)))
	b.WriteString("\n\n")

	// Layout: 6 chars count, gap, path (truncated to fit), gap, breakdown.
	// Total width budget: m.width - 4 (2 leading + 2 trailing margin).
	pathW := m.width - 6 - 2 - 30 - 4
	if pathW < 20 {
		pathW = 20
	}
	for _, r := range d.rows {
		key := r.path
		if len(key) > pathW {
			key = key[:pathW-1] + "…"
		}
		breakdown := formatPathsBreakdown(r.byApp, 30)
		b.WriteString(fmt.Sprintf("  %5d  %-*s  %s\n",
			r.total, pathW, key, dimStyle.Render(breakdown)))
	}
	return b.String()
}

// renderErrorsView aggregates pattern-fire alerts (`app:<source>:<pattern>`
// rule keys) over the last errorsViewWindow into a top-N table. Same
// shape as the paths view: <count>  <pattern>  <src1:N1 src2:N2 …>.
//
// When one pattern fires across every source, that's the
// "everything's broken at once" signature — typically a shared library
// regression hitting every app at the same time. When a pattern is
// concentrated on one source, the breakdown column is blank, just like
// in the paths view.
func (m model) renderErrorsView() string {
	d := m.errors
	var b strings.Builder

	b.WriteString("  ")
	b.WriteString(labelStyle.Render(fmt.Sprintf(
		"PATTERN FIRES — last %s, %d sources active",
		errorsViewWindow, len(d.sourcesSeen),
	)))
	b.WriteString("\n")

	if d.err != nil {
		b.WriteString("  ")
		b.WriteString(critStyle.Render("error reading alerts.log: " + d.err.Error()))
		b.WriteString("\n")
		return b.String()
	}

	if len(d.rows) == 0 {
		b.WriteString("  ")
		if d.totalFires == 0 {
			b.WriteString(dimStyle.Render(
				"no app:* fires in the last " + errorsViewWindow,
			))
			b.WriteString("\n")
			b.WriteString("  ")
			b.WriteString(dimStyle.Render(
				"(quiet apps, or PATTERNS_ENABLED=0 in milog.conf)",
			))
		} else {
			// totalFires > 0 but rows == 0 shouldn't happen — guard
			// against future refactors that could break the invariant.
			b.WriteString(dimStyle.Render(
				"no rows after aggregation (unexpected — file a bug)",
			))
		}
		b.WriteString("\n")
		return b.String()
	}

	b.WriteString("  ")
	b.WriteString(dimStyle.Render(fmt.Sprintf(
		"%d total fires across %d distinct patterns",
		d.totalFires, len(d.rows),
	)))
	b.WriteString("\n\n")

	// Same width budget as the paths view: 5-char count + 2 + pattern +
	// 2 + 30-char breakdown + 4 margin. Pattern column gets whatever's
	// left over.
	patW := m.width - 6 - 2 - 30 - 4
	if patW < 20 {
		patW = 20
	}
	for _, r := range d.rows {
		key := r.pattern
		if len(key) > patW {
			key = key[:patW-1] + "…"
		}
		// Reuse the paths-view breakdown formatter — same shape, same
		// "single source = empty breakdown" convention.
		breakdown := formatPathsBreakdown(r.bySource, 30)
		b.WriteString(fmt.Sprintf("  %5d  %-*s  %s\n",
			r.total, patW, key, dimStyle.Render(breakdown)))
	}
	return b.String()
}

// renderTrendView shows per-app request-rate sparklines from the
// SQLite history DB over the last hour. One row per app:
//
//	app   ▁▂▅▇▆▃▂▁ ··· ▆█▇▅  cur=12 1h=4567 peak=89
//
// The bash daemon writes one row per minute, so the sparkline is
// 60 chars wide (one glyph per minute). Apps with no data in the
// window don't appear; missing minutes (server idle) render as the
// flattest glyph.
func (m model) renderTrendView() string {
	d := m.trend
	var b strings.Builder

	b.WriteString("  ")
	b.WriteString(labelStyle.Render(fmt.Sprintf(
		"REQUEST TREND — last %d min, per minute",
		trendWindowMinutes,
	)))
	b.WriteString("\n")

	if d.loadErr != nil {
		// ErrNotConfigured / ErrNoBinary get a fix-it hint; other
		// errors render verbatim so the operator can debug without
		// shelling around. Both paths share the warn color rather
		// than crit — missing-history is a feature off, not a bug.
		hint := ""
		switch {
		case errors.Is(d.loadErr, history.ErrNotConfigured):
			hint = "  enable with: HISTORY_ENABLED=1 + `milog install history` (provisions sqlite3 + DB schema)"
		case errors.Is(d.loadErr, history.ErrNoBinary):
			hint = "  install with: `milog install history` (resolves apt/dnf/brew per host)"
		}
		b.WriteString("  ")
		b.WriteString(warnStyle.Render(d.loadErr.Error()))
		b.WriteString("\n")
		if hint != "" {
			b.WriteString(dimStyle.Render(hint))
			b.WriteString("\n")
		}
		return b.String()
	}

	if len(d.rows) == 0 {
		b.WriteString("  ")
		b.WriteString(dimStyle.Render(
			"no data in window (quiet host, or daemon hasn't completed a minute yet)",
		))
		b.WriteString("\n")
		return b.String()
	}

	// Layout per row:
	//   2 leading spaces + nameW + 1 + sparkW + 2 + statsW
	// nameW: longest app name in d.rows + 1 padding char
	// sparkW: trendWindowMinutes (= 60 by default)
	// statsW: ~24 chars for "cur=NNN 1h=NNNNNN peak=NNN"
	nameW := 4
	for _, r := range d.rows {
		if len(r.app) > nameW {
			nameW = len(r.app)
		}
	}
	for _, r := range d.rows {
		spark := renderSparkline(r.mins, trendWindowMinutes)
		stats := fmt.Sprintf("cur=%-4d 1h=%-7d peak=%-4d",
			r.cur, r.sum, r.peak)
		b.WriteString(fmt.Sprintf("  %-*s  %s  %s\n",
			nameW, r.app, spark, dimStyle.Render(stats)))
	}
	return b.String()
}

// formatPathsBreakdown renders the per-app counts as a compact
// `app1:N1 app2:N2 …` string capped at width chars. When the path
// shows up under just one app, the breakdown is left blank — the
// total column already conveys the count and the empty per-app
// column visually distinguishes "scan-across-apps" rows from
// "concentrated on one app" rows.
func formatPathsBreakdown(rows []kv, width int) string {
	if len(rows) <= 1 {
		// One-app paths get an empty breakdown — the visual gap
		// signals "not cross-app" at a glance.
		return ""
	}
	var b strings.Builder
	for i, r := range rows {
		seg := fmt.Sprintf("%s:%d", r.key, r.count)
		if i > 0 {
			seg = " " + seg
		}
		if b.Len()+len(seg) > width {
			b.WriteString(" …")
			break
		}
		b.WriteString(seg)
	}
	return b.String()
}

func renderTopPane(title string, rows []kv, width int) string {
	var b strings.Builder
	b.WriteString("  ")
	b.WriteString(labelStyle.Render(title))
	b.WriteString("\n")
	if len(rows) == 0 {
		b.WriteString("  ")
		b.WriteString(dimStyle.Render("(no data — quiet app or fresh start)"))
		return b.String()
	}
	keyW := width - 8 // leave 2 leading spaces + 6 chars for count
	if keyW < 12 {
		keyW = 12
	}
	for _, r := range rows {
		k := r.key
		if len(k) > keyW {
			k = k[:keyW-1] + "…"
		}
		b.WriteString(fmt.Sprintf("  %-*s %5d\n", keyW, k, r.count))
	}
	return b.String()
}

// joinPanesHorizontal stacks two multi-line panes side-by-side, padding
// the left pane's lines so the right pane starts at the same column.
// lipgloss.JoinHorizontal handles ANSI widths correctly — needed because
// our styled strings carry escape codes that confuse plain padding.
func joinPanesHorizontal(left, right string) string {
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

// renderSparkline renders a history ring to a fixed-width string of
// block characters, same palette bash uses.
func renderSparkline(buf []int, width int) string {
	if len(buf) == 0 || width <= 0 {
		return strings.Repeat(" ", width)
	}
	// Trim from the LEFT to width (keep newest samples on the right).
	sparks := buf
	if len(sparks) > width {
		sparks = sparks[len(sparks)-width:]
	}
	maxV := 1
	for _, v := range sparks {
		if v > maxV {
			maxV = v
		}
	}
	var b strings.Builder
	runes := 0
	for _, v := range sparks {
		idx := int(float64(v) / float64(maxV) * float64(len(sparkChars)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		b.WriteRune(sparkChars[idx])
		runes++
	}
	// Left-pad with spaces if we haven't filled the full bar yet.
	// b.Len() is BYTES (block glyphs are multi-byte); we need rune width.
	pad := width - runes
	if pad > 0 {
		return strings.Repeat(" ", pad) + b.String()
	}
	return b.String()
}

func (m model) renderFooter() string {
	status := ""
	if m.status != "" {
		status = " · " + critStyle.Render(m.status)
	}
	keys := "  q:quit  p:pause  r:refresh  +/-:rate (%ds)  ?:help"
	switch m.view {
	case viewOverview:
		keys += "  ↑↓:select  enter:drill  a:alerts  P:paths  e:errors  t:trend"
	case viewDrilldown:
		keys += "  esc:back"
	case viewAlerts:
		keys += "  esc:back"
	case viewPaths:
		keys += "  esc:back"
	case viewErrors:
		keys += "  esc:back"
	case viewTrend:
		keys += "  esc:back"
	}
	return dimStyle.Render(fmt.Sprintf(keys, m.refreshSec) + status)
}

func (m model) renderHelp() string {
	help := strings.TrimSpace(`
  q / Ctrl+C   quit
  p            pause (freezes sparklines + numbers)
  r            refresh right now (bypasses the tick)
  + / =        faster refresh (down to 1s)
  - / _        slower refresh (up to 60s)
  ?            toggle this help

  Overview view:
    ↑/k ↓/j         move row selection
    enter / l       drill into the highlighted app
    a               open the global alerts view
    P               open the paths-cross-app view (capital P; lowercase p is pause)
    e               open the errors aggregation view
    t               open the trend view (per-app sparklines, last hour)

  Drill-down view:
    esc / h         back to overview
    r               refresh the focused-app data now

  Alerts view:
    esc / h         back to overview
    r               reload alerts.log

  Paths view:
    esc / h         back to overview
    r               re-tail every app's log

  Errors view:
    esc / h         back to overview
    r               re-aggregate alerts.log

  Trend view:
    esc / h         back to overview
    r               re-query the SQLite history DB

  MILOG_APPS / MILOG_LOG_DIR pick the apps shown. Config loaded from
  env vars matching the bash side — no separate TUI config.`)
	box := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("8")).
		Padding(0, 2)
	return box.Render(help)
}

// ---- Entry ------------------------------------------------------------

func main() {
	// Non-TTY escape hatches: let CI / packaging scripts inspect the
	// binary without launching bubbletea (which requires a real terminal).
	for _, a := range os.Args[1:] {
		switch a {
		case "-v", "--version":
			fmt.Println("milog-tui v=" + buildVersion)
			return
		case "-h", "--help":
			fmt.Println(`milog-tui — bubbletea TUI for MiLog

USAGE
  milog-tui               run the TUI (needs a terminal)
  milog-tui --version     print version and exit
  milog-tui --help        this message

ENV VARS (shared with bash side)
  MILOG_APPS              space-separated app names
  MILOG_LOG_DIR           nginx access-log directory
  MILOG_REFRESH           seconds between sample ticks

KEYS (inside the TUI)
  q / Ctrl+C   quit            p   pause    r   refresh now
  + / -        adjust rate     ?   toggle help
  ↑/k ↓/j      select row      enter / l   drill into app
  a            open alerts view
  P            open paths-cross-app view (capital P; lowercase p is pause)
  e            open errors aggregation view
  t            open trend view (per-app sparklines, last hour)
  esc / h      back from drill-down / alerts / paths / errors / trend`)
			return
		}
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "milog-tui: config:", err)
		os.Exit(1)
	}
	refresh := cfg.Refresh
	if refresh < minRefreshSec {
		refresh = defaultRefreshS
	}
	m := model{
		cfg:        cfg,
		refreshSec: refresh,
		history:    map[string][]int{},
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatalf("milog-tui: %v", err)
	}
}
