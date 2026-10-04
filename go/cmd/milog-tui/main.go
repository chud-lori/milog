// milog-tui is the Bubble Tea TUI for MiLog. It shares internal/* with
// milog-web, so both show the same numbers.
//
// Nine views:
//
//	overview    header + system bars + per-app table (default)
//	drilldown   one app: top paths, top IPs, recent alerts
//	alerts      global last-24h alert log, latest first
//	paths       top paths summed across every configured app
//	errors      pattern-fire aggregation (app:* rule keys) with per-source breakdown
//	trend       per-app request-rate sparklines over the last hour from the SQLite history DB
//	history     alerts.log newest first, with per-alert detail and silencing
//	silences    active alerts.silences rows, shared with `milog silence`
//	integrity   audit drift over the last 7 days from the SQLite history DB
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
//	H / S       open alert history / active silences
//	s / x       silence the selected alert's rule / clear the selected silence
//	i           open the integrity view
//	esc / h     leave drill-down / alerts / paths / errors / trend / history / silences / integrity → overview
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

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
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

// sparkChars match the bash monitor's glyphs.
var sparkChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

const (
	sparkLen        = 30 // samples kept per app
	minRefreshSec   = 1
	maxRefreshSec   = 60
	defaultRefreshS = 5

	// Lines parsed per drill-down refresh.
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
	viewHistory
	viewSilences
	viewIntegrity
)

const (
	alertsViewWindow = "24h"
	alertsViewCap    = 50

	// Per app, so total work scales with the app count.
	pathsViewTailLines = 1000
	pathsViewCap       = 12 // top-N rows shown

	errorsViewWindow = "24h"
	errorsViewCap    = 12

	// The daemon writes one row per minute, so 60 minutes is 60 glyphs
	// with no bucketing.
	trendWindowMinutes = 60
)

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

// kv is a name and count for top-N tables.
type kv struct {
	key   string
	count int
}

// drilldownData is computed off the UI goroutine by drilldownSampleCmd.
type drilldownData struct {
	app        string
	topPaths   []kv
	topIPs     []kv
	totalLines int
	aiLines    int
	alerts     []alertlog.Row
	err        error
}

type tickMsg time.Time

type sampleMsg struct {
	sys  sysSample
	apps []appSample
	err  error
}

type drilldownMsg struct {
	data drilldownData
}

type alertsData struct {
	rows  []alertlog.Row // newest first, capped at alertsViewCap
	total int            // total rows within window before capping
	err   error
}

type alertsMsg struct {
	data alertsData
}

// pathRow is one path with its total and per-app counts, sorted at sample time.
type pathRow struct {
	path  string
	total int
	byApp []kv // {app: count}, sorted count-desc
}

type pathsData struct {
	rows        []pathRow
	totalLines  int      // total parsed lines across every app
	appsSampled []string // apps that produced at least one parsed line
	appsErrored []string // apps whose log couldn't be tailed (missing, perm)
}

type pathsMsg struct {
	data pathsData
}

// errorRow is one pattern (the part after `app:<source>:`) with per-source counts.
type errorRow struct {
	pattern  string
	total    int
	bySource []kv
}

type errorsData struct {
	rows        []errorRow
	totalFires  int      // total app:* rule fires within window
	sourcesSeen []string // distinct sources that had at least one fire
	err         error    // alertlog read failure (rare)
}

type errorsMsg struct {
	data errorsData
}

// trendRow is one app's per-minute requests over the window.
type trendRow struct {
	app  string
	mins []int // length up to trendWindowMinutes, oldest → newest
	cur  int
	peak int
	sum  int
}

type trendData struct {
	rows []trendRow
	// ErrNotConfigured, ErrNoBinary or another LoadMinutes error; nil
	// with no rows just means a quiet host.
	loadErr error
}

type trendMsg struct {
	data trendData
}

type keyMap struct {
	Quit    key.Binding
	Pause   key.Binding
	Refresh key.Binding
	Faster  key.Binding
	Slower  key.Binding
	Help    key.Binding

	Up    key.Binding
	Down  key.Binding
	Drill key.Binding

	Alerts key.Binding
	Paths  key.Binding
	Errors key.Binding
	Trend  key.Binding
	Back   key.Binding

	Integrity key.Binding

	PageDown key.Binding
	PageUp   key.Binding
	HalfDown key.Binding
	HalfUp   key.Binding
}

func newKeyMap() keyMap {
	return keyMap{
		Quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Pause:   key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause")),
		Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		Faster:  key.NewBinding(key.WithKeys("+", "="), key.WithHelp("+/-", "rate")),
		Slower:  key.NewBinding(key.WithKeys("-", "_"), key.WithHelp("+/-", "rate")),
		Help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),

		Up:    key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:  key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Drill: key.NewBinding(key.WithKeys("enter", "l", "right"), key.WithHelp("enter/l", "drill")),

		Alerts: key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "alerts")),
		Paths:  key.NewBinding(key.WithKeys("P"), key.WithHelp("P", "paths")),
		Errors: key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "errors")),
		Trend:  key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "trend")),
		Back:   key.NewBinding(key.WithKeys("esc", "h", "left", "backspace"), key.WithHelp("esc", "back")),

		Integrity: key.NewBinding(key.WithKeys("i"), key.WithHelp("i", "integrity")),

		PageDown: key.NewBinding(key.WithKeys("pgdown", " ", "f"), key.WithHelp("f/pgdn", "page down")),
		PageUp:   key.NewBinding(key.WithKeys("pgup", "b"), key.WithHelp("b/pgup", "page up")),
		HalfDown: key.NewBinding(key.WithKeys("d", "ctrl+d"), key.WithHelp("d", "½ down")),
		HalfUp:   key.NewBinding(key.WithKeys("u", "ctrl+u"), key.WithHelp("u", "½ up")),
	}
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
	keys     keyMap
	help     help.Model
	viewport viewport.Model

	view        viewMode
	selectedIdx int           // highlighted row in overview
	drill       drilldownData // current drill-down payload (empty when in overview)
	alerts      alertsData    // current alerts-view payload (empty when not in viewAlerts)
	paths       pathsData     // current paths-view payload (empty when not in viewPaths)
	errors      errorsData    // current errors-view payload (empty when not in viewErrors)
	trend       trendData     // current trend-view payload (empty when not in viewTrend)
	hist        historyState  // history and silences views
	integrity   integrityData // current integrity-view payload (empty when not in viewIntegrity)
}

// sampleCmd runs the blocking sampling off the UI goroutine.
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

func tickCmd(sec int) tea.Cmd {
	return tea.Tick(time.Duration(sec)*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// drilldownSampleCmd computes top paths and IPs from the app's log tail,
// plus 24h alerts with a rule-key segment equal to the app (e.g. 5xx:api,
// app:api:panic_go). Whole segments, so overlapping app names don't match.
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
			if nginxlog.IsAICrawler(ln.UA) {
				d.aiLines++
			}
		}
		d.topPaths = topN(paths, drilldownTopN)
		d.topIPs = topN(ips, drilldownTopN)

		cutoff, _ := alertlog.WindowToCutoff("24h", time.Now())
		rows, _ := alertlog.Load(filepath.Join(cfg.AlertStateDir, "alerts.log"), cutoff, 0)
		var hits []alertlog.Row
		for _, r := range rows {
			if ruleMentionsApp(r.Rule, app) {
				hits = append(hits, r)
			}
		}
		if len(hits) > drilldownAlertsCap {
			hits = hits[len(hits)-drilldownAlertsCap:]
		}
		// Keep the newest drilldownAlertsCap, newest first.
		for i, j := 0, len(hits)-1; i < j; i, j = i+1, j-1 {
			hits[i], hits[j] = hits[j], hits[i]
		}
		d.alerts = hits

		return drilldownMsg{data: d}
	}
}

// alertsSampleCmd loads every rule's alerts in the window, newest first,
// capped at alertsViewCap.
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
		// Load returns oldest first; cap before reversing so the newest rows survive.
		if len(rows) > alertsViewCap {
			rows = rows[len(rows)-alertsViewCap:]
		}
		for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
			rows[i], rows[j] = rows[j], rows[i]
		}
		d.rows = rows
		return alertsMsg{data: d}
	}
}

// trendSampleCmd aligns per-minute history rows to fixed minute slots so
// apps line up. Errors go to the view, which shows a fix-it hint for a
// missing history DB or sqlite3.
func trendSampleCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var d trendData
		// One extra minute because the daemon writes the previous
		// minute, so the newest row can sit just past an hour.
		since := time.Now().Add(-time.Duration(trendWindowMinutes+1) * time.Minute).Unix()
		raw, err := history.LoadMinutes(cfg.HistoryDB, since)
		if err != nil {
			d.loadErr = err
			return trendMsg{data: d}
		}

		// Configured apps first, then apps only present in the DB, so
		// rows don't reorder between ticks.
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
			// Slot 0 is the oldest minute and the last slot is now; idle
			// minutes stay 0.
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

// parseAppRule splits `app:<source>:<pattern>`; ok is false for other keys.
// Only the first colon after the source splits, since user patterns may
// contain colons.
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

// errorsSampleCmd counts `app:*` fires in the window per pattern and
// source, returning the top errorsViewCap patterns.
func errorsSampleCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var d errorsData
		cutoff, _ := alertlog.WindowToCutoff(errorsViewWindow, time.Now())
		rows, err := alertlog.Load(filepath.Join(cfg.AlertStateDir, "alerts.log"), cutoff, 0)
		if err != nil {
			d.err = err
			return errorsMsg{data: d}
		}
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
		// Total desc, then name, so equal counts don't reorder between ticks.
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

// pathsSampleCmd sums path hits across every app's log tail, keeping a
// per-app breakdown; a path spread across apps is the scanner signature.
// Unreadable logs are listed in appsErrored without failing the sample.
func pathsSampleCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var d pathsData
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
		// Total desc, then path, so equal counts don't reorder between ticks.
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

// topN returns the n highest counts, ties broken by key.
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

// ruleMentionsApp reports whether any colon-separated segment of rule is app.
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

func (m model) controls() keyMap {
	if !m.keys.Quit.Enabled() {
		return newKeyMap()
	}
	return m.keys
}

func (m model) Init() tea.Cmd {
	return tea.Batch(sampleCmd(m.cfg), tickCmd(m.refreshSec))
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width
		m.viewport.Width = msg.Width
		m.viewport.Height = m.viewportHeight()
		m.viewport.SetYOffset(m.viewport.YOffset)
		return m, nil

	case tea.KeyMsg:
		if m.hist.prompting {
			return m.updateSilencePrompt(msg)
		}
		keys := m.controls()
		// Keys that behave the same in every view.
		switch {
		case key.Matches(msg, keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, keys.Pause):
			m.paused = !m.paused
			return m, nil
		case key.Matches(msg, keys.Faster):
			// `=` is unshifted `+` on US layouts.
			if m.refreshSec > minRefreshSec {
				m.refreshSec--
			}
			return m, nil
		case key.Matches(msg, keys.Slower):
			if m.refreshSec < maxRefreshSec {
				m.refreshSec++
			}
			return m, nil
		case key.Matches(msg, keys.Help):
			m.showHelp = !m.showHelp
			return m, nil
		case key.Matches(msg, keys.Refresh):
			switch m.view {
			case viewDrilldown:
				if m.selectedIdx < len(m.apps) {
					return m, drilldownSampleCmd(m.cfg, m.apps[m.selectedIdx].name)
				}
				return m, nil
			case viewAlerts:
				return m, alertsSampleCmd(m.cfg)
			case viewPaths:
				return m, pathsSampleCmd(m.cfg)
			case viewErrors:
				return m, errorsSampleCmd(m.cfg)
			case viewTrend:
				return m, trendSampleCmd(m.cfg)
			case viewHistory, viewSilences:
				return m, historyLoadCmd(m.cfg)
			case viewIntegrity:
				return m, integritySampleCmd(m.cfg)
			default:
				return m, sampleCmd(m.cfg)
			}
		}
		if next, cmd, handled := m.updateHistoryKey(msg); handled {
			return next, cmd
		}
		switch m.view {
		case viewOverview:
			switch {
			case key.Matches(msg, keys.Up):
				if m.selectedIdx > 0 {
					m.selectedIdx--
				}
				return m, nil
			case key.Matches(msg, keys.Down):
				if m.selectedIdx < len(m.apps)-1 {
					m.selectedIdx++
				}
				return m, nil
			case key.Matches(msg, keys.Drill):
				if len(m.apps) == 0 {
					return m, nil
				}
				if m.selectedIdx >= len(m.apps) {
					m.selectedIdx = len(m.apps) - 1
				}
				m.view = viewDrilldown
				m.resetViewport()
				return m, drilldownSampleCmd(m.cfg, m.apps[m.selectedIdx].name)
			case key.Matches(msg, keys.Alerts):
				m.view = viewAlerts
				m.resetViewport()
				return m, alertsSampleCmd(m.cfg)
			case key.Matches(msg, keys.Paths):
				// Capital P, because p is the global pause.
				m.view = viewPaths
				m.resetViewport()
				return m, pathsSampleCmd(m.cfg)
			case key.Matches(msg, keys.Errors):
				m.view = viewErrors
				m.resetViewport()
				return m, errorsSampleCmd(m.cfg)
			case key.Matches(msg, keys.Trend):
				m.view = viewTrend
				m.resetViewport()
				return m, trendSampleCmd(m.cfg)
			case key.Matches(msg, keys.Integrity):
				m.view = viewIntegrity
				m.resetViewport()
				return m, integritySampleCmd(m.cfg)
			}
		case viewDrilldown:
			switch {
			case key.Matches(msg, keys.Back):
				m.view = viewOverview
				m.drill = drilldownData{}
				m.resetViewport()
				return m, nil
			}
		case viewAlerts:
			switch {
			case key.Matches(msg, keys.Back):
				m.view = viewOverview
				m.alerts = alertsData{}
				m.resetViewport()
				return m, nil
			}
		case viewPaths:
			switch {
			case key.Matches(msg, keys.Back):
				m.view = viewOverview
				m.paths = pathsData{}
				m.resetViewport()
				return m, nil
			}
		case viewErrors:
			switch {
			case key.Matches(msg, keys.Back):
				m.view = viewOverview
				m.errors = errorsData{}
				m.resetViewport()
				return m, nil
			}
		case viewTrend:
			switch {
			case key.Matches(msg, keys.Back):
				m.view = viewOverview
				m.trend = trendData{}
				m.resetViewport()
				return m, nil
			}
		case viewIntegrity:
			switch {
			case key.Matches(msg, keys.Back):
				m.view = viewOverview
				m.integrity = integrityData{}
				m.resetViewport()
				return m, nil
			}
		}
		if m.view != viewOverview {
			m.syncViewportContent()
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}

	case tickMsg:
		// Keep ticking while paused so unpausing is quick; just skip sampling.
		next := tickCmd(m.refreshSec)
		if m.paused {
			return m, next
		}
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
		case viewHistory, viewSilences:
			batch = append(batch, historyLoadCmd(m.cfg))
		case viewIntegrity:
			batch = append(batch, integritySampleCmd(m.cfg))
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
		if m.selectedIdx >= len(m.apps) {
			m.selectedIdx = len(m.apps) - 1
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
		}
		// Skip while paused so unpausing doesn't append a backdated jump.
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
		m.syncViewportContent()

	case alertsMsg:
		m.alerts = msg.data
		if msg.data.err != nil {
			m.status = "alerts: " + msg.data.err.Error()
		}
		m.syncViewportContent()

	case pathsMsg:
		m.paths = msg.data
		m.syncViewportContent()

	case errorsMsg:
		m.errors = msg.data
		if msg.data.err != nil {
			m.status = "errors: " + msg.data.err.Error()
		}
		m.syncViewportContent()

	case trendMsg:
		m.trend = msg.data
		// The trend view shows loadErr inline, so leave m.status alone.
		m.syncViewportContent()

	case historyMsg:
		m.applyHistory(msg)
		m.syncViewportContent()

	case silenceDoneMsg:
		return m.applySilenceDone(msg)
	case integrityMsg:
		m.integrity = msg.data
		m.syncViewportContent()
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder

	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")
	body := m.renderBodyContent()
	if m.view != viewOverview {
		body = m.renderViewport(body)
	}
	b.WriteString(body)
	b.WriteString("\n")
	b.WriteString(m.renderFooter())
	if m.showHelp {
		b.WriteString("\n\n")
		b.WriteString(m.renderHelp())
	}
	return b.String()
}

func (m *model) resetViewport() {
	m.viewport.YOffset = 0
}

func (m *model) syncViewportContent() {
	if m.view == viewOverview {
		return
	}
	m.viewport.Width = m.width
	m.viewport.Height = m.viewportHeight()
	m.viewport.SetContent(m.renderBodyContent())
	m.viewport.SetYOffset(m.viewport.YOffset)
}

func (m model) viewportHeight() int {
	if m.height <= 0 {
		return 0
	}
	h := m.height - 4 // header, spacer, footer, and body/footer separator.
	if m.showHelp {
		h -= lipgloss.Height(m.renderHelp()) + 2
	}
	if h < 1 {
		return 1
	}
	return h
}

func (m model) renderViewport(content string) string {
	h := m.viewportHeight()
	if h <= 0 {
		return content
	}
	vp := m.viewport
	vp.Width = m.width
	vp.Height = h
	vp.SetContent(content)
	return vp.View()
}

func (m model) renderBodyContent() string {
	switch m.view {
	case viewDrilldown:
		return m.renderDrilldown()
	case viewAlerts:
		return m.renderAlertsView()
	case viewPaths:
		return m.renderPathsView()
	case viewErrors:
		return m.renderErrorsView()
	case viewTrend:
		return m.renderTrendView()
	case viewHistory:
		return m.renderHistoryView()
	case viewSilences:
		return m.renderSilencesView()
	case viewIntegrity:
		return m.renderIntegrityView()
	default:
		var overview strings.Builder
		overview.WriteString(m.renderSystem())
		overview.WriteString("\n\n")
		overview.WriteString(m.renderApps())
		return overview.String()
	}
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
	pad := 0
	if m.width > lipgloss.Width(left)+lipgloss.Width(right) {
		pad = m.width - lipgloss.Width(left) - lipgloss.Width(right)
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, left, strings.Repeat(" ", pad), right)
}

// renderSystem draws CPU/MEM/DISK bars sized to fit one line.
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
		// `›` is one column, so the cursor keeps rows aligned.
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

// renderDrilldown shows placeholders rather than blank panes for an idle app.
func (m model) renderDrilldown() string {
	d := m.drill
	if d.app == "" {
		return dimStyle.Render("  loading drill-down…")
	}
	var b strings.Builder

	scanned := fmt.Sprintf("(scanned %d recent lines)", d.totalLines)
	if d.totalLines > 0 {
		scanned = fmt.Sprintf("(scanned %d recent lines, AI crawlers %d%%)", d.totalLines, d.aiLines*100/d.totalLines)
	}
	subhead := fmt.Sprintf("  %s %s   %s",
		labelStyle.Render("APP"),
		titleStyle.Render(d.app),
		dimStyle.Render(scanned))
	b.WriteString(subhead)
	b.WriteString("\n\n")

	colW := (m.width - 6) / 2
	if colW < 24 {
		colW = 24
	}
	pathPane := renderTopPane("TOP PATHS", d.topPaths, colW)
	ipPane := renderTopPane("TOP IPs", d.topIPs, colW)
	b.WriteString(joinPanesHorizontal(pathPane, ipPane))
	b.WriteString("\n")

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

// renderAlertRow: `<HH:MM> [<sev>] <rule>  <body>`, with the ``` fences
// stripped and the body capped at 60 chars to fit 100 columns.
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
	body := ttySafe(strings.TrimSpace(strings.Trim(r.Body, "`")))
	if len(body) > 60 {
		body = body[:57] + "…"
	}
	return fmt.Sprintf("  %s %s %s %s\n",
		dimStyle.Render(when),
		sevStyle.Render(fmt.Sprintf("[%s]", r.Sev)),
		ruleShort,
		dimStyle.Render(body))
}

// renderAlertsView tells "no alerts in window" apart from "couldn't load
// alerts.log".
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

// renderPathsView: a path near the top with hits on every app is usually a
// scanner (/wp-login.php, /.git/config).
func (m model) renderPathsView() string {
	d := m.paths
	var b strings.Builder

	b.WriteString("  ")
	b.WriteString(labelStyle.Render(fmt.Sprintf(
		"TOP PATHS — across %d app(s), last %d lines/app",
		len(d.appsSampled), pathsViewTailLines,
	)))
	b.WriteString("\n")

	// Unreadable logs get an inline note instead of silently disappearing.
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

	// 6-char count, path, breakdown; m.width-4 leaves 2-char margins.
	pathW := m.width - 6 - 2 - 30 - 4
	if pathW < 20 {
		pathW = 20
	}
	for _, r := range d.rows {
		key := ttySafe(r.path)
		if len(key) > pathW {
			key = key[:pathW-1] + "…"
		}
		breakdown := formatPathsBreakdown(r.byApp, 30)
		b.WriteString(fmt.Sprintf("  %5d  %-*s  %s\n",
			r.total, pathW, key, dimStyle.Render(breakdown)))
	}
	return b.String()
}

// renderErrorsView: one pattern firing on every source usually means a
// shared regression hitting every app at once.
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
			// Unreachable while totalFires > 0 implies rows; kept as a guard.
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

	// 5-char count, pattern, 30-char breakdown; the pattern takes the rest.
	patW := m.width - 6 - 2 - 30 - 4
	if patW < 20 {
		patW = 20
	}
	for _, r := range d.rows {
		key := r.pattern
		if len(key) > patW {
			key = key[:patW-1] + "…"
		}
		breakdown := formatPathsBreakdown(r.bySource, 30)
		b.WriteString(fmt.Sprintf("  %5d  %-*s  %s\n",
			r.total, patW, key, dimStyle.Render(breakdown)))
	}
	return b.String()
}

// renderTrendView draws one sparkline per app, one glyph per minute:
//
//	app   ▁▂▅▇▆▃▂▁ ··· ▆█▇▅  cur=12 1h=4567 peak=89
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
		// Warn colour, not crit: missing history is a disabled
		// feature, not a fault.
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

	// Row: 2 spaces, name, sparkline (trendWindowMinutes wide), ~24-char stats.
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

// formatPathsBreakdown renders `app1:N1 app2:N2 …` within width; a single
// app gets an empty string so cross-app rows stand out.
func formatPathsBreakdown(rows []kv, width int) string {
	if len(rows) <= 1 {
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

// ttySafe replaces C0 controls (except tab), DEL and C1 with '?' so log text can't drive the terminal.
func ttySafe(s string) string {
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t') || (r >= 0x7f && r <= 0x9f) {
			return '?'
		}
		return r
	}, s)
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
		k := ttySafe(r.key)
		if len(k) > keyW {
			k = k[:keyW-1] + "…"
		}
		b.WriteString(fmt.Sprintf("  %-*s %5d\n", keyW, k, r.count))
	}
	return b.String()
}

// joinPanesHorizontal uses lipgloss because styled strings carry ANSI
// codes that break plain padding.
func joinPanesHorizontal(left, right string) string {
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

// renderSparkline keeps the newest samples on the right.
func renderSparkline(buf []int, width int) string {
	if len(buf) == 0 || width <= 0 {
		return strings.Repeat(" ", width)
	}
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
	// Pad by rune count; block glyphs are multi-byte.
	pad := width - runes
	if pad > 0 {
		return strings.Repeat(" ", pad) + b.String()
	}
	return b.String()
}

func (m model) renderFooter() string {
	if m.hist.prompting {
		return m.renderSilencePrompt()
	}
	status := ""
	if m.status != "" {
		status = " · " + critStyle.Render(m.status)
	}
	keys := m.controls()
	parts := []string{
		bindingHint(keys.Quit),
		bindingHint(keys.Pause),
		bindingHint(keys.Refresh),
		fmt.Sprintf("%s (%ds)", bindingHint(keys.Faster), m.refreshSec),
		bindingHint(keys.Help),
	}
	switch m.view {
	case viewOverview:
		parts = append(parts,
			"↑↓:select",
			bindingHint(keys.Drill),
			bindingHint(keys.Alerts),
			bindingHint(keys.Paths),
			bindingHint(keys.Errors),
			bindingHint(keys.Trend),
			bindingHint(historyKeys.History),
			bindingHint(historyKeys.Silences),
			bindingHint(keys.Integrity),
		)
	case viewDrilldown:
		parts = append(parts, bindingHint(keys.Back), "↑↓:scroll", bindingHint(keys.PageDown), bindingHint(keys.PageUp))
	case viewAlerts:
		parts = append(parts, bindingHint(keys.Back), "↑↓:scroll", bindingHint(keys.PageDown), bindingHint(keys.PageUp))
	case viewPaths:
		parts = append(parts, bindingHint(keys.Back), "↑↓:scroll", bindingHint(keys.PageDown), bindingHint(keys.PageUp))
	case viewErrors:
		parts = append(parts, bindingHint(keys.Back), "↑↓:scroll", bindingHint(keys.PageDown), bindingHint(keys.PageUp))
	case viewTrend:
		parts = append(parts, bindingHint(keys.Back), "↑↓:scroll", bindingHint(keys.PageDown), bindingHint(keys.PageUp))
	case viewHistory, viewSilences:
		parts = append(parts, historyFooterHints(m)...)
	case viewIntegrity:
		parts = append(parts, bindingHint(keys.Back), "↑↓:scroll", bindingHint(keys.PageDown), bindingHint(keys.PageUp))
	}
	return dimStyle.Render("  " + strings.Join(parts, "  ") + status)
}

func (m model) renderHelp() string {
	h := m.help
	if h.Width == 0 {
		h = help.New()
	}
	h.Width = m.width
	h.ShowAll = true
	help := h.View(m)
	if help == "" {
		return ""
	}
	box := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("8")).
		Padding(0, 2)
	return box.Render(help)
}

func bindingHint(b key.Binding) string {
	h := b.Help()
	return h.Key + ":" + h.Desc
}

func (m model) ShortHelp() []key.Binding {
	keys := m.controls()
	out := []key.Binding{keys.Quit, keys.Pause, keys.Refresh, keys.Faster, keys.Help}
	switch m.view {
	case viewOverview:
		out = append(out, keys.Up, keys.Down, keys.Drill, keys.Alerts, keys.Paths, keys.Errors, keys.Trend, historyKeys.History, historyKeys.Silences, keys.Integrity)
	default:
		out = append(out, keys.Up, keys.Down, keys.PageDown, keys.PageUp, keys.Back)
	}
	return out
}

func (m model) FullHelp() [][]key.Binding {
	keys := m.controls()
	groups := [][]key.Binding{
		{keys.Quit, keys.Pause, keys.Refresh, keys.Faster, keys.Slower, keys.Help},
	}
	switch m.view {
	case viewOverview:
		groups = append(groups, []key.Binding{
			keys.Up, keys.Down, keys.Drill, keys.Alerts, keys.Paths, keys.Errors, keys.Trend,
			historyKeys.History, historyKeys.Silences, keys.Integrity,
		})
	default:
		groups = append(groups, []key.Binding{
			keys.Up, keys.Down, keys.Back,
		})
		groups = append(groups, []key.Binding{
			keys.PageDown, keys.PageUp, keys.HalfDown, keys.HalfUp,
		})
	}
	return groups
}

func main() {
	// Handle -v/-h before Bubble Tea, which needs a real terminal.
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
  H            open alert history (enter: detail, s: silence the rule)
  S            open active silences (x: clear one)
  i            open integrity view (audit drift, last 7 days)
  ↑/k ↓/j      scroll focused views; f/pgdn and b/pgup page
  esc / h      back from any view to the overview`)
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
		keys:       newKeyMap(),
		help:       help.New(),
		viewport:   viewport.New(0, 0),
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatalf("milog-tui: %v", err)
	}
}
