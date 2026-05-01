// milog-tui — bubbletea TUI for MiLog.
//
// Reuses the same internal/* data packages the Go web daemon uses, so
// numbers between `milog tui` and the web dashboard can never drift.
// Bash `milog monitor` stays — this is an additional option, not a
// replacement.
//
// Two views:
//
//	overview    header + system bars + per-app table (default)
//	drilldown   one app: top paths, top IPs, recent alerts
//
// Key bindings:
//
//	q / Ctrl+C  quit (anywhere)
//	p           pause (freeze sparklines)
//	r           refresh now
//	+ / -       decrease / increase refresh interval
//	?           toggle help
//	↑/k ↓/j     move row selection (overview)
//	enter / l   drill into the highlighted app
//	esc / h     leave drill-down → overview
package main

import (
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
		if m.view == viewDrilldown && m.selectedIdx < len(m.apps) {
			batch = append(batch, drilldownSampleCmd(m.cfg, m.apps[m.selectedIdx].name))
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
		when := time.Unix(r.TS, 0).Format("15:04")
		sevStyle := labelStyle
		switch r.Sev {
		case "crit":
			sevStyle = critStyle
		case "warn":
			sevStyle = warnStyle
		}
		title := r.Title
		// Pull the trailing app context off the rule so the row reads
		// `15:04 [crit] panic_go  body…` rather than repeating the app.
		ruleShort := r.Rule
		if len(ruleShort) > 32 {
			ruleShort = ruleShort[:29] + "…"
		}
		body := strings.TrimSpace(strings.Trim(r.Body, "`"))
		if len(body) > 60 {
			body = body[:57] + "…"
		}
		b.WriteString(fmt.Sprintf("  %s %s %s %s\n",
			dimStyle.Render(when),
			sevStyle.Render(fmt.Sprintf("[%s]", r.Sev)),
			ruleShort,
			dimStyle.Render(body)))
		_ = title
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
		keys += "  ↑↓:select  enter:drill"
	case viewDrilldown:
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

  Drill-down view:
    esc / h         back to overview
    r               refresh the focused-app data now

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
  esc / h      back from drill-down`)
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
