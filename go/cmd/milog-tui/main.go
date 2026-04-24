// milog-tui — bubbletea TUI for MiLog.
//
// Reuses the same internal/* data packages the Go web daemon uses, so
// numbers between `milog tui` and the web dashboard can never drift.
// Bash `milog monitor` stays — this is an additional option, not a
// replacement.
//
// Key bindings:
//
//	q / Ctrl+C  quit
//	p           pause (freeze sparklines)
//	r           refresh now
//	+ / -       decrease / increase refresh interval
//	?           toggle help
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

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

// tickMsg triggers a fresh sample pass. Sent via tea.Every.
type tickMsg time.Time

// sampleMsg carries the result of a sample pass (ran off the UI thread).
type sampleMsg struct {
	sys  sysSample
	apps []appSample
	err  error
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
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "p":
			m.paused = !m.paused
			return m, nil
		case "r":
			// Immediate sample, but don't reset the schedule.
			return m, sampleCmd(m.cfg)
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

	case tickMsg:
		// Re-schedule regardless of pause (so the UI stays responsive
		// and unpausing picks up quickly), but only sample when not paused.
		next := tickCmd(m.refreshSec)
		if m.paused {
			return m, next
		}
		return m, tea.Batch(sampleCmd(m.cfg), next)

	case sampleMsg:
		if msg.err != nil {
			m.status = "sample: " + msg.err.Error()
		} else {
			m.status = ""
		}
		m.sys = msg.sys
		m.apps = msg.apps
		m.lastAt = time.Now()
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
	}
	return m, nil
}

// ---- View -------------------------------------------------------------

func (m model) View() string {
	var b strings.Builder

	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")
	b.WriteString(m.renderSystem())
	b.WriteString("\n\n")
	b.WriteString(m.renderApps())
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

	for _, a := range m.apps {
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
		lines = append(lines, fmt.Sprintf("  %-*s  %7d  %7d  %7d  %s  %s  %s",
			nameW, displayName,
			a.count, a.c2xx, a.c3xx,
			errColor.Render(fmt.Sprintf("%7d", a.c4xx)),
			errColor.Render(fmt.Sprintf("%7d", a.c5xx)),
			sparkStyled))
	}
	return strings.Join(lines, "\n")
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
	return dimStyle.Render(fmt.Sprintf("  q:quit  p:pause  r:refresh  +/-:rate (%ds)  ?:help%s",
		m.refreshSec, status))
}

func (m model) renderHelp() string {
	help := strings.TrimSpace(`
  q / Ctrl+C   quit
  p            pause (freezes sparklines + numbers)
  r            refresh right now (bypasses the tick)
  + / =        faster refresh (down to 1s)
  - / _        slower refresh (up to 60s)
  ?            toggle this help

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
  q / Ctrl+C   quit         p   pause    r   refresh now
  + / -        adjust rate  ?   toggle help`)
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
