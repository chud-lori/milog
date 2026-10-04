package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/chud-lori/milog/internal/alertlog"
	"github.com/chud-lori/milog/internal/config"
)

const (
	historyViewCap  = 500
	defaultSilence  = "1h"
	historyHeadRows = 3 // title, status and blank or column-header lines sit above the list
)

var historyKeys = struct {
	History, Silences, Silence, Clear key.Binding
}{
	History:  key.NewBinding(key.WithKeys("H"), key.WithHelp("H", "history")),
	Silences: key.NewBinding(key.WithKeys("S"), key.WithHelp("S", "silences")),
	Silence:  key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "silence")),
	Clear:    key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "clear")),
}

type historyState struct {
	rows      []alertlog.Row // newest first
	silences  []alertlog.Silence
	err       error
	cursor    int
	silCursor int
	detail    *alertlog.Row

	prompting  bool
	promptRule string
	input      string
	note       string // outcome of the last silence or clear
}

type historyMsg struct {
	rows     []alertlog.Row
	silences []alertlog.Silence
	err      error
}

type silenceDoneMsg struct {
	note string
	err  error
}

func silencesPath(cfg *config.Config) string {
	return filepath.Join(cfg.AlertStateDir, "alerts.silences")
}

func historyLoadCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		rows, err := alertlog.Load(filepath.Join(cfg.AlertStateDir, "alerts.log"), 0, historyViewCap)
		for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
			rows[i], rows[j] = rows[j], rows[i]
		}
		sil, serr := alertlog.LoadSilences(silencesPath(cfg), time.Now())
		if err == nil {
			err = serr
		}
		return historyMsg{rows: rows, silences: sil, err: err}
	}
}

func addSilenceCmd(cfg *config.Config, rule string, d time.Duration) tea.Cmd {
	return func() tea.Msg {
		s, err := alertlog.AddSilence(silencesPath(cfg), rule, d, "", time.Now())
		if err != nil {
			return silenceDoneMsg{err: err}
		}
		return silenceDoneMsg{note: fmt.Sprintf("silenced %s until %s",
			rule, time.Unix(s.Until, 0).Format("2006-01-02 15:04"))}
	}
}

func clearSilenceCmd(cfg *config.Config, rule string) tea.Cmd {
	return func() tea.Msg {
		removed, err := alertlog.RemoveSilence(silencesPath(cfg), rule)
		switch {
		case err != nil:
			return silenceDoneMsg{err: err}
		case !removed:
			return silenceDoneMsg{note: "no silence on " + rule}
		}
		return silenceDoneMsg{note: "cleared silence on " + rule}
	}
}

func (m model) applySilenceDone(msg silenceDoneMsg) (tea.Model, tea.Cmd) {
	m.hist.note = msg.note
	if msg.err != nil {
		m.hist.note = "silence: " + msg.err.Error()
	}
	return m, historyLoadCmd(m.cfg)
}

// applyHistory keeps the cursor on the same alert when new fires push rows down.
func (m *model) applyHistory(msg historyMsg) {
	h := &m.hist
	if h.cursor < len(h.rows) {
		prev := h.rows[h.cursor]
		for i, r := range msg.rows {
			if r == prev {
				h.cursor = i
				break
			}
		}
	}
	h.rows, h.silences, h.err = msg.rows, msg.silences, msg.err
	h.cursor = clampIndex(h.cursor, len(h.rows))
	h.silCursor = clampIndex(h.silCursor, len(h.silences))
}

func clampIndex(i, n int) int {
	if i >= n {
		i = n - 1
	}
	if i < 0 {
		return 0
	}
	return i
}

func (m model) updateSilencePrompt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	h := &m.hist
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		h.prompting, h.note = false, ""
	case tea.KeyEnter:
		in := strings.TrimSpace(h.input)
		if in == "" {
			in = defaultSilence
		}
		d, err := alertlog.ParseDuration(in)
		if err != nil {
			h.note = err.Error()
			return m, nil
		}
		h.prompting = false
		return m, addSilenceCmd(m.cfg, h.promptRule, d)
	case tea.KeyBackspace:
		if r := []rune(h.input); len(r) > 0 {
			h.input = string(r[:len(r)-1])
		}
	case tea.KeyRunes:
		if len([]rune(h.input)) < 12 {
			h.input += string(msg.Runes)
		}
	}
	return m, nil
}

// updateHistoryKey handles keys owned by the history and silences views;
// handled is false for keys the shared handlers should get.
func (m model) updateHistoryKey(msg tea.KeyMsg) (tea.Model, tea.Cmd, bool) {
	keys := m.controls()
	h := &m.hist
	if m.view == viewOverview || m.view == viewHistory || m.view == viewSilences {
		switch {
		case key.Matches(msg, historyKeys.History):
			m.view, h.detail, h.note = viewHistory, nil, ""
			m.resetViewport()
			return m, historyLoadCmd(m.cfg), true
		case key.Matches(msg, historyKeys.Silences):
			m.view, h.detail, h.note = viewSilences, nil, ""
			m.resetViewport()
			return m, historyLoadCmd(m.cfg), true
		}
	}

	switch m.view {
	case viewHistory:
		switch {
		case key.Matches(msg, keys.Back):
			if h.detail != nil {
				h.detail = nil
				m.resetViewport()
				m.followCursor(h.cursor)
			} else {
				m.view, m.hist = viewOverview, historyState{}
				m.resetViewport()
			}
			return m, nil, true
		case key.Matches(msg, historyKeys.Silence):
			rule := ""
			if h.detail != nil {
				rule = h.detail.Rule
			} else if h.cursor < len(h.rows) {
				rule = h.rows[h.cursor].Rule
			}
			if rule != "" {
				h.prompting, h.promptRule, h.input, h.note = true, rule, "", ""
			}
			return m, nil, true
		case h.detail != nil:
			return m, nil, false
		case key.Matches(msg, keys.Drill):
			if h.cursor < len(h.rows) {
				r := h.rows[h.cursor]
				h.detail = &r
				m.resetViewport()
				m.syncViewportContent()
			}
			return m, nil, true
		case key.Matches(msg, keys.Up), key.Matches(msg, keys.Down):
			h.cursor = clampIndex(h.cursor+step(msg, keys), len(h.rows))
			m.followCursor(h.cursor)
			return m, nil, true
		}
	case viewSilences:
		switch {
		case key.Matches(msg, keys.Back):
			m.view, m.hist = viewOverview, historyState{}
			m.resetViewport()
			return m, nil, true
		case key.Matches(msg, historyKeys.Clear):
			if h.silCursor < len(h.silences) {
				return m, clearSilenceCmd(m.cfg, h.silences[h.silCursor].Key), true
			}
			return m, nil, true
		case key.Matches(msg, keys.Up), key.Matches(msg, keys.Down):
			h.silCursor = clampIndex(h.silCursor+step(msg, keys), len(h.silences))
			m.followCursor(h.silCursor)
			return m, nil, true
		}
	}
	return m, nil, false
}

func step(msg tea.KeyMsg, keys keyMap) int {
	if key.Matches(msg, keys.Up) {
		return -1
	}
	return 1
}

// followCursor scrolls the viewport just enough to keep list row i on screen.
func (m *model) followCursor(i int) {
	line := historyHeadRows + i
	h := m.viewportHeight()
	if line < m.viewport.YOffset {
		m.viewport.YOffset = line
	} else if h > 0 && line >= m.viewport.YOffset+h {
		m.viewport.YOffset = line - h + 1
	}
	m.syncViewportContent()
}

func (m model) silenceFor(rule string) (alertlog.Silence, bool) {
	for _, s := range m.hist.silences {
		if s.Matches(rule) {
			return s, true
		}
	}
	return alertlog.Silence{}, false
}

func (m model) historyStatus(summary string) string {
	if m.hist.err != nil {
		return "  " + critStyle.Render("error: "+m.hist.err.Error())
	}
	return "  " + dimStyle.Render(summary)
}

// renderSilencePrompt replaces the footer so the prompt stays visible however far the list is scrolled.
func (m model) renderSilencePrompt() string {
	h := m.hist
	return "  " + warnStyle.Render(fmt.Sprintf("silence %s for (enter: %s, esc: cancel, e.g. 30m 2h 1d): ",
		ttySafe(h.promptRule), defaultSilence)) + h.input + "█  " + critStyle.Render(h.note)
}

func (m model) renderHistoryView() string {
	h := m.hist
	if h.detail != nil {
		return m.renderHistoryDetail(*h.detail)
	}
	var b strings.Builder
	b.WriteString("  " + labelStyle.Render("ALERT HISTORY (alerts.log, newest first)") + "\n")
	summary := fmt.Sprintf("%d fires, %d active silences", len(h.rows), len(h.silences))
	if len(h.rows) == historyViewCap {
		summary = fmt.Sprintf("latest %d fires, %d active silences", historyViewCap, len(h.silences))
	}
	b.WriteString(m.historyStatus(summary) + "\n\n")
	if len(h.rows) == 0 {
		b.WriteString("  " + dimStyle.Render("no alerts recorded yet (quiet host, or the daemon is not running)"))
		return b.String()
	}

	bodyW := m.width - 2 - 11 - 1 - 6 - 1 - 32 - 1 - 8 - 2
	if bodyW < 20 {
		bodyW = 20
	}
	for i, r := range h.rows {
		cursor := "  "
		if i == h.cursor {
			cursor = warnStyle.Render("› ")
		}
		mark := ""
		if _, ok := m.silenceFor(r.Rule); ok {
			mark = "silenced"
		}
		b.WriteString(fmt.Sprintf("%s%s %s %-32s %s  %s\n",
			cursor,
			dimStyle.Render(time.Unix(r.TS, 0).Format("01-02 15:04")),
			sevStyle(r.Sev).Render(fmt.Sprintf("%-6s", "["+r.Sev+"]")),
			truncate(ttySafe(r.Rule), 32),
			warnStyle.Render(fmt.Sprintf("%-8s", mark)),
			dimStyle.Render(truncate(alertBody(r), bodyW))))
	}
	return b.String()
}

func (m model) renderHistoryDetail(r alertlog.Row) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  %s %s  %s  %s\n",
		labelStyle.Render("ALERT"), titleStyle.Render(ttySafe(r.Rule)),
		sevStyle(r.Sev).Render("["+r.Sev+"]"),
		dimStyle.Render(time.Unix(r.TS, 0).Format("2006-01-02 15:04:05"))))
	status := "not silenced"
	if s, ok := m.silenceFor(r.Rule); ok {
		status = fmt.Sprintf("silenced by %s until %s (%s)", ttySafe(s.Key),
			time.Unix(s.Until, 0).Format("2006-01-02 15:04"), ttySafe(s.AddedBy))
	}
	b.WriteString(m.historyStatus(status) + "\n\n")

	wrap := lipgloss.NewStyle().Width(max(m.width-4, 20))
	b.WriteString("  " + ttySafe(r.Title) + "\n")
	for _, ln := range strings.Split(wrap.Render(alertBody(r)), "\n") {
		b.WriteString("  " + ln + "\n")
	}

	ip := firstIP(r.Body)
	b.WriteString("\n")
	if ip == "" {
		b.WriteString("  " + dimStyle.Render("no client IP in this alert body") + "\n")
		return b.String()
	}
	var others []alertlog.Row
	for _, o := range m.hist.rows {
		if o != r && firstIP(o.Body) == ip {
			others = append(others, o)
		}
	}
	b.WriteString("  " + labelStyle.Render(fmt.Sprintf("OTHER FIRES FROM %s (%d in the loaded history)", ip, len(others))) + "\n")
	for _, o := range others {
		b.WriteString(fmt.Sprintf("  %s %s %s\n",
			dimStyle.Render(time.Unix(o.TS, 0).Format("01-02 15:04")),
			sevStyle(o.Sev).Render("["+o.Sev+"]"),
			ttySafe(o.Rule)))
	}
	return b.String()
}

func (m model) renderSilencesView() string {
	h := m.hist
	var b strings.Builder
	b.WriteString("  " + labelStyle.Render("ACTIVE SILENCES (alerts.silences, shared with `milog silence`)") + "\n")
	b.WriteString(m.historyStatus(fmt.Sprintf("%d active", len(h.silences))) + "\n")
	if len(h.silences) == 0 {
		b.WriteString("\n  " + dimStyle.Render("none. Press s on a row in alert history (H) to silence its rule."))
		return b.String()
	}
	b.WriteString(labelStyle.Render(fmt.Sprintf("  %-28s %-16s %-9s %-10s %s", "RULE", "UNTIL", "REMAINING", "BY", "NOTE")) + "\n")
	now := time.Now()
	for i, s := range h.silences {
		cursor := "  "
		if i == h.silCursor {
			cursor = warnStyle.Render("› ")
		}
		note := s.Message
		if note == "" {
			note = "-"
		}
		b.WriteString(fmt.Sprintf("%s%-28s %s %-9s %-10s %s\n",
			cursor,
			truncate(ttySafe(s.Key), 28),
			dimStyle.Render(time.Unix(s.Until, 0).Format("2006-01-02 15:04")),
			fmtRemaining(time.Unix(s.Until, 0).Sub(now)),
			truncate(ttySafe(s.AddedBy), 10),
			dimStyle.Render(truncate(ttySafe(note), 48))))
	}
	return b.String()
}

func historyFooterHints(m model) []string {
	keys := m.controls()
	var hints []string
	switch {
	case m.view == viewSilences:
		hints = []string{bindingHint(keys.Back), "↑↓:select", bindingHint(historyKeys.Clear), bindingHint(historyKeys.History)}
	case m.hist.detail != nil:
		hints = []string{bindingHint(keys.Back), "↑↓:scroll", bindingHint(historyKeys.Silence)}
	default:
		hints = []string{bindingHint(keys.Back), "↑↓:select", "enter:detail", bindingHint(historyKeys.Silence), bindingHint(historyKeys.Silences)}
	}
	if m.hist.note != "" {
		hints = append(hints, warnStyle.Render(ttySafe(m.hist.note)))
	}
	return hints
}

func sevStyle(sev string) lipgloss.Style {
	switch sev {
	case "crit":
		return critStyle
	case "warn":
		return warnStyle
	}
	return labelStyle
}

// alertBody drops the ``` fence bash wraps around raw log lines.
func alertBody(r alertlog.Row) string {
	return ttySafe(strings.TrimSpace(strings.Trim(r.Body, "`")))
}

// firstIP returns the first IPv4/IPv6 token in body; for fenced nginx lines that is the client.
func firstIP(body string) string {
	for _, f := range strings.Fields(strings.Trim(body, "`")) {
		if a, err := netip.ParseAddr(strings.Trim(f, "`,;()[]\"'")); err == nil {
			return a.String()
		}
	}
	return ""
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func fmtRemaining(d time.Duration) string {
	s := int64(d / time.Second)
	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm", s/60)
	case s < 86400:
		return fmt.Sprintf("%dh %02dm", s/3600, s%3600/60)
	}
	return fmt.Sprintf("%dd %02dh", s/86400, s%86400/3600)
}
