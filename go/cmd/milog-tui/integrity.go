package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/chud-lori/milog/internal/config"
	"github.com/chud-lori/milog/internal/history"
)

const (
	integrityWindowDays = 7
	integritySubjectCap = 60 // subject column pad; longer subjects push the time right
)

type integrityData struct {
	events  []history.AuditEvent // newest first
	loadErr error
}

type integrityMsg struct {
	data integrityData
}

func integritySampleCmd(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		since := time.Now().AddDate(0, 0, -integrityWindowDays).Unix()
		events, err := history.LoadAuditEvents(cfg.HistoryDB, since)
		return integrityMsg{data: integrityData{events: events, loadErr: err}}
	}
}

// renderIntegrityView lists audit drift from the history DB, one row per stored finding.
func (m model) renderIntegrityView() string {
	d := m.integrity
	var b strings.Builder

	b.WriteString("  ")
	b.WriteString(labelStyle.Render(fmt.Sprintf("INTEGRITY DRIFT (last %d days, newest first)", integrityWindowDays)))
	b.WriteString("\n")

	if d.loadErr != nil {
		hint := ""
		switch {
		case errors.Is(d.loadErr, history.ErrNotConfigured):
			hint = "  enable with: HISTORY_ENABLED=1 and AUDIT_ENABLED=1, then restart milog daemon"
		case errors.Is(d.loadErr, history.ErrNoBinary):
			hint = "  install with: `milog install history`"
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

	if len(d.events) == 0 {
		b.WriteString("  ")
		b.WriteString(dimStyle.Render(fmt.Sprintf(
			"no drift recorded in the last %d days (or AUDIT_ENABLED=0)",
			integrityWindowDays,
		)))
		b.WriteString("\n")
		return b.String()
	}

	subjW := 0
	for _, e := range d.events {
		if n := len(ttySafe(e.Subject)); n > subjW {
			subjW = n
		}
	}
	if subjW > integritySubjectCap {
		subjW = integritySubjectCap
	}
	for _, e := range d.events {
		// Removals are mostly housekeeping, so they stay dim.
		kindStyle := warnStyle
		if e.Kind == "removed" {
			kindStyle = dimStyle
		}
		when := time.Unix(e.TS, 0).Format("Mon 02 Jan 15:04")
		b.WriteString(fmt.Sprintf("  %-11s  %s  %-*s  %s\n",
			ttySafe(e.Scanner), kindStyle.Render(fmt.Sprintf("%-10s", ttySafe(e.Kind))),
			subjW, ttySafe(e.Subject), dimStyle.Render(when)))
	}
	return b.String()
}
