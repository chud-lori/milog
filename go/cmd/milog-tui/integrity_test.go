package main

import (
	"strings"
	"testing"
	"time"

	"github.com/chud-lori/milog/internal/config"
	"github.com/chud-lori/milog/internal/history"
)

func TestRenderIntegrityView_RowsAndControlBytes(t *testing.T) {
	ts := time.Date(2026, 9, 29, 3, 12, 0, 0, time.Local).Unix()
	m := model{
		cfg:        &config.Config{},
		width:      120,
		refreshSec: 5,
		view:       viewIntegrity,
		integrity: integrityData{events: []history.AuditEvent{
			{TS: ts, Scanner: "ports", Kind: "appeared", Subject: "0.0.0.0:4444/tcp"},
			{TS: ts - 60, Scanner: "fim", Kind: "modified", Subject: "/etc/ho\x1b[2Jsts"},
		}},
	}
	out := m.renderIntegrityView()
	ports := strings.Index(out, "0.0.0.0:4444/tcp")
	fim := strings.Index(out, "/etc/ho?[2Jsts")
	if ports < 0 || fim < 0 || ports > fim {
		t.Errorf("expected ports row then sanitised fim row; got:\n%s", out)
	}
	if !strings.Contains(out, "Tue 29 Sep 03:12") {
		t.Errorf("expected the event time; got:\n%s", out)
	}
}

func TestRenderIntegrityView_HistoryDisabled(t *testing.T) {
	m := model{view: viewIntegrity, integrity: integrityData{loadErr: history.ErrNotConfigured}}
	if out := m.renderIntegrityView(); !strings.Contains(out, "HISTORY_ENABLED=1") {
		t.Errorf("expected an enable hint; got:\n%s", out)
	}
}

func TestUpdate_IKeyOpensIntegrityAndEscReturns(t *testing.T) {
	m := model{
		cfg:        &config.Config{},
		width:      120,
		refreshSec: 5,
		view:       viewOverview,
	}
	updated, cmd := m.Update(keyMsg("i"))
	got := updated.(model)
	if got.view != viewIntegrity || cmd == nil {
		t.Fatalf("after 'i', view=%v cmd=%v; want viewIntegrity with a load cmd", got.view, cmd)
	}
	updated, _ = got.Update(keyMsg("esc"))
	if updated.(model).view != viewOverview {
		t.Errorf("after 'esc' from integrity, view=%v want viewOverview", updated.(model).view)
	}
}
