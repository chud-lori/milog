package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/chud-lori/milog/internal/alertlog"
	"github.com/chud-lori/milog/internal/config"
)

func historyModel(t *testing.T) model {
	dir := t.TempDir()
	log := "1800000000\texploit:api:sqli\t15158332\tExploit attempt\t```203.0.113.7 - - [x] \"GET /?id=1' OR 1=1\" 404```\n" +
		"1800000100\tprobe:api\t15844367\tProbe traffic\t```198.51.100.2 - - [x] \"GET /.env\" 404```\n" +
		"1800000200\tprobe:web\t15844367\tProbe traffic\t```203.0.113.7 - - [x] \"GET /wp-login.php\" 404```\n"
	if err := os.WriteFile(filepath.Join(dir, "alerts.log"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	return model{
		cfg:        &config.Config{AlertStateDir: dir},
		width:      140,
		height:     30,
		refreshSec: 5,
		view:       viewOverview,
	}
}

// press sends key and runs any returned command once, as the Bubble Tea loop would.
func press(t *testing.T, m model, k string) model {
	t.Helper()
	next, cmd := m.Update(keyMsg(k))
	for cmd != nil {
		msg := cmd()
		if _, ok := msg.(tea.QuitMsg); ok || msg == nil {
			break
		}
		next, cmd = next.Update(msg)
	}
	return next.(model)
}

func TestHistory_OpensNewestFirst(t *testing.T) {
	m := press(t, historyModel(t), "H")
	if m.view != viewHistory {
		t.Fatalf("view=%v want viewHistory", m.view)
	}
	if len(m.hist.rows) != 3 || m.hist.rows[0].Rule != "probe:web" {
		t.Fatalf("rows not newest first: %+v", m.hist.rows)
	}
	view := m.View()
	for _, want := range []string{"ALERT HISTORY", "probe:web", "exploit:api:sqli", "s:silence"} {
		if !strings.Contains(view, want) {
			t.Errorf("history view missing %q:\n%s", want, view)
		}
	}
}

func TestHistory_DetailListsSameIPFires(t *testing.T) {
	m := press(t, historyModel(t), "H")
	m = press(t, m, "j")
	m = press(t, m, "j")
	m = press(t, m, "enter")
	if m.hist.detail == nil || m.hist.detail.Rule != "exploit:api:sqli" {
		t.Fatalf("detail: %+v", m.hist.detail)
	}
	view := m.View()
	for _, want := range []string{"OTHER FIRES FROM 203.0.113.7 (1", "probe:web", "OR 1=1"} {
		if !strings.Contains(view, want) {
			t.Errorf("detail missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "probe:api") {
		t.Errorf("detail lists a fire from another IP:\n%s", view)
	}
	m = press(t, m, "esc")
	if m.view != viewHistory || m.hist.detail != nil {
		t.Errorf("esc from detail should return to the list; view=%v", m.view)
	}
}

func TestHistory_SilenceDefaultsToOneHourAndMarksRows(t *testing.T) {
	m := press(t, historyModel(t), "H")
	m = press(t, m, "s")
	if !m.hist.prompting || m.hist.promptRule != "probe:web" {
		t.Fatalf("prompt not opened for selected rule: %+v", m.hist)
	}
	if !strings.Contains(m.View(), "silence probe:web for (enter: 1h") {
		t.Errorf("prompt not rendered:\n%s", m.View())
	}
	// q types into the prompt instead of quitting.
	m = press(t, m, "q")
	if m.hist.input != "q" {
		t.Fatalf("input=%q", m.hist.input)
	}
	m = press(t, m, "backspace")
	before := time.Now().Unix()
	m = press(t, m, "enter")

	sil, err := alertlog.LoadSilences(filepath.Join(m.cfg.AlertStateDir, "alerts.silences"), time.Now())
	if err != nil || len(sil) != 1 || sil[0].Key != "probe:web" {
		t.Fatalf("silences: %v %+v", err, sil)
	}
	if d := sil[0].Until - before; d < 3600 || d > 3602 {
		t.Errorf("default duration: until-now=%ds want 3600", d)
	}
	view := m.View()
	if !strings.Contains(view, "silenced probe:web until") {
		t.Errorf("no confirmation:\n%s", view)
	}
	var marked int
	for _, ln := range strings.Split(view, "\n") {
		if strings.Contains(ln, "silenced") && strings.Contains(ln, "probe:") {
			marked++
		}
	}
	if marked != 2 { // the confirmation line plus the probe:web row
		t.Errorf("want only probe:web marked silenced, got %d lines:\n%s", marked, view)
	}
}

func TestHistory_BadDurationKeepsPromptOpen(t *testing.T) {
	m := press(t, historyModel(t), "H")
	m = press(t, m, "s")
	m = press(t, m, "2")
	m = press(t, m, "w")
	m = press(t, m, "enter")
	if !m.hist.prompting || !strings.Contains(m.View(), "invalid duration") {
		t.Errorf("prompt should stay open with an error:\n%s", m.View())
	}
	if _, err := os.Stat(filepath.Join(m.cfg.AlertStateDir, "alerts.silences")); err == nil {
		t.Error("silence written for an invalid duration")
	}
}

func TestSilences_ViewClearsSelected(t *testing.T) {
	m := historyModel(t)
	f := filepath.Join(m.cfg.AlertStateDir, "alerts.silences")
	now := time.Now()
	alertlog.AddSilence(f, "exploit:*", time.Hour, "pentest", now)
	alertlog.AddSilence(f, "5xx:api", 2*time.Hour, "", now)

	m = press(t, m, "S")
	view := m.View()
	for _, want := range []string{"ACTIVE SILENCES", "exploit:*", "pentest", "5xx:api", "x:clear"} {
		if !strings.Contains(view, want) {
			t.Errorf("silences view missing %q:\n%s", want, view)
		}
	}
	m = press(t, m, "j")
	m = press(t, m, "x")
	left, _ := alertlog.LoadSilences(f, time.Now())
	if len(left) != 1 || left[0].Key != "exploit:*" {
		t.Errorf("after x on row 2: %+v", left)
	}
	if !strings.Contains(m.View(), "cleared silence on 5xx:api") {
		t.Errorf("no confirmation:\n%s", m.View())
	}
}

func TestSilences_EmptyState(t *testing.T) {
	m := press(t, historyModel(t), "S")
	if !strings.Contains(m.View(), "none. Press s on a row") {
		t.Errorf("empty state missing:\n%s", m.View())
	}
}

func TestFirstIP(t *testing.T) {
	cases := map[string]string{
		"```203.0.113.7 - - [04/Oct/2026] \"GET /\" 404```": "203.0.113.7",
		"```2001:db8::1 - - \"GET /\"```":                   "2001:db8::1",
		"5xx rate 12% on api (threshold 5%)":                "",
		"blocked (198.51.100.9), 40 req/min":                "198.51.100.9",
	}
	for in, want := range cases {
		if got := firstIP(in); got != want {
			t.Errorf("firstIP(%q) = %q want %q", in, got, want)
		}
	}
}
