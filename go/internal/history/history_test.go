package history

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireSqlite skips when sqlite3 is not installed.
func requireSqlite(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 not on PATH — skipping (install via brew install sqlite or apt install sqlite3)")
	}
}

// makeDB creates dir/metrics.db with the daemon's metrics_minute schema and rows.
func makeDB(t *testing.T, dir string, rows []MinuteRow, app string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "metrics.db")
	var sql strings.Builder
	sql.WriteString(`
		CREATE TABLE metrics_minute (
			ts INTEGER NOT NULL, app TEXT NOT NULL, req INTEGER NOT NULL,
			c2xx INTEGER NOT NULL, c3xx INTEGER NOT NULL,
			c4xx INTEGER NOT NULL, c5xx INTEGER NOT NULL,
			p50_ms INTEGER, p95_ms INTEGER, p99_ms INTEGER,
			PRIMARY KEY (ts, app)
		);
	`)
	for _, r := range rows {
		fmt.Fprintf(&sql, "INSERT INTO metrics_minute VALUES(%d,'%s',%d,0,0,0,0,NULL,NULL,NULL);\n",
			r.TS, app, r.Req)
	}
	cmd := exec.Command("sqlite3", dbPath)
	cmd.Stdin = strings.NewReader(sql.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seed sqlite: %v: %s", err, out)
	}
	return dbPath
}

// makeMultiAppDB seeds rows for multiple apps in one DB.
func makeMultiAppDB(t *testing.T, dir string, perApp map[string][]MinuteRow) string {
	t.Helper()
	dbPath := filepath.Join(dir, "metrics.db")
	var sql strings.Builder
	sql.WriteString(`
		CREATE TABLE metrics_minute (
			ts INTEGER NOT NULL, app TEXT NOT NULL, req INTEGER NOT NULL,
			c2xx INTEGER NOT NULL, c3xx INTEGER NOT NULL,
			c4xx INTEGER NOT NULL, c5xx INTEGER NOT NULL,
			p50_ms INTEGER, p95_ms INTEGER, p99_ms INTEGER,
			PRIMARY KEY (ts, app)
		);
	`)
	for app, rows := range perApp {
		for _, r := range rows {
			fmt.Fprintf(&sql, "INSERT INTO metrics_minute VALUES(%d,'%s',%d,0,0,0,0,NULL,NULL,NULL);\n",
				r.TS, app, r.Req)
		}
	}
	cmd := exec.Command("sqlite3", dbPath)
	cmd.Stdin = strings.NewReader(sql.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seed sqlite: %v: %s", err, out)
	}
	return dbPath
}

func TestLoadMinutes_HappyPath(t *testing.T) {
	requireSqlite(t)
	dir := t.TempDir()
	db := makeMultiAppDB(t, dir, map[string][]MinuteRow{
		"api": {{TS: 1700000000, Req: 12}, {TS: 1700000060, Req: 18}},
		"web": {{TS: 1700000060, Req: 5}, {TS: 1700000120, Req: 7}},
	})

	got, err := LoadMinutes(db, 1700000000)
	if err != nil {
		t.Fatalf("LoadMinutes: %v", err)
	}
	if len(got["api"]) != 2 || got["api"][0].Req != 12 || got["api"][1].Req != 18 {
		t.Errorf("api rows wrong: %+v", got["api"])
	}
	if len(got["web"]) != 2 || got["web"][0].Req != 5 {
		t.Errorf("web rows wrong: %+v", got["web"])
	}
	// Check ts ordering.
	if got["api"][0].TS > got["api"][1].TS {
		t.Errorf("api rows not ascending by ts; got %+v", got["api"])
	}
}

func TestLoadMinutes_SinceFilters(t *testing.T) {
	requireSqlite(t)
	dir := t.TempDir()
	db := makeDB(t, dir, []MinuteRow{
		{TS: 1700000000, Req: 1},
		{TS: 1700000060, Req: 2},
		{TS: 1700000120, Req: 3},
	}, "api")

	got, err := LoadMinutes(db, 1700000060)
	if err != nil {
		t.Fatalf("LoadMinutes: %v", err)
	}
	if len(got["api"]) != 2 {
		t.Errorf("expected 2 rows after since cutoff, got %d: %+v", len(got["api"]), got["api"])
	}
	if got["api"][0].Req != 2 {
		t.Errorf("first row should be ts=1700000060 req=2; got %+v", got["api"][0])
	}
}

func TestLoadMinutes_EmptyResultMapNotNil(t *testing.T) {
	requireSqlite(t)
	dir := t.TempDir()
	db := makeDB(t, dir, []MinuteRow{{TS: 1700000000, Req: 1}}, "api")
	// No rows still returns a non-nil map.
	got, err := LoadMinutes(db, 9999999999)
	if err != nil {
		t.Fatalf("LoadMinutes: %v", err)
	}
	if got == nil {
		t.Errorf("expected non-nil empty map, got nil")
	}
	if len(got) != 0 {
		t.Errorf("expected empty result for far-future cutoff; got %+v", got)
	}
}

func TestLoadMinutes_MissingDBReturnsErrNotConfigured(t *testing.T) {
	requireSqlite(t)
	_, err := LoadMinutes(filepath.Join(t.TempDir(), "does-not-exist.db"), 0)
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("expected ErrNotConfigured for missing DB; got %v", err)
	}
}

func TestLoadMinutes_EmptyPathReturnsErrNotConfigured(t *testing.T) {
	_, err := LoadMinutes("", 0)
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("expected ErrNotConfigured for empty path; got %v", err)
	}
}

func TestLoadMinutes_NoSqliteBinaryReturnsErrNoBinary(t *testing.T) {
	// Force LookPath to fail by clearing PATH.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "metrics.db")
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv("PATH", "/nonexistent")
	_, err := LoadMinutes(dbPath, 0)
	if !errors.Is(err, ErrNoBinary) {
		t.Errorf("expected ErrNoBinary with empty PATH; got %v", err)
	}
}
