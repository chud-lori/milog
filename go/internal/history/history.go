// Package history reads the daemon's history DB through the sqlite3 CLI,
// which history already requires. A Go binding would need cgo (mattn) or
// add about 3 MB (modernc) for this one reader.
package history

import (
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// MinuteRow is the subset of metrics_minute the trend view uses.
type MinuteRow struct {
	TS  int64 // epoch seconds at the start of the minute
	Req int   // total requests in that minute
}

// AuditEvent is one audit_event row: a finding an audit scanner stored.
type AuditEvent struct {
	TS      int64
	Scanner string // fim, persistence, ports, yara, accounts, rootkit
	Kind    string // appeared, removed, modified, ...
	Subject string // path, bind:port/proto, account file, or heuristic
}

var (
	// ErrNotConfigured means there is no DB, usually HISTORY_ENABLED=0.
	ErrNotConfigured = errors.New("history: DB not present (HISTORY_ENABLED=0 or milog install history not run)")

	// ErrNoBinary means sqlite3 is not on PATH.
	ErrNoBinary = errors.New("history: sqlite3 binary not found on PATH")
)

// query runs one read-only SELECT and returns its tab-separated rows.
func query(dbPath, sql string) ([]string, error) {
	if dbPath == "" {
		return nil, ErrNotConfigured
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil, ErrNoBinary
	}
	// Read-only open; a missing file shows up as "unable to open" below.
	cmd := exec.Command("sqlite3",
		"-readonly",
		"-separator", "\t",
		dbPath,
		sql,
	)
	out, err := cmd.Output()
	if err != nil {
		// A missing DB file is ErrNotConfigured; other failures carry stderr.
		if ee, ok := err.(*exec.ExitError); ok {
			stderr := string(ee.Stderr)
			if strings.Contains(stderr, "unable to open") ||
				strings.Contains(stderr, "no such file") {
				return nil, ErrNotConfigured
			}
			return nil, fmt.Errorf("history: sqlite3 failed: %s", strings.TrimSpace(stderr))
		}
		return nil, fmt.Errorf("history: sqlite3 invocation: %w", err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// LoadMinutes returns rows with ts >= since, keyed by app and sorted by ts.
// Apps without rows are absent from the map.
func LoadMinutes(dbPath string, since int64) (map[string][]MinuteRow, error) {
	lines, err := query(dbPath, fmt.Sprintf(
		"SELECT app, ts, req FROM metrics_minute WHERE ts >= %d ORDER BY app, ts",
		since,
	))
	if err != nil {
		return nil, err
	}

	result := map[string][]MinuteRow{}
	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			// Skip a malformed row instead of failing the whole load.
			continue
		}
		ts, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}
		req, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		app := parts[0]
		result[app] = append(result[app], MinuteRow{TS: ts, Req: req})
	}

	// ORDER BY already sorts; this keeps the guarantee if the query changes.
	for _, rows := range result {
		sort.Slice(rows, func(i, j int) bool { return rows[i].TS < rows[j].TS })
	}
	return result, nil
}

// LoadAuditEvents returns audit_event rows with ts >= since, newest first.
// A DB written by a daemon that predates the table yields no rows.
func LoadAuditEvents(dbPath string, since int64) ([]AuditEvent, error) {
	lines, err := query(dbPath, fmt.Sprintf(
		"SELECT ts, scanner, kind, subject FROM audit_event WHERE ts >= %d ORDER BY ts DESC",
		since,
	))
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, err
	}

	var events []AuditEvent
	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			continue
		}
		ts, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}
		events = append(events, AuditEvent{TS: ts, Scanner: parts[1], Kind: parts[2], Subject: parts[3]})
	}
	return events, nil
}
