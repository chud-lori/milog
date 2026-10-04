// Package history reads the daemon's metrics_minute table through the
// sqlite3 CLI, which history already requires. A Go binding would need cgo
// (mattn) or add about 3 MB (modernc) for this one reader.
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

var (
	// ErrNotConfigured means there is no DB, usually HISTORY_ENABLED=0.
	ErrNotConfigured = errors.New("history: DB not present (HISTORY_ENABLED=0 or milog install history not run)")

	// ErrNoBinary means sqlite3 is not on PATH.
	ErrNoBinary = errors.New("history: sqlite3 binary not found on PATH")
)

// LoadMinutes returns rows with ts >= since, keyed by app and sorted by ts.
// Apps without rows are absent from the map.
func LoadMinutes(dbPath string, since int64) (map[string][]MinuteRow, error) {
	if dbPath == "" {
		return nil, ErrNotConfigured
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil, ErrNoBinary
	}
	// Read-only open; a missing file shows up as "unable to open" below.
	query := fmt.Sprintf(
		"SELECT app, ts, req FROM metrics_minute WHERE ts >= %d ORDER BY app, ts",
		since,
	)
	cmd := exec.Command("sqlite3",
		"-readonly",
		"-separator", "\t",
		dbPath,
		query,
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

	result := map[string][]MinuteRow{}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
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
