// Package history reads the bash-side metrics DB. The bash daemon
// writes per-minute rows to `metrics_minute` (schema: ts, app, req,
// c2xx..c5xx, p50/p95/p99 ms); this package surfaces the columns the
// Go-side viewers need without depending on a SQLite Go binding.
//
// Strategy: shell out to the system `sqlite3` CLI. The bash side
// already requires it (you can't have history without it), so the
// dependency is guaranteed when there's any data to read. Returns
// ErrNotConfigured / ErrNoBinary on the two graceful-degrade paths,
// letting callers render a useful empty state instead of panicking.
//
// Why not a Go SQLite binding:
//   - mattn/go-sqlite3 needs cgo, which complicates goreleaser
//     cross-compile (every (os, arch) target gets its own toolchain).
//   - modernc.org/sqlite is pure-Go but adds ~3 MB to the binary for
//     the one feature that ever reads from this DB.
// Shell-out costs one fork per refresh (the TUI's tick cadence is
// 5s default), which is negligible vs. the binary-size / build-tax
// alternatives.
package history

import (
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// MinuteRow is one row from metrics_minute, scoped to the columns the
// trend view needs. Add fields here when a future view wants them —
// the SELECT in LoadMinutes is the single edit point.
type MinuteRow struct {
	TS  int64 // epoch seconds at the start of the minute
	Req int   // total requests in that minute
}

var (
	// ErrNotConfigured is returned when the DB file doesn't exist —
	// typically because `HISTORY_ENABLED=0` or `milog install history`
	// hasn't been run yet. Treat as "feature off, render empty state".
	ErrNotConfigured = errors.New("history: DB not present (HISTORY_ENABLED=0 or milog install history not run)")

	// ErrNoBinary is returned when `sqlite3` isn't on PATH. Trigger to
	// hint the operator at `milog install history` (which provisions
	// it) rather than failing silently.
	ErrNoBinary = errors.New("history: sqlite3 binary not found on PATH")
)

// LoadMinutes returns per-app minute-rows from the metrics DB whose
// `ts >= since`. Rows are sorted ascending by ts within each app.
// dbPath empty or pointing to a non-existent file returns
// ErrNotConfigured.
//
// Output shape: map keyed by app name → ordered MinuteRow slice. An
// app with zero rows in the window doesn't appear in the map at all
// — caller treats absent keys as "no data".
func LoadMinutes(dbPath string, since int64) (map[string][]MinuteRow, error) {
	if dbPath == "" {
		return nil, ErrNotConfigured
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil, ErrNoBinary
	}
	// `file:` URI with `mode=ro` so we never race the daemon's writes.
	// sqlite3 CLI handles the URI form and silently treats a missing
	// file as `unable to open` — the trailing exit-code check below
	// surfaces that as ErrNotConfigured.
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
		// Distinguish missing-file from real query failure. SQLite CLI
		// prints "Error: unable to open database file" on stderr and
		// exits non-zero; either way we return ErrNotConfigured for
		// the missing-file case so the caller can render the right
		// empty state.
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
			// Skip malformed rows rather than failing the whole call —
			// the TUI's "show whatever data we got" behaviour is
			// more useful than blanking the view on one bad row.
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

	// SQL ORDER BY already sorts; the explicit sort here is a defensive
	// guarantee for the "skip malformed row" path which could theoretically
	// drop a row out of order (it can't with our query, but the pure-Go
	// path is cheap insurance for a future schema change).
	for _, rows := range result {
		sort.Slice(rows, func(i, j int) bool { return rows[i].TS < rows[j].TS })
	}
	return result, nil
}
