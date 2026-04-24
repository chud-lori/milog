// Package alertlog reads MiLog's alerts.log history (TSV) and filters it
// by a user-supplied window.
//
// File format (one row per fired alert):
//
//	<epoch>  <rule_key>  <color_int>  <title>  <body_truncated>
//
// separated by literal TABs. Written by bash `_alert_record`.
//
// Window grammar (same as `milog alerts`):
//
//	today         since local midnight
//	yesterday     24h window ending at today's midnight
//	all           no cutoff
//	<N>h / d / w  relative to now
package alertlog

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Row struct {
	TS    int64  `json:"ts"`
	Rule  string `json:"rule"`
	Sev   string `json:"sev"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// WindowToCutoff resolves a window string into a Unix-epoch cutoff. Rows
// with TS >= cutoff are included; anything older is filtered out.
// Returns (0, nil) for "all" — include every row.
func WindowToCutoff(w string, now time.Time) (int64, error) {
	if w == "" {
		w = "today"
	}
	nowU := now.Unix()
	switch {
	case w == "today":
		// Local midnight today — approximate by (now - now%86400); exact to
		// the timezone boundary isn't critical for this view.
		return nowU - (nowU % 86400), nil
	case w == "yesterday":
		return nowU - (nowU % 86400) - 86400, nil
	case w == "all":
		return 0, nil
	case strings.HasSuffix(w, "h") || strings.HasSuffix(w, "H"):
		return relative(w, 3600)
	case strings.HasSuffix(w, "d") || strings.HasSuffix(w, "D"):
		return relative(w, 86400)
	case strings.HasSuffix(w, "w") || strings.HasSuffix(w, "W"):
		return relative(w, 7*86400)
	}
	return 0, fmt.Errorf("invalid window: %q", w)
}

func relative(w string, unitSec int64) (int64, error) {
	n, err := strconv.ParseInt(w[:len(w)-1], 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid window: %q", w)
	}
	return time.Now().Unix() - n*unitSec, nil
}

// Severity maps the Discord color int recorded per row to a short word
// used by the web panel for styling. Matches the bash `milog alerts`
// colour map exactly — same numeric constants, same outcome.
func Severity(color int64) string {
	switch color {
	case 15158332, 16711680:
		return "crit"
	case 16753920, 15844367:
		return "warn"
	default:
		return "info"
	}
}

// Load reads the TSV file, filtering rows with epoch >= cutoff and
// truncating the result to at most maxRows (oldest-first is the file's
// natural order; we keep the latest N by slicing at the tail).
//
// Missing file is not an error — returns an empty slice. Rows with
// malformed fields are silently skipped (matching bash awk behaviour).
func Load(path string, cutoff int64, maxRows int) ([]Row, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var rows []Row
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.SplitN(line, "\t", 5)
		if len(parts) < 5 {
			continue
		}
		ts, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || ts < cutoff {
			continue
		}
		color, _ := strconv.ParseInt(parts[2], 10, 64)
		rows = append(rows, Row{
			TS:    ts,
			Rule:  parts[1],
			Sev:   Severity(color),
			Title: parts[3],
			Body:  parts[4],
		})
	}
	if err := sc.Err(); err != nil {
		return rows, err
	}

	// Cap at maxRows, keeping the newest.
	if maxRows > 0 && len(rows) > maxRows {
		rows = rows[len(rows)-maxRows:]
	}
	return rows, nil
}
