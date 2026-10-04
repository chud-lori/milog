// Package alertlog reads alerts.log, the TSV written by bash _alert_record:
//
//	<epoch>  <rule_key>  <color_int>  <title>  <body_truncated>
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

// WindowToCutoff turns today | yesterday | all | Nh | Nd | Nw into the
// oldest epoch to include; all is 0. There's no upper bound, so yesterday
// includes today.
func WindowToCutoff(w string, now time.Time) (int64, error) {
	if w == "" {
		w = "today"
	}
	nowU := now.Unix()
	switch {
	case w == "today":
		// UTC midnight, not local; close enough for this view.
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

// WindowToRange is WindowToCutoff plus an exclusive upper bound; until is 0
// for every open-ended window, and today's midnight for "yesterday".
func WindowToRange(w string, now time.Time) (from, until int64, err error) {
	from, err = WindowToCutoff(w, now)
	if err != nil {
		return 0, 0, err
	}
	if w == "yesterday" {
		until = from + 86400
	}
	return from, until, nil
}

func relative(w string, unitSec int64) (int64, error) {
	n, err := strconv.ParseInt(w[:len(w)-1], 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid window: %q", w)
	}
	return time.Now().Unix() - n*unitSec, nil
}

// Severity maps the color int to crit/warn/info, the same mapping bash uses.
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

// Load returns rows with epoch >= cutoff, keeping the newest maxRows in
// file order (oldest first). A missing file returns no rows; malformed rows
// are skipped.
func Load(path string, cutoff int64, maxRows int) ([]Row, error) {
	return LoadRange(path, cutoff, 0, maxRows)
}

// LoadRange is Load with an exclusive upper bound; until <= 0 means none.
func LoadRange(path string, cutoff, until int64, maxRows int) ([]Row, error) {
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
		if err != nil || ts < cutoff || (until > 0 && ts >= until) {
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

	if maxRows > 0 && len(rows) > maxRows {
		rows = rows[len(rows)-maxRows:]
	}
	return rows, nil
}
