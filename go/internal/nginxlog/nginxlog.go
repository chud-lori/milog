// Package nginxlog parses nginx combined-format access logs.
//
// Scope today: MinuteCounts — given a log file + the current-minute
// timestamp prefix (dd/Mon/yyyy:HH:MM), count total / 2xx / 3xx / 4xx /
// 5xx matches. Mirrors the awk in bash `nginx_minute_counts`.
//
// Reads the whole file for now. That's fine: the file is nginx's live
// access log, which is rotated daily; 24h of moderate traffic (~50
// req/min) is a few MB. If this proves slow on big hosts we'll reverse-
// scan with a tail buffer — but the minute-specific match means most
// lines fail the initial substring check cheaply anyway.
package nginxlog

import (
	"bufio"
	"os"
	"strings"
	"time"
)

type Counts struct {
	Total int
	C2xx  int
	C3xx  int
	C4xx  int
	C5xx  int
}

// MinuteCounts scans file for lines matching the given minute-prefix
// (e.g. "24/Apr/2026:12:34") and bucketizes by status class. A missing
// or unreadable file returns zero counts without error — callers render
// those as "0 / 0 / 0 / 0 / 0" in the UI, which is correct ("no traffic
// this minute" looks the same as "can't read the log").
func MinuteCounts(path, minute string) (Counts, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Counts{}, nil
		}
		return Counts{}, err
	}
	defer f.Close()

	var c Counts
	sc := bufio.NewScanner(f)
	// nginx lines can include long User-Agent headers; bump buffer so
	// bufio.Scanner doesn't error on "token too long".
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, minute) {
			continue
		}
		c.Total++
		// Look for " Nxx " somewhere in the line — the nginx combined
		// format has status in a fixed position, but substring search is
		// robust against log-format variants and cheaper than parsing
		// the whole line.
		if cls := extractStatusClass(line); cls != 0 {
			switch cls {
			case 2:
				c.C2xx++
			case 3:
				c.C3xx++
			case 4:
				c.C4xx++
			case 5:
				c.C5xx++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	return c, nil
}

// extractStatusClass looks for " Nxx " (space, digit 1-5, two digits, space)
// in the line and returns the leading digit. Returns 0 if not found.
func extractStatusClass(s string) byte {
	// Walk the string looking for `[space][1-5][0-9][0-9][space]`.
	// Faster than regex for this hot path; this runs once per matching
	// log line per dashboard poll.
	for i := 0; i < len(s)-4; i++ {
		if s[i] != ' ' {
			continue
		}
		d0, d1, d2 := s[i+1], s[i+2], s[i+3]
		if d0 >= '1' && d0 <= '5' && d1 >= '0' && d1 <= '9' && d2 >= '0' && d2 <= '9' {
			if i+4 < len(s) && s[i+4] == ' ' {
				return d0 - '0'
			}
		}
	}
	return 0
}

// CurrentMinutePrefix returns the nginx timestamp prefix for the given
// time. Format: dd/Mon/yyyy:HH:MM  (no seconds — caller decides how wide
// a window to match on).
func CurrentMinutePrefix(t time.Time) string {
	// Nginx uses uppercase 3-letter month names, which time.Format does
	// natively via the reference "Jan" token.
	return t.Format("02/Jan/2006:15:04")
}
