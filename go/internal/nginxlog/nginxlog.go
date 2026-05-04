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
	"fmt"
	"os"
	"strconv"
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

// Line is a structured parse of one nginx combined-format line. Fields
// populated on a best-effort basis — unparseable lines get Status=0 and
// callers filter them out. Matches the shape of the bash
// `/api/logs.json` row (ip / method / path / status / ua / class).
type Line struct {
	TS     string `json:"ts"`     // `[dd/Mon/yyyy:HH:MM:SS]`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`   // query string stripped
	Status int    `json:"status"`
	UA     string `json:"ua"`
	Class  string `json:"class"`  // `2xx`/`3xx`/`4xx`/`5xx`; empty for malformed
}

// ParseLine extracts fields from one combined-format access-log line.
// Shape assumed:
//
//	<ip> - - [<time>] "METHOD <path> HTTP/1.1" <status> <bytes> "<ref>" "<ua>" [<rt>]
//
// Implementation scans on `"` boundaries — that's the only stable
// anchor in the combined format. Resilient to missing $request_time
// and unusual UA strings; returns Status=0 on any malformed row.
func ParseLine(raw string) Line {
	var ln Line
	// Split on `"`. Fields are:
	//   [0] "<ip> - - [<time>] "   (ends in a space before the opening quote)
	//   [1] "METHOD <path> HTTP/1.1"
	//   [2] " <status> <bytes> "
	//   [3] "<referer>"
	//   [4] " "
	//   [5] "<ua>"
	//   [6] " <rt>?"
	parts := strings.Split(raw, `"`)
	if len(parts) < 3 {
		return ln
	}

	// --- ip + ts ---
	pre := strings.Fields(parts[0])
	if len(pre) >= 1 {
		ln.IP = pre[0]
	}
	for _, tok := range pre {
		if strings.HasPrefix(tok, "[") {
			ln.TS = strings.TrimSuffix(tok, "]")
			break
		}
	}

	// --- method + path ---
	reqFields := strings.Fields(parts[1])
	if len(reqFields) >= 1 {
		ln.Method = reqFields[0]
	}
	if len(reqFields) >= 2 {
		raw := reqFields[1]
		if q := strings.IndexByte(raw, '?'); q > 0 {
			raw = raw[:q]
		}
		if strings.HasPrefix(raw, "/") {
			ln.Path = raw
		}
	}

	// --- status ---
	statusField := strings.TrimSpace(parts[2])
	statusTok := strings.Fields(statusField)
	if len(statusTok) >= 1 {
		if n, err := strconv.Atoi(statusTok[0]); err == nil {
			if n >= 100 && n < 600 {
				ln.Status = n
				ln.Class = fmt.Sprintf("%dxx", n/100)
			}
		}
	}

	// --- ua ---
	if len(parts) >= 6 {
		ln.UA = parts[5]
	}
	return ln
}

// TailLines reads the last n lines of a file. Small-file safe (reads
// whole file into memory). For access logs rotated daily this stays in
// the low-MB range — fine.
func TailLines(path string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return lines, err
	}
	if len(lines) > n {
		return lines[len(lines)-n:], nil
	}
	return lines, nil
}

// Bucket is one per-minute histogram entry.
type Bucket struct {
	T string `json:"t"` // `dd/Mon/yyyy:HH:MM`
	C int    `json:"c"` // count
}

// Histogram scans `path` and returns one Bucket per minute over the last
// `minutes` minutes (newest-last). Missing minutes render as zero counts
// so the client can draw a full bar strip without gap logic.
//
// Scan budget: `minutes * 500` lines from the tail. Enough headroom for
// high-traffic paths; lower for small minutes values.
func Histogram(path string, minutes int, now time.Time) ([]Bucket, error) {
	if minutes <= 0 {
		minutes = 60
	}
	if minutes > 1440 {
		minutes = 1440
	}
	buckets := make([]Bucket, minutes)
	keyIndex := make(map[string]int, minutes)
	for i := 0; i < minutes; i++ {
		t := now.Add(-time.Duration(minutes-1-i) * time.Minute)
		key := t.Format("02/Jan/2006:15:04")
		buckets[i].T = key
		keyIndex[key] = i
	}

	scanN := minutes * 500
	if scanN < 1000 {
		scanN = 1000
	}
	lines, err := TailLines(path, scanN)
	if err != nil {
		return buckets, err
	}
	for _, line := range lines {
		for key, idx := range keyIndex {
			if strings.Contains(line, key) {
				buckets[idx].C++
				break
			}
		}
	}
	return buckets, nil
}
