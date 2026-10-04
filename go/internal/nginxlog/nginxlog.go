// Package nginxlog parses nginx combined-format access logs: per-minute
// status counts, single-line parsing, tails and per-minute histograms.
// Files are read whole; daily-rotated access logs stay small.
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

// MinuteCounts counts lines containing the minute prefix (e.g.
// "24/Apr/2026:12:34") by status class. A missing or unreadable file gives
// zero counts and no error, so the UI shows "no traffic".
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
	// Long User-Agents exceed bufio.Scanner's default token size.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, minute) {
			continue
		}
		c.Total++
		// A substring search for " Nxx " tolerates log-format variants.
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

// extractStatusClass returns the leading digit of the first " [1-5]xx " in s, or 0.
func extractStatusClass(s string) byte {
	// Hand-rolled instead of a regexp: this runs per matching line per poll.
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

// CurrentMinutePrefix returns t as nginx's dd/Mon/yyyy:HH:MM timestamp prefix.
func CurrentMinutePrefix(t time.Time) string {
	return t.Format("02/Jan/2006:15:04")
}

// Line is one parsed access-log line; unparseable lines have Status 0.
type Line struct {
	TS     string `json:"ts"`     // `[dd/Mon/yyyy:HH:MM:SS]`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`   // query string stripped
	Status int    `json:"status"`
	UA     string `json:"ua"`
	Class  string `json:"class"`  // `2xx`/`3xx`/`4xx`/`5xx`; empty for malformed
}

// ParseLine splits on `"`, the only stable anchor in the combined format:
//
//	<ip> - - [<time>] "METHOD <path> HTTP/1.1" <status> <bytes> "<ref>" "<ua>" [<rt>]
//
// A missing $request_time is fine; malformed rows get Status 0.
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

	if len(parts) >= 6 {
		ln.UA = parts[5]
	}
	return ln
}

// AICrawlerTokens must equal AI_CRAWLER_UA_RE in src/nginx.sh; TestAICrawlerTokensMatchBash checks it.
var AICrawlerTokens = []string{
	"gptbot", "chatgpt-user", "oai-searchbot",
	"claudebot", "claude-user", "claude-searchbot", "anthropic-ai",
	"perplexitybot", "perplexity-user",
	"meta-externalagent", "meta-externalfetcher",
	"bytespider", "amazonbot", "ccbot", "cohere-ai",
	"duckassistbot", "mistralai-user", "youbot",
}

// IsAICrawler reports whether ua contains any AICrawlerTokens entry, ignoring case.
func IsAICrawler(ua string) bool {
	ua = strings.ToLower(ua)
	for _, tok := range AICrawlerTokens {
		if strings.Contains(ua, tok) {
			return true
		}
	}
	return false
}

// TailLines returns the last n lines, reading the whole file into memory.
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

// Histogram returns one Bucket per minute for the last `minutes` minutes,
// oldest first, with zero buckets for idle minutes. It scans at most
// minutes*500 lines from the tail.
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
