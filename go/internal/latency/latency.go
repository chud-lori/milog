// Package latency computes request-time percentiles from nginx logs.
//
// v1 is on-demand + sort-based: the /api/latency route tails a bounded
// number of log lines per query and computes quantiles over the result.
// That's adequate for MiLog's single-host scale where "how slow is api
// this minute" is a handful of thousand samples, not millions.
//
// When a live sampler lands (inotify tail ingesting every request), the
// Percentiles() signature here is the same one a streaming HDR
// implementation would expose — downstream routes don't need to change.
package latency

import (
	"math"
	"sort"
	"strconv"
	"strings"
)

// ExtractRequestTimeMs parses a combined_timed nginx line and returns
// the $request_time in milliseconds. Returns -1 when no numeric
// request_time is the final field (plain `combined` format, malformed
// rows, etc.) — callers filter negatives out.
//
// Expected tail of the line:  … "user-agent-str" 0.123
// where 0.123 is the request time in seconds.
func ExtractRequestTimeMs(line string) int64 {
	// Find the last unquoted whitespace-delimited token. Everything after
	// the final `"` is a candidate; if it parses as float, we have a
	// request_time — else we're looking at plain `combined`.
	q := strings.LastIndexByte(line, '"')
	if q < 0 || q == len(line)-1 {
		return -1
	}
	rest := strings.TrimSpace(line[q+1:])
	if rest == "" {
		return -1
	}
	// Keep the first whitespace-delimited token (handles any future
	// trailing fields — e.g. if a log_format appends $upstream_response_time
	// we'd land on $request_time, which is spec-consistent).
	first := rest
	if i := strings.IndexByte(rest, ' '); i > 0 {
		first = rest[:i]
	}
	f, err := strconv.ParseFloat(first, 64)
	if err != nil || f < 0 {
		return -1
	}
	return int64(f*1000.0 + 0.5)
}

// Stats is the summary over a sample set. Zero-value when no samples
// matched — caller renders "—" in the UI.
type Stats struct {
	Count int
	MinMs int64
	MaxMs int64
	// Quantile → value in ms. Keys match the input quantile list.
	Pct map[string]int64
}

// DefaultQuantiles is the set MiLog's dashboard + Prom metrics expose.
// Kept stable so PromQL queries + clients don't break between releases.
var DefaultQuantiles = []string{"p50", "p75", "p90", "p95", "p99", "p99.9"}

// Percentiles returns count / min / max / one entry per quantile. `qs`
// are label strings like "p50", "p99.9" — the leading 'p' is optional.
// Out-of-range quantiles (>100) clamp to the max sample.
func Percentiles(samplesMs []int64, qs []string) Stats {
	if len(samplesMs) == 0 {
		return Stats{Pct: map[string]int64{}}
	}
	sorted := append([]int64(nil), samplesMs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	stats := Stats{
		Count: len(sorted),
		MinMs: sorted[0],
		MaxMs: sorted[len(sorted)-1],
		Pct:   make(map[string]int64, len(qs)),
	}
	for _, q := range qs {
		stats.Pct[q] = pick(sorted, parseQ(q))
	}
	return stats
}

// parseQ strips the leading "p" if present and returns the percentile as
// a fraction in [0, 1]. Returns 1 (max) for unparseable — safer than
// panicking on user-typed ?q= values.
func parseQ(label string) float64 {
	s := label
	s = strings.TrimPrefix(s, "p")
	s = strings.TrimPrefix(s, "P")
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		return 1
	}
	if f > 100 {
		f = 100
	}
	return f / 100.0
}

// pick returns the q-th percentile via the ceiling-index convention
// (matches bash `percentiles()` in nginx.sh): idx = ceil(N*q), clamp to
// [1, N], return sorted[idx-1]. Gives sensible results for small N and
// matches the existing CLI output.
func pick(sorted []int64, q float64) int64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(n) * q))
	if idx < 1 {
		idx = 1
	}
	if idx > n {
		idx = n
	}
	return sorted[idx-1]
}
