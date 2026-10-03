// Package latency computes request-time percentiles from nginx log lines,
// sorting a bounded tail per query; enough at single-host scale.
package latency

import (
	"math"
	"sort"
	"strconv"
	"strings"
)

// ExtractRequestTimeMs returns the trailing $request_time (seconds) of a
// combined_timed line in ms, or -1 when the line has none.
func ExtractRequestTimeMs(line string) int64 {
	// Candidate is whatever follows the last `"`; plain `combined` has nothing numeric there.
	q := strings.LastIndexByte(line, '"')
	if q < 0 || q == len(line)-1 {
		return -1
	}
	rest := strings.TrimSpace(line[q+1:])
	if rest == "" {
		return -1
	}
	// Take the first token, so extra appended fields don't shift us off $request_time.
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

// Stats summarises a sample set; the zero value means no samples.
type Stats struct {
	Count int
	MinMs int64
	MaxMs int64
	// Quantile label -> value in ms.
	Pct map[string]int64
}

// DefaultQuantiles are the labels the dashboard and /metrics expose; changing
// them breaks PromQL queries.
var DefaultQuantiles = []string{"p50", "p75", "p90", "p95", "p99", "p99.9"}

// Percentiles accepts labels like "p50" or "99.9"; quantiles above 100 clamp
// to the max sample.
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

// parseQ returns the quantile as a fraction, or 1 for unparseable input.
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

// pick uses the ceiling index, idx = ceil(N*q) clamped to [1, N], like the
// bash percentiles().
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
