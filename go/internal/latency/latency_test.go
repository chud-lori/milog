package latency

import (
	"testing"
)

func TestExtractRequestTimeMs(t *testing.T) {
	cases := map[string]int64{
		`1.2.3.4 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua" 0.123`: 123,
		`1.2.3.4 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua" 0.0005`: 1, // rounds up
		`1.2.3.4 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua" 2.5`:   2500,
		`1.2.3.4 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua"`:        -1, // no request_time
		`1.2.3.4 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua" not-a-number`: -1,
		`garbage-no-quotes`: -1,
	}
	for in, want := range cases {
		if got := ExtractRequestTimeMs(in); got != want {
			t.Errorf("ExtractRequestTimeMs(%q): got %d want %d", in, got, want)
		}
	}
}

func TestPercentiles_Empty(t *testing.T) {
	s := Percentiles(nil, DefaultQuantiles)
	if s.Count != 0 {
		t.Errorf("Count: %d want 0", s.Count)
	}
	if len(s.Pct) != 0 {
		t.Errorf("Pct: %v want empty", s.Pct)
	}
}

func TestPercentiles_Basic(t *testing.T) {
	// Uniform 1..100 — p50=50, p90=90, p99=99, p100=100.
	samples := make([]int64, 100)
	for i := range samples {
		samples[i] = int64(i + 1)
	}
	s := Percentiles(samples, []string{"p50", "p90", "p99", "p100"})
	if s.Count != 100 || s.MinMs != 1 || s.MaxMs != 100 {
		t.Errorf("stats: %+v", s)
	}
	if s.Pct["p50"] != 50 || s.Pct["p90"] != 90 || s.Pct["p99"] != 99 || s.Pct["p100"] != 100 {
		t.Errorf("percentiles: %+v", s.Pct)
	}
}

func TestPercentiles_SparseHighQuantile(t *testing.T) {
	// 10 samples, p99.9 should clamp to max.
	samples := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	s := Percentiles(samples, []string{"p99.9"})
	if s.Pct["p99.9"] != 100 {
		t.Errorf("p99.9 on small set should be max, got %d", s.Pct["p99.9"])
	}
}

func TestParseQ(t *testing.T) {
	cases := map[string]float64{
		"p50":   0.5,
		"p99":   0.99,
		"p99.9": 0.999,
		"75":    0.75,
		"P95":   0.95,
		"bogus": 1,
		"0":     1, // guard against div-by-zero
	}
	for in, want := range cases {
		got := parseQ(in)
		if want-got > 1e-9 || got-want > 1e-9 {
			t.Errorf("parseQ(%q): got %v want %v", in, got, want)
		}
	}
}
