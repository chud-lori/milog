package promtext

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func TestEncode_Basic(t *testing.T) {
	metrics := []Metric{
		{
			Name: "milog_up",
			Help: "1 when milog-web is reachable",
			Type: "gauge",
			Samples: []Sample{{Value: 1}},
		},
		{
			Name: "milog_cpu_percent",
			Help: "Current CPU busy %",
			Type: "gauge",
			Samples: []Sample{{Value: 42}},
		},
	}
	var buf bytes.Buffer
	if err := Encode(&buf, metrics); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	want := []string{
		"# HELP milog_up 1 when milog-web is reachable",
		"# TYPE milog_up gauge",
		"milog_up 1",
		"# HELP milog_cpu_percent Current CPU busy %",
		"# TYPE milog_cpu_percent gauge",
		"milog_cpu_percent 42",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing line %q in output:\n%s", w, out)
		}
	}
}

func TestEncode_Labels_Deterministic(t *testing.T) {
	m := []Metric{{
		Name: "milog_requests",
		Type: "gauge",
		Samples: []Sample{
			{Labels: map[string]string{"app": "b", "class": "2xx"}, Value: 5},
			{Labels: map[string]string{"app": "a", "class": "2xx"}, Value: 3},
			{Labels: map[string]string{"app": "a", "class": "4xx"}, Value: 1},
		},
	}}
	var buf bytes.Buffer
	_ = Encode(&buf, m)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// Drop TYPE/HELP headers.
	var data []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") {
			data = append(data, l)
		}
	}
	// Sorted by label string: {app="a",class="2xx"} < {app="a",class="4xx"} < {app="b",class="2xx"}
	wantPrefix := []string{
		`milog_requests{app="a",class="2xx"} 3`,
		`milog_requests{app="a",class="4xx"} 1`,
		`milog_requests{app="b",class="2xx"} 5`,
	}
	if len(data) != 3 {
		t.Fatalf("want 3 data lines got %d:\n%s", len(data), buf.String())
	}
	for i, w := range wantPrefix {
		if data[i] != w {
			t.Errorf("line %d: got %q want %q", i, data[i], w)
		}
	}
}

func TestEscape(t *testing.T) {
	if got := escapeLabelValue(`path with "quote" and \backslash`); got != `path with \"quote\" and \\backslash` {
		t.Errorf("label value escape: %q", got)
	}
	if got := escapeHelp("line1\nline2"); got != `line1\nline2` {
		t.Errorf("help escape: %q", got)
	}
}

func TestFormatValue(t *testing.T) {
	cases := map[float64]string{
		0:   "0",
		1:   "1",
		42:  "42",
		3.5: "3.5",
		math.NaN():    "NaN",
	}
	for v, want := range cases {
		if got := formatValue(v); got != want {
			t.Errorf("formatValue(%v): got %q want %q", v, got, want)
		}
	}
}
