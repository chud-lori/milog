// Package promtext emits Prometheus text-format 0.0.4 payloads.
//
// Tiny hand-rolled encoder — MiLog's /metrics exposure is a dozen
// series, not the thousands that justify pulling in the full
// prometheus/client_golang module. Stays in stdlib.
//
// Format spec:
//   https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md
package promtext

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Sample is one observation of a metric. Labels must be valid Prom label
// names (letters, digits, underscores; first char non-digit). Values are
// escaped by the encoder — callers pass raw strings.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Metric is a named metric with HELP + TYPE + samples.
type Metric struct {
	Name    string   // e.g. "milog_cpu_percent"
	Help    string   // one-line description
	Type    string   // "gauge" | "counter" | "untyped"
	Samples []Sample // zero or more labelled observations
}

// Encode writes every metric in prom plaintext 0.0.4. Samples within a
// metric are sorted by label-string so output is deterministic
// (simplifies diffing, helps Prom's dedup).
func Encode(w io.Writer, metrics []Metric) error {
	for _, m := range metrics {
		if m.Name == "" {
			continue
		}
		typ := m.Type
		if typ == "" {
			typ = "untyped"
		}
		if m.Help != "" {
			if _, err := fmt.Fprintf(w, "# HELP %s %s\n", m.Name, escapeHelp(m.Help)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", m.Name, typ); err != nil {
			return err
		}
		// Sort samples deterministically.
		sort.Slice(m.Samples, func(i, j int) bool {
			return labelString(m.Samples[i].Labels) < labelString(m.Samples[j].Labels)
		})
		for _, s := range m.Samples {
			if _, err := fmt.Fprintf(w, "%s%s %s\n", m.Name, labelString(s.Labels), formatValue(s.Value)); err != nil {
				return err
			}
		}
	}
	return nil
}

// labelString renders `{k1="v1",k2="v2"}` sorted by key. Empty labels →
// empty string (not `{}`).
func labelString(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(labels[k]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// escapeHelp per spec: backslash and newline escape.
func escapeHelp(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// escapeLabelValue per spec: backslash, newline, double-quote.
func escapeLabelValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// formatValue renders a float per spec. Integers render without trailing
// `.0`; NaN / ±Inf use their spec tokens.
func formatValue(v float64) string {
	switch {
	case v != v: // NaN
		return "NaN"
	case v > 1e308:
		return "+Inf"
	case v < -1e308:
		return "-Inf"
	}
	// Integers as integers for readability.
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
