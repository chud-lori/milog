// Package promtext writes Prometheus text format 0.0.4. Hand-rolled because
// /metrics has a dozen series, not enough to justify client_golang.
// Spec: https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md
package promtext

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Sample is one observation. Label names must be valid Prometheus names;
// values are escaped by the encoder.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Metric is a named metric with its HELP, TYPE and samples.
type Metric struct {
	Name    string   // e.g. "milog_cpu_percent"
	Help    string   // one-line description
	Type    string   // "gauge" | "counter" | "untyped"
	Samples []Sample // zero or more labelled observations
}

// Encode writes metrics with samples sorted by labels so output is deterministic.
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

// labelString renders `{k1="v1",k2="v2"}` sorted by key, or "" with no labels.
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

// escapeHelp escapes backslash and newline.
func escapeHelp(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// escapeLabelValue escapes backslash, newline and double quote.
func escapeLabelValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// formatValue drops `.0` from integers and uses the spec's NaN/+Inf/-Inf tokens.
func formatValue(v float64) string {
	switch {
	case v != v: // NaN
		return "NaN"
	case v > 1e308:
		return "+Inf"
	case v < -1e308:
		return "-Inf"
	}
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
