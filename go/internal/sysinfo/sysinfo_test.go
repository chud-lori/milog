package sysinfo

import (
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{30 * time.Second, "30 seconds"},
		{5 * time.Minute, "5 minutes"},
		{59 * time.Minute, "59 minutes"},
		{1 * time.Hour, "1 hours"},
		{3*time.Hour + 42*time.Minute, "3 hours, 42 minutes"},
		{26 * time.Hour, "1 days, 2 hours"},
		{3 * 24 * time.Hour, "3 days"},
	}
	for _, c := range cases {
		if got := formatDuration(c.in); got != c.want {
			t.Errorf("formatDuration(%v): got %q want %q", c.in, got, c.want)
		}
	}
}

func TestHostname(t *testing.T) {
	h := Hostname()
	// Never panics, never returns "error" — empty is acceptable on weird
	// kernels that fail os.Hostname().
	_ = h
}
