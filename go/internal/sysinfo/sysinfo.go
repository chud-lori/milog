// Package sysinfo exposes tiny OS primitives that don't warrant a dep.
//
// The broader /proc readers (CPU %, mem, disk) live separately in
// internal/sysstat when the Phase 5 summary.json port lands. This file
// only covers what /api/meta.json needs right now: uptime + hostname.
package sysinfo

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Uptime returns a human-readable uptime string, matching the `uptime -p`
// format bash uses ("up 3 hours, 42 minutes" → we strip the "up "). On
// unsupported OSes returns empty string, not an error — meta.json treats
// it as informational.
func Uptime() string {
	// Linux: /proc/uptime is "secs.fraction idle.fraction"
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/proc/uptime")
		if err == nil {
			fields := strings.Fields(string(b))
			if len(fields) >= 1 {
				secs, err := strconv.ParseFloat(fields[0], 64)
				if err == nil {
					return formatDuration(time.Duration(secs) * time.Second)
				}
			}
		}
	}
	// Fallback: no uptime available (darwin dev, minimal containers, etc.)
	return ""
}

// Hostname is a thin wrapper over os.Hostname that swallows errors so the
// returned value is always a usable string (empty on error, not "error").
func Hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return ""
}

// formatDuration renders something like "3 hours, 42 minutes" for the
// common ranges (seconds/minutes/hours/days).
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%d hours", h)
		}
		return fmt.Sprintf("%d hours, %d minutes", h, m)
	}
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	if hours == 0 {
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%d days, %d hours", days, hours)
}
