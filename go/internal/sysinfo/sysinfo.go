// Package sysinfo provides uptime and hostname for /api/meta.json.
package sysinfo

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Uptime returns `uptime -p` style text without the "up " prefix, or "" where
// /proc/uptime doesn't exist.
func Uptime() string {
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
	return ""
}

// Hostname returns os.Hostname, or "" on error.
func Hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return ""
}

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
