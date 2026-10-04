// Package config reads the MILOG_* env vars that bash exports to the Go
// binaries; it does not parse the bash config file.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	Bind           string
	Port           string
	LogDir         string
	Apps           []string
	Refresh        int    // seconds between TUI / daemon ticks
	AlertsEnabled  bool
	DiscordWebhook string // raw; use RedactedDiscordWebhook() for display
	AlertStateDir  string // where alerts.log + alerts.state live
	HistoryDB      string // path to the SQLite metrics DB (empty when HISTORY_ENABLED=0)
}

// Load reads the env with defaults and errors on invalid values such as a
// non-numeric port.
func Load() (*Config, error) {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	c := &Config{
		Bind:           getEnv("MILOG_WEB_BIND", "127.0.0.1"),
		Port:           getEnv("MILOG_WEB_PORT", "8765"),
		LogDir:         getEnv("MILOG_LOG_DIR", "/var/log/nginx"),
		DiscordWebhook: os.Getenv("MILOG_DISCORD_WEBHOOK"),
		AlertStateDir:  getEnv("MILOG_ALERT_STATE_DIR", home+"/.cache/milog"),
		// Same default path as the bash side.
		HistoryDB: getEnv("MILOG_HISTORY_DB", home+"/.local/share/milog/metrics.db"),
	}
	if _, err := strconv.Atoi(c.Port); err != nil {
		return nil, fmt.Errorf("MILOG_WEB_PORT must be numeric, got %q", c.Port)
	}

	if apps := os.Getenv("MILOG_APPS"); apps != "" {
		for _, a := range strings.Fields(apps) {
			c.Apps = append(c.Apps, a)
		}
	}

	refresh, err := strconv.Atoi(getEnv("MILOG_REFRESH", "5"))
	if err != nil {
		return nil, fmt.Errorf("MILOG_REFRESH must be numeric, got %q", os.Getenv("MILOG_REFRESH"))
	}
	c.Refresh = refresh

	c.AlertsEnabled = os.Getenv("MILOG_ALERTS_ENABLED") == "1"

	return c, nil
}

// RedactedDiscordWebhook masks the webhook token with `****`; empty when unset.
func (c *Config) RedactedDiscordWebhook() string {
	w := c.DiscordWebhook
	if w == "" {
		return ""
	}
	re := regexp.MustCompile(`^(https?://[^/]+/api/webhooks/\d+/)[A-Za-z0-9_-]+`)
	if m := re.FindStringSubmatch(w); m != nil {
		return m[1] + "****"
	}
	if len(w) > 20 {
		return w[:20] + "…"
	}
	return w
}

// AlertsStatus returns "enabled" or "disabled" for /api/meta.json.
func (c *Config) AlertsStatus() string {
	if c.AlertsEnabled && c.DiscordWebhook != "" {
		return "enabled"
	}
	return "disabled"
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
