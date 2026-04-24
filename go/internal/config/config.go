// Package config reads MiLog's env overrides.
//
// Future: parse the bash config file directly so Go and bash see the same
// config without a second syntax. Today the Go binary takes the env-vars
// that bash exposes (MILOG_WEB_PORT, MILOG_WEB_BIND, MILOG_LOG_DIR, etc.) —
// that's the same boundary the bash daemon offers to its own subprocesses,
// and it keeps the Go side simple.
package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Bind   string
	Port   string
	LogDir string
}

// Load resolves the Config from env vars, falling back to documented
// defaults. Returns an error if any provided value is syntactically
// invalid (e.g. a non-numeric port).
func Load() (*Config, error) {
	c := &Config{
		Bind:   getEnv("MILOG_WEB_BIND", "127.0.0.1"),
		Port:   getEnv("MILOG_WEB_PORT", "8765"),
		LogDir: getEnv("MILOG_LOG_DIR", "/var/log/nginx"),
	}
	if _, err := strconv.Atoi(c.Port); err != nil {
		return nil, fmt.Errorf("MILOG_WEB_PORT must be numeric, got %q", c.Port)
	}
	return c, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
