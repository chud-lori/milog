package config

import (
	"testing"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"MILOG_WEB_BIND", "MILOG_WEB_PORT", "MILOG_LOG_DIR",
		"MILOG_APPS", "MILOG_REFRESH",
		"MILOG_ALERTS_ENABLED", "MILOG_DISCORD_WEBHOOK",
	} {
		t.Setenv(k, "")
	}
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bind != "127.0.0.1" {
		t.Errorf("Bind: got %q", cfg.Bind)
	}
	if cfg.Port != "8765" {
		t.Errorf("Port: got %q", cfg.Port)
	}
	if cfg.LogDir != "/var/log/nginx" {
		t.Errorf("LogDir: got %q", cfg.LogDir)
	}
	if cfg.Refresh != 5 {
		t.Errorf("Refresh: got %d", cfg.Refresh)
	}
	if len(cfg.Apps) != 0 {
		t.Errorf("Apps default: got %v", cfg.Apps)
	}
	if cfg.AlertsEnabled {
		t.Errorf("AlertsEnabled default: got true")
	}
}

func TestLoad_Overrides(t *testing.T) {
	clearEnv(t)
	t.Setenv("MILOG_WEB_BIND", "0.0.0.0")
	t.Setenv("MILOG_WEB_PORT", "9000")
	t.Setenv("MILOG_LOG_DIR", "/tmp/logs")
	t.Setenv("MILOG_APPS", "api  web  finance")
	t.Setenv("MILOG_REFRESH", "3")
	t.Setenv("MILOG_ALERTS_ENABLED", "1")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bind != "0.0.0.0" || cfg.Port != "9000" || cfg.LogDir != "/tmp/logs" {
		t.Errorf("basic overrides: %+v", cfg)
	}
	if len(cfg.Apps) != 3 || cfg.Apps[0] != "api" || cfg.Apps[2] != "finance" {
		t.Errorf("apps: got %v", cfg.Apps)
	}
	if cfg.Refresh != 3 {
		t.Errorf("refresh: got %d", cfg.Refresh)
	}
	if !cfg.AlertsEnabled {
		t.Errorf("alerts enabled should be true")
	}
}

func TestLoad_InvalidPort(t *testing.T) {
	clearEnv(t)
	t.Setenv("MILOG_WEB_PORT", "not-a-number")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for non-numeric port")
	}
}

func TestLoad_InvalidRefresh(t *testing.T) {
	clearEnv(t)
	t.Setenv("MILOG_REFRESH", "nope")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for non-numeric refresh")
	}
}

func TestRedactedDiscordWebhook(t *testing.T) {
	cases := map[string]string{
		"": "",
		"https://discord.com/api/webhooks/111222333/AAAAAAAAAAAAA": "https://discord.com/api/webhooks/111222333/****",
		"https://discordapp.com/api/webhooks/42/secrettoken":       "https://discordapp.com/api/webhooks/42/****",
		"not-a-url":     "not-a-url",
		"https://example.com/something/very/long/here/that/is/a/fallback": "https://example.com/…",
	}
	for in, want := range cases {
		c := &Config{DiscordWebhook: in}
		got := c.RedactedDiscordWebhook()
		if got != want {
			t.Errorf("redact(%q): got %q want %q", in, got, want)
		}
	}
}

func TestAlertsStatus(t *testing.T) {
	c := &Config{}
	if got := c.AlertsStatus(); got != "disabled" {
		t.Errorf("empty: %q", got)
	}
	c.AlertsEnabled = true
	if got := c.AlertsStatus(); got != "disabled" {
		t.Errorf("enabled but no webhook: %q", got)
	}
	c.DiscordWebhook = "https://x"
	if got := c.AlertsStatus(); got != "enabled" {
		t.Errorf("both set: %q", got)
	}
}
