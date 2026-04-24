package config

import (
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("MILOG_WEB_BIND", "")
	t.Setenv("MILOG_WEB_PORT", "")
	t.Setenv("MILOG_LOG_DIR", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bind != "127.0.0.1" {
		t.Errorf("Bind default: got %q want 127.0.0.1", cfg.Bind)
	}
	if cfg.Port != "8765" {
		t.Errorf("Port default: got %q want 8765", cfg.Port)
	}
	if cfg.LogDir != "/var/log/nginx" {
		t.Errorf("LogDir default: got %q want /var/log/nginx", cfg.LogDir)
	}
}

func TestLoad_Overrides(t *testing.T) {
	t.Setenv("MILOG_WEB_BIND", "0.0.0.0")
	t.Setenv("MILOG_WEB_PORT", "9000")
	t.Setenv("MILOG_LOG_DIR", "/tmp/logs")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bind != "0.0.0.0" {
		t.Errorf("Bind override: got %q", cfg.Bind)
	}
	if cfg.Port != "9000" {
		t.Errorf("Port override: got %q", cfg.Port)
	}
	if cfg.LogDir != "/tmp/logs" {
		t.Errorf("LogDir override: got %q", cfg.LogDir)
	}
}

func TestLoad_InvalidPort(t *testing.T) {
	t.Setenv("MILOG_WEB_PORT", "not-a-number")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for non-numeric port, got nil")
	}
}
