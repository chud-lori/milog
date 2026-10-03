package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chud-lori/milog/internal/config"
)

const testLogLine = `1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /ok HTTP/1.1" 200 12 "-" "curl" 0.010` + "\n"

// newTraversalFixture lays out LogDir with one configured app plus a
// "secret" access log outside LogDir that a traversal would try to reach.
func newTraversalFixture(t *testing.T) (*config.Config, string) {
	t.Helper()
	root := t.TempDir()
	logDir := filepath.Join(root, "logs")
	if err := os.Mkdir(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "api.access.log"), []byte(testLogLine), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret.access.log")
	if err := os.WriteFile(secret, []byte(testLogLine), 0o644); err != nil {
		t.Fatal(err)
	}
	return &config.Config{LogDir: logDir, Apps: []string{"api"}}, strings.TrimSuffix(secret, ".access.log")
}

func TestAppParam_RejectsUnconfiguredApps(t *testing.T) {
	cfg, secret := newTraversalFixture(t)
	handlers := map[string]http.HandlerFunc{
		"/api/logs.json":           logsHandler(cfg),
		"/api/logs/histogram.json": logsHistogramHandler(cfg),
		"/api/logs/stream":         logsStreamHandler(cfg),
		"/api/latency.json":        latencyHandler(cfg),
	}
	// Raw query strings, so the encoded forms reach the handler undecoded.
	payloads := map[string]string{
		"relative traversal":      "app=../../etc/passwd",
		"traversal to real file":  "app=../secret",
		"absolute path":           "app=" + secret,
		"encoded traversal":       "app=..%2F..%2Fetc%2Fpasswd",
		"double-encoded":          "app=%252e%252e%252fsecret",
		"unknown app":             "app=nonexistent",
		"configured app plus dir": "app=api/../api",
		"empty":                   "app=",
	}
	for path, h := range handlers {
		for name, rawQuery := range payloads {
			req := httptest.NewRequest(http.MethodGet, path+"?"+rawQuery, nil)
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s %s (%s): status %d, want 400; body %q", path, name, rawQuery, rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "/ok") {
				t.Errorf("%s %s: leaked log content: %q", path, name, rec.Body.String())
			}
		}
	}
}

func TestAppParam_ConfiguredAppServed(t *testing.T) {
	cfg, _ := newTraversalFixture(t)
	handlers := map[string]http.HandlerFunc{
		"/api/logs.json":           logsHandler(cfg),
		"/api/logs/histogram.json": logsHistogramHandler(cfg),
		"/api/latency.json":        latencyHandler(cfg),
	}
	for path, h := range handlers {
		req := httptest.NewRequest(http.MethodGet, path+"?app=api", nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s app=api: status %d, want 200; body %q", path, rec.Code, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/logs.json?app=api", nil)
	rec := httptest.NewRecorder()
	logsHandler(cfg)(rec, req)
	if !strings.Contains(rec.Body.String(), `"/ok"`) {
		t.Errorf("logs app=api: want the configured log line, got %q", rec.Body.String())
	}
}

func TestAppParam_ConfiguredButMissingIs404(t *testing.T) {
	cfg, _ := newTraversalFixture(t)
	cfg.Apps = append(cfg.Apps, "web")
	req := httptest.NewRequest(http.MethodGet, "/api/logs.json?app=web", nil)
	rec := httptest.NewRecorder()
	logsHandler(cfg)(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("configured app without a log: status %d, want 404", rec.Code)
	}
}

func TestAppLogPath_ConfiguredNameOutsideLogDir(t *testing.T) {
	cfg := &config.Config{LogDir: "/var/log/nginx", Apps: []string{"../../etc/passwd", "sub/api", "api"}}
	for _, app := range []string{"../../etc/passwd", "sub/api"} {
		if p, ok := appLogPath(cfg, app); ok {
			t.Errorf("appLogPath(%q) = %q, want rejected", app, p)
		}
	}
	if p, ok := appLogPath(cfg, "api"); !ok || p != "/var/log/nginx/api.access.log" {
		t.Errorf("appLogPath(api) = %q, %v", p, ok)
	}
}
