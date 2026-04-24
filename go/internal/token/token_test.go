package token

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeToken(t *testing.T, tok string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "web.token")
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRead(t *testing.T) {
	if got := Read("/does/not/exist"); got != "" {
		t.Errorf("missing file: got %q want empty", got)
	}
	p := writeToken(t, "abc123")
	if got := Read(p); got != "abc123" {
		t.Errorf("Read: got %q want abc123", got)
	}
}

func TestResolveFromEnv(t *testing.T) {
	t.Setenv("MILOG_WEB_TOKEN_FILE", "/tmp/custom.token")
	if got := Resolve(); got != "/tmp/custom.token" {
		t.Errorf("env override: got %q", got)
	}
}

func TestMiddleware(t *testing.T) {
	p := writeToken(t, "secret")
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	h := Middleware(p)(inner)

	// No token → 401
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: got %d want 401", rec.Code)
	}

	// Wrong token → 401
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d want 401", rec.Code)
	}

	// Right token via header → 200
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("right token: got %d want 200", rec.Code)
	}

	// Right token via query → 200
	req = httptest.NewRequest("GET", "/?t=secret", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("query token: got %d want 200", rec.Code)
	}
}

func TestMiddleware_MissingTokenFile(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	h := Middleware("/does/not/exist")(inner)
	req := httptest.NewRequest("GET", "/?t=anything", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing token file: got %d want 401", rec.Code)
	}
}
