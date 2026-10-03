package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/chud-lori/milog/internal/config"
)

func TestNewHandler_StaticPublicDataGated(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "web.token")
	if err := os.WriteFile(tokenPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	staticFS, err := fs.Sub(webFS, "web")
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(&config.Config{}, tokenPath, staticFS)

	cases := []struct {
		path string
		want int
	}{
		{"/static/app.js", http.StatusOK},
		{"/static/app.css", http.StatusOK},
		{"/static/milog-icon.png", http.StatusOK},
		{"/healthz", http.StatusOK},
		{"/", http.StatusUnauthorized},
		{"/?t=secret", http.StatusOK},
		{"/api/meta.json", http.StatusUnauthorized},
		{"/api/logs.json", http.StatusUnauthorized},
		{"/api/stream", http.StatusUnauthorized},
		{"/api/logs/stream", http.StatusUnauthorized},
		{"/metrics", http.StatusUnauthorized},
		{"/debug", http.StatusUnauthorized},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", c.path, nil))
		if rec.Code != c.want {
			t.Errorf("GET %s: got %d want %d", c.path, rec.Code, c.want)
		}
	}
}
