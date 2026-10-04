// Package token handles web-UI auth. ~/.config/milog/web.token (0600) is
// written by bash _web_token_ensure and reread on every request, so
// `milog web rotate-token` takes effect without a restart.
package token

import (
	"crypto/subtle"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Resolve returns the token file path, defaulting to $HOME/.config/milog/web.token.
func Resolve() string {
	if v := os.Getenv("MILOG_WEB_TOKEN_FILE"); v != "" {
		return v
	}
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	return filepath.Join(home, ".config", "milog", "web.token")
}

// Read returns the trimmed token, or "" when the file is missing, which makes
// every request 401.
func Read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Middleware requires the token as `Authorization: Bearer <token>` or, on
// first page load, ?t=<token> (the page JS then moves it to sessionStorage).
func Middleware(tokenPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expected := Read(tokenPath)
			if expected == "" {
				http.Error(w, "token file missing — generate with `milog web rotate-token`", http.StatusUnauthorized)
				return
			}
			provided := extract(r)
			if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// extract prefers the header so sessions survive the JS stripping ?t= from the URL.
func extract(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		const pfx = "Bearer "
		if strings.HasPrefix(h, pfx) {
			return strings.TrimSpace(h[len(pfx):])
		}
	}
	return r.URL.Query().Get("t")
}
