// Package token handles web-UI auth.
//
// The file ~/.config/milog/web.token (mode 0600, 32-byte hex) is the
// single source of truth: the bash launcher generates it (see
// `_web_token_ensure`), `milog web rotate-token` regenerates, and this
// package reads it on every request — never cached, so rotation takes
// effect at the next HTTP call without restarting milog-web.
package token

import (
	"crypto/subtle"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Resolve returns the path to the token file, honouring env vars that
// bash would see. Falls back to $HOME/.config/milog/web.token.
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

// Read loads the current token from disk, trimming any trailing whitespace
// (matching bash `tr -d '[:space:]'`). Empty string on missing/unreadable —
// callers treat that as "no auth configured yet", which produces 401 on
// every request (correct default).
func Read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Middleware returns an HTTP middleware that enforces token auth on every
// protected route. The token path is resolved once per request (not
// cached) so rotation via `milog web rotate-token` takes effect on the
// next request, no daemon restart needed — matching bash behaviour.
//
// Token may be provided via:
//   - Authorization: Bearer <token>   (preferred; API calls)
//   - ?t=<token> query parameter       (first page load; the HTML JS
//                                       moves it to sessionStorage + strips)
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

// extract pulls the token from Authorization or ?t=. Header wins so
// long-lived sessions survive after the URL token is stripped by the JS.
func extract(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		const pfx = "Bearer "
		if strings.HasPrefix(h, pfx) {
			return strings.TrimSpace(h[len(pfx):])
		}
	}
	return r.URL.Query().Get("t")
}
