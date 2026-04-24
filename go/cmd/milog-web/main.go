// milog-web — optional Go implementation of `milog web`.
//
// Phase 5 foundation + the first actually-functional route. `/healthz`
// is public; everything under `/api/*` and `/` is token-gated by the same
// web.token file the bash handler uses. More routes (summary, alerts,
// logs, SSE stream) land in subsequent commits.
//
// Intentionally scoped to the Go standard library — no third-party deps —
// to keep the binary buildable from any Go 1.22+ toolchain with no module
// dance.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/chud-lori/milog/internal/config"
	"github.com/chud-lori/milog/internal/nginxlog"
	"github.com/chud-lori/milog/internal/sysinfo"
	"github.com/chud-lori/milog/internal/sysstat"
	"github.com/chud-lori/milog/internal/token"
)

// buildVersion is overridden at link time: `go build -ldflags "-X main.buildVersion=abc1234"`.
var buildVersion = "unknown"

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("milog-web: config: %v", err)
	}

	tokenPath := token.Resolve()
	auth := token.Middleware(tokenPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)                        // public
	mux.Handle("/api/meta.json", auth(metaHandler(cfg)))       // token-gated
	mux.Handle("/api/summary.json", auth(summaryHandler(cfg))) // token-gated
	mux.Handle("/", auth(rootHandler(cfg)))

	// Security headers on every response — match bash `_web_respond`.
	handler := securityHeaders(mux)

	addr := net.JoinHostPort(cfg.Bind, cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("milog-web v=%s listening on http://%s  (token: %s)", buildVersion, addr, tokenPath)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("milog-web: listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("milog-web: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

// healthz is the liveness probe — kept public so systemd WatchdogSec and
// future k8s probes don't need the token.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintln(w, "ok")
}

// metaHandler returns the same shape as bash `_web_route_meta`:
//
//	{"apps":[…], "log_dir":"…", "alerts":"enabled|disabled",
//	 "webhook":"…redacted…", "uptime":"…", "refresh":N}
func metaHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		payload := struct {
			Apps    []string `json:"apps"`
			LogDir  string   `json:"log_dir"`
			Alerts  string   `json:"alerts"`
			Webhook string   `json:"webhook"`
			Uptime  string   `json:"uptime"`
			Refresh int      `json:"refresh"`
		}{
			Apps:    cfg.Apps,
			LogDir:  cfg.LogDir,
			Alerts:  cfg.AlertsStatus(),
			Webhook: cfg.RedactedDiscordWebhook(),
			Uptime:  sysinfo.Uptime(),
			Refresh: cfg.Refresh,
		}
		writeJSON(w, payload)
	}
}

// summaryHandler assembles the live dashboard payload: system metrics +
// per-app nginx counts for the current minute. Matches the bash
// `_web_route_summary` output shape so the existing HTML/JS keeps
// working once the dashboard is served from Go.
func summaryHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		type appRow struct {
			Name string `json:"name"`
			Req  int    `json:"req"`
			C2xx int    `json:"c2xx"`
			C3xx int    `json:"c3xx"`
			C4xx int    `json:"c4xx"`
			C5xx int    `json:"c5xx"`
		}
		type sys struct {
			CPU         int   `json:"cpu"`
			MemPct      int   `json:"mem_pct"`
			MemUsedMB   int64 `json:"mem_used_mb"`
			MemTotalMB  int64 `json:"mem_total_mb"`
			DiskPct     int   `json:"disk_pct"`
			DiskUsedGB  int64 `json:"disk_used_gb"`
			DiskTotalGB int64 `json:"disk_total_gb"`
		}
		type payload struct {
			TS       string   `json:"ts"`
			System   sys      `json:"system"`
			TotalReq int      `json:"total_req"`
			Apps     []appRow `json:"apps"`
		}

		// System metrics — /proc-based on Linux, zeros on darwin dev.
		cpu, _ := sysstat.CPU()
		mem, _ := sysstat.Mem()
		disk, _ := sysstat.DiskAt("/")

		// Per-app counts. Minute prefix scoped to NOW so the count
		// matches what `milog monitor` is showing in the terminal.
		minute := nginxlog.CurrentMinutePrefix(time.Now())
		apps := make([]appRow, 0, len(cfg.Apps))
		total := 0
		for _, a := range cfg.Apps {
			path := filepath.Join(cfg.LogDir, a+".access.log")
			c, _ := nginxlog.MinuteCounts(path, minute)
			apps = append(apps, appRow{
				Name: a, Req: c.Total,
				C2xx: c.C2xx, C3xx: c.C3xx, C4xx: c.C4xx, C5xx: c.C5xx,
			})
			total += c.Total
		}

		writeJSON(w, payload{
			TS: time.Now().Format(time.RFC3339),
			System: sys{
				CPU:         cpu,
				MemPct:      mem.Pct,
				MemUsedMB:   mem.UsedMB,
				MemTotalMB:  mem.TotalMB,
				DiskPct:     disk.Pct,
				DiskUsedGB:  disk.UsedGB,
				DiskTotalGB: disk.TotalGB,
			},
			TotalReq: total,
			Apps:     apps,
		})
	}
}

// rootHandler is the placeholder index until the dashboard HTML gets
// ported. Returns a short plain-text page so curl smoke tests still show
// something meaningful.
func rootHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		var sb strings.Builder
		sb.WriteString("milog-web (Go; route parity in progress)\n\n")
		fmt.Fprintf(&sb, "version:  %s\n", buildVersion)
		fmt.Fprintf(&sb, "bind:     %s:%s\n", cfg.Bind, cfg.Port)
		fmt.Fprintf(&sb, "log_dir:  %s\n", cfg.LogDir)
		fmt.Fprintf(&sb, "apps:     %s\n", strings.Join(cfg.Apps, " "))
		sb.WriteString("\nPorted routes:\n  /healthz           public liveness\n  /api/meta.json     apps + alerts status + uptime\n  /api/summary.json  system + nginx counts (current minute)\n")
		sb.WriteString("\nStill bash-served (next commits):\n  /api/alerts.json   fire history\n  /api/logs.json     log viewer tier 1\n  /api/stream        SSE live push\n")
		_, _ = w.Write([]byte(sb.String()))
	}
}

// securityHeaders wraps every response with the same set bash emits.
// Keeps CSP strict, disables framing/referrer, no-store cache.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'none'")
		next.ServeHTTP(w, r)
	})
}

// writeJSON emits a JSON payload with matching Content-Type + no-store.
// Errors during Encode get logged but not surfaced — the client already
// got the status code, trying to write a new body would corrupt the
// stream.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("milog-web: json encode: %v", err)
	}
}

// Compile-time pin of os import for future main-level uses; remove when
// the next routes land and genuinely import os themselves.
var _ = os.Getenv
