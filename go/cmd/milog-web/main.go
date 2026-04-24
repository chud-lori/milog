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
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chud-lori/milog/internal/alertlog"
	"github.com/chud-lori/milog/internal/config"
	"github.com/chud-lori/milog/internal/nginxlog"
	"github.com/chud-lori/milog/internal/promtext"
	"github.com/chud-lori/milog/internal/sysinfo"
	"github.com/chud-lori/milog/internal/sysstat"
	"github.com/chud-lori/milog/internal/token"
)

// dashboardHTML is the self-contained dashboard page — HTML + inline CSS
// + inline JS. Copied from bash `_web_route_index`'s heredoc and embedded
// at build time. The bash version stays as a fallback for installs
// without the Go binary, but this is the authoritative copy going
// forward.
//
//go:embed dashboard.html
var dashboardHTML []byte

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
	mux.Handle("/api/alerts.json", auth(alertsHandler(cfg)))   // token-gated
	mux.Handle("/api/logs.json", auth(logsHandler(cfg)))       // token-gated
	mux.Handle("/api/logs/histogram.json", auth(logsHistogramHandler(cfg)))
	mux.Handle("/api/stream", auth(streamHandler(cfg)))
	mux.Handle("/metrics", auth(metricsHandler(cfg)))
	mux.Handle("/debug", auth(debugHandler(cfg)))
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

// summaryHandler is the legacy poll endpoint — kept for curl / CI
// scripts and for clients that don't speak SSE. Uses the same
// collectSummary snapshot function as /api/stream, so output shape is
// guaranteed identical between the two.
func summaryHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, collectSummary(cfg))
	}
}

// alertsHandler returns recent alerts.log rows filtered by the `window`
// query param (default "24h", same grammar as `milog alerts`). Capped at
// 100 rows. Shape matches bash `_web_route_alerts`:
//
//	{"window":"24h","alerts":[{"ts":…,"rule":…,"sev":…,"title":…,"body":…}, …]}
func alertsHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		window := r.URL.Query().Get("window")
		if window == "" {
			window = "24h"
		}
		cutoff, err := alertlog.WindowToCutoff(window, time.Now())
		if err != nil {
			// Fall back to 24h rather than 400 — UI sends known-good
			// values, invalid ones only come from URL fiddling.
			cutoff, _ = alertlog.WindowToCutoff("24h", time.Now())
		}
		rows, err := alertlog.Load(filepath.Join(cfg.AlertStateDir, "alerts.log"), cutoff, 100)
		if err != nil {
			// Best-effort: log, return empty set. Panel is informational.
			log.Printf("milog-web: alertlog.Load: %v", err)
		}
		if rows == nil {
			rows = []alertlog.Row{}
		}
		writeJSON(w, struct {
			Window string          `json:"window"`
			Alerts []alertlog.Row  `json:"alerts"`
		}{Window: window, Alerts: rows})
	}
}

// metricsHandler emits a Prometheus plaintext 0.0.4 /metrics payload.
// Metric surface:
//
//	milog_up                                                gauge, always 1
//	milog_cpu_percent                                       gauge
//	milog_mem_percent / milog_mem_used_bytes / _total_bytes gauge
//	milog_disk_percent{path=…} + used_bytes + total_bytes   gauge
//	milog_requests_last_minute{app=…,class=…}               gauge
//	milog_alerts_fired_total{rule=…,sev=…}                  gauge (running sum from alerts.log)
//	milog_apps_configured                                   gauge
//
// Token-gated like the other routes — Prom scrapers pass the token via
// Authorization header in their scrape_config. Alternatively, they pull
// via `?t=TOKEN` but keeping it off the URL is preferable.
func metricsHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")

		// Collect once — same snapshot function other routes use, so the
		// metrics line up with the dashboard numbers.
		cpu, _ := sysstat.CPU()
		mem, _ := sysstat.Mem()
		disk, _ := sysstat.DiskAt("/")
		diskLabel := map[string]string{"path": "/"}

		// Per-app request counts by class.
		minute := nginxlog.CurrentMinutePrefix(time.Now())
		var reqSamples []promtext.Sample
		for _, a := range cfg.Apps {
			file := filepath.Join(cfg.LogDir, a+".access.log")
			c, _ := nginxlog.MinuteCounts(file, minute)
			// Emit one sample per class so PromQL can slice with `class=~"4xx|5xx"`.
			reqSamples = append(reqSamples,
				promtext.Sample{Labels: map[string]string{"app": a, "class": "2xx"}, Value: float64(c.C2xx)},
				promtext.Sample{Labels: map[string]string{"app": a, "class": "3xx"}, Value: float64(c.C3xx)},
				promtext.Sample{Labels: map[string]string{"app": a, "class": "4xx"}, Value: float64(c.C4xx)},
				promtext.Sample{Labels: map[string]string{"app": a, "class": "5xx"}, Value: float64(c.C5xx)},
			)
		}

		// Alert fires — total count per rule across the whole alerts.log.
		// Read cheaply; bucket in memory.
		alertRows, _ := alertlog.Load(filepath.Join(cfg.AlertStateDir, "alerts.log"), 0, 0)
		type rk struct{ rule, sev string }
		alertCount := map[rk]int{}
		for _, r := range alertRows {
			alertCount[rk{r.Rule, r.Sev}]++
		}
		var alertSamples []promtext.Sample
		for k, n := range alertCount {
			alertSamples = append(alertSamples, promtext.Sample{
				Labels: map[string]string{"rule": k.rule, "sev": k.sev},
				Value:  float64(n),
			})
		}

		metrics := []promtext.Metric{
			{Name: "milog_up", Help: "1 when milog-web is reachable.", Type: "gauge",
				Samples: []promtext.Sample{{Value: 1}}},
			{Name: "milog_apps_configured", Help: "Number of nginx apps MiLog is watching.", Type: "gauge",
				Samples: []promtext.Sample{{Value: float64(len(cfg.Apps))}}},
			{Name: "milog_cpu_percent", Help: "Current CPU busy percent (instant sample, Linux only).", Type: "gauge",
				Samples: []promtext.Sample{{Value: float64(cpu)}}},
			{Name: "milog_mem_percent", Help: "Memory used as percent of total.", Type: "gauge",
				Samples: []promtext.Sample{{Value: float64(mem.Pct)}}},
			{Name: "milog_mem_used_bytes", Help: "Memory used in bytes.", Type: "gauge",
				Samples: []promtext.Sample{{Value: float64(mem.UsedMB) * 1024 * 1024}}},
			{Name: "milog_mem_total_bytes", Help: "Memory total in bytes.", Type: "gauge",
				Samples: []promtext.Sample{{Value: float64(mem.TotalMB) * 1024 * 1024}}},
			{Name: "milog_disk_percent", Help: "Disk used percent, by mount point.", Type: "gauge",
				Samples: []promtext.Sample{{Labels: diskLabel, Value: float64(disk.Pct)}}},
			{Name: "milog_disk_used_bytes", Help: "Disk used in bytes, by mount point.", Type: "gauge",
				Samples: []promtext.Sample{{Labels: diskLabel, Value: float64(disk.UsedGB) * 1024 * 1024 * 1024}}},
			{Name: "milog_disk_total_bytes", Help: "Disk total in bytes, by mount point.", Type: "gauge",
				Samples: []promtext.Sample{{Labels: diskLabel, Value: float64(disk.TotalGB) * 1024 * 1024 * 1024}}},
			{Name: "milog_requests_last_minute", Help: "Nginx request count in the current minute, per app + status class.",
				Type: "gauge", Samples: reqSamples},
			{Name: "milog_alerts_fired_total", Help: "Total alerts in alerts.log, per rule + severity.",
				Type: "gauge", Samples: alertSamples},
		}
		_ = promtext.Encode(w, metrics)
	}
}

// streamHandler is the Phase 5 marquee — Server-Sent Events push of the
// same snapshot `/api/summary.json` returns, every REFRESH seconds. No
// polling; the browser holds a single connection open and renders on
// each `summary` event. Request volume drops by ~10× versus the
// previous 3-second poll loop.
//
// Protocol: text/event-stream with named events. A `ping` event every
// 15s keeps proxies / CF Tunnel from closing the connection on idle.
//
// Fan-out is implicit — every connected client calls collectSummary()
// on its own goroutine. For <50 concurrent clients (MiLog's typical
// audience: a handful of ops) the 3-second re-scan cost is negligible.
// If concurrent count ever gets real we'll move to a broadcast channel.
func streamHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/event-stream; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("Connection", "keep-alive")
		h.Set("X-Accel-Buffering", "no") // disable nginx proxy buffering

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported by server", http.StatusInternalServerError)
			return
		}

		// Snapshot cadence. Defaults to cfg.Refresh (usually 5s); the
		// ?refresh= query param lets a specific client tighten the rate.
		cadence := time.Duration(cfg.Refresh) * time.Second
		if v := r.URL.Query().Get("refresh"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 60 {
				cadence = time.Duration(n) * time.Second
			}
		}
		if cadence <= 0 {
			cadence = 3 * time.Second
		}

		// Fire a snapshot immediately so the client renders on connect
		// without waiting `cadence` seconds for the first tick.
		pushSummary(w, flusher, cfg)

		tick := time.NewTicker(cadence)
		defer tick.Stop()
		ping := time.NewTicker(15 * time.Second)
		defer ping.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				pushSummary(w, flusher, cfg)
			case <-ping.C:
				if _, err := fmt.Fprintf(w, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}

// pushSummary collects + emits one `summary` SSE event. Errors are
// silent: the client reconnects on its own via EventSource's built-in
// retry; logging every transient write error would drown useful logs.
func pushSummary(w http.ResponseWriter, flusher http.Flusher, cfg *config.Config) {
	snap := collectSummary(cfg)
	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	// Prefix each payload with `event: summary` so the client can attach
	// a named listener. Body must end with a blank line.
	_, _ = fmt.Fprintf(w, "event: summary\ndata: %s\n\n", b)
	flusher.Flush()
}

// collectSummary returns the same payload summaryHandler emits — shared
// so SSE and JSON-poll can't drift. Moved out of summaryHandler so both
// call sites can produce an identical snapshot.
func collectSummary(cfg *config.Config) any {
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
	cpu, _ := sysstat.CPU()
	mem, _ := sysstat.Mem()
	disk, _ := sysstat.DiskAt("/")

	minute := nginxlog.CurrentMinutePrefix(time.Now())
	apps := make([]appRow, 0, len(cfg.Apps))
	total := 0
	for _, a := range cfg.Apps {
		path := filepath.Join(cfg.LogDir, a+".access.log")
		c, _ := nginxlog.MinuteCounts(path, minute)
		apps = append(apps, appRow{Name: a, Req: c.Total, C2xx: c.C2xx, C3xx: c.C3xx, C4xx: c.C4xx, C5xx: c.C5xx})
		total += c.Total
	}
	return struct {
		TS       string   `json:"ts"`
		System   sys      `json:"system"`
		TotalReq int      `json:"total_req"`
		Apps     []appRow `json:"apps"`
	}{
		TS: time.Now().Format(time.RFC3339),
		System: sys{
			CPU: cpu, MemPct: mem.Pct, MemUsedMB: mem.UsedMB, MemTotalMB: mem.TotalMB,
			DiskPct: disk.Pct, DiskUsedGB: disk.UsedGB, DiskTotalGB: disk.TotalGB,
		},
		TotalReq: total,
		Apps:     apps,
	}
}

// logsHandler returns recent log lines for one nginx app, filtered by
// grep / path / status-class. Shape matches bash `_web_route_logs`:
//
//	{"app":"api","lines":[{"ts":"…","ip":"…","method":"…","path":"…",
//	                        "status":200,"ua":"…","class":"2xx"}, …]}
func logsHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		app := q.Get("app")
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 {
			limit = 200
		}
		if limit > 500 {
			limit = 500
		}
		grep := q.Get("grep")
		pathPfx := q.Get("path")
		cls := q.Get("class")

		file := filepath.Join(cfg.LogDir, app+".access.log")
		if app == "" || !fileExists(file) {
			http.Error(w, `{"app":"","lines":[],"error":"no such app"}`, http.StatusNotFound)
			return
		}

		// Read tail×3 so filters have room to yield `limit` rows.
		raw, err := nginxlog.TailLines(file, limit*3)
		if err != nil {
			log.Printf("milog-web: tail %s: %v", file, err)
		}

		out := make([]nginxlog.Line, 0, limit)
		for _, line := range raw {
			if grep != "" && !strings.Contains(line, grep) {
				continue
			}
			l := nginxlog.ParseLine(line)
			if l.Path == "" || l.Status == 0 {
				continue
			}
			if pathPfx != "" && !strings.HasPrefix(l.Path, pathPfx) {
				continue
			}
			if cls != "" && cls != "any" && l.Class != cls {
				continue
			}
			out = append(out, l)
			if len(out) > limit {
				// Sliding window: keep the newest `limit` matches.
				out = out[1:]
			}
		}

		writeJSON(w, struct {
			App   string            `json:"app"`
			Lines []nginxlog.Line   `json:"lines"`
		}{App: app, Lines: out})
	}
}

// logsHistogramHandler returns per-minute request counts for the app
// over the last `minutes` minutes. Used for the timeline strip above
// the log table.
func logsHistogramHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		app := q.Get("app")
		minutes, _ := strconv.Atoi(q.Get("minutes"))
		if minutes <= 0 {
			minutes = 60
		}
		file := filepath.Join(cfg.LogDir, app+".access.log")
		if app == "" || !fileExists(file) {
			http.Error(w, `{"app":"","buckets":[]}`, http.StatusNotFound)
			return
		}
		buckets, err := nginxlog.Histogram(file, minutes, time.Now())
		if err != nil {
			log.Printf("milog-web: histogram %s: %v", file, err)
		}
		writeJSON(w, struct {
			App     string             `json:"app"`
			Buckets []nginxlog.Bucket  `json:"buckets"`
		}{App: app, Buckets: buckets})
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// rootHandler serves the embedded dashboard HTML on "/" and 404s
// anything else that slipped through the auth-guarded catch-all.
func rootHandler(cfg *config.Config) http.HandlerFunc {
	// cfg currently unused — kept in signature for symmetry with the other
	// handlers and for future template substitution (e.g. injecting the
	// version banner server-side).
	_ = cfg
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(dashboardHTML)
	}
}

// debugHandler (mounted at /debug) retains the old plaintext
// status page — handy for smoke-testing that the Go binary is reachable
// without the dashboard JS interfering.
func debugHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		var sb strings.Builder
		sb.WriteString("milog-web (Go)\n\n")
		fmt.Fprintf(&sb, "version:  %s\n", buildVersion)
		fmt.Fprintf(&sb, "bind:     %s:%s\n", cfg.Bind, cfg.Port)
		fmt.Fprintf(&sb, "log_dir:  %s\n", cfg.LogDir)
		fmt.Fprintf(&sb, "apps:     %s\n", strings.Join(cfg.Apps, " "))
		sb.WriteString("\nRoutes:\n")
		sb.WriteString("  /                        dashboard (HTML + inline JS)\n")
		sb.WriteString("  /healthz                 public liveness probe\n")
		sb.WriteString("  /api/meta.json           apps + alerts status + uptime\n")
		sb.WriteString("  /api/summary.json        system + nginx counts\n")
		sb.WriteString("  /api/alerts.json         fire history\n")
		sb.WriteString("  /api/logs.json           log viewer tier 1\n")
		sb.WriteString("  /api/logs/histogram.json timeline strip\n")
		sb.WriteString("  /api/stream              SSE live push\n")
		sb.WriteString("  /metrics                 Prometheus plaintext 0.0.4\n")
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
