// milog-web serves the `milog web` dashboard. /healthz is public; every
// other route needs the token from web.token. Standard library only.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
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
	"github.com/chud-lori/milog/internal/latency"
	"github.com/chud-lori/milog/internal/nginxlog"
	"github.com/chud-lori/milog/internal/promtext"
	"github.com/chud-lori/milog/internal/sysinfo"
	"github.com/chud-lori/milog/internal/sysstat"
	"github.com/chud-lori/milog/internal/tail"
	"github.com/chud-lori/milog/internal/token"
)

// webFS holds index.html, app.css and app.js; assets are served under /static/.
//
//go:embed web
var webFS embed.FS

// buildVersion is set at link time with -ldflags "-X main.buildVersion=...".
var buildVersion = "unknown"

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("milog-web: config: %v", err)
	}

	tokenPath := token.Resolve()
	auth := token.Middleware(tokenPath)

	staticFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("milog-web: embed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)                        // public
	mux.Handle("/api/meta.json", auth(metaHandler(cfg)))       // token-gated
	mux.Handle("/api/summary.json", auth(summaryHandler(cfg))) // token-gated
	mux.Handle("/api/alerts.json", auth(alertsHandler(cfg)))   // token-gated
	mux.Handle("/api/logs.json", auth(logsHandler(cfg)))       // token-gated
	mux.Handle("/api/logs/histogram.json", auth(logsHistogramHandler(cfg)))
	mux.Handle("/api/stream", auth(streamHandler(cfg)))
	mux.Handle("/api/logs/stream", auth(logsStreamHandler(cfg)))
	mux.Handle("/metrics", auth(metricsHandler(cfg)))
	mux.Handle("/api/latency.json", auth(latencyHandler(cfg)))
	mux.Handle("/debug", auth(debugHandler(cfg)))
	mux.Handle("/static/", auth(http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))))
	mux.Handle("/", auth(rootHandler(staticFS)))

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

// healthz is public so liveness checks don't need the token.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintln(w, "ok")
}

// metaHandler returns dashboard config:
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

// summaryHandler is the polling twin of /api/stream, built from the same
// collectSummary snapshot.
func summaryHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, collectSummary(cfg))
	}
}

// alertsHandler returns up to 100 alerts.log rows for `window` (default
// 24h, parsed by alertlog.WindowToCutoff):
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
			// Bad values only come from URL fiddling, so fall back to 24h.
			cutoff, _ = alertlog.WindowToCutoff("24h", time.Now())
		}
		rows, err := alertlog.Load(filepath.Join(cfg.AlertStateDir, "alerts.log"), cutoff, 100)
		if err != nil {
			// The panel is informational: log and return an empty set.
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

// latencyHandler returns p50 to p99.9 for one app from its log tail. Without
// $request_time it returns count 0, so clients show "no samples" instead of
// a fake zero latency.
//
//	app=<name>    required, an nginx source in LOGS
//	lines=<N>     tail depth, default 2000, max 10000
func latencyHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		app := q.Get("app")
		lineN, _ := strconv.Atoi(q.Get("lines"))
		if lineN <= 0 {
			lineN = 2000
		}
		if lineN > 10000 {
			lineN = 10000
		}

		file, ok := appLogPath(cfg, app)
		if !ok {
			http.Error(w, `{"app":"","count":0,"error":"unknown app"}`, http.StatusBadRequest)
			return
		}
		if !fileExists(file) {
			http.Error(w, `{"app":"","count":0,"error":"no such app"}`, http.StatusNotFound)
			return
		}

		raw, err := nginxlog.TailLines(file, lineN)
		if err != nil {
			log.Printf("milog-web: latency tail %s: %v", file, err)
		}
		samples := make([]int64, 0, len(raw))
		for _, line := range raw {
			if ms := latency.ExtractRequestTimeMs(line); ms >= 0 {
				samples = append(samples, ms)
			}
		}
		stats := latency.Percentiles(samples, latency.DefaultQuantiles)
		writeJSON(w, struct {
			App    string              `json:"app"`
			Window int                 `json:"window_lines"`
			Count  int                 `json:"count"`
			MinMs  int64               `json:"min_ms"`
			MaxMs  int64               `json:"max_ms"`
			Pct    map[string]int64    `json:"pct"`
		}{
			App: app, Window: lineN, Count: stats.Count,
			MinMs: stats.MinMs, MaxMs: stats.MaxMs, Pct: stats.Pct,
		})
	}
}

// metricsHandler serves Prometheus text format 0.0.4:
//
//	milog_up                                                gauge, always 1
//	milog_cpu_percent                                       gauge
//	milog_mem_percent / milog_mem_used_bytes / _total_bytes gauge
//	milog_disk_percent{path=…} + used_bytes + total_bytes   gauge
//	milog_requests_last_minute{app=…,class=…}               gauge
//	milog_alerts_fired_total{rule=…,sev=…}                  gauge (running sum from alerts.log)
//	milog_apps_configured                                   gauge
//
// It is token-gated; scrapers should send the token in the Authorization
// header rather than ?t= in the URL.
func metricsHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")

		// Same snapshot as the dashboard, so the numbers agree.
		cpu, _ := sysstat.CPU()
		mem, _ := sysstat.Mem()
		disk, _ := sysstat.DiskAt("/")
		diskLabel := map[string]string{"path": "/"}

		minute := nginxlog.CurrentMinutePrefix(time.Now())
		var reqSamples []promtext.Sample
		for _, a := range cfg.Apps {
			file := filepath.Join(cfg.LogDir, a+".access.log")
			c, _ := nginxlog.MinuteCounts(file, minute)
			// One sample per class, so PromQL can filter with class=~"4xx|5xx".
			reqSamples = append(reqSamples,
				promtext.Sample{Labels: map[string]string{"app": a, "class": "2xx"}, Value: float64(c.C2xx)},
				promtext.Sample{Labels: map[string]string{"app": a, "class": "3xx"}, Value: float64(c.C3xx)},
				promtext.Sample{Labels: map[string]string{"app": a, "class": "4xx"}, Value: float64(c.C4xx)},
				promtext.Sample{Labels: map[string]string{"app": a, "class": "5xx"}, Value: float64(c.C5xx)},
			)
		}

		// Latency from the last 2000 lines per app; apps without
		// $request_time emit no samples.
		var latencySamples []promtext.Sample
		for _, a := range cfg.Apps {
			file := filepath.Join(cfg.LogDir, a+".access.log")
			raw, _ := nginxlog.TailLines(file, 2000)
			var ms []int64
			for _, line := range raw {
				if v := latency.ExtractRequestTimeMs(line); v >= 0 {
					ms = append(ms, v)
				}
			}
			if len(ms) == 0 {
				continue
			}
			stats := latency.Percentiles(ms, latency.DefaultQuantiles)
			for _, qLabel := range latency.DefaultQuantiles {
				latencySamples = append(latencySamples, promtext.Sample{
					Labels: map[string]string{"app": a, "quantile": qLabel},
					Value:  float64(stats.Pct[qLabel]),
				})
			}
		}

		// Fires per rule across the whole alerts.log.
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
			{Name: "milog_request_latency_ms", Help: "Request-time percentile in milliseconds, per app + quantile.",
				Type: "gauge", Samples: latencySamples},
			{Name: "milog_alerts_fired_total", Help: "Total alerts in alerts.log, per rule + severity.",
				Type: "gauge", Samples: alertSamples},
		}
		_ = promtext.Encode(w, metrics)
	}
}

// logsStreamHandler streams one app's new log lines as SSE `log` events,
// filtered server-side, after replaying recent matches so reconnects keep
// context. A ping every 15s keeps idle proxies from closing it.
//
//	event: log
//	data: {"ts":…,"ip":…,"method":…,"path":…,"status":200,"ua":…,"class":"2xx"}
//
//	app=<name>        required, an nginx source in LOGS
//	limit=<N>         replay depth, default 200, max 500
//	grep=<substring>  case-sensitive substring filter
//	path=<prefix>     path-prefix filter, must start with '/'
//	class=<2xx|3xx|4xx|5xx|any>
//
// Lines go through nginxlog.ParseLine, so fields match /api/logs.json.
func logsStreamHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		app := q.Get("app")
		if app == "" {
			http.Error(w, "app is required", http.StatusBadRequest)
			return
		}
		file, ok := appLogPath(cfg, app)
		if !ok {
			http.Error(w, "unknown app", http.StatusBadRequest)
			return
		}
		if !fileExists(file) {
			http.Error(w, "no such app", http.StatusNotFound)
			return
		}
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

		matches := func(l nginxlog.Line, raw string) bool {
			if grep != "" && !strings.Contains(raw, grep) {
				return false
			}
			if l.Path == "" || l.Status == 0 {
				return false
			}
			if pathPfx != "" && !strings.HasPrefix(l.Path, pathPfx) {
				return false
			}
			if cls != "" && cls != "any" && l.Class != cls {
				return false
			}
			return true
		}

		h := w.Header()
		h.Set("Content-Type", "text/event-stream; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("Connection", "keep-alive")
		h.Set("X-Accel-Buffering", "no")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		emit := func(line nginxlog.Line) bool {
			b, err := json.Marshal(line)
			if err != nil {
				return true
			}
			if _, err := fmt.Fprintf(w, "event: log\ndata: %s\n\n", b); err != nil {
				return false
			}
			flusher.Flush()
			return true
		}

		// Replay: scan limit*3 lines and emit up to limit matches.
		raw, _ := nginxlog.TailLines(file, limit*3)
		var replayed []nginxlog.Line
		for _, rline := range raw {
			l := nginxlog.ParseLine(rline)
			if matches(l, rline) {
				replayed = append(replayed, l)
				if len(replayed) > limit {
					replayed = replayed[1:]
				}
			}
		}
		for _, l := range replayed {
			if !emit(l) {
				return
			}
		}
		// Lets the client tell "replay finished" from a quiet stream.
		if _, err := fmt.Fprintf(w, "event: ready\ndata: {\"replayed\":%d}\n\n", len(replayed)); err != nil {
			return
		}
		flusher.Flush()

		ctx := r.Context()
		tl, err := tail.Open(ctx, file)
		if err != nil {
			log.Printf("milog-web: tail.Open(%s): %v", file, err)
			return
		}

		ping := time.NewTicker(15 * time.Second)
		defer ping.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ping.C:
				if _, err := fmt.Fprintf(w, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			case raw, ok := <-tl.Lines():
				if !ok {
					return
				}
				l := nginxlog.ParseLine(raw)
				if !matches(l, raw) {
					continue
				}
				if !emit(l) {
					return
				}
			}
		}
	}
}

// streamHandler pushes the /api/summary.json snapshot as SSE `summary`
// events every REFRESH seconds, with a `ping` every 15s for idle proxies.
// Each client collects its own snapshot; fine for a handful of viewers.
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

		// ?refresh= lets one client tighten the default cadence.
		cadence := time.Duration(cfg.Refresh) * time.Second
		if v := r.URL.Query().Get("refresh"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 60 {
				cadence = time.Duration(n) * time.Second
			}
		}
		if cadence <= 0 {
			cadence = 3 * time.Second
		}

		// Send one immediately so the client renders on connect.
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

// pushSummary ignores write errors; EventSource reconnects by itself.
func pushSummary(w http.ResponseWriter, flusher http.Flusher, cfg *config.Config) {
	snap := collectSummary(cfg)
	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	// Named event; the body must end with a blank line.
	_, _ = fmt.Fprintf(w, "event: summary\ndata: %s\n\n", b)
	flusher.Flush()
}

// collectSummary is shared by summaryHandler and streamHandler so their
// output can't drift.
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

// logsHandler returns one app's recent lines filtered by grep, path and
// status class:
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

		file, ok := appLogPath(cfg, app)
		if !ok {
			http.Error(w, `{"app":"","lines":[],"error":"unknown app"}`, http.StatusBadRequest)
			return
		}
		if !fileExists(file) {
			http.Error(w, `{"app":"","lines":[],"error":"no such app"}`, http.StatusNotFound)
			return
		}

		// Read tail×3 so the filters can still yield `limit` rows.
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
				// Keep the newest `limit` matches.
				out = out[1:]
			}
		}

		writeJSON(w, struct {
			App   string            `json:"app"`
			Lines []nginxlog.Line   `json:"lines"`
		}{App: app, Lines: out})
	}
}

// logsHistogramHandler returns per-minute request counts for the timeline strip.
func logsHistogramHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		app := q.Get("app")
		minutes, _ := strconv.Atoi(q.Get("minutes"))
		if minutes <= 0 {
			minutes = 60
		}
		file, ok := appLogPath(cfg, app)
		if !ok {
			http.Error(w, `{"app":"","buckets":[]}`, http.StatusBadRequest)
			return
		}
		if !fileExists(file) {
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

// appLogPath returns the access log for app only if app is one of cfg.Apps
// and the resulting path sits directly inside LogDir.
func appLogPath(cfg *config.Config, app string) (string, bool) {
	for _, a := range cfg.Apps {
		if a != app {
			continue
		}
		dir := filepath.Clean(cfg.LogDir)
		file := filepath.Join(dir, a+".access.log")
		if filepath.Dir(file) != dir {
			return "", false
		}
		return file, true
	}
	return "", false
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// rootHandler serves index.html on "/" and 404s anything else.
func rootHandler(staticFS fs.FS) http.HandlerFunc {
	indexHTML, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		// The asset is embedded at build time, so a miss means a broken binary.
		log.Fatalf("milog-web: read index.html from embed: %v", err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(indexHTML)
	}
}

// debugHandler is a plaintext status page for checking the binary
// without the dashboard JS.
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
		sb.WriteString("  /                        dashboard (index.html)\n")
		sb.WriteString("  /static/{app.css,app.js} dashboard assets (embedded)\n")
		sb.WriteString("  /healthz                 public liveness probe\n")
		sb.WriteString("  /api/meta.json           apps + alerts status + uptime\n")
		sb.WriteString("  /api/summary.json        system + nginx counts\n")
		sb.WriteString("  /api/alerts.json         fire history\n")
		sb.WriteString("  /api/logs.json           recent nginx lines (filtered)\n")
		sb.WriteString("  /api/logs/histogram.json per-minute timeline strip\n")
		sb.WriteString("  /api/latency.json        request-time percentiles (requires combined_timed)\n")
		sb.WriteString("  /api/stream              SSE live summary push\n")
		sb.WriteString("  /api/logs/stream         SSE live log tail (per app, with filters)\n")
		sb.WriteString("  /metrics                 Prometheus plaintext 0.0.4\n")
		_, _ = w.Write([]byte(sb.String()))
	}
}

// securityHeaders sets CSP, nosniff, frame denial and no-referrer on every
// response; Cache-Control is set per handler.
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

// writeJSON only logs Encode errors: the status line is already sent.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("milog-web: json encode: %v", err)
	}
}

// Redundant: os is already used by os.Stat above.
var _ = os.Getenv
