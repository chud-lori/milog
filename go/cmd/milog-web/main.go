// milog-web — optional Go implementation of `milog web`.
//
// Phase 5 foundation: scaffolding only. This binary currently serves a
// /healthz probe and a placeholder root. The bash socat-based handler in
// src/modes/web.sh remains the default — this is present so future Phase 5
// chunks (SSE summary, SSE log tail, HDR histograms, Prometheus /metrics)
// can build on top of a proper HTTP server without re-paying the
// scaffolding cost.
//
// Intentionally scoped to the Go standard library — no third-party deps —
// to keep the binary buildable from any Go 1.22+ toolchain with no module
// dance. HDR histogram + YAML config etc. introduce their deps when the
// feature that needs them lands.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chud-lori/milog/internal/config"
)

// buildVersion is overridden at link time: `go build -ldflags "-X main.buildVersion=abc1234"`.
// Default `unknown` when built without -ldflags, matching the bash
// MILOG_VERSION=unknown fallback convention.
var buildVersion = "unknown"

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("milog-web: config: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/", root(cfg))

	addr := net.JoinHostPort(cfg.Bind, cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM — current-day use of `milog web`
	// is Ctrl+C'd by users often; future systemd unit will stop(SIGTERM).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("milog-web v=%s listening on http://%s", buildVersion, addr)
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

// healthz is the liveness probe. Always 200 OK + "ok\n" — used by systemd
// unit WatchdogSec= and future k8s probes. Deliberately does no work so a
// wedged request-handler path can't starve it.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintln(w, "ok")
}

// root is the placeholder index. Until the SSE dashboard lands in a
// subsequent Phase 5 chunk, it just prints a note + directs the user back
// to the bash socat handler for the real UI.
func root(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		var sb strings.Builder
		sb.WriteString("milog-web (Go foundation)\n")
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "version:  %s\n", buildVersion)
		fmt.Fprintf(&sb, "bind:     %s:%s\n", cfg.Bind, cfg.Port)
		fmt.Fprintf(&sb, "log_dir:  %s\n", cfg.LogDir)
		sb.WriteString("\n")
		sb.WriteString("Scaffolding only. The interactive dashboard still runs via\n")
		sb.WriteString("the bash socat handler (`milog web` without --use-go). The SSE\n")
		sb.WriteString("implementation lands in subsequent Phase 5 chunks.\n")
		sb.WriteString("\n")
		sb.WriteString("Try:  curl http://" + net.JoinHostPort(cfg.Bind, cfg.Port) + "/healthz\n")
		_, _ = w.Write([]byte(sb.String()))
	}
}

// Compile-time assurance that `os` is still linked — removed if the init
// block below goes away, but kept as a cheap guard while the binary is
// stub-ish.
var _ = os.Getenv
