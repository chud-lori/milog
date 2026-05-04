// milog-probe — eBPF-backed exec watcher.
//
// Runs as a root systemd sidecar to milog daemon. Loads the
// sched_process_exec tracepoint, runs the rule engine over each event,
// and shells out to `milog _internal_alert` for matching hits — which
// reuses the bash daemon's full alert pipeline (cooldown, silence,
// dedup, routing, hooks). No parallel state in the probe.
//
// Why a separate binary
//   - eBPF needs CAP_BPF + CAP_PERFMON (kernel 5.8+) or CAP_SYS_ADMIN
//     (older kernels). The bash daemon should NOT run as root in v1;
//     splitting the privileged pieces into milog-probe keeps that
//     boundary clean.
//   - The probe can crash, exit, or be temporarily disabled (verifier
//     reject on exotic kernels) without affecting the rest of milog —
//     systemd `Restart=on-failure` papers over transient failures.
//
// Privileges
//   - Requires CAP_BPF + CAP_PERFMON in the systemd unit (preferred)
//     or root via `User=root`. The unit ships in
//     `milog probe install-service` — coming in a follow-up branch
//     once the binary itself is field-tested.
//
// Output / IPC
//   - Default: shell out to `milog _internal_alert <key> <title> <body> <color>`
//     for each rule hit. milog (bash) does the actual delivery.
//   - With --json: print one event per line as JSON to stdout. Useful
//     for `milog-probe --json | jq` debugging on a fresh box.
//   - With --dry-run: process events but don't fire — diagnostic mode
//     to gauge rate / false-positive surface before enabling alerts.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/chud-lori/milog/internal/probe"
)

// buildVersion is link-time stamped via `-ldflags -X main.buildVersion`
// matching the bash MILOG_VERSION embedding. Unstamped → "dev".
var buildVersion = "dev"

func main() {
	var (
		flagJSON    = flag.Bool("json", false, "emit each matched event as JSON to stdout (debug mode)")
		flagDryRun  = flag.Bool("dry-run", false, "match rules but do NOT fire alerts (diagnostic)")
		flagMilog   = flag.String("milog", "milog", "path to milog bash binary (used for shelling out to _internal_alert)")
		flagVersion = flag.Bool("version", false, "print version + exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "milog-probe — eBPF exec watcher\n\n"+
			"Usage:\n"+
			"  milog-probe [flags]\n\n"+
			"Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nNote: requires Linux (kernel 4.18+) and CAP_BPF + CAP_PERFMON or root.\n")
	}
	flag.Parse()

	if *flagVersion {
		fmt.Printf("milog-probe %s (%s/%s)\n", buildVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	// Pre-flight: bail early on non-Linux with a useful message rather
	// than letting probe.Run return ErrUnsupported anonymously deep in
	// the goroutine. Operators running this on macOS for testing get
	// a clear "you need Linux" instead of silent stall.
	if runtime.GOOS != "linux" {
		log.Fatalf("milog-probe needs Linux for eBPF; running on %s", runtime.GOOS)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	events := make(chan probe.Event, 256)
	errCh := make(chan error, 1)

	go func() {
		errCh <- probe.Run(ctx, events)
	}()

	log.Printf("milog-probe %s — watching exec() events (json=%v dry-run=%v)",
		buildVersion, *flagJSON, *flagDryRun)

	for {
		select {
		case <-ctx.Done():
			// Drain the run goroutine so we surface its error if it
			// stopped on something other than ctx cancellation.
			if err := <-errCh; err != nil {
				log.Printf("probe: %v", err)
				os.Exit(1)
			}
			return
		case err := <-errCh:
			if err != nil {
				log.Fatalf("probe: %v", err)
			}
			return
		case ev := <-events:
			handleEvent(ev, *flagJSON, *flagDryRun, *flagMilog)
		}
	}
}

// handleEvent runs the rule engine over one Event and dispatches the
// configured side effect (json, dry-run, or shell-out to milog).
func handleEvent(ev probe.Event, asJSON, dryRun bool, milogBin string) {
	hits := probe.Match(ev)
	if asJSON {
		// Even when no rule matched, emit the event so debugging
		// "why didn't it fire?" is straightforward.
		emitJSON(ev, hits)
		return
	}
	if len(hits) == 0 {
		return
	}
	for _, h := range hits {
		if dryRun {
			log.Printf("DRY: %s :: %s", h.RuleKey, h.Title)
			continue
		}
		fireAlert(h, milogBin)
	}
}

func emitJSON(ev probe.Event, hits []probe.Hit) {
	type wire struct {
		Event probe.Event `json:"event"`
		Hits  []probe.Hit `json:"hits"`
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(wire{Event: ev, Hits: hits})
}

// fireAlert shells out to `milog _internal_alert <key> <title> <body> <color>`.
// Color = 15158332 (Discord red) — same value the audit modules pass.
// We don't wait for delivery to complete; alert_fire backgrounds the
// webhook calls anyway, and a slow milog process shouldn't block the
// next event in the ring.
func fireAlert(h probe.Hit, milogBin string) {
	const color = "15158332"
	cmd := exec.Command(milogBin, "_internal_alert", h.RuleKey, h.Title, h.Body, color)
	// Inherit env so MILOG_CONFIG / DISCORD_WEBHOOK / etc. propagate
	// to the bash daemon's resolution path.
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		log.Printf("milog-probe: failed to invoke %s: %v", milogBin, err)
		return
	}
	// Reap async — don't wait for the bash process to finish, but
	// release its zombie when it does. exec.Cmd.Wait only works
	// once; calling in a goroutine is the standard pattern.
	go func() { _ = cmd.Wait() }()
}
