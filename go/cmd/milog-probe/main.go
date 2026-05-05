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

	// Three independent event streams: exec (sched_process_exec),
	// tcp connect (sock:inet_sock_set_state), and file open
	// (syscalls:sys_enter_openat). Each runs in its own goroutine
	// with its own BPF collection so a verifier reject on one doesn't
	// take down the other two — the operator still gets the remaining
	// probes' coverage with a logged warning for the failed one. Only
	// when all three die do we exit non-zero so systemd restarts us.
	events := make(chan probe.Event, 256)
	netEvents := make(chan probe.NetEvent, 256)
	fileEvents := make(chan probe.FileEvent, 256)
	execErrCh := make(chan error, 1)
	netErrCh := make(chan error, 1)
	fileErrCh := make(chan error, 1)

	go func() { execErrCh <- probe.Run(ctx, events) }()
	go func() { netErrCh <- probe.RunNet(ctx, netEvents) }()
	go func() { fileErrCh <- probe.RunFile(ctx, fileEvents) }()

	log.Printf("milog-probe %s — watching exec + tcp connect + file open (json=%v dry-run=%v)",
		buildVersion, *flagJSON, *flagDryRun)

	for {
		select {
		case <-ctx.Done():
			drainErrors(execErrCh, netErrCh, fileErrCh)
			return
		case err := <-execErrCh:
			// One probe died but the others might still be alive. Log,
			// keep running. Only when ALL three die do we exit non-zero.
			if err != nil {
				log.Printf("probe (exec): %v — exec coverage degraded", err)
			}
			execErrCh = nil
			if netErrCh == nil && fileErrCh == nil {
				os.Exit(1)
			}
		case err := <-netErrCh:
			if err != nil {
				log.Printf("probe (net): %v — outbound-connect coverage degraded", err)
			}
			netErrCh = nil
			if execErrCh == nil && fileErrCh == nil {
				os.Exit(1)
			}
		case err := <-fileErrCh:
			if err != nil {
				log.Printf("probe (file): %v — sensitive-file coverage degraded", err)
			}
			fileErrCh = nil
			if execErrCh == nil && netErrCh == nil {
				os.Exit(1)
			}
		case ev := <-events:
			handleEvent(ev, *flagJSON, *flagDryRun, *flagMilog)
		case nev := <-netEvents:
			handleNetEvent(nev, *flagJSON, *flagDryRun, *flagMilog)
		case fev := <-fileEvents:
			handleFileEvent(fev, *flagJSON, *flagDryRun, *flagMilog)
		}
	}
}

// drainErrors picks up any pending non-nil errors from each probe
// after ctx cancellation. Logs anything that wasn't `nil` — useful
// signal in the journal when a clean shutdown still had a failing
// load on one side. Variadic so adding a fourth probe later doesn't
// touch this signature.
func drainErrors(chs ...chan error) {
	for _, ch := range chs {
		if ch == nil {
			continue
		}
		select {
		case err := <-ch:
			if err != nil {
				log.Printf("probe: %v", err)
			}
		default:
		}
	}
}

// handleEvent runs the rule engine over one exec Event and dispatches
// the configured side effect (json, dry-run, or shell-out to milog).
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

// handleNetEvent runs the network rule engine over one NetEvent —
// same dispatch shape as handleEvent. Kept separate so future net
// rules can grow independently.
func handleNetEvent(ev probe.NetEvent, asJSON, dryRun bool, milogBin string) {
	hits := probe.MatchNet(ev)
	if asJSON {
		emitNetJSON(ev, hits)
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

// handleFileEvent runs the file-audit rule engine over one FileEvent.
// Same dispatch shape as the other handle* helpers — separated so the
// emitFileJSON wire shape can carry the openat flags field that the
// other event types don't have.
func handleFileEvent(ev probe.FileEvent, asJSON, dryRun bool, milogBin string) {
	hits := probe.MatchFile(ev)
	if asJSON {
		emitFileJSON(ev, hits)
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

func emitNetJSON(ev probe.NetEvent, hits []probe.Hit) {
	type wire struct {
		NetEvent probe.NetEvent `json:"net_event"`
		Hits     []probe.Hit    `json:"hits"`
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(wire{NetEvent: ev, Hits: hits})
}

func emitFileJSON(ev probe.FileEvent, hits []probe.Hit) {
	type wire struct {
		FileEvent probe.FileEvent `json:"file_event"`
		Hits      []probe.Hit     `json:"hits"`
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(wire{FileEvent: ev, Hits: hits})
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
