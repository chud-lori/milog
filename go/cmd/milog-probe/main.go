// milog-probe is the root-run eBPF sidecar for milog. It runs the rule
// engine over exec, connect, file, ptrace, kmod, retransmit, syscall-rate
// and bpf-load events and sends each hit through `milog _internal_alert`,
// so cooldown, silence, dedup, routing and hooks all apply. It is a
// separate binary so the bash daemon never needs root.
//
//	--json     print every event with its hits instead of alerting
//	--dry-run  log hits without alerting
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
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	"github.com/chud-lori/milog/internal/probe"
)

// buildVersion is set at link time with -ldflags -X.
var buildVersion = "dev"

// alertCred is the identity `milog _internal_alert` runs as; nil keeps the probe's own.
var alertCred *syscall.Credential

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

	// Fail clearly on non-Linux instead of stalling inside probe.Run.
	if runtime.GOOS != "linux" {
		log.Fatalf("milog-probe needs Linux for eBPF; running on %s", runtime.GOOS)
	}

	if name := os.Getenv("MILOG_PROBE_ALERT_USER"); name != "" {
		cred, err := lookupCredential(name)
		if err != nil {
			log.Fatalf("milog-probe: MILOG_PROBE_ALERT_USER=%s: %v", name, err)
		}
		if int(cred.Uid) != os.Getuid() {
			alertCred = cred
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// One goroutine and BPF collection per probe, so a verifier reject
	// only loses that probe; exit non-zero once all of them have died.
	events := make(chan probe.Event, 256)
	netEvents := make(chan probe.NetEvent, 256)
	fileEvents := make(chan probe.FileEvent, 256)
	ptraceEvents := make(chan probe.PtraceEvent, 64)
	kmodEvents := make(chan probe.KmodEvent, 16)
	retransEvents := make(chan probe.RetransEvent, 64)
	rateEvents := make(chan probe.RateAnomalyEvent, 256)
	bpfLoadEvents := make(chan probe.BpfLoadEvent, 16)
	execErrCh := make(chan error, 1)
	netErrCh := make(chan error, 1)
	fileErrCh := make(chan error, 1)
	ptraceErrCh := make(chan error, 1)
	kmodErrCh := make(chan error, 1)
	retransErrCh := make(chan error, 1)
	rateErrCh := make(chan error, 1)
	bpfLoadErrCh := make(chan error, 1)

	go func() { execErrCh <- probe.Run(ctx, events) }()
	go func() { netErrCh <- probe.RunNet(ctx, netEvents) }()
	go func() { fileErrCh <- probe.RunFile(ctx, fileEvents) }()
	go func() { ptraceErrCh <- probe.RunPtrace(ctx, ptraceEvents) }()
	go func() { kmodErrCh <- probe.RunKmod(ctx, kmodEvents) }()
	go func() { retransErrCh <- probe.RunRetrans(ctx, retransEvents) }()
	go func() { rateErrCh <- probe.RunSyscallRate(ctx, rateEvents) }()
	go func() { bpfLoadErrCh <- probe.RunBpfLoad(ctx, bpfLoadEvents) }()

	log.Printf("milog-probe %s — watching exec + tcp connect + file open + ptrace + kmod load + tcp retransmit + syscall rate + bpf prog-load (json=%v dry-run=%v)",
		buildVersion, *flagJSON, *flagDryRun)

	allDead := func() bool {
		return execErrCh == nil && netErrCh == nil && fileErrCh == nil &&
			ptraceErrCh == nil && kmodErrCh == nil && retransErrCh == nil &&
			rateErrCh == nil && bpfLoadErrCh == nil
	}

	for {
		select {
		case <-ctx.Done():
			drainErrors(execErrCh, netErrCh, fileErrCh, ptraceErrCh, kmodErrCh, retransErrCh, rateErrCh, bpfLoadErrCh)
			return
		case err := <-execErrCh:
			if err != nil {
				log.Printf("probe (exec): %v — exec coverage degraded", err)
			}
			execErrCh = nil
			if allDead() {
				os.Exit(1)
			}
		case err := <-netErrCh:
			if err != nil {
				log.Printf("probe (net): %v — outbound-connect coverage degraded", err)
			}
			netErrCh = nil
			if allDead() {
				os.Exit(1)
			}
		case err := <-fileErrCh:
			if err != nil {
				log.Printf("probe (file): %v — sensitive-file coverage degraded", err)
			}
			fileErrCh = nil
			if allDead() {
				os.Exit(1)
			}
		case err := <-ptraceErrCh:
			if err != nil {
				log.Printf("probe (ptrace): %v — process-injection coverage degraded", err)
			}
			ptraceErrCh = nil
			if allDead() {
				os.Exit(1)
			}
		case err := <-kmodErrCh:
			if err != nil {
				log.Printf("probe (kmod): %v — kernel-module-load coverage degraded", err)
			}
			kmodErrCh = nil
			if allDead() {
				os.Exit(1)
			}
		case err := <-retransErrCh:
			if err != nil {
				log.Printf("probe (retrans): %v — tcp-retransmit coverage degraded", err)
			}
			retransErrCh = nil
			if allDead() {
				os.Exit(1)
			}
		case err := <-rateErrCh:
			if err != nil {
				log.Printf("probe (syscall-rate): %v — syscall-rate-anomaly coverage degraded", err)
			}
			rateErrCh = nil
			if allDead() {
				os.Exit(1)
			}
		case err := <-bpfLoadErrCh:
			if err != nil {
				log.Printf("probe (bpf-load): %v — bpf-program-load coverage degraded", err)
			}
			bpfLoadErrCh = nil
			if allDead() {
				os.Exit(1)
			}
		case ev := <-events:
			handleEvent(ev, *flagJSON, *flagDryRun, *flagMilog)
		case nev := <-netEvents:
			handleNetEvent(nev, *flagJSON, *flagDryRun, *flagMilog)
		case fev := <-fileEvents:
			handleFileEvent(fev, *flagJSON, *flagDryRun, *flagMilog)
		case pev := <-ptraceEvents:
			handlePtraceEvent(pev, *flagJSON, *flagDryRun, *flagMilog)
		case kev := <-kmodEvents:
			handleKmodEvent(kev, *flagJSON, *flagDryRun, *flagMilog)
		case rev := <-retransEvents:
			handleRetransEvent(rev, *flagJSON, *flagDryRun, *flagMilog)
		case aev := <-rateEvents:
			handleRateAnomalyEvent(aev, *flagJSON, *flagDryRun, *flagMilog)
		case bev := <-bpfLoadEvents:
			handleBpfLoadEvent(bev, *flagJSON, *flagDryRun, *flagMilog)
		}
	}
}

// drainErrors logs any errors still pending after shutdown.
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

// handleEvent runs the exec rules and prints, logs or fires each hit.
func handleEvent(ev probe.Event, asJSON, dryRun bool, milogBin string) {
	hits := probe.Match(ev)
	if asJSON {
		// Print events without hits too, to debug "why didn't it fire?".
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

// handleNetEvent is handleEvent for connect events.
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

// handleFileEvent is handleEvent for file opens.
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

// handlePtraceEvent is handleEvent for ptrace attaches.
func handlePtraceEvent(ev probe.PtraceEvent, asJSON, dryRun bool, milogBin string) {
	hits := probe.MatchPtrace(ev)
	if asJSON {
		emitPtraceJSON(ev, hits)
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

// handleKmodEvent is handleEvent for module loads.
func handleKmodEvent(ev probe.KmodEvent, asJSON, dryRun bool, milogBin string) {
	hits := probe.MatchKmod(ev)
	if asJSON {
		emitKmodJSON(ev, hits)
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

// handleRetransEvent is handleEvent for retransmit samples.
func handleRetransEvent(ev probe.RetransEvent, asJSON, dryRun bool, milogBin string) {
	hits := probe.MatchRetrans(ev)
	if asJSON {
		emitRetransJSON(ev, hits)
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

// handleRateAnomalyEvent is handleEvent for syscall-rate samples.
func handleRateAnomalyEvent(ev probe.RateAnomalyEvent, asJSON, dryRun bool, milogBin string) {
	hits := probe.MatchRateAnomaly(ev)
	if asJSON {
		emitRateJSON(ev, hits)
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

// handleBpfLoadEvent is handleEvent for BPF program loads.
func handleBpfLoadEvent(ev probe.BpfLoadEvent, asJSON, dryRun bool, milogBin string) {
	hits := probe.MatchBpfLoad(ev)
	if asJSON {
		emitBpfLoadJSON(ev, hits)
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

func emitPtraceJSON(ev probe.PtraceEvent, hits []probe.Hit) {
	type wire struct {
		PtraceEvent probe.PtraceEvent `json:"ptrace_event"`
		Hits        []probe.Hit       `json:"hits"`
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(wire{PtraceEvent: ev, Hits: hits})
}

func emitKmodJSON(ev probe.KmodEvent, hits []probe.Hit) {
	type wire struct {
		KmodEvent probe.KmodEvent `json:"kmod_event"`
		Hits      []probe.Hit     `json:"hits"`
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(wire{KmodEvent: ev, Hits: hits})
}

func emitRetransJSON(ev probe.RetransEvent, hits []probe.Hit) {
	type wire struct {
		RetransEvent probe.RetransEvent `json:"retrans_event"`
		Hits         []probe.Hit        `json:"hits"`
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(wire{RetransEvent: ev, Hits: hits})
}

func emitRateJSON(ev probe.RateAnomalyEvent, hits []probe.Hit) {
	type wire struct {
		RateEvent probe.RateAnomalyEvent `json:"rate_anomaly_event"`
		Hits      []probe.Hit            `json:"hits"`
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(wire{RateEvent: ev, Hits: hits})
}

func emitBpfLoadJSON(ev probe.BpfLoadEvent, hits []probe.Hit) {
	type wire struct {
		BpfLoadEvent probe.BpfLoadEvent `json:"bpf_load_event"`
		Hits         []probe.Hit        `json:"hits"`
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(wire{BpfLoadEvent: ev, Hits: hits})
}

// fireAlert runs `milog _internal_alert` with Discord red and doesn't wait,
// so a slow milog can't stall the event loop.
func fireAlert(h probe.Hit, milogBin string) {
	const color = "15158332"
	cmd := exec.Command(milogBin, "_internal_alert", h.RuleKey, h.Title, h.Body, color)
	// Pass the env through so MILOG_CONFIG reaches milog.
	cmd.Env = os.Environ()
	if alertCred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: alertCred}
	}
	if err := cmd.Start(); err != nil {
		log.Printf("milog-probe: failed to invoke %s: %v", milogBin, err)
		return
	}
	// Reap in the background so the child doesn't linger as a zombie.
	go func() { _ = cmd.Wait() }()
}

// lookupCredential sets supplementary groups too, else the child keeps root's.
func lookupCredential(name string) (*syscall.Credential, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	groups := make([]uint32, 0, len(ids))
	for _, id := range ids {
		g, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return nil, err
		}
		groups = append(groups, uint32(g))
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}, nil
}
