// Package probe — eBPF-backed exec watcher and rule engine.
//
// rules.go holds the rule-matching logic, deliberately OS-independent
// so it can be unit-tested on any platform. The actual BPF loading +
// ringbuf consumption lives in exec_linux.go (and a stub exec_other.go
// for non-Linux builds).
//
// Rule firing is fingerprint-based: the userspace consumer feeds an
// `Event` to `Match`, gets back a slice of `Hit` (rule key + body
// detail) per matching rule, and shells those out to milog's existing
// alert path. Cooldown / silence / dedup all apply via the rule key —
// no parallel state in the probe.
package probe

import (
	"strings"
)

// Event is the userspace mirror of the BPF-side `struct exec_event`,
// enriched with parent-process info that's cheaper to look up in /proc
// than to follow CO-RE chain reads from the BPF program itself.
//
// Field-order with the C struct does NOT have to match — Go only sees
// this Go-side type. The wire format for events from BPF is laid out
// in exec_linux.go.
type Event struct {
	PID        uint32
	PPID       uint32 // looked up via /proc/<pid>/status
	UID        uint32
	Comm       string // child process name (16-byte kernel comm)
	ParentComm string // /proc/<ppid>/comm
	Filename   string // exe path captured at tracepoint
}

// Hit represents one rule firing for one event. RuleKey is the
// `process:<rule>:<detail>` string passed to milog's alert path —
// cooldown groups by this exact string.
type Hit struct {
	RuleKey string
	Title   string
	Body    string
}

// webWorkerComms — process names that almost never legitimately spawn
// an interactive shell. nginx workers sometimes spawn `sh` for cgi-bin
// or temp file rotation, but on most production setups any shell
// descendant of a web worker is a strong RCE indicator. Operators
// running cgi-bin can silence the rule with `milog silence
// process:shell_from_web_worker:* 1h` while they triage.
var webWorkerComms = map[string]struct{}{
	"nginx":       {},
	"php-fpm":     {},
	"php-fpm7.4":  {},
	"php-fpm8.0":  {},
	"php-fpm8.1":  {},
	"php-fpm8.2":  {},
	"php-fpm8.3":  {},
	"apache2":     {},
	"httpd":       {},
	"caddy":       {},
	"haproxy":     {},
	"unicorn":     {},
	"uwsgi":       {},
}

// shellComms — process names treated as "interactive shell". A
// hardcoded list rather than checking `/etc/shells` because attackers
// rename their shell, and we want to alert on the *original* name as
// captured by the kernel comm field (which is the actual exec name,
// not what the process later calls itself).
var shellComms = map[string]struct{}{
	"sh":   {},
	"bash": {},
	"dash": {},
	"zsh":  {},
	"ksh":  {},
	"ash":  {},
	"tcsh": {},
}

// Trusted shell-launching parents whose children we DON'T flag — these
// are normal tools that legitimately exec shells. Interactive admin
// sessions, build tools, package managers etc.
var shellParentAllowlist = map[string]struct{}{
	"sshd":           {},
	"login":          {},
	"sudo":           {},
	"su":             {},
	"systemd":        {},
	"systemd-logind": {},
	"cron":           {},
	"crond":          {},
	"agetty":         {},
	"getty":          {},
	"tmux":           {},
	"screen":         {},
	"make":           {},
	"npm":            {},
	"yarn":           {},
	"pnpm":           {},
}

// tmpExecPrefixes — directories where attacker-dropped binaries
// typically land. /home/<user>/tmp etc. is NOT here because legitimate
// build tools (cargo, go) do drop binaries under user temp paths.
var tmpExecPrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
}

// Match runs every rule against the event and returns the hits.
// Empty slice when nothing matched — caller checks len, fires nothing
// when zero.
func Match(e Event) []Hit {
	var hits []Hit

	if h, ok := matchShellFromWebWorker(e); ok {
		hits = append(hits, h)
	}
	if h, ok := matchExecFromTmp(e); ok {
		hits = append(hits, h)
	}
	if h, ok := matchSuidEscalation(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// matchShellFromWebWorker fires when an HTTP server process (nginx,
// php-fpm, apache, etc.) spawns an interactive shell. Classic RCE tell:
// PHP eval()/system()/passthru() of attacker input dropping into /bin/sh.
//
// The allowlist on shellParentAllowlist lets sshd/sudo/cron-style
// flows through — those are normal admin sessions, not RCE.
func matchShellFromWebWorker(e Event) (Hit, bool) {
	if _, isShell := shellComms[e.Comm]; !isShell {
		return Hit{}, false
	}
	if _, isWebParent := webWorkerComms[e.ParentComm]; !isWebParent {
		return Hit{}, false
	}
	// Per-(parent, child) rule key so both nginx→bash and php-fpm→sh
	// are tracked independently. Cooldown groups by the full key, so
	// the same flow re-firing within ALERT_COOLDOWN is silenced.
	return Hit{
		RuleKey: "process:shell_from_web_worker:" + e.ParentComm + ":" + e.Comm,
		Title:   "Shell from web worker: " + e.ParentComm + " → " + e.Comm,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " exe=" + e.Filename + "```",
	}, true
}

// matchExecFromTmp fires when a binary executes from /tmp, /var/tmp,
// or /dev/shm. Attacker payload drop sites — almost no legitimate
// software lives there.
//
// The rule key embeds the comm so a single misbehaving program
// re-execing itself doesn't cooldown-mask other tmp-drops in the same
// window.
func matchExecFromTmp(e Event) (Hit, bool) {
	for _, prefix := range tmpExecPrefixes {
		if strings.HasPrefix(e.Filename, prefix) {
			return Hit{
				RuleKey: "process:exec_from_tmp:" + e.Comm,
				Title:   "Exec from tmp: " + e.Filename,
				Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
					" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
					" parent=" + e.ParentComm + " exe=" + e.Filename + "```",
			}, true
		}
	}
	return Hit{}, false
}

// matchSuidEscalation fires when a setuid binary executes AND the
// effective UID at exec time differs from the parent's expected UID.
// Without BPF-side capture of pre/post UID we approximate: alert when
// uid==0 and the exec is from a non-root parent comm — the strongest
// signal that doesn't require root-privilege task_struct CO-RE chains.
//
// In practice: a non-root web worker (e.g. php-fpm running as
// www-data) is the parent, but the child exec lands at uid=0. That's
// suid escalation in flight.
func matchSuidEscalation(e Event) (Hit, bool) {
	if e.UID != 0 {
		return Hit{}, false
	}
	// Limit false-positive surface: only flag when the parent is a web
	// worker. Normal sudo/login flows already have allowlisted parents
	// elsewhere; widening this rule beyond webserver-descendant exec
	// would page on every cron job.
	if _, isWeb := webWorkerComms[e.ParentComm]; !isWeb {
		return Hit{}, false
	}
	return Hit{
		RuleKey: "process:suid_escalation:" + e.ParentComm + ":" + e.Comm,
		Title:   "SUID escalation: " + e.ParentComm + " → uid=0 " + e.Comm,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " exe=" + e.Filename + "```",
	}, true
}

// uitoa is a tiny stdlib-free uint→ascii helper. Kept inline so the
// probe binary doesn't pull strconv just for body formatting on the
// hot path. PID/UID values are always small (<10 digits).
func uitoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
