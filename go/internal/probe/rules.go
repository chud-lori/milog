// Package probe — eBPF-backed exec watcher and rule engine.
//
// rules.go holds the rule-matching logic, deliberately OS-independent
// so it can be unit-tested on any platform. The actual BPF loading +
// ringbuf consumption lives in exec_linux.go / tcp_linux.go /
// file_linux.go / ptrace_linux.go / kmod_linux.go (and a stub
// exec_other.go for non-Linux builds).
//
// Rule firing is fingerprint-based: the userspace consumer feeds an
// `Event` / `NetEvent` / `FileEvent` / `PtraceEvent` / `KmodEvent` to
// `Match` / `MatchNet` / `MatchFile` / `MatchPtrace` / `MatchKmod`,
// gets back a slice of `Hit` (rule key + body detail) per matching
// rule, and shells those out to milog's existing alert path. Cooldown
// / silence / dedup all apply via the rule key — no parallel state in
// the probe.
package probe

import (
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
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

// =============================================================================
// Network probe — outbound TCP connect monitoring.
// =============================================================================

// NetEvent is the userspace mirror of `struct tcp_event` from
// tcp.bpf.c. Fired once per outbound TCP connect attempt
// (TCP_CLOSE → TCP_SYN_SENT transition). DAddr is the destination
// formatted as a string ("1.2.3.4" for v4, RFC 5952 for v6) so the
// rule engine doesn't need to handle byte-array/IP conversion in two
// places.
type NetEvent struct {
	PID        uint32
	PPID       uint32 // looked up via /proc/<pid>/status
	UID        uint32
	Comm       string
	ParentComm string
	DAddr      string // destination IP, already stringified
	DPort      uint16
	IsIPv6     bool
}

// MatchNet runs every network rule against the event and returns hits.
// Mirrors Match() for exec events. Currently one rule
// (`net:unexpected_outbound`); space for `net:retrans_spike` once the
// retransmit probe lands.
func MatchNet(e NetEvent) []Hit {
	var hits []Hit
	if h, ok := matchUnexpectedOutbound(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// matchUnexpectedOutbound fires when a process initiates a TCP connect
// to a destination not on the operator-configured allowlist. Defaults
// cover loopback + DNS + NTP + RFC1918/ULA private ranges so a
// freshly-installed milog probe doesn't immediately page on every
// internal hop. Operators tighten the allowlist via
// MILOG_PROBE_NET_ALLOWLIST or by silencing the rule key per-flow.
//
// The rule key embeds the comm so a single misbehaving process
// connecting to many destinations shows up as one cooldown group, not
// fifty. If you need per-destination granularity, swap the key suffix
// to `:<comm>:<daddr>:<dport>` — but expect cooldown noise on long
// connection bursts.
func matchUnexpectedOutbound(e NetEvent) (Hit, bool) {
	allow := loadNetAllowlist()
	if allow.permits(e.DAddr, e.DPort) {
		return Hit{}, false
	}
	dest := e.DAddr + ":" + uitoa(uint32(e.DPort))
	return Hit{
		RuleKey: "net:unexpected_outbound:" + e.Comm,
		Title:   "Unexpected outbound: " + e.Comm + " → " + dest,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " dst=" + dest + "```",
	}, true
}

// netAllowlist holds the parsed allowlist as IP networks + bare ports.
// Each connect event is checked against three buckets:
//
//   1. Wildcard ports — entries like `:53`, match any IP at that port.
//   2. Networks       — entries like `10.0.0.0/8`, match any port in that net.
//   3. Network+port   — entries like `10.0.0.0/8:443`, match both.
//
// Buckets are computed once via loadNetAllowlist(); subsequent events
// reuse the cached value.
type netAllowlist struct {
	wildcardPorts map[uint16]struct{}
	nets          []*net.IPNet
	netPorts      []netPortEntry
}

type netPortEntry struct {
	cidr *net.IPNet
	port uint16
}

func (a *netAllowlist) permits(addr string, port uint16) bool {
	if _, ok := a.wildcardPorts[port]; ok {
		return true
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		// Bad address from the BPF side — better to alert than to
		// silently allow. Return false so the rule fires.
		return false
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, np := range a.netPorts {
		if np.port == port && np.cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// defaultNetAllowlist is the baseline shipped with milog-probe. Picks
// the conservative set: loopback (always benign), DNS / NTP (every
// machine does these), and RFC1918 / ULA / link-local (typical
// private-network infra). Operators on a tightly-firewalled host can
// override via MILOG_PROBE_NET_ALLOWLIST to drop the private-net
// entries and force every outbound to be explicit.
const defaultNetAllowlist = "127.0.0.0/8,::1/128," +
	":53,:123," +
	"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16," +
	"169.254.0.0/16," +
	"fc00::/7,fe80::/10"

// allowlistCache holds the parsed allowlist so MatchNet doesn't re-parse
// on every event. Single-shot init via the `cached` flag — if the env
// changes mid-run the operator restarts milog-probe to pick it up.
//
// Not a sync.Once because tests need to clear the cache between cases.
// resetNetAllowlistCache is a test-only escape hatch declared in
// rules_test.go.
var (
	cachedAllowlist netAllowlist
	allowlistReady  bool
)

func loadNetAllowlist() *netAllowlist {
	if allowlistReady {
		return &cachedAllowlist
	}
	src := os.Getenv("MILOG_PROBE_NET_ALLOWLIST")
	if src == "" {
		src = defaultNetAllowlist
	}
	cachedAllowlist = parseNetAllowlist(src)
	allowlistReady = true
	return &cachedAllowlist
}

// parseNetAllowlist accepts a comma-separated list. Each entry is one
// of three shapes:
//
//	":<port>"                    — bare port, any IP
//	"<cidr>"                     — network, any port
//	"<cidr>:<port>"              — both
//
// Bare IPs (no /mask) are normalised to /32 (v4) or /128 (v6).
// Malformed entries are skipped silently — the only effect of a typo
// is that the entry doesn't allowlist anything, which fails safe (the
// alert fires).
func parseNetAllowlist(src string) netAllowlist {
	out := netAllowlist{wildcardPorts: map[uint16]struct{}{}}
	for _, raw := range strings.Split(src, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		// Bare port: ":53" or ":123". Guard against IPv6 literals
		// like "::1/128" — those also start with ":" but the second
		// colon means "address", not "port". Distinguish by the
		// double-colon shape, not by attempting ParseUint (a parse
		// failure would silently drop the entry, which the v0.1 of
		// this code did and caused the IPv6 loopback default to never
		// take effect).
		if strings.HasPrefix(entry, ":") && !strings.HasPrefix(entry, "::") {
			if p, err := strconv.ParseUint(entry[1:], 10, 16); err == nil {
				out.wildcardPorts[uint16(p)] = struct{}{}
			}
			continue
		}
		// CIDR + optional :port. Tricky bit: ParseCIDR doesn't accept
		// trailing :port, and IPv6 literals already contain colons —
		// disambiguate by splitting on the LAST colon only when what
		// follows looks like a port number (and there's a `/` somewhere
		// before it, signalling we're past the v6 body).
		cidr, port, hasPort := splitCIDRPort(entry)
		ipnet, err := parseCIDROrIP(cidr)
		if err != nil {
			continue
		}
		if hasPort {
			out.netPorts = append(out.netPorts, netPortEntry{cidr: ipnet, port: port})
		} else {
			out.nets = append(out.nets, ipnet)
		}
	}
	return out
}

// splitCIDRPort separates an entry like "10.0.0.0/8:443" into
// "10.0.0.0/8" + 443. For pure-IPv6 CIDRs ("fc00::/7") with no port,
// returns the input unchanged with hasPort=false. For an IPv6 entry
// WITH a port we require the bracket form ("[fc00::/7]:443") to
// disambiguate from the v6 colons themselves; that's standard URL
// notation and matches what `net.JoinHostPort` produces.
func splitCIDRPort(entry string) (cidr string, port uint16, hasPort bool) {
	// Bracketed v6: "[<cidr>]:<port>"
	if strings.HasPrefix(entry, "[") {
		end := strings.Index(entry, "]")
		if end < 0 || end+1 >= len(entry) || entry[end+1] != ':' {
			return entry, 0, false
		}
		body := entry[1:end]
		p, err := strconv.ParseUint(entry[end+2:], 10, 16)
		if err != nil {
			return entry, 0, false
		}
		return body, uint16(p), true
	}
	// IPv4-style "<cidr>:<port>". A v6 literal without brackets has
	// multiple colons; we explicitly only treat the LAST colon as a
	// port separator if the part after parses as a uint16 AND the
	// part before contains a slash (i.e. it's a CIDR).
	last := strings.LastIndex(entry, ":")
	if last < 0 {
		return entry, 0, false
	}
	candidate := entry[last+1:]
	p, err := strconv.ParseUint(candidate, 10, 16)
	if err != nil {
		return entry, 0, false
	}
	body := entry[:last]
	// IPv6 cidr without brackets ("fc00::/7"): body would have multiple
	// colons. Don't treat as port-suffixed.
	if strings.Count(body, ":") > 0 && !strings.Contains(body, "/") {
		return entry, 0, false
	}
	return body, uint16(p), true
}

// parseCIDROrIP wraps net.ParseCIDR so a bare "1.2.3.4" or "fe80::1"
// works as if `/32` or `/128` was specified. Saves operators having
// to remember the mask suffix for single-host allowlist entries.
func parseCIDROrIP(s string) (*net.IPNet, error) {
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		return n, err
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, &net.ParseError{Type: "IP address", Text: s}
	}
	if ip.To4() != nil {
		return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// =============================================================================
// File-audit probe — sensitive-path open monitoring.
// =============================================================================

// FileEvent is the userspace mirror of `struct file_event` from
// file.bpf.c. Fired once per openat(2) on a file under one of the
// BPF-side prefixes (`/etc/`, `/root`, `/home`, `/var/`); precise
// per-path matching against the configurable sensitive list happens
// here so operators can tune without re-compiling BPF.
type FileEvent struct {
	PID        uint32
	PPID       uint32 // looked up via /proc/<pid>/status
	UID        uint32
	Flags      uint32 // openat(2) flags — O_RDONLY, O_WRONLY, O_RDWR plus O_CREAT etc.
	Comm       string
	ParentComm string
	Filename   string
}

// MatchFile runs every file rule against the event and returns hits.
// Mirrors Match / MatchNet. Currently one rule
// (`file:sensitive_read`); space for `file:cred_write` once we plumb
// write-flag detection (the openat tracepoint already gives us the
// flags, the rule just hasn't been written yet).
func MatchFile(e FileEvent) []Hit {
	var hits []Hit
	if h, ok := matchSensitiveRead(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// sensitiveCommAllowlist — processes that legitimately read sensitive
// files as part of normal operation. Any of these reading
// /etc/shadow / authorized_keys / sudoers is expected; alerting on
// them would be pure noise. Operators can override via
// MILOG_PROBE_FILE_ALLOWLIST (comma-separated comm names).
//
// Kept conservative: PAM / nss / system auth path get implicit access
// via their toolnames, but anything beyond this list (curl, cat, less,
// php-fpm, nginx, …) reading a sensitive file is the alert-worthy case.
var defaultSensitiveCommAllowlist = []string{
	"sshd",
	"sshd-session",
	"sudo",
	"su",
	"login",
	"getty",
	"agetty",
	"cron",
	"crond",
	"anacron",
	"systemd",
	"systemd-logind",
	"systemd-userdb",
	"systemd-tmpfile",
	"systemd-resolve",
	"auditd",
	"audisp-syslog",
	"adduser",
	"useradd",
	"usermod",
	"userdel",
	"chpasswd",
	"passwd",
	"chage",
	"visudo",
	"pam_unix",
	"nscd",
	"nslcd",
	"sssd",
	"milog",
	"milog-probe",
}

// defaultSensitivePaths — files whose reads are alert-worthy when
// performed by a non-allowlisted process. Entries ending in `/` are
// treated as prefix matches (covers /etc/sudoers.d/anything,
// /etc/ssh/sshd_config + host keys, /root/.ssh/* including
// authorized_keys2 + known_hosts).
//
// Mirrors the audit FIM module's defaults so file:sensitive_read
// alerts and the audit-side hash-change alerts cover the same
// ground from two different angles (live vs. periodic).
var defaultSensitivePaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	"/etc/ssh/",
	"/etc/ld.so.preload",
	"/root/.ssh/",
}

// fileRules holds the parsed file-audit configuration. Computed once
// via loadFileRules(); subsequent events reuse the cached value.
// Same single-shot init pattern as netAllowlist — operator restarts
// milog-probe to pick up env changes.
type fileRules struct {
	sensitivePaths []string            // raw entries; suffix `/` means prefix match
	allowedComms   map[string]struct{} // exact-match comm allowlist
}

func (r *fileRules) isSensitive(path string) bool {
	for _, p := range r.sensitivePaths {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(path, p) {
				return true
			}
			continue
		}
		if path == p {
			return true
		}
	}
	return false
}

func (r *fileRules) commAllowed(comm string) bool {
	_, ok := r.allowedComms[comm]
	return ok
}

var (
	cachedFileRules fileRules
	fileRulesReady  bool
)

func loadFileRules() *fileRules {
	if fileRulesReady {
		return &cachedFileRules
	}
	cachedFileRules = parseFileRules(
		os.Getenv("MILOG_PROBE_FILE_SENSITIVE"),
		os.Getenv("MILOG_PROBE_FILE_ALLOWLIST"),
	)
	fileRulesReady = true
	return &cachedFileRules
}

// parseFileRules accepts comma-separated overrides for the sensitive
// path list and the comm allowlist. Empty string → use the defaults;
// any non-empty value REPLACES the default rather than appending, so
// operators tightening the policy don't accidentally inherit the
// shipped list. Same shape as MILOG_PROBE_NET_ALLOWLIST.
func parseFileRules(pathsSrc, commsSrc string) fileRules {
	out := fileRules{allowedComms: map[string]struct{}{}}

	paths := defaultSensitivePaths
	if strings.TrimSpace(pathsSrc) != "" {
		paths = nil
		for _, raw := range strings.Split(pathsSrc, ",") {
			p := strings.TrimSpace(raw)
			if p == "" {
				continue
			}
			paths = append(paths, p)
		}
	}
	out.sensitivePaths = paths

	comms := defaultSensitiveCommAllowlist
	if strings.TrimSpace(commsSrc) != "" {
		comms = nil
		for _, raw := range strings.Split(commsSrc, ",") {
			c := strings.TrimSpace(raw)
			if c == "" {
				continue
			}
			comms = append(comms, c)
		}
	}
	for _, c := range comms {
		out.allowedComms[c] = struct{}{}
	}
	return out
}

// matchSensitiveRead fires when a non-allowlisted process opens a
// sensitive file. The rule key embeds the comm AND the path so that
// different (comm, path) pairs alert independently — e.g. nginx
// reading /etc/shadow and curl reading /root/.ssh/id_rsa are two
// distinct cooldown groups. Same process opening the same file
// repeatedly within ALERT_COOLDOWN dedups to a single alert.
func matchSensitiveRead(e FileEvent) (Hit, bool) {
	rules := loadFileRules()
	if rules.commAllowed(e.Comm) {
		return Hit{}, false
	}
	if !rules.isSensitive(e.Filename) {
		return Hit{}, false
	}
	return Hit{
		RuleKey: "file:sensitive_read:" + e.Comm + ":" + e.Filename,
		Title:   "Sensitive file read: " + e.Comm + " → " + e.Filename,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " path=" + e.Filename +
			" flags=0x" + uhex(e.Flags) + "```",
	}, true
}

// uhex is the lowercase-hex sibling of uitoa, used for openat flag
// rendering in alert bodies. Same stdlib-free constraint — strconv
// would pull a fair bit of code into the probe binary just for
// formatting on the hot path.
func uhex(v uint32) string {
	if v == 0 {
		return "0"
	}
	const digits = "0123456789abcdef"
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v&0xf]
		v >>= 4
	}
	return string(buf[i:])
}

// =============================================================================
// ptrace anti-injection probe — cross-process attach monitoring.
// =============================================================================

// PtraceEvent is the userspace mirror of `struct ptrace_event` from
// ptrace.bpf.c. Fired once per attach-class ptrace call
// (PTRACE_TRACEME, PTRACE_ATTACH, PTRACE_SEIZE) — the BPF side filters
// out per-attached-target operations (PEEK/POKE/CONT/…) so userspace
// only sees the "begin tracing" events.
type PtraceEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	Comm       string
	ParentComm string
	TargetPID  uint32
	Request    uint32 // PTRACE_TRACEME=0, PTRACE_ATTACH=16, PTRACE_SEIZE=0x4206
}

// MatchPtrace runs every ptrace rule against the event. Mirrors
// Match / MatchNet / MatchFile.
func MatchPtrace(e PtraceEvent) []Hit {
	var hits []Hit
	if h, ok := matchPtraceInject(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultPtraceDebuggers — comms that legitimately use ptrace as
// their primary mechanism. Any of these attaching is part of normal
// engineering / ops work and shouldn't page anyone. Operators add
// custom debuggers via MILOG_PROBE_PTRACE_DEBUGGERS (replaces, not
// appends — same semantics as the other env overrides).
//
// `dlv` is the Go debugger. `py-spy` and `bpftrace` use ptrace under
// the hood for their sampling probes. `criu` is checkpoint/restore.
// Generic "node" / "python" are NOT here — those would whitelist any
// scripted attacker who runs their tool as `python rce.py`.
var defaultPtraceDebuggers = []string{
	"gdb",
	"strace",
	"ltrace",
	"lldb",
	"lldb-server",
	"rr",
	"perf",
	"dlv",
	"dlv-dap",
	"py-spy",
	"bpftrace",
	"criu",
}

type ptraceRules struct {
	debuggers map[string]struct{}
}

func (r *ptraceRules) isDebugger(comm string) bool {
	_, ok := r.debuggers[comm]
	return ok
}

var (
	cachedPtraceRules ptraceRules
	ptraceRulesReady  bool
)

func loadPtraceRules() *ptraceRules {
	if ptraceRulesReady {
		return &cachedPtraceRules
	}
	cachedPtraceRules = parsePtraceRules(os.Getenv("MILOG_PROBE_PTRACE_DEBUGGERS"))
	ptraceRulesReady = true
	return &cachedPtraceRules
}

func parsePtraceRules(src string) ptraceRules {
	out := ptraceRules{debuggers: map[string]struct{}{}}
	list := defaultPtraceDebuggers
	if strings.TrimSpace(src) != "" {
		list = nil
		for _, raw := range strings.Split(src, ",") {
			c := strings.TrimSpace(raw)
			if c != "" {
				list = append(list, c)
			}
		}
	}
	for _, c := range list {
		out.debuggers[c] = struct{}{}
	}
	return out
}

// ptraceRequestName returns the human-readable mnemonic for the three
// attach-class request values the BPF side captures. Other values
// shouldn't reach here (BPF filtered them out) — fall back to hex
// rather than swallowing a kernel-side bug.
func ptraceRequestName(req uint32) string {
	switch req {
	case 0:
		return "TRACEME"
	case 16:
		return "ATTACH"
	case 0x4206:
		return "SEIZE"
	default:
		return "0x" + uhex(req)
	}
}

// matchPtraceInject fires when a non-debugger comm performs an
// attach-class ptrace. The rule key embeds (comm, target_pid) so
// distinct attacker→victim pairs alert independently. PTRACE_TRACEME
// from a debugger startup pattern (parent attached BEFORE its child
// runs the target binary) is permitted by the comm allowlist filter
// up the call chain — only attacker comms reach here.
func matchPtraceInject(e PtraceEvent) (Hit, bool) {
	rules := loadPtraceRules()
	if rules.isDebugger(e.Comm) {
		return Hit{}, false
	}
	req := ptraceRequestName(e.Request)
	return Hit{
		RuleKey: "proc:ptrace_inject:" + e.Comm + ":" + uitoa(e.TargetPID),
		Title:   "Process injection via ptrace: " + e.Comm + " → pid " + uitoa(e.TargetPID) + " (" + req + ")",
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " target_pid=" + uitoa(e.TargetPID) +
			" request=" + req + "```",
	}, true
}

// =============================================================================
// Kernel module load probe — rootkit / persistence monitoring.
// =============================================================================

// KmodEvent is the userspace mirror of `struct kmod_event` from
// kmod.bpf.c. Fired once per `module:module_load` tracepoint —
// covers both init_module(2) and finit_module(2) paths.
type KmodEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	Comm       string
	ParentComm string
	Module     string // module name, e.g. "nf_conntrack"
}

// MatchKmod runs every module-load rule against the event.
func MatchKmod(e KmodEvent) []Hit {
	var hits []Hit
	if h, ok := matchKmodLoad(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultKmodLoaders — comms that legitimately load kernel modules
// during normal operation. systemd-modules-load runs at boot from
// /etc/modules-load.d; modprobe is invoked by udev rules + manual
// admin work; dkms rebuilds modules on kernel upgrade. Anything else
// loading a kernel module is alert-worthy.
//
// Operators on locked-down hosts (kernel.modules_disabled=1 after
// boot) should set MILOG_PROBE_KMOD_ALLOWLIST="" to alert on EVERY
// module load — on those hosts a module load shouldn't be possible
// at all, so any event is signal.
var defaultKmodLoaders = []string{
	"systemd-modules",       // systemd kernel-modules-load.service
	"systemd-modules-load",  // alternate name on some distros
	"modprobe",
	"insmod",                // raw load — typically dkms / boot scripts
	"kmod",
	"dkms",
	"systemd-udevd",         // udev triggers module loads via rules
}

type kmodRules struct {
	allowedLoaders map[string]struct{}
}

func (r *kmodRules) isAllowedLoader(comm string) bool {
	_, ok := r.allowedLoaders[comm]
	return ok
}

var (
	cachedKmodRules kmodRules
	kmodRulesReady  bool
)

// loadKmodRules differs subtly from loadFileRules / loadPtraceRules:
// an EXPLICITLY EMPTY MILOG_PROBE_KMOD_ALLOWLIST="" is a meaningful
// "no allowlist, alert on EVERY load" setting — the locked-down host
// pattern (`kernel.modules_disabled=1` post-boot, where any module
// load attempt is signal). An undefined env var falls back to the
// shipped defaults. os.LookupEnv distinguishes the two; os.Getenv
// would conflate them.
func loadKmodRules() *kmodRules {
	if kmodRulesReady {
		return &cachedKmodRules
	}
	src, set := os.LookupEnv("MILOG_PROBE_KMOD_ALLOWLIST")
	if set && strings.TrimSpace(src) == "" {
		cachedKmodRules = kmodRules{allowedLoaders: map[string]struct{}{}}
	} else {
		cachedKmodRules = parseKmodRules(src)
	}
	kmodRulesReady = true
	return &cachedKmodRules
}

// parseKmodRules takes an env-string override; empty / whitespace-only
// → shipped defaults, comma-separated → custom list (replaces, not
// appends — same semantics as the other env overrides).
func parseKmodRules(src string) kmodRules {
	out := kmodRules{allowedLoaders: map[string]struct{}{}}
	list := defaultKmodLoaders
	if strings.TrimSpace(src) != "" {
		list = nil
		for _, raw := range strings.Split(src, ",") {
			c := strings.TrimSpace(raw)
			if c != "" {
				list = append(list, c)
			}
		}
	}
	for _, c := range list {
		out.allowedLoaders[c] = struct{}{}
	}
	return out
}

// matchKmodLoad fires when a non-allowlisted process loads a kernel
// module. The rule key embeds (comm, module) so distinct loads alert
// independently. Same module reloaded by the same process within
// cooldown dedups to one alert.
func matchKmodLoad(e KmodEvent) (Hit, bool) {
	rules := loadKmodRules()
	if rules.isAllowedLoader(e.Comm) {
		return Hit{}, false
	}
	mod := e.Module
	if mod == "" {
		mod = "<unknown>"
	}
	return Hit{
		RuleKey: "proc:kmod_load:" + e.Comm + ":" + mod,
		Title:   "Kernel module loaded: " + mod + " by " + e.Comm,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " module=" + mod + "```",
	}, true
}

// =============================================================================
// TCP retransmit observability — periodic-sample probe.
// =============================================================================

// RetransEvent is a sampled count, not a per-packet event. The
// userspace loader (retrans_linux.go) ticks every Window, reads the
// BPF count map, computes deltas vs the previous sample, and emits
// one RetransEvent per (DAddr, DPort) whose count grew. No process
// attribution: tcp_retransmit_skb fires from softirq context where
// bpf_get_current_pid_tgid would be confidently wrong.
type RetransEvent struct {
	DAddr  string        // destination IP, already stringified
	DPort  uint16
	IsIPv6 bool
	Count  uint64        // retransmits to this destination during the window
	Window time.Duration // sample window — included so alert body shows the rate context
}

// MatchRetrans runs every retransmit rule against the event. Mirrors
// MatchNet shape; only one rule for now (`net:retrans_spike`).
func MatchRetrans(e RetransEvent) []Hit {
	var hits []Hit
	if h, ok := matchRetransSpike(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultRetransThreshold — minimum retransmit count per window
// before the rule fires. 10 retransmits in 60s is a sustained ~1
// retransmit every 6s to a single destination, which on most healthy
// flows is well above noise. Operators on lossy links can raise via
// MILOG_PROBE_RETRANS_THRESHOLD; on tight links lower it to catch
// developing problems earlier.
const defaultRetransThreshold uint64 = 10

func retransThreshold() uint64 {
	v := os.Getenv("MILOG_PROBE_RETRANS_THRESHOLD")
	if v == "" {
		return defaultRetransThreshold
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n == 0 {
		return defaultRetransThreshold
	}
	return n
}

// matchRetransSpike fires when a destination's retransmit count
// during the current sample window exceeds the threshold. Per-(daddr,
// dport) rule key — distinct flows alert independently, the same
// flow re-spiking dedups via cooldown.
//
// Threshold filtering happens here rather than in the loader so the
// rule engine's tunable knob lives in one place (alongside the other
// MILOG_PROBE_* env vars) and unit tests can stage thresholds
// without spinning up the BPF side.
func matchRetransSpike(e RetransEvent) (Hit, bool) {
	if e.Count < retransThreshold() {
		return Hit{}, false
	}
	dest := e.DAddr + ":" + uitoa(uint32(e.DPort))
	return Hit{
		RuleKey: "net:retrans_spike:" + e.DAddr + ":" + uitoa(uint32(e.DPort)),
		Title:   "TCP retransmit spike: " + dest + " (" + uitoa64(e.Count) + " retrans / " + e.Window.String() + ")",
		Body: "```dst=" + dest + " retrans=" + uitoa64(e.Count) +
			" window=" + e.Window.String() + "```",
	}, true
}

// uitoa64 is the uint64 sibling of uitoa — same stdlib-free formatter
// constraint, just with a wider value space. Retransmit counts can
// theoretically exceed uint32 on a long-running probe + busy host
// (though in practice they reset every window).
func uitoa64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// =============================================================================
// Per-PID syscall rate anomaly probe — sampled with Welford σ baselines.
// =============================================================================

// Welford is an online (single-pass) mean + variance accumulator. Used
// to track per-PID syscall counts without storing the full sample
// history — memory bound is constant per tracked PID. Public so the
// userspace loader can carry the state alongside other per-PID
// bookkeeping (`lastSeenAt` for age-out, `last` for delta vs. raw
// counter), and so unit tests can drive it directly.
//
// References: https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance
type Welford struct {
	N    uint64  // sample count
	Mean float64 // running mean
	M2   float64 // sum of squared deltas — used to compute variance
}

// Update folds one new sample into the running statistics. O(1)
// memory, O(1) time. Numerically stable for the count ranges we'll
// see (syscalls/window is at most ~10^9 even on a torture-test host).
func (w *Welford) Update(x float64) {
	w.N++
	delta := x - w.Mean
	w.Mean += delta / float64(w.N)
	delta2 := x - w.Mean
	w.M2 += delta * delta2
}

// Variance returns the sample variance (n-1 denominator). Returns 0
// for n < 2 — a single sample has no spread, and we use this 0 as
// the "no-σ-yet" signal in matchSyscallBurst.
func (w *Welford) Variance() float64 {
	if w.N < 2 {
		return 0
	}
	return w.M2 / float64(w.N-1)
}

// Stddev wraps Variance — just sqrt. Kept as a method for callsite
// readability ("threshold = mean + 3*stddev" reads cleaner).
func (w *Welford) Stddev() float64 {
	return math.Sqrt(w.Variance())
}

// RateAnomalyEvent is the userspace-side projection of one PID's
// behaviour during one sample window: the count for THIS window plus
// the running baseline (mean, stddev) computed by Welford from prior
// windows. The rule decides whether the count is far enough above
// baseline to alert.
//
// Carrying the baseline in the event (rather than recomputing in the
// rule) is deliberate: it keeps `matchSyscallBurst` pure-functional
// for unit testing, and lets the alert body show the operator the
// numbers that drove the decision.
type RateAnomalyEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	Comm       string
	ParentComm string
	Count      uint64        // syscalls observed in this window
	Mean       float64       // running mean (samples per window)
	Stddev     float64       // running stddev (samples per window)
	Window     time.Duration // sample window (for rate-per-sec rendering)
	Samples    uint64        // total samples included in mean/stddev — used for burn-in gate
}

// MatchRateAnomaly runs the rate-anomaly rule against the event.
// Mirrors the other Match* functions.
func MatchRateAnomaly(e RateAnomalyEvent) []Hit {
	var hits []Hit
	if h, ok := matchSyscallBurst(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultSyscallFloor — minimum count-per-window before the rule can
// fire. Suppresses two classes of false positive:
//   1. Near-idle processes: mean ≈ 0, σ ≈ 0, ANY non-zero count would
//      otherwise look like an "infinite-σ spike". The floor blocks
//      those until the absolute count is meaningful on its own.
//   2. Newly-tracked PIDs whose baseline isn't established yet —
//      the burn-in gate handles the mean stability part, the floor
//      handles the absolute-magnitude part.
//
// Default scales with the default window (60s); operator on a tight
// host (rare syscalls, small expected counts) can lower via
// MILOG_PROBE_SYSCALL_FLOOR; on a database/web-server host the
// shipped defaults already filter out the bulk of normal load.
const defaultSyscallFloor uint64 = 1000

// defaultSyscallBurnIn — number of samples the Welford state must
// see before its (mean, σ) is considered stable enough to gate
// alerts on. 10 windows × 60s = 10 minutes of warm-up per process.
const defaultSyscallBurnIn uint64 = 10

func syscallFloor() uint64 {
	v := os.Getenv("MILOG_PROBE_SYSCALL_FLOOR")
	if v == "" {
		return defaultSyscallFloor
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n == 0 {
		return defaultSyscallFloor
	}
	return n
}

func syscallBurnIn() uint64 {
	v := os.Getenv("MILOG_PROBE_SYSCALL_BURNIN")
	if v == "" {
		return defaultSyscallBurnIn
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n == 0 {
		return defaultSyscallBurnIn
	}
	return n
}

// matchSyscallBurst fires when a PID's syscall count for the current
// window is more than 3σ above its running mean AND above the
// absolute floor AND past the burn-in. Per-(comm, pid) rule key —
// distinct processes alert independently; the same process bursting
// repeatedly within ALERT_COOLDOWN dedups to one alert.
//
// PID reuse is an accepted false-positive source: when a long-idle
// PID's baseline gets inherited by a new process that reuses the
// PID after the original exits. Mitigation lives userspace-side via
// age-out — practical risk is low on hosts with PID-max ~4M.
func matchSyscallBurst(e RateAnomalyEvent) (Hit, bool) {
	if e.Count < syscallFloor() {
		return Hit{}, false
	}
	if e.Samples < syscallBurnIn() {
		return Hit{}, false
	}
	threshold := e.Mean + 3.0*e.Stddev
	if float64(e.Count) <= threshold {
		return Hit{}, false
	}
	windowSec := e.Window.Seconds()
	if windowSec <= 0 {
		// Can't compute rate without a positive window — guard
		// against config error or tests that pass zero. Don't fire.
		return Hit{}, false
	}
	rate := float64(e.Count) / windowSec
	meanRate := e.Mean / windowSec
	stddevRate := e.Stddev / windowSec
	dest := e.Comm + "(pid=" + uitoa(e.PID) + ")"
	return Hit{
		RuleKey: "process:syscall_burst:" + e.Comm + ":" + uitoa(e.PID),
		Title:   "Syscall rate anomaly: " + dest + " — " + ftoa1(rate) + "/s vs baseline " + ftoa1(meanRate) + "/s ±" + ftoa1(stddevRate),
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " count=" + uitoa64(e.Count) +
			" rate=" + ftoa1(rate) + "/s mean=" + ftoa1(meanRate) +
			"/s stddev=" + ftoa1(stddevRate) + "/s samples=" + uitoa64(e.Samples) + "```",
	}, true
}

// ftoa1 formats a float64 with one decimal place. Used by the
// syscall-burst rule to render rate / mean / stddev in alert
// bodies. Uses strconv (already imported for the netallowlist
// parser) rather than rolling our own — float formatting isn't
// hot-path here, runs at most a handful of times per minute.
func ftoa1(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}
