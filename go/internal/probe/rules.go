// Package probe is milog-probe's eBPF event loaders and rule engine.
//
// rules.go is OS-independent so the rules test anywhere. Each Match* function
// turns one event into Hits whose RuleKey goes through milog's alert path,
// so cooldown, silence and dedup apply there rather than in the probe.
package probe

import (
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Event is a process exec, with parent info looked up in /proc rather than
// read through CO-RE chains in BPF.
type Event struct {
	PID        uint32
	PPID       uint32 // looked up via /proc/<pid>/status
	UID        uint32
	Comm       string // child process name (16-byte kernel comm)
	ParentComm string // /proc/<ppid>/comm
	Filename   string // exe path captured at tracepoint
}

// Hit is one rule firing. RuleKey is what milog's cooldown groups by.
type Hit struct {
	RuleKey string
	Title   string
	Body    string
}

// webWorkerComms are servers whose shell children are a strong RCE signal.
// Hosts running cgi-bin can silence process:shell_from_web_worker:*.
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

// shellComms is a fixed list rather than /etc/shells.
var shellComms = map[string]struct{}{
	"sh":   {},
	"bash": {},
	"dash": {},
	"zsh":  {},
	"ksh":  {},
	"ash":  {},
	"tcsh": {},
}

// shellParentAllowlist lists parents that routinely exec shells.
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

// tmpExecPrefixes omits per-user temp dirs, where cargo and go legitimately drop binaries.
var tmpExecPrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
}

// Match runs every exec rule against e.
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

// matchShellFromWebWorker catches a web server spawning a shell, the usual
// result of eval/system on attacker input.
func matchShellFromWebWorker(e Event) (Hit, bool) {
	if _, isShell := shellComms[e.Comm]; !isShell {
		return Hit{}, false
	}
	if _, isWebParent := webWorkerComms[e.ParentComm]; !isWebParent {
		return Hit{}, false
	}
	return Hit{
		RuleKey: "process:shell_from_web_worker:" + e.ParentComm + ":" + e.Comm,
		Title:   "Shell from web worker: " + e.ParentComm + " → " + e.Comm,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " exe=" + e.Filename + "```",
	}, true
}

// matchExecFromTmp keys on comm so one program re-execing itself doesn't
// cooldown-mask other drops.
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

// matchSuidEscalation flags a uid 0 exec whose parent is a web worker,
// approximating setuid escalation without capturing pre/post UIDs in BPF.
func matchSuidEscalation(e Event) (Hit, bool) {
	if e.UID != 0 {
		return Hit{}, false
	}
	// Limited to web-worker parents; wider would page on every cron job.
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

// uitoa formats v in decimal.
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

// NetEvent is one outbound TCP connect (TCP_CLOSE -> TCP_SYN_SENT), with
// DAddr already formatted as a string.
type NetEvent struct {
	PID        uint32
	PPID       uint32 // looked up via /proc/<pid>/status
	UID        uint32
	Comm       string
	ParentComm string
	DAddr      string // destination IP, already stringified
	DPort      uint16
	IsIPv6     bool
	Exe        string // /proc/<pid>/exe target
	Cgroup     string // systemd cgroup path, see cgroupPath
}

// MatchNet runs every network rule against e.
func MatchNet(e NetEvent) []Hit {
	var hits []Hit
	if h, ok := matchUnexpectedOutbound(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// matchUnexpectedOutbound flags connects outside the allowlist (default:
// loopback, DNS, NTP and private ranges). Keyed by comm so one process
// hitting many destinations is one cooldown group.
func matchUnexpectedOutbound(e NetEvent) (Hit, bool) {
	if isMilogDelivery(e) {
		return Hit{}, false
	}
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

// milogUnitCgroups are the system units milog installs; only root can move a
// process into them.
var milogUnitCgroups = map[string]struct{}{
	"/system.slice/milog.service":       {},
	"/system.slice/milog-probe.service": {},
}

// curlExes are root-owned paths, so a renamed binary or a prctl'd comm
// doesn't pass.
var curlExes = map[string]struct{}{
	"/usr/bin/curl":       {},
	"/bin/curl":           {},
	"/usr/local/bin/curl": {},
}

// isMilogDelivery reports milog's own alert sends: curl running inside one of
// milog's systemd units. Any other process in those units still alerts.
func isMilogDelivery(e NetEvent) bool {
	if _, ok := milogUnitCgroups[e.Cgroup]; !ok {
		return false
	}
	_, ok := curlExes[e.Exe]
	return ok
}

// cgroupPath picks the systemd cgroup path out of /proc/<pid>/cgroup: the
// unified "0::" line, else the v1 "name=systemd" line.
func cgroupPath(procCgroup string) string {
	var legacy string
	for _, line := range strings.Split(procCgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			return parts[2]
		}
		if parts[1] == "name=systemd" {
			legacy = parts[2]
		}
	}
	return legacy
}

// netAllowlist matches `:port` (any IP), `cidr` (any port) or `cidr:port`.
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
		// Unparseable address from BPF: alert rather than allow.
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

// defaultNetAllowlist covers loopback, DNS, NTP and private ranges; tightly
// firewalled hosts can drop the private ranges via MILOG_PROBE_NET_ALLOWLIST.
const defaultNetAllowlist = "127.0.0.0/8,::1/128," +
	":53,:123," +
	"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16," +
	"169.254.0.0/16," +
	"fc00::/7,fe80::/10"

// Parsed once; env changes need a probe restart. Not a sync.Once so tests
// can reset it.
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

// parseNetAllowlist takes comma-separated `:port`, `cidr` or `cidr:port`
// entries; bare IPs become /32 or /128. Malformed entries are skipped,
// which fails safe because nothing gets allowlisted.
func parseNetAllowlist(src string) netAllowlist {
	out := netAllowlist{wildcardPorts: map[uint16]struct{}{}}
	for _, raw := range strings.Split(src, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		// Bare port. Check for "::" so IPv6 entries like "::1/128" aren't
		// taken for ports and dropped.
		if strings.HasPrefix(entry, ":") && !strings.HasPrefix(entry, "::") {
			if p, err := strconv.ParseUint(entry[1:], 10, 16); err == nil {
				out.wildcardPorts[uint16(p)] = struct{}{}
			}
			continue
		}
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

// splitCIDRPort splits "10.0.0.0/8:443". IPv6 with a port needs brackets,
// "[fc00::/7]:443", as net.JoinHostPort writes it.
func splitCIDRPort(entry string) (cidr string, port uint16, hasPort bool) {
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
	// Unbracketed: the last colon is a port separator only if a uint16
	// follows and the part before is a CIDR.
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
	if strings.Count(body, ":") > 0 && !strings.Contains(body, "/") {
		return entry, 0, false
	}
	return body, uint16(p), true
}

// parseCIDROrIP treats a bare IP as /32 or /128.
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

// FileEvent is one openat(2) under a BPF-side prefix (/etc/, /root,
// /home, /var/); exact path matching happens here so it's tunable without
// rebuilding BPF.
type FileEvent struct {
	PID        uint32
	PPID       uint32 // looked up via /proc/<pid>/status
	UID        uint32
	Flags      uint32 // openat(2) flags — O_RDONLY, O_WRONLY, O_RDWR plus O_CREAT etc.
	Comm       string
	ProcComm   string // process name; Comm is the thread's
	ParentComm string
	Filename   string
}

// MatchFile runs every file rule against e.
func MatchFile(e FileEvent) []Hit {
	var hits []Hit
	if h, ok := matchSensitiveRead(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultSensitiveCommAllowlist lists processes that read auth files as
// part of normal operation. MILOG_PROBE_FILE_ALLOWLIST replaces it.
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

// defaultSensitivePaths match exactly, or by prefix when they end in `/`.
// They mirror the audit FIM defaults.
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

// fileRules is parsed once; env changes need a probe restart.
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

// parseFileRules: a non-empty override replaces the defaults instead of
// appending to them.
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

// matchSensitiveRead keys on comm and path, so each pair has its own cooldown.
func matchSensitiveRead(e FileEvent) (Hit, bool) {
	rules := loadFileRules()
	if rules.commAllowed(e.Comm) || rules.commAllowed(e.ProcComm) {
		return Hit{}, false
	}
	if !rules.isSensitive(e.Filename) {
		return Hit{}, false
	}
	return Hit{
		RuleKey: "file:sensitive_read:" + e.Comm + ":" + e.Filename,
		Title:   "Sensitive file read: " + e.Comm + " → " + e.Filename,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm + procField(e.Comm, e.ProcComm) +
			" parent=" + e.ParentComm + " path=" + e.Filename +
			" flags=0x" + uhex(e.Flags) + "```",
	}, true
}

// procField names the process when a thread renamed itself, so the alert
// shows which name to allowlist.
func procField(comm, procComm string) string {
	if procComm == "" || procComm == comm {
		return ""
	}
	return " proc=" + procComm
}

// uhex formats v in lowercase hex.
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

// PtraceEvent is one attach-class ptrace (TRACEME, ATTACH, SEIZE); BPF
// drops the per-target requests.
type PtraceEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	Comm       string
	ProcComm   string // process name; Comm is the thread's
	ParentComm string
	TargetPID  uint32
	Request    uint32 // PTRACE_TRACEME=0, PTRACE_ATTACH=16, PTRACE_SEIZE=0x4206
}

// MatchPtrace runs every ptrace rule against e.
func MatchPtrace(e PtraceEvent) []Hit {
	var hits []Hit
	if h, ok := matchPtraceInject(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultPtraceDebuggers is replaced by MILOG_PROBE_PTRACE_DEBUGGERS.
// Interpreters like python stay off so `python exploit.py` can't hide.
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

// ptraceRequestName falls back to hex for values BPF should have filtered.
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

// matchPtraceInject keys on comm and target pid so each attacker/victim
// pair alerts separately.
func matchPtraceInject(e PtraceEvent) (Hit, bool) {
	rules := loadPtraceRules()
	if rules.isDebugger(e.Comm) || rules.isDebugger(e.ProcComm) {
		return Hit{}, false
	}
	req := ptraceRequestName(e.Request)
	return Hit{
		RuleKey: "proc:ptrace_inject:" + e.Comm + ":" + uitoa(e.TargetPID),
		Title:   "Process injection via ptrace: " + e.Comm + " → pid " + uitoa(e.TargetPID) + " (" + req + ")",
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm + procField(e.Comm, e.ProcComm) +
			" parent=" + e.ParentComm + " target_pid=" + uitoa(e.TargetPID) +
			" request=" + req + "```",
	}, true
}

// KmodEvent is one module_load tracepoint, covering init_module and
// finit_module.
type KmodEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	Comm       string
	ProcComm   string // process name; Comm is the thread's
	ParentComm string
	Module     string // module name, e.g. "nf_conntrack"
}

// MatchKmod runs every module-load rule against e.
func MatchKmod(e KmodEvent) []Hit {
	var hits []Hit
	if h, ok := matchKmodLoad(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultKmodLoaders is replaced by MILOG_PROBE_KMOD_ALLOWLIST; set it to ""
// on hosts with kernel.modules_disabled=1 so every load alerts.
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

// loadKmodRules treats an explicitly empty MILOG_PROBE_KMOD_ALLOWLIST as
// "no allowlist", so it needs os.LookupEnv; unset means the defaults.
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

// parseKmodRules: a non-empty list replaces the defaults.
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

// matchKmodLoad keys on comm and module.
func matchKmodLoad(e KmodEvent) (Hit, bool) {
	rules := loadKmodRules()
	if rules.isAllowedLoader(e.Comm) || rules.isAllowedLoader(e.ProcComm) {
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
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm + procField(e.Comm, e.ProcComm) +
			" parent=" + e.ParentComm + " module=" + mod + "```",
	}, true
}

// RetransEvent is a per-destination retransmit count for one sample window.
// It has no process: tcp_retransmit_skb runs in softirq context, where the
// current pid is meaningless.
type RetransEvent struct {
	DAddr  string        // destination IP, already stringified
	DPort  uint16
	IsIPv6 bool
	Count  uint64        // retransmits to this destination during the window
	Window time.Duration // sample window — included so alert body shows the rate context
}

// MatchRetrans runs every retransmit rule against e.
func MatchRetrans(e RetransEvent) []Hit {
	var hits []Hit
	if h, ok := matchRetransSpike(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultRetransThreshold is retransmits per window per destination;
// tune with MILOG_PROBE_RETRANS_THRESHOLD.
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

// matchRetransSpike keys on destination. The threshold lives here, not in
// the loader, so tests can drive it without BPF.
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

// uitoa64 formats v in decimal.
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

// Welford is an online mean and variance accumulator with constant memory
// per tracked PID.
type Welford struct {
	N    uint64  // sample count
	Mean float64 // running mean
	M2   float64 // sum of squared deltas — used to compute variance
}

// Update folds in one sample.
func (w *Welford) Update(x float64) {
	w.N++
	delta := x - w.Mean
	w.Mean += delta / float64(w.N)
	delta2 := x - w.Mean
	w.M2 += delta * delta2
}

// Variance returns the sample variance, or 0 below two samples, which
// matchSyscallBurst reads as "no baseline yet".
func (w *Welford) Variance() float64 {
	if w.N < 2 {
		return 0
	}
	return w.M2 / float64(w.N-1)
}

// Stddev returns the square root of Variance.
func (w *Welford) Stddev() float64 {
	return math.Sqrt(w.Variance())
}

// RateAnomalyEvent is one PID's syscall count for a window plus its
// baseline from earlier windows, carried in the event so the rule stays
// pure and the alert can show the numbers.
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

// MatchRateAnomaly runs the rate-anomaly rule against e.
func MatchRateAnomaly(e RateAnomalyEvent) []Hit {
	var hits []Hit
	if h, ok := matchSyscallBurst(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultSyscallFloor stops near-idle processes, whose σ is about 0, from
// alerting on any small count. Tune with MILOG_PROBE_SYSCALL_FLOOR.
const defaultSyscallFloor uint64 = 1000

// defaultSyscallBurnIn is the number of windows a PID's baseline needs
// before it can alert.
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

// matchSyscallBurst needs count > mean+3σ, the floor and the burn-in.
// A reused PID can inherit an old baseline; the loader's age-out limits that.
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
		// A zero window means a config or test error; don't fire.
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

// ftoa1 formats v with one decimal place.
func ftoa1(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// BpfLoadEvent is one bpf(BPF_PROG_LOAD); BPF filters out other commands.
type BpfLoadEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	Cmd        uint32 // always BPF_PROG_LOAD (5) given current BPF-side filter
	Comm       string
	ProcComm   string // process name; Comm is the thread's
	ParentComm string
}

// MatchBpfLoad runs every bpf-load rule against e.
func MatchBpfLoad(e BpfLoadEvent) []Hit {
	var hits []Hit
	if h, ok := matchBpfLoad(e); ok {
		hits = append(hits, h)
	}
	return hits
}

// defaultBpfLoaders covers systemd's cgroup programs, container runtimes and
// tracing tools. It must include milog-probe or the probe alerts on itself.
var defaultBpfLoaders = []string{
	"milog-probe",
	"systemd",
	"systemd-networkd",
	"systemd-resolved",
	"systemd-logind",
	"systemd-udevd",
	"systemd-journald",
	"bpftrace",
	"bpftool",
	"bcc",
	"perf",
	"docker",
	"dockerd",
	"containerd",
	"runc",
	"crun",
	"snapd",
	"node_exporter",
	"istio-proxy",
	"envoy",
	"falco",
	"tetragon",
	"cilium-agent",
}

type bpfLoadRules struct {
	allowed map[string]struct{}
}

func (r *bpfLoadRules) isAllowed(comm string) bool {
	_, ok := r.allowed[comm]
	return ok
}

var (
	cachedBpfLoadRules bpfLoadRules
	bpfLoadRulesReady  bool
)

func loadBpfLoadRules() *bpfLoadRules {
	if bpfLoadRulesReady {
		return &cachedBpfLoadRules
	}
	cachedBpfLoadRules = parseBpfLoadRules(os.Getenv("MILOG_PROBE_BPFLOAD_ALLOWLIST"))
	bpfLoadRulesReady = true
	return &cachedBpfLoadRules
}

func parseBpfLoadRules(src string) bpfLoadRules {
	out := bpfLoadRules{allowed: map[string]struct{}{}}
	list := defaultBpfLoaders
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
		out.allowed[c] = struct{}{}
	}
	return out
}

// matchBpfLoad keys on comm.
func matchBpfLoad(e BpfLoadEvent) (Hit, bool) {
	rules := loadBpfLoadRules()
	if rules.isAllowed(e.Comm) || rules.isAllowed(e.ProcComm) {
		return Hit{}, false
	}
	return Hit{
		RuleKey: "proc:bpf_load:" + e.Comm,
		Title:   "BPF program loaded by non-allowlisted process: " + e.Comm,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm + procField(e.Comm, e.ProcComm) +
			" parent=" + e.ParentComm + " cmd=BPF_PROG_LOAD```",
	}, true
}
