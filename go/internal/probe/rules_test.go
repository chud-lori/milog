package probe

import (
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func TestShellFromWebWorker(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want bool
	}{
		{
			"nginx → bash fires",
			Event{Comm: "bash", ParentComm: "nginx", Filename: "/bin/bash"},
			true,
		},
		{
			"php-fpm → sh fires",
			Event{Comm: "sh", ParentComm: "php-fpm8.2", Filename: "/bin/sh"},
			true,
		},
		{
			"apache2 → zsh fires",
			Event{Comm: "zsh", ParentComm: "apache2", Filename: "/usr/bin/zsh"},
			true,
		},
		{
			"sshd → bash does NOT fire (admin session)",
			Event{Comm: "bash", ParentComm: "sshd", Filename: "/bin/bash"},
			false,
		},
		{
			"sudo → bash does NOT fire",
			Event{Comm: "bash", ParentComm: "sudo", Filename: "/bin/bash"},
			false,
		},
		{
			"nginx → ls does NOT fire (not a shell)",
			Event{Comm: "ls", ParentComm: "nginx", Filename: "/bin/ls"},
			false,
		},
		{
			"systemd → bash does NOT fire",
			Event{Comm: "bash", ParentComm: "systemd", Filename: "/bin/bash"},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got := matchShellFromWebWorker(c.ev)
			if got != c.want {
				t.Fatalf("got=%v want=%v event=%+v", got, c.want, c.ev)
			}
		})
	}
}

func TestExecFromTmp(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"/tmp fires", "/tmp/dropper", true},
		{"/var/tmp fires", "/var/tmp/payload", true},
		{"/dev/shm fires", "/dev/shm/.x", true},
		{"/usr/bin does NOT fire", "/usr/bin/ls", false},
		{"/home does NOT fire", "/home/alice/build/foo", false},
		{"empty path does NOT fire", "", false},
		{"/tmpfile (similar prefix) does NOT fire", "/tmpfile", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got := matchExecFromTmp(Event{Filename: c.path, Comm: "x"})
			if got != c.want {
				t.Fatalf("got=%v want=%v path=%q", got, c.want, c.path)
			}
		})
	}
}

func TestSuidEscalation(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want bool
	}{
		{
			"php-fpm child as uid=0 fires",
			Event{Comm: "id", ParentComm: "php-fpm8.2", UID: 0},
			true,
		},
		{
			"nginx child as uid=0 fires",
			Event{Comm: "whoami", ParentComm: "nginx", UID: 0},
			true,
		},
		{
			"sshd child as uid=0 does NOT fire (admin login is fine)",
			Event{Comm: "bash", ParentComm: "sshd", UID: 0},
			false,
		},
		{
			"php-fpm child as uid=33 (www-data) does NOT fire",
			Event{Comm: "id", ParentComm: "php-fpm8.2", UID: 33},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got := matchSuidEscalation(c.ev)
			if got != c.want {
				t.Fatalf("got=%v want=%v event=%+v", got, c.want, c.ev)
			}
		})
	}
}

func TestMatch_combinesHits(t *testing.T) {
	// One event can match multiple rules — e.g. nginx spawning bash from
	// /tmp matches both shell_from_web_worker AND exec_from_tmp.
	ev := Event{
		Comm:       "bash",
		ParentComm: "nginx",
		UID:        0,
		Filename:   "/tmp/sh",
		PID:        1234,
		PPID:       1000,
	}
	hits := Match(ev)
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits (shell + tmp + suid), got %d: %+v", len(hits), hits)
	}
	keys := map[string]bool{}
	for _, h := range hits {
		keys[h.RuleKey] = true
	}
	for _, want := range []string{
		"process:shell_from_web_worker:nginx:bash",
		"process:exec_from_tmp:bash",
		"process:suid_escalation:nginx:bash",
	} {
		if !keys[want] {
			t.Errorf("missing rule key %q in hits %+v", want, hits)
		}
	}
}

func TestMatch_cleanEventReturnsNoHits(t *testing.T) {
	// A normal admin shell session: sshd → bash from /bin/bash, not uid=0.
	hits := Match(Event{
		Comm: "bash", ParentComm: "sshd", Filename: "/bin/bash",
		UID: 1000, PID: 4242, PPID: 4000,
	})
	if len(hits) != 0 {
		t.Fatalf("expected zero hits, got %d: %+v", len(hits), hits)
	}
}

func TestUitoa(t *testing.T) {
	cases := map[uint32]string{
		0:          "0",
		1:          "1",
		9:          "9",
		10:         "10",
		1234:       "1234",
		4294967295: "4294967295",
	}
	for v, want := range cases {
		if got := uitoa(v); got != want {
			t.Errorf("uitoa(%d) = %q, want %q", v, got, want)
		}
	}
}

// resetNetAllowlistCache wipes the package-level cache so each test
// can stage its own MILOG_PROBE_NET_ALLOWLIST. Test-only escape hatch
// — the cache flag is unexported so production callers can't reach it.
func resetNetAllowlistCache() {
	cachedAllowlist = netAllowlist{}
	allowlistReady = false
}

func TestMatchNet_DefaultsAllowDNSAndPrivate(t *testing.T) {
	t.Setenv("MILOG_PROBE_NET_ALLOWLIST", "")
	resetNetAllowlistCache()

	cases := []NetEvent{
		{Comm: "systemd-resolved", DAddr: "1.1.1.1", DPort: 53},
		{Comm: "chrony", DAddr: "192.168.1.1", DPort: 123},
		{Comm: "curl", DAddr: "127.0.0.1", DPort: 80},
		{Comm: "curl", DAddr: "::1", DPort: 80},
		{Comm: "ssh", DAddr: "10.0.0.5", DPort: 22},
		{Comm: "ssh", DAddr: "172.16.0.5", DPort: 22},
		{Comm: "ssh", DAddr: "192.168.99.5", DPort: 22},
		{Comm: "wget", DAddr: "169.254.169.254", DPort: 80},
		{Comm: "ipv6tool", DAddr: "fe80::1", DPort: 22},
		{Comm: "ulatool", DAddr: "fd12:3456::1", DPort: 443},
	}
	for _, ev := range cases {
		if hits := MatchNet(ev); len(hits) != 0 {
			t.Errorf("default allowlist should permit %+v, got hits: %+v", ev, hits)
		}
	}
}

func TestMatchNet_FiresOnPublicHTTPS(t *testing.T) {
	t.Setenv("MILOG_PROBE_NET_ALLOWLIST", "")
	resetNetAllowlistCache()

	ev := NetEvent{
		PID: 1234, UID: 33, Comm: "php-fpm8.2", ParentComm: "nginx",
		DAddr: "203.0.113.42", DPort: 443,
	}
	hits := MatchNet(ev)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit on public outbound, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.RuleKey != "net:unexpected_outbound:php-fpm8.2" {
		t.Errorf("rule key = %q, want net:unexpected_outbound:php-fpm8.2", h.RuleKey)
	}
	if !strings.Contains(h.Title, "203.0.113.42:443") {
		t.Errorf("title missing destination 203.0.113.42:443: %q", h.Title)
	}
	if !strings.Contains(h.Body, "parent=nginx") {
		t.Errorf("body missing parent context: %q", h.Body)
	}
}

func TestMatchNet_FiresOnPublicIPv6(t *testing.T) {
	t.Setenv("MILOG_PROBE_NET_ALLOWLIST", "")
	resetNetAllowlistCache()

	ev := NetEvent{
		PID: 555, Comm: "wget", DAddr: "2001:db8::1", DPort: 443, IsIPv6: true,
	}
	hits := MatchNet(ev)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit on public v6 outbound, got %d: %+v", len(hits), hits)
	}
}

func TestMatchNet_CustomAllowlist_TightenedDefault(t *testing.T) {
	// Operator wants ONLY DNS + a single corporate proxy CIDR allowed.
	// Everything else — including loopback — fires.
	t.Setenv("MILOG_PROBE_NET_ALLOWLIST", ":53,10.7.0.0/16:443")
	resetNetAllowlistCache()

	allowed := []NetEvent{
		{Comm: "resolver", DAddr: "8.8.8.8", DPort: 53},
		{Comm: "curl", DAddr: "10.7.42.1", DPort: 443},
	}
	for _, ev := range allowed {
		if hits := MatchNet(ev); len(hits) != 0 {
			t.Errorf("tightened allowlist should permit %+v, got: %+v", ev, hits)
		}
	}

	denied := []NetEvent{
		{Comm: "curl", DAddr: "127.0.0.1", DPort: 80},      // loopback no longer allowed
		{Comm: "curl", DAddr: "10.7.42.1", DPort: 80},      // wrong port for the CIDR
		{Comm: "curl", DAddr: "10.8.0.1", DPort: 443},      // right port, wrong CIDR
		{Comm: "miner", DAddr: "203.0.113.5", DPort: 3333}, // public, no rule
	}
	for _, ev := range denied {
		if hits := MatchNet(ev); len(hits) != 1 {
			t.Errorf("tightened allowlist should deny %+v, got %d hits", ev, len(hits))
		}
	}
}

func TestMatchNet_BareIPInAllowlist(t *testing.T) {
	// Bare IPs (no /mask) get normalised to /32 (v4) or /128 (v6).
	t.Setenv("MILOG_PROBE_NET_ALLOWLIST", "203.0.113.99,2001:db8::42")
	resetNetAllowlistCache()

	allowed := []NetEvent{
		{Comm: "x", DAddr: "203.0.113.99", DPort: 443},
		{Comm: "x", DAddr: "2001:db8::42", DPort: 80},
	}
	for _, ev := range allowed {
		if hits := MatchNet(ev); len(hits) != 0 {
			t.Errorf("bare-IP allowlist should permit %+v, got: %+v", ev, hits)
		}
	}
	if hits := MatchNet(NetEvent{Comm: "x", DAddr: "203.0.113.100", DPort: 443}); len(hits) != 1 {
		t.Errorf("neighbour IP should fire, got %d hits", len(hits))
	}
}

func TestParseNetAllowlist_MalformedSkipped(t *testing.T) {
	a := parseNetAllowlist(":53,not-a-cidr,10.0.0.0/99,fc00::/7,:abc, ,:8443")
	if _, ok := a.wildcardPorts[53]; !ok {
		t.Errorf("expected port 53 in wildcardPorts: %+v", a.wildcardPorts)
	}
	if _, ok := a.wildcardPorts[8443]; !ok {
		t.Errorf("expected port 8443 in wildcardPorts: %+v", a.wildcardPorts)
	}
	if len(a.nets) != 1 {
		t.Errorf("expected exactly 1 valid CIDR (fc00::/7), got %d: %+v", len(a.nets), a.nets)
	}
}

// resetFileRulesCache mirrors resetNetAllowlistCache for the file
// probe — wipes the parsed-config cache so each test can stage its
// own MILOG_PROBE_FILE_* env vars.
func resetFileRulesCache() {
	cachedFileRules = fileRules{}
	fileRulesReady = false
}

func TestMatchFile_DefaultsFireOnSensitiveRead(t *testing.T) {
	// A non-allowlisted process reading /etc/shadow is the canonical
	// post-compromise signal the audit FIM module hashes for; here we
	// catch the live read instead of the periodic re-hash.
	t.Setenv("MILOG_PROBE_FILE_SENSITIVE", "")
	t.Setenv("MILOG_PROBE_FILE_ALLOWLIST", "")
	resetFileRulesCache()

	cases := []struct {
		name string
		ev   FileEvent
	}{
		{"php-fpm reading /etc/shadow", FileEvent{
			Comm: "php-fpm8.2", ParentComm: "nginx",
			Filename: "/etc/shadow", PID: 1234, UID: 33,
		}},
		{"curl reading /etc/sudoers", FileEvent{
			Comm: "curl", Filename: "/etc/sudoers",
		}},
		{"cat reading sudoers.d entry", FileEvent{
			Comm: "cat", Filename: "/etc/sudoers.d/90-extra",
		}},
		{"nginx reading authorized_keys", FileEvent{
			Comm: "nginx", Filename: "/root/.ssh/authorized_keys",
		}},
		{"cat reading sshd_config", FileEvent{
			Comm: "cat", Filename: "/etc/ssh/sshd_config",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := MatchFile(c.ev)
			if len(hits) != 1 {
				t.Fatalf("expected 1 hit for %+v, got %d: %+v", c.ev, len(hits), hits)
			}
			h := hits[0]
			wantKey := "file:sensitive_read:" + c.ev.Comm + ":" + c.ev.Filename
			if h.RuleKey != wantKey {
				t.Errorf("rule key = %q, want %q", h.RuleKey, wantKey)
			}
			if !strings.Contains(h.Body, "comm="+c.ev.Comm) {
				t.Errorf("body missing comm=%s: %q", c.ev.Comm, h.Body)
			}
		})
	}
}

func TestMatchFile_AllowlistedCommsSilent(t *testing.T) {
	// sshd reading authorized_keys, cron reading /etc/sudoers, etc. —
	// all expected, all allowlisted. The whole point of the comm
	// allowlist is that operators don't get paged on every login.
	t.Setenv("MILOG_PROBE_FILE_SENSITIVE", "")
	t.Setenv("MILOG_PROBE_FILE_ALLOWLIST", "")
	resetFileRulesCache()

	cases := []FileEvent{
		{Comm: "sshd", Filename: "/root/.ssh/authorized_keys"},
		{Comm: "sudo", Filename: "/etc/sudoers"},
		{Comm: "cron", Filename: "/etc/shadow"},
		{Comm: "systemd", Filename: "/etc/passwd"},
		{Comm: "auditd", Filename: "/etc/shadow"},
		{Comm: "milog-probe", Filename: "/etc/shadow"},
	}
	for _, ev := range cases {
		if hits := MatchFile(ev); len(hits) != 0 {
			t.Errorf("allowlisted comm should not fire: %+v → %+v", ev, hits)
		}
	}
}

func TestMatchFile_NonSensitivePathSilent(t *testing.T) {
	// The BPF prefix filter is coarse (/etc /root /home /var) so the
	// userspace gets opens that aren't on the precise sensitive list.
	// Those must NOT fire — the rule is per-path, not per-prefix.
	t.Setenv("MILOG_PROBE_FILE_SENSITIVE", "")
	t.Setenv("MILOG_PROBE_FILE_ALLOWLIST", "")
	resetFileRulesCache()

	cases := []FileEvent{
		{Comm: "nginx", Filename: "/etc/nginx/nginx.conf"},
		{Comm: "vim", Filename: "/home/alice/notes.md"},
		{Comm: "tail", Filename: "/var/log/syslog"},
		{Comm: "less", Filename: "/etc/hostname"},
	}
	for _, ev := range cases {
		if hits := MatchFile(ev); len(hits) != 0 {
			t.Errorf("non-sensitive path should not fire: %+v → %+v", ev, hits)
		}
	}
}

func TestMatchFile_CustomSensitivePaths(t *testing.T) {
	// Operator extends defaults to also alert on webroot env files.
	// Custom list REPLACES defaults rather than appending — same
	// semantics as MILOG_PROBE_NET_ALLOWLIST.
	t.Setenv("MILOG_PROBE_FILE_SENSITIVE", "/var/www/.env,/etc/myapp/secret.key")
	t.Setenv("MILOG_PROBE_FILE_ALLOWLIST", "")
	resetFileRulesCache()

	if hits := MatchFile(FileEvent{Comm: "curl", Filename: "/var/www/.env"}); len(hits) != 1 {
		t.Errorf("custom sensitive path should fire, got %d hits", len(hits))
	}
	// The default /etc/shadow should NO LONGER fire — custom list replaces.
	if hits := MatchFile(FileEvent{Comm: "curl", Filename: "/etc/shadow"}); len(hits) != 0 {
		t.Errorf("custom list replaces defaults; /etc/shadow should not fire, got %+v", hits)
	}
}

func TestMatchFile_CustomCommAllowlist(t *testing.T) {
	// Operator runs a custom secrets-rotation tool that legitimately
	// reads /etc/shadow. They allowlist its comm and expect silence.
	t.Setenv("MILOG_PROBE_FILE_SENSITIVE", "")
	t.Setenv("MILOG_PROBE_FILE_ALLOWLIST", "rotator,backup-agent")
	resetFileRulesCache()

	// Allowlisted comms silent.
	if hits := MatchFile(FileEvent{Comm: "rotator", Filename: "/etc/shadow"}); len(hits) != 0 {
		t.Errorf("custom-allowlisted comm should be silent, got %+v", hits)
	}
	// And — because the custom list REPLACES — the previously-
	// shipped sshd allowlist no longer applies.
	if hits := MatchFile(FileEvent{Comm: "sshd", Filename: "/etc/shadow"}); len(hits) != 1 {
		t.Errorf("custom allowlist replaces defaults; sshd should now fire, got %+v", hits)
	}
}

func TestUhex(t *testing.T) {
	// Spot-check the openat-flag formatter. Common openat values:
	//   0x0  = O_RDONLY
	//   0x1  = O_WRONLY
	//   0x2  = O_RDWR
	//   0x42 = O_RDWR | O_CREAT (most common open() default for write)
	cases := map[uint32]string{
		0:          "0",
		1:          "1",
		2:          "2",
		0x42:       "42",
		0x80000:    "80000",
		0xffffffff: "ffffffff",
	}
	for v, want := range cases {
		if got := uhex(v); got != want {
			t.Errorf("uhex(0x%x) = %q, want %q", v, got, want)
		}
	}
}

// resetPtraceRulesCache mirrors the reset helpers for the other rule
// engines — wipes the parsed-config cache so each test stages its own
// MILOG_PROBE_PTRACE_DEBUGGERS.
func resetPtraceRulesCache() {
	cachedPtraceRules = ptraceRules{}
	ptraceRulesReady = false
}

func TestMatchPtrace_DebuggersSilent(t *testing.T) {
	// gdb / strace / lldb / dlv all live cleanly inside the default
	// allowlist — no operator should ever get paged on a normal debug
	// session.
	t.Setenv("MILOG_PROBE_PTRACE_DEBUGGERS", "")
	resetPtraceRulesCache()

	cases := []PtraceEvent{
		{Comm: "gdb", TargetPID: 1234, Request: 16},      // ATTACH
		{Comm: "strace", TargetPID: 5678, Request: 16},
		{Comm: "lldb", TargetPID: 9999, Request: 0x4206}, // SEIZE
		{Comm: "dlv", TargetPID: 100, Request: 16},
		{Comm: "py-spy", TargetPID: 200, Request: 0x4206},
		{Comm: "bpftrace", TargetPID: 300, Request: 0x4206},
	}
	for _, ev := range cases {
		if hits := MatchPtrace(ev); len(hits) != 0 {
			t.Errorf("debugger should be silent: %+v → %+v", ev, hits)
		}
	}
}

func TestMatchPtrace_AttackerCommFires(t *testing.T) {
	// Non-debugger comm performing a cross-process attach is the
	// canonical post-RCE injection pattern. php-fpm child somehow
	// running ptrace, sshd-spawned worker attaching to root pid 1, etc.
	t.Setenv("MILOG_PROBE_PTRACE_DEBUGGERS", "")
	resetPtraceRulesCache()

	cases := []struct {
		name string
		ev   PtraceEvent
		want string // expected mnemonic in title
	}{
		{"php-fpm ATTACH", PtraceEvent{
			Comm: "php-fpm8.2", ParentComm: "nginx",
			TargetPID: 1, Request: 16,
		}, "ATTACH"},
		{"sh SEIZE", PtraceEvent{
			Comm: "sh", ParentComm: "nginx",
			TargetPID: 4242, Request: 0x4206,
		}, "SEIZE"},
		{"random binary TRACEME", PtraceEvent{
			Comm: "dropper", TargetPID: 0, Request: 0,
		}, "TRACEME"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := MatchPtrace(c.ev)
			if len(hits) != 1 {
				t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
			}
			h := hits[0]
			wantKey := "proc:ptrace_inject:" + c.ev.Comm + ":" + uitoa(c.ev.TargetPID)
			if h.RuleKey != wantKey {
				t.Errorf("rule key = %q, want %q", h.RuleKey, wantKey)
			}
			if !strings.Contains(h.Title, c.want) {
				t.Errorf("title missing %q mnemonic: %q", c.want, h.Title)
			}
		})
	}
}

func TestMatchPtrace_CustomDebuggerAllowlist(t *testing.T) {
	// Operator runs an in-house profiler that uses ptrace. They want
	// it allowlisted alongside the defaults.
	t.Setenv("MILOG_PROBE_PTRACE_DEBUGGERS", "myprofiler,gdb")
	resetPtraceRulesCache()

	if hits := MatchPtrace(PtraceEvent{Comm: "myprofiler", TargetPID: 1, Request: 16}); len(hits) != 0 {
		t.Errorf("custom-allowlisted comm should be silent, got %+v", hits)
	}
	// Custom list REPLACES — so strace (default) is no longer silent.
	if hits := MatchPtrace(PtraceEvent{Comm: "strace", TargetPID: 1, Request: 16}); len(hits) != 1 {
		t.Errorf("custom allowlist replaces defaults; strace should now fire, got %+v", hits)
	}
}

func TestPtraceRequestName(t *testing.T) {
	cases := map[uint32]string{
		0:        "TRACEME",
		16:       "ATTACH",
		0x4206:   "SEIZE",
		0xdead:   "0xdead", // unexpected — fall back to hex
	}
	for v, want := range cases {
		if got := ptraceRequestName(v); got != want {
			t.Errorf("ptraceRequestName(0x%x) = %q, want %q", v, got, want)
		}
	}
}

// resetKmodRulesCache mirrors the others — clears parsed-config so
// each test can stage its own MILOG_PROBE_KMOD_ALLOWLIST.
func resetKmodRulesCache() {
	cachedKmodRules = kmodRules{}
	kmodRulesReady = false
}

func TestMatchKmod_DefaultsAllowKnownLoaders(t *testing.T) {
	// Defaults apply when the env var is UNSET (vs. the explicit-empty
	// case, which means "no allowlist at all"). os.Unsetenv plus a
	// cache reset stages the unset state cleanly — t.Setenv is no help
	// here because it sets, never unsets.
	if err := os.Unsetenv("MILOG_PROBE_KMOD_ALLOWLIST"); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}
	resetKmodRulesCache()

	cases := []KmodEvent{
		{Comm: "modprobe", Module: "nf_conntrack"},
		{Comm: "systemd-udevd", Module: "snd_hda_intel"},
		{Comm: "dkms", Module: "nvidia"},
		{Comm: "systemd-modules", Module: "ip_tables"},
	}
	for _, ev := range cases {
		if hits := MatchKmod(ev); len(hits) != 0 {
			t.Errorf("known loader should be silent: %+v → %+v", ev, hits)
		}
	}
}

func TestMatchKmod_NonAllowlistedFires(t *testing.T) {
	t.Setenv("MILOG_PROBE_KMOD_ALLOWLIST", "modprobe")
	resetKmodRulesCache()

	ev := KmodEvent{
		PID: 4242, UID: 0, Comm: "rootkit-installer", ParentComm: "sh",
		Module: "evil_lkm",
	}
	hits := MatchKmod(ev)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	wantKey := "proc:kmod_load:rootkit-installer:evil_lkm"
	if h.RuleKey != wantKey {
		t.Errorf("rule key = %q, want %q", h.RuleKey, wantKey)
	}
	if !strings.Contains(h.Title, "evil_lkm") {
		t.Errorf("title missing module name: %q", h.Title)
	}
}

func TestMatchKmod_ExplicitEmptyDisablesAllowlist(t *testing.T) {
	// Locked-down host pattern: kernel.modules_disabled=1 is set, so
	// any kmod load is signal. Operator sets MILOG_PROBE_KMOD_ALLOWLIST=""
	// (empty STRING, not unset) to disable the allowlist entirely.
	t.Setenv("MILOG_PROBE_KMOD_ALLOWLIST", "")
	resetKmodRulesCache()

	// modprobe (a default-allowlisted comm) should NOW fire.
	if hits := MatchKmod(KmodEvent{Comm: "modprobe", Module: "anything"}); len(hits) != 1 {
		t.Errorf("explicit-empty allowlist should make modprobe fire, got %d hits", len(hits))
	}
}

func TestMatchKmod_UnknownModuleNameFallback(t *testing.T) {
	// Defensive: if BPF couldn't read the module name (data_loc trick
	// failed on an exotic kernel), the alert should still emit with
	// a placeholder rather than a blank-name "load by …" title.
	t.Setenv("MILOG_PROBE_KMOD_ALLOWLIST", "modprobe")
	resetKmodRulesCache()

	hits := MatchKmod(KmodEvent{Comm: "weird-tool", Module: ""})
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if !strings.Contains(hits[0].Title, "<unknown>") {
		t.Errorf("expected <unknown> placeholder in title, got: %q", hits[0].Title)
	}
}

func TestMatchRetrans_BelowThresholdSilent(t *testing.T) {
	// Default threshold is 10 retransmits per window. A single-digit
	// count shouldn't fire — every healthy network sees a few
	// retransmits during connection setup.
	t.Setenv("MILOG_PROBE_RETRANS_THRESHOLD", "")
	cases := []RetransEvent{
		{DAddr: "1.2.3.4", DPort: 443, Count: 1, Window: 60 * time.Second},
		{DAddr: "1.2.3.4", DPort: 443, Count: 9, Window: 60 * time.Second},
		{DAddr: "::1", DPort: 80, Count: 0, Window: 60 * time.Second},
	}
	for _, ev := range cases {
		if hits := MatchRetrans(ev); len(hits) != 0 {
			t.Errorf("count=%d below threshold should not fire: %+v", ev.Count, hits)
		}
	}
}

func TestMatchRetrans_AtAndAboveThresholdFires(t *testing.T) {
	t.Setenv("MILOG_PROBE_RETRANS_THRESHOLD", "")
	cases := []RetransEvent{
		{DAddr: "203.0.113.42", DPort: 443, Count: 10, Window: 60 * time.Second},
		{DAddr: "203.0.113.42", DPort: 443, Count: 50, Window: 60 * time.Second},
		{DAddr: "2001:db8::1", DPort: 8080, Count: 100, Window: 30 * time.Second, IsIPv6: true},
	}
	for _, ev := range cases {
		hits := MatchRetrans(ev)
		if len(hits) != 1 {
			t.Fatalf("expected 1 hit for %+v, got %d: %+v", ev, len(hits), hits)
		}
		h := hits[0]
		wantKey := "net:retrans_spike:" + ev.DAddr + ":" + uitoa(uint32(ev.DPort))
		if h.RuleKey != wantKey {
			t.Errorf("rule key = %q, want %q", h.RuleKey, wantKey)
		}
		if !strings.Contains(h.Title, ev.DAddr) {
			t.Errorf("title missing destination %q: %q", ev.DAddr, h.Title)
		}
		if !strings.Contains(h.Body, "retrans=") {
			t.Errorf("body missing retrans=N counter: %q", h.Body)
		}
	}
}

func TestMatchRetrans_CustomThreshold(t *testing.T) {
	// Operator on a tight link wants to alert on much smaller spikes.
	t.Setenv("MILOG_PROBE_RETRANS_THRESHOLD", "3")

	// Count=3 fires now, count=2 doesn't.
	if hits := MatchRetrans(RetransEvent{DAddr: "1.1.1.1", DPort: 53, Count: 3, Window: 60 * time.Second}); len(hits) != 1 {
		t.Errorf("count=3 with threshold=3 should fire, got %d hits", len(hits))
	}
	if hits := MatchRetrans(RetransEvent{DAddr: "1.1.1.1", DPort: 53, Count: 2, Window: 60 * time.Second}); len(hits) != 0 {
		t.Errorf("count=2 with threshold=3 should NOT fire, got %d hits", len(hits))
	}
}

func TestMatchRetrans_MalformedThresholdFallsBackToDefault(t *testing.T) {
	// A garbage env value should NOT silently disable the rule. Fall
	// back to the default 10 so operators don't lose coverage from a
	// typo.
	t.Setenv("MILOG_PROBE_RETRANS_THRESHOLD", "not-a-number")
	if hits := MatchRetrans(RetransEvent{DAddr: "1.1.1.1", DPort: 80, Count: 11, Window: 60 * time.Second}); len(hits) != 1 {
		t.Errorf("malformed env should fall back to default 10; count=11 should fire, got %d hits", len(hits))
	}
	if hits := MatchRetrans(RetransEvent{DAddr: "1.1.1.1", DPort: 80, Count: 5, Window: 60 * time.Second}); len(hits) != 0 {
		t.Errorf("malformed env fall back to default 10; count=5 should NOT fire, got %d hits", len(hits))
	}
}

func TestUitoa64(t *testing.T) {
	cases := map[uint64]string{
		0:                    "0",
		1:                    "1",
		1234567890:           "1234567890",
		18446744073709551615: "18446744073709551615", // max uint64
	}
	for v, want := range cases {
		if got := uitoa64(v); got != want {
			t.Errorf("uitoa64(%d) = %q, want %q", v, got, want)
		}
	}
}

func TestWelford_TextbookValues(t *testing.T) {
	// Sample {1, 2, 3, 4, 5}: mean=3, sample-variance=2.5, σ=√2.5
	w := Welford{}
	for _, x := range []float64{1, 2, 3, 4, 5} {
		w.Update(x)
	}
	if w.N != 5 {
		t.Errorf("N = %d, want 5", w.N)
	}
	const eps = 1e-9
	if math.Abs(w.Mean-3.0) > eps {
		t.Errorf("Mean = %v, want 3.0", w.Mean)
	}
	if math.Abs(w.Variance()-2.5) > eps {
		t.Errorf("Variance = %v, want 2.5", w.Variance())
	}
	if math.Abs(w.Stddev()-math.Sqrt(2.5)) > eps {
		t.Errorf("Stddev = %v, want sqrt(2.5)", w.Stddev())
	}
}

func TestWelford_DegenerateCases(t *testing.T) {
	// n=0: variance is 0 (no data); n=1: variance is 0 (no spread).
	// Both used as the "no-σ-yet" sentinel by matchSyscallBurst.
	var w Welford
	if w.Variance() != 0 || w.Stddev() != 0 {
		t.Errorf("zero-sample Welford should report 0 variance/stddev")
	}
	w.Update(42)
	if w.N != 1 || w.Mean != 42 {
		t.Errorf("after one update: N=%d Mean=%v, want 1, 42", w.N, w.Mean)
	}
	if w.Variance() != 0 || w.Stddev() != 0 {
		t.Errorf("one-sample Welford should still report 0 spread, got Var=%v σ=%v", w.Variance(), w.Stddev())
	}
}

func TestMatchSyscallBurst_BurnInGate(t *testing.T) {
	// Even a 100σ spike should not fire while still in burn-in.
	t.Setenv("MILOG_PROBE_SYSCALL_FLOOR", "")
	t.Setenv("MILOG_PROBE_SYSCALL_BURNIN", "")

	ev := RateAnomalyEvent{
		PID: 1234, Comm: "miner",
		Count:   1_000_000, // huge spike
		Mean:    1000,
		Stddev:  100,
		Window:  60 * time.Second,
		Samples: 5, // below default burn-in (10)
	}
	if hits := MatchRateAnomaly(ev); len(hits) != 0 {
		t.Errorf("burn-in gate should suppress: got %d hits", len(hits))
	}
}

func TestMatchSyscallBurst_FloorGate(t *testing.T) {
	// A small absolute count shouldn't fire even if it's many σ
	// above a near-zero baseline. Floor protects against the
	// "infinite-σ on idle" pathology.
	t.Setenv("MILOG_PROBE_SYSCALL_FLOOR", "")
	t.Setenv("MILOG_PROBE_SYSCALL_BURNIN", "")

	ev := RateAnomalyEvent{
		PID: 1234, Comm: "idle-daemon",
		Count:   500, // below default floor (1000)
		Mean:    1,
		Stddev:  1,
		Window:  60 * time.Second,
		Samples: 100, // well past burn-in
	}
	if hits := MatchRateAnomaly(ev); len(hits) != 0 {
		t.Errorf("floor gate should suppress: got %d hits", len(hits))
	}
}

func TestMatchSyscallBurst_SpikeAboveBaselineFires(t *testing.T) {
	t.Setenv("MILOG_PROBE_SYSCALL_FLOOR", "")
	t.Setenv("MILOG_PROBE_SYSCALL_BURNIN", "")

	// Process normally does ~5000 syscalls/min ± ~500. 50000 is
	// 90σ above mean, well past 3σ, well past floor (1000), past
	// burn-in (10).
	ev := RateAnomalyEvent{
		PID: 4242, PPID: 1, UID: 33,
		Comm: "php-fpm8.2", ParentComm: "nginx",
		Count:   50_000,
		Mean:    5_000,
		Stddev:  500,
		Window:  60 * time.Second,
		Samples: 60, // 1 hour past burn-in
	}
	hits := MatchRateAnomaly(ev)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	wantKey := "process:syscall_burst:php-fpm8.2:4242"
	if h.RuleKey != wantKey {
		t.Errorf("rule key = %q, want %q", h.RuleKey, wantKey)
	}
	if !strings.Contains(h.Title, "php-fpm8.2") {
		t.Errorf("title missing comm: %q", h.Title)
	}
	// 50000 / 60s = 833.3/s
	if !strings.Contains(h.Title, "833") {
		t.Errorf("title missing rate ≈833/s: %q", h.Title)
	}
}

func TestMatchSyscallBurst_BelowSigmaSilent(t *testing.T) {
	t.Setenv("MILOG_PROBE_SYSCALL_FLOOR", "")
	t.Setenv("MILOG_PROBE_SYSCALL_BURNIN", "")

	// Sample within 2σ of the mean — normal jitter, not anomaly.
	ev := RateAnomalyEvent{
		PID: 1234, Comm: "nginx",
		Count:   12_000, // mean=10000, σ=1000 → 2σ
		Mean:    10_000,
		Stddev:  1_000,
		Window:  60 * time.Second,
		Samples: 60,
	}
	if hits := MatchRateAnomaly(ev); len(hits) != 0 {
		t.Errorf("2σ jitter should NOT fire, got %d hits", len(hits))
	}
}

func TestMatchSyscallBurst_CustomFloor(t *testing.T) {
	// Operator on a tightly-locked-down host expects all processes
	// to be near-idle; anything over 100 syscalls/window is signal.
	t.Setenv("MILOG_PROBE_SYSCALL_FLOOR", "100")
	t.Setenv("MILOG_PROBE_SYSCALL_BURNIN", "")

	ev := RateAnomalyEvent{
		PID: 1234, Comm: "weird-binary",
		Count:   500,
		Mean:    10,
		Stddev:  3,
		Window:  60 * time.Second,
		Samples: 60,
	}
	if hits := MatchRateAnomaly(ev); len(hits) != 1 {
		t.Errorf("custom-floor 100, count=500 should fire, got %d hits", len(hits))
	}
}

func TestMatchSyscallBurst_ZeroWindowSafe(t *testing.T) {
	// Defensive: a config bug or test passing Window=0 must not
	// cause divide-by-zero or a NaN-laced alert title.
	t.Setenv("MILOG_PROBE_SYSCALL_FLOOR", "")
	t.Setenv("MILOG_PROBE_SYSCALL_BURNIN", "")

	ev := RateAnomalyEvent{
		PID: 1234, Comm: "x",
		Count: 100_000, Mean: 100, Stddev: 10,
		Window: 0, Samples: 60,
	}
	if hits := MatchRateAnomaly(ev); len(hits) != 0 {
		t.Errorf("zero window should be suppressed defensively, got %+v", hits)
	}
}
