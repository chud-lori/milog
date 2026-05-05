package probe

import (
	"strings"
	"testing"
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
