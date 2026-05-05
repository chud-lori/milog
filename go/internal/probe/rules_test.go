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
