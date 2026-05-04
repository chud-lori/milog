package probe

import "testing"

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
