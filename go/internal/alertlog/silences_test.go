package alertlog

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSilences_RoundTrip(t *testing.T) {
	f := filepath.Join(t.TempDir(), "milog", "alerts.silences")
	now := time.Unix(1_800_000_000, 0)
	t.Setenv("USER", "alice")

	if _, err := AddSilence(f, "exploit:*", time.Hour, "pentest\tin progress", now); err != nil {
		t.Fatal(err)
	}
	if _, err := AddSilence(f, "5xx:api", 2*time.Hour, "", now); err != nil {
		t.Fatal(err)
	}
	// Re-silencing extends the existing row instead of adding a second one.
	if _, err := AddSilence(f, "exploit:*", 3*time.Hour, "longer", now); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(f)
	want := "5xx:api\t1800007200\t1800000000\talice\t\n" +
		"exploit:*\t1800010800\t1800000000\talice\tlonger\n"
	if string(raw) != want {
		t.Fatalf("file:\n%q\nwant\n%q", raw, want)
	}

	got, err := LoadSilences(f, now)
	if err != nil || len(got) != 2 {
		t.Fatalf("LoadSilences: %v %+v", err, got)
	}
	if got[1] != (Silence{Key: "exploit:*", Until: 1800010800, Added: 1800000000, AddedBy: "alice", Message: "longer"}) {
		t.Errorf("row: %+v", got[1])
	}

	if active, _ := LoadSilences(f, now.Add(150*time.Minute)); len(active) != 1 || active[0].Key != "exploit:*" {
		t.Errorf("expired row still active: %+v", active)
	}

	if removed, err := RemoveSilence(f, "5xx:api"); err != nil || !removed {
		t.Fatalf("RemoveSilence: %v %v", removed, err)
	}
	if removed, _ := RemoveSilence(f, "5xx:api"); removed {
		t.Error("second remove reported a match")
	}
	if left, _ := LoadSilences(f, now); len(left) != 1 || left[0].Key != "exploit:*" {
		t.Errorf("after remove: %+v", left)
	}
	if matches, _ := filepath.Glob(f + ".*"); len(matches) != 0 {
		t.Errorf("temp files left behind: %v", matches)
	}
}

func TestSilences_AddDropsExpiredAndMalformedRows(t *testing.T) {
	f := filepath.Join(t.TempDir(), "alerts.silences")
	now := time.Unix(1_800_000_000, 0)
	os.WriteFile(f, []byte("old\t1700000000\t1690000000\tbob\t\njunk\n"), 0o600)
	if _, err := AddSilence(f, "probe:api", time.Minute, "", now); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(f)
	if strings.Contains(string(raw), "old") || strings.Contains(string(raw), "junk") {
		t.Errorf("stale rows kept:\n%s", raw)
	}
}

func TestSilences_RejectsBadInput(t *testing.T) {
	f := filepath.Join(t.TempDir(), "alerts.silences")
	if _, err := AddSilence(f, "a\tb", time.Hour, "", time.Now()); err == nil {
		t.Error("tab in key accepted")
	}
	if _, err := AddSilence(f, "a", 0, "", time.Now()); err == nil {
		t.Error("zero duration accepted")
	}
}

func TestParseDuration(t *testing.T) {
	ok := map[string]time.Duration{
		"300": 300 * time.Second, "30s": 30 * time.Second, "5m": 5 * time.Minute,
		"2H": 2 * time.Hour, "1d": 24 * time.Hour,
	}
	for in, want := range ok {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "h", "-5m", "1.5h", "2w", "abc"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("ParseDuration(%q): expected error", in)
		}
	}
}

func TestSilence_Matches(t *testing.T) {
	s := Silence{Key: "exploit:*"}
	if !s.Matches("exploit:api:sqli") || s.Matches("probe:api") {
		t.Error("glob match wrong")
	}
	if !(Silence{Key: "5xx:api"}).Matches("5xx:api") {
		t.Error("exact match wrong")
	}
}

// Bash `milog silence list` must read what AddSilence wrote.
func TestSilences_BashListReadsGoWrite(t *testing.T) {
	script, _ := filepath.Abs("../../../milog.sh")
	if _, err := os.Stat(script); err != nil {
		t.Skip("milog.sh not found")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	home := t.TempDir()
	t.Setenv("USER", "gotest")
	f := filepath.Join(home, ".cache", "milog", "alerts.silences")
	if _, err := AddSilence(f, "exploit:*", time.Hour, "written by go", time.Now()); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bash, script, "silence", "list")
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "USER=gotest", "TERM=dumb"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("milog silence list: %v\n%s", err, out)
	}
	for _, want := range []string{"exploit:*", "gotest", "written by go"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("silence list missing %q:\n%s", want, out)
		}
	}
}
