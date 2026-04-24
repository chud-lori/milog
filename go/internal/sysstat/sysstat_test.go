package sysstat

import "testing"

func TestParseMeminfoKB(t *testing.T) {
	cases := map[string]int64{
		"MemTotal:       16334088 kB": 16334088,
		"MemAvailable:    8080728 kB": 8080728,
		"garbage":                      0,
		"MemTotal:":                    0,
	}
	for in, want := range cases {
		if got := parseMeminfoKB(in); got != want {
			t.Errorf("parseMeminfoKB(%q): got %d want %d", in, got, want)
		}
	}
}

func TestDiskAt_CurrentDir(t *testing.T) {
	d, err := DiskAt(".")
	if err != nil {
		t.Fatalf("DiskAt: %v", err)
	}
	if d.TotalGB <= 0 {
		t.Errorf("TotalGB should be > 0, got %d", d.TotalGB)
	}
	if d.Pct < 0 || d.Pct > 100 {
		t.Errorf("Pct out of range: %d", d.Pct)
	}
}

func TestCPU_NonLinuxReturnsZero(t *testing.T) {
	// Not a strict check — on Linux CPU() returns a number; on darwin it
	// returns 0,nil. Either is acceptable. Just confirm no panic.
	_, err := CPU()
	if err != nil {
		t.Errorf("CPU unexpected error: %v", err)
	}
}

func TestMem_NonLinuxReturnsZero(t *testing.T) {
	m, err := Mem()
	if err != nil {
		t.Errorf("Mem unexpected error: %v", err)
	}
	_ = m // zero value on darwin is fine
}
