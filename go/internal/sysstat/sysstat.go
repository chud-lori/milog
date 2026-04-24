// Package sysstat reads host metrics for MiLog's dashboard.
//
// CPU: sampled via /proc/stat delta — two reads 100ms apart. Memory:
// /proc/meminfo. Disk: syscall.Statfs on the given path.
//
// On darwin (dev machines) the /proc-based readers return zero values
// without error — the binary is still exercisable for development, the
// dashboard just shows 0% until deployed on Linux.
package sysstat

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Memory struct {
	Pct     int   // % used
	UsedMB  int64 // used (MemTotal - MemAvailable) in MiB
	TotalMB int64 // total in MiB
}

type Disk struct {
	Pct     int   // % used
	UsedGB  int64 // used in GiB
	TotalGB int64 // total in GiB
}

// CPU returns the instantaneous CPU-busy percentage. Two samples 100 ms
// apart — adequate for a 3-second dashboard poll. SSE will want a
// background sampler; that's a future refactor.
func CPU() (int, error) {
	if runtime.GOOS != "linux" {
		return 0, nil
	}
	a, err := readStat()
	if err != nil {
		return 0, err
	}
	time.Sleep(100 * time.Millisecond)
	b, err := readStat()
	if err != nil {
		return 0, err
	}
	// idle includes iowait (4th field); everything else is "busy".
	busyDelta := (b.total - b.idle) - (a.total - a.idle)
	totalDelta := b.total - a.total
	if totalDelta <= 0 {
		return 0, nil
	}
	pct := int(float64(busyDelta) / float64(totalDelta) * 100.0)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct, nil
}

type cpuSample struct{ total, idle uint64 }

// readStat reads the first `cpu ...` line of /proc/stat and sums fields.
// Field order (Linux): user nice system idle iowait irq softirq steal guest guest_nice
func readStat() (cpuSample, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return cpuSample{}, fmt.Errorf("/proc/stat empty")
	}
	line := sc.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return cpuSample{}, fmt.Errorf("unexpected /proc/stat: %q", line)
	}
	fields := strings.Fields(line)[1:]
	var s cpuSample
	for i, v := range fields {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return cpuSample{}, err
		}
		s.total += n
		// idle = field 3 (0-indexed) ; include iowait (field 4) as "not busy"
		if i == 3 || i == 4 {
			s.idle += n
		}
	}
	return s, nil
}

// Mem returns memory usage. Uses MemAvailable when available (kernel >=
// 3.14, ubiquitous now); falls back to MemFree on older kernels.
func Mem() (Memory, error) {
	if runtime.GOOS != "linux" {
		return Memory{}, nil
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return Memory{}, err
	}
	defer f.Close()

	var total, available, free int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = parseMeminfoKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			available = parseMeminfoKB(line)
		case strings.HasPrefix(line, "MemFree:"):
			free = parseMeminfoKB(line)
		}
	}
	if total == 0 {
		return Memory{}, fmt.Errorf("/proc/meminfo missing MemTotal")
	}
	avail := available
	if avail == 0 {
		avail = free // fallback for older kernels
	}
	used := total - avail
	pct := int(float64(used) / float64(total) * 100.0)
	return Memory{
		Pct:     pct,
		UsedMB:  used / 1024,
		TotalMB: total / 1024,
	}, nil
}

// parseMeminfoKB extracts the numeric kB value from a /proc/meminfo line
// shaped "KeyName: 12345 kB".
func parseMeminfoKB(line string) int64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// DiskAt returns disk usage for the filesystem containing `path`. Uses
// statfs — works on both Linux and darwin without code branches.
func DiskAt(path string) (Disk, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return Disk{}, err
	}
	blockSize := uint64(s.Bsize)
	total := blockSize * uint64(s.Blocks)
	avail := blockSize * uint64(s.Bavail)
	used := total - avail
	if total == 0 {
		return Disk{}, nil
	}
	pct := int(float64(used) / float64(total) * 100.0)
	return Disk{
		Pct:     pct,
		UsedGB:  int64(used) / (1024 * 1024 * 1024),
		TotalGB: int64(total) / (1024 * 1024 * 1024),
	}, nil
}
