// Package sysstat reads CPU (/proc/stat), memory (/proc/meminfo) and disk
// (statfs). Off Linux the /proc readers return zeros without error.
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

// CPU returns busy percent from two /proc/stat reads 100 ms apart.
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
	// iowait counts as idle.
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

// readStat sums the first `cpu` line of /proc/stat:
// user nice system idle iowait irq softirq steal guest guest_nice.
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
		if i == 3 || i == 4 {
			s.idle += n
		}
	}
	return s, nil
}

// Mem prefers MemAvailable (kernel 3.14+) and falls back to MemFree.
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

// parseMeminfoKB reads the number from a "KeyName: 12345 kB" line.
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

// DiskAt returns usage for the filesystem containing path.
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
