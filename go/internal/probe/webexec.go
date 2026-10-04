package probe

import (
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/chud-lori/milog/internal/alertlog"
)

// WebExecGrace is how long the caller waits before WebTriggeredExec, because
// the bash exploit watcher records the request that caused an exec after the exec itself.
const WebExecGrace = 3 * time.Second

// defaultWebExecWindow is in seconds; tune with MILOG_PROBE_WEB_EXEC_WINDOW.
const defaultWebExecWindow = 30

func webExecWindow() time.Duration {
	n, err := strconv.ParseUint(os.Getenv("MILOG_PROBE_WEB_EXEC_WINDOW"), 10, 32)
	if err != nil || n == 0 {
		n = defaultWebExecWindow
	}
	return time.Duration(n) * time.Second
}

// FromWebWorker reports whether e's parent is a web server process.
func FromWebWorker(e Event) bool {
	_, ok := webWorkerComms[e.ParentComm]
	return ok
}

// Bash rotates alerts.log at 10 MB, so a bigger file isn't one milog wrote.
const (
	alertsLogMaxBytes = 16 << 20
	alertsTailBytes   = 64 << 10
)

// WebTriggeredExec reads alerts.log for an exploit or 5xx fire near at, the
// time e was seen. The mtime check keeps the common case to one stat.
func WebTriggeredExec(e Event, alertsLog string, at time.Time) (Hit, bool) {
	if !FromWebWorker(e) {
		return Hit{}, false
	}
	window := webExecWindow()
	rows, ok := readAlertsTail(alertsLog, at.Add(-window).Unix())
	if !ok {
		return Hit{}, false
	}
	return matchWebTriggeredExec(e, rows, at, window)
}

// readAlertsTail parses the last alertsTailBytes of alerts.log when it was
// modified at or after since. The file is user-writable and the probe is root,
// so FIFOs, symlinks and oversized files are refused.
func readAlertsTail(path string, since int64) ([]alertlog.Row, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > alertsLogMaxBytes || fi.ModTime().Unix() < since {
		return nil, false
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	// The path can be swapped between Lstat and open.
	if ofi, err := f.Stat(); err != nil || !os.SameFile(fi, ofi) {
		return nil, false
	}
	off := max(fi.Size()-alertsTailBytes, 0)
	buf := make([]byte, fi.Size()-off)
	n, err := f.ReadAt(buf, off)
	if err != nil && err != io.EOF {
		return nil, false
	}
	lines := strings.Split(string(buf[:n]), "\n")
	if off > 0 {
		lines = lines[1:] // partial line
	}
	var rows []alertlog.Row
	for _, l := range lines {
		if r, ok := alertlog.ParseRow(l); ok && r.TS >= since {
			rows = append(rows, r)
		}
	}
	return rows, true
}

// matchWebTriggeredExec takes the newest exploit or 5xx row from window
// before at up to WebExecGrace after it.
func matchWebTriggeredExec(e Event, rows []alertlog.Row, at time.Time, window time.Duration) (Hit, bool) {
	from := at.Add(-window).Unix()
	until := at.Add(WebExecGrace).Unix()
	var prev *alertlog.Row
	for i := range rows {
		r := &rows[i]
		if r.TS < from || r.TS > until {
			continue
		}
		if !strings.HasPrefix(r.Rule, "exploit:") && !strings.HasPrefix(r.Rule, "5xx:") {
			continue
		}
		if prev == nil || r.TS >= prev.TS {
			prev = r
		}
	}
	if prev == nil {
		return Hit{}, false
	}
	rule := sanitizeRequest(prev.Rule)
	return Hit{
		RuleKey: "process:web_triggered_exec:" + e.ParentComm + ":" + e.Comm,
		Title:   "Web-triggered exec: " + e.ParentComm + " → " + e.Comm + " after " + rule,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " exe=" + e.Filename +
			"\npreceding " + rule + " at " + strconv.FormatInt(prev.TS, 10) +
			": " + sanitizeRequest(prev.Body) + "```",
	}, true
}

// sanitizeRequest strips backticks so alerts.log text can't close the fence,
// and control characters so it can't carry terminal escapes.
func sanitizeRequest(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '`' || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
