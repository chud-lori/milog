package probe

import (
	"os"
	"strconv"
	"strings"
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

// WebTriggeredExec reads alerts.log for an exploit or 5xx fire near at, the
// time e was seen. The mtime check keeps the common case to one stat.
func WebTriggeredExec(e Event, alertsLog string, at time.Time) (Hit, bool) {
	if !FromWebWorker(e) {
		return Hit{}, false
	}
	window := webExecWindow()
	fi, err := os.Stat(alertsLog)
	if err != nil || fi.ModTime().Before(at.Add(-window)) {
		return Hit{}, false
	}
	rows, err := alertlog.Load(alertsLog, at.Add(-window).Unix(), 0)
	if err != nil {
		return Hit{}, false
	}
	return matchWebTriggeredExec(e, rows, at, window)
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
	return Hit{
		RuleKey: "process:web_triggered_exec:" + e.ParentComm + ":" + e.Comm,
		Title:   "Web-triggered exec: " + e.ParentComm + " → " + e.Comm + " after " + prev.Rule,
		Body: "```pid=" + uitoa(e.PID) + " ppid=" + uitoa(e.PPID) +
			" uid=" + uitoa(e.UID) + " comm=" + e.Comm +
			" parent=" + e.ParentComm + " exe=" + e.Filename +
			"\npreceding " + prev.Rule + " at " + strconv.FormatInt(prev.TS, 10) +
			": " + sanitizeRequest(prev.Body) + "```",
	}, true
}

// sanitizeRequest strips backticks so the alerts.log body can't close the fence,
// and control characters so it can't carry terminal escapes.
func sanitizeRequest(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '`' || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
