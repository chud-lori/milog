#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
pid=""

cleanup() {
    if [[ -n "$pid" ]]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() { printf 'smoke_mode_scripts: %s\n' "$1" >&2; exit 1; }

export LC_ALL=C TZ=UTC
mkdir -p "$tmp/home/.config/milog" "$tmp/logs"
export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_HISTORY_DB="$tmp/metrics.db"

# Combined-format line: ip epoch status [user-agent]
line() {
    printf '%s - - [%(%d/%b/%Y:%H:%M:%S)T +0000] "GET / HTTP/1.1" %s 12 "-" "%s"\n' "$1" "$2" "$3" "${4:-curl}"
}

now=$(printf '%(%s)T' -1)
minute=$(( now / 60 * 60 - 3600 ))
two_days_ago=$(( now - 2 * 86400 ))

# probes: more apps than colours must not trip set -u.
apps=(app1 app2 app3 app4 app5 app6 app7)
for app in "${apps[@]}"; do
    : > "$tmp/logs/${app}.access.log"
done
MILOG_APPS="${apps[*]}" "$ROOT/milog.sh" probes >"$tmp/out" 2>"$tmp/err" &
pid=$!
sleep 1
kill -0 "$pid" 2>/dev/null || fail "probes exited early: $(cat "$tmp/err")"
grep -q 'unbound variable' "$tmp/err" && fail "probes: $(cat "$tmp/err")"
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
pid=""
rm -f "$tmp"/logs/app*.access.log

{
    line 10.0.0.1 "$minute" 200
    line 10.0.0.1 "$(( minute + 30 ))" 404
    # UA carries the bucketed minute but the row belongs to two days ago.
    line 10.0.0.9 "$two_days_ago" 500 "bot $(printf '%(%d/%b/%Y:%H:%M)T' "$minute")"
} > "$tmp/logs/api.access.log"
export MILOG_APPS="nginx:api"

# config validate: AUDIT_* keys are known.
printf 'AUDIT_ENABLED=1\nAUDIT_YARA_PATHS=(/srv)\n' > "$HOME/.config/milog/config.sh"
out=$("$ROOT/milog.sh" config validate 2>&1 || true)
grep -q 'unknown key: AUDIT_' <<< "$out" && fail "config validate flags AUDIT_ keys"
rm -f "$HOME/.config/milog/config.sh"

# doctor: a live web pidfile is reported as running.
mkdir -p "$HOME/.cache/milog"
printf '%s\n' "$$" > "$HOME/.cache/milog/web.pid"
out=$("$ROOT/milog.sh" doctor 2>&1 || true)
grep -q "milog web running  (pid=$$" <<< "$out" || fail "doctor did not see running web pid"
rm -f "$HOME/.cache/milog/web.pid"

# stats: hourly buckets with the system awk.
out=$(MILOG_APPS=api "$ROOT/milog.sh" stats api 2>&1) || fail "stats failed: $out"
grep -q "$(printf '%(%H)T' "$minute"):00 .* 2\$" <<< "$out" || fail "stats missing hour bucket: $out"

# digest: the window actually filters rows.
req_for() { "$ROOT/milog.sh" digest "$1" | awk '$1 == "api" {print $2}'; }
[[ "$(req_for 1d)" == "2" ]] || fail "digest 1d REQ=$(req_for 1d), want 2"
[[ "$(req_for week)" == "3" ]] || fail "digest week REQ=$(req_for week), want 3"

if command -v sqlite3 >/dev/null 2>&1; then
    # history: typed entry reads the right file and buckets on the stamp field.
    bash -c '
        . "$1" help >/dev/null
        HISTORY_ENABLED=1
        history_init >/dev/null 2>&1
        history_write_minute "$2" "$(_cur_time_at "$2")"
        history_write_hour "$(( $2 / 3600 * 3600 ))"
    ' _ "$ROOT/milog.sh" "$minute"
    got=$(sqlite3 "$MILOG_HISTORY_DB" "SELECT app, req, c4xx FROM metrics_minute; SELECT ip, hits FROM top_ip_hour;")
    want=$'nginx:api|2|1\n10.0.0.1|2'
    [[ "$got" == "$want" ]] || fail "history rows: $got"

    # anomaly: baseline follows local minute-of-day across a DST change.
    rm -f "$MILOG_HISTORY_DB"
    (
        export TZ='EST5EDT,M3.2.0,M11.1.0'
        at() { sqlite3 :memory: "SELECT strftime('%s', '$1 10:00', 'utc');"; }
        bash -c '. "$1" help >/dev/null; HISTORY_ENABLED=1; history_init >/dev/null 2>&1' _ "$ROOT/milog.sh"
        for d in 05 06 07 08 09 10 11; do
            sqlite3 "$MILOG_HISTORY_DB" "INSERT INTO metrics_minute VALUES ($(at "2026-03-$d"), 'api', $(( 10#$d % 2 + 20 )), 0, 0, 0, 0, NULL, NULL, NULL);"
        done
        cur=$(at 2026-03-12)
        sqlite3 "$MILOG_HISTORY_DB" "INSERT INTO metrics_minute VALUES ($cur, 'api', 500, 0, 0, 0, 0, NULL, NULL, NULL);"
        bash -c '
            alerts="$2"
            . "$1" help >/dev/null
            HISTORY_ENABLED=1 ANOMALY_ENABLED=1 ANOMALY_MIN_DAYS=7
            LOGS=(api)
            alert_should_fire() { return 0; }
            alert_fire() { printf "%s\n" "$1" >> "$alerts"; }
            _anomaly_check_minute "$3"
        ' _ "$ROOT/milog.sh" "$tmp/alerts" "$cur"
    )
    grep -q 'Anomaly: request rate on api' "$tmp/alerts" 2>/dev/null || fail "anomaly did not fire across DST"
else
    printf 'smoke_mode_scripts: sqlite3 missing, history/anomaly skipped\n' >&2
fi

printf 'smoke_mode_scripts: ok\n'
