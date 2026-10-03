#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

mkdir -p "$tmp/home/.config/milog" "$tmp/logs" "$tmp/watch"
: > "$tmp/logs/app.access.log"
: > "$tmp/watch/known"
printf 'AUDIT_PERSISTENCE_PATHS=(%q)\n' "$tmp/watch/*" > "$tmp/home/.config/milog/config.sh"

export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"
export MILOG_AUDIT_ENABLED=1
export MILOG_AUDIT_PERSISTENCE_INTERVAL=0
export MILOG_AUDIT_PORTS_INTERVAL=0
state="$tmp/home/.cache/milog/audit"

"$ROOT/milog.sh" audit persistence baseline >/dev/null
"$ROOT/milog.sh" audit ports baseline >/dev/null

# `check` reads the diff through $(...), the daemon tick through <(...).
for _ in 1 2 3; do
    "$ROOT/milog.sh" audit persistence check >/dev/null
    "$ROOT/milog.sh" audit ports check >/dev/null
done

: > "$tmp/watch/dropped"
bash -c '
    alerts="$2"
    . "$1" help >/dev/null
    alert_should_fire() { return 0; }
    alert_fire() { printf "%s\n" "$1" >> "$alerts"; }
    for _ in 1 2 3; do
        _audit_persistence_tick
        _audit_ports_tick
    done
    wait
' _ "$ROOT/milog.sh" "$tmp/alerts"

shopt -s nullglob
leftovers=( "$state"/*.current.* "$state"/*.sortedb.* )
if (( ${#leftovers[@]} > 0 )); then
    printf 'audit diff left temp files behind:\n' >&2
    printf '  %s\n' "${leftovers[@]}" >&2
    exit 1
fi

if ! grep -qF "Persistence: new $tmp/watch/dropped" "$tmp/alerts" 2>/dev/null; then
    printf 'persistence tick did not alert on a new file\n' >&2
    exit 1
fi

printf 'smoke_audit_tempfiles: ok\n'
