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

fail() {
    printf 'smoke_tty_escapes: %s\n' "$1" >&2
    printf '%s\n' '--- output ---' >&2
    cat -v "$2" >&2 || true
    exit 1
}

# Output must carry no OSC/CSI/BEL from the log; milog's own SGR colours (ESC[..m) are allowed.
check_inert() {
    local out="$1"
    if LC_ALL=C grep -Eq $'\033\\]|\a|\033\\[[0-9;]*[A-Za-ln-z]|\302\233' "$out"; then
        fail "log-derived escape reached the terminal" "$out"
    fi
    grep -q '?]0;pwned?' "$out" || fail "sanitised OSC not shown" "$out"
}

mkdir -p "$tmp/home" "$tmp/logs"
export HOME="$tmp/home"
log="$tmp/logs/app1.access.log"
ip="203.0.113.9"
ua=$'curl \033]0;pwned\007 \033[2J\033[1A \302\233 31m'
printf '%s - - [03/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 12 "-" "%s"\n' "$ip" "$ua" > "$log"

MILOG_LOG_DIR="$tmp/logs" MILOG_APPS="app1" \
    "$ROOT/milog.sh" attacker "$ip" > "$tmp/attacker.out" 2>&1
check_inert "$tmp/attacker.out"

MILOG_LOG_DIR="$tmp/logs" MILOG_APPS="app1" \
    "$ROOT/milog.sh" exploits > "$tmp/exploits.out" 2>&1 &
pid=$!
sleep 1
printf '%s - - [03/Oct/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 12 "-" "%s"\n' "$ip" "$ua" >> "$log"
sleep 2
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
pid=""
grep -q 'EXPLOIT' "$tmp/exploits.out" || fail "exploits printed no match" "$tmp/exploits.out"
check_inert "$tmp/exploits.out"

printf 'smoke_tty_escapes: ok\n'
