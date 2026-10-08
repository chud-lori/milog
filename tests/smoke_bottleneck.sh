#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() { printf 'smoke_bottleneck: %s\n' "$1" >&2; exit 1; }

export LC_ALL=C TZ=UTC
mkdir -p "$tmp/home" "$tmp/logs"
unset MILOG_APPS MILOG_CONFIG
export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"

# default run: exits 0 with a verdict line, no nginx apps needed.
"$ROOT/milog.sh" bottleneck >"$tmp/plain" 2>"$tmp/err" \
    || fail "bottleneck exited non-zero: $(cat "$tmp/err")"
grep -Eq '^BOTTLENECK:|No resource saturation detected' "$tmp/plain" \
    || fail "bottleneck printed no verdict line: $(cat "$tmp/plain")"

# --json: exits 0 and emits valid JSON.
"$ROOT/milog.sh" bottleneck --json >"$tmp/json" 2>"$tmp/err" \
    || fail "bottleneck --json exited non-zero: $(cat "$tmp/err")"
if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; json.load(sys.stdin)' <"$tmp/json" \
        || fail "bottleneck --json is not valid JSON: $(cat "$tmp/json")"
elif command -v jq >/dev/null 2>&1; then
    jq . <"$tmp/json" >/dev/null \
        || fail "bottleneck --json is not valid JSON: $(cat "$tmp/json")"
else
    printf 'smoke_bottleneck: python3 and jq missing, JSON validation skipped\n' >&2
fi

# invalid arg: non-zero exit with a usage message on stderr.
if "$ROOT/milog.sh" bottleneck --nope >"$tmp/out" 2>"$tmp/err"; then
    fail "bottleneck --nope should exit non-zero"
fi
grep -qi 'usage' "$tmp/err" \
    || fail "bottleneck --nope should print usage to stderr: $(cat "$tmp/err")"

# no stray escapes: strip the known color SGR codes, nothing else may carry ESC.
esc=$(printf '\033')
if sed "s/${esc}\[[0-9;]*m//g" "$tmp/plain" | grep -q "$esc"; then
    fail "bottleneck output carries a non-color ESC byte"
fi

printf 'smoke_bottleneck: ok\n'
