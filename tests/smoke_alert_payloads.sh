#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

command -v python3 >/dev/null 2>&1 || { printf 'smoke_alert_payloads: python3 required\n' >&2; exit 1; }

mkdir -p "$tmp/home" "$tmp/logs" "$tmp/out"
: > "$tmp/logs/app.access.log"
export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"

. "$ROOT/milog.sh" help >/dev/null

failures=0
fail() { printf 'FAIL: %s\n' "$*" >&2; failures=$(( failures + 1 )); }

# Capture each POST body instead of sending it.
dest="" curl_rc=0
curl() {
    while (( $# )); do
        [[ "$1" == -d ]] && printf '%s' "$2" > "$tmp/out/$dest"
        shift
    done
    (( curl_rc )) && printf '\n000' || printf '\n204'
    return "$curl_rc"
}

# Placeholders, quotes, backslashes, \xHH, C0 controls, backticks, length.
ctl=""
for (( i=1; i<32; i++ )); do
    printf -v h '%02x' "$i"
    printf -v c "\\x$h"
    ctl+="$c"
done
body="GET /%SEV%/%BODY%/%TITLE%/%RULE%?a=1&b=\"x\" \\ /a\\x22b ${ctl} \`\`\` @everyone <b>x</b> é"
body+="$(printf 'A%.0s' {1..5000})"
title="Exploit attempt: app / %BODY% \"q\""

export DISCORD_WEBHOOK=http://x SLACK_WEBHOOK=http://x TELEGRAM_BOT_TOKEN=t TELEGRAM_CHAT_ID=1
export MATRIX_HOMESERVER=http://x MATRIX_TOKEN=t MATRIX_ROOM='!r:x' WEBHOOK_URL=http://x
export WEBHOOK_TEMPLATE='{"title":%TITLE%,"body":%BODY%,"severity":%SEV%,"rule":%RULE%,"pct":"100%"}'

for dest in discord slack telegram matrix webhook; do
    "_alert_send_$dest" "$title" "$body" 15158332 "exploit:app:sqli"
    python3 -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$tmp/out/$dest" 2>/dev/null \
        || fail "$dest payload is not valid JSON"
done

printf '%s' "$title" > "$tmp/title"
printf '%s' "$body" > "$tmp/body"
python3 - "$tmp/out/webhook" "$tmp/title" "$tmp/body" <<'PY' || fail "webhook template did not round-trip"
import json, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
title = open(sys.argv[2], encoding="utf-8", newline="").read()
body = open(sys.argv[3], encoding="utf-8", newline="").read()
assert p == {"title": title, "body": body, "severity": "crit", "rule": "exploit:app:sqli", "pct": "100%"}
PY

fenced=$(_alert_fence "$body")
ticks="${fenced//[^\`]/}"
[[ ${#ticks} -eq 6 ]] || fail "_alert_fence left ${#ticks} backticks (want 6)"

# Delivery failures are recorded, not swallowed.
curl_rc=22 dest=discord
_alert_send_discord "t" "b"
grep -q $'\tdiscord\t000$' "$ALERT_STATE_DIR/send_failures.log" 2>/dev/null \
    || fail "failed send was not recorded"

# Dedup keys holding nginx \xHH escapes must match their stored row.
fp='203.0.113.9:/a\x22b'
alert_fingerprint_fresh "$fp" || fail "first fingerprint should fire"
if alert_fingerprint_fresh "$fp"; then fail "repeat fingerprint with \\x22 was not deduped"; fi
alert_fingerprint_fresh '203.0.113.9:/ax22b' || fail "distinct fingerprint was suppressed"

# Status class comes from the status field, not a status-like token elsewhere.
ts="03/Oct/2026:10:00"
{
    printf '203.0.113.9 - - [%s:01 +0000] "GET /x 200 y HTTP/1.1" 404 153 "-" "ua"\n' "$ts"
    printf '203.0.113.9 - - [%s:02 +0000] "GET /a 500 b HTTP/1.1" 403 153 "-" "ua"\n' "$ts"
    printf '203.0.113.9 - - [%s:03 +0000] "GET / HTTP/1.1" 200 404 "-" "ua 500 "\n' "$ts"
} > "$tmp/logs/app.access.log"
counts=$(nginx_minute_counts app "$ts")
[[ "$counts" == "3 1 0 2 0" ]] || fail "nginx_minute_counts gave '$counts' (want '3 1 0 2 0')"
health=$(mode_health | sed 's/\x1b\[[0-9;]*m//g' | awk '$1 == "app" {print $2, $3, $4, $5, $6}')
[[ "$health" == "3 1 0 2 0" ]] || fail "health gave '$health' (want '3 1 0 2 0')"

(( failures == 0 )) || exit 1
printf 'smoke_alert_payloads: ok\n'
