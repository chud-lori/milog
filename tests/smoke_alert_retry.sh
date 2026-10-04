#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

mkdir -p "$tmp/home" "$tmp/logs" "$tmp/bin"
: > "$tmp/logs/app.access.log"
export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"

# Answers 429 for the first STUB_429S calls, then 204; counts calls in $tmp/calls.
cat > "$tmp/bin/curl" <<'SH'
#!/usr/bin/env bash
n=$(( $(cat "$STUB_DIR/calls" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_DIR/calls"
if (( n <= STUB_429S )); then
    printf 'HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\r\n'
    printf '{"message": "You are being rate limited.", "retry_after": 0.2, "global": false}\n429'
else
    printf 'HTTP/1.1 204 No Content\r\n\r\n\n204'
fi
SH
chmod +x "$tmp/bin/curl"
export PATH="$tmp/bin:$PATH" STUB_DIR="$tmp"

. "$ROOT/milog.sh" help >/dev/null

failures=0
fail() { printf 'FAIL: %s\n' "$*" >&2; failures=$(( failures + 1 )); }

export DISCORD_WEBHOOK=http://x
flog="$ALERT_STATE_DIR/send_failures.log"

STUB_429S=1; export STUB_429S
rm -f "$tmp/calls" "$flog"
_alert_send_discord "t" "b"
[[ "$(cat "$tmp/calls")" == 2 ]] || fail "429 then 204: expected 2 calls, got $(cat "$tmp/calls")"
[[ ! -s "$flog" ]] || fail "429 then 204: recorded a failure: $(cat "$flog")"

STUB_429S=99
rm -f "$tmp/calls" "$flog"
_alert_send_discord "t" "b"
[[ "$(cat "$tmp/calls")" == 2 ]] || fail "always 429: expected 2 calls, got $(cat "$tmp/calls")"
[[ "$(wc -l < "$flog" | tr -d ' ')" == 1 ]] || fail "always 429: expected 1 failure row"
grep -q $'^[0-9]*\tdiscord\t429$' "$flog" || fail "always 429: row lacks status: $(cat "$flog")"

(( failures == 0 )) || exit 1
printf 'smoke_alert_retry: ok\n'
