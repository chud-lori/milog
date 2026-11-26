#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/home" "$tmp/logs" "$tmp/bin"
: > "$tmp/logs/app.access.log"
export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"
export MILOG_ALERTS_ENABLED=1

# 429 with retry_after=1 for the first STUB_429S calls, then 204; each request body goes to $tmp/bodies.
cat > "$tmp/bin/curl" <<'SH'
#!/usr/bin/env bash
n=$(( $(cat "$STUB_DIR/calls" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_DIR/calls"
while (( $# )); do
    [[ "$1" == -d ]] && { printf '%s\n' "$2" >> "$STUB_DIR/bodies"; shift; }
    shift
done
if (( n <= STUB_429S )); then
    printf 'HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\r\n'
    printf '{"message": "You are being rate limited.", "retry_after": 1, "global": false}\n429'
else
    printf 'HTTP/1.1 204 No Content\r\n\r\n\n204'
fi
SH
chmod +x "$tmp/bin/curl"
export PATH="$tmp/bin:$PATH" STUB_DIR="$tmp"

. "$ROOT/milog.sh" help >/dev/null

failures=0
fail() { printf 'FAIL: %s\n' "$*" >&2; failures=$(( failures + 1 )); }

DISCORD_WEBHOOK=http://x
flog="$ALERT_STATE_DIR/send_failures.log"

# Two 429s: the first is retried after retry_after, the second starts a backoff that holds later alerts.
export STUB_429S=2
alert_fire "first alert" "b" 15158332 "r:1"
for _ in $(seq 50); do [[ -f "$ALERT_STATE_DIR/backoff.discord" ]] && break; sleep 0.1; done
[[ -f "$ALERT_STATE_DIR/backoff.discord" ]] || fail "no backoff after a repeated 429"
alert_fire "second alert" "b" 15158332 "r:2"
alert_fire "third alert" "b" 16753920 "r:3"
alert_fire "third alert" "b" 16753920 "r:3"
wait

[[ "$(cat "$tmp/calls")" == 3 ]] || fail "want 2 attempts plus 1 summary, got $(cat "$tmp/calls") calls"
summary=$(tail -n 1 "$tmp/bodies")
for want in 'Rate limited: 4 alerts held' 'first alert x1' 'second alert x1' 'third alert x2'; do
    [[ "$summary" == *"$want"* ]] || fail "summary lacks '$want': $summary"
done
[[ ! -s "$flog" ]] || fail "held alerts were recorded as failures: $(cat "$flog")"
[[ ! -s "$ALERT_STATE_DIR/queue.discord" ]] || fail "queue not drained"

# Direct sends keep the old contract: one retry, then one failure row in the same format.
rm -f "$tmp/calls"
STUB_429S=99 _alert_send_discord "t" "b"
grep -q $'^[0-9]*\tdiscord\t429$' "$flog" || fail "direct send: no 429 failure row: $(cat "$flog" 2>/dev/null)"

# A growing failure log is reported once to the daemon log and as an alert, then not again.
alog="$ALERT_STATE_DIR/alerts.log"
rm -f "$ALERT_STATE_DIR/backoff.discord"
export STUB_429S=0
_alert_delivery_check 2>"$tmp/err"; wait
grep -q 'WARNING: 1 alert deliveries failed' "$tmp/err" || fail "delivery check did not log: $(cat "$tmp/err")"
grep -q $'\tmilog:delivery\t' "$alog" || fail "delivery check did not alert"
_alert_delivery_check 2>"$tmp/err"; wait
[[ ! -s "$tmp/err" ]] || fail "delivery check repeated without new failures: $(cat "$tmp/err")"
[[ "$(grep -c $'\tmilog:delivery\t' "$alog")" == 1 ]] || fail "delivery alert repeated"

# Backoff length: rounded up, capped, and safe on huge values.
[[ "$(_alert_backoff_secs 1.5)" == 2 ]] || fail "backoff 1.5 -> $(_alert_backoff_secs 1.5)"
[[ "$(_alert_backoff_secs 08)" == 9 ]] || fail "backoff 08 -> $(_alert_backoff_secs 08)"
[[ "$(_alert_backoff_secs 9223372036854775808)" == 300 ]] || fail "backoff overflow -> $(_alert_backoff_secs 9223372036854775808)"
[[ "$(_alert_backoff_secs '')" == 30 ]] || fail "backoff missing -> $(_alert_backoff_secs '')"

(( failures == 0 )) || exit 1
printf 'smoke_alert_backpressure: ok\n'
