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
if [[ -n "${STUB_CODE:-}" ]]; then
    printf 'HTTP/1.1 %s Error\r\n\r\n\n%s' "$STUB_CODE" "$STUB_CODE"
elif (( n <= STUB_429S )); then
    printf 'HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\r\n'
    printf '{"message": "You are being rate limited.", "retry_after": %s, "global": false}\n429' "${STUB_WAIT:-1}"
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

q="$ALERT_STATE_DIR/queue.discord"
row() { printf '%s\t15158332\t%s\t%s\n' "$(date +%s)" "$1" "$2"; }
rows_for() { awk -F'\t' -v r="$1" '$4 == r' "$flog" | wc -l | tr -d ' '; }

# A summary that fails with a non-429 is retried once, then logged per held alert with its rule key.
rm -f "$flog" "$tmp/calls" "$tmp/bodies"
{ row r:a "held a"; row r:b "held b"; } > "$q"
STUB_CODE=500 _alert_flush discord
[[ "$(cat "$tmp/calls")" == 2 ]] || fail "500 summary: want 2 attempts, got $(cat "$tmp/calls")"
[[ "$(rows_for r:a)$(rows_for r:b)" == 11 ]] || fail "500 summary: want one row per held alert: $(cat "$flog")"
grep -q $'\tdiscord\t500\tr:a$' "$flog" || fail "500 summary: row lacks status or rule key: $(cat "$flog")"

# A single alert failing outside a backoff is logged once, with its rule key.
rm -f "$flog"
STUB_CODE=503 alert_fire "lone alert" "b" 15158332 "r:lone"; wait
[[ "$(rows_for r:lone)" == 1 ]] || fail "single 503: want 1 row with rule key: $(cat "$flog" 2>/dev/null)"

# Invalid UTF-8 in a title is stripped before it can poison a summary.
rm -f "$q"
_alert_enqueue discord $'bad\xff\xfetitle' "b" 15158332 "r:utf"
LC_ALL=C grep -q $'\xff' "$q" && fail "invalid UTF-8 reached the queue"
grep -q 'badtitle' "$q" || fail "title lost while stripping invalid UTF-8: $(cat "$q")"
rm -f "$q"

# A future-dated backoff file holds at most 300s and is removed after the flush succeeds.
rm -f "$tmp/calls" "$tmp/sleeps"
sleep() { printf '%s\n' "$1" >> "$tmp/sleeps"; }
echo $(( $(date +%s) + 999999 )) > "$ALERT_STATE_DIR/backoff.discord"
alert_fire "forged hold" "b" 15158332 "r:forged"; wait
unset -f sleep
(( $(sort -n "$tmp/sleeps" | tail -1) <= 300 )) || fail "forged backoff: slept $(sort -n "$tmp/sleeps" | tail -1)s"
[[ "$(tail -n 1 "$tmp/bodies")" == *"forged hold x1"* ]] || fail "forged backoff: held alert not sent"
[[ ! -e "$ALERT_STATE_DIR/backoff.discord" ]] || fail "backoff file kept after a successful flush"

# Five rate-limited rounds log the batch; an alert queued during that dump still goes out in a fresh round.
rm -f "$flog" "$tmp/calls" "$tmp/bodies" "$ALERT_STATE_DIR/backoff.discord"
eval "$(declare -f _alert_fail_rows | sed '1s/^_alert_fail_rows/_orig_fail_rows/')"
_alert_fail_rows() { _orig_fail_rows "$@"; [[ -s "$q" ]] || row r:late "late alert" >> "$q"; }
row r:old "old alert" > "$q"
STUB_429S=10 STUB_WAIT=0 _alert_flush discord
[[ "$(rows_for r:old)" == 1 ]] || fail "after 5 rounds: want the held alert logged once: $(cat "$flog" 2>/dev/null)"
[[ "$(tail -n 1 "$tmp/bodies")" == *"late alert x1"* ]] || fail "alert queued during the dump was dropped"
[[ ! -e "$q.drop" ]] || fail "drop file left behind"

# The hourly check re-sends a batch a dead flusher left mid-send and restarts a stranded queue.
rm -f "$tmp/calls" "$tmp/bodies"
row r:orphan "orphan alert" > "$q.send.dead01"
touch -d '10 minutes ago' "$q.send.dead01"
row r:fresh "in flight" > "$q.send.live01"
_alert_delivery_check 2>/dev/null; wait
[[ "$(cat "$tmp/bodies" 2>/dev/null)" == *"orphan alert x1"* ]] || fail "orphaned send file not re-sent"
[[ ! -e "$q.send.dead01" ]] || fail "orphaned send file left behind"
[[ -e "$q.send.live01" ]] || fail "a recent send file was taken from a live flusher"
rm -f "$q.send.live01"

# The delivery alert's own failures do not re-trigger it.
_alert_delivery_check 2>/dev/null; wait
printf '%s\tdiscord\t000\tmilog:delivery\n' "$(date +%s)" >> "$flog"
before=$(grep -c $'\tmilog:delivery\t' "$alog" || :)
_alert_delivery_check 2>"$tmp/err"; wait
[[ "$(grep -c $'\tmilog:delivery\t' "$alog" || :)" == "$before" ]] || fail "milog:delivery failure re-fired the delivery alert"
[[ ! -s "$tmp/err" ]] || fail "milog:delivery failure logged a warning: $(cat "$tmp/err")"

# Backoff length: rounded up, capped, and safe on huge values.
[[ "$(_alert_backoff_secs 1.5)" == 2 ]] || fail "backoff 1.5 -> $(_alert_backoff_secs 1.5)"
[[ "$(_alert_backoff_secs 08)" == 9 ]] || fail "backoff 08 -> $(_alert_backoff_secs 08)"
[[ "$(_alert_backoff_secs 9223372036854775808)" == 300 ]] || fail "backoff overflow -> $(_alert_backoff_secs 9223372036854775808)"
[[ "$(_alert_backoff_secs '')" == 30 ]] || fail "backoff missing -> $(_alert_backoff_secs '')"

(( failures == 0 )) || exit 1
printf 'smoke_alert_backpressure: ok\n'
