#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/home/.config/milog" "$tmp/logs" "$tmp/watch" "$tmp/acc"
: > "$tmp/logs/app.access.log"
printf 'v1\n' > "$tmp/fim-target"
: > "$tmp/watch/known"
printf 'root:x:0:0\n' > "$tmp/acc/passwd"
{
    printf 'AUDIT_FIM_PATHS=(%q)\n' "$tmp/fim-target"
    printf 'AUDIT_PERSISTENCE_PATHS=(%q)\n' "$tmp/watch/*"
    printf 'AUDIT_ACCOUNTS_PATHS=(%q)\n' "$tmp/acc/passwd"
} > "$tmp/home/.config/milog/config.sh"

export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"
export MILOG_ALERTS_ENABLED=1
# Shorter than the tick spacing, the way 300s sat under the 3600s audit interval.
export MILOG_ALERT_COOLDOWN=1
export MILOG_AUDIT_ENABLED=1
export MILOG_AUDIT_FIM_INTERVAL=0
export MILOG_AUDIT_PERSISTENCE_INTERVAL=0
export MILOG_AUDIT_ACCOUNTS_INTERVAL=0
export MILOG_HISTORY_ENABLED=0

. "$ROOT/milog.sh" help >/dev/null

failures=0
fail() { printf 'FAIL: %s\n' "$*" >&2; failures=$(( failures + 1 )); }

alog="$ALERT_STATE_DIR/alerts.log"
# Sweeps compare whole-second epochs and the daemon sleeps at least REFRESH=1 between ticks, so do the same.
tick() { sleep 1; _audit_fim_tick; _audit_persistence_tick; _audit_accounts_tick; wait; }
fires() { awk -F'\t' -v t="$1" 'index($4, t) == 1' "$alog" 2>/dev/null | wc -l | tr -d ' '; }

# The default config must not leave a periodic check re-alerting every tick.
(( ALERT_REMINDER_INTERVAL >= AUDIT_FIM_INTERVAL )) || fail "default reminder interval is shorter than the check"

tick   # first run baselines silently
[[ ! -s "$alog" ]] || fail "baseline tick alerted: $(cat "$alog")"

printf 'v2\n' > "$tmp/fim-target"
: > "$tmp/watch/evil.timer"
printf 'mallory:x:0:0\n' >> "$tmp/acc/passwd"
for _ in 1 2 3 4 5; do tick; done
[[ "$(fires 'FIM drift: MODIFIED')" == 1 ]]   || fail "5 FIM ticks: want 1 alert, got $(fires 'FIM drift: MODIFIED')"
[[ "$(fires 'Persistence: new')" == 1 ]]      || fail "5 persistence ticks: want 1 alert, got $(fires 'Persistence: new')"
[[ "$(fires 'Account drift:')" == 1 ]]        || fail "5 accounts ticks: want 1 alert, got $(fires 'Account drift:')"

# A further change to the same file is new information.
printf 'v3\n' > "$tmp/fim-target"
tick; tick
[[ "$(fires 'FIM drift: MODIFIED')" == 2 ]]   || fail "changed again: want 2 FIM alerts, got $(fires 'FIM drift: MODIFIED')"

# Reminder once the interval has passed, then quiet again.
awk -F'\t' 'BEGIN{OFS="\t"} $1 ~ /^audit:persistence:/ {$3 = 1} 1' "$ALERT_STATE_DIR/alerts.conditions" > "$tmp/c" \
    && mv "$tmp/c" "$ALERT_STATE_DIR/alerts.conditions"
tick; tick
[[ "$(fires 'Still open: Persistence')" == 1 ]] || fail "reminder: want 1, got $(fires 'Still open: Persistence')"
ALERT_REMINDER_INTERVAL=0
awk -F'\t' 'BEGIN{OFS="\t"} $1 ~ /^audit:persistence:/ {$3 = 1} 1' "$ALERT_STATE_DIR/alerts.conditions" > "$tmp/c" \
    && mv "$tmp/c" "$ALERT_STATE_DIR/alerts.conditions"
tick
[[ "$(fires 'Still open: Persistence')" == 1 ]] || fail "ALERT_REMINDER_INTERVAL=0 still reminded"
ALERT_REMINDER_INTERVAL=86400

# Clearing gives one resolved alert, and nothing after.
printf 'v1\n' > "$tmp/fim-target"
rm -f "$tmp/watch/evil.timer"
tick; tick; tick
[[ "$(fires 'Resolved: FIM drift: MODIFIED')" == 1 ]] || fail "cleared FIM: want 1 resolved, got $(fires 'Resolved: FIM drift')"
[[ "$(fires 'Resolved: Persistence: new')" == 1 ]]    || fail "cleared persistence: want 1 resolved, got $(fires 'Resolved: Persistence')"
awk -F'\t' '$4 ~ /^Resolved: FIM/ && $3 != 3066993 {bad = 1} END {exit bad}' "$alog" || fail "resolved alert is not low severity"
grep -q '^audit:fim:' "$ALERT_STATE_DIR/alerts.conditions" && fail "FIM condition still open after clearing"

# A re-baseline closes the condition quietly, and the same drift later opens a new one.
printf 'v4\n' > "$tmp/fim-target"
tick
[[ "$(fires 'FIM drift: MODIFIED')" == 3 ]] || fail "reopen: want 3 FIM alerts, got $(fires 'FIM drift: MODIFIED')"
_audit_fim_baseline >/dev/null
_audit_accounts_baseline >/dev/null
grep -q '^audit:fim:' "$ALERT_STATE_DIR/alerts.conditions" && fail "FIM baseline left the condition open"
grep -q '^audit:accounts:' "$ALERT_STATE_DIR/alerts.conditions" && fail "accounts baseline left the condition open"
before=$(wc -l < "$alog")
tick; tick
[[ "$(wc -l < "$alog")" == "$before" ]] || fail "ticks after re-baseline alerted: $(tail -n +"$(( before + 1 ))" "$alog")"
printf 'v5\n' > "$tmp/fim-target"
tick
[[ "$(fires 'FIM drift: MODIFIED')" == 4 ]] || fail "after re-baseline: new drift did not alert"

# Point-in-time rules keep the per-rule cooldown.
ALERT_COOLDOWN=300
rm -f "$ALERT_STATE_DIR/alerts.state"
alert_should_fire "exploit:app:sqli" || fail "first exploit fire was suppressed"
alert_should_fire "exploit:app:sqli" && fail "second exploit fire inside the cooldown went through"

(( failures == 0 )) || exit 1
printf 'smoke_alert_conditions: ok\n'
