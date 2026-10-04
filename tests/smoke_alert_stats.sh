#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MILOG="$ROOT/milog.sh"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    printf 'smoke_alert_stats: %s\n' "$1" >&2
    exit 1
}

mkdir -p "$tmp/home" "$tmp/logs"
export HOME="$tmp/home"
export MILOG_CONFIG="$tmp/home/.config/milog/config.sh"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="api"
state="$tmp/home/.cache/milog"
mkdir -p "$state"
: > "$tmp/logs/api.access.log"

# Over 7 days: 5xx:api fires 100 times with counts 6..105, cpu 80 times at 100%,
# exploit 90 times, 4xx:api 3 times, plus one fire older than the window.
now=$(date +%s)
{
    for i in $(seq 1 100); do
        printf '%s\t5xx:api\t15158332\t5xx spike: api\t%d 5xx responses in the last minute (threshold 5)\n' \
            "$(( now - i * 3000 ))" "$(( i + 5 ))"
    done
    for i in $(seq 1 80); do
        printf '%s\tcpu\t15158332\tCPU critical\tCPU at 100%% (crit=90%%)\n' "$(( now - i * 3000 ))"
    done
    for i in $(seq 1 90); do
        printf '%s\texploit:api:sqli\t15158332\tExploit attempt\tGET /x\n' "$(( now - i * 3000 ))"
    done
    for i in 1 2 3; do
        printf '%s\t4xx:api\t16753920\t4xx spike: api\t25 4xx responses\n' "$(( now - i * 3000 ))"
    done
    printf '%s\told:rule\t15158332\tOld\tbody\n' "$(( now - 20 * 86400 ))"
} | sort -n > "$state/alerts.log"

"$MILOG" alert stats 7d > "$tmp/stats.out" 2>&1 || fail "alert stats exited non-zero"
first=$(awk '$1 ~ /^[0-9]+$/ { print $NF; exit }' "$tmp/stats.out")
[[ "$first" == "5xx:api" ]] || fail "busiest rule not listed first (got '$first')"
grep -qE '^ +100 +14\.3 ' "$tmp/stats.out" || fail "5xx:api count or per-day rate wrong"
grep -qF 'old:rule' "$tmp/stats.out" && fail "fire outside the window was counted"
"$MILOG" alert stats 30d > "$tmp/stats30.out" 2>&1
grep -qF 'old:rule' "$tmp/stats30.out" || fail "30d window lost the old fire"

# Silenced rules get no suggestion; the rest get a threshold raise or a silence.
printf 'exploit:api:sqli\t%s\t%s\ttester\tknown\n' "$(( now + 3600 ))" "$now" > "$state/alerts.silences"
"$MILOG" alert stats 7d > "$tmp/stats.out" 2>&1
grep -q 'exploit:api:sqli.*silenced' "$tmp/stats.out" || fail "silenced rule not marked"

"$MILOG" auto-tune 7 > "$tmp/tune.out" 2>&1 || true
# Top 70 fire values are 36..105, so the 71st is 35 and the new threshold is 36.
grep -qF 'milog config set THRESH_5XX_WARN_api 36' "$tmp/tune.out" || fail "no 5xx threshold suggestion"
grep -qF 'milog silence cpu 7d' "$tmp/tune.out" || fail "cpu at 100% should get a silence, not a threshold over 100"
grep -qF 'exploit:api:sqli' "$tmp/tune.out" && fail "silenced rule still got a suggestion"
grep -qF '4xx:api' "$tmp/tune.out" && fail "quiet rule got a suggestion"
grep -q '^THRESH_5XX_WARN' "$MILOG_CONFIG" 2>/dev/null && fail "auto-tune changed the config"

echo "smoke_alert_stats: ok"
