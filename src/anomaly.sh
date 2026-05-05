# ==============================================================================
# anomaly.sh — daily-pattern anomaly detection over per-minute history.
#
# For every (app, metric) tuple, the rolling window of values at the SAME
# minute-of-day across the last 14 days forms a baseline. When the
# freshly-written row exceeds mean + sigma*stddev AND clears an absolute
# floor, alert_fire is called with rule key anomaly:<app>:<metric>.
#
# Why same-minute-of-day:
#   Daily traffic patterns dwarf weekly ones for a typical nginx host.
#   A naive "anomalous vs all of yesterday" check pages on every 9am
#   rush because the average includes the 3am quiet. Same-minute-of-day
#   absorbs the daily curve so what's left is genuine deviation.
#
# Hard sample-count gate: skip until ANOMALY_MIN_DAYS distinct days exist
# in the rolling window (default 14). Without it the rule alert-spams
# during ramp-up while history accumulates.
#
# Floors prevent low-volume noise: at near-zero baseline, a single hit
# is mathematically 3σ above zero. The current value must clear an
# absolute floor before we even consult the σ band.
#
# Three metrics covered:
#   req   — request count per minute
#   c5xx  — 5xx count per minute
#   p95   — p95 request time (ms; rows with NULL p95_ms skipped)
#
# Wire point: src/modes/daemon.sh calls _anomaly_check_minute right
# after history_write_minute lands the row.
# ==============================================================================

# Per-metric defaults. Operators tune via ANOMALY_FLOOR_<METRIC>=…
# in milog config or the matching MILOG_ANOMALY_FLOOR_* env var.
_anomaly_floor() {
    case "$1" in
        req)  printf '%s' "${ANOMALY_FLOOR_REQ:-10}"  ;;
        c5xx) printf '%s' "${ANOMALY_FLOOR_C5XX:-2}"  ;;
        p95)  printf '%s' "${ANOMALY_FLOOR_P95:-100}" ;;
    esac
}

# Pretty metric name for the alert title.
_anomaly_label() {
    case "$1" in
        req)  printf '%s' "request rate" ;;
        c5xx) printf '%s' "5xx rate"     ;;
        p95)  printf '%s' "p95 latency"  ;;
        *)    printf '%s' "$1"           ;;
    esac
}

# Unit suffix on the current value in the body (req/c5xx are unitless
# counts; p95 is milliseconds).
_anomaly_unit() {
    case "$1" in
        p95)  printf '%s' " ms" ;;
        *)    printf '%s' ""    ;;
    esac
}

# Run the check for one freshly-landed minute. Called from the daemon
# loop after history_write_minute. Self-gates on ANOMALY_ENABLED +
# HISTORY_ENABLED + sqlite3 + DB existence — cheap to call every tick;
# returns immediately when prerequisites aren't met.
_anomaly_check_minute() {
    [[ "${ANOMALY_ENABLED:-0}" != "1" ]] && return 0
    [[ "${HISTORY_ENABLED:-0}" != "1" ]] && return 0
    command -v sqlite3 >/dev/null 2>&1 || return 0
    [[ -f "$HISTORY_DB" ]] || return 0

    local write_ts="$1"
    [[ "$write_ts" =~ ^[0-9]+$ ]] || return 0

    local minute_of_day=$(( write_ts % 86400 ))
    local min_days="${ANOMALY_MIN_DAYS:-14}"
    local since_ts=$((     write_ts - min_days * 86400 ))
    local sigma="${ANOMALY_SIGMA:-3}"
    local floor_req  floor_c5  floor_p95
    floor_req=$(_anomaly_floor req)
    floor_c5=$(_anomaly_floor c5xx)
    floor_p95=$(_anomaly_floor p95)

    local app
    for app in "${LOGS[@]}"; do
        # Single sqlite3 invocation per app: every baseline row tagged
        # 'B', the current row tagged 'C'. awk pivots to mean+stddev
        # per metric and prints one line per breached metric. Cheaper
        # than two round-trips at minute-rollover frequency.
        local out
        out=$(sqlite3 "$HISTORY_DB" <<SQL 2>/dev/null
SELECT 'B', req, c5xx, IFNULL(p95_ms,-1), ts/86400
  FROM metrics_minute
  WHERE app=$(_sql_quote "$app")
    AND (ts%86400)=$minute_of_day
    AND ts>=$since_ts
    AND ts<$write_ts;
SELECT 'C', req, c5xx, IFNULL(p95_ms,-1), 0
  FROM metrics_minute
  WHERE app=$(_sql_quote "$app")
    AND ts=$write_ts;
SQL
        )
        [[ -z "$out" ]] && continue

        # Each line: TYPE|req|c5xx|p95(-1=NULL)|day_idx
        # awk computes mean + stddev (Welford-equivalent via E[X²]-E[X]²)
        # for each metric over baseline rows, then prints one line per
        # breach: <metric> <current> <mean> <stddev> <z>.
        local hits
        hits=$(printf '%s\n' "$out" | awk -F'|' \
            -v sigma="$sigma" -v min_days="$min_days" \
            -v fr="$floor_req" -v fc="$floor_c5" -v fp="$floor_p95" '
            $1=="B" {
                n_req++;          sum_req += $2; sumsq_req += $2*$2
                n_c5++;           sum_c5  += $3; sumsq_c5  += $3*$3
                if ($4 >= 0) { n_p95++; sum_p95 += $4; sumsq_p95 += $4*$4 }
                days[int($5)] = 1
            }
            $1=="C" {
                cur_req = $2 + 0
                cur_c5  = $3 + 0
                cur_p95 = $4 + 0
            }
            END {
                d = 0; for (k in days) d++
                if (d < min_days) exit 0

                if (n_req > 1 && cur_req > fr) {
                    m = sum_req / n_req
                    var = sumsq_req / n_req - m*m
                    if (var < 0) var = 0
                    sd = sqrt(var)
                    if (sd > 0 && cur_req > m + sigma*sd)
                        printf "req %d %.2f %.2f %.2f\n", cur_req, m, sd, (cur_req - m) / sd
                }
                if (n_c5 > 1 && cur_c5 > fc) {
                    m = sum_c5 / n_c5
                    var = sumsq_c5 / n_c5 - m*m
                    if (var < 0) var = 0
                    sd = sqrt(var)
                    if (sd > 0 && cur_c5 > m + sigma*sd)
                        printf "c5xx %d %.2f %.2f %.2f\n", cur_c5, m, sd, (cur_c5 - m) / sd
                }
                if (n_p95 > 1 && cur_p95 > fp) {
                    m = sum_p95 / n_p95
                    var = sumsq_p95 / n_p95 - m*m
                    if (var < 0) var = 0
                    sd = sqrt(var)
                    if (sd > 0 && cur_p95 > m + sigma*sd)
                        printf "p95 %d %.2f %.2f %.2f\n", cur_p95, m, sd, (cur_p95 - m) / sd
                }
            }
        ')

        [[ -z "$hits" ]] && continue

        # One alert per breached metric. alert_should_fire applies
        # ALERT_COOLDOWN per rule key so a sustained anomaly doesn't
        # spam the webhook every minute.
        local metric current mean stddev z key title body
        while read -r metric current mean stddev z; do
            [[ -z "$metric" ]] && continue
            key="anomaly:${app}:${metric}"
            alert_should_fire "$key" || continue
            title="Anomaly: $(_anomaly_label "$metric") on ${app}"
            body=$(printf '%s' '```'"current=${current}$(_anomaly_unit "$metric") mean=${mean} σ=${stddev} z=${z}σ window=${min_days}d (same-minute-of-day)"'```')
            alert_fire "$title" "$body" 15158332 "$key"
        done <<< "$hits"
    done
}
