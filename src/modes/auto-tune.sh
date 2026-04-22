# ==============================================================================
# MODE: auto-tune — suggest thresholds from history baselines
#
# Picks thresholds that would have fired ~rarely on your actual traffic
# instead of making users guess "what's a reasonable 5xx/min for this box?".
# Reads metrics_minute over a recent window and prints:
#   1) side-by-side table of CURRENT vs SUGGESTED
#   2) a copy-paste block of `milog config set …` commands
#
# Percentile picks:
#   THRESH_REQ_WARN  = p90(req)       — alert on the top 10% of minutes
#   THRESH_REQ_CRIT  = p99(req)       — alert on clear outliers
#   THRESH_4XX_WARN  = p95(c4xx)      — floor at 5 so tiny clients don't spam
#   THRESH_5XX_WARN  = p95(c5xx)      — floor at 1 (any 5xx > 0 is worth a ping)
#   P95_WARN_MS      = p75(p95_ms)    — warn when current p95 worse than 3-in-4 historical minutes
#   P95_CRIT_MS      = p99(p95_ms)    — crit on top 1% latency outliers
#
# CPU/MEM/DISK are not in the DB, so those thresholds aren't tuned here.
# ==============================================================================

# Stdin-to-percentile helper: read newline-separated numbers, print the
# p-th percentile (1..100) using the existing `sort -n | awk positional`
# idiom (same logic as percentiles() but for a generic stream).
_pct_from_stdin() {
    local p=$1
    sort -n | awk -v p="$p" '
        NF && $1 ~ /^[0-9]+(\.[0-9]+)?$/ { v[++n] = $1 }
        END {
            if (n == 0) exit
            i = int((n * p + 99) / 100)
            if (i < 1) i = 1
            if (i > n) i = n
            print v[i]
        }'
}

# Format one table row. Visual widths: METRIC(20) CURRENT(11) SUGGESTED(11) DELTA(9)
_tune_row() {
    local metric="$1" current="$2" suggested="$3"
    local delta=""
    if [[ "$current" =~ ^[0-9]+$ && "$suggested" =~ ^[0-9]+$ ]]; then
        local d=$(( suggested - current ))
        if   (( d > 0 )); then delta="${Y}+${d}${NC}"
        elif (( d < 0 )); then delta="${G}${d}${NC}"
        else                   delta="${D}0${NC}"
        fi
    else
        delta="${D}  —${NC}"
    fi
    printf "  %-20s  %-11s  ${W}%-11s${NC}  %b\n" \
        "$metric" "$current" "$suggested" "$delta"
}

mode_auto_tune() {
    local days="${1:-7}"
    [[ "$days" =~ ^[1-9][0-9]*$ ]] \
        || { echo -e "${R}auto-tune: days must be a positive integer${NC}" >&2; return 1; }

    _history_precheck || return 1

    local now since count
    now=$(date +%s)
    since=$(( now - days * 86400 ))
    count=$(sqlite3 "$HISTORY_DB" \
        "SELECT COUNT(*) FROM metrics_minute WHERE ts >= $since;" 2>/dev/null || echo 0)
    [[ "$count" =~ ^[0-9]+$ ]] || count=0

    echo -e "\n${W}── MiLog: auto-tune (window=${days}d, ${count} rows) ──${NC}\n"

    # 100 rows ≈ 100 minutes ≈ 1.6h of data — anything less and percentiles
    # are too noisy to base thresholds on.
    if (( count < 100 )); then
        echo -e "${R}Not enough history (${count} rows — need ≥100).${NC}"
        echo -e "${D}  let 'milog daemon' run for a few hours with HISTORY_ENABLED=1,${NC}"
        echo -e "${D}  or widen the window: milog auto-tune 30${NC}\n"
        return 1
    fi

    # Pull each metric's samples once. Filtering req>0 excludes quiet-hour
    # zeros so the percentile reflects real traffic — otherwise a mostly-idle
    # server would suggest THRESH_REQ_WARN=0.
    local p95_samples req_samples c4_samples c5_samples
    p95_samples=$(sqlite3 "$HISTORY_DB" \
        "SELECT p95_ms FROM metrics_minute WHERE ts >= $since AND p95_ms IS NOT NULL AND req > 0;" 2>/dev/null)
    req_samples=$(sqlite3 "$HISTORY_DB" \
        "SELECT req FROM metrics_minute WHERE ts >= $since AND req > 0;" 2>/dev/null)
    c4_samples=$(sqlite3 "$HISTORY_DB" \
        "SELECT c4xx FROM metrics_minute WHERE ts >= $since;" 2>/dev/null)
    c5_samples=$(sqlite3 "$HISTORY_DB" \
        "SELECT c5xx FROM metrics_minute WHERE ts >= $since;" 2>/dev/null)

    local s_req_warn s_req_crit s_c4_warn s_c5_warn s_p95_warn s_p95_crit
    s_req_warn=$(printf '%s\n' "$req_samples" | _pct_from_stdin 90)
    s_req_crit=$(printf '%s\n' "$req_samples" | _pct_from_stdin 99)
    s_c4_warn=$( printf '%s\n' "$c4_samples"  | _pct_from_stdin 95)
    s_c5_warn=$( printf '%s\n' "$c5_samples"  | _pct_from_stdin 95)
    s_p95_warn=$(printf '%s\n' "$p95_samples" | _pct_from_stdin 75)
    s_p95_crit=$(printf '%s\n' "$p95_samples" | _pct_from_stdin 99)

    # Floors so "empty" days don't suggest zeros that fire on any activity.
    [[ "$s_c4_warn"  =~ ^[0-9]+$ ]] && (( s_c4_warn  < 5 )) && s_c4_warn=5
    [[ "$s_c5_warn"  =~ ^[0-9]+$ ]] && (( s_c5_warn  < 1 )) && s_c5_warn=1
    [[ "$s_req_warn" =~ ^[0-9]+$ ]] && (( s_req_warn < 5 )) && s_req_warn=5

    # Fall back to blank when we had zero samples for a metric (no timed
    # traffic at all means p95 tuning is impossible).
    : "${s_req_warn:=}"; : "${s_req_crit:=}"; : "${s_c4_warn:=}"; : "${s_c5_warn:=}"
    : "${s_p95_warn:=}"; : "${s_p95_crit:=}"

    printf "  %-20s  %-11s  %-11s  %-s\n" "METRIC" "CURRENT" "SUGGESTED" "DELTA"
    printf "  %-20s  %-11s  %-11s  %-s\n" "────────────────────" "───────────" "───────────" "──────"
    _tune_row "THRESH_REQ_WARN"  "$THRESH_REQ_WARN"  "${s_req_warn:--}"
    _tune_row "THRESH_REQ_CRIT"  "$THRESH_REQ_CRIT"  "${s_req_crit:--}"
    _tune_row "THRESH_4XX_WARN"  "$THRESH_4XX_WARN"  "${s_c4_warn:--}"
    _tune_row "THRESH_5XX_WARN"  "$THRESH_5XX_WARN"  "${s_c5_warn:--}"
    _tune_row "P95_WARN_MS"      "$P95_WARN_MS"      "${s_p95_warn:--}"
    _tune_row "P95_CRIT_MS"      "$P95_CRIT_MS"      "${s_p95_crit:--}"

    # Ready-to-apply block — skip lines we couldn't tune.
    echo -e "\n${W}Ready to apply${NC} ${D}(copy-paste to set):${NC}"
    local line printed=0
    for line in \
        "THRESH_REQ_WARN $s_req_warn" \
        "THRESH_REQ_CRIT $s_req_crit" \
        "THRESH_4XX_WARN $s_c4_warn" \
        "THRESH_5XX_WARN $s_c5_warn" \
        "P95_WARN_MS $s_p95_warn" \
        "P95_CRIT_MS $s_p95_crit"
    do
        local k v
        k="${line%% *}"; v="${line#* }"
        [[ -n "$v" && "$v" =~ ^[0-9]+$ ]] || continue
        printf "  milog config set %s %s\n" "$k" "$v"
        printed=$(( printed + 1 ))
    done
    if (( printed == 0 )); then
        echo -e "  ${D}(no actionable suggestions — samples were empty for every tuned metric)${NC}"
    fi
    echo -e "\n  ${D}note: tunes to the quiet-hour-excluded p90/p75/p95/p99 of your last ${days} day(s).${NC}"
    echo -e "  ${D}       re-run after traffic patterns change (new service, traffic source, load).${NC}\n"
    return 0
}

