# ==============================================================================
# MODE: trend — ASCII sparkline chart from metrics_minute history
# Requires HISTORY_ENABLED daemon to have written the DB. Renders two rows
# per app: req/min (green) and 4xx+5xx errors (red). Bucket-aggregates so
# the sparkline fits the fixed 60-char width.
# ==============================================================================
_render_trend_one() {
    local app="$1" since="$2" window_sec="$3" width="$4"

    # SQL buckets row timestamps into exactly `width` columns across the
    # window. Empty columns (no samples) won't appear in output — we fill
    # them in with zeros on the shell side below.
    local rows
    rows=$(sqlite3 -separator $'\t' "$HISTORY_DB" <<SQL 2>/dev/null
SELECT CAST((ts - $since) * $width / $window_sec AS INTEGER) AS col,
       COALESCE(SUM(req), 0),
       COALESCE(SUM(c4xx + c5xx), 0)
FROM metrics_minute
WHERE app = $(_sql_quote "$app") AND ts >= $since
GROUP BY col
ORDER BY col;
SQL
)
    if [[ -z "$rows" ]]; then
        printf "  ${D}%-10s  no data in window${NC}\n\n" "$app"
        return
    fi

    local -a req_samples=() err_samples=()
    local i
    for (( i = 0; i < width; i++ )); do
        req_samples+=(0)
        err_samples+=(0)
    done

    local col req err
    while IFS=$'\t' read -r col req err; do
        [[ "$col" =~ ^[0-9]+$ ]] || continue
        if (( col >= 0 && col < width )); then
            req_samples[$col]="${req:-0}"
            err_samples[$col]="${err:-0}"
        fi
    done <<< "$rows"

    local req_spark err_spark v peak=0 total=0
    req_spark=$(sparkline_render "${req_samples[*]}")
    err_spark=$(sparkline_render "${err_samples[*]}")
    for v in "${req_samples[@]}"; do (( v > peak  )) && peak=$v; done
    for v in "${err_samples[@]}"; do total=$(( total + v )); done

    printf "  ${W}%-10s${NC}  req ${G}%s${NC}  peak=%d/bucket\n" "$app" "$req_spark" "$peak"
    printf "  %-10s  err ${R}%s${NC}  total=%d\n" "" "$err_spark" "$total"
    echo
}

mode_trend() {
    local app_arg="${1:-}" hours="${2:-24}"
    [[ "$hours" =~ ^[1-9][0-9]*$ ]] \
        || { echo -e "${R}trend: hours must be a positive integer${NC}" >&2; return 1; }

    _history_precheck || return 1

    # Sparkline width scales with terminal: 40-char floor so short terms
    # still show something useful; each bucket maps to window_sec/width seconds.
    milog_update_geometry
    local now since width window_sec
    width=$(( INNER - 40 ))
    (( width < 40 )) && width=40
    now=$(date +%s)
    window_sec=$(( hours * 3600 ))
    since=$(( now - window_sec ))

    local -a apps
    if [[ -n "$app_arg" ]]; then
        # Reject app names that can't appear in LOGS, so a typo doesn't
        # render "no data" forever.
        local ok=0 name
        for name in "${LOGS[@]}"; do
            [[ "$name" == "$app_arg" ]] && { ok=1; break; }
        done
        if (( ! ok )); then
            echo -e "${R}trend: unknown app '$app_arg'${NC}  Apps: ${LOGS[*]}" >&2
            return 1
        fi
        apps=("$app_arg")
    else
        apps=("${LOGS[@]}")
    fi

    echo -e "\n${W}── MiLog: Trend (last ${hours}h, ${width} buckets) ──${NC}\n"

    local a
    for a in "${apps[@]}"; do
        _render_trend_one "$a" "$since" "$window_sec" "$width"
    done
}

