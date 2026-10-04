# milog diff: this hour vs the same hour 1 and 7 days ago, per app, from metrics_minute.
mode_diff() {
    _history_precheck || return 1

    local now hr_start_now
    now=$(date +%s)
    hr_start_now=$(( now - (now % 3600) ))

    local yest_start=$((  hr_start_now - 86400     ))
    local yest_end=$((    yest_start   + 3600      ))
    local week_start=$((  hr_start_now - 7 * 86400 ))
    local week_end=$((    week_start   + 3600      ))

    local hr_label
    hr_label=$(date -d "@${hr_start_now}" '+%H:00' 2>/dev/null \
               || date -r "$hr_start_now" '+%H:00' 2>/dev/null \
               || echo "this hour")

    echo -e "\n${W}── MiLog: Hourly diff (${hr_label} vs 1d/7d ago) ──${NC}\n"

    local rows
    rows=$(sqlite3 -separator $'\t' "$HISTORY_DB" <<SQL 2>/dev/null
SELECT app,
       COALESCE(SUM(CASE WHEN ts >= $hr_start_now AND ts < $now      THEN req END), 0) AS now_r,
       COALESCE(SUM(CASE WHEN ts >= $yest_start   AND ts < $yest_end THEN req END), 0) AS d1,
       COALESCE(SUM(CASE WHEN ts >= $week_start   AND ts < $week_end THEN req END), 0) AS d7
FROM metrics_minute
WHERE ts >= $week_start
GROUP BY app
ORDER BY app;
SQL
)
    if [[ -z "$rows" ]]; then
        echo -e "  ${D}no data in the windows${NC}\n"
        return 0
    fi

    # ASCII labels and dividers sized to visual width; Δ is multi-byte and breaks printf padding.
    printf "  %-12s  %10s  %10s  %10s  %8s  %8s\n" \
           "APP" "NOW" "1d ago" "7d ago" "d1 %" "d7 %"
    printf "  %-12s  %10s  %10s  %10s  %8s  %8s\n" \
           "────────────" "──────────" "──────────" "──────────" "────────" "────────"

    local app now_r d1 d7 d1p d7p d1_col d7_col
    while IFS=$'\t' read -r app now_r d1 d7; do
        now_r=${now_r:-0}; d1=${d1:-0}; d7=${d7:-0}
        if (( d1 > 0 )); then
            d1p=$(( (now_r - d1) * 100 / d1 ))
            d1_col=$G
            (( d1p <= -25 || d1p >= 50 ))  && d1_col=$Y
            (( d1p <= -50 || d1p >= 100 )) && d1_col=$R
            d1p="$(printf '%+d%%' "$d1p")"
        else
            d1p="—"; d1_col="$D"
        fi
        if (( d7 > 0 )); then
            d7p=$(( (now_r - d7) * 100 / d7 ))
            d7_col=$G
            (( d7p <= -25 || d7p >= 50 ))  && d7_col=$Y
            (( d7p <= -50 || d7p >= 100 )) && d7_col=$R
            d7p="$(printf '%+d%%' "$d7p")"
        else
            d7p="—"; d7_col="$D"
        fi
        printf "  %-12s  %10d  %10d  %10d  ${d1_col}%8s${NC}  ${d7_col}%8s${NC}\n" \
               "$app" "$now_r" "$d1" "$d7" "$d1p" "$d7p"
    done <<< "$rows"
    echo
    echo -e "  ${D}(NOW is the partial current hour so far; 1d/7d are full same-hour windows)${NC}"
    echo
}

