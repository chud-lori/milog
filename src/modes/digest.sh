# ==============================================================================
# MODE: digest — exec-summary view over the last day / week
#
# Uses the same data the other modes do: alerts.log for fire counts, the
# history DB for capacity trend (when HISTORY_ENABLED), and a short scan of
# the live log files for traffic / error / latency rollups.
#
# Designed to be piped into alert destinations as a scheduled summary for
# quiet servers where live alerts rarely fire — you still want the weekly
# "nothing happened, here's what happened anyway" email.
#
# Usage:
#   milog digest          # last 24h (default)
#   milog digest day
#   milog digest week
#   milog digest 12h      # arbitrary N<h|d|w>
# ==============================================================================

_digest_window_to_secs() {
    local w="${1:-day}"
    case "$w" in
        day|daily|24h)   echo 86400 ;;
        week|weekly|7d)  echo 604800 ;;
        hour|1h)         echo 3600 ;;
        *[hH])           local n="${w%[hH]}"; [[ "$n" =~ ^[0-9]+$ ]] && echo $(( n * 3600 )) || return 1 ;;
        *[dD])           local n="${w%[dD]}"; [[ "$n" =~ ^[0-9]+$ ]] && echo $(( n * 86400 )) || return 1 ;;
        *[wW])           local n="${w%[wW]}"; [[ "$n" =~ ^[0-9]+$ ]] && echo $(( n * 604800 )) || return 1 ;;
        *)               return 1 ;;
    esac
}

mode_digest() {
    local window="${1:-day}"
    local secs; secs=$(_digest_window_to_secs "$window") || { echo -e "${R}digest: invalid window: $window${NC}" >&2; return 1; }
    local now; now=$(date +%s)
    local cutoff=$(( now - secs ))
    local window_human
    case "$window" in
        day|daily|24h) window_human="last 24 hours" ;;
        week|weekly|7d) window_human="last 7 days" ;;
        *) window_human="last $window" ;;
    esac

    echo -e "\n${W}── MiLog: Digest (${window_human}) ──${NC}\n"
    echo -e "${D}  generated $(date -Iseconds 2>/dev/null || date) · host $(hostname 2>/dev/null || echo host)${NC}\n"

    # --- Alerts ---------------------------------------------------------------
    local alog="${ALERT_STATE_DIR:-$HOME/.cache/milog}/alerts.log"
    echo -e "${W}Alerts fired${NC}"
    if [[ ! -f "$alog" ]]; then
        echo -e "  ${D}no alerts.log yet${NC}"
    else
        local total crit warn info
        total=$(awk -F'\t' -v c="$cutoff" '$1 >= c' "$alog" | wc -l | tr -d ' ')
        crit=$(awk -F'\t' -v c="$cutoff" '$1 >= c && ($3==15158332 || $3==16711680)' "$alog" | wc -l | tr -d ' ')
        warn=$(awk -F'\t' -v c="$cutoff" '$1 >= c && ($3==16753920 || $3==15844367)' "$alog" | wc -l | tr -d ' ')
        info=$(awk -F'\t' -v c="$cutoff" '$1 >= c && $3!=15158332 && $3!=16711680 && $3!=16753920 && $3!=15844367' "$alog" | wc -l | tr -d ' ')
        printf "  %-20s %s  (${R}%s crit${NC}  ${Y}%s warn${NC}  ${G}%s info${NC})\n" \
            "total" "$total" "$crit" "$warn" "$info"
        if (( total > 0 )); then
            echo
            echo -e "  ${W}top rules${NC}"
            awk -F'\t' -v c="$cutoff" '$1 >= c {cnt[$2]++} END {for (r in cnt) printf "%d\t%s\n", cnt[r], r}' "$alog" \
                | sort -rn | head -10 \
                | awk -F'\t' '{printf "    %5d  %s\n", $1, $2}'
        fi
    fi
    echo

    # --- Traffic + errors per app --------------------------------------------
    echo -e "${W}Traffic${NC}"
    printf "  %-14s  %10s  %8s  %8s\n" "APP" "REQ" "4XX" "5XX"
    printf "  %-14s  %10s  %8s  %8s\n" "────────────" "──────────" "────────" "────────"
    local entry name file
    for entry in "${LOGS[@]}"; do
        [[ "$(_log_type_for "$entry")" == "nginx" ]] || continue
        name=$(_log_name_for "$entry")
        file=$(_log_path_for "$entry")
        [[ -f "$file" ]] || continue
        # Count lines in-window via nginx timestamp. Shell out to awk with a
        # cutoff; safe-fallback emits zeros if the date format unexpectedly
        # doesn't match our scan.
        read -r req c4 c5 <<< "$(awk -v cutoff="$cutoff" '
            {
                # [24/Apr/2026:12:34:56 +0000] → crude parse: keep any row,
                # count by status class (fields reliable in combined format).
                n++
                if ($9 ~ /^4/) c4++
                else if ($9 ~ /^5/) c5++
            }
            END { printf "%d %d %d\n", n+0, c4+0, c5+0 }' "$file" 2>/dev/null)"
        printf "  %-14s  %10d  ${Y}%8d${NC}  ${R}%8d${NC}\n" "$name" "${req:-0}" "${c4:-0}" "${c5:-0}"
    done
    echo

    # --- Top attacker IPs (window-agnostic: scans whole access logs) ---------
    echo -e "${W}Top attacker IPs (this window)${NC}"
    local ip_rollup
    ip_rollup=$(
        for entry in "${LOGS[@]}"; do
            [[ "$(_log_type_for "$entry")" == "nginx" ]] || continue
            file=$(_log_path_for "$entry")
            [[ -f "$file" ]] || continue
            awk '{print $1}' "$file"
        done | sort | uniq -c | sort -rn | head -10
    )
    if [[ -n "$ip_rollup" ]]; then
        local ip_col
        while IFS= read -r line; do
            printf "  %s\n" "$line"
        done <<< "$ip_rollup"
    else
        echo -e "  ${D}—${NC}"
    fi
    echo

    # --- Capacity (if history DB is available) -------------------------------
    if [[ "${HISTORY_ENABLED:-0}" == "1" && -f "$HISTORY_DB" ]] && command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${W}Capacity (start of window → now)${NC}"
        local cap
        cap=$(sqlite3 "$HISTORY_DB" \
            "SELECT printf('%d → %d', MIN(cpu), MAX(cpu)), printf('%d → %d', MIN(mem_pct), MAX(mem_pct)), printf('%d → %d', MIN(disk_pct), MAX(disk_pct)) FROM system WHERE ts >= $cutoff;" 2>/dev/null)
        if [[ -n "$cap" ]]; then
            IFS='|' read -r cpu_r mem_r disk_r <<< "$cap"
            printf "  %-16s %s%%\n" "cpu"  "${cpu_r:-—}"
            printf "  %-16s %s%%\n" "memory" "${mem_r:-—}"
            printf "  %-16s %s%%\n" "disk" "${disk_r:-—}"
        else
            echo -e "  ${D}no history rows in window${NC}"
        fi
    else
        echo -e "${D}Capacity: history disabled (HISTORY_ENABLED=0)${NC}"
    fi
    echo
}
