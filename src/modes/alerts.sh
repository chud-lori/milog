# milog alerts [window]: what fired, read from alerts.log.

# today | yesterday | all | Nm | Nh | Nd | Nw -> cutoff epoch; there is no upper bound, so `yesterday` includes today.
_alerts_window_to_epoch() {
    local w="$1"
    local now; now=$(date +%s)
    case "$w" in
        today)
            # UTC midnight, not local; close enough for this view.
            echo $(( now - (now % 86400) ))
            ;;
        yesterday)
            echo $(( now - (now % 86400) - 86400 ))
            ;;
        all)
            echo 0
            ;;
        *[mM])
            local n="${w%[mM]}"
            [[ "$n" =~ ^[0-9]+$ ]] || { echo "invalid window: $w" >&2; return 1; }
            echo $(( now - n * 60 ))
            ;;
        *[hH])
            local n="${w%[hH]}"
            [[ "$n" =~ ^[0-9]+$ ]] || { echo "invalid window: $w" >&2; return 1; }
            echo $(( now - n * 3600 ))
            ;;
        *[dD])
            local n="${w%[dD]}"
            [[ "$n" =~ ^[0-9]+$ ]] || { echo "invalid window: $w" >&2; return 1; }
            echo $(( now - n * 86400 ))
            ;;
        *[wW])
            local n="${w%[wW]}"
            [[ "$n" =~ ^[0-9]+$ ]] || { echo "invalid window: $w" >&2; return 1; }
            echo $(( now - n * 7 * 86400 ))
            ;;
        *)
            echo "invalid window: $w (valid: today / yesterday / all / Nm / Nh / Nd / Nw)" >&2
            return 1
            ;;
    esac
}

# Exclusive upper bound for a window spec, same midnight math as above; 0 = open-ended.
_alerts_window_end_epoch() {
    local now; now=$(date +%s)
    if [[ "$1" == "yesterday" ]]; then
        echo $(( now - (now % 86400) ))
    else
        echo 0
    fi
}

_alerts_fmt_epoch() {
    date -d "@$1" '+%Y-%m-%d %H:%M' 2>/dev/null \
    || date -r  "$1" '+%Y-%m-%d %H:%M' 2>/dev/null \
    || printf '%s' "$1"
}

mode_alerts() {
    local window="${1:-today}"
    local log_file="$ALERT_STATE_DIR/alerts.log"

    if [[ ! -f "$log_file" ]]; then
        echo -e "${D}No alerts logged yet at $log_file${NC}"
        echo -e "${D}  log entries appear here the first time an alert fires with ALERTS_ENABLED=1${NC}"
        return 0
    fi

    local cutoff cutoff_fmt end
    cutoff=$(_alerts_window_to_epoch "$window") || return 1
    cutoff_fmt=$(_alerts_fmt_epoch "$cutoff")
    end=$(_alerts_window_end_epoch "$window")

    echo -e "\n${W}── MiLog: Alerts since ${cutoff_fmt} (window=$window) ──${NC}\n"

    local filtered; filtered=$(mktemp -t milog_alerts.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$filtered'" RETURN

    awk -F'\t' -v cutoff="$cutoff" -v end="$end" '$1 >= cutoff && (end == 0 || $1 < end)' "$log_file" > "$filtered"

    local total; total=$(wc -l < "$filtered" | tr -d ' ')
    total=${total:-0}

    if (( total == 0 )); then
        echo -e "  ${D}no alerts in window${NC}\n"
        return 0
    fi

    # Newest 30 rows, oldest first.
    local list_cap=30
    local shown=$total
    (( shown > list_cap )) && shown=$list_cap
    echo -e "  ${W}timeline${NC} ${D}(showing latest ${shown} of ${total})${NC}"
    printf "  %-16s  %-28s  %s\n" "WHEN" "RULE" "TITLE"
    printf "  %-16s  %-28s  %s\n" "────────────────" "────────────────────────────" "──────"

    # Format dates in bash: awk strftime is gawk-only.
    local epoch rule color title body when rule_disp title_disp col
    while IFS=$'\t' read -r epoch rule color title body; do
        [[ -z "$epoch" ]] && continue
        when=$(_alerts_fmt_epoch "$epoch")
        rule_disp="$rule"
        (( ${#rule_disp} > 28 )) && rule_disp="${rule_disp:0:25}..."
        title_disp="$title"
        (( ${#title_disp} > 50 )) && title_disp="${title_disp:0:47}..."
        case "$color" in
            15158332|16711680)    col="$R" ;;
            16753920|15844367)    col="$Y" ;;
            *)                    col="$G" ;;
        esac
        printf "  %-16s  %b%-28s%b  %s\n" "$when" "$col" "$rule_disp" "$NC" "$title_disp"
    done < <(tail -n "$list_cap" "$filtered")

    echo -e "\n  ${W}by rule (top 10)${NC}"
    awk -F'\t' '{c[$2]++} END {for (r in c) printf "%d\t%s\n", c[r], r}' "$filtered" \
        | sort -rn | head -n 10 \
        | awk -F'\t' '{printf "    %5d  %s\n", $1, $2}'

    echo -e "\n  ${D}total: $total alert(s) in window — log at $log_file${NC}\n"
}

# TSV per rule key in alerts.log since epoch $1: fires, key, last fire epoch; busiest first.
_alerts_counts_since() {
    awk -F'\t' -v cutoff="$1" '
        $1 >= cutoff && $2 != "" { c[$2]++; if ($1 > last[$2]) last[$2] = $1 }
        END { for (k in c) printf "%d\t%s\t%d\n", c[k], k, last[k] }
    ' "$ALERT_STATE_DIR/alerts.log" | sort -t "$(printf '\t')" -k1,1rn -k2,2
}

# milog alert stats [window]: fires per rule key over the window.
alert_stats() {
    local window="${1:-7d}"
    local log_file="$ALERT_STATE_DIR/alerts.log"

    if [[ ! -f "$log_file" ]]; then
        echo -e "${D}No alerts logged yet at $log_file${NC}"
        return 0
    fi

    local cutoff now rows
    cutoff=$(_alerts_window_to_epoch "$window") || return 1
    now=$(date +%s)
    rows=$(_alerts_counts_since "$cutoff")

    echo -e "\n${W}── MiLog: alert stats since $(_alerts_fmt_epoch "$cutoff") (window=$window) ──${NC}\n"

    if [[ -z "$rows" ]]; then
        echo -e "  ${D}no alerts in window${NC}\n"
        return 0
    fi

    # `all` has no window length, so the per-day rate runs from the oldest fire.
    (( cutoff == 0 )) && cutoff=$(awk -F'\t' '{ print $1; exit }' "$log_file")
    local span=$(( now - cutoff ))
    (( span > 0 )) || span=1

    printf "  %6s  %7s  %-16s  %s\n" "FIRES" "PER DAY" "LAST" "RULE"
    printf "  %6s  %7s  %-16s  %s\n" "──────" "───────" "────────────────" "────"
    local count key last per_day note total=0
    while IFS=$'\t' read -r count key last; do
        per_day=$(awk -v c="$count" -v s="$span" 'BEGIN { printf "%.1f", c * 86400 / s }')
        note=""
        alert_is_silenced "$key" >/dev/null && note="  ${D}(silenced)${NC}"
        printf "  %6d  %7s  %-16s  %s%b\n" "$count" "$per_day" "$(_alerts_fmt_epoch "$last")" "$key" "$note"
        total=$(( total + count ))
    done < <(printf '%s\n' "$rows" | _tty_safe)

    echo -e "\n  ${D}total: $total fire(s); silenced and deduped fires are never written to alerts.log, so they are not counted.${NC}"
    echo -e "  ${D}milog auto-tune suggests fixes for rules firing more than 10 times a day.${NC}\n"
}
