# ==============================================================================
# MODE: alerts — read the local alert history log
#
# The log itself is appended to by `_alert_record` (called from
# `alert_discord`) — one TSV row per fired alert. This mode presents the
# "what fired overnight? / this week?" view that was previously
# unanswerable (the cooldown state file tracks last-fire per rule but
# not history).
#
# Window grammar:
#   today        since local midnight today
#   yesterday    24h window ending at today's midnight
#   all          no cutoff
#   <N>m         last N minutes
#   <N>h         last N hours
#   <N>d         last N days
#   <N>w         last N weeks
# Default: today.
#
# Log file:       $ALERT_STATE_DIR/alerts.log
# Rotation:       automatic, in-place, on each append. When the file
#                 exceeds ALERT_LOG_MAX_BYTES (default 10 MB) it's truncated
#                 to ~50% keeping the most recent records. No `.1` backup.
#                 Set ALERT_LOG_MAX_BYTES=0 to disable.
# ==============================================================================

# Parse a window spec (today/yesterday/all/Nh/Nd/Nw) to a Unix epoch cutoff.
# Echoes the cutoff on success; non-zero exit + stderr message on invalid
# input. Separated from mode_alerts so tests can exercise it independently.
_alerts_window_to_epoch() {
    local w="$1"
    local now; now=$(date +%s)
    case "$w" in
        today)
            # Local midnight today — (now % 86400) is seconds since UTC
            # midnight, not local, but on most servers localtime=UTC and it
            # doesn't meaningfully drift. Precise-to-the-timezone is overkill
            # for an "alerts today" view.
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

# Human-readable timestamp from epoch, portable across GNU/BSD date.
# Used for the WHEN column in the table.
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

    local cutoff cutoff_fmt
    cutoff=$(_alerts_window_to_epoch "$window") || return 1
    cutoff_fmt=$(_alerts_fmt_epoch "$cutoff")

    echo -e "\n${W}── MiLog: Alerts since ${cutoff_fmt} (window=$window) ──${NC}\n"

    # Filter once by epoch, feed the result to both the list and the summary.
    local filtered; filtered=$(mktemp -t milog_alerts.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$filtered'" RETURN

    awk -F'\t' -v cutoff="$cutoff" '$1 >= cutoff' "$log_file" > "$filtered"

    local total; total=$(wc -l < "$filtered" | tr -d ' ')
    total=${total:-0}

    if (( total == 0 )); then
        echo -e "  ${D}no alerts in window${NC}\n"
        return 0
    fi

    # --- Timeline (last ~30 rows, chronological) ---------------------------
    # Most recent is most relevant, but humans read top-down and expect
    # chronological order. Cap at 30 so the table stays glanceable.
    local list_cap=30
    local shown=$total
    (( shown > list_cap )) && shown=$list_cap
    echo -e "  ${W}timeline${NC} ${D}(showing latest ${shown} of ${total})${NC}"
    printf "  %-16s  %-28s  %s\n" "WHEN" "RULE" "TITLE"
    printf "  %-16s  %-28s  %s\n" "────────────────" "────────────────────────────" "──────"

    # Per-row format in bash — calling _alerts_fmt_epoch (which forks date)
    # inside awk's strftime is gawk-only; BSD awk on macOS lacks strftime.
    # 30 row cap keeps the fork count trivial.
    local epoch rule color title body when rule_disp title_disp col
    while IFS=$'\t' read -r epoch rule color title body; do
        [[ -z "$epoch" ]] && continue
        when=$(_alerts_fmt_epoch "$epoch")
        rule_disp="$rule"
        (( ${#rule_disp} > 28 )) && rule_disp="${rule_disp:0:25}..."
        title_disp="$title"
        (( ${#title_disp} > 50 )) && title_disp="${title_disp:0:47}..."
        # Color the rule column by severity (derived from Discord color int):
        #   15158332 / 16711680 → crit  (red)    — exploits, 5xx, sys crit
        #   16753920 / 15844367 → warn  (yellow) — 4xx spike, probes
        #   other               → info  (green)  — test alert etc.
        case "$color" in
            15158332|16711680)    col="$R" ;;
            16753920|15844367)    col="$Y" ;;
            *)                    col="$G" ;;
        esac
        printf "  %-16s  %b%-28s%b  %s\n" "$when" "$col" "$rule_disp" "$NC" "$title_disp"
    done < <(tail -n "$list_cap" "$filtered")

    # --- Summary by rule ----------------------------------------------------
    echo -e "\n  ${W}by rule (top 10)${NC}"
    awk -F'\t' '{c[$2]++} END {for (r in c) printf "%d\t%s\n", c[r], r}' "$filtered" \
        | sort -rn | head -n 10 \
        | awk -F'\t' '{printf "    %5d  %s\n", $1, $2}'

    echo -e "\n  ${D}total: $total alert(s) in window — log at $log_file${NC}\n"
}
