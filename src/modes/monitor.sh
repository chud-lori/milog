# ==============================================================================
# MODE: monitor  +  tui
#
# `milog monitor` runs the bash refresh-and-redraw dashboard (works on any
# POSIX box, no extra binary). `milog tui` execs the Go bubbletea TUI
# when available — richer UI, same data source. Both coexist.
# ==============================================================================

# Locate milog-tui, the Go bubbletea binary. Preference order mirrors
# _web_go_binary so install layouts stay consistent across companions.
_tui_go_binary() {
    if [[ -n "${MILOG_TUI_BIN:-}" && -x "$MILOG_TUI_BIN" ]]; then
        printf '%s' "$MILOG_TUI_BIN"; return 0
    fi
    local candidate
    for candidate in \
        /usr/local/libexec/milog/milog-tui \
        /usr/local/bin/milog-tui; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"
    local self_dir; self_dir=$(cd "$(dirname "$self")" && pwd)
    for candidate in "$self_dir/go/bin/milog-tui" "$self_dir/../go/bin/milog-tui" "$self_dir/../../go/bin/milog-tui"; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    return 1
}

# `milog tui` — run the Go bubbletea TUI. Separate subcommand from
# `milog monitor` so both coexist and users pick. Clear install hint
# when the binary is missing.
mode_tui() {
    local go_bin
    if ! go_bin=$(_tui_go_binary); then
        echo -e "${R}milog-tui is not installed.${NC}" >&2
        echo -e "${D}  it builds alongside milog-web. From a clone:${NC}" >&2
        echo -e "${D}    bash build.sh${NC}" >&2
        echo -e "${D}  until packaged releases arrive, \`milog monitor\` (bash)" >&2
        echo -e "${D}  gives the same data with a simpler render loop.${NC}" >&2
        return 1
    fi
    # Pass the MILOG_* surface through so config stays single-source.
    export MILOG_LOG_DIR="$LOG_DIR" \
           MILOG_APPS="${LOGS[*]}" \
           MILOG_REFRESH="${REFRESH:-5}" \
           MILOG_ALERT_STATE_DIR="${ALERT_STATE_DIR:-$HOME/.cache/milog}"
    exec "$go_bin" "$@"
}

mode_monitor() {
    # Async CPU sampler — reads /proc/stat in a background loop, writes the
    # latest % to a tmpfile. Keeps the render loop from blocking on sleep 0.2.
    local cpu_file cpu_pid
    cpu_file=$(mktemp 2>/dev/null || echo "/tmp/milog.cpu.$$")
    echo 0 > "$cpu_file"
    (
        while :; do
            v=$(cpu_usage)
            printf '%s\n' "$v" > "${cpu_file}.tmp" 2>/dev/null \
                && mv "${cpu_file}.tmp" "$cpu_file" 2>/dev/null
            sleep 1
        done
    ) & cpu_pid=$!

    # Enable sparkline history for nginx_row
    MILOG_HIST_ENABLED=1
    declare -gA HIST

    # Hide cursor and quiet input echo so keystrokes don't litter the TUI.
    tput civis 2>/dev/null || true
    stty -echo 2>/dev/null || true

    local _cleanup='
        kill '"$cpu_pid"' 2>/dev/null
        rm -f "'"$cpu_file"'" "'"${cpu_file}.tmp"'" 2>/dev/null
        stty echo 2>/dev/null
        tput cnorm 2>/dev/null
        printf "\n"
    '
    trap "$_cleanup; exit 0" INT TERM
    trap "$_cleanup" EXIT

    local net_prev_rx=0 net_prev_tx=0
    read -r net_prev_rx net_prev_tx _ <<< "$(net_rx_tx)"

    local first=1 paused=0
    while true; do
        # Reflow for terminal size — runs per tick so SIGWINCH just works.
        milog_update_geometry
        if (( first )); then
            clear
            first=0
        else
            tput cup 0 0 2>/dev/null || printf '\033[H'
        fi
        local CUR_TIME TIMESTAMP TOTAL=0
        CUR_TIME=$(date '+%d/%b/%Y:%H:%M')
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

        local cpu mem_pct mem_used mem_total disk_pct disk_used disk_total
        cpu=$(cat "$cpu_file" 2>/dev/null); cpu=${cpu:-0}
        [[ "$cpu" =~ ^[0-9]+$ ]] || cpu=0
        read -r mem_pct mem_used mem_total <<< "$(mem_info)"
        read -r disk_pct disk_used disk_total <<< "$(disk_info)"

        local net_rx net_tx net_iface
        read -r net_rx net_tx net_iface <<< "$(net_rx_tx)"
        local drx=$(( net_rx - net_prev_rx ))
        local dtx=$(( net_tx - net_prev_tx ))
        if (( ! paused )); then
            net_prev_rx=$net_rx; net_prev_tx=$net_tx
        fi
        local rx_s tx_s; rx_s=$(fmt_bytes "$drx"); tx_s=$(fmt_bytes "$dtx")

        local cpu_col mem_col disk_col
        cpu_col=$(tcol "$cpu"      $THRESH_CPU_WARN  $THRESH_CPU_CRIT)
        mem_col=$(tcol "$mem_pct"  $THRESH_MEM_WARN  $THRESH_MEM_CRIT)
        disk_col=$(tcol "$disk_pct" $THRESH_DISK_WARN $THRESH_DISK_CRIT)

        local cpu_bar mem_bar disk_bar
        cpu_bar=$(ascii_bar $BW "$cpu"      100)
        mem_bar=$(ascii_bar $BW "$mem_pct"  100)
        disk_bar=$(ascii_bar $BW "$disk_pct" 100)

        # --- Single unified box starts here ---
        bdr_top

        # Title row
        local t_p=" MiLog   ${TIMESTAMP}   ${net_iface}"
        local t_c=" ${W}MiLog${NC}   ${D}${TIMESTAMP}${NC}   ${D}${net_iface}${NC}"
        draw_row "$t_p" "$t_c"

        bdr_mid

        # System metrics row 1 — bars
        # Plain: " CPU  xx% [bar18]  MEM  xx% [bar18]  DISK  xx% [bar18]"
        local r1_p
        r1_p=$(printf " CPU %3d%% [%-${BW}s]  MEM %3d%% [%-${BW}s]  DISK %3d%% [%-${BW}s]" \
            "$cpu" "$cpu_bar" "$mem_pct" "$mem_bar" "$disk_pct" "$disk_bar")
        local r1_c
        r1_c=$(printf " CPU %b%3d%%%b [%b%s%b]  MEM %b%3d%%%b [%b%s%b]  DISK %b%3d%%%b [%b%s%b]" \
            "$cpu_col"  "$cpu"      "$NC" "$cpu_col"  "$cpu_bar"  "$NC" \
            "$mem_col"  "$mem_pct"  "$NC" "$mem_col"  "$mem_bar"  "$NC" \
            "$disk_col" "$disk_pct" "$NC" "$disk_col" "$disk_bar" "$NC")
        draw_row "$r1_p" "$r1_c"

        # System metrics row 2 — detail + net
        # Max visible: ' MEM 99999/99999MB  DISK 999.9/999.9GB  dn:999.9MB/s up:999.9MB/s' = 72
        local r2_p=" MEM ${mem_used}/${mem_total}MB  DISK ${disk_used}/${disk_total}GB  dn:${rx_s}/s up:${tx_s}/s"
        local r2_c=" ${D}MEM${NC} ${mem_used}/${mem_total}MB  ${D}DISK${NC} ${disk_used}/${disk_total}GB  ${C}dn:${rx_s}/s${NC} ${G}up:${tx_s}/s${NC}"
        draw_row "$r2_p" "$r2_c"

        bdr_mid

        # Nginx workers
        draw_row " NGINX WORKERS" " ${W}NGINX WORKERS${NC}"
        local workers worker_count
        workers=$(ps aux 2>/dev/null | awk '/nginx: worker/{printf "  pid:%-8s  cpu:%5s%%  mem:%5s%%\n",$2,$3,$4}' | head -6)
        if [[ -z "$workers" ]]; then
            worker_count=0
            draw_row "  (no nginx worker processes found)" "  ${D}(no nginx worker processes found)${NC}"
        else
            worker_count=$(printf '%s\n' "$workers" | wc -l | awk '{print $1}')
            while IFS= read -r wline; do
                draw_row "$wline" "  ${D}${wline:2}${NC}"
            done <<< "$workers"
        fi

        sys_check_alerts "$cpu" "$mem_pct" "$mem_used" "$mem_total" \
                         "$disk_pct" "$disk_used" "$disk_total" "$worker_count"

        bdr_mid

        # Nginx per-app table (no nested box — continues same box with col separators)
        bdr_hdr
        hdr_row
        bdr_hdr

        for name in "${LOGS[@]}"; do
            nginx_row "$name" "$CUR_TIME" TOTAL
        done

        bdr_sep

        # Footer
        local upstr; upstr=$(uptime -p 2>/dev/null | sed 's/up //' || echo 'n/a')
        local f_p=" TOTAL: ${TOTAL} req/min   UP: ${upstr}"
        local f_c=" ${W}TOTAL:${NC} ${TOTAL} req/min   ${D}UP: ${upstr}${NC}"
        draw_row "$f_p" "$f_c"

        bdr_bot
        local ptag=""
        (( paused )) && ptag="  ${R}[PAUSED]${NC}"
        # Clear-to-EOL so shorter footer over a longer one doesn't leave junk.
        printf "${D} q:quit  p:pause  r:refresh  +/-:rate (${REFRESH}s)  |  5xx>=${THRESH_5XX_WARN} blinks${NC}${ptag}\033[K\n"
        # Also clear from cursor down in case previous frame was taller.
        printf '\033[J'

        MILOG_HIST_PAUSED=$paused
        local key
        key=$(wait_or_key "$REFRESH")
        case "$key" in
            q|Q) break ;;
            p|P) paused=$(( 1 - paused )) ;;
            r|R) ;;
            +)   (( REFRESH > 1 )) && REFRESH=$(( REFRESH - 1 )) ;;
            -)   REFRESH=$(( REFRESH + 1 )) ;;
            *)   ;;
        esac
    done
}

