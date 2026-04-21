#!/usr/bin/env bash
# ==============================================================================
# MiLog — Nginx + System Monitor (V5.0)
# ==============================================================================
set -euo pipefail

# --- Configuration (defaults; overridable via config file or env) ---
LOG_DIR="/var/log/nginx"
LOGS=("dolanan" "ethok" "finance" "ldr" "profile" "sinepil")
REFRESH=5

# Optional user config — sourced if present. Can override any variable above.
# Example:
#     LOG_DIR="/var/log/nginx"
#     LOGS=(myapp api web)          # or leave unset to auto-discover
#     REFRESH=3
MILOG_CONFIG="${MILOG_CONFIG:-$HOME/.config/milog/config.sh}"
# shellcheck disable=SC1090
[[ -f "$MILOG_CONFIG" ]] && . "$MILOG_CONFIG"

# Env var overrides win over the config file
[[ -n "${MILOG_LOG_DIR:-}" ]] && LOG_DIR="$MILOG_LOG_DIR"
[[ -n "${MILOG_APPS:-}"    ]] && read -r -a LOGS <<< "$MILOG_APPS"

# Auto-discover: if no apps ended up configured, glob *.access.log in LOG_DIR
if [[ ${#LOGS[@]} -eq 0 ]]; then
    shopt -s nullglob
    for f in "$LOG_DIR"/*.access.log; do
        name="${f##*/}"; name="${name%.access.log}"
        LOGS+=("$name")
    done
    shopt -u nullglob
fi

if [[ ${#LOGS[@]} -eq 0 ]]; then
    echo "MiLog: no apps configured and none found in $LOG_DIR" >&2
    echo "  Set MILOG_APPS=\"a b c\", edit $MILOG_CONFIG, or drop *.access.log into $LOG_DIR" >&2
    exit 1
fi

# Alert thresholds
THRESH_REQ_WARN=15
THRESH_REQ_CRIT=40
THRESH_CPU_WARN=70
THRESH_CPU_CRIT=90
THRESH_MEM_WARN=80
THRESH_MEM_CRIT=95
THRESH_DISK_WARN=80
THRESH_DISK_CRIT=95
THRESH_4XX_WARN=20
THRESH_5XX_WARN=5

# Sparkline history depth (samples kept per app in monitor mode)
SPARK_LEN=30

# --- ANSI ---
R="\033[0;31m"  G="\033[0;32m"  Y="\033[0;33m"  B="\033[0;34m"
M="\033[0;35m"  C="\033[0;36m"  W="\033[1;37m"  D="\033[0;90m"
RBLINK="\033[0;31;5m"
NC="\033[0m"

# ==============================================================================
# BOX DRAWING — single source of truth for geometry
#
# Table columns: APP(10) | REQ/MIN(8) | STATUS(10) | INTENSITY(35)
# Row layout between outer │…│:
#   " " app(10) " │ " req(8) " │ " status(10) " │ " bar(35) " "
#   = 1+10 + 3+8 + 3+10 + 3+35+1 = 74
# Box rules:  ─(12)┬─(10)┬─(12)┬─(37) = 12+1+10+1+12+1+37 = 74  ✓
# ==============================================================================
W_APP=10; W_REQ=8; W_ST=10; W_BAR=35
INNER=74   # verified: row chars == rule chars == 74

spc() { printf '%*s' "$1" ''; }
hrule() { printf '─%.0s' $(seq 1 "$1"); }

# Single-box rules — all share INNER=74
bdr_top() { printf "${W}┌$(hrule $((W_APP+2)))┬$(hrule $((W_REQ+2)))┬$(hrule $((W_ST+2)))┬$(hrule $((W_BAR+2)))┐${NC}\n"; }
bdr_hdr() { printf "${W}├$(hrule $((W_APP+2)))┼$(hrule $((W_REQ+2)))┼$(hrule $((W_ST+2)))┼$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_mid() { printf "${W}├$(hrule $((INNER)))┤${NC}\n"; }
bdr_sep() { printf "${W}├$(hrule $((W_APP+2)))┴$(hrule $((W_REQ+2)))┴$(hrule $((W_ST+2)))┴$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_bot() { printf "${W}└$(hrule $((INNER)))┘${NC}\n"; }

# Full-width content row: │ plain/colored content + padding │
# $1=plain_text (for measuring)  $2=colored_text (for printing)
# Plain must not contain any ANSI sequences.
draw_row() {
    local plain="$1" colored="$2"
    local pad=$(( INNER - ${#plain} ))
    printf "${W}│${NC}%b" "$colored"
    [[ $pad -gt 0 ]] && spc "$pad"
    printf "${W}│${NC}\n"
}

# Table data row — padding computed from plain args only
# $1=name $2=count $3=st_plain(10 chars) $4=st_colored $5=bars_plain $6=bars_colored $7=alert_color
trow() {
    local name="$1" count="$2" st_plain="$3" st_col="$4" bars_plain="$5" bars_col="$6" alert="${7:-}"
    local n_pad=$(( W_APP - ${#name}       ))
    local r_pad=$(( W_REQ - ${#count}      ))
    local b_pad=$(( W_BAR - ${#bars_plain} ))
    printf "${W}│${NC} %b%s${NC}" "$alert" "$name";  spc "$n_pad"
    printf " ${W}│${NC} %s"       "$count";           spc "$r_pad"
    printf " ${W}│${NC} %b"       "$st_col"
    printf " ${W}│${NC} %b"       "$bars_col";        spc "$b_pad"
    printf " ${W}│${NC}\n"
}

# Column header row (no color escape issues — plain printf)
hdr_row() {
    printf "${W}│${NC} %-${W_APP}s ${W}│${NC} %-${W_REQ}s ${W}│${NC} %-${W_ST}s ${W}│${NC} %-${W_BAR}s ${W}│${NC}\n" \
        "APP" "REQ/MIN" "STATUS" "INTENSITY"
}

# ==============================================================================
# SYSTEM METRICS
# ==============================================================================

cpu_usage() {
    local s1 s2 t1 i1 t2 i2
    s1=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
    sleep 0.2
    s2=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
    read -r t1 i1 <<< "$s1"; read -r t2 i2 <<< "$s2"
    local dt=$(( t2-t1 )) di=$(( i2-i1 ))
    [[ $dt -eq 0 ]] && echo 0 || echo $(( 100*(dt-di)/dt ))
}

mem_info() {
    awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}
         END{u=t-a; printf "%d %d %d\n", int(u*100/t), int(u/1024), int(t/1024)}' /proc/meminfo
}

disk_info() {
    df / | awk 'NR==2{gsub(/%/,"",$5); printf "%d %.1f %.1f\n",$5,$3/1048576,$2/1048576}'
}

net_rx_tx() {
    local iface
    iface=$(ip route 2>/dev/null | awk '/^default/{print $5;exit}')
    [[ -z "$iface" ]] && iface=$(ls /sys/class/net/ | grep -v lo | head -1)
    local rx tx
    rx=$(cat /sys/class/net/"$iface"/statistics/rx_bytes 2>/dev/null || echo 0)
    tx=$(cat /sys/class/net/"$iface"/statistics/tx_bytes 2>/dev/null || echo 0)
    echo "$rx $tx $iface"
}

fmt_bytes() {
    local b=$1
    if   (( b >= 1073741824 )); then awk "BEGIN{printf \"%.1fGB\",$b/1073741824}"
    elif (( b >= 1048576 ));    then awk "BEGIN{printf \"%.1fMB\",$b/1048576}"
    elif (( b >= 1024 ));       then awk "BEGIN{printf \"%.1fKB\",$b/1024}"
    else printf "%dB" "$b"
    fi
}

# ASCII progress bar using only hyphen and equals — no wide-glyph block chars
# $1=width  $2=value  $3=max → prints exactly $1 chars
ascii_bar() {
    local width=$1 val=$2 max=${3:-100}
    [[ $max -le 0 ]] && max=1
    local f=$(( val * width / max ))
    [[ $f -gt $width ]] && f=$width
    local e=$(( width - f ))
    local i
    for (( i=0; i<f; i++ )); do printf '|'; done
    for (( i=0; i<e; i++ )); do printf '.'; done
}

tcol() {
    local v=$1 w=$2 c=$3
    (( v >= c )) && { printf '%s' "$R"; return; }
    (( v >= w )) && { printf '%s' "$Y"; return; }
    printf '%s' "$G"
}

# Unicode sparkline: reads space-separated ints on $1, prints sparkline chars.
# Each sample scales to one of 8 block chars relative to the max in the series.
sparkline_render() {
    local -a vals=( $1 )
    local -a blk=('▁' '▂' '▃' '▄' '▅' '▆' '▇' '█')
    local max=0 v
    for v in "${vals[@]}"; do (( v > max )) && max=$v; done
    local out="" idx
    if (( max == 0 )); then
        for v in "${vals[@]}"; do out+="${blk[0]}"; done
    else
        for v in "${vals[@]}"; do
            idx=$(( v * 7 / max ))
            (( idx > 7 )) && idx=7
            (( idx < 0 )) && idx=0
            out+="${blk[$idx]}"
        done
    fi
    printf '%s' "$out"
}

# Wait up to $1 seconds for a single keypress. Prints the key if pressed, empty
# on timeout. Needs an interactive tty; silent read so input doesn't echo.
wait_or_key() {
    local k
    if read -rsn1 -t "$1" k 2>/dev/null; then
        printf '%s' "$k"
    fi
}

# ==============================================================================
# NGINX ROW HELPERS
# ==============================================================================

nginx_row() {
    local name="$1" CUR_TIME="$2" TOTAL_ref="$3"
    local file="$LOG_DIR/$name.access.log"
    local count=0 c4=0 c5=0

    # Single awk pass: total + 4xx + 5xx in one file scan.
    if [[ -f "$file" ]]; then
        read -r count c4 c5 <<< "$(awk -v t="$CUR_TIME" '
            index($0, t) {
                n++
                if (match($0, / [45][0-9][0-9] /)) {
                    if (substr($0, RSTART+1, 1) == "4") e4++; else e5++
                }
            }
            END { printf "%d %d %d\n", n+0, e4+0, e5+0 }
        ' "$file" 2>/dev/null)"
        count=${count:-0}; c4=${c4:-0}; c5=${c5:-0}
    fi
    # shellcheck disable=SC2034
    eval "$TOTAL_ref=$(( ${!TOTAL_ref} + count ))"

    local st_plain st_col b_col alert=""
    if [[ $count -gt 0 ]]; then
        st_plain="● ACTIVE  "; st_col="${G}● ACTIVE  ${NC}"; b_col=$G
        [[ $count -gt $THRESH_REQ_WARN ]] && b_col=$Y
        [[ $count -gt $THRESH_REQ_CRIT ]] && { b_col=$R; st_col="${R}● ACTIVE  ${NC}"; }
    else
        st_plain="○ IDLE    "; st_col="${D}○ IDLE    ${NC}"; b_col=$D
    fi

    [[ $c5 -ge $THRESH_5XX_WARN ]]                   && alert="$RBLINK"
    [[ $c4 -ge $THRESH_4XX_WARN && -z "$alert" ]]    && alert="$R"
    [[ $count -gt $THRESH_REQ_CRIT && -z "$alert" ]] && alert="$R"

    local bars_plain bars_col
    if [[ "${MILOG_HIST_ENABLED:-0}" == "1" ]]; then
        # Push current sample into ring buffer (HIST is a global assoc array).
        # Freeze the buffer when MILOG_HIST_PAUSED=1 so paused view doesn't drift.
        local -a hist_arr=( ${HIST[$name]:-} )
        if [[ "${MILOG_HIST_PAUSED:-0}" != "1" ]]; then
            hist_arr+=( "$count" )
            if (( ${#hist_arr[@]} > SPARK_LEN )); then
                hist_arr=( "${hist_arr[@]: -$SPARK_LEN}" )
            fi
            HIST[$name]="${hist_arr[*]}"
        fi
        # Handle first tick before any samples exist
        (( ${#hist_arr[@]} == 0 )) && hist_arr=( 0 )

        local spark n_samples=${#hist_arr[@]}
        spark=$(sparkline_render "${hist_arr[*]}")
        # Plain placeholder of equal column-width for padding arithmetic.
        bars_plain=$(printf '.%.0s' $(seq 1 "$n_samples"))
        bars_col="${b_col}${spark}${NC}"
    else
        local bc=$(( count / 2 ))
        [[ $bc -gt $W_BAR ]] && bc=$W_BAR
        if [[ $bc -gt 0 ]]; then
            bars_plain=$(printf '|%.0s' $(seq 1 $bc))
            bars_col="${b_col}${bars_plain}${NC}"
        else
            bars_plain="-"; bars_col="${D}-${NC}"
        fi
    fi

    # Append error tag, trimming bar/sparkline to fit
    if [[ $c4 -gt 0 || $c5 -gt 0 ]]; then
        local etag_p=" 4xx:${c4} 5xx:${c5}"
        local etag_c=" ${Y}4xx:${c4}${NC} ${R}5xx:${c5}${NC}"
        local max_b=$(( W_BAR - ${#etag_p} ))
        if [[ ${#bars_plain} -gt $max_b ]]; then
            bars_plain="${bars_plain:0:$max_b}"
            if [[ "${MILOG_HIST_ENABLED:-0}" == "1" ]]; then
                # Re-render sparkline truncated to max_b samples (tail end)
                local -a trimmed=( ${HIST[$name]:-} )
                trimmed=( "${trimmed[@]: -$max_b}" )
                bars_col="${b_col}$(sparkline_render "${trimmed[*]}")${NC}"
            else
                bars_col="${b_col}${bars_plain}${NC}"
            fi
        fi
        bars_plain="${bars_plain}${etag_p}"
        bars_col="${bars_col}${etag_c}"
    fi

    trow "$name" "$count" "$st_plain" "$st_col" "$bars_plain" "$bars_col" "$alert"
}

# ==============================================================================
# MODE: monitor
# ==============================================================================
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

        local BW=11  # bar width: (INNER=74 - 39 fixed chars) / 3 cols = 11 max
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
        local workers
        workers=$(ps aux 2>/dev/null | awk '/nginx: worker/{printf "  pid:%-8s  cpu:%5s%%  mem:%5s%%\n",$2,$3,$4}' | head -6)
        if [[ -z "$workers" ]]; then
            draw_row "  (no nginx worker processes found)" "  ${D}(no nginx worker processes found)${NC}"
        else
            while IFS= read -r wline; do
                draw_row "$wline" "  ${D}${wline:2}${NC}"
            done <<< "$workers"
        fi

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

# ==============================================================================
# MODE: rate — nginx-only
# ==============================================================================
mode_rate() {
    while true; do
        clear
        local CUR_TIME TIMESTAMP TOTAL=0
        CUR_TIME=$(date '+%d/%b/%Y:%H:%M')
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

        bdr_top
        draw_row " MiLog   ${TIMESTAMP}" " ${W}MiLog${NC}   ${D}${TIMESTAMP}${NC}"
        bdr_mid
        bdr_hdr
        hdr_row
        bdr_hdr

        for name in "${LOGS[@]}"; do
            nginx_row "$name" "$CUR_TIME" TOTAL
        done

        bdr_sep
        draw_row " TOTAL: ${TOTAL} req/min" " ${W}TOTAL:${NC} ${TOTAL} req/min"
        bdr_bot
        printf "${D} Ctrl+C to exit  |  Refresh: ${REFRESH}s${NC}\n"
        sleep "$REFRESH"
    done
}

# ==============================================================================
# MODE: health
# ==============================================================================
mode_health() {
    echo -e "\n${W}── MiLog: Status Code Health ──${NC}\n"
    printf "%-12s  %8s  %8s  %8s  %8s  %8s\n" "APP" "TOTAL" "2xx" "3xx" "4xx" "5xx"
    printf "%-12s  %8s  %8s  %8s  %8s  %8s\n" "───────────" "───────" "───────" "───────" "───────" "───────"
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        [[ -f "$file" ]] || { printf "%-12s  %8s\n" "$name" "(not found)"; continue; }
        local total s2=0 s3=0 s4=0 s5=0
        total=$(wc -l < "$file")
        s2=$(grep -c ' 2[0-9][0-9] ' "$file" 2>/dev/null || true)
        s3=$(grep -c ' 3[0-9][0-9] ' "$file" 2>/dev/null || true)
        s4=$(grep -c ' 4[0-9][0-9] ' "$file" 2>/dev/null || true)
        s5=$(grep -c ' 5[0-9][0-9] ' "$file" 2>/dev/null || true)
        local c4=$NC c5=$NC
        [[ $s4 -gt $THRESH_4XX_WARN ]] && c4=$Y
        [[ $s5 -gt $THRESH_5XX_WARN ]] && c5=$R
        printf "%-12s  %8s  %8s  %8s  ${c4}%8s${NC}  ${c5}%8s${NC}\n" \
            "$name" "$total" "$s2" "$s3" "$s4" "$s5"
    done
    echo ""
}

# ==============================================================================
# MODE: top
# ==============================================================================
mode_top() {
    local n="${1:-10}"
    echo -e "\n${W}── MiLog: Top ${n} IPs ──${NC}\n"
    printf "%-5s  %-18s  %10s\n" "RANK" "IP" "REQUESTS"
    printf "%-5s  %-18s  %10s\n" "────" "─────────────────" "────────"
    local tmp; tmp=$(mktemp)
    for name in "${LOGS[@]}"; do
        [[ -f "$LOG_DIR/$name.access.log" ]] && awk '{print $1}' "$LOG_DIR/$name.access.log" >> "$tmp"
    done
    sort "$tmp" | uniq -c | sort -rn | head -n "$n" | \
    awk -v r="$R" -v y="$Y" -v nc="$NC" 'BEGIN{i=1}{
        col=""; if(i==1)col=r; else if(i<=3)col=y
        printf "%-5s  %-18s  %s%10s%s\n","#"i,$2,col,$1,nc; i++}'
    rm -f "$tmp"; echo ""
}

# ==============================================================================
# MODE: stats
# ==============================================================================
mode_stats() {
    local name="${1:-}"
    [[ -z "$name" || ! " ${LOGS[*]} " =~ " $name " ]] && {
        echo -e "${R}Usage: $0 stats <app>${NC}  Apps: ${LOGS[*]}"; exit 1; }
    local file="$LOG_DIR/$name.access.log"
    [[ -f "$file" ]] || { echo -e "${R}Not found: $file${NC}"; exit 1; }
    echo -e "\n${W}── MiLog: Hourly breakdown — ${name} ──${NC}\n"
    awk '{match($4,/\[([0-9]{2}\/[A-Za-z]+\/[0-9]{4}):([0-9]{2})/,a)
         if(a[2]!="")h[a[2]]++}
         END{for(x in h)print x,h[x]}' "$file" | sort | \
    awk -v g="$G" -v y="$Y" -v r="$R" -v nc="$NC" '
    BEGIN{max=0}{if($2>max)max=$2;d[NR]=$0;n=NR}
    END{for(i=1;i<=n;i++){split(d[i],a," ")
        b=int((a[2]/max)*40); bars=""
        for(j=0;j<b;j++) bars=bars"|"
        col=g; if(a[2]/max>0.6)col=y; if(a[2]/max>0.85)col=r
        printf "%s:00  %s%-40s%s  %d\n",a[1],col,bars,nc,a[2]}}'
    echo ""
}

# ==============================================================================
# MODE: grep
# ==============================================================================
mode_grep() {
    local name="${1:-}" pattern="${2:-.}"
    [[ -z "$name" || ! " ${LOGS[*]} " =~ " $name " ]] && {
        echo -e "${R}Usage: $0 grep <app> <pattern>${NC}  Apps: ${LOGS[*]}"; exit 1; }
    echo -e "${D}tail -F $LOG_DIR/$name.access.log | grep '$pattern'  (Ctrl+C)${NC}\n"
    tail -F "$LOG_DIR/$name.access.log" | grep --line-buffered -i "$pattern"
}

# ==============================================================================
# MODE: errors
# ==============================================================================
mode_errors() {
    echo -e "${D}Watching 4xx/5xx across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$i]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            tail -F "$file" 2>/dev/null | \
                grep --line-buffered ' [45][0-9][0-9] ' | \
                awk -v col="$col" -v lbl="$label" -v nc="$NC" \
                    '{print col"["lbl"]"nc" "$0; fflush()}' &
            pids+=($!)
        fi
        (( i++ )) || true
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

# ==============================================================================
# MODE: probes — scanner / bot traffic by user-agent + protocol-level probes
# Wide UA database covering security tools, mass scanners, SEO bots,
# generic HTTP libs, AI crawlers, and non-HTTP protocol smuggling attempts.
# ==============================================================================
mode_probes() {
    echo -e "${D}Watching scanner/bot traffic across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    # Protocol-level: SSH banner, TLS ClientHello sent to plain HTTP (nginx logs
    # the bytes as literal \xNN — double backslash so grep sees one).
    local pat='SSH-2\.0|\\x16\\x03|\\x00\\x00'
    # Security / pentest tools
    pat+='|masscan|zmap|zgrab|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster'
    pat+='|dirb|ffuf|wfuzz|feroxbuster|nessus|openvas|acunetix|wpscan|joomscan'
    pat+='|burp|zaproxy|owasp|metasploit|meterpreter|w3af|webshag'
    # Mass internet scanners / research crawlers
    pat+='|l9explore|l9tcpid|l9retrieve|leakix'
    pat+='|libredtail|httpx|naabu|katana|subfinder'
    pat+='|expanseinc|censysinspect|shodan|stretchoid|internet-measurement'
    pat+='|greenbone|qualys|rapid7|detectify|intruder\.io|netcraftsurvey'
    pat+='|netsystemsresearch|paloalto|projectdiscovery|odin\.ai|onyphe'
    # SEO / advertising crawlers (often unwanted)
    pat+='|ahrefsbot|semrushbot|dotbot|mj12bot|blexbot|petalbot|serpstat'
    pat+='|dataforseobot|bytespider|mauibot|megaindex|seznambot'
    # AI crawlers
    pat+='|claudebot|gptbot|ccbot|anthropic-ai|perplexitybot|youbot'
    pat+='|amazonbot|applebot-extended|cohere-ai|diffbot'
    # Generic HTTP libraries (legit use exists but often scripted)
    pat+='|python-requests|python-urllib|aiohttp|go-http-client|okhttp'
    pat+='|libwww-perl|java/1\.|apache-httpclient|restsharp|http_request2'
    pat+='|guzzlehttp|node-fetch|axios|got\(|scrapy|mechanize'
    # Headless / automation
    pat+='|headlesschrome|phantomjs|puppeteer|playwright|selenium'
    # Generic bot / crawler hints in UA
    pat+='|[Ss]canner|[Bb]ot/|[Cc]rawler|[Ss]pider|probe-|fuzzer|harvester'
    # Known payloads
    pat+='|hello,\s*world'

    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$i]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            tail -F "$file" 2>/dev/null | \
                grep --line-buffered -Ei "$pat" | \
                awk -v col="$col" -v lbl="$label" -v nc="$NC" \
                    '{print col"["lbl"]"nc" "$0; fflush()}' &
            pids+=($!)
        fi
        (( i++ )) || true
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

# ==============================================================================
# MODE: suspects — heuristic IP ranking (behavioral, not just UA)
# Scores each IP in the last N log lines across all apps, using:
#   4xx hits      × 2   (probing non-existent paths)
#   5xx hits      × 3   (causing errors)
#   missing UA    × 1   (scripted requests often send "-")
#   scanner UA    + 10  (flat bonus if UA matches known tool)
#   unique paths  / 5   (scanning behavior — many endpoints from one IP)
# Prints top N with flags explaining why.
# ==============================================================================
mode_suspects() {
    local topn="${1:-20}"
    local window="${2:-2000}"

    echo -e "\n${W}── MiLog: Suspicious IPs (last ${window} lines/app, top ${topn}) ──${NC}\n"
    printf "%-6s  %-18s  %6s  %5s  %5s  %6s  %s\n" \
        "SCORE" "IP" "REQ" "4XX" "5XX" "PATHS" "FLAGS"
    printf "%-6s  %-18s  %6s  %5s  %5s  %6s  %s\n" \
        "─────" "─────────────────" "──────" "─────" "─────" "──────" "──────────"

    local tmp; tmp=$(mktemp)
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        [[ -f "$file" ]] && tail -n "$window" "$file" >> "$tmp"
    done

    awk '
    BEGIN { FS = "\"" }
    NF >= 6 {
        split($1, a, " ");  ip = a[1]
        gsub(/^ +| +$/, "", $3);  split($3, s, " ");  status = s[1]
        req = $2;  ua = $6

        reqs[ip]++
        if (status ~ /^4/) e4[ip]++
        if (status ~ /^5/) e5[ip]++
        if (ua == "-" || ua == "") no_ua[ip]++

        key = ip "|" req
        if (!(key in seen)) { seen[key] = 1;  paths[ip]++ }

        ual = tolower(ua)
        if (ual ~ /masscan|zgrab|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster|ffuf|wfuzz|feroxbuster|libredtail|l9explore|shodan|censysinspect|expanseinc|httpx|python-requests|go-http-client|okhttp|libwww-perl|scanner|fuzzer|leakix/) {
            scanner_ua[ip] = 1
        }
    }
    END {
        for (ip in reqs) {
            sc = e4[ip]*2 + e5[ip]*3 + no_ua[ip] + (scanner_ua[ip]?10:0) + int(paths[ip]/5)
            if (sc < 3) continue
            f = ""
            if (scanner_ua[ip])    f = f " SCANNER"
            if (no_ua[ip] > 0)     f = f " NO-UA"
            if (e4[ip] >= 20)      f = f " HIGH-4XX"
            if (e5[ip] >= 5)       f = f " HIGH-5XX"
            if (paths[ip] >= 10)   f = f " MANY-PATHS"
            sub(/^ /, "", f)
            printf "%d\t%s\t%d\t%d\t%d\t%d\t%s\n", sc, ip, reqs[ip], e4[ip]+0, e5[ip]+0, paths[ip]+0, f
        }
    }' "$tmp" | sort -t$'\t' -k1,1 -rn | head -n "$topn" | \
    awk -F'\t' -v R="$R" -v Y="$Y" -v G="$G" -v NC="$NC" '{
        c = G;  if ($1+0 >= 10) c = Y;  if ($1+0 >= 30) c = R
        printf "%s%-6s%s  %-18s  %6s  %5s  %5s  %6s  %s\n", c, $1, NC, $2, $3, $4, $5, $6, $7
    }'

    rm -f "$tmp"
    echo ""
}

# ==============================================================================
# MODE: exploits — L7 attack payloads + scanner fingerprints
# Catches path traversal, LFI, RCE, SQLi, XSS, Log4Shell, dotfile/secret probes,
# infra-API probes (Docker/actuator/etc), CMS admin scans, and known scanner UAs.
# Example matches:
#   GET /index.php?lang=../../../../tmp/foo      (path traversal)
#   GET /containers/json                         (docker API probe)
#   GET /SDK/webLanguage                         (hikvision probe)
#   "libredtail-http" user-agent                 (scanner UA)
# ==============================================================================
mode_exploits() {
    echo -e "${D}Watching exploit attempts across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    # Pattern built in groups for readability. ERE, case-insensitive.
    local pat='\.\./|%2e%2e'                                                   # path traversal
    pat+='|/etc/passwd|/etc/shadow|/proc/self/environ'                         # target files
    pat+='|/containers/json|/actuator/|/server-status|/console(/|\?)|/druid/'  # infra probes
    pat+='|/SDK/web|/cgi-bin/|/boaform/|/HNAP1'                                # embedded-device probes
    pat+='|/wp-admin|/wp-login|/wp-content/plugins|/xmlrpc\.php'               # wordpress
    pat+='|/phpmyadmin|/pma/|/mysql/admin'                                     # phpmyadmin
    pat+='|/\.env|/\.git/|/\.aws/|/\.ssh/|/\.DS_Store'                         # dotfiles / secrets
    pat+='|/config\.(php|json|yml|yaml)|/web\.config'                          # config files
    pat+='|jndi:|\$\{jndi|log4j'                                               # log4shell
    pat+='|union[+% ]+select|select[+% ]+from|sleep\([0-9]|benchmark\('        # sqli
    pat+='|or[+% ]+1=1|%27[+% ]*or|%27%20or'                                  # sqli
    pat+='|<script|%3cscript|onerror=|onload=|javascript:'                     # xss
    pat+='|base64_decode|eval\(|system\(|passthru\(|shell_exec'                # rce fn
    pat+='|libredtail|nikto|masscan|zgrab|sqlmap|nuclei|gobuster'              # scanner UAs
    pat+='|dirbuster|wfuzz|l9explore|l9tcpid|hello,\s?world'                   # scanner UAs

    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$i]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            tail -F "$file" 2>/dev/null | \
                grep --line-buffered -Ei "$pat" | \
                awk -v col="$col" -v lbl="$label" -v r="$R" -v nc="$NC" \
                    '{print col"["lbl"]"nc" "r"[EXPLOIT]"nc" "$0; fflush()}' &
            pids+=($!)
        fi
        (( i++ )) || true
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

# ==============================================================================
# MODE: config — manage the user config file without opening an editor
# ==============================================================================

_cfg_ensure_dir() {
    local d; d=$(dirname "$MILOG_CONFIG")
    mkdir -p "$d" 2>/dev/null || {
        echo -e "${R}Cannot create config directory: $d${NC}" >&2; return 1; }
}

# Read LOGS array as defined LITERALLY in the config file (ignores the
# hardcoded script defaults). Outputs one app per line; empty if no LOGS= line.
_cfg_read_logs() {
    [[ -f "$MILOG_CONFIG" ]] || return 0
    (
        LOGS=()
        # shellcheck disable=SC1090
        . "$MILOG_CONFIG" 2>/dev/null || true
        (( ${#LOGS[@]} > 0 )) && printf '%s\n' "${LOGS[@]}"
    )
}

# Replace or append a single-line assignment `KEY=VALUE` in the config file.
_cfg_write_line() {
    local line="$1" key="${1%%=*}"
    _cfg_ensure_dir || return 1
    [[ -e "$MILOG_CONFIG" ]] || : > "$MILOG_CONFIG"
    if grep -qE "^[[:space:]]*${key}=" "$MILOG_CONFIG" 2>/dev/null; then
        local tmp; tmp=$(mktemp)
        awk -v k="$key" -v repl="$line" '
            $0 ~ "^[[:space:]]*" k "=" && !done { print repl; done=1; next }
            { print }
        ' "$MILOG_CONFIG" > "$tmp" && mv "$tmp" "$MILOG_CONFIG"
    else
        printf '%s\n' "$line" >> "$MILOG_CONFIG"
    fi
}

config_show() {
    echo -e "${W}Config path:${NC} $MILOG_CONFIG"
    if [[ -f "$MILOG_CONFIG" ]]; then
        echo -e "${D}  (exists)${NC}"
    else
        echo -e "${D}  (not created yet — run 'milog config init')${NC}"
    fi
    echo
    echo -e "${W}Resolved values:${NC}"
    printf "  %-22s %s\n" "LOG_DIR"          "$LOG_DIR"
    printf "  %-22s (%s)\n" "LOGS"           "${LOGS[*]}"
    printf "  %-22s %s\n" "REFRESH"          "$REFRESH"
    printf "  %-22s %s\n" "SPARK_LEN"        "$SPARK_LEN"
    printf "  %-22s warn=%s crit=%s\n" "req/min"  "$THRESH_REQ_WARN"  "$THRESH_REQ_CRIT"
    printf "  %-22s warn=%s crit=%s\n" "cpu"      "$THRESH_CPU_WARN"  "$THRESH_CPU_CRIT"
    printf "  %-22s warn=%s crit=%s\n" "mem"      "$THRESH_MEM_WARN"  "$THRESH_MEM_CRIT"
    printf "  %-22s warn=%s crit=%s\n" "disk"     "$THRESH_DISK_WARN" "$THRESH_DISK_CRIT"
    printf "  %-22s 4xx=%s 5xx=%s\n"   "status thresholds" "$THRESH_4XX_WARN" "$THRESH_5XX_WARN"
}

config_init() {
    if [[ -e "$MILOG_CONFIG" ]]; then
        echo -e "${Y}Config already exists:${NC} $MILOG_CONFIG"
        echo "Use 'milog config edit' to modify, or delete the file first."
        return 1
    fi
    _cfg_ensure_dir || return 1
    cat > "$MILOG_CONFIG" <<'EOF'
# MiLog config — sourced as bash. Overrides defaults from milog.sh.
# Uncomment a line to activate it.

# Directory containing nginx access logs
# LOG_DIR="/var/log/nginx"

# Apps to monitor (basenames of <name>.access.log).
# Leave empty () to auto-discover all *.access.log in LOG_DIR.
# LOGS=(api web admin)

# Dashboard refresh interval (seconds) and sparkline history depth
# REFRESH=5
# SPARK_LEN=30

# Thresholds
# THRESH_REQ_WARN=15
# THRESH_REQ_CRIT=40
# THRESH_CPU_WARN=70
# THRESH_CPU_CRIT=90
# THRESH_MEM_WARN=80
# THRESH_MEM_CRIT=95
# THRESH_DISK_WARN=80
# THRESH_DISK_CRIT=95
# THRESH_4XX_WARN=20
# THRESH_5XX_WARN=5
EOF
    echo -e "${G}Created${NC} $MILOG_CONFIG"
    echo "Edit with 'milog config edit' or set values with 'milog config set <KEY> <VALUE>'."
}

config_edit() {
    _cfg_ensure_dir || return 1
    [[ -e "$MILOG_CONFIG" ]] || config_init >/dev/null
    "${EDITOR:-vi}" "$MILOG_CONFIG"
}

config_path() {
    echo "$MILOG_CONFIG"
}

config_set() {
    local key="$1" val="$2"
    if [[ -z "$key" || $# -lt 2 ]]; then
        echo -e "${R}Usage:${NC} milog config set <KEY> <VALUE>"
        return 1
    fi
    # Numeric values unquoted; strings double-quoted; empty string → ""
    local quoted
    if [[ "$val" =~ ^-?[0-9]+$ ]]; then
        quoted="$val"
    else
        # Escape any embedded double-quotes
        quoted="\"${val//\"/\\\"}\""
    fi
    _cfg_write_line "${key}=${quoted}"
    echo -e "${G}Set${NC} ${key}=${quoted} in $MILOG_CONFIG"
}

config_add() {
    local name="$1"
    [[ -z "$name" ]] && { echo -e "${R}Usage:${NC} milog config add <app>"; return 1; }
    local -a cur=()
    local l
    while IFS= read -r l; do [[ -n "$l" ]] && cur+=("$l"); done < <(_cfg_read_logs)
    if (( ${#cur[@]} > 0 )); then
        for l in "${cur[@]}"; do
            [[ "$l" == "$name" ]] && { echo -e "${Y}Already present:${NC} $name"; return 0; }
        done
    fi
    cur+=("$name")
    _cfg_write_line "LOGS=(${cur[*]})"
    echo -e "${G}Added${NC} '$name' → LOGS=(${cur[*]})"
    local f="$LOG_DIR/$name.access.log"
    [[ -f "$f" ]] || echo -e "${D}  note: $f does not exist yet${NC}"
}

config_rm() {
    local name="$1"
    [[ -z "$name" ]] && { echo -e "${R}Usage:${NC} milog config rm <app>"; return 1; }
    local -a cur=() new=()
    local l found=0
    while IFS= read -r l; do [[ -n "$l" ]] && cur+=("$l"); done < <(_cfg_read_logs)
    if (( ${#cur[@]} > 0 )); then
        for l in "${cur[@]}"; do
            if [[ "$l" == "$name" ]]; then found=1; else new+=("$l"); fi
        done
    fi
    if (( ! found )); then
        echo -e "${Y}Not present in config LOGS:${NC} $name"
        echo -e "${D}  current: (${cur[*]})${NC}"
        return 1
    fi
    _cfg_write_line "LOGS=(${new[*]})"
    echo -e "${G}Removed${NC} '$name' → LOGS=(${new[*]})"
}

config_dir() {
    local dir="$1"
    [[ -z "$dir" ]] && { echo -e "${R}Usage:${NC} milog config dir <path>"; return 1; }
    config_set LOG_DIR "$dir"
}

config_help() {
    echo -e "
${W}milog config${NC} — edit the user config without opening a text editor

${W}USAGE${NC}
  ${C}milog config${NC}                         show resolved values + config path
  ${C}milog config path${NC}                    print config file path
  ${C}milog config init${NC}                    write a commented template
  ${C}milog config edit${NC}                    open in \$EDITOR  ${D}(escape hatch)${NC}
  ${C}milog config add <app>${NC}               append to LOGS
  ${C}milog config rm  <app>${NC}               remove from LOGS
  ${C}milog config dir <path>${NC}              set LOG_DIR
  ${C}milog config set <KEY> <VALUE>${NC}       set any variable ${D}(REFRESH, THRESH_*, …)${NC}

${W}EXAMPLES${NC}
  milog config add api
  milog config dir /var/log/nginx
  milog config set REFRESH 3
  milog config set THRESH_REQ_CRIT 60
"
}

mode_config() {
    local sub="${1:-show}"; shift 2>/dev/null || true
    case "$sub" in
        ""|show)        config_show ;;
        path)           config_path ;;
        init)           config_init ;;
        edit)           config_edit ;;
        add)            config_add "${1:-}" ;;
        rm|remove|del)  config_rm  "${1:-}" ;;
        dir)            config_dir "${1:-}" ;;
        set)            config_set "${1:-}" "${2:-}" ;;
        -h|--help|help) config_help ;;
        *) echo -e "${R}Unknown config subcommand:${NC} $sub"; config_help; exit 1 ;;
    esac
}

# ==============================================================================
# COLOR PREFIX — merged initial dump sorted by nginx timestamp, then live tails
# ==============================================================================
color_prefix() {
    local pids=()
    local colors=("$B" "$C" "$G" "$M" "$Y" "$R")
    local -a F_files=() F_cols=() F_labels=()
    local i=0
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$i]}"
        local label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            F_files+=("$file")
            F_cols+=("$col")
            F_labels+=("$label")
        fi
        (( i++ )) || true
    done

    # Initial dump: last 10 lines from every file, merged and sorted by log timestamp
    # so output is globally by recency rather than grouped per app.
    {
        local idx
        for idx in "${!F_files[@]}"; do
            tail -n 10 "${F_files[$idx]}" 2>/dev/null | \
                awk -v col="${F_cols[$idx]}" -v lbl="${F_labels[$idx]}" -v nc="$NC" '
                {
                    if (match($0, /\[[0-9]{2}\/[A-Za-z]+\/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}/)) {
                        d     = substr($0, RSTART+1,  2)
                        mname = substr($0, RSTART+4,  3)
                        y     = substr($0, RSTART+8,  4)
                        hms   = substr($0, RSTART+13, 8)
                        mi = index("JanFebMarAprMayJunJulAugSepOctNovDec", mname)
                        mo = int((mi + 2) / 3)
                        key = sprintf("%s%02d%s%s", y, mo, d, hms)
                    } else {
                        key = "00000000000000000"
                    }
                    printf "%s\t%s[%s]%s %s\n", key, col, lbl, nc, $0
                }'
        done
    } | sort -k1,1 | cut -f2-

    # Live tails: parallel, naturally interleaved by arrival time.
    # -n 0 suppresses each tail's own initial dump (we already emitted a merged one).
    for idx in "${!F_files[@]}"; do
        tail -n 0 -F "${F_files[$idx]}" 2>/dev/null | \
            awk -v col="${F_cols[$idx]}" -v lbl="${F_labels[$idx]}" -v nc="$NC" \
                '{print col"["lbl"]"nc" "$0; fflush()}' &
        pids+=($!)
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

# ==============================================================================
# HELP
# ==============================================================================
show_help() {
    echo -e "
${W}MiLog${NC} — nginx + system monitor

${W}USAGE${NC}  $0 [command] [args]

${W}DASHBOARDS${NC}
  ${C}monitor${NC}            full TUI: nginx + CPU/MEM/DISK/NET + workers
                     ${D}keys: q=quit  p=pause  r=refresh  +/-=rate${NC}
  ${C}rate${NC}               nginx-only req/min dashboard

${W}ANALYSIS${NC}
  ${C}health${NC}             2xx/3xx/4xx/5xx per app
  ${C}top [N]${NC}            top N source IPs  ${D}(default: 10)${NC}
  ${C}stats <app>${NC}        hourly request histogram
  ${C}suspects [N] [W]${NC}   heuristic bot ranking ${D}(top N=20, window=2000 lines/app)${NC}

${W}CONFIG${NC}
  ${C}config${NC}             show resolved config + path
  ${C}config init${NC}        create template config file
  ${C}config add <app>${NC}   append app to LOGS
  ${C}config rm  <app>${NC}   remove app from LOGS
  ${C}config dir <path>${NC}  set LOG_DIR
  ${C}config set <K> <V>${NC} set any variable (REFRESH, THRESH_*, …)
  ${C}config edit${NC}        open in \$EDITOR

${W}TAILING${NC}
  ${C}(none) / logs${NC}      tail all logs, color prefixed  ${D}<- default${NC}
  ${C}errors${NC}             4xx/5xx lines only
  ${C}exploits${NC}           LFI / RCE / SQLi / XSS / infra-probe payloads
  ${C}probes${NC}             scanner/bot traffic
  ${C}grep <app> <pat>${NC}   filter-tail one app
  ${C}<app>${NC}              raw tail for one app

${W}THRESHOLDS${NC}
  req/min  warn=${THRESH_REQ_WARN}  crit=${THRESH_REQ_CRIT}
  cpu      warn=${THRESH_CPU_WARN}%  crit=${THRESH_CPU_CRIT}%
  mem      warn=${THRESH_MEM_WARN}%  crit=${THRESH_MEM_CRIT}%
  4xx      warn=${THRESH_4XX_WARN}   5xx warn=${THRESH_5XX_WARN}

${W}APPS${NC}  ${LOGS[*]}
  ${D}dir:${NC} ${LOG_DIR}
  ${D}config:${NC} ${MILOG_CONFIG}  ${D}(override LOG_DIR, LOGS, REFRESH, thresholds)${NC}
  ${D}env:${NC} MILOG_LOG_DIR, MILOG_APPS=\"a b c\", MILOG_CONFIG=/path/to/config.sh
  ${D}auto-discover:${NC} if LOGS is empty, all ${LOG_DIR}/*.access.log are picked up
"
}

# ==============================================================================
# DISPATCH
# ==============================================================================
case "${1:-}" in
    monitor)  mode_monitor ;;
    rate)     mode_rate ;;
    health)   mode_health ;;
    top)      mode_top "${2:-10}" ;;
    stats)    mode_stats "${2:-}" ;;
    grep)     mode_grep "${2:-}" "${3:-.}" ;;
    errors)   mode_errors ;;
    exploits) mode_exploits ;;
    probes)   mode_probes ;;
    suspects) mode_suspects "${2:-20}" "${3:-2000}" ;;
    config)   shift; mode_config "$@" ;;
    -h|--help|help) show_help ;;
    ""|logs)  color_prefix ;;
    *)
        if [[ " ${LOGS[*]} " =~ " $1 " ]]; then
            tail -F "$LOG_DIR/$1.access.log"
        else
            echo -e "${R}Unknown command: '$1'${NC}"; show_help; exit 1
        fi ;;
esac
