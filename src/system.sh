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

# Daemon/history stderr log — timestamped, never to stdout. Shared by any
# code path that runs under mode_daemon (rule evaluator, history writers).
_dlog() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

