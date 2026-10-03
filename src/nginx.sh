# nginx access-log counters and monitor rows.

# Prints "count c2 c3 c4 c5" for lines containing timestamp $2, or zeros when the log is missing.
nginx_minute_counts() {
    local file="$LOG_DIR/$1.access.log"
    [[ -f "$file" ]] || { printf '0 0 0 0 0\n'; return; }
    awk -v t="$2" '
        index($0, t) {
            n++
            if (match($0, / [1-5][0-9][0-9] /)) {
                cls = substr($0, RSTART+1, 1)
                if      (cls == "2") e2++
                else if (cls == "3") e3++
                else if (cls == "4") e4++
                else if (cls == "5") e5++
            }
        }
        END { printf "%d %d %d %d %d\n", n+0, e2+0, e3+0, e4+0, e5+0 }
    ' "$file" 2>/dev/null
}

# Prints "p50 p95 p99" in ms for $1 at minute $2, or "— — —" when no line ends in a numeric $request_time.
percentiles() {
    local name="$1" cur="$2"
    local file="$LOG_DIR/$name.access.log"
    [[ -f "$file" ]] || { printf -- '— — —\n'; return; }
    local sorted
    sorted=$(awk -v t="$cur" '
        index($0, t) && $NF ~ /^[0-9]+(\.[0-9]+)?$/ {
            print int($NF * 1000 + 0.5)
        }' "$file" 2>/dev/null | sort -n)
    if [[ -z "$sorted" ]]; then
        printf -- '— — —\n'
        return
    fi
    # Ceiling-index pick: idx = ceil(N*k/100), clamped to [1,N].
    printf '%s\n' "$sorted" | awk '
        { a[NR] = $1; n = NR }
        END {
            if (n == 0) { print "— — —"; exit }
            p50 = int((n * 50 + 99) / 100); if (p50 < 1) p50 = 1; if (p50 > n) p50 = n
            p95 = int((n * 95 + 99) / 100); if (p95 < 1) p95 = 1; if (p95 > n) p95 = n
            p99 = int((n * 99 + 99) / 100); if (p99 < 1) p99 = 1; if (p99 > n) p99 = n
            printf "%d %d %d\n", a[p50], a[p95], a[p99]
        }'
}

# ISO country code, or "—" when GeoIP is off or unavailable. Forks mmdblookup, so only call it on deduped IP sets.
geoip_country() {
    [[ "${GEOIP_ENABLED:-0}" != "1" ]] && { printf -- '—'; return; }
    [[ ! -f "$MMDB_PATH" ]]            && { printf -- '—'; return; }
    command -v mmdblookup >/dev/null 2>&1 || { printf -- '—'; return; }
    local out
    out=$(mmdblookup --file "$MMDB_PATH" --ip "$1" country iso_code 2>/dev/null \
          | awk -F'"' 'NF>=3 {print $2; exit}')
    printf '%s' "${out:-—}"
}

# p95 for the monitor row, cached per app per minute so a 5s refresh doesn't rescan the log.
# Apps found without $request_time are never scanned again until MiLog restarts.
_p95_cached() {
    # bash 3.2 has no associative arrays, so skip the cache there.
    if (( ${BASH_VERSINFO[0]:-3} < 4 )); then
        local _p50 p95 _p99
        read -r _p50 p95 _p99 <<< "$(percentiles "$1" "$2")"
        [[ "$p95" =~ ^[0-9]+$ ]] && printf '%s' "$p95"
        return 0
    fi
    declare -gA TIMED_APPS P95_LAST_MIN P95_LAST_VAL
    local name="$1" cur="$2"

    [[ "${TIMED_APPS[$name]:-}" == "0" ]] && return 0

    if [[ "${P95_LAST_MIN[$name]:-}" == "$cur" ]]; then
        printf '%s' "${P95_LAST_VAL[$name]}"
        return 0
    fi

    local _p50 p95 _p99
    read -r _p50 p95 _p99 <<< "$(percentiles "$name" "$cur")"
    if [[ "$p95" =~ ^[0-9]+$ ]]; then
        TIMED_APPS[$name]=1
        P95_LAST_MIN[$name]="$cur"
        P95_LAST_VAL[$name]="$p95"
        printf '%s' "$p95"
    else
        TIMED_APPS[$name]=0
    fi
}

# 4xx/5xx spike alerts, shared by nginx_row and the daemon; thresholds go through _thresh.
nginx_check_http_alerts() {
    local name="$1" c4="$2" c5="$3"
    local t5 t4
    t5=$(_thresh THRESH_5XX_WARN "$name")
    t4=$(_thresh THRESH_4XX_WARN "$name")
    if (( c5 >= t5 )) && alert_should_fire "5xx:$name"; then
        alert_fire "5xx spike: $name" "${c5} 5xx responses in the last minute (threshold ${t5})" 15158332 "5xx:$name" &
    fi
    if (( c4 >= t4 )) && alert_should_fire "4xx:$name"; then
        alert_fire "4xx spike: $name" "${c4} 4xx responses in the last minute (threshold ${t4})" 16753920 "4xx:$name" &
    fi
}

# CPU/MEM/DISK/worker alerts, shared by monitor and daemon.
sys_check_alerts() {
    local cpu="$1" mem_pct="$2" mem_used="$3" mem_total="$4"
    local disk_pct="$5" disk_used="$6" disk_total="$7" worker_count="$8"
    if (( cpu >= THRESH_CPU_CRIT )) && alert_should_fire "cpu"; then
        alert_fire "CPU critical" "CPU at ${cpu}% (crit=${THRESH_CPU_CRIT}%)" 15158332 "cpu" &
    fi
    if (( mem_pct >= THRESH_MEM_CRIT )) && alert_should_fire "mem"; then
        alert_fire "Memory critical" "MEM at ${mem_pct}% — used ${mem_used}MB of ${mem_total}MB (crit=${THRESH_MEM_CRIT}%)" 15158332 "mem" &
    fi
    if (( disk_pct >= THRESH_DISK_CRIT )) && alert_should_fire "disk:/"; then
        alert_fire "Disk critical" "Disk at ${disk_pct}% on / — ${disk_used}GB of ${disk_total}GB used (crit=${THRESH_DISK_CRIT}%)" 15158332 "disk:/" &
    fi
    if (( worker_count == 0 )) && alert_should_fire "workers"; then
        alert_fire "Nginx workers down" "Zero nginx worker processes detected on $(hostname 2>/dev/null || echo host)" 15158332 "workers" &
    fi
}

nginx_row() {
    local name="$1" CUR_TIME="$2" TOTAL_ref="$3"
    local count=0 c2=0 c3=0 c4=0 c5=0

    read -r count c2 c3 c4 c5 <<< "$(nginx_minute_counts "$name" "$CUR_TIME")"
    count=${count:-0}; c4=${c4:-0}; c5=${c5:-0}
    # shellcheck disable=SC2034
    eval "$TOTAL_ref=$(( ${!TOTAL_ref} + count ))"

    local tr_warn tr_crit t4_warn t5_warn
    tr_warn=$(_thresh THRESH_REQ_WARN  "$name")
    tr_crit=$(_thresh THRESH_REQ_CRIT  "$name")
    t4_warn=$(_thresh THRESH_4XX_WARN  "$name")
    t5_warn=$(_thresh THRESH_5XX_WARN  "$name")

    local st_plain st_col b_col alert=""
    if [[ $count -gt 0 ]]; then
        st_plain="● ACTIVE  "; st_col="${G}● ACTIVE  ${NC}"; b_col=$G
        [[ $count -gt $tr_warn ]] && b_col=$Y
        [[ $count -gt $tr_crit ]] && { b_col=$R; st_col="${R}● ACTIVE  ${NC}"; }
    else
        st_plain="○ IDLE    "; st_col="${D}○ IDLE    ${NC}"; b_col=$D
    fi

    [[ $c5 -ge $t5_warn ]]                   && alert="$RBLINK"
    [[ $c4 -ge $t4_warn && -z "$alert" ]]    && alert="$R"
    [[ $count -gt $tr_crit && -z "$alert" ]] && alert="$R"

    nginx_check_http_alerts "$name" "$c4" "$c5"

    local p95_ms
    p95_ms=$(_p95_cached "$name" "$CUR_TIME")

    local bars_plain bars_col
    if [[ "${MILOG_HIST_ENABLED:-0}" == "1" ]]; then
        # MILOG_HIST_PAUSED=1 freezes the ring buffer while the view is paused.
        local -a hist_arr=( ${HIST[$name]:-} )
        if [[ "${MILOG_HIST_PAUSED:-0}" != "1" ]]; then
            hist_arr+=( "$count" )
            if (( ${#hist_arr[@]} > SPARK_LEN )); then
                hist_arr=( "${hist_arr[@]: -$SPARK_LEN}" )
            fi
            HIST[$name]="${hist_arr[*]}"
        fi
        (( ${#hist_arr[@]} == 0 )) && hist_arr=( 0 )

        local spark n_samples=${#hist_arr[@]}
        spark=$(sparkline_render "${hist_arr[*]}")
        # Placeholder with the sparkline's width for padding maths.
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

    # Trim the bar so the 4xx/5xx and p95 tags fit in the column.
    local etag_p="" etag_c=""
    if (( c4 > 0 || c5 > 0 )); then
        etag_p+=" 4xx:${c4} 5xx:${c5}"
        etag_c+=" ${Y}4xx:${c4}${NC} ${R}5xx:${c5}${NC}"
    fi
    if [[ -n "$p95_ms" ]]; then
        local pcol p95w p95c
        p95w=$(_thresh P95_WARN_MS "$name")
        p95c=$(_thresh P95_CRIT_MS "$name")
        pcol=$(tcol "$p95_ms" "$p95w" "$p95c")
        etag_p+=" p95:${p95_ms}ms"
        etag_c+=" ${pcol}p95:${p95_ms}ms${NC}"
    fi
    if [[ -n "$etag_p" ]]; then
        local max_b=$(( W_BAR - ${#etag_p} ))
        if [[ ${#bars_plain} -gt $max_b ]]; then
            bars_plain="${bars_plain:0:$max_b}"
            if [[ "${MILOG_HIST_ENABLED:-0}" == "1" ]]; then
                local -a trimmed=( ${HIST[$name]:-} )
                (( max_b > 0 && ${#trimmed[@]} > max_b )) && trimmed=( "${trimmed[@]: -$max_b}" )
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

