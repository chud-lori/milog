# ==============================================================================
# NGINX ROW HELPERS
# ==============================================================================

# Extract the single awk pass so the daemon can reuse it without the
# rendering side-effects of nginx_row. Prints "count c2 c3 c4 c5" (zeros
# if the log file is missing or unreadable). One scan, four class buckets;
# callers that only need c4/c5 just consume the first three fields they
# care about and leave the rest as locals.
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

# Response-time percentiles for the current-minute window. Requires the
# extended log_format that appends $request_time as the final field (see
# README → "Response-time percentiles"). Gracefully degrades to the em-dash
# sentinel when no numeric $request_time is present on any matching line.
#   $1 app   $2 CUR_TIME   →   prints "p50 p95 p99" in ms, or "— — —"
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
    # Ceiling-index percentile pick: idx = ceil(N*k/100), clamped to [1,N].
    # Single awk pass over the already-sorted stream keeps us to one fork.
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

# GeoIP lookup for a single IP. Returns the 2-letter ISO country code or
# the em-dash sentinel when disabled, when the MMDB is missing, when
# mmdblookup isn't on $PATH, or when the IP isn't in the database.
#
# Performance: forks mmdblookup per call. Callers MUST only invoke this on
# already-aggregated IP sets (post uniq/awk dedup) — never per log line in
# a live tail, where it would fork thousands of processes.
geoip_country() {
    [[ "${GEOIP_ENABLED:-0}" != "1" ]] && { printf -- '—'; return; }
    [[ ! -f "$MMDB_PATH" ]]            && { printf -- '—'; return; }
    command -v mmdblookup >/dev/null 2>&1 || { printf -- '—'; return; }
    local out
    out=$(mmdblookup --file "$MMDB_PATH" --ip "$1" country iso_code 2>/dev/null \
          | awk -F'"' 'NF>=3 {print $2; exit}')
    printf '%s' "${out:-—}"
}

# Cached p95 lookup for the monitor row. Two-level cache:
#   TIMED_APPS[name]   — unset=unknown, 0=never-timed, 1=timed. Skips the
#                        file scan forever for apps that don't log
#                        $request_time (restart MiLog after a log_format
#                        change to re-probe).
#   P95_LAST_MIN[name] — last minute string (dd/Mon/yyyy:HH:MM) we probed
#   P95_LAST_VAL[name] — p95 value for that minute
#
# Within the same minute, re-use the cached p95 so a 5s monitor refresh
# doesn't re-scan the whole log 12× per minute per app.
#
# Declared lazily (`-gA` inside the function) so the script stays parseable
# on bash 3.2 hosts without associative arrays — same pattern used for HIST.
#
# Prints the p95 in milliseconds on stdout, or empty when unavailable.
_p95_cached() {
    # On bash 3.2 (macOS dev boxes) associative arrays aren't available,
    # so skip the cache entirely — correct result, uncached probe every
    # call. Real deployments target bash 4+ Linux.
    if (( ${BASH_VERSINFO[0]:-3} < 4 )); then
        local _p50 p95 _p99
        read -r _p50 p95 _p99 <<< "$(percentiles "$1" "$2")"
        [[ "$p95" =~ ^[0-9]+$ ]] && printf '%s' "$p95"
        return 0
    fi
    declare -gA TIMED_APPS P95_LAST_MIN P95_LAST_VAL
    local name="$1" cur="$2"

    # Hard negative cache — don't scan apps we've already proven untimed.
    [[ "${TIMED_APPS[$name]:-}" == "0" ]] && return 0

    # Per-minute positive cache — reuse the previous probe inside the same
    # minute bucket so render loops at sub-minute cadence don't rescan.
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

# HTTP rule-hook — fires 4xx/5xx spike alerts. Called from both nginx_row
# (render-mode) and mode_daemon. Cooldown gate inside alert_should_fire.
nginx_check_http_alerts() {
    local name="$1" c4="$2" c5="$3"
    if (( c5 >= THRESH_5XX_WARN )) && alert_should_fire "5xx:$name"; then
        alert_discord "5xx spike: $name" "${c5} 5xx responses in the last minute (threshold ${THRESH_5XX_WARN})" 15158332 &
    fi
    if (( c4 >= THRESH_4XX_WARN )) && alert_should_fire "4xx:$name"; then
        alert_discord "4xx spike: $name" "${c4} 4xx responses in the last minute (threshold ${THRESH_4XX_WARN})" 16753920 &
    fi
}

# System rule-hook — fires CPU/MEM/DISK/workers alerts. Shared by monitor
# and daemon so threshold logic has one home.
sys_check_alerts() {
    local cpu="$1" mem_pct="$2" mem_used="$3" mem_total="$4"
    local disk_pct="$5" disk_used="$6" disk_total="$7" worker_count="$8"
    if (( cpu >= THRESH_CPU_CRIT )) && alert_should_fire "cpu"; then
        alert_discord "CPU critical" "CPU at ${cpu}% (crit=${THRESH_CPU_CRIT}%)" 15158332 &
    fi
    if (( mem_pct >= THRESH_MEM_CRIT )) && alert_should_fire "mem"; then
        alert_discord "Memory critical" "MEM at ${mem_pct}% — used ${mem_used}MB of ${mem_total}MB (crit=${THRESH_MEM_CRIT}%)" 15158332 &
    fi
    if (( disk_pct >= THRESH_DISK_CRIT )) && alert_should_fire "disk:/"; then
        alert_discord "Disk critical" "Disk at ${disk_pct}% on / — ${disk_used}GB of ${disk_total}GB used (crit=${THRESH_DISK_CRIT}%)" 15158332 &
    fi
    if (( worker_count == 0 )) && alert_should_fire "workers"; then
        alert_discord "Nginx workers down" "Zero nginx worker processes detected on $(hostname 2>/dev/null || echo host)" 15158332 &
    fi
}

nginx_row() {
    local name="$1" CUR_TIME="$2" TOTAL_ref="$3"
    local count=0 c2=0 c3=0 c4=0 c5=0

    read -r count c2 c3 c4 c5 <<< "$(nginx_minute_counts "$name" "$CUR_TIME")"
    count=${count:-0}; c4=${c4:-0}; c5=${c5:-0}
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

    nginx_check_http_alerts "$name" "$c4" "$c5"

    # Response-time p95 (skipped automatically for apps without the timed
    # log format after the first probe — see _p95_cached / TIMED_APPS).
    local p95_ms
    p95_ms=$(_p95_cached "$name" "$CUR_TIME")

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

    # Build the right-aligned tag strip — 4xx/5xx counts and/or p95 — then
    # trim the bar/sparkline to fit before concatenating. Each tag is
    # optional; the tag strip is only applied when at least one is present.
    local etag_p="" etag_c=""
    if (( c4 > 0 || c5 > 0 )); then
        etag_p+=" 4xx:${c4} 5xx:${c5}"
        etag_c+=" ${Y}4xx:${c4}${NC} ${R}5xx:${c5}${NC}"
    fi
    if [[ -n "$p95_ms" ]]; then
        local pcol
        pcol=$(tcol "$p95_ms" "$P95_WARN_MS" "$P95_CRIT_MS")
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

