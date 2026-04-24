# ==============================================================================
# MODE: ws — WebSocket session metrics (complementary to `slow`)
#
# nginx's `$request_time` for a WebSocket-upgraded connection is the full
# session lifetime (start-of-HTTP-request to socket-close), not request
# latency. `milog slow` / `top-paths` filter WS paths out so they don't
# top the "slowest" table with healthy long-lived sessions. This mode is
# the other side: shows WS sessions on their own terms — count, duration
# distribution, longest, per-path breakdown.
#
# "Which paths are WebSocket?" comes from SLOW_EXCLUDE_PATHS (default:
# "/ws/* /socket.io/*"). One source of truth — customising the exclude
# list moves paths in/out of `ws` at the same time.
#
# Requires the combined_timed log format (with $request_time). Skipping
# silently if no WS samples match in the window.
# ==============================================================================

# Format a duration given in seconds into a short human string.
#   < 1 s          → "<1s"
#   < 60 s         → "Ns"
#   < 3600 s       → "MmSSs"
#   < 86400 s      → "HhMMm"
#   >= 86400 s     → "DdHHh"
_ws_fmt_duration() {
    local s="$1"
    if ! [[ "$s" =~ ^[0-9]+$ ]]; then printf -- '—'; return; fi
    if   (( s < 1 ));     then printf '<1s'
    elif (( s < 60 ));    then printf '%ds' "$s"
    elif (( s < 3600 ));  then printf '%dm %02ds' $(( s / 60 )) $(( s % 60 ))
    elif (( s < 86400 )); then printf '%dh %02dm' $(( s / 3600 )) $(( (s % 3600) / 60 ))
    else                       printf '%dd %02dh' $(( s / 86400 )) $(( (s % 86400) / 3600 ))
    fi
}

mode_ws() {
    local n="${1:-10}"
    local window="${SLOW_WINDOW:-1000}"

    [[ "$n"      =~ ^[0-9]+$ ]] || { echo -e "${R}ws: N must be numeric${NC}" >&2; return 1; }
    [[ "$window" =~ ^[0-9]+$ ]] || { echo -e "${R}ws: SLOW_WINDOW must be numeric${NC}" >&2; return 1; }

    local ws_paths="${SLOW_EXCLUDE_PATHS:-}"
    if [[ -z "$ws_paths" ]]; then
        echo -e "${R}ws:${NC} SLOW_EXCLUDE_PATHS is empty — nothing identifies WebSocket paths"
        echo -e "${D}  set e.g. SLOW_EXCLUDE_PATHS=\"/ws/* /socket.io/*\" in your config${NC}"
        return 1
    fi

    echo -e "\n${W}── MiLog: WebSocket sessions (window=${window} lines/app) ──${NC}\n"

    local name files=()
    for name in "${LOGS[@]}"; do
        local f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] && files+=("$name:$f")
    done

    if (( ${#files[@]} == 0 )); then
        echo -e "${R}No log files found in ${LOG_DIR}${NC}"
        return 1
    fi

    # Per-file extraction: emit `app \t path \t ms` for WS-prefixed paths
    # only. Done in a loop rather than `tail -q` so we can tag each line
    # with its source app.
    local raw
    raw=$(
        for entry in "${files[@]}"; do
            local app="${entry%%:*}"
            local file="${entry#*:}"
            tail -n "$window" "$file" 2>/dev/null | awk \
                -v APP="$app" \
                -v EXCLUDE_LIST="$ws_paths" '
                BEGIN {
                    n_excl = split(EXCLUDE_LIST, excl, " ")
                    for (i = 1; i <= n_excl; i++) { sub(/\/\*$/, "/", excl[i]) }
                }
                function is_ws_path(p,   i) {
                    for (i = 1; i <= n_excl; i++) {
                        if (excl[i] == "") continue
                        if (index(p, excl[i]) == 1) return 1
                    }
                    return 0
                }
                $NF ~ /^[0-9]+(\.[0-9]+)?$/ && NF >= 8 {
                    path = $7
                    q = index(path, "?")
                    if (q > 0) path = substr(path, 1, q - 1)
                    if (substr(path, 1, 1) != "/") next
                    if (!is_ws_path(path)) next
                    # Emit milliseconds (int) so downstream sort is clean.
                    printf "%s\t%s\t%d\n", APP, path, int($NF * 1000 + 0.5)
                }'
        done
    )

    if [[ -z "$raw" ]]; then
        echo -e "${D}No WebSocket samples in window — either no WS traffic or${NC}"
        echo -e "${D}nginx isn't logging \$request_time for these paths.${NC}"
        echo
        return 0
    fi

    # --- Summary across all apps --------------------------------------------
    # Single awk pass: total count, sum, max, p50/p95, long-session count.
    local long_threshold_s=3600   # sessions > this are "long"
    local summary
    summary=$(printf '%s\n' "$raw" \
        | awk -F'\t' -v LT_MS=$((long_threshold_s * 1000)) '
            { n++; ms[n] = $3; sum += $3; if ($3 > max) max = $3; if ($3 > LT_MS) long++ }
            END {
                if (n == 0) { print "0\t0\t0\t0\t0\t0"; exit }
                # In-place numeric sort — bubble for small N is fine; asort
                # is gawk-only. For typical windows n < 10k which takes <20ms.
                for (i = 2; i <= n; i++) {
                    k = ms[i]; j = i - 1
                    while (j >= 1 && ms[j] > k) { ms[j+1] = ms[j]; j-- }
                    ms[j+1] = k
                }
                p50_idx = int((n * 50 + 99) / 100); if (p50_idx < 1) p50_idx = 1; if (p50_idx > n) p50_idx = n
                p95_idx = int((n * 95 + 99) / 100); if (p95_idx < 1) p95_idx = 1; if (p95_idx > n) p95_idx = n
                avg = int(sum / n)
                # Output: total_sessions, avg_ms, p50_ms, p95_ms, max_ms, long_count
                printf "%d\t%d\t%d\t%d\t%d\t%d\n", n, avg, ms[p50_idx], ms[p95_idx], max, long
            }')

    local total_sessions avg_ms p50_ms p95_ms max_ms long_count
    IFS=$'\t' read -r total_sessions avg_ms p50_ms p95_ms max_ms long_count <<< "$summary"

    echo -e "${W}Summary${NC}"
    printf "  %-16s %s\n" "total sessions"  "$total_sessions"
    printf "  %-16s %s\n" "avg duration"    "$(_ws_fmt_duration $(( avg_ms / 1000 )))"
    printf "  %-16s %s\n" "p50 duration"    "$(_ws_fmt_duration $(( p50_ms / 1000 )))"
    printf "  %-16s %s\n" "p95 duration"    "$(_ws_fmt_duration $(( p95_ms / 1000 )))"
    printf "  %-16s %s\n" "longest session" "$(_ws_fmt_duration $(( max_ms / 1000 )))"
    if (( long_count > 0 )); then
        local col="$Y"
        (( long_count > 10 )) && col="$R"
        printf "  %-16s ${col}%d${NC} (threshold %s)\n" ">long sessions" "$long_count" "$(_ws_fmt_duration "$long_threshold_s")"
    else
        printf "  %-16s %s\n" ">long sessions" "0"
    fi
    echo

    # --- Per-(app, path) breakdown -------------------------------------------
    # Group by app+path, emit: sessions, p50, p95, max per group. Sort by
    # session count desc.
    local rows
    rows=$(printf '%s\n' "$raw" \
        | sort -t $'\t' -k1,1 -k2,2 -k3,3n \
        | awk -F'\t' '
            function emit(   pi, pi95) {
                if (cur_app == "") return
                if (n > 0) {
                    pi   = int((n * 50 + 99) / 100); if (pi < 1) pi = 1; if (pi > n) pi = n
                    pi95 = int((n * 95 + 99) / 100); if (pi95 < 1) pi95 = 1; if (pi95 > n) pi95 = n
                    printf "%s\t%s\t%d\t%d\t%d\t%d\n", cur_app, cur_path, n, v[pi], v[pi95], v[n]
                }
            }
            BEGIN { cur_app = ""; cur_path = ""; n = 0 }
            {
                if ($1 != cur_app || $2 != cur_path) {
                    emit()
                    cur_app = $1; cur_path = $2; n = 0; delete v
                }
                n++
                v[n] = $3
            }
            END { emit() }' \
        | sort -t $'\t' -k3,3 -rn \
        | head -n "$n")

    echo -e "${W}Top WebSocket paths (by session count)${NC}"
    printf "%-5s  %8s  %9s  %9s  %9s  %-10s  %s\n" "RANK" "SESS" "p50" "p95" "LONGEST" "APP" "PATH"
    printf "%-5s  %8s  %9s  %9s  %9s  %-10s  %s\n" "────" "────────" "─────────" "─────────" "─────────" "──────────" "────────────"

    local i=1 app_col path sessions p50 p95 mx path_disp
    while IFS=$'\t' read -r app_col path sessions p50 p95 mx; do
        [[ -z "$app_col" ]] && continue
        path_disp="$path"
        (( ${#path_disp} > 40 )) && path_disp="${path_disp:0:37}..."
        local app_disp="$app_col"
        (( ${#app_disp} > 10 )) && app_disp="${app_disp:0:7}..."
        printf "#%-4d  %8d  %9s  %9s  %9s  %-10s  %s\n" \
            "$i" "$sessions" \
            "$(_ws_fmt_duration $(( p50 / 1000 )))" \
            "$(_ws_fmt_duration $(( p95 / 1000 )))" \
            "$(_ws_fmt_duration $(( mx / 1000 )))" \
            "$app_disp" \
            "$path_disp"
        i=$(( i + 1 ))
    done <<< "$rows"
    echo
}
