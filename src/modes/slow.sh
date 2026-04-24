# ==============================================================================
# MODE: slow — top N endpoints by p95 response time
# Requires the extended (combined_timed) log format — see README.
# Pipeline: tail -> extract (path, ms) -> sort by path -> per-path p95
#           -> sort by p95 desc -> head N. All portable POSIX awk; no
#           gawk-only features (asort / PROCINFO) required.
# ==============================================================================
mode_slow() {
    local n="${1:-10}"
    local window="${SLOW_WINDOW:-1000}"

    # Basic arg validation — integers only, otherwise later arithmetic trips.
    [[ "$n"      =~ ^[0-9]+$ ]] || { echo -e "${R}slow: N must be numeric${NC}" >&2; return 1; }
    [[ "$window" =~ ^[0-9]+$ ]] || { echo -e "${R}slow: SLOW_WINDOW must be numeric${NC}" >&2; return 1; }

    echo -e "\n${W}── MiLog: Top ${n} slow endpoints (window=${window} lines/app) ──${NC}\n"

    local files=() name
    for name in "${LOGS[@]}"; do
        local f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] && files+=("$f")
    done

    if (( ${#files[@]} == 0 )); then
        echo -e "${R}No log files found in ${LOG_DIR}${NC}"
        return 1
    fi

    # Stream through two awk stages with sort in between so per-path p95 can
    # be computed without multi-dim arrays.
    local top_rows
    top_rows=$(tail -q -n "$window" "${files[@]}" 2>/dev/null \
        | awk -v EXCLUDE_LIST="${SLOW_EXCLUDE_PATHS:-}" '
            BEGIN {
                # Pre-process the exclude glob list: strip trailing "/*" to
                # leave a plain prefix, then match by string equality at the
                # start. Space-separated input, empty entries ignored.
                n_excl = split(EXCLUDE_LIST, excl, " ")
                for (i = 1; i <= n_excl; i++) { sub(/\/\*$/, "/", excl[i]) }
            }
            function path_excluded(p,   i) {
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
                # Defensive: URL paths start with "/". Malformed request
                # lines (garbage that awk field-split wrongly) can yield
                # rows like PATH="400" — skip before they pollute the p95
                # table.
                if (substr(path, 1, 1) != "/") next
                # WebSocket / configured-exclude filter — WS $request_time
                # is session lifetime, not latency; excluding prevents a
                # healthy 22-minute chat from topping the slowest list.
                if (path_excluded(path)) next
                if (length(path) > 0) {
                    printf "%s\t%d\n", path, int($NF * 1000 + 0.5)
                }
            }' \
        | sort -t $'\t' -k1,1 -k2,2n \
        | awk -F'\t' '
            function emit(   pi) {
                if (n > 0) {
                    pi = int((n * 95 + 99) / 100)
                    if (pi < 1) pi = 1
                    if (pi > n) pi = n
                    printf "%s\t%d\t%d\n", cur, v[pi], n
                }
            }
            BEGIN { cur = ""; n = 0 }
            {
                if ($1 != cur) {
                    emit()
                    cur = $1; n = 0; delete v
                }
                n++
                v[n] = $2
            }
            END { emit() }' \
        | sort -t $'\t' -k2,2 -rn \
        | head -n "$n")

    if [[ -z "$top_rows" ]]; then
        echo -e "${D}No timed samples in window — is \$request_time in your log_format?${NC}"
        echo
        return 0
    fi

    printf "%-5s  %-9s  %7s  %s\n" "RANK" "P95"     "COUNT" "PATH"
    printf "%-5s  %-9s  %7s  %s\n" "────" "────────" "───────" "────────────────────"

    local i=1 path p95 count col
    while IFS=$'\t' read -r path p95 count; do
        col=$(tcol "$p95" "$P95_WARN_MS" "$P95_CRIT_MS")
        # Truncate absurdly long paths so the table stays aligned. URL paths
        # are ASCII, so ${#path} is safe for width math.
        local display="$path"
        if (( ${#display} > 80 )); then
            display="${display:0:77}..."
        fi
        printf "#%-4d  %b%-9s${NC}  %7d  %s\n" "$i" "$col" "${p95}ms" "$count" "$display"
        i=$((i+1))
    done <<< "$top_rows"
    echo
}

