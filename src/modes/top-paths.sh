# milog top-paths [N]: requests, 4xx, 5xx and p95 per path (query strings stripped); p95 shows n/a without $request_time.
mode_top_paths() {
    local n="${1:-20}"
    local window="${SLOW_WINDOW:-2000}"

    [[ "$n"      =~ ^[0-9]+$ ]] || { echo -e "${R}top-paths: N must be numeric${NC}" >&2; return 1; }
    [[ "$window" =~ ^[0-9]+$ ]] || { echo -e "${R}top-paths: SLOW_WINDOW must be numeric${NC}" >&2; return 1; }

    echo -e "\n${W}── MiLog: Top ${n} paths (window=${window} lines/app) ──${NC}\n"

    local files=() name f
    for name in "${LOGS[@]}"; do
        f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] && files+=("$f")
    done
    if (( ${#files[@]} == 0 )); then
        echo -e "${R}No log files found in ${LOG_DIR}${NC}"
        return 1
    fi

    # Rows of path, status, ms (or "-"); sorting by ms within each path lets the group pass index p95 over the timed samples only.
    local rows
    rows=$(tail -q -n "$window" "${files[@]}" 2>/dev/null \
        | awk -v EXCLUDE_LIST="${SLOW_EXCLUDE_PATHS:-}" '
            BEGIN {
                # Shared with mode_slow: strip trailing "/*" from each glob
                # and prefix-match. WebSocket paths would otherwise poison
                # both the p95 column AND the request-count table (WS
                # connections can be very long-lived, so they accumulate
                # inflated per-path counts).
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
            NF >= 9 {
                path = $7
                q = index(path, "?")
                if (q > 0) path = substr(path, 1, q - 1)
                if (length(path) == 0) next
                # Defensive path guard — drop malformed request lines that
                # yield non-absolute "paths" like PATH="400".
                if (substr(path, 1, 1) != "/") next
                if (path_excluded(path)) next
                status = $9
                if (status !~ /^[0-9]+$/) next
                lf = $NF
                if (lf ~ /^[0-9]+(\.[0-9]+)?$/ && NF >= 12) {
                    printf "%s\t%s\t%d\n", path, status, int(lf * 1000 + 0.5)
                } else {
                    printf "%s\t%s\t-\n", path, status
                }
            }' \
        | sort -t $'\t' -k1,1 -k3,3n \
        | awk -F'\t' '
            function emit(   pi, p95) {
                if (cur == "") return
                if (nt > 0) {
                    pi = int((nt * 95 + 99) / 100)
                    if (pi < 1) pi = 1
                    if (pi > nt) pi = nt
                    p95 = v[pi]
                } else {
                    p95 = "-"
                }
                printf "%s\t%d\t%d\t%d\t%s\n", cur, count, c4, c5, p95
            }
            BEGIN { cur = ""; count = 0; c4 = 0; c5 = 0; nt = 0 }
            {
                if ($1 != cur) {
                    emit()
                    cur = $1; count = 0; c4 = 0; c5 = 0; nt = 0; delete v
                }
                count++
                if ($2 ~ /^4/) c4++
                if ($2 ~ /^5/) c5++
                if ($3 != "-") { nt++; v[nt] = $3 }
            }
            END { emit() }' \
        | sort -t $'\t' -k2,2 -rn \
        | head -n "$n")

    if [[ -z "$rows" ]]; then
        echo -e "${D}No loglines matched in window.${NC}\n"
        return 0
    fi

    printf "%-5s  %7s  %5s  %5s  %9s  %s\n" "RANK" "REQ" "4XX" "5XX" "P95" "PATH"
    printf "%-5s  %7s  %5s  %5s  %9s  %s\n" "────" "───────" "─────" "─────" "─────────" "────────────────────"

    local i=1 path count c4 c5 p95 col_err col_p95 p95_disp display
    while IFS=$'\t' read -r path count c4 c5 p95; do
        col_err=""
        (( c5 > 0 )) && col_err="$R"
        col_err+=""    # no-op but keeps the colour local
        if [[ "$p95" == "-" ]]; then
            # ASCII, because the 3-byte em-dash breaks printf width alignment.
            p95_disp=$(printf "%b%9s%b" "$D" "n/a" "$NC")
            col_p95=""
        else
            col_p95=$(tcol "$p95" "$P95_WARN_MS" "$P95_CRIT_MS")
            p95_disp=$(printf "%b%7sms%b" "$col_p95" "$p95" "$NC")
        fi
        display="$path"
        if (( ${#display} > 60 )); then
            display="${display:0:57}..."
        fi
        printf "#%-4d  %7d  %b%5d%b  %b%5d%b  %b  %s\n" \
            "$i" "$count" \
            "$Y" "$c4" "$NC" \
            "$R" "$c5" "$NC" \
            "$p95_disp" "$display"
        i=$(( i + 1 ))
    done <<< "$rows"
    echo
}

