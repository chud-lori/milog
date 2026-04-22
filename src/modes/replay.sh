# ==============================================================================
# MODE: replay — postmortem summary of one archived log file
# Read-only: never writes history. Handles .gz / .bz2 transparently.
# Three passes of the file: counts + date range, timings (sort + percentile),
# top source IPs. Each pass is single-awk-per-metric — same discipline as
# the live dashboard helpers.
# ==============================================================================
mode_replay() {
    local file="${1:-}"
    if [[ -z "$file" ]]; then
        echo -e "${R}Usage:${NC} milog replay <log-file>" >&2
        return 1
    fi
    [[ -f "$file" ]] || { echo -e "${R}Not found: $file${NC}" >&2; return 1; }

    # Pick reader based on extension. Array form so no word-splitting risks
    # when $file contains spaces.
    local -a reader=(cat --)
    case "$file" in
        *.gz)
            if   command -v gzcat >/dev/null 2>&1; then reader=(gzcat --)
            elif command -v zcat  >/dev/null 2>&1; then reader=(zcat  --)
            else echo -e "${R}gzcat/zcat needed for .gz files${NC}" >&2; return 1
            fi
            ;;
        *.bz2)
            command -v bzcat >/dev/null 2>&1 \
                || { echo -e "${R}bzcat needed for .bz2 files${NC}" >&2; return 1; }
            reader=(bzcat --)
            ;;
    esac

    echo -e "\n${W}── MiLog: Replay — ${file} ──${NC}\n"

    # Pass 1: lines, first/last timestamp, status-class tallies.
    local summary n first last e2 e3 e4 e5
    summary=$("${reader[@]}" "$file" 2>/dev/null | awk '
        {
            n++
            if (match($0, /\[[0-9]{2}\/[A-Za-z]+\/[0-9]{4}:[0-9]{2}:[0-9]{2}/)) {
                t = substr($0, RSTART+1, 20)
                if (first == "") first = t
                last = t
            }
            if (match($0, / [1-5][0-9][0-9] /)) {
                cls = substr($0, RSTART+1, 1)
                if      (cls == "2") e2++
                else if (cls == "3") e3++
                else if (cls == "4") e4++
                else if (cls == "5") e5++
            }
        }
        END { printf "%d\t%s\t%s\t%d\t%d\t%d\t%d\n", n+0, first, last, e2+0, e3+0, e4+0, e5+0 }')
    IFS=$'\t' read -r n first last e2 e3 e4 e5 <<< "$summary"

    if [[ -z "$n" || "$n" -eq 0 ]]; then
        echo -e "  ${D}(empty or unreadable)${NC}\n"
        return 0
    fi

    printf "  %-10s  %d\n"           "lines"   "$n"
    printf "  %-10s  %s  →  %s\n"    "range"   "${first:--}" "${last:--}"
    printf "  %-10s  2xx=%s  3xx=%s  ${Y}4xx=%s${NC}  ${R}5xx=%s${NC}\n" \
           "status"  "$e2" "$e3" "$e4" "$e5"

    # Pass 2: percentiles, only if any line has a numeric final field.
    local sorted
    sorted=$("${reader[@]}" "$file" 2>/dev/null \
        | awk '$NF ~ /^[0-9]+(\.[0-9]+)?$/ { print int($NF * 1000 + 0.5) }' \
        | sort -n)
    if [[ -n "$sorted" ]]; then
        local pct p50 p95 p99
        pct=$(printf '%s\n' "$sorted" | awk '
            { a[NR]=$1; n=NR }
            END {
                i50=int((n*50+99)/100); if (i50<1) i50=1; if (i50>n) i50=n
                i95=int((n*95+99)/100); if (i95<1) i95=1; if (i95>n) i95=n
                i99=int((n*99+99)/100); if (i99<1) i99=1; if (i99>n) i99=n
                printf "%d %d %d\n", a[i50], a[i95], a[i99]
            }')
        read -r p50 p95 p99 <<< "$pct"
        printf "  %-10s  p50=%dms  p95=%dms  p99=%dms\n" "response" "$p50" "$p95" "$p99"
    fi

    # Pass 3: top 10 source IPs.
    echo
    echo -e "  ${W}Top source IPs:${NC}"
    "${reader[@]}" "$file" 2>/dev/null \
        | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 \
        | awk -v Y="$Y" -v R="$R" -v NC="$NC" '{
              col = ""
              if      (NR == 1) col = R
              else if (NR <= 3) col = Y
              printf "    %s#%-3d%s  %-18s  %d requests\n", col, NR, NC, $2, $1
          }'
    echo
}

