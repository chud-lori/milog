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

    local show_geo=0
    [[ "${GEOIP_ENABLED:-0}" == "1" && -f "$MMDB_PATH" ]] && show_geo=1

    if (( show_geo )); then
        printf "%-6s  %-18s  %-7s  %6s  %5s  %5s  %6s  %s\n" \
            "SCORE" "IP" "COUNTRY" "REQ" "4XX" "5XX" "PATHS" "FLAGS"
        printf "%-6s  %-18s  %-7s  %6s  %5s  %5s  %6s  %s\n" \
            "─────" "─────────────────" "───────" "──────" "─────" "─────" "──────" "──────────"
    else
        printf "%-6s  %-18s  %6s  %5s  %5s  %6s  %s\n" \
            "SCORE" "IP" "REQ" "4XX" "5XX" "PATHS" "FLAGS"
        printf "%-6s  %-18s  %6s  %5s  %5s  %6s  %s\n" \
            "─────" "─────────────────" "──────" "─────" "─────" "──────" "──────────"
    fi

    local tmp; tmp=$(mktemp)
    local name
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        [[ -f "$file" ]] && tail -n "$window" "$file" >> "$tmp"
    done

    # Score + top-N in one awk+sort pipeline. Post-aggregation, we pretty-
    # print in bash so we can slot in an optional per-IP country lookup
    # (mmdblookup runs at most $topn times — never per-line).
    local ranked
    ranked=$(awk '
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
        }' "$tmp" | sort -t$'\t' -k1,1 -rn | head -n "$topn")

    rm -f "$tmp"

    [[ -z "$ranked" ]] && { echo; return 0; }

    local sc ip req e4 e5 p_count flags c country
    while IFS=$'\t' read -r sc ip req e4 e5 p_count flags; do
        c=$G
        (( sc >= 10 )) && c=$Y
        (( sc >= 30 )) && c=$R
        if (( show_geo )); then
            country=$(geoip_country "$ip")
            printf "%b%-6s%b  %-18s  %-7s  %6s  %5s  %5s  %6s  %s\n" \
                "$c" "$sc" "$NC" "$ip" "$country" "$req" "$e4" "$e5" "$p_count" "$flags"
        else
            printf "%b%-6s%b  %-18s  %6s  %5s  %5s  %6s  %s\n" \
                "$c" "$sc" "$NC" "$ip" "$req" "$e4" "$e5" "$p_count" "$flags"
        fi
    done <<< "$ranked"

    echo
}

