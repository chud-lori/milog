# ==============================================================================
# MODE: top
# ==============================================================================
mode_top() {
    local n="${1:-10}"
    echo -e "\n${W}── MiLog: Top ${n} IPs ──${NC}\n"

    local show_geo=0
    [[ "${GEOIP_ENABLED:-0}" == "1" && -f "$MMDB_PATH" ]] && show_geo=1

    if (( show_geo )); then
        printf "%-5s  %-18s  %-7s  %10s\n" "RANK" "IP" "COUNTRY" "REQUESTS"
        printf "%-5s  %-18s  %-7s  %10s\n" "────" "─────────────────" "───────" "────────"
    else
        printf "%-5s  %-18s  %10s\n" "RANK" "IP" "REQUESTS"
        printf "%-5s  %-18s  %10s\n" "────" "─────────────────" "────────"
    fi

    local tmp; tmp=$(mktemp)
    local name
    for name in "${LOGS[@]}"; do
        [[ -f "$LOG_DIR/$name.access.log" ]] \
            && awk '{print $1}' "$LOG_DIR/$name.access.log" >> "$tmp"
    done

    # Geo lookup happens here — after uniq has already collapsed the IP set
    # to at most $n rows, so we fork mmdblookup $n times, not once per line.
    local i=1 count ip col country
    while read -r count ip; do
        col=""
        (( i == 1 ))             && col="$R"
        (( i > 1 && i <= 3 ))    && col="$Y"
        if (( show_geo )); then
            country=$(geoip_country "$ip")
            printf "%-5s  %-18s  %-7s  %b%10s%b\n" \
                "#$i" "$ip" "$country" "$col" "$count" "$NC"
        else
            printf "%-5s  %-18s  %b%10s%b\n" \
                "#$i" "$ip" "$col" "$count" "$NC"
        fi
        i=$((i+1))
    done < <(sort "$tmp" | uniq -c | sort -rn | head -n "$n")

    rm -f "$tmp"
    echo
}

