# milog top [N]: busiest IPs across all apps.
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
    local name ai tot ai_sum=0 tot_sum=0
    for name in "${LOGS[@]}"; do
        [[ -f "$LOG_DIR/$name.access.log" ]] || continue
        awk '{print $1}' "$LOG_DIR/$name.access.log" >> "$tmp"
        read -r ai tot < <(nginx_ai_counts "$name")
        ai_sum=$(( ai_sum + ai )); tot_sum=$(( tot_sum + tot ))
    done

    # Geo lookup after uniq, so mmdblookup forks at most $n times.
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
    if (( tot_sum > 0 )); then
        echo -e "\n${D}AI crawlers: $(( ai_sum * 100 / tot_sum ))% of requests (${ai_sum} of ${tot_sum})${NC}"
    fi
    echo
}

