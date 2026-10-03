# milog top-ip-by-app [N]: top IPs per app, which `milog top` hides by merging apps.
mode_top_ip_by_app() {
    local n="${1:-5}"

    if (( ${#LOGS[@]} == 0 )); then
        echo -e "${R}no apps configured (LOGS=())${NC}" >&2
        return 1
    fi

    echo -e "\n${W}── MiLog: Top ${n} IPs per app ──${NC}\n"

    local show_geo=0
    [[ "${GEOIP_ENABLED:-0}" == "1" && -f "$MMDB_PATH" ]] && show_geo=1

    if (( show_geo )); then
        printf "%-14s  %-5s  %-18s  %-7s  %10s\n" "APP" "RANK" "IP" "COUNTRY" "REQUESTS"
        printf "%-14s  %-5s  %-18s  %-7s  %10s\n" "──────────────" "────" "─────────────────" "───────" "────────"
    else
        printf "%-14s  %-5s  %-18s  %10s\n" "APP" "RANK" "IP" "REQUESTS"
        printf "%-14s  %-5s  %-18s  %10s\n" "──────────────" "────" "─────────────────" "────────"
    fi

    local name path i count ip col country printed_anything=0
    for name in "${LOGS[@]}"; do
        path="$LOG_DIR/$name.access.log"
        [[ -f "$path" ]] || continue

        # Show apps with no traffic instead of silently dropping them.
        if [[ ! -s "$path" ]]; then
            if (( show_geo )); then
                printf "%-14s  %-5s  %-18s  %-7s  %10s\n" "$name" "-" "(no traffic)" "-" "0"
            else
                printf "%-14s  %-5s  %-18s  %10s\n" "$name" "-" "(no traffic)" "0"
            fi
            printed_anything=1
            continue
        fi

        i=1
        while read -r count ip; do
            col=""
            (( i == 1 ))            && col="$R"
            (( i > 1 && i <= 3 ))   && col="$Y"
            if (( show_geo )); then
                country=$(geoip_country "$ip")
                printf "%-14s  %-5s  %-18s  %-7s  %b%10s%b\n" \
                    "$name" "#$i" "$ip" "$country" "$col" "$count" "$NC"
            else
                printf "%-14s  %-5s  %-18s  %b%10s%b\n" \
                    "$name" "#$i" "$ip" "$col" "$count" "$NC"
            fi
            i=$((i+1))
        done < <(awk '{print $1}' "$path" | sort | uniq -c | sort -rn | head -n "$n")

        printed_anything=1
        echo
    done

    if (( ! printed_anything )); then
        echo -e "${D}no readable access logs under $LOG_DIR${NC}"
    fi
}
