# ==============================================================================
# MODE: health
# ==============================================================================
mode_health() {
    echo -e "\n${W}── MiLog: Status Code Health ──${NC}\n"
    printf "%-12s  %8s  %8s  %8s  %8s  %8s\n" "APP" "TOTAL" "2xx" "3xx" "4xx" "5xx"
    printf "%-12s  %8s  %8s  %8s  %8s  %8s\n" "───────────" "───────" "───────" "───────" "───────" "───────"
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        [[ -f "$file" ]] || { printf "%-12s  %8s\n" "$name" "(not found)"; continue; }
        local total s2=0 s3=0 s4=0 s5=0
        total=$(wc -l < "$file")
        s2=$(grep -c ' 2[0-9][0-9] ' "$file" 2>/dev/null || true)
        s3=$(grep -c ' 3[0-9][0-9] ' "$file" 2>/dev/null || true)
        s4=$(grep -c ' 4[0-9][0-9] ' "$file" 2>/dev/null || true)
        s5=$(grep -c ' 5[0-9][0-9] ' "$file" 2>/dev/null || true)
        local c4=$NC c5=$NC t4 t5
        t4=$(_thresh THRESH_4XX_WARN "$name")
        t5=$(_thresh THRESH_5XX_WARN "$name")
        [[ $s4 -gt $t4 ]] && c4=$Y
        [[ $s5 -gt $t5 ]] && c5=$R
        printf "%-12s  %8s  %8s  %8s  ${c4}%8s${NC}  ${c5}%8s${NC}\n" \
            "$name" "$total" "$s2" "$s3" "$s4" "$s5"
    done
    echo ""
}

