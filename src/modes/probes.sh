# milog probes: scanner, bot and crawler traffic by user-agent, plus non-HTTP protocol probes.
mode_probes() {
    echo -e "${D}Watching scanner/bot traffic across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    _rules_load

    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$(( i % ${#colors[@]} ))]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            (
                app="$name"
                tail -F "$file" 2>/dev/null | \
                    grep --line-buffered -Ei -e "$RULES_PROBE" | \
                while IFS= read -r line; do
                    printf '%b[%s]%b %s\n' "$col" "$label" "$NC" "$(_tty_safe <<< "$line")"
                    # Dedup with exploits, which often matches the same scanner line.
                    fp=$(alert_fingerprint_from_line "$line")
                    if alert_should_fire "probe:$app" \
                       && alert_fingerprint_fresh "$fp"; then
                        alert_fire "Probe traffic: $app" "$(_alert_fence "${line:0:1800}")$(cti_alert_note "${line%% *}")" 15844367 "probe:$app" "${line%% *}" &
                    fi
                done
            ) &
            pids+=($!)
        fi
        (( i++ )) || true
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

