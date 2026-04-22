# ==============================================================================
# MODE: errors
# ==============================================================================
mode_errors() {
    echo -e "${D}Watching 4xx/5xx across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$i]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            tail -F "$file" 2>/dev/null | \
                grep --line-buffered ' [45][0-9][0-9] ' | \
                awk -v col="$col" -v lbl="$label" -v nc="$NC" \
                    '{print col"["lbl"]"nc" "$0; fflush()}' &
            pids+=($!)
        fi
        (( i++ )) || true
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

