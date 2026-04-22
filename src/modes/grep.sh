# ==============================================================================
# MODE: grep
# ==============================================================================
mode_grep() {
    local name="${1:-}" pattern="${2:-.}"
    [[ -z "$name" || ! " ${LOGS[*]} " =~ " $name " ]] && {
        echo -e "${R}Usage: $0 grep <app> <pattern>${NC}  Apps: ${LOGS[*]}"; exit 1; }
    echo -e "${D}tail -F $LOG_DIR/$name.access.log | grep '$pattern'  (Ctrl+C)${NC}\n"
    tail -F "$LOG_DIR/$name.access.log" | grep --line-buffered -i "$pattern"
}

