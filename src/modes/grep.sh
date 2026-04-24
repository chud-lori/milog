# ==============================================================================
# MODE: grep — filter-tail one source (any type: nginx / text / journal / docker)
# ==============================================================================
mode_grep() {
    local name="${1:-}" pattern="${2:-.}"
    if [[ -z "$name" ]]; then
        local apps=""
        for entry in "${LOGS[@]}"; do apps+="$(_log_name_for "$entry") "; done
        echo -e "${R}Usage: $0 grep <app> <pattern>${NC}  Apps: ${apps% }"
        exit 1
    fi
    local matching
    matching=$(_log_entry_by_name "$name") || {
        echo -e "${R}unknown source: $name${NC}" >&2; exit 1; }
    local cmd
    cmd=$(_log_reader_cmd "$matching") || {
        echo -e "${R}cannot build reader for $name${NC}" >&2; exit 1; }
    [[ -z "$cmd" ]] && { echo -e "${R}reader empty for $name${NC}" >&2; exit 1; }
    echo -e "${D}stream $matching | grep '$pattern'  (Ctrl+C)${NC}\n"
    bash -c "$cmd" 2>/dev/null | grep --line-buffered -i "$pattern"
}

