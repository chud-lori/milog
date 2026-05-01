# ==============================================================================
# MODE: errors — show what's broken right now, across every log source
#
# Two faces:
#
#   1. Live tail (default, backward-compatible)
#      `milog errors`      → tail every source. nginx-typed sources show
#                            4xx/5xx lines; journal/docker/text sources show
#                            app-pattern matches (Go panics, OOM kills, …).
#
#   2. Summary report (any flag triggers it)
#      `milog errors --since 24h [--source X] [--pattern Y]`
#                          → scan alerts.log for `app:<source>:<pattern>`
#                            fires in the window, group counts, list samples.
#
# Window grammar mirrors `milog alerts`: today / yesterday / all / Nh/Nd/Nw.
# ==============================================================================

mode_errors() {
    # Flag-driven summary mode. Plain `milog errors` keeps doing the live
    # mixed tail — that's what existing scripts and muscle memory expect.
    case "${1:-}" in
        --since|--since=*|--source|--source=*|--pattern|--pattern=*|--summary|summary)
            _errors_summary "$@"; return $? ;;
        live|--live|"")
            _errors_live;     return $? ;;
        --help|-h|help)
            _errors_help;     return 0 ;;
        *)
            echo -e "${R}unknown errors flag: $1${NC}" >&2
            _errors_help; return 1 ;;
    esac
}

_errors_help() {
    cat <<EOF
${W}milog errors${NC} — what's broken right now, across every log source

  ${C}milog errors${NC}                          live tail (mixed view)
  ${C}milog errors --since <window>${NC}         summary report
  ${C}milog errors --source <name>${NC}          restrict summary to one source
  ${C}milog errors --pattern <name>${NC}         restrict summary to one pattern
  ${C}milog errors --since 1d --pattern panic_go${NC}

Live view (no flags):
  - nginx sources    → tail of 4xx/5xx HTTP lines
  - other sources    → tail of app-pattern matches (panic, OOM, …)

Summary view (any flag): scans alerts.log for ${C}app:<src>:<pat>${NC} fires
within the window. Window grammar: today / yesterday / all / Nm / Nh / Nd / Nw.
EOF
}

# --- Live tail ----------------------------------------------------------------
# Nginx sources: classic 4xx/5xx line filter.
# Non-nginx sources: pattern union from the patterns module — same source of
# truth as `milog patterns`, so adding a pattern there extends this view too.
_errors_live() {
    echo -e "${D}Watching errors across all sources... (Ctrl+C)${NC}"
    echo -e "${D}  nginx sources: 4xx/5xx tail   |   other sources: app-pattern matches${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0
    local pattern_union; pattern_union=$(_patterns_collect | _patterns_union_ere)

    local entry
    for entry in "${LOGS[@]}"; do
        local type;        type=$(_log_type_for "$entry")
        local source_name; source_name=$(_log_name_for "$entry")
        local cmd;         cmd=$(_log_reader_cmd "$entry") || { (( i++ )) || true; continue; }
        [[ -z "$cmd" ]] && { (( i++ )) || true; continue; }
        local col="${colors[$(( i % ${#colors[@]} ))]}" label
        label=$(printf "%-10s" "$source_name")

        case "$type" in
            nginx)
                # Backward-compat tail: 4xx/5xx HTTP status filter on the
                # combined-format access line. Same regex as v1.
                ( bash -c "$cmd" 2>/dev/null \
                    | grep --line-buffered -E ' [45][0-9][0-9] ' \
                    | awk -v col="$col" -v lbl="$label" -v nc="$NC" \
                        '{print col"["lbl"]"nc" "$0; fflush()}' ) &
                pids+=($!)
                ;;
            *)
                # App-pattern tail — only spawn when at least one pattern is
                # defined; otherwise the union ERE is empty and grep would
                # match every line.
                if [[ -n "$pattern_union" ]]; then
                    ( bash -c "$cmd" 2>/dev/null \
                        | grep --line-buffered -v '^#' \
                        | grep --line-buffered -E -i -- "$pattern_union" \
                        | awk -v col="$col" -v lbl="$label" -v nc="$NC" \
                            '{print col"["lbl"]"nc" "$0; fflush()}' ) &
                    pids+=($!)
                fi
                ;;
        esac
        (( i++ )) || true
    done
    if (( ${#pids[@]} == 0 )); then
        echo -e "${Y}no readable sources — check LOGS in milog config${NC}" >&2
        return 1
    fi
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

# --- Summary report -----------------------------------------------------------
# Reads alerts.log for `app:<source>:<pattern>` fires in the window. Optional
# --source / --pattern filters narrow the report; both are exact match on the
# rule-key segment so users can paste from `milog patterns list`.
_errors_summary() {
    local window="today" want_source="" want_pattern="" arg
    while (( $# )); do
        arg="$1"
        case "$arg" in
            --since)         window="${2:?--since needs a value}";  shift 2 ;;
            --since=*)       window="${arg#--since=}";              shift   ;;
            --source)        want_source="${2:?--source needs a name}"; shift 2 ;;
            --source=*)      want_source="${arg#--source=}";        shift   ;;
            --pattern)       want_pattern="${2:?--pattern needs a name}"; shift 2 ;;
            --pattern=*)     want_pattern="${arg#--pattern=}";      shift   ;;
            --summary|summary) shift ;;
            *)               echo -e "${R}unknown flag: $arg${NC}" >&2; return 1 ;;
        esac
    done

    local log_file="$ALERT_STATE_DIR/alerts.log"
    if [[ ! -s "$log_file" ]]; then
        echo -e "${D}no alerts.log yet — set ALERTS_ENABLED=1 and run \`milog daemon\` to populate${NC}"
        return 0
    fi

    local cutoff cutoff_fmt
    cutoff=$(_alerts_window_to_epoch "$window") || return 1
    cutoff_fmt=$(_alerts_fmt_epoch "$cutoff")

    # Filter once: in-window AND rule_key starts with `app:`. Optional
    # source/pattern filters refine further. awk does the heavy lift; bash
    # consumes the small filtered result.
    local filtered; filtered=$(mktemp -t milog_errors.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$filtered'" RETURN

    awk -F'\t' \
        -v cutoff="$cutoff" \
        -v want_src="$want_source" \
        -v want_pat="$want_pattern" '
        $1 < cutoff { next }
        $2 !~ /^app:/ { next }
        {
            n = split($2, parts, ":")
            if (n < 3) next
            src = parts[2]
            pat = parts[3]
            if (want_src != "" && src != want_src) next
            if (want_pat != "" && pat != want_pat) next
            print $0 "\t" src "\t" pat
        }' "$log_file" > "$filtered"

    local total; total=$(wc -l < "$filtered" | tr -d ' '); total=${total:-0}
    local hdr_filters=""
    [[ -n "$want_source"  ]] && hdr_filters+=" source=$want_source"
    [[ -n "$want_pattern" ]] && hdr_filters+=" pattern=$want_pattern"
    echo -e "\n${W}── MiLog: app errors since ${cutoff_fmt} (window=$window${hdr_filters}) ──${NC}\n"

    if (( total == 0 )); then
        echo -e "  ${D}no app-pattern fires in window — quiet system or PATTERNS_ENABLED=0${NC}\n"
        return 0
    fi

    echo -e "  ${W}by source${NC}"
    awk -F'\t' '{print $6}' "$filtered" \
        | sort | uniq -c | sort -rn \
        | awk '{printf "    %5d  %s\n", $1, $2}'

    echo -e "\n  ${W}by pattern${NC}"
    awk -F'\t' '{print $7}' "$filtered" \
        | sort | uniq -c | sort -rn \
        | awk '{printf "    %5d  %s\n", $1, $2}'

    local list_cap=20
    local shown=$total
    (( shown > list_cap )) && shown=$list_cap
    echo -e "\n  ${W}timeline${NC} ${D}(latest ${shown} of ${total})${NC}"
    printf "  %-16s  %-12s  %-22s  %s\n" "WHEN" "SOURCE" "PATTERN" "SAMPLE"
    printf "  %-16s  %-12s  %-22s  %s\n" "────────────────" "────────────" "──────────────────────" "──────"
    local epoch rule color title body src pat when sample
    while IFS=$'\t' read -r epoch rule color title body src pat; do
        [[ -z "$epoch" ]] && continue
        when=$(_alerts_fmt_epoch "$epoch")
        # Body is the matched line wrapped in ```; strip the fences and cap
        # at 60 chars so the row stays scanable.
        sample="${body#\`\`\`}"; sample="${sample%\`\`\`}"
        (( ${#sample} > 60 )) && sample="${sample:0:57}..."
        printf "  %-16s  ${R}%-12s${NC}  ${Y}%-22s${NC}  %s\n" "$when" "$src" "$pat" "$sample"
    done < <(tail -n "$list_cap" "$filtered")

    echo -e "\n  ${D}total: $total fire(s) — log at $log_file${NC}\n"
}
