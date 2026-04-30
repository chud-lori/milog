# ==============================================================================
# MODE: patterns — generic app-error detection across all LOGS source types
# Watches every configured source through `_log_reader_cmd`, runs each line
# against a built-in catalog of universal app-error signatures plus any
# user-defined extras (APP_PATTERN_<name>=regex), and fires alerts keyed
# `app:<source>:<pattern>` through the existing alert infra.
# Source-agnostic by design — works on nginx, journal, docker, and text logs.
# Parallel indexed arrays (not associative) keep the module bash-3.2-friendly
# for dev boxes; the catalog is small enough that O(N) lookups are free.
# ==============================================================================

# Built-in pattern catalog. Names + regexes paired by index. ERE, matched
# case-insensitively. Each entry is anchored to a phrase narrow enough that
# a false positive justifies waking someone — broaden only with care.
_PATTERNS_BUILTIN_NAMES=(
    panic_go
    traceback_python
    stacktrace_java
    unhandled_promise_node
    oom_kill
    generic_critical
    segfault
    out_of_memory
)
_PATTERNS_BUILTIN_REGEX=(
    '^panic:'
    'Traceback \(most recent call last\):'
    '^[[:space:]]+at .*\(.*\.java:[0-9]+\)'
    'UnhandledPromiseRejectionWarning'
    'Killed process [0-9]+ \(.*\) total-vm'
    '(ERROR|FATAL|CRITICAL)[[:space:]]'
    'segfault at'
    'out of memory'
)

# Look up a built-in regex by name. Empty stdout = not a built-in.
_patterns_builtin_get() {
    local want="$1" i
    for i in "${!_PATTERNS_BUILTIN_NAMES[@]}"; do
        if [[ "${_PATTERNS_BUILTIN_NAMES[$i]}" == "$want" ]]; then
            printf '%s' "${_PATTERNS_BUILTIN_REGEX[$i]}"
            return 0
        fi
    done
    return 1
}

# Walk env for `APP_PATTERN_<name>=<regex>` overrides + extras, merge with
# built-ins, emit one `<name>\t<regex>\n` line per active entry. An empty
# user value disables a same-named built-in (mute panic_go etc. without
# touching the source). Stable sorted output for deterministic listings.
_patterns_collect() {
    local i name regex
    local -a out_names=() out_regex=()
    for i in "${!_PATTERNS_BUILTIN_NAMES[@]}"; do
        out_names+=("${_PATTERNS_BUILTIN_NAMES[$i]}")
        out_regex+=("${_PATTERNS_BUILTIN_REGEX[$i]}")
    done
    # Apply user overrides + additions from env.
    local k v idx found
    while IFS='=' read -r k v; do
        [[ "$k" == APP_PATTERN_* ]] || continue
        name="${k#APP_PATTERN_}"
        found=-1
        for idx in "${!out_names[@]}"; do
            [[ "${out_names[$idx]}" == "$name" ]] && { found=$idx; break; }
        done
        if [[ -z "$v" ]]; then
            if (( found >= 0 )); then
                unset "out_names[$found]" "out_regex[$found]"
                out_names=("${out_names[@]}")
                out_regex=("${out_regex[@]}")
            fi
            continue
        fi
        if (( found >= 0 )); then
            out_regex[$found]="$v"
        else
            out_names+=("$name")
            out_regex+=("$v")
        fi
    done < <(env)
    # Pair-emit and sort by name.
    for i in "${!out_names[@]}"; do
        printf '%s\t%s\n' "${out_names[$i]}" "${out_regex[$i]}"
    done | sort
}

# Build a single union ERE from the collected patterns — one tail+grep pipe
# per source instead of N. The classifier below re-tests each pattern in
# bash to attribute matches by name (rare path; only on actual matches).
_patterns_union_ere() {
    local first=1 out="" name re
    while IFS=$'\t' read -r name re; do
        [[ -z "$re" ]] && continue
        if (( first )); then out="(${re})"; first=0
        else out+="|(${re})"; fi
    done
    printf '%s' "$out"
}

# Classify which named pattern(s) a line matched. Multiple matches per line
# are possible (e.g. an OOM line trips both `oom_kill` and `out_of_memory`);
# we fire one alert per classified pattern so silence rules can target each
# independently. Stdout: pattern names, space-separated.
_patterns_classify() {
    local line="$1"
    local name re hits=""
    while IFS=$'\t' read -r name re; do
        [[ -z "$re" ]] && continue
        if printf '%s' "$line" | grep -Eqi -- "$re"; then
            hits+="$name "
        fi
    done < <(_patterns_collect)
    printf '%s' "${hits% }"
}

mode_patterns() {
    [[ "${PATTERNS_ENABLED:-1}" == "1" ]] || {
        _dlog "patterns: disabled (PATTERNS_ENABLED=0)" 2>/dev/null
        return 0
    }
    local -a names=() regexes=()
    local n r
    while IFS=$'\t' read -r n r; do
        [[ -z "$r" ]] && continue
        names+=("$n"); regexes+=("$r")
    done < <(_patterns_collect)
    if (( ${#names[@]} == 0 )); then
        _dlog "patterns: no patterns enabled — nothing to watch" 2>/dev/null
        return 0
    fi
    local union; union=$(_patterns_collect | _patterns_union_ere)
    [[ -n "$union" ]] || return 0

    local interactive=0
    [[ -t 1 ]] && interactive=1
    if (( interactive )); then
        echo -e "${D}Watching app-error patterns across ${#LOGS[@]} source(s)... (Ctrl+C)${NC}"
        echo -e "${D}Patterns: ${names[*]}${NC}\n"
    fi

    # Single sequential consumer — multiple parallel watchers race on
    # alerts.state's read-modify-write (concurrent renames clobber each
    # other, leading to lost cooldown entries and double-fires). All sources
    # funnel into one merged stream tagged `<source>\t<line>` and a single
    # consumer processes lines one at a time, so cooldown is rock-solid.
    # awk handles the per-line tagging + fflush so output is line-buffered
    # on both Linux (gawk) and macOS (BSD awk) without GNU-only flags.
    local colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    {
        local entry
        for entry in "${LOGS[@]}"; do
            local source_name; source_name=$(_log_name_for "$entry")
            local cmd;         cmd=$(_log_reader_cmd "$entry") || continue
            [[ -z "$cmd" ]] && continue
            # Strip diagnostic lines (`#journal unavailable: …`) BEFORE
            # tagging so they never match `(ERROR|FATAL|CRITICAL)\s` and
            # self-page. awk fflush() forces line-buffering portably.
            ( bash -c "$cmd" 2>/dev/null \
                | grep --line-buffered -v '^#' \
                | awk -v src="$source_name" '{print src "\t" $0; fflush()}' ) &
        done
        wait
    } | while IFS=$'\t' read -r src line; do
            [[ -z "$line" ]] && continue
            # Union pre-filter via bash =~ — avoids the cost of forking grep
            # per line, and (critically) anchors patterns like `^panic:`
            # against the actual line content, not against the post-tag
            # stream where `^` would match nothing.
            shopt -s nocasematch
            [[ "$line" =~ $union ]] || { shopt -u nocasematch; continue; }
            shopt -u nocasematch
            local hits; hits=$(_patterns_classify "$line")
            [[ -z "$hits" ]] && continue
            if (( interactive )); then
                local col="${colors[$(( i % ${#colors[@]} ))]}" label
                label=$(printf "%-10s" "$src")
                printf '%b[%s]%b %b[%s]%b %s\n' \
                    "$col" "$label" "$NC" "$R" "$hits" "$NC" "${line:0:280}"
                (( i++ )) || true
            fi
            local pat
            for pat in $hits; do
                local key="app:$src:$pat"
                if alert_should_fire "$key"; then
                    alert_fire \
                        "App pattern: $src / $pat" \
                        "\`\`\`${line:0:1800}\`\`\`" \
                        15158332 "$key" &
                fi
            done
        done
}

# Inspect mode — `milog patterns list` shows the merged catalog including any
# user overrides, with a `builtin` / `override` / `custom` tag. Useful for
# debugging why a given pattern isn't firing.
mode_patterns_list() {
    local name re origin builtin_re
    printf '%-28s %-10s %s\n' "NAME" "ORIGIN" "REGEX"
    while IFS=$'\t' read -r name re; do
        builtin_re=$(_patterns_builtin_get "$name") || true
        if [[ -z "$builtin_re" ]]; then
            origin="custom"
        elif [[ "$builtin_re" != "$re" ]]; then
            origin="override"
        else
            origin="builtin"
        fi
        printf '%-28s %-10s %s\n' "$name" "$origin" "$re"
    done < <(_patterns_collect)
}
