# ==============================================================================
# MODE: audit — point-in-time host integrity scans
#
# Today: file integrity monitoring (FIM). SHA256 baseline of a configurable
# watchlist (AUDIT_FIM_PATHS) re-checked on a timer. Drift fires
# `audit:fim:<path>` through the existing alert path — silence + cooldown
# + dedup all apply for free.
#
# Layout: `audit` is the umbrella subcommand. `fim` is the first scanner;
# more land beside it (persistence diff, listening-port baseline, SSH key
# audit, rootkit hints) without renaming anything.
#
# Storage: $ALERT_STATE_DIR/audit/fim.baseline (TSV, one row per path)
#   <path>\t<sha256>\t<mtime_epoch>\t<size_bytes>\t<recorded_epoch>
# Special sha256 value `MISSING` means the path was absent at baseline
# time — alerts fire when an absent path subsequently appears.
# ==============================================================================

# --- helpers ------------------------------------------------------------------

# Portable sha256 of one file. Returns the hex digest on stdout, empty on
# error (unreadable / nonexistent). Avoids forking the same binary
# differently across distros.
_audit_sha256() {
    local path="$1"
    [[ -r "$path" ]] || return 0
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$path" 2>/dev/null | awk '{print $1; exit}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$path" 2>/dev/null | awk '{print $1; exit}'
    fi
}

# Portable mtime + size in epoch seconds + bytes. Returns "<mtime>\t<size>"
# on stdout, empty on missing-file. GNU stat (`-c`) on Linux, BSD stat
# (`-f`) on macOS — same outputs, different flags.
_audit_stat() {
    local path="$1"
    [[ -e "$path" ]] || return 0
    stat -c '%Y	%s' -- "$path" 2>/dev/null \
        || stat -f '%m	%z' -- "$path" 2>/dev/null
}

_audit_state_dir() {
    local d="${ALERT_STATE_DIR:-$HOME/.cache/milog}/audit"
    mkdir -p "$d" 2>/dev/null
    printf '%s' "$d"
}

# Expand AUDIT_FIM_PATHS with shell globbing into a deduped, sorted list of
# concrete paths. Patterns that match nothing contribute the literal
# pattern itself — so a watchlist entry pointing at a path that doesn't
# exist yet is still tracked (and fires the moment it does appear).
_audit_fim_expand_paths() {
    local pat path
    local -a out=()
    shopt -s nullglob
    for pat in "${AUDIT_FIM_PATHS[@]}"; do
        local -a matches=( $pat )
        if (( ${#matches[@]} > 0 )); then
            for path in "${matches[@]}"; do
                out+=("$path")
            done
        else
            # No match — keep the literal pattern so absence is auditable.
            # (Globless paths fall through here too — `/etc/shadow` with no
            # glob chars matches itself if present, lands in this branch
            # otherwise.)
            out+=("$pat")
        fi
    done
    shopt -u nullglob
    # Dedupe + sort for stable diff output.
    printf '%s\n' "${out[@]}" | sort -u
}

# --- baseline / check ---------------------------------------------------------

# (Re)build the FIM baseline from the current filesystem state. Overwrites
# the previous baseline. No alerts fire — this is the "I trust the host
# right now" moment. Use `milog audit fim check` to compare against the
# baseline later.
_audit_fim_baseline() {
    local dir; dir=$(_audit_state_dir)
    local out="$dir/fim.baseline"
    local tmp; tmp=$(mktemp "$dir/fim.baseline.tmp.XXXXXX") || return 1
    local now; now=$(date +%s)
    local path sha mtime size st
    local count=0 missing=0

    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        if [[ -e "$path" ]]; then
            sha=$(_audit_sha256 "$path")
            st=$(_audit_stat "$path")
            mtime="${st%%	*}"
            size="${st##*	}"
            [[ -z "$sha" ]] && sha="UNREADABLE"
            (( count++ )) || true
        else
            sha="MISSING"; mtime=0; size=0
            (( missing++ )) || true
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "$path" "$sha" "$mtime" "$size" "$now" >> "$tmp"
    done < <(_audit_fim_expand_paths)

    mv "$tmp" "$out"
    # Stdout: `<count_present> <count_missing> <path>` — read with
    # `read present missing path` in the caller. Three fields on one
    # line dodges the subshell-scope problem that bites globals when
    # this function is invoked via $().
    printf '%d %d %s\n' "$count" "$missing" "$out"
}

# Compare current state against the baseline. Stdout: one line per
# drifted path, format `<change>\t<path>\t<old>→<new>`. Change types:
#   MODIFIED   sha256 differs
#   APPEARED   was MISSING, now present
#   REMOVED    was present, now MISSING
#   UNREADABLE was readable, now denied (perm change is itself signal)
# Empty stdout = no drift.
_audit_fim_diff() {
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/fim.baseline"
    [[ -f "$baseline" ]] || return 1

    local path old_sha old_mtime old_size old_recorded
    local new_sha new_mtime new_size st
    while IFS=$'\t' read -r path old_sha old_mtime old_size old_recorded; do
        [[ -z "$path" ]] && continue
        if [[ -e "$path" ]]; then
            new_sha=$(_audit_sha256 "$path")
            [[ -z "$new_sha" ]] && new_sha="UNREADABLE"
            if [[ "$old_sha" == "MISSING" ]]; then
                printf 'APPEARED\t%s\t%s→%s\n' "$path" "$old_sha" "${new_sha:0:16}"
            elif [[ "$old_sha" == "UNREADABLE" && "$new_sha" != "UNREADABLE" ]]; then
                # Was perm-blocked at baseline, now readable — record as
                # APPEARED-equivalent so the operator sees the new content.
                printf 'APPEARED\t%s\t%s→%s\n' "$path" "$old_sha" "${new_sha:0:16}"
            elif [[ "$old_sha" != "$new_sha" ]]; then
                if [[ "$new_sha" == "UNREADABLE" ]]; then
                    printf 'UNREADABLE\t%s\t%s→%s\n' "$path" "${old_sha:0:16}" "$new_sha"
                else
                    printf 'MODIFIED\t%s\t%s→%s\n' "$path" "${old_sha:0:16}" "${new_sha:0:16}"
                fi
            fi
        else
            if [[ "$old_sha" != "MISSING" ]]; then
                printf 'REMOVED\t%s\t%s→MISSING\n' "$path" "${old_sha:0:16}"
            fi
        fi
    done < "$baseline"
}

# Daemon-side periodic check. Auto-baselines on first run (no alerts);
# later runs alert on drift. Throttled by AUDIT_FIM_INTERVAL via an
# epoch marker file so multiple daemon ticks per minute don't all hash.
_audit_fim_tick() {
    [[ "${AUDIT_ENABLED:-0}" == "1" ]] || return 0
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/fim.baseline"
    local marker="$dir/fim.lastcheck"
    local now; now=$(date +%s)
    local last=0
    [[ -f "$marker" ]] && last=$(cat "$marker" 2>/dev/null || echo 0)
    [[ -z "$last" ]] && last=0
    if (( now - last < AUDIT_FIM_INTERVAL )); then
        return 0
    fi

    if [[ ! -f "$baseline" ]]; then
        # First run: silently baseline. The user's own
        # `milog audit fim check` is how to verify the watchlist —
        # surprise-firing on the first daemon tick would be noise.
        # We discard the count line; the daemon doesn't print it.
        _audit_fim_baseline >/dev/null 2>&1
        printf '%s' "$now" > "$marker"
        return 0
    fi

    # Drift check; one alert per drifted path.
    local change path detail key body
    while IFS=$'\t' read -r change path detail; do
        [[ -z "$change" ]] && continue
        key="audit:fim:$change:$path"
        if alert_should_fire "$key"; then
            body="\`\`\`$change $path $detail\`\`\`"
            alert_fire "FIM drift: $change $path" "$body" 15158332 "$key" &
        fi
    done < <(_audit_fim_diff)

    printf '%s' "$now" > "$marker"
}

# --- user-facing subcommands --------------------------------------------------

mode_audit() {
    case "${1:-}" in
        ""|help|--help|-h) _audit_help ;;
        fim) shift; _audit_fim_subcmd "$@" ;;
        *)
            echo -e "${R}unknown audit subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}

_audit_help() {
    cat <<EOF
${W}milog audit${NC} — point-in-time host integrity scans

  ${C}milog audit fim baseline${NC}   record SHA256 of every watched path NOW
  ${C}milog audit fim check${NC}      diff current state against baseline
  ${C}milog audit fim status${NC}     show watchlist + baseline timestamps

The watcher runs inside ${C}milog daemon${NC} when ${C}AUDIT_ENABLED=1${NC} —
auto-baselines on first run, then fires ${C}audit:fim:<change>:<path>${NC}
through the existing alert path on every subsequent drift.

Watchlist: ${C}AUDIT_FIM_PATHS${NC} (config / env). Glob patterns OK.
EOF
}

_audit_fim_subcmd() {
    case "${1:-status}" in
        baseline)
            local present missing path
            read -r present missing path < <(_audit_fim_baseline)
            echo -e "${G}baseline${NC} written to ${C}$path${NC}"
            echo -e "  ${D}tracked: ${present:-0} present, ${missing:-0} missing${NC}"
            ;;
        check)
            local dir; dir=$(_audit_state_dir)
            if [[ ! -f "$dir/fim.baseline" ]]; then
                echo -e "${Y}no baseline yet — run \`milog audit fim baseline\` first${NC}"
                return 1
            fi
            local out; out=$(_audit_fim_diff)
            if [[ -z "$out" ]]; then
                echo -e "${G}no drift${NC} — every watched path matches baseline"
                return 0
            fi
            echo -e "${R}drift detected:${NC}"
            printf '%s\n' "$out" | awk -F'\t' '{
                color = "31"  # red
                if ($1 == "APPEARED") color = "33"   # yellow — new file
                if ($1 == "UNREADABLE") color = "33"
                printf "  \033[%sm%-11s\033[0m  %-50s  %s\n", color, $1, $2, $3
            }'
            return 1
            ;;
        status)
            local dir; dir=$(_audit_state_dir)
            local baseline="$dir/fim.baseline"
            local marker="$dir/fim.lastcheck"
            echo -e "${W}milog audit fim — status${NC}"
            echo -e "  ${D}AUDIT_ENABLED=${NC}${AUDIT_ENABLED:-0}   ${D}AUDIT_FIM_INTERVAL=${NC}${AUDIT_FIM_INTERVAL:-3600}s"
            if [[ -f "$baseline" ]]; then
                local age count
                age=$(stat -c '%Y' "$baseline" 2>/dev/null || stat -f '%m' "$baseline" 2>/dev/null || echo 0)
                count=$(wc -l < "$baseline" 2>/dev/null | tr -d ' ')
                echo -e "  ${D}baseline:${NC} $baseline"
                echo -e "  ${D}  paths tracked:${NC} ${count:-0}"
                if [[ "$age" -gt 0 ]]; then
                    local now; now=$(date +%s)
                    local mins=$(( (now - age) / 60 ))
                    echo -e "  ${D}  recorded:${NC} ${mins}m ago"
                fi
            else
                echo -e "  ${D}baseline:${NC} ${Y}not yet recorded${NC}"
            fi
            if [[ -f "$marker" ]]; then
                local last; last=$(cat "$marker" 2>/dev/null || echo 0)
                local now; now=$(date +%s)
                local mins=$(( (now - last) / 60 ))
                echo -e "  ${D}last check:${NC} ${mins}m ago"
            else
                echo -e "  ${D}last check:${NC} ${Y}never${NC}"
            fi
            echo -e "  ${D}watchlist (${#AUDIT_FIM_PATHS[@]} entries):${NC}"
            local p
            for p in "${AUDIT_FIM_PATHS[@]}"; do
                printf "    %s\n" "$p"
            done
            ;;
        *)
            echo -e "${R}unknown fim subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}
