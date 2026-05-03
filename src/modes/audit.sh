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
        persistence) shift; _audit_persistence_subcmd "$@" ;;
        ports) shift; _audit_ports_subcmd "$@" ;;
        *)
            echo -e "${R}unknown audit subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}

_audit_help() {
    cat <<EOF
${W}milog audit${NC} — point-in-time host integrity scans

  ${C}milog audit fim ${NC}<sub>          file integrity (SHA256 drift on watched files)
  ${C}milog audit persistence ${NC}<sub>  re-entry surface diff (new cron / systemd units / rc.local)
  ${C}milog audit ports ${NC}<sub>        listening-port baseline (new TCP/UDP listeners)

  Subs (all): ${C}baseline${NC} | ${C}check${NC} | ${C}status${NC}

The watcher runs inside ${C}milog daemon${NC} when ${C}AUDIT_ENABLED=1${NC} —
auto-baselines on first run, then fires ${C}audit:fim:<change>:<path>${NC},
${C}audit:persistence:APPEARED:<path>${NC}, or ${C}audit:ports:NEW:<proto>:<port>${NC}
on every subsequent drift.

Watchlists: ${C}AUDIT_FIM_PATHS${NC} / ${C}AUDIT_PERSISTENCE_PATHS${NC}. Glob patterns OK.
Listening-port scan reads from ${C}ss${NC} (or ${C}netstat${NC} fallback).
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

# ==============================================================================
# Persistence diff — file-existence drift across the classic re-entry surface
# (cron drops, systemd units, rc.local, ld.so.preload). Tracks "did a file
# appear that wasn't there before?" — the high-signal half of post-compromise
# scanning. Hash-drift on existing files is FIM's job; this scanner watches
# directories where attackers DROP NEW FILES.
#
# Storage: $ALERT_STATE_DIR/audit/persistence.baseline (TSV)
#   <path>\t<size>\t<mtime_epoch>\t<recorded_epoch>
#
# Drift policy:
#   APPEARED  fires alert. Sysadmin adding a unit usually goes through
#             config management; a new file in /etc/cron.d/ that wasn't
#             planned is exactly what we want to know about.
#   REMOVED   informational on `check` output but does NOT alert. Pruning
#             stale units is normal sysadmin housekeeping.
# ==============================================================================

_audit_persistence_expand() {
    local pat path
    local -a out=()
    shopt -s nullglob
    for pat in "${AUDIT_PERSISTENCE_PATHS[@]}"; do
        local -a matches=( $pat )
        if (( ${#matches[@]} > 0 )); then
            for path in "${matches[@]}"; do
                # Skip directories — cron drops and systemd units are files.
                # A bare directory entry from the glob would match every
                # daemon tick and produce no useful baseline.
                [[ -d "$path" ]] && continue
                out+=("$path")
            done
        fi
        # Globs that match nothing contribute zero entries — different from
        # FIM where literal-tracked-as-absent is desirable. For persistence
        # we only care about presence; a never-populated /etc/cron.d/ tree
        # is the steady state, not signal.
    done
    shopt -u nullglob
    printf '%s\n' "${out[@]}" | sort -u
}

_audit_persistence_baseline() {
    local dir; dir=$(_audit_state_dir)
    local out="$dir/persistence.baseline"
    local tmp; tmp=$(mktemp "$dir/persistence.baseline.tmp.XXXXXX") || return 1
    local now; now=$(date +%s)
    local path mtime size st count=0

    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        st=$(_audit_stat "$path")
        mtime="${st%%	*}"
        size="${st##*	}"
        printf '%s\t%s\t%s\t%s\n' "$path" "${size:-0}" "${mtime:-0}" "$now" >> "$tmp"
        (( count++ )) || true
    done < <(_audit_persistence_expand)

    mv "$tmp" "$out"
    printf '%d %s\n' "$count" "$out"
}

# Diff current vs baseline. Stdout: `<change>\t<path>` per line.
# Changes: APPEARED, REMOVED. APPEARED fires alerts; REMOVED is shown
# in `check` output but doesn't fire.
_audit_persistence_diff() {
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/persistence.baseline"
    [[ -f "$baseline" ]] || return 1

    local current; current=$(mktemp "$dir/persistence.current.XXXXXX") || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$current'" RETURN
    _audit_persistence_expand > "$current"

    # comm needs sorted inputs. Strip baseline to its path column first.
    local sorted_baseline; sorted_baseline=$(mktemp "$dir/persistence.sortedb.XXXXXX") || return 1
    awk -F'\t' '{print $1}' "$baseline" | sort -u > "$sorted_baseline"

    # APPEARED: in current, not in baseline.
    comm -23 "$current" "$sorted_baseline" | awk '{print "APPEARED\t" $0}'
    # REMOVED: in baseline, not in current.
    comm -13 "$current" "$sorted_baseline" | awk '{print "REMOVED\t" $0}'

    rm -f "$sorted_baseline"
}

_audit_persistence_tick() {
    [[ "${AUDIT_ENABLED:-0}" == "1" ]] || return 0
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/persistence.baseline"
    local marker="$dir/persistence.lastcheck"
    local now; now=$(date +%s)
    local last=0
    [[ -f "$marker" ]] && last=$(cat "$marker" 2>/dev/null || echo 0)
    [[ -z "$last" ]] && last=0
    if (( now - last < AUDIT_PERSISTENCE_INTERVAL )); then
        return 0
    fi

    if [[ ! -f "$baseline" ]]; then
        _audit_persistence_baseline >/dev/null 2>&1
        printf '%s' "$now" > "$marker"
        return 0
    fi

    # Only APPEARED entries fire — REMOVED is intentional silent (housekeeping).
    local change path key body
    while IFS=$'\t' read -r change path; do
        [[ "$change" == "APPEARED" ]] || continue
        [[ -z "$path" ]] && continue
        key="audit:persistence:APPEARED:$path"
        if alert_should_fire "$key"; then
            body="\`\`\`new file in re-entry surface: $path\`\`\`"
            alert_fire "Persistence: new $path" "$body" 15158332 "$key" &
        fi
    done < <(_audit_persistence_diff)

    printf '%s' "$now" > "$marker"
}

_audit_persistence_subcmd() {
    case "${1:-status}" in
        baseline)
            local count path
            read -r count path < <(_audit_persistence_baseline)
            echo -e "${G}baseline${NC} written to ${C}$path${NC}"
            echo -e "  ${D}tracked: ${count:-0} paths in re-entry surface${NC}"
            ;;
        check)
            local dir; dir=$(_audit_state_dir)
            if [[ ! -f "$dir/persistence.baseline" ]]; then
                echo -e "${Y}no baseline yet — run \`milog audit persistence baseline\` first${NC}"
                return 1
            fi
            local out; out=$(_audit_persistence_diff)
            if [[ -z "$out" ]]; then
                echo -e "${G}no drift${NC} — re-entry surface unchanged from baseline"
                return 0
            fi
            local appeared removed
            appeared=$(printf '%s\n' "$out" | grep -c '^APPEARED' || true)
            removed=$(printf '%s\n' "$out"  | grep -c '^REMOVED'  || true)
            if (( appeared > 0 )); then
                echo -e "${R}NEW persistence entries (alert-worthy):${NC}"
                printf '%s\n' "$out" | awk -F'\t' '$1=="APPEARED" {printf "  \033[31m%-9s\033[0m  %s\n", $1, $2}'
            fi
            if (( removed > 0 )); then
                echo -e "${D}removed (housekeeping, no alert):${NC}"
                printf '%s\n' "$out" | awk -F'\t' '$1=="REMOVED"  {printf "  \033[90m%-9s\033[0m  %s\n", $1, $2}'
            fi
            (( appeared > 0 )) && return 1 || return 0
            ;;
        status)
            local dir; dir=$(_audit_state_dir)
            local baseline="$dir/persistence.baseline"
            local marker="$dir/persistence.lastcheck"
            echo -e "${W}milog audit persistence — status${NC}"
            echo -e "  ${D}AUDIT_ENABLED=${NC}${AUDIT_ENABLED:-0}   ${D}AUDIT_PERSISTENCE_INTERVAL=${NC}${AUDIT_PERSISTENCE_INTERVAL:-3600}s"
            if [[ -f "$baseline" ]]; then
                local age count
                age=$(stat -c '%Y' "$baseline" 2>/dev/null || stat -f '%m' "$baseline" 2>/dev/null || echo 0)
                count=$(wc -l < "$baseline" 2>/dev/null | tr -d ' ')
                echo -e "  ${D}baseline:${NC} $baseline"
                echo -e "  ${D}  paths tracked:${NC} ${count:-0}"
                if [[ "$age" -gt 0 ]]; then
                    local now; now=$(date +%s); local mins=$(( (now - age) / 60 ))
                    echo -e "  ${D}  recorded:${NC} ${mins}m ago"
                fi
            else
                echo -e "  ${D}baseline:${NC} ${Y}not yet recorded${NC}"
            fi
            if [[ -f "$marker" ]]; then
                local last; last=$(cat "$marker" 2>/dev/null || echo 0)
                local now; now=$(date +%s); local mins=$(( (now - last) / 60 ))
                echo -e "  ${D}last check:${NC} ${mins}m ago"
            else
                echo -e "  ${D}last check:${NC} ${Y}never${NC}"
            fi
            echo -e "  ${D}watchlist (${#AUDIT_PERSISTENCE_PATHS[@]} patterns):${NC}"
            local p
            for p in "${AUDIT_PERSISTENCE_PATHS[@]}"; do
                printf "    %s\n" "$p"
            done
            ;;
        *)
            echo -e "${R}unknown persistence subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}

# ==============================================================================
# Listening-port baseline — snapshot every TCP/UDP listener at first run,
# diff each subsequent tick. NEW listener fires; gone listener is silent
# (services restart routinely; the brief gap shouldn't page anyone).
#
# Storage: $ALERT_STATE_DIR/audit/ports.baseline (TSV)
#   <proto>\t<bind>\t<port>\t<recorded>
#
# Capture: prefers `ss -tulnH` (iproute2). Falls back to `netstat -tunl`
# on hosts where ss isn't available — same fields, slower. PID/process
# columns intentionally NOT captured: `ss -p` requires CAP_NET_ADMIN /
# root and we never escalate ourselves; the bind+port tuple is enough
# to fire the alert and let the operator investigate with `lsof -i`.
# ==============================================================================

# Capture current listeners as TSV `<proto>\t<bind>\t<port>` rows.
# Output is sorted+deduped so set-diff against baseline is straight `comm`.
_audit_ports_capture() {
    if command -v ss >/dev/null 2>&1; then
        # `-H` (no header) is iproute2-recent; older versions ignore it
        # and emit a header row that the awk filter below drops anyway.
        ss -tulnH 2>/dev/null | awk '
            # Columns: Netid State Recv-Q Send-Q Local-Addr:Port Peer-Addr:Port ...
            # State col absent for UDP (where it would be UNCONN, not LISTEN);
            # so just key on Netid + Local-Addr column.
            NR==1 && $1 ~ /^Netid/ { next }
            {
                proto = $1
                addr  = $5
                # Split on the LAST colon — bind addr can be `[::]` or
                # `0.0.0.0` or `127.0.0.1`. Port is the trailing :NNNNN.
                n = length(addr)
                p = 0
                for (i = n; i > 0; i--) if (substr(addr, i, 1) == ":") { p = i; break }
                if (p == 0) next
                bind = substr(addr, 1, p - 1)
                port = substr(addr, p + 1)
                # Strip surrounding [] from IPv6 binds for readability.
                gsub(/^\[|\]$/, "", bind)
                printf "%s\t%s\t%s\n", proto, bind, port
            }
        ' | sort -u
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tunl 2>/dev/null | awk '
            $1 == "tcp" || $1 == "udp" || $1 == "tcp6" || $1 == "udp6" {
                proto = $1; sub(/6$/, "", proto)   # collapse tcp6→tcp
                addr  = $4
                n = length(addr); p = 0
                for (i = n; i > 0; i--) if (substr(addr, i, 1) == ":") { p = i; break }
                if (p == 0) next
                bind = substr(addr, 1, p - 1)
                port = substr(addr, p + 1)
                gsub(/^\[|\]$/, "", bind)
                printf "%s\t%s\t%s\n", proto, bind, port
            }
        ' | sort -u
    fi
    # Both missing → empty stdout. Caller treats that as "no listeners",
    # which is not great signal — but not our problem to fix; install a
    # tools layer.
}

_audit_ports_baseline() {
    local dir; dir=$(_audit_state_dir)
    local out="$dir/ports.baseline"
    local tmp; tmp=$(mktemp "$dir/ports.baseline.tmp.XXXXXX") || return 1
    local now; now=$(date +%s)
    local count=0

    local proto bind port
    while IFS=$'\t' read -r proto bind port; do
        [[ -z "$proto" ]] && continue
        printf '%s\t%s\t%s\t%s\n' "$proto" "$bind" "$port" "$now" >> "$tmp"
        (( count++ )) || true
    done < <(_audit_ports_capture)

    mv "$tmp" "$out"
    printf '%d %s\n' "$count" "$out"
}

# Diff current vs baseline. Stdout: `<change>\t<proto>\t<bind>\t<port>` per
# line. Changes: NEW (in current, not baseline), GONE (in baseline, not
# current). Only NEW fires alerts.
_audit_ports_diff() {
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/ports.baseline"
    [[ -f "$baseline" ]] || return 1

    local current; current=$(mktemp "$dir/ports.current.XXXXXX") || return 1
    local sorted_baseline; sorted_baseline=$(mktemp "$dir/ports.sortedb.XXXXXX") || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$current' '$sorted_baseline'" RETURN

    _audit_ports_capture > "$current"
    awk -F'\t' '{print $1 "\t" $2 "\t" $3}' "$baseline" | sort -u > "$sorted_baseline"

    comm -23 "$current" "$sorted_baseline" | awk -F'\t' '{print "NEW\t" $0}'
    comm -13 "$current" "$sorted_baseline" | awk -F'\t' '{print "GONE\t" $0}'
}

_audit_ports_tick() {
    [[ "${AUDIT_ENABLED:-0}" == "1" ]] || return 0
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/ports.baseline"
    local marker="$dir/ports.lastcheck"
    local now; now=$(date +%s)
    local last=0
    [[ -f "$marker" ]] && last=$(cat "$marker" 2>/dev/null || echo 0)
    [[ -z "$last" ]] && last=0
    if (( now - last < AUDIT_PORTS_INTERVAL )); then
        return 0
    fi

    if [[ ! -f "$baseline" ]]; then
        _audit_ports_baseline >/dev/null 2>&1
        printf '%s' "$now" > "$marker"
        return 0
    fi

    local change proto bind port key body
    while IFS=$'\t' read -r change proto bind port; do
        [[ "$change" == "NEW" ]] || continue
        [[ -z "$proto" || -z "$port" ]] && continue
        key="audit:ports:NEW:$proto:$port"
        if alert_should_fire "$key"; then
            body="\`\`\`new listener: $proto $bind:$port\`\`\`"
            alert_fire "Listener: new $proto $bind:$port" "$body" 15158332 "$key" &
        fi
    done < <(_audit_ports_diff)

    printf '%s' "$now" > "$marker"
}

_audit_ports_subcmd() {
    case "${1:-status}" in
        baseline)
            local count path
            read -r count path < <(_audit_ports_baseline)
            echo -e "${G}baseline${NC} written to ${C}$path${NC}"
            echo -e "  ${D}tracked: ${count:-0} listeners${NC}"
            ;;
        check)
            local dir; dir=$(_audit_state_dir)
            if [[ ! -f "$dir/ports.baseline" ]]; then
                echo -e "${Y}no baseline yet — run \`milog audit ports baseline\` first${NC}"
                return 1
            fi
            local out; out=$(_audit_ports_diff)
            if [[ -z "$out" ]]; then
                echo -e "${G}no drift${NC} — every listener matches baseline"
                return 0
            fi
            local new gone
            new=$(printf  '%s\n' "$out" | grep -c '^NEW'  || true)
            gone=$(printf '%s\n' "$out" | grep -c '^GONE' || true)
            if (( new > 0 )); then
                echo -e "${R}NEW listeners (alert-worthy):${NC}"
                printf '%s\n' "$out" | awk -F'\t' '$1=="NEW"  {printf "  \033[31m%-5s\033[0m  %-4s  %s:%s\n", $1, $2, $3, $4}'
            fi
            if (( gone > 0 )); then
                echo -e "${D}gone (housekeeping, no alert):${NC}"
                printf '%s\n' "$out" | awk -F'\t' '$1=="GONE" {printf "  \033[90m%-5s\033[0m  %-4s  %s:%s\n", $1, $2, $3, $4}'
            fi
            (( new > 0 )) && return 1 || return 0
            ;;
        status)
            local dir; dir=$(_audit_state_dir)
            local baseline="$dir/ports.baseline"
            local marker="$dir/ports.lastcheck"
            echo -e "${W}milog audit ports — status${NC}"
            echo -e "  ${D}AUDIT_ENABLED=${NC}${AUDIT_ENABLED:-0}   ${D}AUDIT_PORTS_INTERVAL=${NC}${AUDIT_PORTS_INTERVAL:-3600}s"
            local backend="none"
            command -v ss      >/dev/null 2>&1 && backend="ss"
            [[ "$backend" == "none" ]] && command -v netstat >/dev/null 2>&1 && backend="netstat"
            echo -e "  ${D}capture backend:${NC} ${backend}"
            if [[ -f "$baseline" ]]; then
                local age count
                age=$(stat -c '%Y' "$baseline" 2>/dev/null || stat -f '%m' "$baseline" 2>/dev/null || echo 0)
                count=$(wc -l < "$baseline" 2>/dev/null | tr -d ' ')
                echo -e "  ${D}baseline:${NC} $baseline"
                echo -e "  ${D}  listeners tracked:${NC} ${count:-0}"
                if [[ "$age" -gt 0 ]]; then
                    local now; now=$(date +%s); local mins=$(( (now - age) / 60 ))
                    echo -e "  ${D}  recorded:${NC} ${mins}m ago"
                fi
            else
                echo -e "  ${D}baseline:${NC} ${Y}not yet recorded${NC}"
            fi
            if [[ -f "$marker" ]]; then
                local last; last=$(cat "$marker" 2>/dev/null || echo 0)
                local now; now=$(date +%s); local mins=$(( (now - last) / 60 ))
                echo -e "  ${D}last check:${NC} ${mins}m ago"
            else
                echo -e "  ${D}last check:${NC} ${Y}never${NC}"
            fi
            ;;
        *)
            echo -e "${R}unknown ports subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}
