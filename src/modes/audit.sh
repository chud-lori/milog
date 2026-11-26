# milog audit: host integrity scanners (fim, persistence, ports, yara, accounts, rootkit).
# Drift is tracked as conditions: one alert when it opens or changes, one when it clears; silences apply.
# fim.baseline rows: path, sha256, mtime, size, recorded; sha256 MISSING means absent at baseline time.

# Hex digest, or empty when unreadable.
_audit_sha256() {
    local path="$1"
    [[ -r "$path" ]] || return 0
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$path" 2>/dev/null | awk '{print $1; exit}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$path" 2>/dev/null | awk '{print $1; exit}'
    fi
}

# Without a hash tool every path hashes to UNREADABLE and FIM never drifts.
_audit_have_sha256() {
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1
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

# Epoch mtime, empty when the path is missing.
_audit_mtime() {
    local st; st=$(_audit_stat "$1")
    printf '%s' "${st%%	*}"
}

_audit_state_dir() {
    local d="${ALERT_STATE_DIR:-$HOME/.cache/milog}/audit"
    mkdir -p "$d" 2>/dev/null
    printf '%s' "$d"
}

# Epoch -> "YYYY-MM-DD HH:MM (<age> ago)".
_audit_when() {
    local ts="$1" age d
    [[ "$ts" =~ ^[0-9]+$ ]] || return 0
    age=$(( $(date +%s) - ts )); (( age < 0 )) && age=0
    d=$(date -d "@$ts" '+%Y-%m-%d %H:%M' 2>/dev/null || date -r "$ts" '+%Y-%m-%d %H:%M' 2>/dev/null)
    printf '%s (%s ago)' "$d" "$(_alert_fmt_dur "$age")"
}

# mtime is settable with touch, ctime is not, so both are shown.
_audit_age_line() {
    local st m c o
    st=$(stat -c '%Y %Z %U' -- "$1" 2>/dev/null || stat -f '%m %c %Su' -- "$1" 2>/dev/null) || return 0
    read -r m c o <<< "$st"
    printf 'mtime %s, ctime %s, owner %s' "$(_audit_when "$m")" "$(_audit_when "$c")" "${o:-?}"
}

# Owner of the exact proto/bind/port listener; none visible or several sockets means unknown.
_audit_listener_owner() {
    local proto="$1" bind="$2" port="$3" m comm pid et
    [[ "$proto" =~ ^(tcp|udp)$ && "$port" =~ ^[0-9]+$ ]] || return 0
    command -v ss >/dev/null 2>&1 || { printf 'owner unknown, ss is not installed'; return 0; }
    m=$(ss -Htulnp "sport = :$port" 2>/dev/null | B="$bind" awk -v pr="$proto" -v po="$port" '
        $1 == pr {
            addr = $5; p = 0
            for (i = length(addr); i > 0; i--) if (substr(addr, i, 1) == ":") { p = i; break }
            if (p == 0) next
            b = substr(addr, 1, p - 1); gsub(/^\[|\]$/, "", b)
            if (b != ENVIRON["B"] || substr(addr, p + 1) != po) next
            if (match($0, /users:\(\("[^"]*",pid=[0-9]+/)) print substr($0, RSTART, RLENGTH); else print "?"
        }' | sort -u || true)
    if [[ -z "$m" || "$m" == *$'\n'* || "$m" == "?" ]]; then
        printf "owner unknown (ss -p shows other users' sockets only to root)"
        return 0
    fi
    pid="${m##*pid=}"
    comm="${m#users:((\"}"; comm="${comm%%\",pid=*}"
    comm=$(printf '%s' "$comm" | LC_ALL=C tr -cd '\40-\176' | tr -d '`' | cut -c1-32)
    et=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
    if [[ "$et" =~ ^[0-9]+$ ]]; then
        printf 'process %s pid %s, started %s' "$comm" "$pid" "$(_audit_when $(( $(date +%s) - et )))"
    else
        printf 'process %s pid %s' "$comm" "$pid"
    fi
}

# Only world-readable files and authorized_keys are copied, so a copy never holds what other users cannot read.
_audit_fim_copyable() {
    local mode
    [[ -f "$1" && ! -L "$1" ]] || return 1
    [[ "${1##*/}" == authorized_keys* ]] && return 0
    mode=$(stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]+$ ]] && (( 8#$mode & 4 ))
}

# Refuses a symlinked or foreign-owned dir so copies and prunes cannot be redirected.
_audit_fim_snap_dir() {
    local d; d=$(_audit_state_dir)/fim.snap
    [[ -L "$d" ]] && return 1
    ( umask 077; mkdir -p "$d" ) 2>/dev/null
    [[ -d "$d" && ! -L "$d" && -O "$d" ]] || return 1
    printf '%s' "$d"
}

# Copies a copyable text file of at most 256 KiB to $2 without following symlinks or blocking on FIFOs.
_audit_fim_read_capped() {
    local src="$1" dst="$2" max=262144 size text
    _audit_fim_copyable "$src" || return 1
    if ! ( umask 077; dd if="$src" of="$dst" iflag=nofollow,nonblock,fullblock bs=$(( max + 1 )) count=1 status=none ) 2>/dev/null; then
        rm -f "$dst"; return 1
    fi
    size=$(wc -c < "$dst" | tr -d ' ')
    text=$(tr -d '\000' < "$dst" | wc -c | tr -d ' ')
    if (( size > max || text != size )); then
        rm -f "$dst"; return 1
    fi
}

# Keeps a private copy of a watched file so later drift can be summarised; stale copies are dropped.
_audit_fim_snap_write() {
    local path="$1" snapdir snap tmp
    snapdir=$(_audit_fim_snap_dir) || return 0
    snap="$snapdir/$(_audit_accounts_sanitise "$path")"
    tmp=$(mktemp "$snap.tmp.XXXXXX") || return 0
    if _audit_fim_read_capped "$path" "$tmp"; then
        mv -f "$tmp" "$snap"
    else
        rm -f "$tmp" "$snap"
    fi
}

# Bounded summary of a FIM change: line counts, and key fingerprints for authorized_keys. Never file contents.
_audit_fim_detail() {
    local change="$1" path="$2"
    local dir; dir=$(_audit_state_dir)
    local row old_sha old_size new_size st snapdir snap old cur added removed out=""
    case "$change" in MODIFIED|APPEARED) ;; *) return 0 ;; esac
    row=$(P="$path" awk -F'\t' '$1 == ENVIRON["P"] { print $2 "\t" $4; exit }' "$dir/fim.baseline" 2>/dev/null)
    old_sha="${row%%$'\t'*}"; old_size="${row#*$'\t'}"
    [[ "$old_sha" == MISSING || "$old_sha" == UNREADABLE ]] && old_size=0
    st=$(_audit_stat "$path"); new_size="${st##*	}"
    out="size ${old_size:-0} -> ${new_size:-0} bytes"
    if [[ -e "$path" ]] && ! _audit_fim_copyable "$path"; then
        printf '%s, contents withheld\n' "$out"
        return 0
    fi
    snap=""
    snapdir=$(_audit_fim_snap_dir) && snap="$snapdir/$(_audit_accounts_sanitise "$path")"
    old=$(mktemp "$dir/fim.old.XXXXXX") || return 0
    cur=$(mktemp "$dir/fim.cur.XXXXXX") || { rm -f "$old"; return 0; }
    if [[ "$old_sha" == MISSING || "$old_sha" == UNREADABLE ]] \
        || { [[ -n "$snap" && -f "$snap" ]] && [[ "$(_audit_sha256 "$snap")" == "$old_sha" ]] && cat "$snap" > "$old"; }; then
        if _audit_fim_read_capped "$path" "$cur"; then
            added=$(comm -13 <(sort "$old") <(sort "$cur") | grep -c . || true)
            removed=$(comm -23 <(sort "$old") <(sort "$cur") | grep -c . || true)
            out="+${added} -${removed} lines, $out"
            if [[ "${path##*/}" == authorized_keys* ]] && command -v ssh-keygen >/dev/null 2>&1; then
                out+=$'\n'$(
                    { comm -13 <(ssh-keygen -lf "$old" 2>/dev/null | sort -u) <(ssh-keygen -lf "$cur" 2>/dev/null | sort -u) | sed 's/^/+ key /'
                      comm -23 <(ssh-keygen -lf "$old" 2>/dev/null | sort -u) <(ssh-keygen -lf "$cur" 2>/dev/null | sort -u) | sed 's/^/- key /'
                    } | LC_ALL=C tr -cd '\n\40-\176' | LC_ALL=C awk '{ gsub(/`/, ""); s = substr($0, 1, 1); n[s]++; if (n[s] <= 5) print substr($0, 1, 160) }
                        END { if (n["+"] > 5) print "+ " n["+"] - 5 " more keys"; if (n["-"] > 5) print "- " n["-"] - 5 " more keys" }'
                )
            fi
        fi
    fi
    rm -f "$old" "$cur"
    printf '%s\n' "${out:0:2000}"
}

# Watchlist globs expanded to a sorted, deduped path list.
_audit_fim_expand_paths() {
    local pat path
    local -a out=()
    # Empty IFS keeps a path with spaces whole while still expanding its glob.
    local IFS=
    shopt -s nullglob
    for pat in "${AUDIT_FIM_PATHS[@]}"; do
        local -a matches=( $pat )
        if (( ${#matches[@]} > 0 )); then
            for path in "${matches[@]}"; do
                out+=("$path")
            done
        else
            # nullglob only drops patterns with glob chars, so this branch is unmatched globs; literal paths never reach it.
            out+=("$pat")
        fi
    done
    shopt -u nullglob
    (( ${#out[@]} == 0 )) || printf '%s\n' "${out[@]}" | sort -u
}

# Overwrites the baseline without alerting.
_audit_fim_baseline() {
    if ! _audit_have_sha256; then
        echo "milog: no sha256sum or shasum on PATH — refusing to write a FIM baseline" >&2
        return 1
    fi
    local dir; dir=$(_audit_state_dir)
    local out="$dir/fim.baseline"
    local tmp; tmp=$(mktemp "$dir/fim.baseline.tmp.XXXXXX") || return 1
    local now; now=$(date +%s)
    local path sha mtime size st f snapdir kept="/"
    local count=0 missing=0
    snapdir=$(_audit_fim_snap_dir) || snapdir=""

    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        if [[ -e "$path" ]]; then
            sha=$(_audit_sha256 "$path")
            st=$(_audit_stat "$path")
            mtime="${st%%	*}"
            size="${st##*	}"
            [[ -z "$sha" ]] && sha="UNREADABLE"
            (( count++ )) || true
            _audit_fim_snap_write "$path"
            kept+="$(_audit_accounts_sanitise "$path")/"
        else
            sha="MISSING"; mtime=0; size=0
            (( missing++ )) || true
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "$path" "$sha" "$mtime" "$size" "$now" >> "$tmp"
    done < <(_audit_fim_expand_paths)

    mv "$tmp" "$out"
    alert_condition_close audit:fim:
    if [[ -n "$snapdir" ]]; then
        for f in "$snapdir"/*; do
            [[ -f "$f" && ! -L "$f" && -O "$f" && "$kept" != */"${f##*/}"/* ]] && rm -f "$f"
        done
    fi
    # One "<present> <missing> <path>" line so callers can `read` it; globals don't survive $(...).
    printf '%d %d %s\n' "$count" "$missing" "$out"
}

# One `<change>\t<path>\t<old>→<new>` line per drifted path: MODIFIED, APPEARED, REMOVED or UNREADABLE.
_audit_fim_diff() {
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/fim.baseline"
    [[ -f "$baseline" ]] || return 1
    _audit_have_sha256 || return 1

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
                # Readable for the first time since baseline, so report it like a new file.
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

# Daemon check, at most once per AUDIT_FIM_INTERVAL; the first run baselines silently.
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

    if ! _audit_have_sha256; then
        echo "milog: FIM skipped — no sha256sum or shasum on PATH" >&2
        printf '%s' "$now" > "$marker"
        return 0
    fi

    if [[ ! -f "$baseline" ]]; then
        _audit_fim_baseline >/dev/null 2>&1
        printf '%s' "$now" > "$marker"
        return 0
    fi

    local change path detail key body rows="" out ok=1
    # A failed diff must not read as every condition clearing.
    out=$(_audit_fim_diff) || ok=0
    while IFS=$'\t' read -r change path detail; do
        [[ -z "$change" ]] && continue
        rows+="$change"$'\t'"$path"$'\n'
        key="audit:fim:$change:$path"
        body="\`\`\`$change $path $detail"$'\n'"$(_audit_fim_detail "$change" "$path")\`\`\`"
        alert_condition_open "$key" "FIM drift: $change $path" "$body" 15158332 "$detail"
    done <<< "$out"
    (( ok )) && alert_condition_sweep audit:fim: "$now"
    history_write_audit fim "$(_audit_mtime "$baseline")" "$rows"

    printf '%s' "$now" > "$marker"
}

mode_audit() {
    case "${1:-}" in
        ""|help|--help|-h) _audit_help ;;
        fim) shift; _audit_fim_subcmd "$@" ;;
        persistence) shift; _audit_persistence_subcmd "$@" ;;
        ports) shift; _audit_ports_subcmd "$@" ;;
        yara) shift; _audit_yara_subcmd "$@" ;;
        accounts) shift; _audit_accounts_subcmd "$@" ;;
        rootkit) shift; _audit_rootkit_subcmd "$@" ;;
        history) shift; _audit_history_subcmd "$@" ;;
        accept) shift; _audit_accept_subcmd "$@" ;;
        *)
            echo -e "${R}unknown audit subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}

_audit_help() {
    # printf '%b' renders the \033 escapes in $W/$C/$NC; a heredoc would print them literally.
    printf '%b' "
${W}milog audit${NC} — point-in-time host integrity scans

  ${C}milog audit fim ${NC}<sub>          file integrity (SHA256 drift on watched files)
  ${C}milog audit persistence ${NC}<sub>  re-entry surface diff (new cron / systemd units / rc.local)
  ${C}milog audit ports ${NC}<sub>        listening-port baseline (new TCP/UDP listeners)
  ${C}milog audit yara ${NC}<sub>         YARA scan over webroot (webshell + obfuscation rules)
  ${C}milog audit accounts ${NC}<sub>     line-level diff over passwd / sudoers / authorized_keys
  ${C}milog audit rootkit ${NC}<sub>      hidden-process / ld.so.preload / tmp-exec heuristics
  ${C}milog audit history ${NC}[days]     drift the daemon recorded (default 7; needs HISTORY_ENABLED=1)
  ${C}milog audit accept ${NC}[check item] accept one drifted item into its baseline; no args lists drift

  Subs (fim/persistence/ports/accounts): ${C}baseline${NC} | ${C}check${NC} | ${C}status${NC}
  Subs (yara):                           ${C}init${NC} | ${C}scan${NC} | ${C}status${NC}
  Subs (rootkit):                        ${C}check${NC} | ${C}status${NC}

The watcher runs inside ${C}milog daemon${NC} when ${C}AUDIT_ENABLED=1${NC} —
auto-baselines on first run, then fires ${C}audit:fim:<change>:<path>${NC},
${C}audit:persistence:APPEARED:<path>${NC}, ${C}audit:ports:NEW:<proto>:<bind>:<port>${NC},
${C}audit:yara:<rule>:<path>${NC}, ${C}audit:accounts:NEW:<path>${NC}, or
${C}audit:rootkit:<heuristic>${NC} on every subsequent drift.

Watchlists: ${C}AUDIT_FIM_PATHS${NC} / ${C}AUDIT_PERSISTENCE_PATHS${NC} / ${C}AUDIT_ACCOUNTS_PATHS${NC}. Glob OK.
Listening-port scan reads from ${C}ss${NC} (or ${C}netstat${NC} fallback).
YARA scan needs the system ${C}yara${NC} binary + ${C}AUDIT_YARA_PATHS${NC} configured.
Rootkit scan is Linux-only (relies on /proc); silent no-op on macOS / BSD.
"
}

_audit_fim_subcmd() {
    case "${1:-status}" in
        baseline)
            local present missing path out
            out=$(_audit_fim_baseline) || return 1
            read -r present missing path <<< "$out"
            echo -e "${G}baseline${NC} written to ${C}$path${NC}"
            echo -e "  ${D}tracked: ${present:-0} present, ${missing:-0} missing${NC}"
            ;;
        check)
            local dir; dir=$(_audit_state_dir)
            if [[ ! -f "$dir/fim.baseline" ]]; then
                echo -e "${Y}no baseline yet — run \`milog audit fim baseline\` first${NC}"
                return 1
            fi
            if ! _audit_have_sha256; then
                echo -e "${R}no sha256sum or shasum on PATH — FIM cannot hash anything${NC}" >&2
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

# Persistence: file-existence diff over cron, systemd and rc paths. Only APPEARED alerts; removals are housekeeping.
# persistence.baseline rows: path, size, mtime, recorded.

_audit_persistence_expand() {
    local pat path
    local -a out=()
    # Empty IFS keeps a path with spaces whole while still expanding its glob.
    local IFS=
    shopt -s nullglob
    for pat in "${AUDIT_PERSISTENCE_PATHS[@]}"; do
        local -a matches=( $pat )
        # nullglob keeps glob-free words, so an absent /etc/rc.local would count as present.
        if (( ${#matches[@]} == 1 )) && [[ "${matches[0]}" == "$pat" && ! -e "$pat" ]]; then
            continue
        fi
        if (( ${#matches[@]} > 0 )); then
            for path in "${matches[@]}"; do
                # Only files; a directory match would never change.
                [[ -d "$path" ]] && continue
                out+=("$path")
            done
        fi
        # Unmatched globs add nothing, but nullglob leaves literal paths in place even when they don't exist.
    done
    shopt -u nullglob
    (( ${#out[@]} == 0 )) || printf '%s\n' "${out[@]}" | sort -u
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
    alert_condition_close audit:persistence:
    printf '%d %s\n' "$count" "$out"
}

# `<change>\t<path>` lines, APPEARED or REMOVED.
_audit_persistence_diff() {
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/persistence.baseline"
    [[ -f "$baseline" ]] || return 1

    local current; current=$(mktemp "$dir/persistence.current.XXXXXX") || return 1
    local sorted_baseline; sorted_baseline=$(mktemp "$dir/persistence.sortedb.XXXXXX") || return 1
    # Never end on an external command: in $(...)/<(...) bash execs it and skips RETURN.
    # shellcheck disable=SC2064
    trap "rm -f '$current' '$sorted_baseline'" RETURN
    _audit_persistence_expand > "$current"

    # comm needs sorted input.
    awk -F'\t' '{print $1}' "$baseline" | sort -u > "$sorted_baseline"

    # APPEARED: in current, not in baseline.
    comm -23 "$current" "$sorted_baseline" | awk '{print "APPEARED\t" $0}'
    # REMOVED: in baseline, not in current.
    comm -13 "$current" "$sorted_baseline" | awk '{print "REMOVED\t" $0}'
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

    local change path key body rows="" out ok=1
    out=$(_audit_persistence_diff) || ok=0
    while IFS=$'\t' read -r change path; do
        [[ -z "$change" ]] && continue
        rows+="$change"$'\t'"$path"$'\n'
        [[ "$change" == "APPEARED" ]] || continue
        [[ -z "$path" ]] && continue
        # milog's own units appear after install, so they are not re-entry.
        case "$path" in
            /etc/systemd/system/milog.service|/etc/systemd/system/milog-probe.service) continue ;;
        esac
        key="audit:persistence:APPEARED:$path"
        body="\`\`\`new file in re-entry surface: $path"$'\n'"$(_audit_age_line "$path")\`\`\`"
        alert_condition_open "$key" "Persistence: new $path" "$body" 15158332
    done <<< "$out"
    (( ok )) && alert_condition_sweep audit:persistence: "$now"
    history_write_audit persistence "$(_audit_mtime "$baseline")" "$rows"

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

# Ports: new TCP/UDP listeners alert, vanished ones don't. ports.baseline rows: proto, bind, port, recorded.
# PIDs aren't captured because `ss -p` needs root.

# Sorted `<proto>\t<bind>\t<port>` rows, ready for comm.
_audit_ports_capture() {
    if command -v ss >/dev/null 2>&1; then
        # Older iproute2 ignores -H and prints a header, which the awk skips.
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
    # With neither ss nor netstat the output is empty.
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
    alert_condition_close audit:ports:
    printf '%d %s\n' "$count" "$out"
}

# `<change>\t<proto>\t<bind>\t<port>` lines, NEW or GONE.
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
    # No listeners at all means ss/netstat failed, not that every port closed.
    [[ -s "$current" || ! -s "$sorted_baseline" ]] || return 1

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

    local change proto bind port key body rows="" out ok=1
    out=$(_audit_ports_diff) || ok=0
    while IFS=$'\t' read -r change proto bind port; do
        case "$change" in
            NEW)  rows+="appeared"$'\t'"$bind:$port/$proto"$'\n' ;;
            GONE) rows+="removed"$'\t'"$bind:$port/$proto"$'\n' ;;
        esac
        [[ "$change" == "NEW" ]] || continue
        [[ -z "$proto" || -z "$port" ]] && continue
        key="audit:ports:NEW:$proto:$bind:$port"
        body="\`\`\`new listener: $proto $bind:$port"$'\n'"$(_audit_listener_owner "$proto" "$bind" "$port")\`\`\`"
        alert_condition_open "$key" "Listener: new $proto $bind:$port" "$body" 15158332
    done <<< "$out"
    (( ok )) && alert_condition_sweep audit:ports: "$now"
    history_write_audit ports "$(_audit_mtime "$baseline")" "$rows"

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

# YARA over AUDIT_YARA_PATHS via the system yara binary; idle until the binary exists and a path is set.
# yara.matches records rule, file, sha256, first_seen, so only new (rule, file, sha) combinations alert.

# Starter rules, written once by `milog audit yara init` and never overwritten.
_audit_yara_default_rules() {
    cat <<'YARA_RULES'
/*
 * milog default YARA ruleset — high-signal webshell + obfuscation
 * detectors. Conservative on purpose: any of these matching a file in
 * the webroot is worth investigating. Drop additional .yar files in
 * this directory to extend; this file is only written on `milog audit
 * yara init` and is not overwritten on subsequent runs.
 */

rule milog_php_eval_obfuscation
{
    meta:
        author      = "milog"
        description = "PHP eval() over an obfuscation primitive — classic dropper signature"
    strings:
        $a1 = /eval\s*\(\s*base64_decode\s*\(/   nocase
        $a2 = /eval\s*\(\s*gzinflate\s*\(/       nocase
        $a3 = /eval\s*\(\s*gzuncompress\s*\(/    nocase
        $a4 = /eval\s*\(\s*str_rot13\s*\(/       nocase
        $a5 = /assert\s*\(\s*base64_decode\s*\(/ nocase
    condition:
        any of them
}

rule milog_php_request_eval
{
    meta:
        author      = "milog"
        description = "Direct eval/assert of $_REQUEST/$_GET/$_POST/$_COOKIE — RCE primitive"
    strings:
        $a1 = /eval\s*\(\s*\$_(REQUEST|GET|POST|COOKIE)/   nocase
        $a2 = /assert\s*\(\s*\$_(REQUEST|GET|POST|COOKIE)/ nocase
        $a3 = /system\s*\(\s*\$_(REQUEST|GET|POST|COOKIE)/ nocase
        $a4 = /passthru\s*\(\s*\$_(REQUEST|GET|POST|COOKIE)/ nocase
        $a5 = /exec\s*\(\s*\$_(REQUEST|GET|POST|COOKIE)/   nocase
    condition:
        any of them
}

rule milog_webshell_families
{
    meta:
        author      = "milog"
        description = "WSO / c99 / r57 webshell family fingerprints"
    strings:
        $wso1 = "WSO " ascii
        $wso2 = "wso_" ascii
        $wso3 = "wsoEx" ascii
        $c99a = "c99shell" nocase
        $c99b = "Captain Crunch Security" nocase
        $r57a = "r57shell" nocase
        $r57b = "r57.gen.tr" nocase
    condition:
        2 of ($wso*) or 2 of ($c99*) or any of ($r57*)
}
YARA_RULES
}

_audit_yara_init_rules() {
    local dir="${AUDIT_YARA_RULES_DIR:-$HOME/.config/milog/yara}"
    mkdir -p "$dir" 2>/dev/null || return 1
    local default="$dir/milog-default.yar"
    if [[ ! -f "$default" ]]; then
        _audit_yara_default_rules > "$default" || return 1
    fi
    return 0
}

# The marker keeps the missing-binary warning to once.
_audit_yara_have_binary() {
    if command -v yara >/dev/null 2>&1; then
        return 0
    fi
    local dir; dir=$(_audit_state_dir)
    local marker="$dir/yara.no_binary_warned"
    if [[ ! -f "$marker" ]]; then
        echo "milog: yara binary not found on PATH — \`milog audit yara\` will no-op until \`apt install yara\` (or equivalent)" >&2
        : > "$marker" 2>/dev/null || true
    fi
    return 1
}

# `<rule>\t<file>` per match.
_audit_yara_scan_path() {
    local target="$1"
    local rules_dir="${AUDIT_YARA_RULES_DIR:-$HOME/.config/milog/yara}"
    [[ -d "$target" || -f "$target" ]] || return 0
    [[ -d "$rules_dir" ]] || return 0

    # One yara run per rule file so a broken file doesn't abort the scan.
    local yar
    for yar in "$rules_dir"/*.yar; do
        [[ -f "$yar" ]] || continue
        # yara exits 1 on match. No `--`: yara 4.x treats it as a filename.
        yara -r -w "$yar" "$target" 2>/dev/null | awk '{
            # Split on the first space only; the path keeps its exact bytes.
            i = index($0, " ")
            if (i == 0) next
            printf "%s\t%s\n", substr($0, 1, i - 1), substr($0, i + 1)
        }'
    done
}

# Run the full scan over every configured path, dedup against the
# matches log. Stdout: one NEW match per line, `<rule>\t<file>\t<sha256>`.
# Already-recorded (rule, file, sha) tuples are filtered out.
#
# Dedup uses awk against the matches log rather than an in-memory set.
# Reasons: (a) typical webroot finds ≤ a handful of hits per scan, so
# fork-per-match is cheap; (b) sidesteps bash-3.2's empty-array
# `unbound variable` trap under `set -u`; (c) one less in-memory data
# structure to keep coherent with the on-disk log.
_audit_yara_scan_all() {
    local dir; dir=$(_audit_state_dir)
    local matches_log="$dir/yara.matches"
    [[ -f "$matches_log" ]] || : > "$matches_log"

    local p rule file sha line esc
    for p in "${AUDIT_YARA_PATHS[@]}"; do
        [[ -e "$p" ]] || continue
        while IFS= read -r line; do
            # The path is everything after the first tab — it may hold tabs itself.
            [[ "$line" == *$'\t'* ]] || continue
            rule="${line%%$'\t'*}"
            file="${line#*$'\t'}"
            [[ -z "$rule" || -z "$file" ]] && continue
            sha=$(_audit_sha256 "$file")
            [[ -z "$sha" ]] && sha="UNREADABLE"
            # Escaped so every log row keeps exactly four tab-separated fields.
            esc="${file//\\/\\\\}"
            esc="${esc//$'\t'/\\t}"
            # ENVIRON, not -v: awk -v would unescape the backslashes.
            if ! R="$rule" F="$esc" S="$sha" awk -F'\t' '
                    $1 == ENVIRON["R"] && $2 == ENVIRON["F"] && $3 == ENVIRON["S"] { found = 1; exit }
                    END { exit !found }' "$matches_log"; then
                printf '%s\t%s\t%s\n' "$rule" "$file" "$sha"
                # Record immediately so a same-tick duplicate path (e.g.
                # the same file matched by two rules) doesn't double-fire.
                _audit_yara_record_match "$rule" "$esc" "$sha"
            fi
        done < <(_audit_yara_scan_path "$p")
    done
}

_audit_yara_record_match() {
    local rule="$1" file="$2" sha="$3"
    local dir; dir=$(_audit_state_dir)
    local matches_log="$dir/yara.matches"
    local now; now=$(date +%s)
    printf '%s\t%s\t%s\t%s\n' "$rule" "$file" "$sha" "$now" >> "$matches_log"
}

_audit_yara_tick() {
    [[ "${AUDIT_ENABLED:-0}" == "1" ]] || return 0
    (( ${#AUDIT_YARA_PATHS[@]} > 0 )) || return 0
    _audit_yara_have_binary || return 0

    local dir; dir=$(_audit_state_dir)
    local marker="$dir/yara.lastcheck"
    local now; now=$(date +%s)
    local last=0
    [[ -f "$marker" ]] && last=$(cat "$marker" 2>/dev/null || echo 0)
    [[ -z "$last" ]] && last=0
    if (( now - last < AUDIT_YARA_INTERVAL )); then
        return 0
    fi

    if ! _audit_yara_init_rules; then
        echo "milog: failed to init yara rules dir at ${AUDIT_YARA_RULES_DIR:-$HOME/.config/milog/yara}" >&2
        printf '%s' "$now" > "$marker"
        return 0
    fi

    # _audit_yara_scan_all records matches inline — we just fire alerts
    # for what comes through (which is already deduped against the log).
    local rule file sha key body line rows=""
    while IFS= read -r line; do
        rule="${line%%$'\t'*}"; sha="${line##*$'\t'}"
        file="${line#*$'\t'}"; file="${file%$'\t'*}"
        [[ -z "$rule" ]] && continue
        rows+="match"$'\t'"$rule $file"$'\n'
        key="audit:yara:$rule:$file"
        if alert_should_fire "$key"; then
            body="\`\`\`yara hit: rule=$rule path=$file sha=${sha:0:16}\`\`\`"
            alert_fire "YARA: $rule on $file" "$body" 15158332 "$key" &
        fi
    done < <(_audit_yara_scan_all)
    # scan_all only emits matches it has not seen before, so dedup only within this tick.
    history_write_audit yara "$now" "$rows"

    printf '%s' "$now" > "$marker"
}

_audit_yara_subcmd() {
    case "${1:-status}" in
        init)
            local dir="${AUDIT_YARA_RULES_DIR:-$HOME/.config/milog/yara}"
            if _audit_yara_init_rules; then
                echo -e "${G}rules dir ready${NC} at ${C}$dir${NC}"
                local n
                n=$(find "$dir" -maxdepth 1 -name '*.yar' 2>/dev/null | wc -l | tr -d ' ')
                echo -e "  ${D}rule files: ${n:-0}${NC}"
                echo -e "  ${D}default rules written to milog-default.yar (your edits NOT overwritten)${NC}"
            else
                echo -e "${R}failed to create $dir${NC}" >&2
                return 1
            fi
            ;;
        scan)
            if ! _audit_yara_have_binary; then
                echo -e "${R}yara binary not found on PATH${NC}" >&2
                echo -e "  Install via: ${C}apt install yara${NC} (Debian/Ubuntu) / ${C}dnf install yara${NC} (Fedora)"
                return 1
            fi
            (( ${#AUDIT_YARA_PATHS[@]} > 0 )) || {
                echo -e "${Y}AUDIT_YARA_PATHS is empty — configure webroot(s) in milog.conf${NC}" >&2
                echo -e "  Example: ${C}AUDIT_YARA_PATHS=(/var/www /usr/share/nginx/html)${NC}"
                return 1
            }
            _audit_yara_init_rules || {
                echo -e "${R}failed to init rules dir${NC}" >&2
                return 1
            }
            local out; out=$(_audit_yara_scan_all)
            if [[ -z "$out" ]]; then
                echo -e "${G}no new matches${NC} across ${#AUDIT_YARA_PATHS[@]} path(s)"
                return 0
            fi
            echo -e "${R}new YARA matches:${NC}"
            local rule file sha line
            while IFS= read -r line; do
                rule="${line%%$'\t'*}"; sha="${line##*$'\t'}"
                file="${line#*$'\t'}"; file="${file%$'\t'*}"
                printf "  \033[31m%-30s\033[0m  %s  \033[90m%s\033[0m\n" \
                    "$rule" "$file" "${sha:0:16}"
            done <<< "$out"
            return 1
            ;;
        status)
            local dir; dir=$(_audit_state_dir)
            local marker="$dir/yara.lastcheck"
            local matches_log="$dir/yara.matches"
            local rules_dir="${AUDIT_YARA_RULES_DIR:-$HOME/.config/milog/yara}"
            echo -e "${W}milog audit yara — status${NC}"
            echo -e "  ${D}AUDIT_ENABLED=${NC}${AUDIT_ENABLED:-0}   ${D}AUDIT_YARA_INTERVAL=${NC}${AUDIT_YARA_INTERVAL:-86400}s"
            local bin_state="missing"
            command -v yara >/dev/null 2>&1 && bin_state="present ($(yara --version 2>/dev/null))"
            echo -e "  ${D}yara binary:${NC} ${bin_state}"
            echo -e "  ${D}rules dir:${NC} $rules_dir"
            if [[ -d "$rules_dir" ]]; then
                local n
                n=$(find "$rules_dir" -maxdepth 1 -name '*.yar' 2>/dev/null | wc -l | tr -d ' ')
                echo -e "  ${D}  rule files:${NC} ${n:-0}"
            else
                echo -e "  ${D}  rule files:${NC} ${Y}not initialised — run \`milog audit yara init\`${NC}"
            fi
            if (( ${#AUDIT_YARA_PATHS[@]} > 0 )); then
                echo -e "  ${D}scan paths (${#AUDIT_YARA_PATHS[@]}):${NC}"
                local p
                for p in "${AUDIT_YARA_PATHS[@]}"; do
                    if [[ -e "$p" ]]; then
                        printf "    %s\n" "$p"
                    else
                        printf "    %s   ${Y}(missing)${NC}\n" "$p"
                    fi
                done
            else
                echo -e "  ${D}scan paths:${NC} ${Y}none configured (set AUDIT_YARA_PATHS)${NC}"
            fi
            if [[ -f "$marker" ]]; then
                local last; last=$(cat "$marker" 2>/dev/null || echo 0)
                local now; now=$(date +%s); local hrs=$(( (now - last) / 3600 ))
                echo -e "  ${D}last scan:${NC} ${hrs}h ago"
            else
                echo -e "  ${D}last scan:${NC} ${Y}never${NC}"
            fi
            if [[ -f "$matches_log" ]]; then
                local match_count
                match_count=$(wc -l < "$matches_log" 2>/dev/null | tr -d ' ')
                echo -e "  ${D}recorded matches (lifetime):${NC} ${match_count:-0}"
            fi
            ;;
        *)
            echo -e "${R}unknown yara subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}

# ==============================================================================
# Account / SSH-key audit — line-level diff over the files where new
# privileges materialise. Stronger than FIM here: FIM tells you "passwd
# changed", this tells you "user `eve` was added with UID 0 and shell
# /bin/bash". Same machinery as persistence-diff but per-file.
#
# Storage: $ALERT_STATE_DIR/audit/accounts/<sanitised-path> — full file
# content captured at baseline time. comm against current state to find
# ADDED / REMOVED lines. Sanitisation: `%`/`_` percent-encoded, `/` → `_`,
# leading slash stripped (so `/etc/passwd` becomes `etc_passwd`).
#
# Drift policy:
#   ADDED   fires alert. Each baseline-vs-current run reports up to 5
#           new lines in the body (capped to fit Discord's 4000-char
#           limit even with many keys at once).
#   REMOVED informational on `check` output but does NOT alert. Admins
#           routinely revoke old SSH keys and clean up sudoers entries.
# ==============================================================================

_audit_accounts_state_dir() {
    local d; d=$(_audit_state_dir)/accounts
    mkdir -p "$d" 2>/dev/null
    printf '%s' "$d"
}

_audit_accounts_sanitise() {
    # `/etc/sudoers.d/foo` → `etc_sudoers.d_foo`. Leading slash stripped
    # so we don't end up with a hidden `_etc_...` file the operator can't
    # see in `ls`. `%` and `_` are percent-encoded so `/a_b` and `/a/b` differ.
    local p="$1"
    p="${p#/}"
    p="${p//%/%25}"
    p="${p//_/%5F}"
    printf '%s' "${p//\//_}"
}

# Pre-encoding name, read only until the first baseline that writes `.encoded`.
_audit_accounts_legacy_name() {
    local p="${1#/}"
    printf '%s' "${p//\//_}"
}

_audit_accounts_expand() {
    local pat path
    local -a out=()
    # Empty IFS keeps a path with spaces whole while still expanding its glob.
    local IFS=
    shopt -s nullglob
    for pat in "${AUDIT_ACCOUNTS_PATHS[@]}"; do
        local -a matches=( $pat )
        if (( ${#matches[@]} > 0 )); then
            for path in "${matches[@]}"; do
                [[ -f "$path" ]] || continue   # files only
                out+=("$path")
            done
        fi
    done
    shopt -u nullglob
    (( ${#out[@]} == 0 )) || printf '%s\n' "${out[@]}" | sort -u
}

# Prints `<count> <dir>`.
_audit_accounts_baseline() {
    local dir; dir=$(_audit_accounts_state_dir)
    local count=0 path safe tmp f kept="/"
    # Renamed into place so a concurrent diff never sees a missing or partial baseline.
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        safe=$(_audit_accounts_sanitise "$path")
        tmp=$(mktemp "$dir/.baseline.tmp.XXXXXX") || return 1
        # `cp -f` would dereference symlinks; we want the actual content
        # at this instant, which `cat >` accomplishes with no metadata.
        if cat "$path" 2>/dev/null > "$tmp" && mv -f "$tmp" "$dir/$safe.baseline"; then
            kept="$kept$safe.baseline/"
            (( count++ )) || true
        else
            rm -f "$tmp"
        fi
    done < <(_audit_accounts_expand)
    : > "$dir/.encoded"
    alert_condition_close audit:accounts:
    # Pruned last so paths dropped from AUDIT_ACCOUNTS_PATHS stop showing up.
    for f in "$dir"/*.baseline; do
        [[ -e "$f" && "$kept" != */"${f##*/}"/* ]] && rm -f "$f"
    done
    printf '%d %s\n' "$count" "$dir"
}

# `<change>\t<file>\t<line>`, ADDED or REMOVED; a file with no baseline reports every line as ADDED.
_audit_accounts_diff() {
    local dir; dir=$(_audit_accounts_state_dir)
    local path safe baseline
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        safe=$(_audit_accounts_sanitise "$path")
        baseline="$dir/$safe.baseline"
        if [[ ! -f "$baseline" && ! -f "$dir/.encoded" ]]; then
            baseline="$dir/$(_audit_accounts_legacy_name "$path").baseline"
        fi
        if [[ ! -f "$baseline" ]]; then
            awk -v p="$path" 'NF { printf "ADDED\t%s\t%s\n", p, $0 }' "$path" 2>/dev/null
            continue
        fi
        comm -23 <(sort -u "$path" 2>/dev/null) <(sort -u "$baseline") \
            | awk -v p="$path" 'NF { printf "ADDED\t%s\t%s\n", p, $0 }'
        comm -13 <(sort -u "$path" 2>/dev/null) <(sort -u "$baseline") \
            | awk -v p="$path" 'NF { printf "REMOVED\t%s\t%s\n", p, $0 }'
    done < <(_audit_accounts_expand)
}

# A tracked file that exists and is readable but has no baseline makes the diff replay its whole
# content as new — happens on a cache wipe or when a path is added to the watchlist after bootstrap.
# Adopt the current content as the baseline for just those files. Unreadable files (e.g. /etc/sudoers
# under a non-root daemon) are skipped: they get no baseline and the diff already emits nothing.
_audit_accounts_heal_missing() {
    local dir; dir=$(_audit_accounts_state_dir)
    local path safe baseline tmp
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        [[ -r "$path" ]] || continue
        safe=$(_audit_accounts_sanitise "$path")
        baseline="$dir/$safe.baseline"
        if [[ ! -f "$baseline" && ! -f "$dir/.encoded" ]]; then
            baseline="$dir/$(_audit_accounts_legacy_name "$path").baseline"
        fi
        [[ -f "$baseline" ]] && continue
        tmp=$(mktemp "$dir/.baseline.tmp.XXXXXX") || continue
        if cat "$path" 2>/dev/null > "$tmp"; then
            mv -f "$tmp" "$dir/$safe.baseline"
        else
            rm -f "$tmp"
        fi
    done < <(_audit_accounts_expand)
}

_audit_accounts_tick() {
    [[ "${AUDIT_ENABLED:-0}" == "1" ]] || return 0
    local dir; dir=$(_audit_accounts_state_dir)
    local marker="$dir/.lastcheck"
    local now; now=$(date +%s)
    local last=0
    [[ -f "$marker" ]] && last=$(cat "$marker" 2>/dev/null || echo 0)
    [[ -z "$last" ]] && last=0
    if (( now - last < AUDIT_ACCOUNTS_INTERVAL )); then
        return 0
    fi

    # The marker, not the per-file baselines, marks bootstrap: the globs can match nothing on a fresh host.
    if [[ ! -f "$marker" ]]; then
        _audit_accounts_baseline >/dev/null 2>&1
        printf '%s' "$now" > "$marker"
        return 0
    fi

    _audit_accounts_heal_missing

    # One alert per file, listing at most 5 new lines.
    local prev_file="" body="" capped=""
    local change file line lines_count=0 key b rows="" out ok=1
    out=$(_audit_accounts_diff | sort) || ok=0
    while IFS=$'\t' read -r change file line; do
        [[ -z "$change" ]] && continue
        rows+="$change"$'\t'"$file"$'\n'
        [[ "$change" == "ADDED" ]] || continue
        [[ -z "$file" ]] && continue
        if [[ "$file" != "$prev_file" ]]; then
            if [[ -n "$prev_file" ]]; then
                [[ -n "$capped" ]] && body="${body}
${capped}"
                key="audit:accounts:NEW:$prev_file"
                b="\`\`\`new lines in $prev_file:
$body\`\`\`"
                alert_condition_open "$key" "Account drift: $prev_file" "$b" 15158332 "$b"
            fi
            prev_file="$file"; body="$line"; lines_count=1; capped=""
        else
            (( lines_count++ ))
            if (( lines_count <= 5 )); then
                body="${body}
${line}"
            else
                capped="… (and $((lines_count - 5)) more)"
            fi
        fi
    done <<< "$out"   # sort groups ADDED rows by file
    if [[ -n "$prev_file" ]]; then
        [[ -n "$capped" ]] && body="${body}
${capped}"
        key="audit:accounts:NEW:$prev_file"
        b="\`\`\`new lines in $prev_file:
$body\`\`\`"
        alert_condition_open "$key" "Account drift: $prev_file" "$b" 15158332 "$b"
    fi
    (( ok )) && alert_condition_sweep audit:accounts: "$now"
    # Subject is the file only, so passwd and sudoers lines stay out of the DB.
    history_write_audit accounts "$(_audit_mtime "$dir/.encoded")" "$rows"

    printf '%s' "$now" > "$marker"
}

_audit_accounts_subcmd() {
    case "${1:-status}" in
        baseline)
            local count path
            read -r count path < <(_audit_accounts_baseline)
            local marker="$path/.lastcheck"
            date +%s > "$marker"
            echo -e "${G}baseline${NC} written under ${C}$path${NC}"
            echo -e "  ${D}tracked: ${count:-0} files${NC}"
            ;;
        check)
            local dir; dir=$(_audit_accounts_state_dir)
            local marker="$dir/.lastcheck"
            if [[ ! -f "$marker" ]]; then
                echo -e "${Y}no baseline yet — run \`milog audit accounts baseline\` first${NC}"
                return 1
            fi
            local out; out=$(_audit_accounts_diff)
            if [[ -z "$out" ]]; then
                echo -e "${G}no drift${NC} — every tracked file matches baseline"
                return 0
            fi
            local added removed
            added=$(printf   '%s\n' "$out" | grep -c '^ADDED'   || true)
            removed=$(printf '%s\n' "$out" | grep -c '^REMOVED' || true)
            if (( added > 0 )); then
                echo -e "${R}NEW lines (alert-worthy):${NC}"
                printf '%s\n' "$out" | awk -F'\t' '$1=="ADDED"   {printf "  \033[31m%-9s\033[0m  %s  ::  %s\n", $1, $2, $3}'
            fi
            if (( removed > 0 )); then
                echo -e "${D}removed (housekeeping, no alert):${NC}"
                printf '%s\n' "$out" | awk -F'\t' '$1=="REMOVED" {printf "  \033[90m%-9s\033[0m  %s  ::  %s\n", $1, $2, $3}'
            fi
            (( added > 0 )) && return 1 || return 0
            ;;
        status)
            local dir; dir=$(_audit_accounts_state_dir)
            local marker="$dir/.lastcheck"
            echo -e "${W}milog audit accounts — status${NC}"
            echo -e "  ${D}AUDIT_ENABLED=${NC}${AUDIT_ENABLED:-0}   ${D}AUDIT_ACCOUNTS_INTERVAL=${NC}${AUDIT_ACCOUNTS_INTERVAL:-3600}s"
            local tracked
            tracked=$(_audit_accounts_expand | wc -l | tr -d ' ')
            echo -e "  ${D}files currently matching globs:${NC} ${tracked:-0}"
            if [[ -f "$marker" ]]; then
                local last; last=$(cat "$marker" 2>/dev/null || echo 0)
                local now; now=$(date +%s); local mins=$(( (now - last) / 60 ))
                echo -e "  ${D}last check:${NC} ${mins}m ago"
            else
                echo -e "  ${D}last check:${NC} ${Y}never (no baseline yet)${NC}"
            fi
            echo -e "  ${D}watchlist (${#AUDIT_ACCOUNTS_PATHS[@]} patterns):${NC}"
            local p
            for p in "${AUDIT_ACCOUNTS_PATHS[@]}"; do
                printf "    %s\n" "$p"
            done
            ;;
        *)
            echo -e "${R}unknown accounts subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}

# ==============================================================================
# Rootkit hint scanner — point-in-time heuristics, no baseline. Each
# heuristic is a yes/no signal that's worth firing on its own:
#
#   hidden_process       /proc dir count > `ps -e` count (slack for racing),
#                        or a PID that answers stat but is not listed
#   ld_preload_present   /etc/ld.so.preload exists at all
#   exec_from_tmp        a running process's exe lives under /tmp,
#                        /dev/shm, or /var/tmp
#   deleted_exe          /proc/<pid>/exe symlink ends with `(deleted)`
#                        — backing file unlinked, classic memory-resident
#                        malware tell
#
# Linux-only (relies on /proc). On macOS / BSD the support check fails
# fast and the module no-ops. Same design as ports — the existing
# point-in-time scanners stay coherent across OS detection.
# ==============================================================================

_audit_rootkit_supported() {
    [[ -d /proc ]] && [[ -d /proc/1 ]]
}

# The slack covers processes that start or exit between the two counts.
_audit_rootkit_check_hidden() {
    local ps_count proc_count slack=5
    ps_count=$(ps -eo pid 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
    proc_count=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l | tr -d ' ')
    [[ -z "$ps_count" || -z "$proc_count" ]] && return 0
    if (( proc_count > ps_count + slack )); then
        printf 'hidden_process\tps_count=%d /proc_count=%d (delta=%d > slack=%d)\n' \
            "$ps_count" "$proc_count" "$((proc_count - ps_count))" "$slack"
    fi
}

# ps, ls and globs list /proc via readdir, which LD_PRELOAD can filter; stat on /proc/<pid> it cannot.
# Kernel-module rootkits and stat hooks are out of reach here; the eBPF exec probe covers those.
_audit_rootkit_check_hidden_stat() {
    local pid_max last_pid limit n p k v tgid comm _
    local -A listed=() relisted=()
    local -a candidates=()
    pid_max=$(cat /proc/sys/kernel/pid_max 2>/dev/null) || pid_max=32768
    read -r _ _ _ _ last_pid 2>/dev/null < /proc/loadavg || last_pid=0
    limit=$pid_max
    for p in /proc/[0-9]*; do
        n=${p#/proc/}
        listed[$n]=1
        (( n > last_pid )) && last_pid=$n
    done
    # Above 64k pid_max only PIDs up to the newest are scanned; a hidden PID from before a wrap is missed.
    (( pid_max > 65536 )) && limit=$last_pid
    for (( n = 1; n <= limit; n++ )); do
        [[ -e /proc/$n && -z "${listed[$n]:-}" ]] && candidates+=("$n")
    done
    (( ${#candidates[@]} > 0 )) || return 0

    # Re-list so processes spawned during the scan don't count as hidden.
    for p in /proc/[0-9]*; do relisted[${p#/proc/}]=1; done
    for n in "${candidates[@]}"; do
        [[ -n "${relisted[$n]:-}" ]] && continue
        tgid=""
        while read -r k v _; do
            [[ "$k" == "Tgid:" ]] && { tgid="$v"; break; }
        done 2>/dev/null < "/proc/$n/status" || continue
        # Thread IDs stat fine but are never listed; only thread-group leaders count.
        [[ "$tgid" == "$n" ]] || continue
        comm=$(cat "/proc/$n/comm" 2>/dev/null) || comm="?"
        printf 'hidden_process:%s\tpid=%s comm=%s answers stat but is missing from the /proc listing\n' \
            "${comm:-?}" "$n" "${comm:-?}"
    done
}

_audit_rootkit_check_preload() {
    if [[ -e /etc/ld.so.preload ]]; then
        local content
        content=$(head -c 200 /etc/ld.so.preload 2>/dev/null | tr '\n' ' ')
        printf 'ld_preload_present\t/etc/ld.so.preload exists: %s\n' "${content:-(empty)}"
    fi
}

# One /proc walk for both exec_from_tmp and deleted_exe; unreadable kernel-thread exe links are skipped.
_audit_rootkit_walk_proc() {
    local pid exe comm
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        [[ -z "$exe" ]] && continue
        comm=$(cat "/proc/$pid/comm" 2>/dev/null | tr -d '\n')
        [[ -z "$comm" ]] && comm="?"
        case "$exe" in
            *" (deleted)")
                printf 'deleted_exe:%s\tpid=%s comm=%s exe=%s\n' \
                    "$comm" "$pid" "$comm" "$exe"
                ;;
            /tmp/*|/var/tmp/*|/dev/shm/*)
                printf 'exec_from_tmp:%s\tpid=%s comm=%s exe=%s\n' \
                    "$comm" "$pid" "$comm" "$exe"
                ;;
        esac
    done
}

# `<heuristic>\t<detail>` per finding; per-process keys carry the comm so cooldown groups by process.
_audit_rootkit_run_all() {
    _audit_rootkit_supported || return 0
    _audit_rootkit_check_hidden
    _audit_rootkit_check_hidden_stat
    _audit_rootkit_check_preload
    _audit_rootkit_walk_proc
}

_audit_rootkit_tick() {
    [[ "${AUDIT_ENABLED:-0}" == "1" ]] || return 0
    _audit_rootkit_supported || return 0
    local dir; dir=$(_audit_state_dir)
    local marker="$dir/rootkit.lastcheck"
    local now; now=$(date +%s)
    local last=0
    [[ -f "$marker" ]] && last=$(cat "$marker" 2>/dev/null || echo 0)
    [[ -z "$last" ]] && last=0
    if (( now - last < AUDIT_ROOTKIT_INTERVAL )); then
        return 0
    fi

    local heur detail key body rows="" out ok=1
    out=$(_audit_rootkit_run_all) || ok=0
    while IFS=$'\t' read -r heur detail; do
        [[ -z "$heur" ]] && continue
        rows+="hint"$'\t'"$heur"$'\n'
        key="audit:rootkit:$heur"
        body="\`\`\`$detail\`\`\`"
        # New ld.so.preload content is new information; the other hints carry pids or counts that churn.
        if [[ "$heur" == ld_preload_present ]]; then
            alert_condition_open "$key" "Rootkit hint: $heur" "$body" 15158332 "$detail"
        else
            alert_condition_open "$key" "Rootkit hint: $heur" "$body" 15158332
        fi
    done <<< "$out"
    (( ok )) && alert_condition_sweep audit:rootkit: "$now"
    # No baseline to reset against, so a hint is stored once per retention window.
    history_write_audit rootkit 0 "$rows"

    printf '%s' "$now" > "$marker"
}

_audit_rootkit_subcmd() {
    case "${1:-status}" in
        check)
            if ! _audit_rootkit_supported; then
                echo -e "${Y}rootkit scan needs /proc — Linux only (this is $(uname -s))${NC}"
                return 1
            fi
            local out; out=$(_audit_rootkit_run_all)
            if [[ -z "$out" ]]; then
                echo -e "${G}no hits${NC} — every heuristic clean"
                return 0
            fi
            echo -e "${R}rootkit hints:${NC}"
            printf '%s\n' "$out" | awk -F'\t' '{
                printf "  \033[31m%-40s\033[0m  %s\n", $1, $2
            }'
            return 1
            ;;
        status)
            local dir; dir=$(_audit_state_dir)
            local marker="$dir/rootkit.lastcheck"
            echo -e "${W}milog audit rootkit — status${NC}"
            echo -e "  ${D}AUDIT_ENABLED=${NC}${AUDIT_ENABLED:-0}   ${D}AUDIT_ROOTKIT_INTERVAL=${NC}${AUDIT_ROOTKIT_INTERVAL:-3600}s"
            local sup="no (needs /proc — Linux only)"
            _audit_rootkit_supported && sup="yes"
            echo -e "  ${D}supported on this host:${NC} $sup"
            echo -e "  ${D}heuristics:${NC} hidden_process, ld_preload_present, exec_from_tmp, deleted_exe"
            if [[ -f "$marker" ]]; then
                local last; last=$(cat "$marker" 2>/dev/null || echo 0)
                local now; now=$(date +%s); local mins=$(( (now - last) / 60 ))
                echo -e "  ${D}last check:${NC} ${mins}m ago"
            else
                echo -e "  ${D}last check:${NC} ${Y}never${NC}"
            fi
            ;;
        *)
            echo -e "${R}unknown rootkit subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}

# Drift the daemon stored in audit_event, newest first.
_audit_history_subcmd() {
    local days="${1:-7}"
    [[ "$days" =~ ^[1-9][0-9]*$ ]] \
        || { echo -e "${R}audit history: days must be a positive integer${NC}" >&2; return 1; }
    _history_precheck || return 1

    local since=$(( $(date +%s) - days * 86400 )) out
    if ! out=$(_history_audit_rows "$since" 2>/dev/null); then
        echo -e "${Y}no audit history in $HISTORY_DB yet${NC}, the daemon creates it on start" >&2
        return 1
    fi
    if [[ -z "$out" ]]; then
        echo -e "${G}no drift recorded${NC} in the last ${days}d"
        return 0
    fi
    printf '%s\n' "$out" | awk -F'\t' '{ printf "  %s  %-11s  %-10s  %s\n", $1, $2, $3, substr($0, length($1 $2 $3) + 4) }' | _tty_safe
}

# The accepting user and time land in audit_event as kind "accepted".
_audit_accept_record() {
    local check="$1" item="$2" who
    who="${SUDO_USER:-$(id -un 2>/dev/null)}"
    echo -e "${G}accepted${NC} $check ${C}$item${NC} into the baseline"
    [[ "${HISTORY_ENABLED:-0}" == "1" && -f "${HISTORY_DB:-}" ]] || return 0
    history_write_audit "$check" "$(date +%s)" "accepted"$'\t'"$item by ${who:-?}"
}

_audit_fim_accept() {
    local path="$1" dir baseline row old_sha sha st mtime=0 size=0 tmp now
    dir=$(_audit_state_dir); baseline="$dir/fim.baseline"
    [[ -f "$baseline" ]] || { echo -e "${Y}no fim baseline yet — run \`milog audit fim baseline\` first${NC}" >&2; return 1; }
    _audit_have_sha256 || { echo -e "${R}no sha256sum or shasum on PATH${NC}" >&2; return 1; }
    row=$(P="$path" awk -F'\t' '$1 == ENVIRON["P"] { print $2; exit }' "$baseline")
    [[ -n "$row" ]] || { echo -e "${R}$path is not in the fim baseline${NC}" >&2; return 1; }
    old_sha="$row"
    if [[ -e "$path" ]]; then
        sha=$(_audit_sha256 "$path"); [[ -z "$sha" ]] && sha="UNREADABLE"
        st=$(_audit_stat "$path"); mtime="${st%%	*}"; size="${st##*	}"
    else
        sha="MISSING"
    fi
    if [[ "$sha" == "$old_sha" ]]; then
        echo -e "${G}no drift${NC} for $path, nothing to accept"
        return 0
    fi
    now=$(date +%s)
    tmp=$(mktemp "$dir/fim.baseline.tmp.XXXXXX") || return 1
    if [[ "$sha" == MISSING ]]; then
        local snapdir; snapdir=$(_audit_fim_snap_dir) && rm -f "$snapdir/$(_audit_accounts_sanitise "$path")"
    else
        _audit_fim_snap_write "$path"
    fi
    if ! P="$path" R="$path"$'\t'"$sha"$'\t'"$mtime"$'\t'"$size"$'\t'"$now" \
        awk -F'\t' '$1 == ENVIRON["P"] { print ENVIRON["R"]; next } { print }' "$baseline" > "$tmp"; then
        rm -f "$tmp"; return 1
    fi
    mv -f "$tmp" "$baseline" || { rm -f "$tmp"; return 1; }
    _audit_accept_record fim "$path"
}

_audit_persistence_accept() {
    local path="$1" dir baseline in_base=0 in_cur=0 st tmp
    dir=$(_audit_state_dir); baseline="$dir/persistence.baseline"
    [[ -f "$baseline" ]] || { echo -e "${Y}no persistence baseline yet — run \`milog audit persistence baseline\` first${NC}" >&2; return 1; }
    P="$path" awk -F'\t' '$1 == ENVIRON["P"] { f = 1; exit } END { exit !f }' "$baseline" && in_base=1
    grep -Fxq -- "$path" < <(_audit_persistence_expand) && in_cur=1
    if (( in_base == in_cur )); then
        echo -e "${G}no drift${NC} for $path, nothing to accept"
        return 0
    fi
    tmp=$(mktemp "$dir/persistence.baseline.tmp.XXXXXX") || return 1
    if ! P="$path" awk -F'\t' '$1 != ENVIRON["P"]' "$baseline" > "$tmp"; then
        rm -f "$tmp"; return 1
    fi
    if (( in_cur )); then
        st=$(_audit_stat "$path")
        printf '%s\t%s\t%s\t%s\n' "$path" "${st##*	}" "${st%%	*}" "$(date +%s)" >> "$tmp"
    fi
    mv -f "$tmp" "$baseline" || { rm -f "$tmp"; return 1; }
    _audit_accept_record persistence "$path"
}

# Item is <proto>:<port>; every bind address on that port is set to what is listening now.
_audit_ports_accept() {
    local item="$1" proto port dir baseline cur tmp
    proto="${item%%:*}"; port="${item##*:}"
    if [[ ! "$proto" =~ ^(tcp|udp)$ || ! "$port" =~ ^[0-9]+$ || "$item" != "$proto:$port" ]]; then
        echo -e "${R}ports item must be <tcp|udp>:<port>, e.g. tcp:443${NC}" >&2
        return 1
    fi
    dir=$(_audit_state_dir); baseline="$dir/ports.baseline"
    [[ -f "$baseline" ]] || { echo -e "${Y}no ports baseline yet — run \`milog audit ports baseline\` first${NC}" >&2; return 1; }
    cur=$(mktemp "$dir/ports.current.XXXXXX") || return 1
    tmp=$(mktemp "$dir/ports.baseline.tmp.XXXXXX") || { rm -f "$cur"; return 1; }
    _audit_ports_capture | awk -F'\t' -v pr="$proto" -v po="$port" '$1 == pr && $3 == po' > "$cur"
    local rc=0
    awk -F'\t' -v OFS='\t' -v pr="$proto" -v po="$port" -v now="$(date +%s)" '
        FILENAME == ARGV[1] { cur[$1 FS $2 FS $3] = 1; next }
        $1 == pr && $3 == po { k = $1 FS $2 FS $3; if (k in cur) { print; seen[k] = 1 } else changed = 1; next }
        { print }
        END { for (k in cur) if (!(k in seen)) { print k, now; changed = 1 }; exit !changed }
    ' "$cur" "$baseline" > "$tmp" || rc=$?
    rm -f "$cur"
    if (( rc != 0 )); then
        rm -f "$tmp"
        echo -e "${G}no drift${NC} for $item, nothing to accept"
        return 0
    fi
    mv -f "$tmp" "$baseline" || { rm -f "$tmp"; return 1; }
    _audit_accept_record ports "$item"
}

_audit_accounts_accept() {
    local path="$1" dir safe tmp
    dir=$(_audit_accounts_state_dir)
    [[ -f "$dir/.lastcheck" ]] || { echo -e "${Y}no accounts baseline yet — run \`milog audit accounts baseline\` first${NC}" >&2; return 1; }
    grep -Fxq -- "$path" < <(_audit_accounts_expand) \
        || { echo -e "${R}$path is not a file in AUDIT_ACCOUNTS_PATHS${NC}" >&2; return 1; }
    if ! grep -Fxq -- "$path" < <(_audit_accounts_diff | awk -F'\t' '{ print $2 }'); then
        echo -e "${G}no drift${NC} for $path, nothing to accept"
        return 0
    fi
    safe=$(_audit_accounts_sanitise "$path")
    tmp=$(mktemp "$dir/.baseline.tmp.XXXXXX") || return 1
    if ! cat "$path" 2>/dev/null > "$tmp"; then
        rm -f "$tmp"; echo -e "${R}cannot read $path${NC}" >&2; return 1
    fi
    mv -f "$tmp" "$dir/$safe.baseline" || { rm -f "$tmp"; return 1; }
    _audit_accept_record accounts "$path"
}

# What is drifting in one check, each with the command that accepts it.
_audit_accept_list() {
    local check="$1" dir out
    dir=$(_audit_state_dir)
    case "$check" in
        fim)
            [[ -f "$dir/fim.baseline" ]] && _audit_have_sha256 || return 0
            out=$(_audit_fim_diff | awk -F'\t' '{ print $1 "\t" $2 }') ;;
        persistence)
            [[ -f "$dir/persistence.baseline" ]] || return 0
            out=$(_audit_persistence_diff) ;;
        ports)
            [[ -f "$dir/ports.baseline" ]] || return 0
            out=$(_audit_ports_diff | awk -F'\t' '{ print $1 "\t" $2 ":" $4 }' | sort -u) ;;
        accounts)
            [[ -f "$dir/accounts/.lastcheck" ]] || return 0
            out=$(_audit_accounts_diff | awk -F'\t' '{ f[$2] = 1; c[$2 FS $1]++ }
                END { for (p in f) printf "+%d -%d lines\t%s\n", c[p FS "ADDED"], c[p FS "REMOVED"], p }' | sort -t$'\t' -k2) ;;
    esac
    [[ -n "$out" ]] || return 0
    echo -e "${W}$check${NC}"
    local change item
    while IFS=$'\t' read -r change item; do
        [[ -n "$item" ]] || continue
        printf '  %-14s %q\n' "$change" "$item"
        printf "    ${D}milog audit accept %s %q${NC}\n" "$check" "$item"
    done <<< "$out"
}

_audit_accept_subcmd() {
    local check="${1:-}" item="${2:-}"
    case "$check" in
        "")
            local listing c
            listing=$(for c in fim persistence ports accounts; do _audit_accept_list "$c"; done)
            if [[ -z "$listing" ]]; then
                echo -e "${G}no drift${NC} in any baselined check"
            else
                printf '%s\n' "$listing"
            fi
            ;;
        fim|persistence|ports|accounts)
            if [[ -z "$item" ]]; then
                local listing; listing=$(_audit_accept_list "$check")
                [[ -n "$listing" ]] && printf '%s\n' "$listing" || echo -e "${G}no drift${NC} in $check"
                return 0
            fi
            "_audit_${check}_accept" "$item"
            ;;
        *)
            echo -e "${R}usage: milog audit accept [fim|persistence|ports|accounts] [path|proto:port]${NC}" >&2
            return 1 ;;
    esac
}
