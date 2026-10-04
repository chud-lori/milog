# milog version: the bundle's build stamp plus the version of each companion binary found.

# Path of the running milog with symlinks resolved.
_milog_self() {
    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"
    readlink -f "$self" 2>/dev/null || printf '%s' "$self"
}

# Value of the `# MILOG_<KEY>=` header line build.sh writes, or "unknown".
_milog_stamp() {
    local v
    v=$(head -5 "$(_milog_self)" 2>/dev/null | awk -F= -v k="# MILOG_$1" '$1 == k {print $2; exit}')
    printf '%s' "${v:-unknown}"
}

# name<TAB>path for each companion binary the mode lookups find.
_milog_companions() {
    local p
    if p=$(_web_go_binary);   then printf 'milog-web\t%s\n' "$p"; fi
    if p=$(_tui_go_binary);   then printf 'milog-tui\t%s\n' "$p"; fi
    if p=$(_probe_binary);    then printf 'milog-probe\t%s\n' "$p"; fi
}

# Version a companion reports for --version; the 3s cap covers milog-web builds that predate the flag and start serving instead.
_companion_version() {
    local name="$1" bin="$2" out f pid
    f=$(mktemp) || { printf 'unknown'; return; }
    # set -m gives the job its own process group, so one kill also reaches its children.
    set -m
    "$bin" --version >"$f" 2>/dev/null &
    pid=$!
    set +m
    for _ in $(seq 30); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -- "-$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    out=$(head -1 "$f")
    rm -f "$f"
    if [[ "$out" != "$name "* ]]; then
        printf 'unknown'; return
    fi
    out=${out#"$name "}
    out=${out#v=}
    printf '%s' "${out%% *}"
}

mode_version() {
    printf '%-12s %s (built %s)  %s\n' milog "$(_milog_stamp VERSION)" "$(_milog_stamp BUILT)" "$(_milog_self)"
    local name path
    while IFS=$'\t' read -r name path; do
        printf '%-12s %s  %s\n' "$name" "$(_companion_version "$name" "$path")" "$path"
    done < <(_milog_companions)
}
