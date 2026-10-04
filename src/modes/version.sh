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

# Version a companion reports for --version; the timeout covers milog-web builds that predate the flag and start serving instead.
_companion_version() {
    local name="$1" bin="$2" out=""
    if command -v timeout >/dev/null 2>&1; then
        out=$(timeout 3 "$bin" --version 2>/dev/null | head -1) || true
    else
        out=$("$bin" --version 2>/dev/null | head -1) || true
    fi
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
