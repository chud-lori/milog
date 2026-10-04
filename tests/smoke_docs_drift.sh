#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# One name per top-level dispatch label: the first alternative that is a
# plain word, so `-h|--help|help` gives `help` and `""|logs` gives `logs`.
dispatch_cmds() {
    sed -n '/^case "\${1:-}" in$/,/^esac$/p' "$ROOT/src/dispatch.sh" \
        | grep -E '^    [^ #][^)]*\)' \
        | sed -E 's/^    ([^)]*)\).*/\1/' \
        | tr '|' ' ' \
        | while read -r -a alts; do
            for a in "${alts[@]}"; do
                if [[ "$a" =~ ^[a-z][a-z-]*$ ]]; then echo "$a"; break; fi
            done
        done | sort -u
}

bash_cmds() {
    sed -n 's/^ *local cmds="\(.*\)"$/\1/p' "$ROOT/completions/milog.bash" | tr ' ' '\n' | sort -u
}

zsh_cmds() {
    sed -n '/^    commands=(/,/^    )/p' "$ROOT/completions/_milog" \
        | sed -n "s/^ *'\([^:]*\):.*/\1/p" | sort -u
}

fish_cmds() {
    sed -n '/^set -l cmds/,/^$/p' "$ROOT/completions/milog.fish" \
        | sed -n 's/^ *"\([^:]*\):.*/\1/p' | sort -u
}

expected=$(dispatch_cmds)
[[ -n "$expected" ]] || { echo "could not read commands from src/dispatch.sh" >&2; exit 1; }

fail=0
compare() {
    local shell="$1" got="$2"
    if [[ "$got" != "$expected" ]]; then
        echo "completions ($shell) differ from src/dispatch.sh (< dispatch, > completions):" >&2
        diff <(printf '%s\n' "$expected") <(printf '%s\n' "$got") >&2 || true
        fail=1
    fi
}
compare bash "$(bash_cmds)"
compare zsh "$(zsh_cmds)"
compare fish "$(fish_cmds)"

while read -r cmd; do
    if ! grep -qE "^\.BR? \"?(milog )?${cmd}( |\"|$)" "$ROOT/man/milog.1"; then
        echo "man/milog.1 has no entry for '$cmd'" >&2
        fail=1
    fi
done <<< "$expected"

exit "$fail"
