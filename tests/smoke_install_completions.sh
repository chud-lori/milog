#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

# Every flag in install.sh's header must be parsed by main().
documented=$(grep -m1 '^# Flags:' "$ROOT/install.sh" | grep -oE -- '--[a-z-]+')
parsed=$(sed -n '/^main() {/,/^}/p' "$ROOT/install.sh" | grep -oE '^ +(-[-a-z|]+)\)' | tr -d ' )' | tr '|' '\n')
for flag in $documented; do
    grep -qxF -- "$flag" <<< "$parsed" || fail "install.sh documents $flag but main() does not parse it"
done

# The bundle must emit completions with no completions/ dir beside it.
mkdir -p "$tmp/bin" "$tmp/home/.config/milog" "$tmp/logs"
: > "$tmp/logs/app.access.log"
cp "$ROOT/milog.sh" "$tmp/bin/milog"

export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"

for pair in bash:milog.bash zsh:_milog fish:milog.fish; do
    shell="${pair%%:*}" file="${pair#*:}"
    "$tmp/bin/milog" completions "$shell" > "$tmp/out.$shell" \
        || fail "milog completions $shell failed"
    cmp -s "$tmp/out.$shell" "$ROOT/completions/$file" \
        || fail "milog completions $shell does not match completions/$file"
done

"$tmp/bin/milog" completions install > /dev/null
for f in "$HOME/.local/share/bash-completion/completions/milog" \
         "$HOME/.local/share/zsh/site-functions/_milog" \
         "$HOME/.config/fish/completions/milog.fish"; do
    [[ -s "$f" ]] || fail "completions install left $f missing or empty"
done

printf 'smoke_install_completions: ok\n'
