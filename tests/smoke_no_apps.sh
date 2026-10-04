#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

mkdir -p "$tmp/home" "$tmp/logs"
unset MILOG_APPS MILOG_CONFIG
export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"

for cmd in help --help "config init" "config validate"; do
    # shellcheck disable=SC2086
    if ! "$ROOT/milog.sh" $cmd >/dev/null 2>"$tmp/err"; then
        echo "FAIL: 'milog $cmd' should run with no apps configured" >&2
        cat "$tmp/err" >&2
        exit 1
    fi
done

# doctor exits 1 when host deps are missing, so check it got past bootstrap.
"$ROOT/milog.sh" doctor >"$tmp/out" 2>&1 || true
grep -q "LOGS is empty" "$tmp/out" || {
    echo "FAIL: 'milog doctor' should run and report the empty LOGS" >&2
    cat "$tmp/out" >&2
    exit 1
}

[[ -f "$HOME/.config/milog/config.sh" ]] || {
    echo "FAIL: 'milog config init' did not write a config" >&2
    exit 1
}

if "$ROOT/milog.sh" rate >/dev/null 2>"$tmp/err"; then
    echo "FAIL: 'milog rate' should exit non-zero with no apps" >&2
    exit 1
fi
grep -q "milog config init" "$tmp/err" || {
    echo "FAIL: 'milog rate' should point at 'milog config init'" >&2
    cat "$tmp/err" >&2
    exit 1
}

echo "OK: no-app bootstrap commands run; app commands fail with guidance"
