#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

mkdir -p "$tmp/home/.config/milog" "$tmp/logs"
: > "$tmp/logs/app.access.log"
export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"
export MILOG_CONFIG="$tmp/home/.config/milog/config.sh"
: > "$MILOG_CONFIG"

fail() { printf 'smoke_probe_unit: %s\n' "$1" >&2; exit 1; }

bash -c '
    . "$1" help >/dev/null
    _probe_unit /usr/local/bin/milog-probe alice /home/alice /home/alice/.config/milog/config.sh "sshd,cron" "CAP_BPF CAP_PERFMON"
' _ "$ROOT/milog.sh" > "$tmp/unit"

for want in \
    "ExecStart=/usr/local/bin/milog-probe" \
    "Environment=MILOG_PROBE_ALERT_USER=alice" \
    "Environment=MILOG_CONFIG=/home/alice/.config/milog/config.sh" \
    "CapabilityBoundingSet=CAP_BPF CAP_PERFMON" \
    "NoNewPrivileges=yes" \
    "ProtectSystem=full" \
    "PrivateTmp=yes"; do
    grep -qxF "$want" "$tmp/unit" || fail "unit is missing: $want"
done

: > "$tmp/user-owned"
bash -c '. "$1" help >/dev/null; _root_trusted_path "$2"' _ "$ROOT/milog.sh" "$tmp/user-owned" \
    && [[ $EUID -ne 0 ]] && fail "user-owned file treated as root-trusted"
bash -c '. "$1" help >/dev/null; _root_trusted_path /usr/bin/env' _ "$ROOT/milog.sh" \
    || fail "/usr/bin/env not treated as root-trusted"

if [[ $EUID -eq 0 ]]; then
    printf ': > %q\n' "$tmp/sourced" > "$MILOG_CONFIG"
    chown nobody "$MILOG_CONFIG"
    "$ROOT/milog.sh" config path >/dev/null 2>"$tmp/err" || true
    [[ -e "$tmp/sourced" ]] && fail "root sourced a non-root-owned config"
    grep -q "refusing to source" "$tmp/err" || fail "no warning for an untrusted config"

    rootcfg="$tmp/rootcfg"
    mkdir -m 0755 "$rootcfg"
    printf ': > %q\n' "$tmp/sourced" > "$rootcfg/config.sh"
    chmod 0644 "$rootcfg/config.sh"
    MILOG_CONFIG="$rootcfg/config.sh" "$ROOT/milog.sh" config path >/dev/null
    [[ -e "$tmp/sourced" ]] || fail "root did not source a root-owned config"
fi

printf 'smoke_probe_unit: ok\n'
