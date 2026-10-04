#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
pid=""

cleanup() {
    if [[ -n "$pid" ]]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT

failures=0
fail() { printf 'FAIL: %s\n' "$*" >&2; failures=$(( failures + 1 )); }

mkdir -p "$tmp/home" "$tmp/logs" "$tmp/state" "$tmp/hooks/on_alert.d" "$tmp/bin"
: > "$tmp/logs/app.access.log"
export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs" MILOG_APPS="app" MILOG_ALERT_STATE_DIR="$tmp/state"
export MILOG_ALERTS_ENABLED=1 MILOG_HOOKS_DIR="$tmp/hooks"

cat > "$tmp/hooks/on_alert.d/10-env" <<EOF
#!/usr/bin/env bash
printf '%s|%s\n' "\$MILOG_RULE_KEY" "\$MILOG_IP" >> "$tmp/hook.out"
EOF
chmod +x "$tmp/hooks/on_alert.d/10-env"

# Exploit fires carry the request's source IP.
"$ROOT/milog.sh" exploits >/dev/null 2>"$tmp/err" &
pid=$!
sleep 1
printf '%s\n' '203.0.113.7 - - [04/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8"' \
    >> "$tmp/logs/app.access.log"
for _ in $(seq 50); do
    [[ -s "$tmp/hook.out" ]] && break
    sleep 0.1
done
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
pid=""
grep -qx 'exploit:app:dotfile|203.0.113.7' "$tmp/hook.out" 2>/dev/null \
    || fail "exploit hook did not get MILOG_IP: $(cat "$tmp/hook.out" 2>/dev/null)"

# Rules without a source IP leave it empty.
: > "$tmp/hook.out"
"$ROOT/milog.sh" _internal_alert cpu "t" "b" >/dev/null 2>&1
for _ in $(seq 50); do
    [[ -s "$tmp/hook.out" ]] && break
    sleep 0.1
done
grep -qx 'cpu|' "$tmp/hook.out" || fail "cpu hook got unexpected env: $(cat "$tmp/hook.out")"

# Example ban scripts, with the firewall tools stubbed.
for tool in fail2ban-client nft; do
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/calls"\n' "$tmp" > "$tmp/bin/$tool"
    chmod +x "$tmp/bin/$tool"
done

# expect <script> <rule> <ip> <exit-code> <call or empty>
expect() {
    local script="$1" rule="$2" ip="$3" want_rc="$4" want_call="$5" rc=0
    : > "$tmp/calls"
    PATH="$tmp/bin:$PATH" "$ROOT/docs/examples/$script" "$rule" "$ip" 2>/dev/null || rc=$?
    [[ "$rc" == "$want_rc" ]] || fail "$script $rule '$ip': exit $rc, want $want_rc"
    [[ "$(cat "$tmp/calls")" == "$want_call" ]] || fail "$script $rule '$ip': called '$(cat "$tmp/calls")', want '$want_call'"
}

for script in milog-ban-fail2ban milog-ban-nft; do
    expect "$script" probe:app          203.0.113.7       0 ""
    expect "$script" exploit:app:sqli   ""                1 ""
    expect "$script" exploit:app:sqli   "203.0.113.7;id"  1 ""
    expect "$script" exploit:app:sqli   "256.1.1.1"       1 ""
    expect "$script" exploit:app:sqli   "010.1.1.1"       1 ""
    expect "$script" exploit:app:sqli   "-1.2.3.4"        1 ""
    expect "$script" exploit:app:sqli   "127.0.0.1"       1 ""
    expect "$script" exploit:app:sqli   "172.20.0.5"      1 ""
    expect "$script" exploit:app:sqli   "fd00::1"         1 ""
done
expect milog-ban-fail2ban exploit:app:sqli 203.0.113.7  0 "set milog banip 203.0.113.7"
expect milog-ban-fail2ban exploit:app:sqli 2001:db8::7  0 "set milog banip 2001:db8::7"
expect milog-ban-fail2ban exploit:app:sqli 172.32.0.5   0 "set milog banip 172.32.0.5"
expect milog-ban-nft      exploit:app:sqli 203.0.113.7  0 "add element inet milog banned4 { 203.0.113.7 }"
expect milog-ban-nft      exploit:app:sqli 2001:db8::7  0 "add element inet milog banned6 { 2001:db8::7 }"

if (( failures )); then
    exit 1
fi
printf 'smoke_ban_hooks: ok\n'
