#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MILOG="$ROOT/milog.sh"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    printf 'smoke_followups: %s\n' "$1" >&2
    exit 1
}

mkdir -p "$tmp/home" "$tmp/logs" "$tmp/target"
export HOME="$tmp/home"
export MILOG_CONFIG="$tmp/home/.config/milog/config.sh"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"
state="$tmp/home/.cache/milog"
mkdir -p "$state"

esc=$'\033' bel=$'\a' csi8=$'\302\233'
evil="/x${esc}]0;PWNED${bel}${esc}[2J${csi8}31m"
printf '1.2.3.4 - - [03/Oct/2026:10:00:00 +0000] "GET %s HTTP/1.1" 500 12 "-" "curl" 0.250\n' "$evil" \
    > "$tmp/logs/app.access.log"

# Daemon must refuse an ERROR-level config instead of carrying on.
rc=0
bash -c '
    . "$1" help >/dev/null
    TELEGRAM_BOT_TOKEN=token TELEGRAM_CHAT_ID=""
    history_init() { exit 3; }
    mode_daemon
' _ "$MILOG" >/dev/null 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || fail "daemon did not refuse a config with errors (rc=$rc)"

# No GeoIP: the attacker header must not show the em-dash placeholder as a country.
"$MILOG" attacker 1.2.3.4 > "$tmp/attacker.out" 2>&1 || true
if grep -qF '[—]' "$tmp/attacker.out"; then
    fail "attacker shows the geoip placeholder as a country tag"
fi

# "yesterday" stops at today's midnight (same UTC-day math as "today").
now=$(date +%s)
midnight=$(( now - now % 86400 ))
{
    printf '%s\trule:yesterday\t15158332\tY\tbody\n' "$(( midnight - 3600 ))"
    printf '%s\trule:today\t15158332\tT\tbody\n' "$midnight"
    printf '%s\tapp:app:yday_pat\t15158332\tY\tbody\n' "$(( midnight - 3600 ))"
    printf '%s\tapp:app:today_pat\t15158332\tT\tbody\n' "$midnight"
} > "$state/alerts.log"
"$MILOG" alerts yesterday > "$tmp/alerts.out" 2>&1
grep -qF 'rule:yesterday' "$tmp/alerts.out" || fail "alerts yesterday lost yesterday's row"
if grep -qF 'rule:today' "$tmp/alerts.out"; then
    fail "alerts yesterday includes today's row"
fi
"$MILOG" errors --since yesterday > "$tmp/errors_y.out" 2>&1
grep -qF 'yday_pat' "$tmp/errors_y.out" || fail "errors --since yesterday lost yesterday's row"
if grep -qF 'today_pat' "$tmp/errors_y.out"; then
    fail "errors --since yesterday includes today's row"
fi

# ALERT_ROUTES is read from another user's config without executing it.
{
    printf 'touch %q\n' "$tmp/pwned"
    printf 'ALERT_ROUTES="old: discord"\n'
    printf 'ALERT_ROUTES="\n    exploit:  slack\n    default:  discord\n"\n'
} > "$tmp/target/config.sh"
bash -c '
    . "$1" help >/dev/null
    _alert_read_routes "$2"
' _ "$MILOG" "$tmp/target/config.sh" > "$tmp/routes.out"
[[ ! -e "$tmp/pwned" ]] || fail "_alert_read_routes executed the target config"
expected=$'\n    exploit:  slack\n    default:  discord\n'
[[ "$(cat "$tmp/routes.out"; printf .)" == "${expected}." ]] \
    || fail "_alert_read_routes returned the wrong value: $(cat "$tmp/routes.out")"

# ...and skips a symlink, a FIFO and an oversized file instead of following, blocking or slurping.
ln -s "$tmp/target/config.sh" "$tmp/target/link.sh"
mkfifo "$tmp/target/fifo.sh"
{ printf 'ALERT_ROUTES="default: slack"\n'; head -c 1100000 /dev/zero | tr '\0' '#'; } > "$tmp/target/big.sh"
for f in link.sh fifo.sh big.sh; do
    out=$(timeout 5 bash -c '
        . "$1" help >/dev/null
        _alert_read_routes "$2"
        _alert_read_key "$2" ALERT_ROUTES
    ' _ "$MILOG" "$tmp/target/$f") || fail "alert config readers hung or failed on $f"
    [[ -z "$out" ]] || fail "alert config readers read $f"
done

# Silence durations are capped at 3650d, so a huge value can't overflow into the past.
"$MILOG" silence 'rule:x' 3650d >/dev/null 2>&1 || fail "silence rejected 3650d"
"$MILOG" silence clear 'rule:x' >/dev/null 2>&1
for d in 3651d 999999999999999d 99999999999999999999; do
    if "$MILOG" silence 'rule:x' "$d" note >/dev/null 2>&1; then
        fail "silence accepted $d"
    fi
done
if grep -qF 'rule:x' "$state/alerts.silences" 2>/dev/null; then
    fail "a rejected silence still wrote a row"
fi

# `alert on` accepts any configured destination, not only Discord.
alert_on_with() {
    bash -c '
        . "$1" help >/dev/null
        unset SUDO_USER
        home="$2"
        _alert_target_home() { printf "%s" "$home"; }
        _alert_install_service() { :; }
        mkdir -p "$home/.config/milog" && cp "$3" "$home/.config/milog/config.sh"
        alert_on
    ' _ "$MILOG" "$1" "$2" >/dev/null 2>&1
}
printf 'TELEGRAM_BOT_TOKEN="t"\n' > "$tmp/target/partial.sh"
printf 'SLACK_WEBHOOK="https://hooks.slack.invalid/x"\n' > "$tmp/target/slack.sh"
if alert_on_with "$tmp/partialhome" "$tmp/target/partial.sh"; then
    fail "alert on accepted a config with only half a Telegram destination"
fi
alert_on_with "$tmp/alerthome" "$tmp/target/slack.sh" || fail "alert on refused a Slack-only config"
grep -qx 'ALERTS_ENABLED=1' "$tmp/alerthome/.config/milog/config.sh" \
    || fail "alert on did not enable alerts for a Slack-only config"

# The daemon counts a Slack-only config as alerting, not as "no webhooks".
bash -c '
    . "$1" help >/dev/null
    ALERTS_ENABLED=1 DISCORD_WEBHOOK="" SLACK_WEBHOOK="https://hooks.slack.invalid/x"
    config_validate() { return 0; }
    history_init() { exit 0; }
    mode_daemon
' _ "$MILOG" > /dev/null 2> "$tmp/daemon.err" || true
grep -qF 'alerts=enabled' "$tmp/daemon.err" || fail "daemon reported alerts disabled with Slack configured"
if grep -qF 'no alert destination' "$tmp/daemon.err"; then
    fail "daemon warned about a missing destination with Slack configured"
fi

# Log-derived text must reach the terminal with its control bytes neutralised.
# shellcheck disable=SC2016
printf '%s\tapp:app:panic_go\t15158332\tpanic\t```panic %s```\n' "$now" "$evil" >> "$state/alerts.log"
"$MILOG" search PWNED   > "$tmp/search.out"    2>&1
"$MILOG" top-paths      > "$tmp/top-paths.out" 2>&1
"$MILOG" slow           > "$tmp/slow.out"      2>&1
"$MILOG" errors --since all > "$tmp/errors.out" 2>&1
bash -c '
    . "$1" help >/dev/null
    log="$2"
    _log_reader_cmd() { printf "cat %q" "$log"; }
    _errors_live > "$3"
    color_prefix > "$4"
' _ "$MILOG" "$tmp/logs/app.access.log" "$tmp/errors-live.out" "$tmp/tail.out" 2>/dev/null

for mode in search top-paths slow errors errors-live tail; do
    out="$tmp/$mode.out"
    grep -qF 'PWNED' "$out" || fail "$mode printed no log line"
    if LC_ALL=C grep -qF -e "${esc}]" -e "$bel" -e "${esc}[2J" -e "$csi8" "$out"; then
        fail "$mode passed terminal control bytes through"
    fi
done

printf 'smoke_followups: ok\n'
