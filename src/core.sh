#!/usr/bin/env bash
# MiLog — nginx + system monitor.
set -euo pipefail

# Defaults; the config file and MILOG_* env vars override them.
LOG_DIR="/var/log/nginx"
LOGS=()
REFRESH=5

# Alert destinations: every configured one fires; each no-ops when its settings are empty.
DISCORD_WEBHOOK=""
SLACK_WEBHOOK=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
MATRIX_HOMESERVER=""
MATRIX_TOKEN=""
MATRIX_ROOM=""

# Generic webhook. %TITLE% %BODY% %SEV% %RULE% are substituted as quoted JSON strings.
WEBHOOK_URL=""
WEBHOOK_TEMPLATE='{"title":%TITLE%,"body":%BODY%,"severity":%SEV%,"rule":%RULE%}'
WEBHOOK_CONTENT_TYPE="application/json"
ALERTS_ENABLED=0
PATTERNS_ENABLED=1
# FIM: the daemon rehashes AUDIT_FIM_PATHS every AUDIT_FIM_INTERVAL seconds; milog never sudoes for read access.
AUDIT_ENABLED=0
AUDIT_FIM_INTERVAL=3600
# Missing paths are baselined as absent, so a file that later appears alerts.
AUDIT_FIM_PATHS=(
    /etc/passwd
    /etc/shadow
    /etc/sudoers
    /etc/crontab
    /etc/ssh/sshd_config
    /etc/ld.so.preload
    /root/.ssh/authorized_keys
    /home/*/.ssh/authorized_keys
)
# New files in these paths alert; removed ones are only logged.
# Keep the globs quoted so they re-expand each tick instead of once at config-source time.
AUDIT_PERSISTENCE_INTERVAL=3600
AUDIT_PERSISTENCE_PATHS=(
    '/etc/cron.d/*'
    '/etc/cron.hourly/*'
    '/etc/cron.daily/*'
    '/etc/cron.weekly/*'
    '/etc/cron.monthly/*'
    '/var/spool/cron/crontabs/*'
    '/var/spool/cron/*'
    '/etc/systemd/system/*.service'
    '/etc/systemd/system/*.timer'
    '/etc/systemd/user/*.service'
    '/etc/systemd/user/*.timer'
    '/root/.config/systemd/user/*.service'
    '/root/.config/systemd/user/*.timer'
    '/home/*/.config/systemd/user/*.service'
    '/home/*/.config/systemd/user/*.timer'
    '/etc/rc.local'
    '/etc/ld.so.preload'
)
# New listeners alert, vanished ones don't; the key includes the bind address, so 127.0.0.1 -> 0.0.0.0 fires too.
AUDIT_PORTS_INTERVAL=3600
# YARA is opt-in: no scan until AUDIT_YARA_PATHS is set, and it no-ops without the yara binary.
AUDIT_YARA_INTERVAL=86400
AUDIT_YARA_RULES_DIR="$HOME/.config/milog/yara"
AUDIT_YARA_PATHS=()
# Line-level diff: added users, sudo grants and SSH keys alert; removed lines don't. Globs stay quoted like the persistence list.
AUDIT_ACCOUNTS_INTERVAL=3600
AUDIT_ACCOUNTS_PATHS=(
    '/etc/passwd'
    '/etc/sudoers'
    '/etc/sudoers.d/*'
    '/root/.ssh/authorized_keys'
    '/root/.ssh/authorized_keys2'
    '/home/*/.ssh/authorized_keys'
    '/home/*/.ssh/authorized_keys2'
)
# Rootkit heuristics need no baseline and no-op where /proc is missing.
AUDIT_ROOTKIT_INTERVAL=3600
ALERT_COOLDOWN=300
# How long one (ip, path) event stays "already reported" across different rules.
ALERT_DEDUP_WINDOW=300
ALERT_STATE_DIR="$HOME/.cache/milog"
# alerts.log is truncated in place to about its newest half past this size; 0 disables rotation.
ALERT_LOG_MAX_BYTES=10485760  # 10 MB

# Every executable in HOOKS_DIR/on_alert.d/ runs per fire (after the silence gate) with MILOG_* env;
# failures go to hooks.log and each run is capped at ALERT_HOOK_TIMEOUT seconds.
HOOKS_DIR="$HOME/.config/milog/hooks"
ALERT_HOOK_TIMEOUT=10

# Detection regexes for exploits/probes; `milog update-rules` writes this file, and without it the built-in copy applies.
RULES_FILE="$HOME/.config/milog/rules.tsv"

# Per-rule destinations, one `key: dest ...` per line; lookup is exact rule, then prefix before `:`, then `default`.
# Destinations: discord slack telegram matrix webhook, or `skip`; empty fans out to everything.
#   ALERT_ROUTES="
#     exploit:  slack telegram
#     probe:    skip
#     default:  discord
#   "
ALERT_ROUTES=""

# p95 colour thresholds in ms; needs $request_time in the nginx log format.
P95_WARN_MS=500
P95_CRIT_MS=1500

# Lines per app that `milog slow` reads from the tail.
SLOW_WINDOW=1000

# WebSocket $request_time is the whole session, so these paths would top `slow` and `top-paths`; "" includes them.
SLOW_EXCLUDE_PATHS="/ws/* /socket.io/*"

# GeoIP needs mmdblookup and a GeoLite2-Country MMDB.
GEOIP_ENABLED=0
MMDB_PATH="/var/lib/GeoIP/GeoLite2-Country.mmdb"

# CrowdSec CTI reputation lookups; empty means milog never contacts the API.
CROWDSEC_CTI_KEY=""

# History needs sqlite3; the daemon writes one row per app per minute.
HISTORY_ENABLED=0
HISTORY_DB="$HOME/.local/share/milog/metrics.db"
HISTORY_RETAIN_DAYS=30
HISTORY_TOP_IP_N=50

# Fires anomaly:<app>:<metric> when a metric exceeds mean + ANOMALY_SIGMA*stddev for that minute of day
# and its floor, but only after ANOMALY_MIN_DAYS days of history.
ANOMALY_ENABLED=0
ANOMALY_SIGMA=3
ANOMALY_MIN_DAYS=14
ANOMALY_FLOOR_REQ=10
ANOMALY_FLOOR_C5XX=2
ANOMALY_FLOOR_P95=100

# milog-web binds loopback; non-loopback needs --trust. 8765 avoids the usual 8080 collisions.
WEB_PORT=8765
WEB_BIND="127.0.0.1"
WEB_STATE_DIR="$HOME/.cache/milog"
WEB_TOKEN_FILE="$HOME/.config/milog/web.token"

MILOG_CONFIG="${MILOG_CONFIG:-$HOME/.config/milog/config.sh}"

# True when root owns the path and its directory and neither is group/other-writable.
_root_trusted_path() {
    local p meta
    for p in "$1" "$(dirname "$1")"; do
        meta=$(stat -c '%u %a' "$p" 2>/dev/null || stat -f '%u %Lp' "$p" 2>/dev/null) || return 1
        [[ "${meta%% *}" == 0 ]] && (( (8#${meta#* } & 8#022) == 0 )) || return 1
    done
}

if [[ -f "$MILOG_CONFIG" ]]; then
    if [[ $EUID -ne 0 ]] || _root_trusted_path "$MILOG_CONFIG"; then
        # shellcheck disable=SC1090
        . "$MILOG_CONFIG"
    else
        echo "milog: running as root, refusing to source $MILOG_CONFIG (not root-owned or group/other-writable)" >&2
    fi
fi

# MILOG_* env vars win over the config file.
[[ -n "${MILOG_LOG_DIR:-}"         ]] && LOG_DIR="$MILOG_LOG_DIR"
[[ -n "${MILOG_APPS:-}"            ]] && read -r -a LOGS <<< "$MILOG_APPS"
[[ -n "${MILOG_REFRESH:-}"         ]] && REFRESH="$MILOG_REFRESH"
[[ -n "${MILOG_DISCORD_WEBHOOK:-}" ]] && DISCORD_WEBHOOK="$MILOG_DISCORD_WEBHOOK"
[[ -n "${MILOG_ALERTS_ENABLED:-}"  ]] && ALERTS_ENABLED="$MILOG_ALERTS_ENABLED"
[[ -n "${MILOG_PATTERNS_ENABLED:-}" ]] && PATTERNS_ENABLED="$MILOG_PATTERNS_ENABLED"
[[ -n "${MILOG_AUDIT_ENABLED:-}"    ]] && AUDIT_ENABLED="$MILOG_AUDIT_ENABLED"
[[ -n "${MILOG_AUDIT_FIM_INTERVAL:-}" ]] && AUDIT_FIM_INTERVAL="$MILOG_AUDIT_FIM_INTERVAL"
[[ -n "${MILOG_AUDIT_PERSISTENCE_INTERVAL:-}" ]] && AUDIT_PERSISTENCE_INTERVAL="$MILOG_AUDIT_PERSISTENCE_INTERVAL"
[[ -n "${MILOG_AUDIT_PORTS_INTERVAL:-}" ]] && AUDIT_PORTS_INTERVAL="$MILOG_AUDIT_PORTS_INTERVAL"
[[ -n "${MILOG_AUDIT_YARA_INTERVAL:-}"  ]] && AUDIT_YARA_INTERVAL="$MILOG_AUDIT_YARA_INTERVAL"
[[ -n "${MILOG_AUDIT_YARA_RULES_DIR:-}" ]] && AUDIT_YARA_RULES_DIR="$MILOG_AUDIT_YARA_RULES_DIR"
[[ -n "${MILOG_AUDIT_YARA_PATHS:-}"     ]] && read -r -a AUDIT_YARA_PATHS <<< "$MILOG_AUDIT_YARA_PATHS"
[[ -n "${MILOG_AUDIT_ACCOUNTS_INTERVAL:-}" ]] && AUDIT_ACCOUNTS_INTERVAL="$MILOG_AUDIT_ACCOUNTS_INTERVAL"
[[ -n "${MILOG_AUDIT_ACCOUNTS_PATHS:-}"    ]] && read -r -a AUDIT_ACCOUNTS_PATHS <<< "$MILOG_AUDIT_ACCOUNTS_PATHS"
[[ -n "${MILOG_AUDIT_ROOTKIT_INTERVAL:-}"  ]] && AUDIT_ROOTKIT_INTERVAL="$MILOG_AUDIT_ROOTKIT_INTERVAL"
[[ -n "${MILOG_ALERT_COOLDOWN:-}"  ]] && ALERT_COOLDOWN="$MILOG_ALERT_COOLDOWN"
[[ -n "${MILOG_ALERT_DEDUP_WINDOW:-}" ]] && ALERT_DEDUP_WINDOW="$MILOG_ALERT_DEDUP_WINDOW"
[[ -n "${MILOG_ALERT_LOG_MAX_BYTES:-}" ]] && ALERT_LOG_MAX_BYTES="$MILOG_ALERT_LOG_MAX_BYTES"
[[ -n "${MILOG_HOOKS_DIR:-}"           ]] && HOOKS_DIR="$MILOG_HOOKS_DIR"
[[ -n "${MILOG_ALERT_HOOK_TIMEOUT:-}"  ]] && ALERT_HOOK_TIMEOUT="$MILOG_ALERT_HOOK_TIMEOUT"
[[ -n "${MILOG_ALERT_ROUTES+x}"         ]] && ALERT_ROUTES="$MILOG_ALERT_ROUTES"
[[ -n "${MILOG_WEBHOOK_URL:-}"          ]] && WEBHOOK_URL="$MILOG_WEBHOOK_URL"
[[ -n "${MILOG_WEBHOOK_TEMPLATE+x}"     ]] && WEBHOOK_TEMPLATE="$MILOG_WEBHOOK_TEMPLATE"
[[ -n "${MILOG_WEBHOOK_CONTENT_TYPE:-}" ]] && WEBHOOK_CONTENT_TYPE="$MILOG_WEBHOOK_CONTENT_TYPE"
[[ -n "${MILOG_SLACK_WEBHOOK:-}"      ]] && SLACK_WEBHOOK="$MILOG_SLACK_WEBHOOK"
[[ -n "${MILOG_TELEGRAM_BOT_TOKEN:-}" ]] && TELEGRAM_BOT_TOKEN="$MILOG_TELEGRAM_BOT_TOKEN"
[[ -n "${MILOG_TELEGRAM_CHAT_ID:-}"   ]] && TELEGRAM_CHAT_ID="$MILOG_TELEGRAM_CHAT_ID"
[[ -n "${MILOG_MATRIX_HOMESERVER:-}"  ]] && MATRIX_HOMESERVER="$MILOG_MATRIX_HOMESERVER"
[[ -n "${MILOG_MATRIX_TOKEN:-}"       ]] && MATRIX_TOKEN="$MILOG_MATRIX_TOKEN"
[[ -n "${MILOG_MATRIX_ROOM:-}"        ]] && MATRIX_ROOM="$MILOG_MATRIX_ROOM"
[[ -n "${MILOG_GEOIP_ENABLED:-}"   ]] && GEOIP_ENABLED="$MILOG_GEOIP_ENABLED"
[[ -n "${MILOG_MMDB_PATH:-}"       ]] && MMDB_PATH="$MILOG_MMDB_PATH"
[[ -n "${MILOG_CROWDSEC_CTI_KEY:-}" ]] && CROWDSEC_CTI_KEY="$MILOG_CROWDSEC_CTI_KEY"
[[ -n "${MILOG_HISTORY_ENABLED:-}" ]] && HISTORY_ENABLED="$MILOG_HISTORY_ENABLED"
[[ -n "${MILOG_HISTORY_DB:-}"      ]] && HISTORY_DB="$MILOG_HISTORY_DB"
[[ -n "${MILOG_ANOMALY_ENABLED:-}"   ]] && ANOMALY_ENABLED="$MILOG_ANOMALY_ENABLED"
[[ -n "${MILOG_ANOMALY_SIGMA:-}"     ]] && ANOMALY_SIGMA="$MILOG_ANOMALY_SIGMA"
[[ -n "${MILOG_ANOMALY_MIN_DAYS:-}"  ]] && ANOMALY_MIN_DAYS="$MILOG_ANOMALY_MIN_DAYS"
[[ -n "${MILOG_ANOMALY_FLOOR_REQ:-}"  ]] && ANOMALY_FLOOR_REQ="$MILOG_ANOMALY_FLOOR_REQ"
[[ -n "${MILOG_ANOMALY_FLOOR_C5XX:-}" ]] && ANOMALY_FLOOR_C5XX="$MILOG_ANOMALY_FLOOR_C5XX"
[[ -n "${MILOG_ANOMALY_FLOOR_P95:-}"  ]] && ANOMALY_FLOOR_P95="$MILOG_ANOMALY_FLOOR_P95"
[[ -n "${MILOG_WEB_PORT:-}"        ]] && WEB_PORT="$MILOG_WEB_PORT"
[[ -n "${MILOG_WEB_BIND:-}"        ]] && WEB_BIND="$MILOG_WEB_BIND"
[[ -n "${MILOG_SLOW_EXCLUDE_PATHS+x}" ]] && SLOW_EXCLUDE_PATHS="$MILOG_SLOW_EXCLUDE_PATHS"

if [[ ${#LOGS[@]} -eq 0 ]]; then
    shopt -s nullglob
    for f in "$LOG_DIR"/*.access.log; do
        name="${f##*/}"; name="${name%.access.log}"
        LOGS+=("$name")
    done
    shopt -u nullglob
fi

# LOGS entries: bare `api` or `nginx:api` read $LOG_DIR/api.access.log; `text:<name>:<path>`,
# `journal:<unit>` and `docker:<container>` are also accepted.
# Only parser-free modes (logs, grep, search, tail) handle every type; digest is the only parsing mode that skips non-nginx entries.

# `journal:` and `docker:` have no fixed path; read through _log_reader_cmd instead.
_log_path_for() {
    local entry="${1-}"
    case "$entry" in
        text:*:*)   printf '%s' "${entry#text:*:}" ;;
        nginx:*)    printf '%s/%s.access.log' "$LOG_DIR" "${entry#nginx:}" ;;
        journal:*)  printf '' ;;                           # no file
        docker:*)   _log_docker_path "${entry#docker:}" ;; # looked up
        *)          printf '%s/%s.access.log' "$LOG_DIR" "$entry" ;;
    esac
}

_log_type_for() {
    case "${1-}" in
        text:*)     printf 'text' ;;
        nginx:*)    printf 'nginx' ;;
        journal:*)  printf 'journal' ;;
        docker:*)   printf 'docker' ;;
        *)          printf 'nginx' ;;
    esac
}

_log_name_for() {
    local entry="${1-}"
    case "$entry" in
        text:*:*)   local rest="${entry#text:}"; printf '%s' "${rest%%:*}" ;;
        nginx:*)    printf '%s' "${entry#nginx:}" ;;
        journal:*)  printf '%s' "${entry#journal:}" ;;
        docker:*)   printf '%s' "${entry#docker:}" ;;
        *)          printf '%s' "$entry" ;;
    esac
}

_log_entry_by_name() {
    local target="${1-}" entry
    for entry in "${LOGS[@]}"; do
        if [[ "$(_log_name_for "$entry")" == "$target" ]]; then
            printf '%s' "$entry"
            return 0
        fi
    done
    return 1
}

# Empty output means the container isn't running or can't be found.
_log_docker_path() {
    local name="${1:-}"
    [[ -z "$name" ]] && return 0
    if command -v docker >/dev/null 2>&1; then
        local path
        path=$(docker inspect --format '{{.LogPath}}' "$name" 2>/dev/null)
        [[ -n "$path" && -r "$path" ]] && { printf '%s' "$path"; return 0; }
    fi
# Reading /var/lib/docker directly works when the docker socket isn't accessible.
    local default_root="${MILOG_DOCKER_ROOT:-/var/lib/docker}"
    [[ -d "$default_root/containers" ]] || return 0
    local cfg cid
    # shellcheck disable=SC2044
    for cfg in "$default_root"/containers/*/config.v2.json; do
        [[ -r "$cfg" ]] || continue
        if grep -q "\"Name\":\"/$name\"" "$cfg" 2>/dev/null \
           || grep -q "\"Name\":\"$name\"" "$cfg" 2>/dev/null; then
            cid=$(basename "$(dirname "$cfg")")
            local log_path="$default_root/containers/$cid/$cid-json.log"
            [[ -r "$log_path" ]] && { printf '%s' "$log_path"; return 0; }
        fi
    done
    return 0
}

# Prints a shell command that streams raw lines for the entry; returns 1 when it can't be resolved.
# Unavailable journal/docker sources print a `#` diagnostic line instead of hanging the caller.
_log_reader_cmd() {
    local entry="${1:-}"
    local type; type=$(_log_type_for "$entry")
    case "$type" in
        nginx|text)
            local path; path=$(_log_path_for "$entry")
            [[ -n "$path" ]] || return 1
            printf 'tail -F -n 0 %q 2>/dev/null' "$path"
            ;;
        journal)
            local unit; unit=$(_log_name_for "$entry")
            if ! command -v journalctl >/dev/null 2>&1; then
                printf "printf '#journal unavailable: journalctl not on PATH\\n'"
                return 0
            fi
            printf 'journalctl -u %q -f --no-pager --since now -o short-iso 2>/dev/null' "$unit"
            ;;
        docker)
            local path; path=$(_log_path_for "$entry")
            if [[ -z "$path" ]]; then
                printf "printf '#docker unavailable: container %s not found\\n'" \
                    "$(_log_name_for "$entry")"
                return 0
            fi
# The sed fallback mangles payloads with embedded quotes or backslashes.
            if command -v jq >/dev/null 2>&1; then
                printf 'tail -F -n 0 %q 2>/dev/null | jq -rj .log 2>/dev/null' "$path"
            else
                printf 'tail -F -n 0 %q 2>/dev/null | sed -E %q' "$path" \
                    's/^\{"log":"(.*)","stream".*/\1/; s/\\n$//; s/\\"/"/g; s/\\\\/\\/g'
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

THRESH_REQ_WARN=15
THRESH_REQ_CRIT=40
THRESH_CPU_WARN=70
THRESH_CPU_CRIT=90
THRESH_MEM_WARN=80
THRESH_MEM_CRIT=95
THRESH_DISK_WARN=80
THRESH_DISK_CRIT=95
THRESH_4XX_WARN=20
THRESH_5XX_WARN=5
THRESH_AICRAWL_WARN=30

# Sparkline history depth (samples kept per app in monitor mode)
SPARK_LEN=30

# Looks up `<var>_<app>` (non [A-Za-z0-9_] chars become `_`) before the global, e.g. THRESH_REQ_CRIT_api.
_thresh() {
    local var="$1" app="${2:-}"
    if [[ -n "$app" ]]; then
        local safe="${app//[^A-Za-z0-9_]/_}"
        local per="${var}_${safe}"
        if [[ -n "${!per:-}" ]]; then
            printf '%s' "${!per}"
            return 0
        fi
    fi
    printf '%s' "${!var:-0}"
}

R="\033[0;31m"  G="\033[0;32m"  Y="\033[0;33m"  B="\033[0;34m"
M="\033[0;35m"  C="\033[0;36m"  W="\033[1;37m"  D="\033[0;90m"
RBLINK="\033[0;31;5m"
NC="\033[0m"
