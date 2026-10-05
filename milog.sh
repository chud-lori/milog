#!/usr/bin/env bash
# MILOG_VERSION=v0.6.0-132-gf4f08ca
# MILOG_BUILT=2026-10-05T03:09:12Z
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
# Alert delivery, silences, routing, cooldown and dedup.

# Output includes the surrounding double quotes.
json_escape() {
    local s="${1-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\b'/\\b}"
    s="${s//$'\f'/\\f}"
    # Remaining C0 controls as \u00XX; NUL can't occur in a bash string.
    if [[ "$s" == *[[:cntrl:]]* ]]; then
        local i h c u
        for (( i=1; i<32; i++ )); do
            printf -v h '%02x' "$i"
            printf -v c "\\x$h"
            printf -v u '\\u00%s' "$h"
            s="${s//"$c"/"$u"}"
        done
    fi
    printf '"%s"' "$s"
}

# Code-fence text; backticks become ' so a log line can't close the fence.
_alert_fence() {
    local s="${1-}"
    printf '```%s```' "${s//\`/\'}"
}

# No surrounding quotes. Keeps log text from injecting tags into Telegram/Matrix HTML.
html_escape() {
    local s="${1-}"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    printf '%s' "$s"
}

# Matrix room IDs contain `!` and `:`, which must be encoded in the PUT path.
_url_encode() {
    local s="${1-}" out="" i c
    for (( i=0; i<${#s}; i++ )); do
        c="${s:$i:1}"
        case "$c" in
            [a-zA-Z0-9._~-]) out+="$c" ;;
            *)               out+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    printf '%s' "$out"
}

# Truncates to about the newest half of ALERT_LOG_MAX_BYTES; never fails the alert path.
_alert_rotate_if_big() {
    local f="$1"
    local max="${ALERT_LOG_MAX_BYTES:-10485760}"
    [[ "$max" =~ ^[0-9]+$ ]] && (( max > 0 )) || return 0
    [[ -f "$f" ]] || return 0
    local sz
    # GNU stat (-c) vs BSD stat (-f). Both harmless-fail on missing file.
    sz=$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f" 2>/dev/null) || return 0
    [[ "$sz" =~ ^[0-9]+$ ]] || return 0
    (( sz > max )) || return 0
    local half=$(( max / 2 )) tmp
    tmp=$(mktemp "${f}.rot.XXXXXX" 2>/dev/null) || return 0
    # tail -c lands mid-line, so drop the first partial record.
    tail -c "$half" "$f" 2>/dev/null | tail -n +2 > "$tmp" 2>/dev/null
    mv "$tmp" "$f" 2>/dev/null || rm -f "$tmp"
}

# alerts.log is TSV: epoch, rule_key, color, title, body (tabs/newlines flattened, 300 chars max).
_alert_record() {
    local log_file="$ALERT_STATE_DIR/alerts.log"
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 0
    local now; now=$(date +%s)
    local body="${3:-}"
    body="${body//$'\t'/ }"
    body="${body//$'\r'/ }"
    body="${body//$'\n'/ }"
    body="${body:0:300}"
    printf '%s\t%s\t%s\t%s\t%s\n' "$now" "${1:-unknown}" "${4:-0}" "${2:-?}" "$body" \
        >> "$log_file" 2>/dev/null || true
    _alert_rotate_if_big "$log_file"
}

# Log a failed delivery (network or HTTP >= 400) for `milog doctor`; status 000 means no HTTP response.
_alert_send_failed() {
    local log_file="$ALERT_STATE_DIR/send_failures.log"
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 0
    printf '%s\t%s\t%s\n' "$(date +%s)" "${1:-unknown}" "${2:-000}" >> "$log_file" 2>/dev/null || true
    _alert_rotate_if_big "$log_file"
}

# _alert_post <dest> <curl args...>. A 429 is retried once when the server asks to wait 5s or less.
_alert_post() {
    local dest="$1"; shift
    local out code wait try
    for try in 1 2; do
        out=$(curl -sS -m 5 -i -w '\n%{http_code}' "$@" 2>/dev/null) || :
        code="${out##*$'\n'}"
        [[ "$code" == 429 && "$try" == 1 ]] || break
        wait=$(printf '%s\n' "$out" | sed -n -E \
            -e '/"retry_after": *[0-9]/{s/.*"retry_after": *([0-9][0-9.]*).*/\1/p;q;}' \
            -e '/^[Rr]etry-[Aa]fter: *[0-9]/{s/^[^:]*: *([0-9][0-9.]*).*/\1/p;q;}') || :
        # A string match, since arithmetic on a server-supplied number can overflow.
        [[ "$wait" =~ ^([0-4](\.[0-9]+)?|5(\.0+)?)$ ]] || break
        sleep "$wait" || break
    done
    [[ "$code" =~ ^[1-3][0-9][0-9]$ ]] || _alert_send_failed "$dest" "$code"
}

# Senders return 0 when unconfigured and post through _alert_post, which records failures.
# The body carries attacker-controlled log text, so each sender escapes it and disables mentions where the API allows.

# allowed_mentions.parse=[] stops @everyone / role pings.
_alert_send_discord() {
    [[ -z "${DISCORD_WEBHOOK:-}" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}"
    local payload
    payload=$(printf '{"embeds":[{"title":%s,"description":%s,"color":%d}],"allowed_mentions":{"parse":[]}}' \
        "$(json_escape "$title")" "$(json_escape "$body")" "$color")
    _alert_post discord -H "Content-Type: application/json" \
         -d "$payload" "$DISCORD_WEBHOOK"
}

# link_names=0 keeps `<@channel>` literal; the body goes in a code block with backticks swapped for single quotes.
_alert_send_slack() {
    [[ -z "${SLACK_WEBHOOK:-}" ]] && return 0
    local title="$1" body="$2"
    local text
    text="*$(json_escape "$title" | sed 's/^"//; s/"$//')*\n\`\`\`$(printf '%s' "$body" | sed 's/`/'\''/g')\`\`\`"
    local payload
    payload=$(printf '{"text":%s,"mrkdwn":true,"link_names":0}' \
        "$(json_escape "$text")")
    _alert_post slack -H "Content-Type: application/json" \
         -d "$payload" "$SLACK_WEBHOOK"
}

# parse_mode=HTML, so every value goes through html_escape.
_alert_send_telegram() {
    [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]] && return 0
    local title="$1" body="$2"
    local safe_title safe_body
    safe_title=$(html_escape "$title")
    safe_body=$(html_escape "$body")
    local text="<b>${safe_title}</b>
<pre>${safe_body}</pre>"
    local payload
    payload=$(printf '{"chat_id":%s,"text":%s,"parse_mode":"HTML","disable_web_page_preview":true,"disable_notification":false}' \
        "$(json_escape "$TELEGRAM_CHAT_ID")" "$(json_escape "$text")")
    _alert_post telegram -H "Content-Type: application/json" \
         -d "$payload" "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
}

# Free-form POST driven by WEBHOOK_TEMPLATE; the color-to-severity mapping matches alerts.log.
_alert_send_webhook() {
    [[ -z "${WEBHOOK_URL:-}" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}"
    local sev
    case "$color" in
        15158332|16711680)  sev=crit ;;
        16753920|15844367)  sev=warn ;;
        *)                  sev=info ;;
    esac
    # Single pass, so a placeholder inside a substituted value stays literal.
    local rest="${WEBHOOK_TEMPLATE:-\"%TITLE%\"}" payload=""
    while [[ "$rest" == *%* ]]; do
        payload+="${rest%%\%*}"
        rest="${rest#*\%}"
        case "$rest" in
            TITLE%*) payload+=$(json_escape "$title");    rest="${rest#TITLE%}" ;;
            BODY%*)  payload+=$(json_escape "$body");     rest="${rest#BODY%}" ;;
            SEV%*)   payload+=$(json_escape "$sev");      rest="${rest#SEV%}" ;;
            RULE%*)  payload+=$(json_escape "$rule_key"); rest="${rest#RULE%}" ;;
            *)       payload+='%' ;;
        esac
    done
    payload+="$rest"
    local ctype="${WEBHOOK_CONTENT_TYPE:-application/json}"
    _alert_post webhook -H "Content-Type: ${ctype}" \
         -d "$payload" "$WEBHOOK_URL"
}

# Room IDs are percent-encoded; the txn id only needs to be unique within the server's dedup window.
_alert_send_matrix() {
    [[ -z "${MATRIX_HOMESERVER:-}" || -z "${MATRIX_TOKEN:-}" || -z "${MATRIX_ROOM:-}" ]] && return 0
    local title="$1" body="$2"
    local safe_title safe_body
    safe_title=$(html_escape "$title")
    safe_body=$(html_escape "$body")
    local formatted="<b>${safe_title}</b><br/><pre>${safe_body}</pre>"
    local plain="${title}

${body}"
    local payload
    payload=$(printf '{"msgtype":"m.text","body":%s,"format":"org.matrix.custom.html","formatted_body":%s}' \
        "$(json_escape "$plain")" "$(json_escape "$formatted")")
    local room_enc txn_id
    room_enc=$(_url_encode "$MATRIX_ROOM")
    txn_id="milog-$(date +%s)-$RANDOM"
    local hs="${MATRIX_HOMESERVER%/}"
    _alert_post matrix -X PUT \
         -H "Authorization: Bearer ${MATRIX_TOKEN}" \
         -H "Content-Type: application/json" \
         -d "$payload" \
         "${hs}/_matrix/client/v3/rooms/${room_enc}/send/m.room.message/${txn_id}"
}

# Silences: explicit mutes that outrank cooldown and dedup.
# alerts.silences rows: key-or-glob, until, added, added_by, message. Expired rows are pruned lazily.

# 30s / 5m / 2h / 1d (or bare seconds) -> seconds, up to 3650d; returns 1 on bad input.
alert_silence_parse_duration() {
    local s="${1:-}" n unit=1
    # `${unit,,}` is bash 4+ only.
    case "$s" in
        *[sS]) n="${s%?}" ;;
        *[mM]) n="${s%?}" unit=60 ;;
        *[hH]) n="${s%?}" unit=3600 ;;
        *[dD]) n="${s%?}" unit=86400 ;;
        *)     n="$s" ;;
    esac
    # At most nine significant digits, so the multiply can't overflow.
    [[ "$n" =~ ^0*([0-9]{1,9})$ ]] || return 1
    n=$(( 10#${BASH_REMATCH[1]} * unit ))
    (( n <= 3650 * 86400 )) || return 1
    printf '%s' "$n"
}

# Prints the matching row; `[[ == $key ]]` is a glob match, so `exploit:*` covers every exploit rule.
alert_is_silenced() {
    local rule="${1:-}"
    [[ -n "$rule" ]] || return 1
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 1
    local now; now=$(date +%s)
    local key until_epoch added_epoch added_by message
    while IFS=$'\t' read -r key until_epoch added_epoch added_by message; do
        [[ -z "$key" ]] && continue
        [[ "$until_epoch" =~ ^[0-9]+$ ]] || continue
        (( until_epoch > now )) || continue
        # shellcheck disable=SC2053
        if [[ "$rule" == "$key" || "$rule" == $key ]]; then
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$key" "$until_epoch" "$added_epoch" "$added_by" "$message"
            return 0
        fi
    done < "$f"
    return 1
}

# Replaces any row for the same key, so re-silencing extends instead of stacking.
alert_silence_add() {
    local key="$1" duration_seconds="$2" message="${3:-}"
    local f="$ALERT_STATE_DIR/alerts.silences"
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 1
    local now until_epoch who
    now=$(date +%s)
    until_epoch=$(( now + duration_seconds ))
    who="${USER:-$(id -un 2>/dev/null || echo unknown)}"
    message="${message//$'\t'/ }"
    message="${message//$'\r'/ }"
    message="${message//$'\n'/ }"
    message="${message:0:200}"
    local tmp
    tmp=$(mktemp "$f.add.XXXXXX" 2>/dev/null) || return 1
    {
        # Also drops expired rows so the file doesn't grow.
        awk -F'\t' -v k="$key" -v now="$now" 'BEGIN{OFS="\t"} $1 != k && $2+0 > now' \
            "$f" 2>/dev/null
        printf '%s\t%s\t%s\t%s\t%s\n' "$key" "$until_epoch" "$now" "$who" "$message"
    } > "$tmp" && mv "$tmp" "$f" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    printf '%s' "$until_epoch"
}

# Returns 1 when no row matched.
alert_silence_remove() {
    local key="$1"
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 1
    # awk field compare instead of grep with a literal tab, which BSD grep handles differently.
    awk -F'\t' -v k="$key" 'BEGIN{found=1} $1==k {found=0; exit} END{exit found}' \
        "$f" 2>/dev/null \
        || return 1
    local tmp
    tmp=$(mktemp "$f.rm.XXXXXX" 2>/dev/null) || return 1
    awk -F'\t' -v k="$key" 'BEGIN{OFS="\t"} $1 != k' "$f" 2>/dev/null > "$tmp" \
        && mv "$tmp" "$f" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    return 0
}

# Raw TSV, newest first.
alert_silence_list_active() {
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 0
    local now; now=$(date +%s)
    awk -F'\t' -v now="$now" 'BEGIN{OFS="\t"} $2+0 > now' "$f" 2>/dev/null \
        | sort -t $'\t' -k3,3 -rn
}

# Destinations for a rule from ALERT_ROUTES: exact key, then prefix before `:`, then `default`.
# Empty output means fan out to every configured destination.
_alert_route_for() {
    local rule_key="${1:-}"
    local routes="${ALERT_ROUTES:-}"
    [[ -z "$routes" ]] && return 0     # unset → empty → fan-out path

    local prefix="${rule_key%%:*}"
    local default_val="" exact_val="" prefix_val=""
    local line key val

    # The first occurrence of each key wins.
    while IFS= read -r line; do
        line="${line%%#*}"
        # trim whitespace both sides
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        # Split on the first ": " so keys like `disk:/` keep their colon.
        if [[ "$line" == *": "* ]]; then
            key="${line%%: *}"
            val="${line#*: }"
        else
            # Tolerate `key:value` without space too.
            key="${line%%:*}"
            val="${line#*:}"
            val="${val# }"
        fi
        # trim both sides (value can still have trailing whitespace)
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        val="${val#"${val%%[![:space:]]*}"}"
        val="${val%"${val##*[![:space:]]}"}"

        if   [[ "$key" == "default" ]]; then
            [[ -z "$default_val" ]] && default_val="$val"
        elif [[ "$key" == "$rule_key" ]]; then
            [[ -z "$exact_val"   ]] && exact_val="$val"
        elif [[ "$key" == "$prefix" ]]; then
            [[ -z "$prefix_val"  ]] && prefix_val="$val"
        fi
    done <<< "$routes"

    if   [[ -n "$exact_val"   ]]; then printf '%s' "$exact_val"
    elif [[ -n "$prefix_val"  ]]; then printf '%s' "$prefix_val"
    elif [[ -n "$default_val" ]]; then printf '%s' "$default_val"
    fi
}

# Runs every executable in HOOKS_DIR/on_alert.d/ in the background with MILOG_RULE_KEY, MILOG_TITLE, MILOG_BODY,
# MILOG_SEV, MILOG_COLOR, MILOG_TS and MILOG_IP set. Non-zero exits are logged to hooks.log, never propagated.
_alert_run_hooks() {
    local hook_dir="${HOOKS_DIR:-$HOME/.config/milog/hooks}/on_alert.d"
    [[ -d "$hook_dir" ]] || return 0

    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}" ip="${5:-}"
    local sev
    case "$color" in
        15158332|16711680)  sev=crit ;;
        16753920|15844367)  sev=warn ;;
        *)                  sev=info ;;
    esac

    local hook_log="${ALERT_STATE_DIR:-$HOME/.cache/milog}/hooks.log"
    mkdir -p "$(dirname "$hook_log")" 2>/dev/null || true
    local ts; ts=$(date +%s)
    local timeout_s="${ALERT_HOOK_TIMEOUT:-10}"
    local have_timeout=0
    command -v timeout >/dev/null 2>&1 && have_timeout=1

    local hook
    # Glob order lets users prefix names with numbers to order hooks.
    for hook in "$hook_dir"/*; do
        [[ -x "$hook" && -f "$hook" ]] || continue
        (
            local rc out
            if (( have_timeout )); then
                out=$(MILOG_RULE_KEY="$rule_key" \
                      MILOG_TITLE="$title"       \
                      MILOG_BODY="$body"         \
                      MILOG_SEV="$sev"           \
                      MILOG_COLOR="$color"       \
                      MILOG_TS="$ts"             \
                      MILOG_IP="$ip"             \
                      timeout "$timeout_s" "$hook" 2>&1)
                rc=$?
            else
                out=$(MILOG_RULE_KEY="$rule_key" \
                      MILOG_TITLE="$title"       \
                      MILOG_BODY="$body"         \
                      MILOG_SEV="$sev"           \
                      MILOG_COLOR="$color"       \
                      MILOG_TS="$ts"             \
                      MILOG_IP="$ip"             \
                      "$hook" 2>&1)
                rc=$?
            fi
            if (( rc != 0 )); then
                # TSV row: epoch \t hook-basename \t exit-code \t output-first-line
                local base; base=$(basename "$hook")
                local first; first=$(printf '%s' "$out" | head -1 | tr -d '\t\r')
                printf '%s\t%s\t%d\t%s\n' "$ts" "$base" "$rc" "${first:0:200}" \
                    >> "$hook_log" 2>/dev/null || true
            fi
        ) &
    done
}

# alert_fire <title> <body> [color] [rule_key] [ip]. Each destination is sent in the background; ip only reaches hooks.
alert_fire() {
    [[ "${ALERTS_ENABLED:-0}" != "1" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}" ip="${5:-}"
    # Silenced fires are not recorded either; the silence row is the audit trail.
    if [[ -n "$rule_key" ]] && alert_is_silenced "$rule_key" >/dev/null; then
        return 0
    fi
    # Record first so the log has the fire even if delivery fails.
    _alert_record "$rule_key" "$title" "$body" "$color"

    # Hooks run before the curl check; they don't need it.
    _alert_run_hooks "$title" "$body" "$color" "$rule_key" "$ip"

    command -v curl >/dev/null 2>&1 || return 0

    local route
    route=$(_alert_route_for "$rule_key")

    if [[ -z "$route" ]]; then
        _alert_send_discord  "$title" "$body" "$color" &
        _alert_send_slack    "$title" "$body" "$color" &
        _alert_send_telegram "$title" "$body" "$color" &
        _alert_send_matrix   "$title" "$body" "$color" &
        _alert_send_webhook  "$title" "$body" "$color" "$rule_key" &
        return 0
    fi

    # Unknown destination names are ignored; `skip` still records to alerts.log but sends nothing.
    local dest
    for dest in $route; do
        case "$dest" in
            discord)   _alert_send_discord  "$title" "$body" "$color" & ;;
            slack)     _alert_send_slack    "$title" "$body" "$color" & ;;
            telegram)  _alert_send_telegram "$title" "$body" "$color" & ;;
            matrix)    _alert_send_matrix   "$title" "$body" "$color" & ;;
            webhook)   _alert_send_webhook  "$title" "$body" "$color" "$rule_key" & ;;
            skip|none) : ;;
            *)         : ;;   # unknown type — silently drop (forward-compat)
        esac
    done
}

# Old name for alert_fire.
alert_discord() { alert_fire "$@"; }

# Redacted previews for `alert status` and `config`: enough to identify the target, never the secret.

_alert_redact_discord() {
    local w="${1:-}"
    [[ -z "$w" ]] && return 0
    if [[ "$w" =~ ^(https?://[^/]+/api/webhooks/[0-9]+/).* ]]; then
        printf '%s****' "${BASH_REMATCH[1]}"
    else
        printf '%.40s…' "$w"
    fi
}

_alert_redact_slack() {
    local w="${1:-}"
    [[ -z "$w" ]] && return 0
    # Slack: https://hooks.slack.com/services/T<workspace>/B<webhook>/<secret>
    if [[ "$w" =~ ^(https?://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/).* ]]; then
        printf '%s****' "${BASH_REMATCH[1]}"
    else
        printf '%.40s…' "$w"
    fi
}

_alert_redact_telegram() {
    local token="${1:-}" chat="${2:-}"
    [[ -z "$token" || -z "$chat" ]] && return 0
    # The bot id is visible to anyone who messages the bot; only the secret is masked.
    local bot_id="${token%%:*}"
    printf 'bot%s:**** chat=%s' "$bot_id" "$chat"
}

_alert_redact_matrix() {
    local hs="${1:-}" token="${2:-}" room="${3:-}"
    [[ -z "$hs" || -z "$token" || -z "$room" ]] && return 0
    printf '%s  room=%s  token=****' "${hs%/}" "$room"
}

# The secret's position is unknown, so keep only scheme, host and first path segment.
_alert_redact_webhook() {
    local w="${1:-}"
    [[ -z "$w" ]] && return 0
    if [[ "$w" =~ ^(https?://[^/]+/[^/?]+) ]]; then
        printf '%s/****' "${BASH_REMATCH[1]}"
    else
        printf '%.40s…' "$w"
    fi
}

# Succeeds when at least one destination has every setting it needs; same args as _alert_destinations_status.
_alert_any_destination() {
    local d="${1:-}" s="${2:-}" tt="${3:-}" tc="${4:-}" mh="${5:-}" mt="${6:-}" mr="${7:-}" wh="${8:-}"
    [[ -n "$d$s$wh" ]] || [[ -n "$tt" && -n "$tc" ]] || [[ -n "$mh" && -n "$mt" && -n "$mr" ]]
}

# Takes values as args so `alert status` can pass ones read from another user's config file.
# Args: discord_url slack_url tg_token tg_chat matrix_hs matrix_token matrix_room webhook_url
_alert_destinations_status() {
    local d="${1:-}" s="${2:-}" tt="${3:-}" tc="${4:-}" mh="${5:-}" mt="${6:-}" mr="${7:-}" wh="${8:-}"
    local preview

    if [[ -n "$d" ]]; then
        preview=$(_alert_redact_discord "$d")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "discord" "$preview"
    else
        printf "    %-10s ${D}—${NC}\n" "discord"
    fi

    if [[ -n "$s" ]]; then
        preview=$(_alert_redact_slack "$s")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "slack" "$preview"
    else
        printf "    %-10s ${D}—${NC}\n" "slack"
    fi

    if [[ -n "$tt" && -n "$tc" ]]; then
        preview=$(_alert_redact_telegram "$tt" "$tc")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "telegram" "$preview"
    elif [[ -n "$tt" || -n "$tc" ]]; then
        printf "    %-10s ${Y}partial${NC} need both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID\n" "telegram"
    else
        printf "    %-10s ${D}—${NC}\n" "telegram"
    fi

    if [[ -n "$mh" && -n "$mt" && -n "$mr" ]]; then
        preview=$(_alert_redact_matrix "$mh" "$mt" "$mr")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "matrix" "$preview"
    elif [[ -n "$mh" || -n "$mt" || -n "$mr" ]]; then
        printf "    %-10s ${Y}partial${NC} need MATRIX_HOMESERVER + MATRIX_TOKEN + MATRIX_ROOM\n" "matrix"
    else
        printf "    %-10s ${D}—${NC}\n" "matrix"
    fi

    if [[ -n "$wh" ]]; then
        preview=$(_alert_redact_webhook "$wh")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "webhook" "$preview"
    else
        printf "    %-10s ${D}—${NC}\n" "webhook"
    fi
}

# Returns 0 and stamps alerts.state when $1 hasn't fired within ALERT_COOLDOWN, else 1.
alert_should_fire() {
    local key="$1"
    local state_file="$ALERT_STATE_DIR/alerts.state"
    local now last tmp
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 1
    now=$(date +%s)
    last=$(awk -v k="$key" -F'\t' '$1==k {print $2; exit}' "$state_file" 2>/dev/null)
    if [[ -n "$last" ]] && (( now - last < ALERT_COOLDOWN )); then
        return 1
    fi
    # mktemp, not $$: daemon watchers are subshells that share the parent's $$.
    tmp=$(mktemp "$ALERT_STATE_DIR/alerts.state.tmp.XXXXXX" 2>/dev/null) || return 1
    {
        awk -v k="$key" -F'\t' 'BEGIN{OFS="\t"} $1!=k' "$state_file" 2>/dev/null
        printf '%s\t%s\n' "$key" "$now"
    } > "$tmp" && mv "$tmp" "$state_file" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    return 0
}

# Cross-rule dedup: one log line can match both exploits and probes, so the fingerprint gets one alert per ALERT_DEDUP_WINDOW.
# Call after alert_should_fire so quiet servers never touch alerts.fingerprints.
alert_fingerprint_fresh() {
    local fp="$1"
    [[ -n "$fp" ]] || return 0   # no fingerprint → pass through, dedup opt-in
    local state_file="$ALERT_STATE_DIR/alerts.fingerprints"
    local now last tmp
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 0
    now=$(date +%s)
    # ENVIRON, not -v: -v would expand the \xHH escapes nginx writes for quotes.
    last=$(MILOG_FP="$fp" awk -F'\t' '$1==ENVIRON["MILOG_FP"] {print $2; exit}' "$state_file" 2>/dev/null)
    if [[ -n "$last" ]] && (( now - last < ALERT_DEDUP_WINDOW )); then
        return 1
    fi
    tmp=$(mktemp "$ALERT_STATE_DIR/alerts.fingerprints.tmp.XXXXXX" 2>/dev/null) || return 0
    {
        # Also drop entries older than 2x the window so the file stays bounded.
        MILOG_FP="$fp" awk -v cutoff=$(( now - ALERT_DEDUP_WINDOW * 2 )) \
            -F'\t' 'BEGIN{OFS="\t"} $1!=ENVIRON["MILOG_FP"] && $2>cutoff' "$state_file" 2>/dev/null
        printf '%s\t%s\n' "$fp" "$now"
    } > "$tmp" && mv "$tmp" "$state_file" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    return 0
}

# `<ip>:<path>` with the query string stripped; empty when the line doesn't parse.
alert_fingerprint_from_line() {
    local line="$1"
    local ip path
    read -r ip path <<< "$(awk '{
        p = $7
        sub(/\?.*/, "", p)
        print $1, p
    }' <<< "$line")"
    [[ -n "$ip" && -n "$path" ]] || { printf ''; return; }
    printf '%s:%s' "$ip" "$path"
}

# Prints the `# version: N` from the first line of a rules file on stdin.
_rules_version() {
    sed -n '1s/^# version: \([0-9][0-9]*\)$/\1/p'
}

# Prints the version of a valid rules file; otherwise prints the reason to stderr and fails.
_rules_check() {
    local f="$1" version bad kind name re rc
    version=$(_rules_version < "$f")
    [[ -n "$version" ]] || { echo "$f: first line must be '# version: N'" >&2; return 1; }
    bad=$(awk -F'\t' '!/^#/ && NF && !(NF == 3 && $1 ~ /^(exploit|probe|category)$/ && $2 != "" && $3 != "") { print NR; exit }' "$f")
    [[ -z "$bad" ]] || { echo "$f:$bad: want <exploit|probe|category><TAB><name><TAB><regex>" >&2; return 1; }
    for kind in exploit probe; do
        grep -q "^$kind"$'\t' "$f" || { echo "$f: no $kind rules" >&2; return 1; }
    done
    while IFS=$'\t' read -r kind name re || [[ -n "$kind" ]]; do
        [[ -n "$kind" && "$kind" != \#* ]] || continue
        # Exit 2 is a bad regex; 0 means it matches an empty line and would flag every request.
        rc=0; grep -Eq -- "$re" <<< "" 2>/dev/null || rc=$?
        (( rc == 1 )) || { echo "$f: $kind/$name: regex does not compile or matches everything: $re" >&2; return 1; }
    done < "$f"
    printf '%s' "$version"
}

# RULES_FILE wins when it passes _rules_check; otherwise the rules baked in by build.sh apply.
_rules_load() {
    local text="" kind name re
    if [[ -f "$RULES_FILE" ]]; then
        if _rules_check "$RULES_FILE" >/dev/null; then
            text=$(cat "$RULES_FILE")
        else
            echo "milog: ignoring $RULES_FILE, using the built-in rules" >&2
        fi
    fi
    [[ -n "$text" ]] || text=$(_rules_default)
    RULES_EXPLOIT="" RULES_PROBE="" RULES_CATEGORY_NAMES=() RULES_CATEGORY_RES=()
    while IFS=$'\t' read -r kind name re; do
        case "$kind" in
            exploit)  RULES_EXPLOIT+="${RULES_EXPLOIT:+|}$re" ;;
            probe)    RULES_PROBE+="${RULES_PROBE:+|}$re" ;;
            category) RULES_CATEGORY_NAMES+=("$name"); RULES_CATEGORY_RES+=("$re") ;;
        esac
    done <<< "$text"
    # The AI crawler list is shared with health/top, so it is not duplicated in the rules file.
    RULES_PROBE+="|$AI_CRAWLER_UA_RE"
}

# First matching category row names the alert's rule key; needs _rules_load first.
_exploit_category() {
    local line="$1" cat="other" i
    shopt -s nocasematch
    for i in "${!RULES_CATEGORY_RES[@]}"; do
        if [[ "$line" =~ ${RULES_CATEGORY_RES[$i]} ]]; then
            cat="${RULES_CATEGORY_NAMES[$i]}"
            break
        fi
    done
    shopt -u nocasematch
    printf '%s' "$cat"
}

# Monitor table geometry. Row: " " app " │ " req " │ " status " │ " bar " " = W_APP+W_REQ+W_ST+W_BAR+11.
# milog_update_geometry runs every render tick and gives spare width to the INTENSITY (sparkline) column.
# Set MILOG_WIDTH=N to pin the width on terminals that misreport cols.
W_APP=10; W_REQ=8; W_ST=10
W_BAR=35                 # INTENSITY column — grows with terminal width
INNER=74                 # interior chars between outer │ │ (grows with terminal)
BW=11                    # sysmetric bar width: (INNER-40)/3 — recomputed per tick
MIN_INNER=74             # layout breaks below this; clamp as floor
MAX_INNER=200            # above this, rows stop being scan-able — clamp as ceiling

milog_update_geometry() {
    local cols
    cols=${MILOG_WIDTH:-0}
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=0
    if (( cols <= 0 )); then
        cols=$(tput cols 2>/dev/null || echo 80)
    fi
    local target=$(( cols - 2 ))   # reserve 2 chars for outer │ │
    (( target < MIN_INNER )) && target=$MIN_INNER
    (( target > MAX_INNER )) && target=$MAX_INNER
    INNER=$target
    W_BAR=$(( INNER - W_APP - W_REQ - W_ST - 11 ))
    # The sysmetric row has 39 fixed chars plus 3 bars; one spare char keeps `]` off the right border.
    BW=$(( (INNER - 40) / 3 ))
    (( BW < 5 )) && BW=5
    return 0   # guard against set -e when BW>=5 makes `((…))` return 1
}
milog_update_geometry    # initialise for non-TUI modes that use draw_row

spc() { printf '%*s' "$1" ''; }
hrule() { printf '─%.0s' $(seq 1 "$1"); }

# Filter: replace C0 controls (except tab), DEL and UTF-8 C1 with '?' so log text can't drive the terminal.
_tty_safe() {
    LC_ALL=C awk '{ gsub(/[\001-\010\013-\037\177]/, "?"); gsub(/\302[\200-\237]/, "?"); print; fflush() }'
}

bdr_top() { printf "${W}┌$(hrule $((W_APP+2)))┬$(hrule $((W_REQ+2)))┬$(hrule $((W_ST+2)))┬$(hrule $((W_BAR+2)))┐${NC}\n"; }
bdr_hdr() { printf "${W}├$(hrule $((W_APP+2)))┼$(hrule $((W_REQ+2)))┼$(hrule $((W_ST+2)))┼$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_mid() { printf "${W}├$(hrule $((INNER)))┤${NC}\n"; }
bdr_sep() { printf "${W}├$(hrule $((W_APP+2)))┴$(hrule $((W_REQ+2)))┴$(hrule $((W_ST+2)))┴$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_bot() { printf "${W}└$(hrule $((INNER)))┘${NC}\n"; }

# $1 is the plain text used for width (no ANSI), $2 the coloured text printed.
draw_row() {
    local plain="$1" colored="$2"
    local pad=$(( INNER - ${#plain} ))
    printf "${W}│${NC}%b" "$colored"
    [[ $pad -gt 0 ]] && spc "$pad"
    printf "${W}│${NC}\n"
}

# $1=name $2=count $3=st_plain(10 chars) $4=st_colored $5=bars_plain $6=bars_colored $7=alert_color
trow() {
    local name="$1" count="$2" st_plain="$3" st_col="$4" bars_plain="$5" bars_col="$6" alert="${7:-}"
    local n_pad=$(( W_APP - ${#name}       ))
    local r_pad=$(( W_REQ - ${#count}      ))
    local b_pad=$(( W_BAR - ${#bars_plain} ))
    printf "${W}│${NC} %b%s${NC}" "$alert" "$name";  spc "$n_pad"
    printf " ${W}│${NC} %s"       "$count";           spc "$r_pad"
    printf " ${W}│${NC} %b"       "$st_col"
    printf " ${W}│${NC} %b"       "$bars_col";        spc "$b_pad"
    printf " ${W}│${NC}\n"
}

hdr_row() {
    printf "${W}│${NC} %-${W_APP}s ${W}│${NC} %-${W_REQ}s ${W}│${NC} %-${W_ST}s ${W}│${NC} %-${W_BAR}s ${W}│${NC}\n" \
        "APP" "REQ/MIN" "STATUS" "INTENSITY"
}

# System metrics from /proc.

cpu_usage() {
    local s1 s2 t1 i1 t2 i2
    s1=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
    sleep 0.2
    s2=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
    read -r t1 i1 <<< "$s1"; read -r t2 i2 <<< "$s2"
    local dt=$(( t2-t1 )) di=$(( i2-i1 ))
    [[ $dt -eq 0 ]] && echo 0 || echo $(( 100*(dt-di)/dt ))
}

mem_info() {
    awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}
         END{u=t-a; printf "%d %d %d\n", int(u*100/t), int(u/1024), int(t/1024)}' /proc/meminfo
}

disk_info() {
    df / | awk 'NR==2{gsub(/%/,"",$5); printf "%d %.1f %.1f\n",$5,$3/1048576,$2/1048576}'
}

net_rx_tx() {
    local iface
    iface=$(ip route 2>/dev/null | awk '/^default/{print $5;exit}')
    [[ -z "$iface" ]] && iface=$(ls /sys/class/net/ | grep -v lo | head -1)
    local rx tx
    rx=$(cat /sys/class/net/"$iface"/statistics/rx_bytes 2>/dev/null || echo 0)
    tx=$(cat /sys/class/net/"$iface"/statistics/tx_bytes 2>/dev/null || echo 0)
    echo "$rx $tx $iface"
}

fmt_bytes() {
    local b=$1
    if   (( b >= 1073741824 )); then awk "BEGIN{printf \"%.1fGB\",$b/1073741824}"
    elif (( b >= 1048576 ));    then awk "BEGIN{printf \"%.1fMB\",$b/1048576}"
    elif (( b >= 1024 ));       then awk "BEGIN{printf \"%.1fKB\",$b/1024}"
    else printf "%dB" "$b"
    fi
}

# Prints exactly $1 chars of `|` and `.`, scaled $2/$3; ASCII so wide glyphs can't break alignment.
ascii_bar() {
    local width=$1 val=$2 max=${3:-100}
    [[ $max -le 0 ]] && max=1
    local f=$(( val * width / max ))
    [[ $f -gt $width ]] && f=$width
    local e=$(( width - f ))
    local i
    for (( i=0; i<f; i++ )); do printf '|'; done
    for (( i=0; i<e; i++ )); do printf '.'; done
}

tcol() {
    local v=$1 w=$2 c=$3
    (( v >= c )) && { printf '%s' "$R"; return; }
    (( v >= w )) && { printf '%s' "$Y"; return; }
    printf '%s' "$G"
}

# Scales each space-separated int in $1 to one of 8 block chars relative to the series max.
sparkline_render() {
    local -a vals=( $1 )
    local -a blk=('▁' '▂' '▃' '▄' '▅' '▆' '▇' '█')
    local max=0 v
    for v in "${vals[@]}"; do (( v > max )) && max=$v; done
    local out="" idx
    if (( max == 0 )); then
        for v in "${vals[@]}"; do out+="${blk[0]}"; done
    else
        for v in "${vals[@]}"; do
            idx=$(( v * 7 / max ))
            (( idx > 7 )) && idx=7
            (( idx < 0 )) && idx=0
            out+="${blk[$idx]}"
        done
    fi
    printf '%s' "$out"
}

# Prints one keypress within $1 seconds, or nothing on timeout.
wait_or_key() {
    local k
    if read -rsn1 -t "$1" k 2>/dev/null; then
        printf '%s' "$k"
    fi
}

# Daemon log to stderr; stdout stays clean.
_dlog() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

# History: SQLite per-minute metrics and hourly top-IP rollups, one sqlite3 process per write.

# Doubles single quotes and wraps the value in ''.
# The quote goes through a variable because bash < 4.3 keeps the backslashes in "${1//\'/\'\'}".
_sql_quote() { local q="'"; printf "'%s'" "${1//$q/$q$q}"; }

# Epoch -> log timestamp prefix (dd/Mon/yyyy:HH:MM); tries GNU `date -d @` then BSD `date -r`.
_cur_time_at() {
    local ts="$1"
    date -d "@${ts}" '+%d/%b/%Y:%H:%M' 2>/dev/null \
        || date -r "$ts" '+%d/%b/%Y:%H:%M' 2>/dev/null \
        || printf ''
}

# Idempotent; any failure disables history so the daemon keeps running.
history_init() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0

    if ! command -v sqlite3 >/dev/null 2>&1; then
        _dlog "WARNING: HISTORY_ENABLED=1 but sqlite3 is not on PATH — disabling history"
        HISTORY_ENABLED=0
        return 1
    fi

    local dir
    dir=$(dirname "$HISTORY_DB")
    if ! mkdir -p "$dir" 2>/dev/null; then
        _dlog "WARNING: cannot create history dir $dir — disabling history"
        HISTORY_ENABLED=0
        return 1
    fi

    if ! sqlite3 "$HISTORY_DB" <<'SQL' 2>/dev/null
CREATE TABLE IF NOT EXISTS metrics_minute (
    ts      INTEGER NOT NULL,
    app     TEXT    NOT NULL,
    req     INTEGER NOT NULL,
    c2xx    INTEGER NOT NULL,
    c3xx    INTEGER NOT NULL,
    c4xx    INTEGER NOT NULL,
    c5xx    INTEGER NOT NULL,
    p50_ms  INTEGER,
    p95_ms  INTEGER,
    p99_ms  INTEGER,
    PRIMARY KEY (ts, app)
);
CREATE TABLE IF NOT EXISTS top_ip_hour (
    ts_hour INTEGER NOT NULL,
    app     TEXT    NOT NULL,
    ip      TEXT    NOT NULL,
    hits    INTEGER NOT NULL,
    PRIMARY KEY (ts_hour, app, ip)
);
CREATE INDEX IF NOT EXISTS idx_metrics_app_ts ON metrics_minute(app, ts);
CREATE TABLE IF NOT EXISTS audit_event (
    ts      INTEGER NOT NULL,
    scanner TEXT    NOT NULL,
    kind    TEXT    NOT NULL,
    subject TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_event_ts ON audit_event(ts);
SQL
    then
        _dlog "WARNING: sqlite3 init failed — disabling history"
        HISTORY_ENABLED=0
        return 1
    fi

    _dlog "history: schema ready at $HISTORY_DB"
}

# cur_time must match the log's dd/Mon/yyyy:HH:MM prefix; percentiles land as NULL when there are no $request_time samples.
history_write_minute() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local ts="$1" cur_time="$2"
    [[ -n "$cur_time" ]] || { _dlog "history: empty cur_time for ts=$ts; skipping"; return 0; }

    local sql="" app name count c2 c3 c4 c5 p50 p95 p99
    for app in "${LOGS[@]}"; do
        [[ "$(_log_type_for "$app")" == "nginx" ]] || continue
        name=$(_log_name_for "$app")
        read -r count c2 c3 c4 c5 _ <<< "$(nginx_minute_counts "$name" "$cur_time")"
        count=${count:-0}; c2=${c2:-0}; c3=${c3:-0}; c4=${c4:-0}; c5=${c5:-0}
        read -r p50 p95 p99 <<< "$(percentiles "$name" "$cur_time")"
        [[ "$p50" =~ ^[0-9]+$ ]] || p50="NULL"
        [[ "$p95" =~ ^[0-9]+$ ]] || p95="NULL"
        [[ "$p99" =~ ^[0-9]+$ ]] || p99="NULL"
        sql+="INSERT OR REPLACE INTO metrics_minute VALUES"
        sql+=" ($ts, $(_sql_quote "$app"), $count, $c2, $c3, $c4, $c5, $p50, $p95, $p99);"$'\n'
    done

    if ! { printf 'BEGIN;\n%sCOMMIT;\n' "$sql"; } | sqlite3 "$HISTORY_DB" 2>/dev/null; then
        _dlog "history: minute write failed for ts=$ts"
    fi
}

# Stores the top HISTORY_TOP_IP_N IPs per app for the hour.
history_write_hour() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local ts_hour="$1"
    local hour_pat
    hour_pat=$(date -d "@${ts_hour}" '+%d/%b/%Y:%H:' 2>/dev/null \
               || date -r "$ts_hour"  '+%d/%b/%Y:%H:' 2>/dev/null)
    [[ -n "$hour_pat" ]] || return 0

    local sql="" app file hits ip
    for app in "${LOGS[@]}"; do
        [[ "$(_log_type_for "$app")" == "nginx" ]] || continue
        file=$(_log_path_for "$app")
        [[ -f "$file" ]] || continue
        while read -r hits ip; do
            [[ -n "$ip" ]] || continue
            sql+="INSERT OR REPLACE INTO top_ip_hour VALUES"
            sql+=" ($ts_hour, $(_sql_quote "$app"), $(_sql_quote "$ip"), $hits);"$'\n'
        done < <(awk -v p="$hour_pat" 'index($4, p) == 2 {print $1}' "$file" 2>/dev/null \
                 | sort | uniq -c | sort -rn \
                 | head -n "${HISTORY_TOP_IP_N:-50}")
    done

    [[ -n "$sql" ]] || return 0
    if ! { printf 'BEGIN;\n%sCOMMIT;\n' "$sql"; } | sqlite3 "$HISTORY_DB" 2>/dev/null; then
        _dlog "history: hour write failed for ts_hour=$ts_hour"
    fi
}

# rows are "<kind>\t<subject>" lines; a finding already stored at or after `since` is skipped, so drift that persists across ticks stays one row.
history_write_audit() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local scanner="$1" since="${2:-0}" rows="$3"
    [[ "$since" =~ ^[0-9]+$ ]] || since=0
    local now; now=$(date +%s)
    local sql="" kind subject k j q="'" s
    s=$(_sql_quote "$scanner")
    # Quoted inline, not via _sql_quote: a subshell per row stalls the daemon tick when thousands of findings persist.
    while IFS=$'\t' read -r kind subject; do
        [[ -n "$kind" && -n "$subject" ]] || continue
        k="lower('${kind//$q/$q$q}')"; j="'${subject//$q/$q$q}'"
        sql+="INSERT INTO audit_event SELECT $now, $s, $k, $j WHERE NOT EXISTS"
        sql+=" (SELECT 1 FROM audit_event WHERE scanner = $s AND kind = $k AND subject = $j AND ts >= $since);"$'\n'
    done <<< "$rows"

    [[ -n "$sql" ]] || return 0
    if ! { printf 'BEGIN;\n%sCOMMIT;\n' "$sql"; } | sqlite3 "$HISTORY_DB" 2>/dev/null; then
        _dlog "history: audit write failed for $scanner"
    fi
}

# audit_event rows with ts >= since, newest first: local time, scanner, kind, subject (tab-separated).
_history_audit_rows() {
    local since="$1"
    [[ "$since" =~ ^-?[0-9]+$ ]] || return 1
    (( since >= 0 )) || since=0
    sqlite3 -readonly -separator $'\t' "$HISTORY_DB" \
        "SELECT strftime('%Y-%m-%d %H:%M', ts, 'unixepoch', 'localtime'), scanner, kind, subject
         FROM audit_event WHERE ts >= $since ORDER BY ts DESC, rowid DESC;"
}

history_prune() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    [[ -f "$HISTORY_DB" ]] || return 0
    local retain="${HISTORY_RETAIN_DAYS:-30}"
    [[ "$retain" =~ ^[0-9]+$ ]] || retain=30
    local cutoff=$(( $(date +%s) - retain * 86400 ))
    if sqlite3 "$HISTORY_DB" <<SQL 2>/dev/null
BEGIN;
DELETE FROM metrics_minute WHERE ts      < $cutoff;
DELETE FROM top_ip_hour    WHERE ts_hour < $cutoff;
DELETE FROM audit_event    WHERE ts      < $cutoff;
COMMIT;
SQL
    then
        _dlog "history: pruned rows older than ${retain}d (cutoff=$cutoff)"
    else
        _dlog "history: prune failed"
    fi
}

_history_precheck() {
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${R}sqlite3 is not installed${NC}" >&2
        echo -e "${D}  re-run the installer (sqlite3 is now installed by default) or:${NC}" >&2
        echo -e "${D}  sudo apt install sqlite3  /  sudo dnf install sqlite  /  sudo pacman -S sqlite${NC}" >&2
        return 1
    fi
    if [[ ! -f "$HISTORY_DB" ]]; then
        echo -e "${R}No history database at $HISTORY_DB${NC}" >&2
        echo -e "${D}  enable with: milog config set HISTORY_ENABLED 1 && milog daemon${NC}" >&2
        return 1
    fi
}

# Anomaly detection: each new minute vs the same minute of day over the last ANOMALY_MIN_DAYS days (req, c5xx, p95).
# Fires only once every day in the window has data and the value clears its floor; near-zero baselines put one hit above 3σ.

_anomaly_floor() {
    case "$1" in
        req)  printf '%s' "${ANOMALY_FLOOR_REQ:-10}"  ;;
        c5xx) printf '%s' "${ANOMALY_FLOOR_C5XX:-2}"  ;;
        p95)  printf '%s' "${ANOMALY_FLOOR_P95:-100}" ;;
    esac
}

_anomaly_label() {
    case "$1" in
        req)  printf '%s' "request rate" ;;
        c5xx) printf '%s' "5xx rate"     ;;
        p95)  printf '%s' "p95 latency"  ;;
        *)    printf '%s' "$1"           ;;
    esac
}

_anomaly_unit() {
    case "$1" in
        p95)  printf '%s' " ms" ;;
        *)    printf '%s' ""    ;;
    esac
}

# Cheap to call every tick: returns at once unless anomaly, history, sqlite3 and the DB are all available.
_anomaly_check_minute() {
    [[ "${ANOMALY_ENABLED:-0}" != "1" ]] && return 0
    [[ "${HISTORY_ENABLED:-0}" != "1" ]] && return 0
    command -v sqlite3 >/dev/null 2>&1 || return 0
    [[ -f "$HISTORY_DB" ]] || return 0

    local write_ts="$1"
    [[ "$write_ts" =~ ^[0-9]+$ ]] || return 0

    local min_days="${ANOMALY_MIN_DAYS:-14}"
    local since_ts=$((     write_ts - min_days * 86400 ))
    local sigma="${ANOMALY_SIGMA:-3}"
    local floor_req  floor_c5  floor_p95
    floor_req=$(_anomaly_floor req)
    floor_c5=$(_anomaly_floor c5xx)
    floor_p95=$(_anomaly_floor p95)

    local app
    for app in "${LOGS[@]}"; do
        # One query per app: baseline rows tagged B, the current row tagged C.
        local out
        out=$(sqlite3 "$HISTORY_DB" <<SQL 2>/dev/null
SELECT 'B', req, c5xx, IFNULL(p95_ms,-1), ts/86400
  FROM metrics_minute
  WHERE app=$(_sql_quote "$app")
    AND strftime('%H:%M', ts, 'unixepoch', 'localtime')=strftime('%H:%M', $write_ts, 'unixepoch', 'localtime')
    AND ts>=$since_ts
    AND ts<$write_ts;
SELECT 'C', req, c5xx, IFNULL(p95_ms,-1), 0
  FROM metrics_minute
  WHERE app=$(_sql_quote "$app")
    AND ts=$write_ts;
SQL
        )
        [[ -z "$out" ]] && continue

        # Rows: TYPE|req|c5xx|p95 (-1 = NULL)|day. Prints `<metric> <current> <mean> <stddev> <z>` per breach.
        local hits
        hits=$(printf '%s\n' "$out" | awk -F'|' \
            -v sigma="$sigma" -v min_days="$min_days" \
            -v fr="$floor_req" -v fc="$floor_c5" -v fp="$floor_p95" '
            $1=="B" {
                n_req++;          sum_req += $2; sumsq_req += $2*$2
                n_c5++;           sum_c5  += $3; sumsq_c5  += $3*$3
                if ($4 >= 0) { n_p95++; sum_p95 += $4; sumsq_p95 += $4*$4 }
                days[int($5)] = 1
            }
            $1=="C" {
                cur_req = $2 + 0
                cur_c5  = $3 + 0
                cur_p95 = $4 + 0
            }
            END {
                d = 0; for (k in days) d++
                if (d < min_days) exit 0

                if (n_req > 1 && cur_req > fr) {
                    m = sum_req / n_req
                    var = sumsq_req / n_req - m*m
                    if (var < 0) var = 0
                    sd = sqrt(var)
                    if (sd > 0 && cur_req > m + sigma*sd)
                        printf "req %d %.2f %.2f %.2f\n", cur_req, m, sd, (cur_req - m) / sd
                }
                if (n_c5 > 1 && cur_c5 > fc) {
                    m = sum_c5 / n_c5
                    var = sumsq_c5 / n_c5 - m*m
                    if (var < 0) var = 0
                    sd = sqrt(var)
                    if (sd > 0 && cur_c5 > m + sigma*sd)
                        printf "c5xx %d %.2f %.2f %.2f\n", cur_c5, m, sd, (cur_c5 - m) / sd
                }
                if (n_p95 > 1 && cur_p95 > fp) {
                    m = sum_p95 / n_p95
                    var = sumsq_p95 / n_p95 - m*m
                    if (var < 0) var = 0
                    sd = sqrt(var)
                    if (sd > 0 && cur_p95 > m + sigma*sd)
                        printf "p95 %d %.2f %.2f %.2f\n", cur_p95, m, sd, (cur_p95 - m) / sd
                }
            }
        ')

        [[ -z "$hits" ]] && continue

        local metric current mean stddev z key title body
        while read -r metric current mean stddev z; do
            [[ -z "$metric" ]] && continue
            key="anomaly:${app}:${metric}"
            alert_should_fire "$key" || continue
            title="Anomaly: $(_anomaly_label "$metric") on ${app}"
            body=$(printf '%s' '```'"current=${current}$(_anomaly_unit "$metric") mean=${mean} σ=${stddev} z=${z}σ window=${min_days}d (same-minute-of-day)"'```')
            alert_fire "$title" "$body" 15158332 "$key"
        done <<< "$hits"
    done
}
# nginx access-log counters and monitor rows.

# Lowercase UA tokens of AI crawlers and assistant fetchers; go/internal/nginxlog mirrors it and a test checks they match.
AI_CRAWLER_UA_RE='gptbot|chatgpt-user|oai-searchbot|claudebot|claude-user|claude-searchbot|anthropic-ai|perplexitybot|perplexity-user|meta-externalagent|meta-externalfetcher|bytespider|amazonbot|ccbot|cohere-ai|duckassistbot|mistralai-user|youbot'

# Prints "count c2 c3 c4 c5 ai" for lines containing timestamp $2, or zeros when the log is missing; ai matches the UA field.
nginx_minute_counts() {
    local file="$LOG_DIR/$1.access.log"
    [[ -f "$file" ]] || { printf '0 0 0 0 0 0\n'; return; }
    awk -v t="$2" -v re="$AI_CRAWLER_UA_RE" '
        index($4, t) == 2 {
            n++
            # Status follows the quoted request; nginx escapes quotes inside it.
            split($0, q, "\"")
            split(q[3], f, " ")
            if (f[1] ~ /^[1-5][0-9][0-9]$/) {
                cls = substr(f[1], 1, 1)
                if      (cls == "2") e2++
                else if (cls == "3") e3++
                else if (cls == "4") e4++
                else if (cls == "5") e5++
            }
            if (tolower(q[6]) ~ re) ai++
        }
        END { printf "%d %d %d %d %d %d\n", n+0, e2+0, e3+0, e4+0, e5+0, ai+0 }
    ' "$file" 2>/dev/null
}

# Prints "p50 p95 p99" in ms for $1 at minute $2, or "— — —" when no line ends in a numeric $request_time.
percentiles() {
    local name="$1" cur="$2"
    local file="$LOG_DIR/$name.access.log"
    [[ -f "$file" ]] || { printf -- '— — —\n'; return; }
    local sorted
    sorted=$(awk -v t="$cur" '
        index($4, t) == 2 && $NF ~ /^[0-9]+(\.[0-9]+)?$/ {
            print int($NF * 1000 + 0.5)
        }' "$file" 2>/dev/null | sort -n)
    if [[ -z "$sorted" ]]; then
        printf -- '— — —\n'
        return
    fi
    # Ceiling-index pick: idx = ceil(N*k/100), clamped to [1,N].
    printf '%s\n' "$sorted" | awk '
        { a[NR] = $1; n = NR }
        END {
            if (n == 0) { print "— — —"; exit }
            p50 = int((n * 50 + 99) / 100); if (p50 < 1) p50 = 1; if (p50 > n) p50 = n
            p95 = int((n * 95 + 99) / 100); if (p95 < 1) p95 = 1; if (p95 > n) p95 = n
            p99 = int((n * 99 + 99) / 100); if (p99 < 1) p99 = 1; if (p99 > n) p99 = n
            printf "%d %d %d\n", a[p50], a[p95], a[p99]
        }'
}

# ISO country code, or "—" when GeoIP is off or unavailable. Forks mmdblookup, so only call it on deduped IP sets.
geoip_country() {
    [[ "${GEOIP_ENABLED:-0}" != "1" ]] && { printf -- '—'; return; }
    [[ ! -f "$MMDB_PATH" ]]            && { printf -- '—'; return; }
    command -v mmdblookup >/dev/null 2>&1 || { printf -- '—'; return; }
    local out
    out=$(mmdblookup --file "$MMDB_PATH" --ip "$1" country iso_code 2>/dev/null \
          | awk -F'"' 'NF>=3 {print $2; exit}')
    printf '%s' "${out:-—}"
}

# Prints "<reputation> (<behaviors>)", or "unknown" when CTI has no record; empty when off or failing.
# Results are cached per IP for a day; pass `cached` to skip the network. Failures land in cti.err for doctor.
cti_lookup() {
    local ip="${1-}" dir="$ALERT_STATE_DIR/cti"
    [[ -n "${CROWDSEC_CTI_KEY:-}" ]] || return 0
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || ( "$ip" == *:* && "$ip" =~ ^[0-9a-fA-F:.]*[0-9a-fA-F][0-9a-fA-F:.]*$ ) ]] || return 0
    ip=$(printf '%s' "$ip" | tr A-F a-f)
    local f="$dir/$ip" mtime
    if [[ -f "$f" ]]; then
        mtime=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0)
        if (( $(date +%s) - mtime < 86400 )); then
            cat "$f"
            return 0
        fi
    fi
    [[ "${2:-}" == cached ]] && return 0
    command -v curl >/dev/null 2>&1 || return 0
    mkdir -p "$dir" 2>/dev/null || return 0
    # After a 429 every request would fail too, so pause lookups for 15 minutes.
    [[ -n "$(find "$dir/.backoff" -mmin -15 2>/dev/null)" ]] && return 0
    local err="$ALERT_STATE_DIR/cti.err"
    # The key goes into a curl config on stdin, so a quote or newline would break out of it.
    if [[ "$CROWDSEC_CTI_KEY" == *[\"\\[:space:]]* ]]; then
        printf '%s\tCROWDSEC_CTI_KEY contains quotes, backslashes or whitespace\n' "$(date +%s)" > "$err"
        return 0
    fi
    local resp code="" summary="" body
    resp=$(mktemp "$dir/.resp.XXXXXX" 2>/dev/null) || return 0
    code=$(printf 'header = "x-api-key: %s"\n' "$CROWDSEC_CTI_KEY" \
        | curl -s -m 3 --max-filesize 65536 -K - -o "$resp" -w '%{http_code}' \
              "https://cti.api.crowdsec.net/v2/smoke/$ip" 2>/dev/null) || true
    case "$code" in
        200) summary=$(tr -d '\n' < "$resp" | _cti_summary) ;;
        # Only a JSON error object counts as "no record"; a proxy or HTML 404 is a failure.
        404) body=$(tr -d '[:space:]' < "$resp")
             [[ "$body" == "{"* && "$body" != *'"ip"'* ]] && summary="unknown" ;;
        429) touch "$dir/.backoff" ;;
    esac
    rm -f "$resp"
    if [[ -z "$summary" ]]; then
        printf '%s\tHTTP %s for %s\n' "$(date +%s)" "${code:-000}" "$ip" > "$err"
        return 0
    fi
    rm -f "$err"
    printf '%s\n' "$summary" > "$f"
    printf '%s\n' "$summary"
}

# Reads one smoke-API JSON object on a single line; output is limited to [A-Za-z0-9 :._,()/-].
_cti_summary() {
    awk '
        { s = s $0 }
        END {
            if (!match(s, /"reputation" *: *"[a-z_]*"/)) exit
            rep = substr(s, RSTART, RLENGTH)
            sub(/^"reputation" *: *"/, "", rep); sub(/"$/, "", rep)
            labels = ""; n = 0
            if (match(s, /"behaviors" *: *\[[^]]*\]/)) {
                b = substr(s, RSTART, RLENGTH)
                while (n < 3 && match(b, /"label" *: *"[^"]*"/)) {
                    l = substr(b, RSTART, RLENGTH)
                    b = substr(b, RSTART + RLENGTH)
                    sub(/^"label" *: *"/, "", l); sub(/"$/, "", l)
                    labels = labels (n++ ? ", " : "") l
                }
            }
            out = rep (labels != "" ? " (" labels ")" : "")
            gsub(/[^A-Za-z0-9 :._,()\/-]/, "", out)
            print out
        }'
}

# Alert-body suffix for exploit and probe alerts; looks up only when alerts are on.
cti_alert_note() {
    [[ "${ALERTS_ENABLED:-0}" == "1" ]] || return 0
    local s; s=$(cti_lookup "${1-}")
    [[ -n "$s" ]] && printf '\nCrowdSec: %s' "$s"
    return 0
}

# p95 for the monitor row, cached per app per minute so a 5s refresh doesn't rescan the log.
# Apps found without $request_time are never scanned again until MiLog restarts.
_p95_cached() {
    # bash 3.2 has no associative arrays, so skip the cache there.
    if (( ${BASH_VERSINFO[0]:-3} < 4 )); then
        local _p50 p95 _p99
        read -r _p50 p95 _p99 <<< "$(percentiles "$1" "$2")"
        [[ "$p95" =~ ^[0-9]+$ ]] && printf '%s' "$p95"
        return 0
    fi
    declare -gA TIMED_APPS P95_LAST_MIN P95_LAST_VAL
    local name="$1" cur="$2"

    [[ "${TIMED_APPS[$name]:-}" == "0" ]] && return 0

    if [[ "${P95_LAST_MIN[$name]:-}" == "$cur" ]]; then
        printf '%s' "${P95_LAST_VAL[$name]}"
        return 0
    fi

    local _p50 p95 _p99
    read -r _p50 p95 _p99 <<< "$(percentiles "$name" "$cur")"
    if [[ "$p95" =~ ^[0-9]+$ ]]; then
        TIMED_APPS[$name]=1
        P95_LAST_MIN[$name]="$cur"
        P95_LAST_VAL[$name]="$p95"
        printf '%s' "$p95"
    else
        TIMED_APPS[$name]=0
    fi
}

# 4xx/5xx spike alerts, shared by nginx_row and the daemon; thresholds go through _thresh.
nginx_check_http_alerts() {
    local name="$1" c4="$2" c5="$3"
    local t5 t4
    t5=$(_thresh THRESH_5XX_WARN "$name")
    t4=$(_thresh THRESH_4XX_WARN "$name")
    if (( c5 >= t5 )) && alert_should_fire "5xx:$name"; then
        alert_fire "5xx spike: $name" "${c5} 5xx responses in the last minute (threshold ${t5})" 15158332 "5xx:$name" &
    fi
    if (( c4 >= t4 )) && alert_should_fire "4xx:$name"; then
        alert_fire "4xx spike: $name" "${c4} 4xx responses in the last minute (threshold ${t4})" 16753920 "4xx:$name" &
    fi
}

# Prints "ai total" over the whole log of $1; matches the UA field, not the whole line.
nginx_ai_counts() {
    local file="$LOG_DIR/$1.access.log"
    [[ -f "$file" ]] || { printf '0 0\n'; return; }
    awk -v re="$AI_CRAWLER_UA_RE" '
        {
            n++
            split($0, q, "\"")
            if (tolower(q[6]) ~ re) ai++
        }
        END { printf "%d %d\n", ai+0, n+0 }
    ' "$file" 2>/dev/null
}

nginx_check_ai_alert() {
    local name="$1" ai="$2" total="$3" t
    t=$(_thresh THRESH_AICRAWL_WARN "$name")
    if (( ai > 0 && ai >= t )) && alert_should_fire "aicrawl:$name"; then
        alert_fire "AI crawler surge: $name" "${ai} AI-crawler requests in the last minute, $(( ai * 100 / total ))% of ${total} (threshold ${t})" 15844367 "aicrawl:$name" &
    fi
}

# CPU/MEM/DISK/worker alerts, shared by monitor and daemon.
sys_check_alerts() {
    local cpu="$1" mem_pct="$2" mem_used="$3" mem_total="$4"
    local disk_pct="$5" disk_used="$6" disk_total="$7" worker_count="$8"
    if (( cpu >= THRESH_CPU_CRIT )) && alert_should_fire "cpu"; then
        alert_fire "CPU critical" "CPU at ${cpu}% (crit=${THRESH_CPU_CRIT}%)" 15158332 "cpu" &
    fi
    if (( mem_pct >= THRESH_MEM_CRIT )) && alert_should_fire "mem"; then
        alert_fire "Memory critical" "MEM at ${mem_pct}% — used ${mem_used}MB of ${mem_total}MB (crit=${THRESH_MEM_CRIT}%)" 15158332 "mem" &
    fi
    if (( disk_pct >= THRESH_DISK_CRIT )) && alert_should_fire "disk:/"; then
        alert_fire "Disk critical" "Disk at ${disk_pct}% on / — ${disk_used}GB of ${disk_total}GB used (crit=${THRESH_DISK_CRIT}%)" 15158332 "disk:/" &
    fi
    if (( worker_count == 0 )) && alert_should_fire "workers"; then
        alert_fire "Nginx workers down" "Zero nginx worker processes detected on $(hostname 2>/dev/null || echo host)" 15158332 "workers" &
    fi
}

nginx_row() {
    local name="$1" CUR_TIME="$2" TOTAL_ref="$3"
    local count=0 c2=0 c3=0 c4=0 c5=0

    read -r count c2 c3 c4 c5 _ <<< "$(nginx_minute_counts "$name" "$CUR_TIME")"
    count=${count:-0}; c4=${c4:-0}; c5=${c5:-0}
    # shellcheck disable=SC2034
    eval "$TOTAL_ref=$(( ${!TOTAL_ref} + count ))"

    local tr_warn tr_crit t4_warn t5_warn
    tr_warn=$(_thresh THRESH_REQ_WARN  "$name")
    tr_crit=$(_thresh THRESH_REQ_CRIT  "$name")
    t4_warn=$(_thresh THRESH_4XX_WARN  "$name")
    t5_warn=$(_thresh THRESH_5XX_WARN  "$name")

    local st_plain st_col b_col alert=""
    if [[ $count -gt 0 ]]; then
        st_plain="● ACTIVE  "; st_col="${G}● ACTIVE  ${NC}"; b_col=$G
        [[ $count -gt $tr_warn ]] && b_col=$Y
        [[ $count -gt $tr_crit ]] && { b_col=$R; st_col="${R}● ACTIVE  ${NC}"; }
    else
        st_plain="○ IDLE    "; st_col="${D}○ IDLE    ${NC}"; b_col=$D
    fi

    [[ $c5 -ge $t5_warn ]]                   && alert="$RBLINK"
    [[ $c4 -ge $t4_warn && -z "$alert" ]]    && alert="$R"
    [[ $count -gt $tr_crit && -z "$alert" ]] && alert="$R"

    nginx_check_http_alerts "$name" "$c4" "$c5"

    local p95_ms
    p95_ms=$(_p95_cached "$name" "$CUR_TIME")

    local bars_plain bars_col
    if [[ "${MILOG_HIST_ENABLED:-0}" == "1" ]]; then
        # MILOG_HIST_PAUSED=1 freezes the ring buffer while the view is paused.
        local -a hist_arr=( ${HIST[$name]:-} )
        if [[ "${MILOG_HIST_PAUSED:-0}" != "1" ]]; then
            hist_arr+=( "$count" )
            if (( ${#hist_arr[@]} > SPARK_LEN )); then
                hist_arr=( "${hist_arr[@]: -$SPARK_LEN}" )
            fi
            HIST[$name]="${hist_arr[*]}"
        fi
        (( ${#hist_arr[@]} == 0 )) && hist_arr=( 0 )

        local spark n_samples=${#hist_arr[@]}
        spark=$(sparkline_render "${hist_arr[*]}")
        # Placeholder with the sparkline's width for padding maths.
        bars_plain=$(printf '.%.0s' $(seq 1 "$n_samples"))
        bars_col="${b_col}${spark}${NC}"
    else
        local bc=$(( count / 2 ))
        [[ $bc -gt $W_BAR ]] && bc=$W_BAR
        if [[ $bc -gt 0 ]]; then
            bars_plain=$(printf '|%.0s' $(seq 1 $bc))
            bars_col="${b_col}${bars_plain}${NC}"
        else
            bars_plain="-"; bars_col="${D}-${NC}"
        fi
    fi

    # Trim the bar so the 4xx/5xx and p95 tags fit in the column.
    local etag_p="" etag_c=""
    if (( c4 > 0 || c5 > 0 )); then
        etag_p+=" 4xx:${c4} 5xx:${c5}"
        etag_c+=" ${Y}4xx:${c4}${NC} ${R}5xx:${c5}${NC}"
    fi
    if [[ -n "$p95_ms" ]]; then
        local pcol p95w p95c
        p95w=$(_thresh P95_WARN_MS "$name")
        p95c=$(_thresh P95_CRIT_MS "$name")
        pcol=$(tcol "$p95_ms" "$p95w" "$p95c")
        etag_p+=" p95:${p95_ms}ms"
        etag_c+=" ${pcol}p95:${p95_ms}ms${NC}"
    fi
    if [[ -n "$etag_p" ]]; then
        local max_b=$(( W_BAR - ${#etag_p} ))
        if [[ ${#bars_plain} -gt $max_b ]]; then
            bars_plain="${bars_plain:0:$max_b}"
            if [[ "${MILOG_HIST_ENABLED:-0}" == "1" ]]; then
                local -a trimmed=( ${HIST[$name]:-} )
                (( max_b > 0 && ${#trimmed[@]} > max_b )) && trimmed=( "${trimmed[@]: -$max_b}" )
                bars_col="${b_col}$(sparkline_render "${trimmed[*]}")${NC}"
            else
                bars_col="${b_col}${bars_plain}${NC}"
            fi
        fi
        bars_plain="${bars_plain}${etag_p}"
        bars_col="${bars_col}${etag_c}"
    fi

    trow "$name" "$count" "$st_plain" "$st_col" "$bars_plain" "$bars_col" "$alert"
}

# Token and pidfile helpers for the milog-web Go binary (go/cmd/milog-web); src/modes/web.sh launches it.
# The server is read-only, binds loopback unless --trust, and checks the token file on every request.

_web_token_read() {
    [[ -r "$WEB_TOKEN_FILE" ]] || return 1
    local t; t=$(tr -d '[:space:]' < "$WEB_TOKEN_FILE")
    [[ -n "$t" ]] && printf '%s' "$t"
}

_web_token_ensure() {
    if [[ -f "$WEB_TOKEN_FILE" ]] && _web_token_read >/dev/null; then
        return 0
    fi
    local dir; dir=$(dirname "$WEB_TOKEN_FILE")
    mkdir -p "$dir" 2>/dev/null || { echo -e "${R}cannot create $dir${NC}" >&2; return 1; }
    # 32 random bytes as hex; openssl is the fallback.
    if head -c 32 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' > "$WEB_TOKEN_FILE" \
            && [[ -s "$WEB_TOKEN_FILE" ]]; then
        :
    elif command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32 > "$WEB_TOKEN_FILE"
    else
        echo -e "${R}no /dev/urandom or openssl — cannot generate token${NC}" >&2
        return 1
    fi
    chmod 600 "$WEB_TOKEN_FILE"
}

_web_pid_file() { echo "$WEB_STATE_DIR/web.pid"; }

_web_token_age() {
    [[ -f "$WEB_TOKEN_FILE" ]] || return 0
    local mtime now delta
    mtime=$(stat -c '%Y' "$WEB_TOKEN_FILE" 2>/dev/null || stat -f '%m' "$WEB_TOKEN_FILE" 2>/dev/null)
    [[ -n "$mtime" ]] || return 0
    now=$(date +%s)
    delta=$(( now - mtime ))
    if   (( delta < 60 ));    then printf '%ds' "$delta"
    elif (( delta < 3600 ));  then printf '%dm' $(( delta / 60 ))
    elif (( delta < 86400 )); then printf '%dh' $(( delta / 3600 ))
    else                           printf '%dd' $(( delta / 86400 ))
    fi
}

# Takes effect on the next request without a restart because the server rereads the token file.
_web_rotate_token() {
    mkdir -p "$(dirname "$WEB_TOKEN_FILE")" 2>/dev/null || true
    rm -f "$WEB_TOKEN_FILE"
    _web_token_ensure || return 1
    local tok; tok=$(_web_token_read)
    [[ -z "$tok" ]] && { echo -e "${R}rotation failed — token file not written${NC}" >&2; return 1; }
    echo -e "${G}✓${NC} rotated web token"
    echo -e "${D}  file: $WEB_TOKEN_FILE${NC}"
    echo -e "${W}  URL:${NC}  http://${WEB_BIND}:${WEB_PORT}/?t=${tok}"
    if _web_systemd_active; then
        echo -e "${D}  service is running — the daemon will accept the new token on next request${NC}"
    fi
    echo -e "${D}  old browser tabs will see 401 until you reopen the URL above${NC}"
}

_web_systemd_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl --user is-active --quiet milog-web.service 2>/dev/null
}

_web_status() {
    # systemd unit first, then the pidfile for foreground runs.
    if _web_systemd_active; then
        local main_pid; main_pid=$(systemctl --user show --value -p MainPID milog-web.service 2>/dev/null)
        echo -e "${G}running${NC}  (systemd user unit)  pid=${main_pid:-?}  bind=${WEB_BIND}:${WEB_PORT}"
        echo -e "${D}  unit:  ${HOME}/.config/systemd/user/milog-web.service${NC}"
        echo -e "${D}  logs:  journalctl --user -u milog-web.service -f${NC}"
        echo -e "${D}  token: $WEB_TOKEN_FILE  (age $(_web_token_age))${NC}"
        return 0
    fi

    local pf; pf=$(_web_pid_file)
    if [[ ! -f "$pf" ]]; then
        echo -e "${D}not running${NC}"
        return 1
    fi
    local pid; pid=$(< "$pf")
    if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
        echo -e "${Y}stale pidfile (pid=$pid not alive); removing${NC}"
        rm -f "$pf"
        return 1
    fi
    echo -e "${G}running${NC}  (foreground)  pid=$pid  bind=${WEB_BIND}:${WEB_PORT}"
    echo -e "${D}  token: $WEB_TOKEN_FILE${NC}"
    echo -e "${D}  request log: journalctl / stdout of milog-web${NC}"
    return 0
}

_web_stop() {
    # Killing a systemd-managed process directly would trigger Restart=on-failure.
    if _web_systemd_active; then
        systemctl --user stop milog-web.service 2>/dev/null \
            && echo -e "${G}stopped${NC}  (systemd user unit)" \
            || echo -e "${R}failed to stop milog-web.service${NC}"
        return 0
    fi

    local pf; pf=$(_web_pid_file)
    if [[ ! -f "$pf" ]]; then
        echo -e "${D}not running${NC}"
        return 0
    fi
    local pid; pid=$(< "$pf")
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    # Kill the process group so children die too.
        kill -TERM -- -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        sleep 0.3
        kill -KILL -- -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        echo -e "${G}stopped${NC}  pid=$pid"
    else
        echo -e "${Y}pidfile stale; cleaning${NC}"
    fi
    rm -f "$pf"
}
# milog alert on|off|status|test|stats: toggle alerting and the systemd service.
# Under sudo, config goes to SUDO_USER's home and the service runs as that user, not root.

_alert_target_user() {
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        printf '%s' "$SUDO_USER"
    else
        id -un
    fi
}

_alert_target_home() {
    local u="$1" h
    h=$(getent passwd "$u" 2>/dev/null | cut -d: -f6)
    [[ -n "$h" ]] && printf '%s' "$h" || printf '%s' "${HOME:-/root}"
}

# Upserts KEY=VALUE in the target user's config.
_alert_write_config() {
    local target_user="$1" target_home="$2" line="$3"
    local dir="$target_home/.config/milog" file="$target_home/.config/milog/config.sh"
    local key="${line%%=*}" tmp
    mkdir -p "$dir" 2>/dev/null || { echo -e "${R}cannot create $dir${NC}" >&2; return 1; }
    [[ -e "$file" ]] || : > "$file"
    if grep -qE "^[[:space:]]*${key}=" "$file" 2>/dev/null; then
        tmp=$(mktemp "$dir/.cfg.XXXXXX") || return 1
        awk -v k="$key" -v repl="$line" '
            $0 ~ "^[[:space:]]*" k "=" && !done { print repl; done=1; next }
            { print }
        ' "$file" > "$tmp" && mv "$tmp" "$file"
    else
        printf '%s\n' "$line" >> "$file"
    fi
    if [[ $(id -u) -eq 0 && "$target_user" != "root" ]]; then
        chown -R "$target_user:$target_user" "$dir" 2>/dev/null || true
    fi
}

# Regular file up to 1 MiB; root also refuses symlinks, since it may be reading another user's file.
_alert_config_readable() {
    local file="$1" size
    [[ -f "$file" && -r "$file" ]] || return 1
    (( EUID != 0 )) || [[ ! -L "$file" ]] || return 1
    size=$(stat -L -c '%s' "$file" 2>/dev/null || stat -L -f '%z' "$file" 2>/dev/null) || return 1
    (( size <= 1048576 ))
}

# Stops before any read or write when the target config exists but the readers would skip it.
_alert_check_config() {
    local file="$1"
    [[ -e "$file" || -L "$file" ]] || return 0
    _alert_config_readable "$file" && return 0
    echo -e "${R}refusing to use $file:${NC} needs a regular file under 1 MiB (not a symlink when run as root)" >&2
    return 1
}

# Always returns 0, printing nothing when the file or key is missing, to stay safe under `set -e`.
_alert_read_webhook() {
    local file="$1"
    _alert_config_readable "$file" || return 0
    {
        grep -E '^[[:space:]]*DISCORD_WEBHOOK=' "$file" 2>/dev/null \
            | head -1 \
            | sed -E 's/^[^=]*=//; s/^"//; s/"[[:space:]]*$//'
    } || true
    return 0
}

_alert_read_routes() {
    local file="$1"
    _alert_config_readable "$file" || return 0
    # Parsed, never sourced: under sudo this is another user's file and we're root.
    awk '
        !on && /^[[:space:]]*(export[[:space:]]+)?ALERT_ROUTES=/ {
            sub(/^[[:space:]]*(export[[:space:]]+)?ALERT_ROUTES=/, ""); val = ""
            q = substr($0, 1, 1)
            if (q != "\"" && q != "\047") { sub(/[[:space:]].*$/, ""); val = $0; next }
            $0 = substr($0, 2); on = 1
        }
        on {
            i = index($0, q)
            if (i) { val = val substr($0, 1, i - 1); on = 0; next }
            val = val $0 "\n"
        }
        END { printf "%s", val }' "$file" 2>/dev/null || true
}

_alert_read_key() {
    local file="$1" key="$2"
    _alert_config_readable "$file" || return 0
    {
        grep -E "^[[:space:]]*${key}=" "$file" 2>/dev/null \
            | head -1 \
            | sed -E 's/^[^=]*=//; s/^"//; s/"[[:space:]]*$//'
    } || true
    return 0
}

# Caller must be root.
_alert_install_service() {
    local target_user="$1" target_config="$2"
    local exe unit="/etc/systemd/system/milog.service"
    exe=$(command -v milog 2>/dev/null || echo "/usr/local/bin/milog")
    cat > "$unit" <<EOF
[Unit]
Description=MiLog headless alerter
After=network.target

[Service]
Type=simple
ExecStart=$exe daemon
Restart=on-failure
RestartSec=5
User=$target_user
Environment=MILOG_CONFIG=$target_config

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable milog.service >/dev/null 2>&1
    systemctl restart milog.service
}

_alert_fmt_dur() {
    local s="$1"
    if   (( s < 60 ));    then printf '%ds' "$s"
    elif (( s < 3600 ));  then printf '%dm' "$((s / 60))"
    elif (( s < 86400 )); then printf '%dh' "$((s / 3600))"
    else                       printf '%dd' "$((s / 86400))"
    fi
}

alert_on() {
    local webhook_arg="${1:-}"
    local target_user target_home target_config
    target_user=$(_alert_target_user)
    target_home=$(_alert_target_home "$target_user")
    target_config="$target_home/.config/milog/config.sh"
    _alert_check_config "$target_config" || return 1

    if [[ -n "$webhook_arg" ]]; then
        case "$webhook_arg" in
            https://discord.com/api/webhooks/*) ;;
            https://discordapp.com/api/webhooks/*) ;;
            *) echo -e "${Y}warning:${NC} URL doesn't look like a Discord webhook — proceeding" ;;
        esac
        _alert_write_config "$target_user" "$target_home" \
            "DISCORD_WEBHOOK=\"$webhook_arg\"" || return 1
    fi
    _alert_write_config "$target_user" "$target_home" "ALERTS_ENABLED=1" || return 1

    local d_url s_url wh_url tg_token tg_chat mx_hs mx_token mx_room
    d_url=$(_alert_read_webhook "$target_config")
    s_url=$(   _alert_read_key "$target_config" "SLACK_WEBHOOK")
    wh_url=$(  _alert_read_key "$target_config" "WEBHOOK_URL")
    tg_token=$(_alert_read_key "$target_config" "TELEGRAM_BOT_TOKEN")
    tg_chat=$( _alert_read_key "$target_config" "TELEGRAM_CHAT_ID")
    mx_hs=$(   _alert_read_key "$target_config" "MATRIX_HOMESERVER")
    mx_token=$(_alert_read_key "$target_config" "MATRIX_TOKEN")
    mx_room=$( _alert_read_key "$target_config" "MATRIX_ROOM")
    if ! _alert_any_destination "$d_url" "$s_url" "$tg_token" "$tg_chat" "$mx_hs" "$mx_token" "$mx_room" "$wh_url"; then
        echo -e "${R}no alert destination configured in $target_config${NC}" >&2
        echo "  pass a Discord webhook:  milog alert on 'https://discord.com/api/webhooks/ID/TOKEN'" >&2
        echo "  or set SLACK_WEBHOOK, TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, MATRIX_* or WEBHOOK_URL there" >&2
        return 1
    fi

    echo -e "${G}✓${NC} ALERTS_ENABLED=1 in $target_config"

    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${Y}no systemctl on this host — run \`milog daemon\` under your own supervisor${NC}"
        return 0
    fi
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${Y}systemd setup needs root. Re-run:${NC}  sudo milog alert on"
        return 0
    fi

    _alert_install_service "$target_user" "$target_config"
    echo -e "${G}✓${NC} milog.service enabled and running (User=$target_user)"
    echo
    echo "  Verify state:  milog alert status"
    echo "  Send a test:   milog alert test"
    echo "  Tail log:      sudo journalctl -u milog -f"
}

alert_off() {
    local target_user target_home target_config
    target_user=$(_alert_target_user)
    target_home=$(_alert_target_home "$target_user")
    target_config="$target_home/.config/milog/config.sh"
    _alert_check_config "$target_config" || return 1

    _alert_write_config "$target_user" "$target_home" "ALERTS_ENABLED=0" \
        && echo -e "${G}✓${NC} ALERTS_ENABLED=0 in $target_config"

    if ! command -v systemctl >/dev/null 2>&1; then return 0; fi

    if [[ ! -f /etc/systemd/system/milog.service ]]; then
        return 0
    fi
    if [[ $(id -u) -ne 0 ]]; then
        echo
        echo -e "${Y}To also stop the systemd service:${NC}  sudo milog alert off"
        return 0
    fi
    systemctl stop    milog.service 2>/dev/null || true
    systemctl disable milog.service >/dev/null 2>&1 || true
    echo -e "${G}✓${NC} milog.service stopped and disabled"
}

alert_status() {
    local target_user target_home target_config
    target_user=$(_alert_target_user)
    target_home=$(_alert_target_home "$target_user")
    target_config="$target_home/.config/milog/config.sh"
    _alert_check_config "$target_config" || return 1

    # Read from the target config, not env, so `sudo milog alert status` shows the user's settings rather than root's.
    local d_url s_url tg_token tg_chat mx_hs mx_token mx_room wh_url
    d_url=$(_alert_read_webhook "$target_config")
    s_url=$(   _alert_read_key "$target_config" "SLACK_WEBHOOK")
    tg_token=$(_alert_read_key "$target_config" "TELEGRAM_BOT_TOKEN")
    tg_chat=$( _alert_read_key "$target_config" "TELEGRAM_CHAT_ID")
    mx_hs=$(   _alert_read_key "$target_config" "MATRIX_HOMESERVER")
    mx_token=$(_alert_read_key "$target_config" "MATRIX_TOKEN")
    mx_room=$( _alert_read_key "$target_config" "MATRIX_ROOM")
    wh_url=$(  _alert_read_key "$target_config" "WEBHOOK_URL")

    local enabled svc_state
    enabled=$(_alert_read_key "$target_config" "ALERTS_ENABLED")
    enabled="${enabled:-0}"

    if ! command -v systemctl >/dev/null 2>&1; then
        svc_state="${D}no systemctl${NC}"
    elif systemctl is-active --quiet milog.service 2>/dev/null; then
        svc_state="${G}active${NC}"
    elif [[ -f /etc/systemd/system/milog.service ]]; then
        svc_state="${Y}installed (not running)${NC}"
    else
        svc_state="${D}not installed${NC}"
    fi

    echo -e "\n${W}── MiLog: Alert status ──${NC}\n"

    echo -e "  ${W}destinations${NC}"
    _alert_destinations_status "$d_url" "$s_url" "$tg_token" "$tg_chat" "$mx_hs" "$mx_token" "$mx_room" "$wh_url"
    echo

    printf "  %-18s %s\n"  "ALERTS_ENABLED"  "$enabled"
    printf "  %-18s %ss\n" "cooldown"        "${ALERT_COOLDOWN:-300}"
    printf "  %-18s %ss\n" "dedup window"    "${ALERT_DEDUP_WINDOW:-300}"
    printf "  %-18s %s\n"  "state dir"       "${ALERT_STATE_DIR:-$HOME/.cache/milog}"
    printf "  %-18s %s\n"  "config"          "$target_config"
    printf "  %-18s %b\n"  "systemd service" "$svc_state"

    local routes_raw
    routes_raw=$(_alert_read_routes "$target_config")
    if [[ -n "$routes_raw" ]]; then
        echo
        echo -e "  ${W}routing${NC}"
        printf "    %-18s  %s\n" "RULE / PREFIX" "DESTINATIONS"
        printf "    %-18s  %s\n" "──────────────────" "────────────────────────"
        local line key val
        while IFS= read -r line; do
            line="${line%%#*}"
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "$line" ]] && continue
            if [[ "$line" == *": "* ]]; then
                key="${line%%: *}"; val="${line#*: }"
            else
                key="${line%%:*}"; val="${line#*:}"; val="${val# }"
            fi
            key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"
            val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
            printf "    ${Y}%-18s${NC}  %s\n" "$key" "$val"
        done <<< "$routes_raw"
    else
        echo
        echo -e "  ${W}routing${NC}   ${D}— (not configured; fires fan out to every configured destination)${NC}"
    fi

    local state_file="${ALERT_STATE_DIR:-$HOME/.cache/milog}/alerts.state"
    if [[ -s "$state_file" ]]; then
        echo
        echo -e "  ${W}Recent fires${NC} (most recent first):"
        local now; now=$(date +%s)
        sort -t$'\t' -k2,2 -rn "$state_file" 2>/dev/null | head -5 | \
        while IFS=$'\t' read -r key ts; do
            [[ -n "$ts" && "$ts" =~ ^[0-9]+$ ]] || continue
            printf "    %-32s  %s ago\n" "$key" "$(_alert_fmt_dur $(( now - ts )))"
        done
    fi
    echo
}

alert_test() {
    local target_user target_home target_config
    target_user=$(_alert_target_user)
    target_home=$(_alert_target_home "$target_user")
    target_config="$target_home/.config/milog/config.sh"
    _alert_check_config "$target_config" || return 1

    # Target user's config, not this process's env, for the same sudo reason as alert_status.
    local d_url s_url tg_token tg_chat mx_hs mx_token mx_room wh_url wh_template wh_ctype
    d_url=$(      _alert_read_webhook "$target_config")
    s_url=$(      _alert_read_key "$target_config" "SLACK_WEBHOOK")
    tg_token=$(   _alert_read_key "$target_config" "TELEGRAM_BOT_TOKEN")
    tg_chat=$(    _alert_read_key "$target_config" "TELEGRAM_CHAT_ID")
    mx_hs=$(      _alert_read_key "$target_config" "MATRIX_HOMESERVER")
    mx_token=$(   _alert_read_key "$target_config" "MATRIX_TOKEN")
    mx_room=$(    _alert_read_key "$target_config" "MATRIX_ROOM")
    wh_url=$(     _alert_read_key "$target_config" "WEBHOOK_URL")
    wh_template=$(_alert_read_key "$target_config" "WEBHOOK_TEMPLATE")
    wh_ctype=$(   _alert_read_key "$target_config" "WEBHOOK_CONTENT_TYPE")

    local -a dests_ok=() dests_partial=()
    [[ -n "$d_url"    ]] && dests_ok+=("discord")
    [[ -n "$s_url"    ]] && dests_ok+=("slack")
    if   [[ -n "$tg_token" && -n "$tg_chat" ]]; then dests_ok+=("telegram")
    elif [[ -n "$tg_token" || -n "$tg_chat" ]]; then dests_partial+=("telegram"); fi
    if   [[ -n "$mx_hs" && -n "$mx_token" && -n "$mx_room" ]]; then dests_ok+=("matrix")
    elif [[ -n "$mx_hs" || -n "$mx_token" || -n "$mx_room" ]]; then dests_partial+=("matrix"); fi
    [[ -n "$wh_url"   ]] && dests_ok+=("webhook")

    if (( ${#dests_ok[@]} == 0 )); then
        echo -e "${R}no alert destinations configured in $target_config${NC}" >&2
        if (( ${#dests_partial[@]} > 0 )); then
            echo -e "${Y}  partial:${NC} ${dests_partial[*]} — needs all required vars" >&2
        fi
        echo "  set one first:  milog alert on 'https://discord.com/api/webhooks/ID/TOKEN'" >&2
        echo "  or edit config: milog config edit" >&2
        return 1
    fi

    # Swap the target's destinations into the env for alert_fire, forcing ALERTS_ENABLED=1, then restore them.
    local _s_enabled="$ALERTS_ENABLED" _s_dw="$DISCORD_WEBHOOK" _s_sw="$SLACK_WEBHOOK"
    local _s_tt="$TELEGRAM_BOT_TOKEN" _s_tc="$TELEGRAM_CHAT_ID"
    local _s_mh="$MATRIX_HOMESERVER"  _s_mt="$MATRIX_TOKEN"    _s_mr="$MATRIX_ROOM"
    local _s_wu="${WEBHOOK_URL:-}"    _s_wt="${WEBHOOK_TEMPLATE:-}"  _s_wc="${WEBHOOK_CONTENT_TYPE:-}"
    ALERTS_ENABLED=1
    DISCORD_WEBHOOK="$d_url"
    SLACK_WEBHOOK="$s_url"
    TELEGRAM_BOT_TOKEN="$tg_token"; TELEGRAM_CHAT_ID="$tg_chat"
    MATRIX_HOMESERVER="$mx_hs";     MATRIX_TOKEN="$mx_token";  MATRIX_ROOM="$mx_room"
    WEBHOOK_URL="$wh_url"
    [[ -n "$wh_template" ]] && WEBHOOK_TEMPLATE="$wh_template"
    [[ -n "$wh_ctype"    ]] && WEBHOOK_CONTENT_TYPE="$wh_ctype"

    echo -e "Firing test alert to: ${G}${dests_ok[*]}${NC}"
    if (( ${#dests_partial[@]} > 0 )); then
        echo -e "${Y}  skipped (incomplete config):${NC} ${dests_partial[*]}"
    fi

    alert_fire "MiLog test alert" \
        "Manual test from \`$(hostname 2>/dev/null || echo host)\` at $(date -Iseconds 2>/dev/null || date)" \
        3447003 "alert:test"

    ALERTS_ENABLED="$_s_enabled"
    DISCORD_WEBHOOK="$_s_dw";       SLACK_WEBHOOK="$_s_sw"
    TELEGRAM_BOT_TOKEN="$_s_tt";    TELEGRAM_CHAT_ID="$_s_tc"
    MATRIX_HOMESERVER="$_s_mh";     MATRIX_TOKEN="$_s_mt";     MATRIX_ROOM="$_s_mr"
    WEBHOOK_URL="$_s_wu";           WEBHOOK_TEMPLATE="$_s_wt"; WEBHOOK_CONTENT_TYPE="$_s_wc"
    echo -e "${G}✓${NC} fanout dispatched — check each channel; any silent dest is a wire issue, not a config issue"
}

alert_help() {
    echo -e "
${W}milog alert${NC} — toggle alerting and manage the systemd service

${W}USAGE${NC}
  ${C}milog alert on [WEBHOOK_URL]${NC}  enable alerts; install + start systemd
  ${C}milog alert off${NC}                disable alerts; stop + disable service
  ${C}milog alert status${NC}             show destinations/service/recent-fire state
  ${C}milog alert test${NC}               fire one test alert to EVERY configured
                              destination (Discord + Slack + Telegram + Matrix)
  ${C}milog alert stats [WINDOW]${NC}     fires per rule from alerts.log (default 7d)

${W}EXAMPLES${NC}
  ${D}# First-time setup in one command (Discord):${NC}
  sudo milog alert on 'https://discord.com/api/webhooks/ID/TOKEN'

  ${D}# Verify end-to-end — pings every configured channel at once:${NC}
  milog alert status
  milog alert test

  ${D}# Pause alerting during maintenance:${NC}
  sudo milog alert off

${W}OTHER DESTINATIONS${NC}
  Slack / Telegram / Matrix are opt-in via ${C}milog config edit${NC} or env vars.
  See: ${C}docs/alerts.md${NC}.
"
}

mode_alert() {
    local sub="${1:-status}"; shift 2>/dev/null || true
    case "$sub" in
        on)             alert_on "${1:-}" ;;
        off)            alert_off ;;
        status|'')      alert_status ;;
        test)           alert_test ;;
        stats)          alert_stats "${1:-7d}" ;;
        -h|--help|help) alert_help ;;
        *) echo -e "${R}Unknown alert subcommand:${NC} $sub"; alert_help; exit 1 ;;
    esac
}

# milog alerts [window]: what fired, read from alerts.log.

# today | yesterday | all | Nm | Nh | Nd | Nw -> cutoff epoch; pair with _alerts_window_end_epoch for the upper bound.
_alerts_window_to_epoch() {
    local w="$1"
    local now; now=$(date +%s)
    case "$w" in
        today)
            # UTC midnight, not local; close enough for this view.
            echo $(( now - (now % 86400) ))
            ;;
        yesterday)
            echo $(( now - (now % 86400) - 86400 ))
            ;;
        all)
            echo 0
            ;;
        *[mM])
            local n="${w%[mM]}"
            [[ "$n" =~ ^[0-9]+$ ]] || { echo "invalid window: $w" >&2; return 1; }
            echo $(( now - n * 60 ))
            ;;
        *[hH])
            local n="${w%[hH]}"
            [[ "$n" =~ ^[0-9]+$ ]] || { echo "invalid window: $w" >&2; return 1; }
            echo $(( now - n * 3600 ))
            ;;
        *[dD])
            local n="${w%[dD]}"
            [[ "$n" =~ ^[0-9]+$ ]] || { echo "invalid window: $w" >&2; return 1; }
            echo $(( now - n * 86400 ))
            ;;
        *[wW])
            local n="${w%[wW]}"
            [[ "$n" =~ ^[0-9]+$ ]] || { echo "invalid window: $w" >&2; return 1; }
            echo $(( now - n * 7 * 86400 ))
            ;;
        *)
            echo "invalid window: $w (valid: today / yesterday / all / Nm / Nh / Nd / Nw)" >&2
            return 1
            ;;
    esac
}

# Exclusive upper bound for a window spec, same midnight math as above; 0 = open-ended.
_alerts_window_end_epoch() {
    local now; now=$(date +%s)
    if [[ "$1" == "yesterday" ]]; then
        echo $(( now - (now % 86400) ))
    else
        echo 0
    fi
}

_alerts_fmt_epoch() {
    date -d "@$1" '+%Y-%m-%d %H:%M' 2>/dev/null \
    || date -r  "$1" '+%Y-%m-%d %H:%M' 2>/dev/null \
    || printf '%s' "$1"
}

mode_alerts() {
    local window="${1:-today}"
    local log_file="$ALERT_STATE_DIR/alerts.log"

    if [[ ! -f "$log_file" ]]; then
        echo -e "${D}No alerts logged yet at $log_file${NC}"
        echo -e "${D}  log entries appear here the first time an alert fires with ALERTS_ENABLED=1${NC}"
        return 0
    fi

    local cutoff cutoff_fmt end
    cutoff=$(_alerts_window_to_epoch "$window") || return 1
    cutoff_fmt=$(_alerts_fmt_epoch "$cutoff")
    end=$(_alerts_window_end_epoch "$window")

    echo -e "\n${W}── MiLog: Alerts since ${cutoff_fmt} (window=$window) ──${NC}\n"

    local filtered; filtered=$(mktemp -t milog_alerts.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$filtered'" RETURN

    awk -F'\t' -v cutoff="$cutoff" -v end="$end" '$1 >= cutoff && (end == 0 || $1 < end)' "$log_file" > "$filtered"

    local total; total=$(wc -l < "$filtered" | tr -d ' ')
    total=${total:-0}

    if (( total == 0 )); then
        echo -e "  ${D}no alerts in window${NC}\n"
        return 0
    fi

    # Newest 30 rows, oldest first.
    local list_cap=30
    local shown=$total
    (( shown > list_cap )) && shown=$list_cap
    echo -e "  ${W}timeline${NC} ${D}(showing latest ${shown} of ${total})${NC}"
    printf "  %-16s  %-28s  %s\n" "WHEN" "RULE" "TITLE"
    printf "  %-16s  %-28s  %s\n" "────────────────" "────────────────────────────" "──────"

    # Format dates in bash: awk strftime is gawk-only.
    local epoch rule color title body when rule_disp title_disp col
    while IFS=$'\t' read -r epoch rule color title body; do
        [[ -z "$epoch" ]] && continue
        when=$(_alerts_fmt_epoch "$epoch")
        rule_disp="$rule"
        (( ${#rule_disp} > 28 )) && rule_disp="${rule_disp:0:25}..."
        title_disp="$title"
        (( ${#title_disp} > 50 )) && title_disp="${title_disp:0:47}..."
        case "$color" in
            15158332|16711680)    col="$R" ;;
            16753920|15844367)    col="$Y" ;;
            *)                    col="$G" ;;
        esac
        printf "  %-16s  %b%-28s%b  %s\n" "$when" "$col" "$rule_disp" "$NC" "$title_disp"
    done < <(tail -n "$list_cap" "$filtered")

    echo -e "\n  ${W}by rule (top 10)${NC}"
    awk -F'\t' '{c[$2]++} END {for (r in c) printf "%d\t%s\n", c[r], r}' "$filtered" \
        | sort -rn | head -n 10 \
        | awk -F'\t' '{printf "    %5d  %s\n", $1, $2}'

    echo -e "\n  ${D}total: $total alert(s) in window — log at $log_file${NC}\n"
}

# TSV per rule key in alerts.log from epoch $1 to before $2 (0 = open): fires, key, last fire epoch; busiest first.
_alerts_counts_since() {
    awk -F'\t' -v cutoff="$1" -v end="${2:-0}" '
        $1 >= cutoff && (end == 0 || $1 < end) && $2 != "" { c[$2]++; if ($1 > last[$2]) last[$2] = $1 }
        END { for (k in c) printf "%d\t%s\t%d\n", c[k], k, last[k] }
    ' "$ALERT_STATE_DIR/alerts.log" | sort -t "$(printf '\t')" -k1,1rn -k2,2
}

# milog alert stats [window]: fires per rule key over the window.
alert_stats() {
    local window="${1:-7d}"
    local log_file="$ALERT_STATE_DIR/alerts.log"

    if [[ ! -f "$log_file" ]]; then
        echo -e "${D}No alerts logged yet at $log_file${NC}"
        return 0
    fi

    local cutoff end rows
    cutoff=$(_alerts_window_to_epoch "$window") || return 1
    end=$(_alerts_window_end_epoch "$window")
    rows=$(_alerts_counts_since "$cutoff" "$end")
    (( end == 0 )) && end=$(date +%s)

    echo -e "\n${W}── MiLog: alert stats since $(_alerts_fmt_epoch "$cutoff") (window=$window) ──${NC}\n"

    if [[ -z "$rows" ]]; then
        echo -e "  ${D}no alerts in window${NC}\n"
        return 0
    fi

    # `all` has no window length, so the per-day rate runs from the oldest fire.
    (( cutoff == 0 )) && cutoff=$(awk -F'\t' '{ print $1; exit }' "$log_file")
    # Floor of one day so a short window like `today` just after midnight doesn't extrapolate.
    local span=$(( end - cutoff ))
    (( span >= 86400 )) || span=86400

    printf "  %6s  %7s  %-16s  %s\n" "FIRES" "PER DAY" "LAST" "RULE"
    printf "  %6s  %7s  %-16s  %s\n" "──────" "───────" "────────────────" "────"
    local count key last per_day note total=0
    while IFS=$'\t' read -r count key last; do
        per_day=$(awk -v c="$count" -v s="$span" 'BEGIN { printf "%.1f", c * 86400 / s }')
        note=""
        alert_is_silenced "$key" >/dev/null && note="  ${D}(silenced)${NC}"
        printf "  %6d  %7s  %-16s  %s%b\n" "$count" "$per_day" "$(_alerts_fmt_epoch "$last")" "$key" "$note"
        total=$(( total + count ))
    done < <(printf '%s\n' "$rows" | _tty_safe)

    echo -e "\n  ${D}total: $total fire(s); silenced and deduped fires are never written to alerts.log, so they are not counted.${NC}"
    echo -e "  ${D}milog auto-tune suggests fixes for rules firing more than 10 times a day.${NC}\n"
}
# milog attacker <IP>: everything one IP did across all apps' current access logs (rotated logs are not read).
mode_attacker() {
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        echo -e "${R}usage: milog attacker <IP>${NC}" >&2
        echo -e "${D}  scans all apps' current access.log for one IP's activity${NC}" >&2
        return 1
    fi
    # Only hex digits, dots and colons get through to awk.
    if [[ ! "$ip" =~ ^[0-9a-fA-F:.]+$ ]]; then
        echo -e "${R}invalid IP: $ip${NC}" >&2
        return 1
    fi

    local files=() name
    for name in "${LOGS[@]}"; do
        [[ -f "$LOG_DIR/$name.access.log" ]] && files+=("$LOG_DIR/$name.access.log")
    done
    if (( ${#files[@]} == 0 )); then
        echo -e "${R}no readable app logs in $LOG_DIR${NC}" >&2
        return 1
    fi

    # One "<app>\t<raw line>" row per request.
    local tmp; tmp=$(mktemp -t milog_attacker.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    # Exact field match, so 10.0.0.1 doesn't also match 10.0.0.10.
    for name in "${LOGS[@]}"; do
        local f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] || continue
        awk -v ip="$ip" -v app="$name" '$1 == ip { print app "\t" $0 }' "$f" | _tty_safe >> "$tmp"
    done

    local total; total=$(wc -l < "$tmp" | tr -d ' ')
    total=${total:-0}

    local country=""
    country=$(geoip_country "$ip" 2>/dev/null || true)
    local tag=""
    [[ -n "$country" && "$country" != "—" ]] && tag="  ${D}[${country}]${NC}"

    echo -e "\n${W}── MiLog: Attacker — ${ip}${tag}${W} ──${NC}\n"

    if (( total == 0 )); then
        echo -e "  ${D}No requests from ${ip} in any configured app.${NC}\n"
        return 0
    fi

    # 2-arg match() only; the 3-arg form is gawk-only.
    local first_seen last_seen apps_hit
    first_seen=$(head -n 1 "$tmp" | awk -F'\t' '
        { if (match($2, /\[[^]]+\]/)) print substr($2, RSTART+1, RLENGTH-2) }')
    last_seen=$( tail -n 1 "$tmp" | awk -F'\t' '
        { if (match($2, /\[[^]]+\]/)) print substr($2, RSTART+1, RLENGTH-2) }')
    apps_hit=$(awk -F'\t' '{print $1}' "$tmp" | sort -u | wc -l | tr -d ' ')

    printf "  %-14s %d\n"  "total hits:" "$total"
    printf "  %-14s %s\n"  "first seen:" "${first_seen:-?}"
    printf "  %-14s %s\n"  "last seen:"  "${last_seen:-?}"
    printf "  %-14s %d of %d\n" "apps touched:" "$apps_hit" "${#LOGS[@]}"
    local cti; cti=$(cti_lookup "$ip")
    [[ -n "$cti" ]] && printf "  %-14s %s\n" "crowdsec:" "$cti"

    echo -e "\n  ${W}per-app${NC}"
    awk -F'\t' '
        {
            app = $1
            count[app]++
            # Status code sits right after the closing quote of the request.
            # Portable match: test, then substr(RSTART+offset, 3) for the code.
            if (match($2, /" [1-5][0-9][0-9] /)) {
                s = substr($2, RSTART+2, 3)
                if (substr(s,1,1) == "4") c4[app]++
                if (substr(s,1,1) == "5") c5[app]++
            }
        }
        END {
            for (a in count) printf "%d\t%s\t%d\t%d\n", count[a], a, c4[a]+0, c5[a]+0
        }' "$tmp" | sort -rn | \
    awk -v y="$Y" -v r="$R" -v nc="$NC" -F'\t' '
        {
            c4col = ($3 > 0) ? y : ""
            c5col = ($4 > 0) ? r : ""
            c4end = ($3 > 0) ? nc : ""
            c5end = ($4 > 0) ? nc : ""
            printf "    %-12s  %5d hits  %s4xx:%d%s  %s5xx:%d%s\n",
                   $2, $1, c4col, $3, c4end, c5col, $4, c5end
        }'

    echo -e "\n  ${W}top paths${NC}"
    awk -F'\t' '
        {
            # Request URI is field 7 of the raw logline (combined format).
            # Split $2 on spaces to reach it — log has quoted fields, but
            # $7 lands inside the "GET /path HTTP/1.1" token so it works.
            n = split($2, f, " ")
            path = f[7]
            sub(/\?.*/, "", path)       # strip query string — aggregates variants
            if (path == "" || path ~ /^[0-9]+$/) next
            counts[path]++
        }
        END { for (p in counts) printf "%d\t%s\n", counts[p], p }' "$tmp" | \
    sort -rn | head -n 10 | \
    awk -F'\t' '{
        p = $2
        if (length(p) > 70) p = substr(p, 1, 67) "..."
        printf "    %5d  %s\n", $1, p
    }'

    echo -e "\n  ${W}top user-agents${NC}"
    awk -F'\t' '
        {
            # UA is the last quoted string on the line:
            #   "GET /x HTTP/1.1" 200 123 "referer" "ua-string"[ reqtime]
            # Combined format has no trailing field; combined_timed appends
            # one. Match either by anchoring on "<ua>" followed by end-of-line
            # OR end-of-line after a space + number.
            line = $2
            if (match(line, /"[^"]*"([[:space:]]+[0-9.]+)?[[:space:]]*$/)) {
                # Trim the trailing reqtime (if any) to isolate the UA.
                s = substr(line, RSTART, RLENGTH)
                # Strip trailing reqtime
                sub(/[[:space:]]+[0-9.]+[[:space:]]*$/, "", s)
                sub(/[[:space:]]*$/, "", s)
                # Now s is `"ua-string"` — strip the outer quotes.
                if (length(s) >= 2 && substr(s,1,1) == "\"" && substr(s,length(s),1) == "\"") {
                    uas[substr(s, 2, length(s)-2)]++
                }
            }
        }
        END { for (u in uas) printf "%d\t%s\n", uas[u], u }' "$tmp" | \
    sort -rn | head -n 5 | \
    awk -F'\t' '{
        u = $2
        if (length(u) > 80) u = substr(u, 1, 77) "..."
        printf "    %5d  %s\n", $1, u
    }'

    # Rough path-substring buckets, close to but not identical to _exploit_category.
    echo -e "\n  ${W}classification${NC}"
    awk -F'\t' '
        {
            low = tolower($2)
            cat = "normal"
            if      (low ~ /\/\.env|\/\.git|\/\.aws|\/\.ssh|\/\.htpasswd|\/\.htaccess/) cat = "dotfile"
            else if (low ~ /wp-admin|wp-login|wp-content|xmlrpc|wordpress/) cat = "wordpress"
            else if (low ~ /phpmyadmin|phpunit\/.*\/php\/eval/)            cat = "phpmyadmin"
            else if (low ~ /\.\.\/|%2e%2e|\/etc\/passwd|\/etc\/shadow/)    cat = "traversal"
            else if (low ~ /<script|javascript:|onerror=|onload=/)         cat = "xss"
            else if (low ~ /union[[:space:]]*select|sleep\(|or[[:space:]]+1=1|--[[:space:]]*$/) cat = "sqli"
            else if (low ~ /\$\{jndi:|log4j/)                              cat = "log4shell"
            else if (low ~ /\/(portal|boaform|setup\.cgi|manager\/html|cgi-bin\/|goform|\.well-known\/acme)/) cat = "infra"
            else if (low ~ /\/(shell|cmd|exec|eval)\.php|\/(webshell|c99|r57)/) cat = "rce"
            else if (low ~ /zgrab|masscan|nmap|nikto|sqlmap|dirbuster|gobuster/) cat = "scanner"
            counts[cat]++
        }
        END { for (c in counts) printf "%d\t%s\n", counts[c], c }' "$tmp" | \
    sort -rn | \
    awk -v r="$R" -v y="$Y" -v g="$G" -v d="$D" -v nc="$NC" -F'\t' '
        {
            col = g
            if ($2 != "normal") col = y
            if ($2 ~ /^(traversal|log4shell|sqli|rce|xss)$/) col = r
            if ($2 == "normal") col = d
            printf "    %s%5d  %-12s%s\n", col, $1, $2, nc
        }'

    echo -e "\n  ${W}sample (first 3 + last 3)${NC}"
    local head_lines tail_lines
    head_lines=$(( total < 3 ? total : 3 ))
    head -n "$head_lines" "$tmp" | awk -F'\t' '{printf "    [%-10s] %s\n", $1, $2}'
    if (( total > 6 )); then
        echo -e "    ${D}… ($(( total - 6 )) more) …${NC}"
        tail -n 3 "$tmp" | awk -F'\t' '{printf "    [%-10s] %s\n", $1, $2}'
    elif (( total > 3 )); then
        tail -n $(( total - 3 )) "$tmp" | awk -F'\t' '{printf "    [%-10s] %s\n", $1, $2}'
    fi
    echo
}
# milog audit: host integrity scanners (fim, persistence, ports, yara, accounts, rootkit).
# Drift goes through alert_fire, so silence, cooldown and dedup apply.
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

# Watchlist globs expanded to a sorted, deduped path list.
_audit_fim_expand_paths() {
    local pat path
    local -a out=()
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
    local path sha mtime size st
    local count=0 missing=0

    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        if [[ -e "$path" ]]; then
            sha=$(_audit_sha256 "$path")
            st=$(_audit_stat "$path")
            mtime="${st%%	*}"
            size="${st##*	}"
            [[ -z "$sha" ]] && sha="UNREADABLE"
            (( count++ )) || true
        else
            sha="MISSING"; mtime=0; size=0
            (( missing++ )) || true
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "$path" "$sha" "$mtime" "$size" "$now" >> "$tmp"
    done < <(_audit_fim_expand_paths)

    mv "$tmp" "$out"
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

    local change path detail key body rows=""
    while IFS=$'\t' read -r change path detail; do
        [[ -z "$change" ]] && continue
        rows+="$change"$'\t'"$path"$'\n'
        key="audit:fim:$change:$path"
        if alert_should_fire "$key"; then
            body="\`\`\`$change $path $detail\`\`\`"
            alert_fire "FIM drift: $change $path" "$body" 15158332 "$key" &
        fi
    done < <(_audit_fim_diff)
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

  Subs (fim/persistence/ports/accounts): ${C}baseline${NC} | ${C}check${NC} | ${C}status${NC}
  Subs (yara):                           ${C}init${NC} | ${C}scan${NC} | ${C}status${NC}
  Subs (rootkit):                        ${C}check${NC} | ${C}status${NC}

The watcher runs inside ${C}milog daemon${NC} when ${C}AUDIT_ENABLED=1${NC} —
auto-baselines on first run, then fires ${C}audit:fim:<change>:<path>${NC},
${C}audit:persistence:APPEARED:<path>${NC}, ${C}audit:ports:NEW:<proto>:<port>${NC},
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

    local change path key body rows=""
    while IFS=$'\t' read -r change path; do
        rows+="$change"$'\t'"$path"$'\n'
        [[ "$change" == "APPEARED" ]] || continue
        [[ -z "$path" ]] && continue
        key="audit:persistence:APPEARED:$path"
        if alert_should_fire "$key"; then
            body="\`\`\`new file in re-entry surface: $path\`\`\`"
            alert_fire "Persistence: new $path" "$body" 15158332 "$key" &
        fi
    done < <(_audit_persistence_diff)
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

    local change proto bind port key body rows=""
    while IFS=$'\t' read -r change proto bind port; do
        case "$change" in
            NEW)  rows+="appeared"$'\t'"$bind:$port/$proto"$'\n' ;;
            GONE) rows+="removed"$'\t'"$bind:$port/$proto"$'\n' ;;
        esac
        [[ "$change" == "NEW" ]] || continue
        [[ -z "$proto" || -z "$port" ]] && continue
        key="audit:ports:NEW:$proto:$port"
        if alert_should_fire "$key"; then
            body="\`\`\`new listener: $proto $bind:$port\`\`\`"
            alert_fire "Listener: new $proto $bind:$port" "$body" 15158332 "$key" &
        fi
    done < <(_audit_ports_diff)
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

    # One alert per file, listing at most 5 new lines.
    local prev_file="" body="" capped=""
    local change file line lines_count=0 key b rows=""
    while IFS=$'\t' read -r change file line; do
        rows+="$change"$'\t'"$file"$'\n'
        [[ "$change" == "ADDED" ]] || continue
        [[ -z "$file" ]] && continue
        if [[ "$file" != "$prev_file" ]]; then
            if [[ -n "$prev_file" ]]; then
                [[ -n "$capped" ]] && body="${body}
${capped}"
                key="audit:accounts:NEW:$prev_file"
                if alert_should_fire "$key"; then
                    b="\`\`\`new lines in $prev_file:
$body\`\`\`"
                    alert_fire "Account drift: $prev_file" "$b" 15158332 "$key" &
                fi
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
    done < <(_audit_accounts_diff | sort)   # sort groups ADDED rows by file
    if [[ -n "$prev_file" ]]; then
        [[ -n "$capped" ]] && body="${body}
${capped}"
        key="audit:accounts:NEW:$prev_file"
        if alert_should_fire "$key"; then
            b="\`\`\`new lines in $prev_file:
$body\`\`\`"
            alert_fire "Account drift: $prev_file" "$b" 15158332 "$key" &
        fi
    fi
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

    local heur detail key body rows=""
    while IFS=$'\t' read -r heur detail; do
        [[ -z "$heur" ]] && continue
        rows+="hint"$'\t'"$heur"$'\n'
        key="audit:rootkit:$heur"
        if alert_should_fire "$key"; then
            body="\`\`\`$detail\`\`\`"
            alert_fire "Rootkit hint: $heur" "$body" 15158332 "$key" &
        fi
    done < <(_audit_rootkit_run_all)
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
# milog auto-tune [days]: suggests HTTP thresholds from percentiles of metrics_minute. CPU/MEM/DISK aren't in the DB.
# Also suggests threshold raises or silences for rules that fire too often in alerts.log.

# p-th percentile (1..100) of newline-separated numbers on stdin.
_pct_from_stdin() {
    local p=$1
    sort -n | awk -v p="$p" '
        NF && $1 ~ /^[0-9]+(\.[0-9]+)?$/ { v[++n] = $1 }
        END {
            if (n == 0) exit
            i = int((n * p + 99) / 100)
            if (i < 1) i = 1
            if (i > n) i = n
            print v[i]
        }'
}

# Columns: METRIC(20) CURRENT(11) SUGGESTED(11) DELTA(9).
_tune_row() {
    local metric="$1" current="$2" suggested="$3"
    local delta=""
    if [[ "$current" =~ ^[0-9]+$ && "$suggested" =~ ^[0-9]+$ ]]; then
        local d=$(( suggested - current ))
        if   (( d > 0 )); then delta="${Y}+${d}${NC}"
        elif (( d < 0 )); then delta="${G}${d}${NC}"
        else                   delta="${D}0${NC}"
        fi
    else
        delta="${D}  —${NC}"
    fi
    printf "  %-20s  %-11s  ${W}%-11s${NC}  %b\n" \
        "$metric" "$current" "$suggested" "$delta"
}

# Rules averaging more than 10 fires a day in alerts.log get a printed fix; nothing is applied.
_tune_alert_noise() {
    local days="$1" log_file="$ALERT_STATE_DIR/alerts.log"
    [[ -f "$log_file" ]] || return 0
    local cutoff=$(( $(date +%s) - days * 86400 )) max=$(( days * 10 ))

    echo -e "\n${W}── MiLog: auto-tune noisy alerts (window=${days}d, over 10 fires/day) ──${NC}\n"
    local count key var app pct current kept suggested found=0
    while IFS=$'\t' read -r count key _; do
        (( count > max )) || break
        alert_is_silenced "$key" >/dev/null && continue
        found=1
        var="" app="" pct=0
        case "$key" in
            5xx:*)  var=THRESH_5XX_WARN; app="${key#5xx:}" ;;
            4xx:*)  var=THRESH_4XX_WARN; app="${key#4xx:}" ;;
            aicrawl:*) var=THRESH_AICRAWL_WARN; app="${key#aicrawl:}" ;;
            cpu)    var=THRESH_CPU_CRIT;  pct=1 ;;
            mem)    var=THRESH_MEM_CRIT;  pct=1 ;;
            disk:/) var=THRESH_DISK_CRIT; pct=1 ;;
        esac
        if [[ -n "$var" ]]; then
            current=$(_thresh "$var" "$app")
            # The body's first number is the value that tripped the rule; the new threshold lets only the top $max through.
            kept=$(MILOG_KEY="$key" awk -F'\t' -v cutoff="$cutoff" '
                $1 >= cutoff && $2 == ENVIRON["MILOG_KEY"] && match($5, /[0-9]+/) { print substr($5, RSTART, RLENGTH) }
            ' "$log_file" | sort -rn | sed -n "$(( max + 1 ))p")
            suggested=$(( kept + 1 ))
            (( suggested > current )) || suggested=$(( current + 1 ))
            if (( ! pct || suggested <= 100 )); then
                [[ -n "$app" ]] && var="${var}_${app//[^A-Za-z0-9_]/_}"
                printf "  ${W}%s${NC}  ${D}%s fires, threshold %s${NC}\n" "$key" "$count" "$current"
                printf "    milog config set %s %s\n" "$var" "$suggested"
                continue
            fi
        fi
        # Attackers drive these counts, so muting them would mute attack detection.
        case "$key" in
            exploit:*|audit:*|process:*|proc:*|net:*|file:*)
                printf "  ${W}%s${NC}  ${D}%s fires, high volume: review the source, not silenced${NC}\n" "$key" "$count"
                continue
                ;;
        esac
        printf "  ${W}%s${NC}  ${D}%s fires, a threshold raise can't quiet it${NC}\n" "$key" "$count"
        printf "    milog silence %q 7d 'noisy rule'\n" "$key"
    done < <(_alerts_counts_since "$cutoff" | _tty_safe)

    if (( found == 0 )); then
        echo -e "  ${D}no unsilenced rule fired more than 10 times a day${NC}"
    else
        echo -e "\n  ${D}nothing was applied; run the lines you agree with. Per-rule counts: milog alert stats ${days}d${NC}"
    fi
}

mode_auto_tune() {
    local days="${1:-7}"
    [[ "$days" =~ ^[1-9][0-9]*$ ]] \
        || { echo -e "${R}auto-tune: days must be a positive integer${NC}" >&2; return 1; }

    _tune_alert_noise "$days"

    _history_precheck || return 1

    local now since count
    now=$(date +%s)
    since=$(( now - days * 86400 ))
    count=$(sqlite3 "$HISTORY_DB" \
        "SELECT COUNT(*) FROM metrics_minute WHERE ts >= $since;" 2>/dev/null || echo 0)
    [[ "$count" =~ ^[0-9]+$ ]] || count=0

    echo -e "\n${W}── MiLog: auto-tune (window=${days}d, ${count} rows) ──${NC}\n"

    # Rows are per app per minute; fewer than 100 makes the percentiles noise.
    if (( count < 100 )); then
        echo -e "${R}Not enough history (${count} rows — need ≥100).${NC}"
        echo -e "${D}  let 'milog daemon' run for a few hours with HISTORY_ENABLED=1,${NC}"
        echo -e "${D}  or widen the window: milog auto-tune 30${NC}\n"
        return 1
    fi

    # req > 0 drops idle minutes, which would otherwise pull suggestions toward 0.
    local p95_samples req_samples c4_samples c5_samples
    p95_samples=$(sqlite3 "$HISTORY_DB" \
        "SELECT p95_ms FROM metrics_minute WHERE ts >= $since AND p95_ms IS NOT NULL AND req > 0;" 2>/dev/null)
    req_samples=$(sqlite3 "$HISTORY_DB" \
        "SELECT req FROM metrics_minute WHERE ts >= $since AND req > 0;" 2>/dev/null)
    c4_samples=$(sqlite3 "$HISTORY_DB" \
        "SELECT c4xx FROM metrics_minute WHERE ts >= $since;" 2>/dev/null)
    c5_samples=$(sqlite3 "$HISTORY_DB" \
        "SELECT c5xx FROM metrics_minute WHERE ts >= $since;" 2>/dev/null)

    local s_req_warn s_req_crit s_c4_warn s_c5_warn s_p95_warn s_p95_crit
    s_req_warn=$(printf '%s\n' "$req_samples" | _pct_from_stdin 90)
    s_req_crit=$(printf '%s\n' "$req_samples" | _pct_from_stdin 99)
    s_c4_warn=$( printf '%s\n' "$c4_samples"  | _pct_from_stdin 95)
    s_c5_warn=$( printf '%s\n' "$c5_samples"  | _pct_from_stdin 95)
    s_p95_warn=$(printf '%s\n' "$p95_samples" | _pct_from_stdin 75)
    s_p95_crit=$(printf '%s\n' "$p95_samples" | _pct_from_stdin 99)

    # Floors stop quiet history from suggesting thresholds that fire on any activity.
    [[ "$s_c4_warn"  =~ ^[0-9]+$ ]] && (( s_c4_warn  < 5 )) && s_c4_warn=5
    [[ "$s_c5_warn"  =~ ^[0-9]+$ ]] && (( s_c5_warn  < 1 )) && s_c5_warn=1
    [[ "$s_req_warn" =~ ^[0-9]+$ ]] && (( s_req_warn < 5 )) && s_req_warn=5

    : "${s_req_warn:=}"; : "${s_req_crit:=}"; : "${s_c4_warn:=}"; : "${s_c5_warn:=}"
    : "${s_p95_warn:=}"; : "${s_p95_crit:=}"

    printf "  %-20s  %-11s  %-11s  %-s\n" "METRIC" "CURRENT" "SUGGESTED" "DELTA"
    printf "  %-20s  %-11s  %-11s  %-s\n" "────────────────────" "───────────" "───────────" "──────"
    _tune_row "THRESH_REQ_WARN"  "$THRESH_REQ_WARN"  "${s_req_warn:--}"
    _tune_row "THRESH_REQ_CRIT"  "$THRESH_REQ_CRIT"  "${s_req_crit:--}"
    _tune_row "THRESH_4XX_WARN"  "$THRESH_4XX_WARN"  "${s_c4_warn:--}"
    _tune_row "THRESH_5XX_WARN"  "$THRESH_5XX_WARN"  "${s_c5_warn:--}"
    _tune_row "P95_WARN_MS"      "$P95_WARN_MS"      "${s_p95_warn:--}"
    _tune_row "P95_CRIT_MS"      "$P95_CRIT_MS"      "${s_p95_crit:--}"

    echo -e "\n${W}Ready to apply${NC} ${D}(copy-paste to set):${NC}"
    local line printed=0
    for line in \
        "THRESH_REQ_WARN $s_req_warn" \
        "THRESH_REQ_CRIT $s_req_crit" \
        "THRESH_4XX_WARN $s_c4_warn" \
        "THRESH_5XX_WARN $s_c5_warn" \
        "P95_WARN_MS $s_p95_warn" \
        "P95_CRIT_MS $s_p95_crit"
    do
        local k v
        k="${line%% *}"; v="${line#* }"
        [[ -n "$v" && "$v" =~ ^[0-9]+$ ]] || continue
        printf "  milog config set %s %s\n" "$k" "$v"
        printed=$(( printed + 1 ))
    done
    if (( printed == 0 )); then
        echo -e "  ${D}(no actionable suggestions — samples were empty for every tuned metric)${NC}"
    fi
    echo -e "\n  ${D}note: tunes to the quiet-hour-excluded p90/p75/p95/p99 of your last ${days} day(s).${NC}"
    echo -e "  ${D}       re-run after traffic patterns change (new service, traffic source, load).${NC}\n"
    return 0
}

# milog bench [--full] [--baseline FILE]: times tail scan, slow, top-paths, top and search on synthetic logs.

_bench_gen_fixture() {
    local dst="$1" n="$2"
    # ~80 paths, random IPs, a 90/8/2 split of 200/404/500.
    awk -v n="$n" 'BEGIN {
        srand(42)
        for (i = 0; i < n; i++) {
            ip = sprintf("%d.%d.%d.%d",
                int(rand()*250)+1, int(rand()*250)+1,
                int(rand()*250)+1, int(rand()*250)+1)
            path = sprintf("/api/endpoint-%d", int(rand()*80)+1)
            if (rand() < 0.05) path = path "?page=" int(rand()*100)
            r = rand()
            if      (r < 0.90) status = 200
            else if (r < 0.98) status = 404
            else                status = 500
            rt = rand() * 2.5   # 0..2.5s request time
            printf "%s - - [24/Apr/2026:12:00:00 +0000] \"GET %s HTTP/1.1\" %d 1024 \"-\" \"bench/1.0\" %.3f\n",
                ip, path, status, rt
        }
    }' > "$dst"
}

_bench_time_ms() {
    # Falls back to whole seconds where `date +%N` is unsupported.
    if date +%N >/dev/null 2>&1 && [[ "$(date +%N)" != "N" ]]; then
        local s ns
        s=$(date +%s); ns=$(date +%N)
        printf '%s' $(( s * 1000 + 10#$ns / 1000000 ))
    else
        printf '%s' $(( $(date +%s) * 1000 ))
    fi
}

_bench_run_one() {
    local label="$1" cmd="$2"
    local t0 t1 rc
    t0=$(_bench_time_ms)
    eval "$cmd" >/dev/null 2>&1
    rc=$?
    t1=$(_bench_time_ms)
    local elapsed=$(( t1 - t0 ))
    printf "%-34s  %6d ms  rc=%d\n" "$label" "$elapsed" "$rc"
    if [[ -n "${BENCH_TSV:-}" ]]; then
        printf '%s\t%d\t%d\n' "$label" "$elapsed" "$rc" >> "$BENCH_TSV"
    fi
}

mode_bench() {
    local full=0
    local baseline=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --full)     full=1; shift ;;
            --baseline) baseline="${2:?}"; shift 2 ;;
            -h|--help)  _bench_help; return 0 ;;
            *) echo -e "${R}bench: unknown flag $1${NC}" >&2; return 1 ;;
        esac
    done

    echo -e "\n${W}── MiLog: Bench (synthetic fixtures) ──${NC}\n"

    local tmp; tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" RETURN
    mkdir -p "$tmp/logs"

    local sizes=(10000 100000)
    (( full )) && sizes+=(1000000)

    if [[ -n "$baseline" ]]; then
        : > "$baseline"
        export BENCH_TSV="$baseline"
    fi

    local n file
    for n in "${sizes[@]}"; do
        file="$tmp/logs/bench.access.log"
        echo -e "${D}  generating $n-line fixture…${NC}"
        _bench_gen_fixture "$file" "$n"
        local bytes; bytes=$(wc -c < "$file" | tr -d ' ')
        local mb; mb=$(( bytes / 1024 / 1024 ))
        printf "${W}─── %d lines  (%d MB) ───${NC}\n" "$n" "$mb"

        local env_prefix="MILOG_APPS=bench MILOG_LOG_DIR=$tmp/logs MILOG_CONFIG=/dev/null"
        _bench_run_one "tail-scan ($n lines)" \
            "wc -l < $file"
        _bench_run_one "slow against $n lines" \
            "$env_prefix SLOW_WINDOW=$n $0 slow 10"
        _bench_run_one "top-paths against $n" \
            "$env_prefix SLOW_WINDOW=$n $0 top-paths 10"
        _bench_run_one "top (IPs) against $n" \
            "$env_prefix SLOW_WINDOW=$n $0 top 10"
        _bench_run_one "search (literal) $n" \
            "$env_prefix $0 search 'endpoint-5'"
        echo
    done

    if [[ -n "$baseline" ]]; then
        echo -e "${G}✓${NC} wrote baseline → $baseline"
    fi
    unset BENCH_TSV
}

_bench_help() {
    echo -e "
${W}milog bench${NC} — benchmark harness with synthetic fixtures

${W}USAGE${NC}
  ${C}milog bench${NC}                  quick run (10k + 100k lines)
  ${C}milog bench --full${NC}            adds a 1M-line pass
  ${C}milog bench --baseline FILE${NC}   also write TSV for CI comparison

${W}MEASURES${NC}
  tail-scan throughput, slow / top-paths / top end-to-end, search
"
}
# milog completions install | bash | zsh | fish.

# Bodies come from completions/ in a repo clone, else from the _completions_payload_<shell> functions build.sh bakes in.

_completions_src_dir() {
    local me self_dir
    me="${BASH_SOURCE[0]:-$0}"
    [[ -n "$me" && -f "$me" ]] || return 1
    self_dir=$(cd -P "$(dirname "$me")" 2>/dev/null && pwd) || return 1
    # src/modes/ in a clone, or the repo root for a built milog.sh.
    local candidate
    for candidate in "$self_dir/../../completions" "$self_dir/../completions" "$self_dir/completions"; do
        [[ -d "$candidate" ]] && { printf '%s' "$(cd -P "$candidate" && pwd)"; return 0; }
    done
    return 1
}

mode_completions() {
    local sub="${1:-help}"
    case "$sub" in
        install|-i)      _completions_install ;;
        bash|zsh|fish)   _completions_emit "$sub" ;;
        -h|--help|help)  _completions_help ;;
        *) echo -e "${R}Unknown completions subcommand:${NC} $sub" >&2; _completions_help; return 1 ;;
    esac
}

_completions_help() {
    echo -e "
${W}milog completions${NC} — shell completion installer

${W}USAGE${NC}
  ${C}milog completions install${NC}   install for bash / zsh / fish (auto-detects locations)
  ${C}milog completions bash${NC}       print bash completion to stdout
  ${C}milog completions zsh${NC}        print zsh completion to stdout
  ${C}milog completions fish${NC}       print fish completion to stdout

${W}Manual install (stdout forms)${NC}
  ${C}milog completions bash | sudo tee /usr/share/bash-completion/completions/milog${NC}
  ${C}milog completions zsh  > ~/.local/share/zsh/site-functions/_milog${NC}
  ${C}milog completions fish > ~/.config/fish/completions/milog.fish${NC}
"
}

_completions_install() {
    local src; src=$(_completions_src_dir) || src=""
    local installed=0

    local bash_dst zsh_dst fish_dst
    if [[ $(id -u) -eq 0 ]]; then
        bash_dst="/usr/share/bash-completion/completions/milog"
        zsh_dst="/usr/share/zsh/site-functions/_milog"
        fish_dst="/usr/share/fish/vendor_completions.d/milog.fish"
    else
        bash_dst="$HOME/.local/share/bash-completion/completions/milog"
        zsh_dst="$HOME/.local/share/zsh/site-functions/_milog"
        fish_dst="$HOME/.config/fish/completions/milog.fish"
    fi

    _write_completion() {
        local shell="$1" dst="$2"
        mkdir -p "$(dirname "$dst")" 2>/dev/null || return 1
        local tmp; tmp=$(mktemp "$dst.XXXXXX" 2>/dev/null) || return 1
        if [[ -n "$src" && -f "$src/$(_completions_filename "$shell")" ]]; then
            cp "$src/$(_completions_filename "$shell")" "$tmp"
        else
            _completions_emit "$shell" > "$tmp"
        fi
        if [[ ! -s "$tmp" ]]; then
            rm -f "$tmp"
            echo -e "${R}✗${NC} $shell: empty completion script, not writing $dst" >&2
            return 1
        fi
        if ! chmod 0644 "$tmp" || ! mv "$tmp" "$dst"; then
            rm -f "$tmp"
            return 1
        fi
        echo -e "${G}✓${NC} $shell → $dst"
        installed=$((installed+1))
    }

    _write_completion bash "$bash_dst" || true
    _write_completion zsh  "$zsh_dst"  || true
    _write_completion fish "$fish_dst" || true

    if (( installed == 0 )); then
        echo -e "${R}nothing installed${NC}" >&2
        return 1
    fi
    echo
    echo -e "${D}open a new shell (or source your rc file) to pick them up${NC}"
}

_completions_filename() {
    case "$1" in
        bash) echo "milog.bash" ;;
        zsh)  echo "_milog" ;;
        fish) echo "milog.fish" ;;
    esac
}

_completions_emit() {
    local shell="$1"
    local src; src=$(_completions_src_dir) || src=""
    if [[ -n "$src" ]]; then
        local fname; fname=$(_completions_filename "$shell")
        if [[ -f "$src/$fname" ]]; then
            cat "$src/$fname"
            return 0
        fi
    fi
    local fn="_completions_payload_${shell}"
    if declare -F "$fn" >/dev/null 2>&1; then
        "$fn"
    else
        echo -e "${R}no completions payload available for shell '$shell'${NC}" >&2
        return 1
    fi
}
# milog config: edit the user config file from the CLI.

_cfg_ensure_dir() {
    local d; d=$(dirname "$MILOG_CONFIG")
    mkdir -p "$d" 2>/dev/null || {
        echo -e "${R}Cannot create config directory: $d${NC}" >&2; return 1; }
}

# LOGS as written in the config file, ignoring script defaults; one app per line.
_cfg_read_logs() {
    [[ -f "$MILOG_CONFIG" ]] || return 0
    (
        LOGS=()
        # shellcheck disable=SC1090
        . "$MILOG_CONFIG" 2>/dev/null || true
        (( ${#LOGS[@]} > 0 )) && printf '%s\n' "${LOGS[@]}"
    )
}

_cfg_write_line() {
    local line="$1" key="${1%%=*}"
    _cfg_ensure_dir || return 1
    [[ -e "$MILOG_CONFIG" ]] || : > "$MILOG_CONFIG"
    if grep -qE "^[[:space:]]*${key}=" "$MILOG_CONFIG" 2>/dev/null; then
        local tmp; tmp=$(mktemp)
        awk -v k="$key" -v repl="$line" '
            $0 ~ "^[[:space:]]*" k "=" && !done { print repl; done=1; next }
            { print }
        ' "$MILOG_CONFIG" > "$tmp" && mv "$tmp" "$MILOG_CONFIG"
    else
        printf '%s\n' "$line" >> "$MILOG_CONFIG"
    fi
}

config_show() {
    echo -e "${W}Config path:${NC} $MILOG_CONFIG"
    if [[ -f "$MILOG_CONFIG" ]]; then
        echo -e "${D}  (exists)${NC}"
    else
        echo -e "${D}  (not created yet — run 'milog config init')${NC}"
    fi
    echo
    echo -e "${W}Resolved values:${NC}"
    printf "  %-22s %s\n" "LOG_DIR"          "$LOG_DIR"
    printf "  %-22s (%s)\n" "LOGS"           "${LOGS[*]}"
    printf "  %-22s %s\n" "REFRESH"          "$REFRESH"
    printf "  %-22s %s\n" "SPARK_LEN"        "$SPARK_LEN"
    printf "  %-22s warn=%s crit=%s\n" "req/min"  "$THRESH_REQ_WARN"  "$THRESH_REQ_CRIT"
    printf "  %-22s warn=%s crit=%s\n" "cpu"      "$THRESH_CPU_WARN"  "$THRESH_CPU_CRIT"
    printf "  %-22s warn=%s crit=%s\n" "mem"      "$THRESH_MEM_WARN"  "$THRESH_MEM_CRIT"
    printf "  %-22s warn=%s crit=%s\n" "disk"     "$THRESH_DISK_WARN" "$THRESH_DISK_CRIT"
    printf "  %-22s 4xx=%s 5xx=%s\n"   "status thresholds" "$THRESH_4XX_WARN" "$THRESH_5XX_WARN"
    printf "  %-22s %s/min\n" "AI crawler alert" "$THRESH_AICRAWL_WARN"
    printf "  %-22s warn=%sms crit=%sms\n" "p95 response time" "$P95_WARN_MS" "$P95_CRIT_MS"
    printf "  %-22s %s\n" "SLOW_WINDOW"   "$SLOW_WINDOW"
    printf "  %-22s enabled=%s mmdb=%s\n" "geoip" "$GEOIP_ENABLED" \
        "$([[ -f "$MMDB_PATH" ]] && echo "$MMDB_PATH" || echo "MISSING:$MMDB_PATH")"
    printf "  %-22s enabled=%s db=%s retain=%sd\n" "history" \
        "$HISTORY_ENABLED" "$HISTORY_DB" "$HISTORY_RETAIN_DAYS"
    printf "  %-22s enabled=%s cooldown=%ss dedup=%ss\n" "alerts" \
        "$ALERTS_ENABLED" "$ALERT_COOLDOWN" "${ALERT_DEDUP_WINDOW:-300}"
    # Process env view; `milog alert status` reads a target user's config under sudo.
    _alert_destinations_status \
        "${DISCORD_WEBHOOK:-}" \
        "${SLACK_WEBHOOK:-}" \
        "${TELEGRAM_BOT_TOKEN:-}" "${TELEGRAM_CHAT_ID:-}" \
        "${MATRIX_HOMESERVER:-}" "${MATRIX_TOKEN:-}" "${MATRIX_ROOM:-}" \
        "${WEBHOOK_URL:-}"
}

config_init() {
    if [[ -e "$MILOG_CONFIG" ]]; then
        echo -e "${Y}Config already exists:${NC} $MILOG_CONFIG"
        echo "Use 'milog config edit' to modify, or delete the file first."
        return 1
    fi
    _cfg_ensure_dir || return 1
    cat > "$MILOG_CONFIG" <<'EOF'
# MiLog config — sourced as bash. Overrides defaults from milog.sh.
# Uncomment a line to activate it.

# Directory containing nginx access logs
# LOG_DIR="/var/log/nginx"

# Apps to monitor (basenames of <name>.access.log).
# Leave empty () to auto-discover all *.access.log in LOG_DIR.
# LOGS=(api web admin)

# Dashboard refresh interval (seconds) and sparkline history depth
# REFRESH=5
# SPARK_LEN=30

# Thresholds
# THRESH_REQ_WARN=15
# THRESH_REQ_CRIT=40
# THRESH_CPU_WARN=70
# THRESH_CPU_CRIT=90
# THRESH_MEM_WARN=80
# THRESH_MEM_CRIT=95
# THRESH_DISK_WARN=80
# THRESH_DISK_CRIT=95
# THRESH_4XX_WARN=20
# THRESH_5XX_WARN=5
# THRESH_AICRAWL_WARN=30   # AI-crawler requests/min per app before an aicrawl alert
# P95_WARN_MS=500
# P95_CRIT_MS=1500
# SLOW_WINDOW=1000      # lines scanned per app by `milog slow`

# GeoIP — requires mmdblookup + a MaxMind GeoLite2-Country.mmdb. See README.
# GEOIP_ENABLED=0
# MMDB_PATH="/var/lib/GeoIP/GeoLite2-Country.mmdb"

# CrowdSec CTI reputation in attacker, suspects and exploit/probe alerts. Free key at app.crowdsec.net.
# CROWDSEC_CTI_KEY=""

# Historical metrics — requires sqlite3; writes from `milog daemon` only.
# HISTORY_ENABLED=0
# HISTORY_DB="$HOME/.local/share/milog/metrics.db"
# HISTORY_RETAIN_DAYS=30
# HISTORY_TOP_IP_N=50

# Discord alerts — requires curl. Leave DISCORD_WEBHOOK empty to disable.
# DISCORD_WEBHOOK="https://discord.com/api/webhooks/ID/TOKEN"
# ALERTS_ENABLED=0
# ALERT_COOLDOWN=300
# ALERT_STATE_DIR="$HOME/.cache/milog"
EOF
    echo -e "${G}Created${NC} $MILOG_CONFIG"
    echo "Edit with 'milog config edit' or set values with 'milog config set <KEY> <VALUE>'."
}

config_edit() {
    _cfg_ensure_dir || return 1
    [[ -e "$MILOG_CONFIG" ]] || config_init >/dev/null
    "${EDITOR:-vi}" "$MILOG_CONFIG"
}

config_path() {
    echo "$MILOG_CONFIG"
}

config_set() {
    local key="$1" val="$2"
    if [[ -z "$key" || $# -lt 2 ]]; then
        echo -e "${R}Usage:${NC} milog config set <KEY> <VALUE>"
        return 1
    fi
    # Integers stay bare; everything else is double-quoted.
    local quoted
    if [[ "$val" =~ ^-?[0-9]+$ ]]; then
        quoted="$val"
    else
        quoted="\"${val//\"/\\\"}\""
    fi
    _cfg_write_line "${key}=${quoted}"
    echo -e "${G}Set${NC} ${key}=${quoted} in $MILOG_CONFIG"
}

config_add() {
    local name="$1"
    [[ -z "$name" ]] && { echo -e "${R}Usage:${NC} milog config add <app>"; return 1; }
    local -a cur=()
    local l
    while IFS= read -r l; do [[ -n "$l" ]] && cur+=("$l"); done < <(_cfg_read_logs)
    if (( ${#cur[@]} > 0 )); then
        for l in "${cur[@]}"; do
            [[ "$l" == "$name" ]] && { echo -e "${Y}Already present:${NC} $name"; return 0; }
        done
    fi
    cur+=("$name")
    _cfg_write_line "LOGS=(${cur[*]})"
    echo -e "${G}Added${NC} '$name' → LOGS=(${cur[*]})"
    # Only file-backed sources can be checked cheaply here.
    local _type; _type=$(_log_type_for "$name")
    case "$_type" in
        nginx|text)
            local f; f=$(_log_path_for "$name")
            [[ -f "$f" ]] || echo -e "${D}  note: $f does not exist yet${NC}"
            ;;
        journal)
            command -v journalctl >/dev/null 2>&1 \
                || echo -e "${D}  note: journalctl not on PATH — journal sources need Linux + systemd${NC}"
            ;;
        docker)
            command -v docker >/dev/null 2>&1 \
                || echo -e "${D}  note: docker CLI not on PATH — will fall back to scanning \$MILOG_DOCKER_ROOT${NC}"
            ;;
    esac
}

config_rm() {
    local name="$1"
    [[ -z "$name" ]] && { echo -e "${R}Usage:${NC} milog config rm <app>"; return 1; }
    local -a cur=() new=()
    local l found=0
    while IFS= read -r l; do [[ -n "$l" ]] && cur+=("$l"); done < <(_cfg_read_logs)
    if (( ${#cur[@]} > 0 )); then
        for l in "${cur[@]}"; do
            if [[ "$l" == "$name" ]]; then found=1; else new+=("$l"); fi
        done
    fi
    if (( ! found )); then
        echo -e "${Y}Not present in config LOGS:${NC} $name"
        echo -e "${D}  current: (${cur[*]})${NC}"
        return 1
    fi
    _cfg_write_line "LOGS=(${new[*]})"
    echo -e "${G}Removed${NC} '$name' → LOGS=(${new[*]})"
}

config_dir() {
    local dir="$1"
    [[ -z "$dir" ]] && { echo -e "${R}Usage:${NC} milog config dir <path>"; return 1; }
    config_set LOG_DIR "$dir"
}

config_help() {
    echo -e "
${W}milog config${NC} — edit the user config without opening a text editor

${W}USAGE${NC}
  ${C}milog config${NC}                         show resolved values + config path
  ${C}milog config path${NC}                    print config file path
  ${C}milog config init${NC}                    write a commented template
  ${C}milog config edit${NC}                    open in \$EDITOR  ${D}(escape hatch)${NC}
  ${C}milog config add <app>${NC}               append to LOGS
  ${C}milog config rm  <app>${NC}               remove from LOGS
  ${C}milog config dir <path>${NC}              set LOG_DIR
  ${C}milog config set <KEY> <VALUE>${NC}       set any variable ${D}(REFRESH, THRESH_*, …)${NC}

${W}EXAMPLES${NC}
  milog config add api
  milog config dir /var/log/nginx
  milog config set REFRESH 3
  milog config set THRESH_REQ_CRIT 60
"
}

mode_config() {
    local sub="${1:-show}"; shift 2>/dev/null || true
    case "$sub" in
        ""|show)        config_show ;;
        path)           config_path ;;
        init)           config_init ;;
        edit)           config_edit ;;
        add)            config_add "${1:-}" ;;
        rm|remove|del)  config_rm  "${1:-}" ;;
        dir)            config_dir "${1:-}" ;;
        set)            config_set "${1:-}" "${2:-}" ;;
        validate|check) config_validate ;;
        -h|--help|help) config_help ;;
        *) echo -e "${R}Unknown config subcommand:${NC} $sub"; config_help; exit 1 ;;
    esac
}

# Validates the resolved config (file plus env). Returns 0 clean, 2 warnings only, 1 errors.
config_validate() {
    local errors=0 warnings=0

    local known_exact=(
        LOG_DIR LOGS REFRESH SPARK_LEN
        DISCORD_WEBHOOK SLACK_WEBHOOK
        TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        MATRIX_HOMESERVER MATRIX_TOKEN MATRIX_ROOM
        WEBHOOK_URL WEBHOOK_TEMPLATE WEBHOOK_CONTENT_TYPE
        ALERTS_ENABLED ALERT_COOLDOWN ALERT_DEDUP_WINDOW ALERT_STATE_DIR
        ALERT_LOG_MAX_BYTES ALERT_ROUTES
        HOOKS_DIR ALERT_HOOK_TIMEOUT RULES_FILE
        P95_WARN_MS P95_CRIT_MS SLOW_WINDOW SLOW_EXCLUDE_PATHS
        GEOIP_ENABLED MMDB_PATH CROWDSEC_CTI_KEY
        HISTORY_ENABLED HISTORY_DB HISTORY_RETAIN_DAYS HISTORY_TOP_IP_N
        WEB_PORT WEB_BIND WEB_STATE_DIR WEB_TOKEN_FILE
        THRESH_REQ_WARN THRESH_REQ_CRIT
        THRESH_CPU_WARN THRESH_CPU_CRIT
        THRESH_MEM_WARN THRESH_MEM_CRIT
        THRESH_DISK_WARN THRESH_DISK_CRIT
        THRESH_4XX_WARN THRESH_5XX_WARN
        THRESH_AICRAWL_WARN
    )
    # Prefixes for per-app overrides like THRESH_REQ_CRIT_finance.
    local known_prefix=( THRESH_ P95_WARN_MS_ P95_CRIT_MS_ AUDIT_ )

    echo -e "\n${W}── MiLog: Config validate ──${NC}\n"
    echo -e "  ${D}config: $MILOG_CONFIG${NC}"

    # Unknown keys, read from the config file itself rather than the environment.
    if [[ -r "$MILOG_CONFIG" ]]; then
        local line key known fam
        while IFS= read -r line; do
            line="${line%%#*}"; line="${line# }"; line="${line%$'\r'}"
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)= ]] || continue
            key="${BASH_REMATCH[1]}"
            known=0
            local kk
            for kk in "${known_exact[@]}"; do
                [[ "$kk" == "$key" ]] && { known=1; break; }
            done
            if (( ! known )); then
                for fam in "${known_prefix[@]}"; do
                    [[ "$key" == "$fam"* ]] && { known=1; break; }
                done
            fi
            if (( ! known )); then
                echo -e "  ${Y}warn${NC}  unknown key: ${key}"
                warnings=$((warnings+1))
            fi
        done < "$MILOG_CONFIG"
    fi

    local v
    _check_int() {
        local name="$1" min="${2:-}" max="${3:-}" val
        val="${!name:-}"
        if [[ -n "$val" && ! "$val" =~ ^[0-9]+$ ]]; then
            echo -e "  ${R}err${NC}   $name must be a non-negative integer, got: $val"
            errors=$((errors+1)); return
        fi
        [[ -z "$val" ]] && return
        if [[ -n "$min" ]] && (( val < min )); then
            echo -e "  ${R}err${NC}   $name < $min: $val"; errors=$((errors+1))
        fi
        if [[ -n "$max" ]] && (( val > max )); then
            echo -e "  ${Y}warn${NC}  $name > $max: $val (unusually high)"; warnings=$((warnings+1))
        fi
    }
    _check_int REFRESH 1 60
    _check_int ALERT_COOLDOWN 1 3600
    _check_int ALERT_DEDUP_WINDOW 0 3600
    _check_int WEB_PORT 1 65535
    _check_int THRESH_CPU_WARN  0 100
    _check_int THRESH_CPU_CRIT  0 100
    _check_int THRESH_MEM_WARN  0 100
    _check_int THRESH_MEM_CRIT  0 100
    _check_int THRESH_DISK_WARN 0 100
    _check_int THRESH_DISK_CRIT 0 100
    _check_int THRESH_AICRAWL_WARN 0
    _check_int P95_WARN_MS 0
    _check_int P95_CRIT_MS 0
    _check_int SLOW_WINDOW 1

    if [[ ! -d "$LOG_DIR" ]]; then
        echo -e "  ${R}err${NC}   LOG_DIR does not exist: $LOG_DIR"
        errors=$((errors+1))
    elif [[ ! -r "$LOG_DIR" ]]; then
        echo -e "  ${R}err${NC}   LOG_DIR not readable: $LOG_DIR (add user to 'adm' group)"
        errors=$((errors+1))
    fi

    # Syntax only; nothing touches the network.
    if [[ -n "${DISCORD_WEBHOOK:-}" && ! "$DISCORD_WEBHOOK" =~ ^https:// ]]; then
        echo -e "  ${Y}warn${NC}  DISCORD_WEBHOOK should start with https://"
        warnings=$((warnings+1))
    fi
    if [[ -n "${SLACK_WEBHOOK:-}" && ! "$SLACK_WEBHOOK" =~ ^https:// ]]; then
        echo -e "  ${Y}warn${NC}  SLACK_WEBHOOK should start with https://"
        warnings=$((warnings+1))
    fi
    if [[ -n "${WEBHOOK_URL:-}" && ! "$WEBHOOK_URL" =~ ^https?:// ]]; then
        echo -e "  ${Y}warn${NC}  WEBHOOK_URL should be http(s)://"
        warnings=$((warnings+1))
    fi
    if [[ -n "${MATRIX_HOMESERVER:-}" && ! "$MATRIX_HOMESERVER" =~ ^https:// ]]; then
        echo -e "  ${Y}warn${NC}  MATRIX_HOMESERVER should start with https://"
        warnings=$((warnings+1))
    fi
    # A partial Telegram or Matrix config can never send, so it's an error.
    if [[ -n "${TELEGRAM_BOT_TOKEN:-}$TELEGRAM_CHAT_ID" ]]; then
        if [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]]; then
            echo -e "  ${R}err${NC}   Telegram partial config — need both BOT_TOKEN and CHAT_ID"
            errors=$((errors+1))
        fi
    fi
    local mx="${MATRIX_HOMESERVER:-}${MATRIX_TOKEN:-}${MATRIX_ROOM:-}"
    if [[ -n "$mx" ]]; then
        if [[ -z "${MATRIX_HOMESERVER:-}" || -z "${MATRIX_TOKEN:-}" || -z "${MATRIX_ROOM:-}" ]]; then
            echo -e "  ${R}err${NC}   Matrix partial config — need HOMESERVER + TOKEN + ROOM"
            errors=$((errors+1))
        fi
    fi

    echo
    if (( errors == 0 && warnings == 0 )); then
        echo -e "  ${G}✓ config is clean${NC}\n"
        return 0
    fi
    printf "  %s errors, %s warnings\n\n" "$errors" "$warnings"
    if (( errors > 0 )); then return 1; fi
    return 2
}

# Default `milog` view: the last 10 lines of every file source merged by timestamp, then live tails of every source.
color_prefix() {
    local pids=()
    local colors=("$B" "$C" "$G" "$M" "$Y" "$R")
    local -a F_files=() F_fcols=() F_flabels=()
    local -a S_cmds=()  S_cols=()  S_labels=()
    local i=0
    local entry
    for entry in "${LOGS[@]}"; do
        local name;  name=$(_log_name_for "$entry")
        local type;  type=$(_log_type_for "$entry")
        local col="${colors[$(( i % ${#colors[@]} ))]}"
        local label; label=$(printf "%-10s" "$name")

        local cmd
        cmd=$(_log_reader_cmd "$entry") || { (( i++ )) || true; continue; }
        [[ -z "$cmd" ]] && { (( i++ )) || true; continue; }
        S_cmds+=("$cmd")
        S_cols+=("$col")
        S_labels+=("$label")

        if [[ "$type" == "nginx" || "$type" == "text" ]]; then
            local file; file=$(_log_path_for "$entry")
            if [[ -f "$file" ]]; then
                F_files+=("$file")
                F_fcols+=("$col")
                F_flabels+=("$label")
            fi
        fi
        (( i++ )) || true
    done

    # journal and docker sources have no cheap "last N lines", so they only stream live.
    if (( ${#F_files[@]} > 0 )); then
        {
            local idx
            for idx in "${!F_files[@]}"; do
                tail -n 10 "${F_files[$idx]}" 2>/dev/null | _tty_safe | \
                    awk -v col="${F_fcols[$idx]}" -v lbl="${F_flabels[$idx]}" -v nc="$NC" '
                    {
                        if (match($0, /\[[0-9]{2}\/[A-Za-z]+\/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}/)) {
                            d     = substr($0, RSTART+1,  2)
                            mname = substr($0, RSTART+4,  3)
                            y     = substr($0, RSTART+8,  4)
                            hms   = substr($0, RSTART+13, 8)
                            mi = index("JanFebMarAprMayJunJulAugSepOctNovDec", mname)
                            mo = int((mi + 2) / 3)
                            key = sprintf("%s%02d%s%s", y, mo, d, hms)
                        } else {
                            key = "00000000000000000"
                        }
                        printf "%s\t%s[%s]%s %s\n", key, col, lbl, nc, $0
                    }'
            done
        } | sort -k1,1 | cut -f2-
    fi

    local idx
    for idx in "${!S_cmds[@]}"; do
        bash -c "${S_cmds[$idx]}" 2>/dev/null | _tty_safe | \
            awk -v col="${S_cols[$idx]}" -v lbl="${S_labels[$idx]}" -v nc="$NC" \
                '{print col"["lbl"]"nc" "$0; fflush()}' &
        pids+=($!)
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

# milog daemon: headless sampler and rule evaluator, logging to stderr.

mode_daemon() {
    # Refuse to start on config errors; warnings only get printed.
    local rc=0
    config_validate >&2 || rc=$?
    if (( rc == 1 )); then
        _dlog "ABORT: config validate reported errors — fix them or run \`milog config validate\`"
        exit 1
    fi

    local hook_state="disabled" have_dest=0
    _alert_any_destination "$DISCORD_WEBHOOK" "$SLACK_WEBHOOK" "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_CHAT_ID" \
        "$MATRIX_HOMESERVER" "$MATRIX_TOKEN" "$MATRIX_ROOM" "$WEBHOOK_URL" && have_dest=1
    [[ "$ALERTS_ENABLED" == "1" ]] && (( have_dest )) && hook_state="enabled"
    _dlog "milog daemon starting — refresh=${REFRESH}s alerts=${hook_state} history=${HISTORY_ENABLED} apps=(${LOGS[*]})"
    [[ "$ALERTS_ENABLED" != "1" ]] && _dlog "WARNING: ALERTS_ENABLED=0 — rules will log but no webhooks will be fired"
    (( have_dest )) || _dlog "WARNING: no alert destination configured — no webhooks will be fired"

    history_init   # no-op when HISTORY_ENABLED=0; disables itself on error

    # Watcher stdout is discarded; their alerts fire from inside each mode.
    local watcher_pids=()
    ( mode_exploits > /dev/null ) & watcher_pids+=($!)
    ( mode_probes   > /dev/null ) & watcher_pids+=($!)
    ( mode_patterns > /dev/null ) & watcher_pids+=($!)

    local _cleanup='
        _dlog "milog daemon shutting down"
        kill "${watcher_pids[@]}" 2>/dev/null
        exit 0
    '
    trap "$_cleanup" INT TERM

    # Start at the current period so the first write covers a complete minute, never a partial one.
    local last_min last_hour last_day now
    now=$(date +%s)
    last_min=$((  now / 60   ))
    last_hour=$(( now / 3600 ))
    last_day=$((  now / 86400 ))

    while :; do
        local CUR_TIME
        CUR_TIME=$(date '+%d/%b/%Y:%H:%M')

        local cpu mem_pct mem_used mem_total disk_pct disk_used disk_total
        cpu=$(cpu_usage)
        [[ "$cpu" =~ ^[0-9]+$ ]] || cpu=0
        read -r mem_pct mem_used mem_total <<< "$(mem_info)"
        read -r disk_pct disk_used disk_total <<< "$(disk_info)"

        local worker_count
        worker_count=$(ps aux 2>/dev/null | awk '/nginx: worker/{n++} END{print n+0}')

        sys_check_alerts "$cpu" "$mem_pct" "$mem_used" "$mem_total" \
                         "$disk_pct" "$disk_used" "$disk_total" "$worker_count"

        local name cnt c2 c3 c4 c5 ai
        for name in "${LOGS[@]}"; do
            read -r cnt c2 c3 c4 c5 ai <<< "$(nginx_minute_counts "$name" "$CUR_TIME")"
            cnt=${cnt:-0}; c4=${c4:-0}; c5=${c5:-0}
            nginx_check_http_alerts "$name" "$c4" "$c5"
            nginx_check_ai_alert "$name" "${ai:-0}" "$cnt"
        done

        # Each scanner throttles itself by its AUDIT_*_INTERVAL and no-ops when disabled.
        _audit_fim_tick
        _audit_persistence_tick
        _audit_ports_tick
        _audit_yara_tick
        _audit_accounts_tick
        _audit_rootkit_tick

        # Write the previous minute and hour, which are complete.
        now=$(date +%s)
        local cur_min=$((  now / 60   ))
        local cur_hour=$(( now / 3600 ))
        if (( cur_min > last_min )); then
            local write_ts=$(( last_min * 60 ))
            history_write_minute "$write_ts" "$(_cur_time_at "$write_ts")"
            _anomaly_check_minute "$write_ts"
            last_min=$cur_min
        fi
        if (( cur_hour > last_hour )); then
            local write_hr_ts=$(( last_hour * 3600 ))
            history_write_hour "$write_hr_ts"
            last_hour=$cur_hour
        fi
        local cur_day=$(( now / 86400 ))
        if (( cur_day > last_day )); then
            history_prune
            last_day=$cur_day
        fi

        sleep "$REFRESH"
    done
}

# milog diff: this hour vs the same hour 1 and 7 days ago, per app, from metrics_minute.
mode_diff() {
    _history_precheck || return 1

    local now hr_start_now
    now=$(date +%s)
    hr_start_now=$(( now - (now % 3600) ))

    local yest_start=$((  hr_start_now - 86400     ))
    local yest_end=$((    yest_start   + 3600      ))
    local week_start=$((  hr_start_now - 7 * 86400 ))
    local week_end=$((    week_start   + 3600      ))

    local hr_label
    hr_label=$(date -d "@${hr_start_now}" '+%H:00' 2>/dev/null \
               || date -r "$hr_start_now" '+%H:00' 2>/dev/null \
               || echo "this hour")

    echo -e "\n${W}── MiLog: Hourly diff (${hr_label} vs 1d/7d ago) ──${NC}\n"

    local rows
    rows=$(sqlite3 -separator $'\t' "$HISTORY_DB" <<SQL 2>/dev/null
SELECT app,
       COALESCE(SUM(CASE WHEN ts >= $hr_start_now AND ts < $now      THEN req END), 0) AS now_r,
       COALESCE(SUM(CASE WHEN ts >= $yest_start   AND ts < $yest_end THEN req END), 0) AS d1,
       COALESCE(SUM(CASE WHEN ts >= $week_start   AND ts < $week_end THEN req END), 0) AS d7
FROM metrics_minute
WHERE ts >= $week_start
GROUP BY app
ORDER BY app;
SQL
)
    if [[ -z "$rows" ]]; then
        echo -e "  ${D}no data in the windows${NC}\n"
        return 0
    fi

    # ASCII labels and dividers sized to visual width; Δ is multi-byte and breaks printf padding.
    printf "  %-12s  %10s  %10s  %10s  %8s  %8s\n" \
           "APP" "NOW" "1d ago" "7d ago" "d1 %" "d7 %"
    printf "  %-12s  %10s  %10s  %10s  %8s  %8s\n" \
           "────────────" "──────────" "──────────" "──────────" "────────" "────────"

    local app now_r d1 d7 d1p d7p d1_col d7_col
    while IFS=$'\t' read -r app now_r d1 d7; do
        now_r=${now_r:-0}; d1=${d1:-0}; d7=${d7:-0}
        if (( d1 > 0 )); then
            d1p=$(( (now_r - d1) * 100 / d1 ))
            d1_col=$G
            (( d1p <= -25 || d1p >= 50 ))  && d1_col=$Y
            (( d1p <= -50 || d1p >= 100 )) && d1_col=$R
            d1p="$(printf '%+d%%' "$d1p")"
        else
            d1p="—"; d1_col="$D"
        fi
        if (( d7 > 0 )); then
            d7p=$(( (now_r - d7) * 100 / d7 ))
            d7_col=$G
            (( d7p <= -25 || d7p >= 50 ))  && d7_col=$Y
            (( d7p <= -50 || d7p >= 100 )) && d7_col=$R
            d7p="$(printf '%+d%%' "$d7p")"
        else
            d7p="—"; d7_col="$D"
        fi
        printf "  %-12s  %10d  %10d  %10d  ${d1_col}%8s${NC}  ${d7_col}%8s${NC}\n" \
               "$app" "$now_r" "$d1" "$d7" "$d1p" "$d7p"
    done <<< "$rows"
    echo
    echo -e "  ${D}(NOW is the partial current hour so far; 1d/7d are full same-hour windows)${NC}"
    echo
}

# milog digest [day|week|N<h|d|w>]: summary of alert fires, per-app traffic and top IPs.

_digest_window_to_secs() {
    local w="${1:-day}"
    case "$w" in
        day|daily|24h)   echo 86400 ;;
        week|weekly|7d)  echo 604800 ;;
        hour|1h)         echo 3600 ;;
        *[hH])           local n="${w%[hH]}"; [[ "$n" =~ ^[0-9]+$ ]] && echo $(( n * 3600 )) || return 1 ;;
        *[dD])           local n="${w%[dD]}"; [[ "$n" =~ ^[0-9]+$ ]] && echo $(( n * 86400 )) || return 1 ;;
        *[wW])           local n="${w%[wW]}"; [[ "$n" =~ ^[0-9]+$ ]] && echo $(( n * 604800 )) || return 1 ;;
        *)               return 1 ;;
    esac
}

# Epoch math is hand-rolled because BSD awk and busybox awk lack mktime().
_digest_in_window() {
    awk -v cutoff="$1" '
        BEGIN {
            split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
            for (i = 1; i <= 12; i++) mon[m[i]] = i
        }
        {
            split(substr($4, 2), t, /[\/:]/)
            if (!(t[2] in mon)) next
            y = t[3] + 0; mo = mon[t[2]]
            if (mo <= 2) { y--; mo += 12 }
            days = 365*y + int(y/4) - int(y/100) + int(y/400) + int((153*(mo-3) + 2) / 5) + t[1] - 719469
            ts = days*86400 + t[4]*3600 + t[5]*60 + t[6]
            off = (substr($5, 2, 2)*60 + substr($5, 4, 2)) * 60
            ts += (substr($5, 1, 1) == "-") ? off : -off
            if (ts >= cutoff) print
        }' "$2"
}

mode_digest() {
    local window="${1:-day}"
    local secs; secs=$(_digest_window_to_secs "$window") || { echo -e "${R}digest: invalid window: $window${NC}" >&2; return 1; }
    local now; now=$(date +%s)
    local cutoff=$(( now - secs ))
    local window_human
    case "$window" in
        day|daily|24h) window_human="last 24 hours" ;;
        week|weekly|7d) window_human="last 7 days" ;;
        *) window_human="last $window" ;;
    esac

    echo -e "\n${W}── MiLog: Digest (${window_human}) ──${NC}\n"
    echo -e "${D}  generated $(date -Iseconds 2>/dev/null || date) · host $(hostname 2>/dev/null || echo host)${NC}\n"

    local alog="${ALERT_STATE_DIR:-$HOME/.cache/milog}/alerts.log"
    echo -e "${W}Alerts fired${NC}"
    if [[ ! -f "$alog" ]]; then
        echo -e "  ${D}no alerts.log yet${NC}"
    else
        local total crit warn info
        total=$(awk -F'\t' -v c="$cutoff" '$1 >= c' "$alog" | wc -l | tr -d ' ')
        crit=$(awk -F'\t' -v c="$cutoff" '$1 >= c && ($3==15158332 || $3==16711680)' "$alog" | wc -l | tr -d ' ')
        warn=$(awk -F'\t' -v c="$cutoff" '$1 >= c && ($3==16753920 || $3==15844367)' "$alog" | wc -l | tr -d ' ')
        info=$(awk -F'\t' -v c="$cutoff" '$1 >= c && $3!=15158332 && $3!=16711680 && $3!=16753920 && $3!=15844367' "$alog" | wc -l | tr -d ' ')
        printf "  %-20s %s  (${R}%s crit${NC}  ${Y}%s warn${NC}  ${G}%s info${NC})\n" \
            "total" "$total" "$crit" "$warn" "$info"
        if (( total > 0 )); then
            echo
            echo -e "  ${W}top rules${NC}"
            awk -F'\t' -v c="$cutoff" '$1 >= c {cnt[$2]++} END {for (r in cnt) printf "%d\t%s\n", cnt[r], r}' "$alog" \
                | sort -rn | head -10 \
                | awk -F'\t' '{printf "    %5d  %s\n", $1, $2}'
        fi
    fi
    echo

    echo -e "${W}Traffic${NC}"
    printf "  %-14s  %10s  %8s  %8s\n" "APP" "REQ" "4XX" "5XX"
    printf "  %-14s  %10s  %8s  %8s\n" "────────────" "──────────" "────────" "────────"
    local entry name file
    for entry in "${LOGS[@]}"; do
        [[ "$(_log_type_for "$entry")" == "nginx" ]] || continue
        name=$(_log_name_for "$entry")
        file=$(_log_path_for "$entry")
        [[ -f "$file" ]] || continue
        read -r req c4 c5 <<< "$(_digest_in_window "$cutoff" "$file" 2>/dev/null | awk '
            {
                n++
                if ($9 ~ /^4/) c4++
                else if ($9 ~ /^5/) c5++
            }
            END { printf "%d %d %d\n", n+0, c4+0, c5+0 }')"
        printf "  %-14s  %10d  ${Y}%8d${NC}  ${R}%8d${NC}\n" "$name" "${req:-0}" "${c4:-0}" "${c5:-0}"
    done
    echo

    echo -e "${W}Top attacker IPs (this window)${NC}"
    local ip_rollup
    ip_rollup=$(
        for entry in "${LOGS[@]}"; do
            [[ "$(_log_type_for "$entry")" == "nginx" ]] || continue
            file=$(_log_path_for "$entry")
            [[ -f "$file" ]] || continue
            _digest_in_window "$cutoff" "$file" | awk '{print $1}'
        done | sort | uniq -c | sort -rn | head -10
    )
    if [[ -n "$ip_rollup" ]]; then
        local ip_col
        while IFS= read -r line; do
            printf "  %s\n" "$line"
        done <<< "$ip_rollup"
    else
        echo -e "  ${D}—${NC}"
    fi
    echo
}
# milog doctor: shows every missing or degraded capability with a hint. Exits 1 only when a required dep is missing.
_doc_line() {
    # $1=marker (colored glyph)  $2=headline  $3=optional hint
    printf "  %b %s\n" "$1" "$2"
    [[ -n "${3:-}" ]] && printf "     ${D}%s${NC}\n" "$3"
    return 0   # guard against set -e when hint is empty
}
_doc_ok()   { _doc_line "${G}✓${NC}" "$1" "${2:-}"; }
_doc_warn() { _doc_line "${Y}!${NC}" "$1" "${2:-}"; }
_doc_fail() { _doc_line "${R}✗${NC}" "$1" "${2:-}"; }
_doc_head() { printf "\n${W}── %s ──${NC}\n" "$1"; }

mode_doctor() {
    local fail=0 warn=0
    echo -e "\n${W}── MiLog: doctor ──${NC}"

    # Core tools (required).
    _doc_head "core tools"
    local tool
    for tool in bash gawk curl; do
        if command -v "$tool" >/dev/null 2>&1; then
            _doc_ok "$tool present  ($(command -v "$tool"))"
        else
            _doc_fail "$tool NOT on PATH" "required — install via your package manager"
            fail=$(( fail + 1 ))
        fi
    done
    local bmaj="${BASH_VERSINFO[0]:-3}"
    if (( bmaj >= 4 )); then
        _doc_ok "bash ${BASH_VERSION}  (sparkline cache enabled)"
    else
        _doc_warn "bash ${BASH_VERSION}" "bash<4 — monitor skips the p95 cache; upgrade for smoother TUI"
        warn=$(( warn + 1 ))
    fi

    # Optional tools.
    _doc_head "optional tools"
    if command -v sqlite3 >/dev/null 2>&1; then
        _doc_ok "sqlite3 present  ($(sqlite3 --version 2>/dev/null | awk '{print $1}'))"
    else
        _doc_warn "sqlite3 missing" "trend/replay/diff/auto-tune will be disabled — install 'sqlite3'"
        warn=$(( warn + 1 ))
    fi
    if command -v mmdblookup >/dev/null 2>&1; then
        _doc_ok "mmdblookup present" "GeoIP country enrichment available when GEOIP_ENABLED=1"
    else
        _doc_warn "mmdblookup missing" "GeoIP column disabled — install 'mmdb-bin' / 'libmaxminddb'"
        warn=$(( warn + 1 ))
    fi
    if _audit_have_sha256; then
        _doc_ok "sha256 tool present" "audit fim can hash watched files"
    elif [[ "${AUDIT_ENABLED:-0}" == "1" ]]; then
        _doc_fail "no sha256sum or shasum on PATH" "AUDIT_ENABLED=1 but FIM refuses to baseline — install coreutils"
        fail=$(( fail + 1 ))
    else
        _doc_warn "no sha256sum or shasum on PATH" "audit fim will refuse to baseline — install coreutils"
        warn=$(( warn + 1 ))
    fi

    # Log dir and per-app logs.
    _doc_head "log directory"
    if [[ -d "$LOG_DIR" && -r "$LOG_DIR" ]]; then
        _doc_ok "$LOG_DIR readable"
    else
        _doc_fail "$LOG_DIR missing or unreadable" "set MILOG_LOG_DIR or edit LOG_DIR in $MILOG_CONFIG"
        fail=$(( fail + 1 ))
    fi

    _doc_head "app logs (${#LOGS[@]} configured)"
    if (( ${#LOGS[@]} == 0 )); then
        _doc_warn "LOGS is empty" "add apps via 'milog config add <name>' or set MILOG_APPS='a b c'"
        warn=$(( warn + 1 ))
    else
        local app file mtime now age
        now=$(date +%s)
        for app in "${LOGS[@]}"; do
            file="$LOG_DIR/$app.access.log"
            if [[ ! -f "$file" ]]; then
                _doc_warn "$app — no access log" "expected: $file"
                warn=$(( warn + 1 ))
                continue
            fi
            mtime=$(stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null || echo 0)
            age=$(( now - mtime ))
            if (( age < 3600 )); then
                _doc_ok "$app — active  (last write ${age}s ago)"
            elif (( age < 86400 )); then
                _doc_warn "$app — stale  (last write $(( age / 3600 ))h ago)"
                warn=$(( warn + 1 ))
            else
                _doc_warn "$app — idle  (last write $(( age / 86400 ))d ago)"
                warn=$(( warn + 1 ))
            fi
        done
    fi

    # $request_time check: ✓ if any app's latest line ends in a number with NF >= 12; others may predate a reload.
    _doc_head "nginx log format"
    if (( ${#LOGS[@]} == 0 )); then
        _doc_warn "no configured apps"
    else
        local app file last nf lastfield
        local timed_apps=() untimed_apps=() witness=""
        for app in "${LOGS[@]}"; do
            file="$LOG_DIR/$app.access.log"
            [[ -f "$file" ]] || continue
            last=$(tail -n 200 "$file" 2>/dev/null | awk 'NF>0' | tail -n 1)
            [[ -n "$last" ]] || continue
            nf=$(awk '{print NF}' <<< "$last")
            lastfield=$(awk '{print $NF}' <<< "$last")
            if [[ "$lastfield" =~ ^[0-9]+(\.[0-9]+)?$ ]] && (( nf >= 12 )); then
                timed_apps+=("$app")
                [[ -z "$witness" ]] && witness="$app line ends with $lastfield"
            else
                untimed_apps+=("$app")
            fi
        done
        if (( ${#timed_apps[@]} > 0 )); then
            _doc_ok "extended log format detected  ($witness)" \
                    "slow / p95 / top-paths fully enabled"
            if (( ${#untimed_apps[@]} > 0 )); then
                _doc_warn "apps still showing old-format tail: ${untimed_apps[*]}" \
                          "likely just no post-reload traffic yet — not a config issue"
            fi
        elif (( ${#untimed_apps[@]} > 0 )); then
            _doc_warn "log format appears to be 'combined' (no \$request_time)" \
                      "add \$request_time as the LAST field to enable slow/p95 — see README"
            warn=$(( warn + 1 ))
        else
            _doc_warn "no loglines to inspect in any app"
            warn=$(( warn + 1 ))
        fi
    fi

    # Discord.
    _doc_head "alerting (Discord)"
    if [[ -z "${DISCORD_WEBHOOK:-}" ]]; then
        _doc_warn "DISCORD_WEBHOOK not configured" \
                  "run: sudo milog alert on \"https://discord.com/api/webhooks/ID/TOKEN\""
        warn=$(( warn + 1 ))
    else
        _doc_ok "DISCORD_WEBHOOK configured  (${DISCORD_WEBHOOK:0:40}…)"
        # GET the webhook: Discord ignores an empty POST, and GET returns 404 for stale webhooks.
        local http
        http=$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 \
               "$DISCORD_WEBHOOK" 2>/dev/null || echo 000)
        case "$http" in
            200) _doc_ok "webhook reachable  (HTTP 200)" ;;
            401|403|404) _doc_fail "webhook rejected  (HTTP $http)" "webhook was deleted or token invalid — regenerate in Discord"; fail=$(( fail + 1 )) ;;
            000) _doc_warn "webhook unreachable (network/timeout)" "is this box allowed to egress to discord.com?"; warn=$(( warn + 1 )) ;;
            *)   _doc_warn "webhook returned HTTP $http" "unexpected — may still work for POSTs; test with 'milog alert test'"; warn=$(( warn + 1 )) ;;
        esac
    fi
    if [[ "${ALERTS_ENABLED:-0}" == "1" ]]; then
        _doc_ok "ALERTS_ENABLED=1  (cooldown=${ALERT_COOLDOWN}s, dedup=${ALERT_DEDUP_WINDOW}s)"
    else
        _doc_warn "ALERTS_ENABLED=0" "alerts are armed but disabled — 'milog alert on' to flip"
        warn=$(( warn + 1 ))
    fi
    # Other destinations are opt-in, so "not configured" is informational.
    [[ -n "${SLACK_WEBHOOK:-}" ]] \
        && _doc_ok "Slack webhook configured  (${SLACK_WEBHOOK:0:40}…)"
    [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]] \
        && _doc_ok "Telegram bot configured  (chat=$TELEGRAM_CHAT_ID)"
    [[ -n "${MATRIX_HOMESERVER:-}" && -n "${MATRIX_TOKEN:-}" && -n "${MATRIX_ROOM:-}" ]] \
        && _doc_ok "Matrix configured  (${MATRIX_HOMESERVER} room=$MATRIX_ROOM)"
    local alog="$ALERT_STATE_DIR/alerts.log"
    if [[ -f "$alog" ]]; then
        local now_epoch today_cutoff today_count total_count
        now_epoch=$(date +%s)
        today_cutoff=$(( now_epoch - (now_epoch % 86400) ))
        today_count=$(awk -F'\t' -v c="$today_cutoff" '$1 >= c' "$alog" | wc -l | tr -d ' ')
        total_count=$(wc -l < "$alog" | tr -d ' ')
        _doc_ok "alerts.log: ${total_count} total, ${today_count} today" \
                "view with: milog alerts [today|Nh|Nd|all]"
    fi
    local flog="$ALERT_STATE_DIR/send_failures.log"
    if [[ -s "$flog" ]]; then
        local fail_cutoff fail_count fail_dests fail_status
        fail_cutoff=$(( $(date +%s) - 86400 ))
        fail_count=$(awk -F'\t' -v c="$fail_cutoff" '$1 >= c' "$flog" | wc -l | tr -d ' ')
        fail_dests=$(awk -F'\t' -v c="$fail_cutoff" '$1 >= c {print $2}' "$flog" | sort -u | tr '\n' ' ')
        # Rows written before the status column existed have no $3.
        fail_status=$(awk -F'\t' -v c="$fail_cutoff" '$1 >= c && $3 != "" {print $3}' "$flog" \
            | sort | uniq -c | sort -rn | awk 'NR == 1 {print $2}')
        [[ -n "$fail_status" ]] && fail_dests="${fail_dests% }; mostly HTTP ${fail_status}"
        if (( fail_count > 0 )); then
            _doc_warn "${fail_count} alert deliveries failed in the last 24h  (${fail_dests% })" \
                      "see $flog; test with 'milog alert test'"
            warn=$(( warn + 1 ))
        fi
    fi

    # History DB.
    _doc_head "history (SQLite)"
    if [[ "${HISTORY_ENABLED:-0}" != "1" ]]; then
        _doc_warn "HISTORY_ENABLED=0" "set to 1 to let 'milog daemon' persist metrics for trend/diff/auto-tune"
        warn=$(( warn + 1 ))
    elif ! command -v sqlite3 >/dev/null 2>&1; then
        _doc_fail "HISTORY_ENABLED=1 but sqlite3 missing" "install sqlite3 or set HISTORY_ENABLED=0"
        fail=$(( fail + 1 ))
    elif [[ ! -f "$HISTORY_DB" ]]; then
        _doc_warn "db not yet written: $HISTORY_DB" "run 'milog daemon' for at least one minute to populate"
        warn=$(( warn + 1 ))
    else
        local rows oldest
        rows=$(sqlite3 "$HISTORY_DB" "SELECT COUNT(*) FROM metrics_minute;" 2>/dev/null || echo 0)
        oldest=$(sqlite3 "$HISTORY_DB" "SELECT MIN(ts) FROM metrics_minute;" 2>/dev/null || echo 0)
        if [[ "$rows" =~ ^[0-9]+$ ]] && (( rows > 0 )); then
            local days=0
            if [[ "$oldest" =~ ^[0-9]+$ ]] && (( oldest > 0 )); then
                days=$(( ( $(date +%s) - oldest ) / 86400 ))
            fi
            _doc_ok "$HISTORY_DB  (${rows} rows, ~${days}d of history, retain=${HISTORY_RETAIN_DAYS}d)"
        else
            _doc_warn "$HISTORY_DB is empty" "daemon hasn't flushed a minute yet"
            warn=$(( warn + 1 ))
        fi
    fi

    # GeoIP.
    _doc_head "geoip"
    if [[ "${GEOIP_ENABLED:-0}" != "1" ]]; then
        _doc_warn "GEOIP_ENABLED=0" "optional — set to 1 + install the MaxMind MMDB to enable country column"
        warn=$(( warn + 1 ))
    elif ! command -v mmdblookup >/dev/null 2>&1; then
        _doc_fail "GEOIP_ENABLED=1 but mmdblookup missing"
        fail=$(( fail + 1 ))
    elif [[ ! -f "$MMDB_PATH" ]]; then
        _doc_fail "MMDB not found: $MMDB_PATH" "sign up at maxmind.com and download GeoLite2-Country.mmdb"
        fail=$(( fail + 1 ))
    else
        local probe
        probe=$(geoip_country 8.8.8.8 2>/dev/null)
        if [[ -n "$probe" && "$probe" != "—" ]]; then
            _doc_ok "$MMDB_PATH  (8.8.8.8 → $probe)"
        else
            _doc_warn "$MMDB_PATH present but lookup returned empty — DB may be corrupt"
            warn=$(( warn + 1 ))
        fi
    fi

    _doc_head "crowdsec cti"
    if [[ -z "${CROWDSEC_CTI_KEY:-}" ]]; then
        _doc_ok "off  (CROWDSEC_CTI_KEY empty, no lookups)"
    elif [[ -s "$ALERT_STATE_DIR/cti.err" ]]; then
        local cti_paused=""
        [[ -n "$(find "$ALERT_STATE_DIR/cti/.backoff" -mmin -15 2>/dev/null)" ]] && cti_paused="  (lookups paused for 15 min)"
        _doc_warn "last lookup failed: $(cut -f2 "$ALERT_STATE_DIR/cti.err")${cti_paused}" \
                  "401/403: key rejected; 429: rate limit hit; 000: no answer within 3s"
        warn=$(( warn + 1 ))
    else
        local cti_cached
        cti_cached=$(find "$ALERT_STATE_DIR/cti" -type f ! -name '.*' 2>/dev/null | wc -l | tr -d ' ')
        _doc_ok "on  (${cti_cached} IPs cached in $ALERT_STATE_DIR/cti)"
    fi

    # Web dashboard.
    _doc_head "web dashboard"
    local web_bin
    if web_bin=$(_web_go_binary 2>/dev/null) && [[ -n "$web_bin" ]]; then
        _doc_ok "milog-web binary present  ($web_bin)"
    else
        _doc_warn "milog-web binary not found" \
                  "rerun install.sh — it pulls milog-web from the latest GitHub release"
        warn=$(( warn + 1 ))
    fi
    if [[ -f "$WEB_STATE_DIR/web.pid" ]]; then
        local wpid; wpid=$(cat "$WEB_STATE_DIR/web.pid" 2>/dev/null || true)
        if [[ -n "$wpid" ]] && kill -0 "$wpid" 2>/dev/null; then
            _doc_ok "milog web running  (pid=$wpid, $WEB_BIND:$WEB_PORT)"
        else
            _doc_warn "stale web pidfile (not running)" "milog web stop  # cleans it up"
            warn=$(( warn + 1 ))
        fi
    fi

    # systemd units.
    if command -v systemctl >/dev/null 2>&1; then
        _doc_head "systemd"
        if [[ ! -f /etc/systemd/system/milog.service ]]; then
            _doc_warn "milog.service not installed" "run: sudo milog alert on (installs + enables the unit)"
            warn=$(( warn + 1 ))
        elif systemctl is-active --quiet milog.service 2>/dev/null; then
            _doc_ok "milog.service active" "logs: journalctl -u milog.service -f"
        else
            _doc_warn "milog.service installed but inactive" "start: sudo systemctl start milog.service"
            warn=$(( warn + 1 ))
        fi
        # milog-probe.service runs as root: anything it executes or sources must be root-controlled.
        if [[ -f "$_PROBE_SYSTEMD_UNIT" ]]; then
            local probe_exec probe_cfg
            probe_exec=$(sed -n 's/^ExecStart=//p' "$_PROBE_SYSTEMD_UNIT" | head -1)
            probe_cfg=$(sed -n 's/^Environment=MILOG_CONFIG=//p' "$_PROBE_SYSTEMD_UNIT" | head -1)
            if ! grep -q '^Environment=MILOG_PROBE_ALERT_USER=' "$_PROBE_SYSTEMD_UNIT" \
                && [[ -n "$probe_cfg" && -e "$probe_cfg" ]] && ! _root_trusted_path "$probe_cfg"; then
                _doc_fail "milog-probe.service sources $probe_cfg as root" \
                          "it is user-writable — reinstall: sudo milog probe install-service"
                fail=$(( fail + 1 ))
            elif [[ -n "$probe_exec" ]] && ! _root_trusted_path "$probe_exec"; then
                _doc_fail "milog-probe binary writable by non-root  ($probe_exec)" \
                          "make it and its directory root-owned and not group/other-writable"
                fail=$(( fail + 1 ))
            else
                _doc_ok "milog-probe.service config + binary are root-controlled"
            fi
        fi
        # milog-web.service is reported only once someone has tried to install it.
        local web_unit="${HOME}/.config/systemd/user/milog-web.service"
        if [[ -f "$web_unit" ]]; then
            if systemctl --user is-active --quiet milog-web.service 2>/dev/null; then
                _doc_ok "milog-web.service active (user unit)" "logs: journalctl --user -u milog-web.service -f"
            else
                _doc_warn "milog-web.service installed but inactive" \
                          "start: systemctl --user start milog-web.service"
                warn=$(( warn + 1 ))
            fi
        fi
    fi

    echo
    if (( fail > 0 )); then
        echo -e "  ${R}${fail} failure(s)${NC}, ${Y}${warn} warning(s)${NC} — required functionality is missing."
        return 1
    elif (( warn > 0 )); then
        echo -e "  ${G}core OK${NC} — ${Y}${warn} optional feature(s) disabled${NC}."
        return 0
    else
        echo -e "  ${G}all checks passed${NC}"
        return 0
    fi
}

# milog errors: live tail of failures per source by default; any flag switches to a summary of `app:` fires from alerts.log.

mode_errors() {
    case "${1:-}" in
        --since|--since=*|--source|--source=*|--pattern|--pattern=*|--summary|summary)
            _errors_summary "$@"; return $? ;;
        live|--live|"")
            _errors_live;     return $? ;;
        --help|-h|help)
            _errors_help;     return 0 ;;
        *)
            echo -e "${R}unknown errors flag: $1${NC}" >&2
            _errors_help; return 1 ;;
    esac
}

_errors_help() {
    # printf '%b' renders the colour escapes; a heredoc would print them literally.
    printf '%b' "
${W}milog errors${NC} — what's broken right now, across every log source

  ${C}milog errors${NC}                          live tail (mixed view)
  ${C}milog errors --since <window>${NC}         summary report
  ${C}milog errors --source <name>${NC}          restrict summary to one source
  ${C}milog errors --pattern <name>${NC}         restrict summary to one pattern
  ${C}milog errors --since 1d --pattern panic_go${NC}

Live view (no flags):
  - nginx sources    → tail of 4xx/5xx HTTP lines
  - other sources    → tail of app-pattern matches (panic, OOM, …)

Summary view (any flag): scans alerts.log for ${C}app:<src>:<pat>${NC} fires
within the window. Window grammar: today / yesterday / all / Nm / Nh / Nd / Nw.
"
}

# nginx sources show 4xx/5xx lines; others show matches of the `milog patterns` union.
_errors_live() {
    echo -e "${D}Watching errors across all sources... (Ctrl+C)${NC}"
    echo -e "${D}  nginx sources: 4xx/5xx tail   |   other sources: app-pattern matches${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0
    local pattern_union; pattern_union=$(_patterns_collect | _patterns_union_ere)

    local entry
    for entry in "${LOGS[@]}"; do
        local type;        type=$(_log_type_for "$entry")
        local source_name; source_name=$(_log_name_for "$entry")
        local cmd;         cmd=$(_log_reader_cmd "$entry") || { (( i++ )) || true; continue; }
        [[ -z "$cmd" ]] && { (( i++ )) || true; continue; }
        local col="${colors[$(( i % ${#colors[@]} ))]}" label
        label=$(printf "%-10s" "$source_name")

        case "$type" in
            nginx)
                ( bash -c "$cmd" 2>/dev/null \
                    | grep --line-buffered -E ' [45][0-9][0-9] ' \
                    | _tty_safe \
                    | awk -v col="$col" -v lbl="$label" -v nc="$NC" \
                        '{print col"["lbl"]"nc" "$0; fflush()}' ) &
                pids+=($!)
                ;;
            *)
                # An empty union would make grep match every line.
                if [[ -n "$pattern_union" ]]; then
                    ( bash -c "$cmd" 2>/dev/null \
                        | grep --line-buffered -v '^#' \
                        | grep --line-buffered -E -i -- "$pattern_union" \
                        | _tty_safe \
                        | awk -v col="$col" -v lbl="$label" -v nc="$NC" \
                            '{print col"["lbl"]"nc" "$0; fflush()}' ) &
                    pids+=($!)
                fi
                ;;
        esac
        (( i++ )) || true
    done
    if (( ${#pids[@]} == 0 )); then
        echo -e "${Y}no readable sources — check LOGS in milog config${NC}" >&2
        return 1
    fi
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

# --source and --pattern match rule-key segments exactly, so names pasted from `milog patterns list` work.
_errors_summary() {
    local window="today" want_source="" want_pattern="" arg
    while (( $# )); do
        arg="$1"
        case "$arg" in
            --since)         window="${2:?--since needs a value}";  shift 2 ;;
            --since=*)       window="${arg#--since=}";              shift   ;;
            --source)        want_source="${2:?--source needs a name}"; shift 2 ;;
            --source=*)      want_source="${arg#--source=}";        shift   ;;
            --pattern)       want_pattern="${2:?--pattern needs a name}"; shift 2 ;;
            --pattern=*)     want_pattern="${arg#--pattern=}";      shift   ;;
            --summary|summary) shift ;;
            *)               echo -e "${R}unknown flag: $arg${NC}" >&2; return 1 ;;
        esac
    done

    local log_file="$ALERT_STATE_DIR/alerts.log"
    if [[ ! -s "$log_file" ]]; then
        echo -e "${D}no alerts.log yet — set ALERTS_ENABLED=1 and run \`milog daemon\` to populate${NC}"
        return 0
    fi

    local cutoff cutoff_fmt end
    cutoff=$(_alerts_window_to_epoch "$window") || return 1
    cutoff_fmt=$(_alerts_fmt_epoch "$cutoff")
    end=$(_alerts_window_end_epoch "$window")

    local filtered; filtered=$(mktemp -t milog_errors.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$filtered'" RETURN

    awk -F'\t' \
        -v cutoff="$cutoff" \
        -v end="$end" \
        -v want_src="$want_source" \
        -v want_pat="$want_pattern" '
        $1 < cutoff { next }
        end != 0 && $1 >= end { next }
        $2 !~ /^app:/ { next }
        {
            n = split($2, parts, ":")
            if (n < 3) next
            src = parts[2]
            pat = parts[3]
            if (want_src != "" && src != want_src) next
            if (want_pat != "" && pat != want_pat) next
            print $0 "\t" src "\t" pat
        }' "$log_file" > "$filtered"

    local total; total=$(wc -l < "$filtered" | tr -d ' '); total=${total:-0}
    local hdr_filters=""
    [[ -n "$want_source"  ]] && hdr_filters+=" source=$want_source"
    [[ -n "$want_pattern" ]] && hdr_filters+=" pattern=$want_pattern"
    echo -e "\n${W}── MiLog: app errors since ${cutoff_fmt} (window=$window${hdr_filters}) ──${NC}\n"

    if (( total == 0 )); then
        echo -e "  ${D}no app-pattern fires in window — quiet system or PATTERNS_ENABLED=0${NC}\n"
        return 0
    fi

    echo -e "  ${W}by source${NC}"
    awk -F'\t' '{print $6}' "$filtered" \
        | sort | uniq -c | sort -rn \
        | awk '{printf "    %5d  %s\n", $1, $2}'

    echo -e "\n  ${W}by pattern${NC}"
    awk -F'\t' '{print $7}' "$filtered" \
        | sort | uniq -c | sort -rn \
        | awk '{printf "    %5d  %s\n", $1, $2}'

    local list_cap=20
    local shown=$total
    (( shown > list_cap )) && shown=$list_cap
    echo -e "\n  ${W}timeline${NC} ${D}(latest ${shown} of ${total})${NC}"
    printf "  %-16s  %-12s  %-22s  %s\n" "WHEN" "SOURCE" "PATTERN" "SAMPLE"
    printf "  %-16s  %-12s  %-22s  %s\n" "────────────────" "────────────" "──────────────────────" "──────"
    local epoch rule color title body src pat when sample
    while IFS=$'\t' read -r epoch rule color title body src pat; do
        [[ -z "$epoch" ]] && continue
        when=$(_alerts_fmt_epoch "$epoch")
        # Strip the ``` fences from the body for the sample column.
        sample="${body#\`\`\`}"; sample="${sample%\`\`\`}"
        (( ${#sample} > 60 )) && sample="${sample:0:57}..."
        printf "  %-16s  ${R}%-12s${NC}  ${Y}%-22s${NC}  %s\n" "$when" "$src" "$pat" "$sample"
    done < <(tail -n "$list_cap" "$filtered" | _tty_safe)

    echo -e "\n  ${D}total: $total fire(s) — log at $log_file${NC}\n"
}
# milog exploits: tails access logs for L7 attack payloads and scanner fingerprints.
mode_exploits() {
    echo -e "${D}Watching exploit attempts across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    _rules_load

    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$(( i % ${#colors[@]} ))]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            (
                app="$name"
                tail -F "$file" 2>/dev/null | \
                    grep --line-buffered -Ei -e "$RULES_EXPLOIT" | \
                while IFS= read -r line; do
                    printf '%b[%s]%b %b[EXPLOIT]%b %s\n' "$col" "$label" "$NC" "$R" "$NC" "$(_tty_safe <<< "$line")"
                    cat_slug=$(_exploit_category "$line")
                    # The fingerprint gate stops a second alert when probes matches the same line.
                    fp=$(alert_fingerprint_from_line "$line")
                    if alert_should_fire "exploit:$app:$cat_slug" \
                       && alert_fingerprint_fresh "$fp"; then
                        alert_fire "Exploit attempt: $app / $cat_slug" "$(_alert_fence "${line:0:1800}")$(cti_alert_note "${line%% *}")" 15158332 "exploit:$app:$cat_slug" "${line%% *}" &
                    fi
                done
            ) &
            pids+=($!)
        fi
        (( i++ )) || true
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}
# milog grep <app> <pattern>: filtered tail of one source of any type.
mode_grep() {
    local name="${1:-}" pattern="${2:-.}"
    if [[ -z "$name" ]]; then
        local apps=""
        for entry in "${LOGS[@]}"; do apps+="$(_log_name_for "$entry") "; done
        echo -e "${R}Usage: $0 grep <app> <pattern>${NC}  Apps: ${apps% }"
        exit 1
    fi
    local matching
    matching=$(_log_entry_by_name "$name") || {
        echo -e "${R}unknown source: $name${NC}" >&2; exit 1; }
    local cmd
    cmd=$(_log_reader_cmd "$matching") || {
        echo -e "${R}cannot build reader for $name${NC}" >&2; exit 1; }
    [[ -z "$cmd" ]] && { echo -e "${R}reader empty for $name${NC}" >&2; exit 1; }
    echo -e "${D}stream $matching | grep '$pattern'  (Ctrl+C)${NC}\n"
    bash -c "$cmd" 2>/dev/null | grep --line-buffered -i "$pattern" | _tty_safe
}

# milog health: status-class totals and AI-crawler share per app.
mode_health() {
    echo -e "\n${W}── MiLog: Status Code Health ──${NC}\n"
    printf "%-12s  %8s  %8s  %8s  %8s  %8s  %6s\n" "APP" "TOTAL" "2xx" "3xx" "4xx" "5xx" "AI"
    printf "%-12s  %8s  %8s  %8s  %8s  %8s  %6s\n" "───────────" "───────" "───────" "───────" "───────" "───────" "─────"
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        [[ -f "$file" ]] || { printf "%-12s  %8s\n" "$name" "(not found)"; continue; }
        local total s2=0 s3=0 s4=0 s5=0 ai=0 ai_pct="-"
        total=$(wc -l < "$file")
        # Status from its field after the quoted request, as in nginx_minute_counts.
        read -r s2 s3 s4 s5 < <(awk '
            {
                split($0, q, "\"")
                split(q[3], f, " ")
                if (f[1] ~ /^[2-5][0-9][0-9]$/) c[substr(f[1], 1, 1)]++
            }
            END { printf "%d %d %d %d\n", c[2], c[3], c[4], c[5] }
        ' "$file" 2>/dev/null)
        read -r ai _ < <(nginx_ai_counts "$name")
        (( total > 0 )) && ai_pct="$(( ai * 100 / total ))%"
        local c4=$NC c5=$NC t4 t5
        t4=$(_thresh THRESH_4XX_WARN "$name")
        t5=$(_thresh THRESH_5XX_WARN "$name")
        [[ $s4 -gt $t4 ]] && c4=$Y
        [[ $s5 -gt $t5 ]] && c5=$R
        printf "%-12s  %8s  %8s  %8s  ${c4}%8s${NC}  ${c5}%8s${NC}  %6s\n" \
            "$name" "$total" "$s2" "$s3" "$s4" "$s5" "$ai_pct"
    done
    echo ""
}

# milog install list | <feature> | remove <feature>: add optional system deps after the first install.
# `remove` only prints the package manager command; other tools may depend on the package.

# name : check_cmd : apt_pkg : dnf_pkg : pacman_pkg : description; check_cmd on PATH means installed.
_install_catalog() {
    cat <<"EOF"
geoip:mmdblookup:mmdb-bin:libmaxminddb:libmaxminddb:GeoIP COUNTRY column via MaxMind lookup
history:sqlite3:sqlite3:sqlite:sqlite:history DB for trend / diff / auto-tune
EOF
}

_install_pkg_for() {
    local feature="$1" pm="$2"
    local line; line=$(_install_catalog | awk -F':' -v f="$feature" '$1==f {print}')
    [[ -z "$line" ]] && return 1
    IFS=':' read -r _name _check apt dnf pac _desc <<< "$line"
    case "$pm" in
        apt-get) printf '%s' "$apt" ;;
        dnf|yum) printf '%s' "$dnf" ;;
        pacman)  printf '%s' "$pac" ;;
        *)       return 1 ;;
    esac
}

_install_detect_pm() {
    local pm
    for pm in apt-get dnf yum pacman; do
        command -v "$pm" >/dev/null 2>&1 && { echo "$pm"; return 0; }
    done
    echo none
}

_install_is_installed() {
    local feature="$1"
    local line; line=$(_install_catalog | awk -F':' -v f="$feature" '$1==f {print}')
    [[ -z "$line" ]] && return 1
    local check; check=$(echo "$line" | cut -d: -f2)
    command -v "$check" >/dev/null 2>&1
}

_install_desc() {
    _install_catalog | awk -F':' -v f="$1" '$1==f {print $6}'
}

mode_install() {
    local sub="${1:-list}"; shift 2>/dev/null || true
    case "$sub" in
        list|ls|'')      _install_list ;;
        remove|rm|uninstall) _install_remove "${1:-}" ;;
        -h|--help|help)  _install_help ;;
        *)               _install_add "$sub" ;;   # treat anything else as feature name
    esac
}

_install_list() {
    echo -e "\n${W}── MiLog: Feature install status ──${NC}\n"
    printf "  %-12s  %-16s  %s\n" "FEATURE" "STATUS" "DESCRIPTION"
    printf "  %-12s  %-16s  %s\n" "────────────" "────────────────" "──────────────────────────────"
    local line name desc state
    while IFS=':' read -r name _check _apt _dnf _pac desc; do
        [[ -z "$name" ]] && continue
        if _install_is_installed "$name"; then
            state="${G}✓ installed${NC}"
        else
            state="${D}— not installed${NC}"
        fi
        printf "  %-12s  %b  %s\n" "$name" "$state                " "$desc"
    done < <(_install_catalog)
    echo
    echo -e "${D}  milog install <feature>          add one${NC}"
    echo -e "${D}  milog install remove <feature>   drop it (keeps MiLog config)${NC}"
    echo
}

_install_add() {
    local feature="$1"
    if [[ -z "$feature" ]]; then
        echo -e "${R}usage:${NC} milog install <feature>" >&2
        return 1
    fi
    if ! _install_catalog | awk -F':' -v f="$feature" '$1==f {found=1} END{exit !found}'; then
        echo -e "${R}unknown feature:${NC} $feature" >&2
        echo -e "${D}  available:${NC} $(_install_catalog | cut -d: -f1 | paste -sd' ' -)"
        return 1
    fi

    if _install_is_installed "$feature"; then
        echo -e "${G}✓${NC} $feature is already installed"
        return 0
    fi

    local pm; pm=$(_install_detect_pm)
    if [[ "$pm" == "none" ]]; then
        echo -e "${R}no supported package manager found${NC} (apt-get/dnf/yum/pacman)" >&2
        return 1
    fi

    local pkg; pkg=$(_install_pkg_for "$feature" "$pm")
    if [[ -z "$pkg" ]]; then
        echo -e "${R}no package known for $feature on $pm${NC}" >&2
        return 1
    fi

    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${Y}system-package install needs root. Run:${NC}"
        echo -e "  ${C}sudo milog install $feature${NC}"
        echo
        echo -e "${D}  will run:${NC} ${pm} install ${pkg}"
        return 1
    fi

    echo -e "${W}Installing${NC} $feature ($pm install $pkg)"
    case "$pm" in
        apt-get) apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" ;;
        dnf)     dnf install -y "$pkg" ;;
        yum)     yum install -y "$pkg" ;;
        pacman)  pacman -S --noconfirm "$pkg" ;;
    esac || { echo -e "${R}install failed${NC}" >&2; return 1; }

    if _install_is_installed "$feature"; then
        echo -e "${G}✓${NC} $feature installed"
        _install_post_hint "$feature"
    else
        echo -e "${Y}warn:${NC} package installed but check command not found on PATH yet — open a new shell"
    fi
}

_install_remove() {
    local feature="$1"
    if [[ -z "$feature" ]]; then
        echo -e "${R}usage:${NC} milog install remove <feature>" >&2
        return 1
    fi
    if ! _install_is_installed "$feature"; then
        echo -e "${D}$feature is not installed${NC}"
        return 0
    fi
    echo -e "${Y}Note:${NC} MiLog's install subcommand intentionally does NOT auto-remove"
    echo -e "system packages — other tools on the host may depend on them."
    echo -e "To remove manually:"
    local pm; pm=$(_install_detect_pm)
    local pkg; pkg=$(_install_pkg_for "$feature" "$pm" 2>/dev/null)
    [[ -n "$pkg" ]] || pkg="(package unknown on $pm)"
    case "$pm" in
        apt-get) echo -e "  ${C}sudo apt-get remove ${pkg}${NC}" ;;
        dnf|yum) echo -e "  ${C}sudo ${pm} remove ${pkg}${NC}" ;;
        pacman)  echo -e "  ${C}sudo pacman -R ${pkg}${NC}" ;;
        *)       echo -e "  remove manually via your package manager" ;;
    esac
    echo
    echo -e "${D}MiLog auto-degrades when the feature's tool disappears (see \`milog doctor\`)${NC}"
}

_install_post_hint() {
    case "$1" in
        geoip)
            echo
            echo -e "${D}  Next:${NC} download a MaxMind GeoLite2 DB and point MiLog at it."
            echo -e "${D}    https://www.maxmind.com/en/geolite2/signup${NC}"
            echo -e "${D}    milog config set GEOIP_ENABLED 1${NC}"
            echo -e "${D}    milog config set MMDB_PATH /var/lib/GeoIP/GeoLite2-Country.mmdb${NC}"
            ;;
        web)
            echo
            echo -e "${D}  Next:${NC} ${C}milog web${NC}   or   ${C}milog web install-service${NC}"
            ;;
        history)
            echo
            echo -e "${D}  Next:${NC} ${C}milog config set HISTORY_ENABLED 1${NC} then restart the daemon"
            ;;
    esac
}

_install_help() {
    echo -e "
${W}milog install${NC} — on-demand feature installer

${W}USAGE${NC}
  ${C}milog install list${NC}                  matrix of features + installed status
  ${C}milog install <feature>${NC}             install the feature's system deps
  ${C}milog install remove <feature>${NC}      print the right apt/dnf remove command

${W}FEATURES${NC}
  geoip      GeoIP COUNTRY column (mmdblookup)
  history    history DB for trend / diff / auto-tune (sqlite3)

${D}The web dashboard ships as the milog-web Go binary (no system deps);
install.sh fetches it from the latest GitHub release alongside milog itself.${NC}

${D}install.sh --with-X flags are the \"first-install\" path; this subcommand is for
later additions without rerunning install.sh.${NC}
"
}
# milog monitor is the bash dashboard; milog tui execs the Go Bubble Tea binary when installed.

# Same lookup order as _web_go_binary.
_tui_go_binary() {
    if [[ -n "${MILOG_TUI_BIN:-}" && -x "$MILOG_TUI_BIN" ]]; then
        printf '%s' "$MILOG_TUI_BIN"; return 0
    fi
    local candidate
    for candidate in \
        /usr/local/libexec/milog/milog-tui \
        /usr/local/bin/milog-tui \
        /usr/bin/milog-tui; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"
    local self_dir; self_dir=$(cd "$(dirname "$self")" && pwd)
    for candidate in "$self_dir/go/bin/milog-tui" "$self_dir/../go/bin/milog-tui" "$self_dir/../../go/bin/milog-tui"; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    return 1
}

mode_tui() {
    local go_bin
    if ! go_bin=$(_tui_go_binary); then
        echo -e "${R}milog-tui is not installed.${NC}" >&2
        echo -e "${D}  it builds alongside milog-web. From a clone:${NC}" >&2
        echo -e "${D}    bash build.sh${NC}" >&2
        echo -e "${D}  until packaged releases arrive, \`milog monitor\` (bash)" >&2
        echo -e "${D}  gives the same data with a simpler render loop.${NC}" >&2
        return 1
    fi
    export MILOG_LOG_DIR="$LOG_DIR" \
           MILOG_APPS="${LOGS[*]}" \
           MILOG_REFRESH="${REFRESH:-5}" \
           MILOG_ALERT_STATE_DIR="${ALERT_STATE_DIR:-$HOME/.cache/milog}"
    exec "$go_bin" "$@"
}

mode_monitor() {
    # Sample CPU in the background; cpu_usage sleeps 0.2s and would stall the render loop.
    local cpu_file cpu_pid
    cpu_file=$(mktemp 2>/dev/null || echo "/tmp/milog.cpu.$$")
    echo 0 > "$cpu_file"
    (
        while :; do
            v=$(cpu_usage)
            printf '%s\n' "$v" > "${cpu_file}.tmp" 2>/dev/null \
                && mv "${cpu_file}.tmp" "$cpu_file" 2>/dev/null
            sleep 1
        done
    ) & cpu_pid=$!

    MILOG_HIST_ENABLED=1
    declare -gA HIST

    tput civis 2>/dev/null || true
    stty -echo 2>/dev/null || true

    local _cleanup='
        kill '"$cpu_pid"' 2>/dev/null
        rm -f "'"$cpu_file"'" "'"${cpu_file}.tmp"'" 2>/dev/null
        stty echo 2>/dev/null
        tput cnorm 2>/dev/null
        printf "\n"
    '
    trap "$_cleanup; exit 0" INT TERM
    trap "$_cleanup" EXIT

    local net_prev_rx=0 net_prev_tx=0
    read -r net_prev_rx net_prev_tx _ <<< "$(net_rx_tx)"

    local first=1 paused=0
    while true; do
        milog_update_geometry
        if (( first )); then
            clear
            first=0
        else
            tput cup 0 0 2>/dev/null || printf '\033[H'
        fi
        local CUR_TIME TIMESTAMP TOTAL=0
        CUR_TIME=$(date '+%d/%b/%Y:%H:%M')
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

        local cpu mem_pct mem_used mem_total disk_pct disk_used disk_total
        cpu=$(cat "$cpu_file" 2>/dev/null); cpu=${cpu:-0}
        [[ "$cpu" =~ ^[0-9]+$ ]] || cpu=0
        read -r mem_pct mem_used mem_total <<< "$(mem_info)"
        read -r disk_pct disk_used disk_total <<< "$(disk_info)"

        local net_rx net_tx net_iface
        read -r net_rx net_tx net_iface <<< "$(net_rx_tx)"
        local drx=$(( net_rx - net_prev_rx ))
        local dtx=$(( net_tx - net_prev_tx ))
        if (( ! paused )); then
            net_prev_rx=$net_rx; net_prev_tx=$net_tx
        fi
        local rx_s tx_s; rx_s=$(fmt_bytes "$drx"); tx_s=$(fmt_bytes "$dtx")

        local cpu_col mem_col disk_col
        cpu_col=$(tcol "$cpu"      $THRESH_CPU_WARN  $THRESH_CPU_CRIT)
        mem_col=$(tcol "$mem_pct"  $THRESH_MEM_WARN  $THRESH_MEM_CRIT)
        disk_col=$(tcol "$disk_pct" $THRESH_DISK_WARN $THRESH_DISK_CRIT)

        local cpu_bar mem_bar disk_bar
        cpu_bar=$(ascii_bar $BW "$cpu"      100)
        mem_bar=$(ascii_bar $BW "$mem_pct"  100)
        disk_bar=$(ascii_bar $BW "$disk_pct" 100)

        bdr_top

        local t_p=" MiLog   ${TIMESTAMP}   ${net_iface}"
        local t_c=" ${W}MiLog${NC}   ${D}${TIMESTAMP}${NC}   ${D}${net_iface}${NC}"
        draw_row "$t_p" "$t_c"

        bdr_mid

        local r1_p
        r1_p=$(printf " CPU %3d%% [%-${BW}s]  MEM %3d%% [%-${BW}s]  DISK %3d%% [%-${BW}s]" \
            "$cpu" "$cpu_bar" "$mem_pct" "$mem_bar" "$disk_pct" "$disk_bar")
        local r1_c
        r1_c=$(printf " CPU %b%3d%%%b [%b%s%b]  MEM %b%3d%%%b [%b%s%b]  DISK %b%3d%%%b [%b%s%b]" \
            "$cpu_col"  "$cpu"      "$NC" "$cpu_col"  "$cpu_bar"  "$NC" \
            "$mem_col"  "$mem_pct"  "$NC" "$mem_col"  "$mem_bar"  "$NC" \
            "$disk_col" "$disk_pct" "$NC" "$disk_col" "$disk_bar" "$NC")
        draw_row "$r1_p" "$r1_c"

        # Widest case is 72 visible chars.
        local r2_p=" MEM ${mem_used}/${mem_total}MB  DISK ${disk_used}/${disk_total}GB  dn:${rx_s}/s up:${tx_s}/s"
        local r2_c=" ${D}MEM${NC} ${mem_used}/${mem_total}MB  ${D}DISK${NC} ${disk_used}/${disk_total}GB  ${C}dn:${rx_s}/s${NC} ${G}up:${tx_s}/s${NC}"
        draw_row "$r2_p" "$r2_c"

        bdr_mid

        draw_row " NGINX WORKERS" " ${W}NGINX WORKERS${NC}"
        local workers worker_count
        workers=$(ps aux 2>/dev/null | awk '/nginx: worker/{printf "  pid:%-8s  cpu:%5s%%  mem:%5s%%\n",$2,$3,$4}' | head -6)
        if [[ -z "$workers" ]]; then
            worker_count=0
            draw_row "  (no nginx worker processes found)" "  ${D}(no nginx worker processes found)${NC}"
        else
            worker_count=$(printf '%s\n' "$workers" | wc -l | awk '{print $1}')
            while IFS= read -r wline; do
                draw_row "$wline" "  ${D}${wline:2}${NC}"
            done <<< "$workers"
        fi

        sys_check_alerts "$cpu" "$mem_pct" "$mem_used" "$mem_total" \
                         "$disk_pct" "$disk_used" "$disk_total" "$worker_count"

        bdr_mid

        bdr_hdr
        hdr_row
        bdr_hdr

        for name in "${LOGS[@]}"; do
            nginx_row "$name" "$CUR_TIME" TOTAL
        done

        bdr_sep

        local upstr; upstr=$(uptime -p 2>/dev/null | sed 's/up //' || echo 'n/a')
        local f_p=" TOTAL: ${TOTAL} req/min   UP: ${upstr}"
        local f_c=" ${W}TOTAL:${NC} ${TOTAL} req/min   ${D}UP: ${upstr}${NC}"
        draw_row "$f_p" "$f_c"

        bdr_bot
        local ptag=""
        (( paused )) && ptag="  ${R}[PAUSED]${NC}"
        # \033[K and \033[J clear leftovers from a longer or taller previous frame.
        printf "${D} q:quit  p:pause  r:refresh  +/-:rate (${REFRESH}s)  |  5xx>=${THRESH_5XX_WARN} blinks${NC}${ptag}\033[K\n"
        printf '\033[J'

        MILOG_HIST_PAUSED=$paused
        local key
        key=$(wait_or_key "$REFRESH")
        case "$key" in
            q|Q) break ;;
            p|P) paused=$(( 1 - paused )) ;;
            r|R) ;;
            +)   (( REFRESH > 1 )) && REFRESH=$(( REFRESH - 1 )) ;;
            -)   REFRESH=$(( REFRESH + 1 )) ;;
            *)   ;;
        esac
    done
}
# milog patterns: app-error signatures over every LOGS source, firing `app:<source>:<pattern>`.
# Parallel indexed arrays instead of associative ones keep it working on bash 3.2.

# EREs matched case-insensitively; APP_PATTERN_<name>=regex adds or overrides one.
_PATTERNS_BUILTIN_NAMES=(
    panic_go
    traceback_python
    stacktrace_java
    unhandled_promise_node
    oom_kill
    generic_critical
    segfault
    out_of_memory
)
_PATTERNS_BUILTIN_REGEX=(
    '^panic:'
    'Traceback \(most recent call last\):'
    '^[[:space:]]+at .*\(.*\.java:[0-9]+\)'
    'UnhandledPromiseRejectionWarning'
    'Killed process [0-9]+ \(.*\) total-vm'
    '(ERROR|FATAL|CRITICAL)[[:space:]]'
    'segfault at'
    'out of memory'
)

# Empty output means not a built-in.
_patterns_builtin_get() {
    local want="$1" i
    for i in "${!_PATTERNS_BUILTIN_NAMES[@]}"; do
        if [[ "${_PATTERNS_BUILTIN_NAMES[$i]}" == "$want" ]]; then
            printf '%s' "${_PATTERNS_BUILTIN_REGEX[$i]}"
            return 0
        fi
    done
    return 1
}

# Built-ins merged with APP_PATTERN_* env, as sorted `<name>\t<regex>` lines; an empty value disables a built-in.
_patterns_collect() {
    local i name regex
    local -a out_names=() out_regex=()
    for i in "${!_PATTERNS_BUILTIN_NAMES[@]}"; do
        out_names+=("${_PATTERNS_BUILTIN_NAMES[$i]}")
        out_regex+=("${_PATTERNS_BUILTIN_REGEX[$i]}")
    done
    local k v idx found
    while IFS='=' read -r k v; do
        [[ "$k" == APP_PATTERN_* ]] || continue
        name="${k#APP_PATTERN_}"
        found=-1
        for idx in "${!out_names[@]}"; do
            [[ "${out_names[$idx]}" == "$name" ]] && { found=$idx; break; }
        done
        if [[ -z "$v" ]]; then
            if (( found >= 0 )); then
                unset "out_names[$found]" "out_regex[$found]"
                out_names=(${out_names[@]+"${out_names[@]}"})
                out_regex=(${out_regex[@]+"${out_regex[@]}"})
            fi
            continue
        fi
        if (( found >= 0 )); then
            out_regex[$found]="$v"
        else
            out_names+=("$name")
            out_regex+=("$v")
        fi
    done < <(env)
    for i in "${!out_names[@]}"; do
        printf '%s\t%s\n' "${out_names[$i]}" "${out_regex[$i]}"
    done | sort
}

# All patterns as one ERE, a cheap pre-filter before per-name classification.
_patterns_union_ere() {
    local first=1 out="" name re
    while IFS=$'\t' read -r name re; do
        [[ -z "$re" ]] && continue
        if (( first )); then out="(${re})"; first=0
        else out+="|(${re})"; fi
    done
    printf '%s' "$out"
}

# Space-separated names of every pattern the line matches; each fires separately so silences can target one.
_patterns_classify() {
    local line="$1"
    local name re hits=""
    while IFS=$'\t' read -r name re; do
        [[ -z "$re" ]] && continue
        if printf '%s' "$line" | grep -Eqi -- "$re"; then
            hits+="$name "
        fi
    done < <(_patterns_collect)
    printf '%s' "${hits% }"
}

mode_patterns() {
    [[ "${PATTERNS_ENABLED:-1}" == "1" ]] || {
        _dlog "patterns: disabled (PATTERNS_ENABLED=0)" 2>/dev/null
        return 0
    }
    local -a names=() regexes=()
    local n r
    while IFS=$'\t' read -r n r; do
        [[ -z "$r" ]] && continue
        names+=("$n"); regexes+=("$r")
    done < <(_patterns_collect)
    if (( ${#names[@]} == 0 )); then
        _dlog "patterns: no patterns enabled — nothing to watch" 2>/dev/null
        return 0
    fi
    local union; union=$(_patterns_collect | _patterns_union_ere)
    [[ -n "$union" ]] || return 0

    local interactive=0
    [[ -t 1 ]] && interactive=1
    if (( interactive )); then
        echo -e "${D}Watching app-error patterns across ${#LOGS[@]} source(s)... (Ctrl+C)${NC}"
        echo -e "${D}Patterns: ${names[*]}${NC}\n"
    fi

    # One sequential consumer: parallel watchers would race on alerts.state and lose cooldowns.
    local colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    {
        local entry
        for entry in "${LOGS[@]}"; do
            local source_name; source_name=$(_log_name_for "$entry")
            local cmd;         cmd=$(_log_reader_cmd "$entry") || continue
            [[ -z "$cmd" ]] && continue
            # Drop `#...unavailable` diagnostics first so they can't match generic_critical.
            ( bash -c "$cmd" 2>/dev/null \
                | grep --line-buffered -v '^#' \
                | awk -v src="$source_name" '{print src "\t" $0; fflush()}' ) &
        done
        wait
    } | while IFS=$'\t' read -r src line; do
            [[ -z "$line" ]] && continue
            # Match the untagged line so `^` anchors like `^panic:` work.
            shopt -s nocasematch
            [[ "$line" =~ $union ]] || { shopt -u nocasematch; continue; }
            shopt -u nocasematch
            local hits; hits=$(_patterns_classify "$line")
            [[ -z "$hits" ]] && continue
            if (( interactive )); then
                local col="${colors[$(( i % ${#colors[@]} ))]}" label
                label=$(printf "%-10s" "$src")
                printf '%b[%s]%b %b[%s]%b %s\n' \
                    "$col" "$label" "$NC" "$R" "$hits" "$NC" "${line:0:280}"
                (( i++ )) || true
            fi
            local pat
            for pat in $hits; do
                local key="app:$src:$pat"
                if alert_should_fire "$key"; then
                    alert_fire \
                        "App pattern: $src / $pat" \
                        "$(_alert_fence "${line:0:1800}")" \
                        15158332 "$key" &
                fi
            done
        done
}

# `milog patterns list`: the merged catalog, each entry tagged builtin, override or custom.
mode_patterns_list() {
    local name re origin builtin_re
    printf '%-28s %-10s %s\n' "NAME" "ORIGIN" "REGEX"
    while IFS=$'\t' read -r name re; do
        builtin_re=$(_patterns_builtin_get "$name") || true
        if [[ -z "$builtin_re" ]]; then
            origin="custom"
        elif [[ "$builtin_re" != "$re" ]]; then
            origin="override"
        else
            origin="builtin"
        fi
        printf '%-28s %-10s %s\n' "$name" "$origin" "$re"
    done < <(_patterns_collect)
}
# ==============================================================================
# MODE: probe — manage the eBPF probe sidecar (milog-probe) via systemd
#
# Counterpart to `milog web install-service`. The probe is Linux-only and
# privileged (eBPF needs root or CAP_BPF + CAP_PERFMON), so its unit lives
# in /etc/systemd/system/ rather than the user-mode location web uses.
#
# Subcommands:
#   milog probe status                run state + journal pointer
#   sudo milog probe install-service  write + enable + start the unit
#   sudo milog probe uninstall-service stop + disable + remove the unit
#
# Why HOME is baked into the unit:
#   The probe shells out to `milog _internal_alert` for every rule hit.
#   Since the probe runs as root, milog inherits root's $HOME and resolves
#   ALERT_STATE_DIR to /root/.cache/milog — invisible to the regular user
#   running `milog alerts` from their shell. Capturing the invoking user's
#   $HOME at install time and pinning it via Environment= keeps alerts +
#   silences in the user's cache where they belong. The alert child runs
#   as that user too (MILOG_PROBE_ALERT_USER), never as root.
# ==============================================================================

_PROBE_SYSTEMD_UNIT="/etc/systemd/system/milog-probe.service"

# File-probe comm allowlist written into the unit; override with MILOG_PROBE_FILE_ALLOWLIST at install time.
_PROBE_DEFAULT_FILE_ALLOWLIST="sshd,sshd-session,sshd-socket-gen,sudo,su,login,getty,agetty,cron,crond,anacron,systemd,systemd-logind,systemd-userdb,systemd-tmpfile,systemd-resolve,systemd-udevd,auditd,audisp-syslog,adduser,useradd,usermod,userdel,chpasswd,passwd,chage,visudo,pam_unix,nscd,nslcd,sssd,milog,milog-probe,ps,runc,runc:[2:INIT],watchtower,whoami"

_probe_service_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl is-active --quiet milog-probe.service 2>/dev/null
}

_probe_status() {
    if _probe_service_active; then
        local main_pid; main_pid=$(systemctl show --value -p MainPID milog-probe.service 2>/dev/null)
        echo -e "${G}running${NC}  (systemd)  pid=${main_pid:-?}"
        echo -e "${D}  unit:    ${_PROBE_SYSTEMD_UNIT}${NC}"
        echo -e "${D}  logs:    sudo journalctl -u milog-probe.service -f${NC}"
        echo -e "${D}  recent:  milog alerts 1h${NC}"
    else
        echo -e "${D}not running${NC}"
        if [[ -f "$_PROBE_SYSTEMD_UNIT" ]]; then
            echo -e "${D}  unit installed but inactive — try:${NC}"
            echo -e "${D}    sudo systemctl start milog-probe.service${NC}"
            echo -e "${D}    sudo journalctl -u milog-probe.service -b   # last-boot logs${NC}"
        fi
    fi
}

# Same lookup order as _web_go_binary.
_probe_binary() {
    if [[ -n "${MILOG_PROBE_BIN:-}" && -x "$MILOG_PROBE_BIN" ]]; then
        printf '%s' "$MILOG_PROBE_BIN"; return 0
    fi
    local candidate
    for candidate in \
        /usr/local/libexec/milog/milog-probe \
        /usr/local/bin/milog-probe \
        /usr/bin/milog-probe; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"
    local self_dir; self_dir=$(cd "$(dirname "$self")" && pwd)
    for candidate in "$self_dir/go/bin/milog-probe" "$self_dir/../go/bin/milog-probe"; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    return 1
}

_probe_no_binary_error() {
    printf '%b' "
${R}milog-probe binary not found.${NC}

The eBPF probe is a small Go binary (Linux only, ~5 MB). It must be on
disk for the systemd unit to start. Pick one:

  ${W}1. Run install.sh (recommended)${NC}
     ${D}curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash${NC}
     ${D}install.sh fetches milog-probe from the latest GitHub release${NC}
     ${D}as part of the Linux install path.${NC}

  ${W}2. Override the path${NC}
     ${D}MILOG_PROBE_BIN=/path/to/milog-probe sudo -E milog probe install-service${NC}

" >&2
}

# Args: probe_bin target_user target_home target_config allowlist caps
_probe_unit() {
    cat <<EOF
[Unit]
Description=MiLog eBPF probe (exec / file / net / ptrace / kmod / retrans / syscall-rate / bpf-load)
Documentation=https://github.com/chud-lori/milog
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=${1}
Restart=on-failure
RestartSec=5s
# HOME + MILOG_CONFIG point at the invoking user's home so probe-fired
# alerts route through that user's bash config (DISCORD_WEBHOOK, silences,
# alerts.log) rather than root's. Edit + daemon-reload + restart to retune.
Environment=HOME=${3}
Environment=MILOG_CONFIG=${4}
Environment=MILOG_PROBE_FILE_ALLOWLIST=${5}
# Alerts run as this user so their config and hooks never execute as root.
Environment=MILOG_PROBE_ALERT_USER=${2}

# ProtectHome / ProtectSystem=strict stay off: the alert child writes the user's ~/.cache/milog.
CapabilityBoundingSet=${6}
NoNewPrivileges=yes
ProtectSystem=full
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
}

_probe_service_install() {
    local kernel; kernel=$(uname -s 2>/dev/null)
    if [[ "$kernel" != "Linux" ]]; then
        echo -e "${R}milog-probe is Linux-only (eBPF doesn't exist on $kernel)${NC}" >&2
        return 1
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${R}systemctl not found — this host doesn't use systemd${NC}" >&2
        return 1
    fi
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${R}milog probe install-service needs root${NC}" >&2
        echo -e "${D}  eBPF + writing to /etc/systemd/system/ both require it${NC}" >&2
        echo -e "${D}  retry:  sudo milog probe install-service${NC}" >&2
        return 1
    fi
    local probe_bin
    probe_bin=$(_probe_binary) || { _probe_no_binary_error; return 1; }
    probe_bin=$(readlink -f "$probe_bin")
    if ! _root_trusted_path "$probe_bin"; then
        echo -e "${R}refusing to run ${probe_bin} as root: it or its directory is not root-owned or is group/other-writable${NC}" >&2
        echo -e "${D}  fix:  sudo install -o root -g root -m 0755 ${probe_bin} /usr/local/bin/milog-probe${NC}" >&2
        return 1
    fi

    # SUDO_USER, else logname, else root.
    local target_user="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
    local target_home
    target_home=$(getent passwd "$target_user" 2>/dev/null | cut -d: -f6)
    [[ -n "$target_home" ]] || target_home="/home/$target_user"
    [[ -d "$target_home" ]] || target_home="/root"
    local target_config="${target_home}/.config/milog/config.sh"

    if [[ ! -f "$target_config" ]]; then
        echo -e "${Y}warning: ${target_config} not found${NC}" >&2
        echo -e "${D}  alerts will fall back to defaults until you run:${NC}" >&2
        echo -e "${D}    milog config init   (as ${target_user}, not root)${NC}" >&2
        echo -e "${D}    milog config set DISCORD_WEBHOOK \"https://...\"${NC}" >&2
    fi

    local allowlist="${MILOG_PROBE_FILE_ALLOWLIST:-$_PROBE_DEFAULT_FILE_ALLOWLIST}"

    # CAP_BPF / CAP_PERFMON only exist from 5.8; older kernels gate eBPF on CAP_SYS_ADMIN.
    local caps="CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SETUID CAP_SETGID"
    local kver; kver=$(uname -r 2>/dev/null)
    local kmaj="${kver%%.*}" kmin; kmin="${kver#*.}"; kmin="${kmin%%[!0-9]*}"
    if [[ "$kmaj" =~ ^[0-9]+$ && "$kmin" =~ ^[0-9]+$ ]] && (( kmaj < 5 || (kmaj == 5 && kmin < 8) )); then
        caps="$caps CAP_SYS_ADMIN"
    fi

    _probe_unit "$probe_bin" "$target_user" "$target_home" "$target_config" "$allowlist" "$caps" \
        > "$_PROBE_SYSTEMD_UNIT"

    echo -e "${G}✓${NC} wrote $_PROBE_SYSTEMD_UNIT"

    systemctl daemon-reload 2>/dev/null \
        || { echo -e "${R}systemctl daemon-reload failed${NC}" >&2; return 1; }
    if ! systemctl enable --now milog-probe.service 2>&1; then
        echo -e "${R}failed to enable milog-probe.service${NC}" >&2
        echo -e "${D}  tail logs: sudo journalctl -u milog-probe.service -b${NC}" >&2
        return 1
    fi

    echo -e "${G}✓${NC} systemctl enable --now milog-probe.service"

    printf '%b' "
${W}milog-probe.service${NC} installed and running.

  ${D}invoking user: ${target_user}  →  alerts route through ${target_config}${NC}

  ${W}manage:${NC}
    sudo systemctl status   milog-probe.service
    sudo systemctl restart  milog-probe.service
    sudo journalctl -u milog-probe.service -f      ${D}# live log stream${NC}
    sudo milog probe uninstall-service             ${D}# remove the unit${NC}

  ${W}retune the file allowlist:${NC}
    sudoedit ${_PROBE_SYSTEMD_UNIT}                 ${D}# edit Environment=MILOG_PROBE_FILE_ALLOWLIST${NC}
    sudo systemctl daemon-reload && sudo systemctl restart milog-probe.service

"
}

_probe_service_uninstall() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${D}systemctl not found — nothing to uninstall${NC}"
        return 0
    fi
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${R}milog probe uninstall-service needs root${NC}" >&2
        echo -e "${D}  retry:  sudo milog probe uninstall-service${NC}" >&2
        return 1
    fi
    if [[ -f "$_PROBE_SYSTEMD_UNIT" ]]; then
        systemctl stop    milog-probe.service 2>/dev/null || true
        systemctl disable milog-probe.service 2>/dev/null || true
        rm -f "$_PROBE_SYSTEMD_UNIT"
        systemctl daemon-reload 2>/dev/null || true
        echo -e "${G}✓${NC} milog-probe.service stopped, disabled, removed"
    else
        echo -e "${D}no unit at $_PROBE_SYSTEMD_UNIT${NC}"
    fi
}

mode_probe() {
    case "${1:-}" in
        status)            _probe_status; return ;;
        install-service)   _probe_service_install; return ;;
        uninstall-service) _probe_service_uninstall; return ;;
        ""|-h|--help|help)
            printf '%b' "
${W}milog probe${NC} — manage the eBPF probe sidecar (Linux only)

  ${W}USAGE${NC}
    milog probe status                  run state + log pointer
    sudo milog probe install-service    write + enable + start systemd unit
    sudo milog probe uninstall-service  stop + disable + remove the unit

  ${D}The probe runs as a system service (root) and shells out to milog
  for every rule hit. HOME + MILOG_CONFIG in the unit pin to the user
  who ran install-service so alerts run as that user and route through
  their webhook config + silences, not root's.${NC}

  ${W}covers:${NC}
    exec  ·  tcp connect  ·  file open  ·  ptrace  ·  kmod load
    tcp retransmit  ·  syscall rate (Welford σ)  ·  bpf prog load

"
            return 0 ;;
        *)
            echo -e "${R}usage: milog probe [status|install-service|uninstall-service]${NC}" >&2
            return 1 ;;
    esac
}
# milog probes: scanner, bot and crawler traffic by user-agent, plus non-HTTP protocol probes.
mode_probes() {
    echo -e "${D}Watching scanner/bot traffic across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    _rules_load

    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$(( i % ${#colors[@]} ))]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            (
                app="$name"
                tail -F "$file" 2>/dev/null | \
                    grep --line-buffered -Ei -e "$RULES_PROBE" | \
                while IFS= read -r line; do
                    printf '%b[%s]%b %s\n' "$col" "$label" "$NC" "$(_tty_safe <<< "$line")"
                    # Dedup with exploits, which often matches the same scanner line.
                    fp=$(alert_fingerprint_from_line "$line")
                    if alert_should_fire "probe:$app" \
                       && alert_fingerprint_fresh "$fp"; then
                        alert_fire "Probe traffic: $app" "$(_alert_fence "${line:0:1800}")$(cti_alert_note "${line%% *}")" 15844367 "probe:$app" "${line%% *}" &
                    fi
                done
            ) &
            pids+=($!)
        fi
        (( i++ )) || true
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

# milog rate: nginx-only refresh dashboard.
mode_rate() {
    while true; do
        milog_update_geometry
        clear
        local CUR_TIME TIMESTAMP TOTAL=0
        CUR_TIME=$(date '+%d/%b/%Y:%H:%M')
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

        bdr_top
        draw_row " MiLog   ${TIMESTAMP}" " ${W}MiLog${NC}   ${D}${TIMESTAMP}${NC}"
        bdr_mid
        bdr_hdr
        hdr_row
        bdr_hdr

        for name in "${LOGS[@]}"; do
            nginx_row "$name" "$CUR_TIME" TOTAL
        done

        bdr_sep
        draw_row " TOTAL: ${TOTAL} req/min" " ${W}TOTAL:${NC} ${TOTAL} req/min"
        bdr_bot
        printf "${D} Ctrl+C to exit  |  Refresh: ${REFRESH}s${NC}\n"
        sleep "$REFRESH"
    done
}

# milog replay <file>: read-only postmortem summary of one log file, plain, .gz or .bz2.
mode_replay() {
    local file="${1:-}"
    if [[ -z "$file" ]]; then
        echo -e "${R}Usage:${NC} milog replay <log-file>" >&2
        return 1
    fi
    [[ -f "$file" ]] || { echo -e "${R}Not found: $file${NC}" >&2; return 1; }

    local -a reader=(cat --)
    case "$file" in
        *.gz)
            if   command -v gzcat >/dev/null 2>&1; then reader=(gzcat --)
            elif command -v zcat  >/dev/null 2>&1; then reader=(zcat  --)
            else echo -e "${R}gzcat/zcat needed for .gz files${NC}" >&2; return 1
            fi
            ;;
        *.bz2)
            command -v bzcat >/dev/null 2>&1 \
                || { echo -e "${R}bzcat needed for .bz2 files${NC}" >&2; return 1; }
            reader=(bzcat --)
            ;;
    esac

    echo -e "\n${W}── MiLog: Replay — ${file} ──${NC}\n"

    local summary n first last e2 e3 e4 e5
    summary=$("${reader[@]}" "$file" 2>/dev/null | awk '
        {
            n++
            if (match($0, /\[[0-9]{2}\/[A-Za-z]+\/[0-9]{4}:[0-9]{2}:[0-9]{2}/)) {
                t = substr($0, RSTART+1, 20)
                if (first == "") first = t
                last = t
            }
            if (match($0, / [1-5][0-9][0-9] /)) {
                cls = substr($0, RSTART+1, 1)
                if      (cls == "2") e2++
                else if (cls == "3") e3++
                else if (cls == "4") e4++
                else if (cls == "5") e5++
            }
        }
        END { printf "%d\t%s\t%s\t%d\t%d\t%d\t%d\n", n+0, first, last, e2+0, e3+0, e4+0, e5+0 }')
    IFS=$'\t' read -r n first last e2 e3 e4 e5 <<< "$summary"

    if [[ -z "$n" || "$n" -eq 0 ]]; then
        echo -e "  ${D}(empty or unreadable)${NC}\n"
        return 0
    fi

    printf "  %-10s  %d\n"           "lines"   "$n"
    printf "  %-10s  %s  →  %s\n"    "range"   "${first:--}" "${last:--}"
    printf "  %-10s  2xx=%s  3xx=%s  ${Y}4xx=%s${NC}  ${R}5xx=%s${NC}\n" \
           "status"  "$e2" "$e3" "$e4" "$e5"

    # Percentiles only when some line ends in a number.
    local sorted
    sorted=$("${reader[@]}" "$file" 2>/dev/null \
        | awk '$NF ~ /^[0-9]+(\.[0-9]+)?$/ { print int($NF * 1000 + 0.5) }' \
        | sort -n)
    if [[ -n "$sorted" ]]; then
        local pct p50 p95 p99
        pct=$(printf '%s\n' "$sorted" | awk '
            { a[NR]=$1; n=NR }
            END {
                i50=int((n*50+99)/100); if (i50<1) i50=1; if (i50>n) i50=n
                i95=int((n*95+99)/100); if (i95<1) i95=1; if (i95>n) i95=n
                i99=int((n*99+99)/100); if (i99<1) i99=1; if (i99>n) i99=n
                printf "%d %d %d\n", a[i50], a[i95], a[i99]
            }')
        read -r p50 p95 p99 <<< "$pct"
        printf "  %-10s  p50=%dms  p95=%dms  p99=%dms\n" "response" "$p50" "$p95" "$p99"
    fi

    echo
    echo -e "  ${W}Top source IPs:${NC}"
    "${reader[@]}" "$file" 2>/dev/null \
        | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 \
        | awk -v Y="$Y" -v R="$R" -v NC="$NC" '{
              col = ""
              if      (NR == 1) col = R
              else if (NR <= 3) col = Y
              printf "    %s#%-3d%s  %-18s  %d requests\n", col, NR, NC, $2, $1
          }'
    echo
}

# milog report [window] [--html] [-o FILE]: static traffic / attacker / alert / anomaly / audit drift summary.

# Stdin records, tab-separated: T title, M meta line, H section, P note, E empty state, C header cells, R row cells.
_report_render() {
    awk -F'\t' -v html="$1" '
        function esc(s) {
            gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s)
            if (html) { gsub(/"/, "\\&quot;", s); gsub(/\047/, "\\&#39;", s) }
            else { gsub(/\|/, "\\&#124;", s); gsub(/`/, "\\&#96;", s); gsub(/\[/, "\\&#91;", s); gsub(/\]/, "\\&#93;", s) }
            return s
        }
        function close_table() { if (open) { print "</tbody></table>"; open = 0 } }
        BEGIN {
            if (html) {
                print "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                print "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                print "<style>"
                print ":root{--bg:#0b0d10;--bg-2:#121519;--fg:#e4e7eb;--fg-2:#a4adb8;--border:#2a2f37;" \
                      "--mono:ui-monospace,SFMono-Regular,\"JetBrains Mono\",Menlo,Monaco,Consolas,monospace;" \
                      "--sans:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif}"
                print "@media (prefers-color-scheme:light){:root{--bg:#fafbfc;--bg-2:#ffffff;--fg:#16191d;--fg-2:#454d57;--border:#dde1e6}}"
                print "body{margin:0 auto;max-width:72rem;padding:2rem 1rem;background:var(--bg);color:var(--fg);font:15px/1.5 var(--sans)}"
                print "h1{font-size:1.4rem;margin:0}h2{font-size:1.1rem;margin:2rem 0 .5rem}p{margin:.25rem 0;color:var(--fg-2)}"
                print "table{border-collapse:collapse;background:var(--bg-2)}"
                print "th,td{border:1px solid var(--border);padding:.3rem .6rem;text-align:left;vertical-align:top}"
                print "td{font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}th{color:var(--fg-2);font-weight:600}"
                print "td.n{text-align:right;white-space:nowrap}"
                print "</style>"
            }
        }
        $1 == "T" {
            if (html) printf "<title>%s</title></head><body>\n<h1>%s</h1>\n", esc($2), esc($2)
            else printf "# %s\n", esc($2)
        }
        $1 == "M" { if (html) printf "<p>%s</p>\n", esc($2); else printf "\n%s\n", esc($2) }
        $1 == "H" { close_table(); if (html) printf "<h2>%s</h2>\n", esc($2); else printf "\n## %s\n\n", esc($2) }
        $1 == "P" { if (html) printf "<p>%s</p>\n", esc($2); else printf "%s\n\n", esc($2) }
        $1 == "E" { if (html) printf "<p>%s</p>\n", esc($2); else printf "%s\n", esc($2) }
        $1 == "C" {
            if (html) {
                printf "<table><thead><tr>"
                for (i = 2; i <= NF; i++) printf "<th>%s</th>", esc($i)
                print "</tr></thead><tbody>"; open = 1
            } else {
                line = "|"; rule = "|"
                for (i = 2; i <= NF; i++) { line = line " " esc($i) " |"; rule = rule " --- |" }
                print line; print rule
            }
        }
        $1 == "R" {
            if (html) {
                printf "<tr>"
                for (i = 2; i <= NF; i++) printf "<td%s>%s</td>", ($i ~ /^[0-9]+$/ ? " class=\"n\"" : ""), esc($i)
                print "</tr>"
            } else {
                line = "|"
                for (i = 2; i <= NF; i++) line = line " " esc($i) " |"
                print line
            }
        }
        END { close_table(); if (html) print "</body></html>" }'
}

# One pass over the windowed access lines: per-app totals, then the top 10 IPs by 4xx.
_report_traffic() {
    local cutoff="$1" entry name file
    for entry in "${LOGS[@]}"; do
        [[ "$(_log_type_for "$entry")" == "nginx" ]] || continue
        name=$(_log_name_for "$entry")
        file=$(_log_path_for "$entry")
        [[ -f "$file" ]] || continue
        if [[ ! -r "$file" ]]; then
            printf 'A\t%s\tunreadable\n' "$name"
            continue
        fi
        printf 'A\t%s\n' "$name"
        _digest_in_window "$cutoff" "$file" | awk -v app="$name" '{ print "L\t" app "\t" $1 "\t" $9 }'
    done | awk -F'\t' '
        $1 == "A" { apps[++na] = $2; if ($3 != "") bad[$2] = 1; next }
        {
            req[$2]++; ipreq[$3]++
            if ($4 ~ /^4/) { c4[$2]++; ip4[$3]++ }
            else if ($4 ~ /^5/) c5[$2]++
        }
        END {
            print "H\tTraffic per app"
            if (!na) print "E\tNo nginx access log found for any configured app."
            else {
                print "C\tApp\tRequests\t4xx\t5xx"
                for (i = 1; i <= na; i++) {
                    a = apps[i]
                    if (a in bad) printf "R\t%s\tlog not readable\t-\t-\n", a
                    else printf "R\t%s\t%d\t%d\t%d\n", a, req[a], c4[a], c5[a]
                }
            }
            print "H\tTop attacker IPs"
            m = 0; for (ip in ip4) m++
            print "P\tRanked by 4xx responses across all apps." (m > 10 ? " Showing 10 of " m "." : "")
            for (n = 0; n < 10; n++) {
                best = ""
                for (ip in ip4) if (!(ip in done) && (best == "" || ip4[ip] > ip4[best] || (ip4[ip] == ip4[best] && ipreq[ip] > ipreq[best]))) best = ip
                if (best == "") break
                done[best] = 1
                if (!n) print "C\tIP\t4xx\tRequests"
                printf "R\t%s\t%d\t%d\n", best, ip4[best], ipreq[best]
            }
            if (!n) print "E\tNo IP got a 4xx response in this window."
        }'
}

_report_alerts() {
    local cutoff="$1" alog="$ALERT_STATE_DIR/alerts.log" tab=$'\t' rows="" total=0 n last rule ts body
    printf 'H\tAlert fires per rule\n'
    if [[ ! -f "$alog" ]]; then
        printf 'E\tNo alerts.log at %s.\n' "$alog"
    else
        rows=$(awk -F'\t' -v c="$cutoff" '$1 >= c { n[$2]++; if ($1 > last[$2]) last[$2] = $1 }
            END { for (r in n) printf "%d\t%s\t%s\n", n[r], last[r], r }' "$alog" | sort -t "$tab" -k1,1rn -k3,3)
        if [[ -z "$rows" ]]; then
            printf 'E\tNo alerts fired in this window.\n'
        else
            printf 'C\tRule\tFires\tLast fired\n'
            while IFS=$'\t' read -r n last rule; do
                printf 'R\t%s\t%s\t%s\n' "$rule" "$n" "$(_alerts_fmt_epoch "$last")"
            done <<< "$rows"
        fi
        rows=$(awk -F'\t' -v c="$cutoff" '$1 >= c && $2 ~ /^anomaly:/ { print $1 "\t" $2 "\t" $5 }' "$alog" \
            | sort -t "$tab" -k1,1rn)
        if [[ -n "$rows" ]]; then
            total=$(printf '%s\n' "$rows" | wc -l | tr -d ' ')
            rows=$(printf '%s\n' "$rows" | head -50)
        fi
    fi

    printf 'H\tAnomalies\n'
    if [[ -z "$rows" ]]; then
        if [[ "${ANOMALY_ENABLED:-0}" == "1" ]]; then
            printf 'E\tNo anomalies fired in this window.\n'
        else
            printf 'E\tNo anomalies fired in this window. Anomaly detection is off (ANOMALY_ENABLED=0).\n'
        fi
    else
        if (( total > 50 )); then printf 'P\tShowing the latest 50 of %s.\n' "$total"; fi
        printf 'C\tTime\tRule\tDetail\n'
        while IFS=$'\t' read -r ts rule body; do
            printf 'R\t%s\t%s\t%s\n' "$(_alerts_fmt_epoch "$ts")" "$rule" "${body//\`/}"
        done <<< "$rows"
    fi
}

_report_audit() {
    local cutoff="$1" rows total n=0 ts scanner kind subject
    printf 'H\tAudit drift\n'
    if [[ "$HISTORY_ENABLED" != "1" ]]; then
        printf 'E\tHistory is off (HISTORY_ENABLED=0), so audit drift is not recorded.\n'
        return 0
    fi
    if ! command -v sqlite3 >/dev/null 2>&1; then
        printf 'E\tsqlite3 is not installed, so audit drift cannot be read.\n'
        return 0
    fi
    if [[ ! -f "$HISTORY_DB" ]]; then
        printf 'E\tNo history DB at %s.\n' "$HISTORY_DB"
        return 0
    fi
    if ! rows=$(_history_audit_rows "$cutoff" 2>&1); then
        if [[ "$rows" == *"no such table: audit_event"* ]]; then
            printf 'E\tNo audit_event table in %s yet. The daemon creates it when it next starts.\n' "$HISTORY_DB"
        else
            printf 'E\tCould not read %s: %s\n' "$HISTORY_DB" "$(printf '%s' "$rows" | tr '\t\n' '  ')"
        fi
        return 0
    fi
    if [[ -z "$rows" ]]; then
        printf 'E\tNo audit drift recorded in this window.\n'
        return 0
    fi
    total=$(printf '%s\n' "$rows" | wc -l | tr -d ' ')
    if (( total > 50 )); then printf 'P\tShowing the latest 50 of %s.\n' "$total"; fi
    printf 'C\tTime\tScanner\tKind\tSubject\n'
    while IFS=$'\t' read -r ts scanner kind subject; do
        (( ++n > 50 )) && break
        printf 'R\t%s\t%s\t%s\t%s\n' "$ts" "$scanner" "$kind" "${subject//$'\t'/ }"
    done <<< "$rows"
}

mode_report() {
    local window="7d" html=0 out="" secs now cutoff report tmp
    while (( $# )); do
        case "$1" in
            --html) html=1 ;;
            -o) [[ -n "${2:-}" ]] || { echo -e "${R}report: -o needs a file${NC}" >&2; return 1; }
                out="$2"; shift ;;
            -*) echo -e "${R}report: unknown flag: $1${NC}" >&2; return 1 ;;
            *)  window="$1" ;;
        esac
        shift
    done
    secs=$(_digest_window_to_secs "$window") || { echo -e "${R}report: invalid window: $window${NC}" >&2; return 1; }
    now=$(date +%s)
    cutoff=$(( now - secs ))
    (( cutoff >= 0 )) || cutoff=0

    report=$(
        printf 'T\tMiLog report: last %s on %s\n' "$window" "$(hostname 2>/dev/null || echo host)"
        printf 'M\t%s to %s\n' "$(_alerts_fmt_epoch "$cutoff")" "$(_alerts_fmt_epoch "$now")"
        _report_traffic "$cutoff"
        _report_alerts "$cutoff"
        _report_audit "$cutoff"
    )
    if [[ -n "$out" ]]; then
        [[ -L "$out" ]] && { echo -e "${R}report: refusing to write through symlink: $out${NC}" >&2; return 1; }
        tmp=$(mktemp "$(dirname "$out")/.milog-report.XXXXXX") || return 1
        if printf '%s\n' "$report" | _report_render "$html" | _tty_safe > "$tmp"; then
            mv -f "$tmp" "$out"
        else
            rm -f "$tmp"
            return 1
        fi
    else
        printf '%s\n' "$report" | _report_render "$html" | _tty_safe
    fi
}
# milog search <pattern> [flags]: fixed-string (or --regex) grep across app logs and, with --archives, rotated ones.
mode_search() {
    local pattern="" since="" app_filter="" path_filter=""
    local use_regex=0 include_archives=0 limit=200

    if [[ $# -gt 0 && "$1" != --* ]]; then
        pattern="$1"; shift
    fi
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --since)     since="$2"; shift 2 ;;
            --app)       app_filter="$2"; shift 2 ;;
            --path)      path_filter="$2"; shift 2 ;;
            --regex)     use_regex=1; shift ;;
            --archives)  include_archives=1; shift ;;
            --limit)     limit="$2"; shift 2 ;;
            -h|--help)   pattern=""; break ;;
            *) echo -e "${R}unknown flag: $1${NC}" >&2; return 1 ;;
        esac
    done

    if [[ -z "$pattern" ]]; then
        printf '%b' "
${R}usage: milog search <pattern> [flags]${NC}

${D}  flags:
    --since today|yesterday|Nh|Nd|Nw|all     time filter on logline timestamp
    --app <name>                              scope to one app (default: all)
    --path <substring>                        only lines whose URL contains it
    --regex                                   interpret pattern as ERE (else -F)
    --archives                                also search .log.1, .log.*.gz
    --limit N                                 cap output; 0=unlimited (default 200)
${NC}"
        return 1
    fi
    [[ "$limit" =~ ^[0-9]+$ ]] \
        || { echo -e "${R}--limit must be numeric${NC}" >&2; return 1; }

    local cutoff_epoch=""
    if [[ -n "$since" ]]; then
        cutoff_epoch=$(_alerts_window_to_epoch "$since") || return 1
        # mktime() exists in gawk and mawk but not BSD awk; without it, skip the time filter rather than fail.
        if ! command -v gawk >/dev/null 2>&1 \
             && ! awk 'BEGIN { if (mktime("2020 1 1 0 0 0") <= 0) exit 1 }' 2>/dev/null; then
            echo -e "${Y}--since requires gawk or mawk (this awk lacks mktime); time filter skipped${NC}" >&2
            cutoff_epoch=""
        fi
    fi

    local awk_bin="awk"
    command -v gawk >/dev/null 2>&1 && awk_bin="gawk"

    local apps_to_scan=()
    if [[ -n "$app_filter" ]]; then
        if [[ ! " ${LOGS[*]} " =~ " $app_filter " ]]; then
            echo -e "${R}unknown app: $app_filter${NC}  Known: ${LOGS[*]}" >&2
            return 1
        fi
        apps_to_scan=("$app_filter")
    else
        apps_to_scan=("${LOGS[@]}")
    fi

    local grep_flag="-F"
    (( use_regex )) && grep_flag="-E"

    # Collect matches in a temp file so --limit and the tally don't rescan the logs.
    local tmp; tmp=$(mktemp -t milog_search.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    local colors=("$B" "$C" "$G" "$M" "$Y" "$R")
    local idx=0
    for app in "${apps_to_scan[@]}"; do
        local col="${colors[$(( idx % ${#colors[@]} ))]}"
        local label; label=$(printf "%-10s" "$app")
        idx=$(( idx + 1 ))

        local files=()
        [[ -f "$LOG_DIR/$app.access.log" ]] && files+=("$LOG_DIR/$app.access.log")
        if (( include_archives )); then
            shopt -s nullglob
            for archive in "$LOG_DIR/$app.access.log."*; do
                files+=("$archive")
            done
            shopt -u nullglob
        fi

        local f
        for f in "${files[@]}"; do
            _search_one_file "$f" "$pattern" "$grep_flag" "$app" "$col" "$label" \
                             "$path_filter" "$cutoff_epoch" "$awk_bin" >> "$tmp"
        done
    done

    local total; total=$(wc -l < "$tmp" | tr -d ' ')
    total=${total:-0}

    echo -e "\n${W}── MiLog: search \"${pattern}\" ──${NC}\n"

    if (( total == 0 )); then
        echo -e "  ${D}no matches in ${#apps_to_scan[@]} app(s)${NC}\n"
        return 0
    fi

    if (( limit > 0 && total > limit )); then
        head -n "$limit" "$tmp"
        echo -e "\n  ${D}… showing $limit of $total matches. Use --limit 0 for all.${NC}"
    else
        cat "$tmp"
    fi

    # Per-app counts from the `[label]` prefix.
    echo -e "\n  ${W}by app${NC}"
    awk '
        {
            # Lines start with "[<app...>]". Strip everything past the
            # closing bracket; trim trailing spaces in the label.
            if (match($0, /\[[^]]+\]/)) {
                lab = substr($0, RSTART+1, RLENGTH-2)
                # The label may contain ANSI color codes around the name.
                # Strip them for a clean group-by.
                gsub(/\033\[[0-9;]*m/, "", lab)
                sub(/[[:space:]]+$/, "", lab)
                c[lab]++
            }
        }
        END { for (a in c) printf "%d\t%s\n", c[a], a }' "$tmp" \
        | sort -rn \
        | awk '{printf "    %5d  %s\n", $1, $2}'

    echo -e "\n  ${D}total: $total match(es)${NC}\n"
}

# Prints matching lines of one plain/.gz/.bz2/.xz file, filtered and prefixed with `[label]`.
_search_one_file() {
    local f="$1" pattern="$2" grep_flag="$3" app="$4" col="$5" label="$6"
    local path_filter="$7" cutoff_epoch="$8" awk_bin="${9:-awk}"

    # gzip -dc rather than zcat: BSD zcat only reads .Z.
    local reader_cmd=""
    case "$f" in
        *.gz)   reader_cmd="gzip -dc"  ;;
        *.bz2)  reader_cmd="bzip2 -dc" ;;
        *.xz)   reader_cmd="xz -dc"    ;;
        *)      reader_cmd="cat"       ;;
    esac
    local probe="${reader_cmd%% *}"
    command -v "$probe" >/dev/null 2>&1 \
        || { echo -e "${D}  (skipping $f — $probe not installed)${NC}" >&2; return 0; }

    # `|| true` keeps grep's no-match exit from aborting under pipefail; search is best-effort.
    $reader_cmd "$f" 2>/dev/null \
        | { grep "$grep_flag" -- "$pattern" || true; } \
        | _tty_safe \
        | "$awk_bin" -v app="$app" -v col="$col" -v nc="$NC" -v label="$label" \
              -v pathf="$path_filter" -v cutoff="$cutoff_epoch" '
            BEGIN {
                split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
                for (i=1; i<=12; i++) mon[m[i]] = i
            }
            {
                # --path substring filter on URL. Request URI is field 7 in
                # combined format; strip query string for cleaner matching.
                if (pathf != "") {
                    p = $7
                    sub(/\?.*/, "", p)
                    if (index(p, pathf) == 0) next
                }
                # --since: parse the [dd/Mon/yyyy:HH:MM:SS tz] timestamp
                # and compare to cutoff. Lines with unparseable timestamps
                # fall through (conservative — we prefer extra matches
                # over dropping ambiguous ones).
                if (cutoff != "" && match($0, /\[[0-9]+\/[A-Z][a-z][a-z]\/[0-9]+:[0-9]+:[0-9]+:[0-9]+/)) {
                    ts = substr($0, RSTART+1, RLENGTH-1)
                    split(ts, part, /[\/:]/)
                    if (part[2] in mon) {
                        epoch = mktime(part[3] " " mon[part[2]] " " part[1] " " part[4] " " part[5] " " part[6])
                        if (epoch > 0 && epoch < cutoff) next
                    }
                }
                printf "[%s%s%s] %s\n", col, label, nc, $0
            }'
}
# milog silence <rule_or_glob> <duration> [message] | list | clear <rule_or_glob>.
# A silence outranks cooldown and dedup and also skips the alerts.log record; globs use bash syntax, so `*` mutes everything.

# Remaining time until a future epoch.
_silence_fmt_remaining() {
    local now target delta
    now=$(date +%s)
    target="$1"
    delta=$(( target - now ))
    if   (( delta < 60 ));    then printf '%ds' "$delta"
    elif (( delta < 3600 ));  then printf '%dm' $(( delta / 60 ))
    elif (( delta < 86400 )); then
        local h=$(( delta / 3600 )) m=$(( (delta % 3600) / 60 ))
        printf '%dh %02dm' "$h" "$m"
    else
        local d=$(( delta / 86400 )) h=$(( (delta % 86400) / 3600 ))
        printf '%dd %02dh' "$d" "$h"
    fi
}

_silence_fmt_epoch() {
    date -d "@$1" '+%Y-%m-%d %H:%M' 2>/dev/null \
    || date -r  "$1" '+%Y-%m-%d %H:%M' 2>/dev/null \
    || printf '%s' "$1"
}

_silence_list() {
    local rows; rows=$(alert_silence_list_active)
    if [[ -z "$rows" ]]; then
        echo -e "${D}No active silences.${NC}"
        echo -e "${D}  milog silence <rule> <duration> [message]   to add one${NC}"
        return 0
    fi
    echo -e "\n${W}── Active silences ──${NC}\n"
    printf "  %-28s  %-16s  %-10s  %-10s  %s\n" "RULE" "UNTIL" "REMAINING" "BY" "NOTE"
    printf "  %-28s  %-16s  %-10s  %-10s  %s\n" \
        "────────────────────────────" "────────────────" "──────────" "──────────" "────"
    local key until_epoch added_epoch added_by message rule_disp note_disp
    while IFS=$'\t' read -r key until_epoch added_epoch added_by message; do
        [[ -z "$key" ]] && continue
        rule_disp="$key"
        (( ${#rule_disp} > 28 )) && rule_disp="${rule_disp:0:25}..."
        note_disp="${message:-—}"
        (( ${#note_disp} > 48 )) && note_disp="${note_disp:0:45}..."
        printf "  ${Y}%-28s${NC}  %-16s  %-10s  %-10s  %s\n" \
            "$rule_disp" \
            "$(_silence_fmt_epoch "$until_epoch")" \
            "$(_silence_fmt_remaining "$until_epoch")" \
            "${added_by:-?}" \
            "$note_disp"
    done <<< "$rows"
    echo
}

_silence_add() {
    local key="$1" duration="$2"; shift 2 || true
    local message="${*:-}"
    if [[ -z "$key" || -z "$duration" ]]; then
        echo -e "${R}usage:${NC} milog silence <rule_or_glob> <duration> [message]" >&2
        echo -e "${D}  duration examples: 30s  5m  2h  1d${NC}" >&2
        return 1
    fi
    local seconds
    seconds=$(alert_silence_parse_duration "$duration") || {
        echo -e "${R}invalid duration:${NC} $duration" >&2
        echo -e "${D}  use N<s|m|h|d> up to 3650d — e.g. 30s, 5m, 2h, 1d${NC}" >&2
        return 1
    }
    if (( seconds < 1 )); then
        echo -e "${R}duration must be > 0${NC}" >&2
        return 1
    fi
    local until_epoch
    until_epoch=$(alert_silence_add "$key" "$seconds" "$message") || {
        echo -e "${R}failed to write silence file${NC}" >&2
        return 1
    }
    local until_fmt; until_fmt=$(_silence_fmt_epoch "$until_epoch")
    local rem_fmt;   rem_fmt=$(_silence_fmt_remaining "$until_epoch")
    echo -e "${G}✓${NC} silenced ${Y}$key${NC} until ${W}$until_fmt${NC} (${rem_fmt})"
    [[ -z "$message" ]] || echo -e "${D}  note: $message${NC}"
}

_silence_clear() {
    local key="$1"
    if [[ -z "$key" ]]; then
        echo -e "${R}usage:${NC} milog silence clear <rule_or_glob>" >&2
        return 1
    fi
    if alert_silence_remove "$key"; then
        echo -e "${G}✓${NC} removed silence on ${Y}$key${NC}"
    else
        echo -e "${D}no active silence on ${key}${NC}"
        return 1
    fi
}

_silence_help() {
    echo -e "
${W}milog silence${NC} — mute an alert rule while you work the fix

${W}USAGE${NC}
  ${C}milog silence <rule_or_glob> <duration> [message]${NC}   add / extend
  ${C}milog silence list${NC}                                   show active
  ${C}milog silence clear <rule_or_glob>${NC}                   remove early

${W}DURATION${NC}
  ${C}30s${NC}  30 seconds      ${C}5m${NC}  5 minutes
  ${C}2h${NC}   2 hours         ${C}1d${NC}  1 day
  ${C}300${NC}  bare int = seconds

${W}EXAMPLES${NC}
  ${D}# Working on the broken deploy, don't page me for 2 hours:${NC}
  milog silence 5xx:api 2h 'investigating deploy, auth service'

  ${D}# Glob — silence every exploit category at once:${NC}
  milog silence 'exploit:*' 30m 'pentester doing authorized scan'

  ${D}# Done early, unmute:${NC}
  milog silence clear 5xx:api

  ${D}# What's currently muted?${NC}
  milog silence list

${W}NOTES${NC}
  - Silence beats cooldown + dedup. A silenced rule does not fire, does not
    record to alerts.log, does not page any destination.
  - Re-silencing the same key extends rather than stacks — no duplicate rows.
  - Glob syntax is bash's (${C}*${NC} ${C}?${NC} ${C}[...]${NC}) — be careful with
    ${C}*${NC} alone, it silences everything.
"
}

mode_silence() {
    local sub="${1:-list}"
    case "$sub" in
        list|'')
            _silence_list
            ;;
        clear)
            shift
            _silence_clear "${1:-}"
            ;;
        -h|--help|help)
            _silence_help
            ;;
        *)
            _silence_add "$@"
            ;;
    esac
}
# milog slow [N]: endpoints ranked by p95 $request_time, in portable awk (no asort/PROCINFO).
mode_slow() {
    local n="${1:-10}"
    local window="${SLOW_WINDOW:-1000}"

    [[ "$n"      =~ ^[0-9]+$ ]] || { echo -e "${R}slow: N must be numeric${NC}" >&2; return 1; }
    [[ "$window" =~ ^[0-9]+$ ]] || { echo -e "${R}slow: SLOW_WINDOW must be numeric${NC}" >&2; return 1; }

    echo -e "\n${W}── MiLog: Top ${n} slow endpoints (window=${window} lines/app) ──${NC}\n"

    local files=() name
    for name in "${LOGS[@]}"; do
        local f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] && files+=("$f")
    done

    if (( ${#files[@]} == 0 )); then
        echo -e "${R}No log files found in ${LOG_DIR}${NC}"
        return 1
    fi

    # Sorting between the two awk passes gives per-path p95 without multi-dim arrays.
    local top_rows
    top_rows=$(tail -q -n "$window" "${files[@]}" 2>/dev/null \
        | awk -v EXCLUDE_LIST="${SLOW_EXCLUDE_PATHS:-}" '
            BEGIN {
                # Pre-process the exclude glob list: strip trailing "/*" to
                # leave a plain prefix, then match by string equality at the
                # start. Space-separated input, empty entries ignored.
                n_excl = split(EXCLUDE_LIST, excl, " ")
                for (i = 1; i <= n_excl; i++) { sub(/\/\*$/, "/", excl[i]) }
            }
            function path_excluded(p,   i) {
                for (i = 1; i <= n_excl; i++) {
                    if (excl[i] == "") continue
                    if (index(p, excl[i]) == 1) return 1
                }
                return 0
            }
            $NF ~ /^[0-9]+(\.[0-9]+)?$/ && NF >= 8 {
                path = $7
                q = index(path, "?")
                if (q > 0) path = substr(path, 1, q - 1)
                # Defensive: URL paths start with "/". Malformed request
                # lines (garbage that awk field-split wrongly) can yield
                # rows like PATH="400" — skip before they pollute the p95
                # table.
                if (substr(path, 1, 1) != "/") next
                # WebSocket / configured-exclude filter — WS $request_time
                # is session lifetime, not latency; excluding prevents a
                # healthy 22-minute chat from topping the slowest list.
                if (path_excluded(path)) next
                if (length(path) > 0) {
                    printf "%s\t%d\n", path, int($NF * 1000 + 0.5)
                }
            }' \
        | sort -t $'\t' -k1,1 -k2,2n \
        | awk -F'\t' '
            function emit(   pi) {
                if (n > 0) {
                    pi = int((n * 95 + 99) / 100)
                    if (pi < 1) pi = 1
                    if (pi > n) pi = n
                    printf "%s\t%d\t%d\n", cur, v[pi], n
                }
            }
            BEGIN { cur = ""; n = 0 }
            {
                if ($1 != cur) {
                    emit()
                    cur = $1; n = 0; delete v
                }
                n++
                v[n] = $2
            }
            END { emit() }' \
        | sort -t $'\t' -k2,2 -rn \
        | head -n "$n" \
        | _tty_safe)

    if [[ -z "$top_rows" ]]; then
        echo -e "${D}No timed samples in window — is \$request_time in your log_format?${NC}"
        echo
        return 0
    fi

    printf "%-5s  %-9s  %7s  %s\n" "RANK" "P95"     "COUNT" "PATH"
    printf "%-5s  %-9s  %7s  %s\n" "────" "────────" "───────" "────────────────────"

    local i=1 path p95 count col
    while IFS=$'\t' read -r path p95 count; do
        col=$(tcol "$p95" "$P95_WARN_MS" "$P95_CRIT_MS")
        # URL paths are ASCII, so ${#path} is the display width.
        local display="$path"
        if (( ${#display} > 80 )); then
            display="${display:0:77}..."
        fi
        printf "#%-4d  %b%-9s${NC}  %7d  %s\n" "$i" "$col" "${p95}ms" "$count" "$display"
        i=$((i+1))
    done <<< "$top_rows"
    echo
}

# milog stats <app>: requests per hour for one app.
mode_stats() {
    local name="${1:-}"
    [[ -z "$name" || ! " ${LOGS[*]} " =~ " $name " ]] && {
        echo -e "${R}Usage: $0 stats <app>${NC}  Apps: ${LOGS[*]}"; exit 1; }
    local file="$LOG_DIR/$name.access.log"
    [[ -f "$file" ]] || { echo -e "${R}Not found: $file${NC}"; exit 1; }
    echo -e "\n${W}── MiLog: Hourly breakdown — ${name} ──${NC}\n"
    awk '{if(match($4,/^\[[0-9][0-9]\/[A-Za-z]+\/[0-9][0-9][0-9][0-9]:[0-9][0-9]/))
         h[substr($4,RSTART+RLENGTH-2,2)]++}
         END{for(x in h)print x,h[x]}' "$file" | sort | \
    awk -v g="$G" -v y="$Y" -v r="$R" -v nc="$NC" '
    BEGIN{max=0}{if($2>max)max=$2;d[NR]=$0;n=NR}
    END{for(i=1;i<=n;i++){split(d[i],a," ")
        b=int((a[2]/max)*40); bars=""
        for(j=0;j<b;j++) bars=bars"|"
        col=g; if(a[2]/max>0.6)col=y; if(a[2]/max>0.85)col=r
        printf "%s:00  %s%-40s%s  %d\n",a[1],col,bars,nc,a[2]}}'
    echo ""
}

# milog suspects [N] [lines]: ranks IPs over the last <lines> per app.
# Score = 4xx×2 + 5xx×3 + missing-UA hits + 10 for a scanner UA + unique requests/5.
mode_suspects() {
    local topn="${1:-20}"
    local window="${2:-2000}"

    echo -e "\n${W}── MiLog: Suspicious IPs (last ${window} lines/app, top ${topn}) ──${NC}\n"

    local show_geo=0
    [[ "${GEOIP_ENABLED:-0}" == "1" && -f "$MMDB_PATH" ]] && show_geo=1

    if (( show_geo )); then
        printf "%-6s  %-18s  %-7s  %6s  %5s  %5s  %6s  %s\n" \
            "SCORE" "IP" "COUNTRY" "REQ" "4XX" "5XX" "PATHS" "FLAGS"
        printf "%-6s  %-18s  %-7s  %6s  %5s  %5s  %6s  %s\n" \
            "─────" "─────────────────" "───────" "──────" "─────" "─────" "──────" "──────────"
    else
        printf "%-6s  %-18s  %6s  %5s  %5s  %6s  %s\n" \
            "SCORE" "IP" "REQ" "4XX" "5XX" "PATHS" "FLAGS"
        printf "%-6s  %-18s  %6s  %5s  %5s  %6s  %s\n" \
            "─────" "─────────────────" "──────" "─────" "─────" "──────" "──────────"
    fi

    local tmp; tmp=$(mktemp)
    local name
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        [[ -f "$file" ]] && tail -n "$window" "$file" >> "$tmp"
    done

    # Country lookups happen after ranking, so mmdblookup runs at most $topn times.
    local ranked
    ranked=$(awk '
        BEGIN { FS = "\"" }
        NF >= 6 {
            split($1, a, " ");  ip = a[1]
            gsub(/^ +| +$/, "", $3);  split($3, s, " ");  status = s[1]
            req = $2;  ua = $6

            reqs[ip]++
            if (status ~ /^4/) e4[ip]++
            if (status ~ /^5/) e5[ip]++
            if (ua == "-" || ua == "") no_ua[ip]++

            key = ip "|" req
            if (!(key in seen)) { seen[key] = 1;  paths[ip]++ }

            ual = tolower(ua)
            if (ual ~ /masscan|zgrab|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster|ffuf|wfuzz|feroxbuster|libredtail|l9explore|shodan|censysinspect|expanseinc|httpx|python-requests|go-http-client|okhttp|libwww-perl|scanner|fuzzer|leakix/) {
                scanner_ua[ip] = 1
            }
        }
        END {
            for (ip in reqs) {
                sc = e4[ip]*2 + e5[ip]*3 + no_ua[ip] + (scanner_ua[ip]?10:0) + int(paths[ip]/5)
                if (sc < 3) continue
                f = ""
                if (scanner_ua[ip])    f = f " SCANNER"
                if (no_ua[ip] > 0)     f = f " NO-UA"
                if (e4[ip] >= 20)      f = f " HIGH-4XX"
                if (e5[ip] >= 5)       f = f " HIGH-5XX"
                if (paths[ip] >= 10)   f = f " MANY-PATHS"
                sub(/^ /, "", f)
                printf "%d\t%s\t%d\t%d\t%d\t%d\t%s\n", sc, ip, reqs[ip], e4[ip]+0, e5[ip]+0, paths[ip]+0, f
            }
        }' "$tmp" | sort -t$'\t' -k1,1 -rn | head -n "$topn")

    rm -f "$tmp"

    [[ -z "$ranked" ]] && { echo; return 0; }

    local sc ip req e4 e5 p_count flags c country cti
    while IFS=$'\t' read -r sc ip req e4 e5 p_count flags; do
        # Cache only: a network lookup per row would stall the table and burn the API quota.
        cti=$(cti_lookup "$ip" cached)
        [[ -n "$cti" && "$cti" != unknown ]] && flags="${flags:+$flags }CS:${cti%% *}"
        c=$G
        (( sc >= 10 )) && c=$Y
        (( sc >= 30 )) && c=$R
        if (( show_geo )); then
            country=$(geoip_country "$ip")
            printf "%b%-6s%b  %-18s  %-7s  %6s  %5s  %5s  %6s  %s\n" \
                "$c" "$sc" "$NC" "$ip" "$country" "$req" "$e4" "$e5" "$p_count" "$flags"
        else
            printf "%b%-6s%b  %-18s  %6s  %5s  %5s  %6s  %s\n" \
                "$c" "$sc" "$NC" "$ip" "$req" "$e4" "$e5" "$p_count" "$flags"
        fi
    done <<< "$ranked"

    echo
}

# milog top-paths [N]: requests, 4xx, 5xx and p95 per path (query strings stripped); p95 shows n/a without $request_time.
mode_top_paths() {
    local n="${1:-20}"
    local window="${SLOW_WINDOW:-2000}"

    [[ "$n"      =~ ^[0-9]+$ ]] || { echo -e "${R}top-paths: N must be numeric${NC}" >&2; return 1; }
    [[ "$window" =~ ^[0-9]+$ ]] || { echo -e "${R}top-paths: SLOW_WINDOW must be numeric${NC}" >&2; return 1; }

    echo -e "\n${W}── MiLog: Top ${n} paths (window=${window} lines/app) ──${NC}\n"

    local files=() name f
    for name in "${LOGS[@]}"; do
        f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] && files+=("$f")
    done
    if (( ${#files[@]} == 0 )); then
        echo -e "${R}No log files found in ${LOG_DIR}${NC}"
        return 1
    fi

    # Rows of path, status, ms (or "-"); sorting by ms within each path lets the group pass index p95 over the timed samples only.
    local rows
    rows=$(tail -q -n "$window" "${files[@]}" 2>/dev/null \
        | awk -v EXCLUDE_LIST="${SLOW_EXCLUDE_PATHS:-}" '
            BEGIN {
                # Shared with mode_slow: strip trailing "/*" from each glob
                # and prefix-match. WebSocket paths would otherwise poison
                # both the p95 column AND the request-count table (WS
                # connections can be very long-lived, so they accumulate
                # inflated per-path counts).
                n_excl = split(EXCLUDE_LIST, excl, " ")
                for (i = 1; i <= n_excl; i++) { sub(/\/\*$/, "/", excl[i]) }
            }
            function path_excluded(p,   i) {
                for (i = 1; i <= n_excl; i++) {
                    if (excl[i] == "") continue
                    if (index(p, excl[i]) == 1) return 1
                }
                return 0
            }
            NF >= 9 {
                path = $7
                q = index(path, "?")
                if (q > 0) path = substr(path, 1, q - 1)
                if (length(path) == 0) next
                # Defensive path guard — drop malformed request lines that
                # yield non-absolute "paths" like PATH="400".
                if (substr(path, 1, 1) != "/") next
                if (path_excluded(path)) next
                status = $9
                if (status !~ /^[0-9]+$/) next
                lf = $NF
                if (lf ~ /^[0-9]+(\.[0-9]+)?$/ && NF >= 12) {
                    printf "%s\t%s\t%d\n", path, status, int(lf * 1000 + 0.5)
                } else {
                    printf "%s\t%s\t-\n", path, status
                }
            }' \
        | sort -t $'\t' -k1,1 -k3,3n \
        | awk -F'\t' '
            function emit(   pi, p95) {
                if (cur == "") return
                if (nt > 0) {
                    pi = int((nt * 95 + 99) / 100)
                    if (pi < 1) pi = 1
                    if (pi > nt) pi = nt
                    p95 = v[pi]
                } else {
                    p95 = "-"
                }
                printf "%s\t%d\t%d\t%d\t%s\n", cur, count, c4, c5, p95
            }
            BEGIN { cur = ""; count = 0; c4 = 0; c5 = 0; nt = 0 }
            {
                if ($1 != cur) {
                    emit()
                    cur = $1; count = 0; c4 = 0; c5 = 0; nt = 0; delete v
                }
                count++
                if ($2 ~ /^4/) c4++
                if ($2 ~ /^5/) c5++
                if ($3 != "-") { nt++; v[nt] = $3 }
            }
            END { emit() }' \
        | sort -t $'\t' -k2,2 -rn \
        | head -n "$n" \
        | _tty_safe)

    if [[ -z "$rows" ]]; then
        echo -e "${D}No loglines matched in window.${NC}\n"
        return 0
    fi

    printf "%-5s  %7s  %5s  %5s  %9s  %s\n" "RANK" "REQ" "4XX" "5XX" "P95" "PATH"
    printf "%-5s  %7s  %5s  %5s  %9s  %s\n" "────" "───────" "─────" "─────" "─────────" "────────────────────"

    local i=1 path count c4 c5 p95 col_err col_p95 p95_disp display
    while IFS=$'\t' read -r path count c4 c5 p95; do
        col_err=""
        (( c5 > 0 )) && col_err="$R"
        col_err+=""    # no-op but keeps the colour local
        if [[ "$p95" == "-" ]]; then
            # ASCII, because the 3-byte em-dash breaks printf width alignment.
            p95_disp=$(printf "%b%9s%b" "$D" "n/a" "$NC")
            col_p95=""
        else
            col_p95=$(tcol "$p95" "$P95_WARN_MS" "$P95_CRIT_MS")
            p95_disp=$(printf "%b%7sms%b" "$col_p95" "$p95" "$NC")
        fi
        display="$path"
        if (( ${#display} > 60 )); then
            display="${display:0:57}..."
        fi
        printf "#%-4d  %7d  %b%5d%b  %b%5d%b  %b  %s\n" \
            "$i" "$count" \
            "$Y" "$c4" "$NC" \
            "$R" "$c5" "$NC" \
            "$p95_disp" "$display"
        i=$(( i + 1 ))
    done <<< "$rows"
    echo
}

# milog top [N]: busiest IPs across all apps.
mode_top() {
    local n="${1:-10}"
    echo -e "\n${W}── MiLog: Top ${n} IPs ──${NC}\n"

    local show_geo=0
    [[ "${GEOIP_ENABLED:-0}" == "1" && -f "$MMDB_PATH" ]] && show_geo=1

    if (( show_geo )); then
        printf "%-5s  %-18s  %-7s  %10s\n" "RANK" "IP" "COUNTRY" "REQUESTS"
        printf "%-5s  %-18s  %-7s  %10s\n" "────" "─────────────────" "───────" "────────"
    else
        printf "%-5s  %-18s  %10s\n" "RANK" "IP" "REQUESTS"
        printf "%-5s  %-18s  %10s\n" "────" "─────────────────" "────────"
    fi

    local tmp; tmp=$(mktemp)
    local name ai tot ai_sum=0 tot_sum=0
    for name in "${LOGS[@]}"; do
        [[ -f "$LOG_DIR/$name.access.log" ]] || continue
        awk '{print $1}' "$LOG_DIR/$name.access.log" >> "$tmp"
        read -r ai tot < <(nginx_ai_counts "$name")
        ai_sum=$(( ai_sum + ai )); tot_sum=$(( tot_sum + tot ))
    done

    # Geo lookup after uniq, so mmdblookup forks at most $n times.
    local i=1 count ip col country
    while read -r count ip; do
        col=""
        (( i == 1 ))             && col="$R"
        (( i > 1 && i <= 3 ))    && col="$Y"
        if (( show_geo )); then
            country=$(geoip_country "$ip")
            printf "%-5s  %-18s  %-7s  %b%10s%b\n" \
                "#$i" "$ip" "$country" "$col" "$count" "$NC"
        else
            printf "%-5s  %-18s  %b%10s%b\n" \
                "#$i" "$ip" "$col" "$count" "$NC"
        fi
        i=$((i+1))
    done < <(sort "$tmp" | uniq -c | sort -rn | head -n "$n")

    rm -f "$tmp"
    if (( tot_sum > 0 )); then
        echo -e "\n${D}AI crawlers: $(( ai_sum * 100 / tot_sum ))% of requests (${ai_sum} of ${tot_sum})${NC}"
    fi
    echo
}

# milog top-ip-by-app [N]: top IPs per app, which `milog top` hides by merging apps.
mode_top_ip_by_app() {
    local n="${1:-5}"

    if (( ${#LOGS[@]} == 0 )); then
        echo -e "${R}no apps configured (LOGS=())${NC}" >&2
        return 1
    fi

    echo -e "\n${W}── MiLog: Top ${n} IPs per app ──${NC}\n"

    local show_geo=0
    [[ "${GEOIP_ENABLED:-0}" == "1" && -f "$MMDB_PATH" ]] && show_geo=1

    if (( show_geo )); then
        printf "%-14s  %-5s  %-18s  %-7s  %10s\n" "APP" "RANK" "IP" "COUNTRY" "REQUESTS"
        printf "%-14s  %-5s  %-18s  %-7s  %10s\n" "──────────────" "────" "─────────────────" "───────" "────────"
    else
        printf "%-14s  %-5s  %-18s  %10s\n" "APP" "RANK" "IP" "REQUESTS"
        printf "%-14s  %-5s  %-18s  %10s\n" "──────────────" "────" "─────────────────" "────────"
    fi

    local name path i count ip col country printed_anything=0
    for name in "${LOGS[@]}"; do
        path="$LOG_DIR/$name.access.log"
        [[ -f "$path" ]] || continue

        # Show apps with no traffic instead of silently dropping them.
        if [[ ! -s "$path" ]]; then
            if (( show_geo )); then
                printf "%-14s  %-5s  %-18s  %-7s  %10s\n" "$name" "-" "(no traffic)" "-" "0"
            else
                printf "%-14s  %-5s  %-18s  %10s\n" "$name" "-" "(no traffic)" "0"
            fi
            printed_anything=1
            continue
        fi

        i=1
        while read -r count ip; do
            col=""
            (( i == 1 ))            && col="$R"
            (( i > 1 && i <= 3 ))   && col="$Y"
            if (( show_geo )); then
                country=$(geoip_country "$ip")
                printf "%-14s  %-5s  %-18s  %-7s  %b%10s%b\n" \
                    "$name" "#$i" "$ip" "$country" "$col" "$count" "$NC"
            else
                printf "%-14s  %-5s  %-18s  %b%10s%b\n" \
                    "$name" "#$i" "$ip" "$col" "$count" "$NC"
            fi
            i=$((i+1))
        done < <(awk '{print $1}' "$path" | sort | uniq -c | sort -rn | head -n "$n")

        printed_anything=1
        echo
    done

    if (( ! printed_anything )); then
        echo -e "${D}no readable access logs under $LOG_DIR${NC}"
    fi
}
# milog trend [app] [hours]: req/min and 4xx+5xx sparklines per app from metrics_minute.
_render_trend_one() {
    local app="$1" since="$2" window_sec="$3" width="$4"

    # Buckets with no rows are missing from the SQL output and filled with zeros below.
    local rows
    rows=$(sqlite3 -separator $'\t' "$HISTORY_DB" <<SQL 2>/dev/null
SELECT CAST((ts - $since) * $width / $window_sec AS INTEGER) AS col,
       COALESCE(SUM(req), 0),
       COALESCE(SUM(c4xx + c5xx), 0)
FROM metrics_minute
WHERE app = $(_sql_quote "$app") AND ts >= $since
GROUP BY col
ORDER BY col;
SQL
)
    if [[ -z "$rows" ]]; then
        printf "  ${D}%-10s  no data in window${NC}\n\n" "$app"
        return
    fi

    local -a req_samples=() err_samples=()
    local i
    for (( i = 0; i < width; i++ )); do
        req_samples+=(0)
        err_samples+=(0)
    done

    local col req err
    while IFS=$'\t' read -r col req err; do
        [[ "$col" =~ ^[0-9]+$ ]] || continue
        if (( col >= 0 && col < width )); then
            req_samples[$col]="${req:-0}"
            err_samples[$col]="${err:-0}"
        fi
    done <<< "$rows"

    local req_spark err_spark v peak=0 total=0
    req_spark=$(sparkline_render "${req_samples[*]}")
    err_spark=$(sparkline_render "${err_samples[*]}")
    for v in "${req_samples[@]}"; do (( v > peak  )) && peak=$v; done
    for v in "${err_samples[@]}"; do total=$(( total + v )); done

    printf "  ${W}%-10s${NC}  req ${G}%s${NC}  peak=%d/bucket\n" "$app" "$req_spark" "$peak"
    printf "  %-10s  err ${R}%s${NC}  total=%d\n" "" "$err_spark" "$total"
    echo
}

mode_trend() {
    local app_arg="${1:-}" hours="${2:-24}"
    [[ "$hours" =~ ^[1-9][0-9]*$ ]] \
        || { echo -e "${R}trend: hours must be a positive integer${NC}" >&2; return 1; }

    _history_precheck || return 1

    # Terminal-width sparkline, at least 40 columns.
    milog_update_geometry
    local now since width window_sec
    width=$(( INNER - 40 ))
    (( width < 40 )) && width=40
    now=$(date +%s)
    window_sec=$(( hours * 3600 ))
    since=$(( now - window_sec ))

    local -a apps
    if [[ -n "$app_arg" ]]; then
        local ok=0 name
        for name in "${LOGS[@]}"; do
            [[ "$name" == "$app_arg" ]] && { ok=1; break; }
        done
        if (( ! ok )); then
            echo -e "${R}trend: unknown app '$app_arg'${NC}  Apps: ${LOGS[*]}" >&2
            return 1
        fi
        apps=("$app_arg")
    else
        apps=("${LOGS[@]}")
    fi

    echo -e "\n${W}── MiLog: Trend (last ${hours}h, ${width} buckets) ──${NC}\n"

    local a
    for a in "${apps[@]}"; do
        _render_trend_one "$a" "$since" "$window_sec" "$width"
    done
}

# milog update-rules: installs the detection rules from the latest release as RULES_FILE.
# checksums.txt comes from the same release, so it catches corruption, not a compromised release.
mode_update_rules() {
    local repo="${MILOG_RELEASE_REPO:-chud-lori/milog}" loc tag base tmp want got new cur dst_tmp
    # /releases/latest redirects to /releases/tag/<tag>.
    loc=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/${repo}/releases/latest" 2>/dev/null) || loc=""
    if [[ ! "$loc" =~ /tag/([^/?#]+) ]]; then
        echo -e "${R}update-rules: no release found for ${repo}${NC}" >&2
        return 1
    fi
    tag="${BASH_REMATCH[1]}"
    base="https://github.com/${repo}/releases/download/${tag}"

    tmp=$(mktemp -d) || return 1
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    # Releases up to v0.6.0 predate the rules file, so a 404 here is expected.
    if ! curl -fsSL --retry 2 --retry-delay 1 --max-time 60 -o "$tmp/milog-rules.tsv" "${base}/milog-rules.tsv" 2>/dev/null; then
        echo -e "${R}update-rules: release ${tag} ships no rules file (or it could not be fetched)${NC}" >&2
        return 1
    fi
    if ! curl -fsSL --retry 2 --retry-delay 1 --max-time 60 -o "$tmp/checksums.txt" "${base}/checksums.txt" 2>/dev/null; then
        echo -e "${R}update-rules: could not fetch checksums.txt for ${tag}; refusing an unverified rules file${NC}" >&2
        return 1
    fi

    want=$(awk '$2 == "milog-rules.tsv" {print $1; exit}' "$tmp/checksums.txt")
    if [[ -z "$want" ]]; then
        echo -e "${R}update-rules: milog-rules.tsv is not listed in checksums.txt for ${tag}${NC}" >&2
        return 1
    fi
    got=$(_audit_sha256 "$tmp/milog-rules.tsv")
    if [[ -z "$got" ]]; then
        echo -e "${R}update-rules: need sha256sum or shasum to verify the download${NC}" >&2
        return 1
    fi
    if [[ "$got" != "$want" ]]; then
        echo -e "${R}update-rules: checksum mismatch for milog-rules.tsv from ${tag} (expected ${want}, got ${got})${NC}" >&2
        return 1
    fi
    if ! new=$(_rules_check "$tmp/milog-rules.tsv"); then
        echo -e "${R}update-rules: rules from ${tag} failed validation; keeping the current rules${NC}" >&2
        return 1
    fi

    cur=$(_rules_check "$RULES_FILE" 2>/dev/null) || cur=$(_rules_default | _rules_version)
    if (( new < cur )); then
        echo -e "${R}update-rules: ${tag} ships rules version ${new}, older than the active version ${cur}; not downgrading${NC}" >&2
        return 1
    fi
    if (( new == cur )); then
        echo "Rules already at version ${cur}."
        return 0
    fi

    mkdir -p "$(dirname "$RULES_FILE")" || return 1
    dst_tmp=$(mktemp "${RULES_FILE}.XXXXXX") || return 1
    if ! cp "$tmp/milog-rules.tsv" "$dst_tmp" || ! chmod 0644 "$dst_tmp" || ! mv -f "$dst_tmp" "$RULES_FILE"; then
        rm -f "$dst_tmp"
        echo -e "${R}update-rules: could not write ${RULES_FILE}${NC}" >&2
        return 1
    fi
    echo -e "${G}✓${NC} rules version ${cur} → ${new} (${tag}) written to ${RULES_FILE}"
    echo "Running exploits/probes watchers and the daemon load rules at start; restart them to pick this up."
}
# milog web: start/stop/status and the systemd user unit for the milog-web binary.
_WEB_SYSTEMD_UNIT="${HOME}/.config/systemd/user/milog-web.service"

_web_service_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl --user is-active --quiet milog-web.service 2>/dev/null
}

# Rewrites the unit from the current config, so re-running picks up a changed WEB_PORT.
_web_service_install() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${R}systemctl not found — this host doesn't use systemd${NC}" >&2
        echo -e "${D}  use nohup or tmux instead:${NC}" >&2
        echo -e "${D}    nohup milog web > ~/.cache/milog/web.out 2>&1 &${NC}" >&2
        return 1
    fi
    if [[ $(id -u) -eq 0 ]]; then
        echo -e "${R}run milog web install-service as your regular user, not root${NC}" >&2
        echo -e "${D}  the web dashboard binds to loopback on a high port — no root needed${NC}" >&2
        return 1
    fi

    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"
    # Prefer the installed copy over a repo clone that may move.
    [[ -x /usr/local/bin/milog ]] && self="/usr/local/bin/milog"

    local unit_dir; unit_dir=$(dirname "$_WEB_SYSTEMD_UNIT")
    mkdir -p "$unit_dir" 2>/dev/null \
        || { echo -e "${R}cannot create $unit_dir${NC}" >&2; return 1; }

    # Pin the current port/bind so restarts serve the URL printed below.
    cat > "$_WEB_SYSTEMD_UNIT" <<EOF
[Unit]
Description=MiLog web dashboard (read-only, loopback)
Documentation=https://github.com/chud-lori/milog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Force bash — $self might be invoked by a shell that doesn't source ~/.bashrc.
ExecStart=/usr/bin/env bash $self web start
Restart=on-failure
RestartSec=5s
Environment=MILOG_WEB_PORT=${WEB_PORT}
Environment=MILOG_WEB_BIND=${WEB_BIND}

[Install]
WantedBy=default.target
EOF

    echo -e "${G}✓${NC} wrote $_WEB_SYSTEMD_UNIT"

    # A foreground instance would hold the port the unit is about to bind.
    if [[ -f "$(_web_pid_file)" ]]; then
        local old_pid; old_pid=$(cat "$(_web_pid_file)" 2>/dev/null || true)
        if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
            echo -e "${Y}stopping existing foreground milog web (pid=$old_pid)${NC}"
            _web_stop >/dev/null 2>&1 || true
        fi
    fi

    systemctl --user daemon-reload 2>/dev/null \
        || { echo -e "${R}systemctl --user daemon-reload failed${NC}" >&2; return 1; }
    if ! systemctl --user enable --now milog-web.service 2>&1; then
        echo -e "${R}failed to enable milog-web.service${NC}" >&2
        echo -e "${D}  tail logs: journalctl --user -u milog-web.service -b${NC}" >&2
        return 1
    fi

    echo -e "${G}✓${NC} systemctl --user enable --now milog-web.service"

    local token; token=$(_web_token_read 2>/dev/null || true)
    [[ -n "$token" ]] || { _web_token_ensure && token=$(_web_token_read); }
    local url="http://${WEB_BIND}:${WEB_PORT}/?t=${token}"

    printf '%b' "
${W}milog-web.service${NC} installed and running.

  ${W}URL:${NC} ${C}${url}${NC}

  ${D}manage:${NC}
    systemctl --user status  milog-web.service
    systemctl --user restart milog-web.service
    milog web uninstall-service     # removes the unit

  ${D}survive logout + reboot (one-time, needs root):${NC}
    sudo loginctl enable-linger \$USER
    ${D}without linger, the service stops when you log out.${NC}

  ${D}forward to your laptop:${NC}
    ssh -L ${WEB_PORT}:localhost:${WEB_PORT} \$USER@<this-host>
    open http://localhost:${WEB_PORT}/?t=${token}

"
}

_web_service_uninstall() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${D}systemctl not found — nothing to uninstall${NC}"
        return 0
    fi
    if [[ -f "$_WEB_SYSTEMD_UNIT" ]]; then
        systemctl --user stop    milog-web.service 2>/dev/null || true
        systemctl --user disable milog-web.service 2>/dev/null || true
        rm -f "$_WEB_SYSTEMD_UNIT"
        systemctl --user daemon-reload 2>/dev/null || true
        echo -e "${G}✓${NC} milog-web.service stopped, disabled, removed"
    else
        echo -e "${D}no unit at $_WEB_SYSTEMD_UNIT${NC}"
    fi
}

# Path to milog-web: $MILOG_WEB_BIN, the package locations, then go/bin next to or above this script.
_web_go_binary() {
    if [[ -n "${MILOG_WEB_BIN:-}" && -x "$MILOG_WEB_BIN" ]]; then
        printf '%s' "$MILOG_WEB_BIN"; return 0
    fi
    local candidate
    for candidate in \
        /usr/local/libexec/milog/milog-web \
        /usr/local/bin/milog-web \
        /usr/bin/milog-web; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"
    local self_dir; self_dir=$(cd "$(dirname "$self")" && pwd)
    for candidate in "$self_dir/go/bin/milog-web" "$self_dir/../go/bin/milog-web"; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    return 1
}

# Usually reached from a git clone that never ran install.sh.
_web_no_binary_error() {
    printf '%b' "
${R}milog-web binary not found.${NC}

The dashboard server is a small Go binary (about 6 MB). It must be on disk
for ${W}milog web${NC} to start. Pick one:

  ${W}1. Run install.sh (recommended)${NC}
     ${D}curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | bash${NC}
     ${D}install.sh fetches milog-web + milog-tui from the latest GitHub release${NC}
     ${D}and places them on PATH alongside milog itself.${NC}

  ${W}2. Build from a clone${NC}
     ${D}git clone https://github.com/chud-lori/milog && cd milog${NC}
     ${D}bash build.sh    # builds go/bin/milog-web${NC}

  ${W}3. Override the path${NC}
     ${D}MILOG_WEB_BIN=/path/to/milog-web milog web${NC}

Search path checked (in order):
  \$MILOG_WEB_BIN
  /usr/local/libexec/milog/milog-web
  /usr/local/bin/milog-web
  /usr/bin/milog-web
  <script-dir>/go/bin/milog-web        (clone / dev)
  <script-dir>/../go/bin/milog-web

" >&2
}

# Execs milog-web with the MILOG_* env it reads through config.Load().
_web_start_go() {
    local go_bin="$1"
    local token; token=$(_web_token_read)
    local url="http://${WEB_BIND}:${WEB_PORT}/?t=${token}"
    printf '%b' "
${W}MiLog web${NC}  starting milog-web  ${D}${go_bin}${NC}

  ${W}URL:${NC} ${C}${url}${NC}

  ${D}Phone/laptop from another machine:${NC}
    ssh -L ${WEB_PORT}:localhost:${WEB_PORT} \$USER@<this-host>
    open http://localhost:${WEB_PORT}/?t=${token}

  ${D}token:${NC}  ${WEB_TOKEN_FILE}
  ${D}stop:${NC}   milog web stop    (or Ctrl+C)

"
    # exec keeps this pid, so it is milog-web's pid for `milog web stop`.
    echo $$ > "$(_web_pid_file)"
    trap 'rm -f "$(_web_pid_file)"' EXIT

    export MILOG_WEB_BIND="$WEB_BIND" \
           MILOG_WEB_PORT="$WEB_PORT" \
           MILOG_LOG_DIR="$LOG_DIR" \
           MILOG_APPS="${LOGS[*]}" \
           MILOG_REFRESH="${REFRESH:-5}" \
           MILOG_ALERTS_ENABLED="${ALERTS_ENABLED:-0}" \
           MILOG_DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}" \
           MILOG_ALERT_STATE_DIR="${ALERT_STATE_DIR:-$HOME/.cache/milog}"
    exec "$go_bin"
}

mode_web() {
    # A leading --flag means implicit `start`.
    case "${1:-}" in
        stop)     _web_stop;   return ;;
        status)   _web_status; return ;;
        start)    shift ;;
        install-service)   _web_service_install;   return ;;
        uninstall-service) _web_service_uninstall; return ;;
        rotate-token)      _web_rotate_token;      return ;;
        ""|--*)   : ;;
        *)        echo -e "${R}usage: milog web [start|stop|status|install-service|uninstall-service|rotate-token] [--port N] [--bind ADDR] [--trust]${NC}" >&2
                  return 1 ;;
    esac

    local trust=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)   WEB_PORT="${2:?}"; shift 2 ;;
            --bind)   WEB_BIND="${2:?}"; shift 2 ;;
            --trust)  trust=1; shift ;;
            *)        echo -e "${R}unknown option: $1${NC}" >&2; return 1 ;;
        esac
    done

    [[ "$WEB_PORT" =~ ^[0-9]+$ ]] \
        || { echo -e "${R}--port must be numeric${NC}" >&2; return 1; }

    if [[ "$WEB_BIND" != "127.0.0.1" && "$WEB_BIND" != "localhost" && "$WEB_BIND" != "::1" ]] && (( ! trust )); then
        printf '%b' "
${R}refusing --bind $WEB_BIND without --trust${NC}
${D}  this exposes the dashboard beyond loopback. Safer transports:${NC}
${D}    1. SSH tunnel:     ssh -L $WEB_PORT:localhost:$WEB_PORT $USER@<host>${NC}
${D}    2. Tailscale/WG:   --bind <overlay-ip> (only reachable on your tailnet)${NC}
${D}    3. Cloudflare:     cloudflared tunnel --url http://localhost:$WEB_PORT${NC}
${D}  If you really mean it:  milog web --bind $WEB_BIND --port $WEB_PORT --trust${NC}
" >&2
        return 1
    fi

    if _web_systemd_active; then
        echo -e "${Y}milog-web.service is already running (systemd). Check: milog web status${NC}"
        return 1
    fi
    if _web_status >/dev/null 2>&1; then
        echo -e "${Y}milog web is already running (foreground). Check: milog web status${NC}"
        return 1
    fi

    _web_token_ensure || return 1
    mkdir -p "$WEB_STATE_DIR" 2>/dev/null

    # No bash fallback server.
    local go_bin
    go_bin=$(_web_go_binary) || { _web_no_binary_error; return 1; }
    _web_start_go "$go_bin"
}

# milog ws: WebSocket session metrics. $request_time is the whole session for these, which is why slow/top-paths exclude them.
# WS paths are SLOW_EXCLUDE_PATHS, so both views always agree; needs $request_time in the log format.

# Seconds -> "<1s", "Ns", "MmSSs", "HhMMm" or "DdHHh".
_ws_fmt_duration() {
    local s="$1"
    if ! [[ "$s" =~ ^[0-9]+$ ]]; then printf -- '—'; return; fi
    if   (( s < 1 ));     then printf '<1s'
    elif (( s < 60 ));    then printf '%ds' "$s"
    elif (( s < 3600 ));  then printf '%dm %02ds' $(( s / 60 )) $(( s % 60 ))
    elif (( s < 86400 )); then printf '%dh %02dm' $(( s / 3600 )) $(( (s % 3600) / 60 ))
    else                       printf '%dd %02dh' $(( s / 86400 )) $(( (s % 86400) / 3600 ))
    fi
}

mode_ws() {
    local n="${1:-10}"
    local window="${SLOW_WINDOW:-1000}"

    [[ "$n"      =~ ^[0-9]+$ ]] || { echo -e "${R}ws: N must be numeric${NC}" >&2; return 1; }
    [[ "$window" =~ ^[0-9]+$ ]] || { echo -e "${R}ws: SLOW_WINDOW must be numeric${NC}" >&2; return 1; }

    local ws_paths="${SLOW_EXCLUDE_PATHS:-}"
    if [[ -z "$ws_paths" ]]; then
        echo -e "${R}ws:${NC} SLOW_EXCLUDE_PATHS is empty — nothing identifies WebSocket paths"
        echo -e "${D}  set e.g. SLOW_EXCLUDE_PATHS=\"/ws/* /socket.io/*\" in your config${NC}"
        return 1
    fi

    echo -e "\n${W}── MiLog: WebSocket sessions (window=${window} lines/app) ──${NC}\n"

    local name files=()
    for name in "${LOGS[@]}"; do
        local f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] && files+=("$name:$f")
    done

    if (( ${#files[@]} == 0 )); then
        echo -e "${R}No log files found in ${LOG_DIR}${NC}"
        return 1
    fi

    # `app \t path \t ms` for WS paths, one file at a time so lines keep their app.
    local raw
    raw=$(
        for entry in "${files[@]}"; do
            local app="${entry%%:*}"
            local file="${entry#*:}"
            tail -n "$window" "$file" 2>/dev/null | awk \
                -v APP="$app" \
                -v EXCLUDE_LIST="$ws_paths" '
                BEGIN {
                    n_excl = split(EXCLUDE_LIST, excl, " ")
                    for (i = 1; i <= n_excl; i++) { sub(/\/\*$/, "/", excl[i]) }
                }
                function is_ws_path(p,   i) {
                    for (i = 1; i <= n_excl; i++) {
                        if (excl[i] == "") continue
                        if (index(p, excl[i]) == 1) return 1
                    }
                    return 0
                }
                $NF ~ /^[0-9]+(\.[0-9]+)?$/ && NF >= 8 {
                    path = $7
                    q = index(path, "?")
                    if (q > 0) path = substr(path, 1, q - 1)
                    if (substr(path, 1, 1) != "/") next
                    if (!is_ws_path(path)) next
                    # Emit milliseconds (int) so downstream sort is clean.
                    printf "%s\t%s\t%d\n", APP, path, int($NF * 1000 + 0.5)
                }'
        done
    )

    if [[ -z "$raw" ]]; then
        echo -e "${D}No WebSocket samples in window — either no WS traffic or${NC}"
        echo -e "${D}nginx isn't logging \$request_time for these paths.${NC}"
        echo
        return 0
    fi

    local long_threshold_s=3600   # sessions > this are "long"
    local summary
    summary=$(printf '%s\n' "$raw" \
        | awk -F'\t' -v LT_MS=$((long_threshold_s * 1000)) '
            { n++; ms[n] = $3; sum += $3; if ($3 > max) max = $3; if ($3 > LT_MS) long++ }
            END {
                if (n == 0) { print "0\t0\t0\t0\t0\t0"; exit }
                # In-place numeric sort — bubble for small N is fine; asort
                # is gawk-only. For typical windows n < 10k which takes <20ms.
                for (i = 2; i <= n; i++) {
                    k = ms[i]; j = i - 1
                    while (j >= 1 && ms[j] > k) { ms[j+1] = ms[j]; j-- }
                    ms[j+1] = k
                }
                p50_idx = int((n * 50 + 99) / 100); if (p50_idx < 1) p50_idx = 1; if (p50_idx > n) p50_idx = n
                p95_idx = int((n * 95 + 99) / 100); if (p95_idx < 1) p95_idx = 1; if (p95_idx > n) p95_idx = n
                avg = int(sum / n)
                # Output: total_sessions, avg_ms, p50_ms, p95_ms, max_ms, long_count
                printf "%d\t%d\t%d\t%d\t%d\t%d\n", n, avg, ms[p50_idx], ms[p95_idx], max, long
            }')

    local total_sessions avg_ms p50_ms p95_ms max_ms long_count
    IFS=$'\t' read -r total_sessions avg_ms p50_ms p95_ms max_ms long_count <<< "$summary"

    echo -e "${W}Summary${NC}"
    printf "  %-16s %s\n" "total sessions"  "$total_sessions"
    printf "  %-16s %s\n" "avg duration"    "$(_ws_fmt_duration $(( avg_ms / 1000 )))"
    printf "  %-16s %s\n" "p50 duration"    "$(_ws_fmt_duration $(( p50_ms / 1000 )))"
    printf "  %-16s %s\n" "p95 duration"    "$(_ws_fmt_duration $(( p95_ms / 1000 )))"
    printf "  %-16s %s\n" "longest session" "$(_ws_fmt_duration $(( max_ms / 1000 )))"
    if (( long_count > 0 )); then
        local col="$Y"
        (( long_count > 10 )) && col="$R"
        printf "  %-16s ${col}%d${NC} (threshold %s)\n" ">long sessions" "$long_count" "$(_ws_fmt_duration "$long_threshold_s")"
    else
        printf "  %-16s %s\n" ">long sessions" "0"
    fi
    echo

    # Per (app, path): sessions, p50, p95, max, busiest first.
    local rows
    rows=$(printf '%s\n' "$raw" \
        | sort -t $'\t' -k1,1 -k2,2 -k3,3n \
        | awk -F'\t' '
            function emit(   pi, pi95) {
                if (cur_app == "") return
                if (n > 0) {
                    pi   = int((n * 50 + 99) / 100); if (pi < 1) pi = 1; if (pi > n) pi = n
                    pi95 = int((n * 95 + 99) / 100); if (pi95 < 1) pi95 = 1; if (pi95 > n) pi95 = n
                    printf "%s\t%s\t%d\t%d\t%d\t%d\n", cur_app, cur_path, n, v[pi], v[pi95], v[n]
                }
            }
            BEGIN { cur_app = ""; cur_path = ""; n = 0 }
            {
                if ($1 != cur_app || $2 != cur_path) {
                    emit()
                    cur_app = $1; cur_path = $2; n = 0; delete v
                }
                n++
                v[n] = $3
            }
            END { emit() }' \
        | sort -t $'\t' -k3,3 -rn \
        | head -n "$n")

    echo -e "${W}Top WebSocket paths (by session count)${NC}"
    printf "%-5s  %8s  %9s  %9s  %9s  %-10s  %s\n" "RANK" "SESS" "p50" "p95" "LONGEST" "APP" "PATH"
    printf "%-5s  %8s  %9s  %9s  %9s  %-10s  %s\n" "────" "────────" "─────────" "─────────" "─────────" "──────────" "────────────"

    local i=1 app_col path sessions p50 p95 mx path_disp
    while IFS=$'\t' read -r app_col path sessions p50 p95 mx; do
        [[ -z "$app_col" ]] && continue
        path_disp="$path"
        (( ${#path_disp} > 40 )) && path_disp="${path_disp:0:37}..."
        local app_disp="$app_col"
        (( ${#app_disp} > 10 )) && app_disp="${app_disp:0:7}..."
        printf "#%-4d  %8d  %9s  %9s  %9s  %-10s  %s\n" \
            "$i" "$sessions" \
            "$(_ws_fmt_duration $(( p50 / 1000 )))" \
            "$(_ws_fmt_duration $(( p95 / 1000 )))" \
            "$(_ws_fmt_duration $(( mx / 1000 )))" \
            "$app_disp" \
            "$path_disp"
        i=$(( i + 1 ))
    done <<< "$rows"
    echo
}
_rules_default() {
    cat <<'MILOG_RULES_EOF'
# version: 1
# <kind>\t<name>\t<ERE>, matched case-insensitively. Rows of one kind are OR-ed in file order.
# exploit: URL payloads for `milog exploits`. probe: scanner/bot traffic for `milog probes`.
# category: classifies exploit hits for the alert key; the first matching row wins, none gives "other".
exploit	traversal	\.\./|%2e%2e
exploit	target-files	/etc/passwd|/etc/shadow|/proc/self/environ
exploit	infra	/containers/json|/actuator/|/server-status|/console(/|\?)|/druid/
exploit	device	/SDK/web|/cgi-bin/|/boaform/|/HNAP1
exploit	wordpress	/wp-admin|/wp-login|/wp-content/plugins|/xmlrpc\.php
exploit	phpmyadmin	/phpmyadmin|/pma/|/mysql/admin
exploit	dotfiles	/\.env|/\.git/|/\.aws/|/\.ssh/|/\.DS_Store
exploit	config-files	/config\.(php|json|yml|yaml)|/web\.config
exploit	log4shell	jndi:|\$\{jndi|log4j
exploit	sqli	union[+% ]+select|select[+% ]+from|sleep\([0-9]|benchmark\(
exploit	sqli	or[+% ]+1=1|%27[+% ]*or|%27%20or
exploit	xss	<script|%3cscript|onerror=|onload=|javascript:
exploit	rce	base64_decode|eval\(|system\(|passthru\(|shell_exec
exploit	scanner-ua	libredtail|nikto|masscan|zgrab|sqlmap|nuclei|gobuster
exploit	scanner-ua	dirbuster|wfuzz|l9explore|l9tcpid|hello,\s?world
# SSH banners and TLS ClientHellos sent to plain HTTP; nginx logs the bytes as literal \xNN.
probe	protocol	SSH-2\.0|\\x16\\x03|\\x00\\x00
probe	pentest-tools	masscan|zmap|zgrab|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster|dirb|ffuf|wfuzz|feroxbuster|nessus|openvas|acunetix|wpscan|joomscan|burp|zaproxy|owasp|metasploit|meterpreter|w3af|webshag
probe	mass-scanners	l9explore|l9tcpid|l9retrieve|leakix|libredtail|httpx|naabu|katana|subfinder|expanseinc|censysinspect|shodan|stretchoid|internet-measurement|greenbone|qualys|rapid7|detectify|intruder\.io|netcraftsurvey|netsystemsresearch|paloalto|projectdiscovery|odin\.ai|onyphe
probe	seo-crawlers	ahrefsbot|semrushbot|dotbot|mj12bot|blexbot|petalbot|serpstat|dataforseobot|mauibot|megaindex|seznambot
# milog adds its AI_CRAWLER_UA_RE tokens (shared with health/top) to the probe rows at load time.
probe	ai-crawlers	diffbot
probe	http-libraries	python-requests|python-urllib|aiohttp|go-http-client|okhttp|libwww-perl|java/1\.|apache-httpclient|restsharp|http_request2|guzzlehttp|node-fetch|axios|got\(|scrapy|mechanize
probe	headless	headlesschrome|phantomjs|puppeteer|playwright|selenium
probe	generic-bot	[Ss]canner|[Bb]ot/|[Cc]rawler|[Ss]pider|probe-|fuzzer|harvester
probe	payloads	hello,\s*world
category	log4shell	\$\{jndi|jndi:|log4j
category	sqli	union.*select|select.*from|sleep\(|benchmark\(| or 1=1|%27.*or
category	xss	<script|%3cscript|onerror=|onload=|javascript:
category	rce	base64_decode|eval\(|system\(|passthru\(|shell_exec
category	traversal	\.\./|%2e%2e|/etc/passwd|/etc/shadow|/proc/self
category	infra	/containers/|/actuator/|/server-status|/console|/druid/
category	device	/SDK/web|/cgi-bin/|/boaform/|/HNAP1
category	wordpress	/wp-admin|/wp-login|/wp-content/plugins|/xmlrpc\.php
category	phpmyadmin	/phpmyadmin|/pma/|/mysql/admin
category	dotfile	/\.env|/\.git/|/\.aws/|/\.ssh/|/\.DS_Store|/config\.php|/config\.json|/config\.yml|/config\.yaml|/web\.config
category	scanner	libredtail|nikto|masscan|zgrab|sqlmap|nuclei|gobuster|dirbuster|wfuzz|l9explore|l9tcpid|hello, world|hello,world
MILOG_RULES_EOF
}
_completions_payload_bash() {
    cat <<'MILOG_COMPLETION_EOF'
# bash-completion for milog.
# Install to /usr/share/bash-completion/completions/milog (system) or
# source from ~/.bash_completion for a user install.

_milog_complete() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    local cmds="monitor tui daemon rate health top top-ip-by-app top-paths attacker slow ws stats trend replay search diff auto-tune logs grep errors exploits probes patterns suspects config alert alerts silence digest report doctor web install update-rules audit probe bench completions help"
    local config_subs="show path init edit add rm dir set validate"
    local config_keys="LOG_DIR LOGS REFRESH SPARK_LEN DISCORD_WEBHOOK SLACK_WEBHOOK TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID MATRIX_HOMESERVER MATRIX_TOKEN MATRIX_ROOM WEBHOOK_URL WEBHOOK_TEMPLATE WEBHOOK_CONTENT_TYPE ALERTS_ENABLED ALERT_COOLDOWN ALERT_DEDUP_WINDOW ALERT_STATE_DIR ALERT_LOG_MAX_BYTES ALERT_ROUTES HOOKS_DIR ALERT_HOOK_TIMEOUT P95_WARN_MS P95_CRIT_MS SLOW_WINDOW SLOW_EXCLUDE_PATHS GEOIP_ENABLED MMDB_PATH HISTORY_ENABLED HISTORY_DB HISTORY_RETAIN_DAYS WEB_PORT WEB_BIND THRESH_REQ_WARN THRESH_REQ_CRIT THRESH_CPU_WARN THRESH_CPU_CRIT THRESH_MEM_WARN THRESH_MEM_CRIT THRESH_DISK_WARN THRESH_DISK_CRIT THRESH_4XX_WARN THRESH_5XX_WARN"
    local alert_subs="on off status test stats"
    local silence_subs="list clear"
    local web_subs="start stop status install-service uninstall-service rotate-token"
    local window_vals="today yesterday 1h 6h 12h 24h 7d 30d all"
    local digest_window_vals="day week 1h 6h 12h 24h 7d 30d"

    case $cword in
        1)
            COMPREPLY=($(compgen -W "$cmds" -- "$cur"))
            return 0
            ;;
    esac

    # Second-level: depend on the chosen command.
    local cmd="${words[1]}"
    case "$cmd" in
        config)
            case $cword in
                2) COMPREPLY=($(compgen -W "$config_subs" -- "$cur")) ;;
                3)
                    case "${words[2]}" in
                        set) COMPREPLY=($(compgen -W "$config_keys" -- "$cur")) ;;
                    esac
                    ;;
            esac
            ;;
        alert)
            case $cword in
                2) COMPREPLY=($(compgen -W "$alert_subs" -- "$cur")) ;;
            esac
            ;;
        silence)
            case $cword in
                2) COMPREPLY=($(compgen -W "$silence_subs" -- "$cur")) ;;
            esac
            ;;
        web)
            case $cword in
                2) COMPREPLY=($(compgen -W "$web_subs" -- "$cur")) ;;
            esac
            ;;
        alerts)
            case $cword in
                2) COMPREPLY=($(compgen -W "$window_vals" -- "$cur")) ;;
            esac
            ;;
        digest|report)
            case $cword in
                2) COMPREPLY=($(compgen -W "$digest_window_vals" -- "$cur")) ;;
            esac
            ;;
    esac
    return 0
}

complete -F _milog_complete milog
MILOG_COMPLETION_EOF
}
_completions_payload_zsh() {
    cat <<'MILOG_COMPLETION_EOF'
#compdef milog
# zsh completion for milog.
# Install to /usr/share/zsh/site-functions/_milog (system) or any dir in $fpath.

_milog() {
    local -a commands config_subs config_keys alert_subs silence_subs web_subs window_vals digest_window_vals

    commands=(
        'monitor:bash dashboard (nginx + system)'
        'tui:bubbletea TUI (Go binary)'
        'daemon:headless alerter — no TUI'
        'rate:nginx-only req/min dashboard'
        'health:2xx/3xx/4xx/5xx per app'
        'top:top N source IPs'
        'top-ip-by-app:top N source IPs per app'
        'top-paths:top N URLs by req/4xx/5xx/p95'
        'attacker:forensic view of one IP'
        'slow:top N slow endpoints by p95'
        'ws:WebSocket session metrics'
        'stats:hourly request histogram per app'
        'trend:sparkline of req/min from history'
        'replay:postmortem for one archived log'
        'search:grep across current + archived logs'
        'diff:per-app req now vs 1d/7d ago'
        'auto-tune:suggest thresholds from history'
        'logs:tail all logs, color prefixed'
        'grep:filter-tail one app'
        'errors:live 4xx/5xx tail'
        'exploits:LFI/RCE/SQLi/XSS/infra-probe tail'
        'probes:scanner/bot traffic tail'
        'patterns:app-error signatures (panics, OOM, stacktraces)'
        'suspects:heuristic bot ranking'
        'config:show / edit / set / init / validate'
        'alert:toggle alerting + systemd service'
        'alerts:local fire history'
        'silence:mute a rule while on-call fixes it'
        'digest:exec-summary view over last day / week'
        'report:static markdown / HTML report'
        'doctor:diagnostic checklist'
        'web:start/stop/status web UI'
        'install:add optional features: geoip / web / history'
        'update-rules:fetch newer exploit/probe rules from the latest release'
        'audit:host integrity scans (fim / persistence / ports / yara / accounts / rootkit)'
        'probe:eBPF probe sidecar service'
        'bench:benchmark harness against synthetic fixtures'
        'completions:install / print bash|zsh|fish completions'
        'help:show help'
    )

    config_subs=(show path init edit add rm dir set validate)
    config_keys=(
        LOG_DIR LOGS REFRESH SPARK_LEN
        DISCORD_WEBHOOK SLACK_WEBHOOK
        TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        MATRIX_HOMESERVER MATRIX_TOKEN MATRIX_ROOM
        WEBHOOK_URL WEBHOOK_TEMPLATE WEBHOOK_CONTENT_TYPE
        ALERTS_ENABLED ALERT_COOLDOWN ALERT_DEDUP_WINDOW
        ALERT_LOG_MAX_BYTES ALERT_ROUTES
        HOOKS_DIR ALERT_HOOK_TIMEOUT
        P95_WARN_MS P95_CRIT_MS SLOW_WINDOW SLOW_EXCLUDE_PATHS
        GEOIP_ENABLED MMDB_PATH
        HISTORY_ENABLED HISTORY_DB HISTORY_RETAIN_DAYS
        WEB_PORT WEB_BIND
        THRESH_REQ_WARN THRESH_REQ_CRIT
        THRESH_CPU_WARN THRESH_CPU_CRIT
        THRESH_MEM_WARN THRESH_MEM_CRIT
        THRESH_DISK_WARN THRESH_DISK_CRIT
        THRESH_4XX_WARN THRESH_5XX_WARN
    )
    alert_subs=(on off status test stats)
    silence_subs=(list clear)
    web_subs=(start stop status install-service uninstall-service rotate-token)
    window_vals=(today yesterday 1h 6h 12h 24h 7d 30d all)
    digest_window_vals=(day week 1h 6h 12h 24h 7d 30d)

    if (( CURRENT == 2 )); then
        _describe -t commands 'milog subcommand' commands
        return
    fi

    case "${words[2]}" in
        config)
            if   (( CURRENT == 3 )); then _describe 'config subcommand' config_subs
            elif (( CURRENT == 4 )); then
                case "${words[3]}" in
                    set) _describe 'config key' config_keys ;;
                esac
            fi
            ;;
        alert)    (( CURRENT == 3 )) && _describe 'alert subcommand' alert_subs ;;
        silence)  (( CURRENT == 3 )) && _describe 'silence subcommand' silence_subs ;;
        web)      (( CURRENT == 3 )) && _describe 'web subcommand' web_subs ;;
        alerts)   (( CURRENT == 3 )) && _describe 'window' window_vals ;;
        digest|report) (( CURRENT == 3 )) && _describe 'window' digest_window_vals ;;
    esac
}

_milog "$@"
MILOG_COMPLETION_EOF
}
_completions_payload_fish() {
    cat <<'MILOG_COMPLETION_EOF'
# fish completion for milog.
# Install to /usr/share/fish/vendor_completions.d/milog.fish (system) or
# ~/.config/fish/completions/milog.fish (user).

function __milog_seen_cmd
    set -l cmd $argv[1]
    set -l tokens (commandline -opc)
    test (count $tokens) -ge 2; and test $tokens[2] = $cmd
end

# Top-level commands
set -l cmds \
    "monitor:bash dashboard" \
    "tui:bubbletea TUI (Go binary)" \
    "daemon:headless alerter" \
    "rate:nginx req/min dashboard" \
    "health:2xx/3xx/4xx/5xx per app" \
    "top:top N source IPs" \
    "top-ip-by-app:top N source IPs per app" \
    "top-paths:top N URLs by req/4xx/5xx/p95" \
    "attacker:forensic view of one IP" \
    "slow:top N slow endpoints" \
    "ws:WebSocket session metrics" \
    "stats:hourly request histogram" \
    "trend:sparkline from history" \
    "replay:postmortem for one log file" \
    "search:grep across current + archived logs" \
    "diff:per-app req now vs 1d/7d ago" \
    "auto-tune:suggest thresholds" \
    "logs:tail all logs, color prefixed" \
    "grep:filter-tail one app" \
    "errors:live 4xx/5xx tail" \
    "exploits:LFI/RCE/SQLi/XSS/infra probe tail" \
    "probes:scanner/bot traffic tail" \
    "patterns:app-error signatures" \
    "suspects:heuristic bot ranking" \
    "config:show/edit/set/init/validate" \
    "alert:toggle alerting + systemd" \
    "alerts:local fire history" \
    "silence:mute a rule while on-call fixes it" \
    "digest:exec-summary view last day / week" \
    "report:static markdown / HTML report" \
    "doctor:diagnostic checklist" \
    "web:start/stop/status web UI" \
    "install:add optional features" \
    "update-rules:fetch newer detection rules" \
    "audit:host integrity scans" \
    "probe:eBPF probe sidecar service" \
    "bench:benchmark harness" \
    "completions:install / print shell completions" \
    "help:show help"

for entry in $cmds
    set -l parts (string split ":" "$entry")
    complete -c milog -n "__fish_is_first_token" -a "$parts[1]" -d "$parts[2]"
end

# Subcommands
set -l config_subs show path init edit add rm dir set validate
for s in $config_subs
    complete -c milog -n "__milog_seen_cmd config" -a "$s"
end

set -l alert_subs on off status test stats
for s in $alert_subs
    complete -c milog -n "__milog_seen_cmd alert" -a "$s"
end

set -l silence_subs list clear
for s in $silence_subs
    complete -c milog -n "__milog_seen_cmd silence" -a "$s"
end

set -l web_subs start stop status install-service uninstall-service rotate-token
for s in $web_subs
    complete -c milog -n "__milog_seen_cmd web" -a "$s"
end

set -l window_vals today yesterday 1h 6h 12h 24h 7d 30d all
for v in $window_vals
    complete -c milog -n "__milog_seen_cmd alerts" -a "$v"
end

set -l digest_window_vals day week 1h 6h 12h 24h 7d 30d
for v in $digest_window_vals
    complete -c milog -n "__milog_seen_cmd digest; or __milog_seen_cmd report" -a "$v"
end
MILOG_COMPLETION_EOF
}
show_help() {
    echo -e "
${W}MiLog${NC} — nginx + system monitor

${W}USAGE${NC}  $0 [command] [args]

${W}DASHBOARDS${NC}
  ${C}monitor${NC}            bash dashboard: nginx + CPU/MEM/DISK + workers
                     ${D}keys: q=quit  p=pause  r=refresh  +/-=rate${NC}
  ${C}tui${NC}                rich Charm TUI ${D}(needs milog-tui Go binary; build.sh builds it)${NC}
  ${C}rate${NC}               nginx-only req/min dashboard
  ${C}daemon${NC}             headless alerter — no TUI, fires every configured destination

${W}ANALYSIS${NC}
  ${C}health${NC}             2xx/3xx/4xx/5xx per app
  ${C}top [N]${NC}            top N source IPs  ${D}(default: 10)${NC}
  ${C}top-ip-by-app [N]${NC}  top N source IPs per app  ${D}(default: 5)${NC}
  ${C}top-paths [N]${NC}      top N URLs — req/4xx/5xx/p95 per path  ${D}(default: 20)${NC}
  ${C}attacker <IP>${NC}      forensic view: one IP's activity across all apps
  ${C}slow [N]${NC}           top N slow endpoints by p95  ${D}(requires \$request_time; excludes WS)${NC}
  ${C}ws [N]${NC}             WebSocket session metrics — count, duration, top paths
  ${C}stats <app>${NC}        hourly request histogram
  ${C}suspects [N] [W]${NC}   heuristic bot ranking ${D}(top N=20, window=2000 lines/app)${NC}
  ${C}trend [app] [H]${NC}    sparkline of req/min from history ${D}(default: all apps, 24h)${NC}
  ${C}diff${NC}               per-app req: now vs 1d ago vs 7d ago
  ${C}auto-tune [D]${NC}      suggest thresholds from history + alert noise  ${D}(default: 7 days)${NC}
  ${C}replay <file>${NC}      postmortem summary for one archived log file
  ${C}search <pat> ...${NC}   grep across all apps (flags: --since/--app/--path/--regex/--archives)

${W}ALERTING${NC}
  ${C}alert on [URL]${NC}     enable alerts + install systemd service
  ${C}alert off${NC}          disable alerts + stop service
  ${C}alert status${NC}       webhook / service / recent-fire state
  ${C}alert test${NC}         send a test alert to every destination
  ${C}alert stats [W]${NC}    fires per rule ${D}(default 7d)${NC}
  ${C}alerts [window]${NC}    local fire history ${D}(today / Nh / Nd / Nw / all)${NC}
  ${C}silence ...${NC}        mute a rule while on-call works the fix ${D}(milog silence --help)${NC}
  ${C}digest [window]${NC}     exec-summary (day / week / Nh / Nd)
  ${C}report [window]${NC}     static markdown / HTML report ${D}(default 7d; --html, -o FILE)${NC}

${W}DIAGNOSTICS${NC}
  ${C}doctor${NC}             checklist: tools, logs, log format, webhook, history, geoip, systemd

${W}WEB UI${NC} ${D}(read-only, token-gated, loopback-only by default)${NC}
  ${C}web${NC}                start the local HTTP dashboard (foreground)
  ${C}web stop${NC}           kill the running dashboard (systemd or foreground)
  ${C}web status${NC}         is it running? on what port?
  ${C}web install-service${NC}   install + start systemd user unit (always-on)
  ${C}web uninstall-service${NC} remove the systemd user unit
  ${C}web rotate-token${NC}   regenerate the web token in place

${W}CONFIG${NC}
  ${C}config${NC}             show resolved config + path
  ${C}config validate${NC}    check for typos, bad ranges, unreachable paths
  ${C}config init${NC}        create template config file
  ${C}config add <app>${NC}   append app to LOGS
  ${C}config rm  <app>${NC}   remove app from LOGS
  ${C}config dir <path>${NC}  set LOG_DIR
  ${C}config set <K> <V>${NC} set any variable (REFRESH, THRESH_*, …)
  ${C}config edit${NC}        open in \$EDITOR

${W}TAILING${NC}
  ${C}(none) / logs${NC}      tail all logs, color prefixed  ${D}<- default${NC}
  ${C}errors${NC}             4xx/5xx + app-pattern live tail (or --since for summary)
  ${C}exploits${NC}           LFI / RCE / SQLi / XSS / infra-probe payloads
  ${C}probes${NC}             scanner/bot traffic
  ${C}patterns${NC}           app-error signatures (panics, OOM, stacktraces…)
  ${C}grep <app> <pat>${NC}   filter-tail one app
  ${C}<app>${NC}              raw tail for one app

${W}OPS${NC}
  ${C}install <feature>${NC}  add optional features: geoip / web / history
  ${C}update-rules${NC}       fetch newer exploit/probe rules from the latest release
  ${C}audit fim${NC}           file integrity monitor (baseline + drift)
  ${C}audit persistence${NC}   re-entry surface diff (new cron / systemd / rc.local)
  ${C}audit ports${NC}         listening-port baseline (new TCP/UDP listeners)
  ${C}audit yara${NC}          YARA scan over webroot (webshell + obfuscation rules)
  ${C}audit accounts${NC}      passwd / sudoers / SSH-key line-level diff
  ${C}audit rootkit${NC}       hidden-process / ld.so.preload / tmp-exec heuristics
  ${C}audit history${NC}       drift the daemon recorded over the last 7 days

${W}KERNEL OBSERVABILITY${NC} (Linux only — needs ${C}milog-probe${NC} sidecar)
  ${C}probe status${NC}              is the eBPF probe sidecar running?
  ${C}probe install-service${NC}     install + start systemd unit (needs sudo)
  ${C}probe uninstall-service${NC}   remove the systemd unit (needs sudo)
  ${C}bench [--full]${NC}     benchmark harness against synthetic fixtures
  ${C}completions <shell>${NC}  install / print bash|zsh|fish completions

${W}MORE HELP${NC}
  ${C}milog <cmd> --help${NC}    detailed help for any command
  ${C}milog config${NC}          current resolved config + destinations + apps
  ${C}milog doctor${NC}          diagnostic checklist

${D}docs → docs/   ·   source → src/   ·   plan → plan.md (gitignored)${NC}
"
}

# `milog <cmd> --help` details; show_help only lists commands.
_cmd_help() {
    local cmd="$1"
    case "$cmd" in
        monitor)
            echo -e "${W}milog monitor${NC} — bash dashboard (refresh-and-redraw)"
            echo -e "  ${D}Keys:${NC} q quit  p pause  r refresh  +/- change rate"
            echo -e "  ${D}Tunes:${NC} REFRESH, THRESH_* (see \`milog config\`)"
            echo -e "  ${D}Richer view:${NC} \`milog tui\` (Go Charm TUI, same data)"
            ;;
        tui)
            echo -e "${W}milog tui${NC} — Charm Bubble Tea TUI (Go binary)"
            echo -e "  ${D}Keys:${NC} q quit  p pause  r refresh  +/- rate  ? help"
            echo -e "        overview: ↑/k ↓/j select  enter/l drill  a alerts  P paths  e errors  t trend"
            echo -e "        focused:  ↑/k ↓/j scroll  f/pgdn page down  b/pgup page up  esc/h back"
            echo -e "  ${D}Tunes:${NC} MILOG_REFRESH env / REFRESH config key"
            echo -e "  ${D}Install:${NC} \`bash build.sh\` in a clone; distro packages land later."
            ;;
        rate)     echo -e "${W}milog rate${NC} — nginx-only req/min dashboard" ;;
        daemon)
            echo -e "${W}milog daemon${NC} — headless alerter; no TUI"
            echo -e "  Runs the rule evaluator on a loop, fires alerts via configured destinations."
            echo -e "  ${D}Refuses to start on config-validate errors; warnings allowed.${NC}"
            ;;
        health)   echo -e "${W}milog health${NC} — 2xx/3xx/4xx/5xx totals per app" ;;
        top)
            echo -e "${W}milog top [N]${NC} — top N source IPs across all apps (default 10)"
            echo -e "  ${D}+country column when GEOIP_ENABLED=1${NC}"
            ;;
        top-ip-by-app|top-by-app)
            echo -e "${W}milog top-ip-by-app [N]${NC} — top N source IPs per app (default 5)"
            echo -e "  ${D}Use when 'milog top' hides per-app scraper patterns${NC}"
            echo -e "  ${D}+country column when GEOIP_ENABLED=1${NC}"
            ;;
        top-paths)
            echo -e "${W}milog top-paths [N]${NC} — top N URLs by req / 4xx / 5xx / p95"
            echo -e "  ${D}Excludes SLOW_EXCLUDE_PATHS (WebSocket paths by default)${NC}"
            ;;
        attacker)
            echo -e "${W}milog attacker <IP>${NC} — forensic view of one IP across apps"
            echo -e "  Per-app requests, top paths, top UAs, classification, sample lines."
            ;;
        slow)
            echo -e "${W}milog slow [N]${NC} — top N slow endpoints by p95"
            echo -e "  ${D}Requires \$request_time in log_format; excludes WebSocket paths.${NC}"
            ;;
        ws)
            echo -e "${W}milog ws [N]${NC} — WebSocket session metrics"
            echo -e "  Duration distribution, longest, long-session flag, top paths per app."
            ;;
        stats)    echo -e "${W}milog stats <app>${NC} — hourly request histogram" ;;
        trend)    echo -e "${W}milog trend [app] [HOURS]${NC} — sparkline from history (HISTORY_ENABLED=1)" ;;
        diff)     echo -e "${W}milog diff${NC} — per-app: now vs 1d ago vs 7d ago" ;;
        auto-tune)echo -e "${W}milog auto-tune [DAYS]${NC} — suggest thresholds from history" ;;
        replay)   echo -e "${W}milog replay <file>${NC} — postmortem for one archived log" ;;
        search)
            echo -e "${W}milog search <pattern> [flags]${NC} — grep across current + archived"
            echo -e "  Flags: --since --app --path --regex --archives --limit"
            ;;
        errors)
            echo -e "${W}milog errors${NC} — live tail or summary report"
            echo -e "  Live:    nginx sources show 4xx/5xx, others show app-pattern matches"
            echo -e "  Summary: ${C}--since 1d${NC} ${C}--source <name>${NC} ${C}--pattern <name>${NC}"
            ;;
        exploits) echo -e "${W}milog exploits${NC} — LFI/RCE/SQLi/XSS/infra-probe live tail" ;;
        probes)   echo -e "${W}milog probes${NC} — scanner/bot traffic live tail" ;;
        patterns)
            echo -e "${W}milog patterns [list]${NC} — app-error pattern detector across all sources"
            echo -e "  Built-ins: Go panic, Python traceback, Java stacktrace, Node UPR, OOM, segfault, ERROR/FATAL/CRITICAL"
            echo -e "  Custom:    APP_PATTERN_<name>='regex' (empty value disables a built-in of the same name)"
            echo -e "  ${C}milog patterns list${NC}  show merged catalog (built-ins + overrides + custom)"
            ;;
        grep)     echo -e "${W}milog grep <app> <pattern>${NC} — filter-tail one app" ;;
        suspects) echo -e "${W}milog suspects [N] [WINDOW]${NC} — heuristic bot ranking" ;;
        config)
            echo -e "${W}milog config [sub]${NC} — show / edit / set / validate"
            echo -e "  Subs: show path init edit add rm dir set validate"
            echo -e "  ${C}milog config validate${NC}   check for typos, invalid ranges, unreachable paths"
            ;;
        alert)
            echo -e "${W}milog alert <sub>${NC} — toggle alerting + systemd service"
            echo -e "  Subs: on off status test stats"
            ;;
        alerts)   echo -e "${W}milog alerts [window]${NC} — fire history (today / Nh / Nd / Nw / all)" ;;
        silence)  echo -e "${W}milog silence <rule> <duration> [message]${NC} — mute a rule"; echo -e "  Also: ${C}milog silence list${NC} · ${C}milog silence clear <rule>${NC}" ;;
        digest)
            echo -e "${W}milog digest [window]${NC} — exec-summary for the period"
            echo -e "  Windows: day (default) / week / 12h / 7d / …"
            ;;
        report)
            echo -e "${W}milog report [window] [--html] [-o FILE]${NC} — static report for sharing"
            echo -e "  Traffic per app, top IPs by 4xx, alert fires per rule, anomalies, audit drift."
            echo -e "  Markdown by default; ${C}--html${NC} writes one self-contained page. Windows as digest (default 7d)."
            ;;
        doctor)   echo -e "${W}milog doctor${NC} — diagnostic checklist" ;;
        web)
            echo -e "${W}milog web${NC} — read-only local HTTP dashboard"
            echo -e "  Subs: start stop status install-service uninstall-service rotate-token"
            ;;
        probe)
            echo -e "${W}milog probe${NC} — eBPF probe sidecar (Linux only)"
            echo -e "  Subs: status install-service uninstall-service"
            echo -e "  Covers: exec / tcp / file / ptrace / kmod / retrans / syscall-rate / bpf-load"
            ;;
        bench)    echo -e "${W}milog bench [--full] [--baseline FILE]${NC} — timing harness" ;;
        completions) echo -e "${W}milog completions <install|bash|zsh|fish>${NC} — install shell completion" ;;
        install)
            echo -e "${W}milog install <feature>${NC} — on-demand feature installer"
            echo -e "  Subs: list, <feature>, remove <feature>"
            echo -e "  Features: geoip / web / history"
            ;;
        update-rules)
            echo -e "${W}milog update-rules${NC}: fetch exploit/probe detection rules from the latest release"
            echo -e "  Checks the SHA-256 against the release's checksums.txt, then that every regex compiles."
            echo -e "  Refuses an older version than the active one; writes ${C}RULES_FILE${NC} atomically."
            echo -e "  ${D}checksums.txt is not a signature: it comes from the same release as the rules.${NC}"
            ;;
        audit)
            echo -e "${W}milog audit <sub>${NC} — point-in-time host integrity scans"
            echo -e "  ${C}fim baseline | check | status${NC}          SHA256 drift on watched files"
            echo -e "  ${C}persistence baseline | check | status${NC}  new files in re-entry surface"
            echo -e "  ${C}ports baseline | check | status${NC}        new TCP/UDP listeners"
            echo -e "  ${C}yara init | scan | status${NC}              YARA scan over webroot"
            echo -e "  ${C}accounts baseline | check | status${NC}     line-level diff over passwd / sudoers / authorized_keys"
            echo -e "  ${C}rootkit check | status${NC}                 hidden-process / ld.so.preload / tmp-exec"
            echo -e "  ${C}history [days]${NC}                         drift the daemon recorded (default 7 days)"
            echo -e "  Watcher runs inside ${C}milog daemon${NC} when ${C}AUDIT_ENABLED=1${NC}"
            echo -e "  YARA additionally needs the system ${C}yara${NC} binary + ${C}AUDIT_YARA_PATHS${NC}"
            echo -e "  Rootkit scan is Linux-only (relies on /proc); silent no-op on macOS / BSD"
            ;;
        *)
            echo -e "${Y}No detailed help for '$cmd'.${NC} Try ${C}milog help${NC}."
            return 1
            ;;
    esac
}

# Dispatch.
if [[ "${2:-}" == "--help" || "${2:-}" == "-h" ]]; then
    _cmd_help "${1:-}"
    exit $?
fi

# Setup and host-level commands must work before any app is configured.
if [[ ${#LOGS[@]} -eq 0 ]]; then
    case "${1:-}" in
        -h|--help|help|config|doctor|completions|install|update-rules|audit|probe|alert|alerts|silence|bench|_internal_alert) ;;
        *)
            echo "MiLog: no apps configured and none found in $LOG_DIR" >&2
            echo "  Run 'milog config init', set MILOG_APPS=\"a b c\", edit $MILOG_CONFIG, or drop *.access.log into $LOG_DIR" >&2
            exit 1 ;;
    esac
fi

case "${1:-}" in
    monitor)  mode_monitor ;;
    tui)      shift; mode_tui "$@" ;;
    daemon)   mode_daemon ;;
    rate)     mode_rate ;;
    health)   mode_health ;;
    top)      mode_top "${2:-10}" ;;
    top-ip-by-app|top-by-app) mode_top_ip_by_app "${2:-5}" ;;
    top-paths|toppaths) mode_top_paths "${2:-20}" "${3:-}" ;;
    attacker) mode_attacker "${2:-}" ;;
    slow)     mode_slow "${2:-10}" ;;
    ws)       mode_ws "${2:-10}" ;;
    stats)    mode_stats "${2:-}" ;;
    trend)    mode_trend "${2:-}" "${3:-24}" ;;
    replay)   mode_replay "${2:-}" ;;
    search)   shift; mode_search "$@" ;;
    diff)     mode_diff ;;
    auto-tune|autotune|tune) mode_auto_tune "${2:-7}" ;;
    grep)     mode_grep "${2:-}" "${3:-.}" ;;
    errors)   shift; mode_errors "$@" ;;
    exploits) mode_exploits ;;
    probes)   mode_probes ;;
    patterns)
        case "${2:-}" in
            list) mode_patterns_list ;;
            *)    mode_patterns ;;
        esac ;;
    suspects) mode_suspects "${2:-20}" "${3:-2000}" ;;
    config)   shift; mode_config "$@" ;;
    alert)    shift; mode_alert  "$@" ;;
    alerts)   mode_alerts "${2:-today}" ;;
    silence)  shift; mode_silence "$@" ;;
    digest)   mode_digest "${2:-day}" ;;
    report)   shift; mode_report "$@" ;;
    completions) shift; mode_completions "$@" ;;
    bench)    shift; mode_bench "$@" ;;
    install)  shift; mode_install "$@" ;;
    update-rules) mode_update_rules ;;
    audit)    shift; mode_audit   "$@" ;;
    doctor)   mode_doctor ;;
    web)      shift; mode_web "$@" ;;
    probe)    shift; mode_probe "$@" ;;
    # Hidden: milog-probe calls this per rule hit with <rule_key> <title> <body> [color] so the full alert path applies.
    _internal_alert)
        shift
        if (( $# < 3 )); then
            echo -e "${R}_internal_alert: needs <rule_key> <title> <body> [color]${NC}" >&2
            exit 1
        fi
        # milog-probe doesn't filter bursts, so the cooldown gate stops exec floods from spamming.
        if alert_should_fire "$1"; then
            alert_fire "$2" "$3" "${4:-15158332}" "$1"
            # Wait for the backgrounded sends, or systemd cgroup teardown can kill them.
            wait
        fi
        ;;
    -h|--help|help) show_help ;;
    ""|logs)  color_prefix ;;
    *)
        _matching_entry=$(_log_entry_by_name "$1" 2>/dev/null) || _matching_entry=""
        if [[ -n "$_matching_entry" ]]; then
            _reader_cmd=$(_log_reader_cmd "$_matching_entry") || _reader_cmd=""
            if [[ -n "$_reader_cmd" ]]; then
                bash -c "$_reader_cmd"
            else
                echo -e "${R}cannot stream $_matching_entry${NC}"; exit 1
            fi
        else
            echo -e "${R}Unknown command: '$1'${NC}"; show_help; exit 1
        fi ;;
esac
