#!/usr/bin/env bash
# MILOG_VERSION=e5538fd-dirty
# MILOG_BUILT=2026-05-03T07:57:44Z
# ==============================================================================
# MiLog — Nginx + System Monitor (V5.0)
# ==============================================================================
set -euo pipefail

# --- Configuration (defaults; overridable via config file or env) ---
LOG_DIR="/var/log/nginx"
LOGS=("dolanan" "ethok" "finance" "ldr" "profile" "sinepil")
REFRESH=5

# Alerts — configure ONE or MORE destinations; alert_fire() fans out to
# everything that's set. ALERTS_ENABLED=1 is the master switch. Each
# destination silently no-ops when its config is missing, so adding a
# second one doesn't require touching anything else.
#
#   Discord:  DISCORD_WEBHOOK
#   Slack:    SLACK_WEBHOOK
#   Telegram: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
#   Matrix:   MATRIX_HOMESERVER + MATRIX_TOKEN + MATRIX_ROOM
#   Webhook:  WEBHOOK_URL (+ optional WEBHOOK_TEMPLATE / WEBHOOK_CONTENT_TYPE)
DISCORD_WEBHOOK=""
SLACK_WEBHOOK=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
MATRIX_HOMESERVER=""
MATRIX_TOKEN=""
MATRIX_ROOM=""

# Generic webhook destination — any POST-accepting endpoint (ntfy.sh,
# Mattermost, Rocket.Chat, custom ingest). Distinct from the discord/slack
# adapters which know each API's specific payload shape; this is free-form.
#
# Template placeholders (all json_escape'd → quoted JSON string literals,
# so the default template below is valid JSON after substitution):
#   %TITLE%  alert title      %SEV%   severity word (crit / warn / info)
#   %BODY%   alert body       %RULE%  rule key     (e.g. `5xx:api`)
#
# For `text/plain` ingest, override the template to a bare string and set
# WEBHOOK_CONTENT_TYPE accordingly — the placeholder values will still be
# quoted, but that's acceptable for most plain-text receivers.
WEBHOOK_URL=""
WEBHOOK_TEMPLATE='{"title":%TITLE%,"body":%BODY%,"severity":%SEV%,"rule":%RULE%}'
WEBHOOK_CONTENT_TYPE="application/json"
ALERTS_ENABLED=0
PATTERNS_ENABLED=1
# File integrity monitor (audit). Off by default — opting in means
# `milog daemon` rehashes the watchlist every AUDIT_FIM_INTERVAL seconds
# and fires `audit:fim:<path>` on drift. Read perms on /etc/shadow etc.
# are the user's deployment problem; we never `sudo` ourselves.
AUDIT_ENABLED=0
AUDIT_FIM_INTERVAL=3600
# Default watchlist — the classic post-compromise re-entry surface.
# Glob patterns expanded with `nullglob`; missing files / dirs are
# tolerated silently (auto-baseline records "absent" and alerts on
# next-time-it-appears, which IS the signal we want).
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
# Persistence diff — track file-existence drift across the classic
# attacker re-entry directories. NEW files in any of these → alert;
# removed files are logged but don't page (a sysadmin pruning unused
# units is normal noise).
#
# Glob patterns are *quoted* so the array stores the patterns themselves,
# not their expansion at config-source time. The expander re-globs every
# tick so a `cron.d/sneaky.cron` dropped after daemon start is detected.
# (Unquoted globs would expand once at startup and miss new files
# entirely — exactly what the watcher exists to catch.)
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
# Listening-port baseline — snapshot of every TCP/UDP listener at first
# daemon tick, then diff each subsequent tick. NEW listeners alert; gone
# listeners are silent (services restart routinely and the brief gap
# shouldn't page anyone). Tracks `<proto>\t<bind>\t<port>` as the key so
# a service moving from 127.0.0.1 to 0.0.0.0 also fires — bind-address
# expansion onto a new interface is itself the signal.
AUDIT_PORTS_INTERVAL=3600
ALERT_COOLDOWN=300
# Cross-rule dedup window: when multiple rules (e.g. exploits + probes) match
# the same logline, only the first to fire records the (ip, path) fingerprint;
# the second sees it fresh and suppresses. Tunes how long one event remains
# "already reported" across distinct rules. Kept separate from ALERT_COOLDOWN
# so rule-level and event-level suppression can evolve independently.
ALERT_DEDUP_WINDOW=300
ALERT_STATE_DIR="$HOME/.cache/milog"
# alerts.log rotation — when the file exceeds this many bytes, truncate it
# in place to roughly the most recent 50%. No `.1` backup is kept: alerts
# beyond the window are forensic noise (the state file + fingerprints already
# carry the recent-fire state the rest of MiLog cares about). Set to 0 to
# disable rotation entirely.
ALERT_LOG_MAX_BYTES=10485760  # 10 MB

# Hook scripts — user escape hatch. Every executable under HOOKS_DIR/on_alert.d/
# runs once per fire, with MILOG_RULE_KEY / MILOG_TITLE / MILOG_BODY /
# MILOG_SEV / MILOG_COLOR / MILOG_TS in its env. Runs AFTER the silence
# gate (so silenced fires skip hooks too) and in parallel with delivery.
# Errors are logged to $ALERT_STATE_DIR/hooks.log and NEVER propagate —
# a broken hook can't wedge the daemon. Individual hook run time is
# capped by ALERT_HOOK_TIMEOUT so a hanging script doesn't leak forever.
HOOKS_DIR="$HOME/.config/milog/hooks"
ALERT_HOOK_TIMEOUT=10

# --- Alert routing ------------------------------------------------------------
# Per-rule destination mapping. Default (empty) = fan out to every configured
# destination — exactly today's behavior, so existing users see no change.
#
# Format: one `key: destinations` pair per line. Whitespace-tolerant, `#`
# begins a comment. Keys:
#   - exact rule (`cpu`, `mem`, `workers`, `5xx:api`, `exploits:log4shell`)
#   - prefix before the first `:` (`5xx`, `exploits`, `probes`)
#   - `default`     — fallback when no other key matches
# Resolution order: exact → prefix → default → empty. Leftmost wins.
#
# Destinations are space-separated types from: discord slack telegram matrix
# (plus `skip` meaning "silently drop — no fire at all" for noise classes).
# Unknown destinations are silently ignored for forward-compatibility.
#
# Example — route exploits to security, system alerts to ops, rest to discord:
#   ALERT_ROUTES="
#     exploits: slack telegram
#     audit:    slack
#     cpu:      discord
#     mem:      discord
#     disk:/:   discord
#     5xx:      slack discord
#     probes:   skip
#     default:  discord
#   "
ALERT_ROUTES=""

# Response-time percentile thresholds (milliseconds) — used to colour the p95
# tag in the monitor dashboard. Requires nginx to log $request_time; see
# README → "Response-time percentiles".
P95_WARN_MS=500
P95_CRIT_MS=1500

# `milog slow` window (lines/app scanned from tail). Larger = wider history
# but slower reads. Hour-of-traffic is a reasonable default on most sites.
SLOW_WINDOW=1000

# Path globs to EXCLUDE from `slow` + `top-paths`. Nginx's `$request_time`
# for a WebSocket-upgraded connection is the full session lifetime, not
# request latency — a healthy 22-minute chat session otherwise tops the
# "slowest endpoints" list. Space-separated glob list; matched against the
# leading path segment. `milog ws` presents WS session metrics separately.
# Set to empty string ("") to include WS paths again.
SLOW_EXCLUDE_PATHS="/ws/* /socket.io/*"

# GeoIP enrichment (off by default). Requires `mmdblookup` and a MaxMind
# GeoLite2-Country MMDB file. Enable both flags only after the MMDB is in
# place — `milog top` and `milog suspects` add a COUNTRY column when on.
# See README → "GeoIP enrichment".
GEOIP_ENABLED=0
MMDB_PATH="/var/lib/GeoIP/GeoLite2-Country.mmdb"

# Historical metrics (off by default; requires sqlite3). When enabled in a
# `milog daemon` context, one minute-aligned row per app lands in a local
# SQLite database. Enables `milog trend` / `milog diff` read modes and
# hour-bucket top-IP rollups. See README → "Historical metrics".
HISTORY_ENABLED=0
HISTORY_DB="$HOME/.local/share/milog/metrics.db"
HISTORY_RETAIN_DAYS=30
HISTORY_TOP_IP_N=50

# Web dashboard. Off by default; `milog web` starts a tiny local HTTP
# listener (socat or ncat) that serves a read-only JSON + HTML view.
# Binds to loopback; expose via SSH tunnel, Tailscale, or Cloudflare
# Tunnel (see README → "milog web"). Non-loopback bind requires --trust.
# 8765 is unassigned by IANA and rarely used (unlike 8080, which collides
# with Jenkins / Tomcat / "my random dev server"). Override via --port.
WEB_PORT=8765
WEB_BIND="127.0.0.1"
WEB_STATE_DIR="$HOME/.cache/milog"
WEB_TOKEN_FILE="$HOME/.config/milog/web.token"
WEB_ACCESS_LOG="$HOME/.cache/milog/web.access.log"

# Optional user config — sourced if present. Can override any variable above.
# Example:
#     LOG_DIR="/var/log/nginx"
#     LOGS=(myapp api web)          # or leave unset to auto-discover
#     REFRESH=3
MILOG_CONFIG="${MILOG_CONFIG:-$HOME/.config/milog/config.sh}"
# shellcheck disable=SC1090
[[ -f "$MILOG_CONFIG" ]] && . "$MILOG_CONFIG"

# Env var overrides win over the config file. MILOG_* prefix keeps them
# from colliding with generic shell env. Add new knobs here when you want
# one-shot / systemd-unit overrides; full tuning still goes through the
# config file.
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
[[ -n "${MILOG_HISTORY_ENABLED:-}" ]] && HISTORY_ENABLED="$MILOG_HISTORY_ENABLED"
[[ -n "${MILOG_HISTORY_DB:-}"      ]] && HISTORY_DB="$MILOG_HISTORY_DB"
[[ -n "${MILOG_WEB_PORT:-}"        ]] && WEB_PORT="$MILOG_WEB_PORT"
[[ -n "${MILOG_WEB_BIND:-}"        ]] && WEB_BIND="$MILOG_WEB_BIND"
[[ -n "${MILOG_SLOW_EXCLUDE_PATHS+x}" ]] && SLOW_EXCLUDE_PATHS="$MILOG_SLOW_EXCLUDE_PATHS"

# Auto-discover: if no apps ended up configured, glob *.access.log in LOG_DIR
if [[ ${#LOGS[@]} -eq 0 ]]; then
    shopt -s nullglob
    for f in "$LOG_DIR"/*.access.log; do
        name="${f##*/}"; name="${name%.access.log}"
        LOGS+=("$name")
    done
    shopt -u nullglob
fi

if [[ ${#LOGS[@]} -eq 0 ]]; then
    echo "MiLog: no apps configured and none found in $LOG_DIR" >&2
    echo "  Set MILOG_APPS=\"a b c\", edit $MILOG_CONFIG, or drop *.access.log into $LOG_DIR" >&2
    exit 1
fi

# --- Typed log sources -------------------------------------------------------
# LOGS entries are bare names by default (`LOGS=(api web)`) and resolve to
# nginx-format files at `$LOG_DIR/<name>.access.log`. A typed prefix makes
# MiLog usable on non-nginx logs too:
#
#   LOGS=(api web text:myapp:/var/log/myapp/error.log)
#   LOGS=(api journal:mybot.service docker:postgres-prod)
#   LOGS=(api text:rails:/var/log/rails/production.log nginx:gateway)
#
# Resolution:
#   bare `api`                          → nginx type, $LOG_DIR/api.access.log
#   `nginx:api`                         → same (explicit)
#   `text:<name>:<absolute path>`       → any text file
#   `journal:<unit>`                    → systemd journal for <unit>
#   `docker:<container>`                → docker JSON-log for <container>
#
# Parser-free modes (logs, grep, search, <name> tail) work for every source
# type via `_log_reader_cmd` below. Parsing modes (monitor, top, slow,
# top-paths, etc.) skip non-nginx sources gracefully — they need the
# combined log format to work.

# Return the file path for a LOGS entry — bare name or typed prefix.
# `journal:` and `docker:` entries have no stable path (journal is a
# streaming command, docker's path is looked up dynamically); prefer
# `_log_reader_cmd` for anything that reads lines.
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

# Return the type for a LOGS entry.
_log_type_for() {
    case "${1-}" in
        text:*)     printf 'text' ;;
        nginx:*)    printf 'nginx' ;;
        journal:*)  printf 'journal' ;;
        docker:*)   printf 'docker' ;;
        *)          printf 'nginx' ;;
    esac
}

# Return the display name (strip type prefix and path).
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

# Find the LOGS entry that matches a display name, or empty if no match.
# Callers use this to map `milog <app>` / `milog grep <app> <pat>` / etc.
# back to the typed source entry they came from.
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

# Resolve a docker container name to the local path of its JSON log.
# Fast path: `docker inspect` if the CLI is available. Fallback: glob
# /var/lib/docker/containers/*/config.v2.json and grep for the name —
# works even when the docker socket isn't accessible to this user.
#
# Returns empty on no-match; callers treat that as "container not
# running right now" and skip.
_log_docker_path() {
    local name="${1:-}"
    [[ -z "$name" ]] && return 0
    # Preferred: `docker inspect` gives us the exact LogPath.
    if command -v docker >/dev/null 2>&1; then
        local path
        path=$(docker inspect --format '{{.LogPath}}' "$name" 2>/dev/null)
        [[ -n "$path" && -r "$path" ]] && { printf '%s' "$path"; return 0; }
    fi
    # Fallback: scan container config files for the matching Name. Needs
    # read perm on /var/lib/docker; silently no-ops if we can't see it.
    local default_root="${MILOG_DOCKER_ROOT:-/var/lib/docker}"
    [[ -d "$default_root/containers" ]] || return 0
    local cfg cid
    # shellcheck disable=SC2044
    for cfg in "$default_root"/containers/*/config.v2.json; do
        [[ -r "$cfg" ]] || continue
        # Matches both `"/name"` and `"name"`. Cheap — no JSON parser.
        if grep -q "\"Name\":\"/$name\"" "$cfg" 2>/dev/null \
           || grep -q "\"Name\":\"$name\"" "$cfg" 2>/dev/null; then
            cid=$(basename "$(dirname "$cfg")")
            local log_path="$default_root/containers/$cid/$cid-json.log"
            [[ -r "$log_path" ]] && { printf '%s' "$log_path"; return 0; }
        fi
    done
    return 0
}

# Return a shell command (suitable for `eval` / process substitution)
# that streams RAW log lines from the source entry on stdout. This is
# the abstraction that lets `color_prefix`, `mode_grep`, and `milog
# <name>` tail work uniformly across source types without each mode
# reinventing "how do I read this".
#
#   nginx:/bare   → tail -F <file>
#   text:         → tail -F <file>
#   journal:      → journalctl -u <unit> -f --no-pager --since now
#                   (on non-Linux / no journalctl: emits a `#` diag
#                   line and exits, so callers don't hang)
#   docker:       → tail -F <container-log> | python3 json-unwrap
#
# Prints the command on stdout; caller wraps in `bash -c "$cmd"` or
# equivalent. On unresolvable entries (docker name not running, etc.)
# prints empty and returns 1 so callers can skip.
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
                # Emit a diagnostic and exit so callers' stdout consumers
                # still see something (preferable to a silent hang).
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
            # Unwrap docker's JSON-per-line format. jq is the robust
            # option (proper JSON parser). Sed fallback handles typical
            # plaintext payloads; pathological lines with embedded
            # quotes/backslashes may render imperfectly.
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

# Alert thresholds
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

# Sparkline history depth (samples kept per app in monitor mode)
SPARK_LEN=30

# Per-app threshold override resolver. Looks up `<var>_<safe_app>` first,
# falls back to the global `<var>`. Bash var names only allow [A-Za-z0-9_],
# so `-` and `.` in an app name are mapped to `_` before the lookup.
#
#   _thresh THRESH_REQ_CRIT api       → $THRESH_REQ_CRIT_api  or  $THRESH_REQ_CRIT
#   _thresh P95_WARN_MS    my-app     → $P95_WARN_MS_my_app   or  $P95_WARN_MS
#
# Overrides live in the config file the same way global thresholds do:
#   THRESH_REQ_CRIT=40
#   THRESH_REQ_CRIT_finance=80    # finance is louder; use its own limit
#   P95_WARN_MS_api=200
#
# Kept in core.sh so every subsystem (nginx.sh, history.sh, daemon) reaches
# the same resolver — threshold divergence between render-path and
# alert-path has bitten us before.
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

# --- ANSI ---
R="\033[0;31m"  G="\033[0;32m"  Y="\033[0;33m"  B="\033[0;34m"
M="\033[0;35m"  C="\033[0;36m"  W="\033[1;37m"  D="\033[0;90m"
RBLINK="\033[0;31;5m"
NC="\033[0m"

# ==============================================================================
# DISCORD ALERTS — helpers (no call sites yet; wired in later)
# ==============================================================================

# Escape a string for safe embedding inside a JSON string literal. Wraps the
# result in surrounding double quotes so callers can interpolate directly.
json_escape() {
    local s="${1-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '"%s"' "$s"
}

# Escape a string for safe embedding inside HTML text content. Emits the
# escaped bytes WITHOUT surrounding quotes — caller assembles the tags.
# Used by Telegram (parse_mode=HTML) and Matrix (formatted_body) so an
# attacker-controlled log line can't inject <b>, <a>, or other tags into
# the rendered alert card.
html_escape() {
    local s="${1-}"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    printf '%s' "$s"
}

# Percent-encode a string for safe use in a URL path or query. ASCII
# alphanumerics and the unreserved set (-._~) pass through; everything
# else becomes %HH. Used for the Matrix room ID (contains `!` and `:`)
# and the transaction token that goes into the PUT path.
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

# In-place rotation for alerts.log. When the file grows past
# ALERT_LOG_MAX_BYTES, keep roughly the most recent half (byte-aligned;
# drops the first partial line to resync on a record boundary). Silent
# on any error — a rotation blip must never block the alert path.
#
# Called from _alert_record AFTER the append, so the current record is
# always in whichever half survives.
_alert_rotate_if_big() {
    local f="$1"
    local max="${ALERT_LOG_MAX_BYTES:-10485760}"
    # 0 (or non-numeric) disables rotation entirely.
    [[ "$max" =~ ^[0-9]+$ ]] && (( max > 0 )) || return 0
    [[ -f "$f" ]] || return 0
    local sz
    # GNU stat (-c) vs BSD stat (-f). Both harmless-fail on missing file.
    sz=$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f" 2>/dev/null) || return 0
    [[ "$sz" =~ ^[0-9]+$ ]] || return 0
    (( sz > max )) || return 0
    local half=$(( max / 2 )) tmp
    tmp=$(mktemp "${f}.rot.XXXXXX" 2>/dev/null) || return 0
    # tail -c lands mid-line; `tail -n +2` drops the first (likely partial)
    # record so every surviving line is a complete TSV row.
    tail -c "$half" "$f" 2>/dev/null | tail -n +2 > "$tmp" 2>/dev/null
    mv "$tmp" "$f" 2>/dev/null || rm -f "$tmp"
}

# Append one alert record to ALERT_STATE_DIR/alerts.log for later inspection
# via `milog alerts`. Silent on error — we never want a disk-full or
# permission blip to crash the caller.
#
# Format: TSV, one line per alert. Fields:
#   <epoch>  <rule_key>  <color_int>  <title>  <body_truncated>
# Body is tab/newline-stripped and capped at 300 chars so each record stays
# on a single line. Reader parses by \t — chosen over CSV to dodge quote
# escaping entirely (log lines often contain quotes, rarely tabs).
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

# --- Per-destination senders --------------------------------------------------
#
# Each `_alert_send_*` is a private sender for one destination. Contract:
#   - silently return 0 when its config is absent (opt-in)
#   - never propagate errors back to the caller (always `|| true` the curl)
#   - apply the right encoding for its wire format (JSON / HTML / URL)
#
# Attacker-controlled inputs to watch for:
#   - User-Agent, URL path, request headers appear in `body` — any
#     mrkdwn/HTML active in the destination needs escaping.
#   - Mentions (@channel, @everyone, <@role>) must not render: each sender
#     explicitly disables them at the API level where possible.

# Discord incoming-webhook embed. `allowed_mentions.parse=[]` blocks any
# @everyone / <@role> etc. from producing pings. Triple-backtick wraps the
# body so markdown (bold, links) renders as literal text.
_alert_send_discord() {
    [[ -z "${DISCORD_WEBHOOK:-}" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}"
    local payload
    payload=$(printf '{"embeds":[{"title":%s,"description":%s,"color":%d}],"allowed_mentions":{"parse":[]}}' \
        "$(json_escape "$title")" "$(json_escape "$body")" "$color")
    curl -sS -m 5 -H "Content-Type: application/json" \
         -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
}

# Slack incoming-webhook message. Uses mrkdwn with the body wrapped in a
# triple-backtick code block. link_names=0 keeps `<@channel>` literal, not
# a ping.
_alert_send_slack() {
    [[ -z "${SLACK_WEBHOOK:-}" ]] && return 0
    local title="$1" body="$2"
    # body wrapped in ```…``` as a code block — Slack renders it literal.
    local text
    text="*$(json_escape "$title" | sed 's/^"//; s/"$//')*\n\`\`\`$(printf '%s' "$body" | sed 's/`/'\''/g')\`\`\`"
    # json_escape of the whole composed text (keeps \n literal in the
    # payload, Slack interprets \n itself).
    local payload
    payload=$(printf '{"text":%s,"mrkdwn":true,"link_names":0}' \
        "$(json_escape "$text")")
    curl -sS -m 5 -H "Content-Type: application/json" \
         -d "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
}

# Telegram Bot API sendMessage. parse_mode=HTML + html_escape on every
# value blocks <b>/<a>/<script> injection via log lines. Bot tokens look
# like `123456789:ABC-DEF…`; the path is /bot<TOKEN>/sendMessage.
_alert_send_telegram() {
    [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]] && return 0
    local title="$1" body="$2"
    local safe_title safe_body
    safe_title=$(html_escape "$title")
    safe_body=$(html_escape "$body")
    # Build the HTML body inline — we control the tags, attacker controls
    # only the escaped text inside them.
    local text="<b>${safe_title}</b>
<pre>${safe_body}</pre>"
    local payload
    payload=$(printf '{"chat_id":%s,"text":%s,"parse_mode":"HTML","disable_web_page_preview":true,"disable_notification":false}' \
        "$(json_escape "$TELEGRAM_CHAT_ID")" "$(json_escape "$text")")
    curl -sS -m 5 -H "Content-Type: application/json" \
         -d "$payload" "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         >/dev/null 2>&1 || true
}

# Generic webhook — POST any JSON (or text) template to an arbitrary URL.
# Used for ntfy.sh, Mattermost, Rocket.Chat, internal triggers, or any other
# POST-accepting endpoint that doesn't have a dedicated adapter. The
# discord/slack/telegram/matrix senders know their API's specific payload
# shape; this one is free-form driven by WEBHOOK_TEMPLATE.
#
# Severity derivation mirrors the alerts.log / web panel convention so the
# same color int means the same severity word everywhere.
_alert_send_webhook() {
    [[ -z "${WEBHOOK_URL:-}" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}"
    local sev
    case "$color" in
        15158332|16711680)  sev=crit ;;
        16753920|15844367)  sev=warn ;;
        *)                  sev=info ;;
    esac
    # Template substitution. json_escape returns the value wrapped in
    # surrounding double-quotes, so the default template's `%TITLE%` etc.
    # expand to valid JSON string literals without additional quoting.
    local payload="${WEBHOOK_TEMPLATE:-\"%TITLE%\"}"
    payload="${payload//%TITLE%/$(json_escape "$title")}"
    payload="${payload//%BODY%/$(json_escape "$body")}"
    payload="${payload//%SEV%/$(json_escape "$sev")}"
    payload="${payload//%RULE%/$(json_escape "$rule_key")}"
    local ctype="${WEBHOOK_CONTENT_TYPE:-application/json}"
    curl -sS -m 5 -H "Content-Type: ${ctype}" \
         -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1 || true
}

# Matrix m.room.message (m.text + custom.html). PUT to
#   <homeserver>/_matrix/client/v3/rooms/<room>/send/m.room.message/<txn>
# Room IDs contain `!` and `:` — both must be percent-encoded. Txn is a
# unique-enough epoch+rand combo (deduped server-side for ~5 min by the
# Matrix spec). HTML body is escaped same as Telegram.
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
    # Strip a possible trailing slash from homeserver so the join is clean.
    local hs="${MATRIX_HOMESERVER%/}"
    curl -sS -m 5 -X PUT \
         -H "Authorization: Bearer ${MATRIX_TOKEN}" \
         -H "Content-Type: application/json" \
         -d "$payload" \
         "${hs}/_matrix/client/v3/rooms/${room_enc}/send/m.room.message/${txn_id}" \
         >/dev/null 2>&1 || true
}

# --- Silence / ack ------------------------------------------------------------
#
# Muting rules while an on-call operator is already working on the underlying
# cause. Separate from cooldown (rate-limits repeats of the same rule) and
# from dedup (cross-rule same-event suppression): silence is an explicit
# user action, outranks both, and carries attribution.
#
# State file: $ALERT_STATE_DIR/alerts.silences
#   Format:   <rule_key_or_glob>\t<until_epoch>\t<added_epoch>\t<added_by>\t<message>
#   Globs:    bash glob syntax — `exploits:*` silences every exploits:<cat>
#             rule. Literal matches are checked first, then globs.
#   Expiry:   passive — compared on each check; the prune path lazily removes
#             rows whose until_epoch has passed. No cron needed.

# Convert a duration like 30s / 5m / 2h / 1d to seconds. Echoes the result;
# returns 1 on unparseable input so callers can surface a clean error.
alert_silence_parse_duration() {
    local s="${1:-}"
    [[ -n "$s" ]] || return 1
    local n="${s%[smhdSMHD]}" unit="${s: -1}"
    # Bare integer → treat as seconds (no unit).
    if [[ "$s" =~ ^[0-9]+$ ]]; then
        printf '%s' "$s"
        return 0
    fi
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    # Accept upper- and lower-case unit letters. `${unit,,}` would be cleaner
    # but it's bash-4+ only — milog.sh runs on bash 3.2 macOS dev boxes too.
    case "$unit" in
        s|S) printf '%s' "$n" ;;
        m|M) printf '%s' $(( n * 60 )) ;;
        h|H) printf '%s' $(( n * 3600 )) ;;
        d|D) printf '%s' $(( n * 86400 )) ;;
        *) return 1 ;;
    esac
}

# Strip expired rows in place. Silent on missing file / read error — the
# worst case is we carry a stale row until the next write, which the
# _is_silenced path ignores anyway.
alert_silence_prune() {
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 0
    local now; now=$(date +%s)
    local tmp
    tmp=$(mktemp "$f.prune.XXXXXX" 2>/dev/null) || return 0
    awk -F'\t' -v now="$now" 'BEGIN{OFS="\t"} $2+0 > now' "$f" 2>/dev/null > "$tmp"
    mv "$tmp" "$f" 2>/dev/null || rm -f "$tmp"
}

# True (0) if rule_key matches an unexpired silence row. Checks literal
# match first, then glob patterns. Echoes the full row of the matching
# silence on stdout so callers (e.g. alert_fire) can include attribution
# in their telemetry.
#
# Bash `[[ $x == $pat ]]` does glob matching (not regex), which is exactly
# what we want: `exploits:*` matches `exploits:log4shell` / `exploits:sqli`.
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
        # Literal match OR glob match.
        # shellcheck disable=SC2053
        if [[ "$rule" == "$key" || "$rule" == $key ]]; then
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$key" "$until_epoch" "$added_epoch" "$added_by" "$message"
            return 0
        fi
    done < "$f"
    return 1
}

# Add / replace a silence row. Callers (mode_silence) pre-validate
# duration_seconds; this function just writes the file.
#
# Replace semantics: an existing row for the same key is overwritten, so
# `milog silence 5xx:api 2h` followed by `milog silence 5xx:api 4h` extends
# the mute rather than stacking two rows.
alert_silence_add() {
    local key="$1" duration_seconds="$2" message="${3:-}"
    local f="$ALERT_STATE_DIR/alerts.silences"
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 1
    local now until_epoch who
    now=$(date +%s)
    until_epoch=$(( now + duration_seconds ))
    # $USER is set by login shells; fall back to `id -un` for systemd/daemon
    # contexts. Fine to be empty if somehow both miss.
    who="${USER:-$(id -un 2>/dev/null || echo unknown)}"
    # Tab/newline strip on message — silence rows live on a single line.
    message="${message//$'\t'/ }"
    message="${message//$'\r'/ }"
    message="${message//$'\n'/ }"
    message="${message:0:200}"
    local tmp
    tmp=$(mktemp "$f.add.XXXXXX" 2>/dev/null) || return 1
    {
        # Drop any existing row with the same key, then append the fresh one.
        # Also drop any already-expired rows so the file doesn't grow.
        awk -F'\t' -v k="$key" -v now="$now" 'BEGIN{OFS="\t"} $1 != k && $2+0 > now' \
            "$f" 2>/dev/null
        printf '%s\t%s\t%s\t%s\t%s\n' "$key" "$until_epoch" "$now" "$who" "$message"
    } > "$tmp" && mv "$tmp" "$f" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    printf '%s' "$until_epoch"
}

# Remove a silence row by exact key. Returns 0 if a row was removed, 1 if
# no match (so callers can print an honest "nothing to clear" message).
alert_silence_remove() {
    local key="$1"
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 1
    # Existence check via awk — `grep -P` / `grep -E "^X\t"` is portable-
    # problematic (BSD grep, some minimal shells). awk field compare is
    # unambiguous and POSIX.
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

# Echo active silences as TSV rows, newest-first (by added_epoch).
# Callers format for display; we keep this function raw so tests can parse.
alert_silence_list_active() {
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 0
    local now; now=$(date +%s)
    # Sort by added_epoch desc so freshest silences render first.
    awk -F'\t' -v now="$now" 'BEGIN{OFS="\t"} $2+0 > now' "$f" 2>/dev/null \
        | sort -t $'\t' -k3,3 -rn
}

# --- Alert routing ------------------------------------------------------------
#
# Resolve a rule_key to its destination list by consulting ALERT_ROUTES.
# See `ALERT_ROUTES` in core.sh for the config-file format.
#
# Resolution:
#   1. Exact match on rule_key  (e.g. `5xx:api` → line `5xx:api: slack`)
#   2. Prefix match (first segment before `:`)  (e.g. `exploits:sqli` → `exploits:`)
#   3. `default:` line
#   4. No match → empty string → caller fans out to all configured dests
#      (back-compat: today's behavior when ALERT_ROUTES is unset)
#
# Echoes the resolved destination list on stdout. Empty output means "no
# routing configured for this key; fan out".
_alert_route_for() {
    local rule_key="${1:-}"
    local routes="${ALERT_ROUTES:-}"
    [[ -z "$routes" ]] && return 0     # unset → empty → fan-out path

    local prefix="${rule_key%%:*}"
    local default_val="" exact_val="" prefix_val=""
    local line key val

    # Parse the multiline config block. Tolerates leading/trailing whitespace
    # and `#` comments. Only the first occurrence of each key wins (so
    # `exploits: slack` before `exploits: discord` in the config means slack).
    while IFS= read -r line; do
        line="${line%%#*}"
        # trim whitespace both sides
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        # Only split on the FIRST `:` so values can contain colons (e.g.
        # `disk:/: discord` — key is `disk:/`, value is `discord`). Find the
        # last `:` followed by space; that's the separator.
        # Simpler: anchor-split — the key/value separator is ": " (colon+space)
        # and unambiguous since neither keys nor destination tokens contain
        # that literal sequence.
        if [[ "$line" == *": "* ]]; then
            key="${line%%: *}"
            val="${line#*: }"
        else
            # Tolerate `key:value` without space too.
            key="${line%%:*}"
            val="${line#*:}"
            # strip one leading space if present
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

# --- User hook scripts --------------------------------------------------------
#
# Run every executable file under HOOKS_DIR/on_alert.d/ with alert metadata
# in env. The /etc/cron.hourly/-style "execute-all-files-in-dir" pattern —
# users add or remove scripts without touching MiLog internals. Useful for
# custom integrations (SMS, PagerDuty, a local audit log, whatever) that
# don't fit into the destination-adapter model.
#
# Called AFTER the silence gate, so silenced fires skip hooks — same
# semantics as destinations. Runs backgrounded per-hook so a slow script
# doesn't delay the others; wrapped in `timeout` (ALERT_HOOK_TIMEOUT) so
# a hung script doesn't leak forever. All failures are logged to
# hooks.log, never propagated. The alert path is never blocked by a
# broken hook.
#
# Env passed to each hook:
#   MILOG_RULE_KEY   the rule that fired (e.g. `5xx:api`, `exploits:sqli`)
#   MILOG_TITLE      short alert title
#   MILOG_BODY       longer alert body (may contain newlines stripped to spaces)
#   MILOG_SEV        "crit" | "warn" | "info"
#   MILOG_COLOR      the raw Discord-compatible color int
#   MILOG_TS         fire epoch seconds
_alert_run_hooks() {
    local hook_dir="${HOOKS_DIR:-$HOME/.config/milog/hooks}/on_alert.d"
    [[ -d "$hook_dir" ]] || return 0

    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}"
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
    # Iterate in deterministic order — users can prefix numbers for
    # priority (`10-log`, `20-notify`), classic /etc/cron.d pattern.
    for hook in "$hook_dir"/*; do
        [[ -x "$hook" && -f "$hook" ]] || continue
        # Run each hook in its own subshell so failures don't propagate.
        # Backgrounded: the four delivery senders already background too,
        # and alert_fire callers typically background the whole fire.
        (
            local rc out
            if (( have_timeout )); then
                out=$(MILOG_RULE_KEY="$rule_key" \
                      MILOG_TITLE="$title"       \
                      MILOG_BODY="$body"         \
                      MILOG_SEV="$sev"           \
                      MILOG_COLOR="$color"       \
                      MILOG_TS="$ts"             \
                      timeout "$timeout_s" "$hook" 2>&1)
                rc=$?
            else
                out=$(MILOG_RULE_KEY="$rule_key" \
                      MILOG_TITLE="$title"       \
                      MILOG_BODY="$body"         \
                      MILOG_SEV="$sev"           \
                      MILOG_COLOR="$color"       \
                      MILOG_TS="$ts"             \
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

# --- Fanout dispatcher --------------------------------------------------------
#
# Fire one alert to every configured destination — or, if ALERT_ROUTES
# matched this rule, just the destinations it lists. Silently no-ops when
# alerts are disabled; each destination no-ops on missing config.
#
# Signature: alert_fire <title> <body> [color] [rule_key]
#   color    — Discord's color int, reused as severity hint for the alert
#              log (red=crit, yellow=warn, green=info).
#   rule_key — optional `<type>:<scope>` string; logged for `milog alerts`.
#
# Delivery is sequential (milliseconds each); callers that want
# non-blocking fanout pattern `alert_fire "..." "..." color key &`.
alert_fire() {
    [[ "${ALERTS_ENABLED:-0}" != "1" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}"
    # Silence gate — explicit user action outranks cooldown + dedup + delivery.
    # Silenced fires are NOT recorded to alerts.log: the user said "I'm on it,
    # stop telling me", and echoing the same rule repeatedly to history would
    # just be a different kind of noise. The silence row itself (in
    # alerts.silences) is the durable audit trail.
    if [[ -n "$rule_key" ]] && alert_is_silenced "$rule_key" >/dev/null; then
        return 0
    fi
    # Record before delivery — the log captures "what fired" even if the
    # webhooks fail (network blip, rate limit, rotated token).
    _alert_record "$rule_key" "$title" "$body" "$color"

    # User hook scripts — run before delivery so custom integrations see the
    # event regardless of whether any destination is configured. Hooks do
    # NOT require curl; they're arbitrary executables under
    # HOOKS_DIR/on_alert.d/. Safe to run even if `curl` is missing.
    _alert_run_hooks "$title" "$body" "$color" "$rule_key"

    command -v curl >/dev/null 2>&1 || return 0

    # Resolve routing — empty = today's behavior (fan out to every configured
    # destination). Non-empty = only the destination types listed here fire.
    local route
    route=$(_alert_route_for "$rule_key")

    if [[ -z "$route" ]]; then
        # Each destination backgrounded so a slow one doesn't delay the
        # others. Callers also typically background `alert_fire &` — the
        # resulting grandchild sends are orphaned to init on exit, which is
        # fine. Webhook takes rule_key as a 4th arg for template
        # substitution; other senders don't need it.
        _alert_send_discord  "$title" "$body" "$color" &
        _alert_send_slack    "$title" "$body" "$color" &
        _alert_send_telegram "$title" "$body" "$color" &
        _alert_send_matrix   "$title" "$body" "$color" &
        _alert_send_webhook  "$title" "$body" "$color" "$rule_key" &
        return 0
    fi

    # Routed fire: dispatch only to the listed destination types. Unknown
    # tokens are silently ignored so a forward-looking config (e.g. naming
    # an adapter before it lands) doesn't break existing rules. `skip` is
    # an explicit "do not fire this class" — useful for noise rules you
    # want to keep recording in alerts.log but not page on.
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

# Back-compat alias for `alert_discord`. Drop-in replacement for code that
# hasn't been updated to the new name yet. Prefer `alert_fire` in new code.
alert_discord() { alert_fire "$@"; }

# --- Redaction previews -------------------------------------------------------
# Each returns a short string that (a) confirms which account/webhook is
# wired up and (b) never leaks the secret. Used by `alert status` and
# `config` so users can tell at a glance what's actually configured.

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
    # Telegram bot token is `<bot_id>:<secret>`. Bot ID is public-ish
    # (visible to anyone messaging the bot), so keep it; mask the secret.
    local bot_id="${token%%:*}"
    printf 'bot%s:**** chat=%s' "$bot_id" "$chat"
}

_alert_redact_matrix() {
    local hs="${1:-}" token="${2:-}" room="${3:-}"
    [[ -z "$hs" || -z "$token" || -z "$room" ]] && return 0
    # Homeserver + room are fine to show (they're addressable); token is
    # the access bearer, always masked.
    printf '%s  room=%s  token=****' "${hs%/}" "$room"
}

# Generic webhook URL — free-form target, so we don't know which part is the
# secret. Preserve scheme + host + first path segment (usually identifies
# the tool / channel), mask the tail. Falls back to a prefix truncation.
_alert_redact_webhook() {
    local w="${1:-}"
    [[ -z "$w" ]] && return 0
    if [[ "$w" =~ ^(https?://[^/]+/[^/?]+) ]]; then
        printf '%s/****' "${BASH_REMATCH[1]}"
    else
        printf '%.40s…' "$w"
    fi
}

# --- Destinations status line renderer ---------------------------------------
# Prints one line per configured-or-not destination. Accepts ALL values as
# positional args so callers can feed either env vars (process-state view,
# used by `config`) or values pre-read from a specific config file (target-
# user view, used by `alert status` under sudo).
#
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

# Cooldown gate. Returns 0 (fire) if no prior fire for $1 is within
# ALERT_COOLDOWN seconds, 1 (suppress) otherwise. On fire, rewrites the
# state file with the current timestamp for that key.
#
# State file format:   <rule_key><TAB><last_fired_epoch>   (one per line)
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
    # mktemp gives a unique path per process — crucial because mode_daemon
    # has multiple backgrounded subshells (exploits + probes watchers) and
    # bash's $$ is the parent PID, so $$-based names would collide.
    tmp=$(mktemp "$ALERT_STATE_DIR/alerts.state.tmp.XXXXXX" 2>/dev/null) || return 1
    {
        awk -v k="$key" -F'\t' 'BEGIN{OFS="\t"} $1!=k' "$state_file" 2>/dev/null
        printf '%s\t%s\n' "$key" "$now"
    } > "$tmp" && mv "$tmp" "$state_file" 2>/dev/null
    # Cleanup if the mv lost a race — content is already in state_file from
    # the winning process, so just drop our redundant tmp.
    [[ -f "$tmp" ]] && rm -f "$tmp"
    return 0
}

# Cross-rule dedup. Same log-line can match both `exploits` (by path) and
# `probes` (by user-agent); without this gate both rules fire a Discord
# embed on the same event.
#
# Contract: identical to `alert_should_fire` but keyed on a *fingerprint*
# (e.g. "<ip>:<path>") with its own TTL `ALERT_DEDUP_WINDOW`. Returns 0
# (fire) if the fingerprint is new or its last record has expired;
# atomically records the current epoch on that success. Returns 1
# (suppress) if the fingerprint was recorded within the dedup window.
#
# Call AFTER `alert_should_fire` — both gates must pass. Putting rule
# cooldown first short-circuits the common case (quiet server) without
# touching the fingerprint file.
#
# State file: $ALERT_STATE_DIR/alerts.fingerprints (same format as
# alerts.state, tabbed). Kept separate from alerts.state so the two
# concerns — rule rate-limit vs event dedup — can have independent TTLs
# and be inspected / purged independently.
alert_fingerprint_fresh() {
    local fp="$1"
    [[ -n "$fp" ]] || return 0   # no fingerprint → pass through, dedup opt-in
    local state_file="$ALERT_STATE_DIR/alerts.fingerprints"
    local now last tmp
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 0
    now=$(date +%s)
    last=$(awk -v k="$fp" -F'\t' '$1==k {print $2; exit}' "$state_file" 2>/dev/null)
    if [[ -n "$last" ]] && (( now - last < ALERT_DEDUP_WINDOW )); then
        return 1
    fi
    tmp=$(mktemp "$ALERT_STATE_DIR/alerts.fingerprints.tmp.XXXXXX" 2>/dev/null) || return 0
    {
        # Drop the old entry for this fingerprint AND any whose last-seen has
        # already expired — keeps the file from growing unbounded on long
        # uptimes. 2×TTL gives a small safety margin.
        awk -v k="$fp" -v cutoff=$(( now - ALERT_DEDUP_WINDOW * 2 )) \
            -F'\t' 'BEGIN{OFS="\t"} $1!=k && $2>cutoff' "$state_file" 2>/dev/null
        printf '%s\t%s\n' "$fp" "$now"
    } > "$tmp" && mv "$tmp" "$state_file" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    return 0
}

# Extract an `<ip>:<path>` fingerprint from a combined-format nginx logline.
# Query string stripped so /x?a=1 and /x?a=2 collapse into one event.
# Returns empty on unparseable input — callers treat empty as "no dedup".
alert_fingerprint_from_line() {
    local line="$1"
    local ip path
    # $1 = IP (first whitespace-separated field), $7 inside the quoted
    # request = URL. Extract via awk because bash string split on the whole
    # line is painful.
    read -r ip path <<< "$(awk '{
        p = $7
        sub(/\?.*/, "", p)
        print $1, p
    }' <<< "$line")"
    [[ -n "$ip" && -n "$path" ]] || { printf ''; return; }
    printf '%s:%s' "$ip" "$path"
}

# Classify an exploit match into a category slug used in the alert rule key.
# Substring-based (case-insensitive via shopt) — classification only needs to
# be good enough for grouping, not exact regex parity with the match pattern.
_exploit_category() {
    local line="$1" cat="other"
    shopt -s nocasematch
    case "$line" in
        *'${jndi'*|*'jndi:'*|*log4j*)                                            cat=log4shell ;;
        *union*select*|*select*from*|*'sleep('*|*'benchmark('*|*' or 1=1'*|*%27*or*) cat=sqli ;;
        *'<script'*|*%3cscript*|*'onerror='*|*'onload='*|*'javascript:'*)        cat=xss ;;
        *base64_decode*|*'eval('*|*'system('*|*'passthru('*|*shell_exec*)         cat=rce ;;
        *'../'*|*%2e%2e*|*/etc/passwd*|*/etc/shadow*|*/proc/self*)               cat=traversal ;;
        */containers/*|*/actuator/*|*/server-status*|*/console*|*/druid/*)       cat=infra ;;
        */SDK/web*|*/cgi-bin/*|*/boaform/*|*/HNAP1*)                             cat=device ;;
        */wp-admin*|*/wp-login*|*/wp-content/plugins*|*/xmlrpc.php*)             cat=wordpress ;;
        */phpmyadmin*|*/pma/*|*/mysql/admin*)                                    cat=phpmyadmin ;;
        */.env*|*/.git/*|*/.aws/*|*/.ssh/*|*/.DS_Store*|*/config.php*|*/config.json*|*/config.yml*|*/config.yaml*|*/web.config*) cat=dotfile ;;
        *libredtail*|*nikto*|*masscan*|*zgrab*|*sqlmap*|*nuclei*|*gobuster*|*dirbuster*|*wfuzz*|*l9explore*|*l9tcpid*|*'hello, world'*|*'hello,world'*) cat=scanner ;;
    esac
    shopt -u nocasematch
    printf '%s' "$cat"
}

# ==============================================================================
# BOX DRAWING — single source of truth for geometry
#
# Table columns: APP(10) | REQ/MIN(8) | STATUS(10) | INTENSITY(W_BAR)
# Row layout between outer │…│:
#   " " app(10) " │ " req(8) " │ " status(10) " │ " bar(W_BAR) " "
#   = 11 + (W_REQ+3) + (W_ST+3) + (W_BAR+4) = W_APP+W_REQ+W_ST+W_BAR+11
#
# INNER is the interior width (chars between the outer │…│) and scales with
# terminal width; W_BAR absorbs the slack so the INTENSITY column — which
# carries the sparkline — gets wider on bigger screens. The fixed columns
# (APP/REQ/STATUS) stay the same so numbers line up at a glance.
#
# milog_update_geometry() recomputes INNER/W_BAR/BW from `tput cols` and is
# called at the top of every render tick — so SIGWINCH / live resize just
# works (next frame reflows). Override with MILOG_WIDTH=N to pin a width,
# useful in terminals that misreport cols (screen, some CI runners).
# ==============================================================================
W_APP=10; W_REQ=8; W_ST=10
W_BAR=35                 # INTENSITY column — grows with terminal width
INNER=74                 # interior chars between outer │ │ (grows with terminal)
BW=11                    # sysmetric bar width: (INNER-39)/3 — recomputed per tick
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
    # Sysmetric row is " CPU xxx% [bar]  MEM xxx% [bar]  DISK xxx% [bar]"
    # → 39 fixed chars + 3 bars. Reserve 1 trailing char so `]` never kisses
    # the right │. Floor BW at 5 so small terms stay legible.
    BW=$(( (INNER - 40) / 3 ))
    (( BW < 5 )) && BW=5
    return 0   # guard against set -e when BW>=5 makes `((…))` return 1
}
milog_update_geometry    # initialise for non-TUI modes that use draw_row

spc() { printf '%*s' "$1" ''; }
hrule() { printf '─%.0s' $(seq 1 "$1"); }

# Single-box rules — all share INNER=74
bdr_top() { printf "${W}┌$(hrule $((W_APP+2)))┬$(hrule $((W_REQ+2)))┬$(hrule $((W_ST+2)))┬$(hrule $((W_BAR+2)))┐${NC}\n"; }
bdr_hdr() { printf "${W}├$(hrule $((W_APP+2)))┼$(hrule $((W_REQ+2)))┼$(hrule $((W_ST+2)))┼$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_mid() { printf "${W}├$(hrule $((INNER)))┤${NC}\n"; }
bdr_sep() { printf "${W}├$(hrule $((W_APP+2)))┴$(hrule $((W_REQ+2)))┴$(hrule $((W_ST+2)))┴$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_bot() { printf "${W}└$(hrule $((INNER)))┘${NC}\n"; }

# Full-width content row: │ plain/colored content + padding │
# $1=plain_text (for measuring)  $2=colored_text (for printing)
# Plain must not contain any ANSI sequences.
draw_row() {
    local plain="$1" colored="$2"
    local pad=$(( INNER - ${#plain} ))
    printf "${W}│${NC}%b" "$colored"
    [[ $pad -gt 0 ]] && spc "$pad"
    printf "${W}│${NC}\n"
}

# Table data row — padding computed from plain args only
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

# Column header row (no color escape issues — plain printf)
hdr_row() {
    printf "${W}│${NC} %-${W_APP}s ${W}│${NC} %-${W_REQ}s ${W}│${NC} %-${W_ST}s ${W}│${NC} %-${W_BAR}s ${W}│${NC}\n" \
        "APP" "REQ/MIN" "STATUS" "INTENSITY"
}

# ==============================================================================
# SYSTEM METRICS
# ==============================================================================

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

# ASCII progress bar using only hyphen and equals — no wide-glyph block chars
# $1=width  $2=value  $3=max → prints exactly $1 chars
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

# Unicode sparkline: reads space-separated ints on $1, prints sparkline chars.
# Each sample scales to one of 8 block chars relative to the max in the series.
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

# Wait up to $1 seconds for a single keypress. Prints the key if pressed, empty
# on timeout. Needs an interactive tty; silent read so input doesn't echo.
wait_or_key() {
    local k
    if read -rsn1 -t "$1" k 2>/dev/null; then
        printf '%s' "$k"
    fi
}

# Daemon/history stderr log — timestamped, never to stdout. Shared by any
# code path that runs under mode_daemon (rule evaluator, history writers).
_dlog() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

# ==============================================================================
# HISTORY — SQLite-backed per-minute time series + hourly top-IP rollups
# All writes go through a single sqlite3 invocation per call (heredoc),
# per the plan's "don't spawn one process per app" rule.
# ==============================================================================

# SQLite string literal escape: doubles embedded single quotes, wraps in ''.
_sql_quote() { local s="${1//\'/\'\'}"; printf "'%s'" "$s"; }

# Portable "date at epoch" → log-line prefix (dd/Mon/yyyy:HH:MM). GNU date
# takes `-d @TS`, BSD date takes `-r TS`. We just try both.
_cur_time_at() {
    local ts="$1"
    date -d "@${ts}" '+%d/%b/%Y:%H:%M' 2>/dev/null \
        || date -r "$ts" '+%d/%b/%Y:%H:%M' 2>/dev/null \
        || printf ''
}

# Create tables + indexes if missing. Idempotent; safe to call on every
# daemon start. Disables history on any failure mode (missing sqlite3,
# unwritable path) so the rest of the daemon keeps running.
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
SQL
    then
        _dlog "WARNING: sqlite3 init failed — disabling history"
        HISTORY_ENABLED=0
        return 1
    fi

    _dlog "history: schema ready at $HISTORY_DB"
}

# Insert one row per configured app for a completed minute. The timestamp
# string must match the log format (dd/Mon/yyyy:HH:MM) so awk filters work.
# p50/p95/p99 land as SQL NULL when the app has no $request_time samples.
history_write_minute() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local ts="$1" cur_time="$2"
    [[ -n "$cur_time" ]] || { _dlog "history: empty cur_time for ts=$ts; skipping"; return 0; }

    local sql="" app count c2 c3 c4 c5 p50 p95 p99
    for app in "${LOGS[@]}"; do
        read -r count c2 c3 c4 c5 <<< "$(nginx_minute_counts "$app" "$cur_time")"
        count=${count:-0}; c2=${c2:-0}; c3=${c3:-0}; c4=${c4:-0}; c5=${c5:-0}
        read -r p50 p95 p99 <<< "$(percentiles "$app" "$cur_time")"
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

# Hourly top-IP rollup. Scans each app's log for lines prefixed with the
# hour pattern (dd/Mon/yyyy:HH:), counts, and stores the top N. Lower N
# caps the database size on servers with very bursty IP diversity.
history_write_hour() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local ts_hour="$1"
    local hour_pat
    hour_pat=$(date -d "@${ts_hour}" '+%d/%b/%Y:%H:' 2>/dev/null \
               || date -r "$ts_hour"  '+%d/%b/%Y:%H:' 2>/dev/null)
    [[ -n "$hour_pat" ]] || return 0

    local sql="" app file hits ip
    for app in "${LOGS[@]}"; do
        file="$LOG_DIR/$app.access.log"
        [[ -f "$file" ]] || continue
        while read -r hits ip; do
            [[ -n "$ip" ]] || continue
            sql+="INSERT OR REPLACE INTO top_ip_hour VALUES"
            sql+=" ($ts_hour, $(_sql_quote "$app"), $(_sql_quote "$ip"), $hits);"$'\n'
        done < <(grep -F "$hour_pat" "$file" 2>/dev/null \
                 | awk '{print $1}' | sort | uniq -c | sort -rn \
                 | head -n "${HISTORY_TOP_IP_N:-50}")
    done

    [[ -n "$sql" ]] || return 0
    if ! { printf 'BEGIN;\n%sCOMMIT;\n' "$sql"; } | sqlite3 "$HISTORY_DB" 2>/dev/null; then
        _dlog "history: hour write failed for ts_hour=$ts_hour"
    fi
}

# Delete rows older than HISTORY_RETAIN_DAYS days from both tables. One
# sqlite3 invocation, transactional. Called once per day from the daemon.
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
COMMIT;
SQL
    then
        _dlog "history: pruned rows older than ${retain}d (cutoff=$cutoff)"
    else
        _dlog "history: prune failed"
    fi
}

# Gate for read-only history modes (trend / diff). Prints a friendly
# message to stderr and returns 1 when sqlite3 or the DB are missing.
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

# ==============================================================================
# NGINX ROW HELPERS
# ==============================================================================

# Extract the single awk pass so the daemon can reuse it without the
# rendering side-effects of nginx_row. Prints "count c2 c3 c4 c5" (zeros
# if the log file is missing or unreadable). One scan, four class buckets;
# callers that only need c4/c5 just consume the first three fields they
# care about and leave the rest as locals.
nginx_minute_counts() {
    local file="$LOG_DIR/$1.access.log"
    [[ -f "$file" ]] || { printf '0 0 0 0 0\n'; return; }
    awk -v t="$2" '
        index($0, t) {
            n++
            if (match($0, / [1-5][0-9][0-9] /)) {
                cls = substr($0, RSTART+1, 1)
                if      (cls == "2") e2++
                else if (cls == "3") e3++
                else if (cls == "4") e4++
                else if (cls == "5") e5++
            }
        }
        END { printf "%d %d %d %d %d\n", n+0, e2+0, e3+0, e4+0, e5+0 }
    ' "$file" 2>/dev/null
}

# Response-time percentiles for the current-minute window. Requires the
# extended log_format that appends $request_time as the final field (see
# README → "Response-time percentiles"). Gracefully degrades to the em-dash
# sentinel when no numeric $request_time is present on any matching line.
#   $1 app   $2 CUR_TIME   →   prints "p50 p95 p99" in ms, or "— — —"
percentiles() {
    local name="$1" cur="$2"
    local file="$LOG_DIR/$name.access.log"
    [[ -f "$file" ]] || { printf -- '— — —\n'; return; }
    local sorted
    sorted=$(awk -v t="$cur" '
        index($0, t) && $NF ~ /^[0-9]+(\.[0-9]+)?$/ {
            print int($NF * 1000 + 0.5)
        }' "$file" 2>/dev/null | sort -n)
    if [[ -z "$sorted" ]]; then
        printf -- '— — —\n'
        return
    fi
    # Ceiling-index percentile pick: idx = ceil(N*k/100), clamped to [1,N].
    # Single awk pass over the already-sorted stream keeps us to one fork.
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

# GeoIP lookup for a single IP. Returns the 2-letter ISO country code or
# the em-dash sentinel when disabled, when the MMDB is missing, when
# mmdblookup isn't on $PATH, or when the IP isn't in the database.
#
# Performance: forks mmdblookup per call. Callers MUST only invoke this on
# already-aggregated IP sets (post uniq/awk dedup) — never per log line in
# a live tail, where it would fork thousands of processes.
geoip_country() {
    [[ "${GEOIP_ENABLED:-0}" != "1" ]] && { printf -- '—'; return; }
    [[ ! -f "$MMDB_PATH" ]]            && { printf -- '—'; return; }
    command -v mmdblookup >/dev/null 2>&1 || { printf -- '—'; return; }
    local out
    out=$(mmdblookup --file "$MMDB_PATH" --ip "$1" country iso_code 2>/dev/null \
          | awk -F'"' 'NF>=3 {print $2; exit}')
    printf '%s' "${out:-—}"
}

# Cached p95 lookup for the monitor row. Two-level cache:
#   TIMED_APPS[name]   — unset=unknown, 0=never-timed, 1=timed. Skips the
#                        file scan forever for apps that don't log
#                        $request_time (restart MiLog after a log_format
#                        change to re-probe).
#   P95_LAST_MIN[name] — last minute string (dd/Mon/yyyy:HH:MM) we probed
#   P95_LAST_VAL[name] — p95 value for that minute
#
# Within the same minute, re-use the cached p95 so a 5s monitor refresh
# doesn't re-scan the whole log 12× per minute per app.
#
# Declared lazily (`-gA` inside the function) so the script stays parseable
# on bash 3.2 hosts without associative arrays — same pattern used for HIST.
#
# Prints the p95 in milliseconds on stdout, or empty when unavailable.
_p95_cached() {
    # On bash 3.2 (macOS dev boxes) associative arrays aren't available,
    # so skip the cache entirely — correct result, uncached probe every
    # call. Real deployments target bash 4+ Linux.
    if (( ${BASH_VERSINFO[0]:-3} < 4 )); then
        local _p50 p95 _p99
        read -r _p50 p95 _p99 <<< "$(percentiles "$1" "$2")"
        [[ "$p95" =~ ^[0-9]+$ ]] && printf '%s' "$p95"
        return 0
    fi
    declare -gA TIMED_APPS P95_LAST_MIN P95_LAST_VAL
    local name="$1" cur="$2"

    # Hard negative cache — don't scan apps we've already proven untimed.
    [[ "${TIMED_APPS[$name]:-}" == "0" ]] && return 0

    # Per-minute positive cache — reuse the previous probe inside the same
    # minute bucket so render loops at sub-minute cadence don't rescan.
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

# HTTP rule-hook — fires 4xx/5xx spike alerts. Called from both nginx_row
# (render-mode) and mode_daemon. Cooldown gate inside alert_should_fire.
#
# Thresholds resolve via _thresh so `THRESH_5XX_WARN_api=10` in config.sh
# loosens just the `api` app while leaving the global default intact.
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

# System rule-hook — fires CPU/MEM/DISK/workers alerts. Shared by monitor
# and daemon so threshold logic has one home.
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

    read -r count c2 c3 c4 c5 <<< "$(nginx_minute_counts "$name" "$CUR_TIME")"
    count=${count:-0}; c4=${c4:-0}; c5=${c5:-0}
    # shellcheck disable=SC2034
    eval "$TOTAL_ref=$(( ${!TOTAL_ref} + count ))"

    # Per-app threshold overrides — config may set THRESH_REQ_WARN_<app> etc.
    # Resolved once per row to keep the branch cheap; _thresh falls back to
    # the global when no override exists.
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

    # Response-time p95 (skipped automatically for apps without the timed
    # log format after the first probe — see _p95_cached / TIMED_APPS).
    local p95_ms
    p95_ms=$(_p95_cached "$name" "$CUR_TIME")

    local bars_plain bars_col
    if [[ "${MILOG_HIST_ENABLED:-0}" == "1" ]]; then
        # Push current sample into ring buffer (HIST is a global assoc array).
        # Freeze the buffer when MILOG_HIST_PAUSED=1 so paused view doesn't drift.
        local -a hist_arr=( ${HIST[$name]:-} )
        if [[ "${MILOG_HIST_PAUSED:-0}" != "1" ]]; then
            hist_arr+=( "$count" )
            if (( ${#hist_arr[@]} > SPARK_LEN )); then
                hist_arr=( "${hist_arr[@]: -$SPARK_LEN}" )
            fi
            HIST[$name]="${hist_arr[*]}"
        fi
        # Handle first tick before any samples exist
        (( ${#hist_arr[@]} == 0 )) && hist_arr=( 0 )

        local spark n_samples=${#hist_arr[@]}
        spark=$(sparkline_render "${hist_arr[*]}")
        # Plain placeholder of equal column-width for padding arithmetic.
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

    # Build the right-aligned tag strip — 4xx/5xx counts and/or p95 — then
    # trim the bar/sparkline to fit before concatenating. Each tag is
    # optional; the tag strip is only applied when at least one is present.
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

# MODE: web — tiny read-only HTTP dashboard
#
# Security posture (read carefully before changing defaults):
#   - Loopback-only bind by default; --bind $other requires --trust.
#   - Every request is token-gated. Token is 32 bytes of urandom hex in
#     $WEB_TOKEN_FILE (mode 600). First page load accepts ?t=TOKEN; the JS
#     then stores it in sessionStorage + strips the query string so the
#     token doesn't linger in browser history.
#   - All routes are READ-ONLY. No endpoint mutates config, webhook,
#     systemd, or the history DB. Locking this down is intentional — if
#     someone bypasses SSH/Tailscale/CF and the token, they still can't
#     pivot to owning the box.
#   - Responses set: no external fetches (CSP: default-src 'self'),
#     X-Content-Type-Options, X-Frame-Options: DENY, Referrer-Policy:
#     no-referrer, Cache-Control: no-store.
#   - DISCORD_WEBHOOK is always redacted to its prefix in API responses.
#
# Transport choices (ranked, see README):
#   1. SSH port-forward:  ssh -L 8765:localhost:8765 host   (zero exposure)
#   2. Tailscale/WireGuard overlay                          (phone-friendly)
#   3. Cloudflare Tunnel  cloudflared tunnel --url http://localhost:8765
#
# Listener: socat or ncat (checked at start; clear error if neither).
# ==============================================================================

# ---- token management --------------------------------------------------------
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
    # 32 bytes → 64 hex chars. /dev/urandom is portable; fall back to openssl.
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

# ---- JSON helpers ------------------------------------------------------------
# Tiny escaper: for string values we already trust (numeric-looking metric
# values, known-good app names from LOGS). User-visible free-text (paths,
# UA strings) must go through json_escape which already exists for Discord.
_web_n() { [[ "$1" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] && printf '%s' "$1" || printf 'null'; }

_web_redact_webhook() {
    # Keep just enough of the URL to identify which webhook — strip the secret.
    local w="${1:-}"
    [[ -z "$w" ]] && { printf ''; return; }
    if [[ "$w" =~ (.*/webhooks/[0-9]+/)[A-Za-z0-9_-]+ ]]; then
        printf '%s****' "${BASH_REMATCH[1]}"
    else
        printf '%s…' "${w:0:20}"
    fi
}

# ---- HTTP response ----------------------------------------------------------
# Emits a full HTTP/1.1 response. Callers pass a pre-built body (can be
# empty). We compute Content-Length from the byte-size of the body.
_web_respond() {
    local status="$1" ctype="$2" body="${3:-}"
    local msg="OK"
    case "$status" in
        200) msg="OK" ;;
        400) msg="Bad Request" ;;
        401) msg="Unauthorized" ;;
        404) msg="Not Found" ;;
        405) msg="Method Not Allowed" ;;
        429) msg="Too Many Requests" ;;
        500) msg="Internal Server Error" ;;
    esac
    # Byte length — NOT ${#body}, which under a UTF-8 locale counts codepoints
    # and under-reports by (bytes-1) for every multi-byte char. That mismatch
    # lets the browser finish reading a truncated response, chopping off the
    # tail of the HTML (including the closing </script> tag). wc -c always
    # counts bytes, regardless of LC_ALL.
    local len
    len=$(printf '%s' "$body" | wc -c | tr -d ' ')
    printf 'HTTP/1.1 %s %s\r\n' "$status" "$msg"
    printf 'Content-Type: %s; charset=utf-8\r\n' "$ctype"
    printf 'Content-Length: %d\r\n' "$len"
    printf 'Connection: close\r\n'
    printf 'Cache-Control: no-store\r\n'
    printf 'X-Content-Type-Options: nosniff\r\n'
    printf 'X-Frame-Options: DENY\r\n'
    printf 'Referrer-Policy: no-referrer\r\n'
    # CSP forbids external fetches. All CSS/JS is inline in the HTML page.
    printf "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'none'\r\n"
    printf '\r\n'
    printf '%s' "$body"
}

# ---- route: /api/summary.json ------------------------------------------------
_web_route_summary() {
    local cur_time; cur_time=$(date '+%d/%b/%Y:%H:%M')
    local ts; ts=$(date -Iseconds 2>/dev/null || date)

    # System metrics — reuse existing helpers.
    local cpu mem_pct mem_used mem_total disk_pct disk_used disk_total
    cpu=$(cpu_usage); [[ "$cpu" =~ ^[0-9]+$ ]] || cpu=0
    read -r mem_pct mem_used mem_total  <<< "$(mem_info)"
    read -r disk_pct disk_used disk_total <<< "$(disk_info)"

    # Per-app nginx counts.
    local app_json="" app count c2 c3 c4 c5
    local first=1 total=0
    for app in "${LOGS[@]}"; do
        read -r count c2 c3 c4 c5 <<< "$(nginx_minute_counts "$app" "$cur_time")"
        count=${count:-0}; c2=${c2:-0}; c3=${c3:-0}; c4=${c4:-0}; c5=${c5:-0}
        total=$(( total + count ))
        if (( first )); then first=0; else app_json+=","; fi
        # json_escape returns the string already quoted — use %s, not "%s".
        app_json+=$(printf '{"name":%s,"req":%d,"c2xx":%d,"c3xx":%d,"c4xx":%d,"c5xx":%d}' \
            "$(json_escape "$app")" "$count" "$c2" "$c3" "$c4" "$c5")
    done

    local body
    body=$(printf '{"ts":%s,"system":{"cpu":%s,"mem_pct":%s,"mem_used_mb":%s,"mem_total_mb":%s,"disk_pct":%s,"disk_used_gb":%s,"disk_total_gb":%s},"total_req":%d,"apps":[%s]}' \
        "$(json_escape "$ts")" \
        "$(_web_n "$cpu")" "$(_web_n "$mem_pct")" "$(_web_n "$mem_used")" "$(_web_n "$mem_total")" \
        "$(_web_n "$disk_pct")" "$(_web_n "$disk_used")" "$(_web_n "$disk_total")" \
        "$total" "$app_json")
    _web_respond 200 "application/json" "$body"
}

# ---- route: /api/meta.json ---------------------------------------------------
_web_route_meta() {
    local up; up=$(uptime -p 2>/dev/null | sed 's/up //' || echo "")
    local hook_status="disabled"
    [[ "$ALERTS_ENABLED" == "1" && -n "$DISCORD_WEBHOOK" ]] && hook_status="enabled"

    # Build apps array JSON-safely (each element through json_escape).
    local apps_json="" first=1 a
    for a in "${LOGS[@]}"; do
        if (( first )); then first=0; else apps_json+=","; fi
        apps_json+=$(json_escape "$a")
    done

    local body
    body=$(printf '{"apps":[%s],"log_dir":%s,"alerts":%s,"webhook":%s,"uptime":%s,"refresh":%d}' \
        "$apps_json" \
        "$(json_escape "$LOG_DIR")" \
        "$(json_escape "$hook_status")" \
        "$(json_escape "$(_web_redact_webhook "$DISCORD_WEBHOOK")")" \
        "$(json_escape "$up")" \
        "$REFRESH")
    _web_respond 200 "application/json" "$body"
}

# ---- route: /api/logs.json ---------------------------------------------------
# Returns recent lines from ONE nginx source, filtered by grep pattern + path
# + status-class. Capped at 500 rows per fetch. For bigger windows, the
# caller narrows filters. Designed for the tier-1 in-browser log viewer —
# every pass scans the tail of one log file, no sqlite layer yet.
#
# Query params:
#   app=<name>    required — must be an nginx source in LOGS
#   limit=<N>     default 200, max 500
#   grep=<sub>    optional substring filter (case-sensitive)
#   path=<pre>    optional path-prefix filter (starts with /)
#   class=<c>     optional status class: 2xx 3xx 4xx 5xx any
_web_route_logs() {
    local app="${1:-}" limit="${2:-200}" grep_s="${3:-}" path_s="${4:-}" cls="${5:-}"
    local max=500
    [[ "$limit" =~ ^[0-9]+$ ]] || limit=200
    (( limit > max )) && limit=$max

    local body
    local file="$LOG_DIR/${app}.access.log"
    if [[ -z "$app" || ! -f "$file" ]]; then
        body=$(printf '{"app":%s,"lines":[],"error":"no such app"}' \
            "$(json_escape "${app:-}")")
        _web_respond 404 "application/json" "$body"
        return
    fi

    # Read last N*3 lines, then filter + cap in awk (lets us filter-then-slice
    # so grep+path+class yield exactly `limit` rows when possible).
    local read_n=$(( limit * 3 ))
    (( read_n < 200 )) && read_n=200
    local raw
    raw=$(tail -n "$read_n" "$file" 2>/dev/null \
        | awk -F'"' -v grep_s="$grep_s" -v path_s="$path_s" -v cls="$cls" -v limit="$limit" '
            function jesc(s) {
                gsub(/\\/, "\\\\", s)
                gsub(/"/,  "\\\"", s)
                gsub(/\t/, "\\t", s)
                gsub(/\n/, "\\n", s)
                gsub(/\r/, "\\r", s)
                return s
            }
            # Combined-format line:
            #   ip - user [t] "METHOD path HTTP" status bytes "ref" "ua" rt?
            # We split on double-quotes: $1 has ip+dash+time, $2 is request,
            # $3 has status+bytes, $4 is referer, $5 has ua+maybe-rt.
            {
                line = $0
                # Substring filter first — cheapest on no-match.
                if (grep_s != "" && index(line, grep_s) == 0) next

                # Parse fields. Field-split on whitespace for the unquoted bits.
                n_ws = split($1, ws, " ")
                ip = ws[1]
                timestamp = ""
                for (i = 1; i <= n_ws; i++) {
                    if (ws[i] ~ /^\[/) { timestamp = ws[i]; break }
                }

                # Request string (field $2): "METHOD /path HTTP/1.1"
                req = $2
                n_rq = split(req, rq, " ")
                method = (n_rq >= 1) ? rq[1] : ""
                raw_path = (n_rq >= 2) ? rq[2] : ""
                q = index(raw_path, "?")
                clean_path = (q > 0) ? substr(raw_path, 1, q-1) : raw_path

                # Defensive: path must start with /
                if (substr(clean_path, 1, 1) != "/") next
                if (path_s != "" && index(clean_path, path_s) != 1) next

                # Status is the first field of $3 (after the closing quote).
                # Strip leading whitespace first — split on " " with a
                # leading-space input yields ["401","0"] not ["","401","0",""]
                # in most awks.
                f3 = $3
                sub(/^[[:space:]]+/, "", f3)
                n_sb = split(f3, sb, " ")
                status = (n_sb >= 1) ? sb[1] : ""
                if (status !~ /^[0-9]+$/) next
                sclass = substr(status, 1, 1) "xx"
                if (cls != "" && cls != "any" && cls != sclass) next

                # UA is field $6 (quoted ua string surrounded by quotes means
                # $6 exactly). After the UA, an optional request_time float.
                ua = ($6 != "" ? $6 : "")

                n++
                # Emit JSON object per surviving row.
                out[n] = sprintf("{\"ts\":\"%s\",\"ip\":\"%s\",\"method\":\"%s\",\"path\":\"%s\",\"status\":%s,\"ua\":\"%s\",\"class\":\"%s\"}",
                    jesc(timestamp), jesc(ip), jesc(method), jesc(clean_path), status, jesc(ua), sclass)

                if (n > limit) {
                    # Drop the oldest if over-cap (keep latest N).
                    for (j = 1; j < n; j++) out[j] = out[j+1]
                    n = limit
                }
            }
            END {
                for (j = 1; j <= n; j++) {
                    print out[j]
                }
            }')

    local arr="[]"
    if [[ -n "$raw" ]]; then
        arr="[$(printf '%s' "$raw" | paste -sd, -)]"
    fi

    body=$(printf '{"app":%s,"lines":%s}' "$(json_escape "$app")" "$arr")
    _web_respond 200 "application/json" "$body"
}

# ---- route: /api/logs/histogram.json -----------------------------------------
# Per-minute request counts for the selected app over a window (N minutes).
# Used for the timeline strip above the log table.
_web_route_logs_histogram() {
    local app="${1:-}" minutes="${2:-60}"
    [[ "$minutes" =~ ^[0-9]+$ ]] || minutes=60
    (( minutes > 1440 )) && minutes=1440
    local file="$LOG_DIR/${app}.access.log"
    local body
    if [[ -z "$app" || ! -f "$file" ]]; then
        body=$(printf '{"app":%s,"buckets":[]}' "$(json_escape "${app:-}")")
        _web_respond 404 "application/json" "$body"
        return
    fi

    # Build N per-minute bucket keys: [dd/Mon/yyyy:HH:MM, ...] for the
    # last `minutes` minutes. Scan tail of file counting matches.
    local now_ts; now_ts=$(date +%s)
    local cur_minute_str
    local i ts_i
    # Pre-generate all minute strings into an awk-readable list.
    local keys=""
    for (( i = minutes - 1; i >= 0; i-- )); do
        ts_i=$(( now_ts - i * 60 ))
        cur_minute_str=$(date -d "@$ts_i" '+%d/%b/%Y:%H:%M' 2>/dev/null \
            || date -r  "$ts_i" '+%d/%b/%Y:%H:%M' 2>/dev/null)
        keys="${keys}${cur_minute_str}\n"
    done

    # For very large logs, only scan a bounded tail slice.
    local scan_lines=$(( minutes * 500 ))
    (( scan_lines < 1000 )) && scan_lines=1000

    local raw
    raw=$(printf '%b' "$keys" | awk -v file="$file" -v scan="$scan_lines" '
        { keys[NR] = $0 }
        END {
            cmd = sprintf("tail -n %d %s 2>/dev/null", scan, file)
            while ((cmd | getline line) > 0) {
                for (k in keys) {
                    if (index(line, keys[k]) > 0) {
                        counts[keys[k]]++
                        break
                    }
                }
            }
            close(cmd)
            for (i = 1; i <= NR; i++) {
                printf "{\"t\":\"%s\",\"c\":%d}\n", keys[i], counts[keys[i]]+0
            }
        }')

    local arr="[]"
    [[ -n "$raw" ]] && arr="[$(printf '%s' "$raw" | paste -sd, -)]"
    body=$(printf '{"app":%s,"buckets":%s}' "$(json_escape "$app")" "$arr")
    _web_respond 200 "application/json" "$body"
}

# ---- route: /api/alerts.json -------------------------------------------------
# Returns the last N alerts from ALERT_STATE_DIR/alerts.log, filtered by a
# window query param (?window=24h, 1d, 7d, today, all — same grammar as
# `milog alerts`). Default window is 24h, capped at 100 rows to keep the
# payload tight. Reads are best-effort: a missing/empty log returns an
# empty array, not an error — the panel is informational, not critical.
#
# Severity is derived from the Discord color int stored per row so the
# client can tint the RULE column without re-computing it.
_web_route_alerts() {
    local window="${1:-24h}" cap=100
    local log_file="$ALERT_STATE_DIR/alerts.log"

    local arr="[]"
    if [[ -f "$log_file" ]]; then
        local cutoff
        cutoff=$(_alerts_window_to_epoch "$window" 2>/dev/null) || cutoff=0
        # The filter + JSON-build runs entirely in awk so log files with tens
        # of thousands of rows don't fork-per-row in bash. Awk emits one JSON
        # object per surviving record (capped at `cap`), newline-separated,
        # which we then comma-join in pure bash.
        local raw
        raw=$(awk -F'\t' -v cutoff="$cutoff" -v cap="$cap" '
            function jesc(s,   r) {
                # Minimal JSON string escaper: backslash, quote, and control
                # chars. Tabs/newlines are already stripped on ingest by
                # _alert_record, but escape defensively in case an older
                # entry slipped through.
                gsub(/\\/, "\\\\", s)
                gsub(/"/,  "\\\"", s)
                gsub(/\n/, "\\n", s)
                gsub(/\r/, "\\r", s)
                gsub(/\t/, "\\t", s)
                return s
            }
            function sev(c) {
                if (c == 15158332 || c == 16711680) return "crit"
                if (c == 16753920 || c == 15844367) return "warn"
                return "info"
            }
            $1 >= cutoff && NF >= 5 {
                rows[++n] = $0
            }
            END {
                start = (n > cap) ? n - cap + 1 : 1
                for (i = start; i <= n; i++) {
                    split(rows[i], f, "\t")
                    printf "{\"ts\":%d,\"rule\":\"%s\",\"sev\":\"%s\",\"title\":\"%s\",\"body\":\"%s\"}\n",
                        f[1]+0, jesc(f[2]), sev(f[3]+0), jesc(f[4]), jesc(f[5])
                }
            }
        ' "$log_file" 2>/dev/null)
        if [[ -n "$raw" ]]; then
            # Join newline-separated objects with commas; no trailing comma.
            arr="[$(printf '%s' "$raw" | paste -sd, -)]"
        fi
    fi

    local body
    body=$(printf '{"window":%s,"alerts":%s}' \
        "$(json_escape "$window")" "$arr")
    _web_respond 200 "application/json" "$body"
}

# ---- route: / ---------------------------------------------------------------
# Single self-contained HTML page. CSS + JS inline. Polls /api/summary.json
# every N seconds with the token in the Authorization header. No external
# network requests; works offline on loopback.
_web_route_index() {
    # NOTE: we read the heredoc via `read -r -d ''` rather than
    # `body=$(cat <<'X' ... X)` because the command-substitution form still
    # tokenizes the body for single quotes even with a quoted delimiter —
    # one `doesn't` in a JS comment aborts the parse. read -d '' reads
    # until NUL (never present) so the whole heredoc lands in $body.
    local body=""
    IFS= read -r -d '' body <<'HTML' || true
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>MiLog</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; background:#0b0d10; color:#d6d9dc; font:14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
  header { display:flex; align-items:baseline; gap:1rem; padding:1rem 1.2rem; border-bottom:1px solid #1b1f24; }
  header h1 { margin:0; font-size:1.05rem; font-weight:600; letter-spacing:.05em; }
  header .ts { color:#6b7177; font-size:.85rem; }
  header .pill { margin-left:auto; padding:.1rem .5rem; border:1px solid #30363d; border-radius:.3rem; font-size:.8rem; }
  .pill.ok  { color:#3fb950; border-color:#1a7f37; }
  .pill.bad { color:#f85149; border-color:#da3633; }
  main { padding:1rem 1.2rem; display:grid; gap:1.5rem; max-width:1000px; margin:0 auto; }
  section h2 { margin:0 0 .6rem; font-size:.8rem; color:#8b949e; text-transform:uppercase; letter-spacing:.1em; font-weight:600; }
  .sys { display:grid; grid-template-columns: repeat(3, 1fr); gap:.8rem; }
  .sys .card { padding:.8rem 1rem; background:#10141a; border:1px solid #1b1f24; border-radius:.4rem; }
  .sys .lbl { color:#8b949e; font-size:.75rem; text-transform:uppercase; letter-spacing:.08em; }
  .sys .val { font-size:1.5rem; font-weight:600; margin-top:.1rem; }
  .sys .sub { color:#6b7177; font-size:.8rem; }
  .bar { margin-top:.5rem; height:6px; background:#1b1f24; border-radius:2px; overflow:hidden; }
  .bar > span { display:block; height:100%; background:#3fb950; transition:width .4s; }
  .bar > span.warn { background:#d29922; }
  .bar > span.crit { background:#f85149; }
  table { width:100%; border-collapse:collapse; font-size:.9rem; }
  th, td { text-align:left; padding:.45rem .6rem; border-bottom:1px solid #1b1f24; }
  th { color:#8b949e; font-weight:500; font-size:.75rem; text-transform:uppercase; letter-spacing:.1em; }
  th.n, td.n { text-align:right; font-variant-numeric: tabular-nums; }
  td.err4 { color:#d29922; }
  td.err5 { color:#f85149; }
  .sev-crit { color:#f85149; font-weight:600; }
  .sev-warn { color:#d29922; font-weight:600; }
  .sev-info { color:#3fb950; font-weight:600; }
  .alerts-head { display:flex; align-items:baseline; justify-content:space-between; margin-bottom:.6rem; gap:.8rem; }
  .alerts-head h2 { margin:0; }
  .alerts-head .meta { color:#6b7177; font-size:.75rem; margin-left:auto; }
  .alerts-head select { background:#10141a; color:#d6d9dc; border:1px solid #30363d; border-radius:.3rem; padding:.15rem .4rem; font:inherit; font-size:.8rem; }
  td.rule { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space:nowrap; }
  td.when { color:#8b949e; white-space:nowrap; font-variant-numeric: tabular-nums; }
  td.title { color:#d6d9dc; overflow:hidden; text-overflow:ellipsis; max-width:48ch; }
  .empty { color:#6b7177; padding:.6rem 0; }
  /* Scroll the alerts table inside its own box instead of growing the page.
     Max ~14 rows visible; header stays pinned while scrolling. */
  .table-scroll { max-height: 26rem; overflow-y: auto; border:1px solid #1b1f24; border-radius:.4rem; }
  .table-scroll table { border-collapse: separate; border-spacing: 0; }
  .table-scroll thead th { position: sticky; top: 0; background:#10141a; z-index: 1; border-bottom:1px solid #1b1f24; }
  .table-scroll tbody tr:last-child td { border-bottom: none; }
  /* Webkit scrollbar styling — matches the dark palette. Firefox uses
     scrollbar-color below. */
  .table-scroll::-webkit-scrollbar { width: 10px; }
  .table-scroll::-webkit-scrollbar-track { background: #0b0d10; }
  .table-scroll::-webkit-scrollbar-thumb { background: #30363d; border-radius: 5px; }
  .table-scroll::-webkit-scrollbar-thumb:hover { background: #484f58; }
  .table-scroll { scrollbar-color: #30363d #0b0d10; scrollbar-width: thin; }
  /* Log viewer histogram strip — N tiny bars that together form a
     per-minute activity timeline above the log table. */
  .histogram { display:flex; align-items:flex-end; gap:1px; height:32px; margin:.4rem 0 .6rem;
               background:#0b0d10; border:1px solid #1b1f24; border-radius:.3rem; padding:2px; }
  .histogram .bar { flex:1 1 auto; background:#3fb950; min-width:1px; border-radius:1px; transition:height .2s; }
  .histogram .bar.empty { background:#1b1f24; }
  .histogram .bar:hover { background:#58a6ff; }
  /* Logs table — denser than alerts since lines are higher volume. */
  #logs td { font-size:.82rem; padding:.25rem .5rem; }
  #logs td.ip  { color:#8b949e; font-variant-numeric: tabular-nums; white-space:nowrap; }
  #logs td.mth { color:#6b7177; white-space:nowrap; }
  #logs td.pth { color:#d6d9dc; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                 overflow:hidden; text-overflow:ellipsis; max-width:52ch; }
  #logs td.st2 { color:#3fb950; text-align:right; font-variant-numeric: tabular-nums; }
  #logs td.st3 { color:#8b949e; text-align:right; font-variant-numeric: tabular-nums; }
  #logs td.st4 { color:#d29922; text-align:right; font-variant-numeric: tabular-nums; }
  #logs td.st5 { color:#f85149; text-align:right; font-variant-numeric: tabular-nums; }
  footer { padding:1rem 1.2rem; color:#6b7177; font-size:.75rem; text-align:center; }
  .err { color:#f85149; padding:.6rem; border:1px solid #da3633; border-radius:.3rem; background:#2a1215; }
</style>
</head><body>
<header>
  <h1>MiLog</h1>
  <span class="ts" id="ts">—</span>
  <span class="pill" id="status">connecting…</span>
</header>
<main>
  <section>
    <h2>System</h2>
    <div class="sys">
      <div class="card"><div class="lbl">CPU</div><div class="val" id="cpu">—</div><div class="sub" id="cpu-sub">&nbsp;</div><div class="bar"><span id="cpu-bar" style="width:0"></span></div></div>
      <div class="card"><div class="lbl">Memory</div><div class="val" id="mem">—</div><div class="sub" id="mem-sub">&nbsp;</div><div class="bar"><span id="mem-bar" style="width:0"></span></div></div>
      <div class="card"><div class="lbl">Disk</div><div class="val" id="disk">—</div><div class="sub" id="disk-sub">&nbsp;</div><div class="bar"><span id="disk-bar" style="width:0"></span></div></div>
    </div>
  </section>
  <section>
    <h2>Nginx (last minute)</h2>
    <table id="apps">
      <thead><tr><th>APP</th><th class="n">REQ</th><th class="n">2xx</th><th class="n">3xx</th><th class="n">4xx</th><th class="n">5xx</th></tr></thead>
      <tbody><tr><td colspan="6">loading…</td></tr></tbody>
    </table>
  </section>
  <section>
    <div class="alerts-head">
      <h2>Recent alerts</h2>
      <span class="meta" id="alerts-count">—</span>
      <select id="alerts-window" aria-label="alerts window">
        <option value="1h">last 1h</option>
        <option value="24h" selected>last 24h</option>
        <option value="7d">last 7d</option>
        <option value="today">today</option>
        <option value="all">all</option>
      </select>
    </div>
    <div class="table-scroll">
      <table id="alerts">
        <thead><tr><th>WHEN</th><th>SEV</th><th>RULE</th><th>TITLE</th></tr></thead>
        <tbody><tr><td colspan="4" class="empty">loading…</td></tr></tbody>
      </table>
    </div>
  </section>
  <section>
    <div class="alerts-head">
      <h2>Logs (live tail)</h2>
      <span class="meta" id="logs-count">—</span>
      <select id="logs-app" aria-label="app"></select>
      <select id="logs-class" aria-label="status class">
        <option value="any" selected>any</option>
        <option value="2xx">2xx</option>
        <option value="3xx">3xx</option>
        <option value="4xx">4xx</option>
        <option value="5xx">5xx</option>
      </select>
      <input id="logs-grep" placeholder="grep…" style="background:#10141a;color:#d6d9dc;border:1px solid #30363d;border-radius:.3rem;padding:.15rem .4rem;font:inherit;font-size:.8rem;width:14ch;">
    </div>
    <div id="logs-histogram" class="histogram"></div>
    <div class="table-scroll">
      <table id="logs">
        <thead><tr><th>WHEN</th><th>IP</th><th>METHOD</th><th>PATH</th><th>STATUS</th></tr></thead>
        <tbody><tr><td colspan="5" class="empty">pick an app…</td></tr></tbody>
      </table>
    </div>
  </section>
  <section id="err-section" hidden><div class="err" id="err">&nbsp;</div></section>
</main>
<footer>read-only · loopback by default · <span id="meta-uptime">—</span></footer>
<script>
(function(){
  // Token handshake: first load accepts ?t=TOKEN, stashes in sessionStorage,
  // then strips query so the token doesn't remain in the URL bar or history.
  var q = new URLSearchParams(location.search);
  if (q.get('t')) {
    sessionStorage.setItem('milog_token', q.get('t'));
    history.replaceState({}, '', location.pathname);
  }
  var token = sessionStorage.getItem('milog_token');
  if (!token) {
    document.getElementById('status').textContent = 'no token';
    document.getElementById('status').classList.add('bad');
    document.getElementById('err-section').hidden = false;
    document.getElementById('err').textContent = 'No session token. Open the URL printed by `milog web` that includes ?t=…';
    return;
  }

  function api(path){
    return fetch(path, { headers: { 'Authorization': 'Bearer ' + token }, cache: 'no-store' })
      .then(function(r){ if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
  }

  function colour(pct) { return pct >= 90 ? 'crit' : pct >= 75 ? 'warn' : ''; }
  function setBar(id, pct) {
    var el = document.getElementById(id);
    el.className = colour(pct);
    el.style.width = Math.min(100, Math.max(0, pct)) + '%';
  }

  function render(s) {
    var sys = s.system || {};
    document.getElementById('ts').textContent = s.ts || '';
    document.getElementById('cpu').textContent  = (sys.cpu || 0) + '%';
    document.getElementById('mem').textContent  = (sys.mem_pct || 0) + '%';
    document.getElementById('disk').textContent = (sys.disk_pct || 0) + '%';
    document.getElementById('mem-sub').textContent  = (sys.mem_used_mb||0) + ' / ' + (sys.mem_total_mb||0) + ' MB';
    document.getElementById('disk-sub').textContent = (sys.disk_used_gb||0) + ' / ' + (sys.disk_total_gb||0) + ' GB';
    setBar('cpu-bar', sys.cpu || 0);
    setBar('mem-bar', sys.mem_pct || 0);
    setBar('disk-bar', sys.disk_pct || 0);

    var tbody = document.querySelector('#apps tbody');
    tbody.innerHTML = '';
    (s.apps || []).forEach(function(a){
      var tr = document.createElement('tr');
      function td(v, cls){ var c = document.createElement('td'); if (cls) c.className = cls; c.textContent = v; return c; }
      tr.appendChild(td(a.name));
      tr.appendChild(td(a.req,  'n'));
      tr.appendChild(td(a.c2xx, 'n'));
      tr.appendChild(td(a.c3xx, 'n'));
      tr.appendChild(td(a.c4xx, 'n ' + (a.c4xx > 0 ? 'err4' : '')));
      tr.appendChild(td(a.c5xx, 'n ' + (a.c5xx > 0 ? 'err5' : '')));
      tbody.appendChild(tr);
    });
    if (!(s.apps || []).length) {
      tbody.innerHTML = '<tr><td colspan="6">no apps</td></tr>';
    }

    var pill = document.getElementById('status');
    pill.textContent = 'live · total ' + (s.total_req || 0) + ' req/min';
    pill.className = 'pill ok';
    document.getElementById('err-section').hidden = true;
  }

  function tick() {
    api('/api/summary.json').then(render).catch(function(e){
      var pill = document.getElementById('status');
      pill.textContent = 'error';
      pill.className = 'pill bad';
      document.getElementById('err-section').hidden = false;
      document.getElementById('err').textContent = e.message + ' — check the token or that milog web is still running';
    });
  }

  api('/api/meta.json').then(function(m){
    document.getElementById('meta-uptime').textContent = 'host uptime: ' + (m.uptime || '?');
  }).catch(function(){ /* non-fatal */ });

  // ---- alerts panel ------------------------------------------------------
  // Refreshes slower than summary — alerts don't change every 3s, and
  // reading alerts.log is cheaper but still pointless at summary cadence.
  function fmtWhen(ts) {
    // ts is Unix epoch seconds. Local time, 24h.
    var d = new Date(ts * 1000);
    function pad(n){ return n < 10 ? '0' + n : '' + n; }
    return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate())
         + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function renderAlerts(d) {
    var tbody = document.querySelector('#alerts tbody');
    var meta = document.getElementById('alerts-count');
    tbody.innerHTML = '';
    var list = (d && d.alerts) || [];
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">no alerts in window</td></tr>';
      meta.textContent = '0 alerts';
      return;
    }
    meta.textContent = list.length + ' alert' + (list.length === 1 ? '' : 's');
    // Chronological order: server returns oldest→newest; reverse so newest first.
    list.slice().reverse().forEach(function(a){
      var tr = document.createElement('tr');
      function td(v, cls){ var c = document.createElement('td'); if (cls) c.className = cls; c.textContent = v; return c; }
      tr.appendChild(td(fmtWhen(a.ts), 'when'));
      var sev = document.createElement('td');
      sev.className = 'sev-' + (a.sev || 'info');
      sev.textContent = (a.sev || 'info').toUpperCase();
      tr.appendChild(sev);
      tr.appendChild(td(a.rule || '', 'rule'));
      tr.appendChild(td(a.title || '', 'title'));
      tbody.appendChild(tr);
    });
  }
  function tickAlerts() {
    var w = document.getElementById('alerts-window').value;
    api('/api/alerts.json?window=' + encodeURIComponent(w))
      .then(renderAlerts)
      .catch(function(){ /* non-fatal; summary tick already surfaces errors */ });
  }
  document.getElementById('alerts-window').addEventListener('change', tickAlerts);

  // ---- logs panel --------------------------------------------------------
  // Short-poll log viewer (tier 1). Every 5s it fetches /api/logs.json with
  // the current filters and /api/logs/histogram.json for the timeline.
  // Tier 2 (SSE live tail) is a Go feature on the roadmap.
  function fmtLogWhen(s) {
    // "[24/Apr/2026:12:34:56 +0000]" → "12:34:56"
    var m = /:(\d\d:\d\d:\d\d)/.exec(s || '');
    return m ? m[1] : (s || '');
  }
  function setLogsApp(apps) {
    var sel = document.getElementById('logs-app');
    if (sel.options.length) return;
    (apps || []).forEach(function(a){
      var opt = document.createElement('option');
      opt.value = a; opt.textContent = a;
      sel.appendChild(opt);
    });
    if (sel.options.length) sel.value = sel.options[0].value;
  }
  function renderLogs(d) {
    var tbody = document.querySelector('#logs tbody');
    var meta = document.getElementById('logs-count');
    tbody.innerHTML = '';
    var list = (d && d.lines) || [];
    meta.textContent = list.length + ' line' + (list.length === 1 ? '' : 's');
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">no matching lines</td></tr>';
      return;
    }
    list.slice().reverse().forEach(function(r){
      var tr = document.createElement('tr');
      function td(v, cls){ var c = document.createElement('td'); if (cls) c.className = cls; c.textContent = v; return c; }
      var stClass = 'st' + String(r.status || '').charAt(0);
      tr.appendChild(td(fmtLogWhen(r.ts), 'when'));
      tr.appendChild(td(r.ip || '', 'ip'));
      tr.appendChild(td(r.method || '', 'mth'));
      tr.appendChild(td(r.path || '', 'pth'));
      tr.appendChild(td(r.status, stClass));
      tbody.appendChild(tr);
    });
  }
  function renderHistogram(d) {
    var el = document.getElementById('logs-histogram');
    el.innerHTML = '';
    var buckets = (d && d.buckets) || [];
    if (!buckets.length) { el.innerHTML = '<div style="flex:1;color:#6b7177;text-align:center;font-size:.7rem;line-height:28px;">no activity</div>'; return; }
    var max = buckets.reduce(function(m,b){ return Math.max(m, b.c || 0); }, 1);
    buckets.forEach(function(b){
      var bar = document.createElement('div');
      var pct = Math.round(((b.c || 0) / max) * 100);
      bar.className = 'bar' + ((b.c || 0) === 0 ? ' empty' : '');
      bar.style.height = ((b.c || 0) === 0 ? 2 : Math.max(4, pct)) + '%';
      bar.title = b.t + '  ' + (b.c || 0) + ' req';
      el.appendChild(bar);
    });
  }
  function tickLogs() {
    var app = document.getElementById('logs-app').value;
    if (!app) return;
    var grep = document.getElementById('logs-grep').value;
    var cls = document.getElementById('logs-class').value;
    var q = 'app=' + encodeURIComponent(app) + '&limit=200';
    if (grep) q += '&grep=' + encodeURIComponent(grep);
    if (cls && cls !== 'any') q += '&class=' + encodeURIComponent(cls);
    api('/api/logs.json?' + q).then(renderLogs).catch(function(){});
  }
  function tickHistogram() {
    var app = document.getElementById('logs-app').value;
    if (!app) return;
    api('/api/logs/histogram.json?app=' + encodeURIComponent(app) + '&minutes=60')
      .then(renderHistogram).catch(function(){});
  }
  // Populate app select from meta.apps
  api('/api/meta.json').then(function(m){ setLogsApp(m.apps || []); tickLogs(); tickHistogram(); }).catch(function(){});
  ['logs-app','logs-class','logs-grep'].forEach(function(id){
    document.getElementById(id).addEventListener('change', function(){ tickLogs(); tickHistogram(); });
  });
  document.getElementById('logs-grep').addEventListener('input', function(){
    // Debounced-lite: just call tickLogs after keystrokes; 200 req/minute
    // ceiling on the server hasn't been hit at this scale.
    clearTimeout(window.__milog_grep_t);
    window.__milog_grep_t = setTimeout(tickLogs, 250);
  });
  setInterval(tickLogs, 5000);
  setInterval(tickHistogram, 30000);

  tick();
  tickAlerts();
  setInterval(tick, 3000);
  setInterval(tickAlerts, 15000);
})();
</script>
</body></html>
HTML
    _web_respond 200 "text/html" "$body"
}

# ---- per-connection handler --------------------------------------------------
# Called by socat/ncat once per TCP accept. Stdin is the raw client bytes,
# stdout flows back to the client. Parses the request line + headers,
# validates the token, routes to a handler.
_web_handle() {
    local request_line line method full_path version
    local path query_string="" auth="" token_provided="" client_ip="${SOCAT_PEERADDR:-$(echo "${NCAT_REMOTE_ADDR:-unknown}")}"

    # First line: "METHOD PATH HTTP/1.1\r\n"
    if ! IFS= read -r request_line; then
        return 0
    fi
    request_line="${request_line%$'\r'}"
    read -r method full_path version <<< "$request_line"

    # Only GET is supported; no mutation routes.
    if [[ "$method" != "GET" ]]; then
        _web_respond 405 "text/plain" "method not allowed"
        _web_access_log "$client_ip" "$method" "$full_path" 405
        return 0
    fi

    # Split path ? query.
    if [[ "$full_path" == *"?"* ]]; then
        path="${full_path%%\?*}"
        query_string="${full_path#*\?}"
    else
        path="$full_path"
    fi

    # Read remaining headers until empty line. Captures Authorization only.
    local hdr_count=0
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "$line" ]] && break
        (( ++hdr_count > 64 )) && { _web_respond 400 "text/plain" "too many headers"; return 0; }
        if [[ "$line" =~ ^[Aa]uthorization:[[:space:]]*Bearer[[:space:]]+([A-Za-z0-9]+) ]]; then
            auth="${BASH_REMATCH[1]}"
        fi
    done

    # Token: prefer Authorization header, then ?t= query.
    if [[ -n "$auth" ]]; then
        token_provided="$auth"
    elif [[ "$query_string" =~ (^|&)t=([A-Za-z0-9]+) ]]; then
        token_provided="${BASH_REMATCH[2]}"
    fi

    local expected; expected=$(_web_token_read 2>/dev/null)
    if [[ -z "$expected" || -z "$token_provided" || "$token_provided" != "$expected" ]]; then
        _web_respond 401 "text/plain" "unauthorized"
        _web_access_log "$client_ip" "$method" "$path" 401
        return 0
    fi

    case "$path" in
        /)                  _web_route_index;   _web_access_log "$client_ip" "$method" "$path" 200 ;;
        /api/summary.json)  _web_route_summary; _web_access_log "$client_ip" "$method" "$path" 200 ;;
        /api/meta.json)     _web_route_meta;    _web_access_log "$client_ip" "$method" "$path" 200 ;;
        /api/alerts.json)
            # Extract window=... from the query string (validated to the
            # grammar _alerts_window_to_epoch accepts; anything malformed
            # falls through to its default).
            local win=""
            if [[ "$query_string" =~ (^|&)window=([A-Za-z0-9]+) ]]; then
                win="${BASH_REMATCH[2]}"
            fi
            _web_route_alerts "$win"
            _web_access_log "$client_ip" "$method" "$path" 200
            ;;
        /api/logs.json)
            local qapp="" qlim="" qg="" qp="" qc=""
            [[ "$query_string" =~ (^|&)app=([A-Za-z0-9_.-]+) ]]   && qapp="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)limit=([0-9]+) ]]          && qlim="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)grep=([^&]+) ]]            && qg="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)path=([^&]+) ]]            && qp="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)class=(2xx|3xx|4xx|5xx|any) ]] && qc="${BASH_REMATCH[2]}"
            _web_route_logs "$qapp" "$qlim" "$qg" "$qp" "$qc"
            _web_access_log "$client_ip" "$method" "$path" 200
            ;;
        /api/logs/histogram.json)
            local qapp="" qmin=""
            [[ "$query_string" =~ (^|&)app=([A-Za-z0-9_.-]+) ]] && qapp="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)minutes=([0-9]+) ]]      && qmin="${BASH_REMATCH[2]}"
            _web_route_logs_histogram "$qapp" "$qmin"
            _web_access_log "$client_ip" "$method" "$path" 200
            ;;
        *)                  _web_respond 404 "text/plain" "not found"
                            _web_access_log "$client_ip" "$method" "$path" 404 ;;
    esac
}

_web_access_log() {
    local ip="$1" method="$2" path="$3" status="$4"
    mkdir -p "$WEB_STATE_DIR" 2>/dev/null
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(date -Iseconds 2>/dev/null || date)" "$ip" "$method" "$path" "$status" \
        >> "$WEB_ACCESS_LOG" 2>/dev/null || true
}

# ---- subcommands: start / stop / status --------------------------------------
_web_pid_file() { echo "$WEB_STATE_DIR/web.pid"; }

# Human-readable age of the web token file. Silent + empty on missing file.
# Tokens are read per-request from disk so they rotate "live" the moment
# the file changes — status just reports when it was last written.
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

# Rotate the web token — delete + regenerate. Safe to call while the
# daemon is running: token is read per-request from disk, so the next
# request after rotation rejects the old token with 401.
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
        echo -e "${D}  service is running — the running daemon will accept the new token on next request${NC}"
    fi
    echo -e "${D}  old browser tabs will see 401 until you reopen the URL above${NC}"
}

# Is the systemd user unit currently active? Returns 0 if yes.
# Guarded so callers on non-systemd hosts short-circuit to "no".
_web_systemd_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl --user is-active --quiet milog-web.service 2>/dev/null
}

_web_status() {
    # Report systemd state first — it's the "installed service" path, which
    # is how most users will run it after install-service. Falls through to
    # pidfile for the foreground/nohup case.
    if _web_systemd_active; then
        local main_pid; main_pid=$(systemctl --user show --value -p MainPID milog-web.service 2>/dev/null)
        echo -e "${G}running${NC}  (systemd user unit)  pid=${main_pid:-?}  bind=${WEB_BIND}:${WEB_PORT}"
        echo -e "${D}  unit:  ${HOME}/.config/systemd/user/milog-web.service${NC}"
        echo -e "${D}  logs:  journalctl --user -u milog-web.service -f${NC}"
        echo -e "${D}  token: $WEB_TOKEN_FILE  (age $(_web_token_age))${NC}"
        if [[ -f "$WEB_ACCESS_LOG" ]]; then
            local hits; hits=$(wc -l < "$WEB_ACCESS_LOG" 2>/dev/null || echo 0)
            echo -e "${D}  ${hits} requests served (total)${NC}"
        fi
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
    echo -e "${D}  access log: $WEB_ACCESS_LOG${NC}"
    if [[ -f "$WEB_ACCESS_LOG" ]]; then
        local hits; hits=$(wc -l < "$WEB_ACCESS_LOG" 2>/dev/null || echo 0)
        echo -e "${D}  ${hits} requests served${NC}"
    fi
    return 0
}

_web_stop() {
    # If the systemd unit is up, stop it via systemctl — direct kill would
    # trigger Restart=on-failure and spawn a replacement.
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
        # Kill the whole process group so socat/ncat children die too.
        kill -TERM -- -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        sleep 0.3
        kill -KILL -- -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        echo -e "${G}stopped${NC}  pid=$pid"
    else
        echo -e "${Y}pidfile stale; cleaning${NC}"
    fi
    rm -f "$pf"
}

# ==============================================================================
# MODE: alert — toggle alerting + manage the systemd service
#
# Subcommands:
#   on [WEBHOOK_URL]  — set Discord webhook (optional), enable, install+start systemd
#   off               — disable alerts, stop + disable systemd
#   status            — show destinations / service / recent-fire state
#   test              — fire a one-off alert to EVERY configured destination
#                       (Discord + Slack + Telegram + Matrix), bypassing
#                       cooldown and ALERTS_ENABLED. Any silent channel is
#                       a wire issue, not config.
#
# `milog alert on` wires only Discord (historical default). Other
# destinations are opt-in via config file or env var — see docs/alerts.md.
#
# When invoked via sudo, we write config into the *invoking* user's home
# (resolved from SUDO_USER) and run the systemd service as that user — not
# as root. Matches user intuition: `sudo milog alert on` sets up alerting
# for the person who ran it, not for root.
# ==============================================================================

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

# Upsert a single KEY=VALUE line in the target user's config file. Handles
# dir creation + ownership fix when running as root on behalf of a user.
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
    # Fix ownership so the target user can read/edit their own config when
    # the write happened as root.
    if [[ $(id -u) -eq 0 && "$target_user" != "root" ]]; then
        chown -R "$target_user:$target_user" "$dir" 2>/dev/null || true
    fi
}

# Read DISCORD_WEBHOOK from a config file (strips surrounding quotes).
# Always returns 0 and emits empty string when the config doesn't exist or
# doesn't set the key — keeps callers simple under `set -euo pipefail`.
_alert_read_webhook() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    {
        grep -E '^[[:space:]]*DISCORD_WEBHOOK=' "$file" 2>/dev/null \
            | head -1 \
            | sed -E 's/^[^=]*=//; s/^"//; s/"[[:space:]]*$//'
    } || true
    return 0
}

# Read the (possibly multiline) ALERT_ROUTES value from a config file.
# Sources the file in a subshell to get the real bash-parsed value, then
# echoes it. `_alert_read_key` grep-hack can't handle heredoc-style
# multiline assignments, so routing gets its own helper.
#
# Silent + empty on any error — caller treats empty as "no routing".
_alert_read_routes() {
    local file="$1"
    [[ -r "$file" ]] || return 0
    # Subshell insulation: ALERT_ROUTES from the target config overrides
    # any env-loaded value only for the duration of this subshell.
    ( set +u; ALERT_ROUTES=""; . "$file" 2>/dev/null; printf '%s' "$ALERT_ROUTES" ) || true
}

# Read a simple KEY's value from the config file — same no-fail contract.
_alert_read_key() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    {
        grep -E "^[[:space:]]*${key}=" "$file" 2>/dev/null \
            | head -1 \
            | sed -E 's/^[^=]*=//; s/^"//; s/"[[:space:]]*$//'
    } || true
    return 0
}

# Write + enable the milog systemd unit. Caller must already be root.
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

# Short human-readable duration — "12s", "3m", "5h", "2d".
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

    local current_webhook
    current_webhook=$(_alert_read_webhook "$target_config")
    if [[ -z "$current_webhook" ]]; then
        echo -e "${R}no DISCORD_WEBHOOK configured in $target_config${NC}" >&2
        echo "  pass one:  milog alert on 'https://discord.com/api/webhooks/ID/TOKEN'" >&2
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

    # Read all destinations from the target config. Done via _alert_read_key
    # (not env) so `sudo milog alert status` shows alice's real config,
    # not root's. Empty strings when unset.
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

    # Routing block — only shown when ALERT_ROUTES is configured. Reads the
    # full block from the target config (not env) for the same sudo-vs-user
    # reason as destinations above.
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

    # Pull every destination from the target-user's config file, not the
    # env this process started with. Makes `sudo milog alert test` test
    # alice's full fanout (Discord + Slack + Telegram + Matrix + Webhook),
    # not just whatever happens to live in root's env.
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

    # Track which destinations will actually fire so we can print a
    # per-destination line. Mirrors the readiness logic in each
    # _alert_send_* guard.
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

    # Swap every destination var into the process env so alert_fire's
    # fanout picks them all up. Saved + restored so a subsequent interactive
    # alert (same bash session) still sees the original state. Force
    # ALERTS_ENABLED=1 — test bypasses the master switch by design.
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
    # Empty template / ctype from target config → keep the process defaults.
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
  ${C}milog alert on [WEBHOOK_URL]${NC}  enable alerts (Discord); install + start systemd
  ${C}milog alert off${NC}                disable alerts; stop + disable service
  ${C}milog alert status${NC}             show destinations/service/recent-fire state
  ${C}milog alert test${NC}               fire one test alert to EVERY configured
                              destination (Discord + Slack + Telegram + Matrix)

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
        -h|--help|help) alert_help ;;
        *) echo -e "${R}Unknown alert subcommand:${NC} $sub"; alert_help; exit 1 ;;
    esac
}

# ==============================================================================
# MODE: alerts — read the local alert history log
#
# The log itself is appended to by `_alert_record` (called from
# `alert_discord`) — one TSV row per fired alert. This mode presents the
# "what fired overnight? / this week?" view that was previously
# unanswerable (the cooldown state file tracks last-fire per rule but
# not history).
#
# Window grammar:
#   today        since local midnight today
#   yesterday    24h window ending at today's midnight
#   all          no cutoff
#   <N>m         last N minutes
#   <N>h         last N hours
#   <N>d         last N days
#   <N>w         last N weeks
# Default: today.
#
# Log file:       $ALERT_STATE_DIR/alerts.log
# Rotation:       automatic, in-place, on each append. When the file
#                 exceeds ALERT_LOG_MAX_BYTES (default 10 MB) it's truncated
#                 to ~50% keeping the most recent records. No `.1` backup.
#                 Set ALERT_LOG_MAX_BYTES=0 to disable.
# ==============================================================================

# Parse a window spec (today/yesterday/all/Nh/Nd/Nw) to a Unix epoch cutoff.
# Echoes the cutoff on success; non-zero exit + stderr message on invalid
# input. Separated from mode_alerts so tests can exercise it independently.
_alerts_window_to_epoch() {
    local w="$1"
    local now; now=$(date +%s)
    case "$w" in
        today)
            # Local midnight today — (now % 86400) is seconds since UTC
            # midnight, not local, but on most servers localtime=UTC and it
            # doesn't meaningfully drift. Precise-to-the-timezone is overkill
            # for an "alerts today" view.
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

# Human-readable timestamp from epoch, portable across GNU/BSD date.
# Used for the WHEN column in the table.
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

    local cutoff cutoff_fmt
    cutoff=$(_alerts_window_to_epoch "$window") || return 1
    cutoff_fmt=$(_alerts_fmt_epoch "$cutoff")

    echo -e "\n${W}── MiLog: Alerts since ${cutoff_fmt} (window=$window) ──${NC}\n"

    # Filter once by epoch, feed the result to both the list and the summary.
    local filtered; filtered=$(mktemp -t milog_alerts.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$filtered'" RETURN

    awk -F'\t' -v cutoff="$cutoff" '$1 >= cutoff' "$log_file" > "$filtered"

    local total; total=$(wc -l < "$filtered" | tr -d ' ')
    total=${total:-0}

    if (( total == 0 )); then
        echo -e "  ${D}no alerts in window${NC}\n"
        return 0
    fi

    # --- Timeline (last ~30 rows, chronological) ---------------------------
    # Most recent is most relevant, but humans read top-down and expect
    # chronological order. Cap at 30 so the table stays glanceable.
    local list_cap=30
    local shown=$total
    (( shown > list_cap )) && shown=$list_cap
    echo -e "  ${W}timeline${NC} ${D}(showing latest ${shown} of ${total})${NC}"
    printf "  %-16s  %-28s  %s\n" "WHEN" "RULE" "TITLE"
    printf "  %-16s  %-28s  %s\n" "────────────────" "────────────────────────────" "──────"

    # Per-row format in bash — calling _alerts_fmt_epoch (which forks date)
    # inside awk's strftime is gawk-only; BSD awk on macOS lacks strftime.
    # 30 row cap keeps the fork count trivial.
    local epoch rule color title body when rule_disp title_disp col
    while IFS=$'\t' read -r epoch rule color title body; do
        [[ -z "$epoch" ]] && continue
        when=$(_alerts_fmt_epoch "$epoch")
        rule_disp="$rule"
        (( ${#rule_disp} > 28 )) && rule_disp="${rule_disp:0:25}..."
        title_disp="$title"
        (( ${#title_disp} > 50 )) && title_disp="${title_disp:0:47}..."
        # Color the rule column by severity (derived from Discord color int):
        #   15158332 / 16711680 → crit  (red)    — exploits, 5xx, sys crit
        #   16753920 / 15844367 → warn  (yellow) — 4xx spike, probes
        #   other               → info  (green)  — test alert etc.
        case "$color" in
            15158332|16711680)    col="$R" ;;
            16753920|15844367)    col="$Y" ;;
            *)                    col="$G" ;;
        esac
        printf "  %-16s  %b%-28s%b  %s\n" "$when" "$col" "$rule_disp" "$NC" "$title_disp"
    done < <(tail -n "$list_cap" "$filtered")

    # --- Summary by rule ----------------------------------------------------
    echo -e "\n  ${W}by rule (top 10)${NC}"
    awk -F'\t' '{c[$2]++} END {for (r in c) printf "%d\t%s\n", c[r], r}' "$filtered" \
        | sort -rn | head -n 10 \
        | awk -F'\t' '{printf "    %5d  %s\n", $1, $2}'

    echo -e "\n  ${D}total: $total alert(s) in window — log at $log_file${NC}\n"
}
# ==============================================================================
# MODE: attacker <IP> — forensic view of one IP's activity across all apps
#
# Used during/after an incident: given an IP pulled from `milog top`,
# `milog suspects`, a Discord alert, or a fail2ban ban event — this mode
# shows everything that IP did, across all configured apps, in one report.
#
# Output sections (in order):
#   1. Header:         ip, geo country, scan window
#   2. Summary:        total hits, first-seen, last-seen, unique apps
#   3. Per-app:        hits / 4xx / 5xx per app
#   4. Top paths:      most-requested URLs (query strings stripped)
#   5. Top UAs:        distinct user-agents, ranked
#   6. Classification: exploit vs probe vs normal distribution
#   7. Sample:         first 3 + last 3 raw loglines for context
#
# Scope: reads current `.access.log` files only. Rotated logs (.1, .gz)
# are ignored — run multiple times with different `LOG_DIR` overrides if
# you need older data, or add a --archives flag later.
#
# IP is passed through a character-class regex guard (digits / hex / . / :)
# before it ever reaches grep, so an attacker can't inject regex metachars
# via, say, a webhook-triggered invocation. grep uses -F for fixed-string
# matching too.
# ==============================================================================
mode_attacker() {
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        echo -e "${R}usage: milog attacker <IP>${NC}" >&2
        echo -e "${D}  scans all apps' current access.log for one IP's activity${NC}" >&2
        return 1
    fi
    # Allow v4 (dots + digits) and v6 (hex + colons). Reject everything else
    # so no regex metacharacter ever reaches awk/grep.
    if [[ ! "$ip" =~ ^[0-9a-fA-F:.]+$ ]]; then
        echo -e "${R}invalid IP: $ip${NC}" >&2
        return 1
    fi

    # Gather files.
    local files=() name
    for name in "${LOGS[@]}"; do
        [[ -f "$LOG_DIR/$name.access.log" ]] && files+=("$LOG_DIR/$name.access.log")
    done
    if (( ${#files[@]} == 0 )); then
        echo -e "${R}no readable app logs in $LOG_DIR${NC}" >&2
        return 1
    fi

    # Tmp: one tab-separated row per request: "<app>\t<raw_logline>".
    local tmp; tmp=$(mktemp -t milog_attacker.XXXXXX) || return 1
    # Use RETURN trap so tmp is cleaned even on a `return` path below.
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    # Stream each app's log, keep only lines where field 1 == $ip. awk's
    # exact-field match beats grep here — avoids matching "10.0.0.10" when
    # probing for "10.0.0.1".
    for name in "${LOGS[@]}"; do
        local f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] || continue
        awk -v ip="$ip" -v app="$name" '$1 == ip { print app "\t" $0 }' "$f" >> "$tmp"
    done

    local total; total=$(wc -l < "$tmp" | tr -d ' ')
    total=${total:-0}

    # --- Header --------------------------------------------------------------
    local country=""
    country=$(geoip_country "$ip" 2>/dev/null || true)
    local tag=""
    [[ -n "$country" && "$country" != "--" ]] && tag="  ${D}[${country}]${NC}"

    echo -e "\n${W}── MiLog: Attacker — ${ip}${tag}${W} ──${NC}\n"

    if (( total == 0 )); then
        echo -e "  ${D}No requests from ${ip} in any configured app.${NC}\n"
        return 0
    fi

    # --- Summary -------------------------------------------------------------
    # Timestamp extraction: portable awk (POSIX match returns RSTART/RLENGTH —
    # the gawk-only 3-arg form breaks on BSD awk / mawk).
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

    # --- Per-app breakdown ---------------------------------------------------
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

    # --- Top paths -----------------------------------------------------------
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

    # --- Top user-agents -----------------------------------------------------
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

    # --- Classification ------------------------------------------------------
    # Substring-matched against the path — cheap, deterministic, close enough
    # for "is this exploit/probe traffic?" not "CVE-level precision".
    # Categories mirror src/alerts.sh::_exploit_category.
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

    # --- Sample loglines -----------------------------------------------------
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
# ==============================================================================
# MODE: audit — point-in-time host integrity scans
#
# Today: file integrity monitoring (FIM). SHA256 baseline of a configurable
# watchlist (AUDIT_FIM_PATHS) re-checked on a timer. Drift fires
# `audit:fim:<path>` through the existing alert path — silence + cooldown
# + dedup all apply for free.
#
# Layout: `audit` is the umbrella subcommand. `fim` is the first scanner;
# more land beside it (persistence diff, listening-port baseline, SSH key
# audit, rootkit hints) without renaming anything.
#
# Storage: $ALERT_STATE_DIR/audit/fim.baseline (TSV, one row per path)
#   <path>\t<sha256>\t<mtime_epoch>\t<size_bytes>\t<recorded_epoch>
# Special sha256 value `MISSING` means the path was absent at baseline
# time — alerts fire when an absent path subsequently appears.
# ==============================================================================

# --- helpers ------------------------------------------------------------------

# Portable sha256 of one file. Returns the hex digest on stdout, empty on
# error (unreadable / nonexistent). Avoids forking the same binary
# differently across distros.
_audit_sha256() {
    local path="$1"
    [[ -r "$path" ]] || return 0
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$path" 2>/dev/null | awk '{print $1; exit}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$path" 2>/dev/null | awk '{print $1; exit}'
    fi
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

_audit_state_dir() {
    local d="${ALERT_STATE_DIR:-$HOME/.cache/milog}/audit"
    mkdir -p "$d" 2>/dev/null
    printf '%s' "$d"
}

# Expand AUDIT_FIM_PATHS with shell globbing into a deduped, sorted list of
# concrete paths. Patterns that match nothing contribute the literal
# pattern itself — so a watchlist entry pointing at a path that doesn't
# exist yet is still tracked (and fires the moment it does appear).
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
            # No match — keep the literal pattern so absence is auditable.
            # (Globless paths fall through here too — `/etc/shadow` with no
            # glob chars matches itself if present, lands in this branch
            # otherwise.)
            out+=("$pat")
        fi
    done
    shopt -u nullglob
    # Dedupe + sort for stable diff output.
    printf '%s\n' "${out[@]}" | sort -u
}

# --- baseline / check ---------------------------------------------------------

# (Re)build the FIM baseline from the current filesystem state. Overwrites
# the previous baseline. No alerts fire — this is the "I trust the host
# right now" moment. Use `milog audit fim check` to compare against the
# baseline later.
_audit_fim_baseline() {
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
    # Stdout: `<count_present> <count_missing> <path>` — read with
    # `read present missing path` in the caller. Three fields on one
    # line dodges the subshell-scope problem that bites globals when
    # this function is invoked via $().
    printf '%d %d %s\n' "$count" "$missing" "$out"
}

# Compare current state against the baseline. Stdout: one line per
# drifted path, format `<change>\t<path>\t<old>→<new>`. Change types:
#   MODIFIED   sha256 differs
#   APPEARED   was MISSING, now present
#   REMOVED    was present, now MISSING
#   UNREADABLE was readable, now denied (perm change is itself signal)
# Empty stdout = no drift.
_audit_fim_diff() {
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/fim.baseline"
    [[ -f "$baseline" ]] || return 1

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
                # Was perm-blocked at baseline, now readable — record as
                # APPEARED-equivalent so the operator sees the new content.
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

# Daemon-side periodic check. Auto-baselines on first run (no alerts);
# later runs alert on drift. Throttled by AUDIT_FIM_INTERVAL via an
# epoch marker file so multiple daemon ticks per minute don't all hash.
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

    if [[ ! -f "$baseline" ]]; then
        # First run: silently baseline. The user's own
        # `milog audit fim check` is how to verify the watchlist —
        # surprise-firing on the first daemon tick would be noise.
        # We discard the count line; the daemon doesn't print it.
        _audit_fim_baseline >/dev/null 2>&1
        printf '%s' "$now" > "$marker"
        return 0
    fi

    # Drift check; one alert per drifted path.
    local change path detail key body
    while IFS=$'\t' read -r change path detail; do
        [[ -z "$change" ]] && continue
        key="audit:fim:$change:$path"
        if alert_should_fire "$key"; then
            body="\`\`\`$change $path $detail\`\`\`"
            alert_fire "FIM drift: $change $path" "$body" 15158332 "$key" &
        fi
    done < <(_audit_fim_diff)

    printf '%s' "$now" > "$marker"
}

# --- user-facing subcommands --------------------------------------------------

mode_audit() {
    case "${1:-}" in
        ""|help|--help|-h) _audit_help ;;
        fim) shift; _audit_fim_subcmd "$@" ;;
        persistence) shift; _audit_persistence_subcmd "$@" ;;
        ports) shift; _audit_ports_subcmd "$@" ;;
        *)
            echo -e "${R}unknown audit subcommand: $1${NC}" >&2
            _audit_help; return 1 ;;
    esac
}

_audit_help() {
    cat <<EOF
${W}milog audit${NC} — point-in-time host integrity scans

  ${C}milog audit fim ${NC}<sub>          file integrity (SHA256 drift on watched files)
  ${C}milog audit persistence ${NC}<sub>  re-entry surface diff (new cron / systemd units / rc.local)
  ${C}milog audit ports ${NC}<sub>        listening-port baseline (new TCP/UDP listeners)

  Subs (all): ${C}baseline${NC} | ${C}check${NC} | ${C}status${NC}

The watcher runs inside ${C}milog daemon${NC} when ${C}AUDIT_ENABLED=1${NC} —
auto-baselines on first run, then fires ${C}audit:fim:<change>:<path>${NC},
${C}audit:persistence:APPEARED:<path>${NC}, or ${C}audit:ports:NEW:<proto>:<port>${NC}
on every subsequent drift.

Watchlists: ${C}AUDIT_FIM_PATHS${NC} / ${C}AUDIT_PERSISTENCE_PATHS${NC}. Glob patterns OK.
Listening-port scan reads from ${C}ss${NC} (or ${C}netstat${NC} fallback).
EOF
}

_audit_fim_subcmd() {
    case "${1:-status}" in
        baseline)
            local present missing path
            read -r present missing path < <(_audit_fim_baseline)
            echo -e "${G}baseline${NC} written to ${C}$path${NC}"
            echo -e "  ${D}tracked: ${present:-0} present, ${missing:-0} missing${NC}"
            ;;
        check)
            local dir; dir=$(_audit_state_dir)
            if [[ ! -f "$dir/fim.baseline" ]]; then
                echo -e "${Y}no baseline yet — run \`milog audit fim baseline\` first${NC}"
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

# ==============================================================================
# Persistence diff — file-existence drift across the classic re-entry surface
# (cron drops, systemd units, rc.local, ld.so.preload). Tracks "did a file
# appear that wasn't there before?" — the high-signal half of post-compromise
# scanning. Hash-drift on existing files is FIM's job; this scanner watches
# directories where attackers DROP NEW FILES.
#
# Storage: $ALERT_STATE_DIR/audit/persistence.baseline (TSV)
#   <path>\t<size>\t<mtime_epoch>\t<recorded_epoch>
#
# Drift policy:
#   APPEARED  fires alert. Sysadmin adding a unit usually goes through
#             config management; a new file in /etc/cron.d/ that wasn't
#             planned is exactly what we want to know about.
#   REMOVED   informational on `check` output but does NOT alert. Pruning
#             stale units is normal sysadmin housekeeping.
# ==============================================================================

_audit_persistence_expand() {
    local pat path
    local -a out=()
    shopt -s nullglob
    for pat in "${AUDIT_PERSISTENCE_PATHS[@]}"; do
        local -a matches=( $pat )
        if (( ${#matches[@]} > 0 )); then
            for path in "${matches[@]}"; do
                # Skip directories — cron drops and systemd units are files.
                # A bare directory entry from the glob would match every
                # daemon tick and produce no useful baseline.
                [[ -d "$path" ]] && continue
                out+=("$path")
            done
        fi
        # Globs that match nothing contribute zero entries — different from
        # FIM where literal-tracked-as-absent is desirable. For persistence
        # we only care about presence; a never-populated /etc/cron.d/ tree
        # is the steady state, not signal.
    done
    shopt -u nullglob
    printf '%s\n' "${out[@]}" | sort -u
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

# Diff current vs baseline. Stdout: `<change>\t<path>` per line.
# Changes: APPEARED, REMOVED. APPEARED fires alerts; REMOVED is shown
# in `check` output but doesn't fire.
_audit_persistence_diff() {
    local dir; dir=$(_audit_state_dir)
    local baseline="$dir/persistence.baseline"
    [[ -f "$baseline" ]] || return 1

    local current; current=$(mktemp "$dir/persistence.current.XXXXXX") || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$current'" RETURN
    _audit_persistence_expand > "$current"

    # comm needs sorted inputs. Strip baseline to its path column first.
    local sorted_baseline; sorted_baseline=$(mktemp "$dir/persistence.sortedb.XXXXXX") || return 1
    awk -F'\t' '{print $1}' "$baseline" | sort -u > "$sorted_baseline"

    # APPEARED: in current, not in baseline.
    comm -23 "$current" "$sorted_baseline" | awk '{print "APPEARED\t" $0}'
    # REMOVED: in baseline, not in current.
    comm -13 "$current" "$sorted_baseline" | awk '{print "REMOVED\t" $0}'

    rm -f "$sorted_baseline"
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

    # Only APPEARED entries fire — REMOVED is intentional silent (housekeeping).
    local change path key body
    while IFS=$'\t' read -r change path; do
        [[ "$change" == "APPEARED" ]] || continue
        [[ -z "$path" ]] && continue
        key="audit:persistence:APPEARED:$path"
        if alert_should_fire "$key"; then
            body="\`\`\`new file in re-entry surface: $path\`\`\`"
            alert_fire "Persistence: new $path" "$body" 15158332 "$key" &
        fi
    done < <(_audit_persistence_diff)

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

# ==============================================================================
# Listening-port baseline — snapshot every TCP/UDP listener at first run,
# diff each subsequent tick. NEW listener fires; gone listener is silent
# (services restart routinely; the brief gap shouldn't page anyone).
#
# Storage: $ALERT_STATE_DIR/audit/ports.baseline (TSV)
#   <proto>\t<bind>\t<port>\t<recorded>
#
# Capture: prefers `ss -tulnH` (iproute2). Falls back to `netstat -tunl`
# on hosts where ss isn't available — same fields, slower. PID/process
# columns intentionally NOT captured: `ss -p` requires CAP_NET_ADMIN /
# root and we never escalate ourselves; the bind+port tuple is enough
# to fire the alert and let the operator investigate with `lsof -i`.
# ==============================================================================

# Capture current listeners as TSV `<proto>\t<bind>\t<port>` rows.
# Output is sorted+deduped so set-diff against baseline is straight `comm`.
_audit_ports_capture() {
    if command -v ss >/dev/null 2>&1; then
        # `-H` (no header) is iproute2-recent; older versions ignore it
        # and emit a header row that the awk filter below drops anyway.
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
    # Both missing → empty stdout. Caller treats that as "no listeners",
    # which is not great signal — but not our problem to fix; install a
    # tools layer.
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

# Diff current vs baseline. Stdout: `<change>\t<proto>\t<bind>\t<port>` per
# line. Changes: NEW (in current, not baseline), GONE (in baseline, not
# current). Only NEW fires alerts.
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

    local change proto bind port key body
    while IFS=$'\t' read -r change proto bind port; do
        [[ "$change" == "NEW" ]] || continue
        [[ -z "$proto" || -z "$port" ]] && continue
        key="audit:ports:NEW:$proto:$port"
        if alert_should_fire "$key"; then
            body="\`\`\`new listener: $proto $bind:$port\`\`\`"
            alert_fire "Listener: new $proto $bind:$port" "$body" 15158332 "$key" &
        fi
    done < <(_audit_ports_diff)

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
# ==============================================================================
# MODE: auto-tune — suggest thresholds from history baselines
#
# Picks thresholds that would have fired ~rarely on your actual traffic
# instead of making users guess "what's a reasonable 5xx/min for this box?".
# Reads metrics_minute over a recent window and prints:
#   1) side-by-side table of CURRENT vs SUGGESTED
#   2) a copy-paste block of `milog config set …` commands
#
# Percentile picks:
#   THRESH_REQ_WARN  = p90(req)       — alert on the top 10% of minutes
#   THRESH_REQ_CRIT  = p99(req)       — alert on clear outliers
#   THRESH_4XX_WARN  = p95(c4xx)      — floor at 5 so tiny clients don't spam
#   THRESH_5XX_WARN  = p95(c5xx)      — floor at 1 (any 5xx > 0 is worth a ping)
#   P95_WARN_MS      = p75(p95_ms)    — warn when current p95 worse than 3-in-4 historical minutes
#   P95_CRIT_MS      = p99(p95_ms)    — crit on top 1% latency outliers
#
# CPU/MEM/DISK are not in the DB, so those thresholds aren't tuned here.
# ==============================================================================

# Stdin-to-percentile helper: read newline-separated numbers, print the
# p-th percentile (1..100) using the existing `sort -n | awk positional`
# idiom (same logic as percentiles() but for a generic stream).
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

# Format one table row. Visual widths: METRIC(20) CURRENT(11) SUGGESTED(11) DELTA(9)
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

mode_auto_tune() {
    local days="${1:-7}"
    [[ "$days" =~ ^[1-9][0-9]*$ ]] \
        || { echo -e "${R}auto-tune: days must be a positive integer${NC}" >&2; return 1; }

    _history_precheck || return 1

    local now since count
    now=$(date +%s)
    since=$(( now - days * 86400 ))
    count=$(sqlite3 "$HISTORY_DB" \
        "SELECT COUNT(*) FROM metrics_minute WHERE ts >= $since;" 2>/dev/null || echo 0)
    [[ "$count" =~ ^[0-9]+$ ]] || count=0

    echo -e "\n${W}── MiLog: auto-tune (window=${days}d, ${count} rows) ──${NC}\n"

    # 100 rows ≈ 100 minutes ≈ 1.6h of data — anything less and percentiles
    # are too noisy to base thresholds on.
    if (( count < 100 )); then
        echo -e "${R}Not enough history (${count} rows — need ≥100).${NC}"
        echo -e "${D}  let 'milog daemon' run for a few hours with HISTORY_ENABLED=1,${NC}"
        echo -e "${D}  or widen the window: milog auto-tune 30${NC}\n"
        return 1
    fi

    # Pull each metric's samples once. Filtering req>0 excludes quiet-hour
    # zeros so the percentile reflects real traffic — otherwise a mostly-idle
    # server would suggest THRESH_REQ_WARN=0.
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

    # Floors so "empty" days don't suggest zeros that fire on any activity.
    [[ "$s_c4_warn"  =~ ^[0-9]+$ ]] && (( s_c4_warn  < 5 )) && s_c4_warn=5
    [[ "$s_c5_warn"  =~ ^[0-9]+$ ]] && (( s_c5_warn  < 1 )) && s_c5_warn=1
    [[ "$s_req_warn" =~ ^[0-9]+$ ]] && (( s_req_warn < 5 )) && s_req_warn=5

    # Fall back to blank when we had zero samples for a metric (no timed
    # traffic at all means p95 tuning is impossible).
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

    # Ready-to-apply block — skip lines we couldn't tune.
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

# ==============================================================================
# MODE: bench — synthetic log fixtures + timing harness
#
# Measures what affects user-perceived latency of the common modes:
#   - tail scan throughput at 10k / 100k / 1M lines
#   - `slow` + `top-paths` end-to-end against a known fixture
#   - `search` throughput including archive read path
#
# Output is a short report plus a machine-readable TSV so CI can compare to
# a committed baseline (tools/bench-baseline.tsv). Regression >20% fails.
#
# Usage:
#   milog bench               # quick run (10k + 100k lines)
#   milog bench --full        # adds 1M-line pass (slower, more stable)
#   milog bench --baseline F  # write baseline TSV to F
# ==============================================================================

_bench_gen_fixture() {
    local dst="$1" n="$2"
    # Vary IP, path, status, latency to exercise grouping + percentile paths.
    # 80 distinct paths, ~200 distinct IPs, 90/8/2 status class split.
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
    # Portable millisecond timer. Falls back to second granularity on
    # hosts without nanosecond `date`.
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
    # Also emit TSV for baseline/CI comparison.
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

    # Export tsv target so _bench_run_one writes machine-readable rows.
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

        # Run as milog modes against the fixture.
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
# ==============================================================================
# MODE: completions — install shell completion files
#
# Static completion scripts live under completions/ in the repo, baked into
# the milog bundle. This mode extracts them back out to the user's shell
# lookup paths. Two flavours:
#
#   milog completions install      # drop to /usr/share or ~/.local
#   milog completions <shell>      # print a single shell's completion to stdout
#                                    (for curl-pipe-bash install paths)
#
# Supported: bash / zsh / fish.
# ==============================================================================

# Embedded completion payloads live in the bundled milog.sh, written there
# by build.sh from completions/*.  Here we extract them via heredocs — the
# content is literally duplicated because bash can't do "read this file
# from inside the bundle" without the source layout.
#
# To stay DRY, we ship a sentinel approach: each completion body lives in
# its own helper below. If a user is on a clone (bundle built from src/),
# we defer to completions/*. Otherwise we use the fallback bodies.

_completions_src_dir() {
    # Return the repo's completions/ dir if we're running from a clone and
    # it exists; empty otherwise.
    local me self_dir
    me="${BASH_SOURCE[0]:-$0}"
    [[ -n "$me" && -f "$me" ]] || return 1
    self_dir=$(cd -P "$(dirname "$me")" 2>/dev/null && pwd) || return 1
    # Walk up — src/modes/completions.sh → repo/completions; or
    # /usr/local/bin/milog (bundle) → no src/ nearby.
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

    # Target paths (system when root, user otherwise).
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
        if [[ -n "$src" && -f "$src/$(_completions_filename "$shell")" ]]; then
            cp "$src/$(_completions_filename "$shell")" "$dst"
        else
            _completions_emit "$shell" > "$dst"
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
    # Fallback: the bundle ships a copy of each completion script inline
    # via build.sh heredocs. If that's missing too, we truly can't emit.
    local fn="_completions_payload_${shell}"
    if declare -F "$fn" >/dev/null 2>&1; then
        "$fn"
    else
        echo -e "${R}no completions payload available for shell '$shell'${NC}" >&2
        return 1
    fi
}
# MODE: config — manage the user config file without opening an editor
# ==============================================================================

_cfg_ensure_dir() {
    local d; d=$(dirname "$MILOG_CONFIG")
    mkdir -p "$d" 2>/dev/null || {
        echo -e "${R}Cannot create config directory: $d${NC}" >&2; return 1; }
}

# Read LOGS array as defined LITERALLY in the config file (ignores the
# hardcoded script defaults). Outputs one app per line; empty if no LOGS= line.
_cfg_read_logs() {
    [[ -f "$MILOG_CONFIG" ]] || return 0
    (
        LOGS=()
        # shellcheck disable=SC1090
        . "$MILOG_CONFIG" 2>/dev/null || true
        (( ${#LOGS[@]} > 0 )) && printf '%s\n' "${LOGS[@]}"
    )
}

# Replace or append a single-line assignment `KEY=VALUE` in the config file.
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
    printf "  %-22s warn=%sms crit=%sms\n" "p95 response time" "$P95_WARN_MS" "$P95_CRIT_MS"
    printf "  %-22s %s\n" "SLOW_WINDOW"   "$SLOW_WINDOW"
    printf "  %-22s enabled=%s mmdb=%s\n" "geoip" "$GEOIP_ENABLED" \
        "$([[ -f "$MMDB_PATH" ]] && echo "$MMDB_PATH" || echo "MISSING:$MMDB_PATH")"
    printf "  %-22s enabled=%s db=%s retain=%sd\n" "history" \
        "$HISTORY_ENABLED" "$HISTORY_DB" "$HISTORY_RETAIN_DAYS"
    printf "  %-22s enabled=%s cooldown=%ss dedup=%ss\n" "alerts" \
        "$ALERTS_ENABLED" "$ALERT_COOLDOWN" "${ALERT_DEDUP_WINDOW:-300}"
    # Render per-destination status from the process-sourced env (same
    # values the running daemon/TUI would use). For a target-user view
    # under sudo, use `milog alert status` instead — it reads the
    # target's config file directly.
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
# P95_WARN_MS=500
# P95_CRIT_MS=1500
# SLOW_WINDOW=1000      # lines scanned per app by `milog slow`

# GeoIP — requires mmdblookup + a MaxMind GeoLite2-Country.mmdb. See README.
# GEOIP_ENABLED=0
# MMDB_PATH="/var/lib/GeoIP/GeoLite2-Country.mmdb"

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
    # Numeric values unquoted; strings double-quoted; empty string → ""
    local quoted
    if [[ "$val" =~ ^-?[0-9]+$ ]]; then
        quoted="$val"
    else
        # Escape any embedded double-quotes
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
    # Type-aware existence hint. Only surfaces when we can check cheaply;
    # docker/journal liveness is better diagnosed at stream time.
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

# Config validator — checks the RESOLVED config (after file + env overrides).
# Surfaces typos (unknown keys), invalid ranges, unreachable paths, and
# malformed destinations. Two modes:
#   - called standalone → prints a report + returns 0 if clean, 2 if warnings,
#     1 if errors. Useful for CI / pre-flight.
#   - imported from `milog daemon` startup → same logic, only errors are
#     fatal; the daemon refuses to start with a clearly-broken config.
config_validate() {
    local errors=0 warnings=0

    # Known top-level keys + per-app-threshold families. Any VAR starting
    # with these is legal; anything else in the user's config is suspicious.
    local known_exact=(
        LOG_DIR LOGS REFRESH SPARK_LEN
        DISCORD_WEBHOOK SLACK_WEBHOOK
        TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        MATRIX_HOMESERVER MATRIX_TOKEN MATRIX_ROOM
        WEBHOOK_URL WEBHOOK_TEMPLATE WEBHOOK_CONTENT_TYPE
        ALERTS_ENABLED ALERT_COOLDOWN ALERT_DEDUP_WINDOW ALERT_STATE_DIR
        ALERT_LOG_MAX_BYTES ALERT_ROUTES
        HOOKS_DIR ALERT_HOOK_TIMEOUT
        P95_WARN_MS P95_CRIT_MS SLOW_WINDOW SLOW_EXCLUDE_PATHS
        GEOIP_ENABLED MMDB_PATH
        HISTORY_ENABLED HISTORY_DB HISTORY_RETAIN_DAYS HISTORY_TOP_IP_N
        WEB_PORT WEB_BIND WEB_STATE_DIR WEB_TOKEN_FILE WEB_ACCESS_LOG
        THRESH_REQ_WARN THRESH_REQ_CRIT
        THRESH_CPU_WARN THRESH_CPU_CRIT
        THRESH_MEM_WARN THRESH_MEM_CRIT
        THRESH_DISK_WARN THRESH_DISK_CRIT
        THRESH_4XX_WARN THRESH_5XX_WARN
    )
    # Families — prefix-matched for per-app overrides like THRESH_REQ_CRIT_finance.
    local known_prefix=( THRESH_ P95_WARN_MS_ P95_CRIT_MS_ )

    echo -e "\n${W}── MiLog: Config validate ──${NC}\n"
    echo -e "  ${D}config: $MILOG_CONFIG${NC}"

    # 1. Unknown keys in the user's config file (source-level, not env).
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

    # 2. Numeric range checks.
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
    _check_int P95_WARN_MS 0
    _check_int P95_CRIT_MS 0
    _check_int SLOW_WINDOW 1

    # 3. LOG_DIR readable.
    if [[ ! -d "$LOG_DIR" ]]; then
        echo -e "  ${R}err${NC}   LOG_DIR does not exist: $LOG_DIR"
        errors=$((errors+1))
    elif [[ ! -r "$LOG_DIR" ]]; then
        echo -e "  ${R}err${NC}   LOG_DIR not readable: $LOG_DIR (add user to 'adm' group)"
        errors=$((errors+1))
    fi

    # 4. Destinations syntactically valid (lightweight — no network).
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
    # Partial Telegram / Matrix — hard errors because the destination won't fire.
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

# ==============================================================================
# COLOR PREFIX — merged initial dump sorted by nginx timestamp, then live tails
# ==============================================================================
color_prefix() {
    local pids=()
    local colors=("$B" "$C" "$G" "$M" "$Y" "$R")
    # File-based sources (nginx / text) can participate in the initial
    # merged-by-timestamp dump. Streaming-only sources (journal /
    # docker) skip it — their commands come through separately.
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

        # Gather file-type sources for the initial merged-dump pass.
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

    # Initial dump: last 10 lines from every FILE source, merged and
    # sorted by log timestamp. Streaming sources (journal / docker)
    # stream live-only — no retrospective view since their readers don't
    # cheaply support "last N matching lines".
    if (( ${#F_files[@]} > 0 )); then
        {
            local idx
            for idx in "${!F_files[@]}"; do
                tail -n 10 "${F_files[$idx]}" 2>/dev/null | \
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

    # Live tails from every source — files via tail -F, journal via
    # journalctl -f, docker via the unwrap pipeline. All reach stdout
    # the same way; awk prefixes each with the coloured app label.
    local idx
    for idx in "${!S_cmds[@]}"; do
        bash -c "${S_cmds[$idx]}" 2>/dev/null | \
            awk -v col="${S_cols[$idx]}" -v lbl="${S_labels[$idx]}" -v nc="$NC" \
                '{print col"["lbl"]"nc" "$0; fflush()}' &
        pids+=($!)
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

# ==============================================================================
# HELP
# ==============================================================================
# ==============================================================================
# MODE: daemon — headless sampler + rule evaluator (no TUI)
# Fires the same rules as the live modes. stderr decision log only;
# webhook sends are backgrounded so a slow Discord never wedges the loop.
# ==============================================================================

mode_daemon() {
    # Config sanity gate — refuse to start with ERROR-level findings so a
    # broken config doesn't silently degrade at 3am. Warnings don't block;
    # they're printed via stderr alongside the normal _dlog output.
    if ! config_validate >&2; then
        local rc=$?
        if (( rc == 1 )); then
            _dlog "ABORT: config validate reported errors — fix them or run \`milog config validate\`"
            exit 1
        fi
        # rc=2 means warnings only → continue, user's been told.
    fi

    local hook_state
    hook_state="disabled"
    [[ "$ALERTS_ENABLED" == "1" && -n "$DISCORD_WEBHOOK" ]] && hook_state="enabled"
    _dlog "milog daemon starting — refresh=${REFRESH}s alerts=${hook_state} history=${HISTORY_ENABLED} apps=(${LOGS[*]})"
    [[ "$ALERTS_ENABLED" != "1" ]] && _dlog "WARNING: ALERTS_ENABLED=0 — rules will log but no webhooks will be fired"
    [[ -z "$DISCORD_WEBHOOK"    ]] && _dlog "WARNING: DISCORD_WEBHOOK empty — no webhooks will be fired"

    history_init   # no-op when HISTORY_ENABLED=0; disables itself on error

    # Live-tail watchers for exploit + probe + app-pattern rules. Their stdout
    # is suppressed; the alert call sites inside each mode fire webhooks
    # directly. `mode_patterns` self-suppresses when PATTERNS_ENABLED=0.
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

    # Init rollover state — start at "current" so the first write happens
    # only once we've crossed a real minute/hour/day boundary, never mid-
    # minute on start-up with partial counts.
    local last_min last_hour last_day now
    now=$(date +%s)
    last_min=$((  now / 60   ))
    last_hour=$(( now / 3600 ))
    last_day=$((  now / 86400 ))

    while :; do
        local CUR_TIME
        CUR_TIME=$(date '+%d/%b/%Y:%H:%M')

        # System metrics — same helpers mode_monitor uses.
        local cpu mem_pct mem_used mem_total disk_pct disk_used disk_total
        cpu=$(cpu_usage)
        [[ "$cpu" =~ ^[0-9]+$ ]] || cpu=0
        read -r mem_pct mem_used mem_total <<< "$(mem_info)"
        read -r disk_pct disk_used disk_total <<< "$(disk_info)"

        local worker_count
        worker_count=$(ps aux 2>/dev/null | awk '/nginx: worker/{n++} END{print n+0}')

        sys_check_alerts "$cpu" "$mem_pct" "$mem_used" "$mem_total" \
                         "$disk_pct" "$disk_used" "$disk_total" "$worker_count"

        # Per-app HTTP rules.
        local name cnt c2 c3 c4 c5
        for name in "${LOGS[@]}"; do
            read -r cnt c2 c3 c4 c5 <<< "$(nginx_minute_counts "$name" "$CUR_TIME")"
            cnt=${cnt:-0}; c4=${c4:-0}; c5=${c5:-0}
            nginx_check_http_alerts "$name" "$c4" "$c5"
        done

        # File integrity + persistence-surface + listening-port scanners.
        # Self-throttled by their respective AUDIT_*_INTERVAL — cheap to
        # call every tick (returns immediately when not due). No-op when
        # AUDIT_ENABLED=0.
        _audit_fim_tick
        _audit_persistence_tick
        _audit_ports_tick

        # History rollover. Write the *previous* complete minute so nothing
        # lands partial. Hour rollup runs similarly on the hour edge.
        now=$(date +%s)
        local cur_min=$((  now / 60   ))
        local cur_hour=$(( now / 3600 ))
        if (( cur_min > last_min )); then
            local write_ts=$(( last_min * 60 ))
            history_write_minute "$write_ts" "$(_cur_time_at "$write_ts")"
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

# ==============================================================================
# MODE: diff — hour-level comparison: now vs 1d ago vs 7d ago, per app
# Same-hour windows against metrics_minute. Percent deltas computed in the
# shell because bash arithmetic handles the small integer math cleanly.
# ==============================================================================
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

    # ASCII header labels — Δ is a 2-byte 1-column char that confuses
    # printf byte-width formatting. Divider em-dashes are counted to match
    # each column's VISUAL width (12/10/10/10/8/8) so rows line up.
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

# ==============================================================================
# MODE: digest — exec-summary view over the last day / week
#
# Uses the same data the other modes do: alerts.log for fire counts, the
# history DB for capacity trend (when HISTORY_ENABLED), and a short scan of
# the live log files for traffic / error / latency rollups.
#
# Designed to be piped into alert destinations as a scheduled summary for
# quiet servers where live alerts rarely fire — you still want the weekly
# "nothing happened, here's what happened anyway" email.
#
# Usage:
#   milog digest          # last 24h (default)
#   milog digest day
#   milog digest week
#   milog digest 12h      # arbitrary N<h|d|w>
# ==============================================================================

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

    # --- Alerts ---------------------------------------------------------------
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

    # --- Traffic + errors per app --------------------------------------------
    echo -e "${W}Traffic${NC}"
    printf "  %-14s  %10s  %8s  %8s\n" "APP" "REQ" "4XX" "5XX"
    printf "  %-14s  %10s  %8s  %8s\n" "────────────" "──────────" "────────" "────────"
    local entry name file
    for entry in "${LOGS[@]}"; do
        [[ "$(_log_type_for "$entry")" == "nginx" ]] || continue
        name=$(_log_name_for "$entry")
        file=$(_log_path_for "$entry")
        [[ -f "$file" ]] || continue
        # Count lines in-window via nginx timestamp. Shell out to awk with a
        # cutoff; safe-fallback emits zeros if the date format unexpectedly
        # doesn't match our scan.
        read -r req c4 c5 <<< "$(awk -v cutoff="$cutoff" '
            {
                # [24/Apr/2026:12:34:56 +0000] → crude parse: keep any row,
                # count by status class (fields reliable in combined format).
                n++
                if ($9 ~ /^4/) c4++
                else if ($9 ~ /^5/) c5++
            }
            END { printf "%d %d %d\n", n+0, c4+0, c5+0 }' "$file" 2>/dev/null)"
        printf "  %-14s  %10d  ${Y}%8d${NC}  ${R}%8d${NC}\n" "$name" "${req:-0}" "${c4:-0}" "${c5:-0}"
    done
    echo

    # --- Top attacker IPs (window-agnostic: scans whole access logs) ---------
    echo -e "${W}Top attacker IPs (this window)${NC}"
    local ip_rollup
    ip_rollup=$(
        for entry in "${LOGS[@]}"; do
            [[ "$(_log_type_for "$entry")" == "nginx" ]] || continue
            file=$(_log_path_for "$entry")
            [[ -f "$file" ]] || continue
            awk '{print $1}' "$file"
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

    # --- Capacity (if history DB is available) -------------------------------
    if [[ "${HISTORY_ENABLED:-0}" == "1" && -f "$HISTORY_DB" ]] && command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${W}Capacity (start of window → now)${NC}"
        local cap
        cap=$(sqlite3 "$HISTORY_DB" \
            "SELECT printf('%d → %d', MIN(cpu), MAX(cpu)), printf('%d → %d', MIN(mem_pct), MAX(mem_pct)), printf('%d → %d', MIN(disk_pct), MAX(disk_pct)) FROM system WHERE ts >= $cutoff;" 2>/dev/null)
        if [[ -n "$cap" ]]; then
            IFS='|' read -r cpu_r mem_r disk_r <<< "$cap"
            printf "  %-16s %s%%\n" "cpu"  "${cpu_r:-—}"
            printf "  %-16s %s%%\n" "memory" "${mem_r:-—}"
            printf "  %-16s %s%%\n" "disk" "${disk_r:-—}"
        else
            echo -e "  ${D}no history rows in window${NC}"
        fi
    else
        echo -e "${D}Capacity: history disabled (HISTORY_ENABLED=0)${NC}"
    fi
    echo
}
# ==============================================================================
# MODE: doctor — checklist of what's installed/configured/reachable
#
# The tool no-ops gracefully when sqlite3, mmdblookup, a webhook, or the
# extended log format are missing — which is friendly but can hide a
# misconfigured install. `doctor` makes every degraded capability visible
# with a one-line hint on how to enable it.
#
# Output: ✓ (ready) / ! (degraded, works-but-limited) / ✗ (broken/required).
# Exit code: 0 if all required deps are present; 1 otherwise. CI-friendly.
# ==============================================================================
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

    # ---- core tools (required) ----------------------------------------------
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

    # ---- optional tools ------------------------------------------------------
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

    # ---- log dir + per-app logs ---------------------------------------------
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

    # ---- nginx log format — does it carry $request_time? --------------------
    #
    # Scan the tail of every configured app's log and look for any timed line
    # (numeric last field, NF>=12). One app's tail might still be pre-reload
    # old-format while others are already new-format — we report ✓ as long
    # as at least one app has timed samples recently. Simultaneously tracks
    # apps with only old-format lines so the hint can call them out for
    # manual verification.
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

    # ---- Discord alerting ----------------------------------------------------
    _doc_head "alerting (Discord)"
    if [[ -z "${DISCORD_WEBHOOK:-}" ]]; then
        _doc_warn "DISCORD_WEBHOOK not configured" \
                  "run: sudo milog alert on \"https://discord.com/api/webhooks/ID/TOKEN\""
        warn=$(( warn + 1 ))
    else
        _doc_ok "DISCORD_WEBHOOK configured  (${DISCORD_WEBHOOK:0:40}…)"
        # Reachability — a POST with an empty content is ignored by Discord,
        # so we GET the webhook metadata instead (returns 200 + JSON on valid
        # webhooks, 404 on stale). 5s cap so doctor never hangs.
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
    # Report other destinations when configured — each is opt-in, so
    # "not configured" is informational (not a warning).
    [[ -n "${SLACK_WEBHOOK:-}" ]] \
        && _doc_ok "Slack webhook configured  (${SLACK_WEBHOOK:0:40}…)"
    [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]] \
        && _doc_ok "Telegram bot configured  (chat=$TELEGRAM_CHAT_ID)"
    [[ -n "${MATRIX_HOMESERVER:-}" && -n "${MATRIX_TOKEN:-}" && -n "${MATRIX_ROOM:-}" ]] \
        && _doc_ok "Matrix configured  (${MATRIX_HOMESERVER} room=$MATRIX_ROOM)"
    # Alert history log — surface count since "today" so users know it works.
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

    # ---- history DB ---------------------------------------------------------
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

    # ---- GeoIP --------------------------------------------------------------
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
        if [[ -n "$probe" && "$probe" != "--" ]]; then
            _doc_ok "$MMDB_PATH  (8.8.8.8 → $probe)"
        else
            _doc_warn "$MMDB_PATH present but lookup returned empty — DB may be corrupt"
            warn=$(( warn + 1 ))
        fi
    fi

    # ---- web dashboard ------------------------------------------------------
    _doc_head "web dashboard"
    if command -v socat >/dev/null 2>&1 || command -v ncat >/dev/null 2>&1; then
        local listener
        listener=$(command -v socat 2>/dev/null || command -v ncat 2>/dev/null)
        _doc_ok "listener available  ($listener)"
    else
        _doc_warn "neither socat nor ncat installed" \
                  "install with: sudo apt install -y socat — enables 'milog web'"
        warn=$(( warn + 1 ))
    fi
    if [[ -f "$WEB_STATE_DIR/web.pid" ]]; then
        local wpid; wpid=$(< "$WEB_STATE_DIR/web.pid" 2>/dev/null)
        if [[ -n "$wpid" ]] && kill -0 "$wpid" 2>/dev/null; then
            _doc_ok "milog web running  (pid=$wpid, $WEB_BIND:$WEB_PORT)"
        else
            _doc_warn "stale web pidfile (not running)" "milog web stop  # cleans it up"
            warn=$(( warn + 1 ))
        fi
    fi

    # ---- systemd units (only meaningful where systemd is installed) ---------
    if command -v systemctl >/dev/null 2>&1; then
        _doc_head "systemd"
        # milog.service (system unit) — the alert daemon.
        if [[ ! -f /etc/systemd/system/milog.service ]]; then
            _doc_warn "milog.service not installed" "run: sudo milog alert on (installs + enables the unit)"
            warn=$(( warn + 1 ))
        elif systemctl is-active --quiet milog.service 2>/dev/null; then
            _doc_ok "milog.service active" "logs: journalctl -u milog.service -f"
        else
            _doc_warn "milog.service installed but inactive" "start: sudo systemctl start milog.service"
            warn=$(( warn + 1 ))
        fi
        # milog-web.service (user unit) — optional dashboard. Only report if
        # something has attempted to install it; absent-by-choice is fine.
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

    # ---- summary -------------------------------------------------------------
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

# ==============================================================================
# ==============================================================================
# MODE: errors — show what's broken right now, across every log source
#
# Two faces:
#
#   1. Live tail (default, backward-compatible)
#      `milog errors`      → tail every source. nginx-typed sources show
#                            4xx/5xx lines; journal/docker/text sources show
#                            app-pattern matches (Go panics, OOM kills, …).
#
#   2. Summary report (any flag triggers it)
#      `milog errors --since 24h [--source X] [--pattern Y]`
#                          → scan alerts.log for `app:<source>:<pattern>`
#                            fires in the window, group counts, list samples.
#
# Window grammar mirrors `milog alerts`: today / yesterday / all / Nh/Nd/Nw.
# ==============================================================================

mode_errors() {
    # Flag-driven summary mode. Plain `milog errors` keeps doing the live
    # mixed tail — that's what existing scripts and muscle memory expect.
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
    cat <<EOF
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
EOF
}

# --- Live tail ----------------------------------------------------------------
# Nginx sources: classic 4xx/5xx line filter.
# Non-nginx sources: pattern union from the patterns module — same source of
# truth as `milog patterns`, so adding a pattern there extends this view too.
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
                # Backward-compat tail: 4xx/5xx HTTP status filter on the
                # combined-format access line. Same regex as v1.
                ( bash -c "$cmd" 2>/dev/null \
                    | grep --line-buffered -E ' [45][0-9][0-9] ' \
                    | awk -v col="$col" -v lbl="$label" -v nc="$NC" \
                        '{print col"["lbl"]"nc" "$0; fflush()}' ) &
                pids+=($!)
                ;;
            *)
                # App-pattern tail — only spawn when at least one pattern is
                # defined; otherwise the union ERE is empty and grep would
                # match every line.
                if [[ -n "$pattern_union" ]]; then
                    ( bash -c "$cmd" 2>/dev/null \
                        | grep --line-buffered -v '^#' \
                        | grep --line-buffered -E -i -- "$pattern_union" \
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

# --- Summary report -----------------------------------------------------------
# Reads alerts.log for `app:<source>:<pattern>` fires in the window. Optional
# --source / --pattern filters narrow the report; both are exact match on the
# rule-key segment so users can paste from `milog patterns list`.
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

    local cutoff cutoff_fmt
    cutoff=$(_alerts_window_to_epoch "$window") || return 1
    cutoff_fmt=$(_alerts_fmt_epoch "$cutoff")

    # Filter once: in-window AND rule_key starts with `app:`. Optional
    # source/pattern filters refine further. awk does the heavy lift; bash
    # consumes the small filtered result.
    local filtered; filtered=$(mktemp -t milog_errors.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$filtered'" RETURN

    awk -F'\t' \
        -v cutoff="$cutoff" \
        -v want_src="$want_source" \
        -v want_pat="$want_pattern" '
        $1 < cutoff { next }
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
        # Body is the matched line wrapped in ```; strip the fences and cap
        # at 60 chars so the row stays scanable.
        sample="${body#\`\`\`}"; sample="${sample%\`\`\`}"
        (( ${#sample} > 60 )) && sample="${sample:0:57}..."
        printf "  %-16s  ${R}%-12s${NC}  ${Y}%-22s${NC}  %s\n" "$when" "$src" "$pat" "$sample"
    done < <(tail -n "$list_cap" "$filtered")

    echo -e "\n  ${D}total: $total fire(s) — log at $log_file${NC}\n"
}
# ==============================================================================
# MODE: exploits — L7 attack payloads + scanner fingerprints
# Catches path traversal, LFI, RCE, SQLi, XSS, Log4Shell, dotfile/secret probes,
# infra-API probes (Docker/actuator/etc), CMS admin scans, and known scanner UAs.
# Example matches:
#   GET /index.php?lang=../../../../tmp/foo      (path traversal)
#   GET /containers/json                         (docker API probe)
#   GET /SDK/webLanguage                         (hikvision probe)
#   "libredtail-http" user-agent                 (scanner UA)
# ==============================================================================
mode_exploits() {
    echo -e "${D}Watching exploit attempts across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    # Pattern built in groups for readability. ERE, case-insensitive.
    local pat='\.\./|%2e%2e'                                                   # path traversal
    pat+='|/etc/passwd|/etc/shadow|/proc/self/environ'                         # target files
    pat+='|/containers/json|/actuator/|/server-status|/console(/|\?)|/druid/'  # infra probes
    pat+='|/SDK/web|/cgi-bin/|/boaform/|/HNAP1'                                # embedded-device probes
    pat+='|/wp-admin|/wp-login|/wp-content/plugins|/xmlrpc\.php'               # wordpress
    pat+='|/phpmyadmin|/pma/|/mysql/admin'                                     # phpmyadmin
    pat+='|/\.env|/\.git/|/\.aws/|/\.ssh/|/\.DS_Store'                         # dotfiles / secrets
    pat+='|/config\.(php|json|yml|yaml)|/web\.config'                          # config files
    pat+='|jndi:|\$\{jndi|log4j'                                               # log4shell
    pat+='|union[+% ]+select|select[+% ]+from|sleep\([0-9]|benchmark\('        # sqli
    pat+='|or[+% ]+1=1|%27[+% ]*or|%27%20or'                                  # sqli
    pat+='|<script|%3cscript|onerror=|onload=|javascript:'                     # xss
    pat+='|base64_decode|eval\(|system\(|passthru\(|shell_exec'                # rce fn
    pat+='|libredtail|nikto|masscan|zgrab|sqlmap|nuclei|gobuster'              # scanner UAs
    pat+='|dirbuster|wfuzz|l9explore|l9tcpid|hello,\s?world'                   # scanner UAs

    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$i]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            (
                app="$name"
                tail -F "$file" 2>/dev/null | \
                    grep --line-buffered -Ei "$pat" | \
                while IFS= read -r line; do
                    printf '%b[%s]%b %b[EXPLOIT]%b %s\n' "$col" "$label" "$NC" "$R" "$NC" "$line"
                    cat_slug=$(_exploit_category "$line")
                    # Fingerprint gate runs AFTER cooldown — both must pass.
                    # Suppresses duplicate alerts when `probes` also matches
                    # the same line (common on scanner traffic like zgrab).
                    fp=$(alert_fingerprint_from_line "$line")
                    if alert_should_fire "exploit:$app:$cat_slug" \
                       && alert_fingerprint_fresh "$fp"; then
                        alert_fire "Exploit attempt: $app / $cat_slug" "\`\`\`${line:0:1800}\`\`\`" 15158332 "exploit:$app:$cat_slug" &
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

# ==============================================================================
# MODE: grep — filter-tail one source (any type: nginx / text / journal / docker)
# ==============================================================================
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
    bash -c "$cmd" 2>/dev/null | grep --line-buffered -i "$pattern"
}

# ==============================================================================
# MODE: health
# ==============================================================================
mode_health() {
    echo -e "\n${W}── MiLog: Status Code Health ──${NC}\n"
    printf "%-12s  %8s  %8s  %8s  %8s  %8s\n" "APP" "TOTAL" "2xx" "3xx" "4xx" "5xx"
    printf "%-12s  %8s  %8s  %8s  %8s  %8s\n" "───────────" "───────" "───────" "───────" "───────" "───────"
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        [[ -f "$file" ]] || { printf "%-12s  %8s\n" "$name" "(not found)"; continue; }
        local total s2=0 s3=0 s4=0 s5=0
        total=$(wc -l < "$file")
        s2=$(grep -c ' 2[0-9][0-9] ' "$file" 2>/dev/null || true)
        s3=$(grep -c ' 3[0-9][0-9] ' "$file" 2>/dev/null || true)
        s4=$(grep -c ' 4[0-9][0-9] ' "$file" 2>/dev/null || true)
        s5=$(grep -c ' 5[0-9][0-9] ' "$file" 2>/dev/null || true)
        local c4=$NC c5=$NC t4 t5
        t4=$(_thresh THRESH_4XX_WARN "$name")
        t5=$(_thresh THRESH_5XX_WARN "$name")
        [[ $s4 -gt $t4 ]] && c4=$Y
        [[ $s5 -gt $t5 ]] && c5=$R
        printf "%-12s  %8s  %8s  %8s  ${c4}%8s${NC}  ${c5}%8s${NC}\n" \
            "$name" "$total" "$s2" "$s3" "$s4" "$s5"
    done
    echo ""
}

# ==============================================================================
# MODE: install — on-demand feature installer
#
# Complement to install.sh's --with-X flags. Lets users add optional
# capabilities AFTER initial install, without re-running the one-liner with
# a different flag set. Idempotent: `install <feature>` is safe to re-run.
#
# Each feature is a declarative spec — package-manager deps + optional
# post-install hint. Binary downloads (for Go-binary features) will plug
# into the same shape once those land.
#
# Usage:
#   milog install list                   # matrix of features + installed status
#   milog install <feature>              # install feature + its system deps
#   milog install remove <feature>       # uninstall (keeps config/data)
#
# Scope today: geoip, web, history. Future: ebpf, audit, sse — they need
# the corresponding Go binaries to land first.
# ==============================================================================

# Feature catalog. Each feature is a colon-separated record:
#   name : check_cmd : apt_pkg : dnf_pkg : pacman_pkg : description
# check_cmd is what we run to decide "installed=yes/no".
_install_catalog() {
    cat <<"EOF"
geoip:mmdblookup:mmdb-bin:libmaxminddb:libmaxminddb:GeoIP COUNTRY column via MaxMind lookup
web:socat:socat:socat:socat:milog web dashboard (socat HTTP listener)
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
  web        milog web dashboard (socat)
  history    history DB for trend / diff / auto-tune (sqlite3)

${D}install.sh --with-X flags are the \"first-install\" path; this subcommand is for
later additions without rerunning install.sh.${NC}
"
}
# ==============================================================================
# MODE: monitor  +  tui
#
# `milog monitor` runs the bash refresh-and-redraw dashboard (works on any
# POSIX box, no extra binary). `milog tui` execs the Go bubbletea TUI
# when available — richer UI, same data source. Both coexist.
# ==============================================================================

# Locate milog-tui, the Go bubbletea binary. Preference order mirrors
# _web_go_binary so install layouts stay consistent across companions.
_tui_go_binary() {
    if [[ -n "${MILOG_TUI_BIN:-}" && -x "$MILOG_TUI_BIN" ]]; then
        printf '%s' "$MILOG_TUI_BIN"; return 0
    fi
    local candidate
    for candidate in \
        /usr/local/libexec/milog/milog-tui \
        /usr/local/bin/milog-tui; do
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

# `milog tui` — run the Go bubbletea TUI. Separate subcommand from
# `milog monitor` so both coexist and users pick. Clear install hint
# when the binary is missing.
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
    # Pass the MILOG_* surface through so config stays single-source.
    export MILOG_LOG_DIR="$LOG_DIR" \
           MILOG_APPS="${LOGS[*]}" \
           MILOG_REFRESH="${REFRESH:-5}" \
           MILOG_ALERT_STATE_DIR="${ALERT_STATE_DIR:-$HOME/.cache/milog}"
    exec "$go_bin" "$@"
}

mode_monitor() {
    # Async CPU sampler — reads /proc/stat in a background loop, writes the
    # latest % to a tmpfile. Keeps the render loop from blocking on sleep 0.2.
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

    # Enable sparkline history for nginx_row
    MILOG_HIST_ENABLED=1
    declare -gA HIST

    # Hide cursor and quiet input echo so keystrokes don't litter the TUI.
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
        # Reflow for terminal size — runs per tick so SIGWINCH just works.
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

        # --- Single unified box starts here ---
        bdr_top

        # Title row
        local t_p=" MiLog   ${TIMESTAMP}   ${net_iface}"
        local t_c=" ${W}MiLog${NC}   ${D}${TIMESTAMP}${NC}   ${D}${net_iface}${NC}"
        draw_row "$t_p" "$t_c"

        bdr_mid

        # System metrics row 1 — bars
        # Plain: " CPU  xx% [bar18]  MEM  xx% [bar18]  DISK  xx% [bar18]"
        local r1_p
        r1_p=$(printf " CPU %3d%% [%-${BW}s]  MEM %3d%% [%-${BW}s]  DISK %3d%% [%-${BW}s]" \
            "$cpu" "$cpu_bar" "$mem_pct" "$mem_bar" "$disk_pct" "$disk_bar")
        local r1_c
        r1_c=$(printf " CPU %b%3d%%%b [%b%s%b]  MEM %b%3d%%%b [%b%s%b]  DISK %b%3d%%%b [%b%s%b]" \
            "$cpu_col"  "$cpu"      "$NC" "$cpu_col"  "$cpu_bar"  "$NC" \
            "$mem_col"  "$mem_pct"  "$NC" "$mem_col"  "$mem_bar"  "$NC" \
            "$disk_col" "$disk_pct" "$NC" "$disk_col" "$disk_bar" "$NC")
        draw_row "$r1_p" "$r1_c"

        # System metrics row 2 — detail + net
        # Max visible: ' MEM 99999/99999MB  DISK 999.9/999.9GB  dn:999.9MB/s up:999.9MB/s' = 72
        local r2_p=" MEM ${mem_used}/${mem_total}MB  DISK ${disk_used}/${disk_total}GB  dn:${rx_s}/s up:${tx_s}/s"
        local r2_c=" ${D}MEM${NC} ${mem_used}/${mem_total}MB  ${D}DISK${NC} ${disk_used}/${disk_total}GB  ${C}dn:${rx_s}/s${NC} ${G}up:${tx_s}/s${NC}"
        draw_row "$r2_p" "$r2_c"

        bdr_mid

        # Nginx workers
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

        # Nginx per-app table (no nested box — continues same box with col separators)
        bdr_hdr
        hdr_row
        bdr_hdr

        for name in "${LOGS[@]}"; do
            nginx_row "$name" "$CUR_TIME" TOTAL
        done

        bdr_sep

        # Footer
        local upstr; upstr=$(uptime -p 2>/dev/null | sed 's/up //' || echo 'n/a')
        local f_p=" TOTAL: ${TOTAL} req/min   UP: ${upstr}"
        local f_c=" ${W}TOTAL:${NC} ${TOTAL} req/min   ${D}UP: ${upstr}${NC}"
        draw_row "$f_p" "$f_c"

        bdr_bot
        local ptag=""
        (( paused )) && ptag="  ${R}[PAUSED]${NC}"
        # Clear-to-EOL so shorter footer over a longer one doesn't leave junk.
        printf "${D} q:quit  p:pause  r:refresh  +/-:rate (${REFRESH}s)  |  5xx>=${THRESH_5XX_WARN} blinks${NC}${ptag}\033[K\n"
        # Also clear from cursor down in case previous frame was taller.
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

# ==============================================================================
# MODE: patterns — generic app-error detection across all LOGS source types
# Watches every configured source through `_log_reader_cmd`, runs each line
# against a built-in catalog of universal app-error signatures plus any
# user-defined extras (APP_PATTERN_<name>=regex), and fires alerts keyed
# `app:<source>:<pattern>` through the existing alert infra.
# Source-agnostic by design — works on nginx, journal, docker, and text logs.
# Parallel indexed arrays (not associative) keep the module bash-3.2-friendly
# for dev boxes; the catalog is small enough that O(N) lookups are free.
# ==============================================================================

# Built-in pattern catalog. Names + regexes paired by index. ERE, matched
# case-insensitively. Each entry is anchored to a phrase narrow enough that
# a false positive justifies waking someone — broaden only with care.
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

# Look up a built-in regex by name. Empty stdout = not a built-in.
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

# Walk env for `APP_PATTERN_<name>=<regex>` overrides + extras, merge with
# built-ins, emit one `<name>\t<regex>\n` line per active entry. An empty
# user value disables a same-named built-in (mute panic_go etc. without
# touching the source). Stable sorted output for deterministic listings.
_patterns_collect() {
    local i name regex
    local -a out_names=() out_regex=()
    for i in "${!_PATTERNS_BUILTIN_NAMES[@]}"; do
        out_names+=("${_PATTERNS_BUILTIN_NAMES[$i]}")
        out_regex+=("${_PATTERNS_BUILTIN_REGEX[$i]}")
    done
    # Apply user overrides + additions from env.
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
                out_names=("${out_names[@]}")
                out_regex=("${out_regex[@]}")
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
    # Pair-emit and sort by name.
    for i in "${!out_names[@]}"; do
        printf '%s\t%s\n' "${out_names[$i]}" "${out_regex[$i]}"
    done | sort
}

# Build a single union ERE from the collected patterns — one tail+grep pipe
# per source instead of N. The classifier below re-tests each pattern in
# bash to attribute matches by name (rare path; only on actual matches).
_patterns_union_ere() {
    local first=1 out="" name re
    while IFS=$'\t' read -r name re; do
        [[ -z "$re" ]] && continue
        if (( first )); then out="(${re})"; first=0
        else out+="|(${re})"; fi
    done
    printf '%s' "$out"
}

# Classify which named pattern(s) a line matched. Multiple matches per line
# are possible (e.g. an OOM line trips both `oom_kill` and `out_of_memory`);
# we fire one alert per classified pattern so silence rules can target each
# independently. Stdout: pattern names, space-separated.
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

    # Single sequential consumer — multiple parallel watchers race on
    # alerts.state's read-modify-write (concurrent renames clobber each
    # other, leading to lost cooldown entries and double-fires). All sources
    # funnel into one merged stream tagged `<source>\t<line>` and a single
    # consumer processes lines one at a time, so cooldown is rock-solid.
    # awk handles the per-line tagging + fflush so output is line-buffered
    # on both Linux (gawk) and macOS (BSD awk) without GNU-only flags.
    local colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    {
        local entry
        for entry in "${LOGS[@]}"; do
            local source_name; source_name=$(_log_name_for "$entry")
            local cmd;         cmd=$(_log_reader_cmd "$entry") || continue
            [[ -z "$cmd" ]] && continue
            # Strip diagnostic lines (`#journal unavailable: …`) BEFORE
            # tagging so they never match `(ERROR|FATAL|CRITICAL)\s` and
            # self-page. awk fflush() forces line-buffering portably.
            ( bash -c "$cmd" 2>/dev/null \
                | grep --line-buffered -v '^#' \
                | awk -v src="$source_name" '{print src "\t" $0; fflush()}' ) &
        done
        wait
    } | while IFS=$'\t' read -r src line; do
            [[ -z "$line" ]] && continue
            # Union pre-filter via bash =~ — avoids the cost of forking grep
            # per line, and (critically) anchors patterns like `^panic:`
            # against the actual line content, not against the post-tag
            # stream where `^` would match nothing.
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
                        "\`\`\`${line:0:1800}\`\`\`" \
                        15158332 "$key" &
                fi
            done
        done
}

# Inspect mode — `milog patterns list` shows the merged catalog including any
# user overrides, with a `builtin` / `override` / `custom` tag. Useful for
# debugging why a given pattern isn't firing.
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
# MODE: probes — scanner / bot traffic by user-agent + protocol-level probes
# Wide UA database covering security tools, mass scanners, SEO bots,
# generic HTTP libs, AI crawlers, and non-HTTP protocol smuggling attempts.
# ==============================================================================
mode_probes() {
    echo -e "${D}Watching scanner/bot traffic across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    # Protocol-level: SSH banner, TLS ClientHello sent to plain HTTP (nginx logs
    # the bytes as literal \xNN — double backslash so grep sees one).
    local pat='SSH-2\.0|\\x16\\x03|\\x00\\x00'
    # Security / pentest tools
    pat+='|masscan|zmap|zgrab|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster'
    pat+='|dirb|ffuf|wfuzz|feroxbuster|nessus|openvas|acunetix|wpscan|joomscan'
    pat+='|burp|zaproxy|owasp|metasploit|meterpreter|w3af|webshag'
    # Mass internet scanners / research crawlers
    pat+='|l9explore|l9tcpid|l9retrieve|leakix'
    pat+='|libredtail|httpx|naabu|katana|subfinder'
    pat+='|expanseinc|censysinspect|shodan|stretchoid|internet-measurement'
    pat+='|greenbone|qualys|rapid7|detectify|intruder\.io|netcraftsurvey'
    pat+='|netsystemsresearch|paloalto|projectdiscovery|odin\.ai|onyphe'
    # SEO / advertising crawlers (often unwanted)
    pat+='|ahrefsbot|semrushbot|dotbot|mj12bot|blexbot|petalbot|serpstat'
    pat+='|dataforseobot|bytespider|mauibot|megaindex|seznambot'
    # AI crawlers
    pat+='|claudebot|gptbot|ccbot|anthropic-ai|perplexitybot|youbot'
    pat+='|amazonbot|applebot-extended|cohere-ai|diffbot'
    # Generic HTTP libraries (legit use exists but often scripted)
    pat+='|python-requests|python-urllib|aiohttp|go-http-client|okhttp'
    pat+='|libwww-perl|java/1\.|apache-httpclient|restsharp|http_request2'
    pat+='|guzzlehttp|node-fetch|axios|got\(|scrapy|mechanize'
    # Headless / automation
    pat+='|headlesschrome|phantomjs|puppeteer|playwright|selenium'
    # Generic bot / crawler hints in UA
    pat+='|[Ss]canner|[Bb]ot/|[Cc]rawler|[Ss]pider|probe-|fuzzer|harvester'
    # Known payloads
    pat+='|hello,\s*world'

    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$i]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            (
                app="$name"
                tail -F "$file" 2>/dev/null | \
                    grep --line-buffered -Ei "$pat" | \
                while IFS= read -r line; do
                    printf '%b[%s]%b %s\n' "$col" "$label" "$NC" "$line"
                    # Fingerprint gate runs AFTER cooldown — see exploits.sh
                    # for rationale. Scanner hits commonly match both rules.
                    fp=$(alert_fingerprint_from_line "$line")
                    if alert_should_fire "probe:$app" \
                       && alert_fingerprint_fresh "$fp"; then
                        alert_fire "Probe traffic: $app" "\`\`\`${line:0:1800}\`\`\`" 15844367 "probe:$app" &
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

# ==============================================================================
# MODE: rate — nginx-only
# ==============================================================================
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

# ==============================================================================
# MODE: replay — postmortem summary of one archived log file
# Read-only: never writes history. Handles .gz / .bz2 transparently.
# Three passes of the file: counts + date range, timings (sort + percentile),
# top source IPs. Each pass is single-awk-per-metric — same discipline as
# the live dashboard helpers.
# ==============================================================================
mode_replay() {
    local file="${1:-}"
    if [[ -z "$file" ]]; then
        echo -e "${R}Usage:${NC} milog replay <log-file>" >&2
        return 1
    fi
    [[ -f "$file" ]] || { echo -e "${R}Not found: $file${NC}" >&2; return 1; }

    # Pick reader based on extension. Array form so no word-splitting risks
    # when $file contains spaces.
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

    # Pass 1: lines, first/last timestamp, status-class tallies.
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

    # Pass 2: percentiles, only if any line has a numeric final field.
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

    # Pass 3: top 10 source IPs.
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

# ==============================================================================
# MODE: search <pattern> [flags] — grep across all app logs + archives
#
# Tier-1 log search: a polite wrapper around `grep -F` (or `grep -E` with
# --regex) across every configured app's access.log. Optional filters:
#
#   --since <spec>   : drop lines older than spec (today/Nh/Nd/Nw/all).
#                      Reuses _alerts_window_to_epoch — same grammar.
#   --app <name>     : scope to one app's logs.
#   --path <sub>     : substring filter on URL path (post-grep).
#   --regex          : pattern is ERE (grep -E) instead of fixed-string.
#   --archives       : also search rotated logs (.log.1, .log.2.gz, ...).
#   --limit N        : cap output to N lines (default 200; 0 = unlimited).
#
# Output: one prefixed line per match — `[app       ] <logline>` with per-app
# coloring. Final tally shows total + per-app counts.
#
# Scaling: grep is linear; fine up to ~10 GB total log volume. Beyond that,
# see the plan's "Full-text search, tier 2 (SQLite FTS5)" item.
# ==============================================================================
mode_search() {
    local pattern="" since="" app_filter="" path_filter=""
    local use_regex=0 include_archives=0 limit=200

    # First positional (if not a flag) is the pattern.
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

    # Resolve --since to a cutoff epoch up-front (one fork, not per-line).
    local cutoff_epoch=""
    if [[ -n "$since" ]]; then
        cutoff_epoch=$(_alerts_window_to_epoch "$since") || return 1
        # --since relies on awk's mktime() — gawk/mawk have it, BSD awk
        # doesn't. Warn + disable gracefully on BSD-awk hosts so the search
        # still runs (users get all matches instead of a hard failure).
        if ! command -v gawk >/dev/null 2>&1 \
             && ! awk 'BEGIN { if (mktime("2020 1 1 0 0 0") <= 0) exit 1 }' 2>/dev/null; then
            echo -e "${Y}--since requires gawk or mawk (this awk lacks mktime); time filter skipped${NC}" >&2
            cutoff_epoch=""
        fi
    fi

    # Prefer gawk for the filtering awk — mawk/gawk have mktime, BSD awk
    # doesn't. Falls back to plain `awk` when neither is explicit (works
    # on Ubuntu where /usr/bin/awk is typically mawk).
    local awk_bin="awk"
    command -v gawk >/dev/null 2>&1 && awk_bin="gawk"

    # Apps: explicit --app filter, else every configured LOGS entry.
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

    # grep -F by default (safe for user-pasted strings like "session_id=abc+xyz");
    # --regex opts into grep -E so callers can use alternation.
    local grep_flag="-F"
    (( use_regex )) && grep_flag="-E"

    # Stream all matches into a tmp file so we can tally + apply --limit
    # after the fact without second-pass scanning the source logs.
    local tmp; tmp=$(mktemp -t milog_search.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    local colors=("$B" "$C" "$G" "$M" "$Y" "$R")
    local idx=0
    for app in "${apps_to_scan[@]}"; do
        local col="${colors[$(( idx % ${#colors[@]} ))]}"
        local label; label=$(printf "%-10s" "$app")
        idx=$(( idx + 1 ))

        # Build the file list (current + optional archives). Expanded
        # globs are sorted so rotated logs come after the current one.
        local files=()
        [[ -f "$LOG_DIR/$app.access.log" ]] && files+=("$LOG_DIR/$app.access.log")
        if (( include_archives )); then
            shopt -s nullglob
            for archive in "$LOG_DIR/$app.access.log."*; do
                files+=("$archive")
            done
            shopt -u nullglob
        fi

        # For each file, decompress if needed then grep. Piped through
        # awk for --path / --since filtering and final prefixing. One
        # awk instance per file keeps the per-app coloring cheap.
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

    # Per-app counts — strip the colored prefix to find the app name.
    # The prefix shape is "[<app padded to 10>]" so we pull field-2 of
    # the raw `[label ] rest...` pattern.
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

# Scan one log file for pattern, applying post-filters, prefix each
# surviving line with `[<colored app label>]`. Handles .gz / .bz2 / plain.
# Emits to stdout; caller appends to the tmp file.
_search_one_file() {
    local f="$1" pattern="$2" grep_flag="$3" app="$4" col="$5" label="$6"
    local path_filter="$7" cutoff_epoch="$8" awk_bin="${9:-awk}"

    # Decompression path — prefer `gzip -dc` over `zcat` because BSD zcat
    # only handles .Z (compress), not .gz. Same for `bzip2 -dc` / `xz -dc`.
    local reader_cmd=""
    case "$f" in
        *.gz)   reader_cmd="gzip -dc"  ;;
        *.bz2)  reader_cmd="bzip2 -dc" ;;
        *.xz)   reader_cmd="xz -dc"    ;;
        *)      reader_cmd="cat"       ;;
    esac
    # Check the first word of reader_cmd is on PATH.
    local probe="${reader_cmd%% *}"
    command -v "$probe" >/dev/null 2>&1 \
        || { echo -e "${D}  (skipping $f — $probe not installed)${NC}" >&2; return 0; }

    # The || true swallows grep's "no matches" exit=1 so `set -euo pipefail`
    # doesn't abort the whole search when one file happens to not contain
    # the pattern (very common on rotated archives). Each stage's other
    # failure modes are intentionally swallowed too — search is best-effort.
    $reader_cmd "$f" 2>/dev/null \
        | { grep "$grep_flag" -- "$pattern" || true; } \
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
# ==============================================================================
# MODE: silence — mute a rule (or glob of rules) while on-call works the fix
#
# Counterpart to the fire path: when a MiLog rule keeps pinging Discord every
# ALERT_COOLDOWN seconds and you're already fixing the cause, mute it. The
# silence outranks cooldown + dedup and even blocks the alerts.log record so
# history stays signal-only.
#
# Subcommands:
#   milog silence <rule_or_glob> <duration> [message]   add or extend
#   milog silence list                                  show active silences
#   milog silence clear <rule_or_glob>                  remove early
#
# Duration grammar: <N><s|m|h|d>  — `30s`, `5m`, `2h`, `1d`. A bare integer is
# treated as seconds.
#
# Glob matching: bash glob syntax. `exploits:*` matches every `exploits:<cat>`
# key fired by the exploits classifier. Be careful with overly broad globs —
# `*` would silence literally every rule.
#
# Attribution: $USER (or `id -un` fallback) is recorded alongside each silence
# so `milog silence list` shows WHO muted what. Useful even on single-user
# hosts — the daemon writes as its own user; manual silences show as yours.
# ==============================================================================

# Human-readable "time remaining" from a future epoch. 0+ only (caller
# guarantees unexpired rows).
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

# Human-readable absolute time, GNU/BSD portable (same trick as alerts.sh).
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
        echo -e "${D}  use N<s|m|h|d> — e.g. 30s, 5m, 2h, 1d${NC}" >&2
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
    [[ -n "$message" ]] && echo -e "${D}  note: $message${NC}"
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
  milog silence 'exploits:*' 30m 'pentester doing authorized scan'

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
            # Otherwise treat the first arg as the rule key and the rest as
            # `<duration> [message]` — the most-used path.
            _silence_add "$@"
            ;;
    esac
}
# ==============================================================================
# MODE: slow — top N endpoints by p95 response time
# Requires the extended (combined_timed) log format — see README.
# Pipeline: tail -> extract (path, ms) -> sort by path -> per-path p95
#           -> sort by p95 desc -> head N. All portable POSIX awk; no
#           gawk-only features (asort / PROCINFO) required.
# ==============================================================================
mode_slow() {
    local n="${1:-10}"
    local window="${SLOW_WINDOW:-1000}"

    # Basic arg validation — integers only, otherwise later arithmetic trips.
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

    # Stream through two awk stages with sort in between so per-path p95 can
    # be computed without multi-dim arrays.
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
        | head -n "$n")

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
        # Truncate absurdly long paths so the table stays aligned. URL paths
        # are ASCII, so ${#path} is safe for width math.
        local display="$path"
        if (( ${#display} > 80 )); then
            display="${display:0:77}..."
        fi
        printf "#%-4d  %b%-9s${NC}  %7d  %s\n" "$i" "$col" "${p95}ms" "$count" "$display"
        i=$((i+1))
    done <<< "$top_rows"
    echo
}

# ==============================================================================
# MODE: stats
# ==============================================================================
mode_stats() {
    local name="${1:-}"
    [[ -z "$name" || ! " ${LOGS[*]} " =~ " $name " ]] && {
        echo -e "${R}Usage: $0 stats <app>${NC}  Apps: ${LOGS[*]}"; exit 1; }
    local file="$LOG_DIR/$name.access.log"
    [[ -f "$file" ]] || { echo -e "${R}Not found: $file${NC}"; exit 1; }
    echo -e "\n${W}── MiLog: Hourly breakdown — ${name} ──${NC}\n"
    awk '{match($4,/\[([0-9]{2}\/[A-Za-z]+\/[0-9]{4}):([0-9]{2})/,a)
         if(a[2]!="")h[a[2]]++}
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

# ==============================================================================
# MODE: suspects — heuristic IP ranking (behavioral, not just UA)
# Scores each IP in the last N log lines across all apps, using:
#   4xx hits      × 2   (probing non-existent paths)
#   5xx hits      × 3   (causing errors)
#   missing UA    × 1   (scripted requests often send "-")
#   scanner UA    + 10  (flat bonus if UA matches known tool)
#   unique paths  / 5   (scanning behavior — many endpoints from one IP)
# Prints top N with flags explaining why.
# ==============================================================================
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

    # Score + top-N in one awk+sort pipeline. Post-aggregation, we pretty-
    # print in bash so we can slot in an optional per-IP country lookup
    # (mmdblookup runs at most $topn times — never per-line).
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

    local sc ip req e4 e5 p_count flags c country
    while IFS=$'\t' read -r sc ip req e4 e5 p_count flags; do
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

# ==============================================================================
# MODE: top-paths — aggregate URLs across all app logs, show per-path stats
#
# The single most useful incident question ("what URL is eating traffic?" or
# "what URL is spiking 5xx?") isn't well served by `top` (IPs) or `slow`
# (p95). This surfaces REQ + 4xx + 5xx + p95 per path. Query string is
# stripped so /search?q=x and /search?q=y collapse into one row.
#
# Pipeline mirrors mode_slow: awk emit → external sort by path → group awk
# → sort by count → head N. p95 requires the extended log format; shows
# "—" when $request_time is absent.
# ==============================================================================
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

    # awk pass 1: extract (path, status, ms-or-"-") per line.
    #   $7  = request URI  (nginx combined: `"GET /path HTTP/1.1"` is fields 6-8)
    #   $9  = status code
    #   $NF = $request_time when combined_timed is in use (plain number)
    # Query string is stripped so /x?a=1 + /x?a=2 collapse to /x.
    #
    # awk pass 2: sort by path + ms-numeric, group, emit count/4xx/5xx/p95.
    # Numeric sort with "-" present: gawk/sort put "-" first (treated as 0),
    # numeric values follow in ascending order — our group-awk only counts
    # numerics into v[], so the p95 position is computed against just the
    # timed samples for each path.
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
        | head -n "$n")

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
            # ASCII placeholder so printf byte-width == visual width. Unicode
            # em-dash is 3 bytes / 1 column → throws off alignment.
            p95_disp=$(printf "%b%9s%b" "$D" "n/a" "$NC")
            col_p95=""
        else
            col_p95=$(tcol "$p95" "$P95_WARN_MS" "$P95_CRIT_MS")
            # 7-wide number + "ms" = 9 visible chars (matches %9s header)
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

# ==============================================================================
# MODE: top
# ==============================================================================
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
    local name
    for name in "${LOGS[@]}"; do
        [[ -f "$LOG_DIR/$name.access.log" ]] \
            && awk '{print $1}' "$LOG_DIR/$name.access.log" >> "$tmp"
    done

    # Geo lookup happens here — after uniq has already collapsed the IP set
    # to at most $n rows, so we fork mmdblookup $n times, not once per line.
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
    echo
}

# ==============================================================================
# MODE: trend — ASCII sparkline chart from metrics_minute history
# Requires HISTORY_ENABLED daemon to have written the DB. Renders two rows
# per app: req/min (green) and 4xx+5xx errors (red). Bucket-aggregates so
# the sparkline fits the fixed 60-char width.
# ==============================================================================
_render_trend_one() {
    local app="$1" since="$2" window_sec="$3" width="$4"

    # SQL buckets row timestamps into exactly `width` columns across the
    # window. Empty columns (no samples) won't appear in output — we fill
    # them in with zeros on the shell side below.
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

    # Sparkline width scales with terminal: 40-char floor so short terms
    # still show something useful; each bucket maps to window_sec/width seconds.
    milog_update_geometry
    local now since width window_sec
    width=$(( INNER - 40 ))
    (( width < 40 )) && width=40
    now=$(date +%s)
    window_sec=$(( hours * 3600 ))
    since=$(( now - window_sec ))

    local -a apps
    if [[ -n "$app_arg" ]]; then
        # Reject app names that can't appear in LOGS, so a typo doesn't
        # render "no data" forever.
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

# Path to the systemd user unit. Kept in sync with _web_service_install.
_WEB_SYSTEMD_UNIT="${HOME}/.config/systemd/user/milog-web.service"

# Is the unit currently active?
_web_service_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl --user is-active --quiet milog-web.service 2>/dev/null
}

# Write the systemd user unit. Idempotent — repeated install just rewrites
# the file with whatever config values are active NOW (so re-running picks
# up `milog config set WEB_PORT 9000` without a second step).
_web_service_install() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${R}systemctl not found — this host doesn't use systemd${NC}" >&2
        echo -e "${D}  use nohup or tmux instead:${NC}" >&2
        echo -e "${D}    nohup milog web > ~/.cache/milog/web.out 2>&1 &${NC}" >&2
        return 1
    fi
    # User services only — no root, no /etc/, no privileged ports.
    if [[ $(id -u) -eq 0 ]]; then
        echo -e "${R}run milog web install-service as your regular user, not root${NC}" >&2
        echo -e "${D}  the web dashboard binds to loopback on a high port — no root needed${NC}" >&2
        return 1
    fi

    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"
    # If we're running from a repo clone, prefer the installed binary at
    # /usr/local/bin/milog — more stable across clone renames / deletes.
    [[ -x /usr/local/bin/milog ]] && self="/usr/local/bin/milog"

    local unit_dir; unit_dir=$(dirname "$_WEB_SYSTEMD_UNIT")
    mkdir -p "$unit_dir" 2>/dev/null \
        || { echo -e "${R}cannot create $unit_dir${NC}" >&2; return 1; }

    # Write the unit. Environment= lines pin the current port/bind so a
    # later `systemctl --user restart` uses the same surface — matches the
    # URL `install-service` prints below.
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

    # If a foreground milog web is already running, it would collide with
    # the about-to-be-started systemd unit on the same port. Warn and stop
    # it first — cleaner than a port-already-in-use failure from socat.
    if [[ -f "$(_web_pid_file)" ]]; then
        local old_pid; old_pid=$(< "$(_web_pid_file)" 2>/dev/null)
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

    local token; token=$(_web_token_read 2>/dev/null)
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

# Locate milog-web, the Go companion binary. Preference order:
#   1. $MILOG_WEB_BIN (explicit override)
#   2. /usr/local/libexec/milog/milog-web (package install location)
#   3. /usr/local/bin/milog-web
#   4. <dir of this script>/../../go/bin/milog-web (clone / dev)
# Echoes the path on success, empty + non-zero on miss.
_web_go_binary() {
    if [[ -n "${MILOG_WEB_BIN:-}" && -x "$MILOG_WEB_BIN" ]]; then
        printf '%s' "$MILOG_WEB_BIN"; return 0
    fi
    local candidate
    for candidate in \
        /usr/local/libexec/milog/milog-web \
        /usr/local/bin/milog-web; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    # Dev/clone path — relative to this script's bundled/unbundled location.
    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"
    local self_dir; self_dir=$(cd "$(dirname "$self")" && pwd)
    # milog bundle is at repo root; go binary at repo/go/bin/milog-web.
    for candidate in "$self_dir/go/bin/milog-web" "$self_dir/../go/bin/milog-web"; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    return 1
}

# Exec milog-web with the bash-env MiLog vars mapped through. The Go
# binary reads the same MILOG_* env set bash exposes, so configuration
# stays single-source. Prints the URL + token once, then hands off.
_web_start_go() {
    local go_bin="$1"
    local token; token=$(_web_token_read)
    local url="http://${WEB_BIND}:${WEB_PORT}/?t=${token}"
    echo -e "${G}✓${NC} starting milog-web (Go)  ${D}${go_bin}${NC}"
    echo -e "${W}  URL:${NC}  ${url}"
    echo -e "${D}  Ctrl+C to stop. --socat forces the legacy bash handler.${NC}"
    # Export the full MILOG_* surface — Go reads these via config.Load().
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
    # Subcommand dispatch — treats a leading --flag as implicit 'start' so
    # `milog web --port 9000` works without the redundant literal 'start'.
    local sub="start"
    case "${1:-}" in
        stop)     _web_stop;   return ;;
        status)   _web_status; return ;;
        start)    shift ;;
        install-service)   _web_service_install;   return ;;
        uninstall-service) _web_service_uninstall; return ;;
        rotate-token)      _web_rotate_token;      return ;;
        ""|--*)   : ;;
        *)        echo -e "${R}usage: milog web [start|stop|status|install-service|uninstall-service|rotate-token] [--port N] [--bind ADDR] [--trust] [--socat]${NC}" >&2
                  return 1 ;;
    esac

    # Parse flags. `--socat` forces the legacy bash handler even when the
    # Go binary is present — useful for A/B debugging and for distros that
    # intentionally don't want the Go binary.
    local trust=0 force_socat=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)   WEB_PORT="${2:?}"; shift 2 ;;
            --bind)   WEB_BIND="${2:?}"; shift 2 ;;
            --trust)  trust=1; shift ;;
            --socat)  force_socat=1; shift ;;
            *)        echo -e "${R}unknown option: $1${NC}" >&2; return 1 ;;
        esac
    done

    [[ "$WEB_PORT" =~ ^[0-9]+$ ]] \
        || { echo -e "${R}--port must be numeric${NC}" >&2; return 1; }

    # Expose-to-network guard — forces explicit consent.
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

    # Already running? Covers both the systemd unit and a foreground pidfile.
    if _web_systemd_active; then
        echo -e "${Y}milog-web.service is already running (systemd). Check: milog web status${NC}"
        return 1
    fi
    if _web_status >/dev/null 2>&1; then
        echo -e "${Y}milog web is already running (foreground). Check: milog web status${NC}"
        return 1
    fi

    # Token + state dirs.
    _web_token_ensure || return 1
    mkdir -p "$WEB_STATE_DIR" 2>/dev/null

    # Prefer the Go binary when available — it handles long-lived SSE
    # connections, serves the same dashboard HTML, and supports the same
    # routes. Falls back to the bash socat handler when the binary isn't
    # installed or when --socat is passed explicitly.
    if (( ! force_socat )); then
        local go_bin
        go_bin=$(_web_go_binary) || go_bin=""
        if [[ -n "$go_bin" ]]; then
            _web_start_go "$go_bin"
            return $?
        fi
    fi

    # Pick a listener.
    local listener=""
    if command -v socat >/dev/null 2>&1; then
        listener="socat"
    elif command -v ncat >/dev/null 2>&1; then
        listener="ncat"
    else
        printf '%b' "
${R}milog web needs socat or ncat to accept connections.${NC}
${D}  sudo apt install -y socat    (Debian/Ubuntu)${NC}
${D}  sudo dnf install -y socat    (RHEL/Fedora/Rocky)${NC}
${D}  sudo pacman -S socat         (Arch)${NC}
" >&2
        return 1
    fi

    # Resolve the milog script path so the per-connection child can re-exec
    # us through the `__web_handler` internal dispatch target. Works whether
    # milog is installed at /usr/local/bin/milog or run from a clone.
    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"

    local token; token=$(_web_token_read)
    local scheme="http"
    local url="${scheme}://${WEB_BIND}:${WEB_PORT}/?t=${token}"

    # printf '%b' interprets the \033[…] escape sequences in $W / $G / $C /
    # $D / $NC. `cat <<EOF` would pass them through literally (you'd see
    # "\033[1;37m" text in the terminal).
    printf '%b' "
${W}MiLog web${NC}  listening on ${G}${WEB_BIND}:${WEB_PORT}${NC}  (${listener}, loopback-only by default)

  ${W}URL:${NC} ${C}${url}${NC}

  ${D}Phone/laptop from another machine:${NC}
    ssh -L ${WEB_PORT}:localhost:${WEB_PORT} \$USER@<this-host>
    open http://localhost:${WEB_PORT}/?t=${token}

  ${D}token:${NC}      ${WEB_TOKEN_FILE}
  ${D}access log:${NC} ${WEB_ACCESS_LOG}
  ${D}stop:${NC}       milog web stop    (or Ctrl+C)

"

    echo $$ > "$(_web_pid_file)"
    trap 'rm -f "$(_web_pid_file)"' EXIT

    # Exec the listener. Both spawn the handler per connection, passing the
    # parsed socket to stdin/stdout.
    case "$listener" in
        socat)
            exec socat "TCP-LISTEN:${WEB_PORT},reuseaddr,fork,bind=${WEB_BIND}" \
                       "EXEC:$self __web_handler"
            ;;
        ncat)
            exec ncat -lk --sh-exec "$self __web_handler" \
                      "$WEB_BIND" "$WEB_PORT"
            ;;
    esac
}

# ==============================================================================
# ==============================================================================
# MODE: ws — WebSocket session metrics (complementary to `slow`)
#
# nginx's `$request_time` for a WebSocket-upgraded connection is the full
# session lifetime (start-of-HTTP-request to socket-close), not request
# latency. `milog slow` / `top-paths` filter WS paths out so they don't
# top the "slowest" table with healthy long-lived sessions. This mode is
# the other side: shows WS sessions on their own terms — count, duration
# distribution, longest, per-path breakdown.
#
# "Which paths are WebSocket?" comes from SLOW_EXCLUDE_PATHS (default:
# "/ws/* /socket.io/*"). One source of truth — customising the exclude
# list moves paths in/out of `ws` at the same time.
#
# Requires the combined_timed log format (with $request_time). Skipping
# silently if no WS samples match in the window.
# ==============================================================================

# Format a duration given in seconds into a short human string.
#   < 1 s          → "<1s"
#   < 60 s         → "Ns"
#   < 3600 s       → "MmSSs"
#   < 86400 s      → "HhMMm"
#   >= 86400 s     → "DdHHh"
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

    # Per-file extraction: emit `app \t path \t ms` for WS-prefixed paths
    # only. Done in a loop rather than `tail -q` so we can tag each line
    # with its source app.
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

    # --- Summary across all apps --------------------------------------------
    # Single awk pass: total count, sum, max, p50/p95, long-session count.
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

    # --- Per-(app, path) breakdown -------------------------------------------
    # Group by app+path, emit: sessions, p50, p95, max per group. Sort by
    # session count desc.
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
show_help() {
    echo -e "
${W}MiLog${NC} — nginx + system monitor

${W}USAGE${NC}  $0 [command] [args]

${W}DASHBOARDS${NC}
  ${C}monitor${NC}            bash dashboard: nginx + CPU/MEM/DISK + workers
                     ${D}keys: q=quit  p=pause  r=refresh  +/-=rate${NC}
  ${C}tui${NC}                rich bubbletea TUI ${D}(needs milog-tui Go binary; build.sh builds it)${NC}
  ${C}rate${NC}               nginx-only req/min dashboard
  ${C}daemon${NC}             headless alerter — no TUI, fires Discord webhooks

${W}ANALYSIS${NC}
  ${C}health${NC}             2xx/3xx/4xx/5xx per app
  ${C}top [N]${NC}            top N source IPs  ${D}(default: 10)${NC}
  ${C}top-paths [N]${NC}      top N URLs — req/4xx/5xx/p95 per path  ${D}(default: 20)${NC}
  ${C}attacker <IP>${NC}      forensic view: one IP's activity across all apps
  ${C}slow [N]${NC}           top N slow endpoints by p95  ${D}(requires \$request_time; excludes WS)${NC}
  ${C}ws [N]${NC}             WebSocket session metrics — count, duration, top paths
  ${C}stats <app>${NC}        hourly request histogram
  ${C}suspects [N] [W]${NC}   heuristic bot ranking ${D}(top N=20, window=2000 lines/app)${NC}
  ${C}trend [app] [H]${NC}    sparkline of req/min from history ${D}(default: all apps, 24h)${NC}
  ${C}diff${NC}               per-app req: now vs 1d ago vs 7d ago
  ${C}auto-tune [D]${NC}      suggest thresholds from history  ${D}(default: 7 days)${NC}
  ${C}replay <file>${NC}      postmortem summary for one archived log file
  ${C}search <pat> ...${NC}   grep across all apps (flags: --since/--app/--path/--regex/--archives)

${W}ALERTING${NC}
  ${C}alert on [URL]${NC}     enable Discord alerts + install systemd service
  ${C}alert off${NC}          disable alerts + stop service
  ${C}alert status${NC}       webhook / service / recent-fire state
  ${C}alert test${NC}         send a test Discord embed right now
  ${C}alerts [window]${NC}    local fire history ${D}(today / Nh / Nd / Nw / all)${NC}
  ${C}silence ...${NC}        mute a rule while on-call works the fix ${D}(milog silence --help)${NC}
  ${C}digest [window]${NC}     exec-summary (day / week / Nh / Nd)

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
  ${C}audit fim${NC}           file integrity monitor (baseline + drift)
  ${C}audit persistence${NC}   re-entry surface diff (new cron / systemd / rc.local)
  ${C}audit ports${NC}         listening-port baseline (new TCP/UDP listeners)
  ${C}bench [--full]${NC}     benchmark harness against synthetic fixtures
  ${C}completions <shell>${NC}  install / print bash|zsh|fish completions

${W}MORE HELP${NC}
  ${C}milog <cmd> --help${NC}    detailed help for any command
  ${C}milog config${NC}          current resolved config + destinations + apps
  ${C}milog doctor${NC}          diagnostic checklist

${D}docs → docs/   ·   source → src/   ·   plan → plan.md (gitignored)${NC}
"
}

# Per-command help registry. Runs when `milog <cmd> --help` is invoked. Keeps
# each block short — usage / args / 1-2 examples. The main `show_help`
# lists all commands; this gives you the details on one without scrolling.
_cmd_help() {
    local cmd="$1"
    case "$cmd" in
        monitor)
            echo -e "${W}milog monitor${NC} — bash dashboard (refresh-and-redraw)"
            echo -e "  ${D}Keys:${NC} q quit  p pause  r refresh  +/- change rate"
            echo -e "  ${D}Tunes:${NC} REFRESH, THRESH_* (see \`milog config\`)"
            echo -e "  ${D}Richer view:${NC} \`milog tui\` (Go bubbletea, same data)"
            ;;
        tui)
            echo -e "${W}milog tui${NC} — bubbletea TUI (Go binary)"
            echo -e "  ${D}Keys:${NC} q quit  p pause  r refresh  +/- change rate  ? help"
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
            echo -e "  Subs: on off status test"
            ;;
        alerts)   echo -e "${W}milog alerts [window]${NC} — fire history (today / Nh / Nd / Nw / all)" ;;
        silence)  echo -e "${W}milog silence <rule> <duration> [message]${NC} — mute a rule"; echo -e "  Also: ${C}milog silence list${NC} · ${C}milog silence clear <rule>${NC}" ;;
        digest)
            echo -e "${W}milog digest [window]${NC} — exec-summary for the period"
            echo -e "  Windows: day (default) / week / 12h / 7d / …"
            ;;
        doctor)   echo -e "${W}milog doctor${NC} — diagnostic checklist" ;;
        web)
            echo -e "${W}milog web${NC} — read-only local HTTP dashboard"
            echo -e "  Subs: start stop status install-service uninstall-service rotate-token"
            ;;
        bench)    echo -e "${W}milog bench [--full] [--baseline FILE]${NC} — timing harness" ;;
        completions) echo -e "${W}milog completions <install|bash|zsh|fish>${NC} — install shell completion" ;;
        install)
            echo -e "${W}milog install <feature>${NC} — on-demand feature installer"
            echo -e "  Subs: list, <feature>, remove <feature>"
            echo -e "  Features: geoip / web / history"
            ;;
        audit)
            echo -e "${W}milog audit <sub>${NC} — point-in-time host integrity scans"
            echo -e "  ${C}fim baseline | check | status${NC}          SHA256 drift on watched files"
            echo -e "  ${C}persistence baseline | check | status${NC}  new files in re-entry surface"
            echo -e "  ${C}ports baseline | check | status${NC}        new TCP/UDP listeners"
            echo -e "  Watcher runs inside ${C}milog daemon${NC} when ${C}AUDIT_ENABLED=1${NC}"
            ;;
        *)
            echo -e "${Y}No detailed help for '$cmd'.${NC} Try ${C}milog help${NC}."
            return 1
            ;;
    esac
}

# ==============================================================================
# DISPATCH
# ==============================================================================
# Intercept `milog <cmd> --help` (and -h) before dispatching to the mode.
# Keeps main `show_help` short while letting each command ship its own
# detail block.
if [[ "${2:-}" == "--help" || "${2:-}" == "-h" ]]; then
    _cmd_help "${1:-}"
    exit $?
fi

case "${1:-}" in
    monitor)  mode_monitor ;;
    tui)      shift; mode_tui "$@" ;;
    daemon)   mode_daemon ;;
    rate)     mode_rate ;;
    health)   mode_health ;;
    top)      mode_top "${2:-10}" ;;
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
    completions) shift; mode_completions "$@" ;;
    bench)    shift; mode_bench "$@" ;;
    install)  shift; mode_install "$@" ;;
    audit)    shift; mode_audit   "$@" ;;
    doctor)   mode_doctor ;;
    web)      shift; mode_web "$@" ;;
    __web_handler) _web_handle ;;
    -h|--help|help) show_help ;;
    ""|logs)  color_prefix ;;
    *)
        # Resolve against LOGS — supports bare names plus `nginx:<name>`,
        # `text:<name>:<path>`, `journal:<unit>`, `docker:<container>`.
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
