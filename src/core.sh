#!/usr/bin/env bash
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
#   LOGS=(api text:rails:/var/log/rails/production.log nginx:gateway)
#
# Resolution:
#   bare `api`                    → nginx type, path = $LOG_DIR/api.access.log
#   `nginx:api`                   → same (explicit)
#   `text:<name>:<absolute path>` → any text file, path = <absolute path>
#
# Parser-free modes (logs, grep, search, <name> tail) work for every source
# type. Parsing modes (monitor, top, slow, top-paths, etc.) skip non-nginx
# sources gracefully — they need combined log format to work.

# Return the file path for a LOGS entry — bare name or typed prefix.
_log_path_for() {
    local entry="${1-}"
    case "$entry" in
        text:*:*) printf '%s' "${entry#text:*:}" ;;
        nginx:*)  printf '%s/%s.access.log' "$LOG_DIR" "${entry#nginx:}" ;;
        *)        printf '%s/%s.access.log' "$LOG_DIR" "$entry" ;;
    esac
}

# Return the type for a LOGS entry.
_log_type_for() {
    case "${1-}" in
        text:*) printf 'text' ;;
        nginx:*) printf 'nginx' ;;
        *) printf 'nginx' ;;
    esac
}

# Return the display name (strip type prefix and path).
_log_name_for() {
    local entry="${1-}"
    case "$entry" in
        text:*:*) local rest="${entry#text:}"; printf '%s' "${rest%%:*}" ;;
        nginx:*)  printf '%s' "${entry#nginx:}" ;;
        *)        printf '%s' "$entry" ;;
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

