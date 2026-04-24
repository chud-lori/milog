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
DISCORD_WEBHOOK=""
SLACK_WEBHOOK=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
MATRIX_HOMESERVER=""
MATRIX_TOKEN=""
MATRIX_ROOM=""
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

