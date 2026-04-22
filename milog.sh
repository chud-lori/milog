#!/usr/bin/env bash
# ==============================================================================
# MiLog — Nginx + System Monitor (V5.0)
# ==============================================================================
set -euo pipefail

# --- Configuration (defaults; overridable via config file or env) ---
LOG_DIR="/var/log/nginx"
LOGS=("dolanan" "ethok" "finance" "ldr" "profile" "sinepil")
REFRESH=5

# Discord alerts (off by default; set DISCORD_WEBHOOK + ALERTS_ENABLED=1)
DISCORD_WEBHOOK=""
ALERTS_ENABLED=0
ALERT_COOLDOWN=300
# Cross-rule dedup window: when multiple rules (e.g. exploits + probes) match
# the same logline, only the first to fire records the (ip, path) fingerprint;
# the second sees it fresh and suppresses. Tunes how long one event remains
# "already reported" across distinct rules. Kept separate from ALERT_COOLDOWN
# so rule-level and event-level suppression can evolve independently.
ALERT_DEDUP_WINDOW=300
ALERT_STATE_DIR="$HOME/.cache/milog"

# Response-time percentile thresholds (milliseconds) — used to colour the p95
# tag in the monitor dashboard. Requires nginx to log $request_time; see
# README → "Response-time percentiles".
P95_WARN_MS=500
P95_CRIT_MS=1500

# `milog slow` window (lines/app scanned from tail). Larger = wider history
# but slower reads. Hour-of-traffic is a reasonable default on most sites.
SLOW_WINDOW=1000

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
[[ -n "${MILOG_GEOIP_ENABLED:-}"   ]] && GEOIP_ENABLED="$MILOG_GEOIP_ENABLED"
[[ -n "${MILOG_MMDB_PATH:-}"       ]] && MMDB_PATH="$MILOG_MMDB_PATH"
[[ -n "${MILOG_HISTORY_ENABLED:-}" ]] && HISTORY_ENABLED="$MILOG_HISTORY_ENABLED"
[[ -n "${MILOG_HISTORY_DB:-}"      ]] && HISTORY_DB="$MILOG_HISTORY_DB"
[[ -n "${MILOG_WEB_PORT:-}"        ]] && WEB_PORT="$MILOG_WEB_PORT"
[[ -n "${MILOG_WEB_BIND:-}"        ]] && WEB_BIND="$MILOG_WEB_BIND"

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

# Fire a Discord webhook embed. Silently no-ops when alerts are disabled,
# no webhook is configured, or curl is missing. Never crashes callers —
# on any error the TUI must keep rendering.
#
# Security: bodies frequently contain attacker-controlled log-line bytes
# (User-Agent, URL path, headers). We set allowed_mentions.parse=[] so an
# embedded `@everyone` or `<@&roleid>` never produces a real ping. The
# triple-backtick code block protects markdown rendering; allowed_mentions
# protects the Discord pings surface.
#   $1 title   $2 body   $3 color_int  (decimal; default 15158332 = red)
alert_discord() {
    [[ "${ALERTS_ENABLED:-0}" != "1" ]] && return 0
    [[ -z "${DISCORD_WEBHOOK:-}" ]]     && return 0
    command -v curl >/dev/null 2>&1     || return 0
    local title="$1" body="$2" color="${3:-15158332}"
    local payload
    payload=$(printf '{"embeds":[{"title":%s,"description":%s,"color":%d}],"allowed_mentions":{"parse":[]}}' \
        "$(json_escape "$title")" "$(json_escape "$body")" "$color")
    curl -sS -m 5 -H "Content-Type: application/json" \
         -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
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
nginx_check_http_alerts() {
    local name="$1" c4="$2" c5="$3"
    if (( c5 >= THRESH_5XX_WARN )) && alert_should_fire "5xx:$name"; then
        alert_discord "5xx spike: $name" "${c5} 5xx responses in the last minute (threshold ${THRESH_5XX_WARN})" 15158332 &
    fi
    if (( c4 >= THRESH_4XX_WARN )) && alert_should_fire "4xx:$name"; then
        alert_discord "4xx spike: $name" "${c4} 4xx responses in the last minute (threshold ${THRESH_4XX_WARN})" 16753920 &
    fi
}

# System rule-hook — fires CPU/MEM/DISK/workers alerts. Shared by monitor
# and daemon so threshold logic has one home.
sys_check_alerts() {
    local cpu="$1" mem_pct="$2" mem_used="$3" mem_total="$4"
    local disk_pct="$5" disk_used="$6" disk_total="$7" worker_count="$8"
    if (( cpu >= THRESH_CPU_CRIT )) && alert_should_fire "cpu"; then
        alert_discord "CPU critical" "CPU at ${cpu}% (crit=${THRESH_CPU_CRIT}%)" 15158332 &
    fi
    if (( mem_pct >= THRESH_MEM_CRIT )) && alert_should_fire "mem"; then
        alert_discord "Memory critical" "MEM at ${mem_pct}% — used ${mem_used}MB of ${mem_total}MB (crit=${THRESH_MEM_CRIT}%)" 15158332 &
    fi
    if (( disk_pct >= THRESH_DISK_CRIT )) && alert_should_fire "disk:/"; then
        alert_discord "Disk critical" "Disk at ${disk_pct}% on / — ${disk_used}GB of ${disk_total}GB used (crit=${THRESH_DISK_CRIT}%)" 15158332 &
    fi
    if (( worker_count == 0 )) && alert_should_fire "workers"; then
        alert_discord "Nginx workers down" "Zero nginx worker processes detected on $(hostname 2>/dev/null || echo host)" 15158332 &
    fi
}

nginx_row() {
    local name="$1" CUR_TIME="$2" TOTAL_ref="$3"
    local count=0 c2=0 c3=0 c4=0 c5=0

    read -r count c2 c3 c4 c5 <<< "$(nginx_minute_counts "$name" "$CUR_TIME")"
    count=${count:-0}; c4=${c4:-0}; c5=${c5:-0}
    # shellcheck disable=SC2034
    eval "$TOTAL_ref=$(( ${!TOTAL_ref} + count ))"

    local st_plain st_col b_col alert=""
    if [[ $count -gt 0 ]]; then
        st_plain="● ACTIVE  "; st_col="${G}● ACTIVE  ${NC}"; b_col=$G
        [[ $count -gt $THRESH_REQ_WARN ]] && b_col=$Y
        [[ $count -gt $THRESH_REQ_CRIT ]] && { b_col=$R; st_col="${R}● ACTIVE  ${NC}"; }
    else
        st_plain="○ IDLE    "; st_col="${D}○ IDLE    ${NC}"; b_col=$D
    fi

    [[ $c5 -ge $THRESH_5XX_WARN ]]                   && alert="$RBLINK"
    [[ $c4 -ge $THRESH_4XX_WARN && -z "$alert" ]]    && alert="$R"
    [[ $count -gt $THRESH_REQ_CRIT && -z "$alert" ]] && alert="$R"

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
        local pcol
        pcol=$(tcol "$p95_ms" "$P95_WARN_MS" "$P95_CRIT_MS")
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
  td.n { text-align:right; font-variant-numeric: tabular-nums; }
  td.err4 { color:#d29922; }
  td.err5 { color:#f85149; }
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

  tick();
  setInterval(tick, 3000);
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

_web_status() {
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
    echo -e "${G}running${NC}  pid=$pid  bind=${WEB_BIND}:${WEB_PORT}"
    echo -e "${D}  token: $WEB_TOKEN_FILE${NC}"
    echo -e "${D}  access log: $WEB_ACCESS_LOG${NC}"
    if [[ -f "$WEB_ACCESS_LOG" ]]; then
        local hits; hits=$(wc -l < "$WEB_ACCESS_LOG" 2>/dev/null || echo 0)
        echo -e "${D}  ${hits} requests served${NC}"
    fi
    return 0
}

_web_stop() {
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
# MODE: alert — toggle Discord alerting + manage the systemd service
#
# Subcommands:
#   on [WEBHOOK_URL]  — set webhook (optional), enable, install+start systemd
#   off               — disable alerts, stop + disable systemd
#   status            — show webhook/service/recent-fire state
#   test              — fire a one-off Discord test embed (bypasses cooldown)
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

    local wh wh_state enabled svc_state
    wh=$(_alert_read_webhook "$target_config")
    if [[ -n "$wh" ]]; then wh_state="${G}set${NC}"; else wh_state="${R}unset${NC}"; fi

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
    printf "  %-18s %b\n"  "webhook"         "$wh_state"
    printf "  %-18s %s\n"  "ALERTS_ENABLED"  "$enabled"
    printf "  %-18s %ss\n" "cooldown"        "${ALERT_COOLDOWN:-300}"
    printf "  %-18s %s\n"  "state dir"       "${ALERT_STATE_DIR:-$HOME/.cache/milog}"
    printf "  %-18s %s\n"  "config"          "$target_config"
    printf "  %-18s %b\n"  "systemd service" "$svc_state"

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
    local target_user target_home target_config webhook
    target_user=$(_alert_target_user)
    target_home=$(_alert_target_home "$target_user")
    target_config="$target_home/.config/milog/config.sh"

    # Prefer the target-user's config over whatever this process loaded at
    # startup — handles `sudo milog alert test` reading alice's webhook.
    webhook=$(_alert_read_webhook "$target_config")
    [[ -z "$webhook" ]] && webhook="${DISCORD_WEBHOOK:-}"
    if [[ -z "$webhook" ]]; then
        echo -e "${R}no DISCORD_WEBHOOK configured${NC}" >&2
        echo "  set one first:  milog alert on 'https://discord.com/api/webhooks/ID/TOKEN'" >&2
        return 1
    fi

    # Temporarily force the gate regardless of ALERTS_ENABLED state — this
    # is a manual test of the webhook wire, not a rule-triggered alert.
    local _saved_enabled="$ALERTS_ENABLED" _saved_webhook="$DISCORD_WEBHOOK"
    ALERTS_ENABLED=1
    DISCORD_WEBHOOK="$webhook"

    echo "Firing test alert to Discord..."
    alert_discord "MiLog test alert" \
        "Manual test from \`$(hostname 2>/dev/null || echo host)\` at $(date -Iseconds 2>/dev/null || date)" \
        3447003

    ALERTS_ENABLED="$_saved_enabled"
    DISCORD_WEBHOOK="$_saved_webhook"
    echo -e "${G}✓${NC} webhook call returned — check your Discord channel"
}

alert_help() {
    echo -e "
${W}milog alert${NC} — toggle Discord alerting and manage the systemd service

${W}USAGE${NC}
  ${C}milog alert on [WEBHOOK_URL]${NC}  enable alerts; install + start systemd
  ${C}milog alert off${NC}                disable alerts; stop + disable service
  ${C}milog alert status${NC}             show webhook/service/recent-fire state
  ${C}milog alert test${NC}               send a one-shot Discord test embed

${W}EXAMPLES${NC}
  ${D}# First-time setup in one command:${NC}
  sudo milog alert on 'https://discord.com/api/webhooks/ID/TOKEN'

  ${D}# Verify end-to-end:${NC}
  milog alert status
  milog alert test

  ${D}# Pause alerting during maintenance:${NC}
  sudo milog alert off
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
    printf "  %-22s webhook=%s enabled=%s cooldown=%ss\n" "discord alerts" \
        "$([[ -n "$DISCORD_WEBHOOK" ]] && echo set || echo unset)" "$ALERTS_ENABLED" "$ALERT_COOLDOWN"
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
    local f="$LOG_DIR/$name.access.log"
    [[ -f "$f" ]] || echo -e "${D}  note: $f does not exist yet${NC}"
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
        -h|--help|help) config_help ;;
        *) echo -e "${R}Unknown config subcommand:${NC} $sub"; config_help; exit 1 ;;
    esac
}

# ==============================================================================
# COLOR PREFIX — merged initial dump sorted by nginx timestamp, then live tails
# ==============================================================================
color_prefix() {
    local pids=()
    local colors=("$B" "$C" "$G" "$M" "$Y" "$R")
    local -a F_files=() F_cols=() F_labels=()
    local i=0
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$i]}"
        local label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            F_files+=("$file")
            F_cols+=("$col")
            F_labels+=("$label")
        fi
        (( i++ )) || true
    done

    # Initial dump: last 10 lines from every file, merged and sorted by log timestamp
    # so output is globally by recency rather than grouped per app.
    {
        local idx
        for idx in "${!F_files[@]}"; do
            tail -n 10 "${F_files[$idx]}" 2>/dev/null | \
                awk -v col="${F_cols[$idx]}" -v lbl="${F_labels[$idx]}" -v nc="$NC" '
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

    # Live tails: parallel, naturally interleaved by arrival time.
    # -n 0 suppresses each tail's own initial dump (we already emitted a merged one).
    for idx in "${!F_files[@]}"; do
        tail -n 0 -F "${F_files[$idx]}" 2>/dev/null | \
            awk -v col="${F_cols[$idx]}" -v lbl="${F_labels[$idx]}" -v nc="$NC" \
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
    local hook_state
    hook_state="disabled"
    [[ "$ALERTS_ENABLED" == "1" && -n "$DISCORD_WEBHOOK" ]] && hook_state="enabled"
    _dlog "milog daemon starting — refresh=${REFRESH}s alerts=${hook_state} history=${HISTORY_ENABLED} apps=(${LOGS[*]})"
    [[ "$ALERTS_ENABLED" != "1" ]] && _dlog "WARNING: ALERTS_ENABLED=0 — rules will log but no webhooks will be fired"
    [[ -z "$DISCORD_WEBHOOK"    ]] && _dlog "WARNING: DISCORD_WEBHOOK empty — no webhooks will be fired"

    history_init   # no-op when HISTORY_ENABLED=0; disables itself on error

    # Live-tail watchers for exploit + probe rules. Their stdout is suppressed;
    # the alert call sites inside each mode fire webhooks directly.
    local watcher_pids=()
    ( mode_exploits > /dev/null ) & watcher_pids+=($!)
    ( mode_probes   > /dev/null ) & watcher_pids+=($!)

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
        _doc_ok "ALERTS_ENABLED=1  (cooldown=${ALERT_COOLDOWN}s)"
    else
        _doc_warn "ALERTS_ENABLED=0" "alerts are armed but disabled — 'milog alert on' to flip"
        warn=$(( warn + 1 ))
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

    # ---- systemd unit (only meaningful where systemd is installed) ----------
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
# MODE: errors
# ==============================================================================
mode_errors() {
    echo -e "${D}Watching 4xx/5xx across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0
    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$i]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            tail -F "$file" 2>/dev/null | \
                grep --line-buffered ' [45][0-9][0-9] ' | \
                awk -v col="$col" -v lbl="$label" -v nc="$NC" \
                    '{print col"["lbl"]"nc" "$0; fflush()}' &
            pids+=($!)
        fi
        (( i++ )) || true
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
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
                        alert_discord "Exploit attempt: $app / $cat_slug" "\`\`\`${line:0:1800}\`\`\`" 15158332 &
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
# MODE: grep
# ==============================================================================
mode_grep() {
    local name="${1:-}" pattern="${2:-.}"
    [[ -z "$name" || ! " ${LOGS[*]} " =~ " $name " ]] && {
        echo -e "${R}Usage: $0 grep <app> <pattern>${NC}  Apps: ${LOGS[*]}"; exit 1; }
    echo -e "${D}tail -F $LOG_DIR/$name.access.log | grep '$pattern'  (Ctrl+C)${NC}\n"
    tail -F "$LOG_DIR/$name.access.log" | grep --line-buffered -i "$pattern"
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
        local c4=$NC c5=$NC
        [[ $s4 -gt $THRESH_4XX_WARN ]] && c4=$Y
        [[ $s5 -gt $THRESH_5XX_WARN ]] && c5=$R
        printf "%-12s  %8s  %8s  %8s  ${c4}%8s${NC}  ${c5}%8s${NC}\n" \
            "$name" "$total" "$s2" "$s3" "$s4" "$s5"
    done
    echo ""
}

# ==============================================================================
# MODE: monitor
# ==============================================================================
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
                        alert_discord "Probe traffic: $app" "\`\`\`${line:0:1800}\`\`\`" 15844367 &
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
        | awk '
            $NF ~ /^[0-9]+(\.[0-9]+)?$/ && NF >= 8 {
                path = $7
                q = index(path, "?")
                if (q > 0) path = substr(path, 1, q - 1)
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
        | awk '
            NF >= 9 {
                path = $7
                q = index(path, "?")
                if (q > 0) path = substr(path, 1, q - 1)
                if (length(path) == 0) next
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

mode_web() {
    # Subcommand dispatch — treats a leading --flag as implicit 'start' so
    # `milog web --port 9000` works without the redundant literal 'start'.
    local sub="start"
    case "${1:-}" in
        stop)     _web_stop;   return ;;
        status)   _web_status; return ;;
        start)    shift ;;
        ""|--*)   : ;;
        *)        echo -e "${R}usage: milog web [start|stop|status] [--port N] [--bind ADDR] [--trust]${NC}" >&2
                  return 1 ;;
    esac

    # Parse flags
    local trust=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)  WEB_PORT="${2:?}"; shift 2 ;;
            --bind)  WEB_BIND="${2:?}"; shift 2 ;;
            --trust) trust=1; shift ;;
            *)       echo -e "${R}unknown option: $1${NC}" >&2; return 1 ;;
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

    # Already running?
    if _web_status >/dev/null 2>&1; then
        echo -e "${Y}milog web is already running (milog web status).${NC}"
        return 1
    fi

    # Token + state dirs.
    _web_token_ensure || return 1
    mkdir -p "$WEB_STATE_DIR" 2>/dev/null

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
show_help() {
    echo -e "
${W}MiLog${NC} — nginx + system monitor

${W}USAGE${NC}  $0 [command] [args]

${W}DASHBOARDS${NC}
  ${C}monitor${NC}            full TUI: nginx + CPU/MEM/DISK/NET + workers
                     ${D}keys: q=quit  p=pause  r=refresh  +/-=rate${NC}
  ${C}rate${NC}               nginx-only req/min dashboard
  ${C}daemon${NC}             headless alerter — no TUI, fires Discord webhooks

${W}ANALYSIS${NC}
  ${C}health${NC}             2xx/3xx/4xx/5xx per app
  ${C}top [N]${NC}            top N source IPs  ${D}(default: 10)${NC}
  ${C}top-paths [N]${NC}      top N URLs — req/4xx/5xx/p95 per path  ${D}(default: 20)${NC}
  ${C}attacker <IP>${NC}      forensic view: one IP's activity across all apps
  ${C}slow [N]${NC}           top N slow endpoints by p95  ${D}(requires \$request_time)${NC}
  ${C}stats <app>${NC}        hourly request histogram
  ${C}suspects [N] [W]${NC}   heuristic bot ranking ${D}(top N=20, window=2000 lines/app)${NC}
  ${C}trend [app] [H]${NC}    sparkline of req/min from history ${D}(default: all apps, 24h)${NC}
  ${C}diff${NC}               per-app req: now vs 1d ago vs 7d ago
  ${C}auto-tune [D]${NC}      suggest thresholds from history  ${D}(default: 7 days)${NC}
  ${C}replay <file>${NC}      postmortem summary for one archived log file

${W}ALERTING${NC}
  ${C}alert on [URL]${NC}     enable Discord alerts + install systemd service
  ${C}alert off${NC}          disable alerts + stop service
  ${C}alert status${NC}       webhook / service / recent-fire state
  ${C}alert test${NC}         send a test Discord embed right now

${W}DIAGNOSTICS${NC}
  ${C}doctor${NC}             checklist: tools, logs, log format, webhook, history, geoip, systemd

${W}WEB UI${NC} ${D}(read-only, token-gated, loopback-only by default)${NC}
  ${C}web${NC}                start the local HTTP dashboard
  ${C}web stop${NC}           kill the running dashboard
  ${C}web status${NC}         is it running? on what port?

${W}CONFIG${NC}
  ${C}config${NC}             show resolved config + path
  ${C}config init${NC}        create template config file
  ${C}config add <app>${NC}   append app to LOGS
  ${C}config rm  <app>${NC}   remove app from LOGS
  ${C}config dir <path>${NC}  set LOG_DIR
  ${C}config set <K> <V>${NC} set any variable (REFRESH, THRESH_*, …)
  ${C}config edit${NC}        open in \$EDITOR

${W}TAILING${NC}
  ${C}(none) / logs${NC}      tail all logs, color prefixed  ${D}<- default${NC}
  ${C}errors${NC}             4xx/5xx lines only
  ${C}exploits${NC}           LFI / RCE / SQLi / XSS / infra-probe payloads
  ${C}probes${NC}             scanner/bot traffic
  ${C}grep <app> <pat>${NC}   filter-tail one app
  ${C}<app>${NC}              raw tail for one app

${W}THRESHOLDS${NC}
  req/min  warn=${THRESH_REQ_WARN}  crit=${THRESH_REQ_CRIT}
  cpu      warn=${THRESH_CPU_WARN}%  crit=${THRESH_CPU_CRIT}%
  mem      warn=${THRESH_MEM_WARN}%  crit=${THRESH_MEM_CRIT}%
  4xx      warn=${THRESH_4XX_WARN}   5xx warn=${THRESH_5XX_WARN}
  p95      warn=${P95_WARN_MS}ms  crit=${P95_CRIT_MS}ms

${W}APPS${NC}  ${LOGS[*]}
  ${D}dir:${NC} ${LOG_DIR}
  ${D}config:${NC} ${MILOG_CONFIG}  ${D}(override LOG_DIR, LOGS, REFRESH, thresholds)${NC}
  ${D}env:${NC} MILOG_LOG_DIR, MILOG_APPS=\"a b c\", MILOG_CONFIG=/path/to/config.sh
  ${D}auto-discover:${NC} if LOGS is empty, all ${LOG_DIR}/*.access.log are picked up
"
}

# ==============================================================================
# DISPATCH
# ==============================================================================
case "${1:-}" in
    monitor)  mode_monitor ;;
    daemon)   mode_daemon ;;
    rate)     mode_rate ;;
    health)   mode_health ;;
    top)      mode_top "${2:-10}" ;;
    top-paths|toppaths) mode_top_paths "${2:-20}" "${3:-}" ;;
    attacker) mode_attacker "${2:-}" ;;
    slow)     mode_slow "${2:-10}" ;;
    stats)    mode_stats "${2:-}" ;;
    trend)    mode_trend "${2:-}" "${3:-24}" ;;
    replay)   mode_replay "${2:-}" ;;
    diff)     mode_diff ;;
    auto-tune|autotune|tune) mode_auto_tune "${2:-7}" ;;
    grep)     mode_grep "${2:-}" "${3:-.}" ;;
    errors)   mode_errors ;;
    exploits) mode_exploits ;;
    probes)   mode_probes ;;
    suspects) mode_suspects "${2:-20}" "${3:-2000}" ;;
    config)   shift; mode_config "$@" ;;
    alert)    shift; mode_alert  "$@" ;;
    doctor)   mode_doctor ;;
    web)      shift; mode_web "$@" ;;
    __web_handler) _web_handle ;;
    -h|--help|help) show_help ;;
    ""|logs)  color_prefix ;;
    *)
        if [[ " ${LOGS[*]} " =~ " $1 " ]]; then
            tail -F "$LOG_DIR/$1.access.log"
        else
            echo -e "${R}Unknown command: '$1'${NC}"; show_help; exit 1
        fi ;;
esac
