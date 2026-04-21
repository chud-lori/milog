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
[[ -n "${MILOG_GEOIP_ENABLED:-}"   ]] && GEOIP_ENABLED="$MILOG_GEOIP_ENABLED"
[[ -n "${MILOG_MMDB_PATH:-}"       ]] && MMDB_PATH="$MILOG_MMDB_PATH"
[[ -n "${MILOG_HISTORY_ENABLED:-}" ]] && HISTORY_ENABLED="$MILOG_HISTORY_ENABLED"
[[ -n "${MILOG_HISTORY_DB:-}"      ]] && HISTORY_DB="$MILOG_HISTORY_DB"

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
    tmp="$state_file.tmp.$$"
    {
        awk -v k="$key" -F'\t' 'BEGIN{OFS="\t"} $1!=k' "$state_file" 2>/dev/null
        printf '%s\t%s\n' "$key" "$now"
    } > "$tmp" && mv "$tmp" "$state_file"
    return 0
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
# Table columns: APP(10) | REQ/MIN(8) | STATUS(10) | INTENSITY(35)
# Row layout between outer │…│:
#   " " app(10) " │ " req(8) " │ " status(10) " │ " bar(35) " "
#   = 1+10 + 3+8 + 3+10 + 3+35+1 = 74
# Box rules:  ─(12)┬─(10)┬─(12)┬─(37) = 12+1+10+1+12+1+37 = 74  ✓
# ==============================================================================
W_APP=10; W_REQ=8; W_ST=10; W_BAR=35
INNER=74   # verified: row chars == rule chars == 74

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
        echo -e "${D}  install with: curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash -s -- --with-history${NC}" >&2
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

        local BW=11  # bar width: (INNER=74 - 39 fixed chars) / 3 cols = 11 max
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
# MODE: rate — nginx-only
# ==============================================================================
mode_rate() {
    while true; do
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
                    if alert_should_fire "probe:$app"; then
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
                    if alert_should_fire "exploit:$app:$cat_slug"; then
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

    local now since width=60 window_sec
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
  ${C}slow [N]${NC}           top N slow endpoints by p95  ${D}(requires \$request_time)${NC}
  ${C}stats <app>${NC}        hourly request histogram
  ${C}suspects [N] [W]${NC}   heuristic bot ranking ${D}(top N=20, window=2000 lines/app)${NC}
  ${C}trend [app] [H]${NC}    sparkline of req/min from history ${D}(default: all apps, 24h)${NC}
  ${C}diff${NC}               per-app req: now vs 1d ago vs 7d ago
  ${C}replay <file>${NC}      postmortem summary for one archived log file

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
    slow)     mode_slow "${2:-10}" ;;
    stats)    mode_stats "${2:-}" ;;
    trend)    mode_trend "${2:-}" "${3:-24}" ;;
    replay)   mode_replay "${2:-}" ;;
    diff)     mode_diff ;;
    grep)     mode_grep "${2:-}" "${3:-.}" ;;
    errors)   mode_errors ;;
    exploits) mode_exploits ;;
    probes)   mode_probes ;;
    suspects) mode_suspects "${2:-20}" "${3:-2000}" ;;
    config)   shift; mode_config "$@" ;;
    -h|--help|help) show_help ;;
    ""|logs)  color_prefix ;;
    *)
        if [[ " ${LOGS[*]} " =~ " $1 " ]]; then
            tail -F "$LOG_DIR/$1.access.log"
        else
            echo -e "${R}Unknown command: '$1'${NC}"; show_help; exit 1
        fi ;;
esac
