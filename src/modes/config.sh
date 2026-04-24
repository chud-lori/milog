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
