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
    local d_url s_url tg_token tg_chat mx_hs mx_token mx_room
    d_url=$(_alert_read_webhook "$target_config")
    s_url=$(   _alert_read_key "$target_config" "SLACK_WEBHOOK")
    tg_token=$(_alert_read_key "$target_config" "TELEGRAM_BOT_TOKEN")
    tg_chat=$( _alert_read_key "$target_config" "TELEGRAM_CHAT_ID")
    mx_hs=$(   _alert_read_key "$target_config" "MATRIX_HOMESERVER")
    mx_token=$(_alert_read_key "$target_config" "MATRIX_TOKEN")
    mx_room=$( _alert_read_key "$target_config" "MATRIX_ROOM")

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
    _alert_destinations_status "$d_url" "$s_url" "$tg_token" "$tg_chat" "$mx_hs" "$mx_token" "$mx_room"
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
    # alice's full fanout (Discord + Slack + Telegram + Matrix), not just
    # whatever happens to live in root's env.
    local d_url s_url tg_token tg_chat mx_hs mx_token mx_room
    d_url=$(   _alert_read_webhook "$target_config")
    s_url=$(   _alert_read_key "$target_config" "SLACK_WEBHOOK")
    tg_token=$(_alert_read_key "$target_config" "TELEGRAM_BOT_TOKEN")
    tg_chat=$( _alert_read_key "$target_config" "TELEGRAM_CHAT_ID")
    mx_hs=$(   _alert_read_key "$target_config" "MATRIX_HOMESERVER")
    mx_token=$(_alert_read_key "$target_config" "MATRIX_TOKEN")
    mx_room=$( _alert_read_key "$target_config" "MATRIX_ROOM")

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
    ALERTS_ENABLED=1
    DISCORD_WEBHOOK="$d_url"
    SLACK_WEBHOOK="$s_url"
    TELEGRAM_BOT_TOKEN="$tg_token"; TELEGRAM_CHAT_ID="$tg_chat"
    MATRIX_HOMESERVER="$mx_hs";     MATRIX_TOKEN="$mx_token";  MATRIX_ROOM="$mx_room"

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

