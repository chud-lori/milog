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
    alert_fire "MiLog test alert" \
        "Manual test from \`$(hostname 2>/dev/null || echo host)\` at $(date -Iseconds 2>/dev/null || date)" \
        3447003 "alert:test"

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

