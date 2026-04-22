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
        ""|--*)   : ;;
        *)        echo -e "${R}usage: milog web [start|stop|status|install-service|uninstall-service] [--port N] [--bind ADDR] [--trust]${NC}" >&2
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
