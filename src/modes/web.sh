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
    # it first — cleaner than a port-already-in-use failure on socket bind.
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

# Print actionable instructions when milog-web isn't on disk. install.sh
# fetches it from a GitHub Release as part of curl-pipe install; the most
# common reason to land here is a manual `git clone && bash milog.sh web`
# without running install. Errors out non-zero so service starts fail loudly.
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
  <script-dir>/go/bin/milog-web        (clone / dev)
  <script-dir>/../go/bin/milog-web

" >&2
}

# Exec milog-web with the bash-env MiLog vars mapped through. The Go
# binary reads the same MILOG_* env set bash exposes, so configuration
# stays single-source. Prints the URL + token once, then hands off.
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
    # Track the exec'd Go binary's pid for `milog web stop`. Written
    # before exec so foreground `Ctrl+C` works without an intermediate
    # supervisor process.
    echo $$ > "$(_web_pid_file)"
    trap 'rm -f "$(_web_pid_file)"' EXIT

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

    # The Go binary is the dashboard server. No bash fallback — keeping
    # two implementations in sync was the whole reason the bash router
    # got deleted.
    local go_bin
    go_bin=$(_web_go_binary) || { _web_no_binary_error; return 1; }
    _web_start_go "$go_bin"
}

# ==============================================================================
