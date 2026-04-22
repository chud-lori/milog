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
