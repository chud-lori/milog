# Token and pidfile helpers for the milog-web Go binary (go/cmd/milog-web); src/modes/web.sh launches it.
# The server is read-only, binds loopback unless --trust, and checks the token file on every request.

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
    # 32 random bytes as hex; openssl is the fallback.
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

_web_pid_file() { echo "$WEB_STATE_DIR/web.pid"; }

_web_token_age() {
    [[ -f "$WEB_TOKEN_FILE" ]] || return 0
    local mtime now delta
    mtime=$(stat -c '%Y' "$WEB_TOKEN_FILE" 2>/dev/null || stat -f '%m' "$WEB_TOKEN_FILE" 2>/dev/null)
    [[ -n "$mtime" ]] || return 0
    now=$(date +%s)
    delta=$(( now - mtime ))
    if   (( delta < 60 ));    then printf '%ds' "$delta"
    elif (( delta < 3600 ));  then printf '%dm' $(( delta / 60 ))
    elif (( delta < 86400 )); then printf '%dh' $(( delta / 3600 ))
    else                           printf '%dd' $(( delta / 86400 ))
    fi
}

# Takes effect on the next request without a restart because the server rereads the token file.
_web_rotate_token() {
    mkdir -p "$(dirname "$WEB_TOKEN_FILE")" 2>/dev/null || true
    rm -f "$WEB_TOKEN_FILE"
    _web_token_ensure || return 1
    local tok; tok=$(_web_token_read)
    [[ -z "$tok" ]] && { echo -e "${R}rotation failed — token file not written${NC}" >&2; return 1; }
    echo -e "${G}✓${NC} rotated web token"
    echo -e "${D}  file: $WEB_TOKEN_FILE${NC}"
    echo -e "${W}  URL:${NC}  http://${WEB_BIND}:${WEB_PORT}/?t=${tok}"
    if _web_systemd_active; then
        echo -e "${D}  service is running — the daemon will accept the new token on next request${NC}"
    fi
    echo -e "${D}  old browser tabs will see 401 until you reopen the URL above${NC}"
}

_web_systemd_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl --user is-active --quiet milog-web.service 2>/dev/null
}

_web_status() {
    # systemd unit first, then the pidfile for foreground runs.
    if _web_systemd_active; then
        local main_pid; main_pid=$(systemctl --user show --value -p MainPID milog-web.service 2>/dev/null)
        echo -e "${G}running${NC}  (systemd user unit)  pid=${main_pid:-?}  bind=${WEB_BIND}:${WEB_PORT}"
        echo -e "${D}  unit:  ${HOME}/.config/systemd/user/milog-web.service${NC}"
        echo -e "${D}  logs:  journalctl --user -u milog-web.service -f${NC}"
        echo -e "${D}  token: $WEB_TOKEN_FILE  (age $(_web_token_age))${NC}"
        return 0
    fi

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
    echo -e "${G}running${NC}  (foreground)  pid=$pid  bind=${WEB_BIND}:${WEB_PORT}"
    echo -e "${D}  token: $WEB_TOKEN_FILE${NC}"
    echo -e "${D}  request log: journalctl / stdout of milog-web${NC}"
    return 0
}

_web_stop() {
    # Killing a systemd-managed process directly would trigger Restart=on-failure.
    if _web_systemd_active; then
        systemctl --user stop milog-web.service 2>/dev/null \
            && echo -e "${G}stopped${NC}  (systemd user unit)" \
            || echo -e "${R}failed to stop milog-web.service${NC}"
        return 0
    fi

    local pf; pf=$(_web_pid_file)
    if [[ ! -f "$pf" ]]; then
        echo -e "${D}not running${NC}"
        return 0
    fi
    local pid; pid=$(< "$pf")
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    # Kill the process group so children die too.
        kill -TERM -- -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        sleep 0.3
        kill -KILL -- -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        echo -e "${G}stopped${NC}  pid=$pid"
    else
        echo -e "${Y}pidfile stale; cleaning${NC}"
    fi
    rm -f "$pf"
}
