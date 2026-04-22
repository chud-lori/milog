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

