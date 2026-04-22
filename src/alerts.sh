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

# Escape a string for safe embedding inside HTML text content. Emits the
# escaped bytes WITHOUT surrounding quotes — caller assembles the tags.
# Used by Telegram (parse_mode=HTML) and Matrix (formatted_body) so an
# attacker-controlled log line can't inject <b>, <a>, or other tags into
# the rendered alert card.
html_escape() {
    local s="${1-}"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    printf '%s' "$s"
}

# Percent-encode a string for safe use in a URL path or query. ASCII
# alphanumerics and the unreserved set (-._~) pass through; everything
# else becomes %HH. Used for the Matrix room ID (contains `!` and `:`)
# and the transaction token that goes into the PUT path.
_url_encode() {
    local s="${1-}" out="" i c
    for (( i=0; i<${#s}; i++ )); do
        c="${s:$i:1}"
        case "$c" in
            [a-zA-Z0-9._~-]) out+="$c" ;;
            *)               out+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    printf '%s' "$out"
}

# Append one alert record to ALERT_STATE_DIR/alerts.log for later inspection
# via `milog alerts`. Silent on error — we never want a disk-full or
# permission blip to crash the caller.
#
# Format: TSV, one line per alert. Fields:
#   <epoch>  <rule_key>  <color_int>  <title>  <body_truncated>
# Body is tab/newline-stripped and capped at 300 chars so each record stays
# on a single line. Reader parses by \t — chosen over CSV to dodge quote
# escaping entirely (log lines often contain quotes, rarely tabs).
_alert_record() {
    local log_file="$ALERT_STATE_DIR/alerts.log"
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 0
    local now; now=$(date +%s)
    local body="${3:-}"
    body="${body//$'\t'/ }"
    body="${body//$'\r'/ }"
    body="${body//$'\n'/ }"
    body="${body:0:300}"
    printf '%s\t%s\t%s\t%s\t%s\n' "$now" "${1:-unknown}" "${4:-0}" "${2:-?}" "$body" \
        >> "$log_file" 2>/dev/null || true
}

# --- Per-destination senders --------------------------------------------------
#
# Each `_alert_send_*` is a private sender for one destination. Contract:
#   - silently return 0 when its config is absent (opt-in)
#   - never propagate errors back to the caller (always `|| true` the curl)
#   - apply the right encoding for its wire format (JSON / HTML / URL)
#
# Attacker-controlled inputs to watch for:
#   - User-Agent, URL path, request headers appear in `body` — any
#     mrkdwn/HTML active in the destination needs escaping.
#   - Mentions (@channel, @everyone, <@role>) must not render: each sender
#     explicitly disables them at the API level where possible.

# Discord incoming-webhook embed. `allowed_mentions.parse=[]` blocks any
# @everyone / <@role> etc. from producing pings. Triple-backtick wraps the
# body so markdown (bold, links) renders as literal text.
_alert_send_discord() {
    [[ -z "${DISCORD_WEBHOOK:-}" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}"
    local payload
    payload=$(printf '{"embeds":[{"title":%s,"description":%s,"color":%d}],"allowed_mentions":{"parse":[]}}' \
        "$(json_escape "$title")" "$(json_escape "$body")" "$color")
    curl -sS -m 5 -H "Content-Type: application/json" \
         -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
}

# Slack incoming-webhook message. Uses mrkdwn with the body wrapped in a
# triple-backtick code block. link_names=0 keeps `<@channel>` literal, not
# a ping.
_alert_send_slack() {
    [[ -z "${SLACK_WEBHOOK:-}" ]] && return 0
    local title="$1" body="$2"
    # body wrapped in ```…``` as a code block — Slack renders it literal.
    local text
    text="*$(json_escape "$title" | sed 's/^"//; s/"$//')*\n\`\`\`$(printf '%s' "$body" | sed 's/`/'\''/g')\`\`\`"
    # json_escape of the whole composed text (keeps \n literal in the
    # payload, Slack interprets \n itself).
    local payload
    payload=$(printf '{"text":%s,"mrkdwn":true,"link_names":0}' \
        "$(json_escape "$text")")
    curl -sS -m 5 -H "Content-Type: application/json" \
         -d "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
}

# Telegram Bot API sendMessage. parse_mode=HTML + html_escape on every
# value blocks <b>/<a>/<script> injection via log lines. Bot tokens look
# like `123456789:ABC-DEF…`; the path is /bot<TOKEN>/sendMessage.
_alert_send_telegram() {
    [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]] && return 0
    local title="$1" body="$2"
    local safe_title safe_body
    safe_title=$(html_escape "$title")
    safe_body=$(html_escape "$body")
    # Build the HTML body inline — we control the tags, attacker controls
    # only the escaped text inside them.
    local text="<b>${safe_title}</b>
<pre>${safe_body}</pre>"
    local payload
    payload=$(printf '{"chat_id":%s,"text":%s,"parse_mode":"HTML","disable_web_page_preview":true,"disable_notification":false}' \
        "$(json_escape "$TELEGRAM_CHAT_ID")" "$(json_escape "$text")")
    curl -sS -m 5 -H "Content-Type: application/json" \
         -d "$payload" "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         >/dev/null 2>&1 || true
}

# Matrix m.room.message (m.text + custom.html). PUT to
#   <homeserver>/_matrix/client/v3/rooms/<room>/send/m.room.message/<txn>
# Room IDs contain `!` and `:` — both must be percent-encoded. Txn is a
# unique-enough epoch+rand combo (deduped server-side for ~5 min by the
# Matrix spec). HTML body is escaped same as Telegram.
_alert_send_matrix() {
    [[ -z "${MATRIX_HOMESERVER:-}" || -z "${MATRIX_TOKEN:-}" || -z "${MATRIX_ROOM:-}" ]] && return 0
    local title="$1" body="$2"
    local safe_title safe_body
    safe_title=$(html_escape "$title")
    safe_body=$(html_escape "$body")
    local formatted="<b>${safe_title}</b><br/><pre>${safe_body}</pre>"
    local plain="${title}

${body}"
    local payload
    payload=$(printf '{"msgtype":"m.text","body":%s,"format":"org.matrix.custom.html","formatted_body":%s}' \
        "$(json_escape "$plain")" "$(json_escape "$formatted")")
    local room_enc txn_id
    room_enc=$(_url_encode "$MATRIX_ROOM")
    txn_id="milog-$(date +%s)-$RANDOM"
    # Strip a possible trailing slash from homeserver so the join is clean.
    local hs="${MATRIX_HOMESERVER%/}"
    curl -sS -m 5 -X PUT \
         -H "Authorization: Bearer ${MATRIX_TOKEN}" \
         -H "Content-Type: application/json" \
         -d "$payload" \
         "${hs}/_matrix/client/v3/rooms/${room_enc}/send/m.room.message/${txn_id}" \
         >/dev/null 2>&1 || true
}

# --- Fanout dispatcher --------------------------------------------------------
#
# Fire one alert to every configured destination. Silently no-ops when
# alerts are disabled; each destination no-ops on missing config.
#
# Signature: alert_fire <title> <body> [color] [rule_key]
#   color    — Discord's color int, reused as severity hint for the alert
#              log (red=crit, yellow=warn, green=info).
#   rule_key — optional `<type>:<scope>` string; logged for `milog alerts`.
#
# Delivery is sequential (milliseconds each); callers that want
# non-blocking fanout pattern `alert_fire "..." "..." color key &`.
alert_fire() {
    [[ "${ALERTS_ENABLED:-0}" != "1" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}"
    # Record before delivery — the log captures "what fired" even if the
    # webhooks fail (network blip, rate limit, rotated token).
    _alert_record "$rule_key" "$title" "$body" "$color"
    command -v curl >/dev/null 2>&1 || return 0
    # Each destination backgrounded so a slow one doesn't delay the others.
    # Callers also typically background `alert_fire &` — the resulting
    # grandchild sends are orphaned to init on exit, which is fine.
    _alert_send_discord  "$title" "$body" "$color" &
    _alert_send_slack    "$title" "$body" "$color" &
    _alert_send_telegram "$title" "$body" "$color" &
    _alert_send_matrix   "$title" "$body" "$color" &
}

# Back-compat alias for `alert_discord`. Drop-in replacement for code that
# hasn't been updated to the new name yet. Prefer `alert_fire` in new code.
alert_discord() { alert_fire "$@"; }

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

