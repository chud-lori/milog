# Alert delivery, silences, routing, cooldown and dedup.

# Output includes the surrounding double quotes.
json_escape() {
    local s="${1-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\b'/\\b}"
    s="${s//$'\f'/\\f}"
    # Remaining C0 controls as \u00XX; NUL can't occur in a bash string.
    if [[ "$s" == *[[:cntrl:]]* ]]; then
        local i h c u
        for (( i=1; i<32; i++ )); do
            printf -v h '%02x' "$i"
            printf -v c "\\x$h"
            printf -v u '\\u00%s' "$h"
            s="${s//"$c"/"$u"}"
        done
    fi
    printf '"%s"' "$s"
}

# Code-fence text; backticks become ' so a log line can't close the fence.
_alert_fence() {
    local s="${1-}"
    printf '```%s```' "${s//\`/\'}"
}

# No surrounding quotes. Keeps log text from injecting tags into Telegram/Matrix HTML.
html_escape() {
    local s="${1-}"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    printf '%s' "$s"
}

# Matrix room IDs contain `!` and `:`, which must be encoded in the PUT path.
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

# Truncates to about the newest half of ALERT_LOG_MAX_BYTES; never fails the alert path.
_alert_rotate_if_big() {
    local f="$1"
    local max="${ALERT_LOG_MAX_BYTES:-10485760}"
    [[ "$max" =~ ^[0-9]+$ ]] && (( max > 0 )) || return 0
    [[ -f "$f" ]] || return 0
    local sz
    # GNU stat (-c) vs BSD stat (-f). Both harmless-fail on missing file.
    sz=$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f" 2>/dev/null) || return 0
    [[ "$sz" =~ ^[0-9]+$ ]] || return 0
    (( sz > max )) || return 0
    local half=$(( max / 2 )) tmp
    tmp=$(mktemp "${f}.rot.XXXXXX" 2>/dev/null) || return 0
    # tail -c lands mid-line, so drop the first partial record.
    tail -c "$half" "$f" 2>/dev/null | tail -n +2 > "$tmp" 2>/dev/null
    mv "$tmp" "$f" 2>/dev/null || rm -f "$tmp"
}

# alerts.log is TSV: epoch, rule_key, color, title, body (tabs/newlines flattened, 300 chars max).
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
    _alert_rotate_if_big "$log_file"
}

# Log a failed delivery (network or HTTP >= 400) for `milog doctor`.
_alert_send_failed() {
    local log_file="$ALERT_STATE_DIR/send_failures.log"
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 0
    printf '%s\t%s\n' "$(date +%s)" "${1:-unknown}" >> "$log_file" 2>/dev/null || true
    _alert_rotate_if_big "$log_file"
}

# Senders return 0 when unconfigured and record failures with _alert_send_failed.
# The body carries attacker-controlled log text, so each sender escapes it and disables mentions where the API allows.

# allowed_mentions.parse=[] stops @everyone / role pings.
_alert_send_discord() {
    [[ -z "${DISCORD_WEBHOOK:-}" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}"
    local payload
    payload=$(printf '{"embeds":[{"title":%s,"description":%s,"color":%d}],"allowed_mentions":{"parse":[]}}' \
        "$(json_escape "$title")" "$(json_escape "$body")" "$color")
    curl -sS -f -m 5 -H "Content-Type: application/json" \
         -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || _alert_send_failed discord
}

# link_names=0 keeps `<@channel>` literal; the body goes in a code block with backticks swapped for single quotes.
_alert_send_slack() {
    [[ -z "${SLACK_WEBHOOK:-}" ]] && return 0
    local title="$1" body="$2"
    local text
    text="*$(json_escape "$title" | sed 's/^"//; s/"$//')*\n\`\`\`$(printf '%s' "$body" | sed 's/`/'\''/g')\`\`\`"
    local payload
    payload=$(printf '{"text":%s,"mrkdwn":true,"link_names":0}' \
        "$(json_escape "$text")")
    curl -sS -f -m 5 -H "Content-Type: application/json" \
         -d "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1 || _alert_send_failed slack
}

# parse_mode=HTML, so every value goes through html_escape.
_alert_send_telegram() {
    [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]] && return 0
    local title="$1" body="$2"
    local safe_title safe_body
    safe_title=$(html_escape "$title")
    safe_body=$(html_escape "$body")
    local text="<b>${safe_title}</b>
<pre>${safe_body}</pre>"
    local payload
    payload=$(printf '{"chat_id":%s,"text":%s,"parse_mode":"HTML","disable_web_page_preview":true,"disable_notification":false}' \
        "$(json_escape "$TELEGRAM_CHAT_ID")" "$(json_escape "$text")")
    curl -sS -f -m 5 -H "Content-Type: application/json" \
         -d "$payload" "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         >/dev/null 2>&1 || _alert_send_failed telegram
}

# Free-form POST driven by WEBHOOK_TEMPLATE; the color-to-severity mapping matches alerts.log.
_alert_send_webhook() {
    [[ -z "${WEBHOOK_URL:-}" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}"
    local sev
    case "$color" in
        15158332|16711680)  sev=crit ;;
        16753920|15844367)  sev=warn ;;
        *)                  sev=info ;;
    esac
    # Single pass, so a placeholder inside a substituted value stays literal.
    local rest="${WEBHOOK_TEMPLATE:-\"%TITLE%\"}" payload=""
    while [[ "$rest" == *%* ]]; do
        payload+="${rest%%\%*}"
        rest="${rest#*\%}"
        case "$rest" in
            TITLE%*) payload+=$(json_escape "$title");    rest="${rest#TITLE%}" ;;
            BODY%*)  payload+=$(json_escape "$body");     rest="${rest#BODY%}" ;;
            SEV%*)   payload+=$(json_escape "$sev");      rest="${rest#SEV%}" ;;
            RULE%*)  payload+=$(json_escape "$rule_key"); rest="${rest#RULE%}" ;;
            *)       payload+='%' ;;
        esac
    done
    payload+="$rest"
    local ctype="${WEBHOOK_CONTENT_TYPE:-application/json}"
    curl -sS -f -m 5 -H "Content-Type: ${ctype}" \
         -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1 || _alert_send_failed webhook
}

# Room IDs are percent-encoded; the txn id only needs to be unique within the server's dedup window.
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
    local hs="${MATRIX_HOMESERVER%/}"
    curl -sS -f -m 5 -X PUT \
         -H "Authorization: Bearer ${MATRIX_TOKEN}" \
         -H "Content-Type: application/json" \
         -d "$payload" \
         "${hs}/_matrix/client/v3/rooms/${room_enc}/send/m.room.message/${txn_id}" \
         >/dev/null 2>&1 || _alert_send_failed matrix
}

# Silences: explicit mutes that outrank cooldown and dedup.
# alerts.silences rows: key-or-glob, until, added, added_by, message. Expired rows are pruned lazily.

# 30s / 5m / 2h / 1d (or bare seconds) -> seconds; returns 1 on bad input.
alert_silence_parse_duration() {
    local s="${1:-}"
    [[ -n "$s" ]] || return 1
    local n="${s%[smhdSMHD]}" unit="${s: -1}"
    if [[ "$s" =~ ^[0-9]+$ ]]; then
        printf '%s' "$s"
        return 0
    fi
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    # `${unit,,}` is bash 4+ only.
    case "$unit" in
        s|S) printf '%s' "$n" ;;
        m|M) printf '%s' $(( n * 60 )) ;;
        h|H) printf '%s' $(( n * 3600 )) ;;
        d|D) printf '%s' $(( n * 86400 )) ;;
        *) return 1 ;;
    esac
}

alert_silence_prune() {
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 0
    local now; now=$(date +%s)
    local tmp
    tmp=$(mktemp "$f.prune.XXXXXX" 2>/dev/null) || return 0
    awk -F'\t' -v now="$now" 'BEGIN{OFS="\t"} $2+0 > now' "$f" 2>/dev/null > "$tmp"
    mv "$tmp" "$f" 2>/dev/null || rm -f "$tmp"
}

# Prints the matching row; `[[ == $key ]]` is a glob match, so `exploit:*` covers every exploit rule.
alert_is_silenced() {
    local rule="${1:-}"
    [[ -n "$rule" ]] || return 1
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 1
    local now; now=$(date +%s)
    local key until_epoch added_epoch added_by message
    while IFS=$'\t' read -r key until_epoch added_epoch added_by message; do
        [[ -z "$key" ]] && continue
        [[ "$until_epoch" =~ ^[0-9]+$ ]] || continue
        (( until_epoch > now )) || continue
        # shellcheck disable=SC2053
        if [[ "$rule" == "$key" || "$rule" == $key ]]; then
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$key" "$until_epoch" "$added_epoch" "$added_by" "$message"
            return 0
        fi
    done < "$f"
    return 1
}

# Replaces any row for the same key, so re-silencing extends instead of stacking.
alert_silence_add() {
    local key="$1" duration_seconds="$2" message="${3:-}"
    local f="$ALERT_STATE_DIR/alerts.silences"
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 1
    local now until_epoch who
    now=$(date +%s)
    until_epoch=$(( now + duration_seconds ))
    who="${USER:-$(id -un 2>/dev/null || echo unknown)}"
    message="${message//$'\t'/ }"
    message="${message//$'\r'/ }"
    message="${message//$'\n'/ }"
    message="${message:0:200}"
    local tmp
    tmp=$(mktemp "$f.add.XXXXXX" 2>/dev/null) || return 1
    {
        # Also drops expired rows so the file doesn't grow.
        awk -F'\t' -v k="$key" -v now="$now" 'BEGIN{OFS="\t"} $1 != k && $2+0 > now' \
            "$f" 2>/dev/null
        printf '%s\t%s\t%s\t%s\t%s\n' "$key" "$until_epoch" "$now" "$who" "$message"
    } > "$tmp" && mv "$tmp" "$f" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    printf '%s' "$until_epoch"
}

# Returns 1 when no row matched.
alert_silence_remove() {
    local key="$1"
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 1
    # awk field compare instead of grep with a literal tab, which BSD grep handles differently.
    awk -F'\t' -v k="$key" 'BEGIN{found=1} $1==k {found=0; exit} END{exit found}' \
        "$f" 2>/dev/null \
        || return 1
    local tmp
    tmp=$(mktemp "$f.rm.XXXXXX" 2>/dev/null) || return 1
    awk -F'\t' -v k="$key" 'BEGIN{OFS="\t"} $1 != k' "$f" 2>/dev/null > "$tmp" \
        && mv "$tmp" "$f" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    return 0
}

# Raw TSV, newest first.
alert_silence_list_active() {
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 0
    local now; now=$(date +%s)
    awk -F'\t' -v now="$now" 'BEGIN{OFS="\t"} $2+0 > now' "$f" 2>/dev/null \
        | sort -t $'\t' -k3,3 -rn
}

# Destinations for a rule from ALERT_ROUTES: exact key, then prefix before `:`, then `default`.
# Empty output means fan out to every configured destination.
_alert_route_for() {
    local rule_key="${1:-}"
    local routes="${ALERT_ROUTES:-}"
    [[ -z "$routes" ]] && return 0     # unset → empty → fan-out path

    local prefix="${rule_key%%:*}"
    local default_val="" exact_val="" prefix_val=""
    local line key val

    # The first occurrence of each key wins.
    while IFS= read -r line; do
        line="${line%%#*}"
        # trim whitespace both sides
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        # Split on the first ": " so keys like `disk:/` keep their colon.
        if [[ "$line" == *": "* ]]; then
            key="${line%%: *}"
            val="${line#*: }"
        else
            # Tolerate `key:value` without space too.
            key="${line%%:*}"
            val="${line#*:}"
            val="${val# }"
        fi
        # trim both sides (value can still have trailing whitespace)
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        val="${val#"${val%%[![:space:]]*}"}"
        val="${val%"${val##*[![:space:]]}"}"

        if   [[ "$key" == "default" ]]; then
            [[ -z "$default_val" ]] && default_val="$val"
        elif [[ "$key" == "$rule_key" ]]; then
            [[ -z "$exact_val"   ]] && exact_val="$val"
        elif [[ "$key" == "$prefix" ]]; then
            [[ -z "$prefix_val"  ]] && prefix_val="$val"
        fi
    done <<< "$routes"

    if   [[ -n "$exact_val"   ]]; then printf '%s' "$exact_val"
    elif [[ -n "$prefix_val"  ]]; then printf '%s' "$prefix_val"
    elif [[ -n "$default_val" ]]; then printf '%s' "$default_val"
    fi
}

# Runs every executable in HOOKS_DIR/on_alert.d/ in the background with MILOG_RULE_KEY, MILOG_TITLE, MILOG_BODY,
# MILOG_SEV, MILOG_COLOR, MILOG_TS and MILOG_IP set. Non-zero exits are logged to hooks.log, never propagated.
_alert_run_hooks() {
    local hook_dir="${HOOKS_DIR:-$HOME/.config/milog/hooks}/on_alert.d"
    [[ -d "$hook_dir" ]] || return 0

    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}" ip="${5:-}"
    local sev
    case "$color" in
        15158332|16711680)  sev=crit ;;
        16753920|15844367)  sev=warn ;;
        *)                  sev=info ;;
    esac

    local hook_log="${ALERT_STATE_DIR:-$HOME/.cache/milog}/hooks.log"
    mkdir -p "$(dirname "$hook_log")" 2>/dev/null || true
    local ts; ts=$(date +%s)
    local timeout_s="${ALERT_HOOK_TIMEOUT:-10}"
    local have_timeout=0
    command -v timeout >/dev/null 2>&1 && have_timeout=1

    local hook
    # Glob order lets users prefix names with numbers to order hooks.
    for hook in "$hook_dir"/*; do
        [[ -x "$hook" && -f "$hook" ]] || continue
        (
            local rc out
            if (( have_timeout )); then
                out=$(MILOG_RULE_KEY="$rule_key" \
                      MILOG_TITLE="$title"       \
                      MILOG_BODY="$body"         \
                      MILOG_SEV="$sev"           \
                      MILOG_COLOR="$color"       \
                      MILOG_TS="$ts"             \
                      MILOG_IP="$ip"             \
                      timeout "$timeout_s" "$hook" 2>&1)
                rc=$?
            else
                out=$(MILOG_RULE_KEY="$rule_key" \
                      MILOG_TITLE="$title"       \
                      MILOG_BODY="$body"         \
                      MILOG_SEV="$sev"           \
                      MILOG_COLOR="$color"       \
                      MILOG_TS="$ts"             \
                      MILOG_IP="$ip"             \
                      "$hook" 2>&1)
                rc=$?
            fi
            if (( rc != 0 )); then
                # TSV row: epoch \t hook-basename \t exit-code \t output-first-line
                local base; base=$(basename "$hook")
                local first; first=$(printf '%s' "$out" | head -1 | tr -d '\t\r')
                printf '%s\t%s\t%d\t%s\n' "$ts" "$base" "$rc" "${first:0:200}" \
                    >> "$hook_log" 2>/dev/null || true
            fi
        ) &
    done
}

# alert_fire <title> <body> [color] [rule_key] [ip]. Each destination is sent in the background; ip only reaches hooks.
alert_fire() {
    [[ "${ALERTS_ENABLED:-0}" != "1" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}" ip="${5:-}"
    # Silenced fires are not recorded either; the silence row is the audit trail.
    if [[ -n "$rule_key" ]] && alert_is_silenced "$rule_key" >/dev/null; then
        return 0
    fi
    # Record first so the log has the fire even if delivery fails.
    _alert_record "$rule_key" "$title" "$body" "$color"

    # Hooks run before the curl check; they don't need it.
    _alert_run_hooks "$title" "$body" "$color" "$rule_key" "$ip"

    command -v curl >/dev/null 2>&1 || return 0

    local route
    route=$(_alert_route_for "$rule_key")

    if [[ -z "$route" ]]; then
        _alert_send_discord  "$title" "$body" "$color" &
        _alert_send_slack    "$title" "$body" "$color" &
        _alert_send_telegram "$title" "$body" "$color" &
        _alert_send_matrix   "$title" "$body" "$color" &
        _alert_send_webhook  "$title" "$body" "$color" "$rule_key" &
        return 0
    fi

    # Unknown destination names are ignored; `skip` still records to alerts.log but sends nothing.
    local dest
    for dest in $route; do
        case "$dest" in
            discord)   _alert_send_discord  "$title" "$body" "$color" & ;;
            slack)     _alert_send_slack    "$title" "$body" "$color" & ;;
            telegram)  _alert_send_telegram "$title" "$body" "$color" & ;;
            matrix)    _alert_send_matrix   "$title" "$body" "$color" & ;;
            webhook)   _alert_send_webhook  "$title" "$body" "$color" "$rule_key" & ;;
            skip|none) : ;;
            *)         : ;;   # unknown type — silently drop (forward-compat)
        esac
    done
}

# Old name for alert_fire.
alert_discord() { alert_fire "$@"; }

# Redacted previews for `alert status` and `config`: enough to identify the target, never the secret.

_alert_redact_discord() {
    local w="${1:-}"
    [[ -z "$w" ]] && return 0
    if [[ "$w" =~ ^(https?://[^/]+/api/webhooks/[0-9]+/).* ]]; then
        printf '%s****' "${BASH_REMATCH[1]}"
    else
        printf '%.40s…' "$w"
    fi
}

_alert_redact_slack() {
    local w="${1:-}"
    [[ -z "$w" ]] && return 0
    # Slack: https://hooks.slack.com/services/T<workspace>/B<webhook>/<secret>
    if [[ "$w" =~ ^(https?://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/).* ]]; then
        printf '%s****' "${BASH_REMATCH[1]}"
    else
        printf '%.40s…' "$w"
    fi
}

_alert_redact_telegram() {
    local token="${1:-}" chat="${2:-}"
    [[ -z "$token" || -z "$chat" ]] && return 0
    # The bot id is visible to anyone who messages the bot; only the secret is masked.
    local bot_id="${token%%:*}"
    printf 'bot%s:**** chat=%s' "$bot_id" "$chat"
}

_alert_redact_matrix() {
    local hs="${1:-}" token="${2:-}" room="${3:-}"
    [[ -z "$hs" || -z "$token" || -z "$room" ]] && return 0
    printf '%s  room=%s  token=****' "${hs%/}" "$room"
}

# The secret's position is unknown, so keep only scheme, host and first path segment.
_alert_redact_webhook() {
    local w="${1:-}"
    [[ -z "$w" ]] && return 0
    if [[ "$w" =~ ^(https?://[^/]+/[^/?]+) ]]; then
        printf '%s/****' "${BASH_REMATCH[1]}"
    else
        printf '%.40s…' "$w"
    fi
}

# Takes values as args so `alert status` can pass ones read from another user's config file.
# Args: discord_url slack_url tg_token tg_chat matrix_hs matrix_token matrix_room webhook_url
_alert_destinations_status() {
    local d="${1:-}" s="${2:-}" tt="${3:-}" tc="${4:-}" mh="${5:-}" mt="${6:-}" mr="${7:-}" wh="${8:-}"
    local preview

    if [[ -n "$d" ]]; then
        preview=$(_alert_redact_discord "$d")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "discord" "$preview"
    else
        printf "    %-10s ${D}—${NC}\n" "discord"
    fi

    if [[ -n "$s" ]]; then
        preview=$(_alert_redact_slack "$s")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "slack" "$preview"
    else
        printf "    %-10s ${D}—${NC}\n" "slack"
    fi

    if [[ -n "$tt" && -n "$tc" ]]; then
        preview=$(_alert_redact_telegram "$tt" "$tc")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "telegram" "$preview"
    elif [[ -n "$tt" || -n "$tc" ]]; then
        printf "    %-10s ${Y}partial${NC} need both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID\n" "telegram"
    else
        printf "    %-10s ${D}—${NC}\n" "telegram"
    fi

    if [[ -n "$mh" && -n "$mt" && -n "$mr" ]]; then
        preview=$(_alert_redact_matrix "$mh" "$mt" "$mr")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "matrix" "$preview"
    elif [[ -n "$mh" || -n "$mt" || -n "$mr" ]]; then
        printf "    %-10s ${Y}partial${NC} need MATRIX_HOMESERVER + MATRIX_TOKEN + MATRIX_ROOM\n" "matrix"
    else
        printf "    %-10s ${D}—${NC}\n" "matrix"
    fi

    if [[ -n "$wh" ]]; then
        preview=$(_alert_redact_webhook "$wh")
        printf "    %-10s ${G}✓ set${NC}   %s\n" "webhook" "$preview"
    else
        printf "    %-10s ${D}—${NC}\n" "webhook"
    fi
}

# Returns 0 and stamps alerts.state when $1 hasn't fired within ALERT_COOLDOWN, else 1.
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
    # mktemp, not $$: daemon watchers are subshells that share the parent's $$.
    tmp=$(mktemp "$ALERT_STATE_DIR/alerts.state.tmp.XXXXXX" 2>/dev/null) || return 1
    {
        awk -v k="$key" -F'\t' 'BEGIN{OFS="\t"} $1!=k' "$state_file" 2>/dev/null
        printf '%s\t%s\n' "$key" "$now"
    } > "$tmp" && mv "$tmp" "$state_file" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    return 0
}

# Cross-rule dedup: one log line can match both exploits and probes, so the fingerprint gets one alert per ALERT_DEDUP_WINDOW.
# Call after alert_should_fire so quiet servers never touch alerts.fingerprints.
alert_fingerprint_fresh() {
    local fp="$1"
    [[ -n "$fp" ]] || return 0   # no fingerprint → pass through, dedup opt-in
    local state_file="$ALERT_STATE_DIR/alerts.fingerprints"
    local now last tmp
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 0
    now=$(date +%s)
    # ENVIRON, not -v: -v would expand the \xHH escapes nginx writes for quotes.
    last=$(MILOG_FP="$fp" awk -F'\t' '$1==ENVIRON["MILOG_FP"] {print $2; exit}' "$state_file" 2>/dev/null)
    if [[ -n "$last" ]] && (( now - last < ALERT_DEDUP_WINDOW )); then
        return 1
    fi
    tmp=$(mktemp "$ALERT_STATE_DIR/alerts.fingerprints.tmp.XXXXXX" 2>/dev/null) || return 0
    {
        # Also drop entries older than 2x the window so the file stays bounded.
        MILOG_FP="$fp" awk -v cutoff=$(( now - ALERT_DEDUP_WINDOW * 2 )) \
            -F'\t' 'BEGIN{OFS="\t"} $1!=ENVIRON["MILOG_FP"] && $2>cutoff' "$state_file" 2>/dev/null
        printf '%s\t%s\n' "$fp" "$now"
    } > "$tmp" && mv "$tmp" "$state_file" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    return 0
}

# `<ip>:<path>` with the query string stripped; empty when the line doesn't parse.
alert_fingerprint_from_line() {
    local line="$1"
    local ip path
    read -r ip path <<< "$(awk '{
        p = $7
        sub(/\?.*/, "", p)
        print $1, p
    }' <<< "$line")"
    [[ -n "$ip" && -n "$path" ]] || { printf ''; return; }
    printf '%s:%s' "$ip" "$path"
}

# Prints the `# version: N` from the first line of a rules file on stdin.
_rules_version() {
    sed -n '1s/^# version: \([0-9][0-9]*\)$/\1/p'
}

# Prints the version of a valid rules file; otherwise prints the reason to stderr and fails.
_rules_check() {
    local f="$1" version bad kind name re rc
    version=$(_rules_version < "$f")
    [[ -n "$version" ]] || { echo "$f: first line must be '# version: N'" >&2; return 1; }
    bad=$(awk -F'\t' '!/^#/ && NF && !(NF == 3 && $1 ~ /^(exploit|probe|category)$/ && $2 != "" && $3 != "") { print NR; exit }' "$f")
    [[ -z "$bad" ]] || { echo "$f:$bad: want <exploit|probe|category><TAB><name><TAB><regex>" >&2; return 1; }
    for kind in exploit probe; do
        grep -q "^$kind"$'\t' "$f" || { echo "$f: no $kind rules" >&2; return 1; }
    done
    while IFS=$'\t' read -r kind name re || [[ -n "$kind" ]]; do
        [[ -n "$kind" && "$kind" != \#* ]] || continue
        # Exit 2 is a bad regex; 0 means it matches an empty line and would flag every request.
        rc=0; grep -Eq -- "$re" <<< "" 2>/dev/null || rc=$?
        (( rc == 1 )) || { echo "$f: $kind/$name: regex does not compile or matches everything: $re" >&2; return 1; }
    done < "$f"
    printf '%s' "$version"
}

# RULES_FILE wins when it passes _rules_check; otherwise the rules baked in by build.sh apply.
_rules_load() {
    local text="" kind name re
    if [[ -f "$RULES_FILE" ]]; then
        if _rules_check "$RULES_FILE" >/dev/null; then
            text=$(cat "$RULES_FILE")
        else
            echo "milog: ignoring $RULES_FILE, using the built-in rules" >&2
        fi
    fi
    [[ -n "$text" ]] || text=$(_rules_default)
    RULES_EXPLOIT="" RULES_PROBE="" RULES_CATEGORY_NAMES=() RULES_CATEGORY_RES=()
    while IFS=$'\t' read -r kind name re; do
        case "$kind" in
            exploit)  RULES_EXPLOIT+="${RULES_EXPLOIT:+|}$re" ;;
            probe)    RULES_PROBE+="${RULES_PROBE:+|}$re" ;;
            category) RULES_CATEGORY_NAMES+=("$name"); RULES_CATEGORY_RES+=("$re") ;;
        esac
    done <<< "$text"
    # The AI crawler list is shared with health/top, so it is not duplicated in the rules file.
    RULES_PROBE+="|$AI_CRAWLER_UA_RE"
}

# First matching category row names the alert's rule key; needs _rules_load first.
_exploit_category() {
    local line="$1" cat="other" i
    shopt -s nocasematch
    for i in "${!RULES_CATEGORY_RES[@]}"; do
        if [[ "$line" =~ ${RULES_CATEGORY_RES[$i]} ]]; then
            cat="${RULES_CATEGORY_NAMES[$i]}"
            break
        fi
    done
    shopt -u nocasematch
    printf '%s' "$cat"
}

