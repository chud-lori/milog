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

# In-place rotation for alerts.log. When the file grows past
# ALERT_LOG_MAX_BYTES, keep roughly the most recent half (byte-aligned;
# drops the first partial line to resync on a record boundary). Silent
# on any error — a rotation blip must never block the alert path.
#
# Called from _alert_record AFTER the append, so the current record is
# always in whichever half survives.
_alert_rotate_if_big() {
    local f="$1"
    local max="${ALERT_LOG_MAX_BYTES:-10485760}"
    # 0 (or non-numeric) disables rotation entirely.
    [[ "$max" =~ ^[0-9]+$ ]] && (( max > 0 )) || return 0
    [[ -f "$f" ]] || return 0
    local sz
    # GNU stat (-c) vs BSD stat (-f). Both harmless-fail on missing file.
    sz=$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f" 2>/dev/null) || return 0
    [[ "$sz" =~ ^[0-9]+$ ]] || return 0
    (( sz > max )) || return 0
    local half=$(( max / 2 )) tmp
    tmp=$(mktemp "${f}.rot.XXXXXX" 2>/dev/null) || return 0
    # tail -c lands mid-line; `tail -n +2` drops the first (likely partial)
    # record so every surviving line is a complete TSV row.
    tail -c "$half" "$f" 2>/dev/null | tail -n +2 > "$tmp" 2>/dev/null
    mv "$tmp" "$f" 2>/dev/null || rm -f "$tmp"
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
    _alert_rotate_if_big "$log_file"
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

# Generic webhook — POST any JSON (or text) template to an arbitrary URL.
# Used for ntfy.sh, Mattermost, Rocket.Chat, internal triggers, or any other
# POST-accepting endpoint that doesn't have a dedicated adapter. The
# discord/slack/telegram/matrix senders know their API's specific payload
# shape; this one is free-form driven by WEBHOOK_TEMPLATE.
#
# Severity derivation mirrors the alerts.log / web panel convention so the
# same color int means the same severity word everywhere.
_alert_send_webhook() {
    [[ -z "${WEBHOOK_URL:-}" ]] && return 0
    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}"
    local sev
    case "$color" in
        15158332|16711680)  sev=crit ;;
        16753920|15844367)  sev=warn ;;
        *)                  sev=info ;;
    esac
    # Template substitution. json_escape returns the value wrapped in
    # surrounding double-quotes, so the default template's `%TITLE%` etc.
    # expand to valid JSON string literals without additional quoting.
    local payload="${WEBHOOK_TEMPLATE:-\"%TITLE%\"}"
    payload="${payload//%TITLE%/$(json_escape "$title")}"
    payload="${payload//%BODY%/$(json_escape "$body")}"
    payload="${payload//%SEV%/$(json_escape "$sev")}"
    payload="${payload//%RULE%/$(json_escape "$rule_key")}"
    local ctype="${WEBHOOK_CONTENT_TYPE:-application/json}"
    curl -sS -m 5 -H "Content-Type: ${ctype}" \
         -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1 || true
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

# --- Silence / ack ------------------------------------------------------------
#
# Muting rules while an on-call operator is already working on the underlying
# cause. Separate from cooldown (rate-limits repeats of the same rule) and
# from dedup (cross-rule same-event suppression): silence is an explicit
# user action, outranks both, and carries attribution.
#
# State file: $ALERT_STATE_DIR/alerts.silences
#   Format:   <rule_key_or_glob>\t<until_epoch>\t<added_epoch>\t<added_by>\t<message>
#   Globs:    bash glob syntax — `exploits:*` silences every exploits:<cat>
#             rule. Literal matches are checked first, then globs.
#   Expiry:   passive — compared on each check; the prune path lazily removes
#             rows whose until_epoch has passed. No cron needed.

# Convert a duration like 30s / 5m / 2h / 1d to seconds. Echoes the result;
# returns 1 on unparseable input so callers can surface a clean error.
alert_silence_parse_duration() {
    local s="${1:-}"
    [[ -n "$s" ]] || return 1
    local n="${s%[smhdSMHD]}" unit="${s: -1}"
    # Bare integer → treat as seconds (no unit).
    if [[ "$s" =~ ^[0-9]+$ ]]; then
        printf '%s' "$s"
        return 0
    fi
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    # Accept upper- and lower-case unit letters. `${unit,,}` would be cleaner
    # but it's bash-4+ only — milog.sh runs on bash 3.2 macOS dev boxes too.
    case "$unit" in
        s|S) printf '%s' "$n" ;;
        m|M) printf '%s' $(( n * 60 )) ;;
        h|H) printf '%s' $(( n * 3600 )) ;;
        d|D) printf '%s' $(( n * 86400 )) ;;
        *) return 1 ;;
    esac
}

# Strip expired rows in place. Silent on missing file / read error — the
# worst case is we carry a stale row until the next write, which the
# _is_silenced path ignores anyway.
alert_silence_prune() {
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 0
    local now; now=$(date +%s)
    local tmp
    tmp=$(mktemp "$f.prune.XXXXXX" 2>/dev/null) || return 0
    awk -F'\t' -v now="$now" 'BEGIN{OFS="\t"} $2+0 > now' "$f" 2>/dev/null > "$tmp"
    mv "$tmp" "$f" 2>/dev/null || rm -f "$tmp"
}

# True (0) if rule_key matches an unexpired silence row. Checks literal
# match first, then glob patterns. Echoes the full row of the matching
# silence on stdout so callers (e.g. alert_fire) can include attribution
# in their telemetry.
#
# Bash `[[ $x == $pat ]]` does glob matching (not regex), which is exactly
# what we want: `exploits:*` matches `exploits:log4shell` / `exploits:sqli`.
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
        # Literal match OR glob match.
        # shellcheck disable=SC2053
        if [[ "$rule" == "$key" || "$rule" == $key ]]; then
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$key" "$until_epoch" "$added_epoch" "$added_by" "$message"
            return 0
        fi
    done < "$f"
    return 1
}

# Add / replace a silence row. Callers (mode_silence) pre-validate
# duration_seconds; this function just writes the file.
#
# Replace semantics: an existing row for the same key is overwritten, so
# `milog silence 5xx:api 2h` followed by `milog silence 5xx:api 4h` extends
# the mute rather than stacking two rows.
alert_silence_add() {
    local key="$1" duration_seconds="$2" message="${3:-}"
    local f="$ALERT_STATE_DIR/alerts.silences"
    mkdir -p "$ALERT_STATE_DIR" 2>/dev/null || return 1
    local now until_epoch who
    now=$(date +%s)
    until_epoch=$(( now + duration_seconds ))
    # $USER is set by login shells; fall back to `id -un` for systemd/daemon
    # contexts. Fine to be empty if somehow both miss.
    who="${USER:-$(id -un 2>/dev/null || echo unknown)}"
    # Tab/newline strip on message — silence rows live on a single line.
    message="${message//$'\t'/ }"
    message="${message//$'\r'/ }"
    message="${message//$'\n'/ }"
    message="${message:0:200}"
    local tmp
    tmp=$(mktemp "$f.add.XXXXXX" 2>/dev/null) || return 1
    {
        # Drop any existing row with the same key, then append the fresh one.
        # Also drop any already-expired rows so the file doesn't grow.
        awk -F'\t' -v k="$key" -v now="$now" 'BEGIN{OFS="\t"} $1 != k && $2+0 > now' \
            "$f" 2>/dev/null
        printf '%s\t%s\t%s\t%s\t%s\n' "$key" "$until_epoch" "$now" "$who" "$message"
    } > "$tmp" && mv "$tmp" "$f" 2>/dev/null
    [[ -f "$tmp" ]] && rm -f "$tmp"
    printf '%s' "$until_epoch"
}

# Remove a silence row by exact key. Returns 0 if a row was removed, 1 if
# no match (so callers can print an honest "nothing to clear" message).
alert_silence_remove() {
    local key="$1"
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 1
    # Existence check via awk — `grep -P` / `grep -E "^X\t"` is portable-
    # problematic (BSD grep, some minimal shells). awk field compare is
    # unambiguous and POSIX.
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

# Echo active silences as TSV rows, newest-first (by added_epoch).
# Callers format for display; we keep this function raw so tests can parse.
alert_silence_list_active() {
    local f="$ALERT_STATE_DIR/alerts.silences"
    [[ -f "$f" ]] || return 0
    local now; now=$(date +%s)
    # Sort by added_epoch desc so freshest silences render first.
    awk -F'\t' -v now="$now" 'BEGIN{OFS="\t"} $2+0 > now' "$f" 2>/dev/null \
        | sort -t $'\t' -k3,3 -rn
}

# --- Alert routing ------------------------------------------------------------
#
# Resolve a rule_key to its destination list by consulting ALERT_ROUTES.
# See `ALERT_ROUTES` in core.sh for the config-file format.
#
# Resolution:
#   1. Exact match on rule_key  (e.g. `5xx:api` → line `5xx:api: slack`)
#   2. Prefix match (first segment before `:`)  (e.g. `exploits:sqli` → `exploits:`)
#   3. `default:` line
#   4. No match → empty string → caller fans out to all configured dests
#      (back-compat: today's behavior when ALERT_ROUTES is unset)
#
# Echoes the resolved destination list on stdout. Empty output means "no
# routing configured for this key; fan out".
_alert_route_for() {
    local rule_key="${1:-}"
    local routes="${ALERT_ROUTES:-}"
    [[ -z "$routes" ]] && return 0     # unset → empty → fan-out path

    local prefix="${rule_key%%:*}"
    local default_val="" exact_val="" prefix_val=""
    local line key val

    # Parse the multiline config block. Tolerates leading/trailing whitespace
    # and `#` comments. Only the first occurrence of each key wins (so
    # `exploits: slack` before `exploits: discord` in the config means slack).
    while IFS= read -r line; do
        line="${line%%#*}"
        # trim whitespace both sides
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        # Only split on the FIRST `:` so values can contain colons (e.g.
        # `disk:/: discord` — key is `disk:/`, value is `discord`). Find the
        # last `:` followed by space; that's the separator.
        # Simpler: anchor-split — the key/value separator is ": " (colon+space)
        # and unambiguous since neither keys nor destination tokens contain
        # that literal sequence.
        if [[ "$line" == *": "* ]]; then
            key="${line%%: *}"
            val="${line#*: }"
        else
            # Tolerate `key:value` without space too.
            key="${line%%:*}"
            val="${line#*:}"
            # strip one leading space if present
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

# --- User hook scripts --------------------------------------------------------
#
# Run every executable file under HOOKS_DIR/on_alert.d/ with alert metadata
# in env. The /etc/cron.hourly/-style "execute-all-files-in-dir" pattern —
# users add or remove scripts without touching MiLog internals. Useful for
# custom integrations (SMS, PagerDuty, a local audit log, whatever) that
# don't fit into the destination-adapter model.
#
# Called AFTER the silence gate, so silenced fires skip hooks — same
# semantics as destinations. Runs backgrounded per-hook so a slow script
# doesn't delay the others; wrapped in `timeout` (ALERT_HOOK_TIMEOUT) so
# a hung script doesn't leak forever. All failures are logged to
# hooks.log, never propagated. The alert path is never blocked by a
# broken hook.
#
# Env passed to each hook:
#   MILOG_RULE_KEY   the rule that fired (e.g. `5xx:api`, `exploits:sqli`)
#   MILOG_TITLE      short alert title
#   MILOG_BODY       longer alert body (may contain newlines stripped to spaces)
#   MILOG_SEV        "crit" | "warn" | "info"
#   MILOG_COLOR      the raw Discord-compatible color int
#   MILOG_TS         fire epoch seconds
_alert_run_hooks() {
    local hook_dir="${HOOKS_DIR:-$HOME/.config/milog/hooks}/on_alert.d"
    [[ -d "$hook_dir" ]] || return 0

    local title="$1" body="$2" color="${3:-15158332}" rule_key="${4:-}"
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
    # Iterate in deterministic order — users can prefix numbers for
    # priority (`10-log`, `20-notify`), classic /etc/cron.d pattern.
    for hook in "$hook_dir"/*; do
        [[ -x "$hook" && -f "$hook" ]] || continue
        # Run each hook in its own subshell so failures don't propagate.
        # Backgrounded: the four delivery senders already background too,
        # and alert_fire callers typically background the whole fire.
        (
            local rc out
            if (( have_timeout )); then
                out=$(MILOG_RULE_KEY="$rule_key" \
                      MILOG_TITLE="$title"       \
                      MILOG_BODY="$body"         \
                      MILOG_SEV="$sev"           \
                      MILOG_COLOR="$color"       \
                      MILOG_TS="$ts"             \
                      timeout "$timeout_s" "$hook" 2>&1)
                rc=$?
            else
                out=$(MILOG_RULE_KEY="$rule_key" \
                      MILOG_TITLE="$title"       \
                      MILOG_BODY="$body"         \
                      MILOG_SEV="$sev"           \
                      MILOG_COLOR="$color"       \
                      MILOG_TS="$ts"             \
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

# --- Fanout dispatcher --------------------------------------------------------
#
# Fire one alert to every configured destination — or, if ALERT_ROUTES
# matched this rule, just the destinations it lists. Silently no-ops when
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
    # Silence gate — explicit user action outranks cooldown + dedup + delivery.
    # Silenced fires are NOT recorded to alerts.log: the user said "I'm on it,
    # stop telling me", and echoing the same rule repeatedly to history would
    # just be a different kind of noise. The silence row itself (in
    # alerts.silences) is the durable audit trail.
    if [[ -n "$rule_key" ]] && alert_is_silenced "$rule_key" >/dev/null; then
        return 0
    fi
    # Record before delivery — the log captures "what fired" even if the
    # webhooks fail (network blip, rate limit, rotated token).
    _alert_record "$rule_key" "$title" "$body" "$color"

    # User hook scripts — run before delivery so custom integrations see the
    # event regardless of whether any destination is configured. Hooks do
    # NOT require curl; they're arbitrary executables under
    # HOOKS_DIR/on_alert.d/. Safe to run even if `curl` is missing.
    _alert_run_hooks "$title" "$body" "$color" "$rule_key"

    command -v curl >/dev/null 2>&1 || return 0

    # Resolve routing — empty = today's behavior (fan out to every configured
    # destination). Non-empty = only the destination types listed here fire.
    local route
    route=$(_alert_route_for "$rule_key")

    if [[ -z "$route" ]]; then
        # Each destination backgrounded so a slow one doesn't delay the
        # others. Callers also typically background `alert_fire &` — the
        # resulting grandchild sends are orphaned to init on exit, which is
        # fine. Webhook takes rule_key as a 4th arg for template
        # substitution; other senders don't need it.
        _alert_send_discord  "$title" "$body" "$color" &
        _alert_send_slack    "$title" "$body" "$color" &
        _alert_send_telegram "$title" "$body" "$color" &
        _alert_send_matrix   "$title" "$body" "$color" &
        _alert_send_webhook  "$title" "$body" "$color" "$rule_key" &
        return 0
    fi

    # Routed fire: dispatch only to the listed destination types. Unknown
    # tokens are silently ignored so a forward-looking config (e.g. naming
    # an adapter before it lands) doesn't break existing rules. `skip` is
    # an explicit "do not fire this class" — useful for noise rules you
    # want to keep recording in alerts.log but not page on.
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

# Back-compat alias for `alert_discord`. Drop-in replacement for code that
# hasn't been updated to the new name yet. Prefer `alert_fire` in new code.
alert_discord() { alert_fire "$@"; }

# --- Redaction previews -------------------------------------------------------
# Each returns a short string that (a) confirms which account/webhook is
# wired up and (b) never leaks the secret. Used by `alert status` and
# `config` so users can tell at a glance what's actually configured.

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
    # Telegram bot token is `<bot_id>:<secret>`. Bot ID is public-ish
    # (visible to anyone messaging the bot), so keep it; mask the secret.
    local bot_id="${token%%:*}"
    printf 'bot%s:**** chat=%s' "$bot_id" "$chat"
}

_alert_redact_matrix() {
    local hs="${1:-}" token="${2:-}" room="${3:-}"
    [[ -z "$hs" || -z "$token" || -z "$room" ]] && return 0
    # Homeserver + room are fine to show (they're addressable); token is
    # the access bearer, always masked.
    printf '%s  room=%s  token=****' "${hs%/}" "$room"
}

# Generic webhook URL — free-form target, so we don't know which part is the
# secret. Preserve scheme + host + first path segment (usually identifies
# the tool / channel), mask the tail. Falls back to a prefix truncation.
_alert_redact_webhook() {
    local w="${1:-}"
    [[ -z "$w" ]] && return 0
    if [[ "$w" =~ ^(https?://[^/]+/[^/?]+) ]]; then
        printf '%s/****' "${BASH_REMATCH[1]}"
    else
        printf '%.40s…' "$w"
    fi
}

# --- Destinations status line renderer ---------------------------------------
# Prints one line per configured-or-not destination. Accepts ALL values as
# positional args so callers can feed either env vars (process-state view,
# used by `config`) or values pre-read from a specific config file (target-
# user view, used by `alert status` under sudo).
#
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

