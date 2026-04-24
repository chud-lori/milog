# MODE: web — tiny read-only HTTP dashboard
#
# Security posture (read carefully before changing defaults):
#   - Loopback-only bind by default; --bind $other requires --trust.
#   - Every request is token-gated. Token is 32 bytes of urandom hex in
#     $WEB_TOKEN_FILE (mode 600). First page load accepts ?t=TOKEN; the JS
#     then stores it in sessionStorage + strips the query string so the
#     token doesn't linger in browser history.
#   - All routes are READ-ONLY. No endpoint mutates config, webhook,
#     systemd, or the history DB. Locking this down is intentional — if
#     someone bypasses SSH/Tailscale/CF and the token, they still can't
#     pivot to owning the box.
#   - Responses set: no external fetches (CSP: default-src 'self'),
#     X-Content-Type-Options, X-Frame-Options: DENY, Referrer-Policy:
#     no-referrer, Cache-Control: no-store.
#   - DISCORD_WEBHOOK is always redacted to its prefix in API responses.
#
# Transport choices (ranked, see README):
#   1. SSH port-forward:  ssh -L 8765:localhost:8765 host   (zero exposure)
#   2. Tailscale/WireGuard overlay                          (phone-friendly)
#   3. Cloudflare Tunnel  cloudflared tunnel --url http://localhost:8765
#
# Listener: socat or ncat (checked at start; clear error if neither).
# ==============================================================================

# ---- token management --------------------------------------------------------
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
    # 32 bytes → 64 hex chars. /dev/urandom is portable; fall back to openssl.
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

# ---- JSON helpers ------------------------------------------------------------
# Tiny escaper: for string values we already trust (numeric-looking metric
# values, known-good app names from LOGS). User-visible free-text (paths,
# UA strings) must go through json_escape which already exists for Discord.
_web_n() { [[ "$1" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] && printf '%s' "$1" || printf 'null'; }

_web_redact_webhook() {
    # Keep just enough of the URL to identify which webhook — strip the secret.
    local w="${1:-}"
    [[ -z "$w" ]] && { printf ''; return; }
    if [[ "$w" =~ (.*/webhooks/[0-9]+/)[A-Za-z0-9_-]+ ]]; then
        printf '%s****' "${BASH_REMATCH[1]}"
    else
        printf '%s…' "${w:0:20}"
    fi
}

# ---- HTTP response ----------------------------------------------------------
# Emits a full HTTP/1.1 response. Callers pass a pre-built body (can be
# empty). We compute Content-Length from the byte-size of the body.
_web_respond() {
    local status="$1" ctype="$2" body="${3:-}"
    local msg="OK"
    case "$status" in
        200) msg="OK" ;;
        400) msg="Bad Request" ;;
        401) msg="Unauthorized" ;;
        404) msg="Not Found" ;;
        405) msg="Method Not Allowed" ;;
        429) msg="Too Many Requests" ;;
        500) msg="Internal Server Error" ;;
    esac
    # Byte length — NOT ${#body}, which under a UTF-8 locale counts codepoints
    # and under-reports by (bytes-1) for every multi-byte char. That mismatch
    # lets the browser finish reading a truncated response, chopping off the
    # tail of the HTML (including the closing </script> tag). wc -c always
    # counts bytes, regardless of LC_ALL.
    local len
    len=$(printf '%s' "$body" | wc -c | tr -d ' ')
    printf 'HTTP/1.1 %s %s\r\n' "$status" "$msg"
    printf 'Content-Type: %s; charset=utf-8\r\n' "$ctype"
    printf 'Content-Length: %d\r\n' "$len"
    printf 'Connection: close\r\n'
    printf 'Cache-Control: no-store\r\n'
    printf 'X-Content-Type-Options: nosniff\r\n'
    printf 'X-Frame-Options: DENY\r\n'
    printf 'Referrer-Policy: no-referrer\r\n'
    # CSP forbids external fetches. All CSS/JS is inline in the HTML page.
    printf "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'none'\r\n"
    printf '\r\n'
    printf '%s' "$body"
}

# ---- route: /api/summary.json ------------------------------------------------
_web_route_summary() {
    local cur_time; cur_time=$(date '+%d/%b/%Y:%H:%M')
    local ts; ts=$(date -Iseconds 2>/dev/null || date)

    # System metrics — reuse existing helpers.
    local cpu mem_pct mem_used mem_total disk_pct disk_used disk_total
    cpu=$(cpu_usage); [[ "$cpu" =~ ^[0-9]+$ ]] || cpu=0
    read -r mem_pct mem_used mem_total  <<< "$(mem_info)"
    read -r disk_pct disk_used disk_total <<< "$(disk_info)"

    # Per-app nginx counts.
    local app_json="" app count c2 c3 c4 c5
    local first=1 total=0
    for app in "${LOGS[@]}"; do
        read -r count c2 c3 c4 c5 <<< "$(nginx_minute_counts "$app" "$cur_time")"
        count=${count:-0}; c2=${c2:-0}; c3=${c3:-0}; c4=${c4:-0}; c5=${c5:-0}
        total=$(( total + count ))
        if (( first )); then first=0; else app_json+=","; fi
        # json_escape returns the string already quoted — use %s, not "%s".
        app_json+=$(printf '{"name":%s,"req":%d,"c2xx":%d,"c3xx":%d,"c4xx":%d,"c5xx":%d}' \
            "$(json_escape "$app")" "$count" "$c2" "$c3" "$c4" "$c5")
    done

    local body
    body=$(printf '{"ts":%s,"system":{"cpu":%s,"mem_pct":%s,"mem_used_mb":%s,"mem_total_mb":%s,"disk_pct":%s,"disk_used_gb":%s,"disk_total_gb":%s},"total_req":%d,"apps":[%s]}' \
        "$(json_escape "$ts")" \
        "$(_web_n "$cpu")" "$(_web_n "$mem_pct")" "$(_web_n "$mem_used")" "$(_web_n "$mem_total")" \
        "$(_web_n "$disk_pct")" "$(_web_n "$disk_used")" "$(_web_n "$disk_total")" \
        "$total" "$app_json")
    _web_respond 200 "application/json" "$body"
}

# ---- route: /api/meta.json ---------------------------------------------------
_web_route_meta() {
    local up; up=$(uptime -p 2>/dev/null | sed 's/up //' || echo "")
    local hook_status="disabled"
    [[ "$ALERTS_ENABLED" == "1" && -n "$DISCORD_WEBHOOK" ]] && hook_status="enabled"

    # Build apps array JSON-safely (each element through json_escape).
    local apps_json="" first=1 a
    for a in "${LOGS[@]}"; do
        if (( first )); then first=0; else apps_json+=","; fi
        apps_json+=$(json_escape "$a")
    done

    local body
    body=$(printf '{"apps":[%s],"log_dir":%s,"alerts":%s,"webhook":%s,"uptime":%s,"refresh":%d}' \
        "$apps_json" \
        "$(json_escape "$LOG_DIR")" \
        "$(json_escape "$hook_status")" \
        "$(json_escape "$(_web_redact_webhook "$DISCORD_WEBHOOK")")" \
        "$(json_escape "$up")" \
        "$REFRESH")
    _web_respond 200 "application/json" "$body"
}

# ---- route: /api/logs.json ---------------------------------------------------
# Returns recent lines from ONE nginx source, filtered by grep pattern + path
# + status-class. Capped at 500 rows per fetch. For bigger windows, the
# caller narrows filters. Designed for the tier-1 in-browser log viewer —
# every pass scans the tail of one log file, no sqlite layer yet.
#
# Query params:
#   app=<name>    required — must be an nginx source in LOGS
#   limit=<N>     default 200, max 500
#   grep=<sub>    optional substring filter (case-sensitive)
#   path=<pre>    optional path-prefix filter (starts with /)
#   class=<c>     optional status class: 2xx 3xx 4xx 5xx any
_web_route_logs() {
    local app="${1:-}" limit="${2:-200}" grep_s="${3:-}" path_s="${4:-}" cls="${5:-}"
    local max=500
    [[ "$limit" =~ ^[0-9]+$ ]] || limit=200
    (( limit > max )) && limit=$max

    local body
    local file="$LOG_DIR/${app}.access.log"
    if [[ -z "$app" || ! -f "$file" ]]; then
        body=$(printf '{"app":%s,"lines":[],"error":"no such app"}' \
            "$(json_escape "${app:-}")")
        _web_respond 404 "application/json" "$body"
        return
    fi

    # Read last N*3 lines, then filter + cap in awk (lets us filter-then-slice
    # so grep+path+class yield exactly `limit` rows when possible).
    local read_n=$(( limit * 3 ))
    (( read_n < 200 )) && read_n=200
    local raw
    raw=$(tail -n "$read_n" "$file" 2>/dev/null \
        | awk -F'"' -v grep_s="$grep_s" -v path_s="$path_s" -v cls="$cls" -v limit="$limit" '
            function jesc(s) {
                gsub(/\\/, "\\\\", s)
                gsub(/"/,  "\\\"", s)
                gsub(/\t/, "\\t", s)
                gsub(/\n/, "\\n", s)
                gsub(/\r/, "\\r", s)
                return s
            }
            # Combined-format line:
            #   ip - user [t] "METHOD path HTTP" status bytes "ref" "ua" rt?
            # We split on double-quotes: $1 has ip+dash+time, $2 is request,
            # $3 has status+bytes, $4 is referer, $5 has ua+maybe-rt.
            {
                line = $0
                # Substring filter first — cheapest on no-match.
                if (grep_s != "" && index(line, grep_s) == 0) next

                # Parse fields. Field-split on whitespace for the unquoted bits.
                n_ws = split($1, ws, " ")
                ip = ws[1]
                timestamp = ""
                for (i = 1; i <= n_ws; i++) {
                    if (ws[i] ~ /^\[/) { timestamp = ws[i]; break }
                }

                # Request string (field $2): "METHOD /path HTTP/1.1"
                req = $2
                n_rq = split(req, rq, " ")
                method = (n_rq >= 1) ? rq[1] : ""
                raw_path = (n_rq >= 2) ? rq[2] : ""
                q = index(raw_path, "?")
                clean_path = (q > 0) ? substr(raw_path, 1, q-1) : raw_path

                # Defensive: path must start with /
                if (substr(clean_path, 1, 1) != "/") next
                if (path_s != "" && index(clean_path, path_s) != 1) next

                # Status is the first field of $3 (after the closing quote).
                # Strip leading whitespace first — split on " " with a
                # leading-space input yields ["401","0"] not ["","401","0",""]
                # in most awks.
                f3 = $3
                sub(/^[[:space:]]+/, "", f3)
                n_sb = split(f3, sb, " ")
                status = (n_sb >= 1) ? sb[1] : ""
                if (status !~ /^[0-9]+$/) next
                sclass = substr(status, 1, 1) "xx"
                if (cls != "" && cls != "any" && cls != sclass) next

                # UA is field $6 (quoted ua string surrounded by quotes means
                # $6 exactly). After the UA, an optional request_time float.
                ua = ($6 != "" ? $6 : "")

                n++
                # Emit JSON object per surviving row.
                out[n] = sprintf("{\"ts\":\"%s\",\"ip\":\"%s\",\"method\":\"%s\",\"path\":\"%s\",\"status\":%s,\"ua\":\"%s\",\"class\":\"%s\"}",
                    jesc(timestamp), jesc(ip), jesc(method), jesc(clean_path), status, jesc(ua), sclass)

                if (n > limit) {
                    # Drop the oldest if over-cap (keep latest N).
                    for (j = 1; j < n; j++) out[j] = out[j+1]
                    n = limit
                }
            }
            END {
                for (j = 1; j <= n; j++) {
                    print out[j]
                }
            }')

    local arr="[]"
    if [[ -n "$raw" ]]; then
        arr="[$(printf '%s' "$raw" | paste -sd, -)]"
    fi

    body=$(printf '{"app":%s,"lines":%s}' "$(json_escape "$app")" "$arr")
    _web_respond 200 "application/json" "$body"
}

# ---- route: /api/logs/histogram.json -----------------------------------------
# Per-minute request counts for the selected app over a window (N minutes).
# Used for the timeline strip above the log table.
_web_route_logs_histogram() {
    local app="${1:-}" minutes="${2:-60}"
    [[ "$minutes" =~ ^[0-9]+$ ]] || minutes=60
    (( minutes > 1440 )) && minutes=1440
    local file="$LOG_DIR/${app}.access.log"
    local body
    if [[ -z "$app" || ! -f "$file" ]]; then
        body=$(printf '{"app":%s,"buckets":[]}' "$(json_escape "${app:-}")")
        _web_respond 404 "application/json" "$body"
        return
    fi

    # Build N per-minute bucket keys: [dd/Mon/yyyy:HH:MM, ...] for the
    # last `minutes` minutes. Scan tail of file counting matches.
    local now_ts; now_ts=$(date +%s)
    local cur_minute_str
    local i ts_i
    # Pre-generate all minute strings into an awk-readable list.
    local keys=""
    for (( i = minutes - 1; i >= 0; i-- )); do
        ts_i=$(( now_ts - i * 60 ))
        cur_minute_str=$(date -d "@$ts_i" '+%d/%b/%Y:%H:%M' 2>/dev/null \
            || date -r  "$ts_i" '+%d/%b/%Y:%H:%M' 2>/dev/null)
        keys="${keys}${cur_minute_str}\n"
    done

    # For very large logs, only scan a bounded tail slice.
    local scan_lines=$(( minutes * 500 ))
    (( scan_lines < 1000 )) && scan_lines=1000

    local raw
    raw=$(printf '%b' "$keys" | awk -v file="$file" -v scan="$scan_lines" '
        { keys[NR] = $0 }
        END {
            cmd = sprintf("tail -n %d %s 2>/dev/null", scan, file)
            while ((cmd | getline line) > 0) {
                for (k in keys) {
                    if (index(line, keys[k]) > 0) {
                        counts[keys[k]]++
                        break
                    }
                }
            }
            close(cmd)
            for (i = 1; i <= NR; i++) {
                printf "{\"t\":\"%s\",\"c\":%d}\n", keys[i], counts[keys[i]]+0
            }
        }')

    local arr="[]"
    [[ -n "$raw" ]] && arr="[$(printf '%s' "$raw" | paste -sd, -)]"
    body=$(printf '{"app":%s,"buckets":%s}' "$(json_escape "$app")" "$arr")
    _web_respond 200 "application/json" "$body"
}

# ---- route: /api/alerts.json -------------------------------------------------
# Returns the last N alerts from ALERT_STATE_DIR/alerts.log, filtered by a
# window query param (?window=24h, 1d, 7d, today, all — same grammar as
# `milog alerts`). Default window is 24h, capped at 100 rows to keep the
# payload tight. Reads are best-effort: a missing/empty log returns an
# empty array, not an error — the panel is informational, not critical.
#
# Severity is derived from the Discord color int stored per row so the
# client can tint the RULE column without re-computing it.
_web_route_alerts() {
    local window="${1:-24h}" cap=100
    local log_file="$ALERT_STATE_DIR/alerts.log"

    local arr="[]"
    if [[ -f "$log_file" ]]; then
        local cutoff
        cutoff=$(_alerts_window_to_epoch "$window" 2>/dev/null) || cutoff=0
        # The filter + JSON-build runs entirely in awk so log files with tens
        # of thousands of rows don't fork-per-row in bash. Awk emits one JSON
        # object per surviving record (capped at `cap`), newline-separated,
        # which we then comma-join in pure bash.
        local raw
        raw=$(awk -F'\t' -v cutoff="$cutoff" -v cap="$cap" '
            function jesc(s,   r) {
                # Minimal JSON string escaper: backslash, quote, and control
                # chars. Tabs/newlines are already stripped on ingest by
                # _alert_record, but escape defensively in case an older
                # entry slipped through.
                gsub(/\\/, "\\\\", s)
                gsub(/"/,  "\\\"", s)
                gsub(/\n/, "\\n", s)
                gsub(/\r/, "\\r", s)
                gsub(/\t/, "\\t", s)
                return s
            }
            function sev(c) {
                if (c == 15158332 || c == 16711680) return "crit"
                if (c == 16753920 || c == 15844367) return "warn"
                return "info"
            }
            $1 >= cutoff && NF >= 5 {
                rows[++n] = $0
            }
            END {
                start = (n > cap) ? n - cap + 1 : 1
                for (i = start; i <= n; i++) {
                    split(rows[i], f, "\t")
                    printf "{\"ts\":%d,\"rule\":\"%s\",\"sev\":\"%s\",\"title\":\"%s\",\"body\":\"%s\"}\n",
                        f[1]+0, jesc(f[2]), sev(f[3]+0), jesc(f[4]), jesc(f[5])
                }
            }
        ' "$log_file" 2>/dev/null)
        if [[ -n "$raw" ]]; then
            # Join newline-separated objects with commas; no trailing comma.
            arr="[$(printf '%s' "$raw" | paste -sd, -)]"
        fi
    fi

    local body
    body=$(printf '{"window":%s,"alerts":%s}' \
        "$(json_escape "$window")" "$arr")
    _web_respond 200 "application/json" "$body"
}

# ---- route: / ---------------------------------------------------------------
# Single self-contained HTML page. CSS + JS inline. Polls /api/summary.json
# every N seconds with the token in the Authorization header. No external
# network requests; works offline on loopback.
_web_route_index() {
    # NOTE: we read the heredoc via `read -r -d ''` rather than
    # `body=$(cat <<'X' ... X)` because the command-substitution form still
    # tokenizes the body for single quotes even with a quoted delimiter —
    # one `doesn't` in a JS comment aborts the parse. read -d '' reads
    # until NUL (never present) so the whole heredoc lands in $body.
    local body=""
    IFS= read -r -d '' body <<'HTML' || true
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>MiLog</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; background:#0b0d10; color:#d6d9dc; font:14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
  header { display:flex; align-items:baseline; gap:1rem; padding:1rem 1.2rem; border-bottom:1px solid #1b1f24; }
  header h1 { margin:0; font-size:1.05rem; font-weight:600; letter-spacing:.05em; }
  header .ts { color:#6b7177; font-size:.85rem; }
  header .pill { margin-left:auto; padding:.1rem .5rem; border:1px solid #30363d; border-radius:.3rem; font-size:.8rem; }
  .pill.ok  { color:#3fb950; border-color:#1a7f37; }
  .pill.bad { color:#f85149; border-color:#da3633; }
  main { padding:1rem 1.2rem; display:grid; gap:1.5rem; max-width:1000px; margin:0 auto; }
  section h2 { margin:0 0 .6rem; font-size:.8rem; color:#8b949e; text-transform:uppercase; letter-spacing:.1em; font-weight:600; }
  .sys { display:grid; grid-template-columns: repeat(3, 1fr); gap:.8rem; }
  .sys .card { padding:.8rem 1rem; background:#10141a; border:1px solid #1b1f24; border-radius:.4rem; }
  .sys .lbl { color:#8b949e; font-size:.75rem; text-transform:uppercase; letter-spacing:.08em; }
  .sys .val { font-size:1.5rem; font-weight:600; margin-top:.1rem; }
  .sys .sub { color:#6b7177; font-size:.8rem; }
  .bar { margin-top:.5rem; height:6px; background:#1b1f24; border-radius:2px; overflow:hidden; }
  .bar > span { display:block; height:100%; background:#3fb950; transition:width .4s; }
  .bar > span.warn { background:#d29922; }
  .bar > span.crit { background:#f85149; }
  table { width:100%; border-collapse:collapse; font-size:.9rem; }
  th, td { text-align:left; padding:.45rem .6rem; border-bottom:1px solid #1b1f24; }
  th { color:#8b949e; font-weight:500; font-size:.75rem; text-transform:uppercase; letter-spacing:.1em; }
  th.n, td.n { text-align:right; font-variant-numeric: tabular-nums; }
  td.err4 { color:#d29922; }
  td.err5 { color:#f85149; }
  .sev-crit { color:#f85149; font-weight:600; }
  .sev-warn { color:#d29922; font-weight:600; }
  .sev-info { color:#3fb950; font-weight:600; }
  .alerts-head { display:flex; align-items:baseline; justify-content:space-between; margin-bottom:.6rem; gap:.8rem; }
  .alerts-head h2 { margin:0; }
  .alerts-head .meta { color:#6b7177; font-size:.75rem; margin-left:auto; }
  .alerts-head select { background:#10141a; color:#d6d9dc; border:1px solid #30363d; border-radius:.3rem; padding:.15rem .4rem; font:inherit; font-size:.8rem; }
  td.rule { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space:nowrap; }
  td.when { color:#8b949e; white-space:nowrap; font-variant-numeric: tabular-nums; }
  td.title { color:#d6d9dc; overflow:hidden; text-overflow:ellipsis; max-width:48ch; }
  .empty { color:#6b7177; padding:.6rem 0; }
  /* Scroll the alerts table inside its own box instead of growing the page.
     Max ~14 rows visible; header stays pinned while scrolling. */
  .table-scroll { max-height: 26rem; overflow-y: auto; border:1px solid #1b1f24; border-radius:.4rem; }
  .table-scroll table { border-collapse: separate; border-spacing: 0; }
  .table-scroll thead th { position: sticky; top: 0; background:#10141a; z-index: 1; border-bottom:1px solid #1b1f24; }
  .table-scroll tbody tr:last-child td { border-bottom: none; }
  /* Webkit scrollbar styling — matches the dark palette. Firefox uses
     scrollbar-color below. */
  .table-scroll::-webkit-scrollbar { width: 10px; }
  .table-scroll::-webkit-scrollbar-track { background: #0b0d10; }
  .table-scroll::-webkit-scrollbar-thumb { background: #30363d; border-radius: 5px; }
  .table-scroll::-webkit-scrollbar-thumb:hover { background: #484f58; }
  .table-scroll { scrollbar-color: #30363d #0b0d10; scrollbar-width: thin; }
  /* Log viewer histogram strip — N tiny bars that together form a
     per-minute activity timeline above the log table. */
  .histogram { display:flex; align-items:flex-end; gap:1px; height:32px; margin:.4rem 0 .6rem;
               background:#0b0d10; border:1px solid #1b1f24; border-radius:.3rem; padding:2px; }
  .histogram .bar { flex:1 1 auto; background:#3fb950; min-width:1px; border-radius:1px; transition:height .2s; }
  .histogram .bar.empty { background:#1b1f24; }
  .histogram .bar:hover { background:#58a6ff; }
  /* Logs table — denser than alerts since lines are higher volume. */
  #logs td { font-size:.82rem; padding:.25rem .5rem; }
  #logs td.ip  { color:#8b949e; font-variant-numeric: tabular-nums; white-space:nowrap; }
  #logs td.mth { color:#6b7177; white-space:nowrap; }
  #logs td.pth { color:#d6d9dc; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                 overflow:hidden; text-overflow:ellipsis; max-width:52ch; }
  #logs td.st2 { color:#3fb950; text-align:right; font-variant-numeric: tabular-nums; }
  #logs td.st3 { color:#8b949e; text-align:right; font-variant-numeric: tabular-nums; }
  #logs td.st4 { color:#d29922; text-align:right; font-variant-numeric: tabular-nums; }
  #logs td.st5 { color:#f85149; text-align:right; font-variant-numeric: tabular-nums; }
  footer { padding:1rem 1.2rem; color:#6b7177; font-size:.75rem; text-align:center; }
  .err { color:#f85149; padding:.6rem; border:1px solid #da3633; border-radius:.3rem; background:#2a1215; }
</style>
</head><body>
<header>
  <h1>MiLog</h1>
  <span class="ts" id="ts">—</span>
  <span class="pill" id="status">connecting…</span>
</header>
<main>
  <section>
    <h2>System</h2>
    <div class="sys">
      <div class="card"><div class="lbl">CPU</div><div class="val" id="cpu">—</div><div class="sub" id="cpu-sub">&nbsp;</div><div class="bar"><span id="cpu-bar" style="width:0"></span></div></div>
      <div class="card"><div class="lbl">Memory</div><div class="val" id="mem">—</div><div class="sub" id="mem-sub">&nbsp;</div><div class="bar"><span id="mem-bar" style="width:0"></span></div></div>
      <div class="card"><div class="lbl">Disk</div><div class="val" id="disk">—</div><div class="sub" id="disk-sub">&nbsp;</div><div class="bar"><span id="disk-bar" style="width:0"></span></div></div>
    </div>
  </section>
  <section>
    <h2>Nginx (last minute)</h2>
    <table id="apps">
      <thead><tr><th>APP</th><th class="n">REQ</th><th class="n">2xx</th><th class="n">3xx</th><th class="n">4xx</th><th class="n">5xx</th></tr></thead>
      <tbody><tr><td colspan="6">loading…</td></tr></tbody>
    </table>
  </section>
  <section>
    <div class="alerts-head">
      <h2>Recent alerts</h2>
      <span class="meta" id="alerts-count">—</span>
      <select id="alerts-window" aria-label="alerts window">
        <option value="1h">last 1h</option>
        <option value="24h" selected>last 24h</option>
        <option value="7d">last 7d</option>
        <option value="today">today</option>
        <option value="all">all</option>
      </select>
    </div>
    <div class="table-scroll">
      <table id="alerts">
        <thead><tr><th>WHEN</th><th>SEV</th><th>RULE</th><th>TITLE</th></tr></thead>
        <tbody><tr><td colspan="4" class="empty">loading…</td></tr></tbody>
      </table>
    </div>
  </section>
  <section>
    <div class="alerts-head">
      <h2>Logs (live tail)</h2>
      <span class="meta" id="logs-count">—</span>
      <select id="logs-app" aria-label="app"></select>
      <select id="logs-class" aria-label="status class">
        <option value="any" selected>any</option>
        <option value="2xx">2xx</option>
        <option value="3xx">3xx</option>
        <option value="4xx">4xx</option>
        <option value="5xx">5xx</option>
      </select>
      <input id="logs-grep" placeholder="grep…" style="background:#10141a;color:#d6d9dc;border:1px solid #30363d;border-radius:.3rem;padding:.15rem .4rem;font:inherit;font-size:.8rem;width:14ch;">
    </div>
    <div id="logs-histogram" class="histogram"></div>
    <div class="table-scroll">
      <table id="logs">
        <thead><tr><th>WHEN</th><th>IP</th><th>METHOD</th><th>PATH</th><th>STATUS</th></tr></thead>
        <tbody><tr><td colspan="5" class="empty">pick an app…</td></tr></tbody>
      </table>
    </div>
  </section>
  <section id="err-section" hidden><div class="err" id="err">&nbsp;</div></section>
</main>
<footer>read-only · loopback by default · <span id="meta-uptime">—</span></footer>
<script>
(function(){
  // Token handshake: first load accepts ?t=TOKEN, stashes in sessionStorage,
  // then strips query so the token doesn't remain in the URL bar or history.
  var q = new URLSearchParams(location.search);
  if (q.get('t')) {
    sessionStorage.setItem('milog_token', q.get('t'));
    history.replaceState({}, '', location.pathname);
  }
  var token = sessionStorage.getItem('milog_token');
  if (!token) {
    document.getElementById('status').textContent = 'no token';
    document.getElementById('status').classList.add('bad');
    document.getElementById('err-section').hidden = false;
    document.getElementById('err').textContent = 'No session token. Open the URL printed by `milog web` that includes ?t=…';
    return;
  }

  function api(path){
    return fetch(path, { headers: { 'Authorization': 'Bearer ' + token }, cache: 'no-store' })
      .then(function(r){ if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
  }

  function colour(pct) { return pct >= 90 ? 'crit' : pct >= 75 ? 'warn' : ''; }
  function setBar(id, pct) {
    var el = document.getElementById(id);
    el.className = colour(pct);
    el.style.width = Math.min(100, Math.max(0, pct)) + '%';
  }

  function render(s) {
    var sys = s.system || {};
    document.getElementById('ts').textContent = s.ts || '';
    document.getElementById('cpu').textContent  = (sys.cpu || 0) + '%';
    document.getElementById('mem').textContent  = (sys.mem_pct || 0) + '%';
    document.getElementById('disk').textContent = (sys.disk_pct || 0) + '%';
    document.getElementById('mem-sub').textContent  = (sys.mem_used_mb||0) + ' / ' + (sys.mem_total_mb||0) + ' MB';
    document.getElementById('disk-sub').textContent = (sys.disk_used_gb||0) + ' / ' + (sys.disk_total_gb||0) + ' GB';
    setBar('cpu-bar', sys.cpu || 0);
    setBar('mem-bar', sys.mem_pct || 0);
    setBar('disk-bar', sys.disk_pct || 0);

    var tbody = document.querySelector('#apps tbody');
    tbody.innerHTML = '';
    (s.apps || []).forEach(function(a){
      var tr = document.createElement('tr');
      function td(v, cls){ var c = document.createElement('td'); if (cls) c.className = cls; c.textContent = v; return c; }
      tr.appendChild(td(a.name));
      tr.appendChild(td(a.req,  'n'));
      tr.appendChild(td(a.c2xx, 'n'));
      tr.appendChild(td(a.c3xx, 'n'));
      tr.appendChild(td(a.c4xx, 'n ' + (a.c4xx > 0 ? 'err4' : '')));
      tr.appendChild(td(a.c5xx, 'n ' + (a.c5xx > 0 ? 'err5' : '')));
      tbody.appendChild(tr);
    });
    if (!(s.apps || []).length) {
      tbody.innerHTML = '<tr><td colspan="6">no apps</td></tr>';
    }

    var pill = document.getElementById('status');
    pill.textContent = 'live · total ' + (s.total_req || 0) + ' req/min';
    pill.className = 'pill ok';
    document.getElementById('err-section').hidden = true;
  }

  function tick() {
    api('/api/summary.json').then(render).catch(function(e){
      var pill = document.getElementById('status');
      pill.textContent = 'error';
      pill.className = 'pill bad';
      document.getElementById('err-section').hidden = false;
      document.getElementById('err').textContent = e.message + ' — check the token or that milog web is still running';
    });
  }

  api('/api/meta.json').then(function(m){
    document.getElementById('meta-uptime').textContent = 'host uptime: ' + (m.uptime || '?');
  }).catch(function(){ /* non-fatal */ });

  // ---- alerts panel ------------------------------------------------------
  // Refreshes slower than summary — alerts don't change every 3s, and
  // reading alerts.log is cheaper but still pointless at summary cadence.
  function fmtWhen(ts) {
    // ts is Unix epoch seconds. Local time, 24h.
    var d = new Date(ts * 1000);
    function pad(n){ return n < 10 ? '0' + n : '' + n; }
    return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate())
         + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function renderAlerts(d) {
    var tbody = document.querySelector('#alerts tbody');
    var meta = document.getElementById('alerts-count');
    tbody.innerHTML = '';
    var list = (d && d.alerts) || [];
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">no alerts in window</td></tr>';
      meta.textContent = '0 alerts';
      return;
    }
    meta.textContent = list.length + ' alert' + (list.length === 1 ? '' : 's');
    // Chronological order: server returns oldest→newest; reverse so newest first.
    list.slice().reverse().forEach(function(a){
      var tr = document.createElement('tr');
      function td(v, cls){ var c = document.createElement('td'); if (cls) c.className = cls; c.textContent = v; return c; }
      tr.appendChild(td(fmtWhen(a.ts), 'when'));
      var sev = document.createElement('td');
      sev.className = 'sev-' + (a.sev || 'info');
      sev.textContent = (a.sev || 'info').toUpperCase();
      tr.appendChild(sev);
      tr.appendChild(td(a.rule || '', 'rule'));
      tr.appendChild(td(a.title || '', 'title'));
      tbody.appendChild(tr);
    });
  }
  function tickAlerts() {
    var w = document.getElementById('alerts-window').value;
    api('/api/alerts.json?window=' + encodeURIComponent(w))
      .then(renderAlerts)
      .catch(function(){ /* non-fatal; summary tick already surfaces errors */ });
  }
  document.getElementById('alerts-window').addEventListener('change', tickAlerts);

  // ---- logs panel --------------------------------------------------------
  // Short-poll log viewer (tier 1). Every 5s it fetches /api/logs.json with
  // the current filters and /api/logs/histogram.json for the timeline.
  // Tier 2 (SSE live tail) is a Go feature on the roadmap.
  function fmtLogWhen(s) {
    // "[24/Apr/2026:12:34:56 +0000]" → "12:34:56"
    var m = /:(\d\d:\d\d:\d\d)/.exec(s || '');
    return m ? m[1] : (s || '');
  }
  function setLogsApp(apps) {
    var sel = document.getElementById('logs-app');
    if (sel.options.length) return;
    (apps || []).forEach(function(a){
      var opt = document.createElement('option');
      opt.value = a; opt.textContent = a;
      sel.appendChild(opt);
    });
    if (sel.options.length) sel.value = sel.options[0].value;
  }
  function renderLogs(d) {
    var tbody = document.querySelector('#logs tbody');
    var meta = document.getElementById('logs-count');
    tbody.innerHTML = '';
    var list = (d && d.lines) || [];
    meta.textContent = list.length + ' line' + (list.length === 1 ? '' : 's');
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">no matching lines</td></tr>';
      return;
    }
    list.slice().reverse().forEach(function(r){
      var tr = document.createElement('tr');
      function td(v, cls){ var c = document.createElement('td'); if (cls) c.className = cls; c.textContent = v; return c; }
      var stClass = 'st' + String(r.status || '').charAt(0);
      tr.appendChild(td(fmtLogWhen(r.ts), 'when'));
      tr.appendChild(td(r.ip || '', 'ip'));
      tr.appendChild(td(r.method || '', 'mth'));
      tr.appendChild(td(r.path || '', 'pth'));
      tr.appendChild(td(r.status, stClass));
      tbody.appendChild(tr);
    });
  }
  function renderHistogram(d) {
    var el = document.getElementById('logs-histogram');
    el.innerHTML = '';
    var buckets = (d && d.buckets) || [];
    if (!buckets.length) { el.innerHTML = '<div style="flex:1;color:#6b7177;text-align:center;font-size:.7rem;line-height:28px;">no activity</div>'; return; }
    var max = buckets.reduce(function(m,b){ return Math.max(m, b.c || 0); }, 1);
    buckets.forEach(function(b){
      var bar = document.createElement('div');
      var pct = Math.round(((b.c || 0) / max) * 100);
      bar.className = 'bar' + ((b.c || 0) === 0 ? ' empty' : '');
      bar.style.height = ((b.c || 0) === 0 ? 2 : Math.max(4, pct)) + '%';
      bar.title = b.t + '  ' + (b.c || 0) + ' req';
      el.appendChild(bar);
    });
  }
  function tickLogs() {
    var app = document.getElementById('logs-app').value;
    if (!app) return;
    var grep = document.getElementById('logs-grep').value;
    var cls = document.getElementById('logs-class').value;
    var q = 'app=' + encodeURIComponent(app) + '&limit=200';
    if (grep) q += '&grep=' + encodeURIComponent(grep);
    if (cls && cls !== 'any') q += '&class=' + encodeURIComponent(cls);
    api('/api/logs.json?' + q).then(renderLogs).catch(function(){});
  }
  function tickHistogram() {
    var app = document.getElementById('logs-app').value;
    if (!app) return;
    api('/api/logs/histogram.json?app=' + encodeURIComponent(app) + '&minutes=60')
      .then(renderHistogram).catch(function(){});
  }
  // Populate app select from meta.apps
  api('/api/meta.json').then(function(m){ setLogsApp(m.apps || []); tickLogs(); tickHistogram(); }).catch(function(){});
  ['logs-app','logs-class','logs-grep'].forEach(function(id){
    document.getElementById(id).addEventListener('change', function(){ tickLogs(); tickHistogram(); });
  });
  document.getElementById('logs-grep').addEventListener('input', function(){
    // Debounced-lite: just call tickLogs after keystrokes; 200 req/minute
    // ceiling on the server hasn't been hit at this scale.
    clearTimeout(window.__milog_grep_t);
    window.__milog_grep_t = setTimeout(tickLogs, 250);
  });
  setInterval(tickLogs, 5000);
  setInterval(tickHistogram, 30000);

  tick();
  tickAlerts();
  setInterval(tick, 3000);
  setInterval(tickAlerts, 15000);
})();
</script>
</body></html>
HTML
    _web_respond 200 "text/html" "$body"
}

# ---- per-connection handler --------------------------------------------------
# Called by socat/ncat once per TCP accept. Stdin is the raw client bytes,
# stdout flows back to the client. Parses the request line + headers,
# validates the token, routes to a handler.
_web_handle() {
    local request_line line method full_path version
    local path query_string="" auth="" token_provided="" client_ip="${SOCAT_PEERADDR:-$(echo "${NCAT_REMOTE_ADDR:-unknown}")}"

    # First line: "METHOD PATH HTTP/1.1\r\n"
    if ! IFS= read -r request_line; then
        return 0
    fi
    request_line="${request_line%$'\r'}"
    read -r method full_path version <<< "$request_line"

    # Only GET is supported; no mutation routes.
    if [[ "$method" != "GET" ]]; then
        _web_respond 405 "text/plain" "method not allowed"
        _web_access_log "$client_ip" "$method" "$full_path" 405
        return 0
    fi

    # Split path ? query.
    if [[ "$full_path" == *"?"* ]]; then
        path="${full_path%%\?*}"
        query_string="${full_path#*\?}"
    else
        path="$full_path"
    fi

    # Read remaining headers until empty line. Captures Authorization only.
    local hdr_count=0
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "$line" ]] && break
        (( ++hdr_count > 64 )) && { _web_respond 400 "text/plain" "too many headers"; return 0; }
        if [[ "$line" =~ ^[Aa]uthorization:[[:space:]]*Bearer[[:space:]]+([A-Za-z0-9]+) ]]; then
            auth="${BASH_REMATCH[1]}"
        fi
    done

    # Token: prefer Authorization header, then ?t= query.
    if [[ -n "$auth" ]]; then
        token_provided="$auth"
    elif [[ "$query_string" =~ (^|&)t=([A-Za-z0-9]+) ]]; then
        token_provided="${BASH_REMATCH[2]}"
    fi

    local expected; expected=$(_web_token_read 2>/dev/null)
    if [[ -z "$expected" || -z "$token_provided" || "$token_provided" != "$expected" ]]; then
        _web_respond 401 "text/plain" "unauthorized"
        _web_access_log "$client_ip" "$method" "$path" 401
        return 0
    fi

    case "$path" in
        /)                  _web_route_index;   _web_access_log "$client_ip" "$method" "$path" 200 ;;
        /api/summary.json)  _web_route_summary; _web_access_log "$client_ip" "$method" "$path" 200 ;;
        /api/meta.json)     _web_route_meta;    _web_access_log "$client_ip" "$method" "$path" 200 ;;
        /api/alerts.json)
            # Extract window=... from the query string (validated to the
            # grammar _alerts_window_to_epoch accepts; anything malformed
            # falls through to its default).
            local win=""
            if [[ "$query_string" =~ (^|&)window=([A-Za-z0-9]+) ]]; then
                win="${BASH_REMATCH[2]}"
            fi
            _web_route_alerts "$win"
            _web_access_log "$client_ip" "$method" "$path" 200
            ;;
        /api/logs.json)
            local qapp="" qlim="" qg="" qp="" qc=""
            [[ "$query_string" =~ (^|&)app=([A-Za-z0-9_.-]+) ]]   && qapp="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)limit=([0-9]+) ]]          && qlim="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)grep=([^&]+) ]]            && qg="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)path=([^&]+) ]]            && qp="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)class=(2xx|3xx|4xx|5xx|any) ]] && qc="${BASH_REMATCH[2]}"
            _web_route_logs "$qapp" "$qlim" "$qg" "$qp" "$qc"
            _web_access_log "$client_ip" "$method" "$path" 200
            ;;
        /api/logs/histogram.json)
            local qapp="" qmin=""
            [[ "$query_string" =~ (^|&)app=([A-Za-z0-9_.-]+) ]] && qapp="${BASH_REMATCH[2]}"
            [[ "$query_string" =~ (^|&)minutes=([0-9]+) ]]      && qmin="${BASH_REMATCH[2]}"
            _web_route_logs_histogram "$qapp" "$qmin"
            _web_access_log "$client_ip" "$method" "$path" 200
            ;;
        *)                  _web_respond 404 "text/plain" "not found"
                            _web_access_log "$client_ip" "$method" "$path" 404 ;;
    esac
}

_web_access_log() {
    local ip="$1" method="$2" path="$3" status="$4"
    mkdir -p "$WEB_STATE_DIR" 2>/dev/null
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(date -Iseconds 2>/dev/null || date)" "$ip" "$method" "$path" "$status" \
        >> "$WEB_ACCESS_LOG" 2>/dev/null || true
}

# ---- subcommands: start / stop / status --------------------------------------
_web_pid_file() { echo "$WEB_STATE_DIR/web.pid"; }

# Human-readable age of the web token file. Silent + empty on missing file.
# Tokens are read per-request from disk so they rotate "live" the moment
# the file changes — status just reports when it was last written.
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

# Rotate the web token — delete + regenerate. Safe to call while the
# daemon is running: token is read per-request from disk, so the next
# request after rotation rejects the old token with 401.
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
        echo -e "${D}  service is running — the running daemon will accept the new token on next request${NC}"
    fi
    echo -e "${D}  old browser tabs will see 401 until you reopen the URL above${NC}"
}

# Is the systemd user unit currently active? Returns 0 if yes.
# Guarded so callers on non-systemd hosts short-circuit to "no".
_web_systemd_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl --user is-active --quiet milog-web.service 2>/dev/null
}

_web_status() {
    # Report systemd state first — it's the "installed service" path, which
    # is how most users will run it after install-service. Falls through to
    # pidfile for the foreground/nohup case.
    if _web_systemd_active; then
        local main_pid; main_pid=$(systemctl --user show --value -p MainPID milog-web.service 2>/dev/null)
        echo -e "${G}running${NC}  (systemd user unit)  pid=${main_pid:-?}  bind=${WEB_BIND}:${WEB_PORT}"
        echo -e "${D}  unit:  ${HOME}/.config/systemd/user/milog-web.service${NC}"
        echo -e "${D}  logs:  journalctl --user -u milog-web.service -f${NC}"
        echo -e "${D}  token: $WEB_TOKEN_FILE  (age $(_web_token_age))${NC}"
        if [[ -f "$WEB_ACCESS_LOG" ]]; then
            local hits; hits=$(wc -l < "$WEB_ACCESS_LOG" 2>/dev/null || echo 0)
            echo -e "${D}  ${hits} requests served (total)${NC}"
        fi
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
    echo -e "${D}  access log: $WEB_ACCESS_LOG${NC}"
    if [[ -f "$WEB_ACCESS_LOG" ]]; then
        local hits; hits=$(wc -l < "$WEB_ACCESS_LOG" 2>/dev/null || echo 0)
        echo -e "${D}  ${hits} requests served${NC}"
    fi
    return 0
}

_web_stop() {
    # If the systemd unit is up, stop it via systemctl — direct kill would
    # trigger Restart=on-failure and spawn a replacement.
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
        # Kill the whole process group so socat/ncat children die too.
        kill -TERM -- -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        sleep 0.3
        kill -KILL -- -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        echo -e "${G}stopped${NC}  pid=$pid"
    else
        echo -e "${Y}pidfile stale; cleaning${NC}"
    fi
    rm -f "$pf"
}

