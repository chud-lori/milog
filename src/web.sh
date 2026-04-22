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

  tick();
  setInterval(tick, 3000);
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
        echo -e "${D}  token: $WEB_TOKEN_FILE${NC}"
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

