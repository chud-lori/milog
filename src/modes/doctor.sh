# ==============================================================================
# MODE: doctor — checklist of what's installed/configured/reachable
#
# The tool no-ops gracefully when sqlite3, mmdblookup, a webhook, or the
# extended log format are missing — which is friendly but can hide a
# misconfigured install. `doctor` makes every degraded capability visible
# with a one-line hint on how to enable it.
#
# Output: ✓ (ready) / ! (degraded, works-but-limited) / ✗ (broken/required).
# Exit code: 0 if all required deps are present; 1 otherwise. CI-friendly.
# ==============================================================================
_doc_line() {
    # $1=marker (colored glyph)  $2=headline  $3=optional hint
    printf "  %b %s\n" "$1" "$2"
    [[ -n "${3:-}" ]] && printf "     ${D}%s${NC}\n" "$3"
    return 0   # guard against set -e when hint is empty
}
_doc_ok()   { _doc_line "${G}✓${NC}" "$1" "${2:-}"; }
_doc_warn() { _doc_line "${Y}!${NC}" "$1" "${2:-}"; }
_doc_fail() { _doc_line "${R}✗${NC}" "$1" "${2:-}"; }
_doc_head() { printf "\n${W}── %s ──${NC}\n" "$1"; }

mode_doctor() {
    local fail=0 warn=0
    echo -e "\n${W}── MiLog: doctor ──${NC}"

    # ---- core tools (required) ----------------------------------------------
    _doc_head "core tools"
    local tool
    for tool in bash gawk curl; do
        if command -v "$tool" >/dev/null 2>&1; then
            _doc_ok "$tool present  ($(command -v "$tool"))"
        else
            _doc_fail "$tool NOT on PATH" "required — install via your package manager"
            fail=$(( fail + 1 ))
        fi
    done
    local bmaj="${BASH_VERSINFO[0]:-3}"
    if (( bmaj >= 4 )); then
        _doc_ok "bash ${BASH_VERSION}  (sparkline cache enabled)"
    else
        _doc_warn "bash ${BASH_VERSION}" "bash<4 — monitor skips the p95 cache; upgrade for smoother TUI"
        warn=$(( warn + 1 ))
    fi

    # ---- optional tools ------------------------------------------------------
    _doc_head "optional tools"
    if command -v sqlite3 >/dev/null 2>&1; then
        _doc_ok "sqlite3 present  ($(sqlite3 --version 2>/dev/null | awk '{print $1}'))"
    else
        _doc_warn "sqlite3 missing" "trend/replay/diff/auto-tune will be disabled — install 'sqlite3'"
        warn=$(( warn + 1 ))
    fi
    if command -v mmdblookup >/dev/null 2>&1; then
        _doc_ok "mmdblookup present" "GeoIP country enrichment available when GEOIP_ENABLED=1"
    else
        _doc_warn "mmdblookup missing" "GeoIP column disabled — install 'mmdb-bin' / 'libmaxminddb'"
        warn=$(( warn + 1 ))
    fi

    # ---- log dir + per-app logs ---------------------------------------------
    _doc_head "log directory"
    if [[ -d "$LOG_DIR" && -r "$LOG_DIR" ]]; then
        _doc_ok "$LOG_DIR readable"
    else
        _doc_fail "$LOG_DIR missing or unreadable" "set MILOG_LOG_DIR or edit LOG_DIR in $MILOG_CONFIG"
        fail=$(( fail + 1 ))
    fi

    _doc_head "app logs (${#LOGS[@]} configured)"
    if (( ${#LOGS[@]} == 0 )); then
        _doc_warn "LOGS is empty" "add apps via 'milog config add <name>' or set MILOG_APPS='a b c'"
        warn=$(( warn + 1 ))
    else
        local app file mtime now age
        now=$(date +%s)
        for app in "${LOGS[@]}"; do
            file="$LOG_DIR/$app.access.log"
            if [[ ! -f "$file" ]]; then
                _doc_warn "$app — no access log" "expected: $file"
                warn=$(( warn + 1 ))
                continue
            fi
            mtime=$(stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null || echo 0)
            age=$(( now - mtime ))
            if (( age < 3600 )); then
                _doc_ok "$app — active  (last write ${age}s ago)"
            elif (( age < 86400 )); then
                _doc_warn "$app — stale  (last write $(( age / 3600 ))h ago)"
                warn=$(( warn + 1 ))
            else
                _doc_warn "$app — idle  (last write $(( age / 86400 ))d ago)"
                warn=$(( warn + 1 ))
            fi
        done
    fi

    # ---- nginx log format — does it carry $request_time? --------------------
    #
    # Scan the tail of every configured app's log and look for any timed line
    # (numeric last field, NF>=12). One app's tail might still be pre-reload
    # old-format while others are already new-format — we report ✓ as long
    # as at least one app has timed samples recently. Simultaneously tracks
    # apps with only old-format lines so the hint can call them out for
    # manual verification.
    _doc_head "nginx log format"
    if (( ${#LOGS[@]} == 0 )); then
        _doc_warn "no configured apps"
    else
        local app file last nf lastfield
        local timed_apps=() untimed_apps=() witness=""
        for app in "${LOGS[@]}"; do
            file="$LOG_DIR/$app.access.log"
            [[ -f "$file" ]] || continue
            last=$(tail -n 200 "$file" 2>/dev/null | awk 'NF>0' | tail -n 1)
            [[ -n "$last" ]] || continue
            nf=$(awk '{print NF}' <<< "$last")
            lastfield=$(awk '{print $NF}' <<< "$last")
            if [[ "$lastfield" =~ ^[0-9]+(\.[0-9]+)?$ ]] && (( nf >= 12 )); then
                timed_apps+=("$app")
                [[ -z "$witness" ]] && witness="$app line ends with $lastfield"
            else
                untimed_apps+=("$app")
            fi
        done
        if (( ${#timed_apps[@]} > 0 )); then
            _doc_ok "extended log format detected  ($witness)" \
                    "slow / p95 / top-paths fully enabled"
            if (( ${#untimed_apps[@]} > 0 )); then
                _doc_warn "apps still showing old-format tail: ${untimed_apps[*]}" \
                          "likely just no post-reload traffic yet — not a config issue"
            fi
        elif (( ${#untimed_apps[@]} > 0 )); then
            _doc_warn "log format appears to be 'combined' (no \$request_time)" \
                      "add \$request_time as the LAST field to enable slow/p95 — see README"
            warn=$(( warn + 1 ))
        else
            _doc_warn "no loglines to inspect in any app"
            warn=$(( warn + 1 ))
        fi
    fi

    # ---- Discord alerting ----------------------------------------------------
    _doc_head "alerting (Discord)"
    if [[ -z "${DISCORD_WEBHOOK:-}" ]]; then
        _doc_warn "DISCORD_WEBHOOK not configured" \
                  "run: sudo milog alert on \"https://discord.com/api/webhooks/ID/TOKEN\""
        warn=$(( warn + 1 ))
    else
        _doc_ok "DISCORD_WEBHOOK configured  (${DISCORD_WEBHOOK:0:40}…)"
        # Reachability — a POST with an empty content is ignored by Discord,
        # so we GET the webhook metadata instead (returns 200 + JSON on valid
        # webhooks, 404 on stale). 5s cap so doctor never hangs.
        local http
        http=$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 \
               "$DISCORD_WEBHOOK" 2>/dev/null || echo 000)
        case "$http" in
            200) _doc_ok "webhook reachable  (HTTP 200)" ;;
            401|403|404) _doc_fail "webhook rejected  (HTTP $http)" "webhook was deleted or token invalid — regenerate in Discord"; fail=$(( fail + 1 )) ;;
            000) _doc_warn "webhook unreachable (network/timeout)" "is this box allowed to egress to discord.com?"; warn=$(( warn + 1 )) ;;
            *)   _doc_warn "webhook returned HTTP $http" "unexpected — may still work for POSTs; test with 'milog alert test'"; warn=$(( warn + 1 )) ;;
        esac
    fi
    if [[ "${ALERTS_ENABLED:-0}" == "1" ]]; then
        _doc_ok "ALERTS_ENABLED=1  (cooldown=${ALERT_COOLDOWN}s, dedup=${ALERT_DEDUP_WINDOW}s)"
    else
        _doc_warn "ALERTS_ENABLED=0" "alerts are armed but disabled — 'milog alert on' to flip"
        warn=$(( warn + 1 ))
    fi
    # Report other destinations when configured — each is opt-in, so
    # "not configured" is informational (not a warning).
    [[ -n "${SLACK_WEBHOOK:-}" ]] \
        && _doc_ok "Slack webhook configured  (${SLACK_WEBHOOK:0:40}…)"
    [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]] \
        && _doc_ok "Telegram bot configured  (chat=$TELEGRAM_CHAT_ID)"
    [[ -n "${MATRIX_HOMESERVER:-}" && -n "${MATRIX_TOKEN:-}" && -n "${MATRIX_ROOM:-}" ]] \
        && _doc_ok "Matrix configured  (${MATRIX_HOMESERVER} room=$MATRIX_ROOM)"
    # Alert history log — surface count since "today" so users know it works.
    local alog="$ALERT_STATE_DIR/alerts.log"
    if [[ -f "$alog" ]]; then
        local now_epoch today_cutoff today_count total_count
        now_epoch=$(date +%s)
        today_cutoff=$(( now_epoch - (now_epoch % 86400) ))
        today_count=$(awk -F'\t' -v c="$today_cutoff" '$1 >= c' "$alog" | wc -l | tr -d ' ')
        total_count=$(wc -l < "$alog" | tr -d ' ')
        _doc_ok "alerts.log: ${total_count} total, ${today_count} today" \
                "view with: milog alerts [today|Nh|Nd|all]"
    fi

    # ---- history DB ---------------------------------------------------------
    _doc_head "history (SQLite)"
    if [[ "${HISTORY_ENABLED:-0}" != "1" ]]; then
        _doc_warn "HISTORY_ENABLED=0" "set to 1 to let 'milog daemon' persist metrics for trend/diff/auto-tune"
        warn=$(( warn + 1 ))
    elif ! command -v sqlite3 >/dev/null 2>&1; then
        _doc_fail "HISTORY_ENABLED=1 but sqlite3 missing" "install sqlite3 or set HISTORY_ENABLED=0"
        fail=$(( fail + 1 ))
    elif [[ ! -f "$HISTORY_DB" ]]; then
        _doc_warn "db not yet written: $HISTORY_DB" "run 'milog daemon' for at least one minute to populate"
        warn=$(( warn + 1 ))
    else
        local rows oldest
        rows=$(sqlite3 "$HISTORY_DB" "SELECT COUNT(*) FROM metrics_minute;" 2>/dev/null || echo 0)
        oldest=$(sqlite3 "$HISTORY_DB" "SELECT MIN(ts) FROM metrics_minute;" 2>/dev/null || echo 0)
        if [[ "$rows" =~ ^[0-9]+$ ]] && (( rows > 0 )); then
            local days=0
            if [[ "$oldest" =~ ^[0-9]+$ ]] && (( oldest > 0 )); then
                days=$(( ( $(date +%s) - oldest ) / 86400 ))
            fi
            _doc_ok "$HISTORY_DB  (${rows} rows, ~${days}d of history, retain=${HISTORY_RETAIN_DAYS}d)"
        else
            _doc_warn "$HISTORY_DB is empty" "daemon hasn't flushed a minute yet"
            warn=$(( warn + 1 ))
        fi
    fi

    # ---- GeoIP --------------------------------------------------------------
    _doc_head "geoip"
    if [[ "${GEOIP_ENABLED:-0}" != "1" ]]; then
        _doc_warn "GEOIP_ENABLED=0" "optional — set to 1 + install the MaxMind MMDB to enable country column"
        warn=$(( warn + 1 ))
    elif ! command -v mmdblookup >/dev/null 2>&1; then
        _doc_fail "GEOIP_ENABLED=1 but mmdblookup missing"
        fail=$(( fail + 1 ))
    elif [[ ! -f "$MMDB_PATH" ]]; then
        _doc_fail "MMDB not found: $MMDB_PATH" "sign up at maxmind.com and download GeoLite2-Country.mmdb"
        fail=$(( fail + 1 ))
    else
        local probe
        probe=$(geoip_country 8.8.8.8 2>/dev/null)
        if [[ -n "$probe" && "$probe" != "--" ]]; then
            _doc_ok "$MMDB_PATH  (8.8.8.8 → $probe)"
        else
            _doc_warn "$MMDB_PATH present but lookup returned empty — DB may be corrupt"
            warn=$(( warn + 1 ))
        fi
    fi

    # ---- web dashboard ------------------------------------------------------
    _doc_head "web dashboard"
    # milog-web is the Go binary served by `milog web`. _web_go_binary
    # checks the same path order the launcher uses, so the warning here
    # mirrors what users will hit at start time.
    local web_bin
    if web_bin=$(_web_go_binary 2>/dev/null) && [[ -n "$web_bin" ]]; then
        _doc_ok "milog-web binary present  ($web_bin)"
    else
        _doc_warn "milog-web binary not found" \
                  "rerun install.sh — it pulls milog-web from the latest GitHub release"
        warn=$(( warn + 1 ))
    fi
    if [[ -f "$WEB_STATE_DIR/web.pid" ]]; then
        local wpid; wpid=$(< "$WEB_STATE_DIR/web.pid" 2>/dev/null)
        if [[ -n "$wpid" ]] && kill -0 "$wpid" 2>/dev/null; then
            _doc_ok "milog web running  (pid=$wpid, $WEB_BIND:$WEB_PORT)"
        else
            _doc_warn "stale web pidfile (not running)" "milog web stop  # cleans it up"
            warn=$(( warn + 1 ))
        fi
    fi

    # ---- systemd units (only meaningful where systemd is installed) ---------
    if command -v systemctl >/dev/null 2>&1; then
        _doc_head "systemd"
        # milog.service (system unit) — the alert daemon.
        if [[ ! -f /etc/systemd/system/milog.service ]]; then
            _doc_warn "milog.service not installed" "run: sudo milog alert on (installs + enables the unit)"
            warn=$(( warn + 1 ))
        elif systemctl is-active --quiet milog.service 2>/dev/null; then
            _doc_ok "milog.service active" "logs: journalctl -u milog.service -f"
        else
            _doc_warn "milog.service installed but inactive" "start: sudo systemctl start milog.service"
            warn=$(( warn + 1 ))
        fi
        # milog-web.service (user unit) — optional dashboard. Only report if
        # something has attempted to install it; absent-by-choice is fine.
        local web_unit="${HOME}/.config/systemd/user/milog-web.service"
        if [[ -f "$web_unit" ]]; then
            if systemctl --user is-active --quiet milog-web.service 2>/dev/null; then
                _doc_ok "milog-web.service active (user unit)" "logs: journalctl --user -u milog-web.service -f"
            else
                _doc_warn "milog-web.service installed but inactive" \
                          "start: systemctl --user start milog-web.service"
                warn=$(( warn + 1 ))
            fi
        fi
    fi

    # ---- summary -------------------------------------------------------------
    echo
    if (( fail > 0 )); then
        echo -e "  ${R}${fail} failure(s)${NC}, ${Y}${warn} warning(s)${NC} — required functionality is missing."
        return 1
    elif (( warn > 0 )); then
        echo -e "  ${G}core OK${NC} — ${Y}${warn} optional feature(s) disabled${NC}."
        return 0
    else
        echo -e "  ${G}all checks passed${NC}"
        return 0
    fi
}

# ==============================================================================
