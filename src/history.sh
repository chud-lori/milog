# ==============================================================================
# HISTORY — SQLite-backed per-minute time series + hourly top-IP rollups
# All writes go through a single sqlite3 invocation per call (heredoc),
# per the plan's "don't spawn one process per app" rule.
# ==============================================================================

# SQLite string literal escape: doubles embedded single quotes, wraps in ''.
_sql_quote() { local s="${1//\'/\'\'}"; printf "'%s'" "$s"; }

# Portable "date at epoch" → log-line prefix (dd/Mon/yyyy:HH:MM). GNU date
# takes `-d @TS`, BSD date takes `-r TS`. We just try both.
_cur_time_at() {
    local ts="$1"
    date -d "@${ts}" '+%d/%b/%Y:%H:%M' 2>/dev/null \
        || date -r "$ts" '+%d/%b/%Y:%H:%M' 2>/dev/null \
        || printf ''
}

# Create tables + indexes if missing. Idempotent; safe to call on every
# daemon start. Disables history on any failure mode (missing sqlite3,
# unwritable path) so the rest of the daemon keeps running.
history_init() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0

    if ! command -v sqlite3 >/dev/null 2>&1; then
        _dlog "WARNING: HISTORY_ENABLED=1 but sqlite3 is not on PATH — disabling history"
        HISTORY_ENABLED=0
        return 1
    fi

    local dir
    dir=$(dirname "$HISTORY_DB")
    if ! mkdir -p "$dir" 2>/dev/null; then
        _dlog "WARNING: cannot create history dir $dir — disabling history"
        HISTORY_ENABLED=0
        return 1
    fi

    if ! sqlite3 "$HISTORY_DB" <<'SQL' 2>/dev/null
CREATE TABLE IF NOT EXISTS metrics_minute (
    ts      INTEGER NOT NULL,
    app     TEXT    NOT NULL,
    req     INTEGER NOT NULL,
    c2xx    INTEGER NOT NULL,
    c3xx    INTEGER NOT NULL,
    c4xx    INTEGER NOT NULL,
    c5xx    INTEGER NOT NULL,
    p50_ms  INTEGER,
    p95_ms  INTEGER,
    p99_ms  INTEGER,
    PRIMARY KEY (ts, app)
);
CREATE TABLE IF NOT EXISTS top_ip_hour (
    ts_hour INTEGER NOT NULL,
    app     TEXT    NOT NULL,
    ip      TEXT    NOT NULL,
    hits    INTEGER NOT NULL,
    PRIMARY KEY (ts_hour, app, ip)
);
CREATE INDEX IF NOT EXISTS idx_metrics_app_ts ON metrics_minute(app, ts);
SQL
    then
        _dlog "WARNING: sqlite3 init failed — disabling history"
        HISTORY_ENABLED=0
        return 1
    fi

    _dlog "history: schema ready at $HISTORY_DB"
}

# Insert one row per configured app for a completed minute. The timestamp
# string must match the log format (dd/Mon/yyyy:HH:MM) so awk filters work.
# p50/p95/p99 land as SQL NULL when the app has no $request_time samples.
history_write_minute() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local ts="$1" cur_time="$2"
    [[ -n "$cur_time" ]] || { _dlog "history: empty cur_time for ts=$ts; skipping"; return 0; }

    local sql="" app count c2 c3 c4 c5 p50 p95 p99
    for app in "${LOGS[@]}"; do
        read -r count c2 c3 c4 c5 <<< "$(nginx_minute_counts "$app" "$cur_time")"
        count=${count:-0}; c2=${c2:-0}; c3=${c3:-0}; c4=${c4:-0}; c5=${c5:-0}
        read -r p50 p95 p99 <<< "$(percentiles "$app" "$cur_time")"
        [[ "$p50" =~ ^[0-9]+$ ]] || p50="NULL"
        [[ "$p95" =~ ^[0-9]+$ ]] || p95="NULL"
        [[ "$p99" =~ ^[0-9]+$ ]] || p99="NULL"
        sql+="INSERT OR REPLACE INTO metrics_minute VALUES"
        sql+=" ($ts, $(_sql_quote "$app"), $count, $c2, $c3, $c4, $c5, $p50, $p95, $p99);"$'\n'
    done

    if ! { printf 'BEGIN;\n%sCOMMIT;\n' "$sql"; } | sqlite3 "$HISTORY_DB" 2>/dev/null; then
        _dlog "history: minute write failed for ts=$ts"
    fi
}

# Hourly top-IP rollup. Scans each app's log for lines prefixed with the
# hour pattern (dd/Mon/yyyy:HH:), counts, and stores the top N. Lower N
# caps the database size on servers with very bursty IP diversity.
history_write_hour() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local ts_hour="$1"
    local hour_pat
    hour_pat=$(date -d "@${ts_hour}" '+%d/%b/%Y:%H:' 2>/dev/null \
               || date -r "$ts_hour"  '+%d/%b/%Y:%H:' 2>/dev/null)
    [[ -n "$hour_pat" ]] || return 0

    local sql="" app file hits ip
    for app in "${LOGS[@]}"; do
        file="$LOG_DIR/$app.access.log"
        [[ -f "$file" ]] || continue
        while read -r hits ip; do
            [[ -n "$ip" ]] || continue
            sql+="INSERT OR REPLACE INTO top_ip_hour VALUES"
            sql+=" ($ts_hour, $(_sql_quote "$app"), $(_sql_quote "$ip"), $hits);"$'\n'
        done < <(grep -F "$hour_pat" "$file" 2>/dev/null \
                 | awk '{print $1}' | sort | uniq -c | sort -rn \
                 | head -n "${HISTORY_TOP_IP_N:-50}")
    done

    [[ -n "$sql" ]] || return 0
    if ! { printf 'BEGIN;\n%sCOMMIT;\n' "$sql"; } | sqlite3 "$HISTORY_DB" 2>/dev/null; then
        _dlog "history: hour write failed for ts_hour=$ts_hour"
    fi
}

# Delete rows older than HISTORY_RETAIN_DAYS days from both tables. One
# sqlite3 invocation, transactional. Called once per day from the daemon.
history_prune() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    [[ -f "$HISTORY_DB" ]] || return 0
    local retain="${HISTORY_RETAIN_DAYS:-30}"
    [[ "$retain" =~ ^[0-9]+$ ]] || retain=30
    local cutoff=$(( $(date +%s) - retain * 86400 ))
    if sqlite3 "$HISTORY_DB" <<SQL 2>/dev/null
BEGIN;
DELETE FROM metrics_minute WHERE ts      < $cutoff;
DELETE FROM top_ip_hour    WHERE ts_hour < $cutoff;
COMMIT;
SQL
    then
        _dlog "history: pruned rows older than ${retain}d (cutoff=$cutoff)"
    else
        _dlog "history: prune failed"
    fi
}

# Gate for read-only history modes (trend / diff). Prints a friendly
# message to stderr and returns 1 when sqlite3 or the DB are missing.
_history_precheck() {
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${R}sqlite3 is not installed${NC}" >&2
        echo -e "${D}  re-run the installer (sqlite3 is now installed by default) or:${NC}" >&2
        echo -e "${D}  sudo apt install sqlite3  /  sudo dnf install sqlite  /  sudo pacman -S sqlite${NC}" >&2
        return 1
    fi
    if [[ ! -f "$HISTORY_DB" ]]; then
        echo -e "${R}No history database at $HISTORY_DB${NC}" >&2
        echo -e "${D}  enable with: milog config set HISTORY_ENABLED 1 && milog daemon${NC}" >&2
        return 1
    fi
}

