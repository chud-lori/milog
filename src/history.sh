# History: SQLite per-minute metrics and hourly top-IP rollups, one sqlite3 process per write.

# Doubles single quotes and wraps the value in ''.
# The quote goes through a variable because bash < 4.3 keeps the backslashes in "${1//\'/\'\'}".
_sql_quote() { local q="'"; printf "'%s'" "${1//$q/$q$q}"; }

# Epoch -> log timestamp prefix (dd/Mon/yyyy:HH:MM); tries GNU `date -d @` then BSD `date -r`.
_cur_time_at() {
    local ts="$1"
    date -d "@${ts}" '+%d/%b/%Y:%H:%M' 2>/dev/null \
        || date -r "$ts" '+%d/%b/%Y:%H:%M' 2>/dev/null \
        || printf ''
}

# Idempotent; any failure disables history so the daemon keeps running.
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
CREATE TABLE IF NOT EXISTS audit_event (
    ts      INTEGER NOT NULL,
    scanner TEXT    NOT NULL,
    kind    TEXT    NOT NULL,
    subject TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_event_ts ON audit_event(ts);
SQL
    then
        _dlog "WARNING: sqlite3 init failed — disabling history"
        HISTORY_ENABLED=0
        return 1
    fi

    _dlog "history: schema ready at $HISTORY_DB"
}

# cur_time must match the log's dd/Mon/yyyy:HH:MM prefix; percentiles land as NULL when there are no $request_time samples.
history_write_minute() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local ts="$1" cur_time="$2"
    [[ -n "$cur_time" ]] || { _dlog "history: empty cur_time for ts=$ts; skipping"; return 0; }

    local sql="" app name count c2 c3 c4 c5 p50 p95 p99
    for app in "${LOGS[@]}"; do
        [[ "$(_log_type_for "$app")" == "nginx" ]] || continue
        name=$(_log_name_for "$app")
        read -r count c2 c3 c4 c5 <<< "$(nginx_minute_counts "$name" "$cur_time")"
        count=${count:-0}; c2=${c2:-0}; c3=${c3:-0}; c4=${c4:-0}; c5=${c5:-0}
        read -r p50 p95 p99 <<< "$(percentiles "$name" "$cur_time")"
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

# Stores the top HISTORY_TOP_IP_N IPs per app for the hour.
history_write_hour() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local ts_hour="$1"
    local hour_pat
    hour_pat=$(date -d "@${ts_hour}" '+%d/%b/%Y:%H:' 2>/dev/null \
               || date -r "$ts_hour"  '+%d/%b/%Y:%H:' 2>/dev/null)
    [[ -n "$hour_pat" ]] || return 0

    local sql="" app file hits ip
    for app in "${LOGS[@]}"; do
        [[ "$(_log_type_for "$app")" == "nginx" ]] || continue
        file=$(_log_path_for "$app")
        [[ -f "$file" ]] || continue
        while read -r hits ip; do
            [[ -n "$ip" ]] || continue
            sql+="INSERT OR REPLACE INTO top_ip_hour VALUES"
            sql+=" ($ts_hour, $(_sql_quote "$app"), $(_sql_quote "$ip"), $hits);"$'\n'
        done < <(awk -v p="$hour_pat" 'index($4, p) == 2 {print $1}' "$file" 2>/dev/null \
                 | sort | uniq -c | sort -rn \
                 | head -n "${HISTORY_TOP_IP_N:-50}")
    done

    [[ -n "$sql" ]] || return 0
    if ! { printf 'BEGIN;\n%sCOMMIT;\n' "$sql"; } | sqlite3 "$HISTORY_DB" 2>/dev/null; then
        _dlog "history: hour write failed for ts_hour=$ts_hour"
    fi
}

# rows are "<kind>\t<subject>" lines; a finding already stored at or after `since` is skipped, so drift that persists across ticks stays one row.
history_write_audit() {
    [[ "$HISTORY_ENABLED" != "1" ]] && return 0
    local scanner="$1" since="${2:-0}" rows="$3"
    [[ "$since" =~ ^[0-9]+$ ]] || since=0
    local now; now=$(date +%s)
    local sql="" kind subject k j q="'" s
    s=$(_sql_quote "$scanner")
    # Quoted inline, not via _sql_quote: a subshell per row stalls the daemon tick when thousands of findings persist.
    while IFS=$'\t' read -r kind subject; do
        [[ -n "$kind" && -n "$subject" ]] || continue
        k="lower('${kind//$q/$q$q}')"; j="'${subject//$q/$q$q}'"
        sql+="INSERT INTO audit_event SELECT $now, $s, $k, $j WHERE NOT EXISTS"
        sql+=" (SELECT 1 FROM audit_event WHERE scanner = $s AND kind = $k AND subject = $j AND ts >= $since);"$'\n'
    done <<< "$rows"

    [[ -n "$sql" ]] || return 0
    if ! { printf 'BEGIN;\n%sCOMMIT;\n' "$sql"; } | sqlite3 "$HISTORY_DB" 2>/dev/null; then
        _dlog "history: audit write failed for $scanner"
    fi
}

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
DELETE FROM audit_event    WHERE ts      < $cutoff;
COMMIT;
SQL
    then
        _dlog "history: pruned rows older than ${retain}d (cutoff=$cutoff)"
    else
        _dlog "history: prune failed"
    fi
}

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

