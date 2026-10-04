# milog report [window] [--html] [-o FILE]: static traffic / attacker / alert / anomaly / audit summary.

# Stdin records, tab-separated: T title, M meta line, H section, P note, E empty state, C header cells, R row cells.
_report_render() {
    awk -F'\t' -v html="$1" '
        function esc(s) {
            gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s)
            if (html) { gsub(/"/, "\\&quot;", s); gsub(/\047/, "\\&#39;", s) }
            else { gsub(/\|/, "\\&#124;", s); gsub(/`/, "\\&#96;", s); gsub(/\[/, "\\&#91;", s); gsub(/\]/, "\\&#93;", s) }
            return s
        }
        function close_table() { if (open) { print "</tbody></table>"; open = 0 } }
        BEGIN {
            if (html) {
                print "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                print "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                print "<style>"
                print ":root{--bg:#0b0d10;--bg-2:#121519;--fg:#e4e7eb;--fg-2:#a4adb8;--border:#2a2f37;" \
                      "--mono:ui-monospace,SFMono-Regular,\"JetBrains Mono\",Menlo,Monaco,Consolas,monospace;" \
                      "--sans:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif}"
                print "@media (prefers-color-scheme:light){:root{--bg:#fafbfc;--bg-2:#ffffff;--fg:#16191d;--fg-2:#454d57;--border:#dde1e6}}"
                print "body{margin:0 auto;max-width:72rem;padding:2rem 1rem;background:var(--bg);color:var(--fg);font:15px/1.5 var(--sans)}"
                print "h1{font-size:1.4rem;margin:0}h2{font-size:1.1rem;margin:2rem 0 .5rem}p{margin:.25rem 0;color:var(--fg-2)}"
                print "table{border-collapse:collapse;background:var(--bg-2)}"
                print "th,td{border:1px solid var(--border);padding:.3rem .6rem;text-align:left;vertical-align:top}"
                print "td{font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}th{color:var(--fg-2);font-weight:600}"
                print "td.n{text-align:right;white-space:nowrap}"
                print "</style>"
            }
        }
        $1 == "T" {
            if (html) printf "<title>%s</title></head><body>\n<h1>%s</h1>\n", esc($2), esc($2)
            else printf "# %s\n", esc($2)
        }
        $1 == "M" { if (html) printf "<p>%s</p>\n", esc($2); else printf "\n%s\n", esc($2) }
        $1 == "H" { close_table(); if (html) printf "<h2>%s</h2>\n", esc($2); else printf "\n## %s\n\n", esc($2) }
        $1 == "P" { if (html) printf "<p>%s</p>\n", esc($2); else printf "%s\n\n", esc($2) }
        $1 == "E" { if (html) printf "<p>%s</p>\n", esc($2); else printf "%s\n", esc($2) }
        $1 == "C" {
            if (html) {
                printf "<table><thead><tr>"
                for (i = 2; i <= NF; i++) printf "<th>%s</th>", esc($i)
                print "</tr></thead><tbody>"; open = 1
            } else {
                line = "|"; rule = "|"
                for (i = 2; i <= NF; i++) { line = line " " esc($i) " |"; rule = rule " --- |" }
                print line; print rule
            }
        }
        $1 == "R" {
            if (html) {
                printf "<tr>"
                for (i = 2; i <= NF; i++) printf "<td%s>%s</td>", ($i ~ /^[0-9]+$/ ? " class=\"n\"" : ""), esc($i)
                print "</tr>"
            } else {
                line = "|"
                for (i = 2; i <= NF; i++) line = line " " esc($i) " |"
                print line
            }
        }
        END { close_table(); if (html) print "</body></html>" }'
}

# One pass over the windowed access lines: per-app totals, then the top 10 IPs by 4xx.
_report_traffic() {
    local cutoff="$1" entry name file
    for entry in "${LOGS[@]}"; do
        [[ "$(_log_type_for "$entry")" == "nginx" ]] || continue
        name=$(_log_name_for "$entry")
        file=$(_log_path_for "$entry")
        [[ -f "$file" ]] || continue
        printf 'A\t%s\n' "$name"
        _digest_in_window "$cutoff" "$file" | awk -v app="$name" '{ print "L\t" app "\t" $1 "\t" $9 }'
    done | awk -F'\t' '
        $1 == "A" { apps[++na] = $2; next }
        {
            req[$2]++; ipreq[$3]++
            if ($4 ~ /^4/) { c4[$2]++; ip4[$3]++ }
            else if ($4 ~ /^5/) c5[$2]++
        }
        END {
            print "H\tTraffic per app"
            if (!na) print "E\tNo nginx access log found for any configured app."
            else {
                print "C\tApp\tRequests\t4xx\t5xx"
                for (i = 1; i <= na; i++) { a = apps[i]; printf "R\t%s\t%d\t%d\t%d\n", a, req[a], c4[a], c5[a] }
            }
            print "H\tTop attacker IPs"
            print "P\tRanked by 4xx responses across all apps."
            for (n = 0; n < 10; n++) {
                best = ""
                for (ip in ip4) if (!(ip in done) && (best == "" || ip4[ip] > ip4[best] || (ip4[ip] == ip4[best] && ipreq[ip] > ipreq[best]))) best = ip
                if (best == "") break
                done[best] = 1
                if (!n) print "C\tIP\t4xx\tRequests"
                printf "R\t%s\t%d\t%d\n", best, ip4[best], ipreq[best]
            }
            if (!n) print "E\tNo IP got a 4xx response in this window."
        }'
}

_report_alerts() {
    local cutoff="$1" alog="$ALERT_STATE_DIR/alerts.log" tab=$'\t' rows="" n last rule ts body
    printf 'H\tAlert fires per rule\n'
    if [[ ! -f "$alog" ]]; then
        printf 'E\tNo alerts.log at %s, so no alert has fired on this host.\n' "$alog"
    else
        rows=$(awk -F'\t' -v c="$cutoff" '$1 >= c { n[$2]++; if ($1 > last[$2]) last[$2] = $1 }
            END { for (r in n) printf "%d\t%s\t%s\n", n[r], last[r], r }' "$alog" | sort -t "$tab" -k1,1rn -k3,3)
        if [[ -z "$rows" ]]; then
            printf 'E\tNo alerts fired in this window.\n'
        else
            printf 'C\tRule\tFires\tLast fired\n'
            while IFS=$'\t' read -r n last rule; do
                printf 'R\t%s\t%s\t%s\n' "$rule" "$n" "$(_alerts_fmt_epoch "$last")"
            done <<< "$rows"
        fi
        rows=$(awk -F'\t' -v c="$cutoff" '$1 >= c && $2 ~ /^anomaly:/ { print $1 "\t" $2 "\t" $5 }' "$alog" \
            | sort -t "$tab" -k1,1rn | head -50)
    fi

    printf 'H\tAnomalies\n'
    if [[ -z "$rows" ]]; then
        if [[ "${ANOMALY_ENABLED:-0}" == "1" ]]; then
            printf 'E\tNo anomalies fired in this window.\n'
        else
            printf 'E\tNo anomalies fired in this window. Anomaly detection is off (ANOMALY_ENABLED=0).\n'
        fi
    else
        printf 'C\tTime\tRule\tDetail\n'
        while IFS=$'\t' read -r ts rule body; do
            printf 'R\t%s\t%s\t%s\n' "$(_alerts_fmt_epoch "$ts")" "$rule" "${body//\`/}"
        done <<< "$rows"
    fi
}

# Prints nothing unless the history DB has an audit* table with a ts column; other columns are shown as stored.
_report_audit() {
    local cutoff="$1" table cols col select="" has_ts=0 out
    command -v sqlite3 >/dev/null 2>&1 && [[ -f "$HISTORY_DB" ]] || return 0
    table=$(sqlite3 "$HISTORY_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'audit%' ORDER BY name LIMIT 1;" 2>/dev/null) || return 0
    [[ "$table" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 0
    cols=$(sqlite3 "$HISTORY_DB" "SELECT name FROM pragma_table_info('$table');" 2>/dev/null) || return 0
    while IFS= read -r col; do
        [[ "$col" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        [[ -n "$select" ]] && select+=", "
        if [[ "$col" == "ts" ]]; then
            has_ts=1
            select+="datetime(ts, 'unixepoch') AS ts"
        else
            select+="replace(replace(CAST($col AS TEXT), char(9), ' '), char(10), ' ') AS $col"
        fi
    done <<< "$cols"
    (( has_ts )) || return 0

    out=$(sqlite3 -header -separator $'\t' "$HISTORY_DB" \
        "SELECT $select FROM $table WHERE ts >= $cutoff ORDER BY ts DESC LIMIT 100;" 2>/dev/null) || return 0
    printf 'H\tAudit drift\n'
    if [[ -z "$out" ]]; then
        printf 'E\tNo audit results recorded in this window.\n'
    else
        printf '%s\n' "$out" | awk 'NR == 1 { print "C\t" $0; next } { print "R\t" $0 }'
    fi
}

mode_report() {
    local window="7d" html=0 out="" secs now cutoff report
    while (( $# )); do
        case "$1" in
            --html) html=1 ;;
            -o) [[ -n "${2:-}" ]] || { echo -e "${R}report: -o needs a file${NC}" >&2; return 1; }
                out="$2"; shift ;;
            -*) echo -e "${R}report: unknown flag: $1${NC}" >&2; return 1 ;;
            *)  window="$1" ;;
        esac
        shift
    done
    secs=$(_digest_window_to_secs "$window") || { echo -e "${R}report: invalid window: $window${NC}" >&2; return 1; }
    now=$(date +%s)
    cutoff=$(( now - secs ))

    report=$(
        printf 'T\tMiLog report: last %s on %s\n' "$window" "$(hostname 2>/dev/null || echo host)"
        printf 'M\t%s to %s\n' "$(_alerts_fmt_epoch "$cutoff")" "$(_alerts_fmt_epoch "$now")"
        _report_traffic "$cutoff"
        _report_alerts "$cutoff"
        _report_audit "$cutoff"
    )
    if [[ -n "$out" ]]; then
        printf '%s\n' "$report" | _report_render "$html" | _tty_safe > "$out"
    else
        printf '%s\n' "$report" | _report_render "$html" | _tty_safe
    fi
}
