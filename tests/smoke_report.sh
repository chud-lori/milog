#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { printf 'smoke_report: %s\n' "$1" >&2; exit 1; }

export LC_ALL=C TZ=UTC
mkdir -p "$tmp/home/.cache/milog" "$tmp/logs"
export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_HISTORY_DB="$tmp/metrics.db"
export MILOG_APPS="api web"

line() {
    printf '%s - - [%(%d/%b/%Y:%H:%M:%S)T +0000] "GET %s HTTP/1.1" %s 12 "-" "curl"\n' "$1" "$2" "$3" "$4"
}

now=$(printf '%(%s)T' -1)
recent=$(( now - 7200 ))
old=$(( now - 10 * 86400 ))

{
    line 10.0.0.1 "$recent" / 200
    line 10.0.0.2 "$recent" /.env 404
    line 10.0.0.2 "$recent" /wp-login.php 404
    line 10.0.0.2 "$recent" / 500
    line '<img>' "$recent" /x 403
    line 10.0.0.9 "$old" /old 404
} > "$tmp/logs/api.access.log"
: > "$tmp/logs/web.access.log"

esc=$'\033'
printf '%s\t%s\t%s\t%s\t%s\n' \
    "$recent" "5xx:api" 15158332 "5xx spike" "body" \
    "$recent" "5xx:api" 15158332 "5xx spike" "body" \
    "$recent" "anomaly:api:req" 15158332 "Anomaly" '```current=<script>x</script> a|b [l](u) '"$esc"'[2J```' \
    "$old" "old:rule" 15158332 "old" "body" \
    > "$HOME/.cache/milog/alerts.log"

md=$("$ROOT/milog.sh" report 7d) || fail "report exited non-zero"
for s in '# MiLog report: last 7d' '## Traffic per app' '## Top attacker IPs' '## Alert fires per rule' '## Anomalies'; do
    grep -qF -- "$s" <<< "$md" || fail "markdown missing '$s': $md"
done
grep -qF '| api | 5 | 3 | 1 |' <<< "$md" || fail "api traffic row wrong: $md"
grep -qF '| web | 0 | 0 | 0 |' <<< "$md" || fail "web traffic row wrong: $md"
grep -qF '| 10.0.0.2 | 2 | 3 |' <<< "$md" || fail "top attacker row wrong: $md"
grep -qF '10.0.0.9' <<< "$md" && fail "out-of-window IP counted"
grep -qF '| 5xx:api | 2 |' <<< "$md" || fail "rule fire count wrong: $md"
grep -qF 'old:rule' <<< "$md" && fail "out-of-window alert counted"
grep -qF '| &lt;img&gt; | 1 | 1 |' <<< "$md" || fail "markdown IP not escaped: $md"
grep -qF 'current=&lt;script&gt;x&lt;/script&gt; a&#124;b &#91;l&#93;(u) ?&#91;2J' <<< "$md" || fail "markdown anomaly not escaped: $md"

"$ROOT/milog.sh" report 7d --html -o "$tmp/r.html" || fail "html report exited non-zero"
html=$(cat "$tmp/r.html")
[[ "$html" == "<!DOCTYPE html>"* ]] || fail "html missing doctype"
for s in '<h2>Traffic per app</h2>' '<h2>Top attacker IPs</h2>' '<h2>Alert fires per rule</h2>' '<h2>Anomalies</h2>' '</body></html>'; do
    grep -qF -- "$s" <<< "$html" || fail "html missing '$s'"
done
grep -qF '<td>&lt;img&gt;</td>' <<< "$html" || fail "html IP not escaped"
grep -qF 'current=&lt;script&gt;x&lt;/script&gt;' <<< "$html" || fail "html anomaly not escaped"
grep -qiE '<script|<img|src=|href=' <<< "$html" && fail "html has a script, image or external asset"
grep -q "$esc" "$tmp/r.html" && fail "html kept a raw escape byte"

# Empty window: sections stay, each says so.
md=$("$ROOT/milog.sh" report 1h --html=no 2>&1) && fail "unknown flag accepted"
rm "$HOME/.cache/milog/alerts.log"
md=$("$ROOT/milog.sh" report 1m 2>&1 || true)
grep -q 'invalid window' <<< "$md" || fail "bad window not rejected: $md"
md=$("$ROOT/milog.sh" report 1h)
grep -qF 'No IP got a 4xx response in this window.' <<< "$md" || fail "empty attacker section: $md"
grep -qF "No alerts.log at $HOME/.cache/milog/alerts.log." <<< "$md" || fail "missing alerts.log not stated: $md"
grep -qF 'Anomaly detection is off' <<< "$md" || fail "anomaly empty state: $md"
grep -qF 'History is off (HISTORY_ENABLED=0)' <<< "$md" || fail "history-off audit state: $md"

# -o refuses a symlink and leaves its target alone.
echo keep > "$tmp/target"
ln -s "$tmp/target" "$tmp/link"
"$ROOT/milog.sh" report -o "$tmp/link" 2>/dev/null && fail "-o wrote through a symlink"
[[ "$(cat "$tmp/target")" == keep ]] || fail "symlink target was modified"

# Capped sections say how many rows exist.
for i in $(seq 1 55); do
    printf '%s\t%s\t15158332\tAnomaly\tbody\n' "$recent" "anomaly:api:req"
done > "$HOME/.cache/milog/alerts.log"
for i in $(seq 1 12); do line "10.1.0.$i" "$recent" /x 404; done >> "$tmp/logs/api.access.log"
md=$("$ROOT/milog.sh" report 7d)
grep -qF 'Showing the latest 50 of 55.' <<< "$md" || fail "anomaly cap not stated: $md"
grep -qF 'Showing 10 of 14.' <<< "$md" || fail "attacker cap not stated: $md"

export MILOG_HISTORY_ENABLED=1
db="$MILOG_HISTORY_DB"
md=$("$ROOT/milog.sh" report 7d)
grep -qF "No history DB at $db." <<< "$md" || fail "missing history DB not stated: $md"

mkdir -p "$tmp/bin"
for d in /usr/local/bin /usr/bin /bin; do
    for f in "$d"/*; do
        name=${f##*/}
        [[ "$name" == sqlite3 || -e "$tmp/bin/$name" ]] && continue
        ln -s "$f" "$tmp/bin/$name"
    done
done
md=$(PATH="$tmp/bin" "$ROOT/milog.sh" report 7d)
grep -qF 'sqlite3 is not installed' <<< "$md" || fail "missing sqlite3 not stated: $md"

sqlite3 "$db" "CREATE TABLE metrics_minute (ts INTEGER);"
md=$("$ROOT/milog.sh" report 7d)
grep -qF "No audit_event table in $db yet." <<< "$md" || fail "missing audit_event table not stated: $md"

sqlite3 "$db" "CREATE TABLE audit_event (ts INTEGER NOT NULL, scanner TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL);"
md=$("$ROOT/milog.sh" report 7d)
grep -qF 'No audit drift recorded in this window.' <<< "$md" || fail "empty audit window not stated: $md"

sqlite3 "$db" "INSERT INTO audit_event VALUES
    ($old, 'fim', 'modified', '/etc/old-drift'),
    ($(( recent - 60 )), 'ports', 'appeared', '0.0.0.0:4444/tcp'),
    ($recent, 'fim', 'modified', '/srv/<script>x</script> a|b it''s' || char(9) || 't');"
md=$("$ROOT/milog.sh" report 7d)
grep -qF '## Audit drift' <<< "$md" || fail "markdown missing audit section: $md"
grep -qF '| fim | modified | /srv/&lt;script&gt;x&lt;/script&gt; a&#124;b it'"'"'s t |' <<< "$md" \
    || fail "markdown audit subject not escaped: $md"
grep -qF '/etc/old-drift' <<< "$md" && fail "out-of-window audit row listed"
first=$(grep -nF '/srv/&lt;script' <<< "$md" | cut -d: -f1)
second=$(grep -nF '0.0.0.0:4444/tcp' <<< "$md" | cut -d: -f1)
(( first < second )) || fail "audit rows not newest first: $md"
html=$("$ROOT/milog.sh" report 7d --html)
grep -qF '<td>/srv/&lt;script&gt;x&lt;/script&gt; a|b it&#39;s t</td>' <<< "$html" || fail "html audit subject not escaped: $html"
grep -qi '<script' <<< "$html" && fail "html audit subject kept a script tag"

for i in $(seq 1 55); do printf "INSERT INTO audit_event VALUES ($recent, 'ports', 'appeared', 'p$i');\n"; done | sqlite3 "$db"
md=$("$ROOT/milog.sh" report 7d)
grep -qF 'Showing the latest 50 of 57.' <<< "$md" || fail "audit cap not stated: $md"
unset MILOG_HISTORY_ENABLED

# Root can read mode-000 files, so this only bites as a normal user.
if (( $(id -u) != 0 )); then
    chmod 000 "$tmp/logs/web.access.log"
    md=$("$ROOT/milog.sh" report 7d)
    grep -qF '| web | log not readable | - | - |' <<< "$md" || fail "unreadable log not reported: $md"
fi

echo "smoke_report: ok"
