#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    printf 'smoke_audit_history: %s\n' "$1" >&2
    exit 1
}

if ! command -v sqlite3 >/dev/null 2>&1; then
    printf 'smoke_audit_history: sqlite3 not installed, skipping\n'
    exit 0
fi

mkdir -p "$tmp/home/.config/milog" "$tmp/logs" "$tmp/watch" "$tmp/acc"
: > "$tmp/logs/app.access.log"
printf 'v1\n' > "$tmp/fim-target"
printf 'root:x:0:0\n' > "$tmp/acc/passwd"
{
    printf 'AUDIT_FIM_PATHS=(%q)\n' "$tmp/fim-target"
    printf 'AUDIT_PERSISTENCE_PATHS=(%q)\n' "$tmp/watch/*"
    printf 'AUDIT_ACCOUNTS_PATHS=(%q)\n' "$tmp/acc/passwd"
} > "$tmp/home/.config/milog/config.sh"

export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"
export MILOG_AUDIT_ENABLED=1
export MILOG_AUDIT_FIM_INTERVAL=0
export MILOG_AUDIT_PERSISTENCE_INTERVAL=0
export MILOG_AUDIT_ACCOUNTS_INTERVAL=0
export MILOG_HISTORY_DB="$tmp/metrics.db"
db="$tmp/metrics.db"

ticks() {
    bash -c '
        . "$1" help >/dev/null
        alert_should_fire() { return 1; }
        _dlog() { :; }
        history_init || true
        _audit_fim_tick
        _audit_persistence_tick
        _audit_accounts_tick
    ' _ "$ROOT/milog.sh"
}
count() { sqlite3 "$db" "SELECT COUNT(*) FROM audit_event WHERE $1;"; }

# History disabled: ticks baseline and drift without creating a DB.
MILOG_HISTORY_ENABLED=0 ticks
printf 'v2\n' > "$tmp/fim-target"
MILOG_HISTORY_ENABLED=0 ticks
[[ -e "$db" ]] && fail 'a DB was created with HISTORY_ENABLED=0'

# sqlite3 missing: history_init disables itself and the ticks still run.
mkdir -p "$tmp/bin"
for d in /usr/local/bin /usr/bin /bin; do
    for f in "$d"/*; do
        name=${f##*/}
        [[ "$name" == sqlite3 || -e "$tmp/bin/$name" ]] && continue
        ln -s "$f" "$tmp/bin/$name"
    done
done
PATH="$tmp/bin" MILOG_HISTORY_ENABLED=1 ticks || fail 'ticks failed without sqlite3'
[[ -e "$db" ]] && fail 'a DB was created without sqlite3'

export MILOG_HISTORY_ENABLED=1
: > "$tmp/watch/cronjob"
printf 'evil:x:0:0\n' >> "$tmp/acc/passwd"
ticks
ticks
[[ "$(count "scanner='fim' AND kind='modified' AND subject='$tmp/fim-target'")" == 1 ]] \
    || fail 'fim drift not stored exactly once across two ticks'
[[ "$(count "scanner='persistence' AND kind='appeared' AND subject='$tmp/watch/cronjob'")" == 1 ]] \
    || fail 'persistence drift not stored exactly once'
[[ "$(count "scanner='accounts' AND kind='added' AND subject='$tmp/acc/passwd'")" == 1 ]] \
    || fail 'accounts drift not stored exactly once'
[[ "$(count "subject LIKE '%evil%'")" == 0 ]] || fail 'account file contents reached the DB'

# Drift after a re-baseline is a new row; backdating stands in for elapsed time.
sqlite3 "$db" "UPDATE audit_event SET ts = ts - 10 WHERE scanner = 'fim';"
"$ROOT/milog.sh" audit fim baseline >/dev/null
printf 'v3\n' > "$tmp/fim-target"
ticks
[[ "$(count "scanner='fim'")" == 2 ]] || fail 'drift after a re-baseline was not stored'
[[ "$(count "scanner='persistence'")" == 1 ]] || fail 'persistence drift stored again without a re-baseline'

out=$("$ROOT/milog.sh" audit history)
[[ "$out" == *persistence*appeared*"$tmp/watch/cronjob"* ]] || fail "audit history missing the persistence row: $out"

sqlite3 "$db" "INSERT INTO audit_event VALUES (1, 'ports', 'appeared', 'old');"
bash -c '. "$1" help >/dev/null; _dlog() { :; }; HISTORY_RETAIN_DAYS=1 history_prune' _ "$ROOT/milog.sh"
[[ "$(count "subject='old'")" == 0 ]] || fail 'prune kept a row past retention'
[[ "$(count "scanner='fim'")" == 2 ]] || fail 'prune dropped recent rows'

printf 'smoke_audit_history: ok\n'
