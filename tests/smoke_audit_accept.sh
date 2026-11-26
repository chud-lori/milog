#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    printf 'smoke_audit_accept: %s\n' "$1" >&2
    exit 1
}

mkdir -p "$tmp/home/.config/milog" "$tmp/logs" "$tmp/watch" "$tmp/etc" "$tmp/u/.ssh"
: > "$tmp/logs/app.access.log"
: > "$tmp/watch/known"
printf 'a\nb\n' > "$tmp/etc/one.conf"
printf 'x\n' > "$tmp/etc/two.conf"
printf 'root:$6$secret-hash-value:19000::::::\n' > "$tmp/etc/shadow.bak"
chmod 600 "$tmp/etc/shadow.bak"
printf 'p\n' > "$tmp/etc/sp ace.conf"
: > "$tmp/u/.ssh/authorized_keys"
{
    printf 'AUDIT_FIM_PATHS=(%q %q %q %q %q)\n' "$tmp/etc/one.conf" "$tmp/etc/two.conf" "$tmp/etc/shadow.bak" "$tmp/u/.ssh/authorized_keys" "$tmp/etc/sp ace.conf"
    printf 'AUDIT_PERSISTENCE_PATHS=(%q)\n' "$tmp/watch/*"
} > "$tmp/home/.config/milog/config.sh"

export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"
export MILOG_HISTORY_ENABLED=0
state="$tmp/home/.cache/milog/audit"
milog() { "$ROOT/milog.sh" "$@"; }

# Runs the daemon ticks with alert_fire captured into $tmp/alerts, one "title<TAB>body" record per NUL.
ticks() {
    : > "$tmp/alerts"
    MILOG_AUDIT_ENABLED=1 MILOG_AUDIT_FIM_INTERVAL=0 MILOG_AUDIT_PERSISTENCE_INTERVAL=0 MILOG_AUDIT_PORTS_INTERVAL=0 \
    bash -c '
        . "$1" help >/dev/null
        alerts_file="$2" listeners="$3"
        alert_should_fire() { return 0; }
        alert_fire() { printf "%s\t%s\0" "$1" "$2" >> "$alerts_file"; }
        alert_condition_open() { alert_fire "$2" "$3"; }
        alert_condition_sweep() { :; }
        _audit_ports_capture() { cat "$listeners"; }
        _audit_listener_owner() { printf "process demo pid 1"; }
        _dlog() { :; }
        _audit_fim_tick; _audit_persistence_tick; _audit_ports_tick
        wait
    ' _ "$ROOT/milog.sh" "$tmp/alerts" "$tmp/ports.now" 2>/dev/null
    rm -f "$state"/*.lastcheck
}
body_for() { tr '\0' '\n' < "$tmp/alerts" | awk -v p="$1" 'index($0, p) { found = 1 } found { print } /```$/ && found { exit }'; }

printf 'tcp\t0.0.0.0\t22\n' > "$tmp/ports.now"
ticks
[[ -f "$state/fim.baseline" && -f "$state/persistence.baseline" && -f "$state/ports.baseline" ]] \
    || fail 'first tick did not write the baselines'
grep -rq 'hash-value' "$state/fim.snap" && fail 'shadow content was snapshotted'

# Drift on every check.
printf 'a\nc\nd\n' > "$tmp/etc/one.conf"
printf 'y\n' > "$tmp/etc/two.conf"
printf 'root:$6$other-hash-value:19001::::::\n' > "$tmp/etc/shadow.bak"
printf 'q\n' > "$tmp/etc/sp ace.conf"
: > "$tmp/watch/new1.service"
: > "$tmp/watch/new2.service"
printf 'tcp\t0.0.0.0\t22\ntcp\t0.0.0.0\t443\nudp\t0.0.0.0\t53\n' > "$tmp/ports.now"

ticks
one=$(body_for "MODIFIED $tmp/etc/one.conf")
[[ "$one" == *"+2 -1 lines"* ]] || fail "text file summary missing line counts: $one"
[[ "$one" == *$'\nc\n'* || "$one" == *"d\`\`\`"* ]] && fail 'text file contents leaked into the alert'
sh=$(body_for "MODIFIED $tmp/etc/shadow.bak")
[[ "$sh" == *"contents withheld"* ]] || fail "shadow alert not withheld: $sh"
tr '\0' '\n' < "$tmp/alerts" | grep -q 'hash-value' && fail 'shadow contents reached an alert'
p=$(body_for "re-entry surface: $tmp/watch/new1.service")
[[ "$p" == *"mtime "*" ago), ctime "*" ago), owner "* ]] || fail "persistence alert has no age: $p"
l=$(body_for "new listener: tcp 0.0.0.0:443")
[[ "$l" == *"process demo pid 1"* ]] || fail "listener alert has no process: $l"

# The bare form lists drift with the command that accepts each item.
list=$(milog audit accept)
[[ "$list" == *"milog audit accept fim $tmp/etc/one.conf"* ]] || fail "listing misses fim drift: $list"
[[ "$list" == *"milog audit accept persistence $tmp/watch/new1.service"* ]] || fail 'listing misses persistence drift'
[[ "$list" == *"milog audit accept fim $(printf '%q' "$tmp/etc/sp ace.conf")"* ]] || fail "listing truncates a path with a space: $list"

# Accepting one item leaves the rest drifting.
milog audit accept fim "$tmp/etc/one.conf" >/dev/null
out=$(milog audit fim check || true)
[[ "$out" == *"$tmp/etc/one.conf"* ]] && fail 'accepted fim path still drifts'
[[ "$out" == *"$tmp/etc/two.conf"* && "$out" == *"$tmp/etc/shadow.bak"* ]] || fail 'accepting one fim path cleared others'
[[ $(grep -c . "$state/fim.baseline") == 5 ]] || fail 'fim baseline lost or gained rows'

milog audit accept persistence "$tmp/watch/new1.service" >/dev/null
out=$(milog audit persistence check || true)
[[ "$out" == *new1.service* ]] && fail 'accepted persistence path still drifts'
[[ "$out" == *new2.service* ]] || fail 'accepting one persistence path cleared the other'
rm "$tmp/watch/known"
milog audit accept persistence "$tmp/watch/known" >/dev/null
grep -qF "$tmp/watch/known" "$state/persistence.baseline" && fail 'accepting a removal kept the row'

ports() {
    bash -c '. "$1" help >/dev/null; listeners="$2"; _audit_ports_capture() { cat "$listeners"; }; shift 2; mode_audit "$@"' \
        _ "$ROOT/milog.sh" "$tmp/ports.now" "$@"
}
ports accept ports tcp:443 >/dev/null
out=$(ports ports check || true)
[[ "$out" == *":443"* ]] && fail 'accepted listener still drifts'
[[ "$out" == *":53"* ]] || fail 'accepting tcp:443 cleared udp:53'
ports accept ports tcp:nope >/dev/null 2>&1 && fail 'malformed ports item accepted'
milog audit accept fim "$tmp/not-tracked" >/dev/null 2>&1 && fail 'untracked fim path accepted'
milog audit accept fim "$tmp/etc/one.conf" | grep -q 'no drift' || fail 'second accept did not report no drift'

# Accept is recorded in the audit history.
if command -v sqlite3 >/dev/null 2>&1; then
    export MILOG_HISTORY_ENABLED=1 MILOG_HISTORY_DB="$tmp/metrics.db"
    bash -c '. "$1" help >/dev/null; _dlog() { :; }; history_init' _ "$ROOT/milog.sh"
    milog audit accept fim "$tmp/etc/two.conf" >/dev/null
    row=$(sqlite3 "$tmp/metrics.db" "SELECT scanner, kind, subject FROM audit_event;")
    [[ "$row" == "fim|accepted|$tmp/etc/two.conf by "?* ]] || fail "accept not recorded in history: $row"
    md=$(milog report 1d)
    [[ "$md" == *"Accepted into the baseline in this window, not shown: 1"* ]] || fail "report does not count the accept: $md"
    [[ "$md" == *"| accepted |"* ]] && fail 'report lists an accept as drift'
    export MILOG_HISTORY_ENABLED=0
fi

# authorized_keys: added and removed keys appear by fingerprint, and the body stays bounded.
if command -v ssh-keygen >/dev/null 2>&1; then
    for k in old keep new; do
        ssh-keygen -q -t ed25519 -N '' -C "$k@host" -f "$tmp/$k" </dev/null
    done
    cat "$tmp/old.pub" "$tmp/keep.pub" > "$tmp/u/.ssh/authorized_keys"
    milog audit accept fim "$tmp/u/.ssh/authorized_keys" >/dev/null
    { cat "$tmp/keep.pub"; printf 'no-pty %s\n' "$(cat "$tmp/new.pub")"; } > "$tmp/u/.ssh/authorized_keys"
    ticks
    ak=$(body_for "MODIFIED $tmp/u/.ssh/authorized_keys")
    new_fp=$(ssh-keygen -lf "$tmp/new.pub" | awk '{ print $2 }')
    old_fp=$(ssh-keygen -lf "$tmp/old.pub" | awk '{ print $2 }')
    [[ "$ak" == *"+ key 256 $new_fp new@host (ED25519)"* ]] || fail "added key not named by fingerprint: $ak"
    [[ "$ak" == *"- key 256 $old_fp old@host (ED25519)"* ]] || fail "removed key not named by fingerprint: $ak"
    [[ "$ak" == *keep@host* ]] && fail 'unchanged key reported'
    [[ "$ak" == *AAAA* ]] && fail 'raw key material reached the alert'

    long=$(printf 'c%.0s' $(seq 1 400))
    for i in $(seq 1 60); do
        ssh-keygen -q -t ed25519 -N '' -C "k$i-$(printf '\xd0\xba\xd0\xbb\xd1\x8e\xd1\x87')-$long" -f "$tmp/bulk$i" </dev/null
        cat "$tmp/bulk$i.pub" >> "$tmp/u/.ssh/authorized_keys"
    done
    ticks
    ak=$(body_for "MODIFIED $tmp/u/.ssh/authorized_keys")
    (( ${#ak} < 4096 )) || fail "authorized_keys alert body is ${#ak} chars"
    [[ "$ak" == *"more keys"* ]] || fail 'capped key list does not say how many were left out'
    [[ $(printf '%s\n' "$ak" | grep '^[+-] ' | LC_ALL=C tr -d '\n -~' | wc -c) -eq 0 ]] || fail 'non-ASCII bytes reached the key lines'
else
    printf 'smoke_audit_accept: ssh-keygen not installed, skipping key fingerprint checks\n'
fi

# The listener owner must match the exact bind address, never a neighbour on the same port.
owner() {
    bash -c '. "$1" help >/dev/null; ss() { printf "%s\n" "${SSOUT[@]}"; }; SSOUT=("${@:3}"); _audit_listener_owner tcp "$2" 22' \
        _ "$ROOT/milog.sh" "$@"
}
v4='tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))'
v6='tcp LISTEN 0 128 [::]:22 [::]:*'
[[ $(owner 0.0.0.0 "$v4" "$v6") == "process sshd pid 1"* ]] || fail "exact bind not attributed: $(owner 0.0.0.0 "$v4" "$v6")"
[[ $(owner :: "$v4" "$v6") == "owner unknown"* ]] || fail "[::]:22 attributed to the 0.0.0.0:22 owner"
[[ $(owner 0.0.0.0 "$v4" "${v4/pid=1/pid=2}") == "owner unknown"* ]] || fail 'two matching sockets not reported as unknown'

# A symlinked fim.snap must not be written through or pruned.
mkdir -p "$tmp/decoy"
: > "$tmp/decoy/keepme"
rm -rf "$state/fim.snap"
ln -s "$tmp/decoy" "$state/fim.snap"
milog audit fim baseline >/dev/null
[[ -e "$tmp/decoy/keepme" ]] || fail 'baseline pruned through a symlinked fim.snap'
[[ $(ls "$tmp/decoy") == keepme ]] || fail 'baseline wrote snapshots through a symlinked fim.snap'
rm "$state/fim.snap"

left=$(find "$state" -name '*.tmp.*' -o -name 'fim.old.*' -o -name 'fim.cur.*' -o -name '*.current.*')
[[ -z "$left" ]] || fail "temp files left behind: $left"

printf 'smoke_audit_accept: ok\n'
