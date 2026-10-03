#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    printf 'smoke_audit_integrity: %s\n' "$1" >&2
    exit 1
}

mkdir -p "$tmp/home/.config/milog/yara" "$tmp/logs" "$tmp/watch" "$tmp/acc/a" "$tmp/www"
: > "$tmp/logs/app.access.log"
: > "$tmp/watch/known"
printf 'daemon:x:1:1\n' > "$tmp/acc/a_b"
printf 'root:x:0:0\n' > "$tmp/acc/a/b"
{
    printf 'AUDIT_PERSISTENCE_PATHS=(%q %q)\n' "$tmp/watch/*" "$tmp/rc.local"
    printf 'AUDIT_FIM_PATHS=(%q)\n' "$tmp/watch/known"
    printf 'AUDIT_ACCOUNTS_PATHS=(%q %q)\n' "$tmp/acc/a_b" "$tmp/acc/a/b"
    printf 'AUDIT_YARA_PATHS=(%q)\n' "$tmp/www"
} > "$tmp/home/.config/milog/config.sh"

export HOME="$tmp/home"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"
state="$tmp/home/.cache/milog/audit"
milog() { "$ROOT/milog.sh" "$@"; }

# Persistence: an absent literal path must not be baselined as present.
milog audit persistence baseline >/dev/null
grep -qF "$tmp/rc.local" "$state/persistence.baseline" \
    && fail 'absent literal persistence path recorded in baseline'
: > "$tmp/rc.local"
out=$(milog audit persistence check || true)
[[ "$out" == *APPEARED*"$tmp/rc.local"* ]] || fail 'creating a literal persistence path did not report APPEARED'

# FIM: with no sha256 tool on PATH, baseline must refuse instead of recording UNREADABLE.
mkdir -p "$tmp/bin"
for d in /usr/local/bin /usr/bin /bin; do
    for f in "$d"/*; do
        name=${f##*/}
        [[ "$name" == sha256sum || "$name" == shasum || -e "$tmp/bin/$name" ]] && continue
        ln -s "$f" "$tmp/bin/$name"
    done
done
if PATH="$tmp/bin" "$ROOT/milog.sh" audit fim baseline >/dev/null 2>"$tmp/fim.err"; then
    fail 'fim baseline succeeded without a sha256 tool'
fi
[[ -e "$state/fim.baseline" ]] && fail 'fim baseline written without a sha256 tool'
grep -q 'sha256sum or shasum' "$tmp/fim.err" || fail 'fim baseline refused silently'
doctor=$(PATH="$tmp/bin" MILOG_AUDIT_ENABLED=1 "$ROOT/milog.sh" doctor 2>&1 || true)
[[ "$doctor" == *"no sha256sum or shasum"* ]] || fail 'doctor did not report the missing sha256 tool'
milog audit fim baseline >/dev/null
milog audit fim check >/dev/null || fail 'fim check drifted right after baseline'

# Accounts: /acc/a_b and /acc/a/b must keep separate baselines.
milog audit accounts baseline >/dev/null
printf 'eve:x:0:0\n' >> "$tmp/acc/a/b"
out=$(milog audit accounts check || true)
[[ "$out" == *"$tmp/acc/a/b"*eve* ]] || fail 'accounts drift in a/b not reported'
[[ "$out" == *root:x* || "$out" == *daemon:x* ]] && fail 'a_b and a/b share one accounts baseline'

# Accounts: a re-baseline running alongside a diff must never expose a gap.
milog audit accounts baseline >/dev/null
bash -c '
    . "$1" help >/dev/null
    for _ in $(seq 1 40); do _audit_accounts_baseline >/dev/null; done &
    for _ in $(seq 1 40); do _audit_accounts_diff; done
    wait
' _ "$ROOT/milog.sh" > "$tmp/acc.diff"
[[ -s "$tmp/acc.diff" ]] && fail "concurrent accounts baseline produced drift: $(head -n 1 "$tmp/acc.diff")"

# YARA: a tab in a filename must not mis-split the record or the dedup.
if command -v yara >/dev/null 2>&1; then
    printf 'rule smoke_marker { strings: $a = "milog-smoke-marker" condition: $a }\n' \
        > "$tmp/home/.config/milog/yara/smoke.yar"
    tabbed="$tmp/www/a"$'\t'"b.php"
    printf 'milog-smoke-marker\n' > "$tabbed"
    printf 'benign\n' > "$tmp/www/a"
    sha=$(shasum -a 256 "$tabbed" 2>/dev/null || sha256sum "$tabbed")
    sha=${sha%% *}
    bash -c '
        . "$1" help >/dev/null
        _audit_yara_scan_all
    ' _ "$ROOT/milog.sh" > "$tmp/yara.1"
    [[ "$(cat "$tmp/yara.1")" == "smoke_marker"$'\t'"$tabbed"$'\t'"$sha" ]] \
        || fail "yara hit misrecorded: $(od -c "$tmp/yara.1" | head -n 3)"
    awk -F'\t' 'NF != 4 { bad = 1 } END { exit bad }' "$state/yara.matches" \
        || fail 'yara.matches row does not have four fields'
    bash -c '
        . "$1" help >/dev/null
        _audit_yara_scan_all
    ' _ "$ROOT/milog.sh" > "$tmp/yara.2"
    [[ -s "$tmp/yara.2" ]] && fail 'yara re-reported an already recorded hit'
else
    printf 'smoke_audit_integrity: yara not installed, skipping yara case\n'
fi

# Hidden processes: threads answer stat but are not listed, so they must not alert.
if [[ -d /proc/1 && -r /proc/sys/kernel/pid_max ]]; then
    out=$(bash -c '
        . "$1" help >/dev/null
        _audit_rootkit_check_hidden_stat
    ' _ "$ROOT/milog.sh")
    [[ -z "$out" ]] || fail "hidden_process false positive on a clean host: $out"
fi

printf 'smoke_audit_integrity: ok\n'
