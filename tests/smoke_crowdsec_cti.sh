#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

failures=0
fail() { printf 'FAIL: %s\n' "$*" >&2; failures=$(( failures + 1 )); }

mkdir -p "$tmp/home" "$tmp/logs" "$tmp/bin" "$tmp/stub"

# Pretty-printed like the API docs; the parser must cope with newlines.
cat > "$tmp/stub/known.json" <<'JSON'
{
  "ip": "203.0.113.9",
  "reputation": "malicious",
  "ip_range_24_reputation": "suspicious",
  "behaviors": [
    { "name": "http:scan", "label": "HTTP Scan", "description": "IP has been reported for performing actions related to HTTP vulnerability scanning and discovery." },
    { "name": "ssh:bruteforce", "label": "SSH Bruteforce", "description": "IP has been reported for performing brute force on ssh services." }
  ],
  "classifications": { "false_positives": [], "classifications": [] }
}
JSON
printf '%s' '{"reputation":"suspicious","behaviors":[{"name":"x","label":"Evil\u001b[31m \"quoted\" `tick`","description":"d"}]}' \
    > "$tmp/stub/hostile.json"

# Fake curl: serves fixtures by IP and records argv plus the config read from stdin.
cat > "$tmp/bin/curl" <<'STUB'
#!/usr/bin/env bash
d="$STUB_DIR"
printf '%s\n' "$*" >> "$d/argv.log"
out="" url=""
while (( $# )); do
    case "$1" in
        -o) out="$2"; shift ;;
        -K) [[ "$2" == - ]] && cat > "$d/config"; shift ;;
        -m|-w) shift ;;
        https://*) url="$1" ;;
    esac
    shift
done
case "${url##*/}" in
    203.0.113.9)  cp "$d/known.json" "$out";   printf 200 ;;
    192.0.2.66)   cp "$d/hostile.json" "$out"; printf 200 ;;
    198.51.100.7) printf '{"message":"not found"}' > "$out"; printf 404 ;;
    *)            printf '{"message":"quota"}' > "$out"; printf 429 ;;
esac
STUB
chmod +x "$tmp/bin/curl"

ts='[04/Oct/2026:10:00:00 +0000]'
{
    for i in 1 2 3 4 5 6; do
        printf '203.0.113.9 - - %s "GET /.env%s HTTP/1.1" 404 10 "-" "zgrab/0.x"\n' "$ts" "$i"
        printf '198.51.100.7 - - %s "GET /wp-login.php?%s HTTP/1.1" 404 10 "-" "-"\n' "$ts" "$i"
    done
} > "$tmp/logs/app.access.log"

export HOME="$tmp/home" STUB_DIR="$tmp/stub"
export MILOG_LOG_DIR="$tmp/logs" MILOG_APPS="app"
export PATH="$tmp/bin:$PATH"
state="$tmp/home/.cache/milog"
calls() { [[ -f "$tmp/stub/argv.log" ]] && wc -l < "$tmp/stub/argv.log" | tr -d ' ' || echo 0; }

# Off by default: no request at all.
MILOG_CROWDSEC_CTI_KEY="" "$ROOT/milog.sh" attacker 203.0.113.9 > "$tmp/off.out" 2>&1 || fail "attacker exited non-zero with CTI off"
grep -q 'crowdsec:' "$tmp/off.out" && fail "crowdsec line printed with no key"
[[ "$(calls)" == 0 ]] || fail "curl called with CROWDSEC_CTI_KEY empty"

export MILOG_CROWDSEC_CTI_KEY="test-key-123"

"$ROOT/milog.sh" attacker 203.0.113.9 > "$tmp/a1.out" 2>&1 || fail "attacker exited non-zero"
grep -q 'crowdsec: *malicious (HTTP Scan, SSH Bruteforce)$' "$tmp/a1.out" \
    || fail "attacker missing reputation line: $(grep crowdsec "$tmp/a1.out" || echo none)"
[[ "$(calls)" == 1 ]] || fail "expected 1 curl call, got $(calls)"
grep -q 'cti.api.crowdsec.net/v2/smoke/203.0.113.9' "$tmp/stub/argv.log" || fail "wrong smoke URL"
grep -q 'x-api-key: test-key-123' "$tmp/stub/config" || fail "key not sent as x-api-key header"
grep -q 'test-key-123' "$tmp/stub/argv.log" && fail "key leaked into curl argv"

"$ROOT/milog.sh" attacker 203.0.113.9 > "$tmp/a2.out" 2>&1 || true
grep -q 'crowdsec: *malicious' "$tmp/a2.out" || fail "cached reputation not shown"
[[ "$(calls)" == 1 ]] || fail "cache miss on second lookup ($(calls) calls)"

# suspects reads the cache only: 198.51.100.7 is a suspect but uncached.
"$ROOT/milog.sh" suspects > "$tmp/s.out" 2>&1 || fail "suspects exited non-zero"
grep '203.0.113.9' "$tmp/s.out" | grep -q 'CS:malicious' || fail "suspects missing CS:malicious tag"
grep '198.51.100.7' "$tmp/s.out" | grep -q 'CS:' && fail "uncached IP got a CS tag"
[[ "$(calls)" == 1 ]] || fail "suspects made network calls"

. "$ROOT/milog.sh" help >/dev/null

[[ "$(cti_lookup 198.51.100.7)" == unknown ]] || fail "404 should map to unknown"
[[ -f "$state/cti/198.51.100.7" ]] || fail "404 result not cached"

hostile=$(cti_lookup 192.0.2.66)
[[ "$hostile" == suspicious* ]] || fail "hostile fixture lost reputation: $hostile"
unsafe='[^A-Za-z0-9 :._,()/-]'
[[ "$hostile" =~ $unsafe ]] && fail "unsafe characters survived: $hostile"

n=$(calls)
for bad in '1.2.3.4/../x' 'a;b' '' '-K' '1.2.3.4?x=1'; do
    [[ -z "$(cti_lookup "$bad")" ]] || fail "invalid IP '$bad' returned data"
done
[[ "$(calls)" == "$n" ]] || fail "invalid IP reached curl"

[[ -z "$(cti_lookup 192.0.2.1)" ]] || fail "429 should print nothing"
grep -q 'HTTP 429 for 192.0.2.1' "$state/cti.err" || fail "429 not recorded in cti.err"
[[ -f "$state/cti/192.0.2.1" ]] && fail "failed lookup was cached"

ALERTS_ENABLED=0
[[ -z "$(cti_alert_note 203.0.113.9)" ]] || fail "alert note with alerts off"
ALERTS_ENABLED=1
[[ "$(cti_alert_note 203.0.113.9)" == $'\nCrowdSec: malicious (HTTP Scan, SSH Bruteforce)' ]] \
    || fail "alert note wrong: $(cti_alert_note 203.0.113.9)"

CROWDSEC_CTI_KEY='bad"key'
rm -f "$state/cti/203.0.113.9"
n=$(calls)
[[ -z "$(cti_lookup 203.0.113.9)" ]] || fail "key with a quote was used"
[[ "$(calls)" == "$n" ]] || fail "key with a quote reached curl"

printf 'CROWDSEC_CTI_KEY="test-key-123"\n' > "$tmp/config.sh"
MILOG_CONFIG="$tmp/config.sh" "$ROOT/milog.sh" config validate > "$tmp/validate.out" 2>&1 || true
grep -q 'unknown key: CROWDSEC_CTI_KEY' "$tmp/validate.out" && fail "config validate flags CROWDSEC_CTI_KEY"

"$ROOT/milog.sh" doctor > "$tmp/doctor.out" 2>&1 || true
grep -q 'last lookup failed' "$tmp/doctor.out" || fail "doctor does not report the failed lookup"

if (( failures )); then
    exit 1
fi
printf 'smoke_crowdsec_cti: ok\n'
