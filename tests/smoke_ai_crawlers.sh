#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MILOG="$ROOT/milog.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
    printf 'smoke_ai_crawlers: %s\n' "$1" >&2
    exit 1
}

mkdir -p "$tmp/home" "$tmp/logs"
export HOME="$tmp/home"
export MILOG_CONFIG="$tmp/home/.config/milog/config.sh"
export MILOG_LOG_DIR="$tmp/logs"
export MILOG_APPS="app"
export LC_ALL=C TZ=UTC

minute=$(date -u '+%d/%b/%Y:%H:%M')
line() {
    printf '1.2.3.4 - - [%s:00 +0000] "GET %s HTTP/1.1" 200 12 "-" "%s"\n' "$minute" "$1" "$2"
}
{
    line / 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)'
    line / 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)'
    line / 'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)'
    # Token in the path only: must not count, the match is on the UA field.
    line /gptbot 'curl/8.5.0'
    line / 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    line / 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0'
} > "$tmp/logs/app.access.log"

"$MILOG" health > "$tmp/health.out" 2>&1
grep -Eq '^app +6 .* 50%$' "$tmp/health.out" \
    || fail "health lacks the 50% AI share: $(cat "$tmp/health.out")"

"$MILOG" top > "$tmp/top.out" 2>&1
grep -qF 'AI crawlers: 50% of requests (3 of 6)' "$tmp/top.out" \
    || fail "top lacks the AI share: $(cat "$tmp/top.out")"

# Rule fires at the threshold and stays quiet below it.
rule() {
    bash -c '
        . "$1" help >/dev/null
        THRESH_AICRAWL_WARN=$2
        alert_should_fire() { return 0; }
        alert_fire() { printf "%s|%s\n" "$4" "$2"; }
        read -r tot _ _ _ _ ai <<< "$(nginx_minute_counts app "$3")"
        nginx_check_ai_alert app "$ai" "$tot"
        wait
    ' _ "$MILOG" "$1" "$minute"
}
out=$(rule 3)
[[ "$out" == "aicrawl:app|3 AI-crawler requests in the last minute, 50% of 6 (threshold 3)" ]] \
    || fail "rule at threshold printed: $out"
out=$(rule 4)
[[ -z "$out" ]] || fail "rule below threshold fired: $out"

printf 'smoke_ai_crawlers: ok\n'
