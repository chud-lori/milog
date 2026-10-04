#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { printf 'smoke_rules: %s\n' "$1" >&2; exit 1; }

mkdir -p "$tmp/home" "$tmp/logs" "$tmp/release"
export HOME="$tmp/home" TMPDIR="$tmp" MILOG_LOG_DIR="$tmp/logs" MILOG_CONFIG="$tmp/none"
# shellcheck disable=SC1091
. "$ROOT/milog.sh" help >/dev/null

# The inline patterns and classifier as they were on main before the rules file existed.
old_exploit='\.\./|%2e%2e|/etc/passwd|/etc/shadow|/proc/self/environ|/containers/json|/actuator/|/server-status|/console(/|\?)|/druid/|/SDK/web|/cgi-bin/|/boaform/|/HNAP1|/wp-admin|/wp-login|/wp-content/plugins|/xmlrpc\.php|/phpmyadmin|/pma/|/mysql/admin|/\.env|/\.git/|/\.aws/|/\.ssh/|/\.DS_Store|/config\.(php|json|yml|yaml)|/web\.config|jndi:|\$\{jndi|log4j|union[+% ]+select|select[+% ]+from|sleep\([0-9]|benchmark\(|or[+% ]+1=1|%27[+% ]*or|%27%20or|<script|%3cscript|onerror=|onload=|javascript:|base64_decode|eval\(|system\(|passthru\(|shell_exec|libredtail|nikto|masscan|zgrab|sqlmap|nuclei|gobuster|dirbuster|wfuzz|l9explore|l9tcpid|hello,\s?world'
old_probe='SSH-2\.0|\\x16\\x03|\\x00\\x00|masscan|zmap|zgrab|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster|dirb|ffuf|wfuzz|feroxbuster|nessus|openvas|acunetix|wpscan|joomscan|burp|zaproxy|owasp|metasploit|meterpreter|w3af|webshag|l9explore|l9tcpid|l9retrieve|leakix|libredtail|httpx|naabu|katana|subfinder|expanseinc|censysinspect|shodan|stretchoid|internet-measurement|greenbone|qualys|rapid7|detectify|intruder\.io|netcraftsurvey|netsystemsresearch|paloalto|projectdiscovery|odin\.ai|onyphe|ahrefsbot|semrushbot|dotbot|mj12bot|blexbot|petalbot|serpstat|dataforseobot|mauibot|megaindex|seznambot|'"$AI_CRAWLER_UA_RE"'|diffbot|python-requests|python-urllib|aiohttp|go-http-client|okhttp|libwww-perl|java/1\.|apache-httpclient|restsharp|http_request2|guzzlehttp|node-fetch|axios|got\(|scrapy|mechanize|headlesschrome|phantomjs|puppeteer|playwright|selenium|[Ss]canner|[Bb]ot/|[Cc]rawler|[Ss]pider|probe-|fuzzer|harvester|hello,\s*world'
old_category() {
    local line="$1" cat="other"
    shopt -s nocasematch
    case "$line" in
        *'${jndi'*|*'jndi:'*|*log4j*)                                            cat=log4shell ;;
        *union*select*|*select*from*|*'sleep('*|*'benchmark('*|*' or 1=1'*|*%27*or*) cat=sqli ;;
        *'<script'*|*%3cscript*|*'onerror='*|*'onload='*|*'javascript:'*)        cat=xss ;;
        *base64_decode*|*'eval('*|*'system('*|*'passthru('*|*shell_exec*)         cat=rce ;;
        *'../'*|*%2e%2e*|*/etc/passwd*|*/etc/shadow*|*/proc/self*)               cat=traversal ;;
        */containers/*|*/actuator/*|*/server-status*|*/console*|*/druid/*)       cat=infra ;;
        */SDK/web*|*/cgi-bin/*|*/boaform/*|*/HNAP1*)                             cat=device ;;
        */wp-admin*|*/wp-login*|*/wp-content/plugins*|*/xmlrpc.php*)             cat=wordpress ;;
        */phpmyadmin*|*/pma/*|*/mysql/admin*)                                    cat=phpmyadmin ;;
        */.env*|*/.git/*|*/.aws/*|*/.ssh/*|*/.DS_Store*|*/config.php*|*/config.json*|*/config.yml*|*/config.yaml*|*/web.config*) cat=dotfile ;;
        *libredtail*|*nikto*|*masscan*|*zgrab*|*sqlmap*|*nuclei*|*gobuster*|*dirbuster*|*wfuzz*|*l9explore*|*l9tcpid*|*'hello, world'*|*'hello,world'*) cat=scanner ;;
    esac
    shopt -u nocasematch
    printf '%s' "$cat"
}

log="$tmp/logs/app1.access.log"
while IFS='|' read -r req ua; do
    printf '203.0.113.7 - - [03/Oct/2026:10:00:00 +0000] "%s" 404 12 "-" "%s"\n' "$req" "$ua"
done > "$log" <<'EOF'
GET /index.html HTTP/1.1|Mozilla/5.0
GET /static/app.js HTTP/1.1|curl/8.5.0
GET /../../etc/passwd HTTP/1.1|Mozilla/5.0
GET /%2e%2e/%2E%2E/etc/shadow HTTP/1.1|Mozilla/5.0
GET /proc/self/environ HTTP/1.1|Mozilla/5.0
GET /?q=${jndi:ldap://198.51.100.2/a} HTTP/1.1|Mozilla/5.0
GET /?q=LOG4J HTTP/1.1|Mozilla/5.0
GET /item?id=1%27%20OR%201=1 HTTP/1.1|Mozilla/5.0
GET /search?q=UNION+SELECT+1,2 HTTP/1.1|Mozilla/5.0
GET /api/select?from=x HTTP/1.1|Mozilla/5.0
GET /?q=a or 1=1 HTTP/1.1|Mozilla/5.0
GET /?q=sleep(5) HTTP/1.1|Mozilla/5.0
GET /?q=benchmark(1000,md5(1)) HTTP/1.1|Mozilla/5.0
GET /?s=<script>alert(1)</script> HTTP/1.1|Mozilla/5.0
GET /?x=JaVaScRiPt:alert(1) HTTP/1.1|Mozilla/5.0
GET /?x=%3Cscript%3E HTTP/1.1|Mozilla/5.0
GET /?a=Base64_Decode(x) HTTP/1.1|Mozilla/5.0
GET /?cmd=system(id) HTTP/1.1|Mozilla/5.0
GET /containers/json HTTP/1.1|Go-http-client/1.1
GET /actuator/env HTTP/1.1|Mozilla/5.0
GET /console/ HTTP/1.1|Mozilla/5.0
GET /consoles HTTP/1.1|Mozilla/5.0
GET /druid/index.html HTTP/1.1|Mozilla/5.0
GET /server-status HTTP/1.1|Mozilla/5.0
GET /SDK/webLanguage HTTP/1.1|Mozilla/5.0
GET /cgi-bin/luci HTTP/1.1|Mozilla/5.0
GET /boaform/admin/formLogin HTTP/1.1|Mozilla/5.0
GET /HNAP1/ HTTP/1.1|Mozilla/5.0
GET /wp-login.php HTTP/1.1|WPScan v3.8
GET /xmlrpc.php HTTP/1.1|Mozilla/5.0
GET /phpmyadmin/ HTTP/1.1|Mozilla/5.0
GET /pma/ HTTP/1.1|Mozilla/5.0
GET /mysql/admin/ HTTP/1.1|Mozilla/5.0
GET /.env HTTP/1.1|Mozilla/5.0
GET /.git/config HTTP/1.1|Mozilla/5.0
GET /config.json HTTP/1.1|Mozilla/5.0
GET /config.yaml HTTP/1.1|Mozilla/5.0
GET /web.config HTTP/1.1|Mozilla/5.0
GET / HTTP/1.1|Mozilla/5.0 zgrab/0.x
GET / HTTP/1.1|Hello, World
GET / HTTP/1.1|hello,world
GET / HTTP/1.1|Nuclei - Open-source project
GET / HTTP/1.1|l9explore/1.2.2
\x16\x03\x01\x00\xee|-
SSH-2.0-Go|-
GET / HTTP/1.1|python-requests/2.31.0
GET / HTTP/1.1|Mozilla/5.0 (compatible; GPTBot/1.0)
GET / HTTP/1.1|Mozilla/5.0 (compatible; Googlebot/2.1)
GET / HTTP/1.1|Mozilla/5.0 (compatible; CensysInspect/1.1)
GET /robots.txt HTTP/1.1|Mozilla/5.0 HeadlessChrome/120
GET / HTTP/1.1|meta-externalagent/1.1
GET / HTTP/1.1|Mozilla/5.0 (compatible; Bytespider)
GET / HTTP/1.1|Mozilla/5.0 ChatGPT-User/1.0
GET / HTTP/1.1|Mozilla/5.0 (compatible; Diffbot/2.0)
EOF

# No override: the baked-in rules reproduce the old patterns and categories exactly.
_rules_load
[[ "$RULES_EXPLOIT" == "$old_exploit" ]] || fail "built-in exploit pattern differs from the old inline one"
# AI_CRAWLER_UA_RE is appended rather than inlined, so compare the probe alternatives as a set.
[[ "$(tr '|' '\n' <<< "$RULES_PROBE" | sort)" == "$(tr '|' '\n' <<< "$old_probe" | sort)" ]] \
    || fail "built-in probe alternatives differ from the old inline ones"
for kind in exploit probe; do
    want="old_$kind"; got="RULES_$(tr a-z A-Z <<< "$kind")"
    grep -Ei "${!want}" "$log" > "$tmp/old.$kind" || true
    grep -Ei "${!got}" "$log" > "$tmp/new.$kind" || true
    [[ -s "$tmp/old.$kind" ]] || fail "synthetic log has no $kind hits"
    diff "$tmp/old.$kind" "$tmp/new.$kind" >&2 || fail "$kind matches changed"
done
while IFS= read -r line; do
    [[ "$(_exploit_category "$line")" == "$(old_category "$line")" ]] \
        || fail "category changed for: $line"
done < "$log"
[[ "$(_rules_check "$ROOT/rules/milog-rules.tsv")" == "$(_rules_default | _rules_version)" ]] \
    || fail "rules/milog-rules.tsv does not validate"

# A valid override replaces the built-in rules; an invalid one is ignored with a warning.
mkdir -p "$HOME/.config/milog"
printf '# version: 2\nexploit\tx\t/only-this\nprobe\tx\tonly-bot\ncategory\tmine\t/only\n' > "$RULES_FILE"
_rules_load
[[ "$RULES_EXPLOIT" == "/only-this" && "$RULES_PROBE" == "only-bot|$AI_CRAWLER_UA_RE" ]] || fail "valid override not loaded"
[[ "$(_exploit_category 'GET /only-this')" == mine ]] || fail "override category not used"
for bad in '# version: 2\nexploit\tx\t(\nprobe\tx\tb\n' \
           '# version: 2\nexploit\tx\ta|\nprobe\tx\tb\n' \
           '# version: 2\nprobe\tx\tb\n' \
           'exploit\tx\ta\nprobe\tx\tb\n' \
           '# version: 2\nexploit x a\nprobe\tx\tb\n'; do
    printf '%b' "$bad" > "$RULES_FILE"
    _rules_load 2> "$tmp/err"
    [[ "$RULES_EXPLOIT" == "$old_exploit" ]] || fail "invalid override was loaded: $bad"
    grep -q "ignoring" "$tmp/err" || fail "no warning for invalid override: $bad"
done
rm -f "$RULES_FILE"

# update-rules against a fake release served by a curl stub; mode_update_rules has its own local $tmp.
rel="$tmp/release" release_tag=v9.9.9
curl() {
    local out="" url="" w=""
    while (( $# )); do
        case "$1" in
            -o) out="$2"; shift 2 ;;
            -w) w="$2"; shift 2 ;;
            -*) shift ;;
            *)  url="$1"; shift ;;
        esac
    done
    if [[ -n "$w" ]]; then printf 'https://github.com/x/y/releases/tag/%s' "$release_tag"; return 0; fi
    [[ -f "$rel/${url##*/}" ]] || return 22
    cp "$rel/${url##*/}" "$out"
}
publish() {
    printf '%s' "$1" > "$rel/milog-rules.tsv"
    printf '%s  milog-rules.tsv\n' "$(_audit_sha256 "$rel/milog-rules.tsv")" > "$rel/checksums.txt"
}
v2=$(sed '1s/.*/# version: 2/' "$ROOT/rules/milog-rules.tsv")

publish "$v2"
mode_update_rules > /dev/null || fail "update-rules failed on a good release"
[[ "$(cat "$RULES_FILE")" == "$v2" ]] || fail "update-rules did not write the release file"

publish "$(sed '1s/.*/# version: 3/' "$ROOT/rules/milog-rules.tsv")"
printf 'x' >> "$rel/milog-rules.tsv"
if out=$(mode_update_rules 2>&1); then fail "tampered rules accepted"; fi
[[ "$out" == *"checksum mismatch"* ]] || fail "unexpected tamper error: $out"

publish "$(cat "$ROOT/rules/milog-rules.tsv")"
if out=$(mode_update_rules 2>&1); then fail "downgrade accepted"; fi
[[ "$out" == *"not downgrading"* ]] || fail "unexpected downgrade error: $out"

publish "$(printf '# version: 4\nexploit\tx\t(\nprobe\tx\tb')"
if out=$(mode_update_rules 2>&1); then fail "rules with a broken regex accepted"; fi
[[ "$out" == *"failed validation"* ]] || fail "unexpected validation error: $out"

# publish() writes without a trailing newline, so these bad rows are the unterminated last line.
for last in 'probe\tx\t(' 'probe\tx\t.*'; do
    publish "$(printf '# version: 5\nexploit\tx\ta\n%b' "$last")"
    if out=$(mode_update_rules 2>&1); then fail "bad unterminated last row accepted: $last"; fi
    [[ "$out" == *"failed validation"* ]] || fail "unexpected validation error: $out"
done

rm "$rel/milog-rules.tsv"
if out=$(mode_update_rules 2>&1); then fail "release without a rules file accepted"; fi
[[ "$out" == *"ships no rules file"* ]] || fail "unexpected missing-file error: $out"

publish "$(sed '1s/.*/# version: 6/' "$ROOT/rules/milog-rules.tsv")"
rm "$rel/checksums.txt"
if out=$(mode_update_rules 2>&1); then fail "update without checksums.txt accepted"; fi
[[ "$out" == *"could not fetch checksums.txt"* ]] || fail "unexpected missing-checksums error: $out"
[[ "$(cat "$RULES_FILE")" == "$v2" ]] || fail "a refused update changed RULES_FILE"

# A rule starting with '-' must reach the watcher's grep as a pattern, not an option.
printf '# version: 2\nexploit\tdash\t-dash-probe\nprobe\tx\tonly-bot\n' > "$RULES_FILE"
: > "$log"
MILOG_APPS=app1 "$ROOT/milog.sh" exploits > "$tmp/dash.out" 2>&1 &
pid=$!
sleep 1
printf '203.0.113.7 - - [03/Oct/2026:10:00:00 +0000] "GET /-dash-probe HTTP/1.1" 404 12 "-" "x"\n' >> "$log"
sleep 2
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
grep -q -e '-dash-probe' "$tmp/dash.out" || { cat "$tmp/dash.out" >&2; fail "rule starting with '-' broke the exploits grep"; }

printf 'smoke_rules: ok\n'
