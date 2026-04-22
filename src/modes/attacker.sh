# ==============================================================================
# MODE: attacker <IP> — forensic view of one IP's activity across all apps
#
# Used during/after an incident: given an IP pulled from `milog top`,
# `milog suspects`, a Discord alert, or a fail2ban ban event — this mode
# shows everything that IP did, across all configured apps, in one report.
#
# Output sections (in order):
#   1. Header:         ip, geo country, scan window
#   2. Summary:        total hits, first-seen, last-seen, unique apps
#   3. Per-app:        hits / 4xx / 5xx per app
#   4. Top paths:      most-requested URLs (query strings stripped)
#   5. Top UAs:        distinct user-agents, ranked
#   6. Classification: exploit vs probe vs normal distribution
#   7. Sample:         first 3 + last 3 raw loglines for context
#
# Scope: reads current `.access.log` files only. Rotated logs (.1, .gz)
# are ignored — run multiple times with different `LOG_DIR` overrides if
# you need older data, or add a --archives flag later.
#
# IP is passed through a character-class regex guard (digits / hex / . / :)
# before it ever reaches grep, so an attacker can't inject regex metachars
# via, say, a webhook-triggered invocation. grep uses -F for fixed-string
# matching too.
# ==============================================================================
mode_attacker() {
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        echo -e "${R}usage: milog attacker <IP>${NC}" >&2
        echo -e "${D}  scans all apps' current access.log for one IP's activity${NC}" >&2
        return 1
    fi
    # Allow v4 (dots + digits) and v6 (hex + colons). Reject everything else
    # so no regex metacharacter ever reaches awk/grep.
    if [[ ! "$ip" =~ ^[0-9a-fA-F:.]+$ ]]; then
        echo -e "${R}invalid IP: $ip${NC}" >&2
        return 1
    fi

    # Gather files.
    local files=() name
    for name in "${LOGS[@]}"; do
        [[ -f "$LOG_DIR/$name.access.log" ]] && files+=("$LOG_DIR/$name.access.log")
    done
    if (( ${#files[@]} == 0 )); then
        echo -e "${R}no readable app logs in $LOG_DIR${NC}" >&2
        return 1
    fi

    # Tmp: one tab-separated row per request: "<app>\t<raw_logline>".
    local tmp; tmp=$(mktemp -t milog_attacker.XXXXXX) || return 1
    # Use RETURN trap so tmp is cleaned even on a `return` path below.
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    # Stream each app's log, keep only lines where field 1 == $ip. awk's
    # exact-field match beats grep here — avoids matching "10.0.0.10" when
    # probing for "10.0.0.1".
    for name in "${LOGS[@]}"; do
        local f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] || continue
        awk -v ip="$ip" -v app="$name" '$1 == ip { print app "\t" $0 }' "$f" >> "$tmp"
    done

    local total; total=$(wc -l < "$tmp" | tr -d ' ')
    total=${total:-0}

    # --- Header --------------------------------------------------------------
    local country=""
    country=$(geoip_country "$ip" 2>/dev/null || true)
    local tag=""
    [[ -n "$country" && "$country" != "--" ]] && tag="  ${D}[${country}]${NC}"

    echo -e "\n${W}── MiLog: Attacker — ${ip}${tag}${W} ──${NC}\n"

    if (( total == 0 )); then
        echo -e "  ${D}No requests from ${ip} in any configured app.${NC}\n"
        return 0
    fi

    # --- Summary -------------------------------------------------------------
    # Timestamp extraction: portable awk (POSIX match returns RSTART/RLENGTH —
    # the gawk-only 3-arg form breaks on BSD awk / mawk).
    local first_seen last_seen apps_hit
    first_seen=$(head -n 1 "$tmp" | awk -F'\t' '
        { if (match($2, /\[[^]]+\]/)) print substr($2, RSTART+1, RLENGTH-2) }')
    last_seen=$( tail -n 1 "$tmp" | awk -F'\t' '
        { if (match($2, /\[[^]]+\]/)) print substr($2, RSTART+1, RLENGTH-2) }')
    apps_hit=$(awk -F'\t' '{print $1}' "$tmp" | sort -u | wc -l | tr -d ' ')

    printf "  %-14s %d\n"  "total hits:" "$total"
    printf "  %-14s %s\n"  "first seen:" "${first_seen:-?}"
    printf "  %-14s %s\n"  "last seen:"  "${last_seen:-?}"
    printf "  %-14s %d of %d\n" "apps touched:" "$apps_hit" "${#LOGS[@]}"

    # --- Per-app breakdown ---------------------------------------------------
    echo -e "\n  ${W}per-app${NC}"
    awk -F'\t' '
        {
            app = $1
            count[app]++
            # Status code sits right after the closing quote of the request.
            # Portable match: test, then substr(RSTART+offset, 3) for the code.
            if (match($2, /" [1-5][0-9][0-9] /)) {
                s = substr($2, RSTART+2, 3)
                if (substr(s,1,1) == "4") c4[app]++
                if (substr(s,1,1) == "5") c5[app]++
            }
        }
        END {
            for (a in count) printf "%d\t%s\t%d\t%d\n", count[a], a, c4[a]+0, c5[a]+0
        }' "$tmp" | sort -rn | \
    awk -v y="$Y" -v r="$R" -v nc="$NC" -F'\t' '
        {
            c4col = ($3 > 0) ? y : ""
            c5col = ($4 > 0) ? r : ""
            c4end = ($3 > 0) ? nc : ""
            c5end = ($4 > 0) ? nc : ""
            printf "    %-12s  %5d hits  %s4xx:%d%s  %s5xx:%d%s\n",
                   $2, $1, c4col, $3, c4end, c5col, $4, c5end
        }'

    # --- Top paths -----------------------------------------------------------
    echo -e "\n  ${W}top paths${NC}"
    awk -F'\t' '
        {
            # Request URI is field 7 of the raw logline (combined format).
            # Split $2 on spaces to reach it — log has quoted fields, but
            # $7 lands inside the "GET /path HTTP/1.1" token so it works.
            n = split($2, f, " ")
            path = f[7]
            sub(/\?.*/, "", path)       # strip query string — aggregates variants
            if (path == "" || path ~ /^[0-9]+$/) next
            counts[path]++
        }
        END { for (p in counts) printf "%d\t%s\n", counts[p], p }' "$tmp" | \
    sort -rn | head -n 10 | \
    awk -F'\t' '{
        p = $2
        if (length(p) > 70) p = substr(p, 1, 67) "..."
        printf "    %5d  %s\n", $1, p
    }'

    # --- Top user-agents -----------------------------------------------------
    echo -e "\n  ${W}top user-agents${NC}"
    awk -F'\t' '
        {
            # UA is the last quoted string on the line:
            #   "GET /x HTTP/1.1" 200 123 "referer" "ua-string"[ reqtime]
            # Combined format has no trailing field; combined_timed appends
            # one. Match either by anchoring on "<ua>" followed by end-of-line
            # OR end-of-line after a space + number.
            line = $2
            if (match(line, /"[^"]*"([[:space:]]+[0-9.]+)?[[:space:]]*$/)) {
                # Trim the trailing reqtime (if any) to isolate the UA.
                s = substr(line, RSTART, RLENGTH)
                # Strip trailing reqtime
                sub(/[[:space:]]+[0-9.]+[[:space:]]*$/, "", s)
                sub(/[[:space:]]*$/, "", s)
                # Now s is `"ua-string"` — strip the outer quotes.
                if (length(s) >= 2 && substr(s,1,1) == "\"" && substr(s,length(s),1) == "\"") {
                    uas[substr(s, 2, length(s)-2)]++
                }
            }
        }
        END { for (u in uas) printf "%d\t%s\n", uas[u], u }' "$tmp" | \
    sort -rn | head -n 5 | \
    awk -F'\t' '{
        u = $2
        if (length(u) > 80) u = substr(u, 1, 77) "..."
        printf "    %5d  %s\n", $1, u
    }'

    # --- Classification ------------------------------------------------------
    # Substring-matched against the path — cheap, deterministic, close enough
    # for "is this exploit/probe traffic?" not "CVE-level precision".
    # Categories mirror src/alerts.sh::_exploit_category.
    echo -e "\n  ${W}classification${NC}"
    awk -F'\t' '
        {
            low = tolower($2)
            cat = "normal"
            if      (low ~ /\/\.env|\/\.git|\/\.aws|\/\.ssh|\/\.htpasswd|\/\.htaccess/) cat = "dotfile"
            else if (low ~ /wp-admin|wp-login|wp-content|xmlrpc|wordpress/) cat = "wordpress"
            else if (low ~ /phpmyadmin|phpunit\/.*\/php\/eval/)            cat = "phpmyadmin"
            else if (low ~ /\.\.\/|%2e%2e|\/etc\/passwd|\/etc\/shadow/)    cat = "traversal"
            else if (low ~ /<script|javascript:|onerror=|onload=/)         cat = "xss"
            else if (low ~ /union[[:space:]]*select|sleep\(|or[[:space:]]+1=1|--[[:space:]]*$/) cat = "sqli"
            else if (low ~ /\$\{jndi:|log4j/)                              cat = "log4shell"
            else if (low ~ /\/(portal|boaform|setup\.cgi|manager\/html|cgi-bin\/|goform|\.well-known\/acme)/) cat = "infra"
            else if (low ~ /\/(shell|cmd|exec|eval)\.php|\/(webshell|c99|r57)/) cat = "rce"
            else if (low ~ /zgrab|masscan|nmap|nikto|sqlmap|dirbuster|gobuster/) cat = "scanner"
            counts[cat]++
        }
        END { for (c in counts) printf "%d\t%s\n", counts[c], c }' "$tmp" | \
    sort -rn | \
    awk -v r="$R" -v y="$Y" -v g="$G" -v d="$D" -v nc="$NC" -F'\t' '
        {
            col = g
            if ($2 != "normal") col = y
            if ($2 ~ /^(traversal|log4shell|sqli|rce|xss)$/) col = r
            if ($2 == "normal") col = d
            printf "    %s%5d  %-12s%s\n", col, $1, $2, nc
        }'

    # --- Sample loglines -----------------------------------------------------
    echo -e "\n  ${W}sample (first 3 + last 3)${NC}"
    local head_lines tail_lines
    head_lines=$(( total < 3 ? total : 3 ))
    head -n "$head_lines" "$tmp" | awk -F'\t' '{printf "    [%-10s] %s\n", $1, $2}'
    if (( total > 6 )); then
        echo -e "    ${D}… ($(( total - 6 )) more) …${NC}"
        tail -n 3 "$tmp" | awk -F'\t' '{printf "    [%-10s] %s\n", $1, $2}'
    elif (( total > 3 )); then
        tail -n $(( total - 3 )) "$tmp" | awk -F'\t' '{printf "    [%-10s] %s\n", $1, $2}'
    fi
    echo
}
