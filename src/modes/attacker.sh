# milog attacker <IP>: everything one IP did across all apps' current access logs (rotated logs are not read).
mode_attacker() {
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        echo -e "${R}usage: milog attacker <IP>${NC}" >&2
        echo -e "${D}  scans all apps' current access.log for one IP's activity${NC}" >&2
        return 1
    fi
    # Only hex digits, dots and colons get through to awk.
    if [[ ! "$ip" =~ ^[0-9a-fA-F:.]+$ ]]; then
        echo -e "${R}invalid IP: $ip${NC}" >&2
        return 1
    fi

    local files=() name
    for name in "${LOGS[@]}"; do
        [[ -f "$LOG_DIR/$name.access.log" ]] && files+=("$LOG_DIR/$name.access.log")
    done
    if (( ${#files[@]} == 0 )); then
        echo -e "${R}no readable app logs in $LOG_DIR${NC}" >&2
        return 1
    fi

    # One "<app>\t<raw line>" row per request.
    local tmp; tmp=$(mktemp -t milog_attacker.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    # Exact field match, so 10.0.0.1 doesn't also match 10.0.0.10.
    for name in "${LOGS[@]}"; do
        local f="$LOG_DIR/$name.access.log"
        [[ -f "$f" ]] || continue
        awk -v ip="$ip" -v app="$name" '$1 == ip { print app "\t" $0 }' "$f" >> "$tmp"
    done

    local total; total=$(wc -l < "$tmp" | tr -d ' ')
    total=${total:-0}

    local country=""
    country=$(geoip_country "$ip" 2>/dev/null || true)
    local tag=""
    [[ -n "$country" && "$country" != "--" ]] && tag="  ${D}[${country}]${NC}"

    echo -e "\n${W}── MiLog: Attacker — ${ip}${tag}${W} ──${NC}\n"

    if (( total == 0 )); then
        echo -e "  ${D}No requests from ${ip} in any configured app.${NC}\n"
        return 0
    fi

    # 2-arg match() only; the 3-arg form is gawk-only.
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

    # Rough path-substring buckets, close to but not identical to _exploit_category.
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
