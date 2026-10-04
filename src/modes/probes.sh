# milog probes: scanner, bot and crawler traffic by user-agent, plus non-HTTP protocol probes.
mode_probes() {
    echo -e "${D}Watching scanner/bot traffic across all apps... (Ctrl+C)${NC}\n"
    local pids=() colors=("$B" "$C" "$G" "$M" "$Y" "$R") i=0

    # SSH banners and TLS ClientHellos sent to plain HTTP; nginx logs the bytes as literal \xNN.
    local pat='SSH-2\.0|\\x16\\x03|\\x00\\x00'
    # Security / pentest tools
    pat+='|masscan|zmap|zgrab|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster'
    pat+='|dirb|ffuf|wfuzz|feroxbuster|nessus|openvas|acunetix|wpscan|joomscan'
    pat+='|burp|zaproxy|owasp|metasploit|meterpreter|w3af|webshag'
    # Mass internet scanners / research crawlers
    pat+='|l9explore|l9tcpid|l9retrieve|leakix'
    pat+='|libredtail|httpx|naabu|katana|subfinder'
    pat+='|expanseinc|censysinspect|shodan|stretchoid|internet-measurement'
    pat+='|greenbone|qualys|rapid7|detectify|intruder\.io|netcraftsurvey'
    pat+='|netsystemsresearch|paloalto|projectdiscovery|odin\.ai|onyphe'
    # SEO / advertising crawlers (often unwanted)
    pat+='|ahrefsbot|semrushbot|dotbot|mj12bot|blexbot|petalbot|serpstat'
    pat+='|dataforseobot|bytespider|mauibot|megaindex|seznambot'
    # AI crawlers
    pat+='|claudebot|gptbot|ccbot|anthropic-ai|perplexitybot|youbot'
    pat+='|amazonbot|applebot-extended|cohere-ai|diffbot'
    # Generic HTTP libraries (legit use exists but often scripted)
    pat+='|python-requests|python-urllib|aiohttp|go-http-client|okhttp'
    pat+='|libwww-perl|java/1\.|apache-httpclient|restsharp|http_request2'
    pat+='|guzzlehttp|node-fetch|axios|got\(|scrapy|mechanize'
    # Headless / automation
    pat+='|headlesschrome|phantomjs|puppeteer|playwright|selenium'
    # Generic bot / crawler hints in UA
    pat+='|[Ss]canner|[Bb]ot/|[Cc]rawler|[Ss]pider|probe-|fuzzer|harvester'
    # Known payloads
    pat+='|hello,\s*world'

    for name in "${LOGS[@]}"; do
        local file="$LOG_DIR/$name.access.log"
        local col="${colors[$(( i % ${#colors[@]} ))]}" label
        label=$(printf "%-8s" "$name")
        if [[ -f "$file" ]]; then
            (
                app="$name"
                tail -F "$file" 2>/dev/null | \
                    grep --line-buffered -Ei "$pat" | \
                while IFS= read -r line; do
                    printf '%b[%s]%b %s\n' "$col" "$label" "$NC" "$(_tty_safe <<< "$line")"
                    # Dedup with exploits, which often matches the same scanner line.
                    fp=$(alert_fingerprint_from_line "$line")
                    if alert_should_fire "probe:$app" \
                       && alert_fingerprint_fresh "$fp"; then
                        alert_fire "Probe traffic: $app" "$(_alert_fence "${line:0:1800}")$(cti_alert_note "${line%% *}")" 15844367 "probe:$app" &
                    fi
                done
            ) &
            pids+=($!)
        fi
        (( i++ )) || true
    done
    trap 'kill "${pids[@]}" 2>/dev/null; exit' INT TERM
    wait
}

