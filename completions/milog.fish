# fish completion for milog.
# Install to /usr/share/fish/vendor_completions.d/milog.fish (system) or
# ~/.config/fish/completions/milog.fish (user).

function __milog_seen_cmd
    set -l cmd $argv[1]
    set -l tokens (commandline -opc)
    test (count $tokens) -ge 2; and test $tokens[2] = $cmd
end

# Top-level commands
set -l cmds \
    "monitor:full TUI" \
    "daemon:headless alerter" \
    "rate:nginx req/min dashboard" \
    "health:2xx/3xx/4xx/5xx per app" \
    "top:top N source IPs" \
    "top-paths:top N URLs by req/4xx/5xx/p95" \
    "attacker:forensic view of one IP" \
    "slow:top N slow endpoints" \
    "ws:WebSocket session metrics" \
    "stats:hourly request histogram" \
    "trend:sparkline from history" \
    "replay:postmortem for one log file" \
    "search:grep across current + archived logs" \
    "diff:per-app req now vs 1d/7d ago" \
    "auto-tune:suggest thresholds" \
    "grep:filter-tail one app" \
    "errors:live 4xx/5xx tail" \
    "exploits:LFI/RCE/SQLi/XSS/infra probe tail" \
    "probes:scanner/bot traffic tail" \
    "suspects:heuristic bot ranking" \
    "config:show/edit/set/init/validate" \
    "alert:toggle alerting + systemd" \
    "alerts:local fire history" \
    "silence:mute a rule while on-call fixes it" \
    "digest:exec-summary view last day / week" \
    "doctor:diagnostic checklist" \
    "web:start/stop/status web UI" \
    "help:show help"

for entry in $cmds
    set -l parts (string split ":" "$entry")
    complete -c milog -n "__fish_is_first_token" -a "$parts[1]" -d "$parts[2]"
end

# Subcommands
set -l config_subs show path init edit add rm dir set validate
for s in $config_subs
    complete -c milog -n "__milog_seen_cmd config" -a "$s"
end

set -l alert_subs on off status test
for s in $alert_subs
    complete -c milog -n "__milog_seen_cmd alert" -a "$s"
end

set -l silence_subs list clear
for s in $silence_subs
    complete -c milog -n "__milog_seen_cmd silence" -a "$s"
end

set -l web_subs start stop status install-service uninstall-service rotate-token
for s in $web_subs
    complete -c milog -n "__milog_seen_cmd web" -a "$s"
end

set -l window_vals today yesterday 1h 6h 12h 24h 7d 30d all
for v in $window_vals
    complete -c milog -n "__milog_seen_cmd alerts; or __milog_seen_cmd digest" -a "$v"
end
