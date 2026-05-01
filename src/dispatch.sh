show_help() {
    echo -e "
${W}MiLog${NC} — nginx + system monitor

${W}USAGE${NC}  $0 [command] [args]

${W}DASHBOARDS${NC}
  ${C}monitor${NC}            bash dashboard: nginx + CPU/MEM/DISK + workers
                     ${D}keys: q=quit  p=pause  r=refresh  +/-=rate${NC}
  ${C}tui${NC}                rich bubbletea TUI ${D}(needs milog-tui Go binary; build.sh builds it)${NC}
  ${C}rate${NC}               nginx-only req/min dashboard
  ${C}daemon${NC}             headless alerter — no TUI, fires Discord webhooks

${W}ANALYSIS${NC}
  ${C}health${NC}             2xx/3xx/4xx/5xx per app
  ${C}top [N]${NC}            top N source IPs  ${D}(default: 10)${NC}
  ${C}top-paths [N]${NC}      top N URLs — req/4xx/5xx/p95 per path  ${D}(default: 20)${NC}
  ${C}attacker <IP>${NC}      forensic view: one IP's activity across all apps
  ${C}slow [N]${NC}           top N slow endpoints by p95  ${D}(requires \$request_time; excludes WS)${NC}
  ${C}ws [N]${NC}             WebSocket session metrics — count, duration, top paths
  ${C}stats <app>${NC}        hourly request histogram
  ${C}suspects [N] [W]${NC}   heuristic bot ranking ${D}(top N=20, window=2000 lines/app)${NC}
  ${C}trend [app] [H]${NC}    sparkline of req/min from history ${D}(default: all apps, 24h)${NC}
  ${C}diff${NC}               per-app req: now vs 1d ago vs 7d ago
  ${C}auto-tune [D]${NC}      suggest thresholds from history  ${D}(default: 7 days)${NC}
  ${C}replay <file>${NC}      postmortem summary for one archived log file
  ${C}search <pat> ...${NC}   grep across all apps (flags: --since/--app/--path/--regex/--archives)

${W}ALERTING${NC}
  ${C}alert on [URL]${NC}     enable Discord alerts + install systemd service
  ${C}alert off${NC}          disable alerts + stop service
  ${C}alert status${NC}       webhook / service / recent-fire state
  ${C}alert test${NC}         send a test Discord embed right now
  ${C}alerts [window]${NC}    local fire history ${D}(today / Nh / Nd / Nw / all)${NC}
  ${C}silence ...${NC}        mute a rule while on-call works the fix ${D}(milog silence --help)${NC}
  ${C}digest [window]${NC}     exec-summary (day / week / Nh / Nd)

${W}DIAGNOSTICS${NC}
  ${C}doctor${NC}             checklist: tools, logs, log format, webhook, history, geoip, systemd

${W}WEB UI${NC} ${D}(read-only, token-gated, loopback-only by default)${NC}
  ${C}web${NC}                start the local HTTP dashboard (foreground)
  ${C}web stop${NC}           kill the running dashboard (systemd or foreground)
  ${C}web status${NC}         is it running? on what port?
  ${C}web install-service${NC}   install + start systemd user unit (always-on)
  ${C}web uninstall-service${NC} remove the systemd user unit
  ${C}web rotate-token${NC}   regenerate the web token in place

${W}CONFIG${NC}
  ${C}config${NC}             show resolved config + path
  ${C}config validate${NC}    check for typos, bad ranges, unreachable paths
  ${C}config init${NC}        create template config file
  ${C}config add <app>${NC}   append app to LOGS
  ${C}config rm  <app>${NC}   remove app from LOGS
  ${C}config dir <path>${NC}  set LOG_DIR
  ${C}config set <K> <V>${NC} set any variable (REFRESH, THRESH_*, …)
  ${C}config edit${NC}        open in \$EDITOR

${W}TAILING${NC}
  ${C}(none) / logs${NC}      tail all logs, color prefixed  ${D}<- default${NC}
  ${C}errors${NC}             4xx/5xx + app-pattern live tail (or --since for summary)
  ${C}exploits${NC}           LFI / RCE / SQLi / XSS / infra-probe payloads
  ${C}probes${NC}             scanner/bot traffic
  ${C}patterns${NC}           app-error signatures (panics, OOM, stacktraces…)
  ${C}grep <app> <pat>${NC}   filter-tail one app
  ${C}<app>${NC}              raw tail for one app

${W}OPS${NC}
  ${C}install <feature>${NC}  add optional features: geoip / web / history
  ${C}bench [--full]${NC}     benchmark harness against synthetic fixtures
  ${C}completions <shell>${NC}  install / print bash|zsh|fish completions

${W}MORE HELP${NC}
  ${C}milog <cmd> --help${NC}    detailed help for any command
  ${C}milog config${NC}          current resolved config + destinations + apps
  ${C}milog doctor${NC}          diagnostic checklist

${D}docs → docs/   ·   source → src/   ·   plan → plan.md (gitignored)${NC}
"
}

# Per-command help registry. Runs when `milog <cmd> --help` is invoked. Keeps
# each block short — usage / args / 1-2 examples. The main `show_help`
# lists all commands; this gives you the details on one without scrolling.
_cmd_help() {
    local cmd="$1"
    case "$cmd" in
        monitor)
            echo -e "${W}milog monitor${NC} — bash dashboard (refresh-and-redraw)"
            echo -e "  ${D}Keys:${NC} q quit  p pause  r refresh  +/- change rate"
            echo -e "  ${D}Tunes:${NC} REFRESH, THRESH_* (see \`milog config\`)"
            echo -e "  ${D}Richer view:${NC} \`milog tui\` (Go bubbletea, same data)"
            ;;
        tui)
            echo -e "${W}milog tui${NC} — bubbletea TUI (Go binary)"
            echo -e "  ${D}Keys:${NC} q quit  p pause  r refresh  +/- change rate  ? help"
            echo -e "  ${D}Tunes:${NC} MILOG_REFRESH env / REFRESH config key"
            echo -e "  ${D}Install:${NC} \`bash build.sh\` in a clone; distro packages land later."
            ;;
        rate)     echo -e "${W}milog rate${NC} — nginx-only req/min dashboard" ;;
        daemon)
            echo -e "${W}milog daemon${NC} — headless alerter; no TUI"
            echo -e "  Runs the rule evaluator on a loop, fires alerts via configured destinations."
            echo -e "  ${D}Refuses to start on config-validate errors; warnings allowed.${NC}"
            ;;
        health)   echo -e "${W}milog health${NC} — 2xx/3xx/4xx/5xx totals per app" ;;
        top)
            echo -e "${W}milog top [N]${NC} — top N source IPs across all apps (default 10)"
            echo -e "  ${D}+country column when GEOIP_ENABLED=1${NC}"
            ;;
        top-paths)
            echo -e "${W}milog top-paths [N]${NC} — top N URLs by req / 4xx / 5xx / p95"
            echo -e "  ${D}Excludes SLOW_EXCLUDE_PATHS (WebSocket paths by default)${NC}"
            ;;
        attacker)
            echo -e "${W}milog attacker <IP>${NC} — forensic view of one IP across apps"
            echo -e "  Per-app requests, top paths, top UAs, classification, sample lines."
            ;;
        slow)
            echo -e "${W}milog slow [N]${NC} — top N slow endpoints by p95"
            echo -e "  ${D}Requires \$request_time in log_format; excludes WebSocket paths.${NC}"
            ;;
        ws)
            echo -e "${W}milog ws [N]${NC} — WebSocket session metrics"
            echo -e "  Duration distribution, longest, long-session flag, top paths per app."
            ;;
        stats)    echo -e "${W}milog stats <app>${NC} — hourly request histogram" ;;
        trend)    echo -e "${W}milog trend [app] [HOURS]${NC} — sparkline from history (HISTORY_ENABLED=1)" ;;
        diff)     echo -e "${W}milog diff${NC} — per-app: now vs 1d ago vs 7d ago" ;;
        auto-tune)echo -e "${W}milog auto-tune [DAYS]${NC} — suggest thresholds from history" ;;
        replay)   echo -e "${W}milog replay <file>${NC} — postmortem for one archived log" ;;
        search)
            echo -e "${W}milog search <pattern> [flags]${NC} — grep across current + archived"
            echo -e "  Flags: --since --app --path --regex --archives --limit"
            ;;
        errors)
            echo -e "${W}milog errors${NC} — live tail or summary report"
            echo -e "  Live:    nginx sources show 4xx/5xx, others show app-pattern matches"
            echo -e "  Summary: ${C}--since 1d${NC} ${C}--source <name>${NC} ${C}--pattern <name>${NC}"
            ;;
        exploits) echo -e "${W}milog exploits${NC} — LFI/RCE/SQLi/XSS/infra-probe live tail" ;;
        probes)   echo -e "${W}milog probes${NC} — scanner/bot traffic live tail" ;;
        patterns)
            echo -e "${W}milog patterns [list]${NC} — app-error pattern detector across all sources"
            echo -e "  Built-ins: Go panic, Python traceback, Java stacktrace, Node UPR, OOM, segfault, ERROR/FATAL/CRITICAL"
            echo -e "  Custom:    APP_PATTERN_<name>='regex' (empty value disables a built-in of the same name)"
            echo -e "  ${C}milog patterns list${NC}  show merged catalog (built-ins + overrides + custom)"
            ;;
        grep)     echo -e "${W}milog grep <app> <pattern>${NC} — filter-tail one app" ;;
        suspects) echo -e "${W}milog suspects [N] [WINDOW]${NC} — heuristic bot ranking" ;;
        config)
            echo -e "${W}milog config [sub]${NC} — show / edit / set / validate"
            echo -e "  Subs: show path init edit add rm dir set validate"
            echo -e "  ${C}milog config validate${NC}   check for typos, invalid ranges, unreachable paths"
            ;;
        alert)
            echo -e "${W}milog alert <sub>${NC} — toggle alerting + systemd service"
            echo -e "  Subs: on off status test"
            ;;
        alerts)   echo -e "${W}milog alerts [window]${NC} — fire history (today / Nh / Nd / Nw / all)" ;;
        silence)  echo -e "${W}milog silence <rule> <duration> [message]${NC} — mute a rule"; echo -e "  Also: ${C}milog silence list${NC} · ${C}milog silence clear <rule>${NC}" ;;
        digest)
            echo -e "${W}milog digest [window]${NC} — exec-summary for the period"
            echo -e "  Windows: day (default) / week / 12h / 7d / …"
            ;;
        doctor)   echo -e "${W}milog doctor${NC} — diagnostic checklist" ;;
        web)
            echo -e "${W}milog web${NC} — read-only local HTTP dashboard"
            echo -e "  Subs: start stop status install-service uninstall-service rotate-token"
            ;;
        bench)    echo -e "${W}milog bench [--full] [--baseline FILE]${NC} — timing harness" ;;
        completions) echo -e "${W}milog completions <install|bash|zsh|fish>${NC} — install shell completion" ;;
        install)
            echo -e "${W}milog install <feature>${NC} — on-demand feature installer"
            echo -e "  Subs: list, <feature>, remove <feature>"
            echo -e "  Features: geoip / web / history"
            ;;
        *)
            echo -e "${Y}No detailed help for '$cmd'.${NC} Try ${C}milog help${NC}."
            return 1
            ;;
    esac
}

# ==============================================================================
# DISPATCH
# ==============================================================================
# Intercept `milog <cmd> --help` (and -h) before dispatching to the mode.
# Keeps main `show_help` short while letting each command ship its own
# detail block.
if [[ "${2:-}" == "--help" || "${2:-}" == "-h" ]]; then
    _cmd_help "${1:-}"
    exit $?
fi

case "${1:-}" in
    monitor)  mode_monitor ;;
    tui)      shift; mode_tui "$@" ;;
    daemon)   mode_daemon ;;
    rate)     mode_rate ;;
    health)   mode_health ;;
    top)      mode_top "${2:-10}" ;;
    top-paths|toppaths) mode_top_paths "${2:-20}" "${3:-}" ;;
    attacker) mode_attacker "${2:-}" ;;
    slow)     mode_slow "${2:-10}" ;;
    ws)       mode_ws "${2:-10}" ;;
    stats)    mode_stats "${2:-}" ;;
    trend)    mode_trend "${2:-}" "${3:-24}" ;;
    replay)   mode_replay "${2:-}" ;;
    search)   shift; mode_search "$@" ;;
    diff)     mode_diff ;;
    auto-tune|autotune|tune) mode_auto_tune "${2:-7}" ;;
    grep)     mode_grep "${2:-}" "${3:-.}" ;;
    errors)   shift; mode_errors "$@" ;;
    exploits) mode_exploits ;;
    probes)   mode_probes ;;
    patterns)
        case "${2:-}" in
            list) mode_patterns_list ;;
            *)    mode_patterns ;;
        esac ;;
    suspects) mode_suspects "${2:-20}" "${3:-2000}" ;;
    config)   shift; mode_config "$@" ;;
    alert)    shift; mode_alert  "$@" ;;
    alerts)   mode_alerts "${2:-today}" ;;
    silence)  shift; mode_silence "$@" ;;
    digest)   mode_digest "${2:-day}" ;;
    completions) shift; mode_completions "$@" ;;
    bench)    shift; mode_bench "$@" ;;
    install)  shift; mode_install "$@" ;;
    doctor)   mode_doctor ;;
    web)      shift; mode_web "$@" ;;
    __web_handler) _web_handle ;;
    -h|--help|help) show_help ;;
    ""|logs)  color_prefix ;;
    *)
        # Resolve against LOGS — supports bare names plus `nginx:<name>`,
        # `text:<name>:<path>`, `journal:<unit>`, `docker:<container>`.
        _matching_entry=$(_log_entry_by_name "$1" 2>/dev/null) || _matching_entry=""
        if [[ -n "$_matching_entry" ]]; then
            _reader_cmd=$(_log_reader_cmd "$_matching_entry") || _reader_cmd=""
            if [[ -n "$_reader_cmd" ]]; then
                bash -c "$_reader_cmd"
            else
                echo -e "${R}cannot stream $_matching_entry${NC}"; exit 1
            fi
        else
            echo -e "${R}Unknown command: '$1'${NC}"; show_help; exit 1
        fi ;;
esac
