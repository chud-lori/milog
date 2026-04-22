show_help() {
    echo -e "
${W}MiLog${NC} — nginx + system monitor

${W}USAGE${NC}  $0 [command] [args]

${W}DASHBOARDS${NC}
  ${C}monitor${NC}            full TUI: nginx + CPU/MEM/DISK/NET + workers
                     ${D}keys: q=quit  p=pause  r=refresh  +/-=rate${NC}
  ${C}rate${NC}               nginx-only req/min dashboard
  ${C}daemon${NC}             headless alerter — no TUI, fires Discord webhooks

${W}ANALYSIS${NC}
  ${C}health${NC}             2xx/3xx/4xx/5xx per app
  ${C}top [N]${NC}            top N source IPs  ${D}(default: 10)${NC}
  ${C}top-paths [N]${NC}      top N URLs — req/4xx/5xx/p95 per path  ${D}(default: 20)${NC}
  ${C}attacker <IP>${NC}      forensic view: one IP's activity across all apps
  ${C}slow [N]${NC}           top N slow endpoints by p95  ${D}(requires \$request_time)${NC}
  ${C}stats <app>${NC}        hourly request histogram
  ${C}suspects [N] [W]${NC}   heuristic bot ranking ${D}(top N=20, window=2000 lines/app)${NC}
  ${C}trend [app] [H]${NC}    sparkline of req/min from history ${D}(default: all apps, 24h)${NC}
  ${C}diff${NC}               per-app req: now vs 1d ago vs 7d ago
  ${C}auto-tune [D]${NC}      suggest thresholds from history  ${D}(default: 7 days)${NC}
  ${C}replay <file>${NC}      postmortem summary for one archived log file

${W}ALERTING${NC}
  ${C}alert on [URL]${NC}     enable Discord alerts + install systemd service
  ${C}alert off${NC}          disable alerts + stop service
  ${C}alert status${NC}       webhook / service / recent-fire state
  ${C}alert test${NC}         send a test Discord embed right now

${W}DIAGNOSTICS${NC}
  ${C}doctor${NC}             checklist: tools, logs, log format, webhook, history, geoip, systemd

${W}WEB UI${NC} ${D}(read-only, token-gated, loopback-only by default)${NC}
  ${C}web${NC}                start the local HTTP dashboard
  ${C}web stop${NC}           kill the running dashboard
  ${C}web status${NC}         is it running? on what port?

${W}CONFIG${NC}
  ${C}config${NC}             show resolved config + path
  ${C}config init${NC}        create template config file
  ${C}config add <app>${NC}   append app to LOGS
  ${C}config rm  <app>${NC}   remove app from LOGS
  ${C}config dir <path>${NC}  set LOG_DIR
  ${C}config set <K> <V>${NC} set any variable (REFRESH, THRESH_*, …)
  ${C}config edit${NC}        open in \$EDITOR

${W}TAILING${NC}
  ${C}(none) / logs${NC}      tail all logs, color prefixed  ${D}<- default${NC}
  ${C}errors${NC}             4xx/5xx lines only
  ${C}exploits${NC}           LFI / RCE / SQLi / XSS / infra-probe payloads
  ${C}probes${NC}             scanner/bot traffic
  ${C}grep <app> <pat>${NC}   filter-tail one app
  ${C}<app>${NC}              raw tail for one app

${W}THRESHOLDS${NC}
  req/min  warn=${THRESH_REQ_WARN}  crit=${THRESH_REQ_CRIT}
  cpu      warn=${THRESH_CPU_WARN}%  crit=${THRESH_CPU_CRIT}%
  mem      warn=${THRESH_MEM_WARN}%  crit=${THRESH_MEM_CRIT}%
  4xx      warn=${THRESH_4XX_WARN}   5xx warn=${THRESH_5XX_WARN}
  p95      warn=${P95_WARN_MS}ms  crit=${P95_CRIT_MS}ms

${W}APPS${NC}  ${LOGS[*]}
  ${D}dir:${NC} ${LOG_DIR}
  ${D}config:${NC} ${MILOG_CONFIG}  ${D}(override LOG_DIR, LOGS, REFRESH, thresholds)${NC}
  ${D}env:${NC} MILOG_LOG_DIR, MILOG_APPS=\"a b c\", MILOG_CONFIG=/path/to/config.sh
  ${D}auto-discover:${NC} if LOGS is empty, all ${LOG_DIR}/*.access.log are picked up
"
}

# ==============================================================================
# DISPATCH
# ==============================================================================
case "${1:-}" in
    monitor)  mode_monitor ;;
    daemon)   mode_daemon ;;
    rate)     mode_rate ;;
    health)   mode_health ;;
    top)      mode_top "${2:-10}" ;;
    top-paths|toppaths) mode_top_paths "${2:-20}" "${3:-}" ;;
    attacker) mode_attacker "${2:-}" ;;
    slow)     mode_slow "${2:-10}" ;;
    stats)    mode_stats "${2:-}" ;;
    trend)    mode_trend "${2:-}" "${3:-24}" ;;
    replay)   mode_replay "${2:-}" ;;
    diff)     mode_diff ;;
    auto-tune|autotune|tune) mode_auto_tune "${2:-7}" ;;
    grep)     mode_grep "${2:-}" "${3:-.}" ;;
    errors)   mode_errors ;;
    exploits) mode_exploits ;;
    probes)   mode_probes ;;
    suspects) mode_suspects "${2:-20}" "${3:-2000}" ;;
    config)   shift; mode_config "$@" ;;
    alert)    shift; mode_alert  "$@" ;;
    doctor)   mode_doctor ;;
    web)      shift; mode_web "$@" ;;
    __web_handler) _web_handle ;;
    -h|--help|help) show_help ;;
    ""|logs)  color_prefix ;;
    *)
        if [[ " ${LOGS[*]} " =~ " $1 " ]]; then
            tail -F "$LOG_DIR/$1.access.log"
        else
            echo -e "${R}Unknown command: '$1'${NC}"; show_help; exit 1
        fi ;;
esac
