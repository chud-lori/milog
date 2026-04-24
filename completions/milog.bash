# bash-completion for milog.
# Install to /usr/share/bash-completion/completions/milog (system) or
# source from ~/.bash_completion for a user install.

_milog_complete() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    local cmds="monitor tui daemon rate health top top-paths attacker slow ws stats trend replay search diff auto-tune grep errors exploits probes suspects config alert alerts silence digest doctor web help"
    local config_subs="show path init edit add rm dir set validate"
    local config_keys="LOG_DIR LOGS REFRESH SPARK_LEN DISCORD_WEBHOOK SLACK_WEBHOOK TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID MATRIX_HOMESERVER MATRIX_TOKEN MATRIX_ROOM WEBHOOK_URL WEBHOOK_TEMPLATE WEBHOOK_CONTENT_TYPE ALERTS_ENABLED ALERT_COOLDOWN ALERT_DEDUP_WINDOW ALERT_STATE_DIR ALERT_LOG_MAX_BYTES ALERT_ROUTES HOOKS_DIR ALERT_HOOK_TIMEOUT P95_WARN_MS P95_CRIT_MS SLOW_WINDOW SLOW_EXCLUDE_PATHS GEOIP_ENABLED MMDB_PATH HISTORY_ENABLED HISTORY_DB HISTORY_RETAIN_DAYS WEB_PORT WEB_BIND THRESH_REQ_WARN THRESH_REQ_CRIT THRESH_CPU_WARN THRESH_CPU_CRIT THRESH_MEM_WARN THRESH_MEM_CRIT THRESH_DISK_WARN THRESH_DISK_CRIT THRESH_4XX_WARN THRESH_5XX_WARN"
    local alert_subs="on off status test"
    local silence_subs="list clear"
    local web_subs="start stop status install-service uninstall-service rotate-token"
    local window_vals="today yesterday 1h 6h 12h 24h 7d 30d all"

    case $cword in
        1)
            COMPREPLY=($(compgen -W "$cmds" -- "$cur"))
            return 0
            ;;
    esac

    # Second-level: depend on the chosen command.
    local cmd="${words[1]}"
    case "$cmd" in
        config)
            case $cword in
                2) COMPREPLY=($(compgen -W "$config_subs" -- "$cur")) ;;
                3)
                    case "${words[2]}" in
                        set) COMPREPLY=($(compgen -W "$config_keys" -- "$cur")) ;;
                    esac
                    ;;
            esac
            ;;
        alert)
            case $cword in
                2) COMPREPLY=($(compgen -W "$alert_subs" -- "$cur")) ;;
            esac
            ;;
        silence)
            case $cword in
                2) COMPREPLY=($(compgen -W "$silence_subs" -- "$cur")) ;;
            esac
            ;;
        web)
            case $cword in
                2) COMPREPLY=($(compgen -W "$web_subs" -- "$cur")) ;;
            esac
            ;;
        alerts|digest)
            case $cword in
                2) COMPREPLY=($(compgen -W "$window_vals" -- "$cur")) ;;
            esac
            ;;
    esac
    return 0
}

complete -F _milog_complete milog
