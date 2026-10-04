# milog daemon: headless sampler and rule evaluator, logging to stderr.

mode_daemon() {
    # Refuse to start on config errors; warnings only get printed.
    local rc=0
    config_validate >&2 || rc=$?
    if (( rc == 1 )); then
        _dlog "ABORT: config validate reported errors — fix them or run \`milog config validate\`"
        exit 1
    fi
    # rc=2 means warnings only → continue, user's been told.

    local hook_state
    hook_state="disabled"
    [[ "$ALERTS_ENABLED" == "1" && -n "$DISCORD_WEBHOOK" ]] && hook_state="enabled"
    _dlog "milog daemon starting — refresh=${REFRESH}s alerts=${hook_state} history=${HISTORY_ENABLED} apps=(${LOGS[*]})"
    [[ "$ALERTS_ENABLED" != "1" ]] && _dlog "WARNING: ALERTS_ENABLED=0 — rules will log but no webhooks will be fired"
    [[ -z "$DISCORD_WEBHOOK"    ]] && _dlog "WARNING: DISCORD_WEBHOOK empty — no webhooks will be fired"

    history_init   # no-op when HISTORY_ENABLED=0; disables itself on error

    # Watcher stdout is discarded; their alerts fire from inside each mode.
    local watcher_pids=()
    ( mode_exploits > /dev/null ) & watcher_pids+=($!)
    ( mode_probes   > /dev/null ) & watcher_pids+=($!)
    ( mode_patterns > /dev/null ) & watcher_pids+=($!)

    local _cleanup='
        _dlog "milog daemon shutting down"
        kill "${watcher_pids[@]}" 2>/dev/null
        exit 0
    '
    trap "$_cleanup" INT TERM

    # Start at the current period so the first write covers a complete minute, never a partial one.
    local last_min last_hour last_day now
    now=$(date +%s)
    last_min=$((  now / 60   ))
    last_hour=$(( now / 3600 ))
    last_day=$((  now / 86400 ))

    while :; do
        local CUR_TIME
        CUR_TIME=$(date '+%d/%b/%Y:%H:%M')

        local cpu mem_pct mem_used mem_total disk_pct disk_used disk_total
        cpu=$(cpu_usage)
        [[ "$cpu" =~ ^[0-9]+$ ]] || cpu=0
        read -r mem_pct mem_used mem_total <<< "$(mem_info)"
        read -r disk_pct disk_used disk_total <<< "$(disk_info)"

        local worker_count
        worker_count=$(ps aux 2>/dev/null | awk '/nginx: worker/{n++} END{print n+0}')

        sys_check_alerts "$cpu" "$mem_pct" "$mem_used" "$mem_total" \
                         "$disk_pct" "$disk_used" "$disk_total" "$worker_count"

        local name cnt c2 c3 c4 c5 ai tot
        for name in "${LOGS[@]}"; do
            read -r cnt c2 c3 c4 c5 <<< "$(nginx_minute_counts "$name" "$CUR_TIME")"
            cnt=${cnt:-0}; c4=${c4:-0}; c5=${c5:-0}
            nginx_check_http_alerts "$name" "$c4" "$c5"
            read -r ai tot <<< "$(nginx_ai_counts "$name" "$CUR_TIME")"
            nginx_check_ai_alert "$name" "${ai:-0}" "${tot:-0}"
        done

        # Each scanner throttles itself by its AUDIT_*_INTERVAL and no-ops when disabled.
        _audit_fim_tick
        _audit_persistence_tick
        _audit_ports_tick
        _audit_yara_tick
        _audit_accounts_tick
        _audit_rootkit_tick

        # Write the previous minute and hour, which are complete.
        now=$(date +%s)
        local cur_min=$((  now / 60   ))
        local cur_hour=$(( now / 3600 ))
        if (( cur_min > last_min )); then
            local write_ts=$(( last_min * 60 ))
            history_write_minute "$write_ts" "$(_cur_time_at "$write_ts")"
            _anomaly_check_minute "$write_ts"
            last_min=$cur_min
        fi
        if (( cur_hour > last_hour )); then
            local write_hr_ts=$(( last_hour * 3600 ))
            history_write_hour "$write_hr_ts"
            last_hour=$cur_hour
        fi
        local cur_day=$(( now / 86400 ))
        if (( cur_day > last_day )); then
            history_prune
            last_day=$cur_day
        fi

        sleep "$REFRESH"
    done
}

