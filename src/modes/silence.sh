# ==============================================================================
# MODE: silence — mute a rule (or glob of rules) while on-call works the fix
#
# Counterpart to the fire path: when a MiLog rule keeps pinging Discord every
# ALERT_COOLDOWN seconds and you're already fixing the cause, mute it. The
# silence outranks cooldown + dedup and even blocks the alerts.log record so
# history stays signal-only.
#
# Subcommands:
#   milog silence <rule_or_glob> <duration> [message]   add or extend
#   milog silence list                                  show active silences
#   milog silence clear <rule_or_glob>                  remove early
#
# Duration grammar: <N><s|m|h|d>  — `30s`, `5m`, `2h`, `1d`. A bare integer is
# treated as seconds.
#
# Glob matching: bash glob syntax. `exploits:*` matches every `exploits:<cat>`
# key fired by the exploits classifier. Be careful with overly broad globs —
# `*` would silence literally every rule.
#
# Attribution: $USER (or `id -un` fallback) is recorded alongside each silence
# so `milog silence list` shows WHO muted what. Useful even on single-user
# hosts — the daemon writes as its own user; manual silences show as yours.
# ==============================================================================

# Human-readable "time remaining" from a future epoch. 0+ only (caller
# guarantees unexpired rows).
_silence_fmt_remaining() {
    local now target delta
    now=$(date +%s)
    target="$1"
    delta=$(( target - now ))
    if   (( delta < 60 ));    then printf '%ds' "$delta"
    elif (( delta < 3600 ));  then printf '%dm' $(( delta / 60 ))
    elif (( delta < 86400 )); then
        local h=$(( delta / 3600 )) m=$(( (delta % 3600) / 60 ))
        printf '%dh %02dm' "$h" "$m"
    else
        local d=$(( delta / 86400 )) h=$(( (delta % 86400) / 3600 ))
        printf '%dd %02dh' "$d" "$h"
    fi
}

# Human-readable absolute time, GNU/BSD portable (same trick as alerts.sh).
_silence_fmt_epoch() {
    date -d "@$1" '+%Y-%m-%d %H:%M' 2>/dev/null \
    || date -r  "$1" '+%Y-%m-%d %H:%M' 2>/dev/null \
    || printf '%s' "$1"
}

_silence_list() {
    local rows; rows=$(alert_silence_list_active)
    if [[ -z "$rows" ]]; then
        echo -e "${D}No active silences.${NC}"
        echo -e "${D}  milog silence <rule> <duration> [message]   to add one${NC}"
        return 0
    fi
    echo -e "\n${W}── Active silences ──${NC}\n"
    printf "  %-28s  %-16s  %-10s  %-10s  %s\n" "RULE" "UNTIL" "REMAINING" "BY" "NOTE"
    printf "  %-28s  %-16s  %-10s  %-10s  %s\n" \
        "────────────────────────────" "────────────────" "──────────" "──────────" "────"
    local key until_epoch added_epoch added_by message rule_disp note_disp
    while IFS=$'\t' read -r key until_epoch added_epoch added_by message; do
        [[ -z "$key" ]] && continue
        rule_disp="$key"
        (( ${#rule_disp} > 28 )) && rule_disp="${rule_disp:0:25}..."
        note_disp="${message:-—}"
        (( ${#note_disp} > 48 )) && note_disp="${note_disp:0:45}..."
        printf "  ${Y}%-28s${NC}  %-16s  %-10s  %-10s  %s\n" \
            "$rule_disp" \
            "$(_silence_fmt_epoch "$until_epoch")" \
            "$(_silence_fmt_remaining "$until_epoch")" \
            "${added_by:-?}" \
            "$note_disp"
    done <<< "$rows"
    echo
}

_silence_add() {
    local key="$1" duration="$2"; shift 2 || true
    local message="${*:-}"
    if [[ -z "$key" || -z "$duration" ]]; then
        echo -e "${R}usage:${NC} milog silence <rule_or_glob> <duration> [message]" >&2
        echo -e "${D}  duration examples: 30s  5m  2h  1d${NC}" >&2
        return 1
    fi
    local seconds
    seconds=$(alert_silence_parse_duration "$duration") || {
        echo -e "${R}invalid duration:${NC} $duration" >&2
        echo -e "${D}  use N<s|m|h|d> — e.g. 30s, 5m, 2h, 1d${NC}" >&2
        return 1
    }
    if (( seconds < 1 )); then
        echo -e "${R}duration must be > 0${NC}" >&2
        return 1
    fi
    local until_epoch
    until_epoch=$(alert_silence_add "$key" "$seconds" "$message") || {
        echo -e "${R}failed to write silence file${NC}" >&2
        return 1
    }
    local until_fmt; until_fmt=$(_silence_fmt_epoch "$until_epoch")
    local rem_fmt;   rem_fmt=$(_silence_fmt_remaining "$until_epoch")
    echo -e "${G}✓${NC} silenced ${Y}$key${NC} until ${W}$until_fmt${NC} (${rem_fmt})"
    [[ -n "$message" ]] && echo -e "${D}  note: $message${NC}"
}

_silence_clear() {
    local key="$1"
    if [[ -z "$key" ]]; then
        echo -e "${R}usage:${NC} milog silence clear <rule_or_glob>" >&2
        return 1
    fi
    if alert_silence_remove "$key"; then
        echo -e "${G}✓${NC} removed silence on ${Y}$key${NC}"
    else
        echo -e "${D}no active silence on ${key}${NC}"
        return 1
    fi
}

_silence_help() {
    echo -e "
${W}milog silence${NC} — mute an alert rule while you work the fix

${W}USAGE${NC}
  ${C}milog silence <rule_or_glob> <duration> [message]${NC}   add / extend
  ${C}milog silence list${NC}                                   show active
  ${C}milog silence clear <rule_or_glob>${NC}                   remove early

${W}DURATION${NC}
  ${C}30s${NC}  30 seconds      ${C}5m${NC}  5 minutes
  ${C}2h${NC}   2 hours         ${C}1d${NC}  1 day
  ${C}300${NC}  bare int = seconds

${W}EXAMPLES${NC}
  ${D}# Working on the broken deploy, don't page me for 2 hours:${NC}
  milog silence 5xx:api 2h 'investigating deploy, auth service'

  ${D}# Glob — silence every exploit category at once:${NC}
  milog silence 'exploits:*' 30m 'pentester doing authorized scan'

  ${D}# Done early, unmute:${NC}
  milog silence clear 5xx:api

  ${D}# What's currently muted?${NC}
  milog silence list

${W}NOTES${NC}
  - Silence beats cooldown + dedup. A silenced rule does not fire, does not
    record to alerts.log, does not page any destination.
  - Re-silencing the same key extends rather than stacks — no duplicate rows.
  - Glob syntax is bash's (${C}*${NC} ${C}?${NC} ${C}[...]${NC}) — be careful with
    ${C}*${NC} alone, it silences everything.
"
}

mode_silence() {
    local sub="${1:-list}"
    case "$sub" in
        list|'')
            _silence_list
            ;;
        clear)
            shift
            _silence_clear "${1:-}"
            ;;
        -h|--help|help)
            _silence_help
            ;;
        *)
            # Otherwise treat the first arg as the rule key and the rest as
            # `<duration> [message]` — the most-used path.
            _silence_add "$@"
            ;;
    esac
}
