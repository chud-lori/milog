# milog bottleneck: one-shot host-slowdown audit naming the saturated resource and its culprits.

_bn_usage() {
    echo "usage: milog bottleneck [--json]"
    echo "  one-shot host-slowdown audit: names the saturated resource and the culprit processes"
}

# avg10 of the `some` line in /proc/pressure/$1; fails when PSI is absent.
_bn_psi() {
    local f="/proc/pressure/$1"
    [[ -r "$f" ]] || return 1
    local v
    v=$(awk '/^some /{for(i=1;i<=NF;i++) if($i ~ /^avg10=/){sub(/avg10=/,"",$i); print $i; exit}}' "$f" 2>/dev/null) || return 1
    [[ -n "$v" ]] || return 1
    printf '%s' "$v"
}

# True when float $1 >= float $2.
_bn_fge() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 >= b+0)}'; }

# Runnable and blocked task counts from /proc/stat as "r b".
_bn_runqueue() {
    awk '/^procs_running /{r=$2} /^procs_blocked /{b=$2} END{printf "%d %d\n", r+0, b+0}' /proc/stat 2>/dev/null || echo "0 0"
}

# Online CPU count, falling back to /proc/cpuinfo then 1.
_bn_ncpu() {
    local n
    n=$(nproc 2>/dev/null) || n=""
    [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] && { echo "$n"; return; }
    n=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null) || n=0
    [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] && { echo "$n"; return; }
    echo 1
}

# iowait percent sampled over 0.2s; empty when /proc/stat is unreadable.
_bn_iowait() {
    local a b t1 w1 t2 w2
    a=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $6}' /proc/stat 2>/dev/null) || return 1
    sleep 0.2
    b=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $6}' /proc/stat 2>/dev/null) || return 1
    read -r t1 w1 <<< "$a"; read -r t2 w2 <<< "$b"
    local dt=$(( t2 - t1 )) dw=$(( w2 - w1 ))
    (( dt > 0 )) || { echo 0; return 0; }
    echo $(( 100 * dw / dt ))
}

# Used swap as a percent of total; 0 when there is no swap.
_bn_swap_used_pct() {
    [[ -r /proc/meminfo ]] || { echo 0; return; }
    awk '/^SwapTotal:/{t=$2}/^SwapFree:/{f=$2}END{ if(t>0) printf "%d\n", (t-f)*100/t; else print 0 }' /proc/meminfo 2>/dev/null || echo 0
}

# swap-out pages per second sampled over 0.2s.
_bn_swap_out_rate() {
    [[ -r /proc/vmstat ]] || { echo 0; return; }
    local o1 o2
    o1=$(awk '/^pswpout /{print $2}' /proc/vmstat 2>/dev/null) || o1=0
    sleep 0.2
    o2=$(awk '/^pswpout /{print $2}' /proc/vmstat 2>/dev/null) || o2=0
    [[ "$o1" =~ ^[0-9]+$ && "$o2" =~ ^[0-9]+$ ]] || { echo 0; return; }
    echo $(( (o2 - o1) * 5 ))
}

# Running process count from /proc.
_bn_proc_count() {
    local n
    n=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l | tr -d ' ') || n=0
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    echo "$n"
}

# Real block-device mounts as "use% mount", skipping pseudo filesystems.
_bn_space_mounts() {
    df -P 2>/dev/null | awk 'NR>1 {
        src=$1; gsub(/%/,"",$5); mnt=$6
        if (src=="tmpfs"||src=="devtmpfs"||src=="udev"||src=="overlay"||src=="none") next
        if (mnt !~ /^\//) next
        print $5, mnt
    }'
}

# Same as _bn_space_mounts but for inode usage.
_bn_inode_mounts() {
    df -Pi 2>/dev/null | awk 'NR>1 {
        src=$1; gsub(/%/,"",$5); mnt=$6
        if (src=="tmpfs"||src=="devtmpfs"||src=="udev"||src=="overlay"||src=="none") next
        if (mnt !~ /^\//) next
        if ($5 !~ /^[0-9]+$/) next
        print $5, mnt
    }'
}

# Process group pgrp from /proc/<pid>/stat, parsed past a comm that may hold ") ".
_bn_pgrp_of() {
    awk '{ s=$0; sub(/.*\) /, "", s); split(s, f, " "); print f[3] }' "$1/stat" 2>/dev/null
}

# Top processes by %cpu as "name<TAB>detail", excluding milog's own group.
_bn_cpu_offenders() {
    command -v ps >/dev/null 2>&1 || return 1
    local pid pct rest
    ps -eo pid,pgid,%cpu,comm --sort=-%cpu 2>/dev/null \
        | awk -v own="$_BN_OWN_PGID" 'NR>1 && $2!=own' | head -5 | while read -r pid _ pct rest; do
        [[ -n "$rest" ]] || rest="?"
        printf '%s\t%s\n' "$rest" "pid $pid, ${pct}% cpu"
    done
}

# Top processes by RSS as "name<TAB>detail", excluding milog's own group.
_bn_mem_offenders() {
    command -v ps >/dev/null 2>&1 || return 1
    local pid rss rest
    ps -eo pid,pgid,rss,comm --sort=-rss 2>/dev/null \
        | awk -v own="$_BN_OWN_PGID" 'NR>1 && $2!=own' | head -5 | while read -r pid _ rss rest; do
        [[ "$rss" =~ ^[0-9]+$ ]] || continue
        [[ -n "$rest" ]] || rest="?"
        printf '%s\t%s\n' "$rest" "pid $pid, $(fmt_bytes $(( rss * 1024 ))) rss"
    done
}

# Top processes by cumulative I/O from /proc/<pid>/io; fails when none are readable.
_bn_io_offenders() {
    local d pid rb wb total comm lines="" any=0
    for d in /proc/[0-9]*; do
        [[ -r "$d/io" ]] || continue
        rb=$(awk '/^read_bytes:/{print $2}' "$d/io" 2>/dev/null) || rb=""
        wb=$(awk '/^write_bytes:/{print $2}' "$d/io" 2>/dev/null) || wb=""
        [[ "$rb" =~ ^[0-9]+$ && "$wb" =~ ^[0-9]+$ ]] || continue
        total=$(( rb + wb ))
        (( total > 0 )) || continue
        pid="${d#/proc/}"
        [[ -n "$_BN_OWN_PGID" ]] && [[ "$(_bn_pgrp_of "$d")" == "$_BN_OWN_PGID" ]] && continue
        comm=$(tr -d '\n' < "$d/comm" 2>/dev/null) || comm="?"
        lines+="${total}	${pid}	${comm:-?}"$'\n'
        any=1
    done
    (( any )) || return 1
    printf '%s' "$lines" | sort -rn | awk 'NR<=5' | while IFS=$'\t' read -r total pid comm; do
        printf '%s\t%s\n' "$comm" "pid $pid, $(fmt_bytes "$total") cumulative I/O"
    done
}

# Top processes by open fd count as "name<TAB>detail".
_bn_fd_offenders() {
    local d pid n comm lines=""
    for d in /proc/[0-9]*; do
        [[ -d "$d/fd" ]] || continue
        n=$(ls "$d/fd" 2>/dev/null | wc -l | tr -d ' ') || continue
        [[ "$n" =~ ^[0-9]+$ ]] || continue
        (( n > 0 )) || continue
        pid="${d#/proc/}"
        [[ -n "$_BN_OWN_PGID" ]] && [[ "$(_bn_pgrp_of "$d")" == "$_BN_OWN_PGID" ]] && continue
        comm=$(tr -d '\n' < "$d/comm" 2>/dev/null) || comm="?"
        lines+="${n}	${pid}	${comm:-?}"$'\n'
    done
    [[ -n "$lines" ]] || return 1
    printf '%s' "$lines" | sort -rn | awk 'NR<=5' | while IFS=$'\t' read -r n pid comm; do
        printf '%s\t%s\n' "$comm" "pid $pid, $n open fds"
    done
}

# Largest entries one level under $1 via a time-bounded du as "path<TAB>size".
_bn_du_offenders() {
    local mnt="$1" tcmd="" out
    command -v timeout >/dev/null 2>&1 && tcmd="timeout 15"
    out=$($tcmd du -kx --max-depth=1 "$mnt" 2>/dev/null | sort -rn | awk 'NR<=6') || true
    local kb path
    while IFS=$'\t' read -r kb path; do
        [[ "$kb" =~ ^[0-9]+$ ]] || continue
        [[ "$path" == "$mnt" ]] && continue
        printf '%s\t%s\n' "$path" "$(fmt_bytes $(( kb * 1024 )))"
    done <<< "$out"
}

# OOM victims from dmesg as "name<TAB>detail"; 2 = dmesg unavailable, 1 = none found.
_bn_oom_victims() {
    command -v dmesg >/dev/null 2>&1 || return 2
    local lines
    lines=$(dmesg 2>/dev/null) || return 2
    [[ -n "$lines" ]] || return 2
    local hits
    hits=$(printf '%s\n' "$lines" | sed -n -E 's/.*Killed process ([0-9]+) \(([^)]*)\).*/\2\tpid \1 (OOM killed)/p' | tail -5) || true
    [[ -n "$hits" ]] || return 1
    printf '%s\n' "$hits"
}

_bn_note_limited() { LIMITED+=("$1"); }

# Appends a resource result: key label saturated(0/1) signal offenders-TSV.
_bn_add() {
    RES_KEY+=("$1"); RES_LABEL+=("$2"); RES_SAT+=("$3"); RES_SIGNAL+=("$4"); RES_OFF+=("$5")
}

_bn_check_cpu() {
    local sat=0 signal="" off="" psi
    psi=$(_bn_psi cpu) || psi=""
    if [[ -n "$psi" ]]; then
        if _bn_fge "$psi" "$CPU_PRESSURE_WARN"; then sat=1; fi
        signal="cpu pressure ${psi}% (avg10)"
    else
        _bn_note_limited "no /proc/pressure (cpu), using load average"
        local ncpu load1 r b perc
        ncpu=$(_bn_ncpu)
        load1=0
        [[ -r /proc/loadavg ]] && { read -r load1 _ < /proc/loadavg 2>/dev/null || load1=0; }
        read -r r b < <(_bn_runqueue)
        perc=$(awk -v l="$load1" -v n="$ncpu" 'BEGIN{ if(n<=0)n=1; printf "%.2f", l/n }')
        if _bn_fge "$perc" "$LOAD_PER_CORE_WARN"; then sat=1; fi
        if (( r > ncpu )); then sat=1; fi
        signal="load ${load1} over ${ncpu} cores (${perc}/core), run-queue r=${r}"
    fi
    if (( sat )); then off=$(_bn_cpu_offenders) || true; fi
    _bn_add "cpu" "CPU" "$sat" "$signal" "$off"
}

_bn_check_io() {
    local sat=0 signal="" off="" psi
    psi=$(_bn_psi io) || psi=""
    if [[ -n "$psi" ]]; then
        if _bn_fge "$psi" "$IO_PRESSURE_WARN"; then sat=1; fi
        signal="io pressure ${psi}% (avg10)"
    else
        _bn_note_limited "no /proc/pressure (io), using iowait + run-queue"
        local iow r b
        iow=$(_bn_iowait) || iow=0
        read -r r b < <(_bn_runqueue)
        if [[ "$iow" =~ ^[0-9]+$ ]] && (( iow >= IOWAIT_WARN )); then sat=1; fi
        signal="iowait ${iow}%, run-queue b=${b}"
    fi
    if (( sat )); then off=$(_bn_io_offenders) || true; fi
    _bn_add "io" "disk I/O" "$sat" "$signal" "$off"
}

_bn_check_memory() {
    local sat=0 signal="" off="" psi
    psi=$(_bn_psi memory) || psi=""
    if [[ -n "$psi" ]]; then
        if _bn_fge "$psi" "$MEM_PRESSURE_WARN"; then sat=1; fi
        signal="memory pressure ${psi}% (avg10)"
    else
        _bn_note_limited "no /proc/pressure (memory), using usage + swap"
        local used swapused so
        used=$(mem_info 2>/dev/null | awk '{print $1}') || used=0
        [[ "$used" =~ ^[0-9]+$ ]] || used=0
        swapused=$(_bn_swap_used_pct)
        so=$(_bn_swap_out_rate)
        signal="mem used ${used}%, swap used ${swapused}%"
        if [[ "$swapused" =~ ^[0-9]+$ ]] && (( swapused >= SWAP_WARN )); then sat=1; fi
        if [[ "$so" =~ ^[0-9]+$ ]] && (( so > 0 )); then sat=1; signal="$signal, swap-out ${so}pg/s"; fi
    fi
    local oom rc=0
    oom=$(_bn_oom_victims) || rc=$?
    if (( rc == 2 )); then
        _bn_note_limited "dmesg unavailable (OOM scan skipped)"
    elif (( rc == 0 )) && [[ -n "$oom" ]]; then
        sat=1
        signal="$signal; recent OOM kill"
        off+="$oom"$'\n'
    fi
    if (( sat )); then
        local rss
        rss=$(_bn_mem_offenders) || true
        [[ -n "$rss" ]] && off+="$rss"$'\n'
    fi
    _bn_add "memory" "memory" "$sat" "$signal" "$off"
}

_bn_check_space() {
    local sat=0 signal="" off="" use mnt worst_mnt="" worst_use=-1
    while read -r use mnt; do
        [[ "$use" =~ ^[0-9]+$ ]] || continue
        if (( use >= DISK_WARN )); then
            sat=1
            if (( use > worst_use )); then worst_use=$use; worst_mnt=$mnt; fi
        fi
    done < <(_bn_space_mounts)
    if (( sat )); then
        signal="${worst_mnt} ${worst_use}% used"
        off=$(_bn_du_offenders "$worst_mnt") || true
    else
        signal="all mounts under ${DISK_WARN}%"
    fi
    _bn_add "disk" "disk space" "$sat" "$signal" "$off"
}

_bn_check_inodes() {
    local sat=0 signal="" off="" use mnt worst_mnt="" worst_use=-1
    while read -r use mnt; do
        [[ "$use" =~ ^[0-9]+$ ]] || continue
        if (( use >= INODE_WARN )); then
            sat=1
            if (( use > worst_use )); then worst_use=$use; worst_mnt=$mnt; fi
        fi
    done < <(_bn_inode_mounts)
    if (( sat )); then
        signal="${worst_mnt} inodes ${worst_use}%"
        off="${worst_mnt}	${worst_use}% inodes used"$'\n'
    else
        signal="all mounts under ${INODE_WARN}%"
    fi
    _bn_add "inodes" "inodes" "$sat" "$signal" "$off"
}

_bn_check_fd() {
    local sat=0 signal="" off="" parts="" alloc max fdpct nproc_cur pid_max procpct
    # No PSI for file descriptors or the process table, so flag at a fixed 90%.
    if [[ -r /proc/sys/fs/file-nr ]]; then
        read -r alloc _ max < /proc/sys/fs/file-nr 2>/dev/null || { alloc=0; max=0; }
        if [[ "$alloc" =~ ^[0-9]+$ && "$max" =~ ^[0-9]+$ ]] && (( max > 0 )); then
            # Above ~2^53 file-max is the kernel "no limit" sentinel, so a percent is meaningless.
            if (( max >= 9007199254740992 )); then
                parts="open files ${alloc}"
            else
                fdpct=$(( alloc * 100 / max ))
                parts="open files ${fdpct}% (${alloc}/${max})"
                if (( fdpct >= 90 )); then sat=1; fi
            fi
        fi
    fi
    if [[ -r /proc/sys/kernel/pid_max ]]; then
        pid_max=$(cat /proc/sys/kernel/pid_max 2>/dev/null) || pid_max=0
        nproc_cur=$(_bn_proc_count)
        if [[ "$pid_max" =~ ^[0-9]+$ ]] && (( pid_max > 0 )); then
            procpct=$(( nproc_cur * 100 / pid_max ))
            parts="${parts:+$parts, }processes ${procpct}% (${nproc_cur}/${pid_max})"
            if (( procpct >= 90 )); then sat=1; fi
        fi
    fi
    [[ -n "$parts" ]] || parts="file-nr/pid_max unavailable"
    signal="$parts"
    if (( sat )); then off=$(_bn_fd_offenders) || true; fi
    _bn_add "fd" "fd / process table" "$sat" "$signal" "$off"
}

_bn_render_text() {
    local worst="$1" verdict="$2" i l name detail sig
    # Mount names reach the verdict and signals, so guard them like the offenders.
    verdict=$(printf '%s' "$verdict" | _tty_safe)
    echo
    if (( worst < 0 )); then
        printf "  %b%s%b\n" "$G" "$verdict" "$NC"
    else
        printf "  %bBOTTLENECK:%b %b%s%b\n" "$R" "$NC" "$W" "$verdict" "$NC"
    fi
    _doc_head "resources"
    for i in "${!RES_KEY[@]}"; do
        sig=$(printf '%s: %s' "${RES_LABEL[$i]}" "${RES_SIGNAL[$i]}" | _tty_safe)
        if [[ "${RES_SAT[$i]}" == 1 ]]; then
            _doc_line "${R}✗${NC}" "$sig"
        else
            _doc_line "${G}✓${NC}" "$sig"
        fi
    done
    if (( ${#LIMITED[@]} > 0 )); then
        for l in "${LIMITED[@]}"; do
            _doc_line "${Y}!${NC}" "limited: $l"
        done
    fi
    for i in "${!RES_KEY[@]}"; do
        [[ "${RES_SAT[$i]}" == 1 ]] || continue
        [[ -n "${RES_OFF[$i]}" ]] || continue
        printf "\n  ${W}%s offenders${NC}\n" "${RES_LABEL[$i]}"
        while IFS=$'\t' read -r name detail; do
            [[ -n "$name$detail" ]] || continue
            printf "     %-26s ${D}%s${NC}\n" "$name" "$detail"
        done < <(printf '%s\n' "${RES_OFF[$i]}" | _tty_safe)
    done
    echo
}

# Joins its args with commas, for building JSON arrays without a trailing comma.
_bn_join_comma() { local IFS=,; printf '%s' "$*"; }

_bn_render_json() {
    local worst="$1" verdict="$2" i name detail l
    local checks=()
    for i in "${!RES_KEY[@]}"; do
        local offs=() satbool=false offjoin=""
        if [[ -n "${RES_OFF[$i]}" ]]; then
            while IFS=$'\t' read -r name detail; do
                [[ -n "$name$detail" ]] || continue
                offs+=("$(printf '{"name":%s,"detail":%s}' "$(json_escape "$name")" "$(json_escape "$detail")")")
            done < <(printf '%s\n' "${RES_OFF[$i]}")
        fi
        if [[ "${RES_SAT[$i]}" == 1 ]]; then satbool=true; fi
        (( ${#offs[@]} > 0 )) && offjoin=$(_bn_join_comma "${offs[@]}")
        checks+=("$(printf '{"resource":%s,"saturated":%s,"signal":%s,"offenders":[%s]}' \
            "$(json_escape "${RES_KEY[$i]}")" "$satbool" "$(json_escape "${RES_SIGNAL[$i]}")" "$offjoin")")
    done
    local satbool=false limjoin=""
    if (( worst >= 0 )); then satbool=true; fi
    if (( ${#LIMITED[@]} > 0 )); then
        local parts=()
        for l in "${LIMITED[@]}"; do parts+=("$(json_escape "$l")"); done
        limjoin=$(_bn_join_comma "${parts[@]}")
    fi
    printf '{"saturated":%s,"verdict":%s,"checks":[%s],"limited":[%s]}\n' \
        "$satbool" "$(json_escape "$verdict")" "$(_bn_join_comma "${checks[@]}")" "$limjoin"
}

mode_bottleneck() {
    local json=0 arg
    for arg in "$@"; do
        case "$arg" in
            --json)     json=1 ;;
            -h|--help)  _bn_usage; return 0 ;;
            *)          _bn_usage >&2; return 2 ;;
        esac
    done

    # Host-global thresholds, env-overridable, independent of the per-app _thresh helper.
    local CPU_PRESSURE_WARN="${CPU_PRESSURE_WARN:-30}"
    local IO_PRESSURE_WARN="${IO_PRESSURE_WARN:-30}"
    local MEM_PRESSURE_WARN="${MEM_PRESSURE_WARN:-20}"
    local DISK_WARN="${DISK_WARN:-90}"
    local INODE_WARN="${INODE_WARN:-90}"
    local IOWAIT_WARN="${IOWAIT_WARN:-30}"
    local LOAD_PER_CORE_WARN="${LOAD_PER_CORE_WARN:-1.5}"
    local SWAP_WARN="${SWAP_WARN:-50}"

    local -a RES_KEY=() RES_LABEL=() RES_SAT=() RES_SIGNAL=() RES_OFF=() LIMITED=()

    # Own process group, so offenders can skip the audit's own ps and shells.
    local _BN_OWN_PGID
    _BN_OWN_PGID=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')
    [[ "$_BN_OWN_PGID" =~ ^[0-9]+$ ]] || _BN_OWN_PGID=""

    _bn_check_cpu
    _bn_check_io
    _bn_check_memory
    _bn_check_space
    _bn_check_inodes
    _bn_check_fd

    local worst=-1 i
    for i in "${!RES_KEY[@]}"; do
        if [[ "${RES_SAT[$i]}" == 1 ]]; then worst=$i; break; fi
    done

    local verdict
    if (( worst < 0 )); then
        verdict="No resource saturation detected"
    else
        verdict="${RES_LABEL[$worst]} saturated  ${RES_SIGNAL[$worst]}"
    fi

    if (( json )); then
        _bn_render_json "$worst" "$verdict"
    else
        _bn_render_text "$worst" "$verdict"
    fi
    return 0
}
