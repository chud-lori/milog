# milog bench [--full] [--baseline FILE]: times tail scan, slow, top-paths, top and search on synthetic logs.

_bench_gen_fixture() {
    local dst="$1" n="$2"
    # ~80 paths, random IPs, a 90/8/2 split of 200/404/500.
    awk -v n="$n" 'BEGIN {
        srand(42)
        for (i = 0; i < n; i++) {
            ip = sprintf("%d.%d.%d.%d",
                int(rand()*250)+1, int(rand()*250)+1,
                int(rand()*250)+1, int(rand()*250)+1)
            path = sprintf("/api/endpoint-%d", int(rand()*80)+1)
            if (rand() < 0.05) path = path "?page=" int(rand()*100)
            r = rand()
            if      (r < 0.90) status = 200
            else if (r < 0.98) status = 404
            else                status = 500
            rt = rand() * 2.5   # 0..2.5s request time
            printf "%s - - [24/Apr/2026:12:00:00 +0000] \"GET %s HTTP/1.1\" %d 1024 \"-\" \"bench/1.0\" %.3f\n",
                ip, path, status, rt
        }
    }' > "$dst"
}

_bench_time_ms() {
    # Falls back to whole seconds where `date +%N` is unsupported.
    if date +%N >/dev/null 2>&1 && [[ "$(date +%N)" != "N" ]]; then
        local s ns
        s=$(date +%s); ns=$(date +%N)
        printf '%s' $(( s * 1000 + 10#$ns / 1000000 ))
    else
        printf '%s' $(( $(date +%s) * 1000 ))
    fi
}

_bench_run_one() {
    local label="$1" cmd="$2"
    local t0 t1 rc
    t0=$(_bench_time_ms)
    eval "$cmd" >/dev/null 2>&1
    rc=$?
    t1=$(_bench_time_ms)
    local elapsed=$(( t1 - t0 ))
    printf "%-34s  %6d ms  rc=%d\n" "$label" "$elapsed" "$rc"
    if [[ -n "${BENCH_TSV:-}" ]]; then
        printf '%s\t%d\t%d\n' "$label" "$elapsed" "$rc" >> "$BENCH_TSV"
    fi
}

mode_bench() {
    local full=0
    local baseline=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --full)     full=1; shift ;;
            --baseline) baseline="${2:?}"; shift 2 ;;
            -h|--help)  _bench_help; return 0 ;;
            *) echo -e "${R}bench: unknown flag $1${NC}" >&2; return 1 ;;
        esac
    done

    echo -e "\n${W}── MiLog: Bench (synthetic fixtures) ──${NC}\n"

    local tmp; tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" RETURN
    mkdir -p "$tmp/logs"

    local sizes=(10000 100000)
    (( full )) && sizes+=(1000000)

    if [[ -n "$baseline" ]]; then
        : > "$baseline"
        export BENCH_TSV="$baseline"
    fi

    local n file
    for n in "${sizes[@]}"; do
        file="$tmp/logs/bench.access.log"
        echo -e "${D}  generating $n-line fixture…${NC}"
        _bench_gen_fixture "$file" "$n"
        local bytes; bytes=$(wc -c < "$file" | tr -d ' ')
        local mb; mb=$(( bytes / 1024 / 1024 ))
        printf "${W}─── %d lines  (%d MB) ───${NC}\n" "$n" "$mb"

        local env_prefix="MILOG_APPS=bench MILOG_LOG_DIR=$tmp/logs MILOG_CONFIG=/dev/null"
        _bench_run_one "tail-scan ($n lines)" \
            "wc -l < $file"
        _bench_run_one "slow against $n lines" \
            "$env_prefix SLOW_WINDOW=$n $0 slow 10"
        _bench_run_one "top-paths against $n" \
            "$env_prefix SLOW_WINDOW=$n $0 top-paths 10"
        _bench_run_one "top (IPs) against $n" \
            "$env_prefix SLOW_WINDOW=$n $0 top 10"
        _bench_run_one "search (literal) $n" \
            "$env_prefix $0 search 'endpoint-5'"
        echo
    done

    if [[ -n "$baseline" ]]; then
        echo -e "${G}✓${NC} wrote baseline → $baseline"
    fi
    unset BENCH_TSV
}

_bench_help() {
    echo -e "
${W}milog bench${NC} — benchmark harness with synthetic fixtures

${W}USAGE${NC}
  ${C}milog bench${NC}                  quick run (10k + 100k lines)
  ${C}milog bench --full${NC}            adds a 1M-line pass
  ${C}milog bench --baseline FILE${NC}   also write TSV for CI comparison

${W}MEASURES${NC}
  tail-scan throughput, slow / top-paths / top end-to-end, search
"
}
