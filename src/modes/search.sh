# milog search <pattern> [flags]: fixed-string (or --regex) grep across app logs and, with --archives, rotated ones.
mode_search() {
    local pattern="" since="" app_filter="" path_filter=""
    local use_regex=0 include_archives=0 limit=200

    if [[ $# -gt 0 && "$1" != --* ]]; then
        pattern="$1"; shift
    fi
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --since)     since="$2"; shift 2 ;;
            --app)       app_filter="$2"; shift 2 ;;
            --path)      path_filter="$2"; shift 2 ;;
            --regex)     use_regex=1; shift ;;
            --archives)  include_archives=1; shift ;;
            --limit)     limit="$2"; shift 2 ;;
            -h|--help)   pattern=""; break ;;
            *) echo -e "${R}unknown flag: $1${NC}" >&2; return 1 ;;
        esac
    done

    if [[ -z "$pattern" ]]; then
        printf '%b' "
${R}usage: milog search <pattern> [flags]${NC}

${D}  flags:
    --since today|yesterday|Nh|Nd|Nw|all     time filter on logline timestamp
    --app <name>                              scope to one app (default: all)
    --path <substring>                        only lines whose URL contains it
    --regex                                   interpret pattern as ERE (else -F)
    --archives                                also search .log.1, .log.*.gz
    --limit N                                 cap output; 0=unlimited (default 200)
${NC}"
        return 1
    fi
    [[ "$limit" =~ ^[0-9]+$ ]] \
        || { echo -e "${R}--limit must be numeric${NC}" >&2; return 1; }

    local cutoff_epoch=""
    if [[ -n "$since" ]]; then
        cutoff_epoch=$(_alerts_window_to_epoch "$since") || return 1
        # mktime() exists in gawk and mawk but not BSD awk; without it, skip the time filter rather than fail.
        if ! command -v gawk >/dev/null 2>&1 \
             && ! awk 'BEGIN { if (mktime("2020 1 1 0 0 0") <= 0) exit 1 }' 2>/dev/null; then
            echo -e "${Y}--since requires gawk or mawk (this awk lacks mktime); time filter skipped${NC}" >&2
            cutoff_epoch=""
        fi
    fi

    local awk_bin="awk"
    command -v gawk >/dev/null 2>&1 && awk_bin="gawk"

    local apps_to_scan=()
    if [[ -n "$app_filter" ]]; then
        if [[ ! " ${LOGS[*]} " =~ " $app_filter " ]]; then
            echo -e "${R}unknown app: $app_filter${NC}  Known: ${LOGS[*]}" >&2
            return 1
        fi
        apps_to_scan=("$app_filter")
    else
        apps_to_scan=("${LOGS[@]}")
    fi

    local grep_flag="-F"
    (( use_regex )) && grep_flag="-E"

    # Collect matches in a temp file so --limit and the tally don't rescan the logs.
    local tmp; tmp=$(mktemp -t milog_search.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    local colors=("$B" "$C" "$G" "$M" "$Y" "$R")
    local idx=0
    for app in "${apps_to_scan[@]}"; do
        local col="${colors[$(( idx % ${#colors[@]} ))]}"
        local label; label=$(printf "%-10s" "$app")
        idx=$(( idx + 1 ))

        local files=()
        [[ -f "$LOG_DIR/$app.access.log" ]] && files+=("$LOG_DIR/$app.access.log")
        if (( include_archives )); then
            shopt -s nullglob
            for archive in "$LOG_DIR/$app.access.log."*; do
                files+=("$archive")
            done
            shopt -u nullglob
        fi

        local f
        for f in "${files[@]}"; do
            _search_one_file "$f" "$pattern" "$grep_flag" "$app" "$col" "$label" \
                             "$path_filter" "$cutoff_epoch" "$awk_bin" >> "$tmp"
        done
    done

    local total; total=$(wc -l < "$tmp" | tr -d ' ')
    total=${total:-0}

    echo -e "\n${W}── MiLog: search \"${pattern}\" ──${NC}\n"

    if (( total == 0 )); then
        echo -e "  ${D}no matches in ${#apps_to_scan[@]} app(s)${NC}\n"
        return 0
    fi

    if (( limit > 0 && total > limit )); then
        head -n "$limit" "$tmp"
        echo -e "\n  ${D}… showing $limit of $total matches. Use --limit 0 for all.${NC}"
    else
        cat "$tmp"
    fi

    # Per-app counts from the `[label]` prefix.
    echo -e "\n  ${W}by app${NC}"
    awk '
        {
            # Lines start with "[<app...>]". Strip everything past the
            # closing bracket; trim trailing spaces in the label.
            if (match($0, /\[[^]]+\]/)) {
                lab = substr($0, RSTART+1, RLENGTH-2)
                # The label may contain ANSI color codes around the name.
                # Strip them for a clean group-by.
                gsub(/\033\[[0-9;]*m/, "", lab)
                sub(/[[:space:]]+$/, "", lab)
                c[lab]++
            }
        }
        END { for (a in c) printf "%d\t%s\n", c[a], a }' "$tmp" \
        | sort -rn \
        | awk '{printf "    %5d  %s\n", $1, $2}'

    echo -e "\n  ${D}total: $total match(es)${NC}\n"
}

# Prints matching lines of one plain/.gz/.bz2/.xz file, filtered and prefixed with `[label]`.
_search_one_file() {
    local f="$1" pattern="$2" grep_flag="$3" app="$4" col="$5" label="$6"
    local path_filter="$7" cutoff_epoch="$8" awk_bin="${9:-awk}"

    # gzip -dc rather than zcat: BSD zcat only reads .Z.
    local reader_cmd=""
    case "$f" in
        *.gz)   reader_cmd="gzip -dc"  ;;
        *.bz2)  reader_cmd="bzip2 -dc" ;;
        *.xz)   reader_cmd="xz -dc"    ;;
        *)      reader_cmd="cat"       ;;
    esac
    local probe="${reader_cmd%% *}"
    command -v "$probe" >/dev/null 2>&1 \
        || { echo -e "${D}  (skipping $f — $probe not installed)${NC}" >&2; return 0; }

    # `|| true` keeps grep's no-match exit from aborting under pipefail; search is best-effort.
    $reader_cmd "$f" 2>/dev/null \
        | { grep "$grep_flag" -- "$pattern" || true; } \
        | "$awk_bin" -v app="$app" -v col="$col" -v nc="$NC" -v label="$label" \
              -v pathf="$path_filter" -v cutoff="$cutoff_epoch" '
            BEGIN {
                split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
                for (i=1; i<=12; i++) mon[m[i]] = i
            }
            {
                # --path substring filter on URL. Request URI is field 7 in
                # combined format; strip query string for cleaner matching.
                if (pathf != "") {
                    p = $7
                    sub(/\?.*/, "", p)
                    if (index(p, pathf) == 0) next
                }
                # --since: parse the [dd/Mon/yyyy:HH:MM:SS tz] timestamp
                # and compare to cutoff. Lines with unparseable timestamps
                # fall through (conservative — we prefer extra matches
                # over dropping ambiguous ones).
                if (cutoff != "" && match($0, /\[[0-9]+\/[A-Z][a-z][a-z]\/[0-9]+:[0-9]+:[0-9]+:[0-9]+/)) {
                    ts = substr($0, RSTART+1, RLENGTH-1)
                    split(ts, part, /[\/:]/)
                    if (part[2] in mon) {
                        epoch = mktime(part[3] " " mon[part[2]] " " part[1] " " part[4] " " part[5] " " part[6])
                        if (epoch > 0 && epoch < cutoff) next
                    }
                }
                printf "[%s%s%s] %s\n", col, label, nc, $0
            }'
}
