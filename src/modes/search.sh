# ==============================================================================
# MODE: search <pattern> [flags] — grep across all app logs + archives
#
# Tier-1 log search: a polite wrapper around `grep -F` (or `grep -E` with
# --regex) across every configured app's access.log. Optional filters:
#
#   --since <spec>   : drop lines older than spec (today/Nh/Nd/Nw/all).
#                      Reuses _alerts_window_to_epoch — same grammar.
#   --app <name>     : scope to one app's logs.
#   --path <sub>     : substring filter on URL path (post-grep).
#   --regex          : pattern is ERE (grep -E) instead of fixed-string.
#   --archives       : also search rotated logs (.log.1, .log.2.gz, ...).
#   --limit N        : cap output to N lines (default 200; 0 = unlimited).
#
# Output: one prefixed line per match — `[app       ] <logline>` with per-app
# coloring. Final tally shows total + per-app counts.
#
# Scaling: grep is linear; fine up to ~10 GB total log volume. Beyond that,
# see the plan's "Full-text search, tier 2 (SQLite FTS5)" item.
# ==============================================================================
mode_search() {
    local pattern="" since="" app_filter="" path_filter=""
    local use_regex=0 include_archives=0 limit=200

    # First positional (if not a flag) is the pattern.
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

    # Resolve --since to a cutoff epoch up-front (one fork, not per-line).
    local cutoff_epoch=""
    if [[ -n "$since" ]]; then
        cutoff_epoch=$(_alerts_window_to_epoch "$since") || return 1
        # --since relies on awk's mktime() — gawk/mawk have it, BSD awk
        # doesn't. Warn + disable gracefully on BSD-awk hosts so the search
        # still runs (users get all matches instead of a hard failure).
        if ! command -v gawk >/dev/null 2>&1 \
             && ! awk 'BEGIN { if (mktime("2020 1 1 0 0 0") <= 0) exit 1 }' 2>/dev/null; then
            echo -e "${Y}--since requires gawk or mawk (this awk lacks mktime); time filter skipped${NC}" >&2
            cutoff_epoch=""
        fi
    fi

    # Prefer gawk for the filtering awk — mawk/gawk have mktime, BSD awk
    # doesn't. Falls back to plain `awk` when neither is explicit (works
    # on Ubuntu where /usr/bin/awk is typically mawk).
    local awk_bin="awk"
    command -v gawk >/dev/null 2>&1 && awk_bin="gawk"

    # Apps: explicit --app filter, else every configured LOGS entry.
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

    # grep -F by default (safe for user-pasted strings like "session_id=abc+xyz");
    # --regex opts into grep -E so callers can use alternation.
    local grep_flag="-F"
    (( use_regex )) && grep_flag="-E"

    # Stream all matches into a tmp file so we can tally + apply --limit
    # after the fact without second-pass scanning the source logs.
    local tmp; tmp=$(mktemp -t milog_search.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    local colors=("$B" "$C" "$G" "$M" "$Y" "$R")
    local idx=0
    for app in "${apps_to_scan[@]}"; do
        local col="${colors[$(( idx % ${#colors[@]} ))]}"
        local label; label=$(printf "%-10s" "$app")
        idx=$(( idx + 1 ))

        # Build the file list (current + optional archives). Expanded
        # globs are sorted so rotated logs come after the current one.
        local files=()
        [[ -f "$LOG_DIR/$app.access.log" ]] && files+=("$LOG_DIR/$app.access.log")
        if (( include_archives )); then
            shopt -s nullglob
            for archive in "$LOG_DIR/$app.access.log."*; do
                files+=("$archive")
            done
            shopt -u nullglob
        fi

        # For each file, decompress if needed then grep. Piped through
        # awk for --path / --since filtering and final prefixing. One
        # awk instance per file keeps the per-app coloring cheap.
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

    # Per-app counts — strip the colored prefix to find the app name.
    # The prefix shape is "[<app padded to 10>]" so we pull field-2 of
    # the raw `[label ] rest...` pattern.
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

# Scan one log file for pattern, applying post-filters, prefix each
# surviving line with `[<colored app label>]`. Handles .gz / .bz2 / plain.
# Emits to stdout; caller appends to the tmp file.
_search_one_file() {
    local f="$1" pattern="$2" grep_flag="$3" app="$4" col="$5" label="$6"
    local path_filter="$7" cutoff_epoch="$8" awk_bin="${9:-awk}"

    # Decompression path — prefer `gzip -dc` over `zcat` because BSD zcat
    # only handles .Z (compress), not .gz. Same for `bzip2 -dc` / `xz -dc`.
    local reader_cmd=""
    case "$f" in
        *.gz)   reader_cmd="gzip -dc"  ;;
        *.bz2)  reader_cmd="bzip2 -dc" ;;
        *.xz)   reader_cmd="xz -dc"    ;;
        *)      reader_cmd="cat"       ;;
    esac
    # Check the first word of reader_cmd is on PATH.
    local probe="${reader_cmd%% *}"
    command -v "$probe" >/dev/null 2>&1 \
        || { echo -e "${D}  (skipping $f — $probe not installed)${NC}" >&2; return 0; }

    # The || true swallows grep's "no matches" exit=1 so `set -euo pipefail`
    # doesn't abort the whole search when one file happens to not contain
    # the pattern (very common on rotated archives). Each stage's other
    # failure modes are intentionally swallowed too — search is best-effort.
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
