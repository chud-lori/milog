# ==============================================================================
# BOX DRAWING — single source of truth for geometry
#
# Table columns: APP(10) | REQ/MIN(8) | STATUS(10) | INTENSITY(W_BAR)
# Row layout between outer │…│:
#   " " app(10) " │ " req(8) " │ " status(10) " │ " bar(W_BAR) " "
#   = 11 + (W_REQ+3) + (W_ST+3) + (W_BAR+4) = W_APP+W_REQ+W_ST+W_BAR+11
#
# INNER is the interior width (chars between the outer │…│) and scales with
# terminal width; W_BAR absorbs the slack so the INTENSITY column — which
# carries the sparkline — gets wider on bigger screens. The fixed columns
# (APP/REQ/STATUS) stay the same so numbers line up at a glance.
#
# milog_update_geometry() recomputes INNER/W_BAR/BW from `tput cols` and is
# called at the top of every render tick — so SIGWINCH / live resize just
# works (next frame reflows). Override with MILOG_WIDTH=N to pin a width,
# useful in terminals that misreport cols (screen, some CI runners).
# ==============================================================================
W_APP=10; W_REQ=8; W_ST=10
W_BAR=35                 # INTENSITY column — grows with terminal width
INNER=74                 # interior chars between outer │ │ (grows with terminal)
BW=11                    # sysmetric bar width: (INNER-39)/3 — recomputed per tick
MIN_INNER=74             # layout breaks below this; clamp as floor
MAX_INNER=200            # above this, rows stop being scan-able — clamp as ceiling

milog_update_geometry() {
    local cols
    cols=${MILOG_WIDTH:-0}
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=0
    if (( cols <= 0 )); then
        cols=$(tput cols 2>/dev/null || echo 80)
    fi
    local target=$(( cols - 2 ))   # reserve 2 chars for outer │ │
    (( target < MIN_INNER )) && target=$MIN_INNER
    (( target > MAX_INNER )) && target=$MAX_INNER
    INNER=$target
    W_BAR=$(( INNER - W_APP - W_REQ - W_ST - 11 ))
    # Sysmetric row is " CPU xxx% [bar]  MEM xxx% [bar]  DISK xxx% [bar]"
    # → 39 fixed chars + 3 bars. Reserve 1 trailing char so `]` never kisses
    # the right │. Floor BW at 5 so small terms stay legible.
    BW=$(( (INNER - 40) / 3 ))
    (( BW < 5 )) && BW=5
    return 0   # guard against set -e when BW>=5 makes `((…))` return 1
}
milog_update_geometry    # initialise for non-TUI modes that use draw_row

spc() { printf '%*s' "$1" ''; }
hrule() { printf '─%.0s' $(seq 1 "$1"); }

# Single-box rules — all share INNER=74
bdr_top() { printf "${W}┌$(hrule $((W_APP+2)))┬$(hrule $((W_REQ+2)))┬$(hrule $((W_ST+2)))┬$(hrule $((W_BAR+2)))┐${NC}\n"; }
bdr_hdr() { printf "${W}├$(hrule $((W_APP+2)))┼$(hrule $((W_REQ+2)))┼$(hrule $((W_ST+2)))┼$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_mid() { printf "${W}├$(hrule $((INNER)))┤${NC}\n"; }
bdr_sep() { printf "${W}├$(hrule $((W_APP+2)))┴$(hrule $((W_REQ+2)))┴$(hrule $((W_ST+2)))┴$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_bot() { printf "${W}└$(hrule $((INNER)))┘${NC}\n"; }

# Full-width content row: │ plain/colored content + padding │
# $1=plain_text (for measuring)  $2=colored_text (for printing)
# Plain must not contain any ANSI sequences.
draw_row() {
    local plain="$1" colored="$2"
    local pad=$(( INNER - ${#plain} ))
    printf "${W}│${NC}%b" "$colored"
    [[ $pad -gt 0 ]] && spc "$pad"
    printf "${W}│${NC}\n"
}

# Table data row — padding computed from plain args only
# $1=name $2=count $3=st_plain(10 chars) $4=st_colored $5=bars_plain $6=bars_colored $7=alert_color
trow() {
    local name="$1" count="$2" st_plain="$3" st_col="$4" bars_plain="$5" bars_col="$6" alert="${7:-}"
    local n_pad=$(( W_APP - ${#name}       ))
    local r_pad=$(( W_REQ - ${#count}      ))
    local b_pad=$(( W_BAR - ${#bars_plain} ))
    printf "${W}│${NC} %b%s${NC}" "$alert" "$name";  spc "$n_pad"
    printf " ${W}│${NC} %s"       "$count";           spc "$r_pad"
    printf " ${W}│${NC} %b"       "$st_col"
    printf " ${W}│${NC} %b"       "$bars_col";        spc "$b_pad"
    printf " ${W}│${NC}\n"
}

# Column header row (no color escape issues — plain printf)
hdr_row() {
    printf "${W}│${NC} %-${W_APP}s ${W}│${NC} %-${W_REQ}s ${W}│${NC} %-${W_ST}s ${W}│${NC} %-${W_BAR}s ${W}│${NC}\n" \
        "APP" "REQ/MIN" "STATUS" "INTENSITY"
}

