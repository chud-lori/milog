# Monitor table geometry. Row: " " app " │ " req " │ " status " │ " bar " " = W_APP+W_REQ+W_ST+W_BAR+11.
# milog_update_geometry runs every render tick and gives spare width to the INTENSITY (sparkline) column.
# Set MILOG_WIDTH=N to pin the width on terminals that misreport cols.
W_APP=10; W_REQ=8; W_ST=10
W_BAR=35                 # INTENSITY column — grows with terminal width
INNER=74                 # interior chars between outer │ │ (grows with terminal)
BW=11                    # sysmetric bar width: (INNER-40)/3 — recomputed per tick
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
    # The sysmetric row has 39 fixed chars plus 3 bars; one spare char keeps `]` off the right border.
    BW=$(( (INNER - 40) / 3 ))
    (( BW < 5 )) && BW=5
    return 0   # guard against set -e when BW>=5 makes `((…))` return 1
}
milog_update_geometry    # initialise for non-TUI modes that use draw_row

spc() { printf '%*s' "$1" ''; }
hrule() { printf '─%.0s' $(seq 1 "$1"); }

bdr_top() { printf "${W}┌$(hrule $((W_APP+2)))┬$(hrule $((W_REQ+2)))┬$(hrule $((W_ST+2)))┬$(hrule $((W_BAR+2)))┐${NC}\n"; }
bdr_hdr() { printf "${W}├$(hrule $((W_APP+2)))┼$(hrule $((W_REQ+2)))┼$(hrule $((W_ST+2)))┼$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_mid() { printf "${W}├$(hrule $((INNER)))┤${NC}\n"; }
bdr_sep() { printf "${W}├$(hrule $((W_APP+2)))┴$(hrule $((W_REQ+2)))┴$(hrule $((W_ST+2)))┴$(hrule $((W_BAR+2)))┤${NC}\n"; }
bdr_bot() { printf "${W}└$(hrule $((INNER)))┘${NC}\n"; }

# $1 is the plain text used for width (no ANSI), $2 the coloured text printed.
draw_row() {
    local plain="$1" colored="$2"
    local pad=$(( INNER - ${#plain} ))
    printf "${W}│${NC}%b" "$colored"
    [[ $pad -gt 0 ]] && spc "$pad"
    printf "${W}│${NC}\n"
}

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

hdr_row() {
    printf "${W}│${NC} %-${W_APP}s ${W}│${NC} %-${W_REQ}s ${W}│${NC} %-${W_ST}s ${W}│${NC} %-${W_BAR}s ${W}│${NC}\n" \
        "APP" "REQ/MIN" "STATUS" "INTENSITY"
}

