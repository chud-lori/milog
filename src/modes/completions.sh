# ==============================================================================
# MODE: completions — install shell completion files
#
# Static completion scripts live under completions/ in the repo, baked into
# the milog bundle. This mode extracts them back out to the user's shell
# lookup paths. Two flavours:
#
#   milog completions install      # drop to /usr/share or ~/.local
#   milog completions <shell>      # print a single shell's completion to stdout
#                                    (for curl-pipe-bash install paths)
#
# Supported: bash / zsh / fish.
# ==============================================================================

# Embedded completion payloads live in the bundled milog.sh, written there
# by build.sh from completions/*.  Here we extract them via heredocs — the
# content is literally duplicated because bash can't do "read this file
# from inside the bundle" without the source layout.
#
# To stay DRY, we ship a sentinel approach: each completion body lives in
# its own helper below. If a user is on a clone (bundle built from src/),
# we defer to completions/*. Otherwise we use the fallback bodies.

_completions_src_dir() {
    # Return the repo's completions/ dir if we're running from a clone and
    # it exists; empty otherwise.
    local me self_dir
    me="${BASH_SOURCE[0]:-$0}"
    [[ -n "$me" && -f "$me" ]] || return 1
    self_dir=$(cd -P "$(dirname "$me")" 2>/dev/null && pwd) || return 1
    # Walk up — src/modes/completions.sh → repo/completions; or
    # /usr/local/bin/milog (bundle) → no src/ nearby.
    local candidate
    for candidate in "$self_dir/../../completions" "$self_dir/../completions" "$self_dir/completions"; do
        [[ -d "$candidate" ]] && { printf '%s' "$(cd -P "$candidate" && pwd)"; return 0; }
    done
    return 1
}

mode_completions() {
    local sub="${1:-help}"
    case "$sub" in
        install|-i)      _completions_install ;;
        bash|zsh|fish)   _completions_emit "$sub" ;;
        -h|--help|help)  _completions_help ;;
        *) echo -e "${R}Unknown completions subcommand:${NC} $sub" >&2; _completions_help; return 1 ;;
    esac
}

_completions_help() {
    echo -e "
${W}milog completions${NC} — shell completion installer

${W}USAGE${NC}
  ${C}milog completions install${NC}   install for bash / zsh / fish (auto-detects locations)
  ${C}milog completions bash${NC}       print bash completion to stdout
  ${C}milog completions zsh${NC}        print zsh completion to stdout
  ${C}milog completions fish${NC}       print fish completion to stdout

${W}Manual install (stdout forms)${NC}
  ${C}milog completions bash | sudo tee /usr/share/bash-completion/completions/milog${NC}
  ${C}milog completions zsh  > ~/.local/share/zsh/site-functions/_milog${NC}
  ${C}milog completions fish > ~/.config/fish/completions/milog.fish${NC}
"
}

_completions_install() {
    local src; src=$(_completions_src_dir) || src=""
    local installed=0

    # Target paths (system when root, user otherwise).
    local bash_dst zsh_dst fish_dst
    if [[ $(id -u) -eq 0 ]]; then
        bash_dst="/usr/share/bash-completion/completions/milog"
        zsh_dst="/usr/share/zsh/site-functions/_milog"
        fish_dst="/usr/share/fish/vendor_completions.d/milog.fish"
    else
        bash_dst="$HOME/.local/share/bash-completion/completions/milog"
        zsh_dst="$HOME/.local/share/zsh/site-functions/_milog"
        fish_dst="$HOME/.config/fish/completions/milog.fish"
    fi

    _write_completion() {
        local shell="$1" dst="$2"
        mkdir -p "$(dirname "$dst")" 2>/dev/null || return 1
        if [[ -n "$src" && -f "$src/$(_completions_filename "$shell")" ]]; then
            cp "$src/$(_completions_filename "$shell")" "$dst"
        else
            _completions_emit "$shell" > "$dst"
        fi
        echo -e "${G}✓${NC} $shell → $dst"
        installed=$((installed+1))
    }

    _write_completion bash "$bash_dst" || true
    _write_completion zsh  "$zsh_dst"  || true
    _write_completion fish "$fish_dst" || true

    if (( installed == 0 )); then
        echo -e "${R}nothing installed${NC}" >&2
        return 1
    fi
    echo
    echo -e "${D}open a new shell (or source your rc file) to pick them up${NC}"
}

_completions_filename() {
    case "$1" in
        bash) echo "milog.bash" ;;
        zsh)  echo "_milog" ;;
        fish) echo "milog.fish" ;;
    esac
}

_completions_emit() {
    local shell="$1"
    local src; src=$(_completions_src_dir) || src=""
    if [[ -n "$src" ]]; then
        local fname; fname=$(_completions_filename "$shell")
        if [[ -f "$src/$fname" ]]; then
            cat "$src/$fname"
            return 0
        fi
    fi
    # Fallback: the bundle ships a copy of each completion script inline
    # via build.sh heredocs. If that's missing too, we truly can't emit.
    local fn="_completions_payload_${shell}"
    if declare -F "$fn" >/dev/null 2>&1; then
        "$fn"
    else
        echo -e "${R}no completions payload available for shell '$shell'${NC}" >&2
        return 1
    fi
}
