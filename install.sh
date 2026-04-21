#!/usr/bin/env bash
# ==============================================================================
# MiLog installer — Linux (Debian/Ubuntu, RHEL/Fedora/Rocky, Arch).
#
# Works two ways:
#
#   1) One-liner (via curl-pipe-bash) — downloads milog.sh from GitHub:
#        curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh \
#          | sudo bash
#        curl -fsSL https://.../install.sh | sudo bash -s -- --with-history
#
#   2) From a clone — uses the milog.sh that sits next to this script:
#        git clone https://github.com/chud-lori/milog.git /opt/milog
#        cd /opt/milog && sudo ./install.sh
#
# Installs gawk + curl + sqlite3 by default. `--with-geoip` adds mmdblookup
# for the optional GeoIP COUNTRY column. Then places milog.sh at
# /usr/local/bin/milog.
#
# Flags:
#   --with-geoip           install mmdblookup for GeoIP enrichment
#   --with-systemd         write + enable /etc/systemd/system/milog.service
#                          so `milog daemon` survives reboots + ssh disconnect
#   --webhook URL          pre-configure DISCORD_WEBHOOK + ALERTS_ENABLED=1
#                          in the target user's config file
#   --with-history         (deprecated — sqlite3 is installed by default)
#   --bin PATH             install destination (default: /usr/local/bin/milog)
#   --script-url URL       override milog.sh source URL (pipe mode)
#   --uninstall            remove binary + systemd unit (configs preserved)
# ==============================================================================
set -euo pipefail

# ---- locations --------------------------------------------------------------
# In pipe mode BASH_SOURCE[0] is empty or a pipe path — we resolve the source
# lazily in resolve_script_src(), after we've confirmed curl is available.
BIN_DST="${BIN_DST:-/usr/local/bin/milog}"
SCRIPT_URL="${MILOG_SCRIPT_URL:-https://raw.githubusercontent.com/chud-lori/milog/main/milog.sh}"
SCRIPT_SRC=""           # populated by resolve_script_src
_CLEANUP_TMP=""         # set if we downloaded — trap removes on exit

# ---- tiny logging -----------------------------------------------------------
_green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
_yellow() { printf '\033[0;33m%s\033[0m\n' "$*" >&2; }
_red()    { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }

info() { _green  "== $*"; }
warn() { _yellow "!! $*"; }
die()  { _red    "!! $*"; exit 1; }

# ---- package manager detection ----------------------------------------------
detect_pkg_manager() {
    local pm
    for pm in apt-get dnf yum pacman; do
        if command -v "$pm" >/dev/null 2>&1; then
            echo "$pm"
            return 0
        fi
    done
    echo "none"
}

# Translate abstract tool names to per-distro package names. Only listed
# packages need per-distro mapping; everything else passes through.
pkg_name_for() {
    local tool="$1" pm="$2"
    case "${tool}:${pm}" in
        sqlite3:apt-get)                echo sqlite3 ;;
        sqlite3:dnf|sqlite3:yum)        echo sqlite ;;
        sqlite3:pacman)                 echo sqlite ;;
        mmdblookup:apt-get)             echo mmdb-bin ;;
        mmdblookup:dnf|mmdblookup:yum)  echo libmaxminddb ;;
        mmdblookup:pacman)              echo libmaxminddb ;;
        *)                              echo "$tool" ;;
    esac
}

pkg_install() {
    local pm="$1"; shift
    case "$pm" in
        apt-get)
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
            ;;
        dnf)    dnf    install -y "$@" ;;
        yum)    yum    install -y "$@" ;;
        pacman) pacman -S --noconfirm "$@" ;;
        none)   die "no supported package manager found — install manually: $*" ;;
    esac
}

# ---- guards -----------------------------------------------------------------
need_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "run as root (try: sudo $0 $*)"
    fi
}

check_bash_version() {
    local major="${BASH_VERSINFO[0]:-3}"
    if (( major < 4 )); then
        warn "current shell is bash ${BASH_VERSION}; MiLog modes (monitor/daemon/…) need bash 4+"
        warn "on macOS use homebrew's bash; on Linux most distros ship bash 4+"
    fi
}

# ---- uninstall --------------------------------------------------------------
uninstall() {
    need_root
    if [[ -e "$BIN_DST" ]]; then
        info "Removing $BIN_DST"
        rm -f "$BIN_DST"
    else
        info "Nothing at $BIN_DST — already clean"
    fi
    cat <<EOF

Uninstalled MiLog binary. Left in place (delete manually if desired):
  ~/.config/milog/        user config
  ~/.cache/milog/         alert cooldown state
  ~/.local/share/milog/   history database (if you enabled it)
  /etc/systemd/system/milog.service   (if you wrote a unit file)
EOF
}

# ---- install ----------------------------------------------------------------
usage() {
    cat <<EOF
Usage: install.sh [--with-geoip] [--bin PATH] [--script-url URL] [--uninstall]

  --with-geoip      install mmdblookup (for GeoIP enrichment in top/suspects)
  --bin PATH        install destination (default: /usr/local/bin/milog)
  --script-url URL  override milog.sh download URL (pipe-install mode)
  --uninstall       remove installed binary (keeps config and state dirs)

Core deps (gawk, curl, sqlite3) are always installed.
The --with-history flag is accepted silently for backward compatibility.
EOF
}

# Resolve where to pull milog.sh from:
#   - if this script is on disk with milog.sh alongside, use the local file
#   - otherwise (curl|bash mode), download from SCRIPT_URL into a tempfile
# The downloaded file is removed on exit via the trap set below.
resolve_script_src() {
    # Trust BASH_SOURCE as a "local clone" signal only when it looks like a
    # real file path (absolute or dir-prefixed). In curl|bash mode bash
    # sets BASH_SOURCE[0] to something like "bash" or "main" — dirname of
    # that collapses to "." and would pick up any milog.sh in the caller's
    # cwd, which is wrong.
    local self_path="${BASH_SOURCE[0]:-}"
    if [[ "$self_path" == /* || "$self_path" == */* ]] && [[ -f "$self_path" ]]; then
        local self_dir
        self_dir=$(cd -P "$(dirname "$self_path")" 2>/dev/null && pwd) || self_dir=""
        if [[ -n "$self_dir" && -f "$self_dir/milog.sh" ]]; then
            SCRIPT_SRC="$self_dir/milog.sh"
            info "Using local milog.sh at $SCRIPT_SRC"
            return 0
        fi
    fi

    # Pipe-install path: we need curl (which got us here) to fetch milog.sh.
    command -v curl >/dev/null 2>&1 \
        || die "curl not available and no local milog.sh found — install curl first"
    info "Downloading milog.sh from $SCRIPT_URL"
    local tmp
    tmp=$(mktemp) || die "mktemp failed"
    _CLEANUP_TMP="$tmp"
    trap 'rm -f "${_CLEANUP_TMP:-}"' EXIT
    if ! curl -fsSL --retry 3 --retry-delay 1 --max-time 30 \
            -o "$tmp" "$SCRIPT_URL"; then
        die "download failed from $SCRIPT_URL"
    fi

    # Sanity: the downloaded file must look like our script. Size guard
    # catches 404 HTML pages; bash -n catches garbage or truncation.
    local size; size=$(wc -c < "$tmp" 2>/dev/null || echo 0)
    (( size >= 1000 )) || die "downloaded file is suspiciously small (${size} bytes) — aborting"
    head -1 "$tmp" | grep -q '^#!.*bash' \
        || die "downloaded file is not a bash script — aborting"
    bash -n "$tmp" \
        || die "downloaded file has syntax errors — aborting"

    SCRIPT_SRC="$tmp"
}

main() {
    local with_geoip=0 do_uninstall=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --with-geoip)   with_geoip=1;   shift ;;
            --with-history) shift ;;   # deprecated no-op; sqlite3 is default
            --bin)          BIN_DST="${2:?--bin needs a path}"; shift 2 ;;
            --script-url)   SCRIPT_URL="${2:?--script-url needs a URL}"; shift 2 ;;
            --uninstall)    do_uninstall=1; shift ;;
            -h|--help)      usage; exit 0 ;;
            *)              die "unknown option: $1" ;;
        esac
    done

    (( do_uninstall )) && { uninstall; exit 0; }

    need_root

    local pm
    pm=$(detect_pkg_manager)
    [[ "$pm" == "none" ]] && die "no supported package manager (apt-get/dnf/yum/pacman) found"
    info "Package manager: $pm"

    # Abstract-name dependency list. gawk is preferred over busybox/mawk
    # for speed on large logs; curl is required for Discord webhooks;
    # sqlite3 powers the history/trend/diff modes and is cheap enough to
    # always install. mmdblookup stays opt-in (needs a MaxMind account).
    local deps=(gawk curl sqlite3)
    (( with_geoip )) && deps+=(mmdblookup)

    # Only install what's missing — idempotent reruns stay fast.
    local need_install=() tool resolved
    for tool in "${deps[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            continue
        fi
        resolved=$(pkg_name_for "$tool" "$pm")
        need_install+=("$resolved")
    done

    if (( ${#need_install[@]} > 0 )); then
        info "Installing: ${need_install[*]}"
        pkg_install "$pm" "${need_install[@]}"
    else
        info "All required tools already present"
    fi

    # Sanity-check that the intended tools are now callable.
    local missing_after=()
    for tool in "${deps[@]}"; do
        command -v "$tool" >/dev/null 2>&1 || missing_after+=("$tool")
    done
    if (( ${#missing_after[@]} > 0 )); then
        warn "post-install still not on PATH: ${missing_after[*]}"
        warn "MiLog will degrade gracefully for missing optional tools"
    fi

    check_bash_version

    # Resolve the milog.sh source (local clone or remote fetch). Deferred
    # until now so a pipe-install has curl installed before we try to use it.
    resolve_script_src

    # Atomic-ish copy: write to a sibling temp then mv to avoid a partial
    # binary if the user ctrl-Cs mid-install.
    info "Installing milog → $BIN_DST"
    local dst_dir tmp
    dst_dir="$(dirname "$BIN_DST")"
    mkdir -p "$dst_dir"
    tmp="$(mktemp "${dst_dir}/.milog.install.XXXXXX")"
    cp "$SCRIPT_SRC" "$tmp"
    chmod 0755 "$tmp"
    mv "$tmp" "$BIN_DST"

    info "MiLog installed. Try:"
    cat <<'NEXT'

    milog help
    milog config init
    milog monitor

Enable Discord alerts (optional):

    milog config set DISCORD_WEBHOOK "https://discord.com/api/webhooks/ID/TOKEN"
    milog config set ALERTS_ENABLED 1
    milog daemon     # or wire up the systemd unit from README.md

Re-run with --with-history or --with-geoip to add optional tools later.
NEXT
}

main "$@"
