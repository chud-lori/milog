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

# GitHub repo that hosts prebuilt Go binaries (milog-web, milog-tui)
# under its Releases. Overridable for forks. The "latest" tag follows
# the most recent non-draft release automatically.
MILOG_RELEASE_REPO="${MILOG_RELEASE_REPO:-chud-lori/milog}"
# Default to the tracking `latest` endpoint — GitHub resolves it to
# whichever release is currently marked Latest. Pin to an exact tag
# (e.g. MILOG_RELEASE_TAG=v0.1.0) for reproducible installs in CI.
MILOG_RELEASE_TAG="${MILOG_RELEASE_TAG:-latest}"

# Cache-bust GitHub's raw-content CDN by default. Appends `?t=<epoch>` to
# the fetch URL (respecting any existing query string). Disable by setting
# MILOG_NO_CACHE_BUST=1 — primarily for reproducibility in CI, where an
# undetermined URL defeats artifact signing.
MILOG_NO_CACHE_BUST="${MILOG_NO_CACHE_BUST:-0}"

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

# ---- version + fingerprint helpers ------------------------------------------
# build.sh embeds `# MILOG_VERSION=…` and `# MILOG_BUILT=…` right after the
# shebang. These helpers extract them so the installer can report exactly
# what code it placed (or: whether it placed anything new at all).

# Print the embedded version line from a milog.sh file. Silent + empty on
# any error — callers treat missing fingerprint as "unknown" rather than
# failing. Only reads the first 10 lines so we don't grep 5000+ LOC just
# for a header that's always line 2.
_read_milog_version() {
    local f="$1"
    [[ -r "$f" ]] || { printf 'unknown'; return; }
    local v
    v=$(head -10 "$f" | awk -F= '/^# MILOG_VERSION=/ {print $2; exit}')
    printf '%s' "${v:-unknown}"
}

_read_milog_built() {
    local f="$1"
    [[ -r "$f" ]] || return 0
    local b
    b=$(head -10 "$f" | awk -F= '/^# MILOG_BUILT=/ {print $2; exit}')
    printf '%s' "$b"
}

# Portable md5 — GNU coreutils has md5sum, macOS has md5. Used for the
# "same bytes" check: if the already-installed milog and the fetched one
# hash identically, report "no change" instead of lying about an upgrade.
_md5() {
    local f="$1"
    [[ -r "$f" ]] || { printf ''; return; }
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "$f" 2>/dev/null | awk '{print $1}'
    elif command -v md5 >/dev/null 2>&1; then
        md5 -q "$f" 2>/dev/null
    fi
}

# ---- prebuilt-binary download (Go companion path) --------------------------
# Fetches milog-web / milog-tui from a GitHub Release asset that matches
# the host OS + architecture. Used in the curl-pipe install flow so end
# users don't need Go on their server — the toolchain work happens in CI.
#
# Silent no-op when the release doesn't publish a matching asset (e.g.
# the project hasn't cut its first binary release yet, or the arch isn't
# covered). Bash milog.sh still installs normally either way.

# Map `uname -m` to the arch slug goreleaser emits in artifact names.
# Covers the pairs .goreleaser.yaml ships: amd64 + arm64 on linux + darwin.
_release_arch_slug() {
    case "$(uname -m)" in
        x86_64|amd64)   echo amd64 ;;
        aarch64|arm64)  echo arm64 ;;
        *)              echo "unsupported" ;;
    esac
}

_release_os_slug() {
    case "$(uname -s)" in
        Linux)   echo linux ;;
        Darwin)  echo darwin ;;
        *)       echo unsupported ;;
    esac
}

# Resolve the "latest" tag to a concrete `vX.Y.Z` so we can build a stable
# archive URL. When MILOG_RELEASE_TAG is already a concrete tag, no-op.
# Prints empty + returns 0 when no release exists yet (fresh repo before
# the first tag); caller treats that as "skip prebuilt download".
_release_resolve_tag() {
    local tag="$MILOG_RELEASE_TAG"
    if [[ "$tag" != "latest" ]]; then
        printf '%s' "$tag"; return 0
    fi
    # GitHub's /releases/latest endpoint redirects to the concrete tag.
    # Parse the Location header without needing jq — single curl + awk.
    local loc
    loc=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/${MILOG_RELEASE_REPO}/releases/latest" 2>/dev/null) || return 0
    # loc looks like: https://github.com/<owner>/<repo>/releases/tag/vX.Y.Z
    [[ "$loc" =~ /tag/([^/?#]+) ]] || { printf ''; return 0; }
    printf '%s' "${BASH_REMATCH[1]}"
}

# Download one companion binary from the Release matching the resolved
# OS + arch. Writes to <dir>/<name> atomically. Silent return on any
# failure — prebuilt install is best-effort, bash milog.sh is the
# primary install path.
_release_download_binary() {
    local name="$1" dst_dir="$2" tag="$3" os="$4" arch="$5"
    local archive="milog_${tag#v}_${os}_${arch}.tar.gz"
    local url="https://github.com/${MILOG_RELEASE_REPO}/releases/download/${tag}/${archive}"
    local tmp
    tmp=$(mktemp -d) || return 1
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN

    if ! curl -fsSL --retry 2 --retry-delay 1 --max-time 60 -o "$tmp/a.tar.gz" "$url" 2>/dev/null; then
        return 1
    fi
    tar -xzf "$tmp/a.tar.gz" -C "$tmp" "$name" 2>/dev/null || return 1
    [[ -f "$tmp/$name" ]] || return 1

    local dst_tmp
    dst_tmp=$(mktemp "${dst_dir}/.${name}.install.XXXXXX") || return 1
    cp "$tmp/$name" "$dst_tmp"
    chmod 0755 "$dst_tmp"
    mv "$dst_tmp" "${dst_dir}/${name}"
    info "Installed ${name} → ${dst_dir}/${name} (from ${tag})"
}

# Top-level entry: try to fetch milog-web + milog-tui from the latest
# release. Prints one line per binary; silent when a binary isn't
# published for this arch. Never fails hard — bash milog.sh already
# installed, and a missing Go binary just means `milog tui` will print
# its install hint.
_release_install_companions() {
    local dst_dir="$1"
    local os arch tag
    os=$(_release_os_slug)
    arch=$(_release_arch_slug)
    if [[ "$os" == "unsupported" || "$arch" == "unsupported" ]]; then
        info "prebuilt binaries: skipped ($(uname -s)/$(uname -m) not in the release matrix)"
        return 0
    fi
    tag=$(_release_resolve_tag)
    if [[ -z "$tag" ]]; then
        info "prebuilt binaries: no release tagged yet — skipping (milog monitor / bash-only install still works)"
        return 0
    fi
    local downloaded=0 name
    for name in milog-web milog-tui; do
        if _release_download_binary "$name" "$dst_dir" "$tag" "$os" "$arch"; then
            downloaded=$((downloaded + 1))
        fi
    done
    if (( downloaded == 0 )); then
        info "prebuilt binaries: no matching assets on ${tag} for ${os}/${arch} — skipping"
    fi
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

    # Stop + remove the systemd unit if it's there (installed via
    # `milog alert on`). Silent on any failure — we're going to delete the
    # unit file anyway.
    if command -v systemctl >/dev/null 2>&1; then
        if [[ -f /etc/systemd/system/milog.service ]]; then
            info "Stopping + removing milog.service"
            systemctl stop    milog.service 2>/dev/null || true
            systemctl disable milog.service 2>/dev/null || true
            rm -f /etc/systemd/system/milog.service
            systemctl daemon-reload 2>/dev/null || true
        fi
    fi

    if [[ -e "$BIN_DST" ]]; then
        info "Removing $BIN_DST"
        rm -f "$BIN_DST"
    else
        info "Nothing at $BIN_DST — already clean"
    fi

    # Companion Go binaries (installed by install_go_companion() above
    # when a clone with built binaries was present).
    local companion_dir; companion_dir=$(dirname "$BIN_DST")
    local name
    for name in milog-web milog-tui; do
        local path="${companion_dir}/${name}"
        if [[ -e "$path" ]]; then
            info "Removing $path"
            rm -f "$path"
        fi
    done

    cat <<EOF

Uninstalled MiLog binary + systemd unit. Left in place (delete manually if desired):
  ~/.config/milog/        user config (webhook + thresholds)
  ~/.cache/milog/         alert cooldown state
  ~/.local/share/milog/   history database (if you enabled it)
EOF
}

# ---- install ----------------------------------------------------------------
usage() {
    cat <<EOF
Usage: install.sh [--with-geoip] [--with-web] [--bin PATH] [--script-url URL] [--uninstall]

  --with-geoip      install mmdblookup (for GeoIP enrichment in top/suspects)
  --with-web        install socat (for the 'milog web' dashboard)
  --bin PATH        install destination (default: /usr/local/bin/milog)
  --script-url URL  override milog.sh download URL (pipe-install mode)
  --uninstall       remove installed binary (keeps config and state dirs)

Core deps (gawk, curl, sqlite3) are always installed.
The --with-history flag is accepted silently for backward compatibility.

Go companion binaries (milog-web, milog-tui) are OPTIONAL. They get
picked up automatically when they're sitting next to install.sh — which
happens if you cloned the repo and ran \`bash build.sh\` yourself (the
contributor path). There's no prebuilt-binary distribution yet; that's
the 'goreleaser' chunk still on the roadmap.
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

    # Cache-bust by default — GitHub's raw CDN caches for a few minutes, which
    # made "I just pushed but install didn't pull the new code" a recurring
    # support question. Appending `?t=<epoch>` forces a fresh fetch.
    local fetch_url="$SCRIPT_URL"
    if [[ "$MILOG_NO_CACHE_BUST" != "1" ]]; then
        if [[ "$fetch_url" == *"?"* ]]; then
            fetch_url="${fetch_url}&t=$(date +%s)"
        else
            fetch_url="${fetch_url}?t=$(date +%s)"
        fi
    fi

    info "Downloading milog.sh from $fetch_url"
    local tmp
    tmp=$(mktemp) || die "mktemp failed"
    _CLEANUP_TMP="$tmp"
    trap 'rm -f "${_CLEANUP_TMP:-}"' EXIT
    if ! curl -fsSL --retry 3 --retry-delay 1 --max-time 30 \
            -o "$tmp" "$fetch_url"; then
        die "download failed from $fetch_url"
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
    local with_geoip=0 with_web=0 do_uninstall=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --with-geoip)   with_geoip=1;   shift ;;
            --with-web)     with_web=1;     shift ;;
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
    (( with_web ))   && deps+=(socat)

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

    # Read the fingerprint of the existing install (if any) and the fetched
    # source, so we can tell the user exactly what's happening.
    local old_version old_md5 new_version new_built new_md5
    old_version=$(_read_milog_version "$BIN_DST")
    old_md5=$(_md5 "$BIN_DST")
    new_version=$(_read_milog_version "$SCRIPT_SRC")
    new_built=$(_read_milog_built  "$SCRIPT_SRC")
    new_md5=$(_md5 "$SCRIPT_SRC")

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

    # Loud version signal — answers "did it actually update?" without
    # forcing the user to grep the binary afterwards.
    if [[ ! -e "$BIN_DST" ]] || [[ -z "$old_md5" ]]; then
        # (Shouldn't happen — we just mv'd — but don't lie if for some
        # reason the binary vanished.)
        info "Installed milog v=${new_version} (built ${new_built:-unknown})"
    elif [[ "$new_md5" == "$old_md5" ]]; then
        info "Already at milog v=${new_version} — no change"
    elif [[ "$old_version" == "unknown" ]]; then
        info "Installed milog v=${new_version} (built ${new_built:-unknown})  ${old_md5:0:7} → ${new_md5:0:7}"
    else
        info "Upgraded milog v=${old_version} → v=${new_version} (built ${new_built:-unknown})  ${old_md5:0:7} → ${new_md5:0:7}"
    fi

    # Install Go companion binaries (milog-web, milog-tui) when they're
    # sitting alongside this script — typical for a clone that ran
    # `bash build.sh` first. Placed next to milog at the same
    # dir as BIN_DST so the bash dispatcher's path walk finds them.
    #
    # Pipe-installs don't have these files; the block no-ops silently.
    install_go_companion() {
        local name="$1" src
        # Probe next to install.sh (clone layout).
        local self_path="${BASH_SOURCE[0]:-}"
        local self_dir=""
        if [[ "$self_path" == /* || "$self_path" == */* ]] && [[ -f "$self_path" ]]; then
            self_dir=$(cd -P "$(dirname "$self_path")" 2>/dev/null && pwd) || self_dir=""
        fi
        [[ -z "$self_dir" ]] && return 0
        src="$self_dir/go/bin/$name"
        [[ -x "$src" ]] || return 0

        local dst="${dst_dir}/${name}"
        local tmp_bin
        tmp_bin="$(mktemp "${dst_dir}/.${name}.install.XXXXXX")"
        cp "$src" "$tmp_bin"
        chmod 0755 "$tmp_bin"
        mv "$tmp_bin" "$dst"
        info "Installed ${name} → ${dst}"
    }
    install_go_companion milog-web
    install_go_companion milog-tui

    # Prebuilt binaries from GitHub Releases — only runs if the clone
    # path didn't already place them (the companion check above is
    # silent when go/bin/* doesn't exist, matching the curl-pipe flow).
    if [[ ! -x "${dst_dir}/milog-web" || ! -x "${dst_dir}/milog-tui" ]]; then
        _release_install_companions "$dst_dir"
    fi

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
