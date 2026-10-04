#!/usr/bin/env bash
# MiLog installer for Linux (apt, dnf, yum, pacman, apk). Uses the milog.sh next to this script, else downloads it:
#   curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash -s -- [--with-geoip]
# Flags: --with-geoip, --bin PATH, --script-url URL, --uninstall (see usage below).
# Alerts and the systemd unit come after install: sudo milog alert on URL
set -euo pipefail

# In pipe mode BASH_SOURCE[0] is not a real path, so the source is resolved later in resolve_script_src.
BIN_DST="${BIN_DST:-/usr/local/bin/milog}"
SCRIPT_URL="${MILOG_SCRIPT_URL:-https://raw.githubusercontent.com/chud-lori/milog/main/milog.sh}"
SCRIPT_SRC=""           # populated by resolve_script_src
_CLEANUP_TMP=""         # set if we downloaded — trap removes on exit

# Release repo for the prebuilt Go binaries; override for forks.
MILOG_RELEASE_REPO="${MILOG_RELEASE_REPO:-chud-lori/milog}"
# Pin an exact tag (e.g. v0.1.0) for reproducible installs.
MILOG_RELEASE_TAG="${MILOG_RELEASE_TAG:-latest}"

# Append ?t=<epoch> to dodge GitHub's raw CDN cache; MILOG_NO_CACHE_BUST=1 keeps the URL stable.
MILOG_NO_CACHE_BUST="${MILOG_NO_CACHE_BUST:-0}"

_green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
_yellow() { printf '\033[0;33m%s\033[0m\n' "$*" >&2; }
_red()    { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }

info() { _green  "== $*"; }
warn() { _yellow "!! $*"; }
die()  { _red    "!! $*"; exit 1; }

# Best-effort: last 3 commit subjects via one GitHub API call, parsed without jq; any failure or MILOG_NO_RECENT=1 skips it.
_print_recent_commits_hint() {
    [[ "${MILOG_NO_RECENT:-0}" == "1" ]] && return 0
    command -v curl >/dev/null 2>&1 || return 0

    local body
    body=$(curl -fsSL --max-time 5 \
        -H 'User-Agent: milog-install' \
        -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/${MILOG_RELEASE_REPO}/commits?per_page=3" \
        2>/dev/null) || return 0
    [[ -n "$body" ]] || return 0

    # Split on `,{"sha":"...","node_id":`; only top-level commits carry node_id, parents[] entries don't.
    local commits
    commits=$(printf '%s' "$body" \
        | sed -E 's/,\{"sha":"([0-9a-f]+)","node_id":/\n{"sha":"\1","node_id":/g; s/^\[//' \
        | head -3)
    [[ -n "$commits" ]] || return 0

    local sha msg
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        sha=$(printf '%s' "$line" \
            | grep -oE '"sha":"[0-9a-f]{40}"' \
            | head -1 \
            | sed -E 's/.*"([0-9a-f]{7})[0-9a-f]+".*/\1/')
        msg=$(printf '%s' "$line" \
            | grep -oE '"message":"[^"]*' \
            | head -1 \
            | sed -E 's/^"message":"//; s/\\[nrtu].*//')
        [[ -n "$sha" && -n "$msg" ]] && info "recent: $sha $msg"
    done <<< "$commits"
}

detect_pkg_manager() {
    local pm
    for pm in apt-get dnf yum pacman apk; do
        if command -v "$pm" >/dev/null 2>&1; then
            echo "$pm"
            return 0
        fi
    done
    echo "none"
}

# Per-distro package names; unlisted tools pass through unchanged.
pkg_name_for() {
    local tool="$1" pm="$2"
    case "${tool}:${pm}" in
        sqlite3:apt-get)                echo sqlite3 ;;
        sqlite3:dnf|sqlite3:yum)        echo sqlite ;;
        sqlite3:pacman|sqlite3:apk)     echo sqlite ;;
        mmdblookup:apt-get)             echo mmdb-bin ;;
        mmdblookup:dnf|mmdblookup:yum)  echo libmaxminddb ;;
        mmdblookup:pacman|mmdblookup:apk) echo libmaxminddb ;;
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
        apk)    apk add --no-cache "$@" ;;
        none)   die "no supported package manager found — install manually: $*" ;;
    esac
}


# Reads only the header lines; "unknown" when absent.
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

# md5sum or macOS md5, for the "no change" check.
_md5() {
    local f="$1"
    [[ -r "$f" ]] || { printf ''; return; }
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "$f" 2>/dev/null | awk '{print $1}'
    elif command -v md5 >/dev/null 2>&1; then
        md5 -q "$f" 2>/dev/null
    fi
}

# Prebuilt milog-web / milog-tui (and milog-probe on Linux) from GitHub Releases, so servers need no Go or clang.
# Best-effort: a missing asset leaves the bash install intact.

# Arch slugs goreleaser uses: amd64 and arm64.
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

# Resolves "latest" to a concrete tag; empty when no release exists yet.
_release_resolve_tag() {
    local tag="$MILOG_RELEASE_TAG"
    if [[ "$tag" != "latest" ]]; then
        printf '%s' "$tag"; return 0
    fi
    # /releases/latest redirects to /releases/tag/<tag>.
    local loc
    loc=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/${MILOG_RELEASE_REPO}/releases/latest" 2>/dev/null) || return 0
    [[ "$loc" =~ /tag/([^/?#]+) ]] || { printf ''; return 0; }
    printf '%s' "${BASH_REMATCH[1]}"
}

# SHA-256 via sha256sum or shasum; empty when neither exists.
_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    fi
}

# Atomic replace of one binary. Returns non-zero when the archive isn't published; dies when it fails checksums.txt.
_release_download_binary() {
    local name="$1" dst_dir="$2" tag="$3" os="$4" arch="$5"
    local archive="milog_${tag#v}_${os}_${arch}.tar.gz"
    local base="https://github.com/${MILOG_RELEASE_REPO}/releases/download/${tag}"
    local url="${base}/${archive}"
    local tmp
    tmp=$(mktemp -d) || return 1
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN

    if ! curl -fsSL --retry 2 --retry-delay 1 --max-time 60 -o "$tmp/a.tar.gz" "$url" 2>/dev/null; then
        return 1
    fi

    local want got
    if ! curl -fsSL --retry 2 --retry-delay 1 --max-time 60 -o "$tmp/checksums.txt" "${base}/checksums.txt" 2>/dev/null; then
        rm -rf "$tmp"
        die "${name}: could not fetch checksums.txt for ${tag}; refusing to install an unverified binary"
    fi
    want=$(awk -v f="$archive" '$2 == f {print $1; exit}' "$tmp/checksums.txt")
    if [[ -z "$want" ]]; then
        rm -rf "$tmp"
        die "${name}: ${archive} is not listed in checksums.txt for ${tag}; refusing to install"
    fi
    got=$(_sha256 "$tmp/a.tar.gz")
    if [[ -z "$got" ]]; then
        rm -rf "$tmp"
        die "${name}: need sha256sum or shasum to verify ${archive}; refusing to install"
    fi
    if [[ "$got" != "$want" ]]; then
        rm -rf "$tmp"
        die "${name}: checksum mismatch for ${archive} (expected ${want}, got ${got}); refusing to install"
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

# A missing binary is not fatal (milog.sh is already in place), but a failed checksum aborts the install.
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
    # goreleaser only builds milog-probe for linux.
    local names=(milog-web milog-tui)
    if [[ "$os" == "linux" ]]; then
        names+=(milog-probe)
    fi
    local downloaded=0 name
    for name in "${names[@]}"; do
        if _release_download_binary "$name" "$dst_dir" "$tag" "$os" "$arch"; then
            downloaded=$((downloaded + 1))
        fi
    done
    if (( downloaded == 0 )); then
        info "prebuilt binaries: no matching assets on ${tag} for ${os}/${arch} — skipping"
    fi
}

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

uninstall() {
    need_root

    # Units written by `milog alert on` and `milog probe install-service`.
    if command -v systemctl >/dev/null 2>&1; then
        local unit removed_units=0
        for unit in milog.service milog-probe.service; do
            if [[ -f "/etc/systemd/system/$unit" ]]; then
                info "Stopping + removing $unit"
                systemctl stop    "$unit" 2>/dev/null || true
                systemctl disable "$unit" 2>/dev/null || true
                rm -f "/etc/systemd/system/$unit"
                removed_units=1
            fi
        done
        if (( removed_units )); then
            systemctl daemon-reload 2>/dev/null || true
        fi
    fi

    # `milog web install-service` writes a user unit into the invoking
    # user's home; stop it through that user's manager when reachable.
    local web_user="${SUDO_USER:-root}" web_home web_unit
    web_home=$(getent passwd "$web_user" 2>/dev/null | cut -d: -f6) || web_home=""
    [[ -n "$web_home" ]] || web_home="${HOME:-/root}"
    web_unit="$web_home/.config/systemd/user/milog-web.service"
    if [[ -f "$web_unit" ]]; then
        info "Stopping + removing $web_unit"
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --user -M "${web_user}@" disable --now milog-web.service 2>/dev/null || true
        fi
        rm -f "$web_unit" "$web_home/.config/systemd/user/default.target.wants/milog-web.service"
    fi

    if [[ -e "$BIN_DST" ]]; then
        info "Removing $BIN_DST"
        rm -f "$BIN_DST"
    else
        info "Nothing at $BIN_DST — already clean"
    fi

    # Companions sit next to the main binary; milog-probe exists only on Linux.
    local companion_dir; companion_dir=$(dirname "$BIN_DST")
    local name
    for name in milog-web milog-tui milog-probe; do
        local path="${companion_dir}/${name}"
        if [[ -e "$path" ]]; then
            info "Removing $path"
            rm -f "$path"
        fi
    done

    cat <<EOF

Uninstalled MiLog binaries + systemd units. Left in place (delete manually if desired):
  ~/.config/milog/        user config (webhook + thresholds)
  ~/.cache/milog/         alert cooldown state
  ~/.local/share/milog/   history database (if you enabled it)
EOF
}

usage() {
    cat <<EOF
Usage: install.sh [--with-geoip] [--bin PATH] [--script-url URL] [--uninstall]

  --with-geoip      install mmdblookup (for GeoIP enrichment in top/suspects)
  --bin PATH        install destination (default: /usr/local/bin/milog)
  --script-url URL  override milog.sh download URL (pipe-install mode)
  --uninstall       remove installed binary (keeps config and state dirs)

Core deps (gawk, curl, sqlite3) are always installed.
The --with-history and --with-web flags are accepted silently for
backward compatibility (history is default; the web dashboard now ships
as a Go binary, no socat needed).

The Go companion binaries milog-web (the dashboard server) and
milog-tui are refreshed automatically from the latest GitHub release in
curl-pipe installs. They also get picked up when sitting next to
install.sh — that happens if you cloned the repo and ran \`bash build.sh\`
yourself (contributor path).
EOF
}

# Local milog.sh next to this script, else a download to a temp file removed on exit.
resolve_script_src() {
    # Under curl|bash, BASH_SOURCE[0] is a bare word like "bash"; its dirname "." would pick up a milog.sh in the caller's cwd.
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

    command -v curl >/dev/null 2>&1 \
        || die "curl not available and no local milog.sh found — install curl first"

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

    # The size check catches 404 pages; bash -n catches truncation.
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
            --with-web)     shift ;;   # deprecated no-op; web is a Go binary now
            --bin)          BIN_DST="${2:?--bin needs a path}"; shift 2 ;;
            --script-url)   SCRIPT_URL="${2:?--script-url needs a URL}"; shift 2 ;;
            --uninstall)    do_uninstall=1; shift ;;
            -h|--help)      usage; exit 0 ;;
            --with-systemd|--webhook)
                die "$1 is not supported — after install run: sudo milog alert on 'WEBHOOK_URL'" ;;
            *)              die "unknown option: $1" ;;
        esac
    done

    (( do_uninstall )) && { uninstall; exit 0; }

    need_root

    [[ "$(uname -s)" == "Linux" ]] \
        || die "unsupported platform: $(uname -s) — install.sh supports Linux only (apt-get/dnf/yum/pacman/apk)"

    local pm
    pm=$(detect_pkg_manager)
    [[ "$pm" == "none" ]] && die "no supported package manager (apt-get/dnf/yum/pacman/apk) found"
    info "Package manager: $pm"

    # mmdblookup stays opt-in because it needs a MaxMind account.
    local deps=(gawk curl sqlite3)
    (( with_geoip )) && deps+=(mmdblookup)

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

    local missing_after=()
    for tool in "${deps[@]}"; do
        command -v "$tool" >/dev/null 2>&1 || missing_after+=("$tool")
    done
    if (( ${#missing_after[@]} > 0 )); then
        warn "post-install still not on PATH: ${missing_after[*]}"
        warn "MiLog will degrade gracefully for missing optional tools"
    fi

    check_bash_version

    # Deferred so a pipe install has curl before it fetches.
    resolve_script_src

    local old_version old_md5 new_version new_built new_md5
    old_version=$(_read_milog_version "$BIN_DST")
    old_md5=$(_md5 "$BIN_DST")
    new_version=$(_read_milog_version "$SCRIPT_SRC")
    new_built=$(_read_milog_built  "$SCRIPT_SRC")
    new_md5=$(_md5 "$SCRIPT_SRC")

    # Copy to a sibling temp then mv, so Ctrl-C can't leave a partial binary.
    info "Installing milog → $BIN_DST"
    local dst_dir tmp
    dst_dir="$(dirname "$BIN_DST")"
    mkdir -p "$dst_dir"
    tmp="$(mktemp "${dst_dir}/.milog.install.XXXXXX")"
    cp "$SCRIPT_SRC" "$tmp"
    chmod 0755 "$tmp"
    mv "$tmp" "$BIN_DST"

    if [[ ! -e "$BIN_DST" ]] || [[ -z "$old_md5" ]]; then
        # Fresh install: there was no previous binary to compare.
        info "Installed milog v=${new_version} (built ${new_built:-unknown})"
    elif [[ "$new_md5" == "$old_md5" ]]; then
        info "Already at milog v=${new_version} — no change"
    elif [[ "$old_version" == "unknown" ]]; then
        info "Installed milog v=${new_version} (built ${new_built:-unknown})  ${old_md5:0:7} → ${new_md5:0:7}"
    else
        info "Upgraded milog v=${old_version} → v=${new_version} (built ${new_built:-unknown})  ${old_md5:0:7} → ${new_md5:0:7}"
    fi

    # A clone that ran `bash build.sh` has go/bin/* next to this script; install those beside milog.
    install_go_companion() {
        local name="$1" src
        local self_path="${BASH_SOURCE[0]:-}"
        local self_dir=""
        if [[ "$self_path" == /* || "$self_path" == */* ]] && [[ -f "$self_path" ]]; then
            self_dir=$(cd -P "$(dirname "$self_path")" 2>/dev/null && pwd) || self_dir=""
        fi
        [[ -z "$self_dir" ]] && return 1
        src="$self_dir/go/bin/$name"
        [[ -x "$src" ]] || return 1

        local dst="${dst_dir}/${name}"
        local tmp_bin
        tmp_bin="$(mktemp "${dst_dir}/.${name}.install.XXXXXX")"
        cp "$src" "$tmp_bin"
        chmod 0755 "$tmp_bin"
        mv "$tmp_bin" "$dst"
        info "Installed ${name} → ${dst}"
    }
    local local_companions=0
    if install_go_companion milog-web; then
        local_companions=$((local_companions + 1))
    fi
    if install_go_companion milog-tui; then
        local_companions=$((local_companions + 1))
    fi
    if install_go_companion milog-probe; then
        local_companions=$((local_companions + 1))
    fi

    # Without local builds, always refresh companions from the release so every binary reports the same version.
    if (( local_companions == 0 )); then
        _release_install_companions "$dst_dir"
    fi

    _print_recent_commits_hint

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
