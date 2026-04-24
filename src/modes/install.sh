# ==============================================================================
# MODE: install — on-demand feature installer
#
# Complement to install.sh's --with-X flags. Lets users add optional
# capabilities AFTER initial install, without re-running the one-liner with
# a different flag set. Idempotent: `install <feature>` is safe to re-run.
#
# Each feature is a declarative spec — package-manager deps + optional
# post-install hint. Binary downloads (for Go-binary features) will plug
# into the same shape once those land.
#
# Usage:
#   milog install list                   # matrix of features + installed status
#   milog install <feature>              # install feature + its system deps
#   milog install remove <feature>       # uninstall (keeps config/data)
#
# Scope today: geoip, web, history. Future: ebpf, audit, sse — they need
# the corresponding Go binaries to land first.
# ==============================================================================

# Feature catalog. Each feature is a colon-separated record:
#   name : check_cmd : apt_pkg : dnf_pkg : pacman_pkg : description
# check_cmd is what we run to decide "installed=yes/no".
_install_catalog() {
    cat <<"EOF"
geoip:mmdblookup:mmdb-bin:libmaxminddb:libmaxminddb:GeoIP COUNTRY column via MaxMind lookup
web:socat:socat:socat:socat:milog web dashboard (socat HTTP listener)
history:sqlite3:sqlite3:sqlite:sqlite:history DB for trend / diff / auto-tune
EOF
}

_install_pkg_for() {
    local feature="$1" pm="$2"
    local line; line=$(_install_catalog | awk -F':' -v f="$feature" '$1==f {print}')
    [[ -z "$line" ]] && return 1
    IFS=':' read -r _name _check apt dnf pac _desc <<< "$line"
    case "$pm" in
        apt-get) printf '%s' "$apt" ;;
        dnf|yum) printf '%s' "$dnf" ;;
        pacman)  printf '%s' "$pac" ;;
        *)       return 1 ;;
    esac
}

_install_detect_pm() {
    local pm
    for pm in apt-get dnf yum pacman; do
        command -v "$pm" >/dev/null 2>&1 && { echo "$pm"; return 0; }
    done
    echo none
}

_install_is_installed() {
    local feature="$1"
    local line; line=$(_install_catalog | awk -F':' -v f="$feature" '$1==f {print}')
    [[ -z "$line" ]] && return 1
    local check; check=$(echo "$line" | cut -d: -f2)
    command -v "$check" >/dev/null 2>&1
}

_install_desc() {
    _install_catalog | awk -F':' -v f="$1" '$1==f {print $6}'
}

mode_install() {
    local sub="${1:-list}"; shift 2>/dev/null || true
    case "$sub" in
        list|ls|'')      _install_list ;;
        remove|rm|uninstall) _install_remove "${1:-}" ;;
        -h|--help|help)  _install_help ;;
        *)               _install_add "$sub" ;;   # treat anything else as feature name
    esac
}

_install_list() {
    echo -e "\n${W}── MiLog: Feature install status ──${NC}\n"
    printf "  %-12s  %-16s  %s\n" "FEATURE" "STATUS" "DESCRIPTION"
    printf "  %-12s  %-16s  %s\n" "────────────" "────────────────" "──────────────────────────────"
    local line name desc state
    while IFS=':' read -r name _check _apt _dnf _pac desc; do
        [[ -z "$name" ]] && continue
        if _install_is_installed "$name"; then
            state="${G}✓ installed${NC}"
        else
            state="${D}— not installed${NC}"
        fi
        printf "  %-12s  %b  %s\n" "$name" "$state                " "$desc"
    done < <(_install_catalog)
    echo
    echo -e "${D}  milog install <feature>          add one${NC}"
    echo -e "${D}  milog install remove <feature>   drop it (keeps MiLog config)${NC}"
    echo
}

_install_add() {
    local feature="$1"
    if [[ -z "$feature" ]]; then
        echo -e "${R}usage:${NC} milog install <feature>" >&2
        return 1
    fi
    if ! _install_catalog | awk -F':' -v f="$feature" '$1==f {found=1} END{exit !found}'; then
        echo -e "${R}unknown feature:${NC} $feature" >&2
        echo -e "${D}  available:${NC} $(_install_catalog | cut -d: -f1 | paste -sd' ' -)"
        return 1
    fi

    if _install_is_installed "$feature"; then
        echo -e "${G}✓${NC} $feature is already installed"
        return 0
    fi

    local pm; pm=$(_install_detect_pm)
    if [[ "$pm" == "none" ]]; then
        echo -e "${R}no supported package manager found${NC} (apt-get/dnf/yum/pacman)" >&2
        return 1
    fi

    local pkg; pkg=$(_install_pkg_for "$feature" "$pm")
    if [[ -z "$pkg" ]]; then
        echo -e "${R}no package known for $feature on $pm${NC}" >&2
        return 1
    fi

    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${Y}system-package install needs root. Run:${NC}"
        echo -e "  ${C}sudo milog install $feature${NC}"
        echo
        echo -e "${D}  will run:${NC} ${pm} install ${pkg}"
        return 1
    fi

    echo -e "${W}Installing${NC} $feature ($pm install $pkg)"
    case "$pm" in
        apt-get) apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" ;;
        dnf)     dnf install -y "$pkg" ;;
        yum)     yum install -y "$pkg" ;;
        pacman)  pacman -S --noconfirm "$pkg" ;;
    esac || { echo -e "${R}install failed${NC}" >&2; return 1; }

    if _install_is_installed "$feature"; then
        echo -e "${G}✓${NC} $feature installed"
        _install_post_hint "$feature"
    else
        echo -e "${Y}warn:${NC} package installed but check command not found on PATH yet — open a new shell"
    fi
}

_install_remove() {
    local feature="$1"
    if [[ -z "$feature" ]]; then
        echo -e "${R}usage:${NC} milog install remove <feature>" >&2
        return 1
    fi
    if ! _install_is_installed "$feature"; then
        echo -e "${D}$feature is not installed${NC}"
        return 0
    fi
    echo -e "${Y}Note:${NC} MiLog's install subcommand intentionally does NOT auto-remove"
    echo -e "system packages — other tools on the host may depend on them."
    echo -e "To remove manually:"
    local pm; pm=$(_install_detect_pm)
    local pkg; pkg=$(_install_pkg_for "$feature" "$pm" 2>/dev/null)
    [[ -n "$pkg" ]] || pkg="(package unknown on $pm)"
    case "$pm" in
        apt-get) echo -e "  ${C}sudo apt-get remove ${pkg}${NC}" ;;
        dnf|yum) echo -e "  ${C}sudo ${pm} remove ${pkg}${NC}" ;;
        pacman)  echo -e "  ${C}sudo pacman -R ${pkg}${NC}" ;;
        *)       echo -e "  remove manually via your package manager" ;;
    esac
    echo
    echo -e "${D}MiLog auto-degrades when the feature's tool disappears (see \`milog doctor\`)${NC}"
}

_install_post_hint() {
    case "$1" in
        geoip)
            echo
            echo -e "${D}  Next:${NC} download a MaxMind GeoLite2 DB and point MiLog at it."
            echo -e "${D}    https://www.maxmind.com/en/geolite2/signup${NC}"
            echo -e "${D}    milog config set GEOIP_ENABLED 1${NC}"
            echo -e "${D}    milog config set MMDB_PATH /var/lib/GeoIP/GeoLite2-Country.mmdb${NC}"
            ;;
        web)
            echo
            echo -e "${D}  Next:${NC} ${C}milog web${NC}   or   ${C}milog web install-service${NC}"
            ;;
        history)
            echo
            echo -e "${D}  Next:${NC} ${C}milog config set HISTORY_ENABLED 1${NC} then restart the daemon"
            ;;
    esac
}

_install_help() {
    echo -e "
${W}milog install${NC} — on-demand feature installer

${W}USAGE${NC}
  ${C}milog install list${NC}                  matrix of features + installed status
  ${C}milog install <feature>${NC}             install the feature's system deps
  ${C}milog install remove <feature>${NC}      print the right apt/dnf remove command

${W}FEATURES${NC}
  geoip      GeoIP COUNTRY column (mmdblookup)
  web        milog web dashboard (socat)
  history    history DB for trend / diff / auto-tune (sqlite3)

${D}install.sh --with-X flags are the \"first-install\" path; this subcommand is for
later additions without rerunning install.sh.${NC}
"
}
