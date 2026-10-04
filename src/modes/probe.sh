# ==============================================================================
# MODE: probe — manage the eBPF probe sidecar (milog-probe) via systemd
#
# Counterpart to `milog web install-service`. The probe is Linux-only and
# privileged (eBPF needs root or CAP_BPF + CAP_PERFMON), so its unit lives
# in /etc/systemd/system/ rather than the user-mode location web uses.
#
# Subcommands:
#   milog probe status                run state + journal pointer
#   sudo milog probe install-service  write + enable + start the unit
#   sudo milog probe uninstall-service stop + disable + remove the unit
#
# Why HOME is baked into the unit:
#   The probe shells out to `milog _internal_alert` for every rule hit.
#   Since the probe runs as root, milog inherits root's $HOME and resolves
#   ALERT_STATE_DIR to /root/.cache/milog — invisible to the regular user
#   running `milog alerts` from their shell. Capturing the invoking user's
#   $HOME at install time and pinning it via Environment= keeps alerts +
#   silences in the user's cache where they belong. The alert child runs
#   as that user too (MILOG_PROBE_ALERT_USER), never as root.
# ==============================================================================

_PROBE_SYSTEMD_UNIT="/etc/systemd/system/milog-probe.service"

# File-probe comm allowlist written into the unit; override with MILOG_PROBE_FILE_ALLOWLIST at install time.
_PROBE_DEFAULT_FILE_ALLOWLIST="sshd,sshd-session,sudo,su,login,getty,agetty,cron,crond,anacron,systemd,systemd-logind,systemd-userdb,systemd-tmpfile,systemd-resolve,systemd-udevd,auditd,audisp-syslog,adduser,useradd,usermod,userdel,chpasswd,passwd,chage,visudo,pam_unix,nscd,nslcd,sssd,milog,milog-probe,ps,runc,runc:[2:INIT],watchtower,whoami"

_probe_service_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl is-active --quiet milog-probe.service 2>/dev/null
}

_probe_status() {
    if _probe_service_active; then
        local main_pid; main_pid=$(systemctl show --value -p MainPID milog-probe.service 2>/dev/null)
        echo -e "${G}running${NC}  (systemd)  pid=${main_pid:-?}"
        echo -e "${D}  unit:    ${_PROBE_SYSTEMD_UNIT}${NC}"
        echo -e "${D}  logs:    sudo journalctl -u milog-probe.service -f${NC}"
        echo -e "${D}  recent:  milog alerts 1h${NC}"
    else
        echo -e "${D}not running${NC}"
        if [[ -f "$_PROBE_SYSTEMD_UNIT" ]]; then
            echo -e "${D}  unit installed but inactive — try:${NC}"
            echo -e "${D}    sudo systemctl start milog-probe.service${NC}"
            echo -e "${D}    sudo journalctl -u milog-probe.service -b   # last-boot logs${NC}"
        fi
    fi
}

# Same lookup order as _web_go_binary.
_probe_binary() {
    if [[ -n "${MILOG_PROBE_BIN:-}" && -x "$MILOG_PROBE_BIN" ]]; then
        printf '%s' "$MILOG_PROBE_BIN"; return 0
    fi
    local candidate
    for candidate in \
        /usr/local/libexec/milog/milog-probe \
        /usr/local/bin/milog-probe; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    local self="${BASH_SOURCE[0]}"
    [[ "$self" != /* ]] && self="$(cd "$(dirname "$self")" && pwd)/$(basename "$self")"
    local self_dir; self_dir=$(cd "$(dirname "$self")" && pwd)
    for candidate in "$self_dir/go/bin/milog-probe" "$self_dir/../go/bin/milog-probe"; do
        [[ -x "$candidate" ]] && { printf '%s' "$candidate"; return 0; }
    done
    return 1
}

_probe_no_binary_error() {
    printf '%b' "
${R}milog-probe binary not found.${NC}

The eBPF probe is a small Go binary (Linux only, ~5 MB). It must be on
disk for the systemd unit to start. Pick one:

  ${W}1. Run install.sh (recommended)${NC}
     ${D}curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash${NC}
     ${D}install.sh fetches milog-probe from the latest GitHub release${NC}
     ${D}as part of the Linux install path.${NC}

  ${W}2. Override the path${NC}
     ${D}MILOG_PROBE_BIN=/path/to/milog-probe sudo -E milog probe install-service${NC}

" >&2
}

# Args: probe_bin target_user target_home target_config allowlist caps
_probe_unit() {
    cat <<EOF
[Unit]
Description=MiLog eBPF probe (exec / file / net / ptrace / kmod / retrans / syscall-rate / bpf-load)
Documentation=https://github.com/chud-lori/milog
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=${1}
Restart=on-failure
RestartSec=5s
# HOME + MILOG_CONFIG point at the invoking user's home so probe-fired
# alerts route through that user's bash config (DISCORD_WEBHOOK, silences,
# alerts.log) rather than root's. Edit + daemon-reload + restart to retune.
Environment=HOME=${3}
Environment=MILOG_CONFIG=${4}
Environment=MILOG_PROBE_FILE_ALLOWLIST=${5}
# Alerts run as this user so their config and hooks never execute as root.
Environment=MILOG_PROBE_ALERT_USER=${2}

# ProtectHome / ProtectSystem=strict stay off: the alert child writes the user's ~/.cache/milog.
CapabilityBoundingSet=${6}
NoNewPrivileges=yes
ProtectSystem=full
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
}

_probe_service_install() {
    local kernel; kernel=$(uname -s 2>/dev/null)
    if [[ "$kernel" != "Linux" ]]; then
        echo -e "${R}milog-probe is Linux-only (eBPF doesn't exist on $kernel)${NC}" >&2
        return 1
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${R}systemctl not found — this host doesn't use systemd${NC}" >&2
        return 1
    fi
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${R}milog probe install-service needs root${NC}" >&2
        echo -e "${D}  eBPF + writing to /etc/systemd/system/ both require it${NC}" >&2
        echo -e "${D}  retry:  sudo milog probe install-service${NC}" >&2
        return 1
    fi
    local probe_bin
    probe_bin=$(_probe_binary) || { _probe_no_binary_error; return 1; }
    probe_bin=$(readlink -f "$probe_bin")
    if ! _root_trusted_path "$probe_bin"; then
        echo -e "${R}refusing to run ${probe_bin} as root: it or its directory is not root-owned or is group/other-writable${NC}" >&2
        echo -e "${D}  fix:  sudo install -o root -g root -m 0755 ${probe_bin} /usr/local/bin/milog-probe${NC}" >&2
        return 1
    fi

    # SUDO_USER, else logname, else root.
    local target_user="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
    local target_home
    target_home=$(getent passwd "$target_user" 2>/dev/null | cut -d: -f6)
    [[ -n "$target_home" ]] || target_home="/home/$target_user"
    [[ -d "$target_home" ]] || target_home="/root"
    local target_config="${target_home}/.config/milog/config.sh"

    if [[ ! -f "$target_config" ]]; then
        echo -e "${Y}warning: ${target_config} not found${NC}" >&2
        echo -e "${D}  alerts will fall back to defaults until you run:${NC}" >&2
        echo -e "${D}    milog config init   (as ${target_user}, not root)${NC}" >&2
        echo -e "${D}    milog config set DISCORD_WEBHOOK \"https://...\"${NC}" >&2
    fi

    local allowlist="${MILOG_PROBE_FILE_ALLOWLIST:-$_PROBE_DEFAULT_FILE_ALLOWLIST}"

    # CAP_BPF / CAP_PERFMON only exist from 5.8; older kernels gate eBPF on CAP_SYS_ADMIN.
    local caps="CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SETUID CAP_SETGID"
    local kver; kver=$(uname -r 2>/dev/null)
    local kmaj="${kver%%.*}" kmin; kmin="${kver#*.}"; kmin="${kmin%%[!0-9]*}"
    if [[ "$kmaj" =~ ^[0-9]+$ && "$kmin" =~ ^[0-9]+$ ]] && (( kmaj < 5 || (kmaj == 5 && kmin < 8) )); then
        caps="$caps CAP_SYS_ADMIN"
    fi

    _probe_unit "$probe_bin" "$target_user" "$target_home" "$target_config" "$allowlist" "$caps" \
        > "$_PROBE_SYSTEMD_UNIT"

    echo -e "${G}✓${NC} wrote $_PROBE_SYSTEMD_UNIT"

    systemctl daemon-reload 2>/dev/null \
        || { echo -e "${R}systemctl daemon-reload failed${NC}" >&2; return 1; }
    if ! systemctl enable --now milog-probe.service 2>&1; then
        echo -e "${R}failed to enable milog-probe.service${NC}" >&2
        echo -e "${D}  tail logs: sudo journalctl -u milog-probe.service -b${NC}" >&2
        return 1
    fi

    echo -e "${G}✓${NC} systemctl enable --now milog-probe.service"

    printf '%b' "
${W}milog-probe.service${NC} installed and running.

  ${D}invoking user: ${target_user}  →  alerts route through ${target_config}${NC}

  ${W}manage:${NC}
    sudo systemctl status   milog-probe.service
    sudo systemctl restart  milog-probe.service
    sudo journalctl -u milog-probe.service -f      ${D}# live log stream${NC}
    sudo milog probe uninstall-service             ${D}# remove the unit${NC}

  ${W}retune the file allowlist:${NC}
    sudoedit ${_PROBE_SYSTEMD_UNIT}                 ${D}# edit Environment=MILOG_PROBE_FILE_ALLOWLIST${NC}
    sudo systemctl daemon-reload && sudo systemctl restart milog-probe.service

"
}

_probe_service_uninstall() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${D}systemctl not found — nothing to uninstall${NC}"
        return 0
    fi
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${R}milog probe uninstall-service needs root${NC}" >&2
        echo -e "${D}  retry:  sudo milog probe uninstall-service${NC}" >&2
        return 1
    fi
    if [[ -f "$_PROBE_SYSTEMD_UNIT" ]]; then
        systemctl stop    milog-probe.service 2>/dev/null || true
        systemctl disable milog-probe.service 2>/dev/null || true
        rm -f "$_PROBE_SYSTEMD_UNIT"
        systemctl daemon-reload 2>/dev/null || true
        echo -e "${G}✓${NC} milog-probe.service stopped, disabled, removed"
    else
        echo -e "${D}no unit at $_PROBE_SYSTEMD_UNIT${NC}"
    fi
}

mode_probe() {
    case "${1:-}" in
        status)            _probe_status; return ;;
        install-service)   _probe_service_install; return ;;
        uninstall-service) _probe_service_uninstall; return ;;
        ""|-h|--help|help)
            printf '%b' "
${W}milog probe${NC} — manage the eBPF probe sidecar (Linux only)

  ${W}USAGE${NC}
    milog probe status                  run state + log pointer
    sudo milog probe install-service    write + enable + start systemd unit
    sudo milog probe uninstall-service  stop + disable + remove the unit

  ${D}The probe runs as a system service (root) and shells out to milog
  for every rule hit. HOME + MILOG_CONFIG in the unit pin to the user
  who ran install-service so alerts run as that user and route through
  their webhook config + silences, not root's.${NC}

  ${W}covers:${NC}
    exec  ·  tcp connect  ·  file open  ·  ptrace  ·  kmod load
    tcp retransmit  ·  syscall rate (Welford σ)  ·  bpf prog load

"
            return 0 ;;
        *)
            echo -e "${R}usage: milog probe [status|install-service|uninstall-service]${NC}" >&2
            return 1 ;;
    esac
}
