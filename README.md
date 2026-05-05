# MiLog

Bash nginx + system monitor. TUI dashboard, read-only web UI with
SSE live-tail, log tailing, heuristic scanner/exploit detection,
multi-destination alerts (Discord / Slack / Telegram / Matrix),
headless daemon, historical metrics with σ-based anomaly detection,
host-integrity audits (FIM / persistence / ports / YARA / accounts /
rootkit), and an optional **eBPF probe sidecar** that streams kernel
events (exec / tcp / file / ptrace / kmod / retransmit / syscall-rate /
bpf-load) through the same alert pipeline.

The shipping artifact is still a single file (`milog.sh` → `/usr/local/bin/milog`),
but it's **built from modular source under [`src/`](src/README.md)** by
[`build.sh`](build.sh). Users install one file; contributors edit small ones.

## Docs

Everything in-depth lives under [`docs/`](docs/) — skim the
[docs index](docs/README.md) or jump straight in:

- [**Configuration**](docs/configuration.md) — variables, env overrides, nginx `log_format`
- [**Alerts**](docs/alerts.md) — Discord / Slack / Telegram / Matrix setup, rule catalog, history
- [**Host integrity audits**](docs/audit.md) — `milog audit` (fim / rootkit / persistence / ports / accounts / yara), provocations to verify detection
- [**Web dashboard**](docs/web-dashboard.md) — `milog web`, systemd user service, SSH / Tailscale / Cloudflare Tunnel exposure patterns
- [**Historical metrics**](docs/historical-metrics.md) — SQLite time series, `trend` / `diff` / `auto-tune`
- [**`milog daemon`**](docs/daemon.md) — headless mode, systemd service, permissions
- [**Kernel observability (`milog probe`)**](docs/probe.md) — eBPF sidecar, the 8 probes, `install-service`, allowlist tuning
- [**GeoIP enrichment**](docs/geoip.md) — MaxMind license + weekly auto-refresh
- [**Troubleshooting**](docs/troubleshooting.md) — `milog doctor` + common failure modes

Plus: [ARCHITECTURE.md](ARCHITECTURE.md) for contributors and
[SERVER_HARDENING.md](SERVER_HARDENING.md) for pairing milog with real
server hardening.

## Requirements

Linux, bash 4+, coreutils, `ps`, `df`, `uptime`, read access to
`/var/log/nginx/*.access.log`. Everything else (gawk, curl, sqlite3,
optionally mmdblookup, plus the `milog-web` / `milog-tui` Go binaries)
is handled by `install.sh`.

## Install

### Native package (preferred when available)

GitHub Releases ship `.deb`, `.rpm`, and `.apk` packages alongside the
tarballs. Pulls in `bash` + `coreutils` + `curl` + `gawk` automatically
through your distro's package manager:

```bash
# Debian / Ubuntu
curl -fsSL -o milog.deb https://github.com/chud-lori/milog/releases/latest/download/milog_<VER>_linux_amd64.deb
sudo apt install ./milog.deb

# Fedora / Rocky / RHEL
curl -fsSL -o milog.rpm https://github.com/chud-lori/milog/releases/latest/download/milog_<VER>_linux_amd64.rpm
sudo dnf install ./milog.rpm

# Alpine
curl -fsSL -o milog.apk https://github.com/chud-lori/milog/releases/latest/download/milog_<VER>_linux_amd64.apk
sudo apk add --allow-untrusted ./milog.apk
```

Replace `<VER>` with the [latest release tag](https://github.com/chud-lori/milog/releases/latest)
(or omit the version and use the unversioned `latest` redirect manually).
The packages drop `milog`, `milog-web`, and `milog-tui` into `/usr/bin`,
plus shell completions and docs under `/usr/share`.

### Curl one-liner (any Linux/macOS)

Drops `milog` + Go binaries into `/usr/local/bin`; uses your distro's
package manager to ensure `gawk` / `curl` / `sqlite3` are present:

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash
```

Opt-in extras:

```bash
# GeoIP enrichment (adds mmdblookup; also needs a MaxMind MMDB later)
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh \
  | sudo bash -s -- --with-geoip
```

The web dashboard ships as the `milog-web` Go binary — `install.sh`
fetches it from the latest GitHub release alongside `milog` itself, so
no separate flag and no system listener (socat / ncat) is needed.

### From a clone (contributors)

Installer auto-detects and uses the local `milog.sh`:

```bash
git clone https://github.com/chud-lori/milog.git /opt/milog
cd /opt/milog
sudo ./install.sh
sudo ./install.sh --uninstall   # keeps ~/.config/milog/, ~/.cache/milog/
```

Verify: `milog help`. Then `milog doctor` — checks every optional
capability (sqlite3, geoip, webhook, log format, systemd units) and
prints a one-line fix for each degraded piece.

## 5-minute quick start

```bash
milog monitor              # bash dashboard — CPU/MEM/DISK + per-app nginx table
milog tui                  # richer bubbletea TUI (same data; needs milog-tui Go binary)
# q quit   p pause   r refresh   +/- change refresh rate

# Turn on Discord alerts in one command (installs systemd service too)
sudo milog alert on 'https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN'
milog alert status
milog alert test

# Turn on historical metrics so trend / diff / auto-tune have data
milog config set HISTORY_ENABLED 1
sudo systemctl restart milog.service

# Investigate a suspicious IP
milog attacker 13.86.116.180

# What fired overnight?
milog alerts 24h

# Linux only — install the eBPF probe sidecar (exec / file / net / ptrace
# / kmod / retransmit / syscall-rate / bpf-load watchers fire through the
# same alert pipeline)
sudo milog probe install-service
sudo journalctl -u milog-probe.service -f
```

Full command list: `milog help`.

## Commands at a glance

```
milog              # merged color-prefixed tail of all apps
milog monitor      # bash dashboard (refresh-and-redraw, POSIX-everywhere)
milog tui          # bubbletea TUI (Go binary; richer panels, same data)
milog rate         # nginx-only req/min dashboard
milog daemon       # headless — fire alerts, no TUI

milog health       # 2xx/3xx/4xx/5xx totals per app
milog top [N]              # top N source IPs
milog top-paths [N]        # top N URLs: req / 4xx / 5xx / p95 per path
milog slow [N]             # slowest endpoints by p95
milog stats <app>          # hourly request histogram
milog suspects [N] [W]     # heuristic bot ranking
milog attacker <IP>        # forensic view: one IP, all apps

milog search <pat> [flags] # grep across current + archived logs
milog trend [app] [H]      # sparkline from history
milog diff                 # per-app: now vs 1d / 7d ago
milog auto-tune [D]        # suggest thresholds from history
milog replay <file>        # postmortem for one archived log
milog alerts [window]      # local fire history

milog errors               # live 4xx/5xx tail
milog exploits             # LFI / RCE / SQLi / XSS / infra-probe live tail
milog probes               # scanner/bot traffic live tail
milog grep <app> <pattern>
milog <app>                # raw tail of one app

milog web [install-service|stop|status]
milog probe [status|install-service|uninstall-service]   # Linux only — eBPF sidecar
milog alert [on|off|status|test]
milog audit [fim|persistence|ports|yara|accounts|rootkit] [baseline|check|status]
milog silence <rule_or_glob> <duration> [msg]
milog config [init|add|rm|dir|set|edit]
milog doctor               # diagnostic checklist
milog help
```

### `monitor` keys

| Key        | Action                     |
| ---------- | -------------------------- |
| `q`        | quit                       |
| `p`        | pause (freezes sparklines) |
| `r`        | refresh now                |
| `+` / `-`  | decrease / increase rate   |

## Uninstall

```bash
sudo rm /usr/local/bin/milog
sudo rm -f /etc/systemd/system/milog.service
rm -f ~/.config/systemd/user/milog-web.service
rm -rf ~/.config/milog ~/.cache/milog ~/.local/share/milog
sudo rm -rf /opt/milog   # if cloned
```

Or via the installer: `sudo ./install.sh --uninstall` (keeps config +
state dirs so re-installing preserves your settings).

## Contributing

The shipping artifact `milog.sh` is generated from `src/*.sh` by
`build.sh`. Don't edit `milog.sh` by hand — edit the file under `src/`
that owns the code, then run `bash build.sh` to regenerate the bundle.
Commit both the source change and the regenerated `milog.sh`.

See [`src/README.md`](src/README.md) for the source layout and
[`ARCHITECTURE.md`](ARCHITECTURE.md) for design internals.
