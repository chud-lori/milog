# MiLog

Single-script nginx + system monitor. TUI dashboards, log tailing,
heuristic scanner/exploit detection, per-app stats.

## Requirements

- Linux (uses `/proc`, `/sys/class/net`, `ip`)
- `bash` 4.x, `awk` (gawk recommended), `grep`, `tail`, `ps`, `df`, `uptime`
- Read access to `/var/log/nginx/*.access.log` (or whatever you configure)

## Install

### Option A — single-file download

```bash
sudo curl -fLo /usr/local/bin/milog \
  https://raw.githubusercontent.com/chud-lori/ldr/main/milog.sh
sudo chmod +x /usr/local/bin/milog
```

### Option B — clone + symlink (easy to update with `git pull`)

```bash
sudo git clone https://github.com/chud-lori/ldr.git /opt/ldr
sudo ln -sf /opt/ldr/milog.sh /usr/local/bin/milog
```

### Verify

```bash
milog help
```

## Configure

MiLog resolves settings in this order (later wins):

1. Hardcoded defaults in the script
2. Config file (`~/.config/milog/config.sh` by default)
3. Environment variables
4. Auto-discovery (only if `LOGS` ends up empty)

### Fastest path: `milog config` subcommands

You don't need to open the config file in a text editor.

```bash
milog config init              # create a commented template
milog config add api           # append app to LOGS
milog config add web
milog config rm old            # remove an app
milog config dir /var/log/nginx
milog config set REFRESH 3
milog config set THRESH_REQ_CRIT 60
milog config                   # show resolved values + path
milog config edit              # open $EDITOR as escape hatch
```

### Config file (manual editing)

```bash
mkdir -p ~/.config/milog
cat > ~/.config/milog/config.sh <<'EOF'
# Where nginx writes its access logs
LOG_DIR="/var/log/nginx"

# Apps to monitor — basenames of <name>.access.log files.
# Leave empty to auto-discover every *.access.log in LOG_DIR.
LOGS=(api web admin)
# LOGS=()

# Dashboard refresh interval (seconds)
REFRESH=5

# Optional threshold overrides
# THRESH_REQ_WARN=15
# THRESH_REQ_CRIT=40
# THRESH_CPU_WARN=70
# THRESH_CPU_CRIT=90
# THRESH_MEM_WARN=80
# THRESH_MEM_CRIT=95
# THRESH_DISK_WARN=80
# THRESH_DISK_CRIT=95
# THRESH_4XX_WARN=20
# THRESH_5XX_WARN=5
EOF
```

Point to a different config file with `MILOG_CONFIG=/path/to/config.sh`.

### Env var overrides (one-shot or scripted)

| Variable         | Effect                                                     |
| ---------------- | ---------------------------------------------------------- |
| `MILOG_LOG_DIR`  | Override `LOG_DIR`                                         |
| `MILOG_APPS`     | Space-separated app list — overrides `LOGS`                |
| `MILOG_CONFIG`   | Path to an alternate config file                           |

```bash
MILOG_LOG_DIR=/var/log/nginx MILOG_APPS="api web" milog monitor
```

### Auto-discovery

If `LOGS` is empty after config + env (e.g. config contains `LOGS=()`),
MiLog globs `$LOG_DIR/*.access.log` and uses the basenames. Good when your
log filenames follow `<name>.access.log` and you don't want to maintain a list.

If nothing is configured and nothing is discovered, MiLog exits with a clear
message telling you where it looked.

## Usage

```
milog              # tail all logs, merged by timestamp, colored per app
milog monitor      # full TUI: nginx + CPU/MEM/DISK/NET + workers
milog rate         # nginx-only req/min dashboard
milog health       # 2xx/3xx/4xx/5xx totals per app
milog top [N]      # top N source IPs (default 10)
milog stats <app>  # hourly request histogram
milog suspects [N] [W]   # heuristic bot ranking (top N=20, last W=2000 lines/app)
milog errors       # live tail of 4xx/5xx
milog exploits     # live tail matching LFI/RCE/SQLi/XSS/infra-probe payloads
milog probes       # live tail matching scanner/bot UAs + protocol smuggling
milog grep <app> <pat>   # filter-tail one app
milog <app>        # raw tail of one app
milog help
```

`Ctrl+C` exits any live view.

### `monitor` keybindings

| Key        | Action                                                |
| ---------- | ----------------------------------------------------- |
| `q`        | quit                                                  |
| `p`        | toggle pause (freezes sparklines; `[PAUSED]` in footer) |
| `r`        | refresh now                                           |
| `+` / `-`  | decrease / increase refresh interval                  |

Sparklines in the INTENSITY column show each app's last ~30 samples of
`req/min`. Change history depth by setting `SPARK_LEN=60` in the config.

## nginx log format

MiLog expects the default `combined` format:

```
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

Per-app log files named `<name>.access.log` inside `LOG_DIR`:

```nginx
access_log /var/log/nginx/api.access.log combined;
```

## Permissions

`/var/log/nginx` is usually owned by `root` or `adm`. Either:

- Run MiLog with `sudo`, or
- Add your user to the `adm` group: `sudo usermod -aG adm $USER` (log out/in)

## Troubleshooting

**"no apps configured and none found"** — `LOG_DIR` is wrong or the
directory has no `*.access.log` files. Check with `ls $LOG_DIR` and either
set `MILOG_APPS` or fix `LOG_DIR` in the config.

**Empty dashboard, no request counts** — MiLog matches the *current minute*
in the log's `[dd/Mon/yyyy:HH:MM` field. If nginx is logging in UTC but the
shell is in a different timezone, counts will be zero. Set `TZ=UTC milog monitor`
or align nginx's timezone.

**`monitor` mode shows 0 workers** — the `ps aux` parse expects processes named
`nginx: worker`. Confirm with `ps aux | grep nginx`.

**Live tails miss new lines after logrotate** — MiLog uses `tail -F` (uppercase),
which re-opens on rotate. If you're on a system without GNU `tail`, install
`coreutils`.

## Uninstall

```bash
sudo rm /usr/local/bin/milog
rm -rf ~/.config/milog
# if cloned:
sudo rm -rf /opt/ldr
```
