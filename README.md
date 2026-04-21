# MiLog

Single-script nginx + system monitor. TUI dashboard, log tailing,
heuristic scanner/exploit detection, Discord alerts, headless daemon.

> Internals, design principles, and extension guide live in
> [ARCHITECTURE.md](ARCHITECTURE.md).

## Requirements

Linux, bash 4+, coreutils, `ps`, `df`, `uptime`, read access to
`/var/log/nginx/*.access.log`. Everything else (gawk, curl, optional
sqlite3 / mmdblookup) is handled by `install.sh`.

## Install

One-liner — downloads the installer, installs `gawk` + `curl` through your
distro's package manager, then drops `milog` into `/usr/local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/ldr/main/install.sh | sudo bash
```

Optional extras (pass through with `-s --`):

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/ldr/main/install.sh \
  | sudo bash -s -- --with-history          # also install sqlite3
curl -fsSL https://raw.githubusercontent.com/chud-lori/ldr/main/install.sh \
  | sudo bash -s -- --with-geoip            # also install mmdblookup
```

Or from a clone (the installer auto-detects and uses the local `milog.sh`):

```bash
git clone https://github.com/chud-lori/ldr.git /opt/ldr
cd /opt/ldr
sudo ./install.sh
sudo ./install.sh --uninstall   # keeps ~/.config/milog/, ~/.cache/milog/
```

Manual single-file download (skip the installer):

```bash
sudo curl -fLo /usr/local/bin/milog \
  https://raw.githubusercontent.com/chud-lori/ldr/main/milog.sh
sudo chmod +x /usr/local/bin/milog
```

Verify: `milog help`.

## Usage

```
milog              # merged color-prefixed tail of all apps
milog monitor      # full TUI: nginx + CPU/MEM/DISK/NET + workers
milog daemon       # headless — fire Discord alerts, no TUI
milog rate         # nginx-only req/min dashboard
milog health       # 2xx/3xx/4xx/5xx totals per app
milog top [N]      # top N source IPs (default 10)
milog slow [N]     # top N slow endpoints by p95 (needs $request_time)
milog stats <app>  # hourly request histogram
milog suspects [N] [W]   # heuristic bot ranking
milog errors       # live tail of 4xx/5xx
milog exploits     # LFI/RCE/SQLi/XSS/infra-probe live tail
milog probes       # scanner/bot traffic live tail
milog grep <app> <pat>
milog <app>        # raw tail of one app
milog config [...]
milog help
```

### `monitor` keys

| Key        | Action                     |
| ---------- | -------------------------- |
| `q`        | quit                       |
| `p`        | pause (freezes sparklines) |
| `r`        | refresh now                |
| `+` / `-`  | decrease / increase rate   |

## Configuration

Resolution order: hardcoded defaults → config file → env vars → auto-discover
(see [ARCHITECTURE.md](ARCHITECTURE.md#configuration-layering) for the full
precedence rules).

Fast path — the `config` subcommand:

```bash
milog config init              # write commented template
milog config add api           # append to LOGS
milog config rm old
milog config dir /var/log/nginx
milog config set REFRESH 3
milog config set THRESH_REQ_CRIT 60
milog config                   # show resolved values + path
milog config edit              # open $EDITOR
```

Config file location: `$MILOG_CONFIG` (default `~/.config/milog/config.sh`).
One-shot env overrides (useful in systemd units or ad-hoc runs):

| Env var                   | Overrides             |
| ------------------------- | --------------------- |
| `MILOG_CONFIG`            | Alternate config path |
| `MILOG_LOG_DIR`           | `LOG_DIR`             |
| `MILOG_APPS="a b c"`      | `LOGS`                |
| `MILOG_REFRESH`           | `REFRESH`             |
| `MILOG_DISCORD_WEBHOOK`   | `DISCORD_WEBHOOK`     |
| `MILOG_ALERTS_ENABLED`    | `ALERTS_ENABLED`      |
| `MILOG_ALERT_COOLDOWN`    | `ALERT_COOLDOWN`      |
| `MILOG_GEOIP_ENABLED`     | `GEOIP_ENABLED`       |
| `MILOG_MMDB_PATH`         | `MMDB_PATH`           |
| `MILOG_HISTORY_ENABLED`   | `HISTORY_ENABLED`     |
| `MILOG_HISTORY_DB`        | `HISTORY_DB`          |

### nginx log format

MiLog expects the default `combined` format per app in `LOG_DIR`, one file
per app named `<name>.access.log`:

```nginx
access_log /var/log/nginx/api.access.log combined;
```

**Optional — response-time percentiles.** To enable p50/p95/p99 rendering in
`monitor` and the `slow` mode, extend `log_format` to append `$request_time`
as the final field:

```nginx
log_format combined_timed '$remote_addr - $remote_user [$time_local] '
                          '"$request" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent" $request_time';

access_log /var/log/nginx/api.access.log combined_timed;
```

MiLog auto-detects the extra field per line; mixed formats degrade gracefully
(lines without `$request_time` are skipped, and the UI shows `—` when no
timed samples exist for the current minute).

### Permissions

`/var/log/nginx` is usually owned by `root` or `adm`. Either run with `sudo`
or add your user to the `adm` group: `sudo usermod -aG adm $USER`.

## Discord alerts

MiLog can POST to a Discord webhook when a threshold trips or an exploit/probe
pattern hits. Off by default.

1. Create a webhook in your Discord channel: *Channel → Edit → Integrations →
   Webhooks → New Webhook → Copy URL*.
2. Configure:

   ```bash
   milog config set DISCORD_WEBHOOK "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
   milog config set ALERTS_ENABLED 1
   ```

   Or via env:

   ```bash
   export DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
   export ALERTS_ENABLED=1
   ```

3. Optional tuning:

   ```bash
   milog config set ALERT_COOLDOWN 300           # seconds between repeats
   milog config set ALERT_STATE_DIR /var/lib/milog
   ```

### What fires

| Rule              | Key                          | Trigger                                        |
| ----------------- | ---------------------------- | ---------------------------------------------- |
| 5xx spike         | `5xx:<app>`                  | last minute ≥ `THRESH_5XX_WARN` (default 5)    |
| 4xx spike         | `4xx:<app>`                  | last minute ≥ `THRESH_4XX_WARN` (default 20)   |
| CPU / MEM / Disk  | `cpu` / `mem` / `disk:/`     | ≥ corresponding `THRESH_*_CRIT`                |
| Workers down      | `workers`                    | zero nginx worker processes                    |
| Exploit match     | `exploit:<app>:<category>`   | `mode_exploits` pattern hit                    |
| Probe match       | `probe:<app>`                | `mode_probes` pattern hit                      |

Every rule is deduped by key inside `ALERT_COOLDOWN`. Alerts fire from both
the interactive modes (`monitor`, `exploits`, `probes`) and from `milog daemon`.

## GeoIP enrichment (optional)

`milog top` and `milog suspects` can show a `COUNTRY` column using a local
MaxMind GeoLite2 database. Off by default — requires an `mmdblookup` binary
and the `.mmdb` file on disk.

1. Install the tool — either via the installer

   ```bash
   curl -fsSL https://raw.githubusercontent.com/chud-lori/ldr/main/install.sh \
     | sudo bash -s -- --with-geoip
   ```

   or directly: `sudo apt install mmdb-bin` (Debian/Ubuntu),
   `sudo dnf install libmaxminddb` (Fedora/RHEL), or
   `sudo pacman -S libmaxminddb` (Arch).

2. Get a free `GeoLite2-Country.mmdb` from MaxMind: register at
   <https://www.maxmind.com/en/geolite2/signup>, download the Country
   edition, put it at `/var/lib/GeoIP/GeoLite2-Country.mmdb` (or point
   `MMDB_PATH` elsewhere).

3. Turn it on:

   ```bash
   milog config set GEOIP_ENABLED 1
   milog config set MMDB_PATH "/var/lib/GeoIP/GeoLite2-Country.mmdb"
   ```

4. (Optional) Auto-update — install the `geoipupdate` package and run it
   from cron. MaxMind publishes refreshed databases weekly.

MiLog looks up country only after the top-N list is already aggregated, so
`mmdblookup` runs at most N times per invocation — never per log line.

## Historical metrics (optional)

When `milog daemon` is running with `HISTORY_ENABLED=1`, every minute it
writes one row per app into a local SQLite database. This unlocks the
upcoming `milog trend` / `milog diff` read modes and keeps an hourly
top-IPs rollup.

Install the CLI tool — via the installer,

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/ldr/main/install.sh \
  | sudo bash -s -- --with-history
```

or directly: `sudo apt install sqlite3` / `sudo dnf install sqlite` /
`sudo pacman -S sqlite`.

Turn it on:

```bash
milog config set HISTORY_ENABLED 1
milog config set HISTORY_RETAIN_DAYS 30    # optional
# Default DB path is ~/.local/share/milog/metrics.db
```

Schema (created idempotently on daemon start):

- `metrics_minute (ts, app, req, c2xx, c3xx, c4xx, c5xx, p50_ms, p95_ms, p99_ms)`
- `top_ip_hour   (ts_hour, app, ip, hits)`

History is daemon-only — the interactive modes (`monitor`, `rate`) don't
write. If you want both alerts and history, run `milog daemon` as a service
(systemd unit below) and use `milog monitor` ad hoc.

## `milog daemon` + systemd

Headless mode runs the same rule evaluator without a TUI. Useful on servers
where nobody is watching the dashboard.

```bash
milog daemon    # foreground; stderr = decision log
```

### systemd unit

```ini
[Unit]
Description=MiLog headless alerter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/milog daemon
Restart=on-failure
User=milog
Environment=MILOG_CONFIG=/etc/milog/config.sh

[Install]
WantedBy=multi-user.target
```

Drop into `/etc/systemd/system/milog.service`, set your config file at
`/etc/milog/config.sh` with `DISCORD_WEBHOOK` + `ALERTS_ENABLED=1`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now milog
sudo journalctl -u milog -f
```

## Troubleshooting

- **"no apps configured and none found"** — check `ls $LOG_DIR`. Either set
  `MILOG_APPS` or fix `LOG_DIR`.
- **Empty dashboard / zero counts** — MiLog matches the *current minute*
  in `[dd/Mon/yyyy:HH:MM`. If nginx logs in UTC but your shell isn't, try
  `TZ=UTC milog monitor`.
- **`monitor` shows 0 workers** — the `ps aux` match expects `nginx: worker`.
  Confirm with `ps aux | grep nginx`.
- **Live tails miss lines after logrotate** — install GNU coreutils; BSD
  `tail -F` is not equivalent.
- **Discord alerts never arrive** — check `ALERTS_ENABLED=1`, `DISCORD_WEBHOOK`
  reachable (`curl -v "$DISCORD_WEBHOOK"`), and state file at
  `$ALERT_STATE_DIR/alerts.state` — stale entries suppress via cooldown.

## Uninstall

```bash
sudo rm /usr/local/bin/milog
rm -rf ~/.config/milog ~/.cache/milog
sudo rm -rf /opt/ldr   # if cloned
```
