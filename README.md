# MiLog

Single-script nginx + system monitor. TUI dashboard, log tailing,
heuristic scanner/exploit detection, Discord alerts, headless daemon.

> Internals, design principles, and extension guide live in
> [ARCHITECTURE.md](ARCHITECTURE.md).

## Requirements

Linux, bash 4+, awk (gawk recommended), coreutils, `ps`, `df`, `uptime`,
read access to `/var/log/nginx/*.access.log`. `curl` is needed for Discord
alerts (optional).

## Install

```bash
# Option A — single file
sudo curl -fLo /usr/local/bin/milog \
  https://raw.githubusercontent.com/chud-lori/ldr/main/milog.sh
sudo chmod +x /usr/local/bin/milog

# Option B — clone + symlink (easy to git pull)
sudo git clone https://github.com/chud-lori/ldr.git /opt/ldr
sudo ln -sf /opt/ldr/milog.sh /usr/local/bin/milog
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
Useful env vars: `MILOG_LOG_DIR`, `MILOG_APPS="a b c"`, `MILOG_CONFIG`.

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
