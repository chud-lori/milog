# MiLog

Bash nginx + system monitor. TUI dashboard, read-only web UI, log tailing,
heuristic scanner/exploit detection, multi-destination alerts
(Discord / Slack / Telegram / Matrix), headless daemon, historical metrics.

The shipping artifact is still a single file (`milog.sh` → `/usr/local/bin/milog`),
but it's **built from modular source under [`src/`](src/README.md)** by
[`build.sh`](build.sh). Users install one file; contributors edit small ones.

> Internals, design principles, and extension guide live in
> [ARCHITECTURE.md](ARCHITECTURE.md).

## Requirements

Linux, bash 4+, coreutils, `ps`, `df`, `uptime`, read access to
`/var/log/nginx/*.access.log`. Everything else (gawk, curl, sqlite3, and
optionally mmdblookup) is handled by `install.sh`.

## Install

One-liner — downloads the installer, installs `gawk` + `curl` + `sqlite3`
through your distro's package manager, then drops `milog` into
`/usr/local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash
```

Add GeoIP enrichment (opt-in — `mmdblookup` + requires a MaxMind MMDB):

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh \
  | sudo bash -s -- --with-geoip
```

Or from a clone (the installer auto-detects and uses the local `milog.sh`):

```bash
git clone https://github.com/chud-lori/milog.git /opt/milog
cd /opt/milog
sudo ./install.sh
sudo ./install.sh --uninstall   # keeps ~/.config/milog/, ~/.cache/milog/
```

Direct download (bypasses the installer — does not install gawk / curl /
sqlite3 / socat for you):

```bash
sudo curl -fLo /usr/local/bin/milog \
  https://raw.githubusercontent.com/chud-lori/milog/main/milog.sh
sudo chmod +x /usr/local/bin/milog
```

`milog.sh` is the bundled artifact — one self-contained bash script, even
though its source is split across `src/*.sh`. No runtime assembly.

Verify: `milog help`. Run `milog doctor` anytime to see what's wired up and
what's degraded — it reports on every optional capability (sqlite3, geoip,
webhook, extended log format, systemd unit) with a one-line fix for each.

## Usage

```
milog              # merged color-prefixed tail of all apps
milog monitor      # full TUI: nginx + CPU/MEM/DISK/NET + workers
milog daemon       # headless — fire Discord alerts, no TUI
milog rate         # nginx-only req/min dashboard
milog health       # 2xx/3xx/4xx/5xx totals per app
milog top [N]      # top N source IPs (default 10)
milog top-paths [N]      # top N URLs: req / 4xx / 5xx / p95 per path (default 20)
milog slow [N]     # top N slow endpoints by p95 (needs $request_time)
milog stats <app>  # hourly request histogram
milog suspects [N] [W]   # heuristic bot ranking
milog trend [app] [H]    # sparkline of req/min from history (needs sqlite3)
milog diff               # req per app: now vs 1d ago vs 7d ago
milog auto-tune [D]      # suggest thresholds from history (default: 7 days)
milog replay <file>      # summary of an archived log (.log, .gz, .bz2)
milog search <pat> [--since Nh] [--app NAME] [--path SUB] [--regex] [--archives]
milog attacker <IP>      # forensic view: one IP's activity across all apps
milog alerts [window]    # local fire history (today / Nh / Nd / Nw / all)
milog doctor       # checklist: tools, logs, log format, webhook, history, geoip
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

## Alerts (Discord, Slack, Telegram, Matrix)

MiLog can POST to Discord, Slack, Telegram, and/or Matrix when a threshold
trips or an exploit/probe pattern hits. Off by default. Configure one or
more — the dispatcher fires every alert to every configured destination.

### One-command setup

```bash
# 1. In Discord: Channel → Edit → Integrations → Webhooks → New → Copy URL
# 2. On the server:
sudo milog alert on 'https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN'
```

That writes the webhook to your config, enables alerts, installs
`/etc/systemd/system/milog.service`, and starts the daemon — survives ssh
disconnect and reboot. Verify:

```bash
milog alert status        # webhook / service / recent fires
milog alert test          # fire a test Discord embed right now
```

To pause alerting (e.g. planned maintenance):

```bash
sudo milog alert off      # stops service + sets ALERTS_ENABLED=0
```

### Manual setup (if you prefer config files)

```bash
milog config set DISCORD_WEBHOOK "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
milog config set ALERTS_ENABLED 1

# Optional tuning
milog config set ALERT_COOLDOWN 300            # seconds between repeats
milog config set ALERT_DEDUP_WINDOW 300        # cross-rule (ip,path) dedup TTL
milog config set ALERT_STATE_DIR /var/lib/milog
```

### Other destinations (configure any combination)

Every alert fires to every configured destination. Set the vars, no reload
needed — the daemon picks them up on next tick.

```bash
# Slack incoming webhook (Apps → Incoming Webhooks → Add to Channel)
milog config set SLACK_WEBHOOK "https://hooks.slack.com/services/T.../B.../XXX"

# Telegram (BotFather → /newbot for token; @userinfobot for chat_id)
milog config set TELEGRAM_BOT_TOKEN "123456789:AAH..."
milog config set TELEGRAM_CHAT_ID   "-100123456789"

# Matrix (homeserver URL + access token + room ID like "!abc:matrix.org")
milog config set MATRIX_HOMESERVER "https://matrix.example.com"
milog config set MATRIX_TOKEN      "syt_..."
milog config set MATRIX_ROOM       "!abc123:matrix.example.com"
```

All destinations share `ALERT_COOLDOWN` and the cross-rule `(ip, path)`
dedup gate — one real event produces one alert per destination, not N.

For env-var overrides (systemd units, one-shot runs), see the env table
in the [Configuration](#configuration) section above.

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
   curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh \
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
writes one row per app into a local SQLite database. This backs the
`milog trend` and `milog diff` read modes and keeps an hourly top-IPs
rollup. `sqlite3` is installed by the default installer, so no extra step
is needed — just turn the feature on:

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

Once a few days of history have built up, `milog auto-tune` will analyze it
and suggest threshold values based on your actual traffic (instead of having
you guess). It prints a ready-to-paste block of `milog config set …`
commands — re-run whenever traffic patterns change.

## Web dashboard (optional)

`milog web` starts a tiny local HTTP server (powered by `socat`) that serves
a read-only JSON + HTML view of the current system + per-app state. Useful
when you want to glance at your server from a phone or laptop without
SSHing in.

```bash
# One-time install of the listener (skip if already present)
sudo apt install -y socat        # or: sudo dnf install -y socat
# or, via the installer:
curl -fsSL https://.../install.sh | sudo bash -s -- --with-web

milog web            # prints a URL with an auto-generated ?t=TOKEN
milog web status     # is it running? on what port?
milog web stop       # kill it (systemd unit or foreground — handles either)
```

**Always-on (systemd user unit):** foreground mode dies when you close the
terminal. For a persistent dashboard, install it as a systemd user service
in one command:

```bash
milog web install-service     # writes + enables + starts milog-web.service
milog web status              # confirms systemd is running it
milog web uninstall-service   # undo
```

To survive logout and reboots, also run (one time, needs root):

```bash
sudo loginctl enable-linger $USER
```

Without linger, the service stops when you log out. Logs go to the user
journal: `journalctl --user -u milog-web.service -f`.

**Security defaults — read before exposing:**

- Binds to `127.0.0.1` only. Non-loopback binds (`--bind 0.0.0.0`) require
  `--trust` to acknowledge the attack surface.
- Every request is token-gated. Token is 32 bytes of urandom in
  `~/.config/milog/web.token` (mode 600). The page JS stores the token in
  `sessionStorage` and strips it from the URL on first load.
- All routes are **read-only** — no endpoint mutates config, webhook,
  history, or systemd state.
- Headers set: `Content-Security-Policy` (no external fetches),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- `DISCORD_WEBHOOK` is redacted (`…/webhooks/ID/****`) in any response.
- Access log at `~/.cache/milog/web.access.log` — `ip → method → path → status`.

### Three access patterns (ranked by blast radius)

**1. SSH port-forward** — simplest, zero public exposure.

```bash
# On your laptop:
ssh -L 8765:localhost:8765 <host>
# then open http://localhost:8765/?t=<TOKEN-from-server-banner>
```

**2. Tailscale / WireGuard overlay** — phone-friendly.

```bash
# One-time: install Tailscale on server + phone/laptop, join the tailnet.
milog web --bind 100.x.y.z   # the server's tailscale IP
# Open the printed URL from any device on your tailnet.
```

**3. Cloudflare Tunnel** — public HTTPS URL, no domain / port / cert needed.

```bash
# One-time: install cloudflared (see https://github.com/cloudflare/cloudflared)
milog web                                   # starts local listener
cloudflared tunnel --url http://localhost:8765
# cloudflared prints a https://<random>.trycloudflare.com URL — paste in browser.
# Stack Cloudflare Access on top for SSO + MFA (free on Zero Trust tier).
```

All three patterns keep MiLog itself bound to loopback — the tunnel/forward
is what crosses the network, which is exactly the property you want.

## `milog daemon`

### What is it for

`milog daemon` is the **headless** mode of MiLog: no TUI, no keyboard input,
just the rule evaluator running on a loop. It's what you run on a server
where nobody is watching a terminal.

Same rules as the interactive modes — 5xx/4xx spikes, CPU/MEM/disk/worker
critical thresholds, exploit and probe pattern hits — all wired to Discord
webhooks with per-rule cooldown. When `HISTORY_ENABLED=1`, it also writes
one per-minute row per app into SQLite so `milog trend` and `milog diff`
have data.

### Run it as a service (recommended)

Use the `alert on` subcommand — it installs the systemd unit, runs the
daemon as your user, and points at your config file:

```bash
sudo milog alert on 'https://discord.com/api/webhooks/ID/TOKEN'
sudo milog alert on                      # webhook already in config; just enable
```

Manage it:

```bash
milog alert status         # webhook / service / recent fires
milog alert test           # fire a Discord test embed
sudo milog alert off       # pause — stops service + sets ALERTS_ENABLED=0
```

If the daemon can't read `/var/log/nginx/*.access.log`, either add your
user to the `adm` group (`sudo usermod -aG adm $USER` — log out/in) or
edit the generated `/etc/systemd/system/milog.service` to `User=root`.

### Run it in the foreground (quick test)

```bash
milog daemon     # Ctrl-C to stop; stderr is the decision log
```

### Update after `curl | bash`

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash
sudo systemctl restart milog      # pick up the new binary
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
sudo rm -rf /opt/milog   # if cloned
```

## Contributing

The shipping artifact at `milog.sh` is generated from `src/*.sh` by
`build.sh`. Don't edit `milog.sh` by hand — edit the file under `src/` that
owns the code, then run `bash build.sh` to regenerate the bundle. Commit
both the source change and the regenerated `milog.sh`.

See [`src/README.md`](src/README.md) for the source layout and
[`ARCHITECTURE.md`](ARCHITECTURE.md) for design internals.
