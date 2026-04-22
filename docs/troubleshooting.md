# Troubleshooting

## First: `milog doctor`

Before anything else, run this:

```bash
milog doctor
```

It walks every dependency + capability and reports what's wired up,
what's degraded, and exactly which command fixes each problem. Covers
core tools, bash version, sqlite3, mmdblookup, log directory access,
per-app log freshness, extended log format detection, all 4 alert
destinations, webhook reachability, `ALERTS_ENABLED`, history DB,
GeoIP, and systemd units (both `milog.service` and
`milog-web.service`).

If `doctor` prints a `✗` failure, fix that first — most other
symptoms are downstream.

## Common failures

### "no apps configured and none found"

MiLog has no logs to look at. Either the directory is wrong or the
file naming doesn't match:

```bash
ls -la "$LOG_DIR"                              # what's actually there?
milog config set LOG_DIR /actual/path          # fix path
milog config set APPS "myapp other"            # or set explicitly
```

File naming must be `<app>.access.log` (not `access.log.myapp`, not
`myapp.log`). If your nginx writes differently, add per-vhost
`access_log /var/log/nginx/<app>.access.log;` lines — see
[configuration.md](configuration.md#nginx-log-format).

### Empty dashboard / zero counts

MiLog matches the **current minute** in `[dd/Mon/yyyy:HH:MM`. If nginx
logs in UTC but your shell isn't, the match misses everything:

```bash
date                     # what milog thinks the time is
tail -1 /var/log/nginx/*.access.log | head -c 50   # what nginx logs
```

Fix: `TZ=UTC milog monitor`, or configure nginx to log in local time.

### `monitor` shows 0 workers

The `ps aux` match expects `nginx: worker`. Confirm with:

```bash
ps aux | grep nginx
```

If nginx is managed differently (k8s, docker), the workers aren't
standard processes and the count will legitimately be zero — no
alert fires in that case (the worker-down rule is practical rather
than strict).

### Live tails miss lines after logrotate

Install GNU coreutils. BSD `tail -F` is not equivalent — it doesn't
re-open the file after rotation:

```bash
tail --version      # should say "GNU coreutils"
```

On macOS dev boxes: `brew install coreutils` and use `gtail -F`
manually, or just skip live-tail testing on macOS (MiLog's target
platform is Linux).

## Alerts never arrive

Four things to check in order:

### 1. Is alerting actually on?

```bash
milog alert status
```

Look at the `destinations` block — at least one must be `✓ set`, and
`ALERTS_ENABLED` must be `1`. If Matrix shows `partial`, all three
Matrix vars must be set together.

### 2. Is the webhook URL live?

For Discord:

```bash
curl -v "$(grep DISCORD_WEBHOOK ~/.config/milog/config.sh | cut -d= -f2- | tr -d '"')"
```

Expect a 200 with `{"type":1}`-like response. 401 / 404 = webhook
deleted in Discord; regenerate.

### 3. Is a cooldown holding it?

```bash
cat ~/.cache/milog/alerts.state
```

Lines `<rule_key>\t<epoch>` are the last fire times. Within
`ALERT_COOLDOWN` (default 300s) of a fire, the same rule won't fire
again. Same for cross-rule dedup at
`~/.cache/milog/alerts.fingerprints`.

To force a fire right now, bypassing both gates:

```bash
milog alert test
```

### 4. Is the daemon actually running?

```bash
sudo systemctl status milog.service
```

If `inactive (dead)`, start it: `sudo systemctl start milog.service`.
If it fails to start, check logs:

```bash
sudo journalctl -u milog.service -n 50
```

Most common: permission denied on `/var/log/nginx/*.access.log`. Fix:
add the daemon's user to `adm` group, or edit the unit's `User=` to
`root`.

## Web dashboard stuck at "connecting…"

The browser reached the HTML but the inline JS never got to call
`/api/summary.json`. Usually:

- **`milog web` was Ctrl+C'd** after you opened the page. Restart it
  (preferably as a systemd user service — see
  [web-dashboard.md](web-dashboard.md#always-on-systemd-user-service)).
- **SSH tunnel dead**. Reconnect: `ssh -L 8765:localhost:8765 <host>`.
- **Old bundled milog.sh without the Content-Length byte-count fix**.
  Reinstall:

  ```bash
  curl -fsSL "https://raw.githubusercontent.com/chud-lori/milog/main/install.sh?$(date +%s)" | sudo bash
  ```

## Server shows literal `\033[…]` instead of colors

Your installed `milog` predates the `printf '%b'` fix. Reinstall:

```bash
curl -fsSL "https://raw.githubusercontent.com/chud-lori/milog/main/install.sh?$(date +%s)" | sudo bash
```

The `?$(date +%s)` query-string busts GitHub's raw-content CDN cache
in case your push hasn't propagated yet.

## Something changed but isn't taking effect

The running daemon has the **old** script loaded in memory. Changes
to `src/*.sh` / `milog.sh` only affect new processes.

```bash
sudo systemctl restart milog.service
sudo systemctl restart milog-web.service    # if you use the web unit
```

For one-shot CLI (`milog monitor`, `milog search`, etc.) this doesn't
apply — each invocation exec's the fresh binary.

## Historical modes say "No history database"

`HISTORY_ENABLED` is off, or the daemon hasn't written anything yet
(wait ~1 minute after starting). `milog doctor` will tell you which.

## Other weirdness — where to look

- **Alert fire log**: `~/.cache/milog/alerts.log` (or
  `milog alerts all`)
- **Cooldown state**: `~/.cache/milog/alerts.state`
- **Fingerprint dedup**: `~/.cache/milog/alerts.fingerprints`
- **Web access log**: `~/.cache/milog/web.access.log`
- **Daemon decisions**: `sudo journalctl -u milog.service -f`
- **Web daemon decisions**: `journalctl --user -u milog-web.service -f`

If `milog doctor` is clean and a specific command misbehaves anyway,
that's a bug — file an issue with the `doctor` output + the exact
command you ran.
