# Web dashboard

`milog web` starts a tiny local HTTP server (powered by `socat`) that
serves a read-only JSON + HTML view of the current system + per-app
state. Useful when you want to glance at your server from a phone or
laptop without SSHing in.

## One-time install

The listener needs `socat` (or `ncat` as a fallback). Either via the
milog installer or direct apt:

```bash
# Via the installer (also brings gawk / curl / sqlite3 if you're starting fresh)
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh \
  | sudo bash -s -- --with-web

# Or direct
sudo apt install -y socat        # Debian / Ubuntu
sudo dnf install -y socat        # Fedora / Rocky / RHEL
```

## Run it

```bash
milog web            # foreground — prints URL with ?t=TOKEN, Ctrl+C to stop
milog web status     # is it running? on what port? via systemd or foreground?
milog web stop       # stop whichever is running (systemd unit or foreground PID)
```

The banner prints a URL like
`http://127.0.0.1:8765/?t=bd10839fa1012c…`. The token stays in the URL
only until the page JS stores it in `sessionStorage` and strips it from
the address bar (first paint).

## Always-on (systemd user service)

Foreground mode dies when you close the terminal. For a persistent
dashboard, install it as a systemd user service in one command:

```bash
milog web install-service     # writes + enables + starts milog-web.service
milog web status              # confirms systemd is running it
milog web uninstall-service   # undo
```

To survive logout and reboots, also run once (needs root):

```bash
sudo loginctl enable-linger $USER
```

Without `linger`, the service stops when you log out. Logs go to the
user journal:

```bash
journalctl --user -u milog-web.service -f
```

The unit is written to `~/.config/systemd/user/milog-web.service` and
pins the current `WEB_PORT` / `WEB_BIND` as `Environment=` values —
re-running `install-service` picks up any `milog config set WEB_PORT N`
changes.

## Security posture

Read this before ever pointing `--bind` at anything other than loopback.

- **Binds to `127.0.0.1` by default.** Non-loopback binds require
  `--trust` to force explicit consent — refuses otherwise.
- **Every request is token-gated.** The token is 32 bytes of
  `/dev/urandom` at `~/.config/milog/web.token` (mode 600). Accepted
  via `?t=TOKEN` query (first page load) or
  `Authorization: Bearer TOKEN` header (API calls).
- **All routes are read-only.** No endpoint mutates config, webhook,
  history, systemd state, or the alerts log. The worst an attacker
  with the token can do is read what `milog monitor` already shows.
- **Response headers**: `Content-Security-Policy: default-src 'self';
  script-src 'self' 'unsafe-inline'`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`.
- **`DISCORD_WEBHOOK` and other secrets are redacted** in every
  response (`…/webhooks/ID/****`). Token rotation strategy: delete
  `~/.config/milog/web.token`; next start generates a new one.
- **Per-request access log** at `~/.cache/milog/web.access.log` —
  TSV of timestamp, client IP, method, path, status.

## Three exposure patterns (ranked by blast radius)

Pick **one**. Milog always binds to loopback; these are how you cross
the network to reach it.

### 1. SSH port-forward — simplest, zero public exposure

```bash
# On your laptop:
ssh -L 8765:localhost:8765 <host>
# Then open: http://localhost:8765/?t=<TOKEN-from-server-banner>
```

No new dependencies, no account with a third party, no open inbound
port on the server. The SSH session itself is the transport.

### 2. Tailscale / WireGuard overlay — phone-friendly

One-time: install Tailscale on both server and phone/laptop, join the
same tailnet. Then:

```bash
milog web --bind 100.x.y.z    # the server's tailscale IP
# Open the printed URL from any device on your tailnet.
```

Still no public inbound; the overlay handles routing. Because
`--bind` is now a non-loopback address, you need `--trust` to force
consent:

```bash
milog web --bind 100.x.y.z --trust
```

### 3. Cloudflare Tunnel — public HTTPS URL, no DNS setup

```bash
# Install cloudflared: https://github.com/cloudflare/cloudflared
milog web                                   # binds loopback
cloudflared tunnel --url http://localhost:8765
# cloudflared prints: https://<random>.trycloudflare.com
```

Stack Cloudflare Access on top for SSO + MFA (free on Zero Trust
tier). Unlike Tailscale, this gives a publicly routable URL you can
hand to a non-technical user.

## What the dashboard shows

- **System row** — CPU / Memory / Disk with colored bars and
  absolute values
- **Nginx table** — per-app req / 2xx / 3xx / 4xx / 5xx counts for
  the **last minute**
- **Recent alerts** — fires from `alerts.log`, filtered by a
  selectable window (1h / 24h / 7d / today / all). Severity is
  color-coded (crit red, warn yellow, info green). Polls every 15 s
  — alerts don't move at the 3-second summary cadence and the log
  file scan is negligible but pointless at that rate. Source is the
  same `$ALERT_STATE_DIR/alerts.log` that `milog alerts` reads.

Deeper investigation (top paths, p95 per app, per-IP drilldown)
still lives in the CLI. Historical charts are planned — see the
plan doc if you're on the contributor path.

## Prometheus `/metrics` (Go binary only)

When `milog web` runs via the Go binary (default when `milog-web`
is installed), it exposes Prometheus plaintext 0.0.4 at `/metrics`.
Same token auth as every other route — Prom scrapers read it via
the `Authorization: Bearer …` header.

Metric surface:

| Metric                                        | Type  | Labels                   |
| --------------------------------------------- | ----- | ------------------------ |
| `milog_up`                                    | gauge | —                        |
| `milog_apps_configured`                       | gauge | —                        |
| `milog_cpu_percent`                           | gauge | —                        |
| `milog_mem_percent` / `_used_bytes` / `_total_bytes` | gauge | —                 |
| `milog_disk_percent` / `_used_bytes` / `_total_bytes` | gauge | `path`            |
| `milog_requests_last_minute`                  | gauge | `app`, `class` (`2xx`…`5xx`) |
| `milog_request_latency_ms`                    | gauge | `app`, `quantile` (`p50`/`p75`/`p90`/`p95`/`p99`/`p99.9`) |
| `milog_alerts_fired_total`                    | gauge | `rule`, `sev` (`crit`/`warn`/`info`) |

**Scrape config** (read the web token once and keep it in your
prometheus.yml or a secret):

```yaml
scrape_configs:
  - job_name: milog
    scrape_interval: 30s
    metrics_path: /metrics
    scheme: http
    authorization:
      type: Bearer
      credentials: __MILOG_WEB_TOKEN__       # cat ~/.config/milog/web.token
    static_configs:
      - targets: ['milog-host:8765']
```

The `milog_requests_last_minute` series is a gauge (not a counter)
because MiLog re-reads the log for each scrape — use PromQL's
`sum by (app) (milog_requests_last_minute)` directly, not `rate()`.

`milog_alerts_fired_total` is the cumulative count from
`alerts.log`; it resets if the log is truncated but otherwise
grows monotonically within a retention window — safe to treat as
a counter for `increase()`.

`milog_request_latency_ms` only emits for apps using the nginx
`combined_timed` log format (with `$request_time` as the final
field). Apps still on plain `combined` produce no latency series.
Percentiles are computed over the tail of the access log on each
scrape, so the `lines=` scan window applies — default 2000 lines
per app per scrape. For apps with heavy traffic, increase
`/api/latency.json?lines=` up to the 10k cap, or decrease scrape
interval to 15s and accept more CPU per scrape.

### Per-app latency endpoint

Alongside the Prom surface, the raw JSON is available at
`/api/latency.json?app=<name>`:

```json
{
  "app": "api",
  "window_lines": 2000,
  "count": 1834,
  "min_ms": 3,
  "max_ms": 4271,
  "pct": {
    "p50": 42, "p75": 58, "p90": 120,
    "p95": 240, "p99": 1200, "p99.9": 3800
  }
}
```

Useful for ad-hoc investigation (`curl … | jq`) without waiting
for a Prom scrape. `count: 0` with empty `pct` = no timed samples
in the tail window (either no traffic or missing `$request_time`).

## Custom port

`milog web` defaults to `127.0.0.1:8765`. Override per-run or
persistently:

```bash
milog web --port 9876                       # one-shot
milog config set WEB_PORT 9876              # persistent (picked up by systemd unit)
```

8765 was chosen because it's unassigned by IANA and rarely collides.
If it's still taken, pick anything in the ephemeral-but-unreserved
range (e.g. 9876, 18765, 49200).
