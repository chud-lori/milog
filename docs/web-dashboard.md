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

Today:

- **System row** — CPU / Memory / Disk with colored bars and
  absolute values
- **Nginx table** — per-app req / 2xx / 3xx / 4xx / 5xx counts for
  the **last minute**

That's the whole UI. It's intentionally minimal for v1 — everything
investigation-flavored (top paths, alerts history, p95 per app) still
lives in the CLI. Adding an alerts panel + historical charts is
planned; see the plan doc if you're on the contributor path.

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
