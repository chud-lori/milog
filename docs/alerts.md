# Alerts

MiLog can POST to **Discord**, **Slack**, **Telegram**, and/or **Matrix**
when a threshold trips or a scanner/exploit pattern hits. Off by default.
Configure one or more destinations; the dispatcher fires every alert to
every configured destination.

## One-command setup (Discord)

The fastest path — sets the webhook, enables alerts, installs the
systemd service, and starts the daemon:

```bash
# 1. In Discord: Channel → Edit → Integrations → Webhooks → New → Copy URL
# 2. On the server:
sudo milog alert on 'https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN'
```

Verify:

```bash
milog alert status   # destinations / enabled / cooldown / service / recent fires
milog alert test     # fire a test embed right now
```

To pause (e.g. planned maintenance):

```bash
sudo milog alert off   # stops service + sets ALERTS_ENABLED=0
```

## Manual setup (config-file route)

```bash
milog config set DISCORD_WEBHOOK "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
milog config set ALERTS_ENABLED 1

# Optional tuning
milog config set ALERT_COOLDOWN      300   # seconds between repeats of one rule
milog config set ALERT_DEDUP_WINDOW  300   # cross-rule (ip,path) dedup TTL
milog config set ALERT_STATE_DIR     /var/lib/milog
```

Then restart the daemon so it picks up the new config:

```bash
sudo systemctl restart milog.service
```

## Additional destinations

Every alert fires to every configured destination — add or remove at
will. Each destination is opt-in: unset values are silently skipped.

### Slack

```bash
# Apps → Incoming Webhooks → Add to Channel → copy the webhook URL
milog config set SLACK_WEBHOOK "https://hooks.slack.com/services/T.../B.../XXX"
```

Format: `*<title>*\n\`\`\`<body>\`\`\`` as mrkdwn. `link_names: 0`
keeps `<@channel>` / `<@here>` literal instead of pinging.

### Telegram

```bash
# 1. Message @BotFather → /newbot → get the bot token
# 2. Message @userinfobot → get your chat_id (numeric; starts with - for groups)
milog config set TELEGRAM_BOT_TOKEN "123456789:AAH..."
milog config set TELEGRAM_CHAT_ID   "-100123456789"
```

Format: `<b>title</b>\n<pre>body</pre>` via `parse_mode: HTML`. Body is
HTML-escaped — log lines with `<script>` or `<a href>` render as
literal text, never executed.

### Matrix

```bash
milog config set MATRIX_HOMESERVER "https://matrix.example.com"
milog config set MATRIX_TOKEN      "syt_..."
milog config set MATRIX_ROOM       "!abc123:matrix.example.com"
```

The access token comes from Element → All Settings → Help & About →
Advanced → Access Token, or via the `/_matrix/client/v3/login` API.
Room IDs start with `!`; room aliases `#room:server` also work if
URL-encoded, but raw IDs are more stable.

Format: `m.room.message` with both plain `body` and HTML
`formatted_body`. Same HTML escaping as Telegram.

### Checking what's configured

`milog alert status` and `milog config` show the state of all four
destinations with **redacted previews** — enough to confirm "yes, this
is the webhook" without leaking the secret:

```
destinations
  discord    ✓ set   https://discord.com/api/webhooks/1496…/****
  slack      ✓ set   https://hooks.slack.com/services/T01/B02/****
  telegram   ✓ set   bot123456789:**** chat=-100987654321
  matrix     partial need MATRIX_HOMESERVER + MATRIX_TOKEN + MATRIX_ROOM
```

The `partial` state catches the common typo where you set only one of
the three Matrix vars — the alert would silently no-op otherwise.

## What fires

| Rule              | Key                          | Trigger                                          |
| ----------------- | ---------------------------- | ------------------------------------------------ |
| 5xx spike         | `5xx:<app>`                  | last minute ≥ `THRESH_5XX_WARN` (default 5)      |
| 4xx spike         | `4xx:<app>`                  | last minute ≥ `THRESH_4XX_WARN` (default 20)    |
| CPU / MEM / Disk  | `cpu` / `mem` / `disk:/`     | ≥ corresponding `THRESH_*_CRIT`                  |
| Workers down      | `workers`                    | zero nginx worker processes                      |
| Exploit match     | `exploit:<app>:<category>`   | `mode_exploits` pattern hit                      |
| Probe match       | `probe:<app>`                | `mode_probes` pattern hit                        |

Alerts fire from the interactive modes (`monitor`, `exploits`,
`probes`) and from [`milog daemon`](daemon.md). The rule keys are
stable strings — you can grep `$ALERT_STATE_DIR/alerts.state` to see
the most recent fire time for any rule.

## Dedup: two layers

Every alert passes through two gates before delivery:

1. **Per-rule cooldown** (`ALERT_COOLDOWN`, default 300s). Same rule
   key can't fire more than once per TTL. Prevents a minute-long 5xx
   storm from producing 60 Discord embeds.
2. **Cross-rule fingerprint** (`ALERT_DEDUP_WINDOW`, default 300s).
   Same `(ip, path)` within the TTL suppresses the second rule. Fixes
   the common case where one scanner logline hits both `exploits` (by
   URL) and `probes` (by user-agent) — you'd see two Discord embeds
   for one event without this.

Both gates share no state; a burst across different rule keys and
different `(ip, path)` fingerprints fires each alert as expected.

## Fire history log

Every fire appends one row to `~/.cache/milog/alerts.log` as TSV:

```
<epoch>\t<rule_key>\t<color_int>\t<title>\t<body_truncated>
```

Read it with `milog alerts`:

```bash
milog alerts            # today (default)
milog alerts 24h
milog alerts 7d
milog alerts all        # full log
milog alerts yesterday
```

Output shows a chronological timeline + a "top rules" summary. Colors
match severity (red for crit, yellow for warn, green for info).

## Troubleshooting alerts

See [troubleshooting.md](troubleshooting.md#alerts-never-arrive).
