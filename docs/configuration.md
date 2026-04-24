# Configuration

MiLog has three layers, resolved in this order (later wins):

1. **Hardcoded defaults** — top of `src/core.sh`, visible in the bundled `milog.sh`.
2. **User config file** — `$MILOG_CONFIG` (default `~/.config/milog/config.sh`), sourced as bash.
3. **Env vars** — `MILOG_*` prefix; overrides both of the above per-invocation.

Then a final **auto-discover** pass kicks in only if `LOGS` is still empty:
every `*.access.log` under `LOG_DIR` becomes an app.

See [`ARCHITECTURE.md`](../ARCHITECTURE.md#configuration-layering) for the
reasoning behind the order.

## Fast path: the `config` subcommand

Most users never edit the config file by hand — the subcommand is
easier and keeps formatting sane:

```bash
milog config                 # show resolved values + path
milog config init            # write commented template at ~/.config/milog/config.sh
milog config add api         # append to LOGS
milog config rm old
milog config dir /var/log/nginx
milog config set REFRESH 3
milog config set THRESH_REQ_CRIT 60
milog config edit            # open $EDITOR
```

`milog config` (no args) prints the resolved state — every variable,
its current value, all four [alert destinations](alerts.md) with
redacted URLs, GeoIP / history / webhook state. Useful for debugging
"why doesn't it see my change?"

## Config file location

Default: `~/.config/milog/config.sh`. Override with `MILOG_CONFIG` env
var per-run:

```bash
MILOG_CONFIG=/etc/milog/config.sh milog monitor
```

The file is just bash — any `VAR=value` assignment works. The template
written by `milog config init` has every known variable commented with
its default.

## Variables — complete reference

### Core

| Variable        | Default                     | Purpose                                   |
| --------------- | --------------------------- | ----------------------------------------- |
| `LOG_DIR`       | `/var/log/nginx`            | Where to find `<app>.access.log` files    |
| `LOGS`          | auto-discover               | Array of app names; becomes `LOG_DIR/<name>.access.log` |
| `REFRESH`       | `5`                         | Seconds between TUI / daemon ticks        |
| `SPARK_LEN`     | `30`                        | Sparkline history length in `monitor`     |

### Thresholds

Both `WARN` and `CRIT` levels; `_CRIT` is what fires alerts (except for
4xx/5xx which fire at `_WARN` since they're lower-severity signals by
default).

| Variable              | Default | Purpose                                      |
| --------------------- | ------- | -------------------------------------------- |
| `THRESH_REQ_WARN`     | `15`    | Per-app req/min — yellow in TUI              |
| `THRESH_REQ_CRIT`     | `40`    | Per-app req/min — red in TUI                 |
| `THRESH_CPU_WARN`     | `70`    | CPU % — yellow                               |
| `THRESH_CPU_CRIT`     | `90`    | CPU % — red + alert                          |
| `THRESH_MEM_WARN`     | `80`    | Memory %                                     |
| `THRESH_MEM_CRIT`     | `95`    | Memory % — red + alert                       |
| `THRESH_DISK_WARN`    | `80`    | Disk %                                       |
| `THRESH_DISK_CRIT`    | `95`    | Disk % — red + alert                         |
| `THRESH_4XX_WARN`     | `20`    | 4xx/min — alert fires                        |
| `THRESH_5XX_WARN`     | `5`     | 5xx/min — alert fires                        |
| `P95_WARN_MS`         | `500`   | Request-time p95 — yellow                    |
| `P95_CRIT_MS`         | `1500`  | Request-time p95 — red                       |

Let `HISTORY_ENABLED=1` bank a few days of data, then run
[`milog auto-tune`](historical-metrics.md#milog-auto-tune-days) to get
calibrated values.

#### Per-app threshold overrides

Append `_<app>` to any of the threshold variables above to override it for
that app. Overrides fall back to the global when unset, so you only list
the apps that differ:

```bash
# config.sh — quiet APIs keep the tight defaults,
# a noisy finance backend gets its own limits.
THRESH_REQ_CRIT=40
THRESH_REQ_CRIT_finance=80
THRESH_5XX_WARN=5
THRESH_5XX_WARN_finance=10
P95_WARN_MS_api=200            # tighter p95 on the critical API
```

App names with `-` or `.` map to `_` for the variable name lookup
(`my-app` → `THRESH_REQ_CRIT_my_app`). Applies to all `THRESH_*` and
`P95_*_MS` variables; **system-wide thresholds** (CPU / MEM / DISK) have
no per-app form — they're not app-scoped.

### Alerts

| Variable              | Default             | Purpose                                   |
| --------------------- | ------------------- | ----------------------------------------- |
| `ALERTS_ENABLED`      | `0`                 | Master switch                              |
| `ALERT_COOLDOWN`      | `300` (5 min)       | Per-rule fire interval                    |
| `ALERT_DEDUP_WINDOW`  | `300` (5 min)       | Cross-rule `(ip, path)` dedup TTL         |
| `ALERT_STATE_DIR`     | `~/.cache/milog`    | Where cooldown/dedup state + alerts.log live |
| `ALERT_LOG_MAX_BYTES` | `10485760` (10 MB)  | In-place rotate alerts.log past this size; `0` disables |
| `ALERT_ROUTES`        | (empty — fan out)   | Per-rule destination mapping; see [alerts.md](alerts.md#routing--different-rules-to-different-destinations) |
| `DISCORD_WEBHOOK`     | (empty)             | Set to enable Discord                     |
| `SLACK_WEBHOOK`       | (empty)             | Set to enable Slack                       |
| `TELEGRAM_BOT_TOKEN`  | (empty)             | Bot token (with matching CHAT_ID)         |
| `TELEGRAM_CHAT_ID`    | (empty)             | Chat/group ID                             |
| `MATRIX_HOMESERVER`   | (empty)             | `https://matrix.example.com`              |
| `MATRIX_TOKEN`        | (empty)             | Long-lived access token                   |
| `MATRIX_ROOM`         | (empty)             | `!abc123:matrix.example.com`              |
| `WEBHOOK_URL`         | (empty)             | Generic POST target (ntfy.sh, Mattermost, custom ingests) |
| `WEBHOOK_TEMPLATE`    | `{"title":%TITLE%,"body":%BODY%,"severity":%SEV%,"rule":%RULE%}` | Body template; placeholders are JSON-quoted |
| `WEBHOOK_CONTENT_TYPE`| `application/json`  | `Content-Type` header on the POST         |

See [alerts.md](alerts.md) for full destination setup.

### History / GeoIP / Web

| Variable                 | Default                                 | Purpose                         |
| ------------------------ | --------------------------------------- | ------------------------------- |
| `HISTORY_ENABLED`        | `0`                                     | Daemon writes metrics to SQLite  |
| `HISTORY_DB`             | `~/.local/share/milog/metrics.db`       | SQLite path                     |
| `HISTORY_RETAIN_DAYS`    | `30`                                    | Prune older rows                |
| `HISTORY_TOP_IP_N`       | `50`                                    | Top-N IPs per app per hour      |
| `GEOIP_ENABLED`          | `0`                                     | Enable COUNTRY column           |
| `MMDB_PATH`              | `/var/lib/GeoIP/GeoLite2-Country.mmdb`  | MaxMind DB path                 |
| `WEB_PORT`               | `8765`                                  | `milog web` listen port         |
| `WEB_BIND`               | `127.0.0.1`                             | `milog web` bind address        |
| `SLOW_WINDOW`            | `1000`                                  | Lines/app scanned by `milog slow` |
| `SLOW_EXCLUDE_PATHS`     | `"/ws/* /socket.io/*"`                   | Path globs excluded from `slow` + `top-paths` (WebSocket sessions). Same list identifies WS paths for `milog ws`. Empty = include everything. |

## Env-var overrides

Every `VAR` above has a matching `MILOG_VAR` env override. Useful in
systemd units, one-shot runs, or CI:

| Env var                       | Overrides              |
| ----------------------------- | ---------------------- |
| `MILOG_CONFIG`                | Alternate config path   |
| `MILOG_LOG_DIR`               | `LOG_DIR`               |
| `MILOG_APPS="a b c"`          | `LOGS` (space-separated)|
| `MILOG_REFRESH`               | `REFRESH`               |
| `MILOG_DISCORD_WEBHOOK`       | `DISCORD_WEBHOOK`       |
| `MILOG_SLACK_WEBHOOK`         | `SLACK_WEBHOOK`         |
| `MILOG_TELEGRAM_BOT_TOKEN`    | `TELEGRAM_BOT_TOKEN`    |
| `MILOG_TELEGRAM_CHAT_ID`      | `TELEGRAM_CHAT_ID`      |
| `MILOG_MATRIX_HOMESERVER`     | `MATRIX_HOMESERVER`     |
| `MILOG_MATRIX_TOKEN`          | `MATRIX_TOKEN`          |
| `MILOG_MATRIX_ROOM`           | `MATRIX_ROOM`           |
| `MILOG_ALERTS_ENABLED`        | `ALERTS_ENABLED`        |
| `MILOG_ALERT_COOLDOWN`        | `ALERT_COOLDOWN`        |
| `MILOG_ALERT_DEDUP_WINDOW`    | `ALERT_DEDUP_WINDOW`    |
| `MILOG_ALERT_LOG_MAX_BYTES`   | `ALERT_LOG_MAX_BYTES`   |
| `MILOG_ALERT_ROUTES`          | `ALERT_ROUTES`          |
| `MILOG_WEBHOOK_URL`           | `WEBHOOK_URL`           |
| `MILOG_WEBHOOK_TEMPLATE`      | `WEBHOOK_TEMPLATE`      |
| `MILOG_WEBHOOK_CONTENT_TYPE`  | `WEBHOOK_CONTENT_TYPE`  |
| `MILOG_GEOIP_ENABLED`         | `GEOIP_ENABLED`         |
| `MILOG_MMDB_PATH`             | `MMDB_PATH`             |
| `MILOG_HISTORY_ENABLED`       | `HISTORY_ENABLED`       |
| `MILOG_HISTORY_DB`            | `HISTORY_DB`            |
| `MILOG_WEB_PORT`              | `WEB_PORT`              |
| `MILOG_WEB_BIND`              | `WEB_BIND`              |
| `MILOG_SLOW_EXCLUDE_PATHS`    | `SLOW_EXCLUDE_PATHS`    |

## nginx log format

MiLog expects the default `combined` format per app in `LOG_DIR`, one
file per app named `<name>.access.log`:

```nginx
access_log /var/log/nginx/api.access.log combined;
```

### Response-time percentiles — optional

To enable p50 / p95 / p99 in `monitor`, `slow`, `top-paths`, and the
daemon, extend the log format to append `$request_time` as the final
field:

```nginx
log_format combined_timed '$remote_addr - $remote_user [$time_local] '
                          '"$request" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent" $request_time';

access_log /var/log/nginx/api.access.log combined_timed;
```

MiLog auto-detects the extra field per line; mixed formats degrade
gracefully (lines without `$request_time` are skipped for timing
purposes, and the UI shows `—` when no timed samples exist for the
current minute).

## Permissions on `/var/log/nginx`

Usually owned by `root:adm` with `640` perms. Either:

- Run MiLog commands with `sudo` (heavy)
- Or add your user to the `adm` group: `sudo usermod -aG adm $USER`
  → log out and back in

`milog doctor` will tell you which state you're in.
