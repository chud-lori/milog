# Historical metrics

When [`milog daemon`](daemon.md) is running with `HISTORY_ENABLED=1`,
every minute it writes one row per configured app into a local SQLite
database. This backs the `trend` / `diff` / `auto-tune` read modes, and
keeps an hourly top-IPs rollup.

`sqlite3` is installed by the default installer — no extra step.

## Turn it on

```bash
milog config set HISTORY_ENABLED 1
milog config set HISTORY_RETAIN_DAYS 30     # optional; default 30
# Default DB path is ~/.local/share/milog/metrics.db
```

Then restart the daemon so it picks up the new config:

```bash
sudo systemctl restart milog.service
```

## Schema (created idempotently on daemon start)

```sql
metrics_minute (
    ts       INTEGER,   -- epoch, aligned to minute
    app      TEXT,
    req      INTEGER,   -- total requests
    c2xx     INTEGER,
    c3xx     INTEGER,
    c4xx     INTEGER,
    c5xx     INTEGER,
    p50_ms   INTEGER,   -- NULL if $request_time not logged
    p95_ms   INTEGER,
    p99_ms   INTEGER,
    PRIMARY KEY (ts, app)
)

top_ip_hour (
    ts_hour  INTEGER,   -- epoch, aligned to hour
    app      TEXT,
    ip       TEXT,
    hits     INTEGER,
    PRIMARY KEY (ts_hour, app, ip)
)
```

The daemon writes to `metrics_minute` once per minute and rolls up
`top_ip_hour` once per hour (keeping the top N IPs per app per hour —
`HISTORY_TOP_IP_N` config, default 50).

## What you can do with the data

### `milog trend [app] [hours]`

ASCII sparkline per app — requests green, errors (4xx+5xx) red — over
the given window (default 24h). Buckets by minute, aggregates into
~`cols-40` columns wide:

```
  dolanan    req ▁▁▁▃▃▇█▅▃▁▁▁▁▂▂▂▂▃  peak=840/bucket
             err ▁▁▁▁▁▁▁▅▂▁▁▁▁▁▁▁▁▁  total=12
```

### `milog diff`

Hour-level comparison — NOW vs 1 day ago vs 7 days ago, per app. Shows
percent deltas so traffic changes are obvious:

```
APP           NOW    1D AGO   Δ 1D     7D AGO   Δ 7D
dolanan       123      142    -13%       210    -41%
finance        42       38     +10%       25    +68%
```

### `milog auto-tune [days]`

Analyze baselines from the last N days (default 7) and print
ready-to-paste `milog config set …` commands that set thresholds to
percentile-based sensible defaults. Useful once you have ≥3 days of
traffic banked:

```
milog auto-tune 7

METRIC                CURRENT      SUGGESTED    DELTA
────────────────────  ───────────  ───────────  ──────
THRESH_REQ_WARN       15           72           +57
THRESH_5XX_WARN       5            3            -2
P95_WARN_MS           500          428          -72
...

Ready to apply (copy-paste to set):
  milog config set THRESH_REQ_WARN 72
  milog config set THRESH_5XX_WARN 3
  milog config set P95_WARN_MS 428
```

Re-run whenever traffic patterns change (new service, traffic source
shift, seasonal change).

## History is daemon-only

The interactive modes (`monitor`, `rate`, etc.) **don't** write to the
DB — they just read logs for the current minute. If you want both live
alerts and historical metrics, run `milog daemon` as a systemd service
and use `milog monitor` ad hoc.

## Retention

`HISTORY_RETAIN_DAYS` (default 30) bounds the DB size. The daemon runs
a prune query once per day that deletes `metrics_minute` and
`top_ip_hour` rows older than the retention window. Rough sizing: ~15
KB per app per day for `metrics_minute`, plus ~3 KB per app per hour
for the hourly rollup — at 30d retention and 6 apps, expect ~3 MB.

## Moving the DB

Default path: `~/.local/share/milog/metrics.db`. Override:

```bash
milog config set HISTORY_DB /var/lib/milog/metrics.db
sudo systemctl restart milog.service
```

Keep the directory on the same filesystem as the server — SQLite's
write-ahead log doesn't cross network filesystems cleanly.
