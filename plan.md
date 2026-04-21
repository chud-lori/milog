# MiLog — Next Phase Plan

This plan hands off three feature tracks to another Claude Code session. It
is self-contained: no prior conversation context required. Read it top to
bottom before editing code.

## Context

MiLog is a single-file bash script (`milog.sh`) that tails nginx access logs
and renders a TUI dashboard plus several one-shot modes. It's designed to
run on a Linux VM with `/var/log/nginx/*.access.log`, no build step, no
runtime dependencies beyond standard coreutils + awk + bash 4+.

- **Entry point:** `milog.sh` (dispatched via symlink at `/usr/local/bin/milog`).
- **User docs:** `milog.md` — install, config, usage. Keep it in sync as
  features land.
- **Conventions:**
  - `set -euo pipefail` at the top — every new code path must survive this.
  - Empty-array expansions guarded with `if (( ${#arr[@]} > 0 ))` to stay
    safe under `set -u` on bash 3.2 (some users dev on Mac).
  - Config layering: hardcoded defaults → `$MILOG_CONFIG` file → env vars
    (`MILOG_*`) → auto-discover. Later wins. Every new config variable must
    fit this precedence.
  - All live tails use `tail -F` (uppercase) so logrotate doesn't break them.
  - Single awk pass per metric — don't spawn one awk per counter.
  - TUI redraws via `tput cup 0 0` + `\033[K`/`\033[J`, not `clear`.
- **Mode map** (current `mode_*` functions in `milog.sh`):
  - `mode_monitor`    — line 302  (full TUI)
  - `mode_rate`       — line 462
  - `mode_health`     — line 491
  - `mode_top`        — line 516
  - `mode_stats`      — line 535
  - `mode_grep`       — line 558
  - `mode_errors`     — line 569
  - `mode_probes`     — line 594
  - `mode_suspects`   — line 655
  - `mode_exploits`   — line 724
  - `mode_config`     — line 952
  - `show_help`       — line 1028
- **Dispatch** is a `case` statement near the bottom (after `show_help`).
  New subcommands go there.

Verify any line number before editing — the file changes fast. Grep for
function names instead.

## Scope

Three tracks, in the order they should be implemented. Each track is
independently shippable — don't block one on another.

1. **Discord alerts** (Action & response) — smallest, highest immediate value.
2. **Detection & signal** — response-time percentiles, slow endpoints, GeoIP.
3. **History & postmortem** — SQLite-backed metrics, trend/replay modes.

Out of scope for this phase: IP blocking/firewall integration, web dashboard,
Prometheus exporter, non-nginx sources. Note these as follow-ups; don't add
stubs.

---

## Track 1 — Discord alerts

**Goal:** turn passive dashboard into active notifier. When a threshold is
crossed or an exploit/probe pattern hits, POST to a Discord webhook.

### Config additions

```bash
DISCORD_WEBHOOK=""              # empty = alerts disabled
ALERTS_ENABLED=0                # explicit on/off so webhook can stay configured
ALERT_COOLDOWN=300              # seconds between repeats of the same rule:target
ALERT_STATE_DIR="$HOME/.cache/milog"
```

Wire these into the config precedence block at the top of `milog.sh`. Add
corresponding `milog config set` examples to `milog.md`.

### Core helper

Add near the top of the script, after the ANSI block:

```bash
alert_discord() {
    # $1 title  $2 body  $3 color_int (decimal, e.g. 15158332 for red)
    [[ "${ALERTS_ENABLED:-0}" != "1" ]] && return 0
    [[ -z "${DISCORD_WEBHOOK:-}" ]]     && return 0
    local title="$1" body="$2" color="${3:-15158332}"
    local payload
    payload=$(printf '{"embeds":[{"title":%s,"description":%s,"color":%d}]}' \
        "$(json_escape "$title")" "$(json_escape "$body")" "$color")
    curl -sS -m 5 -H "Content-Type: application/json" \
         -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
}

json_escape() {
    # Minimal JSON string escaper. Wraps output in double quotes.
    local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"
    printf '"%s"' "$s"
}
```

Curl is already a reasonable assumption (milog.md's install uses curl). If
curl is missing, silently no-op — don't crash the TUI.

### Cooldown / dedup

Alerts must not spam. Use a line-oriented state file:

```
rule_key<TAB>last_fired_epoch
```

`ALERT_STATE_DIR/alerts.state`. Helper:

```bash
alert_should_fire() {
    # $1 rule_key — returns 0 (fire) or 1 (suppress)
    local key="$1" now state_file="$ALERT_STATE_DIR/alerts.state"
    mkdir -p "$ALERT_STATE_DIR"
    now=$(date +%s)
    local last
    last=$(awk -v k="$key" -F'\t' '$1==k {print $2; exit}' "$state_file" 2>/dev/null)
    if [[ -n "$last" ]] && (( now - last < ALERT_COOLDOWN )); then
        return 1
    fi
    # Rewrite state file with updated timestamp
    local tmp="$state_file.tmp"
    { awk -v k="$key" -F'\t' 'BEGIN{OFS="\t"} $1!=k' "$state_file" 2>/dev/null
      printf '%s\t%s\n' "$key" "$now"
    } > "$tmp" && mv "$tmp" "$state_file"
    return 0
}
```

### Rule hook points

Implement these rules. Each has a stable `rule_key` for dedup.

| Rule | Key | Trigger |
|---|---|---|
| 5xx spike | `5xx:<app>` | `5xx_count_last_min >= THRESH_5XX_WARN` |
| 4xx spike | `4xx:<app>` | `4xx_count_last_min >= THRESH_4XX_WARN` |
| CPU crit | `cpu` | `cpu_usage >= THRESH_CPU_CRIT` |
| MEM crit | `mem` | `mem_usage >= THRESH_MEM_CRIT` |
| Disk crit | `disk:<mount>` | `disk_usage >= THRESH_DISK_CRIT` |
| Workers zero | `workers` | `nginx worker count == 0` |
| Exploit hit | `exploit:<app>:<category>` | line matched in `mode_exploits` patterns |
| Probe hit | `probe:<app>` | line matched in `mode_probes` patterns (coalesce per app per cooldown) |

Thresholds and patterns already exist. Add alert calls at the point of
detection — don't duplicate the matching logic.

### Headless daemon mode

New subcommand: `milog daemon`.
- Runs the sampler + rule evaluator on a loop at `REFRESH` cadence.
- No TUI, just logs decisions to stderr (quiet) and fires Discord alerts.
- Exits cleanly on SIGTERM/SIGINT.
- Document a systemd unit in `milog.md` (template below). Ship the template
  content inside `milog.md` — don't create a separate unit file in the repo.

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

### Testing

- Unit-test `json_escape` on an input with quotes, backslashes, and newlines
  — verify valid JSON round-trips (pipe into `python3 -c 'import sys,json;json.loads(sys.stdin.read())'`).
- Integration: set `DISCORD_WEBHOOK` to a real test webhook, run
  `milog daemon` in foreground, synthesize a 5xx burst by appending to a
  throwaway `*.access.log`, confirm one Discord message, confirm no repeats
  within cooldown.
- Confirm disabling works: `ALERTS_ENABLED=0` → `alert_discord` returns 0
  without calling curl (check with `strace` or by setting webhook to a
  non-routable URL and confirming no delay).

---

## Track 2 — Detection & signal

Three related additions. Do them in this order.

### 2a. Response-time percentiles

**Prereq:** nginx must log `$request_time`. Document in `milog.md` that the
user needs to extend their `log_format`:

```
log_format combined_timed '$remote_addr - $remote_user [$time_local] '
                          '"$request" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent" $request_time';
```

Detect the extended format by checking whether the field count per line is
>= 11 (combined has 10). If not, skip percentiles and show `—` in the UI
rather than erroring.

**New helper:** `percentiles <app>` — prints `p50 p95 p99` (space-separated,
in milliseconds) for the last minute's requests. Single awk pass that
collects `$request_time` values into an array, sorts, picks indices.

**Monitor integration:** add a new column or a second sub-row under each
app showing `p95` colored by threshold (`P95_WARN_MS=500`, `P95_CRIT_MS=1500`
— make configurable).

**Gotcha:** awk doesn't have a native sort. Either shell out to `sort -n`
via `printf ... | sort -n | awk '...'`, or use gawk's `asort`. Prefer
`sort -n` so non-gawk systems work.

### 2b. Slow endpoints

New mode: `milog slow [N]` (default N=10). For the last window (default
1000 lines/app — add `SLOW_WINDOW` config var), group by URL path
(strip query string), compute p95 per path, show top N sorted by p95 desc.

Output format matches existing `mode_top` aesthetics (box-drawing, colored
threshold). Reuse `hrule`/`draw_row` where practical.

### 2c. GeoIP enrichment

Use libmaxminddb's `mmdblookup` CLI — it's the path of least resistance
and already packaged on most distros (`apt install mmdb-bin` or
`libmaxminddb-tools` depending on distro).

**Config:**
```bash
MMDB_PATH="/var/lib/GeoIP/GeoLite2-Country.mmdb"
GEOIP_ENABLED=0   # off by default — requires user to download MMDB
```

Document in `milog.md` how to get a free GeoLite2 MMDB (MaxMind account →
download), where to put it, and how to auto-update (cron + `geoipupdate`
package). Don't ship or fetch the MMDB from the script.

**Helper:**

```bash
geoip_country() {
    # $1 ip → prints 2-letter country code or "—"
    [[ "${GEOIP_ENABLED:-0}" != "1" ]] && { printf '—'; return; }
    [[ ! -f "$MMDB_PATH" ]] && { printf '—'; return; }
    local out
    out=$(mmdblookup --file "$MMDB_PATH" --ip "$1" country iso_code 2>/dev/null \
          | awk -F'"' '/iso_code/ {print $2; exit}')
    printf '%s' "${out:-—}"
}
```

**Apply to:** `mode_top` (add COUNTRY column), `mode_suspects` (same).
Do NOT call per-line during live tails — only during the already-batched
aggregation step, otherwise you'll fork `mmdblookup` thousands of times.

### Testing

- Feed a synthetic log with known `$request_time` values; verify p50/p95/p99
  match expectation.
- Feed a combined log (no `$request_time`); verify graceful degradation.
- With `GEOIP_ENABLED=0`, verify no `mmdblookup` is spawned (`strace -f -e execve` on Linux).
- With a real MMDB and a known IP (`8.8.8.8` → `US`), verify country shown.

---

## Track 3 — History & postmortem

Biggest track. Adds a write path and new read modes.

### Storage

SQLite, at `${HISTORY_DB:-$HOME/.local/share/milog/metrics.db}`. Assume
`sqlite3` CLI is available (add to requirements in `milog.md`). Schema:

```sql
CREATE TABLE IF NOT EXISTS metrics_minute (
    ts        INTEGER NOT NULL,     -- unix epoch, minute-aligned
    app       TEXT    NOT NULL,
    req       INTEGER NOT NULL,
    c2xx      INTEGER NOT NULL,
    c3xx      INTEGER NOT NULL,
    c4xx      INTEGER NOT NULL,
    c5xx      INTEGER NOT NULL,
    p50_ms    INTEGER,              -- NULL if $request_time not logged
    p95_ms    INTEGER,
    p99_ms    INTEGER,
    PRIMARY KEY (ts, app)
);

CREATE TABLE IF NOT EXISTS top_ip_hour (
    ts_hour   INTEGER NOT NULL,     -- unix epoch, hour-aligned
    app       TEXT    NOT NULL,
    ip        TEXT    NOT NULL,
    hits      INTEGER NOT NULL,
    PRIMARY KEY (ts_hour, app, ip)
);

CREATE INDEX IF NOT EXISTS idx_metrics_app_ts ON metrics_minute(app, ts);
```

Initialize on first write (idempotent `CREATE TABLE IF NOT EXISTS`).

### Writer

A sampler loop that once per minute computes the same metrics the TUI
already computes, then UPSERTs into `metrics_minute`. Top IPs roll up once
per hour into `top_ip_hour`.

Shares the sampler loop with `milog daemon` (Track 1) — one background
loop, two consumers (alerts + history). Guard history writes with
`HISTORY_ENABLED=1`.

Use a single `sqlite3` invocation per minute with a heredoc batch of
`INSERT OR REPLACE` statements — don't spawn one process per app.

### Retention

Once per day (simple modulo check inside the minute loop), delete rows
older than `HISTORY_RETAIN_DAYS` (default 30) from both tables.

### Read modes

- **`milog trend [app] [hours]`** — ASCII chart of `req/min` for the last
  N hours (default 24). Reuse the sparkline renderer but wider. Show 4xx/5xx
  overlay as a second row.
- **`milog replay <log-file>`** — pipe an archived log through the same
  parsers that feed the live dashboard. Useful for postmortems. Honors all
  config, but writes nothing to history (read-only).
- **`milog diff`** — show req/min per app for the current hour vs same hour
  yesterday and same hour last week. Simple SQL query + formatted table.

### Testing

- Seed `metrics_minute` with synthetic rows and verify `milog trend` output.
- Run `milog daemon` against a live log for 5 minutes; confirm rows land.
- Confirm retention prune leaves `HISTORY_RETAIN_DAYS` of data and no more.
- `milog replay` on an old gzipped log (`zcat | milog replay /dev/stdin`)
  should work — document this in `milog.md`.

---

## Suggested commit cadence

Small commits, one per bullet below. Run the script after each to confirm
nothing regressed (at minimum: `milog help`, `milog config`, `milog monitor`
for a few seconds).

1. `alert_discord` + `json_escape` helpers, config vars (no call sites yet).
2. Cooldown state file + `alert_should_fire`.
3. Wire alerts into each rule hook point (one commit per rule is fine).
4. `milog daemon` subcommand skeleton.
5. Document Discord setup + systemd unit in `milog.md`.
6. Response-time parsing (detection + `percentiles` helper).
7. Monitor p95 column + thresholds.
8. `milog slow` mode.
9. GeoIP helper + apply to `top`/`suspects`.
10. SQLite schema init + writer.
11. `milog trend`.
12. `milog replay`.
13. `milog diff`.
14. Retention prune.

## Things to watch

- The TUI row width is hand-computed (`INNER=74`). Adding columns means
  recomputing — read the comment block at the top of the box-drawing
  section before touching widths.
- `set -euo pipefail` + associative arrays means empty-array iteration
  errors on bash 3.2. New ring buffers / maps need the same guard pattern
  as `HIST` in the existing code.
- Don't add `| cat`/`| head` inside single-awk-pass blocks — it breaks the
  "one awk per metric" principle and noticeably slows the monitor on busy
  servers.
- `tail -F` on macOS (BSD tail) doesn't behave the same as GNU. Target is
  Linux only; if you dev on Mac, test against a real Linux VM before
  claiming "done."
- Discord webhooks rate-limit at ~30 req/min per webhook. Cooldown defaults
  should keep us well under, but if alert rules ever fire in a burst,
  consider a small coalescing queue in `milog daemon` before sending.

## Not doing (yet)

- IP block/firewall actions.
- Non-nginx log sources (journald, docker).
- Web/HTML dashboard.
- Prometheus exporter.
- Multi-host aggregation.

If the user asks for any of these, treat them as a new plan phase, not an
inline extension of this one.
