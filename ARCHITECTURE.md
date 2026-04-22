# MiLog architecture

Internals for contributors. For install/usage, see [README.md](README.md).

## Overview

MiLog renders a TUI dashboard, tails nginx access logs, detects
scanner/exploit traffic, and — via `milog daemon` + Discord webhooks — alerts
headlessly. A read-only web dashboard (`milog web`) exposes the same data
over HTTP with a minimal single-page HTML UI.

**Runtime deps:** bash 4+, coreutils, `awk` (gawk preferred), `ps`, `df`,
`curl` (alerts), `sqlite3` (history/trend/diff/auto-tune), and optionally
`socat`/`ncat` (web dashboard) and `mmdblookup` (GeoIP).

**Target:** Linux VMs, `/var/log/nginx` (or an arbitrary dir via `LOG_DIR`).

## Source layout

The shipping artifact is still `milog.sh` — a single bundled bash file
installed to `/usr/local/bin/milog`. Contributors don't edit it directly:
it's generated from `src/*.sh` by `build.sh`.

```
milog/
├── milog.sh          # bundled artifact (shipped to users; regenerated)
├── build.sh          # concatenates src/** → milog.sh
├── src/
│   ├── README.md     # contributor guide
│   ├── core.sh       # shebang, set -euo, config defaults, env overrides,
│   │                 # colors. This is the only file that executes at load.
│   ├── alerts.sh     # alert_discord, alert_should_fire, _exploit_category
│   ├── ui.sh         # box rules, geometry, milog_update_geometry
│   ├── system.sh     # cpu_usage, mem_info, disk_info, sparkline_render
│   ├── history.sh    # SQLite schema + writes, percentiles
│   ├── nginx.sh      # nginx_minute_counts, nginx_row, sys_check_alerts
│   ├── web.sh        # _web_* helpers for the read-only dashboard
│   ├── modes/*.sh    # one file per subcommand (mode_<name>)
│   └── dispatch.sh   # show_help + the final `case "${1:-}"`
├── install.sh        # downloads + installs milog.sh (unchanged UX)
└── docs/*.md
```

Order matters only for `src/core.sh` (first, executes) and `src/dispatch.sh`
(last, runs the chosen mode). Everything between is function definitions
whose load order is irrelevant.

CI contract: `bash build.sh && git diff --exit-code milog.sh` must succeed.
Editing a `src/*.sh` file without regenerating the bundle fails CI.

## Design principles

- **`set -euo pipefail`** at the top of `milog.sh`. Every new code path must
  survive this. Don't let pipe exit codes leak; use `|| true` where a grep
  miss is legitimate.
- **Single awk pass per metric.** No `| grep … | awk …` chains for counts.
  One parse, one metric output. Cheap enough to run every `REFRESH` tick
  on busy servers.
- **Bash 3.2 guards.** Some users dev on macOS. Empty-array iteration is
  undefined under `set -u` on old bash, so guard with
  `if (( ${#arr[@]} > 0 ))` wherever you expand a potentially empty array.
- **`tail -F` (uppercase).** Uses inode-reopen; survives logrotate. BSD
  `tail` is not equivalent — assume GNU coreutils.
- **TUI redraws via `tput cup 0 0` + `\033[K`/`\033[J`, not `clear`.** `clear`
  blinks; cursor-home + EOL-clear is flicker-free.
- **Never block the render loop.** Webhook sends run in background
  (`alert_discord … &`). The CPU sampler for `monitor` runs in a subshell
  feeding a tmpfile — the render loop reads the latest value without
  waiting on `sleep 0.2` inside `cpu_usage`.

## Configuration layering

Precedence (later wins):

1. Hardcoded defaults at the top of `milog.sh`.
2. User config file at `$MILOG_CONFIG` (default `~/.config/milog/config.sh`),
   sourced with `.`.
3. Env var overrides — currently `MILOG_LOG_DIR`, `MILOG_APPS`, and Discord
   vars when set in the shell before invoking MiLog.
4. Auto-discover — only kicks in when `LOGS` is empty after the above.

**Every new config variable must fit this precedence.** Declare the default
in the top block (*before* the `. "$MILOG_CONFIG"` line), so the config file
can override it. Don't declare defaults later in the script — they'll stomp
the user's config.

## Runtime model

Dispatch is a `case` statement in `src/dispatch.sh` that runs after every
other file has been sourced. Each subcommand maps to a `mode_*` function
defined in `src/modes/<cmd>.sh`. To add a command:

1. Create `src/modes/foo.sh` with a `mode_foo` function.
2. Add `foo) mode_foo ;;` to the dispatch block in `src/dispatch.sh`.
3. Add a line to `show_help` (also in `src/dispatch.sh`).
4. Run `bash build.sh` to regenerate `milog.sh`.
5. Commit both the new source file and the regenerated `milog.sh`.

Component index (subject to drift — grep for function names, don't trust
line numbers):

| Function                  | Role                                              |
| ------------------------- | ------------------------------------------------- |
| `mode_monitor`            | Full TUI loop                                     |
| `mode_daemon`             | Headless rule evaluator                           |
| `mode_rate`               | Nginx-only req/min TUI                            |
| `mode_health`             | Per-app 2xx/3xx/4xx/5xx totals                    |
| `mode_top`                | Top-N source IPs                                  |
| `mode_stats`              | Hourly histogram for one app                      |
| `mode_grep`               | Filter-tail one app                               |
| `mode_errors`             | Multi-app 4xx/5xx live tail                       |
| `mode_exploits`           | L7 attack payload live tail                       |
| `mode_probes`             | Scanner/bot UA live tail                          |
| `mode_suspects`           | Behavioral IP ranking                             |
| `mode_top_paths`          | Per-URL req / 4xx / 5xx / p95 (query-stripped)    |
| `mode_trend`              | Sparkline chart from `metrics_minute`             |
| `mode_diff`               | Hour-level now vs 1d ago vs 7d ago                |
| `mode_auto_tune`          | Suggest thresholds from history percentiles       |
| `mode_doctor`             | Runtime health/config checklist                   |
| `mode_config`             | Config-file subcommand router                     |
| `color_prefix`            | Default merged log tail                           |

Shared helpers (must be callable from any mode):

| Helper                      | Role                                              |
| --------------------------- | ------------------------------------------------- |
| `nginx_minute_counts`       | One-pass awk: count, c4, c5 for an app            |
| `nginx_check_http_alerts`   | Fire 4xx/5xx spike rules                          |
| `sys_check_alerts`          | Fire CPU/MEM/DISK/workers rules                   |
| `nginx_row`                 | Render one table row (calls the two above)        |
| `alert_discord`             | POST embed to webhook (noop when disabled)        |
| `alert_should_fire`         | Cooldown gate                                     |
| `json_escape`               | Minimal JSON string escaper                       |
| `_exploit_category`         | Classify an exploit match into a category slug    |
| `_dlog`                     | Timestamped stderr log (daemon)                   |
| `percentiles` / `_p95_cached` | Per-minute p50/p95/p99 on `$request_time` field |
| `_pct_from_stdin`           | Stream-based percentile for auto-tune             |
| `milog_update_geometry`     | Recompute `INNER`/`W_BAR`/`BW` from `tput cols`   |

## TUI rendering

The box drawing is hand-computed and **reflows to terminal width** each
render tick. `milog_update_geometry()` reads `tput cols` (or `MILOG_WIDTH`
if set) and sets `INNER` to `cols-2`, clamped to `[MIN_INNER=74,
MAX_INNER=200]`. Fixed columns (`W_APP=10`, `W_REQ=8`, `W_ST=10`) stay
constant; the slack flows into `W_BAR` (INTENSITY/sparkline column), and
the 3-bar sysmetric row picks up `BW = (INNER - 40) / 3`. Adding a new
column means updating both the geometry helper and the border rule fns
(`bdr_top`/`bdr_hdr`/`bdr_sep`) — read the comment block at the top of the
box-drawing section before touching widths.

Sparklines use 8 Unicode block characters (`▁▂▃…█`). Each app's ring buffer
lives in a global associative array `HIST`. When paused (`p` key), the
sampler skips pushing new samples so the displayed line freezes.

## Alerts

### Fanout

`alert_fire <title> <body> [color] [rule_key]` is the one public entry
point. It records to `alerts.log` (see below) and then dispatches to
every configured destination:

| Destination | Config                                    | Format       |
| ----------- | ----------------------------------------- | ------------ |
| Discord     | `DISCORD_WEBHOOK`                          | embed JSON   |
| Slack       | `SLACK_WEBHOOK`                           | mrkdwn JSON  |
| Telegram    | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | HTML in JSON |
| Matrix      | `MATRIX_HOMESERVER` + `_TOKEN` + `_ROOM`  | html + text  |

Each `_alert_send_<dest>` silently no-ops when its own config is missing
(opt-in), so configuring Slack doesn't require touching Discord and vice
versa. All destinations share the cooldown + `(ip, path)` dedup gate — one
logical event produces one alert per destination, not N.

Backwards compat: `alert_discord` is kept as a thin alias to
`alert_fire`. New code should call `alert_fire`.

### Wire-level

Each sender does one `curl -sS -m 5 …` with the wire format for its
service. Fire-and-forget: error output is swallowed, return always 0.
Callers background the whole `alert_fire` call with `&` so a slow
webhook never stalls a render tick, and the dispatcher further
backgrounds each per-destination send so one laggy service doesn't
delay the others.

### Injection defenses

Log lines embedded in `body` are attacker-controlled (User-Agent, URL,
headers). Each destination applies the right encoding:

- **Discord**: `json_escape` on every string. `"allowed_mentions":
  {"parse":[]}` blocks `@everyone` / `<@role>` pings from log content.
  Triple-backtick wrap renders markdown as literal text.
- **Slack**: `json_escape` on the composed text; body's own backticks
  are rewritten to single quotes so an attacker can't close the code
  block early. `"link_names": 0` keeps `<@channel>` literal.
- **Telegram**: `parse_mode: "HTML"`, so every user value goes through
  `html_escape` before assembly into `<b>…</b><pre>…</pre>`. Tags in log
  lines (`<script>`, `<a>`) render as `&lt;script&gt;`.
  `disable_web_page_preview: true` blocks unfurls on log-embedded URLs.
- **Matrix**: plain `body` is literal (no HTML rendering). The
  `formatted_body` uses `html_escape` same as Telegram. Room ID with `!`
  and `:` is passed through `_url_encode` before landing in the PUT path.

Discord's server-side rate limit is ~30 req/min per webhook. The cooldown
+ dedup gates keep us well under in normal operation.

### Cooldown state

`$ALERT_STATE_DIR/alerts.state` is a flat file:

```
<rule_key><TAB><last_fired_epoch>
```

`alert_should_fire <key>`:

1. Reads the current epoch for `<key>` via awk.
2. If `now - last < ALERT_COOLDOWN`, returns 1 (suppress).
3. Otherwise: write a temp file with all lines except `<key>`, append the
   new `<key> <now>`, `mv` atomically, return 0 (fire).

Atomic `mv` is the concurrency story. Multiple backgrounded modes
(`mode_exploits` + `mode_probes` + `mode_daemon`) can all try to write; the
last write wins. Worst case is a lost update — acceptable for dedup
purposes.

### Cross-rule event dedup

A single scanner logline often matches both `exploits` (by URL) and
`probes` (by user-agent). The per-rule cooldown above doesn't help —
each rule has a distinct key and both fire independently on the same
event. The fingerprint gate stops that:

- **State file:** `$ALERT_STATE_DIR/alerts.fingerprints`, same tabbed
  format as `alerts.state`.
- **Fingerprint shape:** `<ip>:<path>` with query string stripped
  (`alert_fingerprint_from_line` extracts it).
- **TTL:** `ALERT_DEDUP_WINDOW` (default 300s, tunable separately from
  `ALERT_COOLDOWN`).
- **Helper:** `alert_fingerprint_fresh <fp>` — returns 0 (fire) if fp is
  new or its last record has expired AND atomically records `<fp>\t<now>`;
  returns 1 (suppress) otherwise. Empty fp opts-out (used when the log
  line can't be parsed).
- **Wire-up:** call AFTER `alert_should_fire` with `&&` so the common
  case (quiet server) short-circuits without touching the fingerprint
  file. Example from `mode_exploits`:

  ```bash
  fp=$(alert_fingerprint_from_line "$line")
  if alert_should_fire "exploit:$app:$cat_slug" \
     && alert_fingerprint_fresh "$fp"; then
      alert_discord "..." "..." 15158332 &
  fi
  ```

The entry-expiry in `alert_fingerprint_fresh` (drops rows older than
`2×TTL` on every write) keeps the file bounded on long uptimes —
unlike `alerts.state` which has a fixed key space.

### Alert history log

Every fire goes through `alert_discord`, which calls `_alert_record`
before the curl. The log at `$ALERT_STATE_DIR/alerts.log` is append-only
TSV:

```
<epoch>  <rule_key>  <color_int>  <title>  <body_truncated>
```

- `rule_key` is the 4th argument to `alert_discord` — callers pass the
  same string they gave `alert_should_fire`. Optional but highly
  preferred; default is the literal `unknown` which makes the record
  harder to filter later.
- Body is tab/newline-stripped and capped at 300 chars so each record
  stays on one line (greppable, awk-splittable by `\t`).
- Recording happens **before** the Discord POST, so entries exist even
  when the webhook is unreachable. Useful for "did anything fire but not
  deliver?" investigations.
- No rotation. One line per fire, bounded by `ALERT_COOLDOWN` per rule
  and `ALERT_DEDUP_WINDOW` cross-rule — negligible growth on most
  deployments. Truncate manually if it ever matters:
  `> ~/.cache/milog/alerts.log`

`milog alerts [window]` reads this file. Window grammar is
`today / yesterday / all / Nh / Nd / Nw` (parsed by
`_alerts_window_to_epoch` in `src/modes/alerts.sh`). The timeline table
colors rules by severity using the recorded color int — red for crit,
yellow for warn, green for info.

### Rule keys

Stable, grep-friendly strings used by the cooldown gate:

| Rule              | Key                          |
| ----------------- | ---------------------------- |
| 5xx spike         | `5xx:<app>`                  |
| 4xx spike         | `4xx:<app>`                  |
| CPU crit          | `cpu`                        |
| MEM crit          | `mem`                        |
| Disk crit         | `disk:<mount>` (currently `disk:/`) |
| Workers zero      | `workers`                    |
| Exploit match     | `exploit:<app>:<category>`   |
| Probe match       | `probe:<app>`                |

Categories emitted by `_exploit_category`: `traversal`, `infra`, `device`,
`wordpress`, `phpmyadmin`, `dotfile`, `log4shell`, `sqli`, `xss`, `rce`,
`scanner`, `other`. Substring-matched (case-insensitive via `shopt
nocasematch`); precision only has to be good enough to group alerts.

## Daemon

`mode_daemon` is a headless loop that runs at `REFRESH` cadence and:

1. Starts `mode_exploits` and `mode_probes` in subshells with stdout
   redirected to `/dev/null`. Their existing alert call sites fire webhooks
   directly.
2. In the main loop: computes CPU/MEM/DISK via the same helpers `mode_monitor`
   uses, counts workers via `ps aux | awk '/nginx: worker/'`, calls
   `sys_check_alerts` and per-app `nginx_check_http_alerts`.
3. Traps `INT`/`TERM`, kills watcher subshells, logs shutdown, exits 0.

Decision log goes to stderr via `_dlog`. Stdout is silent so `journalctl`
stays clean.

## Extending — how to add a new alert rule

1. Edit the right file under `src/` — detection lives at the natural single
   source of truth for the metric (usually a mode file in `src/modes/`, or
   `src/nginx.sh` for HTTP rules, `src/system.sh` for CPU/MEM/DISK). Don't
   re-scan logs just to fire an alert.
2. Build a stable `rule_key` — the `<type>:<scope>` shape keeps keys
   predictable and greppable in the state file.
3. Call `alert_should_fire "<rule_key>"`, then on true call
   `alert_discord "..." "..." <color> &`.
4. Background the webhook. Always.
5. Document the rule key in the table in [README.md](README.md#what-fires)
   and here.
6. Run `bash build.sh` and commit the regenerated `milog.sh` alongside the
   source change.

## Things to watch

- **Regenerate the bundle.** Editing `src/*.sh` without running `bash build.sh`
  produces a diff in `src/` but no behavior change on deployed boxes. CI
  catches this (`git diff --exit-code milog.sh`) but local testing won't.
- Adding TUI columns → recompute `INNER` and every `hrule` / `spc` width.
- Empty associative-array iteration under `set -u` on bash 3.2 — guard.
- Don't insert `| cat` / `| head` inside single-awk-pass blocks — it
  breaks the "one awk per metric" principle and noticeably slows the
  monitor on busy servers.
- `tail -F` on macOS (BSD tail) doesn't behave the same as GNU. Target is
  Linux only; test against a real Linux VM before claiming "done."
- Discord rate limit is ~30 req/min per webhook. Cooldown defaults keep us
  under, but a burst of rule hits inside one cooldown window still all
  produce webhooks if they're separate rule keys. Consider a coalescing
  queue in `mode_daemon` if this ever matters in practice.
- **HTTP responses built in bash:** use byte-count (`wc -c`) for
  `Content-Length`, not `${#var}` — under UTF-8 locales the latter counts
  codepoints and truncates multi-byte responses. See `_web_respond` in
  `src/web.sh` for the pattern.
