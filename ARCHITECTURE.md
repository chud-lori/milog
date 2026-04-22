# MiLog architecture

Internals for contributors. For install/usage, see [README.md](README.md).

## Overview

MiLog is a single-file bash script (`milog.sh`) that renders a TUI dashboard,
tails nginx access logs, detects scanner/exploit traffic, and — as of the
alerts work — fires Discord webhooks headlessly via `milog daemon`.

No build step. No runtime deps beyond bash 4+, coreutils, awk, `ps`, `df`,
and optionally `curl` (webhooks). Target: Linux VMs, `/var/log/nginx`.

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

Dispatch is a `case` statement at the bottom of the script. Each subcommand
maps to a `mode_*` function. To add a command:

1. Write `mode_foo`.
2. Add `foo) mode_foo ;;` to the dispatch block.
3. Add a line to `show_help`.

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

## Discord alerts

### Wire-level

`alert_discord` does one `curl -sS -m 5 -d '<payload>' "$DISCORD_WEBHOOK"`.
Fire-and-forget: error output is swallowed, return always 0. Callers always
background it with `&` so a slow Discord never stalls a render tick.

JSON string literals are built via `json_escape`, which wraps its input in
double quotes and escapes `\`, `"`, `\n`, `\r`, `\t`. The full payload is
constructed with `printf` field by field so a log line with embedded quotes
never breaks the JSON.

Discord's server-side rate limit is ~30 req/min per webhook. The cooldown
gate (default 300s) keeps us well under in normal operation.

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

1. Add the detection at the natural single source of truth for the metric
   (a mode function or a shared helper). Don't re-scan logs just to fire
   an alert.
2. Build a stable `rule_key` — the `<type>:<scope>` shape keeps keys
   predictable and greppable in the state file.
3. Call `alert_should_fire "<rule_key>"`, then on true call
   `alert_discord "..." "..." <color> &`.
4. Background the webhook. Always.
5. Document the rule key in the table in [README.md](README.md#what-fires)
   and here.

## Things to watch

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
