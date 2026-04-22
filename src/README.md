# `src/` — split source of `milog.sh`

## TL;DR

- **Users:** ignore this directory. `milog.sh` at the repo root is still the
  single-file artifact that ships to `/usr/local/bin/milog`. The installer
  downloads it unchanged.
- **Contributors:** edit files under `src/`, then run `bash build.sh` to
  regenerate `milog.sh`. CI verifies the regenerated file matches the
  committed one.

## Layout

```
src/
├── core.sh         # shebang, set -euo pipefail, config defaults,
│                   # MILOG_CONFIG file load, env overrides, auto-discover,
│                   # log-dir validation, colors, json_escape.
│                   # Everything here executes at source time — not just
│                   # function definitions. Must come first.
├── alerts.sh       # Discord alert helpers: alert_discord, alert_should_fire,
│                   # _exploit_category, json_escape.
├── ui.sh           # TUI geometry: box rules, draw_row, trow, hdr_row,
│                   # milog_update_geometry (reflow to terminal width).
├── system.sh       # /proc-based metrics: cpu_usage, mem_info, disk_info,
│                   # net_rx_tx, fmt_bytes, ascii_bar, sparkline_render, tcol.
├── history.sh      # SQLite schema + writes: history_init, history_write_*,
│                   # history_prune, percentiles, _p95_cached, _pct_from_stdin,
│                   # _history_precheck, _sql_quote.
├── nginx.sh        # Log-parsing helpers called by many modes:
│                   # nginx_minute_counts, nginx_check_http_alerts, nginx_row,
│                   # sys_check_alerts, geoip_country, color_prefix, wait_or_key.
├── web.sh          # Everything for `milog web` *except* the mode_web entry
│                   # point: _web_handle, _web_respond, _web_route_*,
│                   # _web_token_*, _web_access_log, _web_status, _web_stop.
├── modes/
│   └── *.sh        # One file per `milog <subcommand>`. Each defines a
│                   # single `mode_<name>` function (plus private `_<name>_*`
│                   # helpers when they're mode-specific, e.g. modes/alert.sh
│                   # carries _alert_* helpers, modes/config.sh carries _cfg_*).
└── dispatch.sh     # `show_help` + the final `case "${1:-}"` that routes
                    # the CLI to a mode. Always concatenated last.
```

## The rules

1. **Functions only, mostly.** `core.sh` is the one file that *runs code at
   load time* (reading config, applying env overrides). Every other file
   should be function definitions and comments — no side-effects during
   sourcing.

2. **Don't cross-reference across files by line number.** Comments that say
   "see line 1234" rot instantly after a split. Reference by function name.

3. **New config variable?** Add the default in `core.sh` *before* the
   `MILOG_CONFIG` source line (so user configs can override), then add the
   env override in the `MILOG_*` block right after.

4. **New mode?** Create `src/modes/<name>.sh` with one `mode_<name>()`
   function. Add the dispatch entry to `src/dispatch.sh`. Update `show_help`
   in the same file.

5. **Bundling is deterministic.** `build.sh` concatenates files in a fixed
   order: `core → alerts → ui → system → history → nginx → web → modes/* →
   dispatch`. `modes/*.sh` uses shell glob order (alphabetic). That order
   matters for readability of diffs, not correctness — every file is pure
   function definitions, so redefinition order is irrelevant.

## Workflow

```bash
# Edit a single mode
$EDITOR src/modes/doctor.sh

# Rebuild the shipping artifact
bash build.sh

# Verify
bash -n milog.sh                      # syntax
bash milog.sh doctor                  # smoke-test
bats tests/                           # unit tests (when they exist)

# Commit both the source change AND the regenerated milog.sh
git add src/modes/doctor.sh milog.sh
git commit -m "doctor: <what you changed>"
```

CI should run `bash build.sh && git diff --exit-code milog.sh` so nobody
ships a source change without regenerating the bundle.
