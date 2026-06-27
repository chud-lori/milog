# TUI — `milog tui`

A richer Charm Bubble Tea-based TUI that runs alongside the existing
bash `milog monitor`. Same data source (system /proc readers + nginx
log tail), different render path: app overview, focused drill-downs,
global alerts, cross-app paths, pattern errors, trends, and contextual
key help.

## When to pick which

| Want                                            | Use               |
| ----------------------------------------------- | ----------------- |
| Works on any POSIX shell with no extra binary   | `milog monitor`   |
| Richer layout, nicer colors, contextual key help | `milog tui`      |
| Script-wrap or embed in a pager                 | `milog monitor`   |
| A TUI you can ship in a terminal-first dev loop | `milog tui`       |

Both pull the same numbers — if they disagree, that's a bug.

## Install

`milog tui` ships as a Go binary (`milog-tui`). The standard
curl-pipe installer downloads it automatically from the matching
GitHub Release — no Go toolchain on your server.

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh \
  | sudo bash
```

On a host with a published release for your arch, the installer prints
`Installed milog-tui → /usr/local/bin/milog-tui (from vX.Y.Z)` and
you're done.

If no release is published yet for your arch (or at all), the
installer prints `prebuilt binaries: no matching asset … — skipping`
and only the bash `milog.sh` lands. `milog monitor` still works;
`milog tui` prints an install hint.

**Pinning to a specific release** (useful for CI / reproducible
deploys): `MILOG_RELEASE_TAG=v0.3.2 curl … install.sh | sudo bash`.

**Contributor path** (cloning + building locally): `bash build.sh`
produces `go/bin/milog-tui`. Re-running `sudo ./install.sh` from the
clone picks those up instead of downloading — clone wins over Release
so contributor builds stay authoritative.

## Binary lookup order

`milog tui` looks for the binary in this order (first match wins):

- `$MILOG_TUI_BIN` (explicit override)
- `/usr/local/libexec/milog/milog-tui` (future package layout)
- `/usr/local/bin/milog-tui` ← where path 1 / 2 install it
- `go/bin/milog-tui` (dev layout, relative to the script)

If none are present, the "not installed" hint points at this page.

## Run it

```bash
milog tui
# or invoke the binary directly:
milog-tui
```

The footer always shows the keys that matter for the current view.
Press `?` for the full in-app help pane. Overview and list-style views
keep navigation predictable as rows grow: move the selection with arrow
keys or Vim-style keys, drill into the selected app, and use the named
views for longer alert/path/error/trend lists instead of letting the
overview overflow the terminal.

Keys (inside the TUI):

| Key                      | Action                                                                |
| ------------------------ | --------------------------------------------------------------------- |
| `q` / `Ctrl+C`           | quit                                                                  |
| `p`                      | pause (freeze sparklines + numbers)                                   |
| `r`                      | refresh now (bypasses the tick)                                       |
| `+` / `=`                | faster refresh (down to 1s)                                           |
| `-` / `_`                | slower refresh (up to 60s)                                            |
| `?`                      | toggle the contextual help pane                                       |
| `↑` / `k`, `↓` / `j`     | move row cursor in overview; scroll focused views                     |
| `enter` / `l` / `→`      | drill into the highlighted app — top paths, top IPs, recent alerts    |
| `esc` / `h` / `←` / `bs` | back to overview from any drill-down or named view                    |
| `f` / `pgdn` / space     | page down in focused views                                            |
| `b` / `pgup`             | page up in focused views                                              |
| `d` / `Ctrl+D`           | half-page down in focused views                                       |
| `u` / `Ctrl+U`           | half-page up in focused views                                         |
| `a`                      | global alerts view (last 24h, newest first, capped at 50)             |
| `P`                      | paths-cross-app view (top 12 paths summed across apps + breakdown)    |
| `e`                      | errors view (`app:*` rule fires aggregated by pattern → source)       |
| `t`                      | trend view (per-app 60-minute request-rate sparklines from history DB) |

Scrolling / long-view behavior is intentionally operator-oriented:
the TUI keeps dense summaries on screen, caps the expensive top lists,
and routes deeper inspection into focused views with their own key
footer, reload action, and Bubbles viewport scrolling. The same
selection/back/help model applies across panes instead of introducing
one-off keys per pane.

## Config

All settings come from the same env vars / config keys the bash side
uses — no separate TUI config:

| Env var         | Default          | Purpose                           |
| --------------- | ---------------- | --------------------------------- |
| `MILOG_APPS`    | auto-discover    | space-separated app names         |
| `MILOG_LOG_DIR` | `/var/log/nginx` | nginx access-log directory        |
| `MILOG_REFRESH` | `5`              | default seconds between ticks     |

So `milog config set REFRESH 3` changes both `milog monitor` and
`milog tui`.

## Non-TTY usage

For CI / packaging scripts, the binary has two non-TTY paths:

```bash
milog-tui --version    # prints "milog-tui v=<sha>" and exits
milog-tui --help       # prints keybinds + env vars and exits
```

Actual TUI rendering needs a real terminal (bubbletea relies on
raw-mode input + altscreen).

## Why `tui` AND `monitor`?

Per the project's bash-and-Go cohabitation rule: anything bash already
does well stays bash. `milog monitor` stays the default and always
will — it works on any POSIX host with zero extra install. `milog tui`
is the richer option for contributors / ops who already have the Go
binary installed (or want to build it).
