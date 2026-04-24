# TUI — `milog tui`

A richer bubbletea-based TUI that runs alongside the existing bash
`milog monitor`. Same data source (system /proc readers + nginx log
tail), different render path.

## When to pick which

| Want                                            | Use               |
| ----------------------------------------------- | ----------------- |
| Works on any POSIX shell with no extra binary   | `milog monitor`   |
| Richer layout, nicer colors, built-in help pane | `milog tui`       |
| Script-wrap or embed in a pager                 | `milog monitor`   |
| A TUI you can ship in a terminal-first dev loop | `milog tui`       |

Both pull the same numbers — if they disagree, that's a bug.

## Install

The Go binary (`milog-tui`) is built by `bash build.sh` when a Go
toolchain is on `$PATH`. From a clone:

```bash
git clone https://github.com/chud-lori/milog.git /opt/milog
cd /opt/milog
bash build.sh          # builds milog.sh + go/bin/milog-web + go/bin/milog-tui
```

`go/bin/milog-tui` is picked up automatically by `milog tui` when any
of these exist (first match wins):

- `$MILOG_TUI_BIN` (explicit override)
- `/usr/local/libexec/milog/milog-tui` (package layout)
- `/usr/local/bin/milog-tui`
- `go/bin/milog-tui` (dev layout relative to the script)

If none are present, `milog tui` prints a one-line install hint and
tells the user to fall back to `milog monitor` until packaged releases
arrive.

## Run it

```bash
milog tui
# or invoke the binary directly:
milog-tui
```

Keys (inside the TUI):

| Key         | Action                                       |
| ----------- | -------------------------------------------- |
| `q` / `Ctrl+C` | quit                                      |
| `p`         | pause (freeze sparklines + numbers)          |
| `r`         | refresh now (bypasses the tick)              |
| `+` / `=`   | faster refresh (down to 1s)                  |
| `-` / `_`   | slower refresh (up to 60s)                   |
| `?`         | toggle help pane                             |

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
