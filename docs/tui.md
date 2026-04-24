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

**Today, `milog tui` is contributor-only.** There's no prebuilt-binary
distribution yet (that's the packaging / release-engineering chunk
still on the roadmap). The standard user path — the `curl install.sh
| sudo bash` one-liner — installs bash `milog monitor` only; `milog
tui` will print an install hint.

Three ways to get the binary today, ordered by who they're for:

### 1. Copy a pre-built binary to your server

Build on any machine that has Go (your laptop, a CI runner):

```bash
git clone https://github.com/chud-lori/milog.git
cd milog
bash build.sh                          # produces go/bin/milog-tui
```

Then ship it to the server:

```bash
scp go/bin/milog-tui tencent:/tmp/
ssh tencent 'sudo install -m 0755 /tmp/milog-tui /usr/local/bin/milog-tui'
```

No Go toolchain on the server. Next `milog tui` picks the binary up
automatically via the lookup below.

### 2. Clone + build on the server itself (contributor layout)

Install Go and build on the box:

```bash
sudo apt install -y golang-go
git clone https://github.com/chud-lori/milog.git /opt/milog
cd /opt/milog && bash build.sh
sudo ./install.sh                      # copies milog + milog-tui to /usr/local/bin
```

`install.sh` auto-copies the binaries when they're sitting in
`go/bin/` next to the script. No separate step.

### 3. Wait for packaged releases

Once the roadmap's release-engineering work lands (goreleaser + `.deb`
/ `.rpm` / `.apk` / Homebrew), `curl install.sh | sudo bash` will
download prebuilt binaries alongside `milog.sh` by arch. For now, 1
or 2 are the paths.

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
