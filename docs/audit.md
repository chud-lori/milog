# Host integrity audits

`milog audit` is a set of point-in-time host integrity scans. Each mode
fingerprints its slice of the system on first run, then alerts on drift.
They're cheap (one fingerprint pass per interval) and bash-only — no
agent, no daemon-of-daemons, no signature feed to keep fresh.

| Mode          | What it watches                                                          | Catches                                                  |
| ------------- | ------------------------------------------------------------------------ | -------------------------------------------------------- |
| `accounts`    | line-level diff over `/etc/passwd`, `/etc/sudoers*`, `authorized_keys`   | back-door SSH keys, sudoers escalation, password edits   |
| `fim`         | SHA256 of any path you list in `AUDIT_FIM_PATHS`                         | tampering with config, binaries, web roots               |
| `persistence` | new entries under cron / systemd / rc.local / `~/.bashrc` etc.           | re-entry mechanisms after exploit                        |
| `ports`       | listening TCP/UDP sockets via `ss` (or `netstat` fallback)               | reverse shells, unexpected services bound to the box     |
| `rootkit`     | hidden process, `LD_PRELOAD`, `/tmp` exec, deleted-but-running exe      | classic Linux rootkits + post-exploit transients         |
| `yara`        | YARA rules over directories you point at it (e.g. webroot)               | webshells, droppers, known malware families              |

`accounts` / `fim` / `persistence` / `ports` follow the same lifecycle:
`baseline` → `check` → `status`. `rootkit` is heuristic-only (no
baseline). `yara` needs the system `yara` binary plus a rules dir
(`milog audit yara init` writes a starter set).

## Turning it on

```bash
# Enable the audit watcher inside milog daemon.
milog config set AUDIT_ENABLED 1

# (Optional) override intervals — defaults are 1h for everything except yara
# (24h) and the daemon tick (60s):
milog config set AUDIT_FIM_INTERVAL 1800        # 30 min
milog config set AUDIT_ROOTKIT_INTERVAL 600     # 10 min

# Start the daemon if it isn't already (also pulls in alert routing):
sudo milog alert on
```

The daemon auto-baselines on first encounter, then fires on every
subsequent drift with rule keys like:

```
audit:fim:MODIFIED:<path>
audit:accounts:NEW:<path>
audit:persistence:APPEARED:<path>
audit:ports:NEW:<proto>:<port>
audit:rootkit:<heuristic>
audit:yara:<rule>:<path>
```

These flow through the same `ALERT_ROUTES` / cooldown / silence /
hooks plumbing as everything else (see [alerts.md](alerts.md)). You
can route `audit:*` to a higher-severity channel, for instance.

## Verify it actually catches things

Run these end-to-end at install time. Each one is a controlled
provocation that should trigger detection — if any of them silently
pass, your alert pipeline has a wiring problem to fix *before* an
attacker exercises the same path. Sample output below is from a real
Ubuntu 24.04 VM.

### 1. Fake `authorized_keys` entry

```console
$ sudo bash -c 'echo "ssh-rsa AAAAFAKEKEY MILOG_TEST" >> /root/.ssh/authorized_keys'
$ sudo milog audit accounts check
NEW lines (alert-worthy):
  ADDED      /root/.ssh/authorized_keys  ::  ssh-rsa AAAAFAKEKEY MILOG_TEST

$ sudo sed -i '/MILOG_TEST/d' /root/.ssh/authorized_keys
$ sudo milog audit accounts baseline
baseline written under /root/.cache/milog/audit/accounts
  tracked: 6 files
```

### 2. Modify a watched config file (FIM)

```console
$ sudo milog audit fim baseline
baseline written to /root/.cache/milog/audit/fim.baseline
  tracked: 7 present, 1 missing

$ echo '# milog-test-comment' | sudo tee -a /etc/sudoers >/dev/null
$ sudo milog audit fim check
drift detected:
  MODIFIED     /etc/sudoers                                        e37f3c98…→c00a18b2…

$ sudo sed -i '/milog-test-comment/d' /etc/sudoers
```

### 3. Rootkit — `/tmp` exec heuristic

The heuristic checks `/proc/<pid>/exe` (the resolved binary the kernel
loaded). For a `#!/bin/bash` script this resolves to `/bin/bash`, not
the script — so shell scripts slip through. Real attackers usually
drop a *compiled* binary, so the test should mirror that:

```console
$ cp /bin/sleep /tmp/milog-test-exec
$ /tmp/milog-test-exec 60 &
$ sudo milog audit rootkit check
rootkit hints:
  exec_from_tmp:milog-test-exec             pid=… exe=/tmp/milog-test-exec

$ kill %1; rm /tmp/milog-test-exec
```

### 4. Rootkit — `LD_PRELOAD`

The heuristic flags presence of `/etc/ld.so.preload` regardless of
content (anything in there hooks every dynamically-linked binary):

```console
$ echo '# test' | sudo tee /etc/ld.so.preload >/dev/null
$ sudo milog audit rootkit check
rootkit hints:
  ld_preload_present                        /etc/ld.so.preload exists: # test

$ sudo rm /etc/ld.so.preload
```

### 5. Persistence — fake cron job

```console
$ sudo milog audit persistence baseline
baseline written to /root/.cache/milog/audit/persistence.baseline
  tracked: 30 paths in re-entry surface

$ echo '* * * * * root echo milog-test' | sudo tee /etc/cron.d/milog-test >/dev/null
$ sudo milog audit persistence check
NEW persistence entries (alert-worthy):
  APPEARED   /etc/cron.d/milog-test

$ sudo rm /etc/cron.d/milog-test
```

### 6. Ports — new listener

```console
$ sudo milog audit ports baseline
baseline written to /root/.cache/milog/audit/ports.baseline
  tracked: 18 listeners

$ python3 -m http.server 19999 >/dev/null 2>&1 &
$ sudo milog audit ports check
NEW listeners (alert-worthy):
  NEW    tcp   0.0.0.0:19999

$ kill %1
```

### 7. Alert pipeline reachability

This proves Discord / Slack / etc. is wired correctly without writing
to any audit baseline:

```console
$ milog alert test
Firing test alert to: discord
✓ fanout dispatched — check each channel; any silent dest is a wire issue, not a config issue
```

A `[TEST]` message should land in the configured channel. If a
destination is silent, the channel is misconfigured (wrong webhook,
revoked token, etc.) — not a milog bug.

### 8. End-to-end with the daemon in the loop

After steps 1–7 work standalone, exercise the **integrated** path:

```bash
sudo milog alert on              # daemon ticks every 60s
echo '# integration-test' | sudo tee -a /etc/sudoers >/dev/null
# Within the next minute → alert fires → routed to your channel.
sudo sed -i '/integration-test/d' /etc/sudoers
```

That's the real win — the audit detects, the daemon ticks, the alert
lands without you running `check` manually.

## Known false positives

Two patterns to recognise before they become noise:

### `deleted_exe:<comm>` after a package upgrade

When `apt upgrade` (or equivalent) replaces a binary while a
long-running service still has the old inode mapped, that service's
`/proc/<pid>/exe` resolves to `<path> (deleted)` until it restarts.
Common offenders: `agetty`, `networkd-dispatcher`, `unattended-upgrades`,
any Python service.

```console
rootkit hints:
  deleted_exe:agetty                pid=1359 comm=agetty exe=/usr/sbin/agetty (deleted)
```

Fix without rebooting:

```bash
# Restart the affected services so they re-exec from the new binary.
sudo systemctl restart networkd-dispatcher.service unattended-upgrades.service

# agetty: bounce the running getty units (kills the console login prompt
# briefly — your SSH session is unaffected).
sudo systemctl restart $(systemctl list-units --state=active --plain --no-legend \
  | grep -E '(serial-)?getty@' | awk '{print $1}')
```

The same hits will fire again after the next package upgrade — that's
expected. A `deleted_exe` hit at a time *not* correlated with a
package upgrade is the one to investigate (e.g.
`exe=/tmp/<random> (deleted)` after a webshell pop).

### `audit:fim:MODIFIED` from log rotation / package management

If you put `/var/log/auth.log` or any actively-written file in
`AUDIT_FIM_PATHS`, it'll drift on every check. FIM is for
**config + binaries**, not log files. Same for paths under
`/var/lib/dpkg/` or package-manager state — these change on every
`apt upgrade`. Keep the watchlist tight.

## Tuning

```bash
# Add custom files to the FIM watchlist (defaults already cover
# /etc/passwd, /etc/sudoers*, /etc/ssh/sshd_config, /etc/hosts, etc.):
milog config set AUDIT_FIM_PATHS "/etc/nginx/nginx.conf /etc/nginx/sites-enabled/*"

# Add directories to scan for persistence (defaults already cover
# /etc/cron*, /etc/systemd/system/, ~/.bashrc, /etc/rc.local):
milog config set AUDIT_PERSISTENCE_PATHS "/opt/myapp/cron.d/*"

# Restrict YARA scanning to your webroot (default: empty — disabled):
milog config set AUDIT_YARA_PATHS "/var/www /tmp"

# Per-channel routing — send any audit hit to its own destination:
milog config set ALERT_ROUTES "audit:*=slack"
```

After any path-list change, rebaseline that mode so the new entries
become part of the known-good state instead of firing once on next
check:

```bash
sudo milog audit fim baseline
sudo milog audit persistence baseline
```

## Outside-in checks (separate from milog)

Worth doing at install time, but orthogonal to the audit modes — these
test the server itself, not your monitoring of it:

```bash
# What's actually reachable from the public internet?
# (Run from a DIFFERENT machine.)
nmap -Pn -sT -p- <your-server-ip>
# Expect: only the ports you intend to expose. Anything else is a
# misconfiguration to fix before the next attacker scanner finds it.

# On the server: which listeners bind beyond loopback?
ss -tlnp | awk '$4 !~ /^127\./ && $4 !~ /^\[::1\]:/'

# sshd hardening:
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|x11forwarding'
# Want: PermitRootLogin no (or prohibit-password), PasswordAuthentication no,
# X11Forwarding no.
```

These are one-time install-time checks. Once the server is hardened,
`milog audit` keeps it that way by alerting when something *changes*.
