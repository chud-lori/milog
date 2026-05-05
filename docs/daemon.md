# `milog daemon`

The **headless** mode of MiLog: no TUI, no keyboard input, just the
rule evaluator running on a loop. It's what you run on a server where
nobody is watching a terminal.

Same rules as the interactive modes — 5xx/4xx spikes, CPU / MEM / disk
/ worker thresholds, exploit + probe pattern matches — all wired to
whichever [alert destinations](alerts.md) you've configured with
per-rule cooldown + cross-rule dedup. When
[`HISTORY_ENABLED=1`](historical-metrics.md), it also writes one
per-minute row per app into SQLite.

## Run it as a systemd service (recommended)

Use the `alert on` subcommand — it installs the unit, runs the daemon
as your user, and points at your config file:

```bash
sudo milog alert on 'https://discord.com/api/webhooks/ID/TOKEN'
# or, if webhook is already in your config:
sudo milog alert on
```

This writes `/etc/systemd/system/milog.service`, enables it, and
starts it. Survives SSH disconnect and reboot.

### Manage it

```bash
milog alert status         # destinations / enabled / service / recent fires
milog alert test           # fire a test embed to every configured destination
sudo milog alert off       # pause — stops service + sets ALERTS_ENABLED=0
```

Low-level controls if you need them:

```bash
sudo systemctl status milog.service
sudo systemctl restart milog.service          # after editing config
sudo journalctl -u milog.service -f           # tail the decision log
```

## Run it in the foreground (quick test)

```bash
milog daemon     # Ctrl-C to stop; stderr is the decision log
```

Useful for verifying your config before flipping it on as a service —
you see every rule evaluation + every webhook fire + every
cooldown/dedup suppression in real time.

## Permissions on `/var/log/nginx`

The daemon needs to read the access logs. Either:

- Add your user to the `adm` group: `sudo usermod -aG adm $USER` →
  log out and back in → `alert on` will run the daemon as you, and it
  can read the logs.
- Or edit `/etc/systemd/system/milog.service` to `User=root` after
  `alert on` creates it.

`milog doctor` will tell you which one you need.

## What the daemon does per tick

Every `REFRESH` seconds (default 5):

1. Reads `/proc/stat`, `/proc/meminfo`, `df /` → fires CPU / MEM /
   DISK / workers alerts if any exceed `THRESH_*_CRIT`.
2. Per app: one awk pass over the access log for the current minute
   → counts req / 2xx / 3xx / 4xx / 5xx. Fires 4xx and 5xx spike
   alerts if any exceed `THRESH_4XX_WARN` / `THRESH_5XX_WARN`.

On top of the per-tick work, two subshells run `tail -F` loops:

- **`mode_exploits`** — matches the URL pattern catalog (LFI / RCE /
  SQLi / XSS / infra probes / CMS scans / dotfile probes). Each
  match fires an `exploit:<app>:<category>` alert.
- **`mode_probes`** — matches the scanner user-agent catalog (zgrab,
  masscan, nikto, Shodan, CensysInspect, AI crawlers, generic HTTP
  libs). Each match fires a `probe:<app>` alert.

Cross-rule dedup keyed on `(ip, path)` ensures one scanner line
doesn't produce two alert embeds.

Once per minute: history write (if enabled), then — when
`ANOMALY_ENABLED=1` — a same-minute-of-day σ check across the
14-day baseline (`anomaly:<app>:<metric>` rule keys; see
[historical-metrics.md](historical-metrics.md#anomaly-detection)).
Once per hour: top-IP rollup (if enabled).
Once per day: history prune (drops rows older than `HISTORY_RETAIN_DAYS`).

The audit watcher (`mode_audit`) ticks alongside the rule evaluator
when `AUDIT_ENABLED=1`. Each sub-mode (fim / persistence / ports /
yara / accounts / rootkit) is throttled by its own
`AUDIT_*_INTERVAL`, so calling them every tick is cheap — the
intervals do the gating.

## Probe sidecar (Linux only)

`milog daemon` is the bash side. The eBPF probe sidecar is a separate
systemd unit installed via `sudo milog probe install-service`. The two
share state via `milog _internal_alert` — when the probe matches a
rule, it shells out to milog (the same binary the daemon runs) which
goes through `alert_should_fire` + `alert_fire`. Cooldown / silence /
dedup / routing / hooks all apply uniformly to probe alerts and bash-
side alerts. See [probe.md](probe.md) for the probe's own service
management.

## Update after `curl | bash`

The binary gets replaced atomically by the installer, but the
**running** daemon has the old code loaded in memory — restart to pick
up the new version:

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash
sudo systemctl restart milog.service
milog doctor                 # confirm post-restart state
```

## Decision log

Stdout of the daemon is silent (keeps `journalctl` clean when you're
tailing for real alerts). Stderr carries one line per decision:

```
[2026-04-22 14:01:33] minute bucket written (app=dolanan req=42 …)
[2026-04-22 14:01:33] alert_should_fire 5xx:dolanan → suppress (cooldown 180s remaining)
[2026-04-22 14:01:35] webhook fired: exploit:dolanan:scanner
```

Tail with `sudo journalctl -u milog.service -f`.
