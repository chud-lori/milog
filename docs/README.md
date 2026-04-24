# MiLog documentation

Topical guides. The main [README](../README.md) covers install + 5-minute
quick start; this directory has everything else.

## By capability

- [**Configuration**](configuration.md) — config file, env-var overrides,
  nginx `log_format` recipe, permissions on `/var/log/nginx`
- [**Alerts**](alerts.md) — Discord / Slack / Telegram / Matrix setup,
  cooldown + dedup, rule catalog, how `milog alerts` history works
- [**Web dashboard**](web-dashboard.md) — `milog web`, systemd user
  service, three exposure patterns (SSH tunnel, Tailscale, Cloudflare)
- [**TUI (`milog tui`)**](tui.md) — bubbletea Go binary, when to pick
  it over bash `milog monitor`
- [**Historical metrics**](historical-metrics.md) — SQLite-backed
  `metrics_minute` + `top_ip_hour` tables, `trend` / `diff` / `auto-tune`
- [**`milog daemon`**](daemon.md) — headless mode, systemd wiring,
  update flow
- [**GeoIP enrichment**](geoip.md) — MaxMind license + `geoipupdate`
  weekly timer + the COUNTRY column
- [**Troubleshooting**](troubleshooting.md) — `milog doctor`, common
  failure modes, where to look when something's wrong

## For contributors

- [`../src/README.md`](../src/README.md) — source layout (the
  `src/*.sh` → `build.sh` → `milog.sh` bundling)
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — internals, design
  principles, how to extend (add an alert rule, a mode, a destination)
- [`../SERVER_HARDENING.md`](../SERVER_HARDENING.md) — companion
  server-hardening playbook

## Typical onboarding order

1. Install (one-liner in the root README)
2. Start the dashboard: `milog monitor`
3. Turn on alerts → [alerts.md](alerts.md)
4. Enable `HISTORY_ENABLED` to bank data → [historical-metrics.md](historical-metrics.md)
5. After a few days: `milog auto-tune` to calibrate thresholds
6. Add [GeoIP](geoip.md) and/or the [web dashboard](web-dashboard.md)
   whenever you want them
7. Run [`milog doctor`](troubleshooting.md) any time to see what's
   wired up and what's degraded
