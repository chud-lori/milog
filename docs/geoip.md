# GeoIP enrichment

When enabled, `milog top`, `milog suspects`, and `milog attacker <IP>` add
a **COUNTRY** column — turning "13.86.116.180 hit you 47 times" into
"13.86.116.180 (US) hit you 47 times". Useful for separating residential
noise from data-center scanner traffic at a glance.

Off by default. Setup is a one-time ~5-minute thing (MaxMind sign-up is
the slow part), then it's maintenance-free via a weekly auto-update
timer.

## What you'll end up with

- `mmdblookup` binary on `$PATH`
- `/var/lib/GeoIP/GeoLite2-Country.mmdb` refreshed weekly by
  `geoipupdate.timer`
- `GEOIP_ENABLED=1` + `MMDB_PATH` set in the milog config
- `milog doctor` reporting `✓ …/GeoLite2-Country.mmdb (8.8.8.8 → US)`

## 1. Install `mmdblookup`

Option A — through the milog installer (also covers the core deps if
you're starting fresh):

```bash
curl -fsSL "https://raw.githubusercontent.com/chud-lori/milog/main/install.sh?$(date +%s)" \
  | sudo bash -s -- --with-geoip
```

Option B — direct, if milog is already installed:

```bash
sudo apt install -y mmdb-bin          # Debian / Ubuntu
sudo dnf install -y libmaxminddb      # Fedora / Rocky / RHEL
sudo pacman -S libmaxminddb           # Arch
```

Verify: `mmdblookup --version`.

## 2. Get a MaxMind GeoLite2 license

MaxMind made accounts + license keys mandatory in 2019 — the pre-2019
direct-download URL no longer works.

1. Sign up (free): <https://www.maxmind.com/en/geolite2/signup>
2. After signup: **My Account** → **Manage License Keys** → **Generate new
   license key**. Name it (e.g. `milog-tencent`). When asked "Will this
   key be used for `geoipupdate`?", answer **Yes**.
3. Save the **Account ID** (numeric, e.g. `1234567`) and the **License
   Key** (16 random chars).

## 3. Configure `geoipupdate`

`geoipupdate` is MaxMind's official downloader. It writes to
`/var/lib/GeoIP/` on Debian/Ubuntu, caches the previous DB's hash, and
does a conditional refresh so re-running is cheap.

```bash
sudo apt install -y geoipupdate        # or: sudo dnf install -y geoipupdate
sudo nano /etc/GeoIP.conf
```

Replace the placeholders with your real values:

```conf
AccountID 1234567
LicenseKey 0abcDEFGHIjklmno
EditionIDs GeoLite2-Country
```

If you also want city-level data later, add ` GeoLite2-City` to
`EditionIDs` — milog only reads `country iso_code` so both editions work;
City is just a bigger file.

Then run the first download:

```bash
sudo geoipupdate -v
```

Expected output ends with:

```
Database GeoLite2-Country successfully updated: <hash>
```

Verify the file landed:

```bash
sudo find / -name "GeoLite2-Country.mmdb" 2>/dev/null
```

Should print `/var/lib/GeoIP/GeoLite2-Country.mmdb`.

## 4. Enable weekly auto-refresh

```bash
sudo systemctl enable --now geoipupdate.timer
systemctl list-timers | grep geoip
```

The timer fires weekly (MaxMind publishes updates at roughly that
cadence for the free tier). Stale mappings aren't dangerous — just
progressively wrong — but letting it drift years is silly when the timer
is free.

## 5. Tell milog about it

```bash
milog config set GEOIP_ENABLED 1
milog config set MMDB_PATH "/var/lib/GeoIP/GeoLite2-Country.mmdb"

# Restart the alert daemon so the running process picks up the new values
sudo systemctl restart milog.service
```

`/var/lib/GeoIP/GeoLite2-Country.mmdb` is also milog's built-in default
`MMDB_PATH`, so the `config set MMDB_PATH` line is a no-op if you used
apt's default `geoipupdate`. Setting it explicitly documents intent.

## 6. Verify

```bash
milog doctor 2>&1 | grep -A3 geoip
```

Should now show:

```
── geoip ──
  ✓ /var/lib/GeoIP/GeoLite2-Country.mmdb  (8.8.8.8 → US)
```

And the country column appears:

```bash
milog top 10                   # RANK IP COUNTRY REQUESTS
milog suspects 20              # same, with behavioral scoring
milog attacker 13.86.116.180   # header line includes [US]
```

## Troubleshooting

### `find` returns nothing after `geoipupdate -v`

`geoipupdate` silently exited or printed an error you scrolled past.
Re-run with `-v` and read the output carefully:

```bash
sudo geoipupdate -v 2>&1
```

Common errors:

| Error                                    | Cause                                         |
| ---------------------------------------- | --------------------------------------------- |
| `401 Unauthorized`                       | License key wrong, or still placeholder text  |
| `403 Forbidden`                          | Account suspended, or you didn't accept the EULA |
| `unknown edition "Foo"`                  | Typo in `EditionIDs`                          |
| `no such file or directory`              | `DatabaseDirectory` doesn't exist — `sudo mkdir -p /var/lib/GeoIP` |

### `doctor` still says `MMDB_PATH` is missing

You set the wrong path. Locate the file:

```bash
sudo find / -name "GeoLite2-Country.mmdb" 2>/dev/null
```

and `milog config set MMDB_PATH` to whatever prints.

### COUNTRY column stays blank in `milog top`

You changed config but didn't restart the running daemon:

```bash
sudo systemctl restart milog.service
```

If that still doesn't fix it, re-run `milog doctor` — it'll point at
the real problem (usually `GEOIP_ENABLED=0`, or `mmdblookup` not on
`PATH` for the daemon user).

### Lookups return `--` for some IPs

MaxMind's free **GeoLite2** is accuracy-limited vs the paid **GeoIP2**
tier. Unknown / private / reserved IPs return empty. Cloudflare, GCP,
AWS, and most big providers are in the DB and map correctly. If you
need "AS14061 DigitalOcean" detail too, you need the paid ASN DB — not
worth it for most use cases.

## Performance

`mmdblookup` is forked **once per unique IP in the aggregated top-N
list**, never per log line. So `milog top 50` does at most 50
`mmdblookup` calls. Bulk operations — `milog exploits`, `milog probes`,
`milog daemon` — don't do GeoIP lookups at all.

## Privacy

Lookups are purely local — the MMDB is a file, no network traffic per
query. MaxMind sees you only when `geoipupdate` refreshes the DB
(weekly). If your threat model cares about "does MaxMind know when this
box does its weekly DB refresh", route `geoipupdate` through a proxy.
