# CrowdSec CTI enrichment

With a CrowdSec CTI API key, milog asks the CrowdSec smoke endpoint what
the CrowdSec network knows about an IP and shows the answer next to its
own findings. This helps separate a known mass scanner from traffic that
deserves a closer look.

Off by default. With `CROWDSEC_CTI_KEY` empty, milog makes no requests
to CrowdSec.

## Setup

1. Create a free CTI API key in the CrowdSec console at
   <https://app.crowdsec.net/settings/cti-api-keys>.
2. Set it in the milog config:

   ```bash
   milog config set CROWDSEC_CTI_KEY "<your key>"
   ```

   or export `MILOG_CROWDSEC_CTI_KEY` for one run.
3. Run `milog doctor`. The `crowdsec cti` section shows whether
   lookups are on and how many IPs are cached.

## Where it shows up

| Place | What you get | Network lookup |
| ----- | ------------ | -------------- |
| `milog attacker <IP>` | A `crowdsec:` line, for example `malicious (HTTP Scan, SSH Bruteforce)` | Yes, when the IP has requests in the logs |
| `milog suspects` | A `CS:<reputation>` tag in the FLAGS column | No, cached results only |
| Exploit and probe alerts | A `CrowdSec: <summary>` line under the log line, also passed to hooks in `MILOG_BODY` | Yes, only when `ALERTS_ENABLED=1` |

The summary is the `reputation` field (`malicious`, `suspicious`,
`known`, `benign`, `safe`, `unknown`) followed by up to three behavior
labels. An IP the API returns 404 for is shown as `unknown`, and
`suspects` leaves it untagged.

## Caching and limits

Each answer is cached for 24 hours in `$ALERT_STATE_DIR/cti/<ip>`
(default `~/.cache/milog/cti/`). The free tier is rate-limited per key,
so `suspects` reads only that cache. It gets populated by `attacker`
runs and by alerts.

Requests time out after 3 seconds. A failed lookup prints nothing in the
command or alert. The most recent failure is kept in
`$ALERT_STATE_DIR/cti.err` until the next successful lookup, and
`milog doctor` reports it:

- `HTTP 401` or `HTTP 403`: the key was rejected.
- `HTTP 429`: the key's rate limit was hit.
- `HTTP 000`: no answer within 3 seconds.

The key is passed to curl on stdin, so it does not appear in the
process list. Only IPv4 and IPv6 addresses are ever placed in the
request URL.
