# Server Hardening Playbook

A practical checklist for locking down a small Linux server that hosts public
web services (nginx + apps). Designed to pair with MiLog: **hardening is your
prevention layer, MiLog is your detection layer.** Use both.

This playbook is distro-agnostic. Commands are shown for Debian/Ubuntu
(`apt`, `ufw`) with notes for RHEL/Fedora/Rocky (`dnf`, `firewalld`). It
assumes a single VM reachable from the public internet — a typical VPS setup
on any cloud (DigitalOcean, Hetzner, AWS Lightsail, Tencent CVM, GCP, etc.).

Ordered by **risk reduction per minute of work**. Each step is independent.

> **⚠ Keep a second SSH session open while making SSH changes.** If you lock
> yourself out, the second session is your escape hatch to roll back.

---

## Step 0 — Create a non-root user (skip if you already have one)

If you're still logging in as `root`, stop and create a regular user first.

```bash
# as root
adduser deploy                  # set a strong password, name fields are optional
usermod -aG sudo deploy         # Debian/Ubuntu
# usermod -aG wheel deploy      # RHEL/Fedora/Rocky

mkdir -p /home/deploy/.ssh
cp ~/.ssh/authorized_keys /home/deploy/.ssh/
chown -R deploy:deploy /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
chmod 600 /home/deploy/.ssh/authorized_keys
```

Verify you can SSH in as `deploy` before locking root out in Step 1b.

---

## Step 1 — Lock down SSH

### 1a. Make sure your SSH key works

On your **local machine**:

```bash
ssh-copy-id deploy@SERVER_IP
ssh deploy@SERVER_IP "echo key-auth-works"   # must succeed without password
```

If `ssh-copy-id` is blocked, append the key manually:

```bash
cat ~/.ssh/id_ed25519.pub | ssh deploy@SERVER_IP \
  "mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
   cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

### 1b. Disable password + root login

On the server:

```bash
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'               /etc/ssh/sshd_config
sudo sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/'       /etc/ssh/sshd_config

# Cloud images often override this in a drop-in file — patch it too:
[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ] && \
  sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' \
    /etc/ssh/sshd_config.d/50-cloud-init.conf

sudo sshd -t                       # config valid → prints nothing
sudo systemctl reload ssh          # or `sshd` on RHEL
```

**Verify from a second terminal** before closing your current session:

```bash
ssh deploy@SERVER_IP whoami        # returns "deploy"
```

### 1c. (Optional) Change SSH port

Moving SSH off port 22 won't stop a targeted attacker, but it removes 99% of
automated bruteforce noise from your logs.

**Standard sshd (most distros):**

```bash
sudo sed -i 's/^#*Port .*/Port 2222/' /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl reload ssh
```

**Socket-activated SSH (modern Ubuntu / systemd):** the port is owned by
`ssh.socket`, not `sshd_config`. Editing `Port` has no effect there.

```bash
sudo systemctl edit ssh.socket
```

Add:

```ini
[Socket]
ListenStream=
ListenStream=2222
```

(The empty `ListenStream=` clears the inherited `:22`.)

```bash
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
sudo ss -tlnp | grep ssh           # must show :2222 only
```

Remember to open `2222` in your cloud firewall (and UFW, Step 4) **before**
closing port 22.

---

## Step 2 — Install fail2ban

Blocks IPs that fail SSH auth repeatedly. Also useful for nginx.

```bash
sudo apt install -y fail2ban                    # Debian/Ubuntu
# sudo dnf install -y fail2ban                  # RHEL/Fedora/Rocky

sudo tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled = true
port    = ssh          # change to 2222 if you moved SSH
EOF

sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

Check bans later: `sudo fail2ban-client status sshd`.

---

## Step 3 — Restrict the cloud firewall (Security Group)

Your cloud provider's firewall is the outer wall. Configure it **before**
touching the host firewall — a misconfigured UFW locks you out; a
misconfigured Security Group usually has a "console revert" button.

Allowlist only:

| Port | Source                          | Purpose       |
| ---- | ------------------------------- | ------------- |
| 22 (or 2222) | **Your home/office IP only** | SSH           |
| 80   | `0.0.0.0/0` (or CDN ranges)     | HTTP          |
| 443  | `0.0.0.0/0` (or CDN ranges)     | HTTPS         |

**If you proxy through a CDN** (Cloudflare, Fastly, CloudFront) — and you
should — lock 80/443 down to the CDN's published IP ranges. Origin IPs get
probed for `.env`, `.git/config`, `/wp-admin/`, etc. daily.

Cloudflare ranges (refresh periodically):
- IPv4: <https://www.cloudflare.com/ips-v4>
- IPv6: <https://www.cloudflare.com/ips-v6>

This alone removes most of the `.env`/`.git` scanner noise from nginx logs.

---

## Step 4 — Enable a host firewall (defense-in-depth)

Don't rely on the cloud Security Group alone. Run UFW (or firewalld) too so
that rules travel with the image if you ever migrate.

**Debian/Ubuntu (UFW):**

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp          # or 2222/tcp if you changed it
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

**RHEL/Fedora/Rocky (firewalld):**

```bash
sudo systemctl enable --now firewalld
sudo firewall-cmd --permanent --add-service=ssh       # or --add-port=2222/tcp
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

Cloud firewall = outer wall. Host firewall = inner wall. Both.

---

## Step 5 — TLS everywhere (Let's Encrypt)

If your origin still serves plain HTTP, anyone who reaches the origin IP
directly (bypassing the CDN) sees requests in clear text — including cookies
and session tokens.

```bash
sudo apt install -y certbot python3-certbot-nginx     # Debian/Ubuntu
# sudo dnf install -y certbot python3-certbot-nginx   # RHEL/Fedora/Rocky

sudo certbot --nginx \
  -d example.com -d www.example.com \
  -d app.example.com
```

**If your CDN's proxy blocks the HTTP-01 challenge**: temporarily set the DNS
record to "DNS only" (Cloudflare: grey cloud), run certbot, flip back to
proxied. Alternative: `--webroot` or DNS-01.

After certificates are issued, set the CDN → origin mode to **Full (strict)**
(Cloudflare dashboard → SSL/TLS → Full (strict)).

Verify auto-renewal:

```bash
sudo certbot renew --dry-run
sudo systemctl list-timers | grep certbot
```

---

## Step 6 — Real client IP from your CDN

If you're behind a CDN, nginx logs the CDN's IP instead of the real visitor.
That breaks rate-limiting, geolocation, and incident forensics.

For **Cloudflare**, drop this into `/etc/nginx/conf.d/cloudflare-realip.conf`
(refresh ranges from <https://www.cloudflare.com/ips-v4> and
<https://www.cloudflare.com/ips-v6> periodically):

```bash
sudo tee /etc/nginx/conf.d/cloudflare-realip.conf > /dev/null <<'EOF'
# Cloudflare IPv4 — refresh from https://www.cloudflare.com/ips-v4
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
# IPv6
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

real_ip_header CF-Connecting-IP;
real_ip_recursive on;
EOF
sudo nginx -t && sudo systemctl reload nginx
```

For AWS CloudFront, use the AWS-published IP ranges and
`real_ip_header X-Forwarded-For;`.

---

## Step 7 — Nginx security headers and server tokens

Cheap wins: hide the nginx version, set a handful of response headers that
mitigate XSS/clickjacking/MIME-sniffing.

Add to the `http {}` block in `/etc/nginx/nginx.conf`:

```nginx
server_tokens off;

add_header X-Content-Type-Options   "nosniff"         always;
add_header X-Frame-Options          "SAMEORIGIN"      always;
add_header Referrer-Policy          "strict-origin-when-cross-origin" always;
add_header Permissions-Policy       "geolocation=(), microphone=(), camera=()" always;
# Only enable HSTS once you're sure all your subdomains are TLS-ready:
# add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

Reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Test headers: `curl -I https://your-site.example.com | grep -Ei 'x-|referrer|strict'`.

---

## Step 8 — Per-service nginx logs (so MiLog can monitor them)

MiLog assumes one access log per app in `/var/log/nginx/`. If everything lands
in `access.log`, you can't answer "did `app1` get traffic today?" without
grepping `Referer`.

Inside each `/etc/nginx/sites-available/<site>` `server {}` block:

```nginx
access_log /var/log/nginx/<site>.access.log;
error_log  /var/log/nginx/<site>.error.log warn;
```

Example for a site named `app1`:

```nginx
access_log /var/log/nginx/app1.access.log;
error_log  /var/log/nginx/app1.error.log warn;
```

Reload nginx; `logrotate` already globs `/var/log/nginx/*.log`, so new files
rotate automatically.

Then point MiLog at them:

```bash
milog config set APPS "app1 app2 app3"
```

---

## Step 9 — Nginx rate limiting (optional but cheap)

Cuts scraper and brute-force traffic at the edge before it reaches your app.

In the `http {}` block:

```nginx
# 10 req/s per IP, burst of 20. Adjust per app profile.
limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;
```

In the `location` you want to protect (e.g. login endpoints, API):

```nginx
location /api/ {
    limit_req zone=perip burst=20 nodelay;
    # ... proxy_pass etc.
}
```

Requests over the limit return `503`. MiLog's `monitor` surfaces 5xx spikes,
so you'll see the zone kicking in.

---

## Step 10 — Cap Docker + journald log sizes

Unbounded logs will eventually fill the disk and take everything down with
them. Cap them now.

**Docker:**

```bash
sudo tee /etc/docker/daemon.json > /dev/null <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "50m", "max-file": "3" }
}
EOF
sudo systemctl restart docker
```

Only applies to **new** containers. Recreate existing ones
(`docker compose up -d --force-recreate` in each app dir) to apply, and
truncate existing oversized files:

```bash
sudo truncate -s 0 /var/lib/docker/containers/<container_id>*/*-json.log
```

**Journald** (cap total on-disk at 200 MB):

```bash
sudo sed -i 's/^#*SystemMaxUse=.*/SystemMaxUse=200M/' /etc/systemd/journald.conf
sudo systemctl restart systemd-journald
sudo journalctl --disk-usage   # confirms drop
```

---

## Step 11 — Unattended security updates

Hands-off security patching. Already enabled on most cloud images — verify.

**Debian/Ubuntu:**

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
sudo cat /etc/apt/apt.conf.d/50unattended-upgrades | grep -A2 'Allowed-Origins'
sudo unattended-upgrade --dry-run -d 2>&1 | tail -20
```

Optional — auto-reboot for kernel updates at 3 AM:

```bash
sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|' \
  /etc/apt/apt.conf.d/50unattended-upgrades
sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' \
  /etc/apt/apt.conf.d/50unattended-upgrades
```

**RHEL/Fedora/Rocky:**

```bash
sudo dnf install -y dnf-automatic
sudo sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
sudo systemctl enable --now dnf-automatic.timer
```

---

## Step 12 — Sysctl network hardening

A handful of kernel knobs that cost nothing and block common network-layer
annoyances (SYN floods, spoofed source addresses, ICMP redirects).

```bash
sudo tee /etc/sysctl.d/99-hardening.conf > /dev/null <<'EOF'
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# Drop source-routed + redirected packets (spoofing / MITM)
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Reverse-path filter (drop packets that claim a source IP you couldn't reply to)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore broadcast pings (Smurf amplifier)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log martians (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1

# Disable IPv6 router advertisements on a server (hosts don't need them)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

sudo sysctl --system
```

---

## Step 13 — Secrets hygiene

`.env` files and credentials in your app directories are the single most
common post-compromise loot. Make them hard to read and hard to leak.

```bash
# Tight perms on every .env in /srv, /opt, /home
sudo find /srv /opt /home -maxdepth 4 -name '.env' -type f \
    -exec chmod 600 {} \; -exec ls -l {} \;

# Nginx: block any request for dotfiles, just in case a misconfigured
# `alias`/`root` exposes a project directory.
sudo tee /etc/nginx/conf.d/deny-dotfiles.conf > /dev/null <<'EOF'
location ~ /\.(?!well-known).* {
    deny all;
    access_log off;
    log_not_found off;
}
EOF
sudo nginx -t && sudo systemctl reload nginx
```

Also: make sure your repo has `.env` in `.gitignore` **and** verify nothing
sensitive landed in git history (`git log -p -- .env` on every repo). If it
did, rotate the secret — don't just rewrite history.

---

## Step 14 — Wire MiLog in as the detection layer

Hardening prevents the 95% boring attacks. MiLog catches what slips through,
and tells you about it over Discord while you're asleep.

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash

# Turn on alerts + daemon in one command
sudo milog alert on "https://discord.com/api/webhooks/ID/TOKEN"

# Verify
milog alert status
milog alert test
```

What MiLog alerts on out of the box:
- 5xx rate spikes (broken deploy or under attack)
- p95 latency breaches
- Exploit-scanner fingerprints in access logs (`.env`, `.git`, `/wp-admin/`,
  Log4Shell, SQLi, XSS, RCE probes)
- Disk / CPU / memory pressure

See `ARCHITECTURE.md` for the full list and how the classifier works.

---

## Step 15 — Reactive hardening: what to do when MiLog flags a suspect

Steps 0-14 build the baseline. This one's different: it's what to do
**after** MiLog surfaces a specific bad actor or attack pattern. Not
everything here applies on day one — pick the subsection that matches
the signal you're reacting to.

### 15a. Triage before blocking

Two minutes of triage beats three hours rolling back a wrong ban. Given
an IP from `milog suspects` / `attacker` / `top`, answer three
questions:

```bash
# 1. What did this IP actually do here?
milog attacker 13.86.116.180
milog search "13.86.116.180" --archives

# 2. Who owns it and what's its reputation?
curl -s "https://ipinfo.io/13.86.116.180/json" | jq '.org,.asn,.country'
# Browser: https://www.abuseipdb.com/check/13.86.116.180
# Or with a free AbuseIPDB API key:
curl -sH "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" \
     "https://api.abuseipdb.com/api/v2/check?ipAddress=13.86.116.180&maxAgeInDays=90" \
  | jq '.data | {abuseConfidenceScore, totalReports, countryCode, usageType, isp}'

# 3. What's the scope — one IP or a subnet?
milog top 50 | grep -E '^\s*(13\.86\.116\.)'
```

Decision shortcuts:

| Signal                             | Action                                      |
| ---------------------------------- | ------------------------------------------- |
| ASN = hosting/cloud (DO, OVH, AWS) | Block the /24 indefinitely — throwaway VMs  |
| ASN = residential ISP              | 24-48h ban only (IP rotates, long bans rot) |
| AbuseIPDB confidence ≥ 50          | Block with high confidence                  |
| Single 404 / no probe pattern      | Do nothing — false positive                 |
| Pattern matches MiLog `exploits`   | Block + consider the class-level fixes 15b  |

### 15b. Block common probe paths at nginx

One nginx include makes 90% of scanner probes land on a `404` before
hitting your app — no logs bloat, no PHP fork, no framework 500.

```bash
sudo tee /etc/nginx/conf.d/block-common-probes.conf > /dev/null <<'EOF'
# Dotfile / VCS / secrets leaks
location ~* /\.(env|git|aws|ssh|docker|npm|DS_Store)(/|$)   { access_log off; return 404; }

# PHP / WordPress probe paths
location ~* /(wp-admin|wp-login|wp-content/plugins|xmlrpc\.php|phpmyadmin|pma) { return 404; }

# Admin consoles + device-CGI fingerprints
location ~* /(actuator|server-status|druid|console|containers/json|HNAP1|boaform|cgi-bin) { return 404; }

# Log4Shell-style JNDI — even in paths (URL-encoded too)
location ~* (\$\{jndi:|%24%7bjndi)  { return 444; }  # 444 = close without response
EOF
sudo nginx -t && sudo systemctl reload nginx
```

Applies globally (`conf.d/*.conf` is included in `http {}`). Effect:

- Noise drop in MiLog's `exploits` / `probes` tails (they still match the
  pattern, but the server spends zero work on them — and `444` on JNDI
  denies the scanner even a status-code signal).
- Real users never hit these; legit apps don't use them either.

### 15c. fail2ban jail for nginx scanners

Step 2 set up fail2ban for sshd. Add a parallel jail that watches nginx
for the same pattern MiLog's `exploits` classifier uses, and auto-bans
repeat offenders.

```bash
sudo tee /etc/fail2ban/filter.d/nginx-scanner.conf > /dev/null <<'EOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) [^"]*(/\.env|/\.git/|/wp-login|/wp-admin|/xmlrpc\.php|/actuator|/\.aws/|/phpmyadmin|/boaform|/HNAP1|/cgi-bin)[^"]*" (4\d\d|5\d\d)
ignoreregex =
EOF

sudo tee /etc/fail2ban/jail.d/nginx-scanner.local > /dev/null <<'EOF'
[nginx-scanner]
enabled  = true
port     = http,https
filter   = nginx-scanner
logpath  = /var/log/nginx/*.access.log
maxretry = 5
findtime = 300           # 5 req matching pattern in 5 min...
bantime  = 86400         # ...gets a 24 h ban. Don't go longer.
EOF

sudo systemctl restart fail2ban
sudo fail2ban-client status nginx-scanner
```

**Behind Cloudflare?** fail2ban must see the real client IP, not the CF
edge. Step 6 (real-IP restoration) handles that at nginx — verify with
`tail -1 /var/log/nginx/*.access.log` that the first field is the real
IP, not `172.x` / `104.x`. Without that, fail2ban would ban Cloudflare.

Check bans over time: `sudo fail2ban-client status nginx-scanner`.

### 15d. Threat-intel IP lists (Spamhaus DROP / FireHOL)

Curated lists of known-hostile networks — hijacked space, confirmed
C2, bulletproof hosting. Drop them at the kernel, zero per-request
cost.

```bash
sudo apt install -y ipset      # Debian/Ubuntu
# sudo dnf install -y ipset    # RHEL/Fedora/Rocky

sudo ipset create spamhaus-drop hash:net maxelem 131072 2>/dev/null || true
sudo iptables -C INPUT -m set --match-set spamhaus-drop src -j DROP 2>/dev/null \
  || sudo iptables -I INPUT -m set --match-set spamhaus-drop src -j DROP

# Hourly refresh
sudo tee /usr/local/sbin/refresh-spamhaus > /dev/null <<'EOF'
#!/bin/sh
set -eu
ipset create spamhaus-drop-new hash:net maxelem 131072 2>/dev/null || ipset flush spamhaus-drop-new
curl -fsSL https://www.spamhaus.org/drop/drop.txt https://www.spamhaus.org/drop/edrop.txt \
  | awk '/^[0-9]/ {print $1}' \
  | while read cidr; do ipset add spamhaus-drop-new "$cidr" 2>/dev/null || true; done
ipset swap spamhaus-drop-new spamhaus-drop
ipset destroy spamhaus-drop-new 2>/dev/null || true
EOF
sudo chmod +x /usr/local/sbin/refresh-spamhaus

sudo tee /etc/systemd/system/spamhaus-refresh.service > /dev/null <<'EOF'
[Unit]
Description=Refresh Spamhaus DROP/eDROP ipset
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/refresh-spamhaus
EOF

sudo tee /etc/systemd/system/spamhaus-refresh.timer > /dev/null <<'EOF'
[Unit]
Description=Refresh Spamhaus ipset hourly
[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now spamhaus-refresh.timer
sudo systemctl start  spamhaus-refresh.service
sudo ipset list spamhaus-drop | head -5
```

Make the iptables rule survive reboot: `iptables-persistent` (Debian) or
`iptables-services` (RHEL), plus `ipset save spamhaus-drop > /etc/ipset.conf`
in a oneshot unit that runs after refresh.

Want more aggressive? Swap `drop.txt` for FireHOL Level 1
(`https://iplists.firehol.org/files/firehol_level1.netset`). Test on a
staging host first — Level 1 includes some broad cloud ranges that may
block legitimate users.

### 15e. Cloudflare WAF rules — block at the edge

If you're already behind Cloudflare, the edge is the correct layer to
block. Origin-side bans still cost you TLS handshake + TCP accept; edge
bans are free.

**Custom rule (Free plan: 5 allowed)** — Security → WAF → Custom rules →
Create rule:

```
Expression:
(http.request.uri.path contains "/.env") or
(http.request.uri.path contains "/.git/") or
(http.request.uri.path contains "/wp-login") or
(http.request.uri.path contains "/wp-admin") or
(http.request.uri.path contains "/xmlrpc.php") or
(http.request.uri.path contains "/actuator") or
(http.request.uri.path contains "/boaform") or
(http.request.uri.path contains "/HNAP1") or
(http.request.uri.path contains "/phpmyadmin")

Action: Managed Challenge
```

Managed Challenge rather than Block — real users occasionally type
these URLs (dev exploring an API); scanners fail the challenge and move
on. Zero false-positive ceilings this way.

**IP Access Rules** — Security → WAF → Tools. Paste single IPs, /24s,
/16s; pick Block or Challenge. Applies zone-wide, survives origin
migrations. Good spot for the residential-rotator IPs that fail2ban
would churn on.

**Country-level Managed Challenge**:

```
Expression:  (ip.geoip.country in {"RU" "CN" "KP" "IR"}) and
             (http.request.uri.path contains "/admin")
Action: Managed Challenge
```

Never blanket-block countries on the public site (real users travel,
VPN, use exit nodes) — scope to admin paths only.

### 15f. Zero-internet admin surface

For anything with a login (`/admin`, `/wp-admin`, the MiLog web panel,
phpMyAdmin) the right move isn't "block bad IPs" — it's "don't be
reachable from the internet at all". Three patterns, pick one:

**Cloudflare Access** — SSO + optional MFA before the request ever
reaches your origin. Free for ≤50 seats. Policy example:

- Application: `https://your-site.example.com/admin/*`
- Policy: email ends in `@yourcompany.com` **and** identity provider is
  Google/GitHub **and** country is your home country.
- Require: Multi-factor (TOTP / WebAuthn).

After enabling, direct requests to `/admin` redirect through a
Cloudflare login page; only authenticated users continue to origin. Your
nginx still sees the request but every one is pre-authenticated.

**Tailscale-only admin** — install Tailscale on server + your
devices, bind admin surface to the tailnet IP:

```bash
# On the server
sudo tailscale up
# Get the tailnet IP, e.g. 100.64.1.2
milog web --bind 100.64.1.2 --trust
```

Anyone off the tailnet can't route to `100.64.1.2`, period. No open
port, no WAF rule, no exposure. Zero-config MFA comes via your identity
provider at the tailscale login step. Tradeoff: every admin needs the
tailscale client installed (free on ≤3 users, cheap above that).

**Turnstile on login endpoints** — if you must leave a login form
public, drop Cloudflare Turnstile in front:

```html
<div class="cf-turnstile" data-sitekey="0x4AAAAA..."></div>
```

Server-side verify the token before accepting the login. Replaces
reCAPTCHA with no user-visible CAPTCHA in the normal case; only suspicious
traffic gets a challenge.

### 15g. Putting it together — response playbook

A worked example: MiLog fires `probes: /actuator/health (12/min)` from
IP `139.162.xxx.yyy`. Do in order:

1. **Triage** (2 min): `milog attacker 139.162.xxx.yyy` shows 40
   requests across 6 paths, all /actuator/*. `ipinfo.io` → Linode ASN
   14061 (hosting). AbuseIPDB score 94 across 200 reports. → **Confirmed
   bad, cloud ASN → block /24 permanently.**
2. **Block at edge** (30 s): Cloudflare IP Access Rule for
   `139.162.0.0/16` (all of Linode ATL-02), action Block. This is the
   whole fix for this IP.
3. **Prevent class of issue** (5 min, one-time): confirm
   `block-common-probes.conf` is loaded and has `/actuator` in it (15b).
   If yes, you're done — no one else can exploit this route again.
4. **Let automation carry residual churn** — fail2ban + Spamhaus pick
   up the tail of IPs you didn't manually block.
5. **Audit**: `milog alerts 7d` a week later, confirm the pattern has
   tapered off.

Don't dwell on manual IP bans. Your time goes on steps 2 and 3; 4 is
the autopilot that keeps step 1 from needing to happen again.

---

## Verification checklist

Run after each major step or at the end:

```bash
ssh deploy@SERVER_IP                               # key-only login works
sudo ss -tlnp                                      # expected listening ports only
sudo fail2ban-client status sshd                   # active
sudo ufw status      # or: sudo firewall-cmd --list-all
curl -I https://your-site.example.com              # 200 OK over TLS
curl -I http://SERVER_IP --max-time 5              # times out (CDN-only) if locked down
curl -I https://your-site.example.com | grep -Ei 'x-frame|x-content|referrer'  # headers present
sudo nginx -t                                      # no warnings
sudo journalctl --disk-usage                       # ~200 MB
sudo sysctl net.ipv4.tcp_syncookies                # = 1
milog alert status                                 # alerts enabled + daemon running
# Reactive layer (Step 15) — optional, skip if 15 not done:
sudo fail2ban-client status nginx-scanner          # jail active, recent bans listed
sudo ipset list spamhaus-drop | head -3            # shows entry count (~300+)
curl -I "https://your-site.example.com/.env"       # 404 from block-common-probes.conf
```

---

## Priorities if you only have 30 minutes

Steps **0 → 1 → 2 → 3** kill ~95% of opportunistic attack surface.
Everything after is hygiene — important, but not urgent.

If you only have 5 minutes: Step 1b (disable password + root SSH) and
Step 14 (install MiLog + turn on alerts).

Already firefighting a live attacker? Jump to **Step 15** — triage
flow + edge blocks + fail2ban nginx jail. Steps 15b (block-common-probes)
and 15e (Cloudflare WAF) together take under 10 minutes and stop 95% of
probe traffic from returning.
