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
```

---

## Priorities if you only have 30 minutes

Steps **0 → 1 → 2 → 3** kill ~95% of opportunistic attack surface.
Everything after is hygiene — important, but not urgent.

If you only have 5 minutes: Step 1b (disable password + root SSH) and
Step 14 (install MiLog + turn on alerts).
