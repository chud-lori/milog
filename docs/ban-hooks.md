# Ban hooks

milog never bans anything by itself. It detects and alerts. If you want an
exploit alert to block the client, an [on_alert hook](alerts.md#hook-scripts--custom-integrations-without-a-pr)
can hand the source IP to a firewall. This page has two recipes: fail2ban
and plain nftables.

## What the hook receives

Every hook gets `MILOG_IP` next to the other `MILOG_*` variables. It is set
for `exploit:<app>:<category>` and `probe:<app>` fires and is empty for
every other rule. The value is the first field of the matching access-log
line, which is `$remote_addr` in the nginx `combined` format.

The example scripts act on `exploit:*` only. `probe:*` also matches SEO
crawlers, AI crawlers and HTTP client libraries, which you may not want to
block.

Limits to know before relying on this:

- Alerts are gated per rule key by `ALERT_COOLDOWN` (default 300s). After
  `exploit:api:sqli` fires for one IP, a second IP sending the same kind
  of payload to the same app within the cooldown fires nothing, so the hook
  never sees it.
- Silenced rules don't run hooks.
- Hooks only run when alerts are enabled (`ALERTS_ENABLED=1`) and a watcher
  is running: `milog daemon` or `milog exploits`.
- Behind a reverse proxy or CDN, `$remote_addr` is the proxy unless nginx
  rewrites it with `real_ip_header` / `set_real_ip_from`. Only list proxies
  you trust in `set_real_ip_from`, or a client can choose the IP you ban.
  When clients reach nginx through a CDN, a host firewall ban never sees
  their traffic at all; block at the CDN instead.

## How the scripts are wired

Hooks run as the user milog runs as (your user, for the default daemon
unit). Changing the firewall needs root, so each recipe has two parts:

1. A root-owned script in `/usr/local/sbin` that takes `<rule_key> <ip>`,
   ignores non-`exploit:` rules, validates the IP, and bans it.
2. A two-line hook in `~/.config/milog/hooks/on_alert.d/` that calls the
   script through `sudo -n`, allowed by one sudoers line.

The script lives outside your home directory because the hook directory
is writable by your user; a sudoers rule pointing into it would let that
user run anything as root.

Both scripts reject:

- anything that isn't a dotted-quad IPv4 address or a hex-and-colons IPv6
  address
- loopback and private ranges (`127/8`, `10/8`, `172.16/12`, `192.168/16`,
  `::1`, `fc00::/7`, `fe80::/10`), since a local source is usually your
  own proxy

A rejected IP exits 1, which milog records in `~/.cache/milog/hooks.log`.
Banning an IP that is already banned succeeds and changes nothing.

Run the commands below as the user milog runs as, from a checkout of this
repo.

## Recipe A: fail2ban

[`examples/milog-ban-fail2ban`](examples/milog-ban-fail2ban) runs
`fail2ban-client set milog banip <ip>`. fail2ban then owns the firewall
rule and unbans after `bantime`.

Add a jail with no filter, so it only bans what the script hands it:

```ini
# /etc/fail2ban/jail.d/milog.local
[milog]
enabled   = true
filter    =
backend   = polling
logpath   = /dev/null
port      = http,https
banaction = nftables-multiport
bantime   = 1h
```

fail2ban logs `No filter set for jail milog` at start; that is expected.
Use `iptables-multiport` as `banaction` on hosts without nftables.

```bash
sudo systemctl reload fail2ban
sudo install -m 0755 -o root -g root docs/examples/milog-ban-fail2ban /usr/local/sbin/
echo "$USER ALL=(root) NOPASSWD: /usr/local/sbin/milog-ban-fail2ban" \
  | sudo tee /etc/sudoers.d/milog-ban >/dev/null
sudo chmod 0440 /etc/sudoers.d/milog-ban
sudo visudo -cf /etc/sudoers.d/milog-ban

mkdir -p ~/.config/milog/hooks/on_alert.d
cat > ~/.config/milog/hooks/on_alert.d/50-ban <<'EOF'
#!/bin/sh
exec sudo -n /usr/local/sbin/milog-ban-fail2ban "$MILOG_RULE_KEY" "$MILOG_IP"
EOF
chmod +x ~/.config/milog/hooks/on_alert.d/50-ban
```

Check it:

```bash
MILOG_RULE_KEY=exploit:test:sqli MILOG_IP=198.51.100.4 ~/.config/milog/hooks/on_alert.d/50-ban
sudo fail2ban-client status milog          # 198.51.100.4 in "Banned IP list"
sudo fail2ban-client set milog unbanip 198.51.100.4
```

## Recipe B: nftables set with a timeout

[`examples/milog-ban-nft`](examples/milog-ban-nft) adds the IP to one of
two sets in a dedicated `inet milog` table. Each set carries its own
timeout, so entries expire without a cleanup job. Change `timeout 1h` to
choose the ban length.

```nft
# /etc/nftables.d/milog.nft
table inet milog {
    set banned4 {
        type ipv4_addr
        flags timeout
        timeout 1h
    }
    set banned6 {
        type ipv6_addr
        flags timeout
        timeout 1h
    }
    chain input {
        type filter hook input priority filter - 1; policy accept;
        ip saddr @banned4 drop
        ip6 saddr @banned6 drop
    }
}
```

Load it from `/etc/nftables.conf` with
`include "/etc/nftables.d/milog.nft"` so it comes back after a reboot, then
`sudo nft -f /etc/nftables.conf`. Loading the file again without the
`flush ruleset` at the top of `nftables.conf` appends the two drop rules a
second time.

```bash
sudo install -m 0755 -o root -g root docs/examples/milog-ban-nft /usr/local/sbin/
echo "$USER ALL=(root) NOPASSWD: /usr/local/sbin/milog-ban-nft" \
  | sudo tee /etc/sudoers.d/milog-ban >/dev/null
sudo chmod 0440 /etc/sudoers.d/milog-ban
sudo visudo -cf /etc/sudoers.d/milog-ban

mkdir -p ~/.config/milog/hooks/on_alert.d
cat > ~/.config/milog/hooks/on_alert.d/50-ban <<'EOF'
#!/bin/sh
exec sudo -n /usr/local/sbin/milog-ban-nft "$MILOG_RULE_KEY" "$MILOG_IP"
EOF
chmod +x ~/.config/milog/hooks/on_alert.d/50-ban
```

Check it:

```bash
MILOG_RULE_KEY=exploit:test:sqli MILOG_IP=198.51.100.4 ~/.config/milog/hooks/on_alert.d/50-ban
sudo nft list set inet milog banned4       # 198.51.100.4 expires ...
sudo nft delete element inet milog banned4 '{ 198.51.100.4 }'
```

## Running milog as root

If the daemon runs as root (`User=root`, see [daemon.md](daemon.md)), skip
sudo and the sudoers file. Put the hook in root's hook directory
(`/root/.config/milog/hooks/on_alert.d/` unless `HOOKS_DIR` says
otherwise) and call the script directly.
