# `milog probe` — eBPF kernel-event sidecar (Linux only)

The probe is a separate Go binary (`milog-probe`) that loads eBPF
programs into the kernel and streams matched events through the
existing milog alert pipeline. eBPF needs root or
`CAP_BPF + CAP_PERFMON` (kernel ≥ 5.8), so the probe runs as a system
service, not the user-mode `milog daemon`.

The probe **does not** keep its own alert state. Every rule hit shells
out to `milog _internal_alert <key> <title> <body> <color>` — the same
bash daemon you already run, with the same cooldown, silence, dedup,
routing, and hooks. Probe alerts and bash alerts are indistinguishable
once they reach Discord.

## What it watches

Eight independent eBPF programs, each in its own ring buffer with its
own load — a verifier reject on one doesn't take the others down.

| Probe          | BPF tracepoint                              | Rule keys it can fire                                                       |
| -------------- | ------------------------------------------- | --------------------------------------------------------------------------- |
| **exec**       | `sched:sched_process_exec`                  | `process:shell_from_web_worker:…`, `process:exec_from_tmp:<comm>`, `process:suid_escalation:…` |
| **tcp**        | `sock:inet_sock_set_state`                  | `net:unexpected_outbound:<comm>`                                            |
| **file**       | `syscalls:sys_enter_openat`                 | `file:sensitive_read:<comm>:<path>`                                         |
| **ptrace**     | `syscalls:sys_enter_ptrace`                 | `proc:ptrace_inject:<comm>`                                                 |
| **kmod**       | `module:module_load`                        | `proc:kmod_load:<module>`                                                   |
| **retrans**    | `tcp:tcp_retransmit_skb`                    | `net:retrans_spike:<dst>:<port>`                                            |
| **syscall-rate** | `raw_tracepoint:sys_enter` (sampled, Welford σ) | `process:syscall_burst:<comm>`                                          |
| **bpf-load**   | `syscalls:sys_enter_bpf` (filtered to `BPF_PROG_LOAD`) | `proc:bpf_load:<comm>`                                          |

Each BPF program is embedded into the Go binary as a CO-RE
relocatable object — one binary works across kernels ≥ 4.18 with BTF
available.

## Install + start

```bash
# Curl-pipe install also fetches milog-probe on Linux:
curl -fsSL https://raw.githubusercontent.com/chud-lori/milog/main/install.sh | sudo bash

# Write + enable + start the systemd unit:
sudo milog probe install-service

# Confirm it's running:
milog probe status
sudo journalctl -u milog-probe.service -f
```

`install-service` writes `/etc/systemd/system/milog-probe.service` and
enables it. The unit captures the **invoking user's** `HOME` and
`MILOG_CONFIG` so probe-fired alerts route through your user's
DISCORD_WEBHOOK + silences + alerts.log — not root's. Re-run
install-service after `milog config set` to pick up changes.

## Pre-flight checklist

Run these before installing on a host you've never used the probe on:

```bash
uname -srm                                                   # need ≥ 5.8 for CAP_BPF without full root
test -r /sys/kernel/btf/vmlinux && echo BTF_OK || echo MISS  # CO-RE needs BTF
id                                                           # confirm sudo
```

The eBPF features it relies on:

| Need                          | Minimum kernel |
| ----------------------------- | -------------- |
| Tracepoint programs           | 4.18           |
| Ring-buffer maps              | 5.8            |
| `CAP_BPF` (no full root)      | 5.8            |
| BTF (CO-RE)                   | most distros default-on since 5.10 |

## Tuning the file allowlist

The file probe is the chattiest by far — every `ps`, every Docker
container init reads `/etc/passwd`, every `curl` invokes glibc's NSS
which also reads it. Default allowlist covers the obvious system
tools (`sshd`, `sudo`, `systemd*`, etc.) but not the noisier real-world
sources observed during smoke testing.

Edit the unit's `Environment=MILOG_PROBE_FILE_ALLOWLIST=…` line:

```bash
sudoedit /etc/systemd/system/milog-probe.service
sudo systemctl daemon-reload && sudo systemctl restart milog-probe.service
```

Default list (set at install time, replaceable as a comma-separated
list of `comm` names):

```
sshd,sshd-session,sudo,su,login,getty,agetty,
cron,crond,anacron,
systemd,systemd-logind,systemd-userdb,systemd-tmpfile,systemd-resolve,systemd-udevd,
auditd,audisp-syslog,
adduser,useradd,usermod,userdel,chpasswd,passwd,chage,visudo,
pam_unix,nscd,nslcd,sssd,
milog,milog-probe,
ps,runc,runc:[2:INIT],watchtower,whoami
```

The `MILOG_PROBE_FILE_ALLOWLIST` env var **replaces** (does not extend)
the default — paste the whole list and add to it. The same applies to
`MILOG_PROBE_NET_ALLOWLIST` (CIDRs + bare ports) and the kmod /
syscall / bpf-load allowlists.

## Net allowlist + per-comm silences

Background daemons that legitimately call out (Docker watchtower
polling GHCR, your Node app calling external APIs, etc.) are best
silenced at the **rule-key** level instead of polluting the net
allowlist with destination IPs that change. The rule key embeds the
comm:

```bash
milog silence 'net:unexpected_outbound:watchtower' 365d "watchtower polls GHCR"
milog silence 'net:unexpected_outbound:node'       365d "node app outbound; revisit with destinations later"
```

`milog silence list` shows what's muted; `milog silence clear …`
removes early.

## Foreground / dry-run modes

Useful before flipping alerts on, or for ad-hoc debugging:

```bash
# Match rules but never fire — print one DRY: line per hit on stderr
sudo milog-probe --dry-run

# Emit every event as JSON to stdout regardless of rule match
sudo milog-probe --json

# Combine — silent stderr except DRY hits, JSON stream of every event on stdout
sudo milog-probe --json --dry-run > /tmp/probe.jsonl
```

`jq` slices the stream by event type:

```bash
# Distribution of event kinds
jq -r 'del(.hits) | keys[0]' /tmp/probe.jsonl | sort | uniq -c | sort -rn

# Only hits (rule matches)
jq -c 'select(.hits != null and (.hits | length) > 0)' /tmp/probe.jsonl
```

## Env vars

All probe-side knobs are read from the systemd unit's `Environment=`
lines. To change one: `sudoedit` the unit, `daemon-reload`, restart.

| Var                              | Default                                       | Effect                                                       |
| -------------------------------- | --------------------------------------------- | ------------------------------------------------------------ |
| `HOME`                           | (unset → root's `/root`)                      | Resolves the bash side's `ALERT_STATE_DIR` and `MILOG_CONFIG` lookups. **Set this** or alerts log to `/root/.cache/milog/`. |
| `MILOG_CONFIG`                   | `$HOME/.config/milog/config.sh`               | Bash-side config the probe-spawned milog reads               |
| `MILOG_PROBE_FILE_ALLOWLIST`     | conservative system-tools list                | Comma-separated `comm` names exempt from `file:sensitive_read` |
| `MILOG_PROBE_FILE_SENSITIVE`     | `/etc/shadow`, `/etc/sudoers`, `/root/.ssh/`, etc. | Comma-separated paths the probe watches                |
| `MILOG_PROBE_NET_ALLOWLIST`      | loopback + private CIDRs + DNS / NTP          | CIDR list + bare port (`:53`) entries; CIDR+port (`10.0.0.0/8:443`) supported |
| `MILOG_PROBE_PTRACE_DEBUGGERS`   | `gdb,lldb,strace,…`                           | Allowlist of legitimate ptracers (replaces, not extends)     |
| `MILOG_PROBE_KMOD_ALLOWLIST`     | conservative module set                       | Set to `""` (explicit empty) to alert on **every** module load |
| `MILOG_PROBE_RETRANS_THRESHOLD`  | retransmits-per-tick threshold                | Lower on tight links to catch flakier issues                 |
| `MILOG_PROBE_SYSCALL_FLOOR`      | absolute floor for syscall-rate σ check       | Prevents low-volume false positives                          |
| `MILOG_PROBE_SYSCALL_BURNIN`     | observations before σ baseline is trusted     | First N samples per PID feed Welford but don't fire          |
| `MILOG_PROBE_BPFLOAD_ALLOWLIST`  | `milog-probe,systemd-udevd,…`                 | Set to a tight list to alert on every ad-hoc bpftrace        |

## Manage / debug

```bash
sudo systemctl status   milog-probe.service
sudo systemctl restart  milog-probe.service        # after editing the unit
sudo journalctl -u milog-probe.service -f          # live event + load log
sudo milog probe uninstall-service                 # full removal
```

The probe logs one line per BPF program load on startup:

```
milog-probe v0.5.0 — watching exec + tcp connect + file open + ptrace
+ kmod load + tcp retransmit + syscall rate + bpf prog-load
(json=false dry-run=false)
```

Followed by a `probe (X): … coverage degraded` line for any program
the verifier rejected — the others keep running. If **all** eight
fail to load, the binary exits non-zero and `Restart=on-failure` in
the unit retries every 5s.

## Common false-positive sources

Real-world hosts surfaced these during smoke testing — allowlist or
silence as appropriate:

| Source                                   | Baseline noise                                                    | Treatment                                  |
| ---------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------ |
| `ps`                                     | reads `/etc/passwd` for UID→name                                  | already in default file allowlist          |
| `runc:[2:INIT]`                          | Docker container init reads `/etc/passwd`                         | already in default file allowlist          |
| `systemd-udevd`                          | udev rules with `OWNER=` read `/etc/passwd`                       | already in default file allowlist          |
| `whoami`                                 | one-shot UID lookup                                               | already in default file allowlist          |
| `watchtower`                             | Docker image-update polling GHCR/Docker Hub                       | silence `net:unexpected_outbound:watchtower` |
| App-level `node` / `python` / `curl`     | normal API calls to external services                             | silence `net:unexpected_outbound:<comm>` (lose attribution for that comm) or extend `MILOG_PROBE_NET_ALLOWLIST` with concrete CIDRs |
| Tencent / AWS / GCP cloud agents (`barad_agent`, `YDService`) | shell-out + `/var/log/auth.log` read | allowlist comm if the agent isn't going to be removed |

If you hit a recurring source not in this table, the easiest path is
`milog silence <full-rule-key> 1d "investigating"` while you decide.

## Why this exists

Bash + log parsing catches what the application logged. eBPF catches
what happened **before** anything got logged: the shell exec from a
compromised PHP worker, the `/etc/shadow` read by the wrong process,
the outbound to a fresh C2 IP that nginx never sees because the
attacker used the host's `curl` directly. Same alert pipeline, same
Discord channel, same on-call workflow.
