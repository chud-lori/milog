#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { printf 'smoke_doctor_risks: %s\n' "$1" >&2; exit 1; }

mkdir -p "$tmp/home/.config/milog" "$tmp/logs"
: > "$tmp/logs/app.access.log"
export HOME="$tmp/home" TMPDIR="$tmp" MILOG_LOG_DIR="$tmp/logs" MILOG_APPS=app
export MILOG_CONFIG="$tmp/home/.config/milog/config.sh"
: > "$MILOG_CONFIG"
rules="$HOME/.config/milog/rules.tsv"

doctor() { "$ROOT/milog.sh" doctor 2>&1 || true; }

if [[ "$(uname -s)" == Linux ]]; then
    out=$(MILOG_BTF_PATH="$tmp/no-btf" MILOG_KERNEL_RELEASE=6.8.0-generic doctor)
    [[ "$out" == *"✓"*"kernel 6.8.0-generic, BTF absent"* ]] || fail "doctor did not report missing BTF as fine: $out"
    [[ "$out" == *"does not need BTF"* ]] || fail "doctor did not explain BTF: $out"
    : > "$tmp/btf"
    out=$(MILOG_BTF_PATH="$tmp/btf" MILOG_KERNEL_RELEASE=5.4.0-150-generic doctor)
    [[ "$out" == *"!"*"kernel 5.4.0-150-generic, BTF present"* ]] || fail "doctor did not warn on a pre-5.8 kernel: $out"
    [[ "$out" == *"ring buffers"*"works without the probe"* ]] || fail "pre-5.8 hint missing: $out"
fi

# Built-in rules take their age from the milog script itself.
out=$("$ROOT/milog.sh" update-rules --check) || fail "fresh built-in rules reported stale: $out"
[[ "$out" == *"(built-in), shipped with this milog, installed"* ]] || fail "unexpected built-in report: $out"

cp "$ROOT/rules/milog-rules.tsv" "$rules"
touch -d '90 days ago' "$rules"
if out=$("$ROOT/milog.sh" update-rules --check); then fail "90-day-old rules file passed: $out"; fi
[[ "$out" == *"($rules), written 90d ago"* && "$out" == *"run: milog update-rules"* ]] || fail "unexpected stale-file report: $out"

ver=$(sed -n '1s/^# version: //p' "$rules")
printf '%s\tv9.9.9\t%s\n' "$(( $(date +%s) - 61 * 86400 ))" "$ver" > "$rules.checked"
if out=$("$ROOT/milog.sh" update-rules --check); then fail "61-day-old stamp passed: $out"; fi
[[ "$out" == *"last checked against a release 61d ago"* ]] || fail "stamp not preferred over mtime: $out"
out=$(doctor)
[[ "$out" == *"!"*"last checked against a release 61d ago"* ]] || fail "doctor did not warn on stale rules: $out"
printf 'RULES_MAX_AGE_DAYS=90\n' > "$MILOG_CONFIG"
"$ROOT/milog.sh" update-rules --check >/dev/null || fail "RULES_MAX_AGE_DAYS=90 still warned at 61d"
printf 'RULES_MAX_AGE_DAYS=0\n' > "$MILOG_CONFIG"
"$ROOT/milog.sh" update-rules --check >/dev/null || fail "RULES_MAX_AGE_DAYS=0 still warned"
: > "$MILOG_CONFIG"

printf '%s\tv9.9.9\t%s\n' "$(date +%s)" "$ver" > "$rules.checked"
out=$("$ROOT/milog.sh" update-rules --check) || fail "fresh stamp reported stale: $out"
[[ "$out" == *"last checked against a release 0d ago"* ]] || fail "unexpected fresh report: $out"

# A stamp for another version must not vouch for the rules now active.
sed -i '1s/.*/# version: 999/' "$rules"
out=$("$ROOT/milog.sh" update-rules --check) || true
[[ "$out" == *"version 999"*"written"* ]] || fail "stamp for version $ver credited to version 999: $out"
rm "$rules"
printf '%s\tv9.9.9\t999\n' "$(date +%s)" > "$rules.checked"
out=$("$ROOT/milog.sh" update-rules --check) || true
[[ "$out" == *"(built-in), shipped with this milog"* ]] || fail "stamp credited to the built-in fallback: $out"
if "$ROOT/milog.sh" update-rules --bogus >/dev/null 2>&1; then fail "unknown update-rules flag accepted"; fi

# install-service must not write a unit when the probe cannot load anything.
if [[ $EUID -eq 0 && "$(uname -s)" == Linux ]]; then
    mkdir -m 0755 "$tmp/bin"
    install_with() {
        printf '#!/bin/sh\n%s\n' "$1" > "$tmp/bin/milog-probe"
        chmod 0755 "$tmp/bin/milog-probe"
        rm -f "$tmp/unit"
        MILOG_PROBE_BIN="$tmp/bin/milog-probe" MILOG_BTF_PATH="$tmp/no-btf" bash -c '
            . "$1" help >/dev/null
            systemctl() { return 0; }
            _PROBE_SYSTEMD_UNIT="$2"
            _probe_service_install
        ' _ "$ROOT/milog.sh" "$tmp/unit" 2>&1
    }
    if out=$(install_with 'echo "FAIL exec: map create: not supported"; echo "0 of 8 probes loaded"; exit 1'); then
        fail "install-service succeeded although no probe loaded: $out"
    fi
    [[ ! -e "$tmp/unit" ]] || fail "install-service wrote a unit that would crash-loop"
    [[ "$out" == *"could not load any eBPF program (kernel "*", BTF absent); not installing the unit"* ]] || fail "unclear refusal: $out"
    [[ "$out" == *"FAIL exec: map create: not supported"* && "$out" == *"works without it"* ]] || fail "refusal lacks the check output: $out"

    out=$(install_with 'echo "flag provided but not defined: -check" >&2; exit 2') || fail "install-service refused a probe without --check: $out"
    [[ -s "$tmp/unit" && "$out" == *"predates --check"* ]] || fail "old probe binary not installed: $out"

    out=$(install_with 'echo "ok   exec"; echo "1 of 8 probes loaded"') || fail "install-service refused a working probe: $out"
    [[ -s "$tmp/unit" && "$out" == *"1 of 8 probes loaded"* ]] || fail "working probe not installed: $out"
fi

printf 'smoke_doctor_risks: ok\n'
