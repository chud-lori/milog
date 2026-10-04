#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT

fail() { printf 'smoke_version_update: %s\n' "$1" >&2; exit 1; }

# The companion lookups also search /usr/local, and update would pick up a host binary there.
for d in /usr/local/libexec/milog /usr/local/bin; do
    for n in milog-web milog-tui milog-probe; do
        if [[ -e "$d/$n" ]]; then
            echo "smoke_version_update: skipped, $d/$n exists on this host"
            exit 0
        fi
    done
done

mkdir -p "$tmp/home" "$tmp/logs" "$tmp/stub" "$tmp/pkg" "$tmp/release" "$tmp/link"
unset MILOG_APPS MILOG_CONFIG MILOG_PROBE_BIN
export HOME="$tmp/home" MILOG_LOG_DIR="$tmp/logs" MILOG_RELEASE_REPO=test/milog
export MILOG_WEB_BIN="$tmp/bin/milog-web" MILOG_TUI_BIN="$tmp/bin/milog-tui"
export FAKE_RELEASE="$tmp/release" CURL_LOG="$tmp/curl.log"

case "$(uname -s)" in Linux) os=linux ;; *) os=darwin ;; esac
case "$(uname -m)" in aarch64|arm64) arch=arm64 ;; *) arch=amd64 ;; esac
archive="milog_9.9.9_${os}_${arch}.tar.gz"

stamp() { sed "2s/.*/# MILOG_VERSION=$1/" "$ROOT/milog.sh" > "$2"; chmod 0755 "$2"; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

# Fake v9.9.9 release served by a curl stub; /releases/latest redirects like GitHub does.
stamp v9.9.9 "$tmp/pkg/milog.sh"
for n in milog-web milog-tui; do
    printf '#!/bin/sh\necho "%s v=9.9.9"\n' "$n" > "$tmp/pkg/$n"
done
printf '#!/bin/sh\necho "milog-probe 9.9.9 (linux/amd64)"\n' > "$tmp/pkg/milog-probe"
chmod 0755 "$tmp/pkg"/milog-*
tar -czf "$tmp/release/$archive" -C "$tmp/pkg" milog.sh milog-web milog-tui milog-probe
printf '%s  %s\n' "$(sha "$tmp/release/$archive")" "$archive" > "$tmp/release/checksums.txt"
cp "$tmp/release/$archive" "$tmp/good.tar.gz"

cat > "$tmp/stub/curl" <<'EOF'
#!/usr/bin/env bash
out="" url=""
while (( $# )); do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -w|--retry|--retry-delay|--max-time) shift 2 ;;
        -*) shift ;;
        *)  url="$1"; shift ;;
    esac
done
echo "$url" >> "$CURL_LOG"
if [[ "$url" == https://github.com/test/milog/releases/latest ]]; then
    printf 'https://github.com/test/milog/releases/tag/v9.9.9'; exit 0
fi
[[ "$url" == https://github.com/test/milog/releases/download/v9.9.9/* ]] || exit 22
[[ -f "$FAKE_RELEASE/${url##*/}" ]] || exit 22
cp "$FAKE_RELEASE/${url##*/}" "$out"
EOF
for pm in rpm apk pacman; do printf '#!/bin/sh\nexit 1\n' > "$tmp/stub/$pm"; done
printf '#!/bin/sh\n[ "${FAKE_DPKG_OWNS:-0}" = 1 ]\n' > "$tmp/stub/dpkg"
printf '#!/bin/sh\n[ "$1 $3" = "is-active milog.service" ]\n' > "$tmp/stub/systemctl"
chmod 0755 "$tmp/stub"/*
export PATH="$tmp/stub:$PATH"

# Installed milog stamped $1 plus milog-web and milog-tui (no milog-probe), reached through a symlink.
install_old() {
    chmod -R u+w "$tmp/bin" 2>/dev/null || true
    rm -rf "${tmp:?}/bin"
    mkdir -p "$tmp/bin"
    stamp "$1" "$tmp/bin/milog"
    for n in milog-web milog-tui; do
        printf '#!/bin/sh\necho "%s v=0.1.0"\n' "$n" > "$tmp/bin/$n"
        chmod 0750 "$tmp/bin/$n"
    done
    ln -sfn "$tmp/bin/milog" "$tmp/link/milog"
}
snap() { ls -A "$tmp/bin"; cat "$tmp/bin"/* | cksum; }

install_old v0.1.0
out=$("$tmp/link/milog" version) || fail "version exited non-zero"
[[ "$out" == *"milog        v0.1.0 (built "* ]] || fail "version missing milog stamp: $out"
[[ "$out" == *"milog-web    0.1.0  $tmp/bin/milog-web"* ]] || fail "version missing milog-web: $out"
[[ "$out" == *"milog-tui    0.1.0"* ]] || fail "version missing milog-tui: $out"
[[ "$out" != *milog-probe* ]] || fail "version listed a probe that is not installed: $out"
[[ "$("$tmp/link/milog" --version)" == "$out" ]] || fail "--version differs from version"

# Up to date, and a dev build ahead of the release, change nothing.
for v in v9.9.9 v9.9.9-3-gabc1234; do
    install_old "$v"
    before=$(snap)
    out=$("$tmp/link/milog" update) || fail "update on $v exited non-zero"
    [[ "$out" == *"is up to date"* ]] || fail "update on $v: $out"
    "$tmp/link/milog" update --check >/dev/null || fail "--check on $v should exit 0"
    [[ "$(snap)" == "$before" ]] || fail "update on $v changed files"
done

# --check exits 10 for an older stamp, including mis-stamped and unparseable ones, and changes nothing.
for v in v0.1.0 v0.3.0-127-gfcec845 abc1234 unknown; do
    install_old "$v"
    before=$(snap)
    rc=0; "$tmp/link/milog" update --check >/dev/null || rc=$?
    [[ "$rc" == 10 ]] || fail "--check on $v exited $rc, want 10"
    [[ "$(snap)" == "$before" ]] || fail "--check on $v changed files"
done

install_old v0.1.0
before=$(snap)

printf 'x' >> "$tmp/release/$archive"
if out=$("$tmp/link/milog" update 2>&1); then fail "tampered tarball did not abort"; fi
[[ "$out" == *"checksum mismatch"* ]] || fail "tampered tarball: $out"
[[ "$(snap)" == "$before" ]] || fail "tampered tarball changed files"
cp "$tmp/good.tar.gz" "$tmp/release/$archive"

if out=$(FAKE_DPKG_OWNS=1 "$tmp/link/milog" update 2>&1); then fail "package-owned milog was updated"; fi
[[ "$out" == *"sudo apt install ./milog_9.9.9_linux_"*.deb* ]] || fail "package-owned: $out"
[[ "$(snap)" == "$before" ]] || fail "package-owned refusal changed files"

# Root writes anywhere, so the unwritable case drops to nobody when the test runs as root.
chmod 0555 "$tmp/bin"
as_user=()
if [[ "$(id -u)" == 0 ]]; then
    as_user=(setpriv --reuid=65534 --regid=65534 --clear-groups)
    chmod -R a+rX "$tmp"
    chmod a+w "$tmp/home"
fi
if out=$("${as_user[@]}" "$tmp/link/milog" update 2>&1); then fail "unwritable install was updated"; fi
[[ "$out" == *"run: sudo milog update"* ]] || fail "unwritable: $out"
chmod 0755 "$tmp/bin"
[[ "$(snap)" == "$before" ]] || fail "unwritable refusal changed files"

install_old v0.1.0
: > "$CURL_LOG"
out=$("$tmp/link/milog" update) || fail "update exited non-zero: $out"
grep -q '/checksums.txt$' "$CURL_LOG" || fail "update did not fetch checksums.txt"
cmp -s "$tmp/bin/milog" "$tmp/pkg/milog.sh" || fail "milog was not replaced"
for n in milog-web milog-tui; do
    cmp -s "$tmp/bin/$n" "$tmp/pkg/$n" || fail "$n was not replaced"
    [[ "$(mode "$tmp/bin/$n")" == 750 ]] || fail "$n mode not preserved: $(mode "$tmp/bin/$n")"
done
[[ "$(mode "$tmp/bin/milog")" == 755 ]] || fail "milog mode not preserved"
[[ -L "$tmp/link/milog" ]] || fail "symlink was replaced instead of its target"
[[ "$(ls -A "$tmp/bin")" == "$(printf 'milog\nmilog-tui\nmilog-web')" ]] || fail "unexpected files: $(ls -A "$tmp/bin")"
[[ "$out" == *"v0.1.0 → v9.9.9"* ]] || fail "update summary: $out"
[[ "$out" == *"sudo systemctl restart milog"* ]] || fail "no daemon restart hint: $out"
[[ "$out" != *"restart milog-probe"* ]] || fail "probe restart hint without an active probe: $out"

out=$("$tmp/link/milog" update) || fail "second update exited non-zero"
[[ "$out" == *"v9.9.9 is up to date"* ]] || fail "second update: $out"

echo "version/update smoke ok"
