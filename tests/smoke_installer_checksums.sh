#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

# Fake release: one tarball carrying milog-web, plus its checksums.txt.
archive="milog_9.9.9_linux_amd64.tar.gz"
mkdir -p "$tmp/pkg" "$tmp/release"
printf '#!/bin/sh\necho web\n' > "$tmp/pkg/milog-web"
tar -czf "$tmp/release/$archive" -C "$tmp/pkg" milog-web
if command -v sha256sum >/dev/null 2>&1; then
    sum=$(sha256sum "$tmp/release/$archive" | awk '{print $1}')
else
    sum=$(shasum -a 256 "$tmp/release/$archive" | awk '{print $1}')
fi
printf '%s  %s\n' "$sum" "$archive" > "$tmp/release/checksums.txt"
sed '/^main "\$@"$/d' "$ROOT/install.sh" > "$tmp/install_lib.sh"

# Runs _release_download_binary with curl served from $tmp/release.
run_download() {
    local dst="$1"
    mkdir -p "$dst"
    bash -c '
        rel="$2" dst="$3"
        . "$1"
        curl() {
            local out="" url
            while (( $# )); do
                case "$1" in
                    -o) out="$2"; shift 2 ;;
                    -*) shift ;;
                    *)  url="$1"; shift ;;
                esac
            done
            [[ -f "$rel/${url##*/}" ]] || return 22
            cp "$rel/${url##*/}" "$out"
        }
        _release_download_binary milog-web "$dst" v9.9.9 linux amd64
    ' _ "$tmp/install_lib.sh" "$tmp/release" "$dst"
}

# Matching checksum installs the binary.
run_download "$tmp/ok" >/dev/null
[[ -x "$tmp/ok/milog-web" ]] || { echo "verified binary was not installed" >&2; exit 1; }

# Tampered archive aborts and installs nothing.
cp "$tmp/release/$archive" "$tmp/good.tar.gz"
printf 'x' >> "$tmp/release/$archive"
if out=$(run_download "$tmp/bad" 2>&1); then
    echo "tampered archive did not abort" >&2; exit 1
fi
[[ "$out" == *"checksum mismatch"* ]] || { echo "unexpected error: $out" >&2; exit 1; }
[[ ! -e "$tmp/bad/milog-web" ]] || { echo "tampered binary was installed" >&2; exit 1; }
cp "$tmp/good.tar.gz" "$tmp/release/$archive"

# Archive missing from checksums.txt aborts.
printf '%s  other.tar.gz\n' "$sum" > "$tmp/release/checksums.txt"
if out=$(run_download "$tmp/unlisted" 2>&1); then
    echo "unlisted archive did not abort" >&2; exit 1
fi
[[ "$out" == *"not listed in checksums.txt"* ]] || { echo "unexpected error: $out" >&2; exit 1; }
[[ ! -e "$tmp/unlisted/milog-web" ]] || { echo "unlisted binary was installed" >&2; exit 1; }

# Release without checksums.txt aborts.
rm "$tmp/release/checksums.txt"
if out=$(run_download "$tmp/nosums" 2>&1); then
    echo "missing checksums.txt did not abort" >&2; exit 1
fi
[[ "$out" == *"could not fetch checksums.txt"* ]] || { echo "unexpected error: $out" >&2; exit 1; }
[[ ! -e "$tmp/nosums/milog-web" ]] || { echo "unverified binary was installed" >&2; exit 1; }

echo "installer checksum smoke ok"
