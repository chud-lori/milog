#!/usr/bin/env bash
# build.sh [out] — concatenate src/ into milog.sh (or <out>).
# core.sh goes first because it runs at source time; dispatch.sh goes last because it runs the mode.
set -euo pipefail

# Glob order follows LC_COLLATE, so pin it or a bundle built on macOS fails CI's freshness diff.
export LC_ALL=C

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

OUT="${1:-milog.sh}"

for required in src/core.sh src/dispatch.sh src/modes; do
    [[ -e "$required" ]] || { echo "build.sh: missing $required — is the repo split into src/ yet?" >&2; exit 1; }
done

# install.sh and `milog doctor` read these `# MILOG_<KEY>=` lines right after the shebang.
MILOG_VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo unknown)
MILOG_BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u 2>/dev/null || echo unknown)

{
    # The shebang must stay on line 1, so the version header goes after it.
    head -1 src/core.sh
    printf '# MILOG_VERSION=%s\n' "$MILOG_VERSION"
    printf '# MILOG_BUILT=%s\n'   "$MILOG_BUILT"
    tail -n +2 src/core.sh
    cat src/alerts.sh
    cat src/ui.sh
    cat src/system.sh
    cat src/history.sh
    cat src/anomaly.sh
    cat src/nginx.sh
    cat src/web.sh
    # shellcheck disable=SC2068
    for f in src/modes/*.sh; do
        cat "$f"
    done
    # completions/* baked in as _completions_payload_<shell> for installs
    # that have no completions/ dir next to the binary.
    for shell in bash zsh fish; do
        case "$shell" in
            bash) f=completions/milog.bash ;;
            zsh)  f=completions/_milog ;;
            fish) f=completions/milog.fish ;;
        esac
        [[ -s "$f" ]] || { echo "build.sh: missing $f" >&2; exit 1; }
        if grep -qx 'MILOG_COMPLETION_EOF' "$f"; then
            echo "build.sh: $f contains the heredoc delimiter" >&2; exit 1
        fi
        printf "_completions_payload_%s() {\n    cat <<'MILOG_COMPLETION_EOF'\n" "$shell"
        cat "$f"
        printf 'MILOG_COMPLETION_EOF\n}\n'
    done
    cat src/dispatch.sh
} > "$OUT"

chmod +x "$OUT"

if ! bash -n "$OUT"; then
    echo "build.sh: $OUT has syntax errors (bash -n failed)" >&2
    exit 1
fi

lines=$(wc -l < "$OUT" | tr -d ' ')
echo "built $OUT  (${lines} lines, bash -n clean)"

# Go companion binaries are optional; milog.sh works without them.
if [[ -d go && -f go/go.mod ]]; then
    if command -v go >/dev/null 2>&1; then
        mkdir -p go/bin
        ( cd go
            for bin in milog-web milog-tui; do
                if go build \
                    -ldflags "-X main.buildVersion=${MILOG_VERSION}" \
                    -o "bin/${bin}" \
                    "./cmd/${bin}"; then
                    echo "built go/bin/${bin}  (version ${MILOG_VERSION})"
                else
                    echo "build.sh: go build ${bin} failed — milog.sh still usable" >&2
                fi
            done

            # milog-probe is Linux-only and embeds .bpf.o objects compiled with clang; all must build first.
            uname_s=$(uname -s 2>/dev/null || echo unknown)
            probe_dir="internal/probe"
            bpf_target_arch=$(uname -m 2>/dev/null | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
            bpf_inc="/usr/include/$(uname -m 2>/dev/null)-linux-gnu"
            # Debian/Ubuntu need the multiarch include dir; Fedora/Arch keep libbpf headers in /usr/include.
            bpf_compile() {
                local src="$1" obj="$2"
                clang -target bpf -O2 -g -Wall \
                    -D__TARGET_ARCH_${bpf_target_arch} \
                    -I"$bpf_inc" \
                    -c "$src" -o "$obj" 2>/dev/null && return 0
                clang -target bpf -O2 -g -Wall \
                    -c "$src" -o "$obj"
            }
            bpf_objs_ok=1
            if [[ "$uname_s" == "Linux" ]]; then
                if command -v clang >/dev/null 2>&1; then
                    for stem in exec tcp file ptrace kmod retrans syscall bpfload; do
                        src="${probe_dir}/bpf/${stem}.bpf.c"
                        obj="${probe_dir}/bpf/${stem}.bpf.o"
                        if ! bpf_compile "$src" "$obj"; then
                            echo "build.sh: clang failed to compile ${src} — skipping milog-probe" >&2
                            bpf_objs_ok=0
                        elif [[ ! -s "$obj" ]]; then
                            echo "build.sh: ${obj} produced empty — skipping milog-probe" >&2
                            bpf_objs_ok=0
                        fi
                    done
                    if (( bpf_objs_ok )); then
                        if go build \
                            -ldflags "-X main.buildVersion=${MILOG_VERSION}" \
                            -o "bin/milog-probe" \
                            "./cmd/milog-probe"; then
                            echo "built go/bin/milog-probe  (version ${MILOG_VERSION})"
                        else
                            echo "build.sh: go build milog-probe failed — milog.sh + other binaries still usable" >&2
                        fi
                    fi
                else
                    echo "build.sh: clang missing — skipping milog-probe (apt install clang llvm libbpf-dev)" >&2
                fi
            fi
            # Non-Linux hosts skip the probe without a message.
        )
    else
        echo "build.sh: go toolchain not found — skipping milog-web + milog-tui (install.sh fallback stays)" >&2
    fi
fi
