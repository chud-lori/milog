#!/usr/bin/env bash
# ==============================================================================
# build.sh — concatenate src/*.sh into a single milog.sh artifact.
#
# Layout rationale:
#   - `src/core.sh` must come first. It owns the shebang, `set -euo pipefail`,
#     the default config vars, the MILOG_CONFIG file sourcing, env overrides,
#     and auto-discovery — all of which execute at source time, not inside
#     functions. We emit its shebang first, inject two `# MILOG_VERSION=…`
#     and `# MILOG_BUILT=…` header lines so tooling can see what's running,
#     then append the rest of core.sh.
#   - Helper libraries (alerts, ui, system, history, nginx, web) come next.
#     These are function-only; order doesn't matter for correctness.
#   - `src/modes/*.sh` follow, glob order (alphabetic). Again, functions only.
#   - `src/dispatch.sh` comes last — it contains `show_help` plus the final
#     `case` that actually runs a mode. Nothing sourced after this.
#
# The output replaces milog.sh at the repo root. CI can verify freshness with:
#   bash build.sh && git diff --exit-code milog.sh
#
# Usage:
#   bash build.sh               # writes milog.sh
#   bash build.sh my-milog.sh   # writes my-milog.sh
# ==============================================================================
set -euo pipefail

# Pin glob/sort collation to byte order. Bash pathname expansion uses
# LC_COLLATE — same `for f in src/modes/*.sh` produces a different
# order under en_US.UTF-8 (darwin / dev laptops) vs C / C.UTF-8 (CI
# Ubuntu, minimal containers). Without this pin, the milog.sh
# committed from a UTF-8 host fails CI's bash-bundle freshness diff
# when CI rebuilds it under C locale. Standardising on C.UTF-8 here
# makes the bundle byte-stable across every host build.sh runs on.
export LC_ALL=C

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

OUT="${1:-milog.sh}"

# Guard: the source layout must exist. Clearer error than sed -n failing.
for required in src/core.sh src/dispatch.sh src/modes; do
    [[ -e "$required" ]] || { echo "build.sh: missing $required — is the repo split into src/ yet?" >&2; exit 1; }
done

# Version fingerprint embedded into milog.sh. install.sh + `milog doctor`
# read these lines to tell the user exactly what code is running. Format
# is stable — two lines, each `# <KEY>=<value>`, immediately after the
# shebang. Grep-friendly, no parsing heroics.
#
# MILOG_VERSION resolves via `git describe --always --dirty`:
#   abc1234             — clean checkout at commit abc1234
#   abc1234-dirty       — uncommitted changes in the working tree
#   unknown             — not in a git repo (e.g. release tarball)
# Uncommitted work gets the `-dirty` suffix so users know they're running
# an in-progress build, not the published code. Honesty over neatness.
MILOG_VERSION=$(git describe --always --dirty 2>/dev/null || echo unknown)
MILOG_BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u 2>/dev/null || echo unknown)

{
    # core.sh already starts with #!/usr/bin/env bash + set -euo pipefail.
    # Emit the shebang line first, then our version header, THEN the rest
    # of core.sh. Preserves the shebang's position 1 so `bash` / kernel
    # exec still work, while letting install.sh `grep ^# MILOG_` early.
    head -1 src/core.sh
    printf '# MILOG_VERSION=%s\n' "$MILOG_VERSION"
    printf '# MILOG_BUILT=%s\n'   "$MILOG_BUILT"
    tail -n +2 src/core.sh
    cat src/alerts.sh
    cat src/ui.sh
    cat src/system.sh
    cat src/history.sh
    cat src/nginx.sh
    cat src/web.sh
    # shellcheck disable=SC2068
    for f in src/modes/*.sh; do
        cat "$f"
    done
    cat src/dispatch.sh
} > "$OUT"

chmod +x "$OUT"

# Syntax-check the result — catches forgotten pieces / mis-ordered sources.
if ! bash -n "$OUT"; then
    echo "build.sh: $OUT has syntax errors (bash -n failed)" >&2
    exit 1
fi

lines=$(wc -l < "$OUT" | tr -d ' ')
echo "built $OUT  (${lines} lines, bash -n clean)"

# ---- Optional Go companion binaries ------------------------------------------
# go/cmd/milog-web   — HTTP + SSE dashboard daemon
# go/cmd/milog-tui   — bubbletea TUI
#
# When a Go toolchain is available we compile both alongside the bash
# bundle; if not we skip silently — users without Go still get a working
# milog.sh. Version is stamped via -ldflags to match the bash
# MILOG_VERSION embedding so every artifact reports the same SHA.
if [[ -d go && -f go/go.mod ]]; then
    if command -v go >/dev/null 2>&1; then
        mkdir -p go/bin
        # Single cd so GOPATH / module cache is resolved once.
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

            # milog-probe is Linux-only (eBPF). On Linux build hosts we
            # also need clang to compile the .bpf.c sources into the
            # .o blobs that exec_linux.go / tcp_linux.go / file_linux.go
            # / ptrace_linux.go / kmod_linux.go embed. Skip path on
            # macOS / BSD, or on a Linux host without clang installed.
            # Each .bpf.c → .bpf.o pair is independent: a failure on
            # one doesn't block the others from compiling, and all
            # objects must succeed before milog-probe builds.
            uname_s=$(uname -s 2>/dev/null || echo unknown)
            probe_dir="internal/probe"
            bpf_target_arch=$(uname -m 2>/dev/null | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
            bpf_inc="/usr/include/$(uname -m 2>/dev/null)-linux-gnu"
            # bpf_compile <src> <obj> — returns 0 on success, non-zero
            # otherwise. Tries the include-path-prefixed invocation
            # first (Debian / Ubuntu layout) and falls back to no-I
            # (Fedora / Arch / minimal containers put libbpf headers
            # at /usr/include directly).
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
            # Non-Linux build hosts skip the probe silently. Probe is
            # never useful off Linux anyway; no point in printing a
            # banner about it on every macOS build.
        )
    else
        echo "build.sh: go toolchain not found — skipping milog-web + milog-tui (install.sh fallback stays)" >&2
    fi
fi
