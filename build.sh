#!/usr/bin/env bash
# ==============================================================================
# build.sh — concatenate src/*.sh into a single milog.sh artifact.
#
# Layout rationale:
#   - `src/core.sh` must come first. It owns the shebang, `set -euo pipefail`,
#     the default config vars, the MILOG_CONFIG file sourcing, env overrides,
#     and auto-discovery — all of which execute at source time, not inside
#     functions.
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

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

OUT="${1:-milog.sh}"

# Guard: the source layout must exist. Clearer error than sed -n failing.
for required in src/core.sh src/dispatch.sh src/modes; do
    [[ -e "$required" ]] || { echo "build.sh: missing $required — is the repo split into src/ yet?" >&2; exit 1; }
done

{
    # core.sh already starts with #!/usr/bin/env bash + set -euo pipefail.
    # Do NOT re-add them here.
    cat src/core.sh
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
