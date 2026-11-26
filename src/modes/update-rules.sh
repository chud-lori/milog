# milog update-rules: installs the detection rules from the latest release as RULES_FILE.
# checksums.txt comes from the same release, so it catches corruption, not a compromised release.
mode_update_rules() {
    case "${1:-}" in
        "") ;;
        --check) _rules_freshness_report; return ;;
        *) echo -e "${R}usage: milog update-rules [--check]${NC}" >&2; return 1 ;;
    esac
    local repo="${MILOG_RELEASE_REPO:-chud-lori/milog}" loc tag base tmp want got new cur dst_tmp
    # /releases/latest redirects to /releases/tag/<tag>.
    loc=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/${repo}/releases/latest" 2>/dev/null) || loc=""
    if [[ ! "$loc" =~ /tag/([^/?#]+) ]]; then
        echo -e "${R}update-rules: no release found for ${repo}${NC}" >&2
        return 1
    fi
    tag="${BASH_REMATCH[1]}"
    base="https://github.com/${repo}/releases/download/${tag}"

    tmp=$(mktemp -d) || return 1
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    # Releases up to v0.6.0 predate the rules file, so a 404 here is expected.
    if ! curl -fsSL --retry 2 --retry-delay 1 --max-time 60 -o "$tmp/milog-rules.tsv" "${base}/milog-rules.tsv" 2>/dev/null; then
        echo -e "${R}update-rules: release ${tag} ships no rules file (or it could not be fetched)${NC}" >&2
        return 1
    fi
    if ! curl -fsSL --retry 2 --retry-delay 1 --max-time 60 -o "$tmp/checksums.txt" "${base}/checksums.txt" 2>/dev/null; then
        echo -e "${R}update-rules: could not fetch checksums.txt for ${tag}; refusing an unverified rules file${NC}" >&2
        return 1
    fi

    want=$(awk '$2 == "milog-rules.tsv" {print $1; exit}' "$tmp/checksums.txt")
    if [[ -z "$want" ]]; then
        echo -e "${R}update-rules: milog-rules.tsv is not listed in checksums.txt for ${tag}${NC}" >&2
        return 1
    fi
    got=$(_audit_sha256 "$tmp/milog-rules.tsv")
    if [[ -z "$got" ]]; then
        echo -e "${R}update-rules: need sha256sum or shasum to verify the download${NC}" >&2
        return 1
    fi
    if [[ "$got" != "$want" ]]; then
        echo -e "${R}update-rules: checksum mismatch for milog-rules.tsv from ${tag} (expected ${want}, got ${got})${NC}" >&2
        return 1
    fi
    if ! new=$(_rules_check "$tmp/milog-rules.tsv"); then
        echo -e "${R}update-rules: rules from ${tag} failed validation; keeping the current rules${NC}" >&2
        return 1
    fi

    cur=$(_rules_check "$RULES_FILE" 2>/dev/null) || cur=$(_rules_default | _rules_version)
    if (( new < cur )); then
        echo -e "${R}update-rules: ${tag} ships rules version ${new}, older than the active version ${cur}; not downgrading${NC}" >&2
        _rules_stamp_checked "$tag" "$cur"
        return 1
    fi
    if (( new == cur )); then
        _rules_stamp_checked "$tag" "$cur"
        echo "Rules already at version ${cur}."
        return 0
    fi

    mkdir -p "$(dirname "$RULES_FILE")" || return 1
    dst_tmp=$(mktemp "${RULES_FILE}.XXXXXX") || return 1
    if ! cp "$tmp/milog-rules.tsv" "$dst_tmp" || ! chmod 0644 "$dst_tmp" || ! mv -f "$dst_tmp" "$RULES_FILE"; then
        rm -f "$dst_tmp"
        echo -e "${R}update-rules: could not write ${RULES_FILE}${NC}" >&2
        return 1
    fi
    _rules_stamp_checked "$tag" "$new"
    echo -e "${G}✓${NC} rules version ${cur} → ${new} (${tag}) written to ${RULES_FILE}"
    echo "Running exploits/probes watchers and the daemon load rules at start; restart them to pick this up."
}

# Records when update-rules last confirmed rules version $2 against release $1.
_rules_stamp_checked() {
    mkdir -p "$(dirname "$RULES_FILE")" 2>/dev/null || true
    printf '%s\t%s\t%s\n' "$(date +%s)" "$1" "$2" > "${RULES_FILE}.checked" \
        || echo -e "${Y}update-rules: could not write ${RULES_FILE}.checked; rules age will be misreported${NC}" >&2
}

# Prints the active rules' version, source and age; fails when older than RULES_MAX_AGE_DAYS (0 never warns).
_rules_freshness() {
    local version src since="" stamped="" what f days
    if [[ -f "$RULES_FILE" ]] && version=$(_rules_check "$RULES_FILE" 2>/dev/null); then
        src="$RULES_FILE"
    else
        version=$(_rules_default | _rules_version)
        src="built-in"
    fi
    [[ -f "${RULES_FILE}.checked" ]] && { IFS=$'\t' read -r since _ stamped < "${RULES_FILE}.checked" || true; }
    # The stamp only vouches for the version it checked, not for a later fallback to the built-in rules.
    if [[ "$since" =~ ^[0-9]+$ && "$stamped" == "$version" ]]; then
        what="last checked against a release"
    else
        f="$RULES_FILE" what="written"
        [[ "$src" == built-in ]] && f="${BASH_SOURCE[0]}" what="shipped with this milog, installed"
        since=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo "")
    fi
    if [[ ! "$since" =~ ^[0-9]+$ ]]; then
        printf 'rules version %s (%s), age unknown' "$version" "$src"
        return 0
    fi
    days=$(( ($(date +%s) - since) / 86400 ))
    printf 'rules version %s (%s), %s %sd ago' "$version" "$src" "$what" "$days"
    (( ${RULES_MAX_AGE_DAYS:-60} <= 0 || days <= ${RULES_MAX_AGE_DAYS:-60} ))
}

_rules_freshness_report() {
    local line
    if line=$(_rules_freshness); then
        echo -e "${G}✓${NC} ${line}"
        return 0
    fi
    echo -e "${Y}!${NC} ${line}"
    echo -e "${D}  older than RULES_MAX_AGE_DAYS=${RULES_MAX_AGE_DAYS:-60}; nothing updates on its own, run: milog update-rules${NC}"
    return 1
}
