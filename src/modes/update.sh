# milog update: replaces milog and its installed companion binaries with the latest GitHub release.
# checksums.txt comes from the same release, so it catches corruption, not a compromised release.

# Latest release tag of repo $1, empty when none; fails when GitHub is unreachable.
_release_latest_tag() {
    local loc rc=0
    # /releases/latest redirects to /releases/tag/<tag> and answers 404 (curl exit 22) when there is no release.
    loc=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/$1/releases/latest" 2>/dev/null) || rc=$?
    (( rc == 0 || rc == 22 )) || return 1
    [[ "$loc" =~ /tag/([^/?#]+) ]] && printf '%s' "${BASH_REMATCH[1]}"
    return 0
}

# Commit SHA that tag $2 of repo $1 points at, empty when it cannot be resolved.
_release_tag_sha() {
    curl -fsSL --max-time 15 -H 'Accept: application/vnd.github.sha' \
        "https://api.github.com/repos/$1/commits/$2" 2>/dev/null || true
}

_release_os_slug() {
    case "$(uname -s)" in
        Linux)  echo linux ;;
        Darwin) echo darwin ;;
        *)      echo unsupported ;;
    esac
}

_release_arch_slug() {
    case "$(uname -m)" in
        x86_64|amd64)  echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *)             echo unsupported ;;
    esac
}

# Downloads asset $3 of repo $1 release $2 into dir $4, verified against that release's checksums.txt.
_release_fetch_verified() {
    local repo="$1" tag="$2" asset="$3" dir="$4" base want got
    base="https://github.com/${repo}/releases/download/${tag}"
    if ! curl -fsSL --retry 2 --retry-delay 1 --max-time 60 -o "$dir/$asset" "$base/$asset" 2>/dev/null; then
        echo -e "${R}could not download ${asset} from ${tag}${NC}" >&2
        return 1
    fi
    if ! curl -fsSL --retry 2 --retry-delay 1 --max-time 60 -o "$dir/checksums.txt" "$base/checksums.txt" 2>/dev/null; then
        echo -e "${R}could not fetch checksums.txt for ${tag}; refusing an unverified download${NC}" >&2
        return 1
    fi
    want=$(awk -v f="$asset" '$2 == f {print $1; exit}' "$dir/checksums.txt")
    if [[ -z "$want" ]]; then
        echo -e "${R}${asset} is not listed in checksums.txt for ${tag}${NC}" >&2
        return 1
    fi
    got=$(_audit_sha256 "$dir/$asset")
    if [[ -z "$got" ]]; then
        echo -e "${R}need sha256sum or shasum to verify ${asset}${NC}" >&2
        return 1
    fi
    if [[ "$got" != "$want" ]]; then
        echo -e "${R}checksum mismatch for ${asset} (expected ${want}, got ${got})${NC}" >&2
        return 1
    fi
}

# True when stamp $1 is older than tag $2; a stamp without a vX.Y.Z prefix counts as older.
_version_older() {
    local re='^v?([0-9]+)\.([0-9]+)\.([0-9]+)' i
    local -a a b
    if [[ ! "$2" =~ $re ]]; then
        [[ "$1" != "$2" ]]; return
    fi
    b=("${BASH_REMATCH[@]:1}")
    [[ "$1" =~ $re ]] || return 0
    a=("${BASH_REMATCH[@]:1}")
    for i in 0 1 2; do
        if (( 10#${a[i]} < 10#${b[i]} )); then return 0; fi
        if (( 10#${a[i]} > 10#${b[i]} )); then return 1; fi
    done
    return 1
}

# Prints how to update $1 through the package manager that owns it; non-zero when none does.
_update_pkg_hint() {
    local path="$1" tag="$2" file pkg
    file="milog_${tag#v}_linux_$(_release_arch_slug)"
    local url="https://github.com/${MILOG_RELEASE_REPO:-chud-lori/milog}/releases/download/${tag}"
    if command -v dpkg >/dev/null 2>&1 && dpkg -S "$path" >/dev/null 2>&1; then
        echo "  curl -fLO ${url}/${file}.deb && sudo apt install ./${file}.deb"
    elif command -v rpm >/dev/null 2>&1 && rpm -qf "$path" >/dev/null 2>&1; then
        echo "  curl -fLO ${url}/${file}.rpm && sudo rpm -U ./${file}.rpm"
    elif command -v apk >/dev/null 2>&1 && apk info --who-owns "$path" >/dev/null 2>&1; then
        echo "  curl -fLO ${url}/${file}.apk && sudo apk add --allow-untrusted ./${file}.apk"
    elif command -v pacman >/dev/null 2>&1 && pkg=$(pacman -Qqo "$path" 2>/dev/null); then
        echo "  upgrade the ${pkg} package the way you installed it (AUR helper or makepkg)"
    else
        return 1
    fi
}

mode_update() {
    local check=0
    case "${1:-}" in
        "")      ;;
        --check) check=1 ;;
        *) echo -e "${R}update: unknown option '$1'${NC} (usage: milog update [--check])" >&2; return 1 ;;
    esac

    local repo="${MILOG_RELEASE_REPO:-chud-lori/milog}" self cur tag cur_sha tag_sha up_to_date=0
    self=$(_milog_self)
    cur=$(_milog_stamp VERSION)
    if ! tag=$(_release_latest_tag "$repo"); then
        echo -e "${R}update: could not reach github.com to look up the latest release of ${repo}${NC}" >&2
        return 1
    fi
    if [[ -z "$tag" ]]; then
        echo -e "${R}update: no release found for ${repo}${NC}" >&2
        return 1
    fi
    if ! _version_older "$cur" "$tag"; then
        up_to_date=1
    elif [[ "$cur" =~ -g([0-9a-f]{7,40})(-dirty)?$ ]]; then
        # Bundles built before build.sh used --tags name an old tag but carry the release commit's SHA.
        cur_sha="${BASH_REMATCH[1]}"
        tag_sha=$(_release_tag_sha "$repo" "$tag")
        [[ -n "$tag_sha" && "$tag_sha" == "$cur_sha"* ]] && up_to_date=1
    fi
    if (( up_to_date )); then
        echo "milog ${cur} is up to date (latest release: ${tag})"
        return 0
    fi
    if (( check )); then
        echo "update available: ${cur} → ${tag}  (run: milog update)"
        return 10
    fi

    if [[ -e "$(dirname "$self")/.git" ]]; then
        echo -e "${R}update: ${self} is in a git checkout; update it with git pull && bash build.sh${NC}" >&2
        return 1
    fi
    local -a names=() paths=()
    local name path hint
    while IFS=$'\t' read -r name path; do
        names+=("$name")
        paths+=("$(readlink -f "$path" 2>/dev/null || printf '%s' "$path")")
    done < <(_milog_companions)
    # milog goes last: its stamp is what the next run compares, so a partial update still reads as outdated.
    names+=(milog)
    paths+=("$self")
    for path in "${paths[@]}"; do
        if hint=$(_update_pkg_hint "$path" "$tag"); then
            echo -e "${R}update: ${path} belongs to a system package; update it through the package manager:${NC}" >&2
            echo "$hint" >&2
            return 1
        fi
    done
    for path in "${paths[@]}"; do
        if [[ ! -w "$(dirname "$path")" ]]; then
            echo -e "${R}update: $(dirname "$path") is not writable; run: sudo milog update${NC}" >&2
            return 1
        fi
    done

    local os arch archive tmp
    os=$(_release_os_slug)
    arch=$(_release_arch_slug)
    if [[ "$os" == unsupported || "$arch" == unsupported ]]; then
        echo -e "${R}update: releases have no build for $(uname -s)/$(uname -m)${NC}" >&2
        return 1
    fi
    archive="milog_${tag#v}_${os}_${arch}.tar.gz"
    tmp=$(mktemp -d) || return 1
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    if ! _release_fetch_verified "$repo" "$tag" "$archive" "$tmp"; then
        echo -e "${R}update: aborted; nothing was changed${NC}" >&2
        return 1
    fi
    mkdir "$tmp/x"
    if ! tar -xzf "$tmp/$archive" -C "$tmp/x" || ! bash -n "$tmp/x/milog.sh" 2>/dev/null; then
        echo -e "${R}update: ${archive} has no usable milog.sh; nothing was changed${NC}" >&2
        return 1
    fi

    # Stage every file before the first mv so a failure leaves the old install whole.
    local -a staged=()
    local i src t
    for i in "${!names[@]}"; do
        staged+=("")
        t=""
        src="$tmp/x/${names[i]}"
        [[ "${names[i]}" == milog ]] && src="$tmp/x/milog.sh"
        if [[ ! -f "$src" ]]; then
            echo -e "${Y}update: ${tag} ships no ${names[i]} for ${os}/${arch}; keeping ${paths[i]}${NC}" >&2
            continue
        fi
        cmp -s "$src" "${paths[i]}" && continue
        # cp -p carries the installed file's mode over before the new bytes land.
        if ! t=$(mktemp "$(dirname "${paths[i]}")/.${names[i]}.update.XXXXXX") \
            || ! cp -p "${paths[i]}" "$t" || ! cat "$src" > "$t"; then
            [[ -n "$t" ]] && rm -f "$t"
            for t in "${staged[@]}"; do [[ -n "$t" ]] && rm -f "$t"; done
            echo -e "${R}update: could not stage ${paths[i]}; nothing was changed${NC}" >&2
            return 1
        fi
        staged[i]="$t"
    done

    local changed=0 j
    local -a left=()
    for i in "${!staged[@]}"; do
        [[ -n "${staged[i]}" ]] || continue
        # A rename leaves the running script's open inode intact.
        if ! mv -f "${staged[i]}" "${paths[i]}"; then
            for j in "${!staged[@]}"; do
                (( j >= i )) && [[ -n "${staged[j]}" ]] || continue
                rm -f "${staged[j]}"
                left+=("${paths[j]}")
            done
            echo -e "${R}update: could not replace ${paths[i]}; these were not updated:${NC}" >&2
            printf '  %s\n' "${left[@]}" >&2
            (( changed == 0 )) || echo -e "${Y}update: files listed as updated above are already ${tag}; rerun milog update once the error is fixed${NC}" >&2
            return 1
        fi
        echo "updated ${paths[i]}"
        changed=$((changed + 1))
    done
    if (( changed == 0 )); then
        echo "milog already matches ${tag}; nothing to replace"
        return 0
    fi
    echo -e "${G}✓${NC} milog ${cur} → ${tag}"

    command -v systemctl >/dev/null 2>&1 || return 0
    if systemctl is-active --quiet milog.service 2>/dev/null; then
        echo "  restart the daemon:  sudo systemctl restart milog"
    fi
    if systemctl is-active --quiet milog-probe.service 2>/dev/null; then
        echo "  restart the probe:   sudo systemctl restart milog-probe"
    fi
    if [[ -f "$_PROBE_SYSTEMD_UNIT" ]]; then
        echo "  refresh the probe unit for this version:  sudo milog probe install-service"
    fi
}
