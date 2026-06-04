#!/usr/bin/env bash
#==============================================================================
# EdgeBox Bootstrap Loader (v4.5.0 - block 6 batch A)
#
# This is the entry point for `curl | bash` installation. It:
#   1. Downloads install.sh and lib/* from GitHub Raw
#   2. Verifies each file's SHA256 against a hardcoded manifest
#   3. Executes install.sh in the normal way
#
# Behavior is identical to the previous monolithic install.sh from the user's
# perspective. The only difference: this bootstrap is small enough to audit
# at a glance, and verifies the integrity of every downloaded artifact.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/bootstrap.sh | bash
#==============================================================================

set +e
set +u

#----- Constants --------------------------------------------------------------

EDGEBOX_BOOTSTRAP_VERSION="4.6.0-batchD"
EDGEBOX_REPO="cuiping89/node"
EDGEBOX_BRANCH="${EDGEBOX_VERSION:-main}"
EDGEBOX_BASE_URL="https://raw.githubusercontent.com/${EDGEBOX_REPO}/${EDGEBOX_BRANCH}/ENV"

# Temporary download directory (cleaned on exit)
BOOTSTRAP_TMP="$(mktemp -d -t edgebox-bootstrap.XXXXXX)"
trap 'rm -rf "$BOOTSTRAP_TMP" 2>/dev/null || true' EXIT

# Files to download. Format: "remote_path local_path sha256"
# These hashes are regenerated at every release via tools/gen-manifest.sh.
# If you change any of these files, you MUST regenerate the manifest.
EDGEBOX_FILES=(
    "install.sh|install.sh|6db3bd56dd3091027179fb1e461e984aa9805b214bc587492ab5671cfe6a395b"
    "lib/common.sh|lib/common.sh|cefa5a9731025fd826999719e2bc293f3a3eb6c594a95add837ff3a237c4b6d8"
    "lib/alert.sh|lib/alert.sh|89b6c0cf1135c909851609b26b28e0c58def566d933b5c8e422f9221b0092309"
    "lib/subscription.sh|lib/subscription.sh|59a4b549cd51ac01007d01f3bbca06f2718e24d317e0d36aece1b1591cc12f36"
    "scripts/edgeboxctl|scripts/edgeboxctl|ae4297609380632c2f9215dc183707013f34c6e48a758373019e2f7be91f7542"
    "scripts/dashboard-backend.sh|scripts/dashboard-backend.sh|fc6d9d559aa90ce7cac2305962a3da3cef390ca61193f1027ceecd2483d844bd"
    "scripts/protocol-health-monitor.sh|scripts/protocol-health-monitor.sh|85f21b25d279063d3d6f4bf064bab2ff00bd60e05fa2040a73d79a33098e1389"
    "scripts/edgebox-traffic-randomize.sh|scripts/edgebox-traffic-randomize.sh|805c41fb142277029bd7e199362ca60516a2a1d3c11ecda2491bca2e41691e0b"
    "scripts/edgebox-ipq.sh|scripts/edgebox-ipq.sh|975b62aaa71d3c546a8fb548434bc417a6ebaed05d1d46ced74988e015547cd4"
    "scripts/traffic-alert.sh|scripts/traffic-alert.sh|faab56de298ad43e19290ccdaf4143673a924080acbad6ac3f1e65e34e0d4270"
    "scripts/traffic-collector.sh|scripts/traffic-collector.sh|c84703c43dcf51b62332afec5752270b777a86fce8abfa8fbe1f4ed06a82eb10"
    "scripts/apply-firewall.sh|scripts/apply-firewall.sh|c646c200ca39d121fe89763534777ee3afb338cabe43c2bbef66c7784f8cd51c"
    "scripts/system-stats.sh|scripts/system-stats.sh|64b4f2e1aa3f7b9d293fb2a50cb21d6aed8268437df31abe92f6e68e1cd3401e"
    "scripts/edgebox-init.sh|scripts/edgebox-init.sh|4d8ac54c6aecdf7d6ee2ba8b96be6f4366cb92cccff7e5f9ead971e618feaabe"
    "web/dashboard.css|web/dashboard.css|ba51eda73867bfda7dc218f4ecbe459d4ff6b57690807daebc5452f86c03f962"
    "web/dashboard.js|web/dashboard.js|4df8eb3d142c36813170a091e4dffcecf4844339a428b117977a14a0e9ec4ee2"
    "web/dashboard.html|web/dashboard.html|ccdc08b48fd9de51952450337bd8af45d81ed8c5a58eae65ad6c2d12e96d23bd"
)

#----- Logging ----------------------------------------------------------------

_color() {
    if [[ -t 1 ]]; then
        printf '\033[%sm%s\033[0m\n' "$1" "$2"
    else
        printf '%s\n' "$2"
    fi
}
log_info()    { _color '0;36' "[BOOTSTRAP] $*"; }
log_ok()      { _color '0;32' "[BOOTSTRAP] $*"; }
log_warn()    { _color '0;33' "[BOOTSTRAP] $*" >&2; }
log_error()   { _color '0;31' "[BOOTSTRAP] $*" >&2; }

#----- Preflight --------------------------------------------------------------

_check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log_error "EdgeBox must be installed as root."
        log_error "Try: sudo bash <(curl -fsSL <url>)"
        exit 1
    fi
}

_check_tools() {
    local missing=()
    for t in curl sha256sum bash; do
        if ! command -v "$t" >/dev/null 2>&1; then
            missing+=("$t")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        log_error "Missing required tools: ${missing[*]}"
        log_error "Install them first. On Debian/Ubuntu:"
        log_error "  apt-get update && apt-get install -y curl coreutils"
        exit 1
    fi
}

_check_bash_version() {
    # Need bash 4+ for associative arrays etc.
    local major
    major=$(bash --version | head -n1 | grep -oE 'version [0-9]+' | grep -oE '[0-9]+' || echo 0)
    if [[ "$major" -lt 4 ]]; then
        log_error "Bash 4+ required, found version: $(bash --version | head -n1)"
        exit 1
    fi
}

#----- Download + Verify ------------------------------------------------------

_download_file() {
    # $1: remote_path (relative to EDGEBOX_BASE_URL)
    # $2: local_path (relative to BOOTSTRAP_TMP)
    # $3: expected sha256
    local remote="$1" local="$2" expected="$3"
    local url="${EDGEBOX_BASE_URL}/${remote}"
    local dest="${BOOTSTRAP_TMP}/${local}"

    mkdir -p "$(dirname "$dest")"

    log_info "  fetching: $remote"
    if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "$dest" "$url"; then
        log_error "Failed to download: $url"
        log_error "Check network connectivity or GitHub status."
        return 1
    fi

    # Verify size > 0
    if [[ ! -s "$dest" ]]; then
        log_error "Downloaded empty file: $remote"
        return 1
    fi

    # Verify SHA256
    local actual
    actual=$(sha256sum "$dest" | awk '{print $1}')
    if [[ "$actual" != "$expected" ]]; then
        log_error "============================================================"
        log_error "  ❌ SHA256 mismatch for $remote"
        log_error "============================================================"
        log_error ""
        log_error "  Expected: $expected"
        log_error "  Actual:   $actual"
        log_error ""
        log_error "  This could mean:"
        log_error "    1. You're using an outdated bootstrap.sh — try fetching"
        log_error "       a newer version from GitHub."
        log_error "    2. The GitHub raw content has been modified since this"
        log_error "       bootstrap was published — verify the commit history."
        log_error "    3. Your connection is being tampered with (MITM)."
        log_error ""
        log_error "  Refusing to continue installation."
        log_error "============================================================"
        return 1
    fi

    return 0
}

_download_all() {
    log_info "Downloading EdgeBox v${EDGEBOX_BOOTSTRAP_VERSION} from ${EDGEBOX_BRANCH}..."
    log_info "Source: ${EDGEBOX_BASE_URL}"
    log_info ""

    local entry remote local sha
    for entry in "${EDGEBOX_FILES[@]}"; do
        IFS='|' read -r remote local sha <<<"$entry"
        if ! _download_file "$remote" "$local" "$sha"; then
            return 1
        fi
    done

    log_ok "All files downloaded and verified."
    return 0
}

#----- Skip-verify mode -------------------------------------------------------
# For testing or when working on bleeding-edge branches, allow
# `EDGEBOX_SKIP_VERIFY=1` to download without hash check.
# Off by default; warns loudly when used.

_download_no_verify() {
    log_warn "============================================================"
    log_warn "  ⚠️  EDGEBOX_SKIP_VERIFY=1 — bypassing SHA256 verification"
    log_warn "  This is unsafe and intended only for development."
    log_warn "============================================================"
    log_info ""

    local entry remote local sha
    for entry in "${EDGEBOX_FILES[@]}"; do
        IFS='|' read -r remote local sha <<<"$entry"
        local url="${EDGEBOX_BASE_URL}/${remote}"
        local dest="${BOOTSTRAP_TMP}/${local}"
        mkdir -p "$(dirname "$dest")"
        log_info "  fetching (no-verify): $remote"
        if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "$dest" "$url"; then
            log_error "Download failed: $url"
            return 1
        fi
    done
    log_ok "All files downloaded (no integrity check)."
}

#----- Execute install.sh -----------------------------------------------------

_run_install() {
    local install_sh="${BOOTSTRAP_TMP}/install.sh"
    if [[ ! -f "$install_sh" ]]; then
        log_error "install.sh missing from download. This is a bootstrap bug."
        return 1
    fi

    # Export paths so install.sh knows where its sibling files live.
    # The current install.sh writes lib files via heredoc, so it doesn't
    # need to know about $BOOTSTRAP_TMP yet — but future batches will.
    export EDGEBOX_BOOTSTRAP_TMP="$BOOTSTRAP_TMP"
    export EDGEBOX_BOOTSTRAP_VERSION

    log_info ""
    log_info "============================================================"
    log_info " Handing off to install.sh"
    log_info "============================================================"
    log_info ""

    bash "$install_sh" "$@"
    return $?
}

#----- Main -------------------------------------------------------------------

main() {
    log_info "============================================================"
    log_info " EdgeBox Bootstrap v${EDGEBOX_BOOTSTRAP_VERSION}"
    log_info "============================================================"

    _check_root
    _check_tools
    _check_bash_version

    if [[ "${EDGEBOX_SKIP_VERIFY:-0}" == "1" ]]; then
        _download_no_verify || exit 1
    else
        _download_all || exit 1
    fi

    _run_install "$@"
    exit $?
}

main "$@"
