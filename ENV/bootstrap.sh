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

EDGEBOX_BOOTSTRAP_VERSION="4.7.0"
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
    "install.sh|install.sh|ed8ad1bb356cafcccc9ac34011f6015ba3c6831254e80f69d7932e7320b780b7"
    "lib/common.sh|lib/common.sh|dc75d1b179ec77a61a4ac6501a7a4caa4323a8772d23e804b56d330091bae95f"
    "lib/alert.sh|lib/alert.sh|d80652f40814bd4249ca24b0d5b20fe6801fc3bfd8c50616fdebedca034b5d36"
    "lib/subscription.sh|lib/subscription.sh|ce8d41497ffd97ccbc09ce70cf63eab24b69d3794376b09ad78fb708fa6e1036"
    "scripts/edgeboxctl|scripts/edgeboxctl|8b576ba74c9403a9f2caa28a049f65e985e43010e6afee7f6f714375ea980113"
    "scripts/dashboard-backend.sh|scripts/dashboard-backend.sh|4cd4bff419e9b4a28613b73ad277218a9dc6ac6517a4cbdbe2462a1df5b4597f"
    "scripts/protocol-health-monitor.sh|scripts/protocol-health-monitor.sh|13560595024e898b46e53ba4539e9bc48da38a25da6d29781432153033aac364"
    "scripts/edgebox-traffic-randomize.sh|scripts/edgebox-traffic-randomize.sh|a1440d24c81265536092b270bbbeb3f55d68fc1382e0d45216adb980430c91e2"
    "scripts/edgebox-ipq.sh|scripts/edgebox-ipq.sh|d2b8b42cac18f76ac7d5b492b2a915720a61d4575fefd5e6fca6d17d6825d84c"
    "scripts/traffic-alert.sh|scripts/traffic-alert.sh|e5c913c69c7ba5e586f72259fe528935215c8f362eb132b47dac06de83d65758"
    "scripts/traffic-collector.sh|scripts/traffic-collector.sh|639637905ff7c3e91b3ce8f99b247ae20f90df1dd9be9364943628ef294165cd"
    "scripts/apply-firewall.sh|scripts/apply-firewall.sh|bb1949c65391462a43a0e9eb678d1758ba989086a53fbc054c4c8893d65c3ac6"
    "scripts/system-stats.sh|scripts/system-stats.sh|64b4f2e1aa3f7b9d293fb2a50cb21d6aed8268437df31abe92f6e68e1cd3401e"
    "scripts/edgebox-init.sh|scripts/edgebox-init.sh|deb6576116c2bbf0cde441179f7888a9c9d4b8ce684af108ee69242737175245"
    "web/dashboard.css|web/dashboard.css|081e2fb6e59217717fa2898a33edd32f3a4fe4afeb46e2fcf4345046029d5c10"
    "web/dashboard.js|web/dashboard.js|779d306eb50a5b56ab67ab3d81b53713dc44be21ad57eeb8802d31b0ff79cfb2"
    "web/dashboard.html|web/dashboard.html|b71177df33492c0dbf09c7ee42e720e910fd04444f11534c475f036c82d4a982"
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
