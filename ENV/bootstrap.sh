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

EDGEBOX_BOOTSTRAP_VERSION="4.6.0-rc1"
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
    "install.sh|install.sh|99f301f732b9a7dcaeec2754ee6e8be2e6dfbf46fe6de8fb59c643a52dd0d1c3"
    "lib/common.sh|lib/common.sh|ff20782a9939c5ecf534ead8da669b802dc85cc1bafba9fe6a7d78c7b44152c3"
    "lib/alert.sh|lib/alert.sh|661b7119345ceba2f6ad3577049fa6d0c2e2e8f82e12a97af5201cd0ecb477bc"
    "lib/subscription.sh|lib/subscription.sh|59a4b549cd51ac01007d01f3bbca06f2718e24d317e0d36aece1b1591cc12f36"
    "scripts/edgeboxctl|scripts/edgeboxctl|6ce4ae440d6f0dce0780a4f356ba348d8e1c8b8e9d6c7563477de8c6982e3189"
    "scripts/dashboard-backend.sh|scripts/dashboard-backend.sh|d878da8d512cda459458ec31e31183d81900be8a406ece8162df31b01dee1f6e"
    "scripts/protocol-health-monitor.sh|scripts/protocol-health-monitor.sh|7d3f43308c2c21e2da45aa6d1302afcc7070bee33d4fd6dc2669a43b9a8b0e26"
    "scripts/edgebox-traffic-randomize.sh|scripts/edgebox-traffic-randomize.sh|9406440bc10afd8165ca0c78d6e15c5b108513617b777338851f06c6d9eab290"
    "scripts/edgebox-ipq.sh|scripts/edgebox-ipq.sh|975b62aaa71d3c546a8fb548434bc417a6ebaed05d1d46ced74988e015547cd4"
    "scripts/traffic-alert.sh|scripts/traffic-alert.sh|e5c913c69c7ba5e586f72259fe528935215c8f362eb132b47dac06de83d65758"
    "scripts/traffic-collector.sh|scripts/traffic-collector.sh|672877bda84f71d20da249a125aec56e7a1ba73b299d0973ac6264e935ee2b45"
    "scripts/apply-firewall.sh|scripts/apply-firewall.sh|bb1949c65391462a43a0e9eb678d1758ba989086a53fbc054c4c8893d65c3ac6"
    "scripts/system-stats.sh|scripts/system-stats.sh|64b4f2e1aa3f7b9d293fb2a50cb21d6aed8268437df31abe92f6e68e1cd3401e"
    "scripts/edgebox-init.sh|scripts/edgebox-init.sh|deb6576116c2bbf0cde441179f7888a9c9d4b8ce684af108ee69242737175245"
    "web/dashboard.css|web/dashboard.css|ba51eda73867bfda7dc218f4ecbe459d4ff6b57690807daebc5452f86c03f962"
    "web/dashboard.js|web/dashboard.js|9673e179e882874f7f19ea25f4e37ccbe9341c9565738136b0a885218ecea6f7"
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
