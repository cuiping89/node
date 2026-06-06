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
    "install.sh|install.sh|dfd901131516feef8e36884f4e4a9ddfe347de7752a5c56a78a98f84d3e7ab8b"
    "lib/common.sh|lib/common.sh|dc75d1b179ec77a61a4ac6501a7a4caa4323a8772d23e804b56d330091bae95f"
    "lib/alert.sh|lib/alert.sh|d80652f40814bd4249ca24b0d5b20fe6801fc3bfd8c50616fdebedca034b5d36"
    "lib/subscription.sh|lib/subscription.sh|4491fff550d5585e4d3fd7e4ad34892b775e172d4ec3231a0da6522f5772d882"
    "scripts/edgeboxctl|scripts/edgeboxctl|1b5d834acbaad7a2c333a50e682316807875bec8721cd93e78d85a481e28c80b"
    "scripts/dashboard-backend.sh|scripts/dashboard-backend.sh|6a0b00f6edec0827d618e9d9cbcc865e7f5200c1cccfc96987cabcca4a62dcab"
    "scripts/protocol-health-monitor.sh|scripts/protocol-health-monitor.sh|4b972c92d1cd8485cc32cf2f5406ad4c528caa41d7369ae6b6fc2f77d13b2451"
    "scripts/edgebox-traffic-randomize.sh|scripts/edgebox-traffic-randomize.sh|a1440d24c81265536092b270bbbeb3f55d68fc1382e0d45216adb980430c91e2"
    "scripts/edgebox-ipq.sh|scripts/edgebox-ipq.sh|d2b8b42cac18f76ac7d5b492b2a915720a61d4575fefd5e6fca6d17d6825d84c"
    "scripts/traffic-alert.sh|scripts/traffic-alert.sh|e5c913c69c7ba5e586f72259fe528935215c8f362eb132b47dac06de83d65758"
    "scripts/traffic-collector.sh|scripts/traffic-collector.sh|639637905ff7c3e91b3ce8f99b247ae20f90df1dd9be9364943628ef294165cd"
    "scripts/apply-firewall.sh|scripts/apply-firewall.sh|bb1949c65391462a43a0e9eb678d1758ba989086a53fbc054c4c8893d65c3ac6"
    "scripts/edgebox-init.sh|scripts/edgebox-init.sh|deb6576116c2bbf0cde441179f7888a9c9d4b8ce684af108ee69242737175245"
    "web/dashboard.css|web/dashboard.css|081e2fb6e59217717fa2898a33edd32f3a4fe4afeb46e2fcf4345046029d5c10"
    "web/dashboard.js|web/dashboard.js|c532e3f387ac891283f0dd199ce24bdb09330242047b72b836ea9be4ba0a0d74"
    "web/dashboard.html|web/dashboard.html|6a48997bf6216363c8446ef841fc8d2b174c42301fa01b6fccf0dad56e3b4ba7"
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
        # v4.7.0: 自动 sudo 提权。原先只是提示 "Try: sudo bash <(curl ...)"，
        # 但那个建议本身在 sudo 下会失败 —— <(...) 的 /dev/fd/N 属于调用者的进程，
        # sudo 切换到 root 后该 fd 不存在 → "bash: /dev/fd/63: No such file or directory"。
        # 改为：把本脚本(无论来源:管道/<(...))写入 tmp，然后 exec sudo bash <tmp>，可靠提升权限。
        local _eb_self
        _eb_self="$(mktemp /tmp/edgebox-bootstrap.XXXXXX.sh)" || {
            log_error "无法创建临时文件用于 sudo 提权"
            exit 1
        }
        # shellcheck disable=SC2128
        cat "${BASH_SOURCE:-/dev/stdin}" > "$_eb_self" 2>/dev/null || cat > "$_eb_self"
        chmod +x "$_eb_self"
        if command -v sudo >/dev/null 2>&1; then
            log_info "需要 root 权限，正在通过 sudo 提权…"
            exec sudo -E bash "$_eb_self" "$@"
        else
            log_error "EdgeBox 需要 root 权限运行。"
            log_error "请改用以下任一方式："
            log_error "  curl -fsSL <url> | sudo bash"
            log_error "  sudo -i ; bash <(curl -fsSL <url>)"
            rm -f "$_eb_self"
            exit 1
        fi
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

    _check_root "$@"
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
