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
    "install.sh|install.sh|a15af3ee6b28d1b5e3e3e1e2f18361ce45fa1053aaff5e3def1a358ee4503dac"
    "lib/common.sh|lib/common.sh|1ae6fd375080ed210f693282859610ec0a2ce3de188fa76c5c1a708ae2a9a4b6"
    "lib/alert.sh|lib/alert.sh|d80652f40814bd4249ca24b0d5b20fe6801fc3bfd8c50616fdebedca034b5d36"
    "lib/subscription.sh|lib/subscription.sh|9646a56d5bd1bf29b6f58e2e1a8a34c1c74517094ac009061b61fd7e669c5a83"
    "scripts/edgeboxctl|scripts/edgeboxctl|b24bf5b86dde8cf63cea973d825e99dcd21cfdf09c58f8388d3720933d582a75"
    "scripts/dashboard-backend.sh|scripts/dashboard-backend.sh|d37f93dec71a9f37cbd1e679280eafd8be7da163e22a7c8a92b8c34d3bace156"
    "scripts/protocol-health-monitor.sh|scripts/protocol-health-monitor.sh|4b972c92d1cd8485cc32cf2f5406ad4c528caa41d7369ae6b6fc2f77d13b2451"
    "scripts/edgebox-traffic-randomize.sh|scripts/edgebox-traffic-randomize.sh|a1440d24c81265536092b270bbbeb3f55d68fc1382e0d45216adb980430c91e2"
    "scripts/edgebox-ipq.sh|scripts/edgebox-ipq.sh|d2b8b42cac18f76ac7d5b492b2a915720a61d4575fefd5e6fca6d17d6825d84c"
    "scripts/traffic-alert.sh|scripts/traffic-alert.sh|e5c913c69c7ba5e586f72259fe528935215c8f362eb132b47dac06de83d65758"
    "scripts/traffic-collector.sh|scripts/traffic-collector.sh|0de953573e69578a9ab2fd48dd6ba4cc94cb2f9c40e0b4854691040015e009cd"
    "scripts/apply-firewall.sh|scripts/apply-firewall.sh|f36170b7e5e8caf727d5c83198391ca1db23b654b34999443facafc4bbed29b9"
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
        # v4.7.0 (修复): 上一版本对所有非 root 场景都 `cat $BASH_SOURCE > tmp` 然后 sudo bash tmp，
        # 但当通过 `curl | bash` 或 `bash <(curl ...)` 调用时，脚本来源是 STDIN/管道 fd，
        # bash 已经读过的部分无法再回放 → tmp 文件为空 → sudo bash <空> 立即静默退出。
        # 现改为：判断"是否能再执行自己"，否则就 re-fetch bootstrap.sh 走 sudo+curl 重跑。
        if ! command -v sudo >/dev/null 2>&1; then
            log_error "EdgeBox 必须以 root 权限运行，但 sudo 不可用。"
            log_error "请以 root 重试，例如先：sudo -i  然后再跑同样的安装命令。"
            exit 1
        fi

        local _self="${BASH_SOURCE[0]:-$0}"
        # 真实磁盘文件 → 可以直接 sudo exec 自己
        if [[ -n "$_self" && -f "$_self" && -r "$_self" \
              && "$_self" != /dev/fd/* && "$_self" != /proc/self/fd/* \
              && "$_self" != bash && "$_self" != -bash && "$_self" != /bin/bash ]]; then
            log_info "需要 root 权限，正在通过 sudo 提权…"
            exec sudo -E bash "$_self" "$@"
        fi

        # 管道 / 进程替换调用：源已被 bash 部分消费，无法本地复制；
        # 用 sudo + curl 直接从仓库 refetch bootstrap.sh，以 root 重跑一次。
        log_info "需要 root 权限，通过 sudo + curl refetch 重跑（管道调用模式）…"
        exec sudo -E bash -c "curl -fsSL '${EDGEBOX_BASE_URL}/bootstrap.sh' | bash"
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

#----- Commit pinning (avoids raw CDN per-file cache lag) ---------------------
# raw.githubusercontent.com caches each file path independently (~分钟级 TTL)。
# 推送后立即安装时，刚改动的那个文件可能还在提供旧缓存，而 bootstrap.sh 的清单已是新的
# → 出现 SHA256 不匹配（其实仓库是对的，只是 CDN 没传播完）。
# 解决：解析 main 的最新 commit SHA，把"本 bootstrap + 全部文件"都改用 /<sha>/ 这种
# 按提交固定、不可变的 URL 拉取 —— 同一提交快照内部一致，不存在"还在提供旧版本"的窗口。
# 失败（API 限流 / 网络不可达 / 显式指定了 EDGEBOX_VERSION）时优雅回退到分支 ref（原行为）。
_pin_to_commit() {
    [[ -n "${EDGEBOX_PINNED:-}" ]] && return 0    # 已是被固定后的二次运行（防无限递归）
    [[ -n "${EDGEBOX_VERSION:-}" ]] && return 0    # 用户显式指定了 ref（含 SHA），尊重之
    command -v curl >/dev/null 2>&1 || return 0

    local sha
    sha="$(curl -fsSL --connect-timeout 10 --max-time 20 \
            -H 'Accept: application/vnd.github.sha' \
            "https://api.github.com/repos/${EDGEBOX_REPO}/commits/${EDGEBOX_BRANCH}" 2>/dev/null \
            | tr -d '[:space:]' | grep -oE '^[0-9a-f]{40}$')"
    if [[ -z "$sha" ]]; then
        log_warn "无法解析最新 commit SHA（API 限流/网络）；回退到 '${EDGEBOX_BRANCH}'（可能遇 CDN 缓存延迟）"
        return 0
    fi
    log_info "锁定到 commit ${sha:0:7}（按提交快照拉取，规避 raw CDN 缓存延迟）"

    local pinned_bs
    pinned_bs="$(curl -fsSL --connect-timeout 10 --max-time 60 \
                 "https://raw.githubusercontent.com/${EDGEBOX_REPO}/${sha}/ENV/bootstrap.sh" 2>/dev/null)"
    if [[ -z "$pinned_bs" ]]; then
        log_warn "无法获取该提交的 bootstrap.sh；回退到 '${EDGEBOX_BRANCH}'"
        return 0
    fi
    # 重跑"该提交的 bootstrap"，使其清单与它校验的文件取自同一快照。
    exec env EDGEBOX_PINNED=1 EDGEBOX_VERSION="$sha" bash -c "$pinned_bs" _ "$@"
}

#----- Main -------------------------------------------------------------------

main() {
    _pin_to_commit "$@"

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
