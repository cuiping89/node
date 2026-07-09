#!/usr/bin/env bash
# ==============================================================================
# EdgeBox Bootstrap Loader v4.7.0
#
# Downloads the release files from one GitHub ref, verifies SHA256, then runs
# install.sh. Set EDGEBOX_VERSION to a commit SHA to pin every downloaded file
# to the same immutable snapshot.
# ==============================================================================

set -o pipefail

EDGEBOX_BOOTSTRAP_VERSION="4.7.0"
EDGEBOX_REPO="cuiping89/node"
EDGEBOX_BRANCH="${EDGEBOX_VERSION:-main}"
EDGEBOX_BASE_URL="https://raw.githubusercontent.com/${EDGEBOX_REPO}/${EDGEBOX_BRANCH}/ENV"

BOOTSTRAP_TMP="$(mktemp -d -t edgebox-bootstrap.XXXXXX)" || {
  echo "[BOOTSTRAP] Failed to create temporary directory." >&2
  exit 1
}
trap 'rm -rf "$BOOTSTRAP_TMP" 2>/dev/null || true' EXIT

# Format: remote_path|local_path|sha256
EDGEBOX_FILES=(
  "install.sh|install.sh|f77b79643c884678efc42a466e9407dae25b230ee20dbfef68ea0af93213517a"
  "lib/common.sh|lib/common.sh|e30dcbf253ff058d8ed0afb99f84c263c0864b8ca437aef7125ce57adc82432d"
  "lib/alert.sh|lib/alert.sh|d80652f40814bd4249ca24b0d5b20fe6801fc3bfd8c50616fdebedca034b5d36"
  "lib/subscription.sh|lib/subscription.sh|9646a56d5bd1bf29b6f58e2e1a8a34c1c74517094ac009061b61fd7e669c5a83"
  "scripts/edgeboxctl|scripts/edgeboxctl|c7ca5d384bb617e73930ded93ba8c8b4489072b20d0c1c0f63941adc7473074f"
  "scripts/dashboard-backend.sh|scripts/dashboard-backend.sh|aaf4d6ea149ce607abc108c5755cd79caec1f5580207d97bcf71e71569b96586"
  "scripts/protocol-health-monitor.sh|scripts/protocol-health-monitor.sh|4b972c92d1cd8485cc32cf2f5406ad4c528caa41d7369ae6b6fc2f77d13b2451"
  "scripts/edgebox-traffic-randomize.sh|scripts/edgebox-traffic-randomize.sh|a1440d24c81265536092b270bbbeb3f55d68fc1382e0d45216adb980430c91e2"
  "scripts/edgebox-ipq.sh|scripts/edgebox-ipq.sh|d2b8b42cac18f76ac7d5b492b2a915720a61d4575fefd5e6fca6d17d6825d84c"
  "scripts/traffic-alert.sh|scripts/traffic-alert.sh|e5c913c69c7ba5e586f72259fe528935215c8f362eb132b47dac06de83d65758"
  "scripts/traffic-collector.sh|scripts/traffic-collector.sh|0de953573e69578a9ab2fd48dd6ba4cc94cb2f9c40e0b4854691040015e009cd"
  "scripts/apply-firewall.sh|scripts/apply-firewall.sh|f36170b7e5e8caf727d5c83198391ca1db23b654b34999443facafc4bbed29b9"
  "scripts/edgebox-init.sh|scripts/edgebox-init.sh|deb6576116c2bbf0cde441179f7888a9c9d4b8ce684af108ee69242737175245"
  "web/dashboard.css|web/dashboard.css|081e2fb6e59217717fa2898a33edd32f3a4fe4afeb46e2fcf4345046029d5c10"
  "web/dashboard.js|web/dashboard.js|c532e3f387ac891283f0dd199ce24bdb09330242047b72b836ea9be4ba0a0d74"
  "web/dashboard.html|web/dashboard.html|4d1a999e57a21b72de5a0d61b094658afdfadc98a9edaebe97cc1c97892a8ca8"
)

_color() {
  local code="$1" text="$2"
  if [[ -t 1 ]]; then
    printf '\033[%sm%s\033[0m\n' "$code" "$text"
  else
    printf '%s\n' "$text"
  fi
}
log_info()  { _color '0;36' "[BOOTSTRAP] $*"; }
log_ok()    { _color '0;32' "[BOOTSTRAP] $*"; }
log_warn()  { _color '0;33' "[BOOTSTRAP] $*" >&2; }
log_error() { _color '0;31' "[BOOTSTRAP] $*" >&2; }

_require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    log_error "EdgeBox must be installed as root."
    log_error "Run this Termius snippet as root, or prefix it with sudo."
    exit 1
  fi
}

_require_tools() {
  local tool missing=()
  for tool in curl sha256sum bash awk mktemp; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if (( ${#missing[@]} )); then
    log_error "Missing required tools: ${missing[*]}"
    log_error "Debian/Ubuntu: apt-get update && apt-get install -y curl coreutils gawk"
    exit 1
  fi
}

_download_one() {
  local remote="$1" local_path="$2" expected="$3"
  local url="${EDGEBOX_BASE_URL}/${remote}"
  local dest="${BOOTSTRAP_TMP}/${local_path}"
  local actual

  mkdir -p "$(dirname "$dest")"
  log_info "  fetching: ${remote}"

  if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "$dest" "$url"; then
    log_error "Failed to download: $url"
    return 1
  fi

  if [[ ! -s "$dest" ]]; then
    log_error "Downloaded file is empty: $remote"
    return 1
  fi

  actual="$(sha256sum "$dest" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    log_error "============================================================"
    log_error "  SHA256 mismatch for ${remote}"
    log_error "============================================================"
    log_error "  Expected: ${expected}"
    log_error "  Actual:   ${actual}"
    log_error ""
    log_error "The GitHub files and ENV/bootstrap.sh are not from the same release snapshot."
    log_error "Regenerate the manifest after every source change, then commit both together."
    log_error "Refusing to continue installation."
    return 1
  fi
}

_download_all() {
  local entry remote local_path sha

  log_info "============================================================"
  log_info " EdgeBox Bootstrap v${EDGEBOX_BOOTSTRAP_VERSION}"
  log_info "============================================================"
  log_info "Downloading EdgeBox v${EDGEBOX_BOOTSTRAP_VERSION} from ${EDGEBOX_BRANCH}..."
  log_info "Source: ${EDGEBOX_BASE_URL}"
  log_info ""

  for entry in "${EDGEBOX_FILES[@]}"; do
    IFS='|' read -r remote local_path sha <<< "$entry"
    _download_one "$remote" "$local_path" "$sha" || return 1
  done

  log_ok "All ${#EDGEBOX_FILES[@]} files downloaded and verified."
}

_run_install() {
  local install_sh="${BOOTSTRAP_TMP}/install.sh"

  [[ -f "$install_sh" ]] || {
    log_error "install.sh is missing after download."
    return 1
  }

  chmod +x "$install_sh"
  export EDGEBOX_BOOTSTRAP_TMP="$BOOTSTRAP_TMP"
  export EDGEBOX_BOOTSTRAP_VERSION

  log_info ""
  log_info "============================================================"
  log_info " Handing off to install.sh"
  log_info "============================================================"
  log_info ""

  bash "$install_sh" "$@"
}

main() {
  _require_root
  _require_tools
  _download_all || exit 1
  _run_install "$@"
}

main "$@"
