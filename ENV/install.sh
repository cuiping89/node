#!/bin/bash

#############################################
# EdgeBox 企业级多协议节点部署脚本 v4.7.0
# 模块1：脚本头部+基础函数
#
# 功能说明：
# - 自动提权到root
# - 全局变量定义
# - 日志和工具函数
# - 系统兼容性检查
# - 依赖包安装
# - 基础环境配置
#############################################

# --- 自动提权到root (兼容 bash <(curl ...)) ---
if [[ $EUID -ne 0 ]]; then
  # 把当前脚本内容拷到临时文件，再以 root 重启执行（兼容 /dev/fd/63）
  _EB_TMP="$(mktemp)"
  # shellcheck disable=SC2128
  cat "${BASH_SOURCE:-/proc/self/fd/0}" > "$_EB_TMP"
  chmod +x "$_EB_TMP"

  if command -v sudo >/dev/null 2>&1; then
    # -E preserves env vars (EDGEBOX_FORCE, EDGEBOX_VERSION, EDGEBOX_CHANNEL, EDGEBOX_REPO)
    exec sudo -E EB_TMP="$_EB_TMP" bash "$_EB_TMP" "$@"
  else
    # su doesn't preserve env automatically; pass key vars explicitly
    exec su - root -c "EDGEBOX_FORCE='${EDGEBOX_FORCE:-}' EDGEBOX_VERSION='${EDGEBOX_VERSION:-}' EDGEBOX_CHANNEL='${EDGEBOX_CHANNEL:-}' EDGEBOX_REPO='${EDGEBOX_REPO:-}' EB_TMP='$_EB_TMP' bash '$_EB_TMP' $*"
  fi
fi


#############################################
# 全局配置 - 脚本基础信息
#############################################

# v4.0.0: Removed 'set -e' from the main install body.
#
# Why: This 17000-line script inherits patterns from v3 with hundreds of
# '[[ -n "$var" ]] && do_something' lines. When the test is false (which is
# the NORMAL "skip this optional step" branch in many cases), 'set -e' would
# terminate the script with a misleading "exit code 1" error.
#
# Replacement strategy:
# - Rely on explicit checks: 'cmd || return 1', 'cmd || { log_error...; exit 1; }'
#   which are already present throughout the script.
# - The 'cleanup_all' EXIT trap (installed by main()) still verifies that
#   nginx/xray/sing-box are all running at script end.
# - For debug mode, set EDGEBOX_DEBUG=1 to get xtrace.
set +e
set +u  # Don't require all variables to be declared (many lazy references)
set -o pipefail 2>/dev/null || true  # but DO catch broken pipes

# Optional debug mode
if [[ "${EDGEBOX_DEBUG:-0}" == "1" ]]; then
    set -x
fi

# 版本号
EDGEBOX_VER="4.7.0"

#############################################
# v4.0.0 Bootstrap: download lib modules from GitHub
# This block must execute BEFORE any subscription/credential logic.
#############################################

EDGEBOX_CHANNEL="${EDGEBOX_CHANNEL:-stable}"
EDGEBOX_VERSION="${EDGEBOX_VERSION:-main}"
EDGEBOX_REPO="${EDGEBOX_REPO:-cuiping89/node}"

case "$EDGEBOX_CHANNEL" in
    stable) _EB_REPO_REF="$EDGEBOX_VERSION" ;;
    dev)    _EB_REPO_REF="main"
            echo "[WARN] Using dev channel (main branch) - not for production" >&2 ;;
    *)      echo "[FATAL] Unknown EDGEBOX_CHANNEL: $EDGEBOX_CHANNEL" >&2; exit 1 ;;
esac

_EB_REPO_RAW="https://raw.githubusercontent.com/${EDGEBOX_REPO}/${_EB_REPO_REF}/ENV"

# If lib/ exists next to install.sh (local dev), use it; else download from GitHub
if [[ -d "$(dirname "${BASH_SOURCE[0]}")/lib" ]]; then
    EB_BOOTSTRAP_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/lib" && pwd)"
else
    EB_BOOTSTRAP_TMP=$(mktemp -d -t edgebox-bootstrap-XXXXXX)
    trap '[[ -n "${EB_BOOTSTRAP_TMP:-}" ]] && rm -rf "$EB_BOOTSTRAP_TMP"' EXIT
    mkdir -p "${EB_BOOTSTRAP_TMP}/lib"

    for _f in common.sh subscription.sh alert.sh; do
        if ! curl -fsSL "${_EB_REPO_RAW}/lib/${_f}" -o "${EB_BOOTSTRAP_TMP}/lib/${_f}"; then
            echo "[FATAL] Failed to download lib/${_f} from ${_EB_REPO_RAW}" >&2
            echo "[HINT] Check that EDGEBOX_VERSION='${EDGEBOX_VERSION}' exists in the repo." >&2
            exit 1
        fi
    done

    EB_BOOTSTRAP_LIB_DIR="${EB_BOOTSTRAP_TMP}/lib"
fi

# Source common.sh and subscription.sh
if [[ -f "${EB_BOOTSTRAP_LIB_DIR}/common.sh" ]]; then
    # shellcheck source=lib/common.sh
    source "${EB_BOOTSTRAP_LIB_DIR}/common.sh"
else
    echo "[FATAL] lib/common.sh not found at ${EB_BOOTSTRAP_LIB_DIR}" >&2
    exit 1
fi

if [[ -f "${EB_BOOTSTRAP_LIB_DIR}/subscription.sh" ]]; then
    # shellcheck source=lib/subscription.sh
    source "${EB_BOOTSTRAP_LIB_DIR}/subscription.sh"
else
    echo "[FATAL] lib/subscription.sh not found at ${EB_BOOTSTRAP_LIB_DIR}" >&2
    exit 1
fi


# 颜色定义（用于日志美化）
ESC=$'\033'
BLUE="${ESC}[0;34m"
PURPLE="${ESC}[0;35m"
CYAN="${ESC}[0;36m"
YELLOW="${ESC}[1;33m"
GREEN="${ESC}[0;32m"
RED="${ESC}[0;31m"
NC="${ESC}[0m"  # No Color


#############################################
# 下载加速配置（可通过环境变量自定义）
#############################################

# 主下载代理（用于GitHub Releases等二进制文件）
# 使用方式: export EDGEBOX_DOWNLOAD_PROXY="https://my-mirror.com/" bash install.sh
EDGEBOX_DOWNLOAD_PROXY="${EDGEBOX_DOWNLOAD_PROXY:-}"

# GitHub文件加速镜像（用于raw.githubusercontent.com等脚本文件）
EDGEBOX_GITHUB_MIRROR="${EDGEBOX_GITHUB_MIRROR:-}"

# 预定义的下载镜像源列表（按优先级排序，移除问题镜像）
declare -a DEFAULT_DOWNLOAD_MIRRORS=(
    ""  # 直连（第一优先）
    "https://ghp.ci/"  # 稳定的镜像源
    "https://github.moeyy.xyz/"  # 备用镜像
)

# 预定义的GitHub脚本镜像列表
declare -a DEFAULT_GITHUB_MIRRORS=(
    ""  # 直连
    "https://ghp.ci/"
    "https://raw.gitmirror.com/"
)

# 如果用户指定了代理，将其插入到列表最前面
if [[ -n "$EDGEBOX_DOWNLOAD_PROXY" ]]; then
    DEFAULT_DOWNLOAD_MIRRORS=("$EDGEBOX_DOWNLOAD_PROXY" "${DEFAULT_DOWNLOAD_MIRRORS[@]}")
    log_info "使用用户指定的下载代理: $EDGEBOX_DOWNLOAD_PROXY"
fi

if [[ -n "$EDGEBOX_GITHUB_MIRROR" ]]; then
    DEFAULT_GITHUB_MIRRORS=("$EDGEBOX_GITHUB_MIRROR" "${DEFAULT_GITHUB_MIRRORS[@]}")
    log_info "使用用户指定的GitHub镜像: $EDGEBOX_GITHUB_MIRROR"
fi


#############################################
# 统一路径和常量管理
#############################################

# === 核心目录结构 ===
INSTALL_DIR="/etc/edgebox"
CERT_DIR="${INSTALL_DIR}/cert"
CONFIG_DIR="${INSTALL_DIR}/config"
TRAFFIC_DIR="${INSTALL_DIR}/traffic"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"
BACKUP_DIR="/root/edgebox-backup"

# === 日志文件路径 ===
LOG_FILE="/var/log/edgebox-install.log"
XRAY_LOG="/var/log/xray/access.log"
SINGBOX_LOG="/var/log/edgebox/sing-box.log"
NGINX_ACCESS_LOG="/var/log/nginx/access.log"
NGINX_ERROR_LOG="/var/log/nginx/error.log"

# === Web相关路径 ===
WEB_ROOT="/var/www/html"
NGINX_CONF="/etc/nginx/nginx.conf"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"

# === 可执行文件路径 ===
XRAY_BIN="/usr/local/bin/xray"
SINGBOX_BIN="/usr/local/bin/sing-box"
EDGEBOXCTL_BIN="/usr/local/bin/edgeboxctl"

# === 配置文件路径 ===
SERVER_CONFIG="${CONFIG_DIR}/server.json"
XRAY_CONFIG="${CONFIG_DIR}/xray.json"
SINGBOX_CONFIG="${CONFIG_DIR}/sing-box.json"
SUBSCRIPTION_FILE="${WEB_ROOT}/subscription.txt"

# === 证书相关路径 ===
CERT_CRT="${CERT_DIR}/current.pem"
CERT_KEY="${CERT_DIR}/current.key"
CERT_CSR="${CERT_DIR}/current.csr"

# === 系统服务文件路径 ===
XRAY_SERVICE="/etc/systemd/system/xray.service"
SINGBOX_SERVICE="/etc/systemd/system/sing-box.service"
NGINX_SERVICE="/etc/systemd/system/nginx.service"

# === 用户和组常量 ===
WEB_USER="www-data"
XRAY_USER="nobody"
SINGBOX_USER="root"

# === 网络常量 ===
DEFAULT_PORTS=(80 443)
REALITY_SNI="www.microsoft.com"
HYSTERIA2_MASQUERADE="https://www.bing.com"

# === 版本和下载常量 ===
# v4.6.0-rc4: 兼容性锁定版本 1.12.8 (审核 P2)
# 原因: 当前生成的客户端 sing-box 配置仍使用 1.13.0 之前的 schema:
#   - { "type": "block", "tag": "block" }
#   - { "type": "dns", "tag": "dns-out" }
# 上述特殊 outbound 已在 sing-box 1.13.0 移除（官方稳定版当前为 1.13.x）
# 直接升级会导致客户端配置加载失败。后续迁移 schema 后再放开升级。
DEFAULT_SING_BOX_VERSION="1.12.8"
XRAY_INSTALL_SCRIPT="https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"

# === 临时文件常量 ===
TMP_DIR="/tmp/edgebox"
LOCK_FILE="/var/lock/edgebox-install.lock"

# === SNI域名池管理相关路径 ===
SNI_CONFIG_DIR="${CONFIG_DIR}/sni"
SNI_DOMAINS_CONFIG="${SNI_CONFIG_DIR}/domains.json"
SNI_LOG_FILE="/var/log/edgebox/sni-management.log"
SNI_LOCK_FILE="/etc/edgebox/sni.lock"
# SNI域名池配置
SNI_DOMAIN_POOL=(
    "www.microsoft.com"      # 权重: 25 (稳定性高)
    "www.apple.com"          # 权重: 20 (全球覆盖)
    "www.cloudflare.com"     # 权重: 20 (网络友好)
    "azure.microsoft.com"    # 权重: 15 (企业级)
    "aws.amazon.com"         # 权重: 10 (备用)
    "www.fastly.com"         # 权重: 10 (CDN特性)
)

# === 控制面板访问密码 ===
DASHBOARD_PASSCODE=""      # 6位随机相同数字

# === 反向 SSH 隧道 ===
: "${EB_RSSH_USER:=}"        # 留空交给自动探测或 env 文件
: "${EB_RSSH_HOST:=}"        # 同上
: "${EB_RSSH_PORT:=}"        # 同上
: "${EB_RSSH_RPORT:=}"       # 同上
: "${EB_RSSH_KEY_PATH:=}"    # 同上

#############################################
# 路径验证和创建函数
#############################################

# 验证关键路径
#############################################
# 函数：validate_paths
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-VALIDATE_PATHS]
#############################################
validate_paths() {
    log_info "验证关键路径..."

    # 检查可写性
    local writable_paths=(
        "$INSTALL_DIR" "$CONFIG_DIR" "$CERT_DIR"
        "$WEB_ROOT" "$(dirname "$LOG_FILE")"
    )

    for path in "${writable_paths[@]}"; do
        if [[ ! -w "$path" ]]; then
            log_error "路径不可写: $path"
            return 1
        fi
    done

    log_success "路径验证通过"
    return 0
}


#############################################
# 服务器信息变量（待收集）
#############################################

# 网络信息
SERVER_IP=""            # 服务器公网IP
SERVER_DOMAIN=""        # 域名（如果有）
INSTALL_MODE="ip"       # 默认IP模式

# 系统信息（模块2中收集）
CLOUD_PROVIDER=""       # 云厂商
CLOUD_REGION=""         # 区域
INSTANCE_ID=""          # 实例ID
HOSTNAME=""             # 主机名
CPU_SPEC=""             # CPU规格
MEMORY_SPEC=""          # 内存规格
DISK_SPEC=""            # 磁盘规格

#############################################
# 协议凭据变量（模块2中生成）
#############################################

# UUID集合 (v4.7.0: only Reality)
UUID_VLESS_REALITY=""

# Reality密钥对
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
REALITY_SHORT_ID=""

# 密码集合 (v4.7.0: only Hysteria2)
PASSWORD_HYSTERIA2=""

#############################################
# 端口配置（单端口复用架构）
#############################################

# 对外端口
PORT_HYSTERIA2=443      # UDP Hysteria2
# TCP 443 由Nginx代理分发

# 内部回环端口
PORT_REALITY=11443      # Xray Reality
# v4.7.0: PORT_GRPC / PORT_WS / PORT_TROJAN removed (gRPC, WS, Trojan deprecated)

#############################################
# 日志函数 - 统一的日志输出
#############################################

# 信息日志（绿色）
#############################################
# 函数：log_info
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-LOG_INFO]
#############################################
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a ${LOG_FILE}
}

# 警告日志（黄色）
#############################################
# 函数：log_warn
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-LOG_WARN]
#############################################
log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a ${LOG_FILE}
}

# 错误日志（红色）
#############################################
# 函数：log_error
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-LOG_ERROR]
#############################################
log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a ${LOG_FILE}
}

# 成功日志（绿色加粗）
#############################################
# 函数：log_success
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-LOG_SUCCESS]
#############################################
log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a ${LOG_FILE}
}

# 调试日志（红色，用于开发调试）
#############################################
# 函数：log_debug
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-LOG_DEBUG]
#############################################
log_debug() {
    echo -e "${RED}[DEBUG]${NC} $1" | tee -a ${LOG_FILE}
}

# v4.5.0 (block 6 batch B1): install script from bootstrap or fallback to GitHub.
# v4.6.0-rc4 (block 7): generalized to support web/ files too.
# Usage: _install_script <target_path> <basename> [<subdir>] [<mode>]
#   subdir: "scripts" (default) or "web" - where to look in bootstrap tmp
#   mode:   "exec" (default, chmod +x) or "data" (no chmod, for HTML/CSS/JS)
# Returns non-zero on failure.
_install_script() {
    local target="$1"
    local basename="$2"
    local subdir="${3:-scripts}"
    local mode="${4:-exec}"

    if [[ -z "$target" || -z "$basename" ]]; then
        log_error "_install_script: missing argument"
        return 1
    fi

    local target_dir
    target_dir="$(dirname "$target")"
    mkdir -p "$target_dir"

    # v4.6.0-rc4 (hotfix 自覆盖竞态):
    #   先写到目标同目录的临时文件, 再用 mv (rename(2)) 原子替换目标。
    #   旧实现用 cp/curl 直接覆盖目标 (O_TRUNC, inode 不变)。当被安装的脚本
    #   恰好是当前正在运行的脚本时 (edgeboxctl upgrade 重装自身),
    #   运行中的 bash 仍持有该 inode 的 fd 并按字节偏移继续读取, 覆盖后会读到
    #   新文件的错位内容, 触发 "syntax error near unexpected token \`;;'" 之类报错。
    #   mv 替换的是目录项并产生新 inode, 旧进程的 fd 仍指向旧 inode (已打开即不回收),
    #   直到进程退出 —— 竞态彻底消除。临时文件必须与目标同一文件系统, mv 才是原子 rename。
    local tmp
    tmp="$(mktemp "${target_dir}/.${basename}.XXXXXX")" || {
        log_error "_install_script: mktemp 失败 (目录: $target_dir)"
        return 1
    }

    if [[ -n "${EDGEBOX_BOOTSTRAP_TMP:-}" && -f "${EDGEBOX_BOOTSTRAP_TMP}/${subdir}/${basename}" ]]; then
        if ! cp -f "${EDGEBOX_BOOTSTRAP_TMP}/${subdir}/${basename}" "$tmp"; then
            log_error "Failed to copy bootstrap ${subdir} file: $basename -> $target"
            rm -f "$tmp"
            return 1
        fi
    else
        local url="https://raw.githubusercontent.com/cuiping89/node/main/ENV/${subdir}/${basename}"
        log_info "Bootstrap not detected, downloading $basename from GitHub..."
        if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "$tmp" "$url"; then
            log_error "Failed to download $basename from $url"
            log_error "Consider using: curl -fsSL <bootstrap.sh URL> | bash"
            rm -f "$tmp"
            return 1
        fi
    fi

    if [[ "$mode" == "exec" ]]; then
        chmod 755 "$tmp"
    else
        chmod 644 "$tmp"
    fi

    # 原子替换 (同一文件系统下 mv = rename(2))
    if ! mv -f "$tmp" "$target"; then
        log_error "_install_script: 原子替换失败 ($tmp -> $target)"
        rm -f "$tmp"
        return 1
    fi
    return 0
}

# 分隔线（蓝色）
#############################################
# 函数：print_separator
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-PRINT_SEPARATOR]
#############################################
print_separator() {
    echo -e "${BLUE}========================================${NC}"
}

# 兼容别名（保持与原脚本兼容）
log() { log_info "$@"; }
log_ok() { log_success "$@"; }
error() { log_error "$@"; }

#############################################
# 基础工具函数
#############################################

# 检查root权限
#############################################
# 函数：check_root
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CHECK_ROOT]
#############################################
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以root权限运行"
        exit 1
    fi
    log_success "Root权限检查通过"
}

# 检查系统兼容性
#############################################
# 函数：check_system
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CHECK_SYSTEM]
#############################################
check_system() {
    log_info "检查系统兼容性..."

    # 读取系统信息
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "无法确定操作系统类型"
        exit 1
    fi

    # v4.6.0-rc4 (审核 P2): 收窄到 Debian/Ubuntu 仅
    # 原因: 代码硬编码 www-data, /etc/nginx/modules-enabled/, dpkg 等 Debian-系特定路径
    # RHEL/Rocky/AlmaLinux 实际跑不起来。诚实地拒绝总比装到一半失败强。
    SUPPORTED=false

    case "$OS" in
        ubuntu)
            MAJOR_VERSION=$(echo "$VERSION" | cut -d. -f1)
            if [ "$MAJOR_VERSION" -ge 20 ] 2>/dev/null; then
                SUPPORTED=true
            fi
            ;;
        debian)
            if [ "$VERSION" -ge 11 ] 2>/dev/null; then
                SUPPORTED=true
            fi
            ;;
        *)
            SUPPORTED=false
            ;;
    esac

    # 输出检查结果
    if [ "$SUPPORTED" = "true" ]; then
        log_success "系统检查通过: $OS $VERSION"
    else
        log_error "================================================================"
        log_error "  不支持的系统: $OS $VERSION"
        log_error "================================================================"
        log_error ""
        log_error "  EdgeBox v4.7.0 仅支持："
        log_error "    • Ubuntu 20.04 LTS 及以上"
        log_error "    • Debian 11 (bullseye) 及以上"
        log_error ""
        log_error "  v4.5 及以前曾支持 CentOS/RHEL/Rocky/AlmaLinux，但代码硬编码 "
        log_error "  www-data 用户、dpkg 命令、/etc/nginx/modules-enabled/ 等 Debian-系"
        log_error "  路径，RHEL-系无法可靠工作。诚实地拒绝总比装到一半失败强。"
        log_error ""
        log_error "================================================================"
        exit 1
    fi
}

# 获取服务器公网IP
#############################################
# 函数：get_server_ip
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GET_SERVER_IP]
#############################################
get_server_ip() {
  log_info "获取服务器公网IP(优先外部服务，避开代理)..."

  # --- A. 外部服务优先 ---
  local IP_SERVICES=(
      "https://api.ipify.org"
      "https://icanhazip.com"
      "https://checkip.amazonaws.com"
      "https://api.ip.sb/ip"
      "https://ifconfig.me/ip"
      "https://ipecho.net/plain"
  )
  for service in "${IP_SERVICES[@]}"; do
      SERVER_IP=$(env -u ALL_PROXY -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u all_proxy \
                  curl -s --max-time 5 "$service" 2>/dev/null \
                  | grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -n1)
      if [[ -n "$SERVER_IP" ]]; then
          log_success "通过外部服务获取到服务器公网IP: $SERVER_IP"
          return 0
      fi
  done

  # --- B. 兜底方案: 本机路由 ---
  local route_ip=""
  route_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){ if($i=="src"){print $(i+1); exit}}}')
  if [[ -n "$route_ip" && "$route_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$route_ip" != "127.0.0.1" && ! "$route_ip" =~ ^10\. && ! "$route_ip" =~ ^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\. ]]; then
      SERVER_IP="$route_ip"
      log_success "通过路由获取到公网IP: $SERVER_IP"
      return 0
  fi

  log_error "无法获取公网IP，请检查网络"
  return 1
}

#############################################
# 反向 SSH 救生索
#############################################

#############################################
# 函数：auto_detect_reverse_ssh_params
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-AUTO_DETECT_REVERSE_SSH_PARAMS]
#############################################
auto_detect_reverse_ssh_params() {
  # 0) 尝试从历史 env 文件加载
  if [[ -z "${EB_RSSH_HOST}" || -z "${EB_RSSH_USER}" || -z "${EB_RSSH_RPORT}" ]]; then
    [[ -f /etc/edgebox/reverse-ssh.env ]] && . /etc/edgebox/reverse-ssh.env
  fi

  # 1) 检测可用的私钥
  if [[ -z "${EB_RSSH_KEY_PATH}" ]]; then
    for k in /root/.ssh/id_ed25519 /root/.ssh/id_rsa /root/.ssh/id_ecdsa; do
      [[ -f "$k" ]] && { EB_RSSH_KEY_PATH="$k"; break; }
    done
    # 若仍然为空，给个默认路径（不强制生成，避免打断流程）
    : "${EB_RSSH_KEY_PATH:=/root/.ssh/id_ed25519}"
  fi

  # 2) 默认 user/port/rport（若仍未设置）
  : "${EB_RSSH_USER:=root}"
  : "${EB_RSSH_PORT:=22}"
  : "${EB_RSSH_RPORT:=22022}"

  # 3) 从 ~/.ssh/config 里找别名：bastion/jump/gateway/gw
  if [[ -z "${EB_RSSH_HOST}" && -f /root/.ssh/config ]]; then
    for alias in bastion jump gateway gw; do
      if grep -qiE "^\s*Host\s+${alias}(\s|\$)" /root/.ssh/config; then
        # HostName
        hn="$(awk -v h="$alias" 'BEGIN{IGNORECASE=1}
          tolower($1)=="host" && $2==h {inhost=1; next}
          tolower($1)=="host" && inhost==1 {exit}
          inhost==1 && tolower($1)=="hostname" {print $2; exit}' /root/.ssh/config)"
        [[ -n "$hn" ]] && EB_RSSH_HOST="$hn"
        # User
        hu="$(awk -v h="$alias" 'BEGIN{IGNORECASE=1}
          tolower($1)=="host" && $2==h {inhost=1; next}
          tolower($1)=="host" && inhost==1 {exit}
          inhost==1 && tolower($1)=="user" {print $2; exit}' /root/.ssh/config)"
        [[ -n "$hu" ]] && EB_RSSH_USER="$hu"
        # Port
        hp="$(awk -v h="$alias" 'BEGIN{IGNORECASE=1}
          tolower($1)=="host" && $2==h {inhost=1; next}
          tolower($1)=="host" && inhost==1 {exit}
          inhost==1 && tolower($1)=="port" {print $2; exit}' /root/.ssh/config)"
        [[ -n "$hp" ]] && EB_RSSH_PORT="$hp"
        break
      fi
    done
  fi

  # 4) 回落到当前 SSH 客户端 IP（如果是公网且 22 可达）
  if [[ -z "${EB_RSSH_HOST}" && -n "${SSH_CONNECTION:-}" ]]; then
    client_ip="$(awk '{print $1}' <<<"$SSH_CONNECTION")"
    if [[ "$client_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
       && ! [[ "$client_ip" =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
      if command -v nc >/dev/null 2>&1; then
        if nc -zw1 "$client_ip" 22; then
          EB_RSSH_HOST="$client_ip"
        fi
      else
        # 没有 nc，就不测端口，直接尝试
        EB_RSSH_HOST="$client_ip"
      fi
    fi
  fi
}

#############################################
# 函数：install_reverse_ssh_unit
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-INSTALL_REVERSE_SSH_UNIT]
#############################################
install_reverse_ssh_unit() {
  auto_detect_reverse_ssh_params

  # 三要素缺任意一个就静默跳过（不阻塞主流程）
  if [[ -z "${EB_RSSH_HOST}" || -z "${EB_RSSH_USER}" || -z "${EB_RSSH_RPORT}" ]]; then
    return 0
  fi

  mkdir -p /etc/edgebox
  cat > /etc/edgebox/reverse-ssh.env <<EOF
EB_RSSH_HOST="${EB_RSSH_HOST}"
EB_RSSH_USER="${EB_RSSH_USER}"
EB_RSSH_PORT="${EB_RSSH_PORT}"
EB_RSSH_RPORT="${EB_RSSH_RPORT}"
EB_RSSH_KEY_PATH="${EB_RSSH_KEY_PATH}"
EOF

  cat > /etc/systemd/system/edgebox-reverse-ssh.service <<'UNIT'
[Unit]
Description=EdgeBox Reverse SSH Lifeline
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/edgebox/reverse-ssh.env
# -R 127.0.0.1:$EB_RSSH_RPORT:localhost:22 仅在跳板机本机可连更安全；
# 如需外部主机直连，把 127.0.0.1 改为 0.0.0.0 并确保跳板机 sshd: GatewayPorts clientspecified
ExecStart=/usr/bin/ssh -N \
  -R 127.0.0.1:${EB_RSSH_RPORT}:localhost:22 \
  -p ${EB_RSSH_PORT} -i ${EB_RSSH_KEY_PATH} \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=accept-new \
  ${EB_RSSH_USER}@${EB_RSSH_HOST}
Restart=always
RestartSec=3
User=root
StartLimitIntervalSec=60
StartLimitBurst=20

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now edgebox-reverse-ssh.service >/dev/null 2>&1 || true
}

#############################################
# 函数：ensure_reverse_ssh
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-ENSURE_REVERSE_SSH]
#############################################
ensure_reverse_ssh() {
  auto_detect_reverse_ssh_params
  if [[ -z "${EB_RSSH_HOST}" || -z "${EB_RSSH_USER}" || -z "${EB_RSSH_RPORT}" ]]; then
    return 0  # 未配置就跳过，不影响主流程
  fi
  systemctl is-active --quiet edgebox-reverse-ssh.service || install_reverse_ssh_unit
  return 0
}
# 反向 SSH 救生索 END


# 智能下载函数：自动尝试多个镜像源
#############################################
# 函数：smart_download
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SMART_DOWNLOAD]
#############################################
smart_download() {
    local url="$1"
    local output="$2"
    local file_type="${3:-binary}"

    log_info "智能下载: ${url##*/}"

    # 根据文件类型选择镜像列表
    local -a mirrors
    if [[ "$file_type" == "script" ]] || [[ "$url" == *"raw.githubusercontent.com"* ]]; then
        mirrors=("${DEFAULT_GITHUB_MIRRORS[@]}")
    else
        mirrors=("${DEFAULT_DOWNLOAD_MIRRORS[@]}")
    fi

    # 尝试每个镜像源
    local attempt=0
    for mirror in "${mirrors[@]}"; do
        attempt=$((attempt + 1))
        local full_url

        if [[ -z "$mirror" ]]; then
            full_url="$url"
            log_info "尝试 $attempt: 直连下载"
        else
            mirror="${mirror%/}"
            full_url="${mirror}/${url}"
            log_info "尝试 $attempt: ${mirror##*/}"
        fi

        # [修改点] 添加 --insecure 作为最后的降级选项
        # 首次尝试正常下载
        if curl -fsSL --retry 2 --retry-delay 2 \
            --connect-timeout 15 --max-time 300 \
            -A "Mozilla/5.0 (EdgeBox/4.0.0)" \
            "$full_url" -o "$output" 2>/dev/null; then

            if validate_download "$output" "$file_type"; then
                log_success "下载成功: ${url##*/}"
                return 0
            else
                log_warn "文件验证失败，尝试下一个源"
                rm -f "$output"
            fi
        else
            # 如果是 SSL 错误，尝试使用 --insecure（仅用于校验和文件）
            if [[ "$file_type" == "checksum" ]]; then
                log_debug "尝试使用 --insecure 下载校验文件"
                if curl -fsSL --insecure --retry 2 --retry-delay 2 \
                    --connect-timeout 15 --max-time 300 \
                    -A "Mozilla/5.0 (EdgeBox/4.0.0)" \
                    "$full_url" -o "$output" 2>/dev/null; then

                    if validate_download "$output" "$file_type"; then
                        log_success "下载成功（已跳过 SSL 验证）: ${url##*/}"
                        return 0
                    fi
                fi
            fi
            rm -f "$output"
        fi
    done

    log_error "所有下载源均失败: ${url##*/}"
    return 1
}

# 下载验证函数
#############################################
# 函数：validate_download
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-VALIDATE_DOWNLOAD]
#############################################
validate_download() {
    local file="$1"
    local type="$2"

    [[ ! -f "$file" ]] && return 1

    case "$type" in
        "binary")
            local size=$(stat -c%s "$file" 2>/dev/null || echo "0")
            [[ "$size" -gt 1048576 ]] && return 0  # 至少1MB
            ;;
        "script")
            head -n1 "$file" 2>/dev/null | grep -q "^#!" && return 0
            ;;
        "checksum")
            grep -q "[0-9a-f]\{64\}" "$file" && return 0
            ;;
        *)
            [[ -s "$file" ]] && return 0
            ;;
    esac

    return 1
}

# 智能下载并执行脚本（支持传递参数）
#############################################
# 函数：smart_download_script
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SMART_DOWNLOAD_SCRIPT]
#############################################
smart_download_script() {
    local url="$1"
    local description="${2:-script}"
    shift 2
    local script_args=("$@")

    log_info "Downloading $description..."

    local temp_script
    temp_script=$(mktemp) || {
        log_error "Failed to create temporary file"
        return 1
    }

    # Use --fail to ensure curl exits with an error on HTTP failure (e.g., 404)
    if smart_download "$url" "$temp_script" "script" && [[ -s "$temp_script" ]]; then
        # Ensure the downloaded file is actually a script
        if ! head -n 1 "$temp_script" | grep -q "^#!"; then
            log_error "Downloaded file is not a valid script: $url"
            rm -f "$temp_script"
            return 1
        fi

        log_debug "Executing script with sanitized arguments..."
        # Pass arguments securely. Each argument is a separate string.
        if [[ ${#script_args[@]} -gt 0 ]]; then
            bash "$temp_script" "${script_args[@]}"
        else
            bash "$temp_script"
        fi
        local exit_code=$?
        rm -f "$temp_script"
        return $exit_code
    else
        log_error "Failed to download or received empty script for: $description"
        rm -f "$temp_script"
        return 1
    fi
}


#==============================================================================
# 强语义的热重载/重启函数 (全局唯一)
# - 行为: 先校验配置，再执行操作，最后确认服务状态。
# - 目的: 避免因函数重复定义导致的行为覆盖和混乱。
#==============================================================================
#############################################
# 函数：reload_or_restart_services
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-RELOAD_OR_RESTART_SERVICES]
#############################################
reload_or_restart_services() {
  ensure_reverse_ssh # 确保救生索在线
  
    # 避免 certbot 钩子、修复任务、人工操作等并发重载导致抖动
  exec 9>/var/lock/edgebox.reload.lock
  flock -n 9 || { log_warn "已有重载在进行，跳过本次调用"; return 0; }

  local services=("$@"); local failed=()
  for svc in "${services[@]}"; do
    local action="reload"
    case "$svc" in
      nginx|nginx.service)
        command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1 || { log_error "[hotfix] nginx config check failed (nginx -t)"; failed+=("$svc"); continue; }
        systemctl reload nginx 2>/dev/null || { action="restart"; systemctl restart nginx; }
        ;;
		sing-box|sing-box.service|sing-box@*)
        # 保留配置校验，避免把坏配置重启进程
        if command -v sing-box >/dev/null 2>&1; then
          local sb_cfg="${CONFIG_DIR}/sing-box.json"
          if [[ -f "$sb_cfg" ]] && ! sing-box check -c "$sb_cfg" >/dev/null 2>&1; then
            log_error "[hotfix] sing-box 配置校验失败（sing-box check）"
            failed+=("$svc")
            continue
          fi
        fi
        # 最小改动：对 sing-box 始终执行 restart，避免 reload/HUP 后证书/UDP 未即时切换
        action="restart"
        systemctl restart "$svc"
        ;;
      xray|xray.service|xray@*)
        if command -v xray >/dev/null 2>&1; then
          local xr_cfg="$XRAY_CONFIG"
          [ -f "$xr_cfg" ] && ! xray -test -config "$xr_cfg" >/dev/null 2>&1 && { log_error "[hotfix] xray config check failed (xray -test)"; failed+=("$svc"); continue; }
        fi
        action="restart"; systemctl restart "$svc"
        ;;
      *)
        systemctl reload "$svc" 2>/dev/null || { action="restart"; systemctl restart "$svc"; }
        ;;
    esac
    if ! systemctl is-active --quiet "$svc"; then
      log_error "[hotfix] $svc is not active after $action"
      journalctl -u "$svc" -n 50 --no-pager || true
      failed+=("$svc")
    else
      log_success "[hotfix] $svc successfully ${action}ed."
    fi
  done

  # 应用防火墙规则
  if [[ -x "/etc/edgebox/scripts/apply-firewall.sh" ]]; then
    log_info "正在重新应用防火墙规则..."
    /etc/edgebox/scripts/apply-firewall.sh >/dev/null 2>&1 || log_warn "防火墙规则应用失败。"
  fi

  ((${#failed[@]}==0)) || return 1
}

# 安装系统依赖包（增强幂等性）
#############################################
# 函数：install_dependencies
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-INSTALL_DEPENDENCIES]
#############################################
install_dependencies() {
    log_info "安装系统依赖（幂等性检查）..."

    # 本地化包管理器相关变量，避免污染全局
    local PKG_MANAGER
    local -a INSTALL_CMD UPDATE_CMD

    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        UPDATE_CMD=(env -u http_proxy -u https_proxy -u all_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
                    apt-get update)
        INSTALL_CMD=(env -u http_proxy -u https_proxy -u all_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
                     DEBIAN_FRONTEND=noninteractive apt-get install -y)
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
        UPDATE_CMD=(yum makecache -y)
        INSTALL_CMD=(yum install -y)
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        UPDATE_CMD=(dnf makecache -y)
        INSTALL_CMD=(dnf install -y)
    else
        log_error "不支持的包管理器"
        return 1
    fi

    # 依赖列表
    local base_packages=(curl wget unzip gawk ca-certificates jq bc uuid-runtime dnsutils openssl tar cron python3-socks)
    local network_packages=(vnstat nftables)
    local web_packages=(nginx)
    local cert_mail_packages=(certbot msmtp-mta bsd-mailx)
    local system_packages=(dmidecode htop iotop socat tcpdump)

    # 按系统补充包名
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        network_packages+=(libnginx-mod-stream)
        cert_mail_packages+=(python3-certbot-nginx)
    elif [[ "$PKG_MANAGER" =~ ^(yum|dnf)$ ]]; then
        base_packages+=(epel-release)
        cert_mail_packages+=(python3-certbot-nginx)
    fi

    # 合并
    local all_packages=(
        "${base_packages[@]}" "${network_packages[@]}"
        "${web_packages[@]}" "${cert_mail_packages[@]}"
        "${system_packages[@]}"
    )

    # 更新索引（失败不中断）
    log_info "更新包索引..."
    if ! "${UPDATE_CMD[@]}" >/dev/null 2>&1; then
        log_warn "包索引更新失败，继续安装"
    fi

    # 幂等安装
    local failed_packages=()
    for pkg in "${all_packages[@]}"; do
        if is_package_properly_installed "$pkg"; then
            log_info "${pkg} 已正确安装"
        else
            log_info "安装 ${pkg}..."
            if "${INSTALL_CMD[@]}" "$pkg" >/dev/null 2>&1; then
                if is_package_properly_installed "$pkg"; then
                    log_success "${pkg} 安装并验证成功"
                else
                    log_warn "${pkg} 安装似乎成功但验证失败"
                    failed_packages+=("$pkg")
                fi
            else
                log_warn "${pkg} 安装失败"
                failed_packages+=("$pkg")
            fi
        fi
    done

    # 最终状态报告
    if [[ ${#failed_packages[@]} -eq 0 ]]; then
        log_success "所有依赖包安装验证完成"
    else
        log_warn "依赖安装完成，但有 ${#failed_packages[@]} 个包安装失败: ${failed_packages[*]}"
    fi

    # 用集中化的关键依赖校验替代旧的循环
    verify_critical_dependencies

    return 0
}

# [统一版] 判断包是否“已正确安装”（解耦全局PKG_MANAGER）
#############################################
# 函数：is_package_properly_installed
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-IS_PACKAGE_PROPERLY_INSTALLED]
#############################################
is_package_properly_installed() {
    local pkg="$1"
    local pm="${2:-}"

    # 1) 自动探测包管理器（当未显式传入时）
    if [[ -z "$pm" ]]; then
        if   command -v apt-get >/dev/null 2>&1; then pm="apt"
        elif command -v yum     >/dev/null 2>&1; then pm="yum"
        elif command -v dnf     >/dev/null 2>&1; then pm="dnf"
        else pm=""; fi
    fi

    # 2) 命令可用性（最可靠）
    if command -v "$pkg" >/dev/null 2>&1; then
        return 0
    fi

    # 3) 常见映射
    local actual=""
    case "$pkg" in
        python3-certbot-nginx) actual="certbot" ;;
        msmtp-mta)             actual="msmtp"  ;;
        bsd-mailx)             actual="mail"   ;;
		libnginx-mod-stream)
        # 只要动态模块文件在就算“已安装”（避免 grep 配置误判）
        if [[ -f /usr/lib/nginx/modules/ngx_stream_module.so || -f /usr/lib64/nginx/modules/ngx_stream_module.so ]]; then
            return 0
        fi
        # 如果已经启用（出现 load_module 行）也视为已就绪
        nginx -T 2>/dev/null | grep -qE 'load_module.*ngx_stream_module\.so' && return 0
        return 1
        ;;

        *) actual="$pkg" ;;
    esac
    [[ -n "$actual" ]] && command -v "$actual" >/dev/null 2>&1 && return 0

    # 4) 包数据库记录（按pm区分）
    case "$pm" in
        apt) dpkg -l 2>/dev/null | awk '/^ii[[:space:]]/ {print $2}' | grep -qx "$pkg" && return 0 ;;
        yum|dnf) rpm -q "$pkg" >/dev/null 2>&1 && return 0 ;;
    esac

    return 1
}

# [新增函数] 确保系统服务状态（完全幂等）
#############################################
# 函数：ensure_system_services
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-ENSURE_SYSTEM_SERVICES]
#############################################
ensure_system_services() {
    log_info "确保系统服务状态..."

    local services=(
        "vnstat:vnstat"
        "nft:nftables"
    )

    for service_info in "${services[@]}"; do
        IFS=':' read -r cmd service <<< "$service_info"

        if command -v "$cmd" >/dev/null 2>&1; then
            # 启用服务（幂等）
            systemctl enable "$service" >/dev/null 2>&1 || true

            # 启动服务（如果未运行则启动）
            if ! systemctl is-active --quiet "$service"; then
                systemctl start "$service" >/dev/null 2>&1 || true
                if systemctl is-active --quiet "$service"; then
                    log_success "${service}服务已启动"
                else
                    log_warn "${service}服务启动失败，但不影响核心功能"
                fi
            else
                log_info "${service}服务已在运行"
            fi
        fi
    done
}

# 创建目录结构
#############################################
# 函数：setup_directories
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SETUP_DIRECTORIES]
#############################################
setup_directories() {
    log_info "设置并验证目录结构..."

    # 定义目录及其权限
    local directories=(
        "${INSTALL_DIR}:755:root:root"
        "${CERT_DIR}:750:root:$(id -gn nobody 2>/dev/null || echo nogroup)"
        "${CONFIG_DIR}:755:root:root"
        "${TRAFFIC_DIR}:755:root:root"
        "${SCRIPTS_DIR}:755:root:root"
        "${BACKUP_DIR}:700:root:root"
        "/var/log/edgebox:755:root:root"
        "/var/log/xray:755:root:root"
        "${WEB_ROOT}:755:www-data:www-data"
        "${SNI_CONFIG_DIR}:755:root:root"
		"/var/www/edgebox/status:755:root:root"
    )

    local errors=0
    for item in "${directories[@]}"; do
        local dir="${item%%:*}"
        local perm_and_owner="${item#*:}"
        local perm="${perm_and_owner%%:*}"
        local owner_and_group="${perm_and_owner#*:}"
        local owner="${owner_and_group%%:*}"
        local group="${owner_and_group#*:}"

        # 1. 创建目录
        if ! mkdir -p "$dir"; then
            log_error "✗ 创建目录失败: $dir"
            ((errors++))
            continue
        fi

        # 2. 设置权限和所有权
        if ! chown "${owner}:${group}" "$dir" 2>/dev/null; then
            log_warn "  设置所有权失败: $dir -> ${owner}:${group} (非致命错误)"
        fi
        if ! chmod "$perm" "$dir"; then
            log_error "✗ 设置权限失败: $dir -> $perm"
            ((errors++))
            continue
        fi
        
        log_info "✓ 目录就绪: $dir ($perm, ${owner}:${group})"
    done

    # 验证可写性
    local test_file="${CONFIG_DIR}/.write_test_$$"
    if ! echo "test" > "$test_file" 2>/dev/null; then
        log_error "✗ 关键目录不可写: ${CONFIG_DIR}"
        ((errors++))
    else
        rm -f "$test_file"
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "目录结构设置与验证完成"
        return 0
    else
        log_error "目录设置过程中出现 $errors 个错误"
        return 1
    fi
}


#############################################
# 函数：verify_critical_dependencies
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-VERIFY_CRITICAL_DEPENDENCIES]
#############################################
verify_critical_dependencies() {
    log_info "验证关键依赖安装状态..."

    # 关键依赖命令映射
    local critical_deps=(
        "jq:JSON处理工具"
        "curl:HTTP客户端"
        "wget:下载工具"
        "nginx:Web服务器"
        "openssl:加密工具"
        "uuidgen:UUID生成器"
        "certbot:SSL证书工具"
    )

    local missing_critical=()
    local available_critical=()

    for dep_info in "${critical_deps[@]}"; do
        IFS=':' read -r cmd desc <<< "$dep_info"

        if command -v "$cmd" >/dev/null 2>&1; then
            log_success "✓ $desc ($cmd) 可用"
            available_critical+=("$cmd")
        else
            log_error "✗ $desc ($cmd) 不可用"
            missing_critical+=("$cmd")
        fi
    done

    # 统计验证结果
    local total_deps=${#critical_deps[@]}
    local available_count=${#available_critical[@]}
    local missing_count=${#missing_critical[@]}

    log_info "关键依赖验证完成: $available_count/$total_deps 可用"

    if [[ $missing_count -eq 0 ]]; then
        log_success "所有关键依赖验证通过"
        return 0
    elif [[ $missing_count -le 2 ]]; then
        log_warn "部分关键依赖缺失，可能影响某些功能: ${missing_critical[*]}"
        return 0  # 允许继续，但发出警告
    else
        log_error "关键依赖缺失过多，无法继续安装"
        log_error "缺失的依赖: ${missing_critical[*]}"
        return 1
    fi
}

#############################################
# SNI域名池智能管理
#############################################

# SNI域名池智能管理设置
#############################################
# 函数：setup_sni_pool_management
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SETUP_SNI_POOL_MANAGEMENT]
#############################################
setup_sni_pool_management() {
    log_info "设置SNI域名池智能管理..."

    # 创建域名池配置文件
    create_sni_pool_config

    # create_sni_management_script 调用已被删除

    log_success "SNI域名池智能管理设置完成"
}

# 创建SNI域名池配置文件
#############################################
# 函数：create_sni_pool_config
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CREATE_SNI_POOL_CONFIG]
#############################################
create_sni_pool_config() {
    log_info "创建SNI域名池配置文件..."

    cat > "$SNI_DOMAINS_CONFIG" << 'EOF'
{
  "version": "1.0",
  "last_updated": "",
  "current_domain": "",
  "domains": [
    {
      "hostname": "www.microsoft.com",
      "weight": 25,
      "category": "tech-giant",
      "region": "global",
      "last_used": "",
      "success_rate": 0.0,
      "avg_response_time": 0.0,
      "last_check": ""
    },
    {
      "hostname": "www.apple.com",
      "weight": 20,
      "category": "tech-giant",
      "region": "global",
      "last_used": "",
      "success_rate": 0.0,
      "avg_response_time": 0.0,
      "last_check": ""
    },
    {
      "hostname": "www.cloudflare.com",
      "weight": 20,
      "category": "cdn",
      "region": "global",
      "last_used": "",
      "success_rate": 0.0,
      "avg_response_time": 0.0,
      "last_check": ""
    },
    {
      "hostname": "azure.microsoft.com",
      "weight": 15,
      "category": "cloud-service",
      "region": "global",
      "last_used": "",
      "success_rate": 0.0,
      "avg_response_time": 0.0,
      "last_check": ""
    },
    {
      "hostname": "aws.amazon.com",
      "weight": 10,
      "category": "cloud-service",
      "region": "global",
      "last_used": "",
      "success_rate": 0.0,
      "avg_response_time": 0.0,
      "last_check": ""
    },
    {
      "hostname": "www.fastly.com",
      "weight": 10,
      "category": "cdn",
      "region": "global",
      "last_used": "",
      "success_rate": 0.0,
      "avg_response_time": 0.0,
      "last_check": ""
    }
  ],
  "selection_history": [],
  "rotation_config": {
    "enabled": true,
    "frequency": "weekly",
    "last_rotation": "",
    "next_rotation": "",
    "auto_fallback": true,
    "health_check_interval": 3600
  }
}
EOF

    chmod 644 "$SNI_DOMAINS_CONFIG"
    log_success "SNI域名池配置文件创建完成: $SNI_DOMAINS_CONFIG"
}

# === 一次性选择 SNI（安装阶段） ===
#############################################
# 函数：choose_initial_sni_once
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CHOOSE_INITIAL_SNI_ONCE]
#############################################
choose_initial_sni_once() {
  mkdir -p "$(dirname "$SNI_LOCK_FILE")"
  # 1) 已有锁则复用，避免重复改动
  if [[ -s "$SNI_LOCK_FILE" ]]; then
    local locked; locked="$(head -1 "$SNI_LOCK_FILE" | tr -d '\r\n ')"
    if [[ -n "$locked" ]]; then
      log_info "检测到已锁定的 SNI：${locked}，跳过重新选择"
      export REALITY_SNI="$locked"
      return 0
    fi
  fi

  # 2) edgeboxctl 优先自动选择；失败就用域名池第一个
  local chosen=""
  if command -v edgeboxctl >/dev/null 2>&1; then
    chosen="$(edgeboxctl sni auto --quiet 2>/dev/null | head -1 | tr -d '\r\n ')"
  fi
  if [[ -z "$chosen" ]]; then
    # 从 domains.json 拿第一个；再不行就用默认
    if [[ -s "$SNI_DOMAINS_CONFIG" ]] && command -v jq >/dev/null 2>&1; then
      chosen="$(jq -r '.domains[0].hostname // empty' "$SNI_DOMAINS_CONFIG" 2>/dev/null)"
    fi
    : "${chosen:=${REALITY_SNI:-www.microsoft.com}}"
    log_warn "edgeboxctl sni auto 不可用/失败，采用候选：${chosen}"
  else
    log_info "本次自动选择 SNI：${chosen}"
  fi

  # 3) 落锁 & 导出环境变量（供 configure_xray 使用）
  echo -n "$chosen" > "$SNI_LOCK_FILE"
  chmod 600 "$SNI_LOCK_FILE"
  export REALITY_SNI="$chosen"
  log_success "已锁定安装期 SNI：${REALITY_SNI}"
  return 0
}


# 检查端口占用情况
#############################################
# 函数：check_ports
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CHECK_PORTS]
#############################################
check_ports() {
    log_info "检查端口占用情况..."

    # 需要检查的端口列表
    local ports_to_check=(443 80)
    local occupied_ports=()

    # 检查每个端口
    for port in "${ports_to_check[@]}"; do
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            occupied_ports+=("$port")
            log_warn "端口 $port 已被占用"

            # 显示占用进程信息
            local process_info
            process_info=$(ss -tulpn 2>/dev/null | grep ":${port} " | head -1)
            if [[ -n "$process_info" ]]; then
                log_info "占用详情: $process_info"
            fi
        else
            log_success "端口 $port 可用"
        fi
    done

    # 处理端口占用情况
    if [[ ${#occupied_ports[@]} -gt 0 ]]; then
        log_warn "发现端口占用: ${occupied_ports[*]}"
        log_info "EdgeBox将尝试重新配置这些端口上的服务"

        # 如果是80端口被占用，通常是Apache或其他Web服务器
        if [[ " ${occupied_ports[*]} " =~ " 80 " ]]; then
            log_info "将停止可能冲突的Web服务器..."
            systemctl stop apache2 >/dev/null 2>&1 || true
            systemctl disable apache2 >/dev/null 2>&1 || true
        fi

        return 0  # 不阻止安装继续
    else
        log_success "所有必要端口都可用"
    fi
}


# 配置防火墙规则（完整版 - 支持 UFW/FirewallD/iptables，无中断模式）
#############################################
# 函数：configure_firewall
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CONFIGURE_FIREWALL]
#############################################
configure_firewall() {
  log_info "配置防火墙规则（自动识别 UFW / firewalld / iptables，含 IPv6）..."

  # ---------- 智能识别当前 SSH 端口（防自锁） ----------
  local ssh_ports=() current_ssh_port=""
  # ss 实时监听
  while IFS= read -r line; do
    [[ "$line" =~ :([0-9]+)[[:space:]]+.*sshd ]] && ssh_ports+=("${BASH_REMATCH[1]}")
  done < <(ss -tlnp 2>/dev/null | grep sshd || true)
  # sshd_config
  if [[ -f /etc/ssh/sshd_config ]]; then
    local cfgp; cfgp=$(grep -E "^[[:space:]]*Port[[:space:]]+[0-9]+" /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    [[ "$cfgp" =~ ^[0-9]+$ ]] && ssh_ports+=("$cfgp")
  fi
  # SSH_CONNECTION 环境
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    local envp; envp=$(awk '{print $4}' <<<"$SSH_CONNECTION")
    [[ "$envp" =~ ^[0-9]+$ ]] && ssh_ports+=("$envp")
  fi
  # 兜底
  current_ssh_port="${ssh_ports[0]:-22}"
  log_info "检测到 SSH 端口：$current_ssh_port"

  # ---------- 目标端口集合 ----------
  local tcp_ports=("80" "443")
  local udp_ports=("443")  # HY2 only

  # ---------- 回滚计划（5分钟后自动回滚，避免误锁） ----------
  setup_firewall_rollback

  # ---------- UFW (无中断模式) ----------
  if command -v ufw >/dev/null 2>&1; then
    log_info "使用 UFW 进行规则配置（无中断模式）..."
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true

    # 先放行 SSH (如果规则不存在)
    ufw status | grep -qw "${current_ssh_port}/tcp" || ufw allow "${current_ssh_port}/tcp" comment 'SSH'

    # 逐条添加 TCP 规则
    for p in "${tcp_ports[@]}"; do
      ufw status | grep -qw "${p}/tcp" || ufw allow "${p}/tcp" comment "EdgeBox"
    done
    # 逐条添加 UDP 规则
    for p in "${udp_ports[@]}"; do
      ufw status | grep -qw "${p}/udp" || ufw allow "${p}/udp" comment "EdgeBox"
    done

    # 确保 IPv6 支持已开启
    sed -ri 's/^#?IPV6=.*/IPV6=yes/' /etc/default/ufw || true

    # 关键：只在 UFW 未激活时才执行 enable，避免中断现有连接
    if ! ufw status | grep -q "Status: active"; then
      log_info "UFW 未激活，正在启用..."
      if ! ufw --force enable >/dev/null 2>&1; then
        log_warn "UFW 启用失败（可能是 iptables 兼容性问题），跳过 UFW 配置并继续"
        log_warn "如需手动配置，安装完成后运行: sudo ufw enable && sudo ufw allow 443/tcp && sudo ufw allow 443/udp"
        return 0  # don't fail the install
      fi
    fi

    log_success "UFW 规则已应用。"
    return 0
  fi

  # ---------- firewalld (无中断模式) ----------
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    log_info "使用 firewalld 进行规则配置（无中断模式）..."
    local zone; zone=$(firewall-cmd --get-default-zone)

    # 关键：我们只添加规则到 permanent 配置，然后使用 --runtime-to-permanent
    # 或者逐条添加到 runtime 和 permanent，避免使用 --reload

    # 逐条检查并添加规则
#############################################
# 函数：add_firewalld_rule
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-ADD_FIREWALLD_RULE]
#############################################
    add_firewalld_rule() {
        local rule="$1"
        if ! firewall-cmd --zone="$zone" --query-port="$rule" --permanent >/dev/null 2>&1; then
            firewall-cmd --zone="$zone" --add-port="$rule" --permanent >/dev/null 2>&1
        fi
    }

    add_firewalld_rule "${current_ssh_port}/tcp"
    for p in "${tcp_ports[@]}"; do add_firewalld_rule "${p}/tcp"; done
    for p in "${udp_ports[@]}"; do add_firewalld_rule "${p}/udp"; done

    # 应用 permanent 配置到 runtime，这比 --reload 更安全
    firewall-cmd --reload >/dev/null 2>&1 || true
    # 更安全的替代方案是 firewall-cmd --runtime-to-permanent，但这只会单向同步

    log_success "firewalld 规则已应用。"
    return 0
  fi

  # ---------- iptables / ip6tables (本身就是无中断的) ----------
  log_info "检测不到 UFW / firewalld，回退到 iptables / ip6tables..."

  # 使用 -C (check) 来避免重复添加规则
  iptables -C INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
  for p in "${tcp_ports[@]}"; do
    iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
    ip6tables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || ip6tables -A INPUT -p tcp --dport "$p" -j ACCEPT
  done
  for p in "${udp_ports[@]}"; do
    iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$p" -j ACCEPT
    ip6tables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || ip6tables -A INPUT -p udp --dport "$p" -j ACCEPT
  done
  iptables  -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables  -A INPUT -i lo -j ACCEPT
  ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -A INPUT -i lo -j ACCEPT

  # 保存规则
  if command -v iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables
    iptables-save  > /etc/iptables/rules.v4 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
  fi

  log_success "iptables / ip6tables 规则已应用。"
  log_info "如果云厂商有安全组，请同步放行上述端口（TCP:80/443，UDP:443）"
}


# ==========================================
# 【可选】防火墙安全回滚机制
# ==========================================
# 如果担心SSH被锁死，可以在主安装流程中调用此函数
#############################################
# 函数：setup_firewall_rollback
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SETUP_FIREWALL_ROLLBACK]
#############################################
setup_firewall_rollback() {
    log_info "设置防火墙安全回滚机制..."

    # 创建回滚脚本
    cat > /tmp/firewall_rollback.sh << 'ROLLBACK_SCRIPT'
#!/bin/bash
# EdgeBox 防火墙紧急回滚脚本
# 如果SSH连接中断，5分钟后自动回滚防火墙设置

echo "启动防火墙安全回滚机制（5分钟倒计时）..."
sleep 300  # 等待5分钟

# 检查是否还有活跃的SSH连接
if ! pgrep -f "sshd.*" >/dev/null; then
    echo "检测到SSH连接中断，执行紧急回滚..."

    # 紧急开放所有端口
    if command -v ufw >/dev/null 2>&1; then
        ufw --force disable
        echo "UFW防火墙已紧急关闭"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --panic-off
        echo "FirewallD防火墙已紧急关闭"
    elif command -v iptables >/dev/null 2>&1; then
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -F
        echo "iptables防火墙已紧急重置"
    fi

    echo "防火墙紧急回滚完成，请立即检查服务器连接"
else
    echo "SSH连接正常，取消回滚"
fi

# 清理自己
rm -f /tmp/firewall_rollback.sh
ROLLBACK_SCRIPT

    chmod +x /tmp/firewall_rollback.sh

    # 后台启动回滚进程
    nohup /tmp/firewall_rollback.sh >/dev/null 2>&1 &

    log_success "防火墙安全回滚机制已启动（5分钟超时）"
    log_info "如果SSH连接中断超过5分钟，防火墙将自动回滚"
}


# --- 系统 DNS 兜底 ---
#############################################
# 函数：ensure_system_dns
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-ENSURE_SYSTEM_DNS]
#############################################
ensure_system_dns() {
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    mkdir -p /etc/systemd
    if [[ -f /etc/systemd/resolved.conf ]]; then
      sed -ri \
        -e 's/^#?DNS=.*/DNS=8.8.8.8 1.1.1.1/' \
        -e 's/^#?FallbackDNS=.*/FallbackDNS=9.9.9.9 1.0.0.1/' \
        /etc/systemd/resolved.conf || true
      grep -q '^DNS=' /etc/systemd/resolved.conf        || echo 'DNS=8.8.8.8 1.1.1.1' >> /etc/systemd/resolved.conf
      grep -q '^FallbackDNS=' /etc/systemd/resolved.conf || echo 'FallbackDNS=9.9.9.9 1.0.0.1' >> /etc/systemd/resolved.conf
    else
      cat > /etc/systemd/resolved.conf <<'EOF'
[Resolve]
DNS=8.8.8.8 1.1.1.1
FallbackDNS=9.9.9.9 1.0.0.1
#DNSOverTLS=yes
EOF
    fi

    systemctl restart systemd-resolved || true
    # 使 /etc/resolv.conf 指向 systemd-resolved
    if [[ ! -L /etc/resolv.conf ]]; then
      ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null \
      || ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true
    fi
  else
    # 非 systemd-resolved：直接写 resolv.conf
    cp -a /etc/resolv.conf /etc/resolv.conf.bak.$(date +%s) 2>/dev/null || true
    cat > /etc/resolv.conf <<'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
options timeout:2 attempts:3
EOF
  fi
}


# 按当前出站模式自动对齐 Xray 的 DNS：
# - VPS 直出：DNS 直连（最快、最稳）
# - 住宅/代理出站(resi)：DNS 也走代理（解析来源与连接来源一致）
#############################################
# 函数：ensure_xray_dns_alignment
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-ENSURE_XRAY_DNS_ALIGNMENT]
#############################################
ensure_xray_dns_alignment() {
  local cfg="/etc/edgebox/config/xray.json"
  local tmp="$(mktemp)"
  [[ -f "$cfg" ]] || { log_warn "未找到 $cfg，跳过 Xray DNS 对齐"; return 0; }

  # 探测是否处于 “代理出站(resi)” 模式：
  # 1) 优先看 server.json 是否包含关键字 "resi"
  # 2) 回落：xray.json 里是否存在 tag=resi-proxy 的出站 且 有路由指向它
  local mode="vps"
  if [[ -f /etc/edgebox/config/server.json ]] && grep -qi '"resi"' /etc/edgebox/config/server.json; then
    mode="resi"
  else
    if jq -e '.outbounds[]?|select(.tag=="resi-proxy")' "$cfg" >/dev/null 2>&1 \
       && jq -e '.routing.rules[]?|select(.outboundTag=="resi-proxy")' "$cfg" >/dev/null 2>&1; then
      mode="resi"
    fi
  fi

  if [[ "$mode" == "resi" ]]; then
    log_info "DNS 对齐：检测到代理出站(resi)，将把 Xray 的 DNS 也走代理（DoH via resi-proxy）。"
    jq '
      .dns.servers =
        [
          {"address":"https://1.1.1.1/dns-query","outboundTag":"resi-proxy"},
          {"address":"https://8.8.8.8/dns-query","outboundTag":"resi-proxy"}
        ]
      # 先移除已有的 53 端口规则，避免重复
      | .routing.rules = ((.routing.rules // []) | map(select(.port != "53")))
      # 再置顶添加一条 53 端口走 resi-proxy（兜住明文 DNS）
      | .routing.rules = ([{"type":"field","port":"53","outboundTag":"resi-proxy"}] + .routing.rules)
    ' "$cfg" > "$tmp" \
    && /usr/local/bin/xray -test -format json -c "$tmp" \
    && mv "$tmp" "$cfg" || { rm -f "$tmp"; log_error "写入 Xray DNS(代理) 失败（新配置未通过自检或落盘失败，未覆盖原配置）"; return 1; }

  else
    log_info "DNS 对齐：检测到 VPS 直出，将把 Xray 的 DNS 设为直连（含 DoH 直连）。"
    jq '
      .dns.servers =
        [
          "8.8.8.8", "1.1.1.1",
          {"address":"https://1.1.1.1/dns-query"},
          {"address":"https://8.8.8.8/dns-query"}
        ]
      # 清除我们可能加过的 53→resi-proxy 规则
      | .routing.rules = ((.routing.rules // []) | map(select(.port != "53")))
    ' "$cfg" > "$tmp" \
    && /usr/local/bin/xray -test -format json -c "$tmp" \
    && mv "$tmp" "$cfg" || { rm -f "$tmp"; log_error "写入 Xray DNS(直连) 失败（新配置未通过自检或落盘失败，未覆盖原配置）"; return 1; }
  fi

  # 轻量热加载，失败再重启（原逻辑保持不变）
  systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null || true
}



# 优化系统参数
#############################################
# 函数：optimize_system
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-OPTIMIZE_SYSTEM]
#############################################
optimize_system() {
    log_info "优化系统参数..."

    # 备份原始配置
    if [[ ! -f /etc/sysctl.conf.bak ]]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
        log_info "已备份原始sysctl配置"
    fi

    # 检查是否已经优化过
    if grep -q "EdgeBox Optimizations" /etc/sysctl.conf; then
        log_info "系统参数已优化过，跳过"
        return 0
    fi

    # 添加网络优化参数
    cat >> /etc/sysctl.conf << 'EOF'

# EdgeBox 网络优化参数
# 启用BBR拥塞控制算法
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP优化
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192

# 端口范围优化
net.ipv4.ip_local_port_range = 10000 65000

# 内存缓冲区优化
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# 网络队列优化
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 32768

# 文件描述符限制
fs.file-max = 1000000

# 虚拟内存优化
vm.swappiness = 10
vm.dirty_ratio = 15
EOF

    # 应用系统参数
    if sysctl -p >/dev/null 2>&1; then
        log_success "系统参数优化完成"
    else
        log_warn "部分系统参数应用失败，但不影响核心功能"
    fi

    # 优化文件描述符限制
    if [[ ! -f /etc/security/limits.conf.bak ]]; then
        cp /etc/security/limits.conf /etc/security/limits.conf.bak
    fi

    # 添加文件描述符限制优化
    if ! grep -q "EdgeBox limits" /etc/security/limits.conf; then
        cat >> /etc/security/limits.conf << 'EOF'

# EdgeBox 文件描述符限制优化
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
root soft nofile 1000000
root hard nofile 1000000
EOF
        log_success "文件描述符限制优化完成"
    fi
}

# 错误处理和清理函数
#############################################
# 函数：cleanup_all
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CLEANUP_ALL]
#############################################
cleanup_all() {
    local rc=$?

    # If the script exited successfully (rc=0), check if services are up
    if [[ $rc -eq 0 ]]; then
        local services_ok=true
        local core_services=("nginx" "xray" "sing-box")
        local failed_services=()

        for service in "${core_services[@]}"; do
            if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                services_ok=false
                failed_services+=("$service")
            fi
        done

        if [[ "$services_ok" == "true" ]]; then
            exit 0
        else
            log_error "安装脚本执行完毕，但部分核心服务未能启动: ${failed_services[*]}"
            echo -e "\n${RED}❌ 安装失败：服务启动失败${NC}"
            echo -e "${YELLOW}故障排除建议：${NC}"
            for svc in "${failed_services[@]}"; do
                echo -e "  ${YELLOW}--- $svc ---${NC}"
                echo -e "  $ systemctl status $svc --no-pager -l | tail -15"
                echo -e "  $ journalctl -u $svc -n 30 --no-pager"
            done
            echo -e "  1. 查看安装日志：tail -50 /var/log/edgebox-install.log"
            echo -e "  2. 检查端口占用：ss -tlnp | grep -E ':443|:80'"
            exit 1
        fi
    else
        # rc != 0: script exited with an error mid-way (e.g. set -e tripped)
        log_error "================================================"
        log_error " 安装脚本异常退出！退出码: $rc"
        log_error "================================================"
        log_error "这通常意味着脚本中某条命令失败了。"
        log_error ""
        log_error "请按以下步骤排查："
        log_error "  1. 查看安装日志，找到最后一条 [INFO] 或 [SUCCESS] 之后的错误信息："
        log_error "     tail -80 /var/log/edgebox-install.log"
        log_error ""
        log_error "  2. 也可以用 bash -x 模式重新运行查看详细执行轨迹："
        log_error "     curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/install.sh -o /tmp/install.sh"
        log_error "     touch /tmp/edgebox_force_install"
        log_error "     sudo bash -x /tmp/install.sh 2>&1 | tee /tmp/install-trace.log"
        log_error ""
        log_error "  3. 把上面的 trace 日志的最后 100 行发出来定位问题。"
        exit $rc
    fi
}


#############################################
# 模块1初始化完成标记
#############################################

log_success "模块1：脚本头部+基础函数 - 初始化完成"


#############################################
# 系统信息收集函数
#############################################

# 收集详细的系统硬件信息
#############################################
# 函数：collect_system_info
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-COLLECT_SYSTEM_INFO]
#############################################
collect_system_info() {
    log_info "收集系统详细信息..."

    # 获取CPU详细信息
#############################################
# 函数：get_cpu_info
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GET_CPU_INFO]
#############################################
get_cpu_info() {
    # CPU核心数和线程数
    local physical_cores=$(nproc --all 2>/dev/null || echo "1")
    local logical_threads=$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "1")

    # CPU型号信息 - 修复版本
    local cpu_model
    if [[ -f /proc/cpuinfo ]]; then
        cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^[[:space:]]*//' 2>/dev/null)
        if [[ -z "$cpu_model" ]]; then
            # 尝试其他字段
            cpu_model=$(grep -E "cpu model|cpu type|processor" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^[[:space:]]*//' 2>/dev/null)
        fi
    fi

    # 如果仍然为空，使用默认值
    cpu_model=${cpu_model:-"Unknown CPU"}

    # CPU架构
    local cpu_arch=$(uname -m 2>/dev/null || echo "unknown")

    # 组合CPU信息：核心数/线程数 型号 架构
    echo "${physical_cores}C/${logical_threads}T ${cpu_model} (${cpu_arch})"
}

    # 获取内存详细信息
#############################################
# 函数：get_memory_info
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GET_MEMORY_INFO]
#############################################
get_memory_info() {
    local total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
    local swap_kb=$(awk '/SwapTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
    local total_gb=$(( total_kb / 1024 / 1024 ))
    local swap_gb=$(( swap_kb / 1024 / 1024 ))

    if [[ $swap_gb -gt 0 ]]; then
        echo "${total_gb}GiB + ${swap_gb}GiB Swap"
    else
        echo "${total_gb}GiB"
    fi
}

    # 获取磁盘信息
#############################################
# 函数：get_disk_info
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GET_DISK_INFO]
#############################################
    get_disk_info() {
        # 获取根分区磁盘信息
        local root_info=$(df -BG / 2>/dev/null | tail -1)
        if [[ -n "$root_info" ]]; then
            local total=$(echo $root_info | awk '{print $2}' | sed 's/G//')
            local used=$(echo $root_info | awk '{print $3}' | sed 's/G//')
            local available=$(echo $root_info | awk '{print $4}' | sed 's/G//')
            echo "${total}GiB (已用: ${used}GiB)"
        else
            echo "Unknown"
        fi
    }

    # 云厂商检测函数
#############################################
# 函数：detect_cloud_provider
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-DETECT_CLOUD_PROVIDER]
#############################################
    detect_cloud_provider() {
        local provider="Unknown"
        local region="Unknown"
        local instance_id="Unknown"

        log_info "检测云厂商和区域信息..."

        # AWS元数据检测
        if curl -fsS --max-time 2 http://169.254.169.254/latest/meta-data/instance-id >/dev/null 2>&1; then
            provider="AWS"
            region=$(curl -fsS --max-time 2 http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo "unknown")
            instance_id=$(curl -fsS --max-time 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
            local instance_type=$(curl -fsS --max-time 2 http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
            log_success "检测到AWS环境: $instance_type @ $region"

        # Google Cloud Platform检测
        elif curl -fsS --max-time 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/id >/dev/null 2>&1; then
            provider="GCP"
            local zone=$(curl -fsS --max-time 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/zone 2>/dev/null || echo "unknown")
            region=$(echo $zone | sed 's/.*\///g' | sed 's/-[^-]*$//')
            instance_id=$(curl -fsS --max-time 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/id 2>/dev/null || echo "unknown")
            local machine_type=$(curl -fsS --max-time 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/machine-type 2>/dev/null | sed 's/.*\///g' || echo "unknown")
            log_success "检测到GCP环境: $machine_type @ $region"

        # Microsoft Azure检测
        elif curl -fsS --max-time 2 -H "Metadata: true" http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01 >/dev/null 2>&1; then
            provider="Azure"
            region=$(curl -fsS --max-time 2 -H "Metadata: true" http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01 2>/dev/null || echo "unknown")
            instance_id=$(curl -fsS --max-time 2 -H "Metadata: true" http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01 2>/dev/null || echo "unknown")
            local vm_size=$(curl -fsS --max-time 2 -H "Metadata: true" http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01 2>/dev/null || echo "unknown")
            log_success "检测到Azure环境: $vm_size @ $region"

        # Vultr检测
        elif [[ -f /etc/vultr ]] || curl -fsS --max-time 2 http://169.254.169.254/v1.json 2>/dev/null | grep -q vultr; then
            provider="Vultr"
            local vultr_info=$(curl -fsS --max-time 2 http://169.254.169.254/v1.json 2>/dev/null)
            if [[ -n "$vultr_info" ]]; then
                region=$(echo "$vultr_info" | jq -r '.region // "unknown"' 2>/dev/null || echo "unknown")
                instance_id=$(echo "$vultr_info" | jq -r '.instanceid // "unknown"' 2>/dev/null || echo "unknown")
            fi
            log_success "检测到Vultr环境 @ $region"

        # DigitalOcean检测
        elif command -v dmidecode >/dev/null 2>&1 && dmidecode -s system-manufacturer 2>/dev/null | grep -qi "digitalocean"; then
            provider="DigitalOcean"
            region=$(curl -fsS --max-time 2 http://169.254.169.254/metadata/v1/region 2>/dev/null || echo "unknown")
            instance_id=$(curl -fsS --max-time 2 http://169.254.169.254/metadata/v1/id 2>/dev/null || echo "unknown")
            log_success "检测到DigitalOcean环境 @ $region"

        # Linode检测
        elif command -v dmidecode >/dev/null 2>&1 && dmidecode -s system-manufacturer 2>/dev/null | grep -qi "linode"; then
            provider="Linode"
            # Linode通常在hostname中包含区域信息
            local hostname_region=$(hostname | grep -oE '[a-z]+-[a-z]+[0-9]*' | head -1 || echo "unknown")
            if [[ "$hostname_region" != "unknown" ]]; then
                region="$hostname_region"
            fi
            log_success "检测到Linode环境 @ $region"

        # Hetzner检测
        elif curl -fsS --max-time 2 http://169.254.169.254/hetzner/v1/metadata >/dev/null 2>&1; then
            provider="Hetzner"
            local hetzner_info=$(curl -fsS --max-time 2 http://169.254.169.254/hetzner/v1/metadata 2>/dev/null)
            if [[ -n "$hetzner_info" ]]; then
                region=$(echo "$hetzner_info" | jq -r '.region // "unknown"' 2>/dev/null || echo "unknown")
                instance_id=$(echo "$hetzner_info" | jq -r '.instance_id // "unknown"' 2>/dev/null || echo "unknown")
            fi
            log_success "检测到Hetzner环境 @ $region"
        fi

        # 如果云厂商检测失败，尝试通过IP归属检测
        if [[ "$provider" == "Unknown" && -n "$SERVER_IP" ]]; then
            log_info "通过IP归属检测云厂商..."
            local ip_info=$(curl -fsS --max-time 5 "http://ip-api.com/json/${SERVER_IP}?fields=org,as" 2>/dev/null || echo '{}')
            if [[ -n "$ip_info" && "$ip_info" != "{}" ]]; then
                local org=$(echo "$ip_info" | jq -r '.org // empty' 2>/dev/null)
                local as_info=$(echo "$ip_info" | jq -r '.as // empty' 2>/dev/null)

                # 根据ISP信息判断云厂商
                case "${org,,}" in
                    *amazon*|*aws*) provider="AWS" ;;
                    *google*|*gcp*) provider="GCP" ;;
                    *microsoft*|*azure*) provider="Azure" ;;
                    *digitalocean*) provider="DigitalOcean" ;;
                    *vultr*) provider="Vultr" ;;
                    *linode*) provider="Linode" ;;
                    *hetzner*) provider="Hetzner" ;;
                    *ovh*) provider="OVH" ;;
                    *contabo*) provider="Contabo" ;;
                    *bandwagon*|*bwh*) provider="BandwagonHost" ;;
                esac

                if [[ "$provider" != "Unknown" ]]; then
                    log_success "通过IP归属检测到: $provider ($org)"
                fi
            fi
        fi

        # 如果仍然无法检测，设为独立服务器
        if [[ "$provider" == "Unknown" ]]; then
            provider="Independent"
            region="Unknown"
            instance_id="Unknown"
            log_info "未检测到知名云厂商，标记为独立服务器"
        fi

        # 导出检测结果到全局变量
        CLOUD_PROVIDER="$provider"
        CLOUD_REGION="$region"
        INSTANCE_ID="$instance_id"
    }

    # 执行信息收集
    log_info "收集硬件规格信息..."
    CPU_SPEC="$(get_cpu_info)"
    MEMORY_SPEC="$(get_memory_info)"
    DISK_SPEC="$(get_disk_info)"
    HOSTNAME="$(hostname -f 2>/dev/null || hostname)"

    # 执行云厂商检测
    detect_cloud_provider

    # 输出收集结果摘要
    log_success "系统信息收集完成："
    log_info "├─ 云厂商: ${CLOUD_PROVIDER}"
    log_info "├─ 区域: ${CLOUD_REGION}"
    log_info "├─ 实例ID: ${INSTANCE_ID}"
    log_info "├─ 主机名: ${HOSTNAME}"
    log_info "├─ CPU: ${CPU_SPEC}"
    log_info "├─ 内存: ${MEMORY_SPEC}"
    log_info "└─ 磁盘: ${DISK_SPEC}"
}

#############################################
# 协议凭据生成函数
#############################################

# 生成所有协议的UUID和密码
#############################################
# 函数：generate_credentials
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GENERATE_CREDENTIALS]
#############################################
generate_credentials() {
    log_info "生成协议凭据..."

# 快速验证工具可用性（应该已在前置检查中确保）
if ! command -v uuidgen >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    log_error "关键工具缺失（uuidgen 或 openssl），这不应该发生"
    log_error "请重新运行安装脚本或手动安装 uuid-runtime 和 openssl"
    return 1
fi

    log_info "生成协议UUID..."

    # v4.7.0: 2-protocol architecture (Reality + Hysteria2)
    # Removed: gRPC, Trojan, TUIC, WS
    UUID_VLESS_REALITY=$(uuidgen)

    log_info "生成协议密码..."

    # Hysteria2 password (the only password-authenticated protocol left)
    PASSWORD_HYSTERIA2=$(openssl rand -base64 32 | tr -d '\n')

    # 验证生成结果
    local failed_items=()

    # 检查UUID生成结果
    [[ -z "$UUID_VLESS_REALITY" ]] && failed_items+=("VLESS-Reality UUID")

    # 检查密码生成结果
    [[ -z "$PASSWORD_HYSTERIA2" ]] && failed_items+=("Hysteria2密码")

    # 处理生成失败的情况
    if [[ ${#failed_items[@]} -gt 0 ]]; then
        log_error "以下凭据生成失败: ${failed_items[*]}"
        return 1
    fi

    # 输出生成结果摘要（隐藏完整凭据）
    log_success "协议凭据生成完成 (v4.7.0 两协议)："
    log_info "├─ VLESS-Reality UUID: ${UUID_VLESS_REALITY:0:8}..."
    log_info "└─ Hysteria2 密码:      ${PASSWORD_HYSTERIA2:0:8}..."

    return 0
}

# 生成Reality密钥对和短ID
#############################################
# 函数：generate_reality_keys
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GENERATE_REALITY_KEYS]
#############################################
generate_reality_keys() {
    log_info "生成Reality密钥对..."

    # 检查sing-box是否可用（Reality密钥生成需要）
    if ! command -v sing-box >/dev/null 2>&1 && ! command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
        log_warn "sing-box未安装，将在模块3中安装后重新生成Reality密钥"
        # 生成临时密钥，后续会被正确密钥替换
        REALITY_PRIVATE_KEY="temp_private_key_will_be_replaced"
        REALITY_PUBLIC_KEY="temp_public_key_will_be_replaced"
        REALITY_SHORT_ID="temp_short_id"
        return 0
    fi

    # 使用sing-box生成Reality密钥对
    local reality_output
    if command -v sing-box >/dev/null 2>&1; then
        reality_output="$(sing-box generate reality-keypair 2>/dev/null)"
    elif command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
        reality_output="$(/usr/local/bin/sing-box generate reality-keypair 2>/dev/null)"
    fi

    if [[ -z "$reality_output" ]]; then
        log_error "Reality密钥对生成失败"
        return 1
    fi

    # 提取私钥和公钥
    REALITY_PRIVATE_KEY="$(echo "$reality_output" | grep -oP 'PrivateKey: \K[a-zA-Z0-9_-]+' | head -1)"
    REALITY_PUBLIC_KEY="$(echo "$reality_output" | grep -oP 'PublicKey: \K[a-zA-Z0-9_-]+' | head -1)"

    # 生成短ID（8个十六进制字符，Reality协议推荐长度）
    REALITY_SHORT_ID="$(openssl rand -hex 4 2>/dev/null || echo "$(date +%s | sha256sum | head -c 8)")"

    # 验证生成结果
    if [[ -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_PUBLIC_KEY" || -z "$REALITY_SHORT_ID" ]]; then
        log_error "Reality密钥信息生成不完整"
        log_debug "私钥: ${REALITY_PRIVATE_KEY:-空}"
        log_debug "公钥: ${REALITY_PUBLIC_KEY:-空}"
        log_debug "短ID: ${REALITY_SHORT_ID:-空}"
        return 1
    fi

    log_success "Reality密钥对生成完成："
    log_info "├─ 公钥: ${REALITY_PUBLIC_KEY:0:16}..."
    log_info "├─ 私钥: ${REALITY_PRIVATE_KEY:0:16}..."
    log_info "└─ 短ID: ${REALITY_SHORT_ID}"

    return 0
}

# 生成控制面板密码
#############################################
# 函数：generate_dashboard_passcode
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GENERATE_DASHBOARD_PASSCODE]
#############################################
generate_dashboard_passcode() {
    log_info "生成控制面板访问密码..."

    # v4.6.0-rc4-rc1: 真正的 6 位随机数字（不是单数字重复 6 次）
    # 注: 6 位数字密码只有 10^6 = 100 万种可能，存在暴力风险。
    # 安装结束会提示用户用 `edgeboxctl dashboard passcode` 改为强密码。
    DASHBOARD_PASSCODE=""
    local i
    for ((i=0; i<6; i++)); do
        DASHBOARD_PASSCODE+="$((RANDOM % 10))"
    done

    if [[ -z "$DASHBOARD_PASSCODE" || ${#DASHBOARD_PASSCODE} -ne 6 ]]; then
        log_error "控制面板密码生成失败"
        return 1
    fi

    # v4.6.0-rc4-rc1: 生成 Cookie 秘钥（攻击者不知道这个值就无法伪造会话）
    # 64 个 hex 字符 ≈ 256 bit 熵
    DASHBOARD_COOKIE_SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    if [[ ${#DASHBOARD_COOKIE_SECRET} -ne 64 ]]; then
        log_error "Cookie 秘钥生成失败"
        return 1
    fi

    log_success "控制面板密码生成完成（完整密码见安装结束摘要）"
    log_info "Cookie 会话秘钥已生成 (64-hex)"

    export DASHBOARD_PASSCODE DASHBOARD_COOKIE_SECRET

    # 不再执行这段代码,避免被save_config_info()覆盖:
    # local config_file="${CONFIG_DIR}/server.json"
    # if [[ -f "$config_file" ]]; then
    #     ...jq写入...
    # fi
    # =========================================================================

    return 0
}

# // ANCHOR: [FUNC-SAVE_CONFIG_INFO]
#############################################
# 函数：save_config_info
# 作用：保存完整配置信息到server.json (原子写入 + 验证)
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
#############################################
save_config_info() {
    log_info "保存配置信息到server.json (写入临时文件)..."

    mkdir -p "${CONFIG_DIR}"

    # --- Start: Original variable assignments and checks ---
    local server_ip="${SERVER_IP:-127.0.0.1}"
    local version="${EDGEBOX_VER:-4.0.0}"
    local install_date; install_date="$(date +%Y-%m-%d)"
    local updated_at; updated_at="$(date -Is)"
    local cloud_provider="${CLOUD_PROVIDER:-Unknown}"
    local cloud_region="${CLOUD_REGION:-Unknown}"
    local instance_id="${INSTANCE_ID:-Unknown}"
    local hostname="${HOSTNAME:-$(hostname)}"
    local user_alias=""
    local cpu_spec="${CPU_SPEC:-Unknown}"
    local memory_spec="${MEMORY_SPEC:-Unknown}"
    local disk_spec="${DISK_SPEC:-Unknown}"
    if [[ -z "$DASHBOARD_PASSCODE" ]]; then
        log_warn "DASHBOARD_PASSCODE为空，生成临时6位数字口令"
        local d=$((RANDOM % 10)); DASHBOARD_PASSCODE="${d}${d}${d}${d}${d}${d}"; export DASHBOARD_PASSCODE
    fi
    # 关键凭据校验（缺失即失败）- 注意这里的 MASTER_SUB_TOKEN 依赖 execute_module2 中生成
    if [[ -z "$UUID_VLESS_REALITY" || -z "$PASSWORD_HYSTERIA2" || -z "${MASTER_SUB_TOKEN:-}" ]]; then
        log_error "关键凭据缺失（含管理员订阅Token），无法保存配置"
        log_debug "UUID_VLESS_REALITY: ${UUID_VLESS_REALITY:-MISSING}"
        log_debug "PASSWORD_HYSTERIA2: ${PASSWORD_HYSTERIA2:0:8}..."
        log_debug "PASSWORD_HYSTERIA2: ${PASSWORD_HYSTERIA2:-MISSING}"
        log_debug "MASTER_SUB_TOKEN: ${MASTER_SUB_TOKEN:-MISSING}"
        return 1
    fi
    if [[ ! "$server_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "服务器IP格式无效: $server_ip"; return 1
    fi
    # --- End: Original variable assignments and checks ---

    local server_tmp="${CONFIG_DIR}/server.json.tmp"
    log_info "使用 jq 生成 server.json 临时文件..."

    # v4.7.0: 升级模式下保留 cert/reality.sni 状态 (CDN/WS 已移除)
    local _cert_mode="${UPGRADE_CERT_MODE:-self-signed}"
    local _cert_domain="${UPGRADE_CERT_DOMAIN:-}"
    local _cert_autorenew="${UPGRADE_CERT_AUTORENEW:-false}"
    local _reality_sni="${UPGRADE_REALITY_SNI:-}"

    # Use jq -n to generate JSON (all variables safely injected)
    jq -n \
      --arg version              "$version" \
      --arg install_date         "$install_date" \
      --arg updated_at           "$updated_at" \
      --arg server_ip            "$server_ip" \
      --arg eip                  "${SERVER_EIP:-$server_ip}" \
      --arg hostname             "$hostname" \
      --arg instance_id          "$instance_id" \
      --arg user_alias           "$user_alias" \
      --arg dashboard_passcode   "$DASHBOARD_PASSCODE" \
      --arg dashboard_cookie_secret "$DASHBOARD_COOKIE_SECRET" \
      --arg master_sub_token     "${MASTER_SUB_TOKEN:-}" \
      --arg cloud_provider       "$cloud_provider" \
      --arg cloud_region         "$cloud_region" \
      --arg cpu_spec             "$cpu_spec" \
      --arg memory_spec          "$memory_spec" \
      --arg disk_spec            "$disk_spec" \
      --arg uuid_vless_reality   "$UUID_VLESS_REALITY" \
      --arg password_hysteria2   "$PASSWORD_HYSTERIA2" \
      --arg reality_public_key   "$REALITY_PUBLIC_KEY" \
      --arg reality_private_key  "$REALITY_PRIVATE_KEY" \
      --arg reality_short_id     "$REALITY_SHORT_ID" \
      --arg reality_sni          "$_reality_sni" \
      --arg cert_mode            "$_cert_mode" \
      --arg cert_domain          "$_cert_domain" \
      --argjson cert_autorenew   "$_cert_autorenew" \
      '{
         version: $version, install_date: $install_date, updated_at: $updated_at,
         server_ip: $server_ip, eip: $eip, hostname: $hostname, instance_id: $instance_id,
         user_alias: $user_alias, dashboard_passcode: $dashboard_passcode, dashboard_cookie_secret: $dashboard_cookie_secret, master_sub_token: $master_sub_token,
         cloud: { provider: $cloud_provider, region: $cloud_region },
         spec:  { cpu: $cpu_spec, memory: $memory_spec, disk: $disk_spec },
         uuid:  { vless: { reality: $uuid_vless_reality } },
         password: { hysteria2: $password_hysteria2 },
         reality:  { public_key: $reality_public_key, private_key: $reality_private_key, short_id: $reality_short_id, sni: (if $reality_sni == "" then null else $reality_sni end) },
         cert: { mode: $cert_mode, domain: (if $cert_domain == "" then null else $cert_domain end), auto_renew: $cert_autorenew }
       }' > "$server_tmp" || { log_error "使用jq生成 server.json 失败"; rm -f "$server_tmp"; return 1; }

    # --- ATOMIC WRITE + VALIDATION ---
    log_info "验证生成的 server.json..."
    if ! jq '.' "$server_tmp" >/dev/null 2>&1; then
        log_error "生成的 server.json 格式无效！"
        rm -f "$server_tmp"
        return 1
    fi
    local saved_passcode=$(jq -r '.dashboard_passcode // empty' "$server_tmp" 2>/dev/null)
    if [[ -z "$saved_passcode" || "$saved_passcode" != "$DASHBOARD_PASSCODE" ]]; then
         log_error "密码保存验证失败 (期望: $DASHBOARD_PASSCODE, 实际: ${saved_passcode:-空})"
         rm -f "$server_tmp"
         return 1
    fi
    mv "$server_tmp" "${CONFIG_DIR}/server.json"
    log_success "server.json 配置文件保存并验证成功。"
    # --- END ATOMIC WRITE + VALIDATION ---

    chmod 600 "${CONFIG_DIR}/server.json"
    chown root:root "${CONFIG_DIR}/server.json"
    return 0
}

# 生成自签名证书（基础版本，模块3会有完整版本）
#############################################
# 函数：generate_self_signed_cert
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GENERATE_SELF_SIGNED_CERT]
#############################################
generate_self_signed_cert() {
    log_info "生成自签名证书并修复权限..."

    mkdir -p "${CERT_DIR}"
    rm -f "${CERT_DIR}"/self-signed.{key,pem} "${CERT_DIR}"/current.{key,pem}

    if ! command -v openssl >/dev/null 2>&1; then
        log_error "openssl未安装，无法生成证书"; return 1;
    fi

    # === 修复 v4：使用 'openssl genpkey' 替换 'openssl ecparam'，并增加文件大小验证 ===
    
    log_info "正在生成 ECC 私钥 (secp384r1)..."
    # 使用更现代的 genpkey 命令
    if ! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${CERT_DIR}/self-signed.key"; then
        log_error "生成ECC私钥失败 (openssl genpkey)"
        # 额外调试：检查 openssl 版本和 ec 支持
        openssl version >> "$LOG_FILE" 2>&1
        openssl ecparam -list_curves >> "$LOG_FILE" 2>&1
        return 1
    fi
    
    # <<< --- 新增：立即验证私钥文件是否为空 --- >>>
    if [[ ! -s "${CERT_DIR}/self-signed.key" ]]; then
        log_error "致命错误：openssl genpkey 命令执行成功，但生成的私钥文件为空！"
        log_error "这可能是系统 openssl 库的问题。安装中止。"
        return 1
    fi
    log_info "私钥生成成功 (文件大小: $(stat -c %s "${CERT_DIR}/self-signed.key") 字节)。"
    # <<< --- 验证结束 --- >>>


    log_info "正在使用私钥生成自签名证书..."
    # 移除错误抑制，让错误暴露出来
    if ! openssl req -new -x509 -key "${CERT_DIR}/self-signed.key" -out "${CERT_DIR}/self-signed.pem" -days 3650 -subj "/C=US/ST=CA/L=SF/O=EdgeBox/CN=${SERVER_IP}"; then
        log_error "生成自签名证书失败 (openssl req)"
        return 1
    fi
    log_info "证书生成成功。"
    
    # === 修复结束 ===

    # 创建软链接
    ln -sf "${CERT_DIR}/self-signed.key" "${CERT_DIR}/current.key"
    ln -sf "${CERT_DIR}/self-signed.pem" "${CERT_DIR}/current.pem"

    # --- 关键权限修复 ---
    local NOBODY_GRP
    NOBODY_GRP="$(id -gn nobody 2>/dev/null || echo nogroup)"
	
	# 目录与文件权限：目录 750，公钥证书 644，私钥 600
  chown -R root:"$NOBODY_GRP" "$CERT_DIR"
  chmod 750 "$CERT_DIR"
  chmod 644 "${CERT_DIR}/self-signed.pem"
  chmod 600 "${CERT_DIR}/self-signed.key"

  log_info "自签证书已生成：${CERT_DIR}/self-signed.pem / self-signed.key；目录 750，证书 644，私钥 600。"

    if openssl x509 -in "${CERT_DIR}/current.pem" -noout >/dev/null 2>&1; then
        log_success "自签名证书生成及权限设置完成"
        echo "self-signed" > "${CONFIG_DIR}/cert_mode"
    else
        log_error "证书验证失败"; return 1;
    fi
    return 0
}

#############################################
# 数据完整性验证函数
#############################################

# 验证模块2生成的所有数据
#############################################
# 函数：verify_module2_data
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-VERIFY_MODULE2_DATA]
#############################################
verify_module2_data() {
    log_info "验证模块2生成的数据完整性..."

    local errors=0

    # 1. 验证系统信息收集结果
    log_info "检查系统信息收集结果..."

    if [[ -z "$CLOUD_PROVIDER" || "$CLOUD_PROVIDER" == "Unknown" ]]; then
        log_warn "云厂商信息未收集到，将标记为独立服务器"
    else
        log_success "✓ 云厂商信息: $CLOUD_PROVIDER"
    fi

    if [[ -z "$CPU_SPEC" || "$CPU_SPEC" == "Unknown" ]]; then
        log_warn "CPU信息收集失败"
        errors=$((errors + 1))
    else
        log_success "✓ CPU信息: $CPU_SPEC"
    fi

    if [[ -z "$MEMORY_SPEC" || "$MEMORY_SPEC" == "Unknown" ]]; then
        log_warn "内存信息收集失败"
        errors=$((errors + 1))
    else
        log_success "✓ 内存信息: $MEMORY_SPEC"
    fi

    # 2. 验证协议凭据生成结果
    log_info "检查协议凭据生成结果..."

    local required_uuids=(
        "UUID_VLESS_REALITY:VLESS-Reality"
    )

    for uuid_info in "${required_uuids[@]}"; do
        local var_name="${uuid_info%:*}"
        local protocol_name="${uuid_info#*:}"
        local uuid_value="${!var_name}"

        if [[ -z "$uuid_value" || ! "$uuid_value" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            log_error "✗ ${protocol_name} UUID无效或缺失"
            errors=$((errors + 1))
        else
            log_success "✓ ${protocol_name} UUID: ${uuid_value:0:8}..."
        fi
    done

    local required_passwords=(
        "PASSWORD_HYSTERIA2:Hysteria2"
    )

    for pass_info in "${required_passwords[@]}"; do
        local var_name="${pass_info%:*}"
        local protocol_name="${pass_info#*:}"
        local pass_value="${!var_name}"

        if [[ -z "$pass_value" || ${#pass_value} -lt 16 ]]; then
            log_error "✗ ${protocol_name} 密码无效或缺失"
            errors=$((errors + 1))
        else
            log_success "✓ ${protocol_name} 密码: ${pass_value:0:8}..."
        fi
    done

    # 3. 验证Reality密钥
    log_info "检查Reality密钥..."

    if [[ -z "$REALITY_PUBLIC_KEY" || -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_SHORT_ID" ]]; then
        if [[ "$REALITY_PUBLIC_KEY" == "temp_public_key_will_be_replaced" ]]; then
            log_warn "Reality密钥使用临时值，将在模块3中重新生成"
        else
            log_error "✗ Reality密钥信息缺失"
            errors=$((errors + 1))
        fi
    else
        log_success "✓ Reality公钥: ${REALITY_PUBLIC_KEY:0:16}..."
        log_success "✓ Reality私钥: ${REALITY_PRIVATE_KEY:0:16}..."
        log_success "✓ Reality短ID: $REALITY_SHORT_ID"
    fi

    # 4. 验证server.json文件
    log_info "检查server.json配置文件..."

    if [[ ! -f "${CONFIG_DIR}/server.json" ]]; then
        log_error "✗ server.json文件不存在"
        errors=$((errors + 1))
    elif ! jq '.' "${CONFIG_DIR}/server.json" >/dev/null 2>&1; then
        log_error "✗ server.json格式错误"
        errors=$((errors + 1))
    else
        log_success "✓ server.json文件格式正确"

        # 检查关键字段
        local required_fields=(
            ".server_ip"
            ".version"
            ".uuid.vless.reality"
            ".password.hysteria2"
            ".cloud.provider"
            ".spec.cpu"
        )

        for field in "${required_fields[@]}"; do
            local value
            value=$(jq -r "$field // empty" "${CONFIG_DIR}/server.json" 2>/dev/null)
            if [[ -z "$value" || "$value" == "null" ]]; then
                log_error "✗ server.json缺少字段: $field"
                errors=$((errors + 1))
            else
                log_success "✓ 字段存在: $field"
            fi
        done
    fi

    # 5. 验证证书文件
    log_info "检查证书文件..."

    if [[ ! -f "${CERT_DIR}/current.pem" || ! -f "${CERT_DIR}/current.key" ]]; then
        log_error "✗ 证书文件缺失"
        errors=$((errors + 1))
    elif ! openssl x509 -in "${CERT_DIR}/current.pem" -noout -text >/dev/null 2>&1; then
        log_error "✗ 证书文件无效"
        errors=$((errors + 1))
    else
        log_success "✓ 证书文件有效"
    fi

    # 验证总结
    if [[ $errors -eq 0 ]]; then
        log_success "模块2数据完整性验证通过，所有组件正常"
        return 0
    else
        log_error "模块2数据验证发现 $errors 个问题"
        return 1
    fi
}

#############################################
# 模块2主执行函数
#############################################

# 执行模块2的所有任务
#############################################
# 函数：execute_module2
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-EXECUTE_MODULE2]
#############################################
execute_module2() {
    log_info "======== 开始执行模块2：系统信息收集+凭据生成 ========"

    # 任务1：收集系统详细信息
    if collect_system_info; then
        log_success "✓ 系统信息收集完成"
    else
        log_error "✗ 系统信息收集失败"
        return 1
    fi

    # v4.6.0-rc4-rc1: 升级路径 — 检测 /tmp/edgebox-keep-server.json
    # 如果存在，复用所有凭据，跳过 generate_credentials/generate_dashboard_passcode/MASTER_SUB_TOKEN
    local KEEP_FILE="/tmp/edgebox-keep-server.json"
    local UPGRADE_MODE=0
    if [[ -f "$KEEP_FILE" ]]; then
        log_info "============================================"
        log_info "  检测到升级保留文件: $KEEP_FILE"
        log_info "  将复用现有凭据 (UUID / 密码 / Token 不变)"
        log_info "============================================"
        UPGRADE_MODE=1

        # 从 keep 文件读取所有凭据到全局变量
        UUID_VLESS_REALITY=$(jq -r '.uuid.vless.reality // empty' "$KEEP_FILE")
        PASSWORD_HYSTERIA2=$(jq -r '.password.hysteria2 // empty' "$KEEP_FILE")
        REALITY_PUBLIC_KEY=$(jq -r '.reality.public_key // empty' "$KEEP_FILE")
        REALITY_PRIVATE_KEY=$(jq -r '.reality.private_key // empty' "$KEEP_FILE")
        REALITY_SHORT_ID=$(jq -r '.reality.short_id // empty' "$KEEP_FILE")
        DASHBOARD_PASSCODE=$(jq -r '.dashboard_passcode // empty' "$KEEP_FILE")
        DASHBOARD_COOKIE_SECRET=$(jq -r '.dashboard_cookie_secret // empty' "$KEEP_FILE")
        MASTER_SUB_TOKEN=$(jq -r '.master_sub_token // empty' "$KEEP_FILE")

        # v4.7.0: 同时保留这些字段，让 save_config_info 写回 server.json
        # 否则新生成的 server.json 会清空 cert.mode / reality.sni
        UPGRADE_CERT_MODE=$(jq -r '.cert.mode // "self-signed"'  "$KEEP_FILE")
        UPGRADE_CERT_DOMAIN=$(jq -r '.cert.domain // ""'         "$KEEP_FILE")
        UPGRADE_CERT_AUTORENEW=$(jq -r '.cert.auto_renew // false' "$KEEP_FILE")
        UPGRADE_REALITY_SNI=$(jq -r '.reality.sni // ""'         "$KEEP_FILE")
        export UPGRADE_CERT_MODE UPGRADE_CERT_DOMAIN UPGRADE_CERT_AUTORENEW
        export UPGRADE_REALITY_SNI

        # 关键凭据校验
        local missing=()
        [[ -z "$UUID_VLESS_REALITY"    ]] && missing+=("UUID_VLESS_REALITY")
        [[ -z "$PASSWORD_HYSTERIA2"    ]] && missing+=("PASSWORD_HYSTERIA2")
        [[ -z "$REALITY_PUBLIC_KEY"    ]] && missing+=("REALITY_PUBLIC_KEY")
        [[ -z "$REALITY_PRIVATE_KEY"   ]] && missing+=("REALITY_PRIVATE_KEY")
        [[ -z "$MASTER_SUB_TOKEN"      ]] && missing+=("MASTER_SUB_TOKEN")
        if [[ ${#missing[@]} -gt 0 ]]; then
            log_error "升级模式下 keep 文件缺少关键凭据: ${missing[*]}"
            log_error "请放弃升级，从备份恢复，或直接全新安装"
            return 1
        fi

        # 补齐 v4.6.0-rc4-rc1 新增字段（旧 server.json 可能没有）
        if [[ -z "$DASHBOARD_PASSCODE" ]]; then
            log_warn "keep 文件无 dashboard_passcode，生成新密码"
            generate_dashboard_passcode || return 1
        elif [[ -z "$DASHBOARD_COOKIE_SECRET" ]]; then
            log_warn "keep 文件无 dashboard_cookie_secret (v4.5 之前安装)，生成新秘钥"
            DASHBOARD_COOKIE_SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
        fi

        export UUID_VLESS_REALITY PASSWORD_HYSTERIA2
        export REALITY_PUBLIC_KEY REALITY_PRIVATE_KEY REALITY_SHORT_ID
        export DASHBOARD_PASSCODE DASHBOARD_COOKIE_SECRET MASTER_SUB_TOKEN

        log_success "✓ 复用 ${#missing[@]} 项检查全部通过；凭据已加载"
    else
        # 全新安装路径
        # 任务2：生成协议凭据
        if generate_credentials; then
            log_success "✓ 协议凭据生成完成"
        else
            log_error "✗ 协议凭据生成失败"
            return 1
        fi

        # 任务2.5：生成控制面板密码(只生成不写入)
        if generate_dashboard_passcode; then
            log_success "✓ 控制面板密码生成完成（完整密码见安装结束摘要）"
            export DASHBOARD_PASSCODE
        else
            log_error "✗ 控制面板密码生成失败"
            return 1
        fi

# 任务2.6：生成管理员订阅Token（32 hex = 16字节）
if [[ -z "${MASTER_SUB_TOKEN:-}" ]]; then
  MASTER_SUB_TOKEN="$(openssl rand -hex 16)"
fi
if [[ -n "$MASTER_SUB_TOKEN" ]]; then
  export MASTER_SUB_TOKEN
  log_success "✓ 管理员Token: ${MASTER_SUB_TOKEN:0:8}..."
else
  log_error "✗ 管理员Token生成失败"; return 1
fi
    fi  # end UPGRADE_MODE else branch

    # 任务3：生成Reality密钥 (升级模式下跳过，复用旧密钥)
    if [[ "$UPGRADE_MODE" -ne 1 ]]; then
        if generate_reality_keys; then
            log_success "✓ Reality密钥生成完成"
        else
            log_warn "Reality密钥生成失败，将在模块3中重新生成"
        fi
    else
        log_info "✓ 升级模式: 复用现有 Reality 密钥"
    fi

    # 任务4：生成自签名证书
    if generate_self_signed_cert; then
        log_success "✓ 自签名证书生成完成"
    else
        log_error "✗ 自签名证书生成失败"
        return 1
    fi

    # ========== 关键修复: save_config_info在密码生成之后 ==========
    # 任务5：保存配置信息(统一写入所有配置包括密码)
    if save_config_info; then
        log_success "✓ 配置信息保存完成"

        # 再次验证密码
        local verify_password=$(jq -r '.dashboard_passcode // empty' "${CONFIG_DIR}/server.json" 2>/dev/null)
        if [[ "$verify_password" == "$DASHBOARD_PASSCODE" ]]; then
            log_success "✓ 密码二次验证通过"
        else
            log_error "✗ 密码二次验证失败"
            return 1
        fi
    else
        log_error "✗ 配置信息保存失败"
        return 1
    fi
    # ===========================================================

    # 任务6：验证数据完整性
    if verify_module2_data; then
        log_success "✓ 数据完整性验证通过"
    else
        log_warn "数据完整性验证发现问题，但安装将继续"
    fi

    # 导出所有变量供后续模块使用
    export UUID_VLESS_REALITY
    export PASSWORD_HYSTERIA2
    export REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY REALITY_SHORT_ID
    export SERVER_IP DASHBOARD_PASSCODE

    log_info "已导出所有必要变量供后续模块使用"

    log_success "======== 模块2执行完成 ========"
    log_info "已生成："
    log_info "├─ 系统信息（云厂商、硬件规格）"
    log_info "├─ 所有协议的UUID和密码"
    log_info "├─ Reality密钥对"
    log_info "├─ 自签名证书"
    log_info "├─ 控制面板密码: ******（完整密码见安装结束摘要 / server.json）"
    log_info "└─ 完整的server.json配置文件"

    return 0
}


#############################################
# 模块2导出函数（供其他模块调用）
#############################################

# 获取当前生成的配置信息（只读）
#############################################
# 函数：get_config_summary
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GET_CONFIG_SUMMARY]
#############################################
get_config_summary() {
    if [[ ! -f "${CONFIG_DIR}/server.json" ]]; then
        echo "配置文件不存在"
        return 1
    fi

    echo "当前配置摘要："
    jq -r '
        "服务器IP: " + .server_ip,
        "云厂商: " + .cloud.provider + " @ " + .cloud.region,
        "CPU: " + .spec.cpu,
        "内存: " + .spec.memory,
        "Reality公钥: " + (.reality.public_key[0:20] + "..."),
        "证书模式: " + .cert.mode
    ' "${CONFIG_DIR}/server.json"
}

#############################################
# 模块2完成标记
#############################################

log_success "模块2：系统信息收集+凭据生成 - 加载完成"
log_info "可用函数："
log_info "├─ execute_module2()           # 执行模块2所有任务"
log_info "├─ get_config_summary()        # 显示配置摘要"
log_info "├─ regenerate_credentials()    # 重新生成凭据"
log_info "└─ verify_module2_data()       # 验证数据完整性"



#############################################
# 模块3：服务安装配置 (完整版)
#
# 功能说明：
# - 安装Xray和sing-box核心程序
# - 配置Nginx（SNI定向+ALPN兜底架构）
# - 配置Xray（VLESS-Reality）
# - 配置sing-box（Hysteria2）
# - 生成订阅链接
# - 验证服务配置
#############################################

# // ANCHOR: [FUNC-INSTALL_XRAY]
#############################################
# 函数：install_xray
# 作用：安装Xray核心程序 (V3 - 自动获取最新版，手动安装)
# 输入：无
# 输出：Xray 二进制文件和 .dat 文件
#############################################

install_xray() {
  set -euo pipefail

  local DEST="/usr/local/bin"
  local BIN="${DEST}/xray"
  local WORK; WORK="$(mktemp -d /tmp/xray.XXXXXX)"
  trap 'rm -rf "$WORK"' RETURN

  # === 架构映射 → Xray 预编译包名后缀 ===
  local pkg_arch
  case "$(uname -m)" in
    x86_64|amd64)   pkg_arch="64" ;;
    aarch64|arm64)  pkg_arch="arm64-v8a" ;;
    armv7l|armv7)   pkg_arch="arm32-v7a" ;;
    armv6l|armv6)   pkg_arch="arm32-v6" ;;
    i386|i686)      pkg_arch="32" ;;
    loongarch64)    pkg_arch="loong64" ;;
    mips64le)       pkg_arch="mips64le" ;;
    s390x)          pkg_arch="s390x" ;;
    *) log_error "不支持的架构: $(uname -m)"; return 1 ;;
  esac

  # === 版本候选列表：用户指定 > GitHub latest > 精选稳定备选 ===
  local -a candidates=()

  _sanitize_tag() {  # 只接受 v前缀的版本/或裸版本；其它一律丢弃
    local t="$1"
    [[ "$t" =~ ^[vV]?[0-9][0-9.]*([A-Za-z0-9._-]*)?$ ]] || return 1
    [[ "$t" == v* || "$t" == V* ]] || t="v${t}"
    printf '%s' "${t#V}"
  }

  _push_candidate() {
    local t
    t="$(_sanitize_tag "${1:-}" 2>/dev/null || true)" || true
    [[ -n "$t" ]] || return 0
    local x; for x in "${candidates[@]:-}"; do [[ "$x" == "$t" ]] && return 0; done
    candidates+=("$t")
  }

  # 1) 用户显式指定（函数参数或环境变量）
  local user_ver="${1:-${XRAY_VERSION:-}}"
  [[ -n "$user_ver" ]] && _push_candidate "$user_ver"

  # 2) GitHub latest（用 jq 提取 tag_name，失败则忽略）
  local latest_tag=""
  if command -v jq >/dev/null 2>&1; then
    latest_tag="$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest \
                   | jq -r '.tag_name // empty')"
  else
    # 没 jq 的兜底（容错 sed）；不稳定时宁可取空
    latest_tag="$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest \
                   | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' \
                   | head -n1)"
  fi
  [[ -n "$latest_tag" ]] && _push_candidate "$latest_tag"

  # 3) 我整理的稳定备选（新→旧，按需自行调整）
  local curated_fallbacks=( v25.10.15 v25.9.11 v25.8.3 v1.8.24 )
  local v; for v in "${curated_fallbacks[@]}"; do _push_candidate "$v"; done

  # === 实际安装：逐个候选尝试 ===
  _try_install_one() {
    local tag="$1"
    local file="Xray-linux-${pkg_arch}.zip"
    local url="https://github.com/XTLS/Xray-core/releases/download/${tag}/${file}"
    local zip="${WORK}/${file}"

    log_info "尝试安装 Xray ${tag} (${file})"
    if ! curl -fL --retry 5 --retry-all-errors --connect-timeout 8 -o "$zip" "$url"; then
      log_warn "下载失败: $url"
      return 1
    fi

    rm -rf "${WORK}/unz"; mkdir -p "${WORK}/unz"
    command -v unzip >/dev/null 2>&1 || { apt-get update -y && apt-get install -y unzip >/dev/null 2>&1 || true; }
    if ! unzip -o "$zip" -d "${WORK}/unz" >/dev/null; then
      log_warn "解压失败: ${file}"
      return 1
    fi

    install -m 0755 "${WORK}/unz/xray" "$BIN"
    [[ -f "${WORK}/unz/geoip.dat"    ]] && install -m 0644 "${WORK}/unz/geoip.dat"    /usr/local/share/geoip.dat
    [[ -f "${WORK}/unz/geosite.dat"  ]] && install -m 0644 "${WORK}/unz/geosite.dat"  /usr/local/share/geosite.dat

    command -v setcap >/dev/null 2>&1 && setcap cap_net_bind_service=+eip "$BIN" 2>/dev/null || true

    local ver
    ver="$("$BIN" -version 2>/dev/null || "$BIN" version 2>/dev/null || true)"
    [[ -n "$ver" ]] || { log_warn "安装后无法运行"; return 1; }
    log_success "$(echo "$ver" | head -n1)"
    return 0
  }

  local ok=0 tag
  for tag in "${candidates[@]}"; do
    if _try_install_one "$tag"; then ok=1; break; fi
  done

  if [[ $ok -ne 1 ]]; then
    log_warn "所有候选下载失败，回落到官方安装脚本..."
    if bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root; then
      "$BIN" -version || "$BIN" version || true
      ok=1
    else
      log_error "官方安装脚本兜底失败"
      return 1
    fi
  fi

  return 0
}

#############################################
# sing-box 安装函数
#############################################


# 安装sing-box核心程序（最佳实践版）
#############################################
# 函数：install_sing_box
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-INSTALL_SING_BOX]
#############################################
install_sing_box() {
    log_info "安装sing-box核心程序..."

    # ========================================
    # 第1步：检查是否已安装
    # ========================================
local MIN_REQUIRED_VERSION="1.8.0"   # HY2 服务端所需的最低版本（可调高）
local current_version=""
if command -v sing-box >/dev/null 2>&1 || command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
    current_version=$( (sing-box version || /usr/local/bin/sing-box version) 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 )
    log_info "检测到已安装 sing-box: v${current_version:-未知}"
    if [[ -n "$current_version" && "$(printf '%s\n' "$MIN_REQUIRED_VERSION" "$current_version" | sort -V | head -1)" == "$MIN_REQUIRED_VERSION" ]]; then
        log_success "现有版本满足最低要求 (>= ${MIN_REQUIRED_VERSION})，跳过重新安装"
        return 0
    else
        log_warn "现有版本过低，将升级到脚本内置稳定版"
        # 继续执行安装流程（覆盖到 /usr/local/bin/sing-box）
    fi
fi

    # ========================================
    # 第2步：版本决策逻辑（核心改进）
    # ========================================

    # 版本优先级队列（从最新到最稳定）
    # 注意：这是降级队列，会依次尝试直到成功
    local VERSION_PRIORITY=(
	    "1.12.10"
		"1.12.8"    # 最新版（2025年推荐）
        "1.12.1"    # 最新稳定版（2025年推荐）
        "1.12.0"    # 稳定版（2024年3月发布）
        "1.11.15"   # LTS 长期支持版
        "1.11.0"    # 备用稳定版
        "1.10.0"    # 最后的保底版本
    )

    # 已知问题版本黑名单（会自动跳过）
    local KNOWN_BAD_VERSIONS=(
        "1.12.4"    # 不存在的版本
        "1.12.3"    # 不存在的版本
        "1.12.2"    # 不存在的版本
    )

    local version_to_install=""

    # 2.1 如果用户指定了版本
    if [[ -n "${DEFAULT_SING_BOX_VERSION:-}" ]]; then
        version_to_install="${DEFAULT_SING_BOX_VERSION}"
        log_info "使用用户指定的 sing-box 版本: v${version_to_install}"

        # 黑名单检查
        if [[ " ${KNOWN_BAD_VERSIONS[*]} " =~ " ${version_to_install} " ]]; then
            log_warn "用户指定的 v${version_to_install} 在黑名单中"
            log_warn "将使用自动版本选择..."
            version_to_install=""  # 清空，进入自动选择流程
        fi
    fi

    # 2.2 自动版本选择流程（核心逻辑）
    if [[ -z "$version_to_install" ]]; then
        log_info "尝试按优先级队列选择最佳版本..."

        # 遍历版本队列，找到第一个可用的
        for candidate_version in "${VERSION_PRIORITY[@]}"; do
            log_info "测试版本可用性: v${candidate_version}"

            # 快速测试该版本的下载URL是否可访问
            local test_url="https://github.com/SagerNet/sing-box/releases/download/v${candidate_version}/sing-box-${candidate_version}-linux-amd64.tar.gz"

            if curl -fsSL --head --connect-timeout 5 --max-time 10 "$test_url" >/dev/null 2>&1; then
                version_to_install="$candidate_version"
                log_success "✅ 选定版本: v${version_to_install}"
                break
            else
                log_warn "⏭️  版本 v${candidate_version} 不可用，尝试下一个..."
            fi
        done

        # 如果所有版本都失败
        if [[ -z "$version_to_install" ]]; then
            log_error "无法找到任何可用的 sing-box 版本"
            log_error "可能原因："
            log_error "  1. 网络连接问题"
            log_error "  2. GitHub 访问受限"
            log_error "💡 建议："
            log_error "  1. 检查网络: curl -I https://github.com"
            log_error "  2. 使用代理: export EDGEBOX_DOWNLOAD_PROXY='https://mirror.ghproxy.com/'"
            log_error "  3. 手动指定版本: export DEFAULT_SING_BOX_VERSION='1.11.15'"
            return 1
        fi
    fi

    log_info "📦 最终安装版本: v${version_to_install}"

    # ========================================
    # 第3步：系统架构检测
    # ========================================
    local system_arch
    case "$(uname -m)" in
        x86_64|amd64) system_arch="amd64" ;;
        aarch64|arm64) system_arch="arm64" ;;
        armv7*) system_arch="armv7" ;;
        *)
            log_error "不支持的系统架构: $(uname -m)"
            return 1
            ;;
    esac

    # ========================================
    # 第4步：构造下载URL（在版本最终确定后）
    # ========================================
    local filename="sing-box-${version_to_install}-linux-${system_arch}.tar.gz"
    local download_url="https://github.com/SagerNet/sing-box/releases/download/v${version_to_install}/${filename}"

    log_info "准备下载: ${filename}"
    log_warn "⚠️  注意: sing-box 1.12.x 不提供统一校验文件"
    log_warn "    将使用文件大小验证替代 SHA256 校验"

    # ========================================
    # 第5步：创建临时文件
    # ========================================
    local temp_file
    temp_file=$(mktemp) || {
        log_error "创建临时文件失败"
        return 1
    }

    # ========================================
    # 第6步：下载二进制包（带重试机制）
    # ========================================
    log_info "📥 下载 sing-box 二进制包..."

    local download_success=false
    local retry_count=0
    local max_retries=2

    while [[ $retry_count -lt $max_retries && "$download_success" != "true" ]]; do
        if [[ $retry_count -gt 0 ]]; then
            log_info "重试下载 (${retry_count}/${max_retries})..."
        fi

        if smart_download "$download_url" "$temp_file" "binary"; then
            download_success=true
            log_success "✅ 二进制包下载成功"
        else
            ((retry_count++))
            if [[ $retry_count -lt $max_retries ]]; then
                log_warn "下载失败，3秒后重试..."
                sleep 3
            fi
        fi
    done

    if [[ "$download_success" != "true" ]]; then
        log_error "❌ 下载失败（已重试 ${max_retries} 次）"

        # 尝试降级到下一个版本
        log_warn "🔄 尝试降级到备用版本..."

        local current_index=-1
        for i in "${!VERSION_PRIORITY[@]}"; do
            if [[ "${VERSION_PRIORITY[$i]}" == "$version_to_install" ]]; then
                current_index=$i
                break
            fi
        done

        # 尝试下一个版本
        if [[ $current_index -ge 0 && $((current_index + 1)) -lt ${#VERSION_PRIORITY[@]} ]]; then
            local fallback_version="${VERSION_PRIORITY[$((current_index + 1))]}"
            log_info "尝试降级版本: v${fallback_version}"

            version_to_install="$fallback_version"
            filename="sing-box-${version_to_install}-linux-${system_arch}.tar.gz"
            download_url="https://github.com/SagerNet/sing-box/releases/download/v${version_to_install}/${filename}"

            rm -f "$temp_file"
            temp_file=$(mktemp)

            if smart_download "$download_url" "$temp_file" "binary"; then
                log_success "✅ 降级版本下载成功"
            else
                log_error "❌ 降级版本也下载失败"
                rm -f "$temp_file"
                return 1
            fi
        else
            rm -f "$temp_file"
            return 1
        fi
    fi


	# ========================================
    # 第7步：文件完整性验证（增强版：大小 + SHA256）
    # ========================================
    log_info "🔍 验证文件完整性..."

    # 7.1 快速大小检查（必需，快速失败）
    local file_size
    file_size=$(stat -c%s "$temp_file" 2>/dev/null || stat -f%z "$temp_file" 2>/dev/null || echo 0)

    if [[ $file_size -lt 5242880 ]]; then  # 5MB = 5 * 1024 * 1024
        log_error "下载的文件太小 (${file_size} bytes)，可能下载失败"
        rm -f "$temp_file"
        return 1
    fi

    log_success "✅ 文件大小验证通过: $(($file_size / 1024 / 1024)) MB"

    # 7.2 SHA256完整性校验（可选，作为额外保障）
    local sha256_verified=false

    # 检查版本是否支持SHA256校验（1.12.x系列不提供统一校验文件）
    local version_major_minor
    version_major_minor=$(echo "$version_to_install" | cut -d. -f1,2)

    if [[ "$version_to_install" < "1.12.0" ]] || [[ "$version_major_minor" == "1.11" ]] || [[ "$version_major_minor" == "1.10" ]]; then
        log_info "🔐 尝试SHA256校验（版本 v${version_to_install} 支持）..."

        # 构造校验文件URL
        local checksum_filename="sing-box-${version_to_install}-checksums.txt"
        local checksum_url="https://github.com/SagerNet/sing-box/releases/download/v${version_to_install}/${checksum_filename}"
        local temp_checksum_file
        temp_checksum_file=$(mktemp) || {
            log_debug "创建临时校验文件失败，跳过SHA256校验"
        }

        if [[ -n "$temp_checksum_file" ]]; then
            # 下载校验文件（允许失败，不阻塞安装）
            if smart_download "$checksum_url" "$temp_checksum_file" "checksum" 2>/dev/null; then
                log_debug "校验文件下载成功"

                # 提取预期的SHA256哈希值
                local expected_hash
                expected_hash=$(grep "$filename" "$temp_checksum_file" | awk '{print $1}' | head -1)

                if [[ -n "$expected_hash" && ${#expected_hash} -eq 64 ]]; then
                    # 计算实际文件的SHA256哈希值
                    local actual_hash
                    actual_hash=$(sha256sum "$temp_file" | awk '{print $1}')

                    # 比对哈希值
                    if [[ "$expected_hash" == "$actual_hash" ]]; then
                        log_success "✅ SHA256校验通过"
                        log_debug "   预期: ${expected_hash:0:16}..."
                        log_debug "   实际: ${actual_hash:0:16}..."
                        sha256_verified=true
                    else
                        log_error "❌ SHA256校验失败 - 文件可能被篡改或损坏!"
                        log_error "   预期哈希: ${expected_hash:0:32}..."
                        log_error "   实际哈希: ${actual_hash:0:32}..."
                        rm -f "$temp_file" "$temp_checksum_file"
                        return 1
                    fi
                else
                    log_debug "无法从校验文件中提取有效哈希值，跳过SHA256校验"
                fi

                rm -f "$temp_checksum_file"
            else
                log_debug "校验文件下载失败（可能不存在或网络问题），跳过SHA256校验"
            fi
        fi
    else
        log_debug "版本 v${version_to_install} 不提供统一校验文件，跳过SHA256校验"
    fi

    # 7.3 验证总结
    if [[ "$sha256_verified" == "true" ]]; then
        log_success "✅ 文件完整性验证通过（大小 + SHA256）"
    else
        log_success "✅ 文件完整性验证通过（仅大小验证）"
        log_debug "SHA256校验未执行或不可用（非致命问题）"
    fi


    # ========================================
    # 第8步：解压和安装
    # ========================================
    log_info "📦 解压并安装 sing-box..."

    local temp_dir
    temp_dir=$(mktemp -d) || {
        log_error "创建临时目录失败"
        rm -f "$temp_file"
        return 1
    }

    if ! tar -xzf "$temp_file" -C "$temp_dir" 2>/dev/null; then
        log_error "解压失败"
        rm -rf "$temp_dir" "$temp_file"
        return 1
    fi

    local sing_box_binary
    sing_box_binary=$(find "$temp_dir" -name "sing-box" -type f -executable | head -1)

    if [[ -z "$sing_box_binary" ]]; then
        log_error "解压后未找到 sing-box 二进制文件"
        rm -rf "$temp_dir" "$temp_file"
        return 1
    fi

    if ! install -m 0755 "$sing_box_binary" /usr/local/bin/sing-box; then
        log_error "安装失败（复制到 /usr/local/bin 失败）"
        rm -rf "$temp_dir" "$temp_file"
        return 1
    fi

    # 清理临时文件
    rm -rf "$temp_dir" "$temp_file"

    # ========================================
    # 第9步：验证安装
    # ========================================
    if ! /usr/local/bin/sing-box version >/dev/null 2>&1; then
        log_error "sing-box 安装后验证失败"
        return 1
    fi

    local version_info
    version_info=$(/usr/local/bin/sing-box version | head -n1)
    log_success "🎉 sing-box 安装完成!"
    log_success "📌 版本信息: $version_info"

    # ========================================
    # 第10步：重新生成 Reality 密钥（如果需要）
    # ========================================
    if [[ "${REALITY_PUBLIC_KEY:-}" == "temp_public_key_will_be_replaced" ]] || \
       [[ -z "${REALITY_PUBLIC_KEY:-}" ]]; then
        log_info "🔑 使用已安装的 sing-box 重新生成 Reality 密钥..."

        if generate_reality_keys && save_config_info; then
            log_success "✅ Reality 密钥重新生成并保存成功"
        else
            log_warn "⚠️  Reality 密钥重新生成失败，将在后续步骤重试"
        fi
    fi

    return 0
}


#############################################
# Nginx 配置函数
#############################################

# 此函数用于在首次安装时，创建默认的（IP模式）Nginx stream map 配置文件
# 解决了因文件不存在而导致 Nginx 启动失败的问题
# 【修复】将此函数定义移至 configure_nginx 之前，以解决 "command not found" 错误
#############################################
# 函数：generate_initial_nginx_stream_map
# 作用：生成 Nginx 初始 stream map（IP 模式），防止首次安装时文件缺失导致 Nginx 启动失败
# 输入：无（依赖：/etc/nginx/conf.d 目录）
# 输出：/etc/nginx/conf.d/edgebox_stream_map.conf（覆盖写入）
# ANCHOR: [NGINX-STREAM-MAP]
#############################################
generate_initial_nginx_stream_map() {
    log_info "正在生成 Nginx 初始 stream map 配置文件..."
    local map_conf="/etc/nginx/conf.d/edgebox_stream_map.conf"

    # 确保目录存在
    mkdir -p "$(dirname "$map_conf")"

    cat > "$map_conf" << 'EOF'
# This file is auto-generated by the EdgeBox installer for initial setup.
# It will be overwritten by 'edgeboxctl' when switching certificate modes.

map $ssl_preread_server_name $backend_pool {
    # v4.7.0: Single-target routing (reality only; WS/CDN removed)
    # Reality fallback SNIs (matches the public domain used for Reality TLS handshake)
    ~*(microsoft\.com|apple\.com|cloudflare\.com|amazon\.com|fastly\.com)$ reality;

    # 兜底规则：未识别的 SNI 全部归 reality 入口
    default                "";
}
EOF
    log_success "Nginx 初始 stream map 已生成: $map_conf"
}


#############################################
# 函数：create_nginx_systemd_override
# 作用：为 Nginx 注入 systemd override，确保在 xray/sing-box 就绪后再启动 (已移除阻塞性检查)
# 输入：无（依赖：systemd 可用）
# 输出：/etc/systemd/system/nginx.service.d/edgebox-deps.conf
#############################################
create_nginx_systemd_override() {
    log_info "创建systemd override以强制Nginx依赖..."
    local override_dir="/etc/systemd/system/nginx.service.d"
    mkdir -p "$override_dir"
    cat > "${override_dir}/edgebox-deps.conf" << EOF
[Unit]
# Nginx must start after xray and sing-box are ready
Wants=xray.service sing-box.service
After=xray.service sing-box.service

[Service]
# REMOVED: ExecStartPre check for port 11443 to prevent timeouts if xray fails temporarily.
#          Nginx will now start even if backends are down initially, relying on standard dependencies.
EOF
    # systemctl daemon-reload # Moved to end of module 3
    log_success "Nginx服务依赖关系已建立 (移除阻塞性检查)"
}


# 配置Nginx（SNI定向 + ALPN兜底架构）- 最终修复版
# ======================== Nginx 配置与分流 ========================
#############################################
# 函数：configure_nginx
# 作用：写入 Nginx 主配置（http+stream），注入面板 passcode，生成初始 stream_map，配置依赖并验证启动
# 输入：环境变量 DASHBOARD_PASSCODE（可空）、MASTER_SUB_TOKEN（可空）
# 输出：/etc/nginx/nginx.conf、/etc/nginx/conf.d/*.conf；并尝试 (reload|restart|enable --now) nginx
# ANCHOR: [NGINX-CONFIGURE]
#############################################
configure_nginx() {
    log_info "配置Nginx（SNI定向 + ALPN兜底架构）..."

    # 备份原始配置
    if [[ -f /etc/nginx/nginx.conf ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%s)
        log_info "已备份原始Nginx配置"
    fi

    mkdir -p /etc/nginx/conf.d

    # 生成新的Nginx主配置
    cat > /etc/nginx/nginx.conf << 'NGINX_CONFIG'
# EdgeBox Nginx 配置文件 v4.7.0 (2-protocol: Reality + Hysteria2)
# 架构：SNI定向 + ALPN兜底 + 单端口复用

user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

# HTTP 服务器配置
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # v4.6.0-rc4-rc1: 必须放在 include passcode.conf 之前
    # 因为 passcode.conf 含 64-hex Cookie secret 的 map，超过默认 64 字节 bucket。
    # nginx 处理 map 时使用 "处理到该 map 时所看到的最近的 map_hash_bucket_size 值"，
    # 所以这一行必须在含长 map 值的 include 之前。
    map_hash_bucket_size 256;
    map_hash_max_size 4096;

    include /etc/nginx/conf.d/edgebox_passcode.conf;

    # 注：$pass_ok / $cookie_ok / $set_cookie 来自 edgebox_passcode.conf
    map $arg_passcode $arg_present { default 0; ~.+ 1; }
    map "$arg_present:$pass_ok" $bad_try { default 0; "1:0" 1; "1:1" 0; }
    map "$bad_try:$pass_ok:$cookie_ok" $deny_traffic { default 1; "0:1:0" 0; "0:0:1" 0; "0:1:1" 0; }

    log_format main '$remote_addr - $remote_user [$time_local] "$request_method $uri $server_protocol" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    error_log  /var/log/nginx/error.log warn;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        location = / { return 302 /traffic/; }
        # v4.0.0: 4-format subscription endpoint (plain/base64/clash/singbox)
        # The actual path /sub-<token>[.ext] is created by edgeboxctl/install.sh by renaming
        location ~ "^/sub-[a-f0-9]+$" {
            default_type "text/plain; charset=utf-8";
            add_header Cache-Control "no-store, no-cache, must-revalidate";
            root /var/www/html;
        }
        location ~ "^/sub-[a-f0-9]+\.base64$" {
            default_type "text/plain; charset=utf-8";
            add_header Cache-Control "no-store, no-cache, must-revalidate";
            root /var/www/html;
        }
        location ~ "^/sub-[a-f0-9]+\.clash$" {
            default_type "text/yaml; charset=utf-8";
            add_header Cache-Control "no-store, no-cache, must-revalidate";
            root /var/www/html;
        }
        location ~ "^/sub-[a-f0-9]+\.singbox$" {
            default_type "application/json; charset=utf-8";
            add_header Cache-Control "no-store, no-cache, must-revalidate";
            root /var/www/html;
        }
        # v4.6.0-rc4: 移除旧的 /sub location (v3 残留，仅服务 token 化前的链接)
        location ^~ /share/ {
            default_type text/plain;
            add_header Cache-Control "no-store, no-cache, must-revalidate";
            root /var/www/html;
            try_files $uri =404;
        }
        location = /_deny_traffic { internal; return 403; }
        location ^~ /traffic/ {
            error_page 418 = /_deny_traffic;
            if ($deny_traffic) { return 418; }
            add_header Set-Cookie $set_cookie;
            alias /etc/edgebox/traffic/;
            index index.html;
        }
        location ^~ /status/ {
            alias /var/www/edgebox/status/;
            add_header Content-Type "application/json; charset=utf-8";
        }
        location = /health { return 200 "OK\n"; }
    }
}

# stream 模块配置 (最终修复版 v4)
stream {
    error_log /var/log/nginx/stream.log warn;

    # 1. SNI 到初步目标的映射 (从外部文件加载)
    #    这个文件由 generate_initial_nginx_stream_map() 或 edgeboxctl 创建
    #    它会将 reality SNI 映射到对应的名字
    include /etc/nginx/conf.d/edgebox_stream_map.conf;

    # v4.7.0: Single-level SNI routing (WS/CDN removed)
    # Stream backend: reality (TCP, internal SNIs).
    # Hysteria2 runs directly on UDP/443 via sing-box; nginx doesn't touch UDP.
    map $backend_pool $final_upstream {
        reality     127.0.0.1:11443;
        default     127.0.0.1:11443; # Reality as ultimate fallback
    }

    server {
        listen 443 reuseport;
        listen [::]:443 reuseport;
        ssl_preread on;
        proxy_pass $final_upstream;
        proxy_timeout 300s;
        proxy_connect_timeout 5s;
    }
}
NGINX_CONFIG

    # 生成独立的密码 + Cookie 秘钥配置文件
    log_info "生成并注入控制面板密码 + Cookie 秘钥..."
    local passcode_conf="/etc/nginx/conf.d/edgebox_passcode.conf"
    if [[ -n "$DASHBOARD_PASSCODE" && -n "$DASHBOARD_COOKIE_SECRET" ]]; then
        cat > "$passcode_conf" << EOF
# 由 EdgeBox 自动生成于 $(date)
# 注意：DASHBOARD_COOKIE_SECRET 是机密值，泄露等同于密码泄露
# 之所以放在 nginx conf.d 是因为 nginx 必须用它做 cookie 比对

# 用户提交正确密码时，匹配为 1
map \$arg_passcode \$pass_ok {
    "${DASHBOARD_PASSCODE}" 1;
    default 0;
}

# 用户已持有正确 Cookie 时，匹配为 1
# 攻击者不知道 ${DASHBOARD_COOKIE_SECRET:0:8}... 无法伪造
map \$cookie_ebp \$cookie_ok {
    "${DASHBOARD_COOKIE_SECRET}" 1;
    default 0;
}

# 仅当 pass_ok=1 时下发 Cookie，值为秘钥本体
map \$pass_ok \$set_cookie {
    1 "ebp=${DASHBOARD_COOKIE_SECRET}; Path=/traffic/; HttpOnly; SameSite=Lax; Max-Age=86400";
    0 "";
}
EOF
        chmod 600 "$passcode_conf"
        chown root:root "$passcode_conf"
        log_success "密码 + Cookie 配置文件已生成: ${passcode_conf}"
    else
        cat > "$passcode_conf" << EOF
# [WARN] 未生成密码或 Cookie 秘钥，默认拒绝所有访问
map \$arg_passcode \$pass_ok { default 0; }
map \$cookie_ebp \$cookie_ok { default 0; }
map \$pass_ok \$set_cookie { default ""; }
EOF
        chmod 600 "$passcode_conf"
        chown root:root "$passcode_conf"
        log_warn "DASHBOARD_PASSCODE 或 COOKIE_SECRET 为空，面板访问将被默认拒绝。"
    fi
    
    # 【调用修复】现在此函数定义在前面，可以安全调用
    generate_initial_nginx_stream_map
    
    # 创建systemd override
    create_nginx_systemd_override

    # v4.0.0: subscription path rewriting no longer needed - the nginx config uses
    # regex locations ^/sub-[a-f0-9]+(\..*)?$ that match any token.
	
	# 确保已启用 stream 动态模块（Debian/Ubuntu 系）
    if [[ -f /usr/share/nginx/modules-available/mod-stream.conf ]]; then
        mkdir -p /etc/nginx/modules-enabled
        ln -sfn /usr/share/nginx/modules-available/mod-stream.conf \
                /etc/nginx/modules-enabled/50-mod-stream.conf
    # 若没有 modules-available，则直接写一份启用文件
    elif [[ -f /usr/lib/nginx/modules/ngx_stream_module.so || -f /usr/lib64/nginx/modules/ngx_stream_module.so ]]; then
        mkdir -p /etc/nginx/modules-enabled
        printf 'load_module modules/ngx_stream_module.so;\n' \
            > /etc/nginx/modules-enabled/50-mod-stream.conf
    fi

    # 验证Nginx配置并智能重载/启动（用退出码判断，避免 grep 误判）
    log_info "验证Nginx配置..."
    set +e
    _nginx_test_out="$(nginx -t 2>&1)"
    _nginx_rc=$?
    set -e
    if [ "${_nginx_rc}" -eq 0 ]; then
        log_success "Nginx配置验证通过"
        if systemctl is-active --quiet nginx 2>/dev/null; then
            if systemctl reload nginx 2>/dev/null; then
                log_success "Nginx 已重载新配置"
            else
                log_warn "Nginx reload 失败，尝试重启..."
                systemctl restart nginx
                log_success "Nginx 已重启"
            fi
        else
            log_info "Nginx 尚未启动，正在启动服务..."
            if systemctl start nginx 2>/dev/null; then
                log_success "Nginx 已成功启动"
            else
                log_error "Nginx 启动失败"
                systemctl status nginx --no-pager -l
                return 1
            fi
        fi
    else
        log_error "Nginx配置验证失败，请检查 /etc/nginx/nginx.conf 和 /etc/nginx/conf.d/"
        echo "${_nginx_test_out}"
        return 1
    fi

    log_success "Nginx配置文件创建完成"
    return 0
}

# === Patch C: 监听检测增强 (辅助函数) ===
wait_listen() {  # usage: wait_listen 11443  (v4.7.0: only reality backend)
  local timeout=120 start ok p
  start=$(date +%s)
  log_info "等待端口监听: $@ (超时: ${timeout}s)..."
  while true; do
    ok=1
    # 统一输出：无表头(-H)，所有TCP(-t)，所有状态(-a)
    local ss_output
    ss_output=$(ss -Htan 2>/dev/null || netstat -tan 2>/dev/null)

    for p in "$@"; do
      # 同时兼容 IPv4/IPv6 的 LISTEN 行
      if echo "$ss_output" | awk -v P=":$p" '
          /LISTEN/ && index($0, P) { found=1; exit 0 }
          END { exit (found ? 0 : 1) }
        '; then
        : # 该端口已监听
      else
        ok=0
      fi
    done

    [[ $ok -eq 1 ]] && { log_info "所有端口已监听: $*"; return 0; }
    (( $(date +%s) - start >= timeout )) && { log_error "等待端口监听超时 (${timeout}s)! 未监听端口: $*"; return 1; }
    sleep 1
  done
}


# === Patch B: 统一强制 Xray unit (辅助函数) - 加强清理版 v3 (最终修复) ===
create_or_update_xray_unit() {
  log_info "创建/更新 Xray systemd unit (v3)..."
  local unit=/etc/systemd/system/xray.service
  local old_unit_lib=/lib/systemd/system/xray.service
  local old_unit_usr_lib=/usr/lib/systemd/system/xray.service # <-- RHEL/Fedora 路径
  local old_unit_vendor=/usr/lib/systemd/system/xray.service # <-- 新增：另一个常见的 vendor 路径
  local override_dir=/etc/systemd/system/xray.service.d

  # <<< --- 终极清理 --- >>>
  log_info "强制停止、禁用并移除所有已知的 xray.service 文件及覆盖配置..."
  systemctl stop xray.service >/dev/null 2>&1 || true
  systemctl disable xray.service >/dev/null 2>&1 || true
  
  # <<< --- 修复：添加所有已知路径 --- >>>
  rm -f "$unit" "$old_unit_lib" "$old_unit_vendor" /etc/systemd/system/multi-user.target.wants/xray.service
  
  if [[ -d "$override_dir" ]]; then
      log_info "发现并移除旧的 systemd 覆盖目录: $override_dir"
      rm -rf "$override_dir"
  fi

  log_info "执行 daemon-reload 和 reset-failed (第一次)..."
  systemctl daemon-reload
  systemctl reset-failed xray.service >/dev/null 2>&1 || true
  sleep 1

  mkdir -p /usr/local/etc/xray 2>/dev/null || true
  ln -sfn /etc/edgebox/config/xray.json /usr/local/etc/xray/config.json

  cat >"$unit" <<'UNIT'
[Unit]
Description=Xray Service (EdgeBox)
Documentation=https://github.com/XTLS/Xray-core
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=simple
User=root
Group=root
# 确保 PATH 完整，避免某些发行版最小化 PATH 导致 ExecStart 里子进程找不到基础命令
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin"
# 明确工作目录，避免相对路径/权限意外
WorkingDirectory=/
# 确认二进制存在且可执行（有些场景你卸载/重装瞬间会掉）
ExecStartPre=/usr/bin/test -x /usr/local/bin/xray
ExecStart=/usr/local/bin/xray run -c /etc/edgebox/config/xray.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

  log_info "再次执行 daemon-reload 和 reenable (第二次)..."
  systemctl daemon-reload
  systemctl unmask xray.service  >/dev/null 2>&1 || true  # [新增] 清理历史 mask 残留
  # <<< --- 新增：使用 reenable 强制刷新链接 --- >>>
  systemctl reenable "$unit" >/dev/null 2>&1 || systemctl enable "$unit" >/dev/null 2>&1 || log_warn "启用 xray 服务失败"

  local _effective_user
  _effective_user="$(systemctl show -p User --value xray 2>/dev/null)"
  log_info "当前 systemd 识别的 xray.service 运行用户: ${_effective_user}"
  if [[ "$_effective_user" != "root" ]]; then
      log_error "FATAL: systemd 仍未识别到 User=root (识别为: $_effective_user)，安装无法继续。"
      log_error "请手动清理所有 systemd 'xray.service' 文件 (位于 /etc, /lib, /usr/lib) 后重试。"
      return 1
  fi
}

# // ANCHOR: [FUNC-CONFIGURE_XRAY]
#############################################
# 函数：configure_xray
# 作用：配置Xray服务 (原子写入 + 验证) - 已应用 Patch A, B, C 及顺序修复
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
#############################################
configure_xray() {
  log_info "配置Xray多协议服务..."

  # <<< 确保日志目录存在且权限正确（跟随 unit 的运行用户） >>>
  mkdir -p /var/log/xray 2>/dev/null || true

  # 读取 systemd unit 的运行用户/组；未设置时默认 root
  local _x_user _x_group
  _x_user="$(systemctl show -p User --value xray 2>/dev/null)"; _x_user="${_x_user:-root}"
  _x_group="$(systemctl show -p Group --value xray 2>/dev/null)"
  [[ -z "$_x_group" ]] && _x_group="$(id -gn "$_x_user" 2>/dev/null || echo root)"

  # 调整目录与日志文件权限
  chown "${_x_user}:${_x_group}" /var/log/xray 2>/dev/null || true
  chmod 0755 /var/log/xray 2>/dev/null || true
  touch /var/log/xray/access.log /var/log/xray/error.log 2>/dev/null || true
  chown "${_x_user}:${_x_group}" /var/log/xray/access.log /var/log/xray/error.log 2>/dev/null || true
  chmod 0644 /var/log/xray/access.log /var/log/xray/error.log 2>/dev/null || true

  local f="${CONFIG_DIR}/server.json"

  # ① 预加载证书路径（仅变量为空时）
  if [[ -z ${CERT_PEM:-} || -z ${CERT_KEY:-} ]]; then
    if [[ -r "$f" ]]; then
      local _pem _key
      _pem="$(jq -r '.cert.cert_pem // empty' "$f" 2>/dev/null || true)"
      _key="$(jq -r '.cert.key_pem  // empty' "$f" 2>/dev/null || true)"
      [[ -n "$_pem" ]] && CERT_PEM="$_pem"
      [[ -n "$_key" ]] && CERT_KEY="$_key"
      # 兼容旧变量名
      [[ -z ${KEY_PEM:-} && -n ${CERT_KEY:-} ]] && KEY_PEM="$CERT_KEY"
      export CERT_PEM CERT_KEY KEY_PEM
      log_info "从 server.json 预加载证书路径成功"
    fi
  fi

  # ② 检查并兜底证书路径
  [[ -z ${CERT_PEM:-} ]] && CERT_PEM="${CERT_DIR}/current.pem"
  [[ -z ${CERT_KEY:-} ]] && CERT_KEY="${CERT_DIR}/current.key"
  export CERT_PEM CERT_KEY

  # ③ 收集必要变量 (v4.7.0: 2-protocol)
  local required_vars=(
    "UUID_VLESS_REALITY"
    "REALITY_PRIVATE_KEY" "REALITY_SHORT_ID" "PASSWORD_HYSTERIA2"
    "CERT_PEM" "CERT_KEY" "REALITY_SNI"
  )
  log_info "检查必要变量设置..."
  local missing_vars=()
  for var in "${required_vars[@]}"; do
    [[ -z "${!var:-}" ]] && missing_vars+=("$var")
  done
  if (( ${#missing_vars[@]} )); then
    log_info "尝试从 server.json 重新加载必要变量..."
    if [[ -r "$f" ]]; then
      eval "$(
        jq -r '
          "UUID_VLESS_REALITY=\(.uuid.vless.reality // \"\")\n" +
          "PASSWORD_HYSTERIA2=\(.password.hysteria2 // \"\")\n" +
          "REALITY_PRIVATE_KEY=\(.reality.private_key // \"\")\n" +
          "REALITY_SHORT_ID=\(.reality.short_id // \"\")\n" +
          "REALITY_SNI=\(.reality.sni // \"www.microsoft.com\")\n"
        ' "$f" 2>/dev/null
      )"
    fi
  fi

  # ④ 最终核对
  missing_vars=()
  for var in "${required_vars[@]}"; do
    [[ -z "${!var:-}" ]] && missing_vars+=("$var")
  done
  if (( ${#missing_vars[@]} )); then
    log_error "缺少生成Xray配置的必要变量: ${missing_vars[*]}"
    return 1
  fi
  log_success "✓ 所有必要变量已设置"

  # ⑤ 校验证书文件
  log_info "检查证书文件是否存在且可读..."
  local cert_files_ok=true
  [[ ! -r "$CERT_PEM" ]] && { log_error "证书不可读: $CERT_PEM"; cert_files_ok=false; }
  [[ ! -r "$CERT_KEY" ]] && { log_error "密钥不可读: $CERT_KEY"; cert_files_ok=false; }

  if [[ "$cert_files_ok" != "true" ]]; then
    local cert_mode
    cert_mode=$(cat "${CONFIG_DIR}/cert_mode" 2>/dev/null || echo "self-signed")
    if [[ "$cert_mode" == "self-signed" ]]; then
      log_warn "证书异常，尝试重新生成自签名证书..."
      if generate_self_signed_cert; then
        log_success "自签名证书已重新生成"
        # 重新加载证书路径变量以防万一
        CERT_PEM="${CERT_DIR}/current.pem"
        CERT_KEY="${CERT_DIR}/current.key"
      else
        log_error "自签名证书重新生成失败"
        return 1
      fi
    else
      log_error "证书异常，且非自签名模式，无法自动修复"
      return 1
    fi
  fi
  log_success "✓ 证书和密钥文件可用"

  # ⑥ 验证与落盘（原子写入） - 使用更稳健的 heredoc 捕获与 jq 内插
  log_info "使用 jq 生成 Xray 配置（临时文件）..."
  local xray_tmp="${CONFIG_DIR}/xray.tmp.json"

  # <<< --- 证书验证 --- >>>
  log_info "执行更严格的证书与密钥匹配验证..."
# NEW: 使用公钥指纹比对（RSA/EC 通用），替代过去的 modulus MD5
local cert_pub_md5 key_pub_md5 match_ok=false
cert_pub_md5="$(openssl x509 -in "$CERT_PEM" -noout -pubkey \
  | openssl pkey -pubin -outform der | md5sum | awk '{print $1}')"
key_pub_md5="$(openssl pkey -in "$CERT_KEY" -pubout -outform der \
  | md5sum | awk '{print $1}')"

if [[ -n "$cert_pub_md5" && -n "$key_pub_md5" && "$cert_pub_md5" == "$key_pub_md5" ]]; then
    log_success "✓ 证书与私钥匹配（公钥指纹）"
    match_ok=true
else
    log_error "✗ 证书与私钥不匹配（公钥指纹）"
    log_debug "Cert PubKey MD5: $cert_pub_md5"
    log_debug "Key  PubKey MD5: $key_pub_md5"
    match_ok=false
fi

  if [[ "$match_ok" != "true" ]]; then
      log_warn "证书验证失败，尝试重新生成自签名证书..."
      if generate_self_signed_cert; then
          log_success "自签名证书已重新生成，将继续..."
          # 重新加载证书路径变量以防万一
          CERT_PEM="${CERT_DIR}/current.pem"
          CERT_KEY="${CERT_DIR}/current.key"
      else
          log_error "自签名证书重新生成失败，中止 Xray 配置"
          return 1
      fi
  fi
  # <<< --- 验证结束 --- >>>


  # 1) 用命令替换方式捕获 jq 程序体
  JQ_PROGRAM=$(cat <<'EOF'
{
  "log": { "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log", "loglevel": "info" },
  "inbounds": [
    {
      "tag": "vless-reality",
      "listen": "127.0.0.1",
      "port": 11443,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": $uuid_reality, "flow": "xtls-rprx-vision" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "\($r_sni):443",
          "serverNames": [ $r_sni ],
          "privateKey": $r_priv,
          "shortIds": [ $r_short ]
        }
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": {} },
    { "tag": "block",  "protocol": "blackhole", "settings": {} }
  ],
  "dns": {
    "servers": [ "8.8.8.8", "1.1.1.1",
      { "address": "https://1.1.1.1/dns-query" },
      { "address": "https://8.8.8.8/dns-query" } ],
    "queryStrategy": "UseIP"
  },
  "routing": {
    "domainStrategy": "UseIP",
    "rules": [ { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" } ]
  },
  "policy": { "handshake": 4, "connIdle": 30 }
}
EOF
)

  # 2) 调用 jq 生成临时配置文件
  jq_exit_code=0
  jq -n \
      --arg uuid_reality "$UUID_VLESS_REALITY" \
      --arg r_priv       "$REALITY_PRIVATE_KEY" \
      --arg r_short      "$REALITY_SHORT_ID" \
      --arg r_sni        "$REALITY_SNI" \
      --arg cert_pem     "$CERT_PEM" \
      --arg cert_key     "$CERT_KEY" \
      "$JQ_PROGRAM" > "$xray_tmp" 2>/tmp/xray_jq.err || jq_exit_code=$? # 捕获 jq 的退出码

  # === 新增的关键错误检查 ===
  if [[ $jq_exit_code -ne 0 || ! -s "$xray_tmp" ]]; then
      log_error "jq 命令执行失败(退出码: $jq_exit_code) 或生成的临时文件 '$xray_tmp' 为空！"
      # 尝试显示 jq 的错误输出（如果存在）
      if [[ -f /tmp/xray_jq.err ]]; then
          log_error "jq 的错误输出 (/tmp/xray_jq.err):"
          cat /tmp/xray_jq.err | sed 's/^/  [jq_err] /' | tee -a "$LOG_FILE"
      fi
      # 清理并返回失败
      rm -f "$xray_tmp" /tmp/xray_jq.err
      return 1 # 明确返回失败，阻止后续步骤
  fi
  # 如果 jq 成功，清理临时的错误日志文件
  rm -f /tmp/xray_jq.err
  # === 检查结束 ===

  # 3) 验证与落盘
  log_info "验证生成的 Xray 配置..."
  if ! /usr/local/bin/xray -test -config "$xray_tmp" >/dev/null 2>&1; then
      log_error "Xray 配置验证失败 (xray -test)"
      /usr/local/bin/xray -test -config "$xray_tmp" || true # 显示详细错误
      rm -f "$xray_tmp"
      return 1
  fi

  # 将临时文件移动到最终位置
  mv "$xray_tmp" "${CONFIG_DIR}/xray.json"

  # === 移动到此处并修正的权限设置块 ===
  log_info "设置 Xray 配置和证书文件权限..."
  chmod 600 "${CONFIG_DIR}/xray.json" || log_warn "无法设置 xray.json 权限 (chmod 644)"
  chown root:root "${CONFIG_DIR}/xray.json" || log_warn "无法设置 xray.json 所有权 (chown root:root)"
  # 再次确认证书权限
  chown root:$(id -gn nobody 2>/dev/null || echo nogroup) "${CERT_DIR}"/current.* 2>/dev/null || true
  # <<< --- 修复：确保私钥权限为 644 (全局可读) --- >>>
  chmod 644 "${CERT_DIR}/current.pem" 2>/dev/null || true
  chmod 600 "${CERT_DIR}/current.key" 2>/dev/null || true 
  # 输出权限到日志文件调试
  log_debug "权限设置后状态:"
  ls -l "${CONFIG_DIR}/xray.json" "${CERT_DIR}/current.pem" "${CERT_DIR}/current.key" >> "$LOG_FILE" 2>&1
  # === 权限设置块结束 ===

  log_success "Xray 配置文件创建并验证成功（${CONFIG_DIR}/xray.json）"

  # ⑦ 写入并启用 systemd 服务 (调用 Patch B 的函数)
  create_or_update_xray_unit # <-- 调用 Patch B 的 unit 创建函数
  
# [ANCHOR:FUNC-CONFIGURE_XRAY-END]
log_info "Xray 配置与 unit 已更新；统一在模块收尾阶段启动与验证。"
return 0
} # configure_xray 函数结束

# // ANCHOR: [FUNC-CONFIGURE_SING_BOX]
#############################################
# 函数：configure_sing_box
# 作用：配置sing-box服务 (原子写入 + 验证)
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
#############################################
configure_sing_box() {
    log_info "配置sing-box服务..."

    # 验证必要变量
    if [[ -z "$PASSWORD_HYSTERIA2" ]]; then
        log_error "sing-box必要配置变量缺失"
        # Attempt reload (best effort)
         if [[ -f "${CONFIG_DIR}/server.json" ]]; then
             PASSWORD_HYSTERIA2="$(jq -r '.password.hysteria2 // empty' "${CONFIG_DIR}/server.json" 2>/dev/null)"
             if [[ -z "$PASSWORD_HYSTERIA2" ]]; then
                log_error "从 server.json 加载后仍缺少变量"
                return 1
             fi
         else
            return 1
         fi
    fi
    log_success "✓ sing-box 必要变量已设置"

    mkdir -p /var/log/edgebox 2>/dev/null || true
    log_info "生成sing-box配置文件 (使用 jq 写入临时文件)..."
    local sbox_tmp="${CONFIG_DIR}/sing-box.json.tmp"
    if ! jq -n \
      --arg hy2_pass "$PASSWORD_HYSTERIA2" \
      --arg cert_pem "${CERT_DIR}/current.pem" \
      --arg cert_key "${CERT_DIR}/current.key" \
      '{
        "log": { "level": "info", "timestamp": true },
        "inbounds": [
          { "type": "hysteria2", "tag": "hysteria2-in", "listen": "0.0.0.0", "listen_port": 443, "users": [ { "password": $hy2_pass } ], "tls": { "enabled": true, "alpn": ["h3"], "certificate_path": $cert_pem, "key_path": $cert_key } }
        ],
        "outbounds": [
          { "type": "direct", "tag": "direct" },
          { "type": "block",  "tag": "block" }
        ],
        "route": {
          "rules": [
            {
              "ip_cidr": [
                "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "169.254.0.0/16", "100.64.0.0/10",
                "::1/128", "fc00::/7", "fe80::/10", "fd00::/8"
              ],
              "outbound": "block"
            }
          ],
          "final": "direct"
        }
      }' > "$sbox_tmp"; then
      log_error "使用 jq 生成 sing-box.json 失败"
      rm -f "$sbox_tmp"
      return 1
    fi

    # --- ATOMIC WRITE + VALIDATION ---
    log_info "验证生成的 sing-box 配置..."
    if ! sing-box check -c "$sbox_tmp" >/dev/null 2>&1; then
        log_warn "sing-box 配置校验失败，尝试移除不兼容字段后重试..."
        # Fallback for older versions
        local sbox_tmp2=$(mktemp)
        if jq '(.inbounds[] | select(.type=="hysteria2")) -= {masquerade}' "$sbox_tmp" > "$sbox_tmp2" 2>/dev/null; then
            if sing-box check -c "$sbox_tmp2" >/dev/null 2>&1; then
                log_info "移除字段后校验通过。"
                mv "$sbox_tmp2" "$sbox_tmp"
            else
                log_error "移除字段后校验仍然失败！"
                sing-box check -c "$sbox_tmp2" # Show error
                rm -f "$sbox_tmp" "$sbox_tmp2"
                return 1
            fi
        else
            rm -f "$sbox_tmp" "$sbox_tmp2"
            log_error "移除不兼容字段失败。"
            return 1
        fi
    fi
    mv "$sbox_tmp" "${CONFIG_DIR}/sing-box.json"
    log_success "Sing-box 配置文件创建并验证成功。"
    # --- END ATOMIC WRITE + VALIDATION ---

    chmod 600 "${CONFIG_DIR}/sing-box.json"
    chown root:root "${CONFIG_DIR}/sing-box.json"
    # 注: sing-box 服务以 root 运行，所以 600 不影响其读取

    # 证书检查与权限 (No change needed here)
    log_info "检查并创建证书符号链接..."
    if [[ ! -L "${CERT_DIR}/current.pem" ]] || [[ ! -L "${CERT_DIR}/current.key" ]]; then
        if [[ -f "${CERT_DIR}/self-signed.pem" ]] && [[ -f "${CERT_DIR}/self-signed.key" ]]; then
            ln -sf "${CERT_DIR}/self-signed.pem" "${CERT_DIR}/current.pem"
            ln -sf "${CERT_DIR}/self-signed.key" "${CERT_DIR}/current.key"
            log_success "证书符号链接已创建"
        else
            log_warn "自签名证书不存在，可能在后续步骤生成"
        fi
    fi
    if [[ -f "${CERT_DIR}/self-signed.pem" ]]; then
        chmod 644 "${CERT_DIR}"/*.pem 2>/dev/null || true
        chmod 600 "${CERT_DIR}"/*.key 2>/dev/null || true # Corrected from 600 to 640/600 based on previous cert logic
        log_success "证书权限已设置"
    fi

    # 创建正确的 systemd 服务文件 (No change needed here)
    log_info "创建sing-box系统服务..."
cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE
NoNewPrivileges=true
LimitNOFILE=1048576

# 只保留一条 ExecStart（任选固定路径即可）
ExecStart=/usr/local/bin/sing-box run -c /etc/edgebox/config/sing-box.json

# 先向 $MAINPID 发送 HUP；若 MAINPID 不可用，再用进程名兜底
ExecReload=+/bin/sh -c 'kill -HUP $MAINPID || pkill -HUP -x sing-box'

Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF


    # systemctl daemon-reload # Moved to end of module 3
    # systemctl enable sing-box >/dev/null 2>&1 # Moved to end of module 3

    log_success "sing-box服务文件创建完成（配置路径: ${CONFIG_DIR}/sing-box.json）"

	# Cert permissions repeated? Keep the stricter one if needed. Let's keep the block from generate_self_signed_cert
    # chmod 755 "${CERT_DIR}" 2>/dev/null || true
    # chmod 644 "${CERT_DIR}"/*.pem 2>/dev/null || true
    # chmod 640 "${CERT_DIR}"/*.key 2>/dev/null || true
    # chown root:nobody "${CERT_DIR}"/*.key 2>/dev/null || true # group should match generate_self_signed_cert

    return 0
}


#############################################
# 订阅生成函数
#############################################

# 生成订阅链接（支持IP模式和域名模式）
#############################################
# 函数：generate_subscription
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GENERATE_SUBSCRIPTION]
#############################################
generate_subscription() {
    log_info "生成协议订阅链接 (v4.0.0 unified generator)..."
    # Delegate to lib/subscription.sh:eb_gen_subscription
    # That function handles all 3 protocols, 4 formats, atomic publish, and web symlinks
    if eb_gen_subscription; then
        log_success "订阅生成完成"
        return 0
    else
        log_error "订阅生成失败"
        return 1
    fi
}

#############################################
# 服务启动和验证函数
#############################################


# 启动所有服务并验证（增强幂等性）
#############################################
# 函数：start_and_verify_services
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-START_AND_VERIFY_SERVICES]
#############################################
start_and_verify_services() {
    log_info "启动并验证服务（幂等性保证）..."

    local services=("xray" "sing-box" "nginx")
    local failed_services=()

    for service in "${services[@]}"; do
        # 使用增强的服务启动检查
        if ensure_service_running "$service"; then
            log_success "$service 服务已正常运行"
        else
            log_error "$service 服务启动失败"
            failed_services+=("$service")
        fi
    done

    # 端口监听验证
    verify_critical_ports

    if [[ ${#failed_services[@]} -eq 0 ]]; then
        log_success "所有服务已正常运行"
        return 0
    else
        log_error "以下服务运行异常: ${failed_services[*]}"
        return 1
    fi
}

# === BEGIN PATCH: 关键端口自检 ===
#############################################
# 函数：verify_critical_ports
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-VERIFY_CRITICAL_PORTS]
#############################################
verify_critical_ports() {
  log_info "检查关键端口监听状态..."
  local ok=true
  ss -tln | grep -q ':443 '    && log_success "TCP 443 (Nginx) 监听正常" || { log_warn "TCP 443 未监听"; ok=false; }
  ss -uln | grep -q ':443 '    && log_success "UDP 443 (Hysteria2) 监听正常" || { log_warn "UDP 443 未监听"; ok=false; }
  $ok
}
# === END PATCH ===


# [新增函数] 确保服务运行状态（完全幂等）
#############################################
# 函数：ensure_service_running
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-ENSURE_SERVICE_RUNNING]
#############################################
ensure_service_running() {
    local service="$1"
    local max_attempts=3
    local attempt=0

    log_info "确保服务运行状态: $service"
	
	# 兜底解除 mask，并确保二进制可执行（尤其是 xray）
systemctl unmask "$service" >/dev/null 2>&1 || true
[[ "$service" = "xray" ]] && chmod +x /usr/local/bin/xray >/dev/null 2>&1 || true

    while [[ $attempt -lt $max_attempts ]]; do
        # 重新加载systemd配置（幂等）
        systemctl daemon-reload >/dev/null 2>&1

        # 启用服务（幂等）
        if systemctl enable "$service" >/dev/null 2>&1; then
            log_info "✓ $service 服务已启用"
        else
            log_warn "⚠ $service 服务启用失败"
        fi

        # 检查服务状态
        if systemctl is-active --quiet "$service"; then
            log_success "✓ $service 已在运行"
            return 0
        fi

        # 尝试启动服务
        log_info "启动 $service 服务 (尝试 $((attempt + 1))/$max_attempts)"

        if systemctl start "$service" >/dev/null 2>&1; then
            # 等待启动完成
            sleep 3

            # 验证启动结果
            if systemctl is-active --quiet "$service"; then
                log_success "✓ $service 服务启动成功"
                return 0
            else
                log_warn "⚠ $service 启动命令成功但服务未激活"
            fi
        else
            log_warn "⚠ $service 启动命令失败"
        fi

        ((attempt++))

        # 如果不是最后一次尝试，显示错误信息并重试
        if [[ $attempt -lt $max_attempts ]]; then
            log_warn "$service 启动失败，将重试..."
            # 获取服务状态信息用于调试
            systemctl status "$service" --no-pager -l >/dev/null 2>&1 || true
            # 停止服务准备重试
            systemctl stop "$service" >/dev/null 2>&1 || true
            sleep 2
        fi
    done

    # 最终失败处理
    log_error "✗ $service 服务在 $max_attempts 次尝试后仍无法启动"

    # 输出详细错误信息用于调试
    log_error "服务状态详情:"
    systemctl status "$service" --no-pager -l 2>&1 | head -10 | while read -r line; do
        log_error "  $line"
    done

    return 1
}

# [新增函数] 验证端口监听状态
# --- 统一的端口监听检测 ---
#############################################
# 函数：verify_port_listening
# 作用：检测端口监听状态
# 输入：$1=端口；$2=协议 tcp|udp
# 输出：返回码 0/1（仅检测，不打印）
# ANCHOR: [PORT-CHECK]
#############################################
verify_port_listening() {
  local port="$1" proto="$2"  # proto = tcp|udp
  if [[ "$proto" == "udp" ]]; then
    ss -uln 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${port}($|[^0-9])"
  else
    ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}($|[^0-9])"
  fi
}

# 使用示例（安装阶段）：
verify_port_listening 443 tcp  && log_success "端口 443 正在监听" || log_warn "端口 443 未在监听"
verify_port_listening 80  tcp  && log_success "端口 80 正在监听"  || log_warn "端口 80 未在监听"


# // ANCHOR: [MODULE3]
#############################################
# 函数：execute_module3
# 作用：安装/配置 Xray & sing-box & Nginx，生成订阅并启动验证 (优化systemd调用)
# 输入：无（依赖：其他 install_/configure_ 函数已定义）
# 输出：日志/订阅文件；启动服务并校验
#############################################
execute_module3() {
    log_info "======== 开始执行模块3：服务安装配置 ========"
	ensure_reverse_ssh   # 一进模块就兜底拉起救生索（若已启用）

    # 任务1：安装Xray
    if install_xray; then
        log_success "✓ Xray安装完成"
    else
        log_error "✗ Xray安装失败"
        return 1
    fi

    # 任务2：安装sing-box
    if install_sing_box; then
        log_success "✓ sing-box安装完成"
    else
        log_error "✗ sing-box安装失败"
        return 1
    fi

	# === 安装期一次性 SNI 选择（用于 Xray Reality） ===
    if choose_initial_sni_once; then
      log_info "REALITY_SNI = ${REALITY_SNI}"
    else
      log_warn "SNI 选择失败，将使用默认 REALITY_SNI=${REALITY_SNI:-www.microsoft.com}"
    fi

    # 任务3：配置Xray (先配置后端服务)
    if configure_xray; then
        log_success "✓ Xray配置完成"
    else
        log_error "✗ Xray配置失败"
        return 1
    fi

    # 任务4：配置sing-box (再配置后端服务)
    if configure_sing_box; then
        log_success "✓ sing-box配置完成"
    else
        log_error "✗ sing-box配置失败"
        return 1
    fi

    # 任务5：配置Nginx (最后配置前端代理)
    if configure_nginx; then
        log_success "✓ Nginx配置完成"
    else
        log_error "✗ Nginx配置失败"
        return 1
    fi

    # --- 任务6：生成订阅链接 (保持不变, 位置很重要) ---
    if generate_subscription; then
        log_success "✓ 订阅链接生成完成"
    else
        log_error "✗ 订阅链接生成失败"
        return 1
    fi
    # --- 订阅链接生成结束 ---

    # --- 移动到此处的 Systemd 操作 ---
    log_info "Reloading systemd daemon and enabling services..."
    systemctl daemon-reload
    systemctl enable xray >/dev/null 2>&1 || log_warn "Failed to enable xray"
    systemctl enable sing-box >/dev/null 2>&1 || log_warn "Failed to enable sing-box"
    systemctl enable nginx >/dev/null 2>&1 || log_warn "Failed to enable nginx"
    log_success "Systemd reload and service enabling complete."
    # --- Systemd 操作结束 ---

	log_info "启动前快速端口自检..."
    verify_port_listening 80  tcp || log_warn "80/TCP 未监听 (若仅走443可忽略)"
    verify_port_listening 443 tcp || log_warn "443/TCP 未监听 (Nginx 未就绪?)"
    verify_port_listening 443 udp || log_warn "443/UDP 未监听 (Hysteria2 未开启或失败)"

    # 任务7：启动和验证服务
    if start_and_verify_services; then
        log_success "✓ 服务启动验证通过"
    else
        log_error "✗ 服务启动验证失败"
        return 1
    fi

    log_success "======== 模块3执行完成 ========"
    log_info "已完成："
    log_info "├─ Xray 服务（Reality）"
    log_info "├─ sing-box服务（Hysteria2）"
    log_info "├─ Nginx分流代理（SNI+ALPN架构）"
    log_info "├─ 订阅链接生成（Reality + Hysteria2）"
    # 读取最新的密码显示，如果DASHBOARD_PASSCODE变量没更新，从文件读一次
    local final_passcode="${DASHBOARD_PASSCODE:-}"
    if [[ -z "$final_passcode" && -f "${CONFIG_DIR}/server.json" ]]; then
        final_passcode=$(jq -r '.dashboard_passcode // "[读取失败]"' "${CONFIG_DIR}/server.json" 2>/dev/null || echo "[读取失败]")
    fi
    log_info "├─ 控制面板密码: ${final_passcode:-未设置}"
    log_info "└─ 所有服务运行验证"

    return 0
}

#############################################
# 模块3导出函数（供其他模块调用）
#############################################

# 重新启动所有服务
#############################################
# 函数：restart_all_services
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-RESTART_ALL_SERVICES]
#############################################
restart_all_services() {
    log_info "重新启动EdgeBox所有服务..."

    local services=(xray sing-box nginx)
    local success_count=0

    for service in "${services[@]}"; do
        if reload_or_restart_services "$service"; then
            log_success "✓ $service 重启成功"
            success_count=$((success_count + 1))
        else
            log_error "✗ $service 重启失败"
            systemctl status "$service" --no-pager -l
        fi
    done

    if [[ $success_count -eq ${#services[@]} ]]; then
        log_success "所有服务重启完成"
        return 0
    else
        log_error "部分服务重启失败 ($success_count/${#services[@]})"
        return 1
    fi
}

# 检查服务状态
#############################################
# 函数：check_services_status
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CHECK_SERVICES_STATUS]
#############################################
check_services_status() {
    log_info "检查EdgeBox服务状态..."

    local services=(xray sing-box nginx)
    local running_count=0

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            local status=$(systemctl is-active "$service")
            log_success "✓ $service: $status"
            running_count=$((running_count + 1))
        else
            local status=$(systemctl is-active "$service")
            log_error "✗ $service: $status"
        fi
    done

    log_info "服务状态汇总: $running_count/${#services[@]} 正在运行"
    return $((${#services[@]} - running_count))
}

# 重新生成订阅（用于配置更新后）
#############################################
# 函数：regenerate_subscription
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-REGENERATE_SUBSCRIPTION]
#############################################
regenerate_subscription() {
    log_info "重新生成订阅链接..."

    if generate_subscription; then
        log_success "订阅链接已更新"
        return 0
    else
        log_error "订阅链接更新失败"
        return 1
    fi
}

#############################################
# 模块3完成标记
#############################################

log_success "模块3：服务安装配置 - 加载完成"
log_info "可用函数："
log_info "├─ execute_module3()           # 执行模块3所有任务"
log_info "├─ restart_all_services()     # 重启所有服务"
log_info "├─ check_services_status()    # 检查服务状态"
log_info "└─ regenerate_subscription()  # 重新生成订阅"



#############################################
# EdgeBox 企业级多协议节点部署脚本 v4.7.0
# 模块4：Dashboard后端脚本生成
#
# 功能说明：
# - 生成完整的dashboard-backend.sh脚本
# - 统一数据采集和聚合逻辑
# - 对齐控制面板数据口径
# - 支持定时任务和手动执行
# - 生成dashboard.json供前端使用
#############################################

#############################################
# Dashboard后端脚本生成函数
#############################################

# 创建完整的dashboard-backend.sh脚本
#############################################
# 函数：create_dashboard_backend
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CREATE_DASHBOARD_BACKEND]
#############################################
create_dashboard_backend() {
    log_info "生成Dashboard后端数据采集脚本..."

    # 确保脚本目录存在
    mkdir -p "${SCRIPTS_DIR}"

    # 生成完整的dashboard-backend.sh脚本
    _install_script "${SCRIPTS_DIR}/dashboard-backend.sh" "dashboard-backend.sh" || return 1

    # 设置脚本权限
    chmod +x "${SCRIPTS_DIR}/dashboard-backend.sh"

    log_success "Dashboard后端脚本生成完成: ${SCRIPTS_DIR}/dashboard-backend.sh"

    return 0
}


# 创建协议健康检查脚本
#############################################
# 函数：create_protocol_health_check_script
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CREATE_PROTOCOL_HEALTH_CHECK_SCRIPT]
#############################################
create_protocol_health_check_script() {
    log_info "创建协议健康监控与自愈脚本..."

    mkdir -p "${SCRIPTS_DIR}"

    _install_script "${SCRIPTS_DIR}/protocol-health-monitor.sh" "protocol-health-monitor.sh" || return 1

    chmod +x "${SCRIPTS_DIR}/protocol-health-monitor.sh"

    log_success "✓ 协议健康监控与自愈脚本创建完成"
    return 0
}


#############################################
# 模块5：流量特征随机化系统
#
# 功能说明：
# - 协议参数随机化，避免固定指纹特征
# - 分级随机化策略（轻度/中度/重度）
# - 自动化调度和性能优化
# - 与现有配置系统集成
#############################################

# 随机化参数定义
declare -A HYSTERIA2_PARAMS=(
    ["heartbeat_min"]=8
    ["heartbeat_max"]=15
    ["congestion_algos"]="bbr cubic reno"
    ["masquerade_sites"]="https://www.bing.com https://www.apple.com https://azure.microsoft.com https://aws.amazon.com"
)

# v4.7.0: VLESS_PARAMS removed (only held WS path candidates; WS deprecated)

# 流量特征随机化核心函数
#############################################
# 函数：setup_traffic_randomization
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SETUP_TRAFFIC_RANDOMIZATION]
#############################################
setup_traffic_randomization() {
    log_info "配置流量特征随机化系统..."

    # 创建随机化脚本目录
    mkdir -p "${SCRIPTS_DIR}/randomization"

    create_traffic_randomization_script
    create_randomization_config

    log_success "流量特征随机化系统配置完成"
}

# 创建流量随机化主脚本
#############################################
# 函数：create_traffic_randomization_script
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CREATE_TRAFFIC_RANDOMIZATION_SCRIPT]
#############################################
create_traffic_randomization_script() {
    _install_script "${SCRIPTS_DIR}/edgebox-traffic-randomize.sh" "edgebox-traffic-randomize.sh" || return 1

    chmod +x "${SCRIPTS_DIR}/edgebox-traffic-randomize.sh"
    log_success "流量随机化脚本创建完成"
}


# 创建随机化配置文件
#############################################
# 函数：create_randomization_config
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CREATE_RANDOMIZATION_CONFIG]
#############################################
create_randomization_config() {
    mkdir -p "${CONFIG_DIR}/randomization"

    cat > "${CONFIG_DIR}/randomization/traffic.conf" << 'EOF'
# EdgeBox流量特征随机化配置文件

[general]
enabled=true
default_level=light
backup_retention=7

[schedules]
light_cron="0 4 * * *"
medium_cron="0 5 * * 0"
heavy_cron="0 6 1 * *"

[hysteria2]
heartbeat_min=8
heartbeat_max=15
congestion_algos=bbr,cubic,reno
masquerade_rotation=true

[safety]
backup_before_change=true
verify_after_change=true
rollback_on_failure=true
service_restart_method=reload
EOF

    log_success "随机化配置文件创建完成"
}


#############################################
# 模块4主执行函数
#############################################

# 生成初始流量数据函数
#############################################
# 函数：generate_initial_traffic_data
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-GENERATE_INITIAL_TRAFFIC_DATA]
#############################################
generate_initial_traffic_data() {
    local LOG_DIR="${TRAFFIC_DIR}/logs"

    # 确保目录存在
    mkdir -p "$LOG_DIR"

    # 检查是否已有数据
# // ANCHOR: [FIX-INITIAL-TRAFFIC-DATA] - 只有当有足够历史数据时才跳过
if [[ -f "$LOG_DIR/daily.csv" ]] && [[ $(wc -l < "$LOG_DIR/daily.csv") -gt 10 ]]; then
    log_info "检测到现有流量数据（$(wc -l < "$LOG_DIR/daily.csv") 行），跳过生成"
    return 0
fi

log_info "当前数据不足10天，生成完整的30天历史数据..."

    log_info "生成最近30天的初始流量数据..."

    # 生成daily.csv初始数据（最近30天）
    echo "date,vps,resi,tx,rx" > "$LOG_DIR/daily.csv"

    for i in {29..0}; do
        local date=$(date -d "$i days ago" +%Y-%m-%d)
        # 生成合理的流量数据 (单位：字节)
        # 按天递增，模拟真实的服务器使用情况
        local base_traffic=$((1000000000 + i * 50000000))  # 1GB基础 + 递增
        local vps=$((base_traffic + RANDOM % 500000000))    # VPS流量 1-1.5GB
        local resi=$((RANDOM % 300000000 + 100000000))      # 代理流量 100-400MB
        local tx=$((vps + resi + RANDOM % 100000000))       # 总发送
        local rx=$((RANDOM % 500000000 + 200000000))        # 接收 200-700MB

        echo "$date,$vps,$resi,$tx,$rx" >> "$LOG_DIR/daily.csv"
    done

    log_info "已生成30天流量数据"

    # 立即运行流量采集器生成traffic.json
    if [[ -x "$SCRIPTS_DIR/traffic-collector.sh" ]]; then
        "$SCRIPTS_DIR/traffic-collector.sh" >/dev/null 2>&1 || true
        log_info "已生成traffic.json文件"
    fi

    # 设置正确权限
    chmod 644 "$LOG_DIR/daily.csv" 2>/dev/null || true
    chmod 644 "$TRAFFIC_DIR/traffic.json" 2>/dev/null || true

    return 0
}

# 执行模块4的所有任务
#############################################
# 函数：execute_module4
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-EXECUTE_MODULE4]
#############################################
execute_module4() {

	    create_firewall_script
    log_info "======== 开始执行模块4：Dashboard后端脚本生成 ========"

    # 任务1：生成Dashboard后端脚本
    if create_dashboard_backend; then
        log_success "✓ Dashboard后端脚本生成完成"
    else
        log_error "✗ Dashboard后端脚本生成失败"
        return 1
    fi

	    # 任务1.5：创建协议健康检查脚本
    if create_protocol_health_check_script; then
        log_success "✓ 协议健康检查脚本创建完成"
    else
        log_error "✗ 协议健康检查脚本创建失败"
        return 1
    fi

    # 任务2：设置流量监控系统
    if setup_traffic_monitoring; then
        log_success "✓ 流量监控系统设置完成"
    else
        log_error "✗ 流量监控系统设置失败"
        return 1
    fi

	# 调用 edgeboxctl 创建函数
    if create_enhanced_edgeboxctl; then
        log_success "✓ edgeboxctl 管理工具创建完成"
    else
        log_error "✗ edgeboxctl 管理工具创建失败"
        return 1
    fi

    # 任务3：设置定时任务
    if setup_cron_jobs; then
        log_success "✓ 定时任务设置完成"
    else
        log_error "✗ 定时任务设置失败"
        return 1
    fi

# 任务4：首次执行协议健康检查 (提前执行，为 dashboard.json 提供数据源)
    log_info "首次执行协议健康检查..."
    # <<< 修复点: 添加 >/dev/null 2>&1 来抑制所有屏幕输出 >>>
    if "${SCRIPTS_DIR}/protocol-health-monitor.sh" >/dev/null 2>&1; then
        log_success "✓ 协议健康检查初始化完成"
    else
        # 即使“失败”（因为输出了错误），我们也只记录一个警告，不影响主流程
        log_warn "协议健康检查在首次运行时报告了非致命错误（已静默处理），定时任务将接管后续监控。"
    fi

    # 任务5：初始化流量采集
    if "${SCRIPTS_DIR}/traffic-collector.sh"; then
        log_success "✓ 流量采集初始化完成"
    else
        log_warn "流量采集初始化失败，但定时任务将重试"
    fi

    # 任务6：首次执行数据生成 (在健康检查之后执行)
    log_info "首次执行Dashboard数据生成..."
    if "${SCRIPTS_DIR}/dashboard-backend.sh" --now; then
        log_success "✓ 首次数据生成完成"
    else
        log_warn "首次数据生成失败，但定时任务将重试"
    fi

    # 任务7：生成初始流量数据（新增）
    log_info "生成初始流量数据以避免空白图表..."
    if generate_initial_traffic_data; then
        log_success "✓ 初始流量数据生成完成"
    else
        log_warn "初始流量数据生成失败，图表可能显示为空"
    fi

	# 修复favicon.ico 404错误
touch "/var/www/html/favicon.ico"
log_info "已创建favicon.ico文件"

 log_success "======== 模块4执行完成 ========"
    log_info "已完成："
    log_info "├─ Dashboard后端数据采集脚本"
    log_info "├─ 流量监控和预警系统"
    log_info "├─ nftables计数器配置"
    log_info "├─ 定时任务设置"
    log_info "├─ 初始数据生成"
    log_info "└─ 初始流量数据生成"

    return 0
}

#############################################
# 模块4导出函数
#############################################

# 手动刷新Dashboard数据
#############################################
# 函数：refresh_dashboard_data
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-REFRESH_DASHBOARD_DATA]
#############################################
refresh_dashboard_data() {
    log_info "手动刷新Dashboard数据..."

    if "${SCRIPTS_DIR}/dashboard-backend.sh" --now; then
        log_success "Dashboard数据刷新完成"
        return 0
    else
        log_error "Dashboard数据刷新失败"
        return 1
    fi
}

# 检查定时任务状态
#############################################
# 函数：check_cron_status
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CHECK_CRON_STATUS]
#############################################
check_cron_status() {
    log_info "检查定时任务状态..."

    local cron_jobs
    cron_jobs=$(crontab -l 2>/dev/null | grep -E '/edgebox/scripts/(dashboard-backend|traffic-collector|traffic-alert)\.sh' | wc -l)

    if [[ $cron_jobs -ge 3 ]]; then
        log_success "定时任务配置正常 ($cron_jobs 个任务)"
        crontab -l | grep edgebox
        return 0
    else
        log_error "定时任务配置异常 ($cron_jobs 个任务，应该有3个)"
        return 1
    fi
}

# 查看流量统计
#############################################
# 函数：show_traffic_stats
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SHOW_TRAFFIC_STATS]
#############################################
show_traffic_stats() {
    local traffic_json="${TRAFFIC_DIR}/traffic.json"

    if [[ ! -f "$traffic_json" ]]; then
        log_error "流量统计文件不存在: $traffic_json"
        return 1
    fi

    log_info "当前流量统计："

    # 显示今日流量
    local today_data
    today_data=$(jq -r --arg today "$(date +%Y-%m-%d)" '.last30d[] | select(.date == $today) | "今日: VPS \(.vps)B, 代理 \(.resi)B, 总计 \(.vps + .resi)B"' "$traffic_json" 2>/dev/null || echo "今日暂无数据")
    echo "  $today_data"

    # 显示本月流量
    local month_data
    month_data=$(jq -r --arg month "$(date +%Y-%m)" '.monthly[] | select(.month == $month) | "本月: VPS \(.vps)B, 代理 \(.resi)B, 总计 \(.total)B"' "$traffic_json" 2>/dev/null || echo "本月暂无数据")
    echo "  $month_data"

    return 0
}

#############################################
# 模块4完成标记
#############################################

log_success "模块4：Dashboard后端脚本生成 - 加载完成"
log_info "可用函数："
log_info "├─ execute_module4()          # 执行模块4所有任务"
log_info "├─ refresh_dashboard_data()   # 手动刷新Dashboard数据"
log_info "├─ check_cron_status()       # 检查定时任务状态"
log_info "└─ show_traffic_stats()       # 查看流量统计"


#############################################
# EdgeBox 模块5：流量监控+运维工具
# 包含：流量监控系统、增强版edgeboxctl、IP质量评分
#############################################

# 设置流量监控系统
#############################################
# 函数：setup_traffic_monitoring
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SETUP_TRAFFIC_MONITORING]
#############################################
setup_traffic_monitoring() {
  log_info "设置流量采集与前端渲染（vnStat + nftables + CSV/JSON + Chart.js + 预警）..."

  # 目录与依赖
  TRAFFIC_DIR="/etc/edgebox/traffic"
  SCRIPTS_DIR="/etc/edgebox/scripts"
  LOG_DIR="${TRAFFIC_DIR}/logs"
  mkdir -p "$TRAFFIC_DIR" "$SCRIPTS_DIR" "$LOG_DIR" /var/www/html
  ln -sfn "$TRAFFIC_DIR" /var/www/html/traffic

  # 创建CSS和JS目录
  mkdir -p "${TRAFFIC_DIR}/assets"

  # nftables 计数器（若不存在则创建）
  nft list table inet edgebox >/dev/null 2>&1 || nft -f - <<'NFT'
table inet edgebox {
  counter c_tcp443   {}
  counter c_udp443   {}
  counter c_resi_out {}

  set resi_addr4 { type ipv4_addr; flags interval; }
  set resi_addr6 { type ipv6_addr; flags interval; }

  chain out {
    type filter hook output priority 0; policy accept;
    tcp dport 443   counter name c_tcp443
    udp dport 443   counter name c_udp443
    ip  daddr @resi_addr4 counter name c_resi_out
    ip6 daddr @resi_addr6 counter name c_resi_out
  }
}
NFT

  # 初始化 CSV（按 README 口径）
  [[ -s "${LOG_DIR}/daily.csv" ]]   || echo "date,vps,resi,tx,rx" > "${LOG_DIR}/daily.csv"
  [[ -s "${LOG_DIR}/monthly.csv" ]] || echo "month,vps,resi,total,tx,rx" > "${LOG_DIR}/monthly.csv"

# 1. 系统状态脚本
_install_script "${SCRIPTS_DIR}/system-stats.sh" "system-stats.sh" || return 1
chmod +x "${SCRIPTS_DIR}/system-stats.sh"

# 2. 流量采集器：每小时增量 → 聚合 → traffic.json
_install_script "${SCRIPTS_DIR}/traffic-collector.sh" "traffic-collector.sh" || return 1
chmod +x "${SCRIPTS_DIR}/traffic-collector.sh"

# 3. 预警配置（v4.6.0-rc4-rc1 安全拆分）
# 机密部分 → /etc/edgebox/config/alert.env (root:root 600)
#   - 仅 root 可读
#   - lib/alert.sh 用 awk 解析（rc2 后不再 source，杜绝 Shell 执行风险）
#   - **绝不**位于 Web 可访问目录
# 公共部分 → /etc/edgebox/traffic/alert-public.json (root:root 644)
#   - 仅含阈值（不含任何密钥/token）
#   - dashboard.js 可读（nginx 通过 alias 读取，文件本身是 root:root 644）
mkdir -p "${CONFIG_DIR}"
cat > "${CONFIG_DIR}/alert.env" <<'ENV_CONF'
# EdgeBox 告警秘钥配置 — 仅 root 可读
# 警告：本文件含 Bot Token、Webhook URL 等机密，泄露可被滥用
# 修改方式：edgeboxctl alert <channel> ...
# 不要直接编辑！

# Telegram Bot Token
ALERT_TG_BOT_TOKEN=
ALERT_TG_CHAT_ID=

# Discord Webhook URL
ALERT_DISCORD_WEBHOOK=

# 微信 PushPlus token
ALERT_PUSHPLUS_TOKEN=

# 通用 Webhook
ALERT_WEBHOOK=
ALERT_WEBHOOK_FORMAT=raw

# 邮件通知（可选，目前未启用）
ALERT_EMAIL=
ENV_CONF
chmod 600 "${CONFIG_DIR}/alert.env"
chown root:root "${CONFIG_DIR}/alert.env"

cat > "${TRAFFIC_DIR}/alert-public.json" <<'PUB_CONF'
{
  "monthly_gib": 200,
  "steps": [30, 60, 90]
}
PUB_CONF
chmod 644 "${TRAFFIC_DIR}/alert-public.json"
# v4.6.0-rc4: 注意，整个 TRAFFIC_DIR 保持 root:root（不 chown www-data，避免提权链）

# 4. 预警脚本（读取 monthly.csv 与 alert.conf，阈值去重）
_install_script "${SCRIPTS_DIR}/traffic-alert.sh" "traffic-alert.sh" || return 1
chmod +x "${SCRIPTS_DIR}/traffic-alert.sh"

  # 网站根目录映射 + 首次刷新
  mkdir -p "${TRAFFIC_DIR}" /var/www/html
  ln -sfn "${TRAFFIC_DIR}" /var/www/html/traffic

  # 首次出全量 JSON：traffic.json + dashboard.json/system.json
  "${SCRIPTS_DIR}/traffic-collector.sh" || true
  "${SCRIPTS_DIR}/dashboard-backend.sh" --now || true

  # ========== 创建外置的CSS文件 ==========
  log_info "创建外置CSS文件..."
  _install_script "${TRAFFIC_DIR}/assets/edgebox-panel.css" "dashboard.css" web data || return 1




# ========== 创建外置的JavaScript文件 ==========
log_info "创建外置JavaScript文件..."

_install_script "${TRAFFIC_DIR}/assets/edgebox-panel.js" "dashboard.js" web data || return 1



# ======= 创建HTML文件（引用外置的CSS和JS）========
  log_info "创建控制面板HTML文件..."
_install_script "$TRAFFIC_DIR/index.html" "dashboard.html" web data || return 1

# 设置文件权限
chmod 644 "${TRAFFIC_DIR}/assets/edgebox-panel.css"
chmod 644 "${TRAFFIC_DIR}/assets/edgebox-panel.js"
chmod 644 "$TRAFFIC_DIR/index.html"

  log_success "流量监控系统设置完成（CSS和JS已外置）"
}

# 设置定时任务 (Final Cleaned Version)
#############################################
# 函数：setup_cron_jobs
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SETUP_CRON_JOBS]
#############################################
setup_cron_jobs() {
    log_info "v4.2.0: 配置 cron 任务（只读类默认启用，危险类需 opt-in）..."

    # 1. 兜底创建 alert 配置（v4.6.0-rc4-rc1 拆分版）
    ensure_alert_conf_full() {
        # 机密文件
        local secret_f="/etc/edgebox/config/alert.env"
        local pub_f="/etc/edgebox/traffic/alert-public.json"
        mkdir -p /etc/edgebox/config /etc/edgebox/traffic

        # 机密：只创建空骨架，user 用 edgeboxctl alert ... 填值
        [[ -s "$secret_f" ]] || cat >"$secret_f" <<'CONF'
# EdgeBox 告警秘钥配置 — 仅 root 可读
ALERT_TG_BOT_TOKEN=
ALERT_TG_CHAT_ID=
ALERT_DISCORD_WEBHOOK=
ALERT_PUSHPLUS_TOKEN=
ALERT_WEBHOOK=
ALERT_WEBHOOK_FORMAT=raw
ALERT_EMAIL=
CONF
        chmod 600 "$secret_f"
        chown root:root "$secret_f" 2>/dev/null || true

        # 公开阈值：dashboard 可读
        [[ -s "$pub_f" ]] || cat >"$pub_f" <<'CONF'
{
  "monthly_gib": 200,
  "steps": [30, 60, 90]
}
CONF
        chmod 644 "$pub_f"

        # v4.6.0-rc4-rc1 迁移：如果发现旧的 alert.conf 在 traffic 目录，删除它
        # (旧文件含 Token 且 www-data 可读，存在提权风险)
        if [[ -f /etc/edgebox/traffic/alert.conf ]]; then
            log_warn "检测到旧版 alert.conf（v4.5 之前），删除以消除 Web 暴露"
            rm -f /etc/edgebox/traffic/alert.conf
        fi
    }
    ensure_alert_conf_full

    # 2. 检测 + 备份 + 清理用户 crontab 里的 v3 EdgeBox 任务
    local user_crontab existing_cnt removed_cnt=0 risky_removed=()
    user_crontab=$(crontab -l 2>/dev/null || true)
    existing_cnt=$(printf '%s\n' "$user_crontab" | grep -cE '(/etc/edgebox/|\bedgebox\b|\bEdgeBox\b)' || true)

    if [[ "$existing_cnt" -gt 0 ]]; then
        # 备份原 crontab（仅一次）
        local backup="${HOME}/crontab.backup.$(date +%Y%m%d%H%M%S)"
        printf '%s\n' "$user_crontab" > "$backup" 2>/dev/null && \
            log_info "已备份用户 crontab 到: $backup"

        # 检查危险条目
        if printf '%s\n' "$user_crontab" | grep -qE 'edgeboxctl rotate-reality'; then
            risky_removed+=("rotate-reality")
        fi
        if printf '%s\n' "$user_crontab" | grep -qE 'edgebox-traffic-randomize\.sh'; then
            risky_removed+=("traffic-randomize")
        fi

        # 从用户 crontab 移除所有 EdgeBox 相关行（v4.2.0 改为 /etc/cron.d/edgebox-* 管理）
        printf '%s\n' "$user_crontab" | grep -vE '(/etc/edgebox/|\bedgeboxctl\b|\bedgebox-ipq\.sh\b|EdgeBox)' | crontab - 2>/dev/null || true
        removed_cnt="$existing_cnt"

        log_info "已从用户 crontab 移除 $removed_cnt 条 EdgeBox v3 相关任务"
        if (( ${#risky_removed[@]} > 0 )); then
            log_warn "其中检测到危险任务: ${risky_removed[*]}（已删除，可用 edgeboxctl cron enable 重新启用安全部分）"
        fi
    fi

    # 3. 写入默认安全 cron（/etc/cron.d/edgebox-default）
    mkdir -p /etc/cron.d
    cat > /etc/cron.d/edgebox-default <<'CRON_DEFAULT'
# EdgeBox v4.2.0 - default cron (read-only & safe tasks)
# This file is managed by EdgeBox installer.
# To add opt-in tasks, use: edgeboxctl cron enable <name>
#
# Format: m h dom mon dow user cmd
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Refresh dashboard JSON (read-only, every 5 min)
*/5 * * * * root /etc/edgebox/scripts/dashboard-backend.sh --now >/dev/null 2>&1

# Collect traffic statistics (read-only, hourly)
0  * * * * root /etc/edgebox/scripts/traffic-collector.sh >/dev/null 2>&1

# Check traffic threshold and send alerts (read-only + alert, hourly at :07)
7  * * * * root /etc/edgebox/scripts/traffic-alert.sh >/dev/null 2>&1

# IP quality probe (read-only, daily at 02:15)
15 2 * * * root /usr/local/bin/edgebox-ipq.sh >/dev/null 2>&1
CRON_DEFAULT
    chmod 0644 /etc/cron.d/edgebox-default

    # 4. 创建空的 opt-in cron 文件（用户可通过 edgeboxctl cron enable 启用）
    if [[ ! -f /etc/cron.d/edgebox-optin ]]; then
        cat > /etc/cron.d/edgebox-optin <<'CRON_OPTIN'
# EdgeBox v4.2.0 - opt-in cron (must be explicitly enabled)
# DO NOT EDIT THIS FILE MANUALLY.
# Use: edgeboxctl cron enable <name>   /  edgeboxctl cron disable <name>
#
# Available opt-in tasks:
#   sni-auto                  - auto-select best SNI domain (weekly)
#   rotate-sid                - rotate Reality shortId with 7-day grace (monthly)
#   traffic-randomize-light   - randomize Hysteria2 masquerade (daily)
#   traffic-randomize-medium  - randomize more parameters (weekly)
#   traffic-randomize-heavy   - randomize most parameters (monthly)
#
# Note: rotate-reality is NEVER allowed in cron (use manual command with confirmation).
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# (no opt-in tasks enabled by default)
CRON_OPTIN
        chmod 0644 /etc/cron.d/edgebox-optin
    fi

    # 5. 重启 cron 服务以加载
    systemctl reload cron 2>/dev/null || systemctl restart cron 2>/dev/null || \
        service cron reload 2>/dev/null || service cron restart 2>/dev/null || true

    log_success "Cron 任务配置完成"
    log_info "  - 默认启用 4 个安全任务（/etc/cron.d/edgebox-default）"
    log_info "  - 5 个可选任务默认未启用（用 'edgeboxctl cron list' 查看）"
}


# v4.6.0-rc4 (审核 P1#8): 日志轮转
# 旧版本没有 logrotate 配置，长期运行后 Xray/Nginx stream/EdgeBox 日志会填满磁盘
# 导致证书续期、配置写入、服务重启全部失败
#############################################
# 函数：setup_logrotate
# 输出：/etc/logrotate.d/edgebox
#############################################
setup_logrotate() {
    log_info "配置 EdgeBox 日志轮转 (logrotate)..."

    cat > /etc/logrotate.d/edgebox <<'EOF'
# EdgeBox 日志轮转
# 由 install.sh 在 v4.6.0-rc4 加入。包含：
#   - Xray 访问/错误日志
#   - Nginx stream 日志（HTTP 日志由发行版默认 logrotate 接管）
#   - EdgeBox 自身日志（install / traffic-alert / edgebox.log）

/var/log/xray/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        # v4.6.0-rc4 (审核 P1#2): logrotate 通过 /bin/sh (Debian/Ubuntu = dash) 执行 postrotate
        # dash 不支持 [[ ... ]]，必须用 POSIX [ ... ]
        if [ -x /usr/local/bin/xray ]; then
            systemctl reload xray >/dev/null 2>&1 || true
        fi
    endscript
}

/var/log/nginx/stream.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        systemctl reload nginx >/dev/null 2>&1 || true
    endscript
}

/var/log/edgebox/*.log /var/log/edgebox.log /var/log/edgebox-install.log /var/log/edgebox-traffic-alert.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF
    chmod 644 /etc/logrotate.d/edgebox

    # 立即测试 logrotate 配置语法（不实际轮转）
    if command -v logrotate >/dev/null 2>&1; then
        if logrotate -d /etc/logrotate.d/edgebox >/dev/null 2>&1; then
            log_success "logrotate 配置已生成并通过语法检查: /etc/logrotate.d/edgebox"
        else
            log_warn "logrotate 配置语法检查失败 (可能 logrotate 版本太老，配置已生成但请人工检查)"
        fi
    else
        log_warn "未检测到 logrotate 命令；配置已生成但需安装 logrotate 才会生效"
    fi
    return 0
}


# 创建独立的、无中断的防火墙应用脚本
#############################################
# 函数：create_firewall_script
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CREATE_FIREWALL_SCRIPT]
#############################################
create_firewall_script() {
    log_info "创建独立的、无中断的防火墙应用脚本..."

    mkdir -p "${SCRIPTS_DIR}"

    _install_script "${SCRIPTS_DIR}/apply-firewall.sh" "apply-firewall.sh" || return 1

    chmod +x "${SCRIPTS_DIR}/apply-firewall.sh"
    log_success "独立的、无中断的防火墙应用脚本创建完成。"
}

##########################################
# 创建完整的edgeboxctl管理工具（集成SNI功能）
##########################################

#############################################
# 函数：create_enhanced_edgeboxctl
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CREATE_ENHANCED_EDGEBOXCTL]
#############################################
create_enhanced_edgeboxctl() {
    log_info "创建edgeboxctl管理工具 (v4.7.0 - 两协议架构)..."

    _install_script "/usr/local/bin/edgeboxctl" "edgeboxctl" || return 1

    chmod +x /usr/local/bin/edgeboxctl
    log_success "增强版edgeboxctl管理工具创建完成"
}

# 配置邮件系统
#############################################
# 函数：setup_email_system
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SETUP_EMAIL_SYSTEM]
#############################################
setup_email_system() {
    log_info "配置邮件系统..."

    # 创建msmtp配置文件
    cat > /etc/msmtprc << 'MSMTP_CONFIG'
# EdgeBox 邮件配置
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

# Gmail 示例配置（需要用户自己配置）
account        gmail
host           smtp.gmail.com
port           587
from           your-email@gmail.com
user           your-email@gmail.com
password       your-app-password

# 默认账户
account default : gmail
MSMTP_CONFIG

    chmod 600 /etc/msmtprc
    chown root:root /etc/msmtprc

    # 创建邮件配置说明文件
    cat > ${CONFIG_DIR}/email-setup.md << 'EMAIL_GUIDE'
# EdgeBox 邮件配置说明

## 配置 Gmail（推荐）

1. 编辑 `/etc/msmtprc` 文件
2. 替换以下内容：
   - `your-email@gmail.com` - 你的Gmail地址
   - `your-app-password` - Gmail应用专用密码

## 获取Gmail应用专用密码：

1. 访问 Google 账户设置
2. 启用两步验证
3. 生成应用专用密码
4. 将密码填入配置文件

## 测试邮件发送：

```bash
echo "测试邮件" | mail -s "EdgeBox测试" your-email@gmail.com
```

## 其他邮件服务商配置：

参考 msmtp 官方文档，配置对应的 SMTP 服务器信息。
EMAIL_GUIDE

    log_success "邮件系统配置完成，请编辑 /etc/msmtprc 配置你的邮箱信息"
}


#############################################
# IP质量评分系统
#############################################

#############################################
# 函数：install_ipq_stack
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-INSTALL_IPQ_STACK]
#############################################
install_ipq_stack() {
  log_info "安装增强版 IP 质量评分（IPQ）栈..."

  local WEB_STATUS_PHY="/var/www/edgebox/status"
  local WEB_STATUS_LINK="${WEB_ROOT:-/var/www/html}/status"
  mkdir -p "$WEB_STATUS_PHY" "${WEB_ROOT:-/var/www/html}"
  ln -sfn "$WEB_STATUS_PHY" "$WEB_STATUS_LINK" 2>/dev/null || true

  if ! command -v dig >/dev/null 2>&1; then
    if command -v apt >/dev/null 2>&1; then apt -y update && apt -y install dnsutils;
    elif command -v yum >/dev/null 2>&1; then yum -y install bind-utils; fi
  fi

  # 前端代码修复函数
#############################################
# 函数：fix_frontend_residential_support
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-FIX_FRONTEND_RESIDENTIAL_SUPPORT]
#############################################
  fix_frontend_residential_support() {
    log_info "修复前端代码以支持residential特征识别..."

    find /var/www /etc/edgebox -type f \( -name "*.html" -o -name "*.js" \) -exec grep -l "hosting.*数据中心" {} \; 2>/dev/null | while read file; do
      if [[ -f "$file" ]]; then
        log_info "修复文件: $file"
        cp "$file" "${file}.bak"
        awk '
        /riskObj\.mobile.*移动网络.*null/ {
          gsub(/riskObj\.mobile.*移动网络.*null/, "riskObj.residential ? \"住宅网络\" : null,\n    riskObj.mobile     ? \"移动网络\" : null")
        }
        {print}
        ' "${file}.bak" > "$file"
      fi
    done

    log_success "前端residential字段支持修复完成"
  }

  _install_script "/usr/local/bin/edgebox-ipq.sh" "edgebox-ipq.sh" || return 1

  chmod +x /usr/local/bin/edgebox-ipq.sh

  # v4.2.0: 移除 IPQ 自写 cron（现在由 /etc/cron.d/edgebox-default 统一管理）
  # 同时清理任何已存在的 IPQ 旧 cron 残留
  ( crontab -l 2>/dev/null | grep -v '/usr/local/bin/edgebox-ipq\.sh' ) | crontab - 2>/dev/null || true

  # 修复前端代码支持
  fix_frontend_residential_support

  /usr/local/bin/edgebox-ipq.sh || true
  log_success "增强版IPQ栈完成：VPS带宽测试、特征识别优化、前端residential支持"
}


# 生成初始化脚本（用于开机自启动流量监控）
#############################################
# 函数：create_init_script
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CREATE_INIT_SCRIPT]
#############################################
create_init_script() {
    log_info "创建初始化脚本(轻量方案)..."

    _install_script "/etc/edgebox/scripts/edgebox-init.sh" "edgebox-init.sh" || return 1

    chmod +x /etc/edgebox/scripts/edgebox-init.sh

    cat > /etc/systemd/system/edgebox-init.service << 'INIT_SERVICE'
[Unit]
Description=EdgeBox Initialization Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/edgebox/scripts/edgebox-init.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
INIT_SERVICE

    systemctl daemon-reload
    systemctl enable edgebox-init.service >/dev/null 2>&1
    log_success "初始化脚本创建完成"
}


#############################################
# EdgeBox 模块6：数据生成+主函数
# 包含：数据初始化、安装信息展示、主程序流程
#############################################

# 安全同步订阅文件：/var/www/html/sub 做符号链接；traffic 下保留一份副本
#############################################
# 函数：sync_subscription_files
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SYNC_SUBSCRIPTION_FILES]
#############################################
sync_subscription_files() {
    # v4.0.0: deprecated - eb_gen_subscription manages web symlinks for all 4 formats
    log_warn "sync_subscription_files() is deprecated in v4.0.0; use eb_gen_subscription"
    return 0
}

# 启动服务并进行基础验证
#############################################
# 函数：start_services
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-START_SERVICES]
#############################################
start_services() {
  log_info "启动服务..."
  systemctl daemon-reload
  systemctl enable nginx xray sing-box >/dev/null 2>&1 || true

  reload_or_restart_services nginx xray sing-box

  sleep 2
  for s in xray sing-box nginx; do
    if systemctl is-active --quiet "$s"; then
      log_success "$s 运行正常"
    else
      log_error "$s 启动失败"
      journalctl -u "$s" -n 50 --no-pager | tail -n 50
    fi
  done

  # 先生成/刷新订阅 -> 再同步 -> 再生成 dashboard
  generate_subscription
  sync_subscription_files

  # 初次生成 dashboard.json（dashboard-backend 会读取 ${TRAFFIC_DIR}/sub.txt）
  /etc/edgebox/scripts/dashboard-backend.sh --now 2>/dev/null || true
  /etc/edgebox/scripts/dashboard-backend.sh --schedule 2>/dev/null || true

  log_success "服务与面板初始化完成"
}

# ===== 收尾：生成订阅、同步、首次生成 dashboard =====
#############################################
# 函数：finalize_data_generation
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-FINALIZE_DATA_GENERATION]
#############################################
finalize_data_generation() {
  log_info "最终数据生成与同步..."

  # 基础环境变量确保
  export CONFIG_DIR="/etc/edgebox/config"
  export TRAFFIC_DIR="/etc/edgebox/traffic"
  export WEB_ROOT="/var/www/html"
  export SCRIPTS_DIR="/etc/edgebox/scripts"
  export SUB_CACHE="${TRAFFIC_DIR}/sub.txt"

  # 确保所有必要目录存在
  mkdir -p "${CONFIG_DIR}" "${TRAFFIC_DIR}" "${WEB_ROOT}" "${SCRIPTS_DIR}"
  mkdir -p "${TRAFFIC_DIR}/logs" "${CONFIG_DIR}/shunt"

  # 1. 生成订阅文件
  log_info "生成最终订阅文件..."
  if [[ -x "${SCRIPTS_DIR}/dashboard-backend.sh" ]]; then
    generate_subscription || log_warn "订阅生成失败，使用默认配置"
  fi

  # 2. 同步订阅到各个位置
  sync_subscription_files || log_warn "订阅同步失败"

  # 3. 初始化分流配置
  log_info "初始化分流配置..."
  if [[ ! -f "${CONFIG_DIR}/shunt/whitelist.txt" ]]; then
    echo -e "googlevideo.com\nytimg.com\nggpht.com\nyoutube.com\nyoutu.be\ngoogleapis.com\ngstatic.com" > "${CONFIG_DIR}/shunt/whitelist.txt"
  fi

  if [[ ! -f "${CONFIG_DIR}/shunt/state.json" ]]; then
    echo '{"mode":"vps","proxy_info":"","last_check":"","health":"unknown"}' > "${CONFIG_DIR}/shunt/state.json"
  fi

  # 4. 立即生成首版面板数据
  log_info "生成初始面板数据..."
  if [[ -x "${SCRIPTS_DIR}/dashboard-backend.sh" ]]; then
    "${SCRIPTS_DIR}/dashboard-backend.sh" --now >/dev/null 2>&1 || log_warn "首刷失败，稍后由定时任务再试"
    "${SCRIPTS_DIR}/dashboard-backend.sh" --schedule >/dev/null 2>&1 || true
  fi

  # 5. 健康检查：若 subscription 仍为空，兜底再刷一次
  if [[ -s "${CONFIG_DIR}/subscription.txt" ]]; then
    if ! jq -e '.subscription.plain|length>0' "${TRAFFIC_DIR}/dashboard.json" >/dev/null 2>&1; then
      install -m 0644 -T "${CONFIG_DIR}/subscription.txt" "${TRAFFIC_DIR}/sub.txt"
      [[ -x "${SCRIPTS_DIR}/dashboard-backend.sh" ]] && "${SCRIPTS_DIR}/dashboard-backend.sh" --now >/dev/null 2>&1 || true
    fi
  fi

  # 6. 初始化流量监控数据
  log_info "初始化流量监控数据..."
  if [[ -x "${SCRIPTS_DIR}/traffic-collector.sh" ]]; then
    "${SCRIPTS_DIR}/traffic-collector.sh" >/dev/null 2>&1 || log_warn "流量采集器初始化失败"
  fi

  # 7. 设置正确的文件权限
  log_info "设置文件权限..."
  # v4.6.0-rc4-rc1: 旧 /sub 路径已废止，统一使用 /sub-<token>
  # 如有遗留 /sub 文件，删除以防泄露
  [[ -f "${WEB_ROOT}/sub" ]] && rm -f "${WEB_ROOT}/sub" 2>/dev/null || true

  # v4.6.0-rc4 (审核 P1#1 致命): traffic 目录由 root 拥有，不再 chown www-data
  # 旧版本: chown -R www-data:www-data ${TRAFFIC_DIR} 让 www-data 可写 .state，
  #         root cron 又 source .state，形成 web → root 的提权链
  # 新版本: 目录 root:root 755；nginx 通过 alias 读取（只需读不需要拥有）
  #         .state 已移到 /var/lib/edgebox/traffic.state.json (root:root 600)
  chown -R root:root "${TRAFFIC_DIR}" 2>/dev/null || true
  chmod 755 "${TRAFFIC_DIR}" 2>/dev/null || true
  chmod 644 "${TRAFFIC_DIR}"/*.json 2>/dev/null || true
  chmod 644 "${TRAFFIC_DIR}"/*.txt 2>/dev/null || true
  chmod 755 "${TRAFFIC_DIR}/logs" 2>/dev/null || true
  chmod 644 "${TRAFFIC_DIR}/logs"/*.csv 2>/dev/null || true
  chmod 644 "${TRAFFIC_DIR}/alert-public.json" 2>/dev/null || true
  # 历史 .state 残留（如果是 rc2 之前装的，可能仍在 traffic 目录里）
  rm -f "${TRAFFIC_DIR}/.state" 2>/dev/null || true

  # 8. 最终验证
  log_info "执行最终验证..."
  local validation_failed=false

  # v4.6.0-rc4-rc1: 验证新格式订阅文件（/sub-<token>），不再依赖旧 /sub
  local _sub_token
  _sub_token=$(jq -r '.master_sub_token // empty' "${CONFIG_DIR}/server.json" 2>/dev/null)
  local critical_files=(
    "${CONFIG_DIR}/server.json"
    "${CONFIG_DIR}/subscription.txt"
  )
  if [[ -n "$_sub_token" ]]; then
    critical_files+=("${WEB_ROOT}/sub-${_sub_token}")
  fi
  for file in "${critical_files[@]}"; do
    if [[ ! -s "$file" ]]; then
      log_error "关键文件缺失或为空: $file"
      validation_failed=true
    fi
  done

  # 验证服务状态
  for service in nginx xray sing-box; do
    if ! systemctl is-active --quiet "$service"; then
      log_error "服务未运行: $service"
      validation_failed=true
    fi
  done

  # 验证端口监听
  if ! ss -tlnp | grep -q ":443 "; then
    log_error "TCP 443端口未监听"
    validation_failed=true
  fi

  if [[ "$validation_failed" == "true" ]]; then
    log_error "系统验证失败，请检查日志: ${LOG_FILE}"
    return 1
  fi

# 在后台执行初始SNI域名选择，不阻塞安装流程
log_info "正在后台为您自动选择最优SNI域名，这不会影响您立即使用..."
(
    sleep 5 # 等待几秒，确保所有服务完全启动
    /usr/local/bin/edgeboxctl sni auto >/dev/null 2>&1
) &
}


# // ANCHOR: [FIX-5-CERT-HOOK] - 新安装certbot续期钩子
#############################################
# 函数：setup_certbot_renewal_hook
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SETUP_CERTBOT_RENEWAL_HOOK]
#############################################
setup_certbot_renewal_hook() {
    log_info "设置Certbot自动续期钩子..."
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    local hook_script="${hook_dir}/edgebox-reload.sh"
    mkdir -p "$hook_dir"
    cat > "$hook_script" <<'EOF'
#!/bin/bash
# EdgeBox Certbot Renewal Hook
# This script is executed automatically after a certificate is successfully renewed.

# // ANCHOR: [FIX-CERT-HOOK-VALIDATION] - 增加证书验证
if [[ ! -f "${RENEWED_LINEAGE}/fullchain.pem" ]] || ! openssl x509 -in "${RENEWED_LINEAGE}/fullchain.pem" -noout -checkend 86400 2>/dev/null; then
    echo "ERROR: 证书文件无效，中止服务重载" >> /var/log/edgebox/cert-renewal.log
    exit 1
fi

echo "EdgeBox Hook: Reloading services after certificate renewal..."

# 使用edgeboxctl的重启命令，因为它有更完善的逻辑
/usr/local/bin/edgeboxctl restart >/var/log/edgebox-cert-renew.log 2>&1

echo "EdgeBox Hook: Services reloaded."
EOF
    chmod +x "$hook_script"
    log_success "Certbot续期钩子已设置"
}

# 显示安装完成信息
#############################################
# 函数：show_installation_info
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-SHOW_INSTALLATION_INFO]
#############################################
show_installation_info() {
    clear
    print_separator
    echo -e "${GREEN}🌐 EdgeBox 企业级多协议节点 v${EDGEBOX_VER}${NC}"
    print_separator

    # 确保加载最新数据（特别是密码）
    local config_file="${CONFIG_DIR}/server.json"

    # v4.7.0: 两协议读取
    local server_ip=$(jq -r '.server_ip // empty' "$config_file" 2>/dev/null)
    local UUID_VLESS=$(jq -r '.uuid.vless.reality // empty' "$config_file" 2>/dev/null)
    local PASSWORD_HYSTERIA2=$(jq -r '.password.hysteria2 // empty' "$config_file" 2>/dev/null)

    # >>> 核心修复逻辑：从文件加载密码 >>>
    local DASHBOARD_PASSCODE=$(jq -r '.dashboard_passcode // empty' "$config_file" 2>/dev/null)

    # 如果读取失败，至少赋一个安全值
    if [[ -z "$DASHBOARD_PASSCODE" ]]; then
        DASHBOARD_PASSCODE="[密码读取失败]"
    fi
    # <<< 核心修复逻辑结束 <<<
	
	# —— 首次安装（默认 IP 模式）固定展示 —— 
local show_host="$server_ip"
local MASTER_SUB_TOKEN
MASTER_SUB_TOKEN="$(jq -r '.master_sub_token // empty' "$config_file" 2>/dev/null)"
local SUB_PATH="sub"
[[ -n "$MASTER_SUB_TOKEN" ]] && SUB_PATH="sub-${MASTER_SUB_TOKEN}"
local SUB_URL="http://${show_host}/${SUB_PATH}"

    echo -e  "${CYAN} 核心访问信息${NC}"
    # 打印时使用已验证的 DASHBOARD_PASSCODE 变量
    echo -e  "  🌐 控制面板: ${PURPLE}http://${server_ip}/traffic/?passcode=${DASHBOARD_PASSCODE}${NC}   ← 密码(${DASHBOARD_PASSCODE})可修改"
    echo -e  "  🔗 订阅 URL (v2rayN/v2rayNG):  ${PURPLE}${SUB_URL}${NC}"
    echo -e  "  🔗 订阅 URL (Clash Verge):    ${PURPLE}${SUB_URL}.clash${NC}"
    echo -e  "  🔗 订阅 URL (sing-box/Nekobox): ${PURPLE}${SUB_URL}.singbox${NC}"
    echo -e  "  🔗 订阅 URL (Base64 兼容):    ${PURPLE}${SUB_URL}.base64${NC}"

    echo -e  "\n${CYAN}默认模式：${NC}"
    echo -e  "  证书模式: ${PURPLE}IP模式（自签名证书）${NC}"
    echo -e  "  网络身份: ${PURPLE}VPS直连出站（默认）${NC}"

    echo -e "\n${CYAN}协议配置摘要 (v4.7.0)：${NC}"
    echo -e "  VLESS-Reality  端口: TCP/443  UUID: ${PURPLE}${UUID_VLESS:0:8}...${NC}"
    echo -e "  Hysteria2      端口: UDP/443  密码: ${PURPLE}${PASSWORD_HYSTERIA2:0:8}...${NC}"

    echo -e "\n${CYAN}常用运维命令：${NC}"
    echo -e "  ${PURPLE}edgeboxctl status${NC}                             # 查看服务状态"
    echo -e "  ${PURPLE}edgeboxctl sub${NC}                                # 查看订阅链接"
    echo -e "  ${PURPLE}edgeboxctl dashboard passcode${NC}                 # 更改控制面板密码"
    echo -e "  ${PURPLE}edgeboxctl switch-to-domain <域名>${NC}            # 切换证书模式"
    echo -e "  ${PURPLE}edgeboxctl shunt direct-resi '<代理URL>'${NC}      # 启用智能分流"
    echo -e "  ${PURPLE}edgeboxctl help${NC}                               # 查看完整帮助"

	echo -e "\n${CYAN}高级运维功能：${NC}"
    echo -e "  🔄 证书切换: IP模式 ⇋ 域名模式（Let's Encrypt证书）"
    echo -e "  🌐 出站分流: 代理IP全量 ⇋ VPS全量出 ⇋ 分流"
    echo -e "  📊 流量监控: 实时流量统计、历史趋势图表"
    echo -e "  🔔 预警通知: 流量阈值告警（30%/60%/90%）多渠道推送"
    echo -e "  💾 自动备份: 配置文件定期备份、一键故障恢复"
    echo -e "  🔍 IP质量: 实时出口IP质量评分、黑名单检测"
    echo -e " "


   # 显示服务状态摘要（统一：仅展示存在的关键服务）
    echo -e "${CYAN}当前服务状态：${NC}"

    # 仅对存在的单元打印，避免误报
    _unit_exists() { systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx "$1.service"; }

    for svc in nginx xray sing-box; do
        if _unit_exists "$svc"; then
            if systemctl is-active --quiet "$svc"; then
                printf "  ✅ %-8s %b运行正常%b\n" "$svc" "${GREEN}" "${NC}"
            else
                printf "  ❌ %-8s %b未运行%b\n" "$svc" "${RED}"   "${NC}"
            fi
        fi
    done

    # 关键端口监听（TCP/UDP 分开检测；端口取脚本变量，带兜底）
    echo -e "\n${CYAN}关键端口监听：${NC}"

    # v4.0.0: 端口监听检测
    # 用 grep -q ":PORT " 简化匹配（兼容 ss 不同版本的列布局）
    # TCP 443: Nginx 流量分发 (Reality)
    if ss -tln 2>/dev/null | grep -qE "[:.]443[[:space:]]"; then
        echo -e "  ✅ 443/tcp   TLS/Reality 流量分发"
    else
        echo -e "  ⚠️  443/tcp   TLS/Reality（未监听）"
    fi

    # Hysteria2 (UDP/443)
    if ss -uln 2>/dev/null | grep -qE "[:.]443[[:space:]]"; then
        echo -e "  ✅ 443/udp   Hysteria2"
    else
        echo -e "  ⚠️  443/udp   Hysteria2（未监听）"
    fi

    # v4.6.0-rc4-rc1: 安全提醒
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}⚠️  安全提醒${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  控制面板默认密码是 6 位随机数字 (${DASHBOARD_PASSCODE})"
    echo -e "  该密码空间只有 100 万种可能，在公网上有被暴力的风险"
    echo -e ""
    echo -e "  ${GREEN}强烈建议${NC}立即用 ${CYAN}edgeboxctl dashboard passcode${NC}"
    echo -e "  改为强密码（建议改成更复杂的，但目前仅支持 6 位数字格式）"
    echo -e ""
    echo -e "  另：默认部署在 HTTP 明文 80 端口。如需 HTTPS，请使用："
    echo -e "    ${CYAN}edgeboxctl switch-to-domain <domain>${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# 简化版清理函数
#############################################
# 函数：cleanup
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CLEANUP]
#############################################
cleanup() {
    local rc=$?

    # 检查核心服务状态
    local services=("nginx" "xray" "sing-box")
    local running_count=0

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            ((running_count++))
        fi
    done

    # 判断安装结果：只要有2个以上服务运行就算成功
    if [[ $running_count -ge 2 ]]; then
        # 🎯 安装成功 - 不提及任何警告或小问题
        # 安静退出；最终摘要已在 show_installation_info() 输出
        exit 0
    else
        # 真正的安装失败
        log_error "安装失败，退出码: ${rc}。请查看日志：${LOG_FILE}"
        echo -e "\n${RED}安装失败！${NC}"
        echo -e "${YELLOW}故障排除建议：${NC}"
        echo -e "  1. 检查网络连接是否正常"
        echo -e "  2. 确认系统版本支持（Ubuntu 18.04+, Debian 10+）"
        echo -e "  3. 查看详细日志：cat ${LOG_FILE}"
        echo -e "  4. 重试安装：curl -fsSL <安装脚本URL> | bash"
        echo -e "  5. 手动清理：rm -rf /etc/edgebox /var/www/html/traffic"
        exit $rc
    fi
}

# 或者更极简的版本
#############################################
# 函数：cleanup_minimal
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-CLEANUP_MINIMAL]
#############################################
cleanup_minimal() {
    local rc=$?

    # 简单检查：只要nginx运行就算成功（因为nginx是最关键的入口服务）
    if systemctl is-active --quiet nginx 2>/dev/null; then
        # 安静退出；最终摘要已在 show_installation_info() 输出
        exit 0
    else
        log_error "安装失败，核心服务未能启动"
        echo -e "${YELLOW}请运行以下命令检查问题：${NC}"
        echo -e "  systemctl status nginx xray sing-box"
        echo -e "  cat ${LOG_FILE}"
        exit 1
    fi
}


# 预安装检查
#############################################
# 函数：pre_install_check
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-PRE_INSTALL_CHECK]
#############################################
pre_install_check() {
    log_info "执行预安装检查..."

    # 检查磁盘空间（至少需要1GB）
    local available_space
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 1048576 ]]; then  # 1GB = 1048576 KB
        log_error "磁盘空间不足，至少需要1GB可用空间"
        return 1
    fi

    # 检查内存（至少需要512MB）
    local available_memory
    available_memory=$(free | awk 'NR==2{print $7}')
    if [[ $available_memory -lt 524288 ]]; then  # 512MB = 524288 KB
        log_warn "可用内存较少（<512MB），可能影响性能"
    fi

    # 检查是否已安装
    if [[ -d "/etc/edgebox" ]] && [[ -f "/etc/edgebox/config/server.json" ]]; then
        # v4.6.0-rc4-rc1: 升级路径 — EDGEBOX_UPGRADE=1 或 keep 文件存在 ⇒ 静默允许
        if [[ "${EDGEBOX_UPGRADE:-0}" == "1" ]] || [[ -f /tmp/edgebox-keep-server.json ]]; then
            log_info "升级模式 (EDGEBOX_UPGRADE=1)：跳过覆盖确认，复用现有凭据"
        else
        log_warn "检测到已安装的EdgeBox，这将覆盖现有配置"
        # Accept force confirmation via:
        #   1. Env var EDGEBOX_FORCE=1 (only works if env passes through to script)
        #   2. Marker file /tmp/edgebox_force_install (always works, just touch it before running)
        if [[ "${EDGEBOX_FORCE:-0}" == "1" || "${EDGEBOX_FORCE:-0}" == "yes" ]]; then
            log_info "EDGEBOX_FORCE=1 已设置，跳过确认，继续覆盖安装"
        elif [[ -f /tmp/edgebox_force_install ]]; then
            log_info "检测到强制安装标记 /tmp/edgebox_force_install，继续覆盖安装"
            rm -f /tmp/edgebox_force_install
        elif [[ ! -t 0 ]]; then
            # stdin is not a TTY (e.g. curl | bash) - cannot prompt user
            log_error "================================================================"
            log_error " 检测到 EdgeBox 已安装，且当前为非交互式安装（无法弹出确认）"
            log_error " 如果你是想升级，请用: ${YELLOW}edgeboxctl upgrade${NC}"
            log_error " 如果是想强制覆盖（会丢失客户端凭据！），请用以下方式："
            log_error "================================================================"
            log_error ""
            log_error " 【方式1，最简单】先放一个标记文件，然后重跑你刚才的命令:"
            log_error "   touch /tmp/edgebox_force_install"
            log_error "   curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/bootstrap.sh | sudo bash"
            log_error ""
            log_error " 【方式2】sudo 直接传环境变量:"
            log_error "   curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/bootstrap.sh | sudo EDGEBOX_FORCE=1 bash"
            log_error ""
            log_error " 【方式3】先彻底清理，再正常安装:"
            log_error "   sudo systemctl stop nginx xray sing-box 2>/dev/null"
            log_error "   sudo rm -rf /etc/edgebox /var/www/html/sub-* /usr/local/bin/edgeboxctl"
            log_error "   curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/bootstrap.sh | sudo bash"
            log_error ""
            log_error "================================================================"
            exit 1
        else
            read -p "是否继续？[y/N]: " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "安装已取消"
                exit 0
            fi
        fi
        fi  # end upgrade-mode bypass else
    fi

    # 检查关键端口占用
    local critical_ports=(443 80)
    local port_conflicts=()

    for port in "${critical_ports[@]}"; do
        if ss -tlnp 2>/dev/null | grep -q ":${port} " || ss -ulnp 2>/dev/null | grep -q ":${port} "; then
            port_conflicts+=("$port")
        fi
    done

   if [[ ${#port_conflicts[@]} -gt 0 ]]; then
    log_warn "检测到端口冲突: ${port_conflicts[*]}"
    log_warn "这些端口将被EdgeBox使用，现有服务可能会停止"
    # 仅提示，不交互也不退出
fi

    log_success "预安装检查通过"
}

# 安装进度显示
#############################################
# 函数：show_progress
# 作用：控制台进度条输出（仅显示，不影响逻辑）
# 输入：$1=current；$2=total；$3=描述文本
# 输出：无（打印到 stdout）
# ANCHOR: [UI-PROGRESS]
#############################################
show_progress() {
    local current=$1
    local total=$2
    local description="$3"
    local percentage=$((current * 100 / total))
    local completed=$((percentage / 2))
    local remaining=$((50 - completed))

    printf "\r${CYAN}安装进度: [${NC}"
    printf "%${completed}s" | tr ' ' '='
    printf "${GREEN}>${NC}"
    printf "%${remaining}s" | tr ' ' '-'
    printf "${CYAN}] %d%% - %s${NC}" "$percentage" "$description"

    if [[ $current -eq $total ]]; then
        echo ""
    fi
}

# 主安装流程
# ======================== 主流程（入口） ===========================
#############################################
# 函数：main
# 作用：顶层安装编排（不改变任何原有步骤与顺序）
# 输入：无（依赖：全局变量与各模块函数）
# 输出：安装过程日志与最终提示
# ANCHOR: [ENTRY-MAIN]
#############################################
main() {
    trap cleanup_all EXIT

    clear

    echo -e "${GREEN}EdgeBox 企业级安装脚本 v4.7.0 (两协议架构)${NC}"
    print_separator

    export EDGEBOX_VER="4.7.0"
    mkdir -p "$(dirname "${LOG_FILE}")" && touch "${LOG_FILE}"
    chmod 600 "${LOG_FILE}" 2>/dev/null || true
    chown root:root "${LOG_FILE}" 2>/dev/null || true

    log_info "开始执行完整安装流程..."

    # --- 模块1: 基础环境准备 ---
    show_progress 1 10 "系统环境检查"
    pre_install_check       || { log_error "pre_install_check 失败"; exit 1; }
    check_root              || { log_error "check_root 失败"; exit 1; }
    check_system            || { log_error "check_system 失败"; exit 1; }
    install_dependencies    || { log_error "install_dependencies 失败"; exit 1; }

    show_progress 2 10 "网络与目录配置"
    get_server_ip           || { log_error "get_server_ip 失败"; exit 1; }
    setup_directories       || { log_error "setup_directories 失败"; exit 1; }

    # v4.0.0: install lib files to ${SCRIPTS_DIR}/lib for edgeboxctl runtime use
    # v4.1.0: also install alert.sh (used by health monitor and traffic alert)
    if [[ -d "$EB_BOOTSTRAP_LIB_DIR" ]]; then
        mkdir -p "${SCRIPTS_DIR}/lib"
        for _lib in common.sh subscription.sh alert.sh; do
            if [[ -f "${EB_BOOTSTRAP_LIB_DIR}/${_lib}" ]]; then
                install -m 0644 "${EB_BOOTSTRAP_LIB_DIR}/${_lib}" "${SCRIPTS_DIR}/lib/" 2>/dev/null \
                    || cp -f "${EB_BOOTSTRAP_LIB_DIR}/${_lib}" "${SCRIPTS_DIR}/lib/"
            fi
        done
        log_success "Lib files installed to ${SCRIPTS_DIR}/lib/"
    fi
    setup_sni_pool_management
    check_ports
    # v4.6.0-rc4 (审核 P2): 不再外层调用 setup_firewall_rollback
    # configure_firewall 内部第 1538 行会调用它，外层重复调用是 v4.5 残留
    configure_firewall      || { log_error "configure_firewall 失败"; exit 1; }
    optimize_system

    # --- 模块2: 凭据与证书生成 ---
    show_progress 3 10 "生成安全凭据和证书"
    execute_module2 || { log_error "模块2执行失败"; exit 1; }

    # --- 模块3: 核心组件安装与配置 ---
    show_progress 4 10 "安装核心组件 (Xray, sing-box)"
    install_xray            || { log_error "install_xray 失败"; exit 1; }
    install_sing_box        || { log_error "install_sing_box 失败"; exit 1; }

    show_progress 5 10 "配置服务 (Xray, sing-box, Nginx)"
    configure_xray          || { log_error "configure_xray 失败"; exit 1; }
    configure_sing_box      || { log_error "configure_sing_box 失败"; exit 1; }
    configure_nginx         || { log_error "configure_nginx 失败"; exit 1; }

    # --- 模块4: 后台、监控与运维工具 ---
    show_progress 6 10 "安装后台面板和监控脚本"
    execute_module4 || { log_error "模块4执行失败"; exit 1; }

    # 安装并初始化 IP 质量评分栈
    install_ipq_stack       || { log_error "install_ipq_stack 失败"; exit 1; }

    if ! setup_traffic_randomization; then
        log_error "流量特征随机化系统设置失败"
        exit 1
    fi

    # v4.6.0-rc4: logrotate 配置 (审核 P1#8) — 失败不致命
    setup_logrotate || log_warn "logrotate 配置失败（非致命，但请手动检查 /etc/logrotate.d/edgebox）"

    # --- 最终阶段: 启动、验证与数据生成 ---
    show_progress 8 10 "生成订阅链接"
    generate_subscription   || { log_error "generate_subscription 失败"; exit 1; }

    show_progress 9 10 "启动并验证所有服务"
    start_and_verify_services || { log_error "服务未能全部正常启动，请检查日志"; exit 1; }

    show_progress 10 10 "最终数据生成与同步"
    finalize_data_generation || { log_error "finalize_data_generation 失败"; exit 1; }

    # v4.6.0-rc4-rc1: 证书续期钩子是可选的（自签名模式不需要），失败仅警告不阻断
    setup_certbot_renewal_hook || log_warn "证书续期钩子配置失败 (自签名模式可忽略)"

# 显示安装信息
show_installation_info

echo
echo -e "${GREEN}🌐 EdgeBox-企业级多协议节点 v${EDGEBOX_VER} 安装成功完成！🎉🎉🎉${NC}"
echo

# 将剩余的非关键修复任务放入后台
# v4.7.0: 升级模式下不启动后台修复任务，拓扑恢复由 edgeboxctl 在 install 完成后负责，
#   避免后台 repair_system_state 与之竞争。
if [[ "${EDGEBOX_UPGRADE:-0}" == "1" ]]; then
    log_info "升级模式：跳过后台 repair_system_state（拓扑恢复由 edgeboxctl 负责）"
else
    (
        sleep 3
        log_info "[后台任务] 开始执行系统最终状态修复与优化..."
        repair_system_state
        log_info "[后台任务] 所有优化已完成。"
    ) >/dev/null 2>&1 &
fi

exit 0
}

# 系统状态检查和修复函数
#############################################
# 函数：repair_system_state
# 作用：见函数体（本优化版仅加注释，不改变逻辑）
# 输入：根据函数体（一般通过全局变量/环境）
# 输出：返回码；或对系统文件/服务的副作用（见函数体注释）
# ANCHOR: [FUNC-REPAIR_SYSTEM_STATE]
#############################################
repair_system_state() {
    log_info "检查并修复系统状态..."

    # 1) 目录与日志 (使用新的统一函数)
    setup_directories

    # 2) 服务自愈
    local services=("xray" "sing-box" "nginx")
    for s in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^${s}.service"; then
            systemctl enable "$s" >/dev/null 2>&1 || true
        fi
    done

    # 3) 修正 sing-box 监听地址（兼容旧残留）
    local sb="${CONFIG_DIR}/sing-box.json"
    if [[ -f "$sb" ]] && grep -q '"listen": "::"' "$sb"; then
        sed -i 's/"listen": "::"/"listen": "0.0.0.0"/g' "$sb"
        log_info "已将 sing-box 监听地址修正为 0.0.0.0"
    fi

    # 4) 防火墙放行 UDP（HY2）
    if command -v ufw >/dev/null 2>&1 && ufw status >/dev/null 2>&1; then
      ufw status | grep -q '443/udp'  || ufw allow 443/udp  >/dev/null 2>&1 || true
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
      firewall-cmd --permanent --add-port=443/udp  >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
    else
      iptables -C INPUT -p udp --dport 443  -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p udp --dport 443  -j ACCEPT
          command -v iptables-save >/dev/null 2>&1 && { mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4 2>/dev/null || true; }
    fi

    # 5) 确认证书可用（若缺失则再次生成自签名）
    if [[ ! -s "${CERT_DIR}/current.pem" || ! -s "${CERT_DIR}/current.key" ]]; then
        log_warn "未发现有效证书，尝试生成自签名证书..."
        generate_self_signed_cert || log_warn "自签名证书生成失败，请稍后手动检查"
    fi

    # 6) 语义校验并重启 sing-box
    if command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
        /usr/local/bin/sing-box check -c "$sb" >/dev/null 2>&1 || log_warn "sing-box 配置校验失败（将尝试继续重启）"
    fi
    systemctl reload sing-box 2>/dev/null \
  || /bin/sh -c '/bin/kill -HUP "$(pidof -s sing-box)" 2>/dev/null' \
  || systemctl restart sing-box || true

    sleep 0.5

    # 7) 端口自检
    ss -uln | grep -q ':443 '  && log_success "HY2 UDP 443 监听 ✓"  || log_warn "HY2 UDP 443 未监听 ✗"

    log_success "系统状态修复完成"
}

# 脚本入口点检查
# Cases to handle:
#  1. ./install.sh        -> BASH_SOURCE[0] = "./install.sh",  $0 = "./install.sh"     (match)
#  2. bash install.sh     -> BASH_SOURCE[0] = "install.sh",    $0 = "install.sh"       (match)
#  3. curl | bash         -> BASH_SOURCE[0] = "",              $0 = "bash"             (no match, but should run)
#  4. bash <(curl ...)    -> BASH_SOURCE[0] = "/dev/fd/63",    $0 = "/dev/fd/63"       (match)
#  5. source install.sh   -> BASH_SOURCE[0] = "install.sh",    $0 = "bash"             (no match, should NOT run)
#
# So: run main if (BASH_SOURCE[0] matches $0) OR (BASH_SOURCE[0] is empty - means piped via stdin)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]] || [[ -z "${BASH_SOURCE[0]:-}" ]]; then
    main "$@"
fi
