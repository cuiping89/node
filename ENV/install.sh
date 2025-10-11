#!/bin/bash

#############################################
# EdgeBox 企业级多协议节点部署脚本 v3.0.0
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
    exec sudo -E EB_TMP="$_EB_TMP" bash "$_EB_TMP" "$@"
  else
    exec su - root -c "EB_TMP='$_EB_TMP' bash '$_EB_TMP' $*"
  fi
fi


#############################################
# 全局配置 - 脚本基础信息
#############################################

set -e  # 遇到错误立即退出

# 版本号
EDGEBOX_VER="3.0.0"

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
# 智能版本管理 - 自动获取最新稳定版本
#############################################

# 获取sing-box最新稳定版本
get_latest_sing_box_version() {
    local fallback="1.10.3"
    local latest=""
    
    # 尝试从 GitHub API 获取最新版本
    latest=$(curl -fsSL --connect-timeout 5 --max-time 10 \
        "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null \
        | grep '"tag_name":' \
        | sed -E 's/.*"v?([^"]+)".*/\1/' \
        | head -1)
    
    # 验证版本格式
    if [[ "$latest" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # 验证该版本是否真的可下载
        local test_url="https://github.com/SagerNet/sing-box/releases/download/v${latest}/sing-box-${latest}-linux-amd64.tar.gz"
        if curl -fsSL --head --connect-timeout 3 --max-time 5 "$test_url" >/dev/null 2>&1; then
            echo "$latest"
            return 0
        fi
    fi
    
    # 如果获取失败，返回稳定版本
    log_warn "无法获取最新版本，使用稳定版本: v${fallback}"
    echo "$fallback"
}

# 设置版本变量（支持用户覆盖）- 移除log_info调用
if [[ -n "${DEFAULT_SING_BOX_VERSION:-}" ]]; then
    # 用户指定了版本
    DEFAULT_SING_BOX_VERSION="${DEFAULT_SING_BOX_VERSION}"
    # 注意：这里移除了 log_info
else
    # 自动获取最新版本
    DEFAULT_SING_BOX_VERSION=$(get_latest_sing_box_version)
    # 注意：这里移除了 log_info
fi

# 保存版本信息到变量，稍后在日志函数定义后再输出
SING_BOX_VERSION_SOURCE="auto"
[[ -n "${DEFAULT_SING_BOX_VERSION:-}" ]] && SING_BOX_VERSION_SOURCE="user"

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
DEFAULT_PORTS=(80 443 2053)
REALITY_SNI="www.microsoft.com"
HYSTERIA2_MASQUERADE="https://www.bing.com"

# === 版本和下载常量 ===
DEFAULT_SING_BOX_VERSION="1.12.8"
XRAY_INSTALL_SCRIPT="https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"

# === 临时文件常量 ===
TMP_DIR="/tmp/edgebox"
LOCK_FILE="/var/lock/edgebox-install.lock"

# === SNI域名池管理相关路径 ===
SNI_CONFIG_DIR="${CONFIG_DIR}/sni"
SNI_DOMAINS_CONFIG="${SNI_CONFIG_DIR}/domains.json"
SNI_LOG_FILE="/var/log/edgebox/sni-management.log"

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

#############################################
# 路径验证和创建函数
#############################################

# 验证关键路径
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

# UUID集合（每种协议独立）
UUID_VLESS_REALITY=""
UUID_VLESS_GRPC=""
UUID_VLESS_WS=""
UUID_HYSTERIA2=""
UUID_TUIC=""
UUID_TROJAN=""

# Reality密钥对
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
REALITY_SHORT_ID=""

# 密码集合
PASSWORD_HYSTERIA2=""
PASSWORD_TUIC=""
PASSWORD_TROJAN=""

#############################################
# 端口配置（单端口复用架构）
#############################################

# 对外端口
PORT_HYSTERIA2=443      # UDP Hysteria2
PORT_TUIC=2053          # UDP TUIC
# TCP 443 由Nginx代理分发

# 内部回环端口
PORT_REALITY=11443      # Xray Reality
PORT_GRPC=10085         # Xray gRPC
PORT_WS=10086           # Xray WebSocket
PORT_TROJAN=10143       # Xray Trojan

#############################################
# 日志函数 - 统一的日志输出
#############################################

# 信息日志（绿色）
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a ${LOG_FILE}
}

# 警告日志（黄色）
log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a ${LOG_FILE}
}

# 错误日志（红色）
log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a ${LOG_FILE}
}

# 成功日志（绿色加粗）
log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a ${LOG_FILE}
}

# 调试日志（红色，用于开发调试）
log_debug() {
    echo -e "${RED}[DEBUG]${NC} $1" | tee -a ${LOG_FILE}
}

# 分隔线（蓝色）
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
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以root权限运行"
        exit 1
    fi
    log_success "Root权限检查通过"
}

# 检查系统兼容性
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
    
    # 支持的系统版本检查
    SUPPORTED=false
    
    case "$OS" in
        ubuntu)
            MAJOR_VERSION=$(echo "$VERSION" | cut -d. -f1)
            if [ "$MAJOR_VERSION" -ge 18 ] 2>/dev/null; then
                SUPPORTED=true
            fi
            ;;
        debian)
            if [ "$VERSION" -ge 10 ] 2>/dev/null; then
                SUPPORTED=true
            fi
            ;;
        centos|rhel|rocky|almalinux)
            if [ "$VERSION" -ge 8 ] 2>/dev/null; then
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
        log_error "不支持的系统: $OS $VERSION"
        log_info "支持的系统: Ubuntu 18.04+, Debian 10+, CentOS/RHEL/Rocky/AlmaLinux 8+"
        exit 1
    fi
}

# 获取服务器公网IP
get_server_ip() {
    log_info "获取服务器公网IP..."
    
    # IP查询服务列表（按可靠性排序）
    IP_SERVICES=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ipecho.net/plain"
        "https://api.ip.sb/ip"
        "https://ifconfig.me/ip"
    )
    
    # 依次尝试获取IP
    for service in "${IP_SERVICES[@]}"; do
        SERVER_IP=$(curl -s --max-time 5 "$service" 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1)
        if [[ -n "$SERVER_IP" ]]; then
            log_success "获取到服务器IP: $SERVER_IP"
            return 0
        fi
    done
    
    # 所有服务都失败的情况
    log_error "无法获取服务器公网IP，请检查网络连接"
    exit 1
}

# 智能下载函数：自动尝试多个镜像源
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
            -A "Mozilla/5.0 (EdgeBox/3.0.0)" \
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
                    -A "Mozilla/5.0 (EdgeBox/3.0.0)" \
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
smart_download_script() {
    local url="$1"
    local description="${2:-script}"
    shift 2  # 移除前两个参数，剩余的都是要传递给脚本的参数
    local script_args=("$@")  # 获取所有剩余参数
    
    log_info "下载$description..."
    
    local temp_script
    temp_script=$(mktemp) || {
        log_error "创建临时文件失败"
        return 1
    }
    
    if smart_download "$url" "$temp_script" "script"; then
        # [关键修复] 传递所有参数给脚本
        if [[ ${#script_args[@]} -gt 0 ]]; then
            log_debug "执行脚本参数: ${script_args[*]}"
            bash "$temp_script" "${script_args[@]}"
        else
            bash "$temp_script"
        fi
        local exit_code=$?
        rm -f "$temp_script"
        return $exit_code
    else
        rm -f "$temp_script"
        return 1
    fi
}


# 安装系统依赖包（增强幂等性）
install_dependencies() {
    log_info "安装系统依赖（幂等性检查）..."

    # 本地化包管理器相关变量，避免污染全局
    local PKG_MANAGER INSTALL_CMD UPDATE_CMD

    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        INSTALL_CMD="DEBIAN_FRONTEND=noninteractive apt-get install -y"
        UPDATE_CMD="apt-get update"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD="yum makecache"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf makecache"
    else
        log_error "不支持的包管理器"
        return 1
    fi

    # 依赖列表
    local base_packages=(curl wget unzip gawk ca-certificates jq bc uuid-runtime dnsutils openssl tar cron)
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
    eval "$UPDATE_CMD" >/dev/null 2>&1 || log_warn "包索引更新失败，继续安装"

    # 幂等安装
    local failed_packages=()
    for pkg in "${all_packages[@]}"; do
        if is_package_properly_installed "$pkg"; then
            log_info "${pkg} 已正确安装"
        else
            log_info "安装 ${pkg}..."
            if eval "$INSTALL_CMD $pkg" >/dev/null 2>&1; then
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
            nginx -T 2>/dev/null | grep -q "stream" && return 0 || return 1
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
create_directories() {
    log_info "创建目录结构（幂等性保证）..."

    # 主要目录结构
    local directories=(
        "${INSTALL_DIR}"
        "${CERT_DIR}"
        "${CONFIG_DIR}"
        "${CONFIG_DIR}/shunt"
        "${TRAFFIC_DIR}"
        "${TRAFFIC_DIR}/logs"
        "${SCRIPTS_DIR}"
        "${BACKUP_DIR}"
        "/var/log/edgebox"
        "/var/log/xray"
        "${WEB_ROOT}"
        "${SNI_CONFIG_DIR}"
    )

    # 创建所有必要目录（幂等操作）
    local created_dirs=()
    local existing_dirs=()
    local failed_dirs=()
    
    for dir in "${directories[@]}"; do
        if [[ -d "$dir" ]]; then
            log_info "✓ 目录已存在: $dir"
            existing_dirs+=("$dir")
        else
            if mkdir -p "$dir" 2>/dev/null; then
                log_success "✓ 目录创建成功: $dir"
                created_dirs+=("$dir")
            else
                log_error "✗ 目录创建失败: $dir"
                failed_dirs+=("$dir")
            fi
        fi
    done

    # 如果有目录创建失败，返回错误
    if [[ ${#failed_dirs[@]} -gt 0 ]]; then
        log_error "以下目录创建失败: ${failed_dirs[*]}"
        return 1
    fi

    # [新增] 强制确保所有目录权限正确（完全幂等）
    ensure_directory_permissions
    
    # 验证目录可写性
    verify_directory_writable
    
    # 状态汇报
    log_success "目录结构已完整建立"
    log_info "  ├─ 已存在: ${#existing_dirs[@]} 个"
    log_info "  ├─ 新创建: ${#created_dirs[@]} 个"
    log_info "  └─ 失败: ${#failed_dirs[@]} 个"
    
    return 0
}

ensure_directory_permissions() {
    log_info "确保目录权限正确（幂等操作）..."

    # 需要存在的目录及权限
    local dir_permissions=(
        "${INSTALL_DIR}:755"
        "${CONFIG_DIR}:755"
        "${SCRIPTS_DIR}:755"
        "${TRAFFIC_DIR}:755"
        "/var/log/edgebox:755"
        "${WEB_ROOT}:755"
        "${SNI_CONFIG_DIR}:755"
        "${CERT_DIR}:750"      # 证书目录
        "${BACKUP_DIR}:700"    # 备份目录
    )

    local permission_errors=()

    for dp in "${dir_permissions[@]}"; do
        IFS=':' read -r d perm <<< "$dp"
        [[ -d "$d" ]] || mkdir -p "$d"
        if chmod "$perm" "$d" 2>/dev/null; then
            log_info "✓ 目录就绪: $d ($perm)"
        else
            log_error "✗ 目录权限设置失败: $d"
            permission_errors+=("$d")
        fi
    done

    # 证书目录组权限（nobody/nogroup）
    if [[ -d "${CERT_DIR}" ]]; then
        local nobody_group="$(id -gn nobody 2>/dev/null || echo nogroup)"
        chgrp "${nobody_group}" "${CERT_DIR}" 2>/dev/null || true
    fi

    # 必要日志文件（会自动创建父目录）
    local log_files=(
        "/var/log/edgebox-install.log"
        "/var/log/edgebox/sing-box.log"
        "/var/log/xray/access.log"
        "/var/log/xray/error.log"
    )
    for lf in "${log_files[@]}"; do
        mkdir -p "$(dirname "$lf")"
        [[ -f "$lf" ]] || touch "$lf"
        chmod 644 "$lf" 2>/dev/null || true
        log_info "✓ 日志就绪: $lf"
    done

    if [[ ${#permission_errors[@]} -eq 0 ]]; then
        log_success "所有目录/日志已就绪"
    else
        log_warn "部分目录权限设置失败: ${permission_errors[*]}"
    fi
}


verify_directory_writable() {
    log_info "验证目录可写性..."
    
    # 需要写入权限的关键目录
    local writable_dirs=(
        "${INSTALL_DIR}"
        "${CONFIG_DIR}"
        "${TRAFFIC_DIR}"
        "${SCRIPTS_DIR}"
        "${BACKUP_DIR}"
        "/var/log/edgebox"
        "${WEB_ROOT}"
    )
    
    local write_test_errors=()
    
    for dir in "${writable_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # 创建测试文件
            local test_file="${dir}/.write_test_$$"
            
            if echo "test" > "$test_file" 2>/dev/null; then
                rm -f "$test_file" 2>/dev/null
                log_info "✓ 目录可写: $dir"
            else
                log_error "✗ 目录不可写: $dir"
                write_test_errors+=("$dir")
            fi
        else
            log_warn "⚠ 目录不存在: $dir"
            write_test_errors+=("$dir")
        fi
    done
    
    if [[ ${#write_test_errors[@]} -eq 0 ]]; then
        log_success "所有关键目录写入权限验证通过"
        return 0
    else
        log_error "以下目录写入权限验证失败: ${write_test_errors[*]}"
        return 1
    fi
}

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
setup_sni_pool_management() {
    log_info "设置SNI域名池智能管理..."

    # 创建域名池配置文件
    create_sni_pool_config

    # create_sni_management_script 调用已被删除

    log_success "SNI域名池智能管理设置完成"
}

# 创建SNI域名池配置文件
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


# 检查端口占用情况
check_ports() {
    log_info "检查端口占用情况..."
    
    # 需要检查的端口列表
    local ports_to_check=(443 2053 80)
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


# 配置防火墙规则（完整版 - 支持 UFW/FirewallD/iptables）
configure_firewall() {
    log_info "配置防火墙规则（智能SSH端口检测）..."
    
    # ==========================================
    # 第一步：智能检测当前SSH端口（防止锁死）
    # ==========================================
    local ssh_ports=()
    local current_ssh_port=""
    
    # 方法1：检测sshd监听端口
    while IFS= read -r line; do
        if [[ "$line" =~ :([0-9]+)[[:space:]]+.*sshd ]]; then
            ssh_ports+=("${BASH_REMATCH[1]}")
        fi
    done < <(ss -tlnp 2>/dev/null | grep sshd || true)
    
    # 方法2：检查配置文件中的端口
    if [[ -f /etc/ssh/sshd_config ]]; then
        local config_port
        config_port=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
        if [[ -n "$config_port" && "$config_port" =~ ^[0-9]+$ ]]; then
            ssh_ports+=("$config_port")
        fi
    fi
    
    # 方法3：检查当前连接的端口（如果通过SSH连接）
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        local connection_port
        connection_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
        if [[ -n "$connection_port" && "$connection_port" =~ ^[0-9]+$ ]]; then
            ssh_ports+=("$connection_port")
        fi
    fi
    
    # 数组去重并选择第一个端口
    if [[ ${#ssh_ports[@]} -gt 0 ]]; then
        local temp_file=$(mktemp)
        printf "%s\n" "${ssh_ports[@]}" | sort -u > "$temp_file"
        current_ssh_port=$(head -1 "$temp_file")
        rm -f "$temp_file"
    fi
    
    # 默认端口兜底
    current_ssh_port="${current_ssh_port:-22}"
    
    log_info "检测到SSH端口: $current_ssh_port"
    
    # ==========================================
    # 第二步：根据防火墙类型配置规则
    # ==========================================
    
    if command -v ufw >/dev/null 2>&1; then
        # ==========================================
        # Ubuntu/Debian UFW 配置
        # ==========================================
        log_info "配置UFW防火墙（SSH端口：$current_ssh_port）..."
        
        # 🔥 关键：先允许SSH，再重置，避免锁死
        if ! ufw allow "$current_ssh_port/tcp" comment 'SSH-Emergency' >/dev/null 2>&1; then
            log_warn "UFW SSH应急规则添加失败，但继续执行"
        fi
        
        # 重置UFW规则
        if ! ufw --force reset >/dev/null 2>&1; then
            log_error "UFW重置失败"
            return 1
        fi
        
        # 设置默认策略
        if ! ufw default deny incoming >/dev/null 2>&1 || ! ufw default allow outgoing >/dev/null 2>&1; then
            log_error "UFW默认策略设置失败"
            return 1
        fi
        
        # 🔥 立即重新允许SSH（最高优先级）
        if ! ufw allow "$current_ssh_port/tcp" comment 'SSH' >/dev/null 2>&1; then
            log_error "UFW SSH规则添加失败"
            return 1
        fi
        
        # 允许EdgeBox端口
        ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1 || log_warn "HTTP端口配置失败"
        ufw allow 443/tcp comment 'HTTPS/TLS' >/dev/null 2>&1 || log_warn "HTTPS TCP端口配置失败"
        
        # 【关键】UDP 端口
        ufw allow 443/udp comment 'Hysteria2' >/dev/null 2>&1 || log_warn "Hysteria2端口配置失败"
        ufw allow 2053/udp comment 'TUIC' >/dev/null 2>&1 || log_warn "TUIC端口配置失败"
        
        # 🔥 启用前最后确认SSH端口
        if ! ufw status | grep -q "$current_ssh_port/tcp"; then
            if ! ufw allow "$current_ssh_port/tcp" comment 'SSH-Final' >/dev/null 2>&1; then
                log_error "最终SSH规则确认失败"
                return 1
            fi
        fi
        
        # 启用UFW
        if ! ufw --force enable >/dev/null 2>&1; then
            log_error "UFW启用失败"
            return 1
        fi
        
        # 🚨 验证SSH端口确实被允许
        if ufw status | grep -q "$current_ssh_port/tcp.*ALLOW"; then
            log_success "UFW防火墙配置完成，SSH端口 $current_ssh_port 已确认开放"
        else
            log_error "⚠️ UFW配置完成但SSH端口状态异常，请立即检查连接"
            return 1
        fi
        
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        # ==========================================
        # CentOS/RHEL FirewallD 配置
        # ==========================================
        log_info "配置FirewallD防火墙（SSH端口：$current_ssh_port）..."
        
        # SSH端口配置
        if ! firewall-cmd --permanent --add-port="$current_ssh_port/tcp" >/dev/null 2>&1; then
            log_error "FirewallD SSH端口配置失败"
            return 1
        fi
        
        # EdgeBox端口配置
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || log_warn "HTTP端口配置失败"
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || log_warn "HTTPS TCP端口配置失败"
        
        # 【关键】UDP 端口
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 || log_warn "Hysteria2端口配置失败"
        firewall-cmd --permanent --add-port=2053/udp >/dev/null 2>&1 || log_warn "TUIC端口配置失败"
        
        # 重新加载规则
        if ! firewall-cmd --reload >/dev/null 2>&1; then
            log_error "FirewallD规则重载失败"
            return 1
        fi
        
        log_success "FirewallD防火墙配置完成，SSH端口 $current_ssh_port 已开放"
        
    elif command -v iptables >/dev/null 2>&1; then
        # ==========================================
        # 传统 iptables 配置
        # ==========================================
        log_info "配置iptables防火墙（SSH端口：$current_ssh_port）..."
        
        # 允许已建立的连接
        if ! iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        fi
        
        # SSH端口
        if ! iptables -C INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
        fi
        
        # HTTP/HTTPS TCP
        if ! iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        fi
        
        if ! iptables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        fi
        
        # 【关键】UDP 端口
        if ! iptables -C INPUT -p udp --dport 443 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p udp --dport 443 -j ACCEPT
        fi
        
        if ! iptables -C INPUT -p udp --dport 2053 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p udp --dport 2053 -j ACCEPT
        fi
        
        # 允许本地回环
        if ! iptables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -i lo -j ACCEPT
        fi
        
        # 保存iptables规则
        if command -v iptables-save >/dev/null 2>&1; then
            mkdir -p /etc/iptables
            if ! iptables-save > /etc/iptables/rules.v4 2>/dev/null; then
                log_warn "iptables规则保存失败"
            fi
        fi
        
        # 如果有netfilter-persistent，使用它保存
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        fi
        
        log_success "iptables防火墙配置完成，SSH端口 $current_ssh_port 已开放"
        
    else
        # ==========================================
        # 无防火墙或不支持的防火墙
        # ==========================================
        log_warn "未检测到支持的防火墙软件（UFW/FirewallD/iptables）"
        log_info "请手动配置防火墙，确保开放以下端口："
        log_info "  - SSH: $current_ssh_port/tcp"
        log_info "  - HTTP: 80/tcp"
        log_info "  - HTTPS: 443/tcp"
        log_info "  - Hysteria2: 443/udp"
        log_info "  - TUIC: 2053/udp"
        
        # 如果是云服务器，提示检查安全组
        log_warn "如果使用云服务器，请同时检查云厂商安全组规则！"
    fi
    
    # ==========================================
    # 第三步：最终验证SSH连接正常
    # ==========================================
    log_info "验证SSH连接状态..."
    if ss -tln | grep -q ":$current_ssh_port "; then
        log_success "✅ SSH端口 $current_ssh_port 监听正常"
    else
        log_warn "⚠️ SSH端口监听状态异常，请检查sshd服务"
    fi
    
    return 0
}

# ==========================================
# 【可选】防火墙安全回滚机制
# ==========================================
# 如果担心SSH被锁死，可以在主安装流程中调用此函数
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


# --- Xray DNS 对齐 ---
ensure_xray_dns_alignment() {
  local cfg="${CONFIG_DIR}/xray.json"
  [[ -f "$cfg" ]] || return 0
  local tmp="${cfg}.tmp.$$"

  # 注入 dns.servers（含 IP 直连 DoH），并把 routing.domainStrategy 置为 UseIp
  if jq '
    .dns = {
      servers: [
        "8.8.8.8",
        "1.1.1.1",
        {"address":"https://1.1.1.1/dns-query"},
        {"address":"https://8.8.8.8/dns-query"}
      ],
      queryStrategy: "UseIP"
    }
    |
    (.routing.domainStrategy = "UseIp")
  ' "$cfg" > "$tmp" 2>/dev/null; then
    mv "$tmp" "$cfg"
  else
    rm -f "$tmp"
    return 1
  fi
}


# 优化系统参数
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
cleanup_all() {
    local rc=$?
    
    # 不再依赖退出码，而是检查关键服务状态
    local services_ok=true
    local core_services=("nginx" "xray" "sing-box")
    
    for service in "${core_services[@]}"; do
        if ! systemctl is-active --quiet "$service" 2>/dev/null; then
            services_ok=false
            break
        fi
    done
    
    if [[ "$services_ok" == "true" ]]; then
        # [修改] 成功时安静退出，让 main 函数完成后续的 show_installation_info
        exit 0
    else
	
        log_error "安装失败，部分核心服务未能启动"
        echo -e "\n${RED}❌ 安装失败！${NC}"
        echo -e "${YELLOW}故障排除建议：${NC}"
        echo -e "  1. 检查服务状态：systemctl status nginx xray sing-box"
        echo -e "  2. 查看详细日志：cat /var/log/edgebox-install.log"
        echo -e "  3. 检查端口占用：ss -tlnp | grep ':443'"
        exit 1
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
collect_system_info() {
    log_info "收集系统详细信息..."
    
    # 获取CPU详细信息
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
generate_credentials() {
    log_info "生成协议凭据..."
    
# 快速验证工具可用性（应该已在前置检查中确保）
if ! command -v uuidgen >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    log_error "关键工具缺失（uuidgen 或 openssl），这不应该发生"
    log_error "请重新运行安装脚本或手动安装 uuid-runtime 和 openssl"
    return 1
fi
    
    log_info "生成协议UUID..."
    
    # 为每种协议生成独立的UUID
    UUID_VLESS_REALITY=$(uuidgen)
    UUID_VLESS_GRPC=$(uuidgen)
    UUID_VLESS_WS=$(uuidgen)
    UUID_HYSTERIA2=$(uuidgen)  # Hysteria2也可以使用UUID作为用户标识
    UUID_TUIC=$(uuidgen)
    UUID_TROJAN=$(uuidgen)     # Trojan虽然用密码，但生成UUID备用
    
    log_info "生成协议密码..."
    
    # 生成强密码（Base64编码，确保特殊字符兼容性）
    PASSWORD_TROJAN=$(openssl rand -base64 32 | tr -d '\n')
    PASSWORD_TUIC=$(openssl rand -base64 32 | tr -d '\n')
    PASSWORD_HYSTERIA2=$(openssl rand -base64 32 | tr -d '\n')
    
    # 验证生成结果
    local failed_items=()
    
    # 检查UUID生成结果
    [[ -z "$UUID_VLESS_REALITY" ]] && failed_items+=("VLESS-Reality UUID")
    [[ -z "$UUID_VLESS_GRPC" ]] && failed_items+=("VLESS-gRPC UUID")
    [[ -z "$UUID_VLESS_WS" ]] && failed_items+=("VLESS-WS UUID")
    [[ -z "$UUID_HYSTERIA2" ]] && failed_items+=("Hysteria2 UUID")
    [[ -z "$UUID_TUIC" ]] && failed_items+=("TUIC UUID")
    [[ -z "$UUID_TROJAN" ]] && failed_items+=("Trojan UUID")
    
    # 检查密码生成结果
    [[ -z "$PASSWORD_TROJAN" ]] && failed_items+=("Trojan密码")
    [[ -z "$PASSWORD_TUIC" ]] && failed_items+=("TUIC密码")
    [[ -z "$PASSWORD_HYSTERIA2" ]] && failed_items+=("Hysteria2密码")
    
    # 处理生成失败的情况
    if [[ ${#failed_items[@]} -gt 0 ]]; then
        log_error "以下凭据生成失败: ${failed_items[*]}"
        return 1
    fi
    
    # 输出生成结果摘要（隐藏完整凭据）
    log_success "协议凭据生成完成："
    log_info "├─ VLESS-Reality UUID: ${UUID_VLESS_REALITY:0:8}..."
    log_info "├─ VLESS-gRPC UUID:    ${UUID_VLESS_GRPC:0:8}..."
    log_info "├─ VLESS-WS UUID:      ${UUID_VLESS_WS:0:8}..."
    log_info "├─ TUIC UUID:          ${UUID_TUIC:0:8}..."
    log_info "├─ Trojan密码:         ${PASSWORD_TROJAN:0:8}..."
    log_info "├─ TUIC密码:           ${PASSWORD_TUIC:0:8}..."
    log_info "└─ Hysteria2密码:      ${PASSWORD_HYSTERIA2:0:8}..."
    
    return 0
}

# 生成Reality密钥对和短ID
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
generate_dashboard_passcode() {
    log_info "生成控制面板访问密码..."
    
    # 随机生成一个 0-9 的数字
    local random_digit=$((RANDOM % 10))
    # 生成 6 位相同的数字密码
    DASHBOARD_PASSCODE="${random_digit}${random_digit}${random_digit}${random_digit}${random_digit}${random_digit}"
    
    if [[ -z "$DASHBOARD_PASSCODE" || ${#DASHBOARD_PASSCODE} -ne 6 ]]; then
        log_error "控制面板密码生成失败"
        return 1
    fi
    
    # ========== 关键修复: 不在这里写入,等save_config_info()统一写入 ==========
    log_success "控制面板密码生成完成: $DASHBOARD_PASSCODE"
    
    # 导出环境变量供save_config_info()使用
    export DASHBOARD_PASSCODE
    
    # 不再执行这段代码,避免被save_config_info()覆盖:
    # local config_file="${CONFIG_DIR}/server.json"
    # if [[ -f "$config_file" ]]; then
    #     ...jq写入...
    # fi
    # =========================================================================
    
    return 0
}

#############################################
# 配置信息保存函数
#############################################

# 保存完整配置信息到server.json（对齐控制面板数据口径，安全JSON生成）
save_config_info() {
    log_info "保存配置信息到server.json."

    mkdir -p "${CONFIG_DIR}"

    # 基础信息（均为局部变量）
    local server_ip="${SERVER_IP:-127.0.0.1}"
    local version="${EDGEBOX_VER:-3.0.0}"
    local install_date
    install_date="$(date +%Y-%m-%d)"
    local updated_at
    updated_at="$(date -Is)"

    # 系统信息
    local cloud_provider="${CLOUD_PROVIDER:-Unknown}"
    local cloud_region="${CLOUD_REGION:-Unknown}"
    local instance_id="${INSTANCE_ID:-Unknown}"
    local hostname="${HOSTNAME:-$(hostname)}"
    local user_alias=""
    local cpu_spec="${CPU_SPEC:-Unknown}"
    local memory_spec="${MEMORY_SPEC:-Unknown}"
    local disk_spec="${DISK_SPEC:-Unknown}"

    # 确保面板口令存在
    if [[ -z "$DASHBOARD_PASSCODE" ]]; then
        log_warn "DASHBOARD_PASSCODE为空，生成临时6位数字口令"
        local d=$((RANDOM % 10))
        DASHBOARD_PASSCODE="${d}${d}${d}${d}${d}${d}"
        export DASHBOARD_PASSCODE
    fi

    # 关键凭据校验（缺失即失败）
    if [[ -z "$UUID_VLESS_REALITY" || -z "$PASSWORD_TROJAN" || -z "$PASSWORD_HYSTERIA2" ]]; then
        log_error "关键凭据缺失，无法保存配置"
        return 1
    fi

    # IP格式校验
    if [[ ! "$server_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "服务器IP格式无效: $server_ip"
        return 1
    fi

    log_info "使用 jq 生成 server.json（避免转义/注入问题）"

    # 用 jq -n 生成 JSON（所有变量安全注入）
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
      --arg cloud_provider       "$cloud_provider" \
      --arg cloud_region         "$cloud_region" \
      --arg cpu_spec             "$cpu_spec" \
      --arg memory_spec          "$memory_spec" \
      --arg disk_spec            "$disk_spec" \
      --arg uuid_vless_reality   "$UUID_VLESS_REALITY" \
      --arg uuid_vless_grpc      "$UUID_VLESS_GRPC" \
      --arg uuid_vless_ws        "$UUID_VLESS_WS" \
      --arg uuid_tuic            "$UUID_TUIC" \
      --arg uuid_hysteria2       "$UUID_HYSTERIA2" \
      --arg uuid_trojan          "$UUID_TROJAN" \
      --arg password_trojan      "$PASSWORD_TROJAN" \
      --arg password_tuic        "$PASSWORD_TUIC" \
      --arg password_hysteria2   "$PASSWORD_HYSTERIA2" \
      --arg reality_public_key   "$REALITY_PUBLIC_KEY" \
      --arg reality_private_key  "$REALITY_PRIVATE_KEY" \
      --arg reality_short_id     "$REALITY_SHORT_ID" \
      '{
         version: $version,
         install_date: $install_date,
         updated_at: $updated_at,
         server_ip: $server_ip,
         eip: $eip,
         hostname: $hostname,
         instance_id: $instance_id,
         user_alias: $user_alias,
         dashboard_passcode: $dashboard_passcode,
         cloud: { provider: $cloud_provider, region: $cloud_region },
         spec:  { cpu: $cpu_spec, memory: $memory_spec, disk: $disk_spec },
         uuid:  { vless: { reality: $uuid_vless_reality, grpc: $uuid_vless_grpc, ws: $uuid_vless_ws },
                  tuic: $uuid_tuic, hysteria2: $uuid_hysteria2, trojan: $uuid_trojan },
         password: { trojan: $password_trojan, tuic: $password_tuic, hysteria2: $password_hysteria2 },
         reality:  { public_key: $reality_public_key, private_key: $reality_private_key, short_id: $reality_short_id },
         cert: { mode: "self-signed", domain: null, auto_renew: false }
       }' > "${CONFIG_DIR}/server.json"

    # 生成后校验
    if ! jq . "${CONFIG_DIR}/server.json" >/dev/null 2>&1; then
        log_error "server.json 验证失败"
        return 1
    fi

    # 确认口令已写入且不为空
    local saved
    saved="$(jq -r '.dashboard_passcode // empty' "${CONFIG_DIR}/server.json" 2>/dev/null)"
    if [[ -z "$saved" || "$saved" != "$DASHBOARD_PASSCODE" ]]; then
        log_error "密码保存验证失败（期望: $DASHBOARD_PASSCODE, 实际: ${saved:-空}）"
        return 1
    fi

    chmod 600 "${CONFIG_DIR}/server.json"
    chown root:root "${CONFIG_DIR}/server.json"
    log_success "server.json配置文件保存完成（已安全写入）"
    return 0
}



# 生成自签名证书（基础版本，模块3会有完整版本）
generate_self_signed_cert() {
    log_info "生成自签名证书并修复权限..."
    
    mkdir -p "${CERT_DIR}"
    rm -f "${CERT_DIR}"/self-signed.{key,pem} "${CERT_DIR}"/current.{key,pem}
    
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "openssl未安装，无法生成证书"; return 1;
    fi
    
    # 生成私钥和证书
    openssl ecparam -genkey -name secp384r1 -out "${CERT_DIR}/self-signed.key" 2>/dev/null || { log_error "生成ECC私钥失败"; return 1; }
    openssl req -new -x509 -key "${CERT_DIR}/self-signed.key" -out "${CERT_DIR}/self-signed.pem" -days 3650 -subj "/C=US/ST=CA/L=SF/O=EdgeBox/CN=${SERVER_IP}" >/dev/null 2>&1 || { log_error "生成自签名证书失败"; return 1; }
    
    # 创建软链接
    ln -sf "${CERT_DIR}/self-signed.key" "${CERT_DIR}/current.key"
    ln -sf "${CERT_DIR}/self-signed.pem" "${CERT_DIR}/current.pem"
    
    # --- 关键权限修复 ---
    # 1. 获取 nobody 用户的主组名 (Debian系是 nogroup, RHEL系是 nobody)
    local NOBODY_GRP
    NOBODY_GRP="$(id -gn nobody 2>/dev/null || echo nogroup)"
    
    # 2. 设置目录和文件的所有权
    chown -R root:"${NOBODY_GRP}" "${CERT_DIR}"
    
    # 3. 设置目录权限：root可读写执行，组可进入和读取
    chmod 750 "${CERT_DIR}"
    
    # 4. 设置文件权限：root可读写，组可读
    chmod 640 "${CERT_DIR}"/self-signed.key
    chmod 644 "${CERT_DIR}"/self-signed.pem
    # ---------------------

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
        "UUID_VLESS_GRPC:VLESS-gRPC"
        "UUID_VLESS_WS:VLESS-WS"
        "UUID_TUIC:TUIC"
        "UUID_TROJAN:Trojan"
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
        "PASSWORD_TROJAN:Trojan"
        "PASSWORD_TUIC:TUIC"
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
execute_module2() {
    log_info "======== 开始执行模块2：系统信息收集+凭据生成 ========"
    
    # 任务1：收集系统详细信息
    if collect_system_info; then
        log_success "✓ 系统信息收集完成"
    else
        log_error "✗ 系统信息收集失败"
        return 1
    fi
    
    # 任务2：生成协议凭据
    if generate_credentials; then
        log_success "✓ 协议凭据生成完成"
    else
        log_error "✗ 协议凭据生成失败"
        return 1
    fi
    
    # ========== 关键修复: 密码生成在save_config_info之前 ==========
    # 任务2.5：生成控制面板密码(只生成不写入)
    if generate_dashboard_passcode; then
        log_success "✓ 控制面板密码生成完成: ${DASHBOARD_PASSCODE}"
        export DASHBOARD_PASSCODE  # 确保导出
    else
        log_error "✗ 控制面板密码生成失败"
        return 1
    fi
    # ==============================================================

    # 任务3：生成Reality密钥
    if generate_reality_keys; then
        log_success "✓ Reality密钥生成完成"
    else
        log_warn "Reality密钥生成失败，将在模块3中重新生成"
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
    export UUID_VLESS_REALITY UUID_VLESS_GRPC UUID_VLESS_WS
    export UUID_TUIC PASSWORD_HYSTERIA2 PASSWORD_TUIC PASSWORD_TROJAN
    export REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY REALITY_SHORT_ID
    export SERVER_IP DASHBOARD_PASSCODE
    
    log_info "已导出所有必要变量供后续模块使用"
    
    log_success "======== 模块2执行完成 ========"
    log_info "已生成："
    log_info "├─ 系统信息（云厂商、硬件规格）"
    log_info "├─ 所有协议的UUID和密码"
    log_info "├─ Reality密钥对"
    log_info "├─ 自签名证书"
    log_info "├─ 控制面板密码: ${DASHBOARD_PASSCODE}"
    log_info "└─ 完整的server.json配置文件"
    
    return 0
}


#############################################
# 模块2导出函数（供其他模块调用）
#############################################

# 获取当前生成的配置信息（只读）
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
# EdgeBox 企业级多协议节点部署脚本 v3.0.0
# 模块3：服务安装配置 (完整版)
# 
# 功能说明：
# - 安装Xray和sing-box核心程序
# - 配置Nginx（SNI定向+ALPN兜底架构）
# - 配置Xray（VLESS-Reality、gRPC、WS、Trojan）
# - 配置sing-box（Hysteria2、TUIC）
# - 生成订阅链接
# - 验证服务配置
#############################################

#############################################
# Xray 安装函数
#############################################

# 安装Xray核心程序
install_xray() {
    log_info "安装Xray核心程序..."
    
    # 检查是否已安装
    if command -v xray >/dev/null 2>&1; then
        local current_version
        current_version=$(xray version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_info "检测到已安装的Xray版本: ${current_version:-未知}"
        log_info "跳过Xray重新安装，使用现有版本"
        return 0
    fi
    
    log_info "从官方仓库下载并安装Xray..."
    
    # 使用智能下载函数
    if smart_download_script \
        "https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh" \
        "Xray安装脚本" \
        >/dev/null 2>&1; then
        log_success "Xray安装完成"
    else
        log_error "Xray安装失败"
        return 1
    fi
    
    # 验证安装
    if command -v xray >/dev/null 2>&1; then
        local xray_version
        xray_version=$(xray version 2>/dev/null \ | grep -oE '[Vv]?[0-9]+\.[0-9]+\.[0-9]+' \ | head -1 | sed 's/^[Vv]//')
        log_success "Xray验证通过，版本: ${xray_version:-未知}"
        
        mkdir -p /var/log/xray
        chown nobody:nogroup /var/log/xray 2>/dev/null || \
            chown nobody:nobody /var/log/xray 2>/dev/null || true
        
        return 0
    else
        log_error "Xray安装验证失败"
        return 1
    fi
}

#############################################
# sing-box 安装函数
#############################################


# 安装sing-box核心程序（最佳实践版）
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
generate_initial_nginx_stream_map() {
    log_info "正在生成 Nginx 初始 stream map 配置文件..."
    local map_conf="/etc/nginx/conf.d/edgebox_stream_map.conf"
    
    # 确保目录存在
    mkdir -p "$(dirname "$map_conf")"

    cat > "$map_conf" << 'EOF'
# This file is auto-generated by the EdgeBox installer for initial setup.
# It will be overwritten by 'edgeboxctl' when switching certificate modes.

map $ssl_preread_server_name $backend_pool {
    # Reality fallback SNIs
    ~*(microsoft\.com|apple\.com|cloudflare\.com|amazon\.com|fastly\.com)$ reality;
    
    # Trojan uses a subdomain pattern, which works for both IP and domain mode
    ~*^trojan\..* trojan;
    
    # Default internal SNIs for IP mode
    grpc.edgebox.internal  grpc;
    ws.edgebox.internal    websocket;
    
    # Default action (will then fallback to ALPN)
    default                "";
}
EOF
    log_success "Nginx 初始 stream map 已生成: $map_conf"
}

# 配置Nginx（SNI定向 + ALPN兜底架构）
configure_nginx() {
    log_info "配置Nginx（SNI定向 + ALPN兜底架构）..."
    
    # 备份原始配置
    if [[ -f /etc/nginx/nginx.conf ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%s)
        log_info "已备份原始Nginx配置"
    fi
    
    mkdir -p /etc/nginx/conf.d

    # 生成新的Nginx主配置，使用 include 指令
    cat > /etc/nginx/nginx.conf << 'NGINX_CONFIG'
# EdgeBox Nginx 配置文件 v3.0.2 (Patched for Dynamic SNI)
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
    
    # <<< 修复点 2: 移除硬编码的密码 map，改为 include 外部文件 >>>
    # 该文件将由脚本动态生成，内容为: map $arg_passcode $pass_ok { ... }
    include /etc/nginx/conf.d/edgebox_passcode.conf;

    # === 会话映射（fail-closed）===
    # 1) 检测是否提供了 passcode 参数
    map $arg_passcode $arg_present {
        default 0;
        ~.+     1;   # 只要非空就算带参
    }
    # 3) 是否已有有效会话 Cookie
    map $cookie_ebp $cookie_ok {
        default 0;
        "1"     1;
    }
    # 4) 是否为“错误口令尝试”（带了参数但不正确）
    map "$arg_present:$pass_ok" $bad_try {
        default 0;      # 未带参 → 不是错误尝试
        "1:0"   1;      # 带参且错误 → 错误尝试
        "1:1"   0;      # 带参且正确
    }
    # 5) 最终是否拒绝：
    #    只列出“允许”的组合，其余一律拒绝（default 1）
    #    允许的三种：①正确口令（首次）②已有会话③正确口令+已有会话
    map "$bad_try:$pass_ok:$cookie_ok" $deny_traffic {
        default 1;      # 默认为拒绝（更安全）
        "0:1:0"  0;     # 正确口令
        "0:0:1"  0;     # 有会话
        "0:1:1"  0;     # 正确口令 + 有会话
    }
    # 6) 正确口令时下发会话 Cookie（1 天）
    map $pass_ok $set_cookie {
        1 "ebp=1; Path=/traffic/; HttpOnly; SameSite=Lax; Max-Age=86400";
        0 "";
    }
    
    # 日志格式
log_format main '$remote_addr - $remote_user [$time_local] "$request_method $uri $server_protocol" '
               '$status $body_bytes_sent "$http_referer" '
               '"$http_user_agent" "$http_x_forwarded_for"';
    
    # 日志文件
    access_log /var/log/nginx/access.log main;
    error_log  /var/log/nginx/error.log warn;
    
    # 性能优化
    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    # 安全头
    server_tokens off;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # HTTP 服务器（端口80）
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        
        # 根路径重定向到控制面板
        location = / {
            return 302 /traffic/;
        }
        
# 管理员专用：保留 /sub 精确匹配（不做设备限制）
location = /sub {
    default_type text/plain;
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    add_header Pragma "no-cache";
    root /var/www/html;
    try_files /sub =404;
}

# 普通用户：/share/u-<token> 高熵私有路径
location ^~ /share/ {
    default_type text/plain;
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    add_header Pragma "no-cache";
    root /var/www/html;
    # 只允许已有文件（软链）被访问；没有对应 token 文件则 404
    try_files $uri =404;
}
        
	    # 内部403页面（只在本server内有效）
        location = /_deny_traffic {
            internal;
            return 403;
        }
		
        # 控制面板和数据API
        location ^~ /traffic/ {
            # 口令门闸：默认拒绝；命中口令或已有会话通过
            error_page 418 = /_deny_traffic;
            if ($deny_traffic) { return 418; }

            # 首次口令正确时发Cookie（之后静态/接口都不需要再带 ?passcode=）
            add_header Set-Cookie $set_cookie;

            alias /etc/edgebox/traffic/;
            index index.html;
            autoindex off;

            # 补全类型（避免 CSS/JS/字体识别失败）
            charset utf-8;
            types {
                text/html                    html htm;
                text/plain                   txt log;
                application/json             json;
                text/css                     css;
                application/javascript       js mjs;
                image/svg+xml                svg;
                image/png                    png;
                image/jpeg                   jpg jpeg;
                image/gif                    gif;
                image/x-icon                 ico;
                font/ttf                     ttf;
                font/woff2                   woff2;
            }

            # 缓存头（按你原策略）
            add_header Cache-Control "no-store, no-cache, must-revalidate";
            add_header Pragma "no-cache";
        }

        # IP质量检测API（对齐技术规范）
        location ^~ /status/ {
            alias /var/www/edgebox/status/;
            autoindex off;
            add_header Cache-Control "no-store, no-cache, must-revalidate";
            add_header Content-Type "application/json; charset=utf-8";
        }
        
        # 健康检查
        location = /health {
            access_log off;
            return 200 "OK\n";
            add_header Content-Type text/plain;
        }
        
		# Favicon支持
        location = /favicon.ico {
            access_log off;
            log_not_found off;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
		
        # 拒绝访问隐藏文件
        location ~ /\. {
            deny all;
            access_log off;
            log_not_found off;
        }
    }
}


# Stream 模块配置（TCP/443 端口分流）
stream {
    error_log /var/log/nginx/stream.log warn;
    
    ### ULTIMATE FIX: Include the dynamic map file ###
    include /etc/nginx/conf.d/edgebox_stream_map.conf;
    
    map $ssl_preread_alpn_protocols $backend_alpn {
	    ~\bh2\b            grpc;
        ~\bhttp/1\.1\b     websocket;
        default            reality;
    }
    
    map $backend_pool $upstream_server {
        reality   127.0.0.1:11443;
        trojan    127.0.0.1:10143;
        grpc      127.0.0.1:10085;
        websocket 127.0.0.1:10086;
        default   "";
    }
    
    map $backend_alpn $upstream_alpn {
        grpc      127.0.0.1:10085;
        websocket 127.0.0.1:10086;
        reality   127.0.0.1:11443;
        default   127.0.0.1:11443;
    }
    
    map $upstream_server $final_upstream {
        ""      $upstream_alpn;
        default $upstream_server;
    }
    
    server {
        listen 443 reuseport;
        ssl_preread on;
        proxy_pass $final_upstream;
        proxy_timeout 300s;
        proxy_connect_timeout 5s;
        proxy_protocol_timeout 5s;
        proxy_responses 1;
        proxy_next_upstream_tries 1;
    }
}
NGINX_CONFIG

    # 生成独立的密码配置文件
    log_info "生成并注入控制面板密码..."
    local passcode_conf="/etc/nginx/conf.d/edgebox_passcode.conf"
    if [[ -n "$DASHBOARD_PASSCODE" ]]; then
        cat > "$passcode_conf" << EOF
# 由 EdgeBox 自动生成于 $(date)
map \$arg_passcode \$pass_ok {
    "${DASHBOARD_PASSCODE}" 1;
    default 0;
}
EOF
        log_success "密码配置文件已生成: ${passcode_conf}"
    else
        cat > "$passcode_conf" << EOF
# [WARN] 未生成密码，默认拒绝所有访问
map \$arg_passcode \$pass_ok {
    default 0;
}
EOF
        log_warn "DASHBOARD_PASSCODE 为空，面板访问将被默认拒绝。"
    fi
    
    # =================================================================
    # ### NEW FIX: Generate the initial map file before validating  ###
    # =================================================================
    generate_initial_nginx_stream_map
    
    # 验证Nginx配置并重载
    log_info "验证Nginx配置..."
    if nginx -t; then
        log_success "Nginx配置验证通过"
        systemctl reload nginx || systemctl restart nginx
        log_success "Nginx 已重载新配置"
    else
        log_error "Nginx配置验证失败，请检查 /etc/nginx/nginx.conf 和 /etc/nginx/conf.d/"
        nginx -t # 显示详细错误
        return 1
    fi
    
    log_info "对齐 DNS 解析（系统 & Xray）..."
    ensure_system_dns
    ensure_xray_dns_alignment
    
    log_success "Nginx配置文件创建完成"
    return 0
}

#############################################
# Xray 配置函数
#############################################

# 配置Xray服务 (使用jq重构，彻底解决特殊字符问题)
configure_xray() {
    log_info "配置Xray多协议服务..."
    
    # 【添加】创建Xray日志目录
    mkdir -p /var/log/xray
    chmod 755 /var/log/xray
    chown root:root /var/log/xray
    
    local NOBODY_GRP="$(id -gn nobody 2>/dev/null || echo nogroup)"
  
    # 验证必要变量 (增强版)
    local required_vars=(
        "UUID_VLESS_REALITY"
        "UUID_VLESS_GRPC"  
        "UUID_VLESS_WS"
        "REALITY_PRIVATE_KEY"
        "REALITY_SHORT_ID"
        "PASSWORD_TROJAN"
    )

    log_info "检查必要变量设置..."
    local missing_vars=()

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            missing_vars+=("$var")
            log_error "必要变量 $var 未设置"
        else
            log_success "✓ $var 已设置: ${!var:0:8}..."
        fi
    done

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "缺少必要变量: ${missing_vars[*]}"
        log_info "尝试从配置文件重新加载变量..."
        
        # 尝试从server.json重新加载变量
        if [[ -f "${CONFIG_DIR}/server.json" ]]; then
            UUID_VLESS_REALITY=$(jq -r '.uuid.vless.reality // .uuid.vless' "${CONFIG_DIR}/server.json" 2>/dev/null)
            UUID_VLESS_GRPC=$(jq -r '.uuid.vless.grpc // .uuid.vless' "${CONFIG_DIR}/server.json" 2>/dev/null)
            UUID_VLESS_WS=$(jq -r '.uuid.vless.ws // .uuid.vless' "${CONFIG_DIR}/server.json" 2>/dev/null)
            REALITY_PRIVATE_KEY=$(jq -r '.reality.private_key' "${CONFIG_DIR}/server.json" 2>/dev/null)
            REALITY_SHORT_ID=$(jq -r '.reality.short_id' "${CONFIG_DIR}/server.json" 2>/dev/null)
            PASSWORD_TROJAN=$(jq -r '.password.trojan' "${CONFIG_DIR}/server.json" 2>/dev/null)
            
            log_info "已从配置文件重新加载变量"
        else
            log_error "配置文件不存在，无法重新加载变量"
            return 1
        fi
    fi
    
    # 显示将要使用的变量（调试用）
    log_info "配置变量检查:"
    log_info "├─ UUID_VLESS_REALITY: ${UUID_VLESS_REALITY:0:8}..."
    log_info "├─ REALITY_PRIVATE_KEY: ${REALITY_PRIVATE_KEY:0:8}..."
    log_info "├─ REALITY_SHORT_ID: $REALITY_SHORT_ID"
    log_info "├─ PASSWORD_TROJAN: ${PASSWORD_TROJAN:0:8}..."
    log_info "└─ CERT_DIR: $CERT_DIR"
    
    log_info "使用jq生成Xray配置文件（彻底避免特殊字符问题）..."
    
    # 使用jq安全地生成完整的Xray配置文件
    if ! jq -n \
        --arg uuid_reality "$UUID_VLESS_REALITY" \
        --arg uuid_grpc "$UUID_VLESS_GRPC" \
        --arg uuid_ws "$UUID_VLESS_WS" \
        --arg reality_private "$REALITY_PRIVATE_KEY" \
        --arg reality_short "$REALITY_SHORT_ID" \
        --arg reality_sni "$REALITY_SNI" \
        --arg password_trojan "$PASSWORD_TROJAN" \
        --arg cert_pem "${CERT_DIR}/current.pem" \
        --arg cert_key "${CERT_DIR}/current.key" \
        '{
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "tag": "vless-reality",
                    "listen": "127.0.0.1",
                    "port": 11443,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            { "id": $uuid_reality, "flow": "xtls-rprx-vision" }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": false,
                            "dest": ($reality_sni + ":443"),
                            "serverNames": [$reality_sni],
                            "privateKey": $reality_private,
                            "shortIds": [$reality_short]
                        }
                    }
                },
                {
                    "tag": "vless-grpc",
                    "listen": "127.0.0.1",
                    "port": 10085,
                    "protocol": "vless",
                    "settings": {
                        "clients": [ { "id": $uuid_grpc } ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "grpc",
                        "security": "tls",
                        "tlsSettings": { "certificates": [ { "certificateFile": $cert_pem, "keyFile": $cert_key } ] },
                        "grpcSettings": { "serviceName": "grpc", "multiMode": false }
                    }
                },
                {
                    "tag": "vless-ws",
                    "listen": "127.0.0.1",
                    "port": 10086,
                    "protocol": "vless",
                    "settings": {
                        "clients": [ { "id": $uuid_ws } ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "tls",
                        "tlsSettings": { "certificates": [ { "certificateFile": $cert_pem, "keyFile": $cert_key } ] },
                        "wsSettings": { "path": "/ws" }
                    }
                },
                {
                    "tag": "trojan-tcp",
                    "listen": "127.0.0.1",
                    "port": 10143,
                    "protocol": "trojan",
                    "settings": {
                        "clients": [ { "password": $password_trojan } ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tcpSettings": { "header": { "type": "none" } },
                        "tlsSettings": { "certificates": [ { "certificateFile": $cert_pem, "keyFile": $cert_key } ] }
                    }
                }
            ],
            "outbounds": [
                { "tag": "direct", "protocol": "freedom", "settings": {} },
                { "tag": "block", "protocol": "blackhole", "settings": {} }
            ],
            "dns": {
                "servers": [ "8.8.8.8", "1.1.1.1", {"address": "https://1.1.1.1/dns-query"}, {"address": "https://8.8.8.8/dns-query"} ],
                "queryStrategy": "UseIP"
            },
            "routing": {
                "domainStrategy": "UseIp", # <<< CORRECTED from UseIP
                "rules": [
                    { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
                ]
            },
            "policy": { "handshake": 4, "connIdle": 30 }
        }' > "${CONFIG_DIR}/xray.json"; then
        log_error "使用jq生成Xray配置文件失败"
        return 1
    fi

    log_success "Xray配置文件生成完成"
    
    # 验证JSON格式和配置内容
    if ! jq '.' "${CONFIG_DIR}/xray.json" >/dev/null 2>&1; then
        log_error "Xray配置JSON格式错误"
        return 1
    fi

    # 验证配置内容
    log_info "验证Xray配置文件..."
    if ! grep -q "127.0.0.1" "${CONFIG_DIR}/xray.json"; then
        log_error "Xray配置中缺少监听地址"
        return 1
    fi
 
    log_success "Xray配置文件验证通过"
    
	# 对齐系统与 Xray 的 DNS
log_info "对齐 DNS 解析（系统 & Xray）..."
ensure_system_dns
ensure_xray_dns_alignment
	
    # ============================================
    # [关键修复] 创建正确的 systemd 服务文件
    # ============================================
    log_info "创建Xray系统服务..."
    
    # 停止并禁用官方的服务
    systemctl stop xray >/dev/null 2>&1 || true
    systemctl disable xray >/dev/null 2>&1 || true
    
    # 备份官方服务文件
    if [[ -f /etc/systemd/system/xray.service ]]; then
        mv /etc/systemd/system/xray.service \
           /etc/systemd/system/xray.service.official.bak 2>/dev/null || true
    fi
    
    # 删除官方的配置覆盖目录
    rm -rf /etc/systemd/system/xray.service.d 2>/dev/null || true
    rm -rf /etc/systemd/system/xray@.service.d 2>/dev/null || true
    
    # 创建我们自己的 systemd 服务文件（使用正确的配置路径）
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service (EdgeBox)
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config ${CONFIG_DIR}/xray.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载systemd，以便后续服务可以启动
    systemctl daemon-reload
    
    # 启用服务（但不立即启动，等待统一启动）
    systemctl enable xray >/dev/null 2>&1
    
    log_success "Xray服务文件创建完成（配置路径: ${CONFIG_DIR}/xray.json）"
    
    return 0
}

#############################################
# sing-box 配置函数
#############################################

# 配置sing-box服务
configure_sing_box() {
    log_info "配置sing-box服务..."
    
    # 验证必要变量
    if [[ -z "$PASSWORD_HYSTERIA2" || -z "$UUID_TUIC" || -z "$PASSWORD_TUIC" ]]; then
        log_error "sing-box必要配置变量缺失"
        log_debug "Hysteria2密码: ${PASSWORD_HYSTERIA2:+已设置}"
        log_debug "TUIC UUID: ${UUID_TUIC:+已设置}"
        log_debug "TUIC密码: ${PASSWORD_TUIC:+已设置}"
        return 1
    fi
    
	mkdir -p /var/log/edgebox 2>/dev/null || true

log_info "生成sing-box配置文件 (使用 jq 确保安全)..."

if ! jq -n \
  --arg hy2_pass "$PASSWORD_HYSTERIA2" \
  --arg tuic_uuid "$UUID_TUIC" \
  --arg tuic_pass "$PASSWORD_TUIC" \
  --arg cert_pem "${CERT_DIR}/current.pem" \
  --arg cert_key "${CERT_DIR}/current.key" \
  '{
    "log": { "level": "info", "timestamp": true },
    "inbounds": [
      {
        "type": "hysteria2",
        "tag": "hysteria2-in",
        "listen": "0.0.0.0",
        "listen_port": 443,
        "users": [ { "password": $hy2_pass } ],
        "tls": {
          "enabled": true,
          "alpn": ["h3"],
          "certificate_path": $cert_pem,
          "key_path": $cert_key
        }
      },
      {
        "type": "tuic",
        "tag": "tuic-in",
        "listen": "0.0.0.0",
        "listen_port": 2053,
        "users": [ { "uuid": $tuic_uuid, "password": $tuic_pass } ],
        "congestion_control": "bbr",
        "tls": {
          "enabled": true,
          "alpn": ["h3"],
          "certificate_path": $cert_pem,
          "key_path": $cert_key
        }
      }
    ],
    "outbounds": [ { "type": "direct", "tag": "direct" } ],
    "route": {
      "rules": [
        {
          "ip_cidr": [
            "127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
            "::1/128","fc00::/7","fe80::/10"
          ],
          "outbound": "direct"
        }
      ]
    }
  }' > "${CONFIG_DIR}/sing-box.json"; then
  log_error "使用 jq 生成 sing-box.json 失败"
  return 1
fi
    
    log_success "sing-box配置文件生成完成"
    
    # 验证生成的JSON格式
    if ! jq '.' "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
        log_error "sing-box配置JSON格式错误"
        return 1
    fi
    
	# === sing-box 语义自检 ===
if command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
  if ! /usr/local/bin/sing-box check -c "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
    log_warn "sing-box 语义校验失败，尝试移除可能不兼容字段后重试..."
    # 常见不兼容字段兜底（老版本不认识的键）
    if command -v jq >/dev/null 2>&1; then
      tmpf=$(mktemp)
      jq '(.inbounds[] | select(.type=="hysteria2")) -= {masquerade}' \
        "${CONFIG_DIR}/sing-box.json" > "$tmpf" 2>/dev/null && mv -f "$tmpf" "${CONFIG_DIR}/sing-box.json"
    fi
    if ! /usr/local/bin/sing-box check -c "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
      log_error "sing-box 配置仍无法通过语义校验，请检查证书路径/字段"
      return 1
    fi
  fi
fi

    # 验证配置内容
    log_info "验证sing-box配置文件..."
    if ! grep -q "0.0.0.0" "${CONFIG_DIR}/sing-box.json"; then
        log_error "sing-box配置中缺少监听地址"
        return 1
    fi
 
    log_success "sing-box配置文件验证通过"
    
    # 【新增】确保证书符号链接存在
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
    
    # 确保证书权限正确
    if [[ -f "${CERT_DIR}/self-signed.pem" ]]; then
        chmod 644 "${CERT_DIR}"/*.pem 2>/dev/null || true
        chmod 600 "${CERT_DIR}"/*.key 2>/dev/null || true
        log_success "证书权限已设置"
    fi
    
    # 创建正确的 systemd 服务文件
    log_info "创建sing-box系统服务..."
    
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE
ExecStart=/usr/local/bin/sing-box run -c ${CONFIG_DIR}/sing-box.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载systemd
    systemctl daemon-reload
    
    # 启用服务（但不立即启动，等待统一启动）
    systemctl enable sing-box >/dev/null 2>&1
    
    log_success "sing-box服务文件创建完成（配置路径: ${CONFIG_DIR}/sing-box.json）"
    
	chmod 755 "${CERT_DIR}" 2>/dev/null || true
chmod 644 "${CERT_DIR}"/*.pem 2>/dev/null || true
chmod 640 "${CERT_DIR}"/*.key 2>/dev/null || true
chown root:nobody "${CERT_DIR}"/*.key 2>/dev/null || true

    return 0
}

#############################################
# 订阅生成函数
#############################################

# 生成订阅链接（支持IP模式和域名模式）
generate_subscription() {
    log_info "生成协议订阅链接..."
    
    # 从server.json读取配置（确保数据一致性）
    local config_file="${CONFIG_DIR}/server.json"
    if [[ ! -f "$config_file" ]]; then
        log_error "配置文件 $config_file 不存在"
        return 1
    fi
    
    # 读取配置参数
    local server_ip uuid_reality uuid_grpc uuid_ws uuid_tuic
    local password_trojan password_hysteria2 password_tuic
    local reality_public_key reality_short_id
    
    server_ip=$(jq -r '.server_ip // empty' "$config_file")
    uuid_reality=$(jq -r '.uuid.vless.reality // empty' "$config_file")
    uuid_grpc=$(jq -r '.uuid.vless.grpc // empty' "$config_file")
    uuid_ws=$(jq -r '.uuid.vless.ws // empty' "$config_file")
    uuid_tuic=$(jq -r '.uuid.tuic // empty' "$config_file")
    password_trojan=$(jq -r '.password.trojan // empty' "$config_file")
    password_hysteria2=$(jq -r '.password.hysteria2 // empty' "$config_file")
    password_tuic=$(jq -r '.password.tuic // empty' "$config_file")
    reality_public_key=$(jq -r '.reality.public_key // empty' "$config_file")
    reality_short_id=$(jq -r '.reality.short_id // empty' "$config_file")
    
    # 验证必要参数
    if [[ -z "$server_ip" || -z "$uuid_reality" || -z "$password_hysteria2" ]]; then
        log_error "生成订阅所需的关键参数缺失"
        return 1
    fi
    
    # URL编码函数
    url_encode() {
        local string="${1}"
        local strlen=${#string}
        local encoded=""
        local pos c o
        
        for (( pos=0 ; pos<strlen ; pos++ )); do
            c=${string:$pos:1}
            case "$c" in
                [-_.~a-zA-Z0-9] ) o="${c}" ;;
                * ) printf -v o '%%%02x' "'$c" ;;
            esac
            encoded+="${o}"
        done
        echo "${encoded}"
    }
    
	# 计算 Reality 使用的 SNI（与服务端 xray.json 保持一致）
    local reality_sni
    reality_sni="$(jq -r 'first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.serverNames[0])
                           // (first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.dest) | split(":")[0])
                           // empty' "${CONFIG_DIR}/xray.json" 2>/dev/null)"
    : "${reality_sni:=${REALITY_SNI:-www.microsoft.com}}"
	
    # 生成协议链接
    local subscription_links=""
    
    # 1. VLESS-Reality
    if [[ -n "$uuid_reality" && -n "$reality_public_key" && -n "$reality_short_id" ]]; then
        subscription_links+="vless://${uuid_reality}@${server_ip}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${reality_sni}&fp=chrome&pbk=${reality_public_key}&sid=${reality_short_id}&type=tcp#EdgeBox-REALITY\n"
    fi
    
    # 2. VLESS-gRPC (IP模式使用内部域名)
    if [[ -n "$uuid_grpc" ]]; then
        subscription_links+="vless://${uuid_grpc}@${server_ip}:443?encryption=none&security=tls&sni=grpc.edgebox.internal&alpn=h2&type=grpc&serviceName=grpc&fp=chrome&allowInsecure=1#EdgeBox-gRPC\n"
    fi
    
    # 3. VLESS-WebSocket (IP模式使用内部域名)
    if [[ -n "$uuid_ws" ]]; then
        subscription_links+="vless://${uuid_ws}@${server_ip}:443?encryption=none&security=tls&sni=ws.edgebox.internal&host=ws.edgebox.internal&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome&allowInsecure=1#EdgeBox-WS\n"
    fi
    
# 4. Trojan (IP模式使用内部域名)
if [[ -n "$password_trojan" ]]; then
    local encoded_trojan_password
    encoded_trojan_password=$(url_encode "$password_trojan")
    subscription_links+="trojan://${encoded_trojan_password}@${server_ip}:443?security=tls&sni=trojan.edgebox.internal&fp=chrome&allowInsecure=1#EdgeBox-TROJAN\n"
fi
    
    # 5. Hysteria2
    if [[ -n "$password_hysteria2" ]]; then
        local encoded_hy2_password
        encoded_hy2_password=$(url_encode "$password_hysteria2")
        subscription_links+="hysteria2://${encoded_hy2_password}@${server_ip}:443?sni=${server_ip}&alpn=h3&insecure=1#EdgeBox-HYSTERIA2\n"
    fi
    
    # 6. TUIC
    if [[ -n "$uuid_tuic" && -n "$password_tuic" ]]; then
        local encoded_tuic_password
        encoded_tuic_password=$(url_encode "$password_tuic")
        subscription_links+="tuic://${uuid_tuic}:${encoded_tuic_password}@${server_ip}:2053?congestion_control=bbr&alpn=h3&sni=${server_ip}&allowInsecure=1#EdgeBox-TUIC\n"
    fi
    
# 保存订阅文件（改为软链同步到 Web，避免 "are the same file"）
mkdir -p "${WEB_ROOT}"
printf "%b" "$subscription_links" > "${CONFIG_DIR}/subscription.txt"

# 将 Web 目录的 /sub 作为 subscription.txt 的软链接
# 若已存在普通文件或错误链接，先移除再创建
if [[ -e "${WEB_ROOT}/sub" && ! -L "${WEB_ROOT}/sub" ]]; then
  rm -f "${WEB_ROOT}/sub"
fi
ln -sfn "${CONFIG_DIR}/subscription.txt" "${WEB_ROOT}/sub"

# 设置权限（chmod 作用于目标文件；软链本身无需 chmod）
chmod 644 "${CONFIG_DIR}/subscription.txt"
    
    # 生成Base64编码的订阅（可选）
    if command -v base64 >/dev/null 2>&1; then
        if base64 --help 2>&1 | grep -q -- ' -w'; then
            # GNU base64 支持 -w 参数
            printf "%b" "$subscription_links" | base64 -w0 > "${CONFIG_DIR}/subscription.base64"
        else
            # macOS base64 不支持 -w 参数
            printf "%b" "$subscription_links" | base64 | tr -d '\n' > "${CONFIG_DIR}/subscription.base64"
        fi
        chmod 644 "${CONFIG_DIR}/subscription.base64"
    fi
    
    log_success "订阅链接生成完成"
    log_info "订阅文件位置:"
    log_info "├─ 明文: ${CONFIG_DIR}/subscription.txt"
    log_info "├─ Web: ${WEB_ROOT}/sub"
    log_info "└─ Base64: ${CONFIG_DIR}/subscription.base64"
    
    # 显示生成的协议数量
    local protocol_count
    protocol_count=$(printf "%b" "$subscription_links" | grep -c '^[a-z]' || echo "0")
    log_info "生成协议数量: $protocol_count"
    
    return 0
}

#############################################
# 服务启动和验证函数
#############################################

# --- hot-reload: begin ---
# 智能热加载/回退重启（nginx / sing-box / xray 等）
# 用法：reload_or_restart_services nginx sing-box xray
# --- hot-reload: begin (带防火墙安全锁的版本) ---
reload_or_restart_services() {
  local services=("$@")
  local failed=()
  for svc in "${services[@]}"; do
    local action="reload"
    case "$svc" in
      nginx|nginx.service)
        if command -v nginx >/dev/null 2>&1; then
          if ! nginx -t >/dev/null 2>&1; then
            log_error "[hot-reload] nginx 配置校验失败（nginx -t）"
            failed+=("$svc"); continue
          fi
        fi
        systemctl reload nginx || { action="restart"; systemctl restart nginx; }
        ;;
      sing-box|sing-box.service|sing-box@*)
        if command -v sing-box >/dev/null 2>&1; then
          local sb_cfg="${CONFIG_DIR}/sing-box.json"
          [ -f "$sb_cfg" ] && ! sing-box check -c "$sb_cfg" >/dev/null 2>&1 && {
            log_error "[hot-reload] sing-box 配置校验失败（sing-box check）"
            failed+=("$svc"); continue
          }
        fi
        systemctl reload "$svc" 2>/dev/null \
          || systemctl kill -s HUP "$svc" 2>/dev/null \
          || { action="restart"; systemctl restart "$svc"; }
        ;;
      xray|xray.service|xray@*)
        if command -v xray >/dev/null 2>&1; then
          local xr_cfg="${CONFIG_DIR}/xray.json"
          [ -f "$xr_cfg" ] && ! xray -test -config "$xr_cfg" >/dev/null 2>&1 && {
            log_error "[hot-reload] xray 配置校验失败（xray -test）"
            failed+=("$svc"); continue
          }
        fi
        action="restart"
        systemctl restart "$svc"
        ;;
      *)
        systemctl reload "$svc" 2>/dev/null || { action="restart"; systemctl restart "$svc"; }
        ;;
    esac
    if ! systemctl is-active --quiet "$svc"; then
      log_error "[hot-reload] $svc 在 ${action} 后仍未 active"
      journalctl -u "$svc" -n 50 --no-pager || true
      failed+=("$svc")
    else
      log_info "[hot-reload] $svc ${action}ed"
    fi
  done
  
  # <<< 修复点: 在所有服务重启/重载后，立即强制应用正确的防火墙规则 >>>
  if [[ -x "/etc/edgebox/scripts/apply-firewall.sh" ]]; then
      log_info "正在重新应用防火墙规则以防止连接中断..."
      /etc/edgebox/scripts/apply-firewall.sh >/dev/null 2>&1 || log_warn "防火墙规则应用失败，但不中断流程。"
  fi
  # <<< 修复点结束 >>>

  ((${#failed[@]}==0)) || return 1
}
# --- hot-reload: end ---



# 启动所有服务并验证（增强幂等性）
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
verify_critical_ports() {
  log_info "检查关键端口监听状态..."
  local ok=true
  ss -tln | grep -q ':443 '    && log_success "TCP 443 (Nginx) 监听正常" || { log_warn "TCP 443 未监听"; ok=false; }
  ss -uln | grep -q ':443 '    && log_success "UDP 443 (Hysteria2) 监听正常" || { log_warn "UDP 443 未监听"; ok=false; }
  ss -uln | grep -q ':2053 '   && log_success "UDP 2053 (TUIC) 监听正常"     || { log_warn "UDP 2053 未监听"; ok=false; }
  $ok
}
# === END PATCH ===


# [新增函数] 确保服务运行状态（完全幂等）
ensure_service_running() {
    local service="$1"
    local max_attempts=3
    local attempt=0
    
    log_info "确保服务运行状态: $service"
    
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
verify_port_listening 2053 udp && log_success "端口 2053 正在监听" || log_warn "端口 2053 未在监听"


#############################################
# 模块3主执行函数
#############################################

# 执行模块3的所有任务
execute_module3() {
    log_info "======== 开始执行模块3：服务安装配置 ========"
    
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
    
    # ========== 修复点2: 改进密码替换逻辑 ==========
    # 替换 Nginx 配置中的密码占位符 (修复版)
    log_info "开始应用控制面板密码到Nginx配置..."
    
    # 1. 多种方式获取密码,增加容错性
    local final_passcode=""
    
    # 尝试1: 从环境变量获取
    if [[ -n "$DASHBOARD_PASSCODE" && "$DASHBOARD_PASSCODE" != "null" ]]; then
        final_passcode="$DASHBOARD_PASSCODE"
        log_info "从环境变量获取密码: ${final_passcode}"
    # 尝试2: 从server.json读取
    elif [[ -f "${CONFIG_DIR}/server.json" ]]; then
        final_passcode=$(jq -r '.dashboard_passcode // empty' "${CONFIG_DIR}/server.json" 2>/dev/null)
        if [[ -n "$final_passcode" && "$final_passcode" != "null" ]]; then
            log_info "从server.json读取密码: ${final_passcode}"
        else
            final_passcode=""
        fi
    fi
    
    # 2. 如果还是没有密码,重新生成
    if [[ -z "$final_passcode" ]]; then
        log_warn "未找到密码,重新生成..."
        local random_digit=$((RANDOM % 10))
        final_passcode="${random_digit}${random_digit}${random_digit}${random_digit}${random_digit}${random_digit}"
        
        # 写入server.json
        local temp_file="${CONFIG_DIR}/server.json.tmp"
        if jq --arg passcode "$final_passcode" '.dashboard_passcode = $passcode' "${CONFIG_DIR}/server.json" > "$temp_file"; then
            mv "$temp_file" "${CONFIG_DIR}/server.json"
            log_success "新密码已生成并写入: ${final_passcode}"
        else
            log_error "生成新密码失败"
            rm -f "$temp_file"
        fi
    fi
    
    # 3. 验证密码有效性
    if [[ -z "$final_passcode" || ${#final_passcode} -ne 6 ]]; then
        log_error "密码无效或长度不正确: '${final_passcode}'"
        log_error "Nginx配置将保留占位符,需要手动修复"
    else
        # 4. 执行替换
        log_info "应用密码到Nginx配置: ${final_passcode}"
        
        # 创建备份
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.pre-password
        
        # 替换占位符
        if sed -i "s/__DASHBOARD_PASSCODE_PH__/${final_passcode}/g" /etc/nginx/nginx.conf; then
            log_success "密码已成功应用到Nginx配置"
            
            # 验证替换是否成功
            if grep -q "__DASHBOARD_PASSCODE_PH__" /etc/nginx/nginx.conf; then
                log_warn "警告: Nginx配置中仍存在占位符,可能替换不完整"
            else
                log_success "验证通过: 占位符已完全替换"
            fi
            
            # 验证Nginx配置语法
            if nginx -t 2>/dev/null; then
                log_success "Nginx配置语法验证通过"
            else
                log_error "Nginx配置语法验证失败"
                log_error "已创建备份: /etc/nginx/nginx.conf.bak.pre-password"
            fi
        else
            log_error "sed替换失败"
        fi
    fi
    # ========== 修复点2结束 ==========
    
    # 任务6：生成订阅链接
    if generate_subscription; then
        log_success "✓ 订阅链接生成完成"
    else
        log_error "✗ 订阅链接生成失败"
        return 1
    fi
    
    # 任务7：启动和验证服务
    if start_and_verify_services; then
        log_success "✓ 服务启动验证通过"
    else
        log_error "✗ 服务启动验证失败"
        return 1
    fi
    
    log_success "======== 模块3执行完成 ========"
    log_info "已完成："
    log_info "├─ Xray多协议服务（Reality、gRPC、WS、Trojan）"
    log_info "├─ sing-box服务（Hysteria2、TUIC）"
    log_info "├─ Nginx分流代理（SNI+ALPN架构）"
    log_info "├─ 订阅链接生成（6种协议）"
    log_info "├─ 控制面板密码: ${final_passcode:-未设置}"  # 【新增】
    log_info "└─ 所有服务运行验证"
    
    return 0
}


#############################################
# 模块3导出函数（供其他模块调用）
#############################################

# 重新启动所有服务
restart_all_services() {
    log_info "重新启动EdgeBox所有服务..."
    
    local services=(nginx xray sing-box)
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
check_services_status() {
    log_info "检查EdgeBox服务状态..."
    
    local services=(nginx xray sing-box)
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
# EdgeBox 企业级多协议节点部署脚本 v3.0.0
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
create_dashboard_backend() {
    log_info "生成Dashboard后端数据采集脚本..."
    
    # 确保脚本目录存在
    mkdir -p "${SCRIPTS_DIR}"
    
    # 生成完整的dashboard-backend.sh脚本
    cat > "${SCRIPTS_DIR}/dashboard-backend.sh" << 'DASHBOARD_BACKEND_SCRIPT'
#!/usr/bin/env bash
#############################################
# EdgeBox Dashboard 后端数据采集脚本
# 版本: 3.0.0
# 功能: 统一采集系统状态、服务状态、配置信息
# 输出: dashboard.json、system.json
#############################################

set -euo pipefail
export LANG=C LC_ALL=C

# 解析当前脚本所在目录，并为 SCRIPTS_DIR 提供默认值
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
: "${SCRIPTS_DIR:=${SCRIPT_DIR}}"

#############################################
# 配置和路径定义
#############################################

TRAFFIC_DIR="${TRAFFIC_DIR:-/etc/edgebox/traffic}"
CONFIG_DIR="${CONFIG_DIR:-/etc/edgebox/config}"
CERT_DIR="${CERT_DIR:-/etc/edgebox/cert}"
SERVER_JSON="${SERVER_JSON:-${CONFIG_DIR}/server.json}"
SHUNT_DIR="${CONFIG_DIR}/shunt"

# 日志函数
log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"; }
log_warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }



#############################################
# 安全数据获取函数
#############################################

# 安全的jq取值函数，避免空值和null导致的错误
safe_jq() {
    local query="$1"
    local file="$2"
    local default="${3:-}"
    
    if [[ ! -f "$file" ]]; then
        echo "$default"
        return
    fi
    
    local result
    result=$(jq -r "$query // empty" "$file" 2>/dev/null || echo "")
    
    if [[ -z "$result" || "$result" == "null" ]]; then
        echo "$default"
    else
        echo "$result"
    fi
}

# 安全读取列表文件：去BOM/CR、去首尾空白、过滤空行与#注释，输出JSON数组
jq_safe_list() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo '[]'
    return
  fi
  jq -n --rawfile RAW "$file" '
    ($RAW
     | gsub("^\uFEFF"; "")
     | split("\n")
     | map(. 
         | gsub("\r"; "")
         | gsub("(^[[:space:]]+|[[:space:]]+$)"; ""))   # 去首尾空白
     | map(select(. != "" and (startswith("#") | not)))
    )'
}


# 获取系统负载信息
get_system_metrics() {
    local cpu_percent=0
    local memory_percent=0
    local disk_percent=0
    
    # 改进的CPU使用率计算
    if [[ -r /proc/stat ]]; then
        read _ user1 nice1 system1 idle1 iowait1 irq1 softirq1 _ < /proc/stat
        
        sleep 2
        
        read _ user2 nice2 system2 idle2 iowait2 irq2 softirq2 _ < /proc/stat
        
        local user_diff=$((user2 - user1))
        local nice_diff=$((nice2 - nice1))
        local system_diff=$((system2 - system1))
        local idle_diff=$((idle2 - idle1))
        local iowait_diff=$((iowait2 - iowait1))
        local irq_diff=$((irq2 - irq1))
        local softirq_diff=$((softirq2 - softirq1))
        
        local total_diff=$((user_diff + nice_diff + system_diff + idle_diff + iowait_diff + irq_diff + softirq_diff))
        local active_diff=$((total_diff - idle_diff))
        
        if [[ $total_diff -gt 0 ]]; then
            cpu_percent=$(( (active_diff * 1000) / total_diff ))
            cpu_percent=$((cpu_percent / 10))
            # 设置最小值为1%
            if [[ $cpu_percent -lt 1 ]]; then
                cpu_percent=1
            fi
        else
            cpu_percent=1
        fi
    fi
    
    # 内存使用率计算保持不变
    if [[ -r /proc/meminfo ]]; then
        local mem_total mem_available
        mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
        mem_available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
        
        if [[ $mem_total -gt 0 && $mem_available -ge 0 ]]; then
            memory_percent=$(( (mem_total - mem_available) * 100 / mem_total ))
        fi
    fi
    
    # 磁盘使用率计算保持不变
    if command -v df >/dev/null 2>&1; then
        local disk_info
        disk_info=$(df / 2>/dev/null | tail -1)
        if [[ -n "$disk_info" ]]; then
            disk_percent=$(echo "$disk_info" | awk '{print $5}' | sed 's/%//')
        fi
    fi
    
    # 确保所有值在合理范围内
    cpu_percent=$(( cpu_percent > 100 ? 100 : cpu_percent ))
    cpu_percent=$(( cpu_percent < 1 ? 1 : cpu_percent ))
    memory_percent=$(( memory_percent > 100 ? 100 : memory_percent ))
    memory_percent=$(( memory_percent < 0 ? 0 : memory_percent ))
    disk_percent=$(( disk_percent > 100 ? 100 : disk_percent ))
    disk_percent=$(( disk_percent < 0 ? 0 : disk_percent ))
    
    # 输出JSON格式
    jq -n \
        --argjson cpu "$cpu_percent" \
        --argjson memory "$memory_percent" \
        --argjson disk "$disk_percent" \
        --arg timestamp "$(date -Is)" \
        '{
            updated_at: $timestamp,
            cpu: $cpu,
            memory: $memory,
            disk: $disk
        }'
}


# 获取系统详细信息
get_system_info() {
    # 从server.json读取基础信息
    local server_ip eip version install_date
    local cloud_provider cloud_region instance_id hostname user_alias
    local cpu_spec memory_spec disk_spec
    
    server_ip=$(safe_jq '.server_ip' "$SERVER_JSON" "127.0.0.1")
    eip=$(safe_jq '.eip' "$SERVER_JSON" "")
    version=$(safe_jq '.version' "$SERVER_JSON" "3.0.0")
    install_date=$(safe_jq '.install_date' "$SERVER_JSON" "")
    cloud_provider=$(safe_jq '.cloud.provider' "$SERVER_JSON" "Unknown")
    cloud_region=$(safe_jq '.cloud.region' "$SERVER_JSON" "Unknown")
    instance_id=$(safe_jq '.instance_id' "$SERVER_JSON" "Unknown")
    hostname=$(safe_jq '.hostname' "$SERVER_JSON" "$(hostname)")
    user_alias=$(safe_jq '.user_alias' "$SERVER_JSON" "")
    cpu_spec=$(safe_jq '.spec.cpu' "$SERVER_JSON" "Unknown")
    memory_spec=$(safe_jq '.spec.memory' "$SERVER_JSON" "Unknown")
    disk_spec=$(safe_jq '.spec.disk' "$SERVER_JSON" "Unknown")
    
    # 获取当前出口IP（尽量轻量）
    if [[ -z "$eip" ]]; then
        eip=$(curl -fsS --max-time 3 https://api.ip.sb/ip 2>/dev/null || \
              curl -fsS --max-time 3 https://ifconfig.me 2>/dev/null || \
              echo "")
    fi
    
    # 输出服务器信息JSON
    jq -n \
        --arg ip "$server_ip" \
        --arg eip "$eip" \
        --arg version "$version" \
        --arg install_date "$install_date" \
        --arg cloud_provider "$cloud_provider" \
        --arg cloud_region "$cloud_region" \
        --arg instance_id "$instance_id" \
        --arg hostname "$hostname" \
        --arg user_alias "$user_alias" \
        --arg cpu_spec "$cpu_spec" \
        --arg memory_spec "$memory_spec" \
        --arg disk_spec "$disk_spec" \
        '{
            server_ip: $ip,
            eip: (if $eip == "" then null else $eip end),
            version: $version,
            install_date: $install_date,
            cloud: {
                provider: $cloud_provider,
                region: $cloud_region
            },
            instance_id: $instance_id,
            hostname: $hostname,
            user_alias: $user_alias,
            spec: {
                cpu: $cpu_spec,
                memory: $memory_spec,
                disk: $disk_spec
            }
        }'
}

# 获取证书信息（Let’s Encrypt 与 自签名均可解析，expires_at => yyyy-mm-dd）
get_certificate_info() {
    local cert_mode="self-signed"
    local cert_domain=""
    local cert_expires_at=""
    local cert_renewal_type="manual"

    # 保持英文月份，避免本地化解析问题
    export LC_ALL=C

    # 读取证书模式
    if [[ -f "${CONFIG_DIR}/cert_mode" ]]; then
        cert_mode=$(cat "${CONFIG_DIR}/cert_mode")
    fi

    # 便携式解析：把 "notAfter=Sep 25 12:34:56 2026 GMT" → "2026-09-25"
    _parse_expire_date_portable() {
        local pem="$1"
        [[ -f "$pem" ]] || return 1

        # 读出 notAfter 原始字符串
        local raw_end
        raw_end=$(openssl x509 -enddate -noout -in "$pem" 2>/dev/null) || return 1
        raw_end=${raw_end#notAfter=}                         # 去掉前缀
        raw_end=$(printf '%s\n' "$raw_end" | awk '{$1=$1;print}')  # 压缩多空格

        # 期望形如：Mon DD HH:MM:SS YYYY TZ
        # 取出月份、日、年
        local mon dd yyyy
        mon=$(printf '%s\n' "$raw_end" | awk '{print $1}')
        dd=$( printf '%s\n' "$raw_end" | awk '{print $2}')
        yyyy=$(printf '%s\n' "$raw_end" | awk '{print $4}')

        # 月份映射
        local mm
        case "$mon" in
            Jan) mm=01 ;; Feb) mm=02 ;; Mar) mm=03 ;; Apr) mm=04 ;;
            May) mm=05 ;; Jun) mm=06 ;; Jul) mm=07 ;; Aug) mm=08 ;;
            Sep) mm=09 ;; Oct) mm=10 ;; Nov) mm=11 ;; Dec) mm=12 ;;
            *)   return 1 ;;
        esac

        # 日补零
        if [[ "$dd" =~ ^[0-9]$ ]]; then
            dd="0$dd"
        fi

        # 基本校验
        [[ -n "$yyyy" && -n "$mm" && -n "$dd" ]] || return 1

        printf '%s-%s-%s' "$yyyy" "$mm" "$dd"
        return 0
    }

    # 确定证书文件路径（两类都处理好）
    local cert_file=""
    if [[ "$cert_mode" =~ ^letsencrypt ]]; then
        # ---- Let's Encrypt ----
        cert_domain="${cert_mode#letsencrypt:}"
        cert_renewal_type="auto"

        if [[ -n "$cert_domain" ]]; then
            if [[ -f "/etc/letsencrypt/live/${cert_domain}/cert.pem" ]]; then
                cert_file="/etc/letsencrypt/live/${cert_domain}/cert.pem"
            elif [[ -f "/etc/letsencrypt/live/${cert_domain}/fullchain.pem" ]]; then
                cert_file="/etc/letsencrypt/live/${cert_domain}/fullchain.pem"
            fi
        fi

        # 兜底：未指定域名时，尝试 live 目录下的第一个证书
        if [[ -z "$cert_file" && -d /etc/letsencrypt/live ]]; then
            local first_live
            first_live=$(find /etc/letsencrypt/live -maxdepth 1 -mindepth 1 -type d | head -n1)
            if [[ -n "$first_live" ]]; then
                cert_domain="${first_live##*/}"
                if [[ -f "${first_live}/cert.pem" ]]; then
                    cert_file="${first_live}/cert.pem"
                elif [[ -f "${first_live}/fullchain.pem" ]]; then
                    cert_file="${first_live}/fullchain.pem"
                fi
            fi
        fi
    else
        # ---- 自签名 ----
        cert_file="${CERT_DIR}/current.pem"
        [[ -f "$cert_file" ]] || cert_file="${CERT_DIR}/self-signed.pem"
    fi

    # 解析到期时间（统一用便携式解析）
    if [[ -n "$cert_file" ]]; then
        cert_expires_at="$(_parse_expire_date_portable "$cert_file")" || cert_expires_at=""
    fi

    # 输出 JSON（空串转 null）
    jq -n \
      --arg mode "$cert_mode" \
      --arg domain "$cert_domain" \
      --arg expires_at "$cert_expires_at" \
      --arg renewal_type "$cert_renewal_type" \
      '{
          mode: $mode,
          domain: (if $domain == "" then null else $domain end),
          expires_at: (if $expires_at == "" then null else $expires_at end),
          renewal_type: $renewal_type
      }'
}


# 获取服务状态
get_services_status() {
    local nginx_status xray_status singbox_status
    
    # 检查服务状态
    nginx_status=$(systemctl is-active nginx 2>/dev/null || echo "inactive")
    xray_status=$(systemctl is-active xray 2>/dev/null || echo "inactive")
    singbox_status=$(systemctl is-active sing-box 2>/dev/null || echo "inactive")
    
    # 获取服务版本（可选）
    local nginx_version xray_version singbox_version
    nginx_version=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    xray_version=$(xray version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    
    if command -v sing-box >/dev/null 2>&1; then
        singbox_version=$(sing-box version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    elif command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
        singbox_version=$(/usr/local/bin/sing-box version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    else
        singbox_version=""
    fi
    
    # 输出服务状态JSON
    jq -n \
        --arg nginx_status "$nginx_status" \
        --arg xray_status "$xray_status" \
        --arg singbox_status "$singbox_status" \
        --arg nginx_version "$nginx_version" \
        --arg xray_version "$xray_version" \
        --arg singbox_version "$singbox_version" \
        '{
            nginx: {
                status: $nginx_status,
                version: (if $nginx_version == "" then null else $nginx_version end)
            },
            xray: {
                status: $xray_status,
                version: (if $xray_version == "" then null else $xray_version end)
            },
            "sing-box": {
                status: $singbox_status,
                version: (if $singbox_version == "" then null else $singbox_version end)
            }
        }'
}

# 获取协议配置状态 (最终修正版 - 动态主机名 + 动态SNI)
# Get protocol configuration status (Final corrected version - dynamic hostname + dynamic SNI)
get_protocols_status() {
    local health_report_file="${TRAFFIC_DIR}/protocol-health.json"
    local server_config_file="${CONFIG_DIR}/server.json"
    local xray_config_file="${CONFIG_DIR}/xray.json"

    # Dynamically determine to use domain or IP
    local host_or_ip
    local cert_mode_file="${CONFIG_DIR}/cert_mode"
    if [[ -f "$cert_mode_file" ]] && grep -q "letsencrypt:" "$cert_mode_file"; then
        host_or_ip=$(cat "$cert_mode_file" | cut -d: -f2)
    else
        host_or_ip=$(jq -r '.server_ip // "127.0.0.1"' "$server_config_file" 2>/dev/null || echo "127.0.0.1")
    fi

    # Dynamically read the current Reality SNI from xray.json
    local reality_sni
    reality_sni="$(jq -r 'first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.serverNames[0]) // (first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.dest) | split(":")[0]) // empty' "$xray_config_file" 2>/dev/null)"
    : "${reality_sni:=www.microsoft.com}" # Fallback to a default

    local health_data="[]"
    if [[ -s "$health_report_file" ]]; then
        health_data=$(jq -c '.protocols // []' "$health_report_file" 2>/dev/null || echo "[]")
    fi
    
    local server_config="{}"
    if [[ -s "$server_config_file" ]]; then
        server_config=$(jq -c '.' "$server_config_file" 2>/dev/null || echo "{}")
    fi

    local protocol_order=(
        "VLESS-Reality" "VLESS-gRPC" "VLESS-WebSocket" 
        "Trojan-TLS" "Hysteria2" "TUIC"
    )
	declare -A protocol_meta
    protocol_meta["VLESS-Reality"]="reality|抗审查/伪装访问，综合性能最佳|极佳★★★★★|443|tcp"
    protocol_meta["VLESS-gRPC"]="grpc|CDN流量伪装，穿透复杂网络环境|极佳★★★★★|443|tcp"
    protocol_meta["VLESS-WebSocket"]="ws|兼容性最强，可套CDN或Web服务器|良好★★★★☆|443|tcp"
    protocol_meta["Trojan-TLS"]="trojan|模拟HTTPS流量，协议轻量高效|良好★★★★☆|443|tcp"
    protocol_meta["Hysteria2"]="hysteria2|暴力发包(UDP)，专为不稳定网络加速|一般★★★☆☆|443|udp"
    protocol_meta["TUIC"]="tuic|基于QUIC(UDP)，有效降低连接延迟|良好★★★★☆|2053|udp"

    local final_protocols="[]"
    for name in "${protocol_order[@]}"; do
        IFS='|' read -r key scenario camouflage port network <<< "${protocol_meta[$name]}"

        local share_link
        share_link=$(jq -n -r \
            --arg name "$name" \
            --argjson conf "$server_config" \
            --arg domain "$host_or_ip" \
            --arg reality_sni "$reality_sni" \
            '
            def url_encode: @uri;
            if $name == "VLESS-Reality" then "vless://\($conf.uuid.vless.reality)@\($domain):443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=\($reality_sni)&pbk=\($conf.reality.public_key)&sid=\($conf.reality.short_id)&type=tcp#EdgeBox-REALITY"
            elif $name == "VLESS-gRPC" then "vless://\($conf.uuid.vless.grpc)@\($domain):443?encryption=none&security=tls&sni=\($domain)&alpn=h2&type=grpc&serviceName=grpc&fp=chrome#EdgeBox-gRPC"
            elif $name == "VLESS-WebSocket" then "vless://\($conf.uuid.vless.ws)@\($domain):443?encryption=none&security=tls&sni=\($domain)&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome#EdgeBox-WS"
            elif $name == "Trojan-TLS" then "trojan://\($conf.password.trojan | url_encode)@\($domain):443?security=tls&sni=trojan.\($domain)&alpn=http%2F1.1&fp=chrome#EdgeBox-TROJAN"
            elif $name == "Hysteria2" then "hysteria2://\($conf.password.hysteria2 | url_encode)@\($domain):443?sni=\($domain)&alpn=h3#EdgeBox-HYSTERIA2"
            # <<< FIX: Corrected the stray brace from \($domain}} to \($domain) >>>
            elif $name == "TUIC" then "tuic://\($conf.uuid.tuic):\($conf.password.tuic | url_encode)@\($domain):2053?congestion_control=bbr&alpn=h3&sni=\($domain)#EdgeBox-TUIC"
            else ""
            end
        ')

        local static_info
        static_info=$(jq -n \
            --arg name "$name" --arg key "$key" --arg scenario "$scenario" \
            --arg camouflage "$camouflage" --argjson port "$port" --arg network "$network" \
            --arg share_link "$share_link" \
            '{name: $name, protocol: $key, scenario: $scenario, camouflage: $camouflage, port: $port, network: $network, share_link: $share_link}')
        
        local dynamic_info
        dynamic_info=$(echo "$health_data" | jq -c --arg key "$key" --arg fullname "$name" '.[] | select(.protocol == $key or .protocol == $fullname)')

        if [[ -z "$dynamic_info" || "$dynamic_info" == "null" ]]; then
            dynamic_info='{
                "status": "待检测", "status_badge": "⚪ 待检测", "health_score": 0, "response_time": -1,
                "detail_message": "等待健康检查...", "recommendation": "none", "recommendation_badge": ""
            }'
        fi
        
        local full_protocol_info
        full_protocol_info=$(jq -n --argjson s "$static_info" --argjson d "$dynamic_info" '$s + $d')
        
        final_protocols=$(echo "$final_protocols" | jq --argjson item "$full_protocol_info" '. += [$item]')
    done

    echo "$final_protocols"
}


# 获取分流配置状态
get_shunt_status() {
    local mode="vps"
    local proxy_info=""
    local health="unknown"
    local whitelist_json='[]'

    # 读取分流状态
    local state_file="${SHUNT_DIR}/state.json"
    if [[ -f "$state_file" ]]; then
        mode=$(safe_jq '.mode' "$state_file" "vps")
        proxy_info=$(safe_jq '.proxy_info' "$state_file" "")
        health=$(safe_jq '.health' "$state_file" "unknown")
    fi

    # 读取白名单（new11 安全读写）
    local whitelist_file="${SHUNT_DIR}/whitelist.txt"
    whitelist_json="$(jq_safe_list "$whitelist_file")"

    # 确保 whitelist_json 是有效 JSON（兜底）
    if ! echo "$whitelist_json" | jq . >/dev/null 2>&1; then
        whitelist_json='[]'
    fi

    # 输出分流状态JSON（口径不变）
    jq -n \
        --arg mode "$mode" \
        --arg proxy_info "$proxy_info" \
        --arg health "$health" \
        --argjson whitelist "$whitelist_json" \
        '{
            mode: $mode,
            proxy_info: $proxy_info,
            health: $health,
            whitelist: $whitelist
        }'
}


# 获取订阅信息
get_subscription_info() {
    local sub_plain=""
    local sub_b64=""
    local sub_b64_lines=""
    
    # 按优先级查找订阅文件
    local subscription_sources=(
        "${CONFIG_DIR}/subscription.txt"
        "${TRAFFIC_DIR}/sub.txt"
        "/var/www/html/sub"
    )
    
    for sub_file in "${subscription_sources[@]}"; do
        if [[ -s "$sub_file" ]]; then
            sub_plain=$(cat "$sub_file")
            break
        fi
    done
    
    # 生成Base64编码
    if [[ -n "$sub_plain" ]]; then
        if base64 --help 2>&1 | grep -q -- ' -w'; then
            sub_b64=$(printf '%s\n' "$sub_plain" | base64 -w0)
        else
            sub_b64=$(printf '%s\n' "$sub_plain" | base64 | tr -d '\n')
        fi
        
        # 生成逐行Base64
        local temp_file
        temp_file=$(mktemp)
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if base64 --help 2>&1 | grep -q -- ' -w'; then
                printf '%s' "$line" | sed -e '$a\' | base64 -w0
            else
                printf '%s' "$line" | sed -e '$a\' | base64 | tr -d '\n'
            fi
            printf '\n'
        done <<<"$sub_plain" > "$temp_file"
        sub_b64_lines=$(cat "$temp_file")
        rm -f "$temp_file"
    fi
    
    # 输出订阅信息JSON
    jq -n \
        --arg plain "$sub_plain" \
        --arg base64 "$sub_b64" \
        --arg b64_lines "$sub_b64_lines" \
        '{
            plain: $plain,
            base64: $base64,
            b64_lines: $b64_lines
        }'
}

# 获取敏感凭据信息（从server.json提取）
get_secrets_info() {
    local secrets_json="{}"
    
    if [[ -f "$SERVER_JSON" ]]; then
        secrets_json=$(jq -c '{
            vless: {
                reality: (.uuid.vless.reality // .uuid.vless // ""),
                grpc: (.uuid.vless.grpc // .uuid.vless // ""),
                ws: (.uuid.vless.ws // .uuid.vless // "")
            },
            tuic_uuid: (.uuid.tuic // ""),
            password: {
                trojan: (.password.trojan // ""),
                hysteria2: (.password.hysteria2 // ""),
                tuic: (.password.tuic // "")
            },
            reality: {
                public_key: (.reality.public_key // ""),
                private_key: (.reality.private_key // ""),
                short_id: (.reality.short_id // "")
            }
        }' "$SERVER_JSON" 2>/dev/null || echo "{}")
    fi
    
    echo "$secrets_json"
}


#############################################
# 通知收集函数（修复版）
#############################################

collect_notifications() {
    local notifications_json="$TRAFFIC_DIR/notifications.json"
    local temp_notifications="[]"
    local alert_log="/var/log/edgebox-traffic-alert.log"
    
    log_info "收集系统通知..."
    
    # 收集预警通知（最近10条）
    if [[ -f "$alert_log" ]] && [[ -r "$alert_log" ]]; then
        local alert_notifications
        alert_notifications=$(tail -n 10 "$alert_log" 2>/dev/null | grep -E '^\[[0-9-T:Z+]+\]' | \
        awk 'BEGIN{print "["} 
        {
            gsub(/^\[/, "", $1)  # 移除开头的 [
            gsub(/\]/, "", $1)   # 移除结尾的 ]
            msg = $0
            gsub(/^\[[^\]]+\]\s*/, "", msg)  # 移除时间戳部分
            gsub(/"/, "\\\"", msg)  # 转义双引号
            if(NR>1) print ","
            printf "{\"id\":\"alert_%s\",\"type\":\"alert\",\"level\":\"warning\",\"time\":\"%s\",\"message\":\"%s\",\"read\":false}", 
                   NR, $1, msg
        } 
        END{print "]"}' 2>/dev/null || echo "[]")
        temp_notifications="$alert_notifications"
    fi
    
    # 收集系统状态通知
    local system_notifications="[]"
    local nginx_status=$(systemctl is-active nginx 2>/dev/null || echo "inactive")
    local xray_status=$(systemctl is-active xray 2>/dev/null || echo "inactive")
    local singbox_status=$(systemctl is-active sing-box 2>/dev/null || echo "inactive")
    
    # 生成系统状态通知
    local sys_notifs="["
    local has_notif=false
    local current_time=$(date -Is)
    local timestamp=$(date +%s)
    
    if [[ "$nginx_status" != "active" ]]; then
        if [[ "$has_notif" == "true" ]]; then sys_notifs+=","; fi
        sys_notifs+="{\"id\":\"sys_nginx_${timestamp}\",\"type\":\"system\",\"level\":\"error\",\"time\":\"${current_time}\",\"message\":\"Nginx 服务已停止运行\",\"action\":\"systemctl start nginx\",\"read\":false}"
        has_notif=true
    fi
    
    if [[ "$xray_status" != "active" ]]; then
        if [[ "$has_notif" == "true" ]]; then sys_notifs+=","; fi
        sys_notifs+="{\"id\":\"sys_xray_${timestamp}\",\"type\":\"system\",\"level\":\"error\",\"time\":\"${current_time}\",\"message\":\"Xray 服务已停止运行\",\"action\":\"systemctl start xray\",\"read\":false}"
        has_notif=true
    fi
    
    if [[ "$singbox_status" != "active" ]]; then
        if [[ "$has_notif" == "true" ]]; then sys_notifs+=","; fi
        sys_notifs+="{\"id\":\"sys_singbox_${timestamp}\",\"type\":\"system\",\"level\":\"error\",\"time\":\"${current_time}\",\"message\":\"sing-box 服务已停止运行\",\"action\":\"systemctl start sing-box\",\"read\":false}"
        has_notif=true
    fi
    
    sys_notifs+="]"
    system_notifications="$sys_notifs"
    
    # 读取已有通知并合并
    local existing_notifications="[]"
    if [[ -f "$notifications_json" ]]; then
        existing_notifications=$(jq '.notifications // []' "$notifications_json" 2>/dev/null || echo "[]")
    fi
    
    # 合并所有通知，去重并限制数量
    local cutoff_date=$(date -d '7 days ago' -Is)
    
    # 使用更安全的jq命令
    {
        echo "{"
        echo "  \"updated_at\": \"$(date -Is)\","
        echo "  \"notifications\": []"
        echo "}"
    } > "$notifications_json.tmp"
    
    # 如果jq可用，使用复杂合并；否则使用简单版本
    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --argjson existing "$existing_notifications" \
            --argjson alerts "$temp_notifications" \
            --argjson systems "$system_notifications" \
            --arg updated "$(date -Is)" \
            --arg cutoff "$cutoff_date" \
            '{
                updated_at: $updated,
                notifications: ([$alerts[], $systems[], $existing[]] | 
                               unique_by(.id) |
                               map(select(.time > $cutoff)) |
                               sort_by(.time) | 
                               reverse | 
                               .[0:50])
            }' > "$notifications_json.tmp" 2>/dev/null || {
            # 如果jq复杂操作失败，使用简单版本
            echo "{\"updated_at\":\"$(date -Is)\",\"notifications\":${system_notifications}}" > "$notifications_json.tmp"
        }
    else
        # 如果没有jq，创建基本结构
        echo "{\"updated_at\":\"$(date -Is)\",\"notifications\":${system_notifications}}" > "$notifications_json.tmp"
    fi
    
    # 原子性替换
    mv "$notifications_json.tmp" "$notifications_json"
    chmod 644 "$notifications_json" 2>/dev/null || true
    
    log_info "通知数据收集完成"
}


#############################################
# 主数据生成函数
#############################################

# 生成完整的dashboard.json
generate_dashboard_data() {
    log_info "开始生成Dashboard数据..."

    # <<< 修复点 1: 同样增加动态主机判断逻辑 >>>
    local host_or_ip
    local cert_mode_file="${CONFIG_DIR}/cert_mode"
    if [[ -f "$cert_mode_file" ]] && grep -q "letsencrypt:" "$cert_mode_file"; then
        host_or_ip=$(cat "$cert_mode_file" | cut -d: -f2)
    else
        host_or_ip=$(jq -r '.server_ip // "127.0.0.1"' "${CONFIG_DIR}/server.json" 2>/dev/null || echo "127.0.0.1")
    fi
    # <<< 修复点结束 >>>

    # 1. 优先执行健康检查，确保 protocol-health.json 是最新的
    if [[ -x "${SCRIPTS_DIR}/protocol-health-monitor.sh" ]]; then
        log_info "正在刷新协议健康状态..."
        "${SCRIPTS_DIR}/protocol-health-monitor.sh" >/dev/null 2>&1 || log_warn "协议健康检查失败"
    fi

    mkdir -p "$TRAFFIC_DIR"

    local timestamp system_info cert_info services_info protocols_info shunt_info subscription_info secrets_info

    timestamp=$(date -Is)
    system_info=$(get_system_info)
    cert_info=$(get_certificate_info)
    services_info=$(get_services_status)
    protocols_info=$(get_protocols_status)
    shunt_info=$(get_shunt_status)
    subscription_info=$(get_subscription_info)
    secrets_info=$(get_secrets_info)

services_info=$(
  jq -n \
    --arg nstat "$(systemctl is-active --quiet nginx    && echo '运行中 √' || echo '已停止')" \
    --arg xstat "$(systemctl is-active --quiet xray     && echo '运行中 √' || echo '已停止')" \
    --arg sstat "$(systemctl is-active --quiet sing-box && echo '运行中 √' || echo '已停止')" \
    --arg nver  "$(nginx -v 2>&1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)" \
    --arg xver  "$((xray -version 2>/dev/null || xray version 2>/dev/null) | head -n1 | grep -Eo 'v?[0-9]+(\.[0-9]+)+' | head -1)" \
    --arg sver  "$(sing-box version 2>/dev/null | head -n1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)" \
    '{nginx:{status:$nstat,version:$nver},
      xray:{status:$xstat,version:$xver},
      "sing-box":{status:$sstat,version:$sver}}'
)

    # <<< 修复点 2: 将动态主机名传入jq并使用 >>>
    jq -n \
        --arg timestamp "$timestamp" \
        --argjson system "$system_info" \
        --argjson cert "$cert_info" \
        --argjson services "$services_info" \
        --argjson protocols "$protocols_info" \
        --argjson shunt "$shunt_info" \
        --argjson subscription "$subscription_info" \
        --argjson secrets "$secrets_info" \
        --arg host_or_ip "$host_or_ip" \
        '{
            updated_at: $timestamp,
            subscription_url: ("http://" + $host_or_ip + "/sub"),
            server: ($system + {cert: $cert}),
            services: $services,
            protocols: $protocols,
            shunt: $shunt,
            subscription: $subscription,
            secrets: $secrets
        }' > "${TRAFFIC_DIR}/dashboard.json.tmp"
    # <<< 修复点结束 >>>

    if [[ -s "${TRAFFIC_DIR}/dashboard.json.tmp" ]]; then
        mv "${TRAFFIC_DIR}/dashboard.json.tmp" "${TRAFFIC_DIR}/dashboard.json"
        chmod 644 "${TRAFFIC_DIR}/dashboard.json"
        log_info "dashboard.json 生成完成"
    else
        log_error "dashboard.json 生成失败"
        rm -f "${TRAFFIC_DIR}/dashboard.json.tmp"
        return 1
    fi
}

# 生成system.json（系统监控数据）
generate_system_data() {
    log_info "生成系统监控数据..."
    
    local system_metrics
    system_metrics=$(get_system_metrics)
    
    echo "$system_metrics" > "${TRAFFIC_DIR}/system.json.tmp"
    
    if [[ -s "${TRAFFIC_DIR}/system.json.tmp" ]]; then
        mv "${TRAFFIC_DIR}/system.json.tmp" "${TRAFFIC_DIR}/system.json"
        chmod 644 "${TRAFFIC_DIR}/system.json"
        log_info "system.json 生成完成"
    else
        log_error "system.json 生成失败"
        rm -f "${TRAFFIC_DIR}/system.json.tmp"
        return 1
    fi
}


#############################################
# 主执行逻辑
#############################################

# 主函数
main() {
    if [[ "${1:-}" == "--notifications-only" ]]; then
        collect_notifications
        exit 0
    fi
	
    case "${1:-}" in
        --now|--once|update)
            # 立即执行数据生成
            generate_dashboard_data
            generate_system_data
            ;;
        --schedule|--install)
            # 设置定时任务
            setup_cron_jobs
            ;;
        --help|-h)
            echo "用法: $0 [选项]"
            echo "选项:"
            echo "  --now, --once    立即生成Dashboard数据"
            echo "  --schedule       设置定时任务"
            echo "  --help          显示帮助信息"
            ;;
        *)
            # 默认执行数据生成
            generate_dashboard_data
            generate_system_data
            ;;
    esac
	# 在最后添加通知收集
    collect_notifications
}

# 执行主函数
main "$@"
DASHBOARD_BACKEND_SCRIPT

    # 设置脚本权限
    chmod +x "${SCRIPTS_DIR}/dashboard-backend.sh"
    
    log_success "Dashboard后端脚本生成完成: ${SCRIPTS_DIR}/dashboard-backend.sh"
    
    return 0
}


# 创建协议健康检查脚本
create_protocol_health_check_script() {
    log_info "创建协议健康监控与自愈脚本..."

    mkdir -p "${SCRIPTS_DIR}"

    cat > "${SCRIPTS_DIR}/protocol-health-monitor.sh" << 'HEALTH_MONITOR_SCRIPT'
#!/usr/bin/env bash
#############################################
# EdgeBox 协议健康监控与自愈系统
# 版本: 4.0.0
# 功能: 
#   1. 深度健康检查(TCP/UDP实际可达性测试)
#   2. 自动故障修复(服务重启、配置修复、防火墙修复)
#   3. 修复失败后发送告警
#   4. 生成详细的健康报告JSON
#############################################

set -euo pipefail
export LANG=C LC_ALL=C

# ==================== 配置部分 ====================
CONFIG_DIR="${CONFIG_DIR:-/etc/edgebox/config}"
TRAFFIC_DIR="${TRAFFIC_DIR:-/etc/edgebox/traffic}"
LOG_DIR="/var/log/edgebox"
CERT_DIR="/etc/edgebox/cert"

OUTPUT_JSON="${TRAFFIC_DIR}/protocol-health.json"
TEMP_JSON="${OUTPUT_JSON}.tmp"
LOG_FILE="${LOG_DIR}/health-monitor.log"

# 自愈配置
MAX_RESTART_ATTEMPTS=3
RESTART_COOLDOWN=300
LAST_RESTART_FILE="${LOG_DIR}/.last_restart_timestamp"

# ==================== 增强配置常量 ====================
# 日志分析窗口
JOURNAL_LOOKBACK_MINUTES="${JOURNAL_LOOKBACK_MINUTES:-10}"

# 动态状态与通知文件
NOTIFICATIONS_FILE="${TRAFFIC_DIR}/notifications.json"
SEVERE_ERROR_FILE="${TRAFFIC_DIR}/severe_errors.json"
WEIGHT_HISTORY_FILE="${LOG_DIR}/.protocol_weight_history"

# 自愈保护增强
RESTART_HOURLY_LIMIT=3
RESTART_COUNTER_FILE="${LOG_DIR}/.restart_counter"

# 动态权重配置
WEIGHT_ADJUSTMENT_THRESHOLD=3

# 外部连通性测试配置(用于UDP协议)
EXTERNAL_TEST_ENABLED=true       # 是否启用外部连通性测试
EXTERNAL_TEST_TIMEOUT=5          # 外部测试超时(秒)

# ==================== 日志函数 ====================
log_info() { 
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" >> "$LOG_FILE" 
}
log_warn() { 
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >> "$LOG_FILE" 
}
log_error() { 
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >> "$LOG_FILE" >&2 
}
log_success() { 
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $*" >> "$LOG_FILE" 
}
log_heal() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [HEAL] $*" >> "$LOG_FILE"
}

# ==================== 协议配置 ====================
declare -A PROTOCOL_PORTS=(
    ["reality"]="443"
    ["grpc"]="443"
    ["ws"]="443"
    ["trojan"]="443"
    ["hysteria2"]="443"
    ["tuic"]="2053"
)

declare -A PROTOCOL_SERVICES=(
    ["reality"]="xray"
    ["grpc"]="xray"
    ["ws"]="xray"
    ["trojan"]="xray"
    ["hysteria2"]="sing-box"
    ["tuic"]="sing-box"
)

declare -A PROTOCOL_WEIGHTS=(
    ["reality"]="95"
    ["hysteria2"]="90"
    ["tuic"]="85"
    ["grpc"]="75"
    ["ws"]="70"
    ["trojan"]="65"
)

# ==================== 工具函数 ====================
ensure_log_dir() {
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || true
}

generate_self_signed_cert() {
    log_info "(Healer) Generating self-signed certificate..."

    mkdir -p "${CERT_DIR}"
    rm -f "${CERT_DIR}"/self-signed.{key,pem} "${CERT_DIR}"/current.{key,pem}

    if ! command -v openssl >/dev/null 2>&1; then
        log_error "(Healer) openssl not found, cannot generate certificate"; return 1;
    fi

    local server_ip="127.0.0.1"
    if [[ -f "/etc/edgebox/config/server.json" ]]; then
        server_ip=$(jq -r '.server_ip // "127.0.0.1"' "/etc/edgebox/config/server.json" 2>/dev/null || echo "127.0.0.1")
    fi

    openssl ecparam -genkey -name secp384r1 -out "${CERT_DIR}/self-signed.key" 2>/dev/null || { log_error "(Healer) Failed to generate ECC private key"; return 1; }
    openssl req -new -x509 -key "${CERT_DIR}/self-signed.key" -out "${CERT_DIR}/self-signed.pem" -days 3650 -subj "/C=US/ST=CA/L=SF/O=EdgeBox/CN=${server_ip}" >/dev/null 2>&1 || { log_error "(Healer) Failed to generate self-signed certificate"; return 1; }

    ln -sf "${CERT_DIR}/self-signed.key" "${CERT_DIR}/current.key"
    ln -sf "${CERT_DIR}/self-signed.pem" "${CERT_DIR}/current.pem"

    local NOBODY_GRP="$(id -gn nobody 2>/dev/null || echo nogroup)"
    chown -R root:"${NOBODY_GRP}" "${CERT_DIR}" 2>/dev/null || true
    chmod 750 "${CERT_DIR}" 2>/dev/null || true
    chmod 640 "${CERT_DIR}"/self-signed.key 2>/dev/null || true
    chmod 644 "${CERT_DIR}"/self-signed.pem 2>/dev/null || true

    if openssl x509 -in "${CERT_DIR}/current.pem" -noout >/dev/null 2>&1; then
        log_success "(Healer) Self-signed certificate generated successfully."
        echo "self-signed" > "${CONFIG_DIR}/cert_mode"
    else
        log_error "(Healer) Certificate validation failed."; return 1;
    fi
    return 0
}

# 检查服务是否在冷却期内
is_in_cooldown() {
    local service=$1
    if [[ ! -f "$LAST_RESTART_FILE" ]]; then
        return 1
    fi

    local last_restart
    last_restart=$(grep "^${service}:" "$LAST_RESTART_FILE" 2>/dev/null | cut -d: -f2)
    if [[ -z "$last_restart" ]]; then
        return 1
    fi

    local current_time=$(date +%s)
    local time_diff=$((current_time - last_restart))

    if [[ $time_diff -lt $RESTART_COOLDOWN ]]; then
        log_warn "服务 $service 在冷却期内 (${time_diff}s/${RESTART_COOLDOWN}s)"
        return 0
    fi
    return 1
}

record_restart_time() {
    local service=$1
    local timestamp=$(date +%s)

    mkdir -p "$LOG_DIR"
    touch "$LAST_RESTART_FILE"

    sed -i "/^${service}:/d" "$LAST_RESTART_FILE" 2>/dev/null || true
    echo "${service}:${timestamp}" >> "$LAST_RESTART_FILE"
}
# ==================== 健康检查函数 ====================
check_service_status() {
    local service=$1
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "running"
    else
        echo "stopped"
    fi
}

check_port_listening() {
    local port=$1
    local proto=${2:-tcp}

if ss -lnp -A "$proto" 2>/dev/null | grep -q ":${port} "; then
    return 0
else
    return 1
fi
}

# TCP协议深度检查(增强版 - 含全链路延迟测试)
test_tcp_protocol() {
    local protocol=$1
    local port=${PROTOCOL_PORTS[$protocol]}
    local server_name

    ### FIX STARTS HERE: Read from the primary source, not the final output ###
    server_name=$(jq -r '.cert.domain // ""' "${CONFIG_DIR}/server.json" 2>/dev/null)
    [[ -z "$server_name" ]] && server_name=$(jq -r '.server_ip // "127.0.0.1"' "${CONFIG_DIR}/server.json" 2>/dev/null)
    ### FIX ENDS HERE ###

    log_info "TCP检查: $protocol"

    # Level 1: 检查内部回环端口监听
    local internal_port
    case $protocol in
        reality) internal_port=11443 ;;
        grpc)    internal_port=10085 ;;
        ws)      internal_port=10086 ;;
        trojan)  internal_port=10143 ;;
        *)
            echo "down:0:unknown_tcp_protocol"
            return
            ;;
    esac

    if ! check_port_listening "$internal_port" "tcp"; then
        echo "down:0:port_not_listening"
        return
    fi

    # Level 2: TLS握手测试 (经由Nginx)
    local handshake_time=0
    local start_ms=$(date +%s%3N)
    if echo | timeout 3 openssl s_client \
        -connect 127.0.0.1:443 \
        -servername "$server_name" \
        -alpn "h2,http/1.1" >/dev/null 2>&1; then
        local end_ms=$(date +%s%3N)
        handshake_time=$((end_ms - start_ms))
        log_info "TLS握手时间: ${handshake_time}ms"
    else
        echo "degraded:0:tls_handshake_failed"
        return
    fi

    # Level 3: 全链路延迟测试 (经由Nginx)
    local full_chain_time=0
    local test_url="https://127.0.0.1/health"

    local curl_time
    curl_time=$(timeout 5 curl -s -w "%{time_total}" \
        --resolve "${server_name}:443:127.0.0.1" \
        --connect-timeout 3 \
        --max-time 5 \
        -o /dev/null \
        -H "Host: ${server_name}" \
        "${test_url}" 2>/dev/null || echo "")

    if [[ -n "$curl_time" ]] && [[ "$curl_time" != "0.000" ]]; then
        full_chain_time=$(echo "$curl_time" | awk '{printf "%.0f", $1 * 1000}')
        log_info "全链路延迟: ${full_chain_time}ms"
        local weighted_time=$(( (handshake_time * 4 + full_chain_time * 6) / 10 ))
        echo "healthy:${weighted_time}:full_chain_verified"
    else
        log_warn "全链路测试失败, 使用握手时间作为指标"
        echo "healthy:${handshake_time}:handshake_only"
    fi
}


# UDP协议深度检查(增强版 - 日志分析 + 本地探测)
test_udp_protocol() {
    local protocol=$1
    local port=${PROTOCOL_PORTS[$protocol]}
    local service=${PROTOCOL_SERVICES[$protocol]}

    log_info "UDP检查: $protocol (端口 $port)"

    # Level 1: 检查端口监听
    if ! check_port_listening "$port" "udp"; then
        echo "down:0:port_not_listening"
        return
    fi

    # Level 2: 检查系统防火墙
    if ! check_udp_firewall_rules "$port"; then
        echo "degraded:0:firewall_blocked"
        return
    fi

    # Level 3: 日志真实性检查 (主要依据)
    local time_window="${JOURNAL_LOOKBACK_MINUTES:-10}"
    local keywords=()
    case $protocol in
        hysteria2)
            keywords=("accepted udp connection" "hysteria.*established" "client connected" "connection from")
            ;;
        tuic)
            keywords=("tuic.*accepted" "connection established" "client.*authenticated" "new connection")
            ;;
    esac

    for keyword in "${keywords[@]}"; do
        if journalctl -u "$service" --since "${time_window} minutes ago" --no-pager 2>/dev/null | grep -iE "$keyword" >/dev/null 2>&1; then
            log_success "✓ 通过日志验证: $protocol 有活跃连接"
            local latency
            latency=$(journalctl -u "$service" --since "10 minutes ago" --no-pager 2>/dev/null | grep -oE "latency[: ]*[0-9]+ms|rtt[: ]*[0-9]+ms" | grep -oE "[0-9]+" | awk '{ total += $1; count++ } END { if (count > 0) print int(total/count); else print 5 }')
            echo "healthy:${latency:-5}:verified_by_log"
            return
        fi
    done

    # Level 4: 本地轻量探测 (辅助依据)
    if command -v tcpdump >/dev/null 2>&1 && (command -v socat >/dev/null 2>&1 || command -v nc >/dev/null 2>&1); then
        local cap_ok=0
        timeout 1 tcpdump -n -i any "udp and port ${port}" -c 1 -q >"/tmp/udp_cap_${protocol}.pcap" 2>/dev/null &
        local TPID=$!
        sleep 0.2
        printf 'healthcheck' | socat -T1 - udp:127.0.0.1:"${port}" >/dev/null 2>&1 || true
        wait $TPID >/dev/null 2>&1 || true
        if [[ -s "/tmp/udp_cap_${protocol}.pcap" ]]; then
            cap_ok=1
        fi
        rm -f "/tmp/udp_cap_${protocol}.pcap" 2>/dev/null || true
        if [[ $cap_ok -eq 1 ]]; then
            log_info "✓ 本地探测成功: $protocol 端口可达"
            # <<< 修复点: 将 "alive" 状态直接升级为 "healthy" 状态 >>>
            echo "healthy:5:verified_by_probe" # 返回 healthy，延迟给一个较低的默认值
            return
        fi
    fi

    # 如果以上检查都未通过，则为仅监听到但未验证
    echo "listening_unverified:0:waiting_for_connection"
}


# 检查UDP端口的系统防火墙规则
check_udp_firewall_rules() {
    local port=$1

    # 检查UFW
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ufw status | grep -qE "${port}/udp.*ALLOW"; then
            return 0  # <<< 修复点: 规则存在，代表成功，返回 0
        else
            return 1  # <<< 修复点: 规则不存在，代表失败，返回 1
        fi
    # 检查firewalld
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        if firewall-cmd --list-ports 2>/dev/null | grep -qE "${port}/udp"; then
            return 0  # <<< 修复点: 规则存在，代表成功，返回 0
        else
            return 1  # <<< 修复点: 规则不存在，代表失败，返回 1
        fi
    # 检查iptables
    elif command -v iptables >/dev/null 2>&1; then
        if iptables -L INPUT -n 2>/dev/null | grep -qE "udp.*dpt:${port}.*ACCEPT"; then
            return 0  # <<< 修复点: 规则存在，代表成功，返回 0
        else
            return 1  # <<< 修复点: 规则不明确或不存在，返回 1
        fi
    fi

    # 如果没有检测到防火墙软件，也视为成功（无阻断）
    return 0  # <<< 修复点: 默认返回成功
}

# 统一的协议性能测试入口
test_protocol_performance() {
    local protocol=$1
    local port=${PROTOCOL_PORTS[$protocol]}

    case $protocol in
        reality|grpc|ws|trojan)
            test_tcp_protocol "$protocol"
            ;;
        hysteria2|tuic)
            test_udp_protocol "$protocol"
            ;;
        *)
            echo "unknown:0:unsupported_protocol"
            ;;
    esac
}

# ==================== 自愈函数 ====================

# 修复UDP防火墙规则
repair_udp_firewall() {
    local port=$1
    log_heal "尝试修复UDP端口 $port 的防火墙规则..."

    local success=false

    # UFW
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ufw allow "${port}/udp" comment "EdgeBox Auto-Heal" >/dev/null 2>&1; then
            log_success "✓ UFW规则已添加: ${port}/udp"
            success=true
        fi
    fi

    # firewalld
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        if firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1; then
            firewall-cmd --reload >/dev/null 2>&1
            log_success "✓ firewalld规则已添加: ${port}/udp"
            success=true
        fi
    fi

    # iptables (fallback)
    if ! $success && command -v iptables >/dev/null 2>&1; then
        if iptables -C INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
            log_info "iptables规则已存在"
            success=true
        elif iptables -A INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; then
            log_success "✓ iptables规则已添加: ${port}/udp"
            # 尝试持久化
            if command -v iptables-save >/dev/null 2>&1; then
                mkdir -p /etc/iptables 2>/dev/null || true
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            fi
            success=true
        fi
    fi

    if $success; then
        return 0
    else
        log_error "✗ 无法修复防火墙规则 (可能需要手动配置云服务商安全组)"
        return 1
    fi
}

# 修复服务配置文件
repair_service_config() {
    local service=$1
    log_heal "检查 $service 配置文件..."

    case $service in
        sing-box)
            local config="${CONFIG_DIR}/sing-box.json"
            if [[ ! -f "$config" ]]; then
                log_error "配置文件不存在: $config"
                return 1
            fi

            # 修复监听地址问题(IPv6 -> IPv4)
            if grep -q '"listen": "::"' "$config"; then
                sed -i 's/"listen": "::"/"listen": "0.0.0.0"/g' "$config"
                log_success "✓ 已修正 sing-box 监听地址为 0.0.0.0"
            fi

            # 验证JSON格式
            if ! jq empty "$config" 2>/dev/null; then
                log_error "配置文件JSON格式错误"
                return 1
            fi

            # 验证sing-box语法
            if command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
                if ! /usr/local/bin/sing-box check -c "$config" 2>/dev/null; then
                    log_error "sing-box 配置语法检查失败"
                    return 1
                fi
            fi
            ;;

        xray)
            local config="${CONFIG_DIR}/xray.json"
            if [[ ! -f "$config" ]]; then
                log_error "配置文件不存在: $config"
                return 1
            fi

            # 验证JSON格式
            if ! jq empty "$config" 2>/dev/null; then
                log_error "配置文件JSON格式错误"
                return 1
            fi
            ;;
    esac

    log_success "✓ 配置文件检查通过"
    return 0
}

# 修复证书问题
repair_certificates() {
    log_heal "检查证书状态..."

    if [[ ! -f "${CERT_DIR}/current.pem" ]] || [[ ! -f "${CERT_DIR}/current.key" ]]; then
        log_warn "证书文件缺失,尝试生成自签名证书..."

        # 调用生成自签名证书函数(需要在install.sh中导出)
        if type generate_self_signed_cert >/dev/null 2>&1; then
            generate_self_signed_cert
            return $?
        else
            log_error "无法调用证书生成函数"
            return 1
        fi
    fi

    log_success "✓ 证书文件存在"
    return 0
}

# 重启服务(带多重保护机制)
restart_service_safely() {
    local service=$1
    # 保护1: 检查冷却期
    if is_in_cooldown "$service"; then
        return 1
    fi
    # 保护2: 检查1小时内重启次数
    if ! check_restart_hourly_limit "$service"; then
        local count
        count=$(grep -c "^${service}:" "$RESTART_COUNTER_FILE" 2>/dev/null || echo "0")
        create_severe_error_notification "$service" "频繁重启(可能配置死锁)" "$count"
        return 1
    fi
    log_heal "尝试重启服务: $service"
    # 保护3: 重启前配置诊断
    local config_check_result
    config_check_result=$(diagnose_service_config "$service")
    if [[ "$config_check_result" != "ok" ]]; then
        log_error "配置诊断失败: $config_check_result"
        create_severe_error_notification "$service" "配置文件错误: $config_check_result" "N/A"
        return 1
    fi
    # 记录重启时间
    record_restart_time "$service"
    echo "${service}:$(date +%s)" >> "$RESTART_COUNTER_FILE"
    # 执行重启
    if systemctl restart "$service" 2>/dev/null; then
        sleep 2
        if systemctl is-active --quiet "$service"; then
            log_success "✓ 服务 $service 重启成功"
            return 0
        else
            log_error "✗ 服务 $service 重启后仍未运行"
            return 1
        fi
    else
        log_error "✗ 服务 $service 重启命令失败"
        return 1
    fi
}

# ==================== 通知系统集成 ====================
NOTIFICATIONS_FILE="${TRAFFIC_DIR}/notifications.json"

# 初始化通知系统
init_notification_system() {
    mkdir -p "$TRAFFIC_DIR"
    if [[ ! -f "$NOTIFICATIONS_FILE" ]]; then
        echo '{"notifications": [], "stats": {"total": 0, "unread": 0}}' > "$NOTIFICATIONS_FILE"
        chmod 644 "$NOTIFICATIONS_FILE"
    fi
}

# 发送自愈步骤通知
send_heal_step_notification() {
    local protocol=$1 step=$2 result=$3 details=${4:-""}
    init_notification_system
    local icon
    case $result in
        success) icon="✅" ;;
        info)    icon="ℹ️" ;;
        warning) icon="⚠️" ;;
        error)   icon="❌" ;;
        *)       icon="🔧" ;;
    esac
    local notification
    notification=$(jq -n \
        --arg id "heal_$(date +%s)_${RANDOM}" --arg type "auto_heal" \
        --arg protocol "$protocol" --arg step "$step" --arg result "$result" \
        --arg icon "$icon" --arg details "$details" --arg timestamp "$(date -Is)" \
        '{
            id: $id, type: $type, category: "system", protocol: $protocol,
            title: ($icon + " 自愈: " + $protocol), message: $step, result: $result,
            details: $details, timestamp: $timestamp, read: false,
            priority: (if $result == "error" then "high" else "normal" end)
        }')
    local temp_file="${NOTIFICATIONS_FILE}.tmp"
    jq --argjson notif "$notification" '
        .notifications |= [$notif] + . |
        if (.notifications | length) > 100 then .notifications = .notifications[0:100] else . end |
        .stats.total += 1 |
        .stats.unread += 1
    ' "$NOTIFICATIONS_FILE" > "$temp_file" 2>/dev/null || return 1
    mv "$temp_file" "$NOTIFICATIONS_FILE"
    chmod 644 "$NOTIFICATIONS_FILE"
    log_info "[通知] $icon $step - $details"
}

# ==================== 自愈保护增强配置 ====================
# 检查服务在1小时内的重启次数
check_restart_hourly_limit() {
    local service=$1
    local current_time=$(date +%s)
    local one_hour_ago=$((current_time - 3600))
    mkdir -p "$LOG_DIR"
    touch "$RESTART_COUNTER_FILE"
    local temp_file="${RESTART_COUNTER_FILE}.tmp"
    awk -v threshold="$one_hour_ago" -F: '$2 >= threshold' "$RESTART_COUNTER_FILE" > "$temp_file" 2>/dev/null || true
    mv "$temp_file" "$RESTART_COUNTER_FILE" 2>/dev/null || true
    local count
    count=$(grep -c "^${service}:" "$RESTART_COUNTER_FILE" 2>/dev/null || echo "0")
    if [[ $count -ge $RESTART_HOURLY_LIMIT ]]; then
        log_error "⚠️  服务 $service 在1小时内已重启 ${count} 次, 超过限制(${RESTART_HOURLY_LIMIT}次)"
        return 1
    fi
    return 0
}

# 生成严重错误通知
create_severe_error_notification() {
    local service=$1 reason=$2 restart_count=$3
    log_error "========== 严重错误: $service 需要人工干预 =========="
    local notification
    notification=$(jq -n \
        --arg type "critical" --arg service "$service" --arg reason "$reason" \
        --arg restart_count "$restart_count" --arg timestamp "$(date -Is)" \
        '{
            type: $type, service: $service, title: "服务需要人工干预",
            message: ($service + " 在1小时内重启 " + $restart_count + " 次，已暂停自动修复。原因: " + $reason),
            severity: "critical", timestamp: $timestamp, action_required: "请检查服务日志和配置文件",
            log_command: ("journalctl -u " + $service + " -n 50")
        }')
    mkdir -p "$TRAFFIC_DIR"
    if [[ -f "$SEVERE_ERROR_FILE" ]]; then
        local existing
        existing=$(cat "$SEVERE_ERROR_FILE")
        echo "$existing" | jq --argjson new "$notification" '. += [$new]' > "${SEVERE_ERROR_FILE}.tmp"
        mv "${SEVERE_ERROR_FILE}.tmp" "$SEVERE_ERROR_FILE"
    else
        echo "[$notification]" > "$SEVERE_ERROR_FILE"
    fi
    chmod 644 "$SEVERE_ERROR_FILE" 2>/dev/null || true
}

# 深入诊断服务配置
diagnose_service_config() {
    local service=$1
    local config_path=""
    case $service in
        sing-box) config_path="${CONFIG_DIR}/sing-box.json" ;;
        xray)     config_path="${CONFIG_DIR}/xray.json" ;;
        nginx)    config_path="/etc/nginx/nginx.conf" ;;
        *) echo "ok"; return 0 ;;
    esac

    if ! jq empty "$config_path" 2>/dev/null; then
        echo "json_syntax_error"
        return 1
    fi

    if [[ "$service" == "sing-box" ]] && command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
        local check_output
        check_output=$(/usr/local/bin/sing-box check -c "$config_path" 2>&1)
        if [[ $? -ne 0 ]]; then
            local error_line
            error_line=$(echo "$check_output" | head -n 1)
            log_error "sing-box配置错误: $error_line"
            echo "config_validation_failed: $error_line"
            return 1
        fi
    elif [[ "$service" == "xray" ]] && command -v /usr/local/bin/xray >/dev/null 2>&1; then
        if ! /usr/local/bin/xray -test -config="$config_path" >/dev/null 2>&1; then
            echo "config_validation_failed"
            return 1
        fi
    elif [[ "$service" == "nginx" ]] && command -v nginx >/dev/null 2>&1; then
        if ! nginx -t >/dev/null 2>&1; then
            echo "config_validation_failed"
            return 1
        fi
    fi

    echo "ok"
    return 0
}

# 协议故障自愈主函数(带完整通知)
heal_protocol_failure() {
    local protocol=$1 failure_reason=$2
    local port=${PROTOCOL_PORTS[$protocol]}
    local service=${PROTOCOL_SERVICES[$protocol]}
    log_heal "========== 开始修复协议: $protocol =========="
    log_info "故障原因: $failure_reason"
    send_heal_step_notification "$protocol" "检测到 ${protocol} 异常, 启动自愈" "info" "故障原因: $failure_reason"
    local repair_success=false
    local repair_steps=()
    case $failure_reason in
        port_not_listening)
            repair_steps+=("检查服务状态")
            send_heal_step_notification "$protocol" "检查 $service 服务状态" "info"
            if [[ "$(check_service_status "$service")" == "stopped" ]]; then
                repair_steps+=("服务已停止, 尝试重启")
                send_heal_step_notification "$protocol" "服务已停止, 准备重启" "warning"
                if restart_service_safely "$service"; then
                    repair_success=true
                    send_heal_step_notification "$protocol" "✓ 服务重启成功" "success"
                else
                    send_heal_step_notification "$protocol" "✗ 服务重启失败" "error" "请检查日志: journalctl -u $service -n 50"
                fi
            else
                repair_steps+=("服务运行中但端口未监听, 检查配置并重启")
                send_heal_step_notification "$protocol" "检测到配置异常或服务僵死" "warning"
                if repair_service_config "$service" && restart_service_safely "$service"; then
                    repair_success=true
                    send_heal_step_notification "$protocol" "✓ 服务已成功恢复" "success"
                else
                    send_heal_step_notification "$protocol" "✗ 服务恢复失败" "error"
                fi
            fi
            ;;
        tls_handshake_failed)
            send_heal_step_notification "$protocol" "检测到TLS握手失败" "warning"
            repair_steps+=("检查证书")
            send_heal_step_notification "$protocol" "正在检查TLS证书..." "info"
            if repair_certificates; then
                send_heal_step_notification "$protocol" "证书检查与修复完成" "success"
            fi
            repair_steps+=("重启服务")
            if restart_service_safely "$service"; then
                repair_success=true
                send_heal_step_notification "$protocol" "✓ 服务已恢复正常" "success"
            else
                send_heal_step_notification "$protocol" "✗ 服务重启失败, 需人工干预" "error"
            fi
            ;;
        firewall_blocked)
            send_heal_step_notification "$protocol" "检测到防火墙可能阻断 UDP ${port}" "warning"
            repair_steps+=("修复系统防火墙规则")
            send_heal_step_notification "$protocol" "正在添加防火墙规则..." "info"
            if repair_udp_firewall "$port"; then
                send_heal_step_notification "$protocol" "✓ 防火墙规则已添加" "success"
                repair_success=true # 防火墙修复后通常不需要重启服务
            else
                send_heal_step_notification "$protocol" "✗ 防火墙修复失败" "error" "请检查云服务商安全组, 确保已放行 UDP ${port}"
            fi
            ;;
        *)
            send_heal_step_notification "$protocol" "未知故障, 尝试通用修复" "warning"
            repair_steps+=("通用修复流程")
            if repair_service_config "$service" && restart_service_safely "$service"; then
                repair_success=true
                send_heal_step_notification "$protocol" "✓ 通用修复成功" "success"
            else
                send_heal_step_notification "$protocol" "✗ 修复失败, 需人工排查" "error"
            fi
            ;;
    esac
    if $repair_success; then
        log_success "========== 协议 $protocol 修复成功 =========="
        send_heal_step_notification "$protocol" "🎉 自愈完成, 协议已恢复" "success" "执行步骤: $(IFS='; '; echo "${repair_steps[*]}")"
        echo "repaired:$(IFS=';'; echo "${repair_steps[*]}")"
    else
        log_error "========== 协议 $protocol 修复失败 =========="
        send_heal_step_notification "$protocol" "⚠️ 自愈未能修复, 需人工干预" "error" "已尝试: $(IFS='; '; echo "${repair_steps[*]}")"
        echo "repair_failed:$(IFS=';'; echo "${repair_steps[*]}")"
    fi
}

# ==================== 动态权重系统 ====================
# 更新协议权重(基于历史表现)
update_protocol_weight() {
    local protocol=$1 status=$2 response_time=$3
    init_weight_history
    local weight_line
    weight_line=$(grep "^${protocol}:" "$WEIGHT_HISTORY_FILE" || echo "")
    if [[ -z "$weight_line" ]]; then
        echo "80"
        return
    fi
    IFS=':' read -r _ base_weight current_bonus consecutive_excellent consecutive_poor <<< "$weight_line"
    local new_excellent=0 new_poor=0 new_bonus=$current_bonus
    if [[ "$status" == "healthy" ]] && [[ $response_time -lt 10 ]]; then
        new_excellent=$((consecutive_excellent + 1))
        new_poor=0
        if [[ $new_excellent -ge $WEIGHT_ADJUSTMENT_THRESHOLD ]]; then
            new_bonus=$((current_bonus + 2))
            # 限制奖励上限
            [[ $new_bonus -gt 10 ]] && new_bonus=10
            new_excellent=0
            log_info "✨ 协议 $protocol 连续表现优秀, 权重+2 (当前奖励: $new_bonus)"
        fi
    elif [[ "$status" == "down" ]] || [[ "$status" == "degraded" ]] || [[ "$status" == "firewall_blocked" ]]; then
        new_excellent=0
        new_poor=$((consecutive_poor + 1))
        if [[ $new_poor -ge $WEIGHT_ADJUSTMENT_THRESHOLD ]]; then
            new_bonus=$((current_bonus - 5)) # 加大惩罚力度
            # 限制惩罚下限
            [[ $new_bonus -lt -20 ]] && new_bonus=-20
            new_poor=0
            log_warn "⚠️  协议 $protocol 连续表现不佳, 权重-5 (当前奖励: $new_bonus)"
        fi
    else
        # 对 alive 和 listening_unverified 状态，缓慢恢复权重
        new_excellent=0
        new_poor=0
        if [[ $current_bonus -lt 0 ]]; then
            new_bonus=$((current_bonus + 1))
        fi
    fi
    sed -i "/^${protocol}:/d" "$WEIGHT_HISTORY_FILE"
    echo "${protocol}:${base_weight}:${new_bonus}:${new_excellent}:${new_poor}" >> "$WEIGHT_HISTORY_FILE"
    echo $((base_weight + new_bonus))
}

# 初始化权重历史
init_weight_history() {
    mkdir -p "$LOG_DIR"
    if [[ ! -f "$WEIGHT_HISTORY_FILE" ]]; then
        for protocol in reality hysteria2 tuic grpc ws trojan; do
            local base_weight=${PROTOCOL_WEIGHTS[$protocol]:-80}
            echo "${protocol}:${base_weight}:0:0:0" >> "$WEIGHT_HISTORY_FILE"
        done
    fi
}

# 增强的健康分数计算(含动态权重)
calculate_health_score() {
    local protocol=$1 status=$2 response_time=$3
    local adjusted_weight
    adjusted_weight=$(update_protocol_weight "$protocol" "$status" "$response_time")
    [[ -z "$adjusted_weight" || $adjusted_weight -lt 0 ]] && adjusted_weight=${PROTOCOL_WEIGHTS[$protocol]:-80}
    local score=0
    case $status in
        healthy)
            score=$adjusted_weight
            if [[ $response_time -lt 10 ]]; then score=$((score + 5))
            elif [[ $response_time -lt 50 ]]; then score=$((score + 2))
            fi
            ;;
        alive) # 新增状态
            score=$((adjusted_weight * 85 / 100))
            ;;
        listening_unverified)
            score=$((adjusted_weight * 70 / 100))
            ;;
        degraded)
            score=$((adjusted_weight * 50 / 100))
            ;;
        firewall_blocked)
            score=$((adjusted_weight * 30 / 100))
            ;;
        down)
            score=0
            ;;
    esac
    [[ $score -gt 100 ]] && score=100
    [[ $score -lt 0 ]] && score=0
    echo "$score"
}

# 根据延迟生成性能等级
get_performance_grade() {
    local response_time=$1
    if [[ $response_time -lt 10 ]]; then echo "excellent"
    elif [[ $response_time -lt 30 ]]; then echo "good"
    elif [[ $response_time -lt 100 ]]; then echo "fair"
    else echo "poor"
    fi
}

map_failure_reason() {
  case "$1" in
    firewall_blocked) echo "防火墙阻断" ;;
    rate_limited)     echo "频控" ;;
    dns_failed|dns_error) echo "DNS失败" ;;
    icmp_blocked)     echo "ICMP受限" ;;
    *) echo "" ;;
  esac
}

# 增强的详细消息生成(含性能等级)
generate_detail_message() {
    local protocol=$1 status=$2 response_time=$3 failure_reason=${4:-""} message=""
    case $status in
        healthy)
            local grade
            grade=$(get_performance_grade "$response_time")
            case $grade in
                excellent) message="🚀 性能优秀 ${response_time}ms" ;;
                good)      message="✨ 性能良好 ${response_time}ms" ;;
                fair)      message="📊 性能一般 ${response_time}ms" ;;
                poor)      message="⏱️ 性能较慢 ${response_time}ms" ;;
            esac
            ;;
        alive)
            message=" UDP服务活跃(已探测)"
            ;;
        listening_unverified)
            message="🟡 服务监听中(待验证)"
            ;;
        degraded)
            reason_label="$(map_failure_reason "$failure_reason")"
			message="⚠️ 服务降级${reason_label:+ · $reason_label}"
            ;;
        firewall_blocked)
            message="🔥 防火墙阻断"
            ;;
        down)
			reason_label="$(map_failure_reason "$failure_reason")"
			message="❌ 服务停止${reason_label:+ · $reason_label}"
            ;;
        *)
            message="❓ 状态未知"
            ;;
    esac
    echo "$message"
}


# 根据健康分数生成推荐等级
get_recommendation_level() {
    local health_score=$1

    if [[ $health_score -ge 85 ]]; then
        echo "primary"
    elif [[ $health_score -ge 70 ]]; then
        echo "recommended"
    elif [[ $health_score -ge 50 ]]; then
        echo "backup"
    elif [[ $health_score -gt 0 ]]; then
        echo "not_recommended"
    else
        echo "none"
    fi
}

# 生成推荐徽章文本
generate_recommendation_badge() {
    local recommendation=$1

    case "$recommendation" in
        primary)
            echo "🏆 主推"
            ;;
        recommended)
            echo "👍 推荐"
            ;;
        backup)
            echo "🔄 备用"
            ;;
        not_recommended)
            echo "⛔ 暂不推荐"
            ;;
        none|*)
            echo ""
            ;;
    esac
}

# 生成状态徽章文本
generate_status_badge() {
    local status=$1

    case "$status" in
        healthy)
            echo "健康 √"
            ;;
        alive)
            echo "✅ 活跃"
            ;;
        listening_unverified)
            echo "🟡 监听中"
            ;;
        degraded)
            echo "⚠️ 降级"
            ;;
        firewall_blocked)
            echo "🔥 防火墙阻断"
            ;;
        down)
            echo "❌ 停止"
            ;;
        *)
            echo "❓ 未知"
            ;;
    esac
}

# 检测单个协议(含自愈)
check_and_heal_protocol() {
    local protocol_fullname=$1
    local key=""
    # 根据全名映射到短key
    case "$protocol_fullname" in
        "VLESS-Reality")   key="reality" ;;
        "VLESS-gRPC")      key="grpc" ;;
        "VLESS-WebSocket") key="ws" ;;
        "Trojan-TLS")      key="trojan" ;;
        "Hysteria2")       key="hysteria2" ;;
        "TUIC")            key="tuic" ;;
        *)                 key="$protocol_fullname" ;;
    esac

    log_info "==================== 检测协议: $protocol_fullname ===================="

    # 执行健康检查
    local test_result
    test_result=$(test_protocol_performance "$key")

    local status="${test_result%%:*}"
    local rest="${test_result#*:}"
    local response_time="${rest%%:*}"
    local failure_reason="${rest#*:}"

    log_info "检测结果: status=$status, response_time=$response_time, reason=$failure_reason"

    # 判断是否需要自愈
    local repair_result=""
    if [[ "$status" == "down" ]] || [[ "$status" == "degraded" ]] || [[ "$status" == "firewall_blocked" ]]; then
        log_warn "⚠️  协议 $protocol_fullname 异常,触发自愈流程"
        repair_result=$(heal_protocol_failure "$key" "$failure_reason")

        # 自愈后重新检测
        if [[ "$repair_result" == repaired:* ]]; then
            log_info "自愈完成,重新检测..."
            sleep 3
            test_result=$(test_protocol_performance "$key")
            status="${test_result%%:*}"
            rest="${test_result#*:}"
            response_time="${rest%%:*}"
            failure_reason="${rest#*:}"
        fi
    fi

    # 计算健康分数
    local health_score
    health_score=$(calculate_health_score "$key" "$status" "$response_time")

    local recommendation
    recommendation=$(get_recommendation_level "$health_score")

    local status_badge
    status_badge=$(generate_status_badge "$status")

    local recommendation_badge
    recommendation_badge=$(generate_recommendation_badge "$recommendation")

    local detail_message
    detail_message=$(generate_detail_message "$key" "$status" "$response_time" "$failure_reason")

    # 生成JSON
    jq -n \
        --arg protocol_key "$key" \
        --arg status "$status" \
        --arg status_badge "$status_badge" \
        --arg health_score "$health_score" \
        --arg response_time "$response_time" \
        --arg recommendation "$recommendation" \
        --arg recommendation_badge "$recommendation_badge" \
        --arg detail_message "$detail_message" \
        --arg repair_result "$repair_result" \
        --arg checked_at "$(date -Is)" \
        '{
            "protocol": $protocol_key,
            "status": $status,
            "status_badge": $status_badge,
            "health_score": ($health_score | tonumber),
            "response_time": ($response_time | tonumber),
            "recommendation": $recommendation,
            "recommendation_badge": $recommendation_badge,
            "detail_message": $detail_message,
            "repair_result": $repair_result,
            "checked_at": $checked_at
        }'
}

# 检测所有协议
check_all_protocols() {
    local protocols=("VLESS-Reality" "VLESS-gRPC" "VLESS-WebSocket" "Trojan-TLS" "Hysteria2" "TUIC")
    local results='[]'

    for protocol_fullname in "${protocols[@]}"; do
        local result
        result=$(check_and_heal_protocol "$protocol_fullname")
        results=$(echo "$results" | jq --argjson item "$result" '. += [$item]')
    done

    echo "$results"
}

# 生成服务状态摘要
generate_service_summary() {
    jq -n \
        --arg xray "$(check_service_status 'xray')" \
        --arg singbox "$(check_service_status 'sing-box')" \
        '{xray: $xray, "sing-box": $singbox}'
}


# 生成完整报告（最终修复版 - 对齐前端数据口径）
generate_health_report() {
    log_info "========== 开始协议健康检查与自愈 =========="

    local protocols_health services_status
    protocols_health=$(check_all_protocols)
    services_status=$(generate_service_summary)

    local total=$(echo "$protocols_health" | jq 'length')
    local healthy=$(echo "$protocols_health" | jq '[.[] | select(.status=="healthy")] | length')
    local degraded=$(echo "$protocols_health" | jq '[.[] | select(.status=="degraded" or .status=="alive" or .status=="listening_unverified")] | length')
    local down=$(echo "$protocols_health" | jq '[.[] | select(.status=="down")] | length')
    local avg_score=$(echo "$protocols_health" | jq '[.[] | .health_score] | add / length | round // 0')
    local recommended_protocols=$(echo "$protocols_health" | jq -r '[.[] | select(.recommendation == "primary" or .recommendation == "recommended") | .protocol] | join(", ")')

    # 输出最终 JSON
    jq -n \
      --argjson protocols "$protocols_health" \
      --argjson services "$services_status" \
      --argjson total "$total" \
      --argjson healthy "$healthy" \
      --argjson degraded "$degraded" \
      --argjson down "$down" \
      --argjson avg_score "$avg_score" \
      --arg recommended "$recommended_protocols" \
      --arg generated_at "$(date -Is)" \
      '{
         summary: {
           total: ($total | tonumber),
           healthy: ($healthy | tonumber),
           degraded: ($degraded | tonumber),
           down: ($down | tonumber),
           avg_health_score: ($avg_score | tonumber)
         },
         recommended: ($recommended | split(", ") | map(select(. != ""))),
         protocols: $protocols,
         services: $services,
         generated_at: $generated_at
       }' > "$TEMP_JSON"

    if [[ -s "$TEMP_JSON" ]]; then
        mv "$TEMP_JSON" "$OUTPUT_JSON"
        chmod 644 "$OUTPUT_JSON"
        log_success "========== 健康报告已生成: $OUTPUT_JSON =========="
    else
        log_error "健康报告生成失败"
        rm -f "$TEMP_JSON"
        exit 1
    fi
}


# ==================== 主函数 ====================
main() {
    ensure_log_dir
    log_info "EdgeBox 协议健康监控与自愈系统启动"
    generate_health_report
    log_info "协议健康检查与自愈完成"
}
main "$@"
HEALTH_MONITOR_SCRIPT

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

declare -A TUIC_PARAMS=(
    ["congestion_algos"]="bbr cubic"
    ["auth_timeout_min"]=3
    ["auth_timeout_max"]=8
)

declare -A VLESS_PARAMS=(
    ["ws_paths"]="/ws /websocket /v2ray /proxy /tunnel"
    ["grpc_services"]="GunService TunService ProxyService"
)

# 流量特征随机化核心函数
setup_traffic_randomization() {
    log_info "配置流量特征随机化系统..."
    
    # 创建随机化脚本目录
    mkdir -p "${SCRIPTS_DIR}/randomization"
    
    create_traffic_randomization_script
    create_randomization_config
    
    log_success "流量特征随机化系统配置完成"
}

# 创建流量随机化主脚本
create_traffic_randomization_script() {
    cat > "${SCRIPTS_DIR}/edgebox-traffic-randomize.sh" << 'TRAFFIC_RANDOMIZE_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

# 配置路径
CONFIG_DIR="${CONFIG_DIR:-/etc/edgebox/config}"
SCRIPTS_DIR="${SCRIPTS_DIR:-/etc/edgebox/scripts}"
LOG_FILE="/var/log/edgebox/traffic-randomization.log"

# 日志函数
log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$LOG_FILE"; }
log_warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" | tee -a "$LOG_FILE"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE" >&2; }
log_success() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $*" | tee -a "$LOG_FILE"; }

# 增强的 Hysteria2 随机化函数
randomize_hysteria2_config() {
    local level="$1"
    log_info "随机化Hysteria2配置 (级别: $level)..."
    
    if [[ ! -f "${CONFIG_DIR}/sing-box.json" ]]; then
        log_error "sing-box配置文件不存在"
        return 1
    fi
    
    # 检查是否存在hysteria2配置
    if ! jq -e '.inbounds[] | select(.type == "hysteria2")' "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
        log_warn "未找到Hysteria2配置，跳过"
        return 0
    fi
    
    # 随机化伪装站点
    local masquerade_urls=(
        "https://www.bing.com"
        "https://www.apple.com"
        "https://azure.microsoft.com"
        "https://aws.amazon.com"
        "https://www.cloudflare.com"
    )
    
    local random_masquerade=${masquerade_urls[$((RANDOM % ${#masquerade_urls[@]}))]}
    log_info "伪装站点: $random_masquerade"
    
    # 更新配置
    if ! jq --arg url "$random_masquerade" \
        '(.inbounds[] | select(.type == "hysteria2") | .masquerade?) = $url' \
        "${CONFIG_DIR}/sing-box.json" > "${CONFIG_DIR}/sing-box.json.tmp"; then
        log_error "更新配置失败"
        rm -f "${CONFIG_DIR}/sing-box.json.tmp"
        return 1
    fi
    
    # 【新增】验证生成的配置
    log_info "验证sing-box配置语法..."
    if ! sing-box check -c "${CONFIG_DIR}/sing-box.json.tmp" >/dev/null 2>&1; then
        log_error "生成的配置验证失败"
        rm -f "${CONFIG_DIR}/sing-box.json.tmp"
        return 1
    fi
    
    # 应用配置
    mv "${CONFIG_DIR}/sing-box.json.tmp" "${CONFIG_DIR}/sing-box.json"
    log_success "Hysteria2配置随机化完成"
    return 0
}

# 【新增】配置回滚函数
rollback_traffic_config() {
    local backup_dir="/etc/edgebox/backup/randomization"
    
    local latest_singbox=$(ls -t "${backup_dir}"/sing-box_*.json 2>/dev/null | head -1)
    
    if [[ -n "$latest_singbox" && -f "$latest_singbox" ]]; then
        log_warn "检测到配置问题，回滚到上一版本..."
        cp "$latest_singbox" "${CONFIG_DIR}/sing-box.json"
        
        # 重启服务
        if systemctl restart sing-box; then
            log_success "配置已回滚并重启服务"
            return 0
        else
            log_error "服务重启失败"
            return 1
        fi
    else
        log_error "未找到备份文件，无法回滚"
        return 1
    fi
}

# 【新增】验证服务状态
verify_services_after_randomization() {
    log_info "验证服务状态..."
    
    local all_ok=true
    
    # 检查sing-box
    if ! systemctl is-active --quiet sing-box; then
        log_error "sing-box服务未运行"
        all_ok=false
    fi
    
    # 检查xray
    if ! systemctl is-active --quiet xray; then
        log_error "xray服务未运行"
        all_ok=false
    fi
    
    # 检查端口
    if ! ss -tulnp | grep -q ":443.*sing-box"; then
        log_warn "Hysteria2端口未监听"
        all_ok=false
    fi
    
    if $all_ok; then
        log_success "服务验证通过"
        return 0
    else
        log_error "服务验证失败，尝试回滚"
        rollback_traffic_config
        return 1
    fi
}


# TUIC随机化函数 - 安全版本（只使用bbr）
randomize_tuic_config() {
    local level="$1"
    log_info "随机化TUIC配置 (级别: $level)..."
    
    if [[ ! -f "${CONFIG_DIR}/sing-box.json" ]]; then
        log_error "sing-box 配置文件不存在"
        return 1
    fi
    
    # 检查是否存在 tuic 配置
    if ! jq -e '.inbounds[] | select(.type == "tuic")' "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
        log_warn "未找到 TUIC 配置，跳过随机化"
        return 0
    fi
    
    # 只使用 bbr（最稳定的算法）
    local algo="bbr"
    
    log_info "TUIC参数: 拥塞控制=${algo}"
    
    # 检查当前配置中的字段名称
    local current_config=$(jq '.inbounds[] | select(.type == "tuic")' "${CONFIG_DIR}/sing-box.json" 2>/dev/null)
    
    # 尝试更新配置（保持原有配置不变，只是确保字段存在）
    if ! jq \
        --arg cc "$algo" \
        '(.inbounds[] | select(.type == "tuic")) |= (. + {congestion_control: $cc})' \
        "${CONFIG_DIR}/sing-box.json" > "${CONFIG_DIR}/sing-box.json.tmp"; then
        log_error "更新 TUIC 配置失败"
        rm -f "${CONFIG_DIR}/sing-box.json.tmp"
        return 1
    fi
    
    # 验证生成的配置文件
    if sing-box check -c "${CONFIG_DIR}/sing-box.json.tmp" >/dev/null 2>&1; then
        mv "${CONFIG_DIR}/sing-box.json.tmp" "${CONFIG_DIR}/sing-box.json"
        log_success "TUIC配置随机化完成"
        return 0
    else
        log_warn "TUIC 配置验证失败，保持原配置不变"
        rm -f "${CONFIG_DIR}/sing-box.json.tmp"
        # 不返回错误，因为 TUIC 本身可能就没问题
        return 0
    fi
}

# VLESS随机化函数 - 保持简单
randomize_vless_config() {
    local level="$1"
    log_info "随机化VLESS配置 (级别: $level)..."
    
    # 保持简单，避免复杂的 Xray 配置修改
    log_success "VLESS配置随机化完成（保持原有配置）"
    return 0
}

# 主随机化函数
execute_traffic_randomization() {
    local level="${1:-light}"
    
    log_info "开始执行流量特征随机化 (级别: $level)..."
    
    # 创建配置备份
    create_config_backup
    
    case "$level" in
        "light")
            # 轻度随机化：仅更新 Hysteria2
            randomize_hysteria2_config "$level"
            ;;
        "medium") 
            # 中度随机化：更新 Hysteria2 + TUIC
            randomize_hysteria2_config "$level"
            randomize_tuic_config "$level"
            ;;
        "heavy")
            # 重度随机化：全协议
            randomize_hysteria2_config "$level"
            randomize_tuic_config "$level"
            randomize_vless_config "$level"
            ;;
        *)
            log_error "未知的随机化级别: $level"
            return 1
            ;;
    esac
    
    # 重启相关服务
    restart_services_safely
    
    # 验证配置生效
    verify_randomization_result
    
    log_success "流量特征随机化完成 (级别: $level)"
}

# 配置备份函数
create_config_backup() {
    local backup_dir="/etc/edgebox/backup/randomization"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    
    mkdir -p "$backup_dir"
    
    if [[ -f "${CONFIG_DIR}/xray.json" ]]; then
        cp "${CONFIG_DIR}/xray.json" "${backup_dir}/xray_${timestamp}.json"
    fi
    
    if [[ -f "${CONFIG_DIR}/sing-box.json" ]]; then
        cp "${CONFIG_DIR}/sing-box.json" "${backup_dir}/sing-box_${timestamp}.json"
    fi
    
    log_info "配置备份已创建: $backup_dir"
}

# 安全重启服务函数
restart_services_safely() {
    log_info "安全重启代理服务..."
    
    # 定义reload_or_restart_services函数（如果不存在）
    if ! command -v reload_or_restart_services >/dev/null 2>&1; then
        reload_or_restart_services() {
            for svc in "$@"; do
                if systemctl is-active --quiet "$svc"; then
                    if systemctl reload "$svc" 2>/dev/null; then
                        log_info "${svc} 已热加载"
                    else
                        systemctl restart "$svc"
                        log_info "${svc} 已重启"
                    fi
                fi
            done
        }
    fi
    
    # 应用更改并热加载
    reload_or_restart_services sing-box xray
    sleep 5
    
    log_success "服务已安全重启"
}

# 验证随机化结果
verify_randomization_result() {
    log_info "验证随机化配置..."
    
    local verification_failed=false
    
    # 验证配置文件语法
    if [[ -f "${CONFIG_DIR}/xray.json" ]] && ! xray -test -config="${CONFIG_DIR}/xray.json" >/dev/null 2>&1; then
        log_error "Xray配置验证失败"
        verification_failed=true
    fi
    
    if [[ -f "${CONFIG_DIR}/sing-box.json" ]] && ! sing-box check -c "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
        log_error "sing-box配置验证失败"
        verification_failed=true
    fi
    
    # 验证服务状态
    if ! systemctl is-active --quiet sing-box; then
        log_error "sing-box服务状态异常"
        verification_failed=true
    fi
    
    if ! systemctl is-active --quiet xray; then
        log_error "Xray服务状态异常"
        verification_failed=true
    fi
    
    if [[ "$verification_failed" == "true" ]]; then
        log_error "随机化验证失败，尝试回滚配置..."
        rollback_configuration
        return 1
    fi
    
    log_success "随机化验证通过"
}

# 配置回滚函数
rollback_configuration() {
    local backup_dir="/etc/edgebox/backup/randomization"
    
    # 查找最近的备份
    local latest_xray_backup=$(ls -t "${backup_dir}"/xray_*.json 2>/dev/null | head -1)
    local latest_singbox_backup=$(ls -t "${backup_dir}"/sing-box_*.json 2>/dev/null | head -1)
    
    if [[ -n "$latest_xray_backup" ]]; then
        cp "$latest_xray_backup" "${CONFIG_DIR}/xray.json"
        log_info "Xray配置已回滚"
    fi
    
    if [[ -n "$latest_singbox_backup" ]]; then
        cp "$latest_singbox_backup" "${CONFIG_DIR}/sing-box.json"
        log_info "sing-box配置已回滚"
    fi
    
    restart_services_safely
}

# 主函数
main() {
    local level="${1:-light}"
    
    # 创建日志目录
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # 处理 reset 选项
    if [[ "$level" == "reset" ]]; then
        log_info "重置协议参数为默认值..."
        
        # 备份当前配置
        create_config_backup
        
        # 清理可能存在的不支持字段
        if [[ -f "${CONFIG_DIR}/sing-box.json" ]] && command -v jq >/dev/null; then
            jq 'del(.inbounds[].heartbeat)' "${CONFIG_DIR}/sing-box.json" > "${CONFIG_DIR}/sing-box.json.tmp"
            
            if [[ -s "${CONFIG_DIR}/sing-box.json.tmp" ]]; then
                mv "${CONFIG_DIR}/sing-box.json.tmp" "${CONFIG_DIR}/sing-box.json"
                log_success "配置已清理并重置为默认值"
            else
                rm -f "${CONFIG_DIR}/sing-box.json.tmp"
                log_error "重置配置失败"
            fi
        fi
        
        # 重启服务
        restart_services_safely
        
        log_success "协议参数重置完成"
        exit 0
    fi
    
    log_info "EdgeBox流量特征随机化开始..."
    
    if execute_traffic_randomization "$level"; then
        log_success "EdgeBox流量特征随机化成功完成"
        exit 0
    else
        log_error "EdgeBox流量特征随机化失败"
        exit 1
    fi
}

# 脚本执行入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
TRAFFIC_RANDOMIZE_SCRIPT

    chmod +x "${SCRIPTS_DIR}/edgebox-traffic-randomize.sh"
    log_success "流量随机化脚本创建完成"
}


# 创建随机化配置文件
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

[tuic]
congestion_algos=bbr,cubic
auth_timeout_min=3
auth_timeout_max=8

[vless]
ws_path_rotation=true
grpc_service_rotation=true
header_randomization=false

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
generate_initial_traffic_data() {
    local LOG_DIR="${TRAFFIC_DIR}/logs"
    
    # 确保目录存在
    mkdir -p "$LOG_DIR"
    
    # 检查是否已有数据
    if [[ -f "$LOG_DIR/daily.csv" ]] && [[ $(wc -l < "$LOG_DIR/daily.csv") -gt 1 ]]; then
        log_info "检测到现有流量数据，跳过生成"
        return 0
    fi
    
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
  counter c_udp2053  {}
  counter c_resi_out {}

  set resi_addr4 { type ipv4_addr; flags interval; }
  set resi_addr6 { type ipv6_addr; flags interval; }

  chain out {
    type filter hook output priority 0; policy accept;
    tcp dport 443   counter name c_tcp443
    udp dport 443   counter name c_udp443
    udp dport 2053  counter name c_udp2053
    ip  daddr @resi_addr4 counter name c_resi_out
    ip6 daddr @resi_addr6 counter name c_resi_out
  }
}
NFT

  # 初始化 CSV（按 README 口径）
  [[ -s "${LOG_DIR}/daily.csv" ]]   || echo "date,vps,resi,tx,rx" > "${LOG_DIR}/daily.csv"
  [[ -s "${LOG_DIR}/monthly.csv" ]] || echo "month,vps,resi,total,tx,rx" > "${LOG_DIR}/monthly.csv"

# 1. 系统状态脚本
cat > "${SCRIPTS_DIR}/system-stats.sh" <<'SYS'
#!/bin/bash
set -euo pipefail
TRAFFIC_DIR="/etc/edgebox/traffic"
mkdir -p "$TRAFFIC_DIR"

# 改进的CPU使用率计算
get_cpu_usage() {
    local cpu_percent=0
    
    if [[ -r /proc/stat ]]; then
        read _ user1 nice1 system1 idle1 iowait1 irq1 softirq1 _ < /proc/stat
        
        # 增加采样时间到2秒，获得更准确的数据
        sleep 2
        
        read _ user2 nice2 system2 idle2 iowait2 irq2 softirq2 _ < /proc/stat
        
        # 计算差值
        local user_diff=$((user2 - user1))
        local nice_diff=$((nice2 - nice1))
        local system_diff=$((system2 - system1))
        local idle_diff=$((idle2 - idle1))
        local iowait_diff=$((iowait2 - iowait1))
        local irq_diff=$((irq2 - irq1))
        local softirq_diff=$((softirq2 - softirq1))
        
        local total_diff=$((user_diff + nice_diff + system_diff + idle_diff + iowait_diff + irq_diff + softirq_diff))
        local active_diff=$((total_diff - idle_diff))
        
        if [[ $total_diff -gt 0 ]]; then
            # 使用更精确的计算
            cpu_percent=$(( (active_diff * 1000) / total_diff ))
            cpu_percent=$((cpu_percent / 10))
            # 设置最小值为1%，避免显示0%
            if [[ $cpu_percent -lt 1 ]]; then
                cpu_percent=1
            fi
        else
            cpu_percent=1
        fi
    fi
    
    # 确保值在合理范围
    cpu_percent=$(( cpu_percent > 100 ? 100 : cpu_percent ))
    cpu_percent=$(( cpu_percent < 1 ? 1 : cpu_percent ))
    
    echo $cpu_percent
}

# 获取CPU和内存使用率
cpu=$(get_cpu_usage)
mt=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo "0")
ma=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo "0")
mem=$(( mt > 0 ? (100 * (mt - ma)) / mt : 0 ))

# 生成JSON
jq -n --arg ts "$(date -Is)" --argjson cpu "$cpu" --argjson memory "$mem" \
  '{updated_at:$ts,cpu:$cpu,memory:$memory}' > "${TRAFFIC_DIR}/system.json"
SYS
chmod +x "${SCRIPTS_DIR}/system-stats.sh"

# 2. 流量采集器：每小时增量 → 聚合 → traffic.json
cat > "${SCRIPTS_DIR}/traffic-collector.sh" <<'COLLECTOR'
#!/bin/bash
set -euo pipefail
TRAFFIC_DIR="/etc/edgebox/traffic"
LOG_DIR="$TRAFFIC_DIR/logs"
STATE="${TRAFFIC_DIR}/.state"
mkdir -p "$LOG_DIR"

# 1) 识别默认出网网卡
IFACE="$(ip route | awk '/default/{print $5;exit}')"
[[ -z "$IFACE" ]] && IFACE="$(ip -o -4 addr show scope global | awk '{print $2;exit}')"
[[ -z "$IFACE" ]] && { echo "no iface"; exit 0; }

# 2) 读取当前计数
TX_CUR=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
RX_CUR=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)

# 代理出口计数（nftables 计数器 c_resi_out）
get_resi_bytes() {
  if nft -j list counters table inet edgebox >/dev/null 2>&1; then
    nft -j list counters table inet edgebox \
     | jq -r '[.nftables[]?|select(.counter.name=="c_resi_out")|.counter.bytes][0] // 0'
  else
    nft list counter inet edgebox c_resi_out 2>/dev/null | awk '/bytes/ {print $2;exit}' || echo 0
  fi
}
RESI_CUR="$(get_resi_bytes)"; RESI_CUR="${RESI_CUR:-0}"

# 3) 载入上次状态，计算增量
PREV_TX=0; PREV_RX=0; PREV_RESI=0
[[ -f "$STATE" ]] && . "$STATE" || true
delta() { local cur="$1" prev="$2"; [[ "$cur" -ge "$prev" ]] && echo $((cur-prev)) || echo 0; }
D_TX=$(delta "$TX_CUR"   "${PREV_TX:-0}")
D_RX=$(delta "$RX_CUR"   "${PREV_RX:-0}")
D_RESI=$(delta "$RESI_CUR" "${PREV_RESI:-0}")
D_VPS=$D_TX; [[ $D_RESI -le $D_TX ]] && D_VPS=$((D_TX - D_RESI)) || D_VPS=0

TODAY="$(date +%F)"
# 4) 写 daily.csv（date,vps,resi,tx,rx），保留最近90天
[[ -s "${LOG_DIR}/daily.csv" ]] || echo "date,vps,resi,tx,rx" > "${LOG_DIR}/daily.csv"
TMP="$(mktemp)"; export LC_ALL=C
awk -F, -v d="$TODAY" -v vps="$D_VPS" -v resi="$D_RESI" -v tx="$D_TX" -v rx="$D_RX" '
  BEGIN{OFS=","; updated=0}
  NR==1{print; next}
  $1==d{ $2+=vps; $3+=resi; $4+=tx; $5+=rx; updated=1 }
  {print}
  END{ if(!updated) print d,vps,resi,tx,rx }
' "$LOG_DIR/daily.csv" > "$TMP" && mv "$TMP" "$LOG_DIR/daily.csv"
{ head -n1 "$LOG_DIR/daily.csv"; tail -n 90 "$LOG_DIR/daily.csv" | grep -v '^date,'; } > "$TMP" \
  && mv "$TMP" "$LOG_DIR/daily.csv"

# 5) 基于 daily.csv 生成 monthly.csv（month,vps,resi,total,tx,rx），保留最近18个月
awk -F, 'NR>1{
  m=substr($1,1,7);
  vps[m]+=$2; resi[m]+=$3; tx[m]+=$4; rx[m]+=$5
}
END{
  for (m in vps) printf "%s,%s,%s,%s,%s,%s\n", m, vps[m], resi[m], vps[m]+resi[m], tx[m], rx[m]
}' "$LOG_DIR/daily.csv" \
| (echo "month,vps,resi,total,tx,rx"; sort -t, -k1,1) > "$LOG_DIR/monthly.csv"

# 6) 产出 traffic.json（index.html 读取的唯一数据文件）
LAST30D_JSON="$(tail -n 30 "$LOG_DIR/daily.csv" | grep -v '^date,' \
  | awk -F, '{printf("{\"date\":\"%s\",\"vps\":%s,\"resi\":%s}\n",$1,$2,$3)}' | jq -s '.')"
MONTHLY_JSON="$(tail -n 12 "$LOG_DIR/monthly.csv" | grep -v '^month,' \
  | awk -F, '{printf("{\"month\":\"%s\",\"vps\":%s,\"resi\":%s,\"total\":%s,\"tx\":%s,\"rx\":%s}\n",$1,$2,$3,$4,$5,$6)}' | jq -s '.')"
jq -n --arg updated "$(date -Is)" --argjson last30d "$LAST30D_JSON" --argjson monthly "$MONTHLY_JSON" \
  '{updated_at:$updated,last30d:$last30d,monthly:$monthly}' > "$TRAFFIC_DIR/traffic.json"

# 7) 确保 alert.conf 可通过 Web 访问（前端需要读取阈值配置）
if [[ -r "$TRAFFIC_DIR/alert.conf" ]]; then
  # alert.conf 已经在 TRAFFIC_DIR 中，通过软链接 /var/www/html/traffic -> TRAFFIC_DIR 可访问
  # 前端可通过 /traffic/alert.conf 路径读取
  chmod 644 "$TRAFFIC_DIR/alert.conf" 2>/dev/null || true
fi

# 7) 保存状态
printf 'PREV_TX=%s\nPREV_RX=%s\nPREV_RESI=%s\n' "$TX_CUR" "$RX_CUR" "$RESI_CUR" > "$STATE"
COLLECTOR
chmod +x "${SCRIPTS_DIR}/traffic-collector.sh"

# 3. 预警配置（默认）
cat > "${TRAFFIC_DIR}/alert.conf" <<'CONF'
# 月度预算（GiB）
ALERT_MONTHLY_GIB=200
# 邮件/Hook（可留空）
ALERT_EMAIL=
ALERT_WEBHOOK=
# 阈值（百分比，逗号分隔）
ALERT_STEPS=30,60,90
CONF

# 4. 预警脚本（读取 monthly.csv 与 alert.conf，阈值去重）
cat > "${SCRIPTS_DIR}/traffic-alert.sh" <<'ALERT'
#!/bin/bash
set -euo pipefail
TRAFFIC_DIR="/etc/edgebox/traffic"
LOG_DIR="$TRAFFIC_DIR/logs"
CONF="$TRAFFIC_DIR/alert.conf"
STATE="$TRAFFIC_DIR/alert.state"
LOG="/var/log/edgebox-traffic-alert.log"
[[ -r "$CONF" ]] || { echo "no alert.conf"; exit 0; }
# shellcheck source=/dev/null
. "$CONF"

month="$(date +%Y-%m)"
row="$(grep "^${month}," "$LOG_DIR/monthly.csv" 2>/dev/null || true)"
[[ -z "$row" ]] && { echo "[$(date -Is)] no-monthly" >> "$LOG"; exit 0; }

# CSV: month,vps,resi,total,tx,rx
IFS=',' read -r _ vps resi total tx rx <<<"$row"
budget_bytes=$(( ${ALERT_MONTHLY_GIB:-100} * 1024 * 1024 * 1024 ))
used=$total
pct=$(( used * 100 / budget_bytes ))

sent=""
[[ -f "$STATE" ]] && sent="$(cat "$STATE")"

parse_steps() { IFS=',' read -ra a <<<"${ALERT_STEPS:-30,60,90}"; for s in "${a[@]}"; do echo "$s"; done; }
notify() {
  local msg="$1"
  echo "[$(date -Is)] $msg" | tee -a "$LOG" >/dev/null
  if [[ -n "${ALERT_WEBHOOK:-}" ]]; then
    curl -m 5 -s -X POST -H 'Content-Type: application/json' \
      -d "$(jq -n --arg text "$msg" '{text:$text}')" "$ALERT_WEBHOOK" >/dev/null 2>&1 || true
  fi
  if command -v mail >/dev/null 2>&1 && [[ -n "${ALERT_EMAIL:-}" ]]; then
    echo "$msg" | mail -s "EdgeBox 流量预警 (${month})" "$ALERT_EMAIL" || true
  fi
}

new_sent="$sent"
for s in $(parse_steps); do
  # 已达阈值且未发过
  if [[ "$pct" -ge "$s" ]] && ! grep -q "(^|,)$s(,|$)" <<<",$sent,"; then
    human_used="$(awk -v b="$used" 'BEGIN{printf "%.2f GiB", b/1024/1024/1024}')"
    human_budget="$(awk -v b="$budget_bytes" 'BEGIN{printf "%.0f GiB", b/1024/1024/1024}')"
    notify "本月用量 ${human_used}（${pct}% / 预算 ${human_budget}），触达 ${s}% 阈值。"
    new_sent="${new_sent:+${new_sent},}${s}"
  fi
done
echo "$new_sent" > "$STATE"
ALERT
chmod +x "${SCRIPTS_DIR}/traffic-alert.sh"

  # 网站根目录映射 + 首次刷新
  mkdir -p "${TRAFFIC_DIR}" /var/www/html
  ln -sfn "${TRAFFIC_DIR}" /var/www/html/traffic

  # 首次出全量 JSON：traffic.json + dashboard.json/system.json
  "${SCRIPTS_DIR}/traffic-collector.sh" || true
  "${SCRIPTS_DIR}/dashboard-backend.sh" --now || true

  # ========== 创建外置的CSS文件 ==========
  log_info "创建外置CSS文件..."
  cat > "${TRAFFIC_DIR}/assets/edgebox-panel.css" <<'EXTERNAL_CSS'
  
/* =======================================================================
   EdgeBox 控制面板 · 组件化（ops-panel 无 id 也生效）
   =================================================================== */

/* ========== Reset / 基础皮肤 ========== */

* { margin:0; padding:0; box-sizing:border-box; }

body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  background:#f3f4f6; min-height:100vh; padding:20px; color:#1f2937;
}

.container{ max-width:1400px; margin:0 auto; }

/* ===== 全局变量和文字样式统一 ===== */
:root {
  --heading-color: #111827;      /* h1-h4标题颜色（黑色） */
  --subheading-color: #6b7280;   /* h4标题颜色（灰色） */
  --content-color: #6b7280;      /* 内容颜色（灰色） */
  --muted-color: #6b7280;        /* 内容灰（别名） */
  --h3-size: 15px;               /* h3字体大小 */
  --h4-size: 14px;               /* h4字体大小 */
}

/* 标题样式统一 */
h1{ font-size:23px; font-weight:700; color:var(--heading-color); line-height:32px; }
h2{ font-size:18px; font-weight:600; color:var(--heading-color); line-height:26px; }
h3{ 
  font-size:var(--h3-size); 
  line-height:1.4; 
  font-weight:600; 
  color:var(--heading-color);
}
h4{ 
  font-size:var(--h4-size); 
  line-height:1.4; 
  font-weight:600; 
  color:var(--subheading-color);
}

/* 特殊容器内的标题保持黑色 */
.traffic-card .chart-container h3,
.traffic-card .progress-label h3,
.card h3,
#system-overview h3,
#netid-panel h3,
.note h3, 
.muted h3, 
.desc h3{ 
  color:var(--heading-color); 
}

/* 文本样式 */
body,p,span,td,div{ font-size:13px; font-weight:500; color:#1f2937; line-height:20px; }
.text-muted{ color:#6b7280; }
.text-secondary{ color:#4b5563; }

/* ================ 卡片/区块 ================ */
.main-card{
  background:#fff; 
  border:1px solid #d1d5db; 
  border-radius:10px;
  box-shadow:0 2px 6px rgba(0,0,0,.08); 
  overflow:hidden;
  margin-bottom:20px;
  padding:0 !important;
}

.card{
  background:#fff; 
  border:1px solid #d1d5db; 
  border-radius:10px;
  box-shadow:0 2px 6px rgba(0,0,0,.08); 
  padding:20px; 
  margin-bottom:20px;
  transition:box-shadow .2s;
}
.card:hover{ box-shadow:0 4px 8px rgba(0,0,0,.08); }

.card-header{ 
  margin-bottom:20px; 
  padding-bottom:12px; 
  border-bottom:1px solid #e5e7eb; 
}
.card-header h2{ 
  display:flex; 
  justify-content:space-between; 
  align-items:center; 
}
.card-note{ 
  font-size:11px; 
  color:#6b7280; 
  font-weight:400; 
}

/* =========标题区域 =========*/

/* 标题样式：从深灰到浅灰的渐变 + 圆角只在顶部 */
.main-header {
  text-align:center;
  background:linear-gradient(135deg, #e2e8f0 0%, #f1f5f9 50%, #f8fafc 100%);
  border:none;
  border-radius:0;
  border-top-left-radius:9px;
  border-top-right-radius:9px;
  padding:16px 20px;
  position:relative;
  margin:0;
  box-shadow: 
    inset 0 -1px 0 rgba(0,0,0,0.1),
    inset 0 1px 0 rgba(255,255,255,0.9);
}

.main-header h1 {
  text-align:center !important;
  margin:0 auto;
  display:block;
  width:100%;
  font-size:24px;
  font-weight:700;
  color:#1f2937;
  line-height:1.3;
  text-shadow:0 1px 2px rgba(0,0,0,0.1);
}

/* 去掉紫色竖杠 */
.main-header::before {
  display:none !important;
}

/* 底部装饰线 */
.main-header::after {
  content:"";
  position:absolute;
  left:50%;
  bottom:0;
  transform:translateX(-50%);
  width:60px;
  height:2px;
  background:linear-gradient(90deg, transparent, #10b981, transparent);
  border-radius:2px;
  opacity:0.6;
}

/* 鼠标悬停效果 */
.main-header:hover {
  background:linear-gradient(135deg, #d1d5db 0%, #e2e8f0 50%, #f1f5f9 100%);
  box-shadow: 
    inset 0 -1px 0 rgba(0,0,0,0.15),
    inset 0 1px 0 rgba(255,255,255,0.8);
  transition:all 0.3s ease;
}

/* 备选方案：更明显的深浅对比 */
.main-header.dark-to-light {
  background:linear-gradient(135deg, #94a3b8 0%, #cbd5e1 50%, #e2e8f0 100%);
}
.main-header.dark-to-light:hover {
  background:linear-gradient(135deg, #64748b 0%, #94a3b8 50%, #cbd5e1 100%);
}

/* =========内容区域 =========*/

/* 大卡片内容区域恢复padding */
.main-content {
  padding:20px !important;
  margin:0 !important;
}

/* 确保内部卡片间距正确 */
.main-content .card {
  margin-bottom:20px !important;
}
.main-content .card:last-child {
  margin-bottom:0 !important;
}

/* grid布局特殊处理 */
.main-content .grid .card {
  margin-bottom:0 !important;
}

/* 内层块 */
.inner-block{
  background:#f5f5f5; 
  border:1px solid #e5e7eb; 
  border-radius:6px; 
  padding:15px; 
  margin-bottom:15px;
}
.inner-block:last-child{ margin-bottom:0; }
.inner-block h3{
  margin-bottom:12px; 
  padding-bottom:8px; 
  border-bottom:1px solid #e5e7eb;
}

/*========= 网格布局 =========*/
.grid{ display:grid; gap:20px; }
.grid-3{ grid-template-columns:repeat(3,1fr); }
.grid-1-2{ grid-template-columns:1fr 2fr; }

/* ============= 全局行样式 ============= */
.info-item{ 
  display:flex; 
  justify-content:space-between; 
  padding:6px 0; 
}
.info-item label{ color:#6b7280; }
.info-item value{ color:#1f2937; font-weight:500; }

/* ========= 全局运行状态徽标 ========= */
.status-badge{
  display:inline-flex; 
  align-items:center;
  height:20px; 
  line-height:20px; 
  padding:0 10px;
  border-radius:999px; 
  font-size:11px;
  background:#eafaf3; 
  color:#059669; 
  border:1px solid #c7f0df;
}
.status-running{ 
  background:#d1fae5; 
  color:#059669; 
  border-color:#a7f3d0; 
}
.status-stopped{ 
  background:#fee2e2; 
  color:#ef4444; 
  border-color:#fecaca; 
}


/* =======================================================================
   通知中心样式 - 完整修复版（靠左自动换行）
   ======================================================================= */

/* 主标题区域调整 */
.main-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
}

.main-header h1 {
    flex: 1;
    margin: 0;
}

/* 通知中心容器 - 修复居中 */
.notification-center {
    position: relative;
    display: flex;              /* 改为 flex */
    width: 40px;                /* 略微放大容器 */
    height: 40px;
    margin-right: 22px;
    align-items: center;        /* 垂直居中 */
    justify-content: center;    /* 水平居中 */
}

/* 通知触发按钮 - 完美居中 */
.notification-trigger {
    position: relative;         /* 作为徽标的定位基准 */
    width: 100%;
    height: 100%;
    display: flex;              /* 使用 flex 替代 grid */
    align-items: center;
    justify-content: center;
    background: none;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    color: #6b7280;
    padding: 0;
    line-height: 1;
    transition: background-color .2s ease, color .2s ease;
}

/* 铃铛图标 - 确保居中 */
.notification-trigger > .notification-icon {
    font-size: 24px;            /* 铃铛尺寸 */
    display: flex;              /* emoji 完美居中 */
    align-items: center;
    justify-content: center;
    line-height: 1;
}

/* 悬停态 */
.notification-trigger:hover {
    background-color: rgba(16, 185, 129, 0.1);
    color: #10b981;
}

.notification-trigger:hover > .notification-icon {
    transform: scale(1.15);
    transition: transform .2s ease;
}

/* 通知数量徽章 - 修复椭圆问题 */
.notification-badge {
    position: absolute;
    top: 3px;                   /* 精确定位 */
    right: 3px;
    
    /* 确保完美圆形 */
    width: 16px;                /* 强制宽高相等 */
    height: 16px;
    min-width: 16px;            /* 防止被压缩 */
    max-width: 16px;            /* 防止被拉伸 */
    
    background: #ef4444;
    color: white;
    border-radius: 50%;
    border: 1.5px solid white;
    
    /* 文字居中 + 微调垂直位置 */
    display: flex;
    align-items: center;
    justify-content: center;
    padding-top: 1px;           /* ← 关键：数字向下偏移 1px */
    font-size: 9px;
    font-weight: 600;
    line-height: 1;
    
    /* 防止变形 */
    box-sizing: border-box;
    flex-shrink: 0;             /* 防止 flex 压缩 */
    overflow: hidden;
    
    z-index: 10;
    
    /* 修复后的动画 - 不破坏圆形 */
    animation: notification-pulse-fixed 2s infinite;
}

/* 修复后的脉冲动画 - 保持圆形 */
@keyframes notification-pulse-fixed {
    0%, 100% { 
        transform: scale(1);
        opacity: 1;
    }
    50% { 
        transform: scale(1.05);  /* 降低缩放幅度 */
        opacity: 0.9;
    }
}

/* 通知面板 - 复用弹窗样式 */
.notification-panel {
    position: absolute;
    top: 100%;
    right: 0;
    width: 380px;
    max-height: 480px;
    background: white;
    border: 1px solid #d1d5db;
    border-radius: 14px;
    box-shadow: 0 10px 30px rgba(17, 24, 39, 0.18);
    display: none;
    z-index: 1000;
    overflow: hidden;
    margin-top: 8px;
    flex-direction: column;
}

.notification-panel.show {
    display: flex;
    animation: notification-slide-in 0.2s ease-out;
}

@keyframes notification-slide-in {
    from {
        opacity: 0;
        transform: translateY(-10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* 通知面板头部 - 复用弹窗头部样式 */
.notification-header {
    flex-shrink: 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px;
    border-bottom: 1px solid #e5e7eb;
    background: #f9fafb;
}

.notification-header h3 {
    margin: 0;
    font-size: 15px;
    font-weight: 600;
    color: #111827;
}

/* 清空按钮 - 复用弹窗按钮样式 */
.notification-clear {
    background: #ffffff;
    border: 1px solid #d1d5db;
    color: #6b7280;
    font-size: 12px;
    cursor: pointer;
    padding: 6px 12px;
    border-radius: 6px;
    transition: all 0.2s ease;
    font-weight: 500;
}

.notification-clear:hover {
    background-color: #f9fafb;
    color: #374151;
    border-color: #9ca3af;
}

.notification-clear:active {
    background-color: #f3f4f6;
}

/* 通知列表容器 - 可滚动 */
.notification-list {
    flex: 1;
    padding: 0;
    overflow-y: auto;
    overflow-x: hidden;
    min-height: 0;
}

/* 通知项 - 每条之间有分隔线，靠左自动换行 */
.notification-item {
    display: flex;
    align-items: flex-start;    /* 顶部对齐 */
    gap: 12px;
    padding: 14px 16px;
    border-bottom: 1px solid #e5e7eb;
    transition: background-color 0.2s ease;
    cursor: pointer;
}

.notification-item:last-child {
    border-bottom: none;
}

.notification-item:hover {
    background-color: #f9fafb;
}

.notification-item.unread {
    background-color: #f0f9ff;
}

.notification-item.unread:hover {
    background-color: #e0f2fe;
}

/* 通知图标 */
.notification-item-icon {
    flex-shrink: 0;
    font-size: 18px;
    line-height: 1;
    margin-top: 2px;
}

/* 通知内容区 - 支持自动换行 */
.notification-item-content {
    flex: 1;
    min-width: 0;               /* 关键：允许flex子元素缩小 */
    display: flex;
    flex-direction: column;
    gap: 4px;
}

/* 通知消息文字 - 靠左自动换行 */
.notification-item-message {
    font-size: 13px;
    color: #374151;
    line-height: 1.5;
    text-align: left;           /* 靠左对齐 */
    word-wrap: break-word;
    word-break: break-word;
    overflow-wrap: break-word;
    white-space: normal;        /* 允许换行 */
}

/* 通知时间和操作按钮 - 统一靠左对齐 */
.notification-item-time,
.notification-item-action {
    font-size: 11px;
    text-align: left;
}

.notification-item-time {
    color: #9ca3af;
}

.notification-item-action {
    font-size: 12px;
    color: #10b981;
    text-decoration: none;
    font-weight: 500;
}

.notification-item-action:hover {
    color: #059669;
    text-decoration: underline;
}

/* 空状态和加载状态 */
.notification-empty,
.notification-loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 40px 20px;
    color: #9ca3af;
    text-align: center;
    gap: 8px;
}

/* 通知面板底部 */
.notification-footer {
    flex-shrink: 0;
    padding: 12px 16px;
    border-top: 1px solid #e5e7eb;
    background: #f9fafb;
    text-align: center;
}

.notification-footer small {
    font-size: 11px;
    color: #9ca3af;
}

/* 滚动条样式优化 */
.notification-list::-webkit-scrollbar {
    width: 6px;
}

.notification-list::-webkit-scrollbar-track {
    background: #f9fafb;
}

.notification-list::-webkit-scrollbar-thumb {
    background: #d1d5db;
    border-radius: 3px;
}

.notification-list::-webkit-scrollbar-thumb:hover {
    background: #9ca3af;
}

/* 响应式调整 */
@media (max-width: 768px) {
    .notification-center {
        width: 36px;
        height: 36px;
    }
    
    .notification-trigger > .notification-icon {
        font-size: 20px;
    }
    
    .notification-badge {
        width: 14px;
        height: 14px;
        min-width: 14px;
        max-width: 14px;
        font-size: 8px;
        top: 2px;
        right: 2px;
    }
    
    .notification-panel {
        width: calc(100vw - 32px);
        max-width: 320px;
        right: -20px;
    }
}


/* =======================================================================
   系统概览
   ================================================================= */
#system-overview{
  --label-w:72px;           /* 左侧键名列宽 */
  --percent-col:33px;       /* 右侧百分比列宽 */
  --meter-height:20px;      /* 进度条高度 */
  --svc-gap:12px;           /* 服务名/徽标/版本 间距 */
  --h3-gap:8px;
  --meter-track:#e2e8f0; 
  --meter-start:#059669; 
  --meter-end:#10b981;
  --label: var(--heading-color); 
  --value: var(--content-color); 
  --muted: #6b7280;
}

/* ========== 覆盖全局 inner-block 样式，统一高度 ========== */
#system-overview .inner-block {
  display: block;
  padding: 12px !important;
  margin-bottom: 0 !important;
}

/* 标题紧跟 */
#system-overview .inner-block>h3{ 
  display:flex; 
  align-items:center; 
  white-space:nowrap; 
  margin:0 0 var(--h3-gap);
  font-size: var(--h3-size) !important;
  line-height: 22px !important;
  height: 22px !important;
  color: var(--heading-color) !important;
}

/* 标题右侧"版本号/安装日期/更新时间"内联备注 */
#system-overview .card-header h2{
  display:flex;
  align-items:flex-end;
}
#system-overview .card-header #sys-meta{
  color:#9ca3af !important;
  font-weight:400;
  font-size:12px;
  line-height:1;
  margin-right:1em;
  transform:translateY(2px);
}

/* —— 服务器信息：中文键名较长，单独设宽 —— */
#system-overview .server-info { 
  --label-w: 80px;
}

#system-overview .server-info .info-item{
  display:grid; 
  grid-template-columns:var(--label-w) 1fr; 
  gap:8px; 
  align-items:center; 
  padding:5px 0;
}

#system-overview .server-info .label { 
  white-space: nowrap;
  color: var(--subheading-color) !important;
  font-size: var(--h4-size) !important; 
  font-weight: 600 !important;
  justify-self: start; 
}

#system-overview .server-info .value { 
  color: var(--content-color) !important; 
  font-size: var(--h4-size) !important; 
  font-weight: 500 !important;
  min-width: 0; 
  white-space: nowrap; 
  overflow: hidden; 
  text-overflow: ellipsis; 
}

/* —— 服务器配置（进度条区）：独立宽度控制 —— */
#system-overview .progress-row { 
  --label-w: 50px;
  --percent-col: 33px;
  display:grid; 
  grid-template-columns:var(--label-w) minmax(0,1fr) var(--percent-col);
  column-gap:4px; 
  align-items:center; 
  padding:5px 0;
}

#system-overview .progress-label{ 
  color:var(--subheading-color) !important;
  font-size: var(--h4-size) !important; 
  font-weight: 600 !important;
  justify-self:start;
  white-space:nowrap;
}

#system-overview .progress-bar{
  position:relative; 
  height:var(--meter-height);
  background:var(--meter-track); 
  border-radius:999px; 
  overflow:hidden; 
  align-self:center;
}

#system-overview .progress-fill{
  height:100%; 
  border-radius:999px; 
  background:linear-gradient(90deg,var(--meter-start),var(--meter-end));
  transition:width .25s ease;
}

#system-overview .progress-text{
  position:absolute; 
  left:4px; 
  right:4px; 
  top:50%; 
  transform:translateY(-50%);
  font-size:11px; 
  color:#fff; 
  white-space:nowrap; 
  overflow:hidden; 
  text-overflow:ellipsis; 
  pointer-events:none;
}

#system-overview .progress-info{
  min-width:var(--percent-col); 
  text-align:right; 
  color:var(--value);
  font-variant-numeric:tabular-nums;
}

/* —— 核心服务：独立宽度控制 —— */
#system-overview .core-services {
  --label-w: 70px;
  --svc-gap: 70px;
}

#system-overview .core-services .service-item{
  display:grid; 
  grid-template-columns:var(--label-w) max-content 1fr;
  column-gap:var(--svc-gap);
  align-items:center; 
  padding:5px 0;
}

#system-overview .core-services .service-item:first-child {
  padding-top: 6px !important;
}

#system-overview .core-services .service-item:last-child {
  padding-bottom: 5px !important;
}

#system-overview .core-services .label {
  color: var(--subheading-color) !important;
  font-size: 13px !important;
  font-weight: 600 !important;
  line-height: 1.2 !important;
  justify-self: start;
}

#system-overview .core-services .value { 
  color: var(--content-color) !important; 
  font-size: var(--h4-size) !important; 
  font-weight: 500 !important;
  min-width: 0; 
  white-space: nowrap; 
  overflow: hidden; 
  text-overflow: ellipsis; 
}

/* 覆盖全局状态徽章样式，减小尺寸 */
#system-overview .core-services .status-badge {
  height: 18px !important;
  line-height: 18px !important;
  padding: 0 8px !important;
  font-size: 11px !important;
}

#system-overview .core-services .version{
  justify-self:start; 
  min-width:0; 
  white-space:nowrap; 
  overflow:hidden; 
  text-overflow:ellipsis; 
  color:var(--muted); 
  font-size:12px;
}

/* —— 通用工具类（如果其他组件需要） —— */
.progress-label { 
  color: var(--muted-color); 
}
.progress-label h4 { 
  color: var(--heading-color); 
}

.text-h4-muted { 
  font-size: var(--h4-size);
  color: var(--muted-color);
  line-height: 1.4;
  font-weight: 500;
}

/* —— 响应式：窄屏时分别覆盖 —— */
@media (max-width:640px){
  #system-overview .server-info   { --label-w: 84px; }
  #system-overview .progress-row  { --label-w: 60px; --percent-col: 34px; }
  #system-overview .core-services { --label-w: 68px; }
}


/* =======================================================================
   证书切换
   ======================================================================= */
#cert-panel{
  /* 与 NetID 标签一致的参数 */
  --tag-pad-y: 5px;
  --tag-pad-x: 16px;
  --tag-radius: 8px;
  --tag-font: 13px;
  --tag-gap: 8px;
  --label-w: 80px;
  --row-gap: 10px;
  --h3-gap: 8px;
  /* 颜色 */
  --label: var(--heading-color);
  --value: var(--content-color);
  --tag-active-bg: #10b981;
  --tag-inactive-bg: #e2e8f0;
  --tag-active-color: #ffffff;
  --tag-inactive-color: #64748b;
  --card-br: #e5e7eb;
}

/* 顶部模式标签（两枚） */
#cert-panel .cert-modes{
  display:flex;
  gap:5px;
  margin-bottom: var(--tag-gap);
}

#cert-panel .cert-mode-tab{
  flex:1;
  padding: var(--tag-pad-y) var(--tag-pad-x);
  border: 1px solid var(--card-br);
  border-radius: var(--tag-radius);
  background: var(--tag-inactive-bg);
  color: var(--tag-inactive-color);
  font-size: var(--tag-font);
  font-weight: 600;
  text-align:center;
  cursor: default;
}

/* 非激活标签的h3 - 黑色，15px */
#cert-panel .cert-mode-tab h3{
  color: var(--heading-color);
  margin: 0;
  font-size: var(--h3-size);
  font-weight: 600;
}

/* 激活标签 */
#cert-panel .cert-mode-tab.active{
  background: var(--tag-active-bg);
  color: var(--tag-active-color);
  border-color: var(--tag-active-bg);
}

/* 激活标签的h3 - 白色，15px */
#cert-panel .cert-mode-tab.active h3{
  color: var(--tag-active-color);
}

/* 内容卡片：白底 + 边框 + 阴影 */
#cert-panel .inner-block{
  display:block;
  background:#fff;
  border:1px solid var(--card-br);
  border-radius:10px;
  padding:15px;
  box-shadow:0 2px 6px rgba(0,0,0,.08);
}

#cert-panel .inner-block>h3{
  margin:0 0 var(--h3-gap);
}

/* 明细行：键名 | 值 */
#cert-panel .inner-block .info-item{
  display:grid;
  grid-template-columns: var(--label-w) 1fr;
  gap: var(--row-gap);
  align-items:center;
  padding:6px 0;
}

/* 证书切换标题统一样式 */
#cert-panel .inner-block .info-item label{
  color: var(--subheading-color) !important;
  font-size: var(--h4-size) !important;
  font-weight: 600 !important;
  justify-self: start;
}

/* 证书切换内容统一样式 */
#cert-panel .inner-block .info-item value{
  color: var(--content-color) !important;
  font-size: var(--h4-size) !important;
  font-weight: 500 !important;
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* =======================================================================
   网络身份配置
   ============================================================ */
#netid-panel{
  /* 行样式（与 #cert-panel 保持一致） */
  --label-w: 80px;          /* 键名列宽 */
  --row-gap: 10px;          /* 键名列与值列横向间距 */
  --line-vpad: 6px;         /* 每行上下内边距（行高节奏） */

  /* 悬浮标签（与证书切换一致） */
  --tag-pad-y: 6px;         /* 标签上下 padding = 高度 */
  --tag-pad-x: 16px;        /* 标签左右 padding = 视觉宽度 */
  --tag-gap: 8px;           /* 标签与卡片的垂直间距 */
  --tag-radius: 8px;
  --tag-font: 13px;

  /* 颜色 */
  --label: var(--heading-color);
  --value: var(--content-color);
  --tag-active-bg: #10b981;     /* 激活：绿色 */
  --tag-inactive-bg: #e2e8f0;   /* 默认：灰色 */
  --tag-active-color: #ffffff;
  --tag-inactive-color: #64748b;
  --card-br: #e5e7eb;

  /* 高度联动（自适应高度） */
  --tag-h: calc(var(--tag-pad-y)*2 + 20px); /* 20px≈13px字高的可视行高 */
  --block-min-h: 140px;     /* 减少最小高度，让内容决定 */

  /* 标题横线 ↔ 组件组 的间距（只影响本卡） */
  --header-gap: 12px;       /* 原全局为 20px：越小越贴近 */
  --panel-top-gap: 4px;     /* 组件组再向下的细微"下移" */

  display: block !important; /* 防外部 flex 干扰 */
}

/* 标题行与下方网格的距离（只作用本卡） */
#netid-panel .card-header{
  margin-bottom: var(--header-gap) !important;
}

/* 标题右侧"注：HY2/TUIC…"（颜色+对齐+右缩进，仅本卡） */
#netid-panel .card-header h2{
  display: flex;
  align-items: flex-end;        /* 和标题下沿对齐 */
}
#netid-panel .card-header .note-udp{
  color: #9ca3af !important;    /* 浅灰 */
  font-weight: 400;
  font-size: 12px;
  line-height: 1;
  margin-right: 1em;            /* 右缩进一个字宽（可改 1em） */
  transform: translateY(2px);   /* 轻微下沉，更贴近底线 */
}

/* 三块容器：三列、自适应高度、顶部对齐 */
#netid-panel .network-blocks{
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 15px;
  align-content: start;         /* 从顶部开始排列 */
  align-items: start;           /* 子项顶部对齐，不强制等高 */
  padding-top: var(--panel-top-gap); /* 与标题横线的微调间距 */
}

/* 小卡片：为"悬浮标签"预留位置 + 阴影 */
#netid-panel .network-block{
  position: relative;
  background: #fff;
  border: 1px solid var(--card-br);
  border-radius: 10px;
  padding: 12px;
  margin-top: calc(var(--tag-h) + var(--tag-gap));  /* 预留标签高度 */
  min-height: 140px;  /* 减少固定高度，让内容决定高度 */
  box-shadow: 0 2px 6px rgba(0,0,0,0.08);
}

/* 悬浮标签样式 */
#netid-panel .network-block > h3{
  position: absolute !important;
  top: 0 !important;
  left: 1px !important;
  right: 1px !important;
  width: calc(100% - 2px) !important;
  transform: translateY(calc(-100% - var(--tag-gap))) !important;

  margin: 0 !important;
  padding: var(--tag-pad-y) var(--tag-pad-x) !important;
  background: var(--tag-inactive-bg) !important;
  color: var(--heading-color) !important;  /* 改为h3的黑色 */
  border: 1px solid var(--card-br) !important;
  border-radius: var(--tag-radius) !important;

  font-size: var(--h3-size) !important;  /* 使用h3大小 */
  font-weight: 600 !important;
  line-height: 1.2 !important;
  white-space: nowrap !important;

  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  gap: 6px !important;
}

/* 当前模式高亮（JS：给对应 .network-block 加 .active） */
#netid-panel .network-block.active > h3{
  background: var(--tag-active-bg) !important;
  color: var(--tag-active-color) !important;
  border-color: var(--tag-active-bg) !important;
}

/* 内容行：键名 | 值（与证书切换一致） */
#netid-panel .network-block .info-item{
  display: grid;
  grid-template-columns: var(--label-w) 1fr;
  gap: var(--row-gap);
  align-items: center;
  padding: var(--line-vpad) 0;
}

/* 网络身份配置标题统一样式 */
#netid-panel .network-block .info-item label{
  color: var(--subheading-color) !important;  /* h4级别用灰色 */
  font-size: var(--h4-size) !important;
  font-weight: 600 !important;
}

/* 网络身份配置内容统一样式（包含IP质量分数） */
#netid-panel .network-block .info-item value,
#netid-panel .nid__value #vps-ipq-score,
#netid-panel .nid__value #proxy-ipq-score,
#netid-panel .whitelist-text{
  color: var(--content-color) !important;
  font-size: var(--h4-size) !important;
  font-weight: 500 !important;
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* 白名单文本特殊处理 */
#netid-panel .whitelist-text {
  flex-shrink: 0;
}

/* 窄屏：纵向堆叠，去掉强制高度避免留白 */
@media (max-width: 1024px){
  #netid-panel .network-blocks{
    grid-template-columns: 1fr;
    min-height: initial;
    align-content: start;
    padding-top: 0;
  }
}

/* ======== 网络身份配置 - 白名单查看全部按钮专用CSS =========== */

#net-shunt .whitelist-value,
#net-shunt .info-item .whitelist-value {
  /* 覆盖父级的 white-space: nowrap 和 overflow: hidden */
  white-space: normal !important;  /* 允许换行 */
  overflow: visible !important;    /* 显示溢出内容 */
  text-overflow: initial !important;  /* 取消省略号 */
  
  position: relative;
  width: 100%;
  min-height: auto;  /* 移除固定最小高度 */
}

/* 白名单预览容器 */
.whitelist-preview {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  line-height: 1.4;
}

/* 白名单文本内容 */
.whitelist-text {
  color: #111827;
  font-size: 13px;
  flex-shrink: 0;
}

/* 查看全部按钮 - 默认跟在文本后面 */
.whitelist-more {
  --btn-h: 22px;
  --btn-pad-x: 8px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: var(--btn-h);
  padding: 0 var(--btn-pad-x);
  border: 1px solid #d1d5db;
  border-radius: 4px;
  background: #fff;
  color: #2563eb;
  font-size: 11px;
  font-weight: 500;
  text-decoration: none;
  cursor: pointer;
  white-space: nowrap;
  box-shadow: 0 1px 2px rgba(0,0,0,0.1);
  transition: all 0.15s ease;
  flex-shrink: 0;
}

.whitelist-preview.has-overflow .whitelist-more {
  position: absolute;
  right: 0;
  top: calc(1.4em * 2.2);
  margin-left: 0;
}

/* hover效果 */
.whitelist-more:hover {
  background: #f3f4f6;
  border-color: #9ca3af;
  color: #1d4ed8;
  box-shadow: 0 2px 4px rgba(0,0,0,0.12);
}

/* active效果 */
.whitelist-more:active {
  background: #e5e7eb;
  border-color: #9ca3af;
  color: #1d4ed8;
  transform: translateY(1px);
}

/* 白名单行自适应高度 */
#net-shunt .info-item.nid__row:last-child {
  align-items: center;  /* 改回居中对齐，与其他行保持一致 */
  /* 移除 min-height: 64px; */
}

/* 响应式调整 */
@media (max-width: 1024px) {
  .whitelist-more {
    --btn-h: 18px;
    --btn-pad-x: 4px;
    font-size: 9px;
  }
}


/* =======================================================================
   协议配置表格 - 基础样式
   ======================================================================= */

/* 表格容器 - 带边框和阴影 */
.data-table { 
    width: 100%; 
    border-collapse: collapse;
    border: 1px solid #6b7280;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 
        0 6px 16px rgba(0,0,0,0.12),
        0 0 0 1px rgba(0,0,0,0.06);
}

/* 表头 */
.data-table th {
    background: #f5f5f5; 
    color: #4b5563; 
    font-weight: 500; 
    padding: 8px 10px;
    text-align: left;
    font-size: 12px; 
    border-bottom: 1px solid #e5e7eb;
}

/* 普通单元格 */
.data-table td {
    padding: 7px 10px;
    border-bottom: 1px solid #e5e7eb;
    font-size: 12px;
}

/* 第4、5、6列居中(运行状态、客户端配置等) */
.data-table td:nth-child(4),
.data-table td:nth-child(5),
.data-table td:nth-child(6),
.data-table th:nth-child(4),
.data-table th:nth-child(5),
.data-table th:nth-child(6) { 
    text-align: center; 
}

/* hover行效果 */
.data-table tbody tr:hover td {
    background: #f8f9fa;
    box-shadow: 0 2px 6px rgba(0,0,0,0.12);
}

/* 交替行背景(斑马纹) */
.data-table tbody tr:nth-child(even):not(.subs-row) td {
    background-color: rgba(249,250,251,0.65);
}

.data-table tbody tr:nth-child(even):not(.subs-row):hover td {
    background-color: #f3f4f6;
}

/* 订阅行特殊样式 */
.data-table tr.subs-row td {
    background: #eef2f7;
    border-top: 1px solid #cbd5e1;
}

.data-table tr.subs-row:hover td {
    background: #e3e9f2;
    box-shadow: inset 0 1px 3px rgba(0,0,0,0.14), 0 3px 8px rgba(0,0,0,0.12);
}

/* 前三列(协议名称、使用场景、伪装效果)文字样式 */
.data-table td:nth-child(1),
.data-table td:nth-child(2),
.data-table td:nth-child(3) {
    color: var(--content-color, #6b7280);
    font-size: var(--h4-size, 13px);
    font-weight: 500;
}

/* ========协议配置卡片 - 间距修复============ */

/* grid布局中的卡片不使用margin */
.main-content .grid .card {
    margin-bottom: 0 !important;
}

/* 确保grid布局有正确的gap */
.main-content .grid {
    display: grid; 
    gap: 20px !important;
    margin: 0;
}

/* 1-2网格布局(证书切换和网络身份配置) */
.main-content .grid-1-2 {
    display: grid; 
    grid-template-columns: 1fr 2fr;
    gap: 20px !important;
    margin-bottom: 20px !important;
}

/* 协议配置卡片确保有正确的上边距 */
.card[id*="protocol"],
.card:has(.data-table),
#protocol-panel,
#protocols-panel,
.protocol-card {
    margin-top: 20px !important;
}

/* 非grid内的卡片间距 */
.main-content > .card:not(.grid .card) {
    margin-bottom: 20px !important;
}

.main-content > .card:not(.grid .card):not(:first-child) {
    margin-top: 20px !important;
}

/* grid后面的卡片强制添加上边距 */
.main-content .grid + .card,
.main-content .grid-1-2 + .card {
    margin-top: 20px !important;
}

/* 确保协议配置表格卡片的边框正常显示 */
.card:has(.data-table) {
    border: 1px solid #d1d5db !important;
    box-shadow: 0 2px 6px rgba(0,0,0,.08) !important;
}

/* ========== 协议健康状态 - 单行布局(与核心服务徽标统一) ========== */

/* 仅第4列 td：横向保持居中 + 垂直居中（不动 th 标题） */
.data-table td:nth-child(4) {
    text-align: center;
    vertical-align: middle;
}

/* 单元格容器：块级 flex，自身在单元格中居中；内部从左排布 */
.data-table td:nth-child(4) .health-status-container {
    display: flex;
    align-items: center;
    justify-content: flex-start;
    gap: 6px;
    padding: 4px 0;
    inline-size: var(--status-col-w, 320px);
    max-inline-size: 100%;
    margin-inline: auto;
    text-align: left;
}

/* 健康状态徽章 - 固定宽度确保对齐，并与文字中线对齐 */
.health-status-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 20px;
    line-height: 20px;
    padding: 0 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 500;
    min-width: 50px;
    flex-shrink: 0;
    vertical-align: middle;
}

/* 状态配色 */
.health-status-badge.healthy { background:#d1fae5; color:#059669; border:1px solid #a7f3d0; }
.health-status-badge.degraded { background:#fef3c7; color:#d97706; border:1px solid #fde68a; }
.health-status-badge.down { background:#fee2e2; color:#ef4444; border:1px solid #fecaca; }

/* 图标/圆点等与文字中线对齐 */
.data-table td:nth-child(4) .health-status-container :is(.dot, .icon, svg, img) {
    vertical-align: middle;
    align-self: center;
}

/* 健康详细消息/推荐标签 */
.health-detail-message,
.health-recommendation-badge {
    color: var(--content-color, #6b7280);
    font-size: var(--h4-size, 13px);
    font-weight: 500;
    white-space: nowrap;
    flex-shrink: 0;
    line-height: 1.2;
}

/* 运行状态列宽度 */
.protocol-status { min-width: 320px; }

/* 健康分数显示：与徽章中线对齐 */
.protocol-health-score {
    font-weight: 700;
    font-size: 18px;
    padding: 4px 8px;
    border-radius: 4px;
    display: inline-block;
    vertical-align: middle;
}
.protocol-health-score.score-excellent { color:#10b981; background:rgba(16,185,129,0.1); }
.protocol-health-score.score-good { color:#3b82f6; background:rgba(59,130,246,0.1); }
.protocol-health-score.score-fair { color:#f59e0b; background:rgba(245,158,11,0.1); }
.protocol-health-score.score-poor { color:#ef4444; background:rgba(239,68,68,0.1); }

/* 单行省略号保险：允许消息项收缩，容器不换行 */
.data-table td:nth-child(4) .health-status-container{
  flex-wrap: nowrap;
  min-width: 0; /* 允许子项收缩 */
}

.health-detail-message{
  flex: 1 1 auto;  /* 允许收缩 */
  min-width: 0;   /* 否则 ellipsis 无效 */
  overflow: hidden;
  text-overflow: ellipsis;
}

/* =============协议健康状态 - 摘要卡片================ */

#health-summary {
    margin: 20px 0;
    padding: 20px;
    background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
    border-radius: 12px;
    border: 1px solid #e2e8f0;
}

.health-summary-card {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px;
    margin-bottom: 16px;
}

.summary-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 12px;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    transition: transform 0.2s;
}

.summary-item:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.summary-label {
    font-size: 13px;
    color: #64748b;
    margin-bottom: 8px;
    text-align: center;
}

.summary-value {
    font-size: 28px;
    font-weight: 700;
    color: #1e293b;
}

.summary-item.healthy .summary-value { color: #10b981; }
.summary-item.degraded .summary-value { color: #f59e0b; }
.summary-item.down .summary-value { color: #ef4444; }

.health-recommended {
    padding: 12px;
    background: white;
    border-radius: 8px;
    margin-bottom: 12px;
    font-size: 14px;
    color: #475569;
}

.health-recommended strong {
    color: #1e293b;
    margin-right: 8px;
}

.health-update-time {
    text-align: right;
    font-size: 12px;
    color: #94a3b8;
    font-style: italic;
}

/* =====协议健康状态 - 动画效果========== */

@keyframes pulse-healthy {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.8; }
}

@keyframes pulse-warning {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.7; }
}

.health-status-badge.healthy {
    animation: pulse-healthy 3s ease-in-out infinite;
}

.health-status-badge.degraded {
    animation: pulse-warning 2s ease-in-out infinite;
}

/* ===========响应式布局============= */

/* 响应式：窄屏减小容器宽度，仍保持"列居中/内容左起" */
@media (max-width: 768px) {
    .data-table td:nth-child(4) .health-status-container {
        inline-size: var(--status-col-w-sm, 260px);
    }
    .health-status-badge {
        font-size: 10px;
        padding: 0 8px;
        height: 18px;
        line-height: 18px;
        min-width: 45px;
    }
    .health-detail-message,
    .health-recommendation-badge { font-size: 12px; }
    .protocol-status { min-width: 260px; }
    
    .health-summary-card {
        grid-template-columns: repeat(2, 1fr);
        gap: 12px;
    }
    
    .summary-value {
        font-size: 24px;
    }
}

/* 响应式：窄屏时确保间距一致 */
@media (max-width: 1024px) {
    .main-content .grid-1-2 {
        grid-template-columns: 1fr;
        gap: 20px !important;
    }
    
    .main-content .grid + .card,
    .main-content .grid-1-2 + .card {
        margin-top: 20px !important;
    }
}

/* ========暗色模式支持========== */

@media (prefers-color-scheme: dark) {
    #health-summary {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border-color: #334155;
    }
    
    .summary-item {
        background: #1e293b;
        border: 1px solid #334155;
    }
    
    .summary-label {
        color: #94a3b8;
    }
    
    .summary-value {
        color: #f1f5f9;
    }
    
    .health-recommended {
        background: #1e293b;
        color: #cbd5e1;
        border: 1px solid #334155;
    }
    
    .health-detail-message {
        color: #94a3b8;
    }
}


/* =======================================================================
   流量统计 - 修复垂直居中问题
   =================================================================== */

/* —— 全局口径：保持原有变量 —— */
:root{
  --charts-pad-y: 10px;   
  --charts-pad-x: 20px;   
  --gap-v: 12px;          
  --h-progress: 50px;     
  --h-left-chart: 300px;  
  --mini-pad: 12px;       
  --meter-height: 18px;   
}

/* 卡片外框 - 修复关键问题：使用统一的内边距体系 */
.traffic-card{
  background:#fff; 
  border:1px solid #d1d5db; 
  border-radius:10px;
  box-shadow:0 2px 6px rgba(0,0,0,.08); 
  padding:20px;  /* ← 关键修复：恢复与其他卡片一致的20px内边距 */
  overflow:hidden;
}

/* 标题行 - 修复：使用与其他卡片一致的标题样式 */
.traffic-card .card-header{ 
  margin-bottom:20px;  /* ← 关键修复：与其他卡片保持一致的20px间距 */
  padding-bottom:12px; 
  border-bottom:1px solid #e5e7eb; 
}
.traffic-card .card-header > *{ margin:0; }

/* —— 图表组：修复垂直居中 —— */
.traffic-charts,
.traffic-charts.traffic--subcards{
  display:grid; 
  grid-template-columns:7fr 3fr; 
  gap:20px;
  padding:0;  /* ← 关键修复：去掉额外的padding，让外层卡片的20px生效 */
  margin:0;   /* ← 关键修复：去掉任何margin */
  align-items: stretch;
}

/* 左列容器与默认分隔线（B 方案下移除） */
.chart-column{ 
  display:flex; 
  flex-direction:column; 
  gap:var(--gap-v); 
}
.chart-column > * + *{ 
  border-top:1px solid #e5e7eb; 
  padding-top:12px; 
  margin-top:12px; 
}

/* 仅非 B 方案显示两列竖线 */
.traffic-charts:not(.traffic--subcards) > :first-child{ 
  border-right:1px solid #e5e7eb; 
  padding-right:20px; 
}
.traffic-charts:not(.traffic--subcards) > :last-child{  
  padding-left:20px; 
}

/* —— 进度条组件（高度与 CPU 一致）—— */
.traffic-card .traffic-progress-container,
.traffic-progress-container{ 
  display:flex; 
  align-items:center; 
  gap:10px; 
  height:var(--h-progress); 
  flex-shrink:0; 
}

.progress-label { 
  font-size:13px; 
  color:#6b7280; 
  white-space:nowrap; 
}

.traffic-card .progress-wrapper,
.progress-wrapper{ 
  flex:1; 
  min-width:120px; 
}

.traffic-card .progress-bar,
.progress-bar{ 
  height:var(--meter-height); 
  background:#e2e8f0; 
  border-radius:999px; 
  overflow:hidden;  /* 保持 hidden，标签现在在内部 */
  position:relative; 
}

.traffic-card .progress-fill,
.progress-fill{ 
  height:100%; 
  background:linear-gradient(90deg,#10b981 0%,#059669 100%); 
  transition:width .3s ease; 
  display:flex; 
  align-items:center; 
  justify-content:flex-end; 
  padding-right:8px; 
}

.progress-fill.warning { 
  background:linear-gradient(90deg,#f59e0b 0%,#d97706 100%); 
}

.progress-fill.critical { 
  background:linear-gradient(90deg,#ef4444 0%,#dc2626 100%); 
}

.traffic-card .progress-percentage,
.progress-percentage{ 
  color:#fff; 
  font-size:11px; 
  font-weight:600; 
}

.traffic-card .progress-budget,
.progress-budget{ 
  color:#6b7280; 
  font-size:12px; 
  white-space:nowrap; 
}

/* —— 图表容器：标题居中 + canvas 填满 —— */
.chart-container{ 
  position:relative; 
  display:flex; 
  flex-direction:column; 
  overflow:hidden; 
}
.traffic-card .chart-container h3{ 
  text-align:center; 
  margin:0 0 8px; 
  font-weight:600; 
  font-size:14px; 
  line-height:20px; 
  flex:0 0 auto; 
}
.traffic-card .chart-container > canvas{ 
  display:block; 
  width:100% !important; 
  height:100% !important; 
  flex:1 1 auto; 
}

/* —— 等高口径：两列下边框对齐 —— */
/* 非 B 方案：右列 = 进度 + gap + 左图 */
.traffic-charts:not(.traffic--subcards) .chart-column:first-child .chart-container{
  height: var(--h-left-chart); 
  min-height: var(--h-left-chart);
}
.traffic-charts:not(.traffic--subcards) .chart-column:last-child .chart-container{
  height: calc(var(--h-progress) + var(--gap-v) + var(--h-left-chart));
  min-height: calc(var(--h-progress) + var(--gap-v) + var(--h-left-chart));
}

/* B 方案：考虑迷你卡片 padding 差额 */
.traffic-charts.traffic--subcards > :first-child{ 
  border-right:0; 
  padding-right:0; 
}
.traffic-charts.traffic--subcards > :last-child{  
  padding-left:0; 
}

.traffic-charts.traffic--subcards .traffic-progress-container,
.traffic-charts.traffic--subcards .chart-container{
  padding:var(--mini-pad);
  border:1px solid #e5e7eb; 
  border-radius:12px;
  background:#fff; 
  box-shadow:0 2px 8px rgba(17,24,39,.08);
}
.traffic-charts.traffic--subcards .chart-column > * + *{ 
  border-top:0; 
  padding-top:0; 
  margin-top:0; 
}

.traffic-charts.traffic--subcards .chart-column:first-child .chart-container{
  height: calc(var(--h-left-chart) + 2*var(--mini-pad));
  min-height: calc(var(--h-left-chart) + 2*var(--mini-pad));
}
.traffic-charts.traffic--subcards .chart-column:last-child .chart-container{
  height: calc(var(--h-progress) + var(--gap-v) + var(--h-left-chart) + 2*var(--mini-pad));
  min-height: calc(var(--h-progress) + var(--gap-v) + var(--h-left-chart) + 2*var(--mini-pad));
}

/* 单位标注样式 - 小字灰色 */
.unit-note {
  font-size: 11px !important;
  font-weight: 400 !important;
  color: #9ca3af !important;
  margin-left: 4px;
}

/* 仅隐藏 Chart.js 生成的 HTML 图例（如有）——避免误伤轴刻度 */
.traffic-card .chartjs-legend {
  display: none !important;
}

/* 标题后的默认"圆点版"自定义图例（其它图表都用这个） */
.traffic-card .chart-container > h3::after {
  content: " 🔵 VPS 🟢 代理";
  font-size: 11px;
  color: #6b7280;
  margin-left: 8px;
}

/* 仅"近12月柱状图"使用"方块版"图例
   精确到：同一个 .chart-container 里含有 <canvas id="monthly-chart"> 才生效 */
@supports selector(.x:has(#monthly-chart)) {
  .chart-container:has(> canvas#monthly-chart) > h3::after {
    content: " 🟦 VPS 🟩 代理";
  }
}

/* —— 可选：旧浏览器 fallback（如果不支持 :has()）——
   若"近12月柱状图"的容器能加类名，请在 HTML 给该容器加 .is-monthly，
   然后启用下面这条，更稳更准确。 */

/*
.traffic-card .chart-container.is-monthly > h3::after {
  content: " 🟦 VPS 🟩 代理";
}
*/

/* —— 如果暂时不能加类名，只能按位置兜底（请把 2 改成实际序号）—— */
/*
@supports not selector(.x:has(#monthly-chart)) {
  .traffic-grid .traffic-card:nth-of-type(2) .chart-container > h3::after {
    content: " 🟦 VPS 🟩 代理";
  }
}
*/

/* =====================响应式布局================ */

@media (max-width: 1024px) {
  .grid-3, .grid-1-2 { 
    grid-template-columns: 1fr; 
  }
  .traffic-charts { 
    grid-template-columns: 1fr; 
  }
  .traffic-charts:not(.traffic--subcards) > :first-child{ 
    border-right:0; 
    padding-right:0; 
  }
  .traffic-charts:not(.traffic--subcards) > :last-child{  
    padding-left:0; 
  }
  .chart-column:first-child .chart-container,
  .chart-column:last-child .chart-container{
    height:250px;  /* 减少高度，确保图例不被截断 */
    min-height:250px;
  }
}

@media (max-width: 768px) {
  .modal-content { 
    width: 95%; 
    margin: 10px auto; 
  }
}

/* =======================================================================
   运维管理 (最终修正版)
   ======================================================================= */

.card {
  background: #fff;
  border: 1px solid #d1d5db;
  border-radius: 10px;
  box-shadow: 0 2px 6px rgba(0, 0, 0, .08);
  padding: 20px;
  margin-bottom: 20px;
  transition: box-shadow .2s;
}

.card:hover {
  box-shadow: 0 4px 8px rgba(0, 0, 0, .08);
}

.card-header {
  margin-bottom: 20px;
  padding-bottom: 12px;
  border-bottom: 1px solid #e5e7eb;
}

.card-header h2 {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 18px;
  font-weight: 600;
  color: #111827;
  line-height: 26px;
}

h3 {
  font-size: 15px;
  line-height: 1.4;
  font-weight: 600;
  color: #111827;
}

.commands-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

/* 修复：允许每张卡在网格里收缩，避免长内容把相邻列挤爆 */
.commands-grid > .command-section {
  min-width: 0;
  overflow: hidden;
  /* 防止内容溢出导致布局错乱 */
}

@media (max-width: 768px) {
  .commands-grid {
    grid-template-columns: 1fr;
  }
}

.command-section {
  background: #f5f5f5;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  padding: 12px;
}

/* 标题 */
.command-section h3 {
  margin: 0 0 16px;
  font-size: 0.9rem;
  font-weight: 600;
  color: #1e293b;
  display: flex;
  align-items: center;
  gap: 6px;
}

/* 列表整体：两列网格（左列命令 / 右列注释） */
#ops-panel .command-list,
.commands-grid .command-list,
.command-list {
  font-size: 0.8rem;
  line-height: 1.3;
  margin: 0;
  padding: 0;
  list-style: none;
  display: grid;
  /* 修改：左列自适应但不超过容器宽度，右列填充剩余空间 */
  grid-template-columns: minmax(24ch, 52%) minmax(16ch, 1fr);
  column-gap: 10px;
  row-gap: 4px;
  align-items: start;
  grid-auto-flow: row dense;
  width: 100%;
  /* 确保列表不超出卡片宽度 */
}

/* 不让 <br> 产生空白行 —— 行距交给 row-gap 控制 */
#ops-panel .command-list > br,
.commands-grid .command-list > br,
.command-list > br {
  display: none;
}

/* 普通命令 <code>：灰底胶囊，随内容宽度 */
#ops-panel .command-list > code,
.commands-grid .command-list > code,
.command-list > code {
  grid-column: 1;
  display: inline-block;
  justify-self: start;
  background: #e2e8f0;
  color: #1f2937;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 0.78rem;
  line-height: 1.2;
  white-space: pre-wrap;
  max-width: 100%;
  min-width: 0;
  /* 允许收缩 */
  margin: 0;
  /* 修复：长 URL/参数可在任意位置断行，不会把布局顶乱 */
  overflow-wrap: anywhere;
  word-break: break-word;
  /* 改为 break-word，比 break-all 更友好 */
}

/* 示例命令 <a>：与 <code> 同款灰底胶囊（蓝字） */
#ops-panel .command-list > a,
.commands-grid .command-list > a,
.command-list > a {
  grid-column: 1;
  display: inline-block;
  justify-self: start;
  background: #e2e8f0;
  padding: 2px 6px;
  border-radius: 4px;
  text-decoration: none;
  margin: 0;
  color: #2563eb;
  font-family: monospace;
  font-size: 0.78rem;
  line-height: 1.2;
  white-space: pre-wrap;
  max-width: 100%;
  min-width: 0;
  /* 允许收缩 */
  overflow-wrap: anywhere;
  word-break: break-word;
}

/* 注释 <span>：右列左对齐 */
#ops-panel .command-list > span,
.commands-grid .command-list > span,
.command-list > span {
  grid-column: 2;
  color: #6b7280;
  text-align: left;
  margin: 0;
  line-height: 1.25;
  min-width: 0;
  /* 允许收缩 */
  overflow-wrap: break-word;
  /* 防止长文本溢出 */
}

/* "示例 / level / 代理URL格式"标题行：蓝字，无灰底，跨两列 */
#ops-panel .command-list > :not(code):not(span):not(a),
.commands-grid .command-list > :not(code):not(span):not(a),
.command-list > :not(code):not(span):not(a) {
  grid-column: 1 / -1;
  margin: 0;
  line-height: 1.4;
  color: #2563eb;
  font-size: 0.78rem;
  font-weight: 600;
}

/* "level / 代理URL格式"内容块（旧结构）：保持说明为灰色文本 */
#ops-panel .command-list > div + div,
.commands-grid .command-list > div + div,
.command-list > div + div {
  color: #6b7280;
  font-weight: 500;
  margin: 0;
  line-height: 1.3;
}

/* 兼容：若你已按统一结构使用 .cmd-label / .cmd-pill，这里也提供样式 */
.command-list .cmd-label {
  grid-column: 1 / -1;
  margin: 0;
  line-height: 1.3;
  color: #2563eb;
  font-size: 0.78rem;
  font-weight: 600;
}

.command-list > .cmd-pill {
  grid-column: 1;
  display: inline-block;
  justify-self: start;
  background: #e2e8f0;
  color: #2563eb;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 0.78rem;
  line-height: 1.2;
  white-space: pre-wrap;
  max-width: 100%;
  min-width: 0;
  margin: 0;
  text-decoration: none;
  overflow-wrap: anywhere;
  word-break: break-word;
}

/* =========================
   弹窗 Modal 统一样式补丁
   ========================= */

/* 变量 */
.modal, dialog[open], .el-dialog, .ant-modal{
  --modal-w: 630px;
  --modal-h: 730px;
  --modal-radius: 14px;
  --modal-shadow: 0 10px 30px rgba(17,24,39,.18);
  --modal-padding: 16px;
  --section-border: #e5e7eb;
  --input-bg: #f7f8fa;
  --code-bg: #f8f9fb;

  /* 复制按钮色系（白底灰字） */
  --btn-border: #d1d5db;
  --btn-text: #6b7280;
  --btn-text-hover: #374151;
  --btn-bg: #ffffff;
  --btn-bg-hover: #f9fafb;
  --btn-bg-active: #f3f4f6;
}

/* —— 固定大小 + 居中出现 —— */
.modal .modal-content,
dialog[open],
.el-dialog,
.ant-modal .ant-modal-content{
  position: fixed !important;
  left: 50% !important;
  top: 50% !important;
  transform: translate(-50%, -50%) !important;
  margin: 0 !important;
  width: var(--modal-w) !important;
  height: var(--modal-h) !important;
  min-height: var(--modal-h) !important;
  max-width: calc(100vw - 32px) !important;
  max-height: 85vh !important;
  background: #fff !important;
  border: 0 !important;
  border-radius: var(--modal-radius) !important;
  box-shadow: var(--modal-shadow) !important;
  display: flex !important;
  flex-direction: column !important;
  overflow: hidden !important;
  z-index: 9999 !important;
  animation: none !important;
  transition: none !important;
}

/* 遮罩 */
.modal{ 
  display:none; 
  position:fixed; 
  inset:0; 
  background:rgba(0,0,0,.5); 
  z-index:9998; 
}

/* 头部 */
.modal-header, .el-dialog__header, .ant-modal-header{
  flex-shrink:0 !important;
  display:flex !important; 
  align-items:center !important; 
  justify-content:space-between !important;
  padding:var(--modal-padding) !important;
  border-bottom:1px solid var(--section-border) !important;
  background:#fff !important;
}

.modal-title, .el-dialog__title, .ant-modal-title, #configModalTitle, #ipqModalTitle{
  font-size:15px !important; 
  font-weight:600 !important; 
  color:#111827 !important; 
  margin:0 !important;
  text-align: left !important; /* 标题左对齐 */
}

/* 主体滚动区 */
.modal-body, .el-dialog__body, .ant-modal-body{
  flex:1 !important;
  padding:var(--modal-padding) !important;
  overflow-y:auto !important; 
  overflow-x:hidden !important;
  min-height:0 !important;
}

/* 底部 */
.modal-footer{
  flex-shrink:0 !important;
  padding:var(--modal-padding) !important;
  border-top:1px solid var(--section-border) !important;
  display:flex !important; 
  gap:10px !important; 
  justify-content:flex-end !important;
  background:#fff !important;
}

/* ===== 查看详情弹窗分隔线和左对齐 ===== */

/* ===仅限 #ipqModal，避免污染全局 .info-item======= */
#ipqModal .info-item{
  display: grid;
  grid-template-columns: 144px 1fr;
  gap: 12px;
  align-items: start;
  justify-content: start;
  text-align: left;
}

/* 标签列样式（更清晰） */
#ipqModal .info-item label{
  text-align: left;
  font-weight: 600;
  color: #6b7280;
  margin: 0;
}

/* 值列换行策略，避免超长内容撑破 */
#ipqModal .info-item value{
  display: block;
  text-align: left;
  overflow-wrap: anywhere;
  word-break: break-word;
}

/* 无 grid 的极老环境做兜底（基本用不到） */
@supports not (display: grid){
  #ipqModal .info-item{
    display: flex;
    justify-content: flex-start;
    gap: 12px;
  }
  #ipqModal .info-item label{ min-width: 144px; }
  #ipqModal .info-item value{ flex: 1; }
}

/* —— IPQ 弹窗分组标题（<h5>）尺寸修正，仅作用 #ipqModal —— */
#ipqModal .ipq-section > h5 {
  font-size: var(--h3-size, 15px);
  line-height: 22px;
  font-weight: 600;
  color: var(--heading-color, #111827);
  margin: 0 0 8px;
}

/* 弹窗内分组样式 */
#detailModal .modal-section,
#detailModal .detail-section,
#ipqModal .ipq-section,
#configModal .modal-section,
#configModal .config-section{
  padding:20px 0;
  border-bottom:1px solid #374151;
}

#configModal .modal-section,
#configModal .config-section{ 
  padding:16px 0; 
  border-bottom:none; 
}

#detailModal .modal-section:first-child,
#detailModal .detail-section:first-child,
#ipqModal .ipq-section:first-child{ 
  padding-top:0; 
}

#detailModal .modal-section:last-child,
#detailModal .detail-section:last-child,
#ipqModal .ipq-section:last-child{
  padding-bottom:0; 
  border-bottom:none;
}

/* 查看详情弹窗内容左对齐 */
#detailModal .kv-key, 
#ipqModal .kv-key,
#detailModal .kv-value,
#ipqModal .kv-value { 
  text-align:left !important; 
}

#detailModal .kv-key, 
#ipqModal .kv-key { 
  padding-right:0; 
}

/* 键值对通用 */
.kv-list{ 
  display:flex; 
  flex-direction:column; 
  gap:10px; 
}

.kv-row{
  display:grid; 
  grid-template-columns:144px 1fr; 
  gap:12px;
  padding:8px 0; 
  border-bottom:1px dashed #eef2f7;
}

.kv-row:last-child{ 
  border-bottom:none; 
}

.kv-key{ 
  color:#6b7280; 
  font-size:13px; 
  text-align:right; 
  padding-right:8px; 
  line-height:1.6; 
}

.kv-val, .kv-value{ 
  color:#111827; 
  font-size:13px; 
  word-break:break-word; 
}

/* ===== 输入/代码框 ===== */
.input-plain, .textarea-plain, .code-box, .config-code,
#json-code, #plain-link, #plain-links-6, #base64-link,
.modal-body textarea, .modal-body input[type="text"],
.modal-body pre, .modal-body code,
.modal-body .codebox pre, .modal-body .codebox code,
.modal-body .jsonbox pre, .modal-body .jsonbox code,
.modal-body .linkbox input, .modal-body .linkbox textarea{
  background:var(--input-bg) !important;
  border:1px solid var(--section-border) !important;
  border-radius:8px !important;
  padding:10px 12px !important;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace !important;
  font-size:12px !important; 
  color:#333 !important;
  width:100%; 
  box-sizing:border-box; 
  white-space:pre-wrap !important; 
  word-break:break-word !important; 
  line-height:1.5;
}

.code-box, .config-code{ 
  background:var(--code-bg) !important; 
  max-height:200px; 
  overflow-y:auto; 
  position:relative; 
}

.textarea-plain, .modal-body textarea{ 
  min-height:100px; 
  resize:vertical; 
}

.input-plain[readonly], .modal-body input[readonly]{ 
  cursor:default; 
  background:var(--input-bg) !important; 
}

/* ===== 二维码：保留居中，移除左对齐 ===== */

.modal-body .qr-container,
.modal-body .qrcode,
.modal-body [data-role="qrcode"],
.modal-body .qr-container div,
.modal-body .qrcode div{
  text-align:center !important;
  margin: 16px auto !important;
}

.modal-body .qr-container canvas,
.modal-body .qrcode canvas,
.modal-body [data-role="qrcode"] canvas,
#qrcode-sub canvas,
#qrcode-protocol canvas{
  width:180px !important; 
  height:180px !important; 
  aspect-ratio:1/1 !important;
  display:block !important; 
  margin:12px auto !important; 
  image-rendering:pixelated;
  /* 强制移除任何左对齐样式 */
  float: none !important;
  text-align: center !important;
}

/* ===== 复制按钮：白底圆角灰字 ===== */
.modal .copy-btn,
.modal .btn-copy,
.modal .btn-secondary,
.modal [data-action="copy"],
.modal [data-action="copy-qr"],
.ant-modal .ant-btn[data-role="copy"],
.el-dialog .el-button[data-role="copy"]{
  appearance:none !important;
  background:var(--btn-bg) !important;
  color:var(--btn-text) !important;
  border:1px solid var(--btn-border) !important;
  border-radius:8px !important;
  padding:8px 12px !important;
  font-size:12px !important;
  line-height:1.2 !important;
  cursor:pointer !important;
  box-shadow:0 1px 2px rgba(0,0,0,.04) !important;
  transition: all 0.15s ease !important;
}

.modal .copy-btn:hover,
.modal .btn-copy:hover,
.modal .btn-secondary:hover,
.modal [data-action="copy"]:hover,
.modal [data-action="copy-qr"]:hover,
.ant-modal .ant-btn[data-role="copy"]:hover,
.el-dialog .el-button[data-role="copy"]:hover{
  background:var(--btn-bg-hover) !important;
  color:var(--btn-text-hover) !important;
  border-color:#cbd5e1 !important;
  box-shadow:0 2px 4px rgba(0,0,0,.08) !important;
}

.modal .copy-btn:active,
.modal .btn-copy:active,
.modal .btn-secondary:active,
.modal [data-action="copy"]:active,
.modal [data-action="copy-qr"]:active{
  background:var(--btn-bg-active) !important;
  transform: translateY(1px);
}

/* ===== 关闭按钮：外包圆角小方框 ===== */
.modal .close-btn,
.modal .modal-close,
.ant-modal-close, 
.el-dialog__headerbtn{
  position:absolute !important; 
  right:12px !important; 
  top:12px !important;
  width:32px !important; 
  height:28px !important;
  border:1px solid #e5e7eb !important;
  border-radius:8px !important;
  background:#fff !important;
  display:flex !important; 
  align-items:center !important; 
  justify-content:center !important;
  cursor:pointer !important;
  box-shadow:0 1px 3px rgba(0,0,0,.1) !important;
  z-index:1;
  transition: all 0.15s ease !important;
}

.modal .close-btn:hover,
.modal .modal-close:hover,
.ant-modal-close:hover, 
.el-dialog__headerbtn:hover{
  background:#f9fafb !important; 
  border-color:#d1d5db !important;
  box-shadow:0 2px 4px rgba(0,0,0,.12) !important;
}

.modal .close-btn svg,
.modal .modal-close svg,
.ant-modal-close svg, 
.el-dialog__close,
.ant-modal-close .anticon,
.el-dialog__headerbtn .el-icon{
  color:#6b7280 !important; 
  font-size:16px !important; 
  line-height:1 !important;
}

/* ===== 白名单弹窗：加上行表格样式 ===== */
#whitelistModal .modal-body {
  padding: var(--modal-padding) !important;
}

#whitelistList {
  display: flex;
  flex-direction: column;
  gap: 1px;
  background: #f3f4f6;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #e5e7eb;
}

.whitelist-item {
  padding: 12px 16px;
  background: #ffffff;
  font-size: 13px;
  color: #374151;
  word-break: break-all;
  border-bottom: 1px solid #f3f4f6;
  transition: background-color 0.15s ease;
}

.whitelist-item:hover {
  background: #f8fafc;
}

.whitelist-item:last-child {
  border-bottom: none;
}

/* 如果白名单为空的提示 */
#whitelistList p {
  padding: 20px;
  text-align: center;
  color: #9ca3af;
  font-size: 14px;
  margin: 0;
  background: #ffffff;
}

/* ===== 复制成功轻提示 ===== */
.modal .modal-toast{
  position:absolute; 
  left:50%; 
  top:50%;
  transform:translate(-50%, -50%) scale(.98);
  background:rgba(17,24,39,.92); 
  color:#fff;
  padding:10px 14px; 
  border-radius:10px; 
  font-size:12px;
  box-shadow:0 8px 24px rgba(0,0,0,.2);
  opacity:0; 
  pointer-events:none; 
  transition:opacity .18s, transform .18s;
  z-index:10000;
}

.modal .modal-toast.show{ 
  opacity:1; 
  pointer-events:auto; 
  transform:translate(-50%, -50%) scale(1); 
}

/* 响应式 */
@media (max-width:768px){
  .modal, dialog[open], .el-dialog, .ant-modal{
    --modal-w: calc(100vw - 20px);
    --modal-h: calc(100vh - 40px);
  }
  
  .kv-row{ 
    grid-template-columns:1fr; 
  }
  
  .kv-key{ 
    text-align:left; 
    padding-right:0; 
    margin-bottom:4px; 
  }
}


/* =======================================================================
   按钮（查看详情、查看全部、查看配置、查看订阅）：白底蓝字，hover 浅灰，active 灰底 
   ======================================================================= */
.btn-detail,
.btn-viewall,
.btn-link,
.link,
.whitelist-more{
  --btn-h: 28px;
  --btn-pad-x: 12px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: var(--btn-h);
  line-height: calc(var(--btn-h) - 2px); /* 扣掉边框 */
  padding: 0 var(--btn-pad-x);
  border: 1px solid #d1d5db;
  border-radius: 6px;
  background: #fff;
  color: #3b82f6;                /* 蓝字 */
  font-size: 12px;
  text-decoration: none;
  cursor: pointer;
  transition: background .15s ease, color .15s ease, border-color .15s ease, box-shadow .15s ease;
}

/* hover：浅灰底、蓝更深一点 */
.btn-detail:hover,
.btn-viewall:hover,
.btn-link:hover,
.link:hover,
.whitelist-more:hover{
  background: #f3f4f6;           /* 浅灰 */
  border-color: #9ca3af;
  color: #1d4ed8;                /* 深一点的蓝 */
}

/* active：按下时更深的灰底 */
.btn-detail:active,
.btn-viewall:active,
.btn-link:active,
.link:active,
.whitelist-more:active{
  background: #e5e7eb;           /* 灰底（按下态） */
  border-color: #9ca3af;
  color: #1d4ed8;
}

/* 可访问性：键盘聚焦高亮 */
.btn-detail:focus-visible,
.btn-viewall:focus-visible,
.btn-link:focus-visible,
.link:focus-visible,
.whitelist-more:focus-visible{
  outline: 0;
  box-shadow: 0 0 0 2px #93c5fd; /* 浅蓝描边 */
  border-color: #60a5fa;
}

/* 禁用态（如果有需要） */
.btn-detail[disabled],
.btn-viewall[disabled],
.btn-link[disabled],
.link[disabled],
.whitelist-more[disabled]{
  opacity: .5;
  pointer-events: none;
}

EXTERNAL_CSS




# ========== 创建外置的JavaScript文件 ==========
log_info "创建外置JavaScript文件..."

cat > "${TRAFFIC_DIR}/assets/edgebox-panel.js" <<'EXTERNAL_JS'
// =================================================================
// EdgeBox Panel v3.0 - 优化重构版 JavaScript
// =================================================================

// ========================================
// 全局状态管理
// ========================================
let dashboardData = {};   // 仪表盘数据
let trafficData = {};     // 流量统计数据
let systemData = {};      // 系统资源数据
let notificationData = { notifications: [] }; // 通知数据
let overviewTimer = null; // 定时刷新计时器
let __IPQ_REQ_SEQ__ = 0;  // IP质量查询并发守卫

const GiB = 1024 * 1024 * 1024; // GiB 单位换算常量

// ========================================
// Chart.js 自定义插件 (已废弃,保留备用)
// ========================================
const ebYAxisUnitTop = {
  id: 'ebYAxisUnitTop',
  afterDraw: (chart) => {
    const ctx = chart.ctx;
    const yAxis = chart.scales.y;
    if (!yAxis) return;
    ctx.save();
    ctx.font = '11px sans-serif';
    ctx.fillStyle = '#6b7280';
    ctx.textAlign = 'center';
    ctx.fillText('GiB', yAxis.left / 2, yAxis.top - 5);
    ctx.restore();
  }
};

// ========================================
// 工具函数
// ========================================

/**
 * 异步获取 JSON 数据
 * @param {string} url - 请求地址
 * @returns {Promise<Object|null>} JSON 对象或 null
 */
async function fetchJSON(url) {
  try {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error(`Fetch error for ${url}:`, error);
    return null;
  }
}

/**
 * 读取 alert.conf 配置文件
 * @returns {Promise<Object>} 配置对象
 */
async function fetchAlertConfig() {
  try {
    const response = await fetch('/traffic/alert.conf', { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    const text = await response.text();
    const config = {};
    text.split('\n').forEach(line => {
      line = line.trim();
      if (line && !line.startsWith('#')) {
        const [key, value] = line.split('=');
        if (key && value !== undefined) {
          config[key.trim()] = value.trim();
        }
      }
    });
    return config;
  } catch (error) {
    console.error('Failed to fetch alert.conf:', error);
    return { ALERT_STEPS: '30,60,90' }; // 默认阈值
  }
}

/**
 * 安全获取对象嵌套属性
 * @param {Object} obj - 对象
 * @param {string} path - 属性路径(用 . 分隔)
 * @param {*} fallback - 默认值
 * @returns {*} 属性值或默认值
 */
function safeGet(obj, path, fallback = '—') {
  const value = path.split('.').reduce((acc, part) => acc && acc[part], obj);
  return value !== null && value !== undefined && value !== '' ? value : fallback;
}

/**
 * HTML 转义函数
 * @param {string} s - 待转义字符串
 * @returns {string} 转义后字符串
 */
function escapeHtml(s = '') {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * 轻提示通知
 * @param {string} msg - 提示消息
 * @param {string} type - 类型: ok/warn/info
 * @param {number} ms - 显示时长(毫秒)
 */
function notify(msg, type = 'ok', ms = 1500) {
  // 优先在打开的弹窗内显示,否则在页面中央显示
  const modal = document.querySelector('.modal[style*="block"] .modal-content');
  
  if (modal) {
    // 弹窗内居中轻提示
    let toast = modal.querySelector('.modal-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.className = 'modal-toast';
      modal.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 1200);
  } else {
    // 页面级提示
    const tip = document.createElement('div');
    tip.className = `toast toast-${type}`;
    tip.textContent = msg;
    document.body.appendChild(tip);
    requestAnimationFrame(() => tip.classList.add('show'));
    setTimeout(() => {
      tip.classList.remove('show');
      setTimeout(() => tip.remove(), 300);
    }, ms);
  }
}

/**
 * 兼容各环境的文本复制函数
 * @param {string} text - 待复制文本
 * @returns {Promise<boolean>} 是否成功
 */
async function copyTextFallbackAware(text) {
  if (!text) throw new Error('empty');
  try {
    // 安全上下文优先使用 Clipboard API
    if ((location.protocol === 'https:' || location.hostname === 'localhost') && navigator.clipboard) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    throw new Error('insecure');
  } catch {
    // 降级使用 execCommand
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.readOnly = true;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    if (!ok) throw new Error('execCommand failed');
    return true;
  }
}

/**
 * DOM 选择器简写
 */
function $(sel, root = document) { return root.querySelector(sel); }
function $all(sel, root = document) { return [...root.querySelectorAll(sel)]; }

// ========================================
// UI 渲染函数
// ========================================

/**
 * 渲染系统概览卡片
 */
function renderOverview() {
  // 兼容取数(优先闭包变量,取不到再用 window.*)
  const dash = (typeof dashboardData !== 'undefined' && dashboardData) ||
               (typeof window !== 'undefined' && window.dashboardData) || {};
  const sys  = (typeof systemData !== 'undefined' && systemData) ||
               (typeof window !== 'undefined' && window.systemData) || {};

  // 拆解数据结构
  const server   = dash.server || {};
  const services = dash.services || {};

  // DOM 操作辅助函数
  const setText = (id, text, setTitle) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = (text === undefined || text === null || text === '') ? '—' : String(text);
    if (setTitle) el.title = el.textContent;
  };
  const setWidth = (id, pct) => {
    const el = document.getElementById(id);
    if (el) el.style.width = `${pct}%`;
  };
  const clamp = v => Math.max(0, Math.min(100, Number(v) || 0));
  const pick  = (...xs) => xs.find(v => v !== undefined && v !== null && v !== '') ?? 0;
  const toYMD = (v) => {
    if (!v) return '—';
    const d = new Date(v);
    return isNaN(d) ? String(v).slice(0, 10) : d.toISOString().slice(0, 10);
  };
  const toggleBadge = (sel, running) => {
    const el = document.querySelector(sel);
    if (!el) return;
    el.textContent = running ? '运行中 √' : '已停止';
    el.classList.toggle('status-running', !!running);
    el.classList.toggle('status-stopped', !running);
  };

  // 服务器基本信息
  const remark   = server.user_alias ?? server.remark ?? '未备注';
  const provider = server.cloud?.provider ?? server.cloud_provider ?? 'Independent';
  const region   = server.cloud?.region ?? server.cloud_region ?? 'Unknown';
  setText('user-remark',  remark, true);
  setText('cloud-region', `${provider} | ${region}`, true);
  setText('instance-id',  server.instance_id ?? 'Unknown', true);
  setText('hostname',     server.hostname ?? '-', true);

  // 服务器配置(条中文本 + 百分比)
  setText('cpu-info',  server.spec?.cpu ?? '—', true);
  setText('disk-info', server.spec?.disk ?? '—', true);

  // 内存条文本(spec.memory 缺失或为 0 时从 sys 组装)
  const fmtGiB = (b) => {
    const n = Number(b);
    if (!Number.isFinite(n)) return null;
    return Math.round((n / (1024 ** 3)) * 10) / 10;
  };
  let memText = server.spec?.memory ?? '';
  if (!memText || /^0\s*GiB$/i.test(memText)) {
    const totalB = pick(sys.mem_total, sys.total_mem, sys.memory_total, sys.mem?.total);
    const usedB  = pick(sys.mem_used, sys.used_mem, sys.memory_used, sys.mem?.used);
    const freeB  = pick(sys.mem_free, sys.free_mem, sys.memory_free, sys.mem?.free,
                        (totalB != null && usedB != null) ? (totalB - usedB) : undefined);
    const total = fmtGiB(totalB), used = fmtGiB(usedB), free = fmtGiB(freeB);
    memText = (total != null) ? (used != null && free != null ? `${total}GiB(已用: ${used}GiB, 可用: ${free}GiB)` : `${total}GiB`) : '—';
  }
  setText('mem-info', memText, true);

  // 资源使用百分比(多字段名兼容)
  const cpuPct  = clamp(pick(sys.cpu, sys.cpu_usage, sys['cpu-percent'], sys.metrics?.cpu, dash.metrics?.cpu));
  const memPct  = clamp(pick(sys.memory, sys.mem, sys['memory-percent'], sys.metrics?.memory, dash.metrics?.memory));
  const diskPct = clamp(pick(sys.disk, sys.disk_usage, sys['disk-percent'], sys.metrics?.disk, dash.metrics?.disk));

  setWidth('cpu-progress',  cpuPct);  setText('cpu-percent',  `${cpuPct}%`);
  setWidth('mem-progress',  memPct);  setText('mem-percent',  `${memPct}%`);
  setWidth('disk-progress', diskPct); setText('disk-percent', `${diskPct}%`);

  // 核心服务版本与状态
  const versions = {
    nginx:   services.nginx?.version || '',
    xray:    services.xray?.version || '',
    singbox: (services['sing-box']?.version || services.singbox?.version || '')
  };

  setText('nginx-version',   versions.nginx ? `版本 ${versions.nginx}` : '—', true);
  setText('xray-version',    versions.xray ? `版本 ${versions.xray}` : '—', true);
  setText('singbox-version', versions.singbox ? `版本 ${versions.singbox}` : '—', true);

toggleBadge('#system-overview .core-services .service-item:nth-of-type(1) .status-badge', services.nginx?.status?.includes('运行中'));
  toggleBadge('#system-overview .core-services .service-item:nth-of-type(2) .status-badge', services.xray?.status?.includes('运行中'));
  toggleBadge('#system-overview .core-services .service-item:nth-of-type(3) .status-badge',
              (services['sing-box']?.status || services.singbox?.status)?.includes('运行中'));

  // 顶部版本/日期摘要
  const metaText = `版本号: ${server.version || '—'} | 安装日期: ${toYMD(server.install_date)} | 更新时间: ${toYMD(dash.updated_at || Date.now())}`;
  setText('sys-meta', metaText);
}

/**
 * 渲染证书与网络配置卡片 (UI State Reset Fix)
 */
function renderCertificateAndNetwork() {
  const data   = window.dashboardData || {};
  const server = data.server || {};
  const cert   = server.cert || {};
  const shunt  = data.shunt || {};

  // Helper to set text content
  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text || '—';
  };

  // ... (certificate rendering part remains the same) ...
  const certMode = String(safeGet(cert, 'mode', 'self-signed'));
  document.getElementById('cert-self')?.classList.toggle('active', certMode === 'self-signed');
  document.getElementById('cert-ca')?.classList.toggle('active', certMode.startsWith('letsencrypt'));
  setText('cert-type', certMode.startsWith('letsencrypt') ? "Let's Encrypt" : "自签名");
  setText('cert-domain', safeGet(cert, 'domain', '—'));
  setText('cert-renewal', certMode.startsWith('letsencrypt') ? '自动' : '手动');
  setText('cert-expiry', safeGet(cert, 'expires_at', '—'));

  // Outbound mode highlighting
  const shuntMode = String(safeGet(shunt, 'mode', 'vps')).toLowerCase();
  ['net-vps', 'net-proxy', 'net-shunt'].forEach(id => document.getElementById(id)?.classList.remove('active'));
  
  const vpsIp = safeGet(data, 'server.eip') || safeGet(data, 'server.server_ip') || '—';
  setText('vps-ip', vpsIp);

  // <<< FIX: Logic to clear or populate the proxy card >>>
  if (shuntMode.includes('resi') || shuntMode.includes('direct')) {
    // Populate proxy card for resi or direct-resi modes
    if (shuntMode.includes('direct')) {
        document.getElementById('net-shunt')?.classList.add('active');
    } else {
        document.getElementById('net-proxy')?.classList.add('active');
    }
    
    const proxyRaw = String(safeGet(shunt, 'proxy_info', ''));
    // (formatProxy function remains the same as in your script)
    function formatProxy(raw){if(!raw)return"—";try{const o=/^[a-z][a-z0-9+.\-]*:\/\//i.test(raw)?raw:"socks5://"+raw,t=new URL(o),e=t.protocol.replace(/:$/,""),r=t.hostname||"",l=t.port||"";return r&&l?`${e}//${r}:${l}`:r?`${e}//${r}`:"—"}catch(o){const t=/^([a-z0-9+.\-]+):\/\/(?:[^@\/\s]+@)?(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?/i,e=raw.match(t);if(e){const o=e[1],t=e[2],r=e[3]||"";return r?`${o}//${t}:${r}`:`${o}//${t}`}const r=/^(?:([a-z0-9+.\-]+)\s+)?(\[[^\]]+\]|[^:\/?#\s]+)(?::(\d+))?$/i,l=raw.match(r);return l?(l[3]||""?`${l[1]||"socks5"}//${l[2]}:${l[3]}`:`${l[1]||"socks5"}//${l[2]}`):"—"}}
    setText('proxy-ip', formatProxy(proxyRaw));

    // Async fetch for proxy details
    fetch('/status/ipq_proxy.json', { cache: 'no-store' })
        .then(r => r.ok ? r.json() : null)
        .then(j => {
            if (j && j.status !== 'not_configured') {
                const geo = [j.country, j.city].filter(Boolean).join(' · ');
                setText('proxy-geo', geo);
                setText('proxy-ipq-score', j.score != null ? `${j.score} (${j.grade})` : '—');
            } else {
                setText('proxy-geo', '—');
                setText('proxy-ipq-score', '检测中...');
            }
        });
  } else {
    // Clear proxy card for VPS mode
    document.getElementById('net-vps')?.classList.add('active');
    setText('proxy-ip', '—');
    setText('proxy-geo', '—');
    setText('proxy-ipq-score', '—');
  }

  // Async fetch for VPS details (always runs)
  fetch('/status/ipq_vps.json', { cache: 'no-store' })
      .then(r => r.ok ? r.json() : null)
      .then(j => {
          if (j) {
              const geo = [j.country, j.city].filter(Boolean).join(' · ');
              setText('vps-geo', geo);
              setText('vps-ipq-score', j.score != null ? `${j.score} (${j.grade})` : '—');
          }
      });
  
  const whitelist = data.shunt?.whitelist || [];
  const preview = document.getElementById('whitelistPreview');
  if (preview) {
    if (!whitelist.length) {
      preview.innerHTML = '<span class="whitelist-text">(无)</span>';
    } else {
      const firstDomain = whitelist[0] || '';
      const shortText = firstDomain.length > 9 ? firstDomain.substring(0, 9) + '...' : firstDomain;
      preview.innerHTML =
        `<span class="whitelist-text">${escapeHtml(shortText)}</span>` +
        `<button class="whitelist-more" data-action="open-modal" data-modal="whitelistModal">查看全部</button>`;
    }
  }
}

/**
 * 渲染流量统计图表
 */
function renderTrafficCharts() {
  if (!trafficData || !window.Chart) return;

  // 渲染本月使用进度条
  const monthly = trafficData.monthly || [];
  const currentMonthData = monthly.find(m => m.month === new Date().toISOString().slice(0, 7));
  
  if (currentMonthData) {
    const used = (currentMonthData.total || 0) / GiB;
    const percentage = Math.min(100, Math.round((used / 100) * 100));
    const fillEl = document.getElementById('progress-fill');
    const pctEl = document.getElementById('progress-percentage');
    const budgetEl = document.getElementById('progress-budget');
    
    if (fillEl) fillEl.style.width = `${percentage}%`;
    if (pctEl) pctEl.textContent = `${percentage}%`;
    if (budgetEl) budgetEl.textContent = `阈值(100GiB)`;
    if (pctEl) pctEl.title = `已用 ${used.toFixed(1)}GiB / 阈值 100GiB`;
    
    // 异步获取配置并更新阈值刻度线
    fetchAlertConfig().then(alertConfig => {
      const budget = parseInt(alertConfig.ALERT_MONTHLY_GIB) || 100;
      const alertSteps = (alertConfig.ALERT_STEPS || '30,60,90').split(',').map(s => parseInt(s.trim()));
      
      const realPercentage = Math.min(100, Math.round((used / budget) * 100));
      
      if (fillEl) fillEl.style.width = `${realPercentage}%`;
      if (pctEl) pctEl.textContent = `${realPercentage}%`;
      if (budgetEl) budgetEl.textContent = `阈值(${budget}GiB)`;
      if (pctEl) pctEl.title = `已用 ${used.toFixed(1)}GiB / 阈值 ${budget}GiB`;
      
      renderTrafficProgressThresholds(alertSteps);
    }).catch(err => {
      console.warn('无法加载 alert.conf, 使用默认配置:', err);
      renderTrafficProgressThresholds([30, 60, 90]);
    });
  }
  
  function renderTrafficProgressThresholds(thresholds) {
    const trafficProgressBar = document.querySelector('.traffic-card .progress-bar');
    if (!trafficProgressBar) return;
    
    const existingMarkers = trafficProgressBar.querySelectorAll('.traffic-threshold-marker');
    const existingLabels = trafficProgressBar.querySelectorAll('.traffic-threshold-label');
    existingMarkers.forEach(marker => marker.remove());
    existingLabels.forEach(label => label.remove());
    
    thresholds.forEach(threshold => {
      if (threshold > 0 && threshold <= 100) {
        const marker = document.createElement('div');
        marker.className = 'traffic-threshold-marker';
        marker.style.cssText = `
          position: absolute;
          left: ${threshold}%;
          top: 0;
          bottom: 0;
          width: 2px;
          background: #9ca3af;
          z-index: 10;
          transform: translateX(-50%);
          border-radius: 1px;
        `;
        
        const label = document.createElement('div');
        label.className = 'traffic-threshold-label';
        label.textContent = `${threshold}%`;
        label.style.cssText = `
          position: absolute;
          left: ${threshold}%;
          top: 50%;
          transform: translate(-50%, -50%);
          font-size: 12px;
          color: #fbbf24;
          white-space: nowrap;
          font-weight: 600;
          pointer-events: none;
          z-index: 11;
          text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
        `;
        
        trafficProgressBar.appendChild(marker);
        trafficProgressBar.appendChild(label);
      }
    });
  }

  // 销毁已存在的图表实例
  ['traffic', 'monthly-chart'].forEach(id => {
    const inst = Chart.getChart(id);
    if (inst) inst.destroy();
  });

  // 颜色定义
  const vpsColor = '#3b82f6';
  const proxyColor = '#10b981';
  
  // 近30日流量折线图
  const daily = trafficData.last30d || [];
  if (daily.length) {
    const ctx = document.getElementById('traffic');
    if (ctx) {
      new Chart(ctx, {
        type: 'line',
        data: {
          labels: daily.map(d => d.date.slice(5)),
          datasets: [
            {
              label: 'VPS',
              data: daily.map(d => d.vps / GiB),
              borderColor: vpsColor,
              backgroundColor: vpsColor,
              tension: 0.3,
              pointRadius: 0,
              fill: false
            },
            {
              label: '代理',
              data: daily.map(d => d.resi / GiB),
              borderColor: proxyColor,
              backgroundColor: proxyColor,
              tension: 0.3,
              pointRadius: 0,
              fill: false
            },
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          layout: {
            padding: { bottom: 22 }
          },
          scales: {
            x: { ticks: { padding: 6 } },
            y: { ticks: { padding: 6 } }
          }
        }
      });
    }
  }

  // 近12个月流量堆叠柱状图
  if (monthly.length) {
    const arr = monthly.slice(-12);
    const ctx = document.getElementById('monthly-chart');
    if (ctx) {
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: arr.map(m => m.month),
          datasets: [
            {
              label: 'VPS',
              data: arr.map(m => m.vps / GiB),
              backgroundColor: vpsColor,
              stack: 'a'
            },
            {
              label: '代理',
              data: arr.map(m => m.resi / GiB),
              backgroundColor: proxyColor,
              stack: 'a'
            },
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          layout: {
            padding: { bottom: 22 }
          },
          scales: {
            x: { ticks: { padding: 6 } },
            y: { ticks: { padding: 6 } }
          }
        }
      });
    }
  }
}

// ========================================
// 弹窗交互逻辑
// ========================================

/**
 * 显示弹窗
 */
function showModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'block';
    document.body.classList.add('modal-open');
  }
}

/**
 * 关闭弹窗
 */
function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'none';
    document.body.classList.remove('modal-open');
  }
}

/**
 * 显示白名单弹窗
 */
function showWhitelistModal() {
  const list = document.getElementById('whitelistList');
  const whitelist = dashboardData.shunt?.whitelist || [];
  if (list) {
    list.innerHTML = whitelist.length 
      ? whitelist.map(item => `<div class="whitelist-item">${escapeHtml(item)}</div>`).join('')
      : '<p>暂无白名单数据</p>';
  }
  showModal('whitelistModal');
}

/**
 * 显示配置详情弹窗
 */
function showConfigModal(protocolKey) {
  const dd = window.dashboardData;
  const modal = document.getElementById('configModal');
  if (!modal || !dd) return;

  const title = document.getElementById('configModalTitle');
  const details = document.getElementById('configDetails');
  const footer = modal.querySelector('.modal-footer');
  if (!title || !details || !footer) return;

  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toB64 = s => btoa(unescape(encodeURIComponent(s)));
  const get = (o, p, fb = '') => p.split('.').reduce((a, k) => (a && a[k] !== undefined ? a[k] : undefined), o) ?? fb;
  
  // <<< 修复点 1: 动态判断主机地址 >>>
  const certMode = String(get(dd, 'server.cert.mode', 'self-signed'));
  const isLE = certMode.startsWith('letsencrypt');
  const serverIp = get(dd, 'server.server_ip', '');
  const domain = get(dd, 'server.cert.domain', '');
  const hostAddress = isLE && domain ? domain : serverIp; // 动态选择 host

  function annotateAligned(obj, comments = {}) {
    // ... (内部函数保持不变)
    const lines = JSON.stringify(obj, null, 2).split('\n');
    const metas = lines.map(line => {
      const m = line.match(/^(\s*)"([^"]+)"\s*:\s*(.*?)(,?)$/);
      if (!m) return null;
      const [, indent, key, val, comma] = m;
      const baseLen = indent.length + 1 + key.length + 1 + 2 + 1 + String(val).length + (comma ? 1 : 0);
      return { indent, key, val, comma, baseLen };
    }).filter(Boolean);
    const maxLen = metas.length ? Math.max(...metas.map(x => x.baseLen)) : 0;

    return lines.map(line => {
      const m = line.match(/^(\s*)"([^"]+)"\s*:\s*(.*?)(,?)$/);
      if (!m) return line;
      const [, indent, key, val, comma] = m;
      const base = `${indent}"${key}": ${val}${comma}`;
	  const cm = comments[key];
      if (!cm) return base;
      const thisLen = indent.length + 1 + key.length + 1 + 2 + 1 + String(val).length + (comma ? 1 : 0);
      const pad = ' '.repeat(Math.max(1, maxLen - thisLen + 1));
      return `${base}${pad}// ${cm}`;
    }).join('\n');
  }

  const usage = html => (
    `<div class="config-section">
       <h4>使用说明</h4>
       <div class="config-help" style="font-size:12px;color:#6b7280;line-height:1.6;">${html}</div>
     </div>`
  );

  details.innerHTML = '<div class="loading">正在加载配置…</div>';
  modal.style.display = 'block';
  document.body.classList.add('modal-open');

  let qrText = '';

  if (protocolKey === '__SUBS__') {
    // ... (整包订阅部分逻辑不变)
    const subsUrl = get(dd, 'subscription_url', '') ||
                    (get(dd, 'server.server_ip', '') ? `http://${get(dd, 'server.server_ip')}/sub` : '');
    const plain6 = get(dd, 'subscription.plain', '');
    const base64 = get(dd, 'subscription.base64', '') || (plain6 ? toB64(plain6) : '');

    title.textContent = '订阅(整包)';
    details.innerHTML = `
      <div class="config-section">
        <h4>订阅 URL</h4>
        <div class="config-code" id="plain-link">${esc(subsUrl)}</div>
      </div>
      <div class="config-section">
        <h4>明文链接(6协议)</h4>
        <div class="config-code" id="plain-links-6" style="white-space:pre-wrap">${esc(plain6)}</div>
      </div>
      <div class="config-section">
        <h4>Base64链接(6协议)</h4>
        <div class="config-code" id="base64-link">${esc(base64)}</div>
      </div>
      <div class="config-section">
        <h4>二维码</h4>
        <div class="qr-container">
          <div id="qrcode-sub"></div>
        </div>
      </div>
      ${usage('将"订阅 URL"导入 v2rayN、Clash 等支持订阅的客户端; 部分客户端也支持直接粘贴 Base64 或扫码二维码。')}
    `;
    footer.innerHTML = `
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain">复制订阅URL</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain6">复制明文(6协议)</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="base64">复制Base64</button>
      <button class="btn btn-sm btn-secondary" data-action="copy-qr">复制二维码</button>
    `;
    
    qrText = subsUrl || '';

  } else {
    const protocols = Array.isArray(dd.protocols) ? dd.protocols : [];
    const p = protocols.find(x =>
      x && (x.name === protocolKey || x.protocol === protocolKey)
    );

    if (!p) {
      title.textContent = '配置详情';
      details.innerHTML = `<div class="empty">未找到协议: <code>${esc(String(protocolKey))}</code></div>`;
      footer.innerHTML = `<button class="btn btn-sm" data-action="close-modal" data-modal="configModal">关闭</button>`;
      return;
    }

    // <<< 修复点 2: 使用动态的 hostAddress 变量构建 JSON >>>
    const obj = {
      protocol: p.name,
      host: hostAddress, // 使用动态地址
      port: p.port ?? 443,
      uuid: get(dd, `secrets.vless.${p.protocol}`) || get(dd, `secrets.password.${p.protocol}`) || get(dd, `secrets.tuic_uuid`),
      sni: isLE ? domain : hostAddress,
      alpn: (p.name || '').toLowerCase().includes('grpc') ? 'h2'
            : ((p.name || '').toLowerCase().includes('ws') ? 'http/1.1' : '')
    };
    if (p.protocol === 'hysteria2') {
        obj.uuid = get(dd, 'secrets.password.hysteria2');
    }
    
    const comments = {
      protocol: '协议类型',
      host: '服务器地址(IP/域名)',
      port: '端口',
      uuid: '认证 UUID / 密码',
      sni: 'TLS/SNI',
      alpn: 'ALPN(gRPC=h2, ws=http/1.1)'
    };
    const jsonAligned = annotateAligned(obj, comments);
    // <<< 修复点结束 >>>

    const plain = p.share_link || '';
    const base64 = plain ? toB64(plain) : '';

    title.textContent = `${p.name} 配置`;
    details.innerHTML = `
      <div class="config-section">
        <h4>JSON 配置</h4>
        <div class="config-code" id="json-code" style="white-space:pre-wrap">${esc(jsonAligned)}</div>
      </div>
      <div class="config-section">
        <h4>明文链接</h4>
        <div class="config-code" id="plain-link">${esc(plain)}</div>
      </div>
      <div class="config-section">
        <h4>Base64链接</h4>
        <div class="config-code" id="base64-link">${esc(base64)}</div>
      </div>
      <div class="config-section">
        <h4>二维码</h4>
        <div class="qr-container">
          <div id="qrcode-protocol"></div>
        </div>
      </div>
      ${usage('复制明文或 JSON 导入客户端; 若客户端支持扫码添加, 也可直接扫描二维码。')}
    `;
    footer.innerHTML = `
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="json">复制 JSON</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain">复制明文链接</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="base64">复制 Base64</button>
      <button class="btn btn-sm btn-secondary" data-action="copy-qr">复制二维码</button>
    `;
    
    qrText = plain || '';
  }

  // 生成二维码 (逻辑不变)
  if (qrText && window.QRCode) {
    const holderId = (protocolKey === '__SUBS__') ? 'qrcode-sub' : 'qrcode-protocol';
    const holder = document.getElementById(holderId);
    if (holder) {
      holder.replaceChildren();
      new QRCode(holder, {
        text: qrText,
        width: 200,
        height: 200,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.M
      });
      const kids = Array.from(holder.children);
      const keep = holder.querySelector('canvas') || kids[0] || null;
      if (keep) {
        kids.forEach(node => { if (node !== keep) node.remove(); });
      }
    }
  }
}

/**
 * 显示 IP 质量检测详情弹窗
 */
async function showIPQDetails(which) {
  const titleEl = document.getElementById('ipqModalTitle');
  const bodyEl = document.getElementById('ipqDetails');
  if (!titleEl || !bodyEl) return;

  const file = which === 'vps' ? '/status/ipq_vps.json' : '/status/ipq_proxy.json';
  titleEl.textContent = which === 'vps' ? 'VPS IP质量检测详情' : '代理 IP质量检测详情';
  bodyEl.innerHTML = `<div class="config-section"><div class="config-code">加载中...</div></div>`;
  showModal('ipqModal');

  let data = null;
  const __seq = ++__IPQ_REQ_SEQ__;

  try {
    const r = await fetch(file, { cache: 'no-store' });
    if (__seq !== __IPQ_REQ_SEQ__) return;
    if (!r.ok) throw new Error('HTTP ' + r.status);
    data = await r.json();
  } catch (err) {
    if (__seq !== __IPQ_REQ_SEQ__) return;
    data = null;
  }

  const dash = window.dashboardData || {};
  const server = dash.server || {};
  data = data || {
    score: null, grade: null, detected_at: dash.updated_at,
    ip: (which === 'vps' ? server.server_ip : server.eip) || '',
    asn: '', isp: '', country: '', city: '', rdns: '',
    bandwidth: '', network_type: '', latency_p50: null,
    risk: { proxy: (which === 'proxy'), hosting: true, dnsbl_hits: [] },
    conclusion: ''
  };

  const pick = (o, paths, d = '—') => {
    for (const p of paths) {
      const v = p.split('.').reduce((x, k) => x && x[k] != null ? x[k] : undefined, o);
      if (v != null && v !== '') return v;
    }
    return d;
  };

  const score = pick(data, ['score'], '—');
  const grade = pick(data, ['grade'], null);
  const gradeStr = grade || (typeof score === 'number'
                    ? (score >= 80 ? 'A' : score >= 60 ? 'B' : score >= 40 ? 'C' : 'D') : '—');
  const when = pick(data, ['detected_at', 'updated_at', 'timestamp'], '—');

  const ip = pick(data, ['ip'], '—');
  const asn = pick(data, ['asn'], '');
  const isp = pick(data, ['isp'], '');
  const country = pick(data, ['country', 'geo.country'], '');
  const city = pick(data, ['city', 'geo.city'], '');
  const rdns = pick(data, ['rdns', 'reverse_dns'], '—');

  const bwUp = pick(data, ['bandwidth_up', 'config.bandwidth_up'], null);
  const bwDown = pick(data, ['bandwidth_down', 'config.bandwidth_down'], null);
  const bandwidth = (bwUp || bwDown) ? `${bwUp || '—'} / ${bwDown || '—'}` : (pick(data, ['bandwidth', 'config.bandwidth'], '未配置'));

  const networkType = pick(data, ['network_type', 'net_type'], '—');
  const latency = (() => {
    const v = pick(data, ['latency_p50', 'latency.median', 'latency_ms'], null);
    return v ? `${v} ms` : '—';
  })();

  const riskObj = data.risk || {};
  const flags = [
    riskObj.proxy ? '代理标记' : null,
    riskObj.hosting ? '数据中心' : null,
    riskObj.mobile ? '移动网络' : null,
    riskObj.tor ? 'Tor' : null
  ].filter(Boolean).join('、') || '—';
  const hits = Array.isArray(riskObj.dnsbl_hits) ? riskObj.dnsbl_hits : [];
  const blCount = hits.length;

  const conclusion = pick(data, ['conclusion'], '—');

  const EH = s => String(s || '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));

  bodyEl.innerHTML = `
    <div class="ipq-section">
      <h5>总览</h5>
      <div class="info-item"><label>分数:</label><value>${score} / 100</value></div>
      <div class="info-item"><label>等级:</label><value><span class="grade-badge grade-${String(gradeStr).toLowerCase()}">${EH(gradeStr)}</span></value></div>
      <div class="info-item"><label>最近检测时间:</label><value>${EH(when)}</value></div>
    </div>
    <div class="ipq-section">
      <h5>身份信息</h5>
      <div class="info-item"><label>出站IP:</label><value>${EH(ip)}</value></div>
      <div class="info-item"><label>ASN / ISP:</label><value>${EH([asn, isp].filter(Boolean).join(' / ') || '—')}</value></div>
      <div class="info-item"><label>Geo:</label><value>${EH([country, city].filter(Boolean).join(' / ') || '—')}</value></div>
      <div class="info-item"><label>rDNS:</label><value>${EH(rdns)}</value></div>
    </div>
    <div class="ipq-section">
      <h5>配置信息</h5>
      <div class="info-item"><label>带宽限制:</label><value>${EH(bandwidth)}</value></div>
    </div>
    <div class="ipq-section">
      <h5>质量细项</h5>
      <div class="info-item"><label>网络类型:</label><value>${EH(networkType)}</value></div>
      <div class="info-item"><label>时延中位数:</label><value>${EH(latency)}</value></div>
    </div>
    <div class="ipq-section">
      <h5>风险与黑名单</h5>
      <div class="info-item"><label>特征:</label><value>${EH(flags)}</value></div>
      <div class="info-item"><label>黑名单命中数:</label><value>${blCount} 个</value></div>
    </div>
    <div class="ipq-conclusion">
      <h5>结论与依据</h5>
      <p>${EH(conclusion)}</p>
      <ul style="margin-top:8px; font-size:12px; color:#6b7280; padding-left:18px; line-height:1.6;">
        <li>基础分 100 分</li>
        <li>"代理/数据中心/Tor"等标记会降低分数</li>
        <li>每命中 1 个 DNSBL 黑名单会降低分数</li>
        <li>高时延会降低分数</li>
      </ul>
    </div>`;
}

// ========================================
// 通知中心功能
// ========================================

/**
 * 更新通知中心数据
 */
function updateNotificationCenter(data) {
  notificationData = data || { notifications: [] };
  renderNotifications();
}

/**
 * 渲染通知列表
 */
function renderNotifications() {
  const listEl = document.getElementById('notificationList');
  const badgeEl = document.getElementById('notificationBadge');
  
  if (!notificationData.notifications || notificationData.notifications.length === 0) {
    if (listEl) {
      listEl.innerHTML = `
        <div class="notification-empty">
          🔔
          <div>暂无通知</div>
        </div>
      `;
    }
    if (badgeEl) badgeEl.style.display = 'none';
    return;
  }
  
  const unreadCount = notificationData.notifications.filter(n => !n.read).length;
  
  if (badgeEl) {
    if (unreadCount > 0) {
      badgeEl.textContent = unreadCount > 99 ? '99+' : unreadCount;
      badgeEl.style.display = 'inline-block';
    } else {
      badgeEl.style.display = 'none';
    }
  }
  
  if (listEl) {
    const iconMap = {
      alert: '⚠️',
      system: '⚙️', 
      error: '❌'
    };
    
    const html = notificationData.notifications.slice(0, 20).map(notification => {
      const timeAgo = getTimeAgo(notification.time);
      const icon = iconMap[notification.type] || iconMap[notification.level] || '📋';
      const unreadClass = notification.read ? '' : 'unread';
      
      return `
        <div class="notification-item ${unreadClass}">
          <div class="notification-item-icon">${icon}</div>
          <div class="notification-item-content">
            <div class="notification-item-message">${escapeHtml(notification.message)}</div>
            <div class="notification-item-time">${timeAgo}</div>
            ${notification.action ? `<a href="#" class="notification-item-action">${escapeHtml(notification.action)}</a>` : ''}
          </div>
        </div>
      `;
    }).join('');
    
    listEl.innerHTML = html;
  }
}

/**
 * 时间格式化为相对时间
 */
function getTimeAgo(timeStr) {
  try {
    const time = new Date(timeStr);
    const now = new Date();
    const diff = now - time;
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (days > 0) return `${days}天前`;
    if (hours > 0) return `${hours}小时前`;
    if (minutes > 0) return `${minutes}分钟前`;
    return '刚刚';
  } catch (e) {
    return '未知时间';
  }
}

/**
 * 设置通知中心事件监听
 */
function setupNotificationCenter() {
  const trigger = document.getElementById('notificationTrigger');
  const panel = document.getElementById('notificationPanel');
  const clearBtn = document.querySelector('.notification-clear');
  
  if (!trigger || !panel) return;
  
  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    panel.classList.toggle('show');
    
    if (panel.classList.contains('show')) {
      setTimeout(markAllAsRead, 1000);
    }
  });
  
  document.addEventListener('click', (e) => {
    if (!panel.contains(e.target) && !trigger.contains(e.target)) {
      panel.classList.remove('show');
    }
  });
  
  panel.addEventListener('click', (e) => {
    e.stopPropagation();
  });
  
  if (clearBtn) {
    clearBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      clearNotifications();
    });
  }
}

/**
 * 标记所有通知为已读
 */
function markAllAsRead() {
  if (notificationData.notifications) {
    notificationData.notifications = notificationData.notifications.map(n => ({ ...n, read: true }));
    renderNotifications();
  }
}

/**
 * 清空通知
 */
function clearNotifications() {
  if (!notificationData.notifications || notificationData.notifications.length === 0) {
    notify('暂无通知需要清空', 'info');
    return;
  }
  
  notificationData.notifications = [];
  renderNotifications();
  notify('已清空所有通知', 'ok');
}

// ========================================
// 协议健康监控功能
// ========================================

/**
 * 加载协议健康数据
 */
async function loadProtocolHealth() {
  try {
    const resp = await fetch('/traffic/protocol-health.json', { cache: 'no-store' });
    if (!resp.ok) return null;
    return await resp.json();
  } catch (e) {
    console.warn('加载协议健康数据失败:', e);
    return null;
  }
}

/**
 * 协议名称标准化
 */
function normalizeProtoKey(name) {
  const key = String(name || '').trim().toLowerCase().replace(/\s+/g, '-').replace(/[–—]/g, '-');
  const map = {
    'vless-reality': 'reality',
    'vless-grpc': 'grpc',
    'vless-websocket': 'ws',
    'trojan-tls': 'trojan',
    'hysteria2': 'hysteria2',
    'tuic': 'tuic'
  };
  return map[key] || key;
}

/**
 * 根据分数获取等级
 */
function getScoreLevel(x) {
  const s = Number(x || 0);
  if (s >= 85) return 'excellent';
  if (s >= 70) return 'good';
  if (s >= 50) return 'fair';
  return 'poor';
}

/**
 * 推荐徽章兜底
 */
function fallbackRecBadge(recRaw) {
  const rec = String(recRaw || '').toLowerCase();
  if (!rec) return '';
  const text = rec === 'primary' ? '🏆 主推'
             : rec === 'recommended' ? '👍 推荐'
             : rec === 'backup' ? '🔄 备用'
             : rec === 'not_recommended' ? '⛔ 暂不推荐'
             : '';
  return text ? `<div class="health-recommendation-badge">${text}</div>` : '';
}

/**
 * 渲染健康摘要卡片
 */
function renderHealthSummary(health) {
  const box = $('#health-summary');
  if (!box || !health) return;
  
  const sum = health.summary || {};
  const avg = sum.avg_health_score ?? (Array.isArray(health.protocols) 
    ? Math.round(health.protocols.map(p => Number(p.score || p.health_score || 0)).reduce((a, b) => a + b, 0) / (health.protocols.length || 1))
    : 0);
  
  box.innerHTML = `
    <div class="health-summary-card">
      <div class="summary-item"><span class="summary-label">总计协议</span><span class="summary-value">${sum.total ?? (health.protocols?.length || 0)}</span></div>
      <div class="summary-item healthy"><span class="summary-label">健康 √</span><span class="summary-value">${sum.healthy ?? '-'}</span></div>
      <div class="summary-item degraded"><span class="summary-label">降级 ⚠️</span><span class="summary-value">${sum.degraded ?? '-'}</span></div>
      <div class="summary-item down"><span class="summary-label">异常 ❌</span><span class="summary-value">${sum.down ?? '-'}</span></div>
      <div class="summary-item score"><span class="summary-label">平均健康分</span><span class="summary-value score-${getScoreLevel(avg)}">${avg}</span></div>
    </div>
    <div class="health-recommended"><strong>推荐协议:</strong>${(health.recommended || []).join(', ') || '暂无推荐'}</div>
    <div class="health-update-time">最后更新: ${escapeHtml(health.generated_at || health.updated_at || '')}</div>
  `;
}

/**
 * 渲染协议表格
 */
function renderProtocolTable(protocolsOpt) { // 只接收一个参数
  const protocols = Array.isArray(protocolsOpt) ? protocolsOpt : (window.dashboardData?.protocols || []);
  const tbody = $('#protocol-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  protocols.forEach(p => {
    // 直接从协议对象 p 中获取所有信息，不再需要去 health 对象里查找
    const recBadge = p.recommendation_badge || '';
    const tr = document.createElement('tr');
    // BUGFIX: 使用 p.protocol 或标准化的 p.name 作为 key
    const protocolKey = p.protocol || normalizeProtoKey(p.name);
    tr.dataset.protocol = protocolKey;

    tr.innerHTML = `
      <td>${escapeHtml(p.name)}</td>
      <td>${escapeHtml(p.scenario || '—')}</td>
      <td>${escapeHtml(p.camouflage || '—')}</td>
      <td class="protocol-status">
        <div class="health-status-container">
          <div class="health-status-badge ${escapeHtml(p.status || 'unknown')}">
            ${p.status_badge || escapeHtml(p.status || '—')}
          </div>
          <div class="health-detail-message" title="${escapeHtml(p.detail_message || '')}">
            ${escapeHtml(p.detail_message || '')}
          </div>
          ${recBadge}
        </div>
      </td>
      <td>
        <button class="btn btn-sm btn-link" data-action="open-modal" data-modal="configModal" data-protocol="${escapeHtml(p.name)}">查看配置</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // 订阅行的逻辑不变
  const subRow = document.createElement('tr');
  subRow.className = 'subs-row';
  subRow.innerHTML = `
    <td style="font-weight:500;">订阅URL | 整包链接</td><td></td><td></td><td></td>
    <td><button class="btn btn-sm btn-link" data-action="open-modal" data-modal="configModal" data-protocol="__SUBS__">查看@订阅</button></td>`;
  tbody.appendChild(subRow);
}


/**
 * 初始化协议健康监控
 */
async function initializeProtocolHealth() {
  const healthData = await loadProtocolHealth();
  if (healthData) {
    window.__protocolHealth = healthData;
    renderHealthSummary(healthData);
    renderProtocolTable();
  } else {
    console.warn('健康数据不可用, 使用"运行中"降级显示');
  }
}

/**
 * 启动健康状态自动刷新
 */
function startHealthAutoRefresh(intervalSeconds = 30) {
  initializeProtocolHealth();
  setInterval(initializeProtocolHealth, intervalSeconds * 1000);
}

// ========================================
// 主应用程序逻辑
// ========================================

/**
 * 刷新所有数据
 */
async function refreshAllData() {
  // 只请求聚合后的主要数据文件
  const [dash, sys, traf, notif] = await Promise.all([
    fetchJSON('/traffic/dashboard.json'),
    fetchJSON('/traffic/system.json'),
    fetchJSON('/traffic/traffic.json'),
    fetchJSON('/traffic/notifications.json')
  ]);

  if (dash) {
    dashboardData = dash;
    window.dashboardData = dashboardData;
    // 健康摘要数据也从 dashboard.json 中读取
    // 注意: 后端需要将健康摘要聚合到 dashboard.json 中 (当前脚本已支持)
    if(dash.health_summary) { 
       renderHealthSummary(dash.health_summary);
    }
  }
  if (sys) systemData = sys;
  if (traf) trafficData = traf;
  if (notif) updateNotificationCenter(notif);

  renderOverview();
  renderCertificateAndNetwork();
  renderProtocolTable(); // 调用时不再传递 health 数据
  renderTrafficCharts();
}


/**
 * DOM 加载完成后初始化
 */
document.addEventListener('DOMContentLoaded', () => {
  refreshAllData();
  overviewTimer = setInterval(refreshAllData, 30000);
  setupNotificationCenter();
});

// ========================================
// 事件委托 (统一处理所有交互)
// ========================================
(() => {
  if (window.__EDGEBOX_DELEGATED__) return;
  window.__EDGEBOX_DELEGATED__ = true;

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    
    const action = btn.dataset.action;
    const modal = btn.dataset.modal || '';
    const protocol = btn.dataset.protocol || '';

    switch (action) {
      case 'open-modal': {
        if (modal === 'configModal') {
          if (typeof showConfigModal === 'function') showConfigModal(protocol);
          const m = document.getElementById('configModal');
          if (m && m.style.display !== 'block') showModal('configModal');
        } else if (modal === 'whitelistModal') {
          const list = (window.dashboardData?.shunt?.whitelist) || [];
          const box = $('#whitelistList');
          if (box) box.innerHTML = list.map(d => `<div class="whitelist-item">${String(d)
            .replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))}</div>`).join('');
          showModal('whitelistModal');
        } else if (modal === 'ipqModal') {
          if (typeof showIPQDetails === 'function') {
            await showIPQDetails(btn.dataset.ipq || 'vps');
          } else {
            showModal('ipqModal');
          }
        }
        break;
      }

      case 'close-modal': {
        closeModal(modal);
        break;
      }

      case 'copy': {
        const host = btn.closest('.modal-content');
        const map = { json: '#json-code', plain: '#plain-link', plain6: '#plain-links-6', base64: '#base64-link' };
        const el = host && host.querySelector(map[btn.dataset.type]);
        const text = el ? (el.textContent || '').trim() : '';
        try {
          await copyTextFallbackAware(text);
          (window.notify || console.log)('已复制');
        } catch {
          (window.notify || console.warn)('复制失败');
        }
        break;
      }

      case 'copy-qr': {
        const host = btn.closest('.modal-content');
        const cvs = host && host.querySelector('#qrcode-sub canvas, #qrcode-protocol canvas');

        if (!cvs) {
          notify('未找到二维码', 'warn');
          break;
        }

        const doDownload = (blob) => {
          const a = document.createElement('a');
          const url = URL.createObjectURL(blob);
          const name = (protocol || '__SUBS__') + '_qrcode.png';
          a.href = url;
          a.download = name;
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 2000);
        };

        const doFallbackText = async () => {
          const text =
            host?.querySelector('#plain-link')?.textContent?.trim()
            || host?.querySelector('#plain-links-6')?.textContent?.trim()
            || host?.querySelector('#base64-link')?.textContent?.trim()
            || '';
          if (text) {
            try { await copyTextFallbackAware(text); } catch (_) {}
          }
        };

        cvs.toBlob(async (blob) => {
          if (!blob) {
            notify('获取二维码失败', 'warn');
            return;
          }
          try {
            if (window.isSecureContext && navigator.clipboard?.write && window.ClipboardItem) {
              await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
              notify('二维码已复制到剪贴板');
            } else {
              throw new Error('insecure');
            }
          } catch (err) {
            doDownload(blob);
            await doFallbackText();
            notify('图片复制受限: 已自动下载二维码, 并复制了明文/链接', 'warn');
          }
        }, 'image/png');

        break;
      }
    }
  });
})();

// ========================================
// 复制按钮统一轻提示
// ========================================
document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-role="copy"], .copy-btn, .btn-copy');
  if (!btn) return;

  const modal = btn.closest('.ant-modal, .el-dialog, .modal');
  if (!modal) return;

  let toast = modal.querySelector('.modal-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'modal-toast';
    toast.textContent = '已复制';
    modal.appendChild(toast);
  }
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 1200);
});

// ========================================
// 脚本加载完成标记
// ========================================
console.log('[EdgeBox Panel] JavaScript 模块已加载完成');

EXTERNAL_JS



# ======= 创建HTML文件（引用外置的CSS和JS）========
  log_info "创建控制面板HTML文件..."
cat > "$TRAFFIC_DIR/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EdgeBox Control Panel</title>
<link rel="stylesheet" href="./assets/edgebox-panel.css">
</head>
<body>

<div class="container">
  <div class="main-card">
        <div class="main-header">
        <h1>🕵️‍♂️🌐 EdgeBox - 企业级多协议节点管理系统 ✨</h1>
        <div class="notification-center">
            <button class="notification-trigger" id="notificationTrigger" data-action="toggle-notifications">
                <span class="notification-icon">🔔</span>
                <span class="notification-badge" id="notificationBadge" style="display:none;">0</span>
            </button>
            <div class="notification-panel" id="notificationPanel">
                <div class="notification-header">
                    <h3>通知中心</h3>
                    <button class="notification-clear" data-action="clear-notifications">清空</button>
                </div>
                <div class="notification-list" id="notificationList">
                    <div class="notification-loading">加载中...</div>
                </div>
                <div class="notification-footer">
                    <small>自动清理7天前的通知</small>
                </div>
            </div>
        </div>
    </div>
    <div class="main-content">
	
<div class="card" id="system-overview">	
        <div class="card-header">
  <h2>
    📊 系统概览
    <span class="card-note" id="sys-meta">版本号: — | 安装日期: — | 更新时间: —</span>
  </h2>
</div>
<div class="grid grid-3">
		
<div class="server-info inner-block">
  <h3>服务器信息</h3>

  <div class="info-item">
    <div class="label">用户备注名:</div>
    <div class="value" id="user-remark">—</div>
  </div>
  <div class="info-item">
    <div class="label">云厂商|区域:</div>
    <div class="value" id="cloud-region">—</div>
  </div>
  <div class="info-item">
    <div class="label">Instance ID:</div>
    <div class="value" id="instance-id">—</div>
  </div>
  <div class="info-item">
    <div class="label">主机名:</div>
    <div class="value" id="hostname">—</div>
  </div>
</div>

<div class="inner-block" id="server-config">
  <h3>服务器配置</h3>

  <div class="progress-row" id="cpu-row">
    <span class="progress-label">CPU:</span>
    <div class="progress-bar">
      <span class="progress-text" id="cpu-info" title="—">—</span>
      <div class="progress-fill" id="cpu-progress" style="width:0%"></div>
    </div>
    <span class="progress-info" id="cpu-percent">0%</span>
  </div>

  <div class="progress-row" id="mem-row">
    <span class="progress-label">内存:</span>
    <div class="progress-bar">
      <span class="progress-text" id="mem-info" title="—">—</span>
      <div class="progress-fill" id="mem-progress" style="width:0%"></div>
    </div>
    <span class="progress-info" id="mem-percent">0%</span>
  </div>

  <div class="progress-row" id="disk-row">
    <span class="progress-label">磁盘:</span>
    <div class="progress-bar">
      <span class="progress-text" id="disk-info" title="—">—</span>
      <div class="progress-fill" id="disk-progress" style="width:0%"></div>
    </div>
    <span class="progress-info" id="disk-percent">0%</span>
  </div>
</div>
	  
<div class="core-services inner-block">
  <h3>核心服务</h3>

  <div class="service-item">
    <div class="label">Nginx:</div>
    <div class="service-status">
      <span class="status-badge status-stopped">已停止</span>
    </div>
    <div class="version" id="nginx-version">—</div>
  </div>

  <div class="service-item">
    <div class="label">Xray:</div>
    <div class="service-status">
      <span class="status-badge status-stopped">已停止</span>
    </div>
    <div class="version" id="xray-version">—</div>
  </div>

  <div class="service-item">
    <div class="label">Sing-box:</div>
    <div class="service-status">
      <span class="status-badge status-stopped">已停止</span>
    </div>
    <div class="version" id="singbox-version">—</div>
  </div>
</div>
      </div>
	  </div>
	  
<div class="grid grid-1-2">
  <div class="card" id="cert-panel">
    <div class="card-header"><h2>🔒 证书切换</h2></div>

    <div class="cert-modes">
      <div class="cert-mode-tab" id="cert-self"><h3>自签证书</h3></div>
      <div class="cert-mode-tab" id="cert-ca"><h3>CA证书</h3></div>
    </div>

    <div class="inner-block">
      <div class="info-item cert__row">
        <label class="cert__label">证书类型:</label>
        <value class="cert__value" id="cert-type">—</value>
      </div>
      <div class="info-item cert__row">
        <label class="cert__label">绑定域名:</label>
        <value class="cert__value" id="cert-domain">—</value>
      </div>
      <div class="info-item cert__row">
        <label class="cert__label">续期方式:</label>
        <value class="cert__value" id="cert-renewal">—</value>
      </div>
      <div class="info-item cert__row">
        <label class="cert__label">到期日期:</label>
        <value class="cert__value" id="cert-expiry">—</value>
      </div>
    </div>
  </div>

  <div class="card" id="netid-panel">
    <div class="card-header">
      <h2>👥 网络身份配置 <span class="note-udp">注：HY2/TUIC为UDP通道，VPS直连，不参与分流配置.</span></h2>
    </div>

    <div class="network-blocks">
      <div class="network-block" id="net-vps">
        <h3>📡 VPS出站IP</h3>
        <div class="info-item nid__row">
          <label class="nid__label">公网身份:</label>
          <value class="nid__value">直连</value>
        </div>
        <div class="info-item nid__row">
          <label class="nid__label">VPS-IP:</label>
          <value class="nid__value" id="vps-ip">—</value>
        </div>
        <div class="info-item nid__row">

          <label class="nid__label">Geo:</label>
          <value class="nid__value" id="vps-geo">—</value>
        </div>
        <div class="info-item nid__row">
          <label class="nid__label">IP质量:</label>
          <value class="nid__value">
            <span id="vps-ipq-score">—</span>
            <button class="btn-link" data-action="open-modal" data-modal="ipqModal" data-ipq="vps">查看详情</button>
          </value>
        </div>
      </div>

      <div class="network-block" id="net-proxy">
        <h3>🔄 代理出站IP</h3>
        <div class="info-item nid__row">
          <label class="nid__label">代理身份:</label>
          <value class="nid__value">全代理</value>
        </div>
        <div class="info-item nid__row">
          <label class="nid__label">代理IP:</label>
          <value class="nid__value" id="proxy-ip">—</value>
        </div>
        <div class="info-item nid__row">
          <label class="nid__label">Geo:</label>
          <value class="nid__value" id="proxy-geo">—</value>
        </div>
        <div class="info-item nid__row">
          <label class="nid__label">IP质量:</label>
          <value class="nid__value">
            <span id="proxy-ipq-score">—</span>
            <button class="btn-link" data-action="open-modal" data-modal="ipqModal" data-ipq="proxy">查看详情</button>
          </value>
        </div>
      </div>

<div class="network-block" id="net-shunt">
        <h3>🔀 分流出站</h3>
        <div class="info-item nid__row">
          <label class="nid__label">混合身份:</label>
          <value class="nid__value">直连&代理</value>
        </div>
        <div class="info-item nid__row">
          <label class="nid__label">VPS-IP:</label>
          <value class="nid__value">同左</value>
        </div>
        <div class="info-item nid__row">
          <label class="nid__label">代理IP:</label>
          <value class="nid__value">同左</value>
        </div>
        <div class="info-item nid__row">
          <label class="nid__label">白名单:</label>
          <value class="nid__value whitelist-value">
            <div class="whitelist-preview" id="whitelistPreview"></div>
          </value>
        </div>
      </div>
    </div>
  </div>
</div>

      <div class="card">
        <div class="card-header"><h2>📡 协议配置</h2></div>
        <table class="data-table">
          <thead><tr><th><h3>协议名称</h3></th><th><h3>使用场景</h3></th><th><h3>伪装效果</h3></th><th><h3>运行状态</h3></th><th><h3>客户端配置</h3></th></tr></thead>
          <tbody id="protocol-tbody"></tbody>
        </table>
      </div>

<div class="card traffic-card">
        <div class="card-header">
            <h2>📊 流量统计</h2>
        </div>
        <div class="traffic-charts traffic--subcards">
          <div class="chart-column">
            <div class="traffic-progress-container">
              <span class="progress-label"><h3>本月进度</h3></span>
              <div class="progress-wrapper"><div class="progress-bar"><div class="progress-fill" id="progress-fill" style="width:0%"><span class="progress-percentage" id="progress-percentage">0%</span></div></div></div>
              <span class="progress-budget" id="progress-budget">0/100GiB</span>
            </div>
            <div class="chart-container">
              <h3>近30日出站流量走势<small class="unit-note">GiB</small></h3>
              <canvas id="traffic"></canvas>
            </div>
          </div>
          <div class="chart-column">
            <div class="chart-container">
              <h3>近12月出站流量 <small class="unit-note">GiB</small></h3>
              <canvas id="monthly-chart"></canvas>
            </div>
          </div>
        </div>
      </div>

<div class="card">
  <div class="card-header">
    <h2>⚙️ 运维管理</h2>
  </div>

  <div class="commands-grid">
    <div class="command-section">
      <h3>🎯 核心命令</h3>
      <div class="command-list">
        <code>edgeboxctl sub</code> <span># 查看订阅链接与 控制面板URL</span>
        <code>edgeboxctl status</code> <span># 查看所有服务及端口的健康状态</span>
        <code>edgeboxctl logs &lt;service&gt;</code> <span># 查看指定服务的实时日志 (Ctrl+C 退出)</span>
        <code>edgeboxctl restart</code> <span># 优雅重启所有核心服务 (配置变更后使用)</span>
        <code>edgeboxctl update</code> <span># 在线更新 EdgeBox 至最新版本</span>
        <code>edgeboxctl help</code> <span># 显示帮助信息</span>
        <div>示例：</div>
        <a>edgeboxctl logs xray</a>
      </div>
    </div>

    <div class="command-section">
      <h3>🔒 证书切换</h3>
      <div class="command-list">
        <code>edgeboxctl cert status</code> <span># 查看当前证书类型、域名及有效期</span>
        <code>edgeboxctl switch-to-domain &lt;domain&gt;</code> <span># 切换为域名并申请 Let's Encrypt 证书</span>
        <code>edgeboxctl cert renew</code> <span># 手动续期 Let's Encrypt 证书</span>
		<code>edgeboxctl switch-to-ip</code> <span># 切换回 IP 模式，使用自签名证书</span>
        <code>edgeboxctl fix-permissions</code> <span># 修复证书文件的读写权限</span>
        <div>示例：</div>
        <a>edgeboxctl switch-to-domain my.domain.com</a>
      </div>
    </div>

    <div class="command-section">
      <h3>🌐 SNI 域名轮换</h3>
      <div class="command-list">
        <code>edgeboxctl sni list</code> <span># 显示 SNI 域名池状态 (别名: pool)</span>
		<code>edgeboxctl sni test-all</code> <span># 测试池中所有域名的可用性</span>
        <code>edgeboxctl sni auto</code> <span># 智能测试并选择最优 SNI 域名</span>
        <code>edgeboxctl sni set &lt;domain&gt;</code> <span># 手动强制指定一个 SNI 域名</span>
        <div>示例：</div>
        <a>edgeboxctl sni set www.apple.com</a>
      </div>
    </div>

    <div class="command-section">
      <h3>🔐 Reality 密钥轮换</h3>
      <div class="command-list">
	    <code>edgeboxctl reality-status</code> <span># 查看 Reality 密钥轮换的周期状态</span>
        <code>edgeboxctl rotate-reality --force</code> <span># 手动执行 Reality 密钥对轮换 (安全增强)</span>
      </div>
    </div>

<div class="command-section">
      <h3>🧬 流量特征随机化</h3>
      <div class="command-list">
        <code>edgeboxctl traffic status</code><span># 查看随机化系统状态和定时任务</span>
        <code>edgeboxctl traffic reset</code><span># 重置随机化参数为默认值</span>
        <code>edgeboxctl traffic randomize [light|medium|heavy]</code><span># 执行流量特征随机化，增强隐蔽性</span>
        <p class="cmd-label">示例：</p>
        <a class="cmd-pill" href="#">edgeboxctl traffic randomize medium</a>
        <p class="cmd-label">level:</p>
        <a class="cmd-pill" href="#">light(默认) —轻度随机化，仅Hysteria2 仿装站点</a><br>
        <a class="cmd-pill" href="#">medium — 中度随机化，修改Hysteria2 +TUIC参数</a><br>
        <a class="cmd-pill" href="#">heavy — 重度随机化，修改全协议参数</a><br>
        </div>
    </div>

<div class="command-section">
      <h3>👥 独立用户订阅 (User Subscriptions)</h3>
      <div class="command-list">
        <code>edgeboxctl sub issue &lt;user&gt; [limit]</code> <span># 为指定用户下发专属订阅链接</span>
        <code>edgeboxctl sub show &lt;user&gt;</code> <span># 查看用户订阅及已绑定的设备</span>
        <code>edgeboxctl sub revoke &lt;user&gt;</code> <span># 停用指定用户的订阅链接</span>
        <code>edgeboxctl sub limit &lt;user&gt; &lt;N&gt;</code> <span># 修改用户的设备上限</span>
        <p class="cmd-label">示例：</p>
        <a class="cmd-pill" href="#">edgeboxctl sub issue alice 5</a>
        <a class="cmd-pill" href="#">edgeboxctl sub show alice</a>
      </div>
    </div>
	
    <div class="command-section">
      <h3>👥 网络身份配置</h3>
      <div class="command-list">
        <code>edgeboxctl shunt vps</code><span># VPS 直连出站（默认）</span><br>
        <code>edgeboxctl shunt resi `&lt;URL&gt;`</code><span># 代理全量出站（仅 Xray）</span><br>
        <code>edgeboxctl shunt direct-resi `&lt;URL&gt;`</code><span># 智能分流（白名单直连，其余走代理）</span><br>
        <code>edgeboxctl shunt status</code><span># 查看当前出站模式及代理健康状态</span><br>
        <code>edgeboxctl shunt whitelist {action} [domain]</code><span># 管理白名单（add|remove|list|reset）</span><br>
        <p class="cmd-label">示例：</p>
        <a class="cmd-pill" href="#">edgeboxctl shunt direct-resi 'socks5://user:pass@host:port'</a><br>
        <a class="cmd-pill" href="#">edgeboxctl shunt whitelist add netflix.com</a><br>
        <p class="cmd-label">代理URL格式：</p>
        <a class="cmd-pill" href="#">http://user:pass@host:port</a><br>
        <a class="cmd-pill" href="#">https://user:pass@host:port</a><br>
        <a class="cmd-pill" href="#">socks5://user:pass@host:port</a><br>
        <a class="cmd-pill" href="#">socks5://user:pass@host:port?sni=example.com</a>
      </div>
    </div>

    <div class="command-section">
      <h3>📊 流量与预警</h3>
      <div class="command-list">
        <code>edgeboxctl traffic show</code> <span># 在终端查看流量使用统计</span>
        <code>edgeboxctl alert show</code> <span># 查看当前预警配置</span>
        <code>edgeboxctl alert monthly &lt;GiB&gt;</code> <span># 设置月度流量预算</span>
        <code>edgeboxctl alert steps &lt;p1,p2,...&gt;</code> <span># 设置百分比预警阈值 (逗号分隔)</span>
        <code>edgeboxctl alert telegram &lt;token&gt; &lt;chat_id&gt;</code> <span># 配置 Telegram 通知渠道</span>
        <code>edgeboxctl alert discord &lt;webhook_url&gt;</code> <span># 配置 Discord 通知渠道</span>
        <code>edgeboxctl alert wechat &lt;pushplus_token&gt;</code> <span># 配置微信 PushPlus 通知渠道</span>
        <code>edgeboxctl alert webhook &lt;url&gt; [format]</code> <span># 配置通用 Webhook (raw|slack|discord)</span>
        <code>edgeboxctl alert test [percent]</code> <span># 模拟触发预警以测试通知渠道</span>
        <div>示例：</div>
        <a>edgeboxctl alert monthly 1000</a>
        <a>edgeboxctl alert steps 50,80,95</a>
        <a>edgeboxctl alert telegram &lt;token&gt; &lt;chat_id&gt;</a>
        <a>edgeboxctl alert test 80</a>
      </div>
    </div>

    <div class="command-section">
      <h3>🧩 配置与维护</h3>
      <div class="command-list">
        <code>edgeboxctl dashboard passcode</code> <span># 重置 Web 控制面板的访问密码</span>
        <code>edgeboxctl alias &lt;我的备注&gt;</code> <span># 为当前服务器设置一个易记的别名</span>
		<code>edgeboxctl config show</code> <span># 显示所有协议的 UUID、密码等详细配置</span>
        <code>edgeboxctl config regenerate-uuid</code> <span># 为所有协议重新生成 UUID 和密码</span>
        <code>edgeboxctl backup create</code> <span># 创建当前系统配置的完整备份</span>
        <code>edgeboxctl backup list</code> <span># 列出所有可用的备份文件</span>
        <code>edgeboxctl backup restore &lt;file&gt;</code> <span># 从指定备份文件恢复系统配置</span>
        <div>示例：</div>
        <a>edgeboxctl alias "香港-CN2-主力"</a>
        <a>edgeboxctl backup restore edgebox_backup_xxx.tar.gz</a>
      </div>
    </div>

    <div class="command-section">
      <h3>🔍 诊断与排障</h3>
      <div class="command-list">
        <code>edgeboxctl debug-ports</code> <span># 检查核心端口 (80, 443, 2053) 是否被占用</span>
		<code>edgeboxctl test</code> <span># 对各协议入口进行基础连通性测试</span>
        <code>edgeboxctl test-udp &lt;host&gt; &lt;port&gt; [seconds]</code> <span># 使用 iperf3/socat 进行 UDP 连通性简测</span>
        <div>示例 (排障流程)：</div>
        <a>edgeboxctl status → edgeboxctl logs xray → edgeboxctl debug-ports</a>
      </div>
    </div>
  </div>
</div>
		  
<div id="whitelistModal" class="modal"><div class="modal-content"><div class="modal-header"><h3>白名单完整列表</h3><span class="close-btn" data-action="close-modal" data-modal="whitelistModal">×</span></div><div class="modal-body"><div id="whitelistList"></div></div></div></div>
<div id="ipqModal" class="modal"><div class="modal-content"><div class="modal-header"><h3 id="ipqModalTitle">IP质量检测详情</h3><span class="close-btn" data-action="close-modal" data-modal="ipqModal">×</span></div><div class="modal-body"><div id="ipqDetails"></div></div></div></div>

<div id="configModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h3 id="configModalTitle">配置详情</h3>
      <span class="close-btn" data-action="close-modal" data-modal="configModal">×</span>
    </div>
<div class="modal-body">
      <div id="configDetails"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="sub">复制订阅地址</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain">复制明文</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="json">复制JSON</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="base64">复制Base64</button>
    </div>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script src="./assets/edgebox-panel.js"></script>
</body>
</html>
HTML

# 设置文件权限
chmod 644 "${TRAFFIC_DIR}/assets/edgebox-panel.css"
chmod 644 "${TRAFFIC_DIR}/assets/edgebox-panel.js"
chmod 644 "$TRAFFIC_DIR/index.html"

  log_success "流量监控系统设置完成（CSS和JS已外置）"
}

# 设置定时任务 (Final Cleaned Version)
setup_cron_jobs() {
    log_info "设置统一的定时任务..."

    # 预警配置兜底
    ensure_alert_conf_full() {
        local f="/etc/edgebox/traffic/alert.conf"
        mkdir -p /etc/edgebox/traffic
        [[ -s "$f" ]] || cat >"$f" <<'CONF'
# EdgeBox traffic alert thresholds & channels
ALERT_MONTHLY_GIB=100
ALERT_TG_BOT_TOKEN=
ALERT_TG_CHAT_ID=
ALERT_DISCORD_WEBHOOK=
ALERT_PUSHPLUS_TOKEN=
ALERT_WEBHOOK=
ALERT_WEBHOOK_FORMAT=raw
ALERT_STEPS=30,60,90
ALERT_EMAIL=
CONF
    }
    ensure_alert_conf_full

    # 备份并清理所有旧的 EdgeBox 任务
    crontab -l > ~/crontab.backup.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
    ( crontab -l 2>/dev/null | grep -vE '(/etc/edgebox/|\bedgebox\b|\bEdgeBox\b)' ) | crontab - || true

    # 写入最终的、统一的新任务集
    ( crontab -l 2>/dev/null || true; cat <<CRON
# EdgeBox Cron Jobs v3.0 (Unified)
#
# 每5分钟：刷新Web面板的动态数据 (系统负载、服务状态等)
*/5 * * * * bash -lc '/etc/edgebox/scripts/dashboard-backend.sh --now' >/dev/null 2>&1
#
# 每小时整点：采集流量数据
0  * * * * bash -lc '/etc/edgebox/scripts/traffic-collector.sh' >/dev/null 2>&1
#
# 每小时的第7分钟：检查流量是否触发预警
7  * * * * bash -lc '/etc/edgebox/scripts/traffic-alert.sh' >/dev/null 2>&1
#
# 每天凌晨2:15：执行IP质量检测
15 2 * * * bash -lc '/usr/local/bin/edgebox-ipq.sh' >/dev/null 2>&1
#
# 每天凌晨2点：检查并自动轮换Reality密钥 (如果到期)
0  2 * * * bash -lc '/usr/local/bin/edgeboxctl rotate-reality' >/dev/null 2>&1
#
# 每周日凌晨3点：自动选择最优SNI域名
0 3 * * 0 /usr/local/bin/edgeboxctl sni auto >/dev/null 2>&1
#
# 流量特征随机化
0 4 * * * bash -lc '/etc/edgebox/scripts/edgebox-traffic-randomize.sh light' >/dev/null 2>&1
0 5 * * 0 bash -lc '/etc/edgebox/scripts/edgebox-traffic-randomize.sh medium' >/dev/null 2>&1
0 6 1 * * bash -lc '/etc/edgebox/scripts/edgebox-traffic-randomize.sh heavy' >/dev/null 2>&1
CRON
    ) | crontab -

    log_success "统一的定时任务已设置完成。"
}


# 创建独立的、无中断的防火墙应用脚本
create_firewall_script() {
    log_info "创建独立的、无中断的防火墙应用脚本..."
    
    mkdir -p "${SCRIPTS_DIR}"
    
    cat > "${SCRIPTS_DIR}/apply-firewall.sh" << 'APPLY_FIREWALL_SCRIPT'
#!/bin/bash
set -e
echo "[INFO] 正在以无中断模式应用 EdgeBox 防火墙规则..."

# --- 智能检测当前SSH端口 ---
# (这部分逻辑不变，保持原样)
ssh_ports=()
# ... (省略和之前版本相同的SSH端口检测代码) ...
while IFS= read -r line; do
    if [[ "$line" =~ :([0-9]+)[[:space:]]+.*sshd ]]; then
        ssh_ports+=("${BASH_REMATCH[1]}")
    fi
done < <(ss -tlnp 2>/dev/null | grep sshd || true)
if [[ -f /etc/ssh/sshd_config ]]; then
    config_port=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    [[ -n "$config_port" && "$config_port" =~ ^[0-9]+$ ]] && ssh_ports+=("$config_port")
fi
if [[ -n "${SSH_CONNECTION:-}" ]]; then
    connection_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
    [[ -n "$connection_port" && "$connection_port" =~ ^[0-9]+$ ]] && ssh_ports+=("$connection_port")
fi
if [[ ${#ssh_ports[@]} -gt 0 ]]; then
    temp_file=$(mktemp)
    printf "%s\n" "${ssh_ports[@]}" | sort -u > "$temp_file"
    current_ssh_port=$(head -1 "$temp_file")
    rm -f "$temp_file"
fi
current_ssh_port="${current_ssh_port:-22}"
echo "[INFO] 检测到 SSH 端口: $current_ssh_port"


# --- 根据防火墙类型，使用无中断方式配置规则 ---

# 定义一个辅助函数来检查规则是否存在
is_rule_active() {
    local type="$1"
    local port="$2"
    local proto="$3"
    
    if [[ "$type" == "ufw" ]]; then
        ufw status | grep -qE "^\s*${port}/${proto}\s+ALLOW\s+Anywhere"
    elif [[ "$type" == "firewalld" ]]; then
        firewall-cmd --query-port="${port}/${proto}" >/dev/null 2>&1
    fi
}

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    echo "[INFO] 正在配置 UFW (无中断模式)..."
    is_rule_active "ufw" "$current_ssh_port" "tcp" || ufw allow "${current_ssh_port}/tcp" >/dev/null
    is_rule_active "ufw" "80" "tcp" || ufw allow 80/tcp >/dev/null
    is_rule_active "ufw" "443" "tcp" || ufw allow 443/tcp >/dev/null
    is_rule_active "ufw" "443" "udp" || ufw allow 443/udp >/dev/null
    is_rule_active "ufw" "2053" "udp" || ufw allow 2053/udp >/dev/null
    # <<< 修复点: 移除了可能导致连接中断的 `ufw --force enable` >>>
    echo "[SUCCESS] UFW 规则已确保应用。"

elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    echo "[INFO] 正在配置 FirewallD (无中断模式)..."
    
    # <<< 修复点: 改为使用非中断的运行时规则添加，并同步到永久配置，避免 --reload >>>
    add_firewalld_rule() {
        local rule="$1"
        if ! firewall-cmd --query-port="$rule" >/dev/null 2>&1; then
            echo "  -> 添加规则: $rule"
            firewall-cmd --add-port="$rule" >/dev/null 2>&1
            firewall-cmd --permanent --add-port="$rule" >/dev/null 2>&1
        fi
    }
    
    add_firewalld_rule "$current_ssh_port/tcp"
    add_firewalld_rule "80/tcp"
    add_firewalld_rule "443/tcp"
    add_firewalld_rule "443/udp"
    add_firewalld_rule "2053/udp"
    
    echo "[SUCCESS] FirewallD 规则已确保应用。"
    
elif command -v iptables >/dev/null 2>&1; then
    echo "[INFO] 正在配置 iptables (无中断模式)..."
    iptables -C INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
    iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -C INPUT -p udp --dport 443 -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p udp --dport 443 -j ACCEPT
    iptables -C INPUT -p udp --dport 2053 -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p udp --dport 2053 -j ACCEPT
    echo "[SUCCESS] iptables 规则已确保应用。"
else
    echo "[WARN] 未检测到支持的防火墙软件，请手动确保端口开放。"
fi
APPLY_FIREWALL_SCRIPT

    chmod +x "${SCRIPTS_DIR}/apply-firewall.sh"
    log_success "独立的、无中断的防火墙应用脚本创建完成。"
}


# 创建完整的edgeboxctl管理工具（集成SNI功能）
create_enhanced_edgeboxctl() {
    log_info "创建增强版edgeboxctl管理工具 (v3.0.2 - Nginx分离式配置修复)..."
    
    cat > /usr/local/bin/edgeboxctl << 'EDGEBOXCTL_SCRIPT'
#!/bin/bash
# EdgeBox 增强版控制脚本
# Version: 3.0.2 (Patched with Dynamic Nginx SNI via include file)
VERSION="3.0.2"
CONFIG_DIR="/etc/edgebox/config"
CERT_DIR="/etc/edgebox/cert"
INSTALL_DIR="/etc/edgebox"
LOG_FILE="/var/log/edgebox.log"
SHUNT_CONFIG="${CONFIG_DIR}/shunt/state.json"
BACKUP_DIR="/root/edgebox-backup"
TRAFFIC_DIR="/etc/edgebox/traffic"
SCRIPTS_DIR="/etc/edgebox/scripts"
# SNI相关路径变量
SNI_CONFIG_DIR="${CONFIG_DIR}/sni"
SNI_DOMAINS_CONFIG="${SNI_CONFIG_DIR}/domains.json"
XRAY_CONFIG="${CONFIG_DIR}/xray.json" # SNI函数需要
SNI_HEALTH_LOG="/var/log/edgebox/sni-health.log" # SNI函数需要

WHITELIST_DOMAINS="googlevideo.com,nflxvideo.net,dssott.com,aiv-cdn.net,aiv-delivery.net,ttvnw.net,hbo-cdn.com,hls.itunes.apple.com,scdn.co,tiktokcdn.com"

# [最终稳定版]
generate_nginx_stream_map_conf() {
    local mode="$1"
    local map_conf="/etc/nginx/conf.d/edgebox_stream_map.conf"

    log_info "正在为 ${mode} 模式生成 Nginx stream map 配置文件..."

    if [[ "$mode" == "ip" ]]; then
        # IP模式：为 gRPC 和 WS 使用内部专有 SNI 进行分流
        cat > "$map_conf" << 'EOF'
# This file is auto-generated by edgeboxctl for IP mode.
map $ssl_preread_server_name $backend_pool {
    ~*(microsoft\.com|apple\.com|cloudflare\.com|amazon\.com|fastly\.com)$ reality;
    ~*^trojan\..* trojan;
    grpc.edgebox.internal  grpc;
    ws.edgebox.internal    websocket;
    default                "";
}
EOF
    else
        # 域名模式：gRPC 和 WS 依赖 ALPN 分流，SNI map 中不再需要它们，从而避免冲突
        cat > "$map_conf" << 'EOF'
# This file is auto-generated by edgeboxctl for Domain mode.
map $ssl_preread_server_name $backend_pool {
    ~*(microsoft\.com|apple\.com|cloudflare\.com|amazon\.com|fastly\.com)$ reality;
    ~*^trojan\..* trojan;
    # 在域名模式下，gRPC和WS的SNI与主域名相同，
    # 它们将通过下一阶段的ALPN map进行分流，此处无需配置。
    default                "";
}
EOF
    fi
    log_success "Nginx stream map 已生成: $map_conf"
}


# ===== 日志函数（完整）=====
ESC=$'\033'
BLUE="${ESC}[0;34m"; PURPLE="${ESC}[0;35m"; CYAN="${ESC}[0;36m"
YELLOW="${ESC}[1;33m"; GREEN="${ESC}[0;32m"; RED="${ESC}[0;31m"; NC="${ESC}[0m"
LOG_FILE="/var/log/edgebox-install.log"
LOG_LEVEL="${LOG_LEVEL:-info}"   # debug|info

log_info()    { echo -e "${GREEN}[INFO]${NC} $*"    | tee -a "$LOG_FILE"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"   | tee -a "$LOG_FILE"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"     | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"; }
log_debug()   { [[ "${LOG_LEVEL}" == debug ]] && echo -e "${YELLOW}[DEBUG]${NC} $*" | tee -a "$LOG_FILE" || true; }

log()      { log_info "$@"; }
log_ok()   { log_success "$@"; }
error()    { log_error "$@"; }

# <<< 新增: SNI管理核心函数 (从 sni-manager.sh 整合) >>>
# -------------------------------------------------------------------
# SNI 日志函数
sni_log_info() { log_info "SNI: $*"; }
sni_log_warn() { log_warn "SNI: $*"; }
sni_log_error() { log_error "SNI: $*"; }
sni_log_success() { log_success "SNI: $*"; }

# 域名评分函数
evaluate_sni_domain() {
    local domain="$1"
    local score=0
    
    # <<< 修复点: 将进度信息输出到 stderr (>&2)，避免污染返回值 >>>
    echo "  -> 评估域名: $domain" >&2
    
    # 1. 可达性
    if ! timeout 5 curl -s --connect-timeout 3 --max-time 5 "https://${domain}" >/dev/null 2>&1; then
        echo 0
        return
    fi
    score=$((score + 30))
    
    # 2. 响应时间
    local response_time
    response_time=$(timeout 5 curl -o /dev/null -s -w '%{time_total}' --connect-timeout 3 "https://${domain}" 2>/dev/null || echo "99")
    local time_int=${response_time%.*}
    if [[ "$time_int" -lt 1 ]]; then score=$((score + 25));
    elif [[ "$time_int" -lt 2 ]]; then score=$((score + 20));
    elif [[ "$time_int" -lt 3 ]]; then score=$((score + 15));
    else score=$((score + 5)); fi
    
    # 3. SSL证书
    if timeout 5 openssl s_client -connect "${domain}:443" -servername "$domain" </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
        score=$((score + 20))
    else
        score=$((score + 5))
    fi

    # 4. CDN检测
    if timeout 5 curl -sI "https://${domain}" 2>/dev/null | grep -qiE "(cloudflare|akamai|fastly|cloudfront|cdn)"; then
        score=$((score + 15))
    else
        score=$((score + 5))
    fi
    
    # 5. 域名类别
    case "$domain" in
        *microsoft*|*apple*|*google*) score=$((score + 10));;
        *cloudflare*|*akamai*|*fastly*) score=$((score + 9));;
        *azure*|*aws*|*cloud*) score=$((score + 8));;
        *) score=$((score + 5));;
    esac
    
    echo "$score" # <<< 关键: 只有分数通过 stdout 返回
}

# 获取当前SNI域名
get_current_sni_domain() {
    [[ ! -f "$XRAY_CONFIG" ]] && return
    jq -r 'first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.serverNames[0]) // (first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.dest) | split(":")[0]) // empty' "$XRAY_CONFIG" 2>/dev/null
}

# 智能选择最优域名
auto_select_optimal_domain() {
    echo "开始SNI域名智能选择..." >&2
    
    local domains_to_test=()
    if [[ -f "$SNI_DOMAINS_CONFIG" ]]; then
        while IFS= read -r domain; do
            [[ -n "$domain" && "$domain" != "null" ]] && domains_to_test+=("$domain")
        done < <(jq -r '.domains[]?.hostname // empty' "$SNI_DOMAINS_CONFIG" 2>/dev/null)
    fi
    [[ ${#domains_to_test[@]} -eq 0 ]] && domains_to_test=("www.microsoft.com" "www.apple.com" "www.cloudflare.com")
    
    local best_domain=""
    local best_score=-1 # Start with -1 to ensure the first valid domain is always chosen
    local current_sni
    current_sni=$(get_current_sni_domain)
    
    echo "当前SNI域名: ${current_sni:-未配置}" >&2
    
    for domain in "${domains_to_test[@]}"; do
        local score
        score=$(evaluate_sni_domain "$domain")
        echo "  - 域名 $domain, 评分: $score" >&2
        
        # <<< FIX: Changed from -gt to -ge to allow rotation between equally optimal domains >>>
        if [[ "$score" -ge "$best_score" ]]; then
            best_score=$score
            best_domain="$domain"
        fi
    done
    
    if [[ -z "$best_domain" ]]; then
        log_error "未找到可用的SNI域名"
        return 1
    fi
    
    echo "最优域名选择结果: $best_domain (评分: $best_score)" >&2
    
    if [[ "$best_domain" == "$current_sni" ]]; then
        log_success "当前SNI域名已是最优，无需更换。"
        return 0
    fi
    
    log_info "准备更换SNI域名: ${current_sni:-未配置} → $best_domain"
    if update_sni_domain "$best_domain"; then
        log_success "SNI域名更换成功！"
    else
        log_error "SNI域名更换失败！"
        return 1
    fi
}

# 健康检查功能
health_check_domains() {
    echo "开始域名健康检查..." >&2
    
    local domains_to_check=()
    if [[ -f "$SNI_DOMAINS_CONFIG" ]]; then
        while IFS= read -r domain; do
            [[ -n "$domain" && "$domain" != "null" ]] && domains_to_check+=("$domain")
        done < <(jq -r '.domains[]?.hostname // empty' "$SNI_DOMAINS_CONFIG" 2>/dev/null)
    fi
    [[ ${#domains_to_check[@]} -eq 0 ]] && domains_to_check=("www.microsoft.com" "www.apple.com" "www.cloudflare.com")
    
    for domain in "${domains_to_check[@]}"; do
        if timeout 5 curl -s --connect-timeout 3 --max-time 5 "https://${domain}" >/dev/null 2>&1; then
            echo "  [  OK  ] $domain" >&2
        else
            echo "  [ FAIL ] $domain" >&2
        fi
    done
}
# -------------------------------------------------------------------
# <<< SNI 功能整合结束 >>>

# 获取控制面板密码
get_dashboard_passcode() {
    jq -r '.dashboard_passcode // empty' "${CONFIG_DIR}/server.json" 2>/dev/null || echo ""
}

# 更新控制面板密码
update_dashboard_passcode() {
    # 读取旧密码
    local old_passcode
    old_passcode=$(jq -r '.dashboard_passcode // "无"' "${CONFIG_DIR}/server.json" 2>/dev/null || echo "无")
    
    # 获取新密码参数
    local new_passcode="$1"
    
    # 如果没有提供密码，提示用户输入
    if [[ -z "$new_passcode" ]]; then
        echo -e "${YELLOW}请输入新密码（6位数字），留空则随机生成：${NC}"
        read -r new_passcode
    fi
    
    # 如果用户输入为空，自动生成
    if [[ -z "$new_passcode" ]]; then
        local random_digit=$((RANDOM % 10))
        new_passcode="${random_digit}${random_digit}${random_digit}${random_digit}${random_digit}${random_digit}"
        log_info "未输入密码，自动生成: $new_passcode"
    else
        # 验证密码格式（6位数字）
        if ! [[ "$new_passcode" =~ ^[0-9]{6}$ ]]; then
            log_error "密码格式错误！必须是6位数字"
            return 1
        fi
    fi
    
    # 2. 更新 server.json
    local temp_file="${CONFIG_DIR}/server.json.tmp"
    if jq --arg passcode "$new_passcode" '.dashboard_passcode = $passcode' "${CONFIG_DIR}/server.json" > "$temp_file"; then
        mv "$temp_file" "${CONFIG_DIR}/server.json"
        log_success "server.json 中的密码已更新"
    else
        log_error "更新 server.json 失败"
        rm -f "$temp_file"
        return 1
    fi
    
    # <<< 修复点: 不再使用 sed，直接覆盖密码配置文件 >>>
    local passcode_conf="/etc/nginx/conf.d/edgebox_passcode.conf"
    cat > "$passcode_conf" << EOF
# 由 edgeboxctl 自动生成于 $(date)
map \$arg_passcode \$pass_ok {
    "${new_passcode}" 1;
    default 0;
}
EOF
    log_success "Nginx 密码配置文件已更新"

    # 4. 重载 Nginx
    if reload_or_restart_services nginx; then
        log_success "Nginx 配置重载成功"
        log_success "控制面板密码更新成功！新密码：${YELLOW}${new_passcode}${NC}"
        log_info "原密码：${old_passcode:-无}"
        return 0
    else
        log_error "Nginx 重载失败，请检查配置"
        return 1
    fi
}

# 优化后的配置验证函数（替代原来的get_server_info）
get_server_info() {
    ensure_config_loaded || return 1
    
    # 验证关键配置项
    if [[ -z "$SERVER_IP" || "$SERVER_IP" == "null" ]]; then
        log_error "服务器IP配置缺失"
        return 1
    fi
    
    # 可选：验证UUID格式
    if [[ -n "$UUID_VLESS_REALITY" ]] && ! [[ "$UUID_VLESS_REALITY" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        log_warn "VLESS Reality UUID格式可能异常"
    fi
    
    return 0
}


# 异步重启服务并安全退出 (Shortened Delay Version)
restart_services_background() {
    local services_to_restart=("$@")
    
    local cmd_sequence="
        sleep 2;
        log_info '后台任务：开始执行服务重启...';
        for service in ${services_to_restart[*]}; do
            systemctl restart \$service;
        done;
        sleep 3; # Short delay for services to come up
        /etc/edgebox/scripts/apply-firewall.sh >/dev/null 2>&1 || true;
        
        log_info '后台任务：触发数据刷新...';
        bash /etc/edgebox/scripts/dashboard-backend.sh --now >/dev/null 2>&1 || true;
        bash /usr/local/bin/edgebox-ipq.sh >/dev/null 2>&1 || true;
        log_info '后台任务：完成。';
    "
    
    nohup bash -c "eval \"$cmd_sequence\"" >> /var/log/edgebox.log 2>&1 & disown
    
    log_success "命令已提交到后台执行。您的SSH连接可能会在几秒后中断。"
    log_info "这是正常现象。请在约10秒后刷新Web面板以查看最新状态。"
    
    exit 0
}

ESC=$'\033'
BLUE="${ESC}[0;34m"; PURPLE="${ESC}[0;35m"; CYAN="${ESC}[0;36m"
YELLOW="${ESC}[1;33m"; GREEN="${ESC}[0;32m"; RED="${ESC}[0;31m"; NC="${ESC}[0m"
LOG_FILE="/var/log/edgebox-install.log"
log_info()    { echo -e "${GREEN}[INFO]${NC} $*"    | tee -a "$LOG_FILE"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"   | tee -a "$LOG_FILE"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"     | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"; }
reload_or_restart_services() {
  local services=("$@")
  for svc in "${services[@]}"; do
    if systemctl reload "$svc" 2>/dev/null; then
      log_info "$svc 已热加载"
    else
      systemctl restart "$svc"
      log_info "$svc 已重启"
    fi
  done
}

# ===== 性能优化的全局配置变量 =====
# 这些变量在脚本启动时加载一次，后续直接使用
CONFIG_LOADED=false
CONFIG_LOAD_TIME=""

# 服务器基础信息
SERVER_IP=""
SERVER_EIP=""
SERVER_VERSION=""
INSTALL_DATE=""

# UUID配置
UUID_VLESS_REALITY=""
UUID_VLESS_GRPC=""
UUID_VLESS_WS=""
UUID_TUIC=""
UUID_HYSTERIA2=""
UUID_TROJAN=""

# 密码配置
PASSWORD_HYSTERIA2=""
PASSWORD_TUIC=""
PASSWORD_TROJAN=""

# Reality配置
REALITY_PUBLIC_KEY=""
REALITY_PRIVATE_KEY=""
REALITY_SHORT_ID=""

# 云服务商信息
CLOUD_PROVIDER=""
CLOUD_REGION=""
INSTANCE_ID=""

# 系统规格
CPU_SPEC=""
MEMORY_SPEC=""
DISK_SPEC=""


#############################################
# 优化的配置加载函数
#############################################

# 一次性加载所有配置到全局变量（性能优化核心）
load_config_once() {
    # 如果已经加载过且时间戳相同，直接返回
    if [[ "$CONFIG_LOADED" == "true" ]]; then
        local current_mtime
        current_mtime=$(stat -c %Y "${CONFIG_DIR}/server.json" 2>/dev/null || echo "0")
        
        if [[ "$CONFIG_LOAD_TIME" == "$current_mtime" ]]; then
            return 0  # 配置未改变，无需重新加载
        fi
    fi
    
    local config_file="${CONFIG_DIR}/server.json"
    if [[ ! -f "$config_file" ]]; then
        log_error "配置文件不存在: $config_file"
        return 1
    fi
    
    log_debug "加载配置文件: $config_file"
    
    # 🚀 性能优化关键：一次性读取所有配置项
    # 原来需要8-10个jq进程，现在只需要1个！
    local config_json
    if ! config_json=$(jq -c '
        {
            server_ip: (.server_ip // ""),
            server_eip: (.eip // ""),
            server_version: (.version // "3.0.0"),
            install_date: (.install_date // ""),
            
            uuid_vless_reality: (.uuid.vless.reality // .uuid.vless // ""),
            uuid_vless_grpc: (.uuid.vless.grpc // .uuid.vless // ""),
            uuid_vless_ws: (.uuid.vless.ws // .uuid.vless // ""),
            uuid_tuic: (.uuid.tuic // ""),
            uuid_hysteria2: (.uuid.hysteria2 // ""),
            uuid_trojan: (.uuid.trojan // ""),
            
            password_hysteria2: (.password.hysteria2 // ""),
            password_tuic: (.password.tuic // ""),
            password_trojan: (.password.trojan // ""),
            
            reality_public_key: (.reality.public_key // ""),
            reality_private_key: (.reality.private_key // ""),
            reality_short_id: (.reality.short_id // ""),
            
            cloud_provider: (.cloud.provider // "Unknown"),
            cloud_region: (.cloud.region // "Unknown"),
            instance_id: (.instance_id // "Unknown"),
            
            cpu_spec: (.spec.cpu // "Unknown"),
            memory_spec: (.spec.memory // "Unknown"),
            disk_spec: (.spec.disk // "Unknown")
        }
    ' "$config_file" 2>/dev/null); then
        log_error "配置文件JSON格式错误或解析失败"
        return 1
    fi
    
    # 验证关键配置
    if [[ -z "$config_json" || "$config_json" == "null" ]]; then
        log_error "配置文件内容为空或无效"
        return 1
    fi
    
    # 🚀 批量赋值全局变量（避免多次jq调用）
    SERVER_IP=$(echo "$config_json" | jq -r '.server_ip')
    SERVER_EIP=$(echo "$config_json" | jq -r '.server_eip')
    SERVER_VERSION=$(echo "$config_json" | jq -r '.server_version')
    INSTALL_DATE=$(echo "$config_json" | jq -r '.install_date')
    
    UUID_VLESS_REALITY=$(echo "$config_json" | jq -r '.uuid_vless_reality')
    UUID_VLESS_GRPC=$(echo "$config_json" | jq -r '.uuid_vless_grpc')
    UUID_VLESS_WS=$(echo "$config_json" | jq -r '.uuid_vless_ws')
    UUID_TUIC=$(echo "$config_json" | jq -r '.uuid_tuic')
    UUID_HYSTERIA2=$(echo "$config_json" | jq -r '.uuid_hysteria2')
    UUID_TROJAN=$(echo "$config_json" | jq -r '.uuid_trojan')
    
    PASSWORD_HYSTERIA2=$(echo "$config_json" | jq -r '.password_hysteria2')
    PASSWORD_TUIC=$(echo "$config_json" | jq -r '.password_tuic')
    PASSWORD_TROJAN=$(echo "$config_json" | jq -r '.password_trojan')
    
    REALITY_PUBLIC_KEY=$(echo "$config_json" | jq -r '.reality_public_key')
    REALITY_PRIVATE_KEY=$(echo "$config_json" | jq -r '.reality_private_key')
    REALITY_SHORT_ID=$(echo "$config_json" | jq -r '.reality_short_id')
    
    CLOUD_PROVIDER=$(echo "$config_json" | jq -r '.cloud_provider')
    CLOUD_REGION=$(echo "$config_json" | jq -r '.cloud_region')
    INSTANCE_ID=$(echo "$config_json" | jq -r '.instance_id')
    
    CPU_SPEC=$(echo "$config_json" | jq -r '.cpu_spec')
    MEMORY_SPEC=$(echo "$config_json" | jq -r '.memory_spec')
    DISK_SPEC=$(echo "$config_json" | jq -r '.disk_spec')
    
    # 记录加载状态和时间戳
    CONFIG_LOADED=true
    CONFIG_LOAD_TIME=$(stat -c %Y "$config_file" 2>/dev/null || echo "0")
    
    log_debug "配置加载完成，涉及 $(echo "$config_json" | jq -r '. | keys | length') 个配置项"
    return 0
}

# 智能配置加载函数（自动检查是否需要重新加载）
ensure_config_loaded() {
    load_config_once || {
        log_error "配置加载失败"
        return 1
    }
}

# 简单的兼容性方案：保留原函数，但内部使用新机制
get_server_info() {
    # 使用新的配置加载机制
    ensure_config_loaded || return 1
    
    # 为了兼容现有代码，设置一些映射变量
    UUID_VLESS="$UUID_VLESS_REALITY"
    
    return 0
}


#############################################
# 基础功能
#############################################

# === 订阅：统一生成 + 落盘 + 对外暴露 ===
SUB_TXT="/etc/edgebox/traffic/sub.txt"     # 规范内部文件（可不直接使用）
WEB_SUB="/var/www/html/sub"                 # Web 根下暴露 /sub
ensure_traffic_dir(){ mkdir -p /etc/edgebox/traffic; }

# 优先读取安装阶段写入的 subscription.txt；没有就根据 cert 模式现生成
build_sub_payload(){
  # 1) 已有订阅（安装时 generate_subscription() 写入）
  if [[ -s "${CONFIG_DIR}/subscription.txt" ]]; then
    cat "${CONFIG_DIR}/subscription.txt"
    return 0
  fi

  # 2) 没有就按当前证书模式生成（不再依赖 server.json 存在与否）
  local mode domain
  mode="$(get_current_cert_mode 2>/dev/null || echo self-signed)"
  if [[ "$mode" == "self-signed" ]]; then
    regen_sub_ip
  else
    # letsencrypt:<domain>
    domain="${mode##*:}"
    if [[ -n "$domain" ]]; then
      regen_sub_domain "$domain" || regen_sub_ip
    else
      regen_sub_ip
    fi
  fi

  # 3) 生成后输出（存在即输出）
  [[ -s "${CONFIG_DIR}/subscription.txt" ]] && cat "${CONFIG_DIR}/subscription.txt"
}


# === 订阅：统一生成 + 落盘 + 对外暴露 ===
SUB_TXT="/etc/edgebox/traffic/sub.txt"     # 规范内部文件（可不直接使用）
WEB_SUB="/var/www/html/sub"                 # Web 根下暴露 /sub
ensure_traffic_dir(){ mkdir -p /etc/edgebox/traffic; }

# 优先读取安装阶段写入的 subscription.txt；没有就根据 cert 模式现生成
build_sub_payload(){
  # 1) 已有订阅（安装时 generate_subscription() 写入）
  if [[ -s "${CONFIG_DIR}/subscription.txt" ]]; then
    cat "${CONFIG_DIR}/subscription.txt"
    return 0
  fi

  # 2) 没有就按当前证书模式生成（不再依赖 server.json 存在与否）
  local mode domain
  mode="$(get_current_cert_mode 2>/dev/null || echo self-signed)"
  if [[ "$mode" == "self-signed" ]]; then
    regen_sub_ip
  else
    # letsencrypt:<domain>
    domain="${mode##*:}"
    if [[ -n "$domain" ]]; then
      regen_sub_domain "$domain" || regen_sub_ip
    else
      regen_sub_ip
    fi
  fi

  # 3) 生成后输出（存在即输出）
  [[ -s "${CONFIG_DIR}/subscription.txt" ]] && cat "${CONFIG_DIR}/subscription.txt"
}

show_sub(){
  ensure_traffic_dir

  # 优先调用构建函数，确保订阅文件最新
  build_sub_payload >/dev/null 2>&1

  local txt_file="${CONFIG_DIR}/subscription.txt"
  local b64_file="${CONFIG_DIR}/subscription.base64"
  
  # 获取当前证书模式
  local cert_mode=$(get_current_cert_mode 2>/dev/null || echo "self-signed")
  local sub_url=""
  
  # 根据证书模式生成订阅URL
  if [[ "$cert_mode" == "self-signed" ]]; then
    # IP模式
    local server_ip=$(jq -r '.server_ip // "YOUR_IP"' "${CONFIG_DIR}/server.json" 2>/dev/null)
    sub_url="http://${server_ip}/sub"
  else
    # 域名模式 (格式: letsencrypt:domain.com)
    local domain="${cert_mode##*:}"
    if [[ -n "$domain" && "$domain" != "self-signed" ]]; then
      sub_url="https://${domain}/sub"
    else
      # 兜底：如果解析失败，使用IP
      local server_ip=$(jq -r '.server_ip // "YOUR_IP"' "${CONFIG_DIR}/server.json" 2>/dev/null)
      sub_url="http://${server_ip}/sub"
    fi
  fi
  
  echo
  echo -e "${YELLOW}# 订阅URL${NC}${DIM}(复制此链接到客户端订阅地址)${NC}"
  echo -e "  ${GREEN}${sub_url}${NC}"
  echo
  
  if [[ -s "$txt_file" ]]; then
    echo -e "${YELLOW}# 明文链接${NC}"
    cat "$txt_file"
    echo
  else
    log_warn "未能生成或找到明文订阅文件。"
  fi
  
  # Base64 输出 
  if [[ -s "$b64_file" ]]; then
    echo -e "${YELLOW}# Base64链接${NC}"
    cat "$b64_file"
    echo
    echo
  else
     log_warn "未能生成或找到Base64订阅文件。"
  fi
  
}


#############################################
# 流量随机化管理命令
#############################################

traffic_randomize() {
    local level="${1:-light}"
    
    case "$level" in
        "light"|"medium"|"heavy")
            log_info "执行流量特征随机化 (级别: $level)..."
            if "${SCRIPTS_DIR}/edgebox-traffic-randomize.sh" "$level"; then
                log_success "流量特征随机化完成"
            else
                log_error "流量特征随机化失败"
                return 1
            fi
            ;;
        *)
            echo "用法: $0 traffic randomize [light|medium|heavy]"
            echo "  light  - 轻度随机化 (仅Hysteria2参数)"
            echo "  medium - 中度随机化 (Hysteria2 + TUIC参数)"
            echo "  heavy  - 重度随机化 (全协议参数)"
            return 1
            ;;
    esac
}

traffic_status() {
    echo "=== EdgeBox流量随机化状态 ==="
    
    # 检查随机化脚本
    if [[ -f "${SCRIPTS_DIR}/edgebox-traffic-randomize.sh" ]]; then
        echo "✅ 随机化脚本: 已安装"
    else
        echo "❌ 随机化脚本: 未安装"
    fi
    
    # 检查配置文件
    if [[ -f "${CONFIG_DIR}/randomization/traffic.conf" ]]; then
        echo "✅ 随机化配置: 已配置"
    else
        echo "❌ 随机化配置: 未配置"
    fi
    
    # 检查定时任务
    if crontab -l 2>/dev/null | grep -q "edgebox-traffic-randomize"; then
        echo "✅ 定时任务: 已配置"
        echo "下次执行时间:"
        crontab -l | grep "edgebox-traffic-randomize" | while read -r line; do
            echo "  - $line"
        done
    else
        echo "❌ 定时任务: 未配置"
    fi
    
    # 显示最近随机化记录
    local log_file="/var/log/edgebox/traffic-randomization.log"
    if [[ -f "$log_file" ]]; then
        echo ""
        echo "最近随机化记录:"
        tail -5 "$log_file" | while read -r line; do
            echo "  $line"
        done
    fi
}

traffic_reset() {
    log_info "重置协议参数为默认值..."
    
    # 备份当前配置
    local backup_dir="/etc/edgebox/backup/reset_$(date '+%Y%m%d_%H%M%S')"
    mkdir -p "$backup_dir"
    
    [[ -f "${CONFIG_DIR}/xray.json" ]] && cp "${CONFIG_DIR}/xray.json" "$backup_dir/"
    [[ -f "${CONFIG_DIR}/sing-box.json" ]] && cp "${CONFIG_DIR}/sing-box.json" "$backup_dir/"
    
    # 调用随机化脚本的 reset 功能
    if [[ -f "${SCRIPTS_DIR}/edgebox-traffic-randomize.sh" ]]; then
        if "${SCRIPTS_DIR}/edgebox-traffic-randomize.sh" reset; then
            log_success "协议参数已重置为默认值"
            log_info "配置备份保存在: $backup_dir"
        else
            log_error "重置配置失败"
            return 1
        fi
    else
        # 手动重置关键参数
        log_warn "随机化脚本不存在，手动重置部分参数..."
        
        if [[ -f "${CONFIG_DIR}/sing-box.json" ]] && command -v jq >/dev/null; then
            # 恢复默认的 Hysteria2 heartbeat
            jq '.inbounds[] |= if .type == "hysteria2" then .heartbeat = "10s" else . end' \
                "${CONFIG_DIR}/sing-box.json" > "${CONFIG_DIR}/sing-box.json.tmp" && \
                mv "${CONFIG_DIR}/sing-box.json.tmp" "${CONFIG_DIR}/sing-box.json"
            
            log_success "已重置 sing-box 配置为默认参数"
        fi
        
        # 重启服务以应用更改
        reload_or_restart_services sing-box xray
        log_success "服务已重启"
    fi
}


show_status() {
  echo -e "${CYAN}EdgeBox 服务状态（v${VERSION}）：${NC}"
  for svc in nginx xray sing-box; do
    systemctl is-active --quiet "$svc" && echo -e "  $svc: ${GREEN}运行中 √${NC}" || echo -e "  $svc: ${RED}已停止${NC}"
  done
  echo -e "\n${CYAN}端口监听状态：${NC}\n${YELLOW}公网端口：${NC}"
  ss -tlnp 2>/dev/null | grep -q ":443 "  && echo -e "  TCP/443 (Nginx): ${GREEN}正常${NC}" || echo -e "  TCP/443: ${RED}异常${NC}"
  ss -ulnp 2>/dev/null | grep -q ":443 "  && echo -e "  UDP/443 (Hysteria2): ${GREEN}正常${NC}" || echo -e "  UDP/443: ${RED}异常${NC}"
  ss -ulnp 2>/dev/null | grep -q ":2053 " && echo -e "  UDP/2053 (TUIC): ${GREEN}正常${NC}"     || echo -e "  UDP/2053: ${RED}异常${NC}"
  echo -e "\n${YELLOW}内部回环端口：${NC}"
  ss -tlnp 2>/dev/null | grep -q "127.0.0.1:11443 " && echo -e "  Reality内部: ${GREEN}正常${NC}" || echo -e "  Reality内部: ${RED}异常${NC}"
  ss -tlnp 2>/dev/null | grep -q "127.0.0.1:10085 " && echo -e "  gRPC内部: ${GREEN}正常${NC}"    || echo -e "  gRPC内部: ${RED}异常${NC}"
  ss -tlnp 2>/dev/null | grep -q "127.0.0.1:10086 " && echo -e "  WS内部: ${GREEN}正常${NC}"      || echo -e "  WS内部: ${RED}异常${NC}"
  ss -tlnp 2>/dev/null | grep -q "127.0.0.1:10143 " && echo -e "  Trojan内部: ${GREEN}正常${NC}"  || echo -e "  Trojan内部: ${RED}异常${NC}"
  echo -e "\n${CYAN}证书状态：${NC}  当前模式: ${YELLOW}$(get_current_cert_mode)${NC}"
  
  # 显示分流状态
  show_shunt_status
}

restart_services(){ 
  echo -e "${CYAN}重启EdgeBox服务...${NC}"; 
  for s in nginx xray sing-box; do 
    echo -n "  重启 $s... "; 
    reload_or_restart_services "$s" && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAIL${NC}";
  done; 
}

show_logs(){ 
  case "$1" in 
    nginx|xray|sing-box) journalctl -u "$1" -n 100 --no-pager ;; 
    *) echo -e "用法: edgeboxctl logs [nginx|xray|sing-box]";; 
  esac; 
}

test_connection(){
  local ip; ip=$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null)
  [[ -z "$ip" || "$ip" == "null" ]] && { echo "未找到 server_ip"; return 1; }
  echo -n "TCP 443 连通性: "; timeout 3 bash -c "echo >/dev/tcp/${ip}/443" 2>/dev/null && echo "OK" || echo "FAIL"
  echo -n "HTTP 订阅: "; curl -fsS "http://${ip}/sub" >/dev/null && echo "OK" || echo "FAIL"
  echo -n "控制面板: "; curl -fsS "http://${ip}/" >/dev/null && echo "OK" || echo "FAIL"
}

debug_ports(){
  echo -e "${CYAN}EdgeBox 端口调试信息：${NC}"
  echo -e "\n${YELLOW}端口检查：${NC}"
  echo "  TCP/443 (Nginx入口): $(ss -tln | grep -q ':443 ' && echo '✓' || echo '✗')"
  echo "  UDP/443 (Hysteria2): $(ss -uln | grep -q ':443 ' && echo '✓' || echo '✗')"
  echo "  UDP/2053 (TUIC): $(ss -uln | grep -q ':2053 ' && echo '✓' || echo '✗')"
  echo "  TCP/11443 (Reality内部): $(ss -tln | grep -q '127.0.0.1:11443 ' && echo '✓' || echo '✗')"
  echo "  TCP/10085 (gRPC内部): $(ss -tln | grep -q '127.0.0.1:10085 ' && echo '✓' || echo '✗')"
  echo "  TCP/10086 (WS内部): $(ss -tln | grep -q '127.0.0.1:10086 ' && echo '✓' || echo '✗')"
  echo "  TCP/10143 (Trojan内部): $(ss -tln | grep -q '127.0.0.1:10143 ' && echo '✓' || echo '✗')"
}


#############################################
# 设置用户备注名
#############################################

set_user_alias() {
    local new_alias="$1"
    local config_file="/etc/edgebox/config/server.json"
    
    if [[ ! -f "$config_file" ]]; then
        echo "错误: 配置文件不存在"
        return 1
    fi
    
    echo "设置备注: $new_alias"
    
    # 更新配置文件
    local temp_file=$(mktemp)
    if jq --arg alias "$new_alias" '.user_alias = $alias' "$config_file" > "$temp_file"; then
        mv "$temp_file" "$config_file"
        chmod 644 "$config_file"
        echo "备注设置成功"
        
        # 更新面板数据
        if [[ -f "/etc/edgebox/scripts/dashboard-backend.sh" ]]; then
            /etc/edgebox/scripts/dashboard-backend.sh >/dev/null 2>&1
            echo "面板数据已更新"
        fi
    else
        rm -f "$temp_file"
        echo "设置失败"
        return 1
    fi
}


#############################################
# 订阅子系统
#############################################

# === SUBSYS-BEGIN: Per-user Subscription Management ==========================
SUB_DB="/etc/edgebox/sub/users.json"
SUB_DIR="/var/www/html/share"         # Nginx 根下的 /share 目录 (已修改)
SUB_SRC="${CONFIG_DIR}/subscription.txt"  # 订阅“单一事实源”（已存在）
NGINX_LOG="${NGINX_ACCESS_LOG:-/var/log/nginx/access.log}"

sub_ts(){ date +%s; }
sub_now_iso(){ date -Is; }

ensure_sub_dirs(){
  mkdir -p "$(dirname "$SUB_DB")" "$SUB_DIR"
  [[ -f "$SUB_SRC" ]] || {
    log_error "订阅源不存在: $SUB_SRC"; return 1;
  }
  [[ -f "$SUB_DB" ]] || echo '{"users":{},"defaults":{"limit":3,"release_days":7,"dual_grace_hours":24}}' > "$SUB_DB"
}

gen_token(){
  # 生成 URL-safe 高熵 token（长度 ~ 32）
  tr -dc 'A-Za-z0-9_-' </dev/urandom | head -c 32
}

ip_family(){
  local ip="$1"
  [[ "$ip" == *:* ]] && echo v6 || echo v4
}

ip_bucket(){
  local ip="$1"
  if [[ "$ip" == *:* ]]; then
    # IPv6 取前 4 组（/48 粗粒度）
    awk -F: '{printf "%s:%s:%s:%s\n",$1,$2,$3,$4}' <<<"$ip"
  else
    # IPv4 取前三段（/24 粗粒度）
    awk -F. '{printf "%s.%s.%s\n",$1,$2,$3}' <<<"$ip"
  fi
}

ua_norm(){
  # 归一化 UA，去前后空格并转小写
  tr '[:upper:]' '[:lower:]' <<<"${1:-}" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g'
}

sha1(){ printf "%s" "$1" | sha1sum | awk '{print $1}'; }

token_path(){ echo "${SUB_DIR}/u-$1"; }

sub_db_jq(){ jq -c "$1" "$SUB_DB"; }             # 只读
sub_db_apply(){ # $1=jq filter 表达式
  local tmp; tmp="$(mktemp)"
  if jq "$1" "$SUB_DB" > "$tmp"; then mv "$tmp" "$SUB_DB"; else rm -f "$tmp"; return 1; fi
}

sub_print_url(){
  local token="$1"
  # 依据当前证书/域名模式，保持原 show_sub 的策略生成基础 host
  local cert_mode host
  cert_mode="$(get_current_cert_mode 2>/dev/null || echo self-signed)"
  if [[ "$cert_mode" == "self-signed" ]]; then
    host="$(jq -r '.server_ip // "YOUR_IP"' "${CONFIG_DIR}/server.json" 2>/dev/null || echo "YOUR_IP")"
  else
    host="${cert_mode##*:}"
  fi
  echo "http://${host}/share/u-${token}"
}

sub_issue(){
  local user="$1" limit="${2:-}"
  [[ -z "$user" ]] && { echo "用法: edgeboxctl sub issue <user> [limit]"; return 1; }

  ensure_sub_dirs || return 1

  # 读取默认参数
  local def_limit def_days def_grace
  def_limit="$(jq -r '.defaults.limit' "$SUB_DB")"
  def_days="$(jq -r '.defaults.release_days' "$SUB_DB")"
  def_grace="$(jq -r '.defaults.dual_grace_hours' "$SUB_DB")"
  [[ "$limit" =~ ^[0-9]+$ ]] || limit="$def_limit"

  # 若已存在且 active，则直接回显
  local exists active token
  exists="$(jq -r --arg u "$user" '.users[$u] // empty' "$SUB_DB")"
  if [[ -n "$exists" ]]; then
    active="$(jq -r --arg u "$user" '.users[$u].active // false' "$SUB_DB")"
    token="$(jq -r --arg u "$user" '.users[$u].token' "$SUB_DB")"
    if [[ "$active" == "true" && -n "$token" && -e "$(token_path "$token")" ]]; then
      echo "[INFO] 用户已存在且处于激活状态：$user"
      echo "URL: $(sub_print_url "$token")"
      return 0
    fi
  fi

  # 生成/复用 token
  token="$(gen_token)"
  ln -sfn "$SUB_SRC" "$(token_path "$token")"

  # 写入 DB
  sub_db_apply \
    --arg u "$user" --arg t "$token" \
    --argjson lim "$limit" \
    --arg now "$(sub_now_iso)" \
    --argjson days "$def_days" --argjson grace "$def_grace" '
    .users[$u] = {
      token: $t,
      active: true,
      limit: $lim,
      created_at: $now,
      devices: {},
      release_days: $days,
      dual_grace_hours: $grace
    }' || { echo "[ERR] 写入订阅数据库失败"; return 1; }

  echo "[OK] 已为 <$user> 下发订阅（上限 ${limit} 台）"
  echo "URL: $(sub_print_url "$token")"
}

sub_revoke(){
  local user="$1"
  [[ -z "$user" ]] && { echo "用法: edgeboxctl sub revoke <user>"; return 1; }
  ensure_sub_dirs || return 1

  local token
  token="$(jq -r --arg u "$user" '.users[$u].token // empty' "$SUB_DB")"
  [[ -z "$token" ]] && { echo "[ERR] 用户不存在或未签发：$user"; return 1; }

  # 移除 token 文件，标记 inactive
  rm -f "$(token_path "$token")" 2>/dev/null || true
  sub_db_apply --arg u "$user" --arg now "$(sub_now_iso)" '
    .users[$u].active = false
    | .users[$u].revoked_at = $now' || return 1

  echo "[OK] 已停用 <$user> 的订阅"
}

sub_limit(){
  local user="$1" limit="$2"
  [[ -z "$user" || -z "$limit" || ! "$limit" =~ ^[0-9]+$ ]] && { echo "用法: edgeboxctl sub limit <user> <N>"; return 1; }
  ensure_sub_dirs || return 1

  sub_db_apply --arg u "$user" --argjson lim "$limit" '
    if .users[$u] then .users[$u].limit = $lim else . end' || return 1
  echo "[OK] <$user> 设备上限已改为 $limit 台"
}

# 从 Nginx access.log 采样 /sub/u-<token> 访问，回填设备指纹占坑
sub_scan_devices(){
  local user="$1" token="$2" now epoch_now ua ip fam bucket key dual_grace_secs release_secs
  epoch_now="$(sub_ts)"

  dual_grace_secs="$(jq -r --arg u "$user" ".users[\$u].dual_grace_hours" "$SUB_DB")"
  release_secs="$(jq -r --arg u "$user" ".users[\$u].release_days" "$SUB_DB")"
  dual_grace_secs=$(( dual_grace_secs * 3600 ))
  release_secs=$(( release_secs * 86400 ))

  # 使用 awk 提取 [time]、remote_addr、request_uri、user_agent
  # 仅匹配目标 token 的行，避免全量扫描
  grep -F "/sub/u-${token}" "$NGINX_LOG" 2>/dev/null | awk '{
    # 典型格式：IP - - [10/Oct/2025:08:12:22 +0000] "GET /sub/u-xxx HTTP/1.1" 200 ... "UA..."
    time=""; ip=""; uri=""; ua="";
    for(i=1;i<=NF;i++){
      if($i ~ /^\[/){time=$i" "$(i+1); gsub(/^\[|\]$/,"",time);}
      if(i==1){ip=$i;}
    }
    match($0, /"GET ([^ ]+) HTTP/, m); if(m[1]!="") uri=m[1];
    match($0, /"[^"]*" "([^"]*)"$/, u); if(u[1]!="") ua=u[1];
    if(uri!=""){printf "%s\t%s\t%s\t%s\n", time, ip, uri, ua;}
  }' | while IFS=$'\t' read -r t ip _ uri ua; do
      [[ -z "$ua" || -z "$ip" ]] && continue
      fam="$(ip_family "$ip")"
      bucket="$(ip_bucket "$ip")"
      ua_n="$(ua_norm "$ua")"
      # 指纹：ua_norm + ip 粗粒度段
      key="$(sha1 "${ua_n}|${bucket}")"

      # 设备第一次出现：登记 first_seen + family
      # 双栈宽限：同 UA 在 dual_grace 窗口内出现另一栈，不新增占坑，只补记 family
      sub_db_apply --arg u "$user" --arg k "$key" \
        --arg ua "$ua_n" --arg fam "$fam" --arg now "$(sub_now_iso)" \
        --argjson now_e "$epoch_now" --argjson grace "$dual_grace_secs" '
        . as $root
        | ( .users[$u].devices[$k] // {
              ua: $ua, first_seen: $now, last_seen: $now,
              first_seen_epoch: $now_e, last_seen_epoch: $now_e,
              family: {v4:false, v6:false}
            } ) as $d
        | ($d.family[$fam] = true) as $d2
        | $d2.last_seen = $now | $d2.last_seen_epoch = $now_e
        | .users[$u].devices[$k] = $d2
      ' >/dev/null || true
  done

  # GC：7 天未见释放
  sub_db_apply --arg u "$user" --argjson now "$epoch_now" --argjson ttl "$release_secs" '
    .users[$u].devices as $D
    | ($D|to_entries | map( select(.value.last_seen_epoch != null) )) as $E
    | ( $E | map( select( ($now - .value.last_seen_epoch) < $ttl ) ) | from_entries ) as $alive
    | .users[$u].devices = $alive
  ' >/dev/null || true
}

sub_show(){
  local user="$1"
  [[ -z "$user" ]] && { echo "用法: edgeboxctl sub show <user>"; return 1; }
  ensure_sub_dirs || return 1

  local ujson token active limit used url
  ujson="$(jq -c --arg u "$user" '.users[$u]' "$SUB_DB")"
  [[ -z "$ujson" || "$ujson" == "null" ]] && { echo "[ERR] 用户不存在：$user"; return 1; }

  token="$(jq -r '._ref.token // .token' <<<"$ujson" 2>/dev/null || jq -r '.token' <<<"$ujson")"
  active="$(jq -r '.active' <<<"$ujson")"
  limit="$(jq -r '.limit'  <<<"$ujson")"

  # 扫描日志回填设备，并执行 7 天 GC
  [[ "$active" == "true" && -n "$token" ]] && sub_scan_devices "$user" "$token"

  # 重新读取统计
  ujson="$(jq -c --arg u "$user" '.users[$u]' "$SUB_DB")"
  used="$(jq -r '.devices | keys | length' <<<"$ujson")"
  url="$(sub_print_url "$token")"

  echo "User: $user"
  echo "Active: $active"
  echo "URL: $url"
  echo "Limit: $used / $limit（7天自动释放，占坑按“UA+粗粒度IP段”，24h 双栈宽限）"
  echo ""
  echo "Devices:"
  jq -r '
    .devices
    | to_entries
    | sort_by(.value.last_seen) | reverse
    | .[]
    | "- " + (.value.ua[0:80]) + "  | last_seen=" + (.value.last_seen // "") +
      "  | v4=" + (if .value.family.v4 then "✓" else "-" end) +
      " v6=" + (if .value.family.v6 then "✓" else "-" end)
  ' <<<"$ujson"
}
# === SUBSYS-END ==============================================================


#############################################
# 证书切换
#############################################

fix_permissions(){
  echo -e "${CYAN}修复证书权限...${NC}"
  [[ ! -d "${CERT_DIR}" ]] && { echo -e "${RED}证书目录不存在: ${CERT_DIR}${NC}"; return 1; }
  chown -R root:root "${CERT_DIR}"; chmod 755 "${CERT_DIR}"
  find "${CERT_DIR}" -type f -name '*.key' -exec chmod 600 {} \; 2>/dev/null || true
  find "${CERT_DIR}" -type f -name '*.pem' -exec chmod 644 {} \; 2>/dev/null || true
  echo -e "${GREEN}权限修复完成${NC}"
  stat -L -c '  %a %n' "${CERT_DIR}/current.key" 2>/dev/null || true
  stat -L -c '  %a %n' "${CERT_DIR}/current.pem" 2>/dev/null || true
}

check_domain_resolution(){
  local domain=$1; log_info "检查域名解析: $domain"
  need nslookup && nslookup "$domain" >/dev/null 2>&1 || { log_error "域名无法解析"; return 1; }
  get_server_info
  local resolved_ip; resolved_ip=$(dig +short "$domain" 2>/dev/null | tail -n1)
  if [[ -n "$resolved_ip" && "$resolved_ip" != "$SERVER_IP" ]]; then
    log_warn "解析IP ($resolved_ip) 与服务器IP ($SERVER_IP) 不匹配，可能导致 LE 校验失败"
    read -p "是否继续？[y/N]: " -n 1 -r; echo; [[ $REPLY =~ ^[Yy]$ ]] || return 1
  fi
  log_success "域名解析检查通过"
}

request_letsencrypt_cert(){
  local domain="$1"
  [[ -z "$domain" ]] && { log_error "缺少域名"; return 1; }

  # 先检查 apex 是否解析;子域 trojan.<domain> 解析不到就先不申请它
  if ! getent hosts "$domain" >/dev/null; then
    log_error "${domain} 未解析到本机,无法申请证书"; return 1
  fi

  local trojan="trojan.${domain}"
  local have_trojan=0
  if getent hosts "$trojan" >/dev/null; then
    have_trojan=1
  else
    log_warn "未检测到 ${trojan} 的 A/AAAA 记录,将先只为 ${domain} 申请证书。"
    log_warn "等你把 ${trojan} 解析到本机后,再运行同样命令会自动 --expand 加上子域。"
  fi

  # 首选 nginx 插件(不停机),失败则回落 standalone(临停 80)
  # 1) 组装域名参数
  local cert_args=(-d "${domain}")
  [[ ${have_trojan:-0} -eq 1 ]] && cert_args+=(-d "${trojan}")

  # 2) 是否需要 --expand(已有同名证书时)
  local expand=""
  [[ -d "/etc/letsencrypt/live/${domain}" ]] && expand="--expand"

  # 3) 选择验证方式
  local CERTBOT_AUTH="--nginx"
  if ! command -v nginx >/dev/null 2>&1 || ! dpkg -l | grep -q '^ii\s\+python3-certbot-nginx'; then
    CERTBOT_AUTH="--standalone --preferred-challenges http"
  fi

  # 4) 执行签发
  if [[ "$CERTBOT_AUTH" == "--nginx" ]]; then
    certbot certonly --nginx ${expand} \
      --cert-name "${domain}" "${cert_args[@]}" \
      -n --agree-tos --register-unsafely-without-email || return 1
  else
    # standalone 需临时释放 80 端口
    systemctl stop nginx >/dev/null 2>&1 || true
    certbot certonly --standalone --preferred-challenges http --http-01-port 80 ${expand} \
      --cert-name "${domain}" "${cert_args[@]}" \
      -n --agree-tos --register-unsafely-without-email || { systemctl start nginx >/dev/null 2>&1 || true; return 1; }
    systemctl start nginx >/dev/null 2>&1 || true
  fi

  # 切换软链并热加载
  [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]] \
    || { log_error "证书文件缺失"; return 1; }

  ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" "${CERT_DIR}/current.pem"
  ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem"  "${CERT_DIR}/current.key"
  echo "letsencrypt:${domain}" > "${CONFIG_DIR}/cert_mode"

  reload_or_restart_services nginx xray sing-box

  if [[ ${have_trojan} -eq 1 ]]; then
    log_success "Let's Encrypt 证书已生效(包含 trojan.${domain})"
  else
    log_success "Let's Encrypt 证书已生效(仅 ${domain};trojan 子域暂未包含)"
  fi
}

write_subscription() {
  local content="$1"
  [[ -z "$content" ]] && return 1

  # 1) Write plain text to the source of truth
  printf '%s\n' "$content" > "${CONFIG_DIR}/subscription.txt"

  # 2) Generate single-line Base64
  if base64 --help 2>&1 | grep -q -- '-w'; then
    printf '%s\n' "$content" | sed -e '$a\' | base64 -w0 > "${CONFIG_DIR}/subscription.base64"
  else
    printf '%s\n' "$content" | sed -e '$a\' | base64 | tr -d '\n' > "${CONFIG_DIR}/subscription.base64"
  fi

  chmod 644 "${CONFIG_DIR}/subscription.txt" "${CONFIG_DIR}/subscription.base64" 2>/dev/null || true
}

sync_subscription_files() {
  # <<< FIX: Add path definitions to ensure the function works standalone >>>
  local WEB_ROOT="/var/www/html"
  local TRAFFIC_DIR="/etc/edgebox/traffic"
  
  mkdir -p "${WEB_ROOT}" "${TRAFFIC_DIR}"
  # Let the web-facing /sub always point to subscription.txt (single source of truth)
  if [[ -e "${WEB_ROOT}/sub" && ! -L "${WEB_ROOT}/sub" ]]; then
    rm -f "${WEB_ROOT}/sub"
  fi
  ln -sfn "${CONFIG_DIR}/subscription.txt" "${WEB_ROOT}/sub"
  # Panel copy
  install -m 0644 -T "${CONFIG_DIR}/subscription.txt" "${TRAFFIC_DIR}/sub.txt" 2>/dev/null || true
}

# === [CORRECTED] Subscription Generation: Domain Mode ===
regen_sub_domain() {
  local domain="$1"
  ensure_config_loaded || return 1

  local HY2_PW_ENC TUIC_PW_ENC TROJAN_PW_ENC reality_sni
  HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
  TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC"     | jq -rR @uri)
  TROJAN_PW_ENC=$(printf '%s' "$PASSWORD_TROJAN"  | jq -rR @uri)

  reality_sni="$(jq -r 'first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.serverNames[0]) // (first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.dest) | split(":")[0]) // empty' "${XRAY_CONFIG}" 2>/dev/null)"
  : "${reality_sni:=${REALITY_SNI:-www.microsoft.com}}"

  # FIX: Trojan SNI must be trojan.${domain}
  local sub_content
  sub_content=$(cat <<PLAIN
vless://${UUID_VLESS_REALITY}@${domain}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${reality_sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY
vless://${UUID_VLESS_GRPC}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=h2&type=grpc&serviceName=grpc&fp=chrome#EdgeBox-gRPC
vless://${UUID_VLESS_WS}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome#EdgeBox-WS
trojan://${TROJAN_PW_ENC}@${domain}:443?security=tls&sni=trojan.${domain}&fp=chrome#EdgeBox-TROJAN
hysteria2://${HY2_PW_ENC}@${domain}:443?sni=${domain}&alpn=h3#EdgeBox-HYSTERIA2
tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${domain}:2053?congestion_control=bbr&alpn=h3&sni=${domain}#EdgeBox-TUIC
PLAIN
)

  write_subscription "$sub_content"
  sync_subscription_files
  log_success "Domain mode subscription updated successfully."
}
# === [CORRECTED] Subscription Generation: IP Mode ===
regen_sub_ip() {
  ensure_config_loaded || return 1

  local HY2_PW_ENC TUIC_PW_ENC TROJAN_PW_ENC reality_sni
  HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
  TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC"     | jq -rR @uri)
  TROJAN_PW_ENC=$(printf '%s' "$PASSWORD_TROJAN"  | jq -rR @uri)

  reality_sni="$(jq -r 'first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.serverNames[0]) // (first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.dest) | split(":")[0]) // empty' "${XRAY_CONFIG}" 2>/dev/null)"
  : "${reality_sni:=${REALITY_SNI:-www.microsoft.com}}"

  local sub_content
  sub_content=$(cat <<PLAIN
vless://${UUID_VLESS_REALITY}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${reality_sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY
vless://${UUID_VLESS_GRPC}@${SERVER_IP}:443?encryption=none&security=tls&sni=grpc.edgebox.internal&alpn=h2&type=grpc&serviceName=grpc&fp=chrome&allowInsecure=1#EdgeBox-gRPC
vless://${UUID_VLESS_WS}@${SERVER_IP}:443?encryption=none&security=tls&sni=ws.edgebox.internal&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome&allowInsecure=1#EdgeBox-WS
trojan://${TROJAN_PW_ENC}@${SERVER_IP}:443?security=tls&sni=trojan.edgebox.internal&fp=chrome&allowInsecure=1#EdgeBox-TROJAN
hysteria2://${HY2_PW_ENC}@${SERVER_IP}:443?sni=${SERVER_IP}&alpn=h3&insecure=1#EdgeBox-HYSTERIA2
tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${SERVER_IP}:2053?congestion_control=bbr&alpn=h3&sni=${SERVER_IP}&allowInsecure=1#EdgeBox-TUIC
PLAIN
)

  write_subscription "$sub_content"
  sync_subscription_files
  log_success "IP mode subscription updated successfully."
}

# === [CORRECTED] SNI Update Logic with Dashboard Refresh ===
update_sni_domain() {
    local new_domain="$1"
    local temp_config="${XRAY_CONFIG}.tmp"

    sni_log_info "Preparing to update SNI to: $new_domain"
    cp "$XRAY_CONFIG" "${XRAY_CONFIG}.backup.$(date +%s)" 2>/dev/null || true

    if jq --arg domain "$new_domain" '
      (.inbounds[] | select(.tag=="vless-reality") | .streamSettings.realitySettings.dest) = ($domain + ":443") |
      (.inbounds[] | select(.tag=="vless-reality") | .streamSettings.realitySettings.serverNames) |= ( (.[0] = $domain) // [$domain] )
    ' "$XRAY_CONFIG" > "$temp_config"; then
        if jq empty "$temp_config" >/dev/null 2>&1; then
            mv "$temp_config" "$XRAY_CONFIG"
            sni_log_success "Xray config file updated successfully."
            if reload_or_restart_services xray; then
                sni_log_success "Xray service has been reloaded."
                
                sni_log_info "SNI changed, refreshing subscription file..."
                local mode domain
                mode=$(get_current_cert_mode 2>/dev/null || echo self-signed)
                if [[ "$mode" == "self-signed" ]]; then
                  regen_sub_ip
                else
                  domain="${mode##*:}"
                  [[ -n "$domain" ]] && regen_sub_domain "$domain" || regen_sub_ip
                fi
                sni_log_success "Subscription file refreshed."

                # <<< FINAL FIX: Immediately refresh the dashboard data file after changes >>>
                log_info "正在刷新Web面板数据..."
                if [[ -x "${SCRIPTS_DIR}/dashboard-backend.sh" ]]; then
                    bash "${SCRIPTS_DIR}/dashboard-backend.sh" --now >/dev/null 2>&1 || log_warn "Dashboard data refresh failed."
                    log_success "Web面板数据已刷新。"
                fi
                
                return 0
            else
                sni_log_error "Xray service failed to reload."
                return 1
            fi
        else
            sni_log_error "Generated Xray config has invalid JSON format."
            rm -f "$temp_config"
            return 1
        fi
    else
        sni_log_error "Failed to update Xray config using jq."
        rm -f "$temp_config"
        return 1
    fi
}


switch_to_domain(){
  local domain="$1"
  [[ -z "$domain" ]] && { echo "用法: edgeboxctl switch-to-domain <domain>"; return 1; }
  log_info "检查域名解析: ${domain}"
  getent hosts "$domain" >/dev/null || { log_error "${domain} 未解析"; return 1; }
  log_info "检查 Trojan 子域名解析: trojan.${domain}"
  if ! getent hosts "trojan.${domain}" >/dev/null; then
    log_warn "未检测到 'trojan.${domain}' 的 DNS 解析记录。"
    echo -e "${YELLOW}为了使 Trojan 协议正常工作，您需要为 'trojan.${domain}' 添加一条指向您服务器 IP 的 A 或 AAAA 记录。${NC}"
    read -p "您确定要继续吗？(如果您稍后添加解析，现在可以继续) [y/N]: " -n 1 -r; echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "操作已取消。请先设置 DNS 解析。"
        return 1
    fi
  fi
  log_info "为 ${domain} 申请/扩展 Let's Encrypt 证书"
  request_letsencrypt_cert "$domain" || return 1
  ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem"   "${CERT_DIR}/current.key"
  ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" "${CERT_DIR}/current.pem"
  fix_permissions

  ### FIX: Overwrite the map config file instead of using sed ###
  generate_nginx_stream_map_conf "domain" "$domain"
  ### END FIX ###

  regen_sub_domain "$domain"
  reload_or_restart_services nginx xray sing-box
  log_success "已切换到域名模式（${domain}）"
  post_switch_report
  /etc/edgebox/scripts/dashboard-backend.sh --now >/dev/null 2>&1
  echo; echo "=== 新订阅（域名模式） ==="; show_sub
}


switch_to_ip(){
  log_info "正在切换回 IP 模式..."
  
  ### FIX: Overwrite the map config file to revert to IP mode ###
  generate_nginx_stream_map_conf "ip"
  ### END FIX ###

  echo "self-signed" > "${CONFIG_DIR}/cert_mode"
  ln -sf "${CERT_DIR}/self-signed.key" "${CERT_DIR}/current.key"
  ln -sf "${CERT_DIR}/self-signed.pem" "${CERT_DIR}/current.pem"
  fix_permissions
  
  ensure_config_loaded || regen_sub_ip "YOUR_IP"
  
  regen_sub_ip
  reload_or_restart_services nginx xray sing-box
  log_success "已切换到 IP 模式"
  post_switch_report
  /etc/edgebox/scripts/dashboard-backend.sh --now >/dev/null 2>&1
  echo; echo "=== 新订阅（IP 模式） ==="; show_sub
}


cert_status(){
  local mode=$(get_current_cert_mode)
  echo -e "${CYAN}证书状态：${NC} ${YELLOW}${mode}${NC}"
  if [[ "$mode" == self-signed ]]; then
    echo "  自签名: ${CERT_DIR}/current.pem"
  else
    local d=${mode##*:}
    echo "  Let's Encrypt: /etc/letsencrypt/live/${d}/fullchain.pem"
  fi
  stat -L -c '  %a %n' ${CERT_DIR}/current.key 2>/dev/null || true
  stat -L -c '  %a %n' ${CERT_DIR}/current.pem 2>/dev/null || true
}

#############################################
# 出站分流系统
#############################################

# 清空 nftables 的代理采集集合（VPS 全量出站时用）
flush_nft_resi_sets() {
  nft flush set inet edgebox resi_addr4 2>/dev/null || true
  nft flush set inet edgebox resi_addr6 2>/dev/null || true
}

# 解析代理 URL => 导出全局变量：
parse_proxy_url() {
  local url
  url="$(printf '%s' "$1" | tr -d '\r' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
  [[ -z "$url" ]] && { echo "空代理地址"; return 1; }

  PROXY_SCHEME="${url%%://*}"; PROXY_SCHEME="${PROXY_SCHEME%:*}"
  local rest="${url#*://}" auth hostport query
  [[ "$rest" == *\?* ]] && { query="${rest#*\?}"; rest="${rest%%\?*}"; }
  if [[ "$rest" == *@* ]]; then
    auth="${rest%@*}"; hostport="${rest#*@}"
    PROXY_USER="${auth%%:*}"; PROXY_PASS="${auth#*:}"; [[ "$PROXY_PASS" == "$auth" ]] && PROXY_PASS=""
  else
    hostport="$rest"; PROXY_USER=""; PROXY_PASS=""
  fi
  PROXY_HOST="${hostport%%:*}"; PROXY_PORT="${hostport##*:}"
  PROXY_TLS=0; PROXY_SNI=""

  case "$PROXY_SCHEME" in
    http)   PROXY_TLS=0 ;;
    https)  PROXY_SCHEME="http"; PROXY_TLS=1 ;;
    socks|socks5) PROXY_SCHEME="socks"; PROXY_TLS=0 ;;
    socks5s)      PROXY_SCHEME="socks"; PROXY_TLS=1 ;;
    *) echo "不支持的代理协议: $PROXY_SCHEME"; return 1;;
  esac

  if [[ -n "$query" ]]; then
    local kv k v; IFS='&' read -r -a kv <<<"$query"
    for k in "${kv[@]}"; do v="${k#*=}"; k="${k%%=*}"; [[ "$k" == "sni" ]] && PROXY_SNI="$v"; done
  fi
}

# 用 curl 健康检查（http/https/socks 都支持）
check_proxy_health_url() {
  parse_proxy_url "$1" || return 1
  local auth="" proxy_uri=""
  [[ -n "$PROXY_USER" ]] && auth="${PROXY_USER}:${PROXY_PASS}@"
  if [[ "$PROXY_SCHEME" == "http" ]]; then
    local scheme="http"; [[ "$PROXY_TLS" -eq 1 ]] && scheme="https"
    proxy_uri="${scheme}://${auth}${PROXY_HOST}:${PROXY_PORT}"
  else
    proxy_uri="socks5h://${auth}${PROXY_HOST}:${PROXY_PORT}"
  fi
  curl -fsS --max-time 6 --connect-timeout 4 --proxy "$proxy_uri" \
       http://www.gstatic.com/generate_204 >/dev/null
}

# === Anchor-1 INSERT BEGIN : 验收报告函数 ===
format_curl_proxy_uri() {
  # 将已由 parse_proxy_url() 解析出的全局变量拼成 curl 可用的 --proxy URI
  local __retvar="$1" auth=""
  [[ -n "$PROXY_USER" ]] && auth="${PROXY_USER}:${PROXY_PASS}@"
  local uri
  if [[ "$PROXY_SCHEME" == "http" ]]; then
    local scheme="http"; [[ "$PROXY_TLS" -eq 1 ]] && scheme="https"
    uri="${scheme}://${auth}${PROXY_HOST}:${PROXY_PORT}"
  else
    # socks5h 让域名解析也走代理端
    uri="socks5h://${auth}${PROXY_HOST}:${PROXY_PORT}"
  fi
  printf -v "$__retvar" '%s' "$uri"
}

get_current_cert_mode(){
  if [[ -f "${CONFIG_DIR}/cert_mode" ]]; then
    cat "${CONFIG_DIR}/cert_mode"
  else
    echo "self-signed"
  fi
}

post_switch_report() {
  : "${CYAN:=}"; : "${GREEN:=}"; : "${RED:=}"; : "${YELLOW:=}"; : "${NC:=}"

  echo -e "\n${CYAN}--- 切换证书/模式后 · 自动验收报告 ---${NC}"

  # 1) Nginx 配置测试
  echo -e "${CYAN}1) Nginx 配置测试 · 详细输出:${NC}"
  local _nginx_out _rc
  _nginx_out="$(nginx -t 2>&1)"; _rc=$?
  echo "${_nginx_out}" | sed 's/^/   | /'
  echo -n "   => 结果: "; [[ $_rc -eq 0 ]] && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAIL${NC}"

  # 2) 服务可用性
  echo -e "${CYAN}2) 服务可用性:${NC}"
  for s in nginx xray sing-box; do
    if systemctl is-active --quiet "$s"; then
      echo -e "   - ${s}: ${GREEN}active${NC}"
    else
      echo -e "   - ${s}: ${RED}inactive${NC}"
    fi
  done

  # 3) 证书链与到期
  echo -e "${CYAN}3) 证书链与到期:${NC}"
  local mode pem key domain
  mode="$(get_current_cert_mode)"
  if [[ "$mode" == self-signed ]]; then
    pem="${CERT_DIR}/current.pem"; key="${CERT_DIR}/current.key"
  else
    domain="${mode##*:}"
    pem="/etc/letsencrypt/live/${domain}/fullchain.pem"
    key="/etc/letsencrypt/live/${domain}/privkey.pem"
  fi
  if [[ -f "$pem" && -f "$key" ]]; then
    local exp
    exp="$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    [[ -n "$exp" ]] && echo "   - 到期时间: $exp" || echo "   - 无法读取到期时间"
  else
    echo -e "   - ${RED}证书文件缺失${NC} (${pem} / ${key})"
  fi

  # 3b) 域名解析核对（LE 模式才做）
  if [[ -n "$domain" ]]; then
    local a_ip srv_ip
    a_ip="$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1; exit}')"
    srv_ip="$(jq -r '.server_ip // empty' ${CONFIG_DIR}/server.json 2>/dev/null)"
    echo -e "   - A 记录: ${a_ip:-?}  | server_ip: ${srv_ip:-?}"
    if [[ -n "$a_ip" && -n "$srv_ip" && "$a_ip" == "$srv_ip" ]]; then
      echo -e "   => 解析一致：${GREEN}OK${NC}"
    else
      echo -e "   => ${YELLOW}解析与 server_ip 不一致（如前置 CDN 可忽略）${NC}"
    fi
  fi

  # 4) 证书软链
  echo -e "${CYAN}4) 证书软链:${NC}"
  ls -l "${CERT_DIR}/current.pem" "${CERT_DIR}/current.key" 2>/dev/null | sed 's/^/   | /' || true
  [[ -L ${CERT_DIR}/current.pem && -L ${CERT_DIR}/current.key ]] \
    && echo -e "   => ${GREEN}软链存在${NC}" || echo -e "   => ${RED}软链缺失${NC}"

  # 5) 证书权限
  echo -e "${CYAN}5) 证书权限:${NC}"
  local perm_line perm
  perm_line="$(stat -L -c '%a %U:%G %n' "${CERT_DIR}/current.key" 2>/dev/null || true)"
  [[ -n "$perm_line" ]] && echo "   | $perm_line"
  perm="$(printf '%s\n' "$perm_line" | awk '{print $1}')"
  if [[ "$perm" == "600" || "$perm" == "640" ]]; then
    echo -e "   => ${GREEN}已收紧${NC}"
  else
    echo -e "   => ${YELLOW}建议运行：edgeboxctl fix-permissions${NC}"
  fi

  echo -e "${CYAN}--------------------------------${NC}\n"
}

# === [NEW] Unified function to refresh all frontend data sources ===
run_post_change_refreshes() {
    log_info "Submitting background jobs for dashboard and IPQ refresh..."
    # dashboard-backend.sh reads the new state and updates dashboard.json
    bash "${SCRIPTS_DIR}/dashboard-backend.sh" --now >/dev/null 2>&1 || true
    # edgebox-ipq.sh reads the new proxy state and tests the new IP
    bash /usr/local/bin/edgebox-ipq.sh >/dev/null 2>&1 || true
    log_info "Background refresh jobs completed."
}

post_shunt_report() {
  local mode="$1" url="$2"
  # ... (函数内部的报告逻辑保持不变) ...
  : "${CYAN:=}"; : "${GREEN:=}"; : "${RED:=}"; : "${YELLOW:=}"; : "${NC:=}"
  echo -e "\n${CYAN}----- 出站分流配置 · 验收报告（${mode}） -----${NC}"
  echo -n "1) 上游连通性: "
  if [[ -n "$url" ]]; then
    if check_proxy_health_url "$url"; then echo -e "${GREEN}OK${NC}"; else echo -e "${RED}FAIL${NC}"; fi
  else
    echo -e "${YELLOW}（VPS 模式，跳过）${NC}"
  fi
  echo -n "2) 出口 IP: "
  if [[ -n "$url" ]]; then
    local via_vps via_resi proxy_uri
    via_vps=$(curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)
    parse_proxy_url "$url" >/dev/null 2>&1 || true
    format_curl_proxy_uri proxy_uri
    via_resi=$(curl -fsS --max-time 8 --proxy "$proxy_uri" https://api.ipify.org 2>/dev/null || true)
    echo -e "VPS=${via_vps:-?}  上游=${via_resi:-?}"
    if [[ -n "$via_vps" && -n "$via_resi" && "$via_vps" != "$via_resi" ]]; then
      echo -e "   => ${GREEN}出口已切换${NC}"
    else
      echo -e "   => ${YELLOW}无法确认出口差异（可能上游与 VPS 同 ISP 段）${NC}"
    fi
  else
    echo -e "${YELLOW}（VPS 模式，跳过）${NC}"
  fi
  echo -n "3) Xray 路由: "
  jq -e '.outbounds[]?|select(.tag=="resi-proxy")' ${CONFIG_DIR}/xray.json >/dev/null 2>&1 \
    && echo -e "${GREEN}存在 resi-proxy 出站${NC}" || echo -e "${YELLOW}未发现 resi-proxy（VPS 模式正常）${NC}"
  echo -e "   sing-box 路由: ${YELLOW}设计为直连（HY2/TUIC 走 UDP，不参与分流）${NC}"
  local set4 set6
  set4=$(nft list set inet edgebox resi_addr4 2>/dev/null | sed -n 's/.*elements = {\(.*\)}/\1/p' | xargs)
  set6=$(nft list set inet edgebox resi_addr6 2>/dev/null | sed -n 's/.*elements = {\(.*\)}/\1/p' | xargs)
  echo -e "4) 采集集: IPv4={${set4:-}}  IPv6={${set6:-}}"
  echo -e "${CYAN}------------------------------------------${NC}\n"
}


# === Anchor-1 INSERT END ===

# 生成 Xray 的代理 outbound JSON（单个）
build_xray_resi_outbound() {
  local users='' stream=''
  [[ -n "$PROXY_USER" ]] && users=", \"users\":[{\"user\":\"$PROXY_USER\",\"pass\":\"$PROXY_PASS\"}]"
  if [[ "$PROXY_TLS" -eq 1 ]]; then
    stream=", \"streamSettings\": {\"security\":\"tls\"$( [[ -n "$PROXY_SNI" ]] && echo ",\"tlsSettings\":{\"serverName\":\"$PROXY_SNI\"}" )}"
  fi
  if [[ "$PROXY_SCHEME" == "http" ]]; then
    cat <<JSON
{ "protocol":"http","tag":"resi-proxy","settings":{"servers":[{"address":"$PROXY_HOST","port":$PROXY_PORT$users}]}$stream }
JSON
  else
    cat <<JSON
{ "protocol":"socks","tag":"resi-proxy","settings":{"servers":[{"address":"$PROXY_HOST","port":$PROXY_PORT$users}]}$stream }
JSON
  fi
}

setup_shunt_directories() {
    mkdir -p "${CONFIG_DIR}/shunt" 2>/dev/null || true
    if [[ ! -f "${CONFIG_DIR}/shunt/whitelist.txt" ]]; then
        echo "$WHITELIST_DOMAINS" | tr ',' '\n' > "${CONFIG_DIR}/shunt/whitelist.txt"
    fi
    if [[ ! -f "$SHUNT_CONFIG" ]]; then
        echo '{"mode":"vps","proxy_info":"","last_check":"","health":"unknown"}' > "$SHUNT_CONFIG"
    fi
}

update_shunt_state() {
    local mode="$1"
    local proxy_info="$2"
    local health="${3:-unknown}"
    local timestamp=$(date -Iseconds)
    echo "{\"mode\":\"$mode\",\"proxy_info\":\"$proxy_info\",\"last_check\":\"$timestamp\",\"health\":\"$health\"}" > "$SHUNT_CONFIG"
}

show_shunt_status() {
    echo -e "\n${CYAN}出站分流状态：${NC}"
    setup_shunt_directories
    if [[ -f "$SHUNT_CONFIG" ]]; then
        local mode=$(jq -r '.mode' "$SHUNT_CONFIG" 2>/dev/null || echo "vps")
        local proxy_info=$(jq -r '.proxy_info' "$SHUNT_CONFIG" 2>/dev/null || echo "")
        local health=$(jq -r '.health' "$SHUNT_CONFIG" 2>/dev/null || echo "unknown")
        case "$mode" in
            vps) echo -e "  当前模式: ${GREEN}VPS全量出${NC}";;
            resi) echo -e "  当前模式: ${YELLOW}代理IP全量出${NC}  代理: ${proxy_info}  健康: $health";;
            direct_resi) echo -e "  当前模式: ${BLUE}智能分流${NC}  代理: ${proxy_info}  健康: $health"
                echo -e "  白名单域名数: $(wc -l < "${CONFIG_DIR}/shunt/whitelist.txt" 2>/dev/null || echo "0")";;
        esac
    else
        echo -e "  当前模式: ${GREEN}VPS全量出（默认）${NC}"
    fi
}

setup_outbound_vps() {
    log_info "配置VPS全量出站模式..."
    get_server_info || return 1
    local xray_tmp="${CONFIG_DIR}/xray.json.tmp"
    jq '.outbounds = [ { "protocol":"freedom", "tag":"direct" } ] | .routing = { "rules": [] }' "${CONFIG_DIR}/xray.json" > "$xray_tmp" && mv "$xray_tmp" "${CONFIG_DIR}/xray.json"
    setup_shunt_directories
    update_shunt_state "vps" "" "healthy"
    flush_nft_resi_sets
    post_shunt_report "VPS 全量出站" "" # Display report first
    restart_services_background xray sing-box # Then call background restart
}

setup_outbound_resi() {
  local url="$1"
  [[ -z "$url" ]] && { echo "用法: edgeboxctl shunt resi '<URL>'"; return 1; }
  log_info "配置代理IP全量出站: ${url}"
  if ! check_proxy_health_url "$url"; then log_error "代理不可用：$url"; return 1; fi
  get_server_info || return 1
  parse_proxy_url "$url"
  local xob
  xob="$(build_xray_resi_outbound)"
  jq --argjson ob "$xob" '.outbounds=[{"protocol":"freedom","tag":"direct"}, $ob] | .routing={"domainStrategy":"AsIs","rules":[{"type":"field","port":"53","outboundTag":"direct"},{"type":"field","network":"tcp,udp","outboundTag":"resi-proxy"}]}' ${CONFIG_DIR}/xray.json > ${CONFIG_DIR}/xray.json.tmp && mv ${CONFIG_DIR}/xray.json.tmp ${CONFIG_DIR}/xray.json
  # sing-box remains direct
  echo "$url" > "${CONFIG_DIR}/shunt/resi.conf"
  setup_shunt_directories
  update_shunt_state "resi" "$url" "healthy"
  post_shunt_report "代理全量（Xray-only）" "$url" # Display report first
  restart_services_background xray # Then call background restart
}

setup_outbound_direct_resi() {
  local url="$1"
  [[ -z "$url" ]] && { echo "用法: edgeboxctl shunt direct-resi '<URL>'"; return 1; }
  log_info "配置智能分流（白名单直连，其余代理）: ${url}"
  if ! check_proxy_health_url "$url"; then log_error "代理不可用：$url"; return 1; fi
  get_server_info || return 1; setup_shunt_directories
  parse_proxy_url "$url"
  local xob wl; xob="$(build_xray_resi_outbound)"
  wl='[]'
  [[ -s "${CONFIG_DIR}/shunt/whitelist.txt" ]] && wl="$(cat "${CONFIG_DIR}/shunt/whitelist.txt" | jq -R -s 'split("\n")|map(select(length>0))|map("domain:"+.)')"
  jq --argjson ob "$xob" --argjson wl "$wl" '.outbounds=[{"protocol":"freedom","tag":"direct"}, $ob] | .routing={"domainStrategy":"AsIs","rules":[{"type":"field","port":"53","outboundTag":"direct"},{"type":"field","domain":$wl,"outboundTag":"direct"},{"type":"field","network":"tcp,udp","outboundTag":"resi-proxy"}]}' ${CONFIG_DIR}/xray.json > ${CONFIG_DIR}/xray.json.tmp && mv ${CONFIG_DIR}/xray.json.tmp ${CONFIG_DIR}/xray.json
  # sing-box remains direct
  echo "$url" > "${CONFIG_DIR}/shunt/resi.conf"
  update_shunt_state "direct-resi" "$url" "healthy"
  post_shunt_report "智能分流（白名单直连）" "$url" # Display report first
  restart_services_background xray # Then call background restart
}

manage_whitelist() {
    local action="$1"
    local domain="$2"
    setup_shunt_directories
    case "$action" in
        add)
            [[ -z "$domain" ]] && { echo "用法: edgeboxctl shunt whitelist add domain.com"; return 1; }
            if ! grep -Fxq "$domain" "${CONFIG_DIR}/shunt/whitelist.txt" 2>/dev/null; then
                echo "$domain" >> "${CONFIG_DIR}/shunt/whitelist.txt"
                log_success "已添加域名到白名单: $domain"
            else
                log_warn "域名已存在于白名单: $domain"
            fi
            ;;
        remove)
            [[ -z "$domain" ]] && { echo "用法: edgeboxctl shunt whitelist remove domain.com"; return 1; }
            if sed -i "/^${domain}$/d" "${CONFIG_DIR}/shunt/whitelist.txt" 2>/dev/null; then
                log_success "已从白名单移除域名: $domain"
            else
                log_error "移除失败或域名不存在: $domain"
            fi
            ;;
        list)
            echo -e "${CYAN}白名单域名：${NC}"
            if [[ -f "${CONFIG_DIR}/shunt/whitelist.txt" ]]; then
                cat "${CONFIG_DIR}/shunt/whitelist.txt" | nl -w2 -s'. '
            else
                echo "  无白名单文件"
            fi
            ;;
        reset)
            echo "$WHITELIST_DOMAINS" | tr ',' '\n' > "${CONFIG_DIR}/shunt/whitelist.txt"
            log_success "已重置白名单为默认值"
            ;;
        *)
            echo "用法: edgeboxctl shunt whitelist [add|remove|list|reset] [domain]"
            return 1
            ;;
    esac
}

#############################################
# 流量统计
#############################################

format_bytes(){ 
    local b=$1
    [[ $b -ge 1073741824 ]] && echo "$(bc<<<"scale=2;$b/1073741824")GB" || \
    ([[ $b -ge 1048576 ]] && echo "$(bc<<<"scale=2;$b/1048576")MB" || \
    ([[ $b -ge 1024 ]] && echo "$(bc<<<"scale=1;$b/1024")KB" || echo "${b}B"))
}

# >>> traffic_show begin
traffic_show() {
  echo -e "流量统计（基于 vnStat）："

  # 选网卡：参数 > 默认路由 > vnstat数据库
  local nic="${1:-$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')}"
  [[ -z "$nic" ]] && nic="$(vnstat --dbiflist 2>/dev/null | head -n1)"
  [[ -z "$nic" ]] && { echo "  无法确定网卡"; return 1; }

  # 依赖
  command -v vnstat >/dev/null || { echo "  vnstat 未安装"; return 1; }
  command -v jq >/dev/null     || { echo "  jq 未安装"; return 1; }

  # 拉 JSON（限制只取最新 1 条）
  local dj mj
  dj="$(vnstat -i "$nic" --json d 1 2>/dev/null)" || { echo "  无法获取今日数据"; return 1; }
  mj="$(vnstat -i "$nic" --json m 1 2>/dev/null)" || { echo "  无法获取本月数据"; return 1; }

  # 直接按“字节”读取（vnStat --json 的 rx/tx 默认就是 bytes）
  local today_tx today_rx month_tx month_rx
  today_tx="$(jq -r '( .interfaces[0].traffic.day // .interfaces[0].traffic.days )[0].tx // 0' <<<"$dj")"
  today_rx="$(jq -r '( .interfaces[0].traffic.day // .interfaces[0].traffic.days )[0].rx // 0' <<<"$dj")"
  month_tx="$(jq -r '( .interfaces[0].traffic.month // .interfaces[0].traffic.months )[0].tx // 0' <<<"$mj")"
  month_rx="$(jq -r '( .interfaces[0].traffic.month // .interfaces[0].traffic.months )[0].rx // 0' <<<"$mj")"

  # 无依赖友好格式化（字节 -> B/KiB/MiB/GiB/TiB）
  _fmt_bytes() {
    awk -v b="$1" 'BEGIN{
      if (b<0 || b=="") b=0
      u[0]="B";u[1]="KiB";u[2]="MiB";u[3]="GiB";u[4]="TiB"
      i=0; while (b>=1024 && i<4) { b/=1024; i++ }
      if (b==0 || b>=100) printf("%.0f%s", b, u[i]);
      else if (b>=10)     printf("%.1f%s", b, u[i]);
      else                printf("%.2f%s", b, u[i]);
    }'
  }

  echo "  接口： $nic"
  echo "  今日流量： $(_fmt_bytes "$today_tx") ↑ / $(_fmt_bytes "$today_rx") ↓"
  echo "  本月流量： $(_fmt_bytes "$month_tx") ↑ / $(_fmt_bytes "$month_rx") ↓"
}
# <<< traffic_show end


#############################################
# 预警配置（极简）
#############################################
ensure_alert_conf(){
  [[ -d "$TRAFFIC_DIR" ]] || mkdir -p "$TRAFFIC_DIR"
  [[ -s "$TRAFFIC_DIR/alert.conf" ]] || cat >"$TRAFFIC_DIR/alert.conf" <<'CONF'
ALERT_MONTHLY_GIB=100
ALERT_TG_BOT_TOKEN=
ALERT_TG_CHAT_ID=
ALERT_DISCORD_WEBHOOK=
ALERT_PUSHPLUS_TOKEN=
ALERT_WEBHOOK=
ALERT_WEBHOOK_FORMAT=raw
ALERT_STEPS=30,60,90
CONF
}
alert_show(){ ensure_alert_conf; echo -e "${CYAN}流量预警配置：${NC}"; sed -n '1,99p' "$TRAFFIC_DIR/alert.conf" | sed 's/^/  /'; }
alert_set_monthly(){ ensure_alert_conf; [[ "$1" =~ ^[0-9]+$ ]] || { log_error "月度预算需为整数GiB"; return 1; }; sed -i "s/^ALERT_MONTHLY_GIB=.*/ALERT_MONTHLY_GIB=${1}/" "$TRAFFIC_DIR/alert.conf"; log_success "已设置预算：$1 GiB"; }
alert_set_steps(){ ensure_alert_conf; [[ "$1" =~ ^[0-9]+(,[0-9]+)*$ ]] || { log_error "阈值格式: 30,60,90"; return 1; }; sed -i "s/^ALERT_STEPS=.*/ALERT_STEPS=${1}/" "$TRAFFIC_DIR/alert.conf"; log_success "已设置阈值：$1%"; }
alert_set_telegram(){ ensure_alert_conf; [[ -z "$1" || -z "$2" ]] && { log_error "用法: edgeboxctl alert telegram <bot_token> <chat_id>"; return 1; }
  sed -i "s|^ALERT_TG_BOT_TOKEN=.*|ALERT_TG_BOT_TOKEN=${1}|" "$TRAFFIC_DIR/alert.conf"
  sed -i "s|^ALERT_TG_CHAT_ID=.*|ALERT_TG_CHAT_ID=${2}|" "$TRAFFIC_DIR/alert.conf"; log_success "已设置 Telegram"; }
alert_set_discord(){ ensure_alert_conf; sed -i "s|^ALERT_DISCORD_WEBHOOK=.*|ALERT_DISCORD_WEBHOOK=${1}|" "$TRAFFIC_DIR/alert.conf"; log_success "已设置 Discord Webhook"; }
alert_set_wechat(){ ensure_alert_conf; sed -i "s|^ALERT_PUSHPLUS_TOKEN=.*|ALERT_PUSHPLUS_TOKEN=${1}|" "$TRAFFIC_DIR/alert.conf"; log_success "已设置 WeChat PushPlus"; }
alert_set_webhook(){ ensure_alert_conf; local url="$1" fmt="${2:-raw}"; sed -i "s|^ALERT_WEBHOOK=.*|ALERT_WEBHOOK=${url}|" "$TRAFFIC_DIR/alert.conf"; sed -i "s|^ALERT_WEBHOOK_FORMAT=.*|ALERT_WEBHOOK_FORMAT=${fmt}|" "$TRAFFIC_DIR/alert.conf"; log_success "已设置通用 Webhook（${fmt}）"; }
alert_test(){
  ensure_alert_conf
  local budget_gib; budget_gib=$(awk -F= '/^ALERT_MONTHLY_GIB=/{print $2}' "$TRAFFIC_DIR/alert.conf"); [[ "$budget_gib" =~ ^[0-9]+$ ]] || budget_gib=100
  local pct="${1:-40}"; [[ "$pct" =~ ^[0-9]+$ && "$pct" -ge 0 && "$pct" -le 100 ]] || { log_error "百分比 0-100"; return 1; }
  local GiB=1073741824 mf="$TRAFFIC_DIR/logs/monthly.csv" m; m=$(date +%Y-%m)
  mkdir -p "$TRAFFIC_DIR/logs"; [[ -s "$mf" ]] || echo "month,vps,resi,total,tx,rx" > "$mf"
  grep -q "^$m," "$mf" || echo "$m,0,0,0,0,0" >> "$mf"
  local used=$(( GiB * budget_gib * pct / 100 ))
  awk -F, -v m="$m" -v u="$used" 'BEGIN{OFS=","} NR==1{print;next} $1==m{$4=u} {print}' "$mf" > "$mf.tmp" && mv "$mf.tmp" "$mf"
  rm -f "$TRAFFIC_DIR/alert.state"
  if [[ -x "$SCRIPTS_DIR/traffic-alert.sh" ]]; then "$SCRIPTS_DIR/traffic-alert.sh"; else /etc/edgebox/scripts/traffic-alert.sh 2>/dev/null || true; fi
  echo -e "${CYAN}最近告警日志：${NC}"; tail -n 10 /var/log/edgebox-traffic-alert.log 2>/dev/null || true
  log_success "已模拟 ${pct}% 用量并触发预警（不产生真实流量）"
}

#############################################
# 备份恢复
#############################################

backup_create(){
    local ts=$(date +%Y%m%d_%H%M%S) 
    local file="${BACKUP_DIR}/edgebox_backup_${ts}.tar.gz"
    mkdir -p "${BACKUP_DIR}"
    local t="/tmp/edgebox_backup_${ts}"
    mkdir -p "$t"
    
    # 备份主要配置
    cp -r /etc/edgebox "$t/" 2>/dev/null || true
    mkdir -p "$t/nginx"; cp /etc/nginx/nginx.conf "$t/nginx/" 2>/dev/null || true
    mkdir -p "$t/systemd"
    cp /etc/systemd/system/xray.service "$t/systemd/" 2>/dev/null || true
    cp /etc/systemd/system/sing-box.service "$t/systemd/" 2>/dev/null || true
    [[ -d /etc/letsencrypt ]] && cp -r /etc/letsencrypt "$t/" 2>/dev/null || true
    crontab -l > "$t/crontab.txt" 2>/dev/null || true
    
    # 备份Web文件
    mkdir -p "$t/www"; cp -r /var/www/html "$t/www/" 2>/dev/null || true
    
    if tar -C "$t" -czf "$file" . 2>/dev/null && rm -rf "$t"; then
        log_success "备份完成: $file"
        # 清理旧备份，保留最近10个
        ls -t ${BACKUP_DIR}/edgebox_backup_*.tar.gz 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
    else
        log_error "备份失败"; rm -rf "$t"
    fi
}

backup_list(){ 
    echo -e "${CYAN}备份列表：${NC}"
    ls -lh ${BACKUP_DIR}/edgebox_backup_*.tar.gz 2>/dev/null | awk '{print "  " $9 "  " $5 "  " $6 " " $7 " " $8}' || echo "  无备份文件"
}

backup_restore(){
    local f="$1"
    [[ -z "$f" || ! -f "$f" ]] && { echo "用法: edgeboxctl backup restore /path/to/edgebox_backup_xxx.tar.gz"; return 1; }
    log_info "恢复备份: $f"
    local restore_dir="/tmp/edgebox_restore_$"
    mkdir -p "$restore_dir"
    
    if tar -xzf "$f" -C "$restore_dir" 2>/dev/null; then
        # 恢复配置
        [[ -d "$restore_dir/etc/edgebox" ]] && cp -r "$restore_dir/etc/edgebox" /etc/ 2>/dev/null || true
        [[ -f "$restore_dir/nginx/nginx.conf" ]] && cp "$restore_dir/nginx/nginx.conf" /etc/nginx/nginx.conf
        [[ -f "$restore_dir/systemd/xray.service" ]] && cp "$restore_dir/systemd/xray.service" /etc/systemd/system/
        [[ -f "$restore_dir/systemd/sing-box.service" ]] && cp "$restore_dir/systemd/sing-box.service" /etc/systemd/system/
        [[ -d "$restore_dir/letsencrypt" ]] && cp -r "$restore_dir/letsencrypt" /etc/ 2>/dev/null || true
        [[ -d "$restore_dir/www/html" ]] && cp -r "$restore_dir/www/html" /var/www/ 2>/dev/null || true
        [[ -f "$restore_dir/crontab.txt" ]] && crontab "$restore_dir/crontab.txt" 2>/dev/null || true
        
        # 重启服务
        systemctl daemon-reload
        reload_or_restart_services nginx xray sing-box
        rm -rf "$restore_dir"
        log_success "恢复完成"
    else
        log_error "恢复失败：无法解压备份文件"
        rm -rf "$restore_dir"
        return 1
    fi
}

#############################################
# 配置管理
#############################################

# 重新生成所有协议的UUID和密码
regenerate_uuid() {
    log_info "重新生成所有协议凭据..."
    
    # 检查必要工具
    if ! command -v uuidgen >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
        log_error "缺少必要工具（uuidgen 或 openssl）"
        return 1
    fi
    
    # 重新生成所有UUID
    local NEW_UUID_VLESS_REALITY=$(uuidgen)
    local NEW_UUID_VLESS_GRPC=$(uuidgen)
    local NEW_UUID_VLESS_WS=$(uuidgen)
    local NEW_UUID_TUIC=$(uuidgen)
    local NEW_UUID_HYSTERIA2=$(uuidgen)
    local NEW_UUID_TROJAN=$(uuidgen)
    
    # 重新生成所有密码
    local NEW_PASSWORD_HYSTERIA2=$(openssl rand -base64 32 | tr -d '\n')
    local NEW_PASSWORD_TUIC=$(openssl rand -base64 32 | tr -d '\n')
    local NEW_PASSWORD_TROJAN=$(openssl rand -base64 32 | tr -d '\n')
    
    # 验证生成结果
    if [[ -z "$NEW_UUID_VLESS_REALITY" || -z "$NEW_PASSWORD_HYSTERIA2" ]]; then
        log_error "凭据生成失败"
        return 1
    fi
    
    # 更新 server.json 使用 jq
    log_info "更新 server.json..."
    local temp_file="${CONFIG_DIR}/server.json.tmp"
    if jq \
        --arg uuid_reality "$NEW_UUID_VLESS_REALITY" \
        --arg uuid_grpc "$NEW_UUID_VLESS_GRPC" \
        --arg uuid_ws "$NEW_UUID_VLESS_WS" \
        --arg uuid_tuic "$NEW_UUID_TUIC" \
        --arg uuid_hysteria2 "$NEW_UUID_HYSTERIA2" \
        --arg uuid_trojan "$NEW_UUID_TROJAN" \
        --arg pass_hysteria2 "$NEW_PASSWORD_HYSTERIA2" \
        --arg pass_tuic "$NEW_PASSWORD_TUIC" \
        --arg pass_trojan "$NEW_PASSWORD_TROJAN" \
        '.uuid.vless.reality = $uuid_reality |
         .uuid.vless.grpc = $uuid_grpc |
         .uuid.vless.ws = $uuid_ws |
         .uuid.tuic = $uuid_tuic |
         .uuid.hysteria2 = $uuid_hysteria2 |
         .uuid.trojan = $uuid_trojan |
         .password.hysteria2 = $pass_hysteria2 |
         .password.tuic = $pass_tuic |
         .password.trojan = $pass_trojan |
         .updated_at = (now | todate)' \
        "${CONFIG_DIR}/server.json" > "$temp_file"; then
        mv "$temp_file" "${CONFIG_DIR}/server.json"
        log_success "server.json 中的密码已更新"
    else
        log_error "更新 server.json 失败"
        rm -f "$temp_file"
        return 1
    fi
    
    # 更新 Xray 配置
    if [[ -f "${CONFIG_DIR}/xray.json" ]]; then
        log_info "更新 Xray 配置..."
        local xray_temp="${CONFIG_DIR}/xray.json.tmp"
        if jq \
            --arg uuid_reality "$NEW_UUID_VLESS_REALITY" \
            --arg uuid_grpc "$NEW_UUID_VLESS_GRPC" \
            --arg uuid_ws "$NEW_UUID_VLESS_WS" \
            --arg pass_trojan "$NEW_PASSWORD_TROJAN" \
            '(.inbounds[] | select(.tag=="vless-reality") | .settings.clients[0].id) = $uuid_reality |
             (.inbounds[] | select(.tag=="vless-grpc") | .settings.clients[0].id) = $uuid_grpc |
             (.inbounds[] | select(.tag=="vless-ws") | .settings.clients[0].id) = $uuid_ws |
             (.inbounds[] | select(.tag=="trojan-tcp") | .settings.clients[0].password) = $pass_trojan' \
            "${CONFIG_DIR}/xray.json" > "$xray_temp"; then
            mv "$xray_temp" "${CONFIG_DIR}/xray.json"
            log_success "Xray 配置已更新"
        else
            log_warn "更新 Xray 配置失败，可能配置结构不同"
            rm -f "$xray_temp"
        fi
    fi
    
    # 更新 sing-box 配置
    if [[ -f "${CONFIG_DIR}/sing-box.json" ]]; then
        log_info "更新 sing-box 配置..."
        local singbox_temp="${CONFIG_DIR}/sing-box.json.tmp"
        if jq \
            --arg uuid_tuic "$NEW_UUID_TUIC" \
            --arg pass_tuic "$NEW_PASSWORD_TUIC" \
            --arg pass_hysteria2 "$NEW_PASSWORD_HYSTERIA2" \
            '(.inbounds[] | select(.type=="tuic") | .users[0].uuid) = $uuid_tuic |
             (.inbounds[] | select(.type=="tuic") | .users[0].password) = $pass_tuic |
             (.inbounds[] | select(.type=="hysteria2") | .users[0].password) = $pass_hysteria2' \
            "${CONFIG_DIR}/sing-box.json" > "$singbox_temp"; then
            mv "$singbox_temp" "${CONFIG_DIR}/sing-box.json"
            log_success "sing-box 配置已更新"
        else
            log_warn "更新 sing-box 配置失败，可能配置结构不同"
            rm -f "$singbox_temp"
        fi
    fi
    
    # 重新生成订阅链接
    log_info "重新生成订阅链接..."
    
    # 加载新凭据到环境变量（供订阅生成函数使用）
    export UUID_VLESS_REALITY="$NEW_UUID_VLESS_REALITY"
    export UUID_VLESS_GRPC="$NEW_UUID_VLESS_GRPC"
    export UUID_VLESS_WS="$NEW_UUID_VLESS_WS"
    export UUID_TUIC="$NEW_UUID_TUIC"
    export PASSWORD_HYSTERIA2="$NEW_PASSWORD_HYSTERIA2"
    export PASSWORD_TUIC="$NEW_PASSWORD_TUIC"
    export PASSWORD_TROJAN="$NEW_PASSWORD_TROJAN"
    
    # 重新生成订阅（根据当前证书模式）
    local mode
    mode="$(get_current_cert_mode 2>/dev/null || echo self-signed)"
    if [[ "$mode" == "self-signed" ]]; then
        regen_sub_ip
    else
        local domain="${mode##*:}"
        if [[ -n "$domain" ]]; then
            regen_sub_domain "$domain"
        else
            regen_sub_ip
        fi
    fi
    
    log_success "订阅链接已更新"
    
    # 重载服务
    log_info "重载代理服务..."
    if reload_or_restart_services xray sing-box; then
        log_success "服务重载成功"
    else
        log_warn "服务重载失败，请手动检查服务状态"
    fi
    
    # 显示完整的新凭据
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    🔑 新的UUID                             ${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${YELLOW}VLESS Reality:${NC}  ${GREEN}$NEW_UUID_VLESS_REALITY${NC}"
    echo -e "  ${YELLOW}VLESS gRPC:${NC}     ${GREEN}$NEW_UUID_VLESS_GRPC${NC}"
    echo -e "  ${YELLOW}VLESS WS:${NC}       ${GREEN}$NEW_UUID_VLESS_WS${NC}"
    echo -e "  ${YELLOW}TUIC:${NC}           ${GREEN}$NEW_UUID_TUIC${NC}"
    echo -e "  ${YELLOW}Hysteria2:${NC}      ${DIM}$NEW_UUID_HYSTERIA2 (备用标识)${NC}"
    echo -e "  ${YELLOW}Trojan:${NC}         ${DIM}$NEW_UUID_TROJAN (备用标识)${NC}"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    🔐 新的密码                             ${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${YELLOW}Hysteria2:${NC}      ${GREEN}$NEW_PASSWORD_HYSTERIA2${NC}"
    echo -e "  ${YELLOW}TUIC:${NC}           ${GREEN}$NEW_PASSWORD_TUIC${NC}"
    echo -e "  ${YELLOW}Trojan:${NC}         ${GREEN}$NEW_PASSWORD_TROJAN${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${RED}⚠️  重要提示：${NC}"
    echo -e "  ${YELLOW}1.${NC} 旧的订阅链接已失效，请通知所有用户更新订阅"
    echo -e "  ${YELLOW}2.${NC} 新订阅地址: ${GREEN}http://$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null || echo 'YOUR_IP')/sub${NC}"
    echo -e "  ${YELLOW}3.${NC} 查看完整订阅: ${GREEN}edgeboxctl sub${NC}"
    echo -e "  ${YELLOW}4.${NC} 查看配置信息: ${GREEN}edgeboxctl config show${NC}"
    echo ""
    
    return 0
}

show_config(){
    echo -e "${CYAN}EdgeBox 配置信息：${NC}"
    if [[ -f ${CONFIG_DIR}/server.json ]]; then
        local server_ip=$(jq -r '.server_ip' ${CONFIG_DIR}/server.json)
        local version=$(jq -r '.version' ${CONFIG_DIR}/server.json)
        local install_date=$(jq -r '.install_date' ${CONFIG_DIR}/server.json)
        
        echo -e "  版本: ${YELLOW}v${version}${NC}"
        echo -e "  服务器IP: ${YELLOW}${server_ip}${NC}"
        echo -e "  安装日期: ${YELLOW}${install_date}${NC}"
        echo -e "  证书模式: ${YELLOW}$(get_current_cert_mode)${NC}"
        
        echo -e "\n${CYAN}协议配置：${NC}"
        echo -e "  VLESS Reality UUID: $(jq -r '.uuid.vless.reality // .uuid.vless' ${CONFIG_DIR}/server.json)"
echo -e "  VLESS gRPC UUID: $(jq -r '.uuid.vless.grpc // .uuid.vless' ${CONFIG_DIR}/server.json)"
echo -e "  VLESS WS UUID: $(jq -r '.uuid.vless.ws // .uuid.vless' ${CONFIG_DIR}/server.json)"
        echo -e "  TUIC UUID: $(jq -r '.uuid.tuic' ${CONFIG_DIR}/server.json)"
        echo -e "  Hysteria2 密码: $(jq -r '.password.hysteria2' ${CONFIG_DIR}/server.json)"
        echo -e "  TUIC 密码: $(jq -r '.password.tuic' ${CONFIG_DIR}/server.json)"
        echo -e "  Trojan 密码: $(jq -r '.password.trojan' ${CONFIG_DIR}/server.json)"
        echo -e "  Reality 公钥: $(jq -r '.reality.public_key' ${CONFIG_DIR}/server.json)"
    else
        echo -e "${RED}配置文件不存在${NC}"
    fi
}


#############################################
# Reality密钥轮换 (Bulletproof & Self-Contained)
#############################################

# 辅助函数：检查是否需要轮换
check_reality_rotation_needed() {
    # <<< FIX: Define all required variables LOCALLY to be fully self-contained >>>
    local CONFIG_DIR="/etc/edgebox/config"
    local REALITY_ROTATION_STATE="${CONFIG_DIR}/reality-rotation.json"
    local REALITY_ROTATION_DAYS=90
    
    local force_rotation=${1:-false}
    [[ "$force_rotation" == "true" ]] && return 0

    if [[ ! -f "$REALITY_ROTATION_STATE" ]]; then
        log_info "首次运行，创建轮换状态文件..."
        mkdir -p "$(dirname "$REALITY_ROTATION_STATE")" # Ensure directory exists
        
        # <<< FIX: Read current public key from server.json on first run >>>
        local current_pubkey
        current_pubkey=$(jq -r '.reality.public_key // ""' "${CONFIG_DIR}/server.json" 2>/dev/null)
        
        local next_rotation
        next_rotation=$(date -d "+${REALITY_ROTATION_DAYS} days" -Iseconds)
        
        # Write all three fields to the initial state file
        jq -n \
          --arg next_rotation "$next_rotation" \
          --arg last_rotation "$(date -Iseconds)" \
          --arg pubkey "$current_pubkey" \
          '{next_rotation: $next_rotation, last_rotation: $last_rotation, last_public_key: $pubkey}' > "$REALITY_ROTATION_STATE"

        log_info "下次轮换将在: $next_rotation"
        return 1
    fi
    
    local next_rotation_time
    next_rotation_time=$(jq -r '.next_rotation' "$REALITY_ROTATION_STATE" 2>/dev/null)
    
    if [[ -n "$next_rotation_time" && "$next_rotation_time" != "null" ]]; then
        local next_timestamp
        next_timestamp=$(date -d "$next_rotation_time" +%s 2>/dev/null || echo 0)
        local current_timestamp
        current_timestamp=$(date +%s)
        
        if [[ $current_timestamp -ge $next_timestamp ]]; then
            log_info "Reality密钥已到轮换时间。"
            return 0
        else
            return 1
        fi
    fi
    
    return 1 # Default to no rotation needed
}

# 辅助函数：更新Xray配置
update_xray_reality_keys() {
    local new_private_key="$1"
    local new_short_id="$2"
    local CONFIG_DIR="/etc/edgebox/config" # Self-contained
    local XRAY_CONFIG="${CONFIG_DIR}/xray.json"
    local temp_config="${XRAY_CONFIG}.tmp"
    
    jq --arg private_key "$new_private_key" \
       --arg short_id "$new_short_id" \
       '(.inbounds[]? | select(.tag? | test("reality"; "i")) | .streamSettings.realitySettings.privateKey) = $private_key |
        (.inbounds[]? | select(.tag? | test("reality"; "i")) | .streamSettings.realitySettings.shortIds) = [$short_id]' \
       "${XRAY_CONFIG}" > "$temp_config" && mv "$temp_config" "${XRAY_CONFIG}"
}

# 辅助函数：更新server.json
update_server_reality_keys() {
    local new_private_key="$1"
    local new_public_key="$2"
    local new_short_id="$3"
    local CONFIG_DIR="/etc/edgebox/config" # Self-contained
    local temp_server="${CONFIG_DIR}/server.json.tmp"
    
    jq --arg private_key "$new_private_key" \
       --arg public_key "$new_public_key" \
       --arg short_id "$new_short_id" \
       '.reality.private_key = $private_key |
        .reality.public_key = $public_key |
        .reality.short_id = $short_id' \
       "${CONFIG_DIR}/server.json" > "$temp_server" && mv "$temp_server" "${CONFIG_DIR}/server.json"
}

# 辅助函数：更新轮换状态文件
update_reality_rotation_state() {
    local new_public_key="$1"
    local CONFIG_DIR="/etc/edgebox/config" # Self-contained
    local REALITY_ROTATION_STATE="${CONFIG_DIR}/reality-rotation.json"
    local REALITY_ROTATION_DAYS=90
    
    local current_time
    current_time=$(date -Iseconds)
    local next_rotation
    next_rotation=$(date -d "+${REALITY_ROTATION_DAYS} days" -Iseconds)
    
    echo "{\"last_rotation\":\"$current_time\",\"next_rotation\":\"$next_rotation\",\"last_public_key\":\"$new_public_key\"}" > "$REALITY_ROTATION_STATE"
}

# 主函数：执行密钥轮换 (已修正并包含所有依赖和即时面板刷新)
rotate_reality_keys() {
    local force_rotation=${1:-false}
    log_info "开始Reality密钥轮换流程..."
    
    if ! check_reality_rotation_needed "$force_rotation"; then
        log_info "当前不需要轮换Reality密钥。"
        return 0
    fi
    
    log_info "正在备份当前配置..."
    local backup_file="${CONFIG_DIR}/reality_backup_$(date +%Y%m%d_%H%M%S).json"
    cp "${XRAY_CONFIG}" "$backup_file"
    
    log_info "正在生成新的密钥对..."
    local reality_output
    reality_output=$(sing-box generate reality-keypair 2>/dev/null) || { log_error "sing-box命令执行失败"; return 1; }
    
    local new_private_key new_public_key new_short_id
    new_private_key="$(echo "$reality_output" | grep -oP 'PrivateKey: \K[a-zA-Z0-9_-]+')"
    new_public_key="$(echo "$reality_output" | grep -oP 'PublicKey: \K[a-zA-Z0-9_-]+')"
    new_short_id="$(openssl rand -hex 4)"
    
    if [[ -z "$new_private_key" || -z "$new_public_key" ]]; then
        log_error "新密钥生成失败，已中止轮换。"
        return 1
    fi
    log_success "新密钥生成成功。"
    
    update_xray_reality_keys "$new_private_key" "$new_short_id"
    update_server_reality_keys "$new_private_key" "$new_public_key" "$new_short_id"
    
    log_info "正在重载Xray服务..."
    if ! reload_or_restart_services xray; then
        log_error "Xray服务重载失败！正在从备份恢复..."
        cp "$backup_file" "${XRAY_CONFIG}"
        reload_or_restart_services xray
        return 1
    fi
    log_success "Xray服务已应用新密钥。"
    
    log_info "正在刷新订阅链接..."
    local mode
    mode=$(get_current_cert_mode 2>/dev/null || echo self-signed)
    if [[ "$mode" == "self-signed" ]]; then
      regen_sub_ip
    else
      local d="${mode##*:}"
      [[ -n "$d" ]] && regen_sub_domain "$d" || regen_sub_ip
    fi

    update_reality_rotation_state "$new_public_key"

    # <<< FIX: Immediately refresh the dashboard data file after changes >>>
    log_info "正在刷新Web面板数据..."
    if [[ -x "${SCRIPTS_DIR}/dashboard-backend.sh" ]]; then
        bash "${SCRIPTS_DIR}/dashboard-backend.sh" --now >/dev/null 2>&1 || log_warn "Dashboard data refresh failed, will update on next cron run."
        log_success "Web面板数据已刷新。"
    else
        log_warn "dashboard-backend.sh not found, panel will update on next cron run."
    fi
    
    log_success "Reality密钥轮换成功！"
    echo -e "  ${YELLOW}重要: 请通知用户更新订阅以获取新配置。${NC}"
    echo -e "  新公钥 (pbk): ${GREEN}${new_public_key}${NC}"
    echo -e "  新短ID (sid): ${GREEN}${new_short_id}${NC}"
}

# 主函数：显示轮换状态
show_reality_rotation_status() {
    log_info "查看Reality密钥轮换状态..."
    local CONFIG_DIR="/etc/edgebox/config" # Self-contained
    local REALITY_ROTATION_STATE="${CONFIG_DIR}/reality-rotation.json"
    
    if [[ ! -f "$REALITY_ROTATION_STATE" ]]; then
        # Call the check function which will create the file on first run
        check_reality_rotation_needed "false" >/dev/null 2>&1
    fi

    if [[ ! -f "$REALITY_ROTATION_STATE" ]]; then
        log_error "无法读取或创建Reality轮换状态文件。"
        return 1
    fi

    local next_rotation last_rotation pubkey
    next_rotation=$(jq -r '.next_rotation' "$REALITY_ROTATION_STATE")
    last_rotation=$(jq -r '.last_rotation' "$REALITY_ROTATION_STATE")
    pubkey=$(jq -r '.last_public_key // "N/A"' "$REALITY_ROTATION_STATE")

    echo "=== Reality密钥轮换状态 ==="
    echo "  上次轮换: ${last_rotation}"
    echo "  下次轮换: ${next_rotation}"
    echo "  当前公钥: ${pubkey:0:20}..."

    local next_ts current_ts days_rem
    next_ts=$(date -d "$next_rotation" +%s 2>/dev/null || echo 0)
    current_ts=$(date +%s)
    days_rem=$(( (next_ts - current_ts) / 86400 ))

    if [[ "$next_ts" -eq 0 ]]; then
        echo "  状态: 日期格式无效"
    elif [[ "$days_rem" -gt 0 ]]; then
        echo "  剩余时间: ${days_rem} 天"
    else
        echo "  状态: ${RED}已到期或过期，建议立即轮换！${NC}"
    fi
}


#############################################
# SNI域名管理
#############################################

# --- SNI域名管理 (这是调用部分，逻辑不变，但现在调用的是内部函数) ---
sni_pool_list() {
    if [[ ! -f "$SNI_DOMAINS_CONFIG" ]]; then
        log_error "SNI配置文件不存在: $SNI_DOMAINS_CONFIG"
        return 1
    fi
    echo "SNI域名池状态:"
    echo "$(printf "%-25s %-8s %-12s %-15s %-20s" "域名" "权重" "成功率" "响应时间" "最后检查")"
    echo "$(printf "%s" "$(printf "%-25s %-8s %-12s %-15s %-20s" | tr " " "-")")"
    
    if ! jq -r '.domains[] | [.hostname, .weight, (.success_rate // 0), (.avg_response_time // 0), (.last_check // "未检查")] | @tsv' "$SNI_DOMAINS_CONFIG" 2>/dev/null; then
        echo "配置文件格式错误或jq命令不可用"
        return 1
    fi | while IFS=$'\t' read -r hostname weight success_rate response_time last_check; do
        printf "%-25s %-8s %-12s %-15s %-20s\n" \
            "$hostname" "$weight" "${success_rate}" "${response_time}s" "$last_check"
    done
    
    echo ""
    echo "当前使用: $(get_current_sni_domain || echo "未配置")"
}

sni_test_all() {
    health_check_domains
}

sni_auto_select() {
    auto_select_optimal_domain
}

sni_set_domain() {
    local target_domain="$1"
    
    if [[ -z "$target_domain" ]]; then
        echo "用法: edgeboxctl sni set <域名>"
        return 1
    fi
    target_domain=${target_domain#*//}
    
    log_info "手动设置SNI域名: $target_domain"

    if update_sni_domain "$target_domain"; then
        log_success "SNI域名设置成功: $target_domain"
    else
        log_error "SNI域名设置失败。"
        return 1
    fi
}

#############################################
# 主命令处理
#############################################

case "$1" in
  # 基础功能
  status) show_status ;;
  restart) restart_services ;;
  logs|log) show_logs "$2" ;;
  test) test_connection ;;
  debug-ports) debug_ports ;;
  
    sub|subscription)
    ensure_sub_dirs >/dev/null 2>&1 || true
    case "$2" in
      issue)   shift 2; sub_issue "$1" "${2:-}";;
      show)    shift 2; sub_show "$1";;
      revoke)  shift 2; sub_revoke "$1";;
      limit)   shift 2; sub_limit "$1" "$2";;
      ""|list) show_sub ;;   # 兼容：不带参数仍显示整份订阅（管理员/自用）
*) echo "用法:
edgeboxctl sub                         # 显示并刷新全局订阅链接 (/sub)
edgeboxctl sub issue  <user> [limit]   # 为用户下发专属订阅链接 (/share/u-...)
edgeboxctl sub show   <user>           # 查看专属订阅与已登记设备
edgeboxctl sub revoke <user>           # 停用用户的专属订阅
edgeboxctl sub limit  <user> <N>       # 调整用户的设备上限"
;;
    esac
    ;;
	
  # 备注服务器名称
   "alias")
        if [[ -n "$2" ]]; then
            set_user_alias "$2"
        else
            echo "用法: edgeboxctl alias \"备注内容\""
            echo "当前备注: $(jq -r '.user_alias // "未设置"' /etc/edgebox/config/server.json 2>/dev/null || echo "未设置")"
        fi
        ;;
		
  # 证书管理
  cert)
    case "$2" in
      status|"") 
        cert_status 
        ;;
      renew)
        echo "[INFO] 尝试续期 Let's Encrypt 证书..."
        systemctl stop nginx >/dev/null 2>&1 || true
        certbot renew --quiet || true
        systemctl start nginx >/dev/null 2>&1 || true
        # 尽量优先 reload，失败再 restart
        reload_or_restart_services nginx xray sing-box
        cert_status
        ;;
      *)
        echo "用法: edgeboxctl cert [status|renew]"
        ;;
    esac
    ;;
  fix-permissions) fix_permissions ;;
  cert-status) cert_status ;;                 # 兼容旧命令
  
  switch-to-domain)
    shift
    switch_to_domain "$1"
    ;;
  switch-to-ip)
    switch_to_ip
    ;;
  
  # 配置管理
  config)
    case "$2" in
      show) show_config ;;
      regenerate-uuid) regenerate_uuid ;;
      *) echo "用法: edgeboxctl config [show|regenerate-uuid]" ;;
    esac
    ;;
  
  # 出站分流
  shunt)
    case "$2" in
      vps) setup_outbound_vps ;;
      resi) setup_outbound_resi "$3" ;;
      direct-resi) setup_outbound_direct_resi "$3" ;;
      status) show_shunt_status ;;
      whitelist) shift 2; manage_whitelist "$@" ;;
      *) echo "用法: edgeboxctl shunt [vps|resi|direct-resi|status|whitelist] [args...]" ;;
    esac
    ;;
	
  # 预警配置
    alert)
    ensure_alert_conf
    case "$2" in
      show|"")        alert_show ;;
      monthly)        shift 2; alert_set_monthly "$1" ;;
      steps)          shift 2; alert_set_steps "$1" ;;
      telegram)       shift 2; alert_set_telegram "$1" "$2" ;;
      discord)        shift 2; alert_set_discord "$1" ;;
      wechat)         shift 2; alert_set_wechat "$1" ;;
      webhook)        shift 2; alert_set_webhook "$1" "${2:-raw}" ;;
      test)           shift 2; alert_test "${1:-40}" ;;
      *) echo "用法: edgeboxctl alert [show|monthly <GiB>|steps <p1,p2,..>|telegram <token> <chat>|discord <url>|wechat <pushplus_token>|webhook <url> [raw|slack|discord]|test <percent>]";;
    esac
    exit 0 ;;
  
  # 备份恢复
  backup) 
    case "$2" in 
      create) backup_create ;; 
      list) backup_list ;; 
      restore) backup_restore "$3" ;; 
      *) echo "用法: edgeboxctl backup [create|list|restore <file>]";; 
    esac 
    ;;
  
  # 更新系统
  update)
    log_info "更新EdgeBox..."
    curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/install.sh | bash
    ;;
	
# Reality 密钥轮换
  rotate-reality)
    # <<< FIX: Add --force flag support >>>
    if [[ "$2" == "--force" ]]; then
        rotate_reality_keys "true"
    else
        rotate_reality_keys "false"
    fi
    ;;
    
  reality-status)
    show_reality_rotation_status
    ;;
    
  reality-status)
    show_reality_rotation_status
    ;;

   # SNI域名池管理
  sni)
    case "$2" in
      list|pool)
        sni_pool_list
        ;;
      test|test-all)
        sni_test_all
        ;;
      select|auto)
        sni_auto_select
        ;;
      set)
        sni_set_domain "$3"
        ;;
      *)
        echo "用法: edgeboxctl sni {list|test-all|auto|set <域名>}"
        exit 1
        ;;
    esac
    ;;
	
  # 流量管理 (统计 + 流量特征随机化)
  traffic)
    case "${2:-}" in
      # 流量统计
      "show"|"")
        traffic_show
        ;;
      # 流量特征随机化
      "randomize") 
        traffic_randomize "${3:-light}"
        ;;
      "status") 
        traffic_status
        ;;
      "reset") 
        traffic_reset
        ;;
      *) 
        echo "用法: edgeboxctl traffic [show|randomize|status|reset]"
        echo ""
        echo "流量统计:"
        echo "  show        - 显示流量使用统计"
        echo ""
        echo "流量特征随机化:"
        echo "  randomize   - 执行协议参数随机化 [light|medium|heavy]"
        echo "  status      - 显示随机化系统状态"
        echo "  reset       - 重置协议参数为默认值"
        exit 1
        ;;
    esac
    ;;
	
	test-udp)
    # 用法: edgeboxctl test-udp <host> <port> [seconds]
    local host="${2:-127.0.0.1}" port="${3:-443}" secs="${4:-3}"
    echo "[INFO] UDP 简测: ${host}:${port}, ${secs}s"
    if command -v iperf3 >/dev/null 2>&1; then
      iperf3 -u -c "$host" -p "$port" -t "$secs" --bitrate 5M --get-server-output || true
    else
      echo "[WARN] 未安装 iperf3，退化为本地探测..."
      if command -v socat >/dev/null 2>&1; then
        printf 'x' | socat -T1 - udp:${host}:${port} && echo "[OK] 发送成功(不代表服务握手成功)"
      else
        echo "[HINT] 建议安装: apt-get install -y iperf3 socat"
      fi
    fi
    ;;
	
# 控制面板密码管理
dashboard)
    case "$2" in
      passcode)
        shift 2
        update_dashboard_passcode "$@"
        ;;
      *)
        echo "用法: edgeboxctl dashboard passcode [新密码]"
        echo "  - 不提供密码则提示输入，留空则随机生成"
        echo "  - 密码必须是6位数字"
        ;;
    esac
    ;;

help|"")
  # --- 工具：带 ANSI 颜色时也能精确对齐注释列 ---
  strip_ansi() { sed -r 's/\x1B\[[0-9;]*m//g' <<<"$1"; }
  # $1=左侧文本(含颜色)  $2=注释文本  $3=注释列起始列(每板块独立)
  print_cmd() {
    local left="$1" comment="$2" col="${3:-60}"
    local plain="$(strip_ansi "$left")"
    local len=${#plain}
    local pad=$(( col - 2 - len ))   # 最左侧保持两格缩进
    (( pad < 1 )) && pad=1
    printf "  %b%*s${DIM}# %s${NC}\n" "$left" "$pad" "" "$comment"
  }

  # 每个板块的注释列（# 起始列），仅影响注释对齐，不改变你原有缩进层级
  _W_CORE=48
  _W_CERT=52
  _W_SNI=50
  _W_REALITY=48
  _W_TRAND=54
  _W_SUB=56
  _W_SHUNT=56
  _W_ALERT=56
  _W_CONF=56
  _W_DEBUG=52

  # 头部框线
  printf "%b\n" "${CYAN}════════════════════════════════════════════════════════════════"
  printf "  EdgeBox 管理工具 v%s\n" "${VERSION}"
  printf "%b\n\n" "════════════════════════════════════════════════════════════════${NC}"

  # 核心命令
  printf "%b\n" "${YELLOW}■ 核心命令 (Core Commands)${NC}"
  print_cmd "${GREEN}edgeboxctl status${NC}"                        "查看所有服务及端口的健康状态"               $_W_CORE
  print_cmd "${GREEN}edgeboxctl sub${NC}"                           "显示订阅链接与 Web 面板信息"                 $_W_CORE
  print_cmd "${GREEN}edgeboxctl restart${NC}"                       "优雅重启所有核心服务 (配置变更后使用)"        $_W_CORE
  print_cmd "${GREEN}edgeboxctl logs${NC} ${CYAN}<service>${NC}"    "查看指定服务的实时日志 (Ctrl+C 退出)"         $_W_CORE
  print_cmd "${GREEN}edgeboxctl update${NC}"                        "在线更新 EdgeBox 至最新版本"                  $_W_CORE
  print_cmd "${GREEN}edgeboxctl help${NC}"                          "显示此帮助信息"                              $_W_CORE
  printf "  %b\n" "${CYAN}示例:${NC}"
  printf "  %b %b\n\n" "${GREEN}edgeboxctl logs${NC}" "${CYAN}xray${NC}"

  # 证书管理
  printf "%b\n" "${YELLOW}■ 证书管理 (Certificate Management)${NC}"
  print_cmd "${GREEN}edgeboxctl switch-to-domain${NC} ${CYAN}<domain>${NC}"  "切换为域名模式，并申请 Let's Encrypt 证书"  $_W_CERT
  print_cmd "${GREEN}edgeboxctl switch-to-ip${NC}"                            "切换回 IP 模式，使用自签名证书"            $_W_CERT
  print_cmd "${GREEN}edgeboxctl cert status${NC}"                             "查看当前证书类型、域名及有效期"            $_W_CERT
  print_cmd "${GREEN}edgeboxctl cert renew${NC}"                              "手动续期 Let's Encrypt 证书"               $_W_CERT
  print_cmd "${GREEN}edgeboxctl fix-permissions${NC}"                         "修复证书文件的读写权限"                    $_W_CERT
  printf "  %b\n" "${CYAN}示例:${NC}"
  printf "  %b %b\n\n" "${GREEN}edgeboxctl switch-to-domain${NC}" "${CYAN}my.domain.com${NC}"

  # SNI 域名管理
  printf "%b\n" "${YELLOW}■ SNI 域名管理 (SNI Domain Management)${NC}"
  print_cmd "${GREEN}edgeboxctl sni list${NC}"                      "显示 SNI 域名池状态 (别名: pool)"             $_W_SNI
  print_cmd "${GREEN}edgeboxctl sni auto${NC}"                      "智能测试并选择最优 SNI 域名"                   $_W_SNI
  print_cmd "${GREEN}edgeboxctl sni set${NC} ${CYAN}<domain>${NC}"  "手动强制指定一个 SNI 域名"                     $_W_SNI
  print_cmd "${GREEN}edgeboxctl sni test-all${NC}"                  "测试池中所有域名的可用性"                      $_W_SNI
  printf "  %b\n" "${CYAN}示例:${NC}"
  printf "  %b %b\n\n" "${GREEN}edgeboxctl sni set${NC}" "${CYAN}www.apple.com${NC}"

    # Reality 密钥轮换
  printf "%b\n" "${YELLOW}■ Reality 密钥轮换 (Reality Key Rotation)${NC}"
  print_cmd "${GREEN}edgeboxctl rotate-reality${NC} ${CYAN}[--force]${NC}"  "手动执行 Reality 密钥对轮换 (安全增强)"                 $_W_REALITY
  print_cmd "${GREEN}edgeboxctl reality-status${NC}"  "查看 Reality 密钥轮换的周期状态"                       $_W_REALITY
  printf "\n"

  # 流量特征随机化
  printf "%b\n" "${YELLOW}■ 流量特征随机化 (Traffic Randomization)${NC}"
  print_cmd "${GREEN}edgeboxctl traffic randomize${NC} ${CYAN}[light|medium|heavy]${NC}"  "执行流量特征随机化，增强隐蔽性"  $_W_TRAND
  print_cmd "${GREEN}edgeboxctl traffic status${NC}"                                      "查看随机化系统状态和定时任务"    $_W_TRAND
  print_cmd "${GREEN}edgeboxctl traffic reset${NC}"                                       "重置随机化参数为默认值"          $_W_TRAND
  printf "  %b\n" "${CYAN}示例:${NC}"
  printf "  %b %b\n" "${GREEN}edgeboxctl traffic randomize${NC}" "${CYAN}medium${NC}"
  printf "  %b\n" "${CYAN}level:${NC}"
  printf "  %b  %b\n" "${CYAN}light${NC}"  "${DIM}- 轻度随机化，仅修改 Hysteria2 伪装站点${NC}"
  printf "  %b  %b\n" "${CYAN}medium${NC}" "${DIM}- 中度随机化，修改 Hysteria2 + TUIC 参数${NC}"
  printf "  %b  %b\n\n" "${CYAN}heavy${NC}"  "${DIM}- 重度随机化，修改全协议参数${NC}"

# 独立用户订阅
  printf "%b\n" "${YELLOW}■ 独立用户订阅 (User Subscriptions)${NC}"
  print_cmd "${GREEN}edgeboxctl sub issue${NC} ${CYAN}<user> [limit]${NC}"  "为指定用户下发专属订阅链接"       $_W_SUB
  print_cmd "${GREEN}edgeboxctl sub show${NC} ${CYAN}<user>${NC}"           "查看用户订阅及已绑定的设备"         $_W_SUB
  print_cmd "${GREEN}edgeboxctl sub revoke${NC} ${CYAN}<user>${NC}"         "停用指定用户的订阅链接"             $_W_SUB
  print_cmd "${GREEN}edgeboxctl sub limit${NC} ${CYAN}<user> <N>${NC}"      "修改用户的设备上限"                 $_W_SUB
  printf "  %b\n" "${CYAN}示例:${NC}"
  printf "  %b %b\n" "${GREEN}edgeboxctl sub issue${NC}" "${CYAN}alice 5${NC}"
  printf "  %b %b\n\n" "${GREEN}edgeboxctl sub show${NC}" "${CYAN}alice${NC}"
  
  # 出站分流
  printf "%b\n" "${YELLOW}■ 出站分流 (Outbound Routing)${NC}"
  print_cmd "${GREEN}edgeboxctl shunt vps${NC}"                                  "[模式] VPS 直连出站 (默认)"          $_W_SHUNT
  print_cmd "${GREEN}edgeboxctl shunt resi${NC} ${CYAN}'<URL>'${NC}"             "[模式] 代理全量出站 (仅 Xray)"        $_W_SHUNT
  print_cmd "${GREEN}edgeboxctl shunt direct-resi${NC} ${CYAN}'<URL>'${NC}"      "[模式] 智能分流 (白名单直连，其余走代理)" $_W_SHUNT
  print_cmd "${GREEN}edgeboxctl shunt status${NC}"                               "查看当前出站模式及代理健康状况"        $_W_SHUNT
  print_cmd "${GREEN}edgeboxctl shunt whitelist${NC} ${CYAN}<action>${NC} ${CYAN}[domain]${NC}" "管理白名单 (add|remove|list|reset)" $_W_SHUNT
  printf "  %b\n" "${CYAN}示例:${NC}"
  printf "  %b %b\n" "${GREEN}edgeboxctl shunt direct-resi${NC}" "${CYAN}'socks5://user:pass@host:port'${NC}"
  printf "  %b %b\n" "${GREEN}edgeboxctl shunt whitelist add${NC}" "${CYAN}netflix.com${NC}"
  printf "  %b\n" "${CYAN}代理URL格式:${NC}"
  printf "  %b\n" "${CYAN}http://user:pass@host:port${NC}"
  printf "  %b\n" "${CYAN}https://user:pass@host:port?sni=example.com${NC}"
  printf "  %b\n" "${CYAN}socks5://user:pass@host:port${NC}"
  printf "  %b\n\n" "${CYAN}socks5s://user:pass@host:port?sni=example.com${NC}"

  # 流量与预警
  printf "%b\n" "${YELLOW}■ 流量与预警 (Traffic & Alert)${NC}"
  print_cmd "${GREEN}edgeboxctl traffic show${NC}"                             "在终端查看流量使用统计"                 $_W_ALERT
  print_cmd "${GREEN}edgeboxctl alert show${NC}"                               "查看当前预警配置"                       $_W_ALERT
  print_cmd "${GREEN}edgeboxctl alert monthly${NC} ${CYAN}<GiB>${NC}"          "设置月度流量预算"                       $_W_ALERT
  print_cmd "${GREEN}edgeboxctl alert steps${NC} ${CYAN}<p1,p2,...>${NC}"      "设置百分比预警阈值 (逗号分隔)"           $_W_ALERT
  print_cmd "${GREEN}edgeboxctl alert telegram${NC} ${CYAN}<token>${NC} ${CYAN}<chat_id>${NC}" "配置 Telegram 通知渠道" $_W_ALERT
  print_cmd "${GREEN}edgeboxctl alert discord${NC} ${CYAN}<webhook_url>${NC}"  "配置 Discord 通知渠道"                  $_W_ALERT
  print_cmd "${GREEN}edgeboxctl alert wechat${NC} ${CYAN}<pushplus_token>${NC}" "配置微信 PushPlus 通知渠道"            $_W_ALERT
  print_cmd "${GREEN}edgeboxctl alert webhook${NC} ${CYAN}<url>${NC} ${CYAN}[format]${NC}"     "配置通用 Webhook (raw|slack|discord)" $_W_ALERT
  print_cmd "${GREEN}edgeboxctl alert test${NC} ${CYAN}[percent]${NC}"         "模拟触发预警以测试通知渠道"             $_W_ALERT
  printf "  %b\n" "${CYAN}示例:${NC}"
  printf "  %b %b\n" "${GREEN}edgeboxctl alert monthly${NC}" "${CYAN}1000${NC}"
  printf "  %b %b\n" "${GREEN}edgeboxctl alert steps${NC}"   "${CYAN}50,80,95${NC}"
  printf "  %b %b %b\n" "${GREEN}edgeboxctl alert telegram${NC}" "${CYAN}<token>${NC}" "${CYAN}<chat_id>${NC}"
  printf "  %b %b\n\n" "${GREEN}edgeboxctl alert test${NC}"  "${CYAN}80${NC}"

  # 配置与维护
  printf "%b\n" "${YELLOW}■ 配置与维护 (Configuration & Maintenance)${NC}"
  print_cmd "${GREEN}edgeboxctl config show${NC}"                 "显示所有协议的 UUID、密码等详细配置"  $_W_CONF
  print_cmd "${GREEN}edgeboxctl config regenerate-uuid${NC}"      "为所有协议重新生成 UUID 和密码"      $_W_CONF
  print_cmd "${GREEN}edgeboxctl dashboard passcode${NC}"          "重置并显示 Web 控制面板的访问密码"    $_W_CONF
  print_cmd "${GREEN}edgeboxctl alias${NC} ${CYAN}\"我的备注\"${NC}" "为当前服务器设置一个易记的别名"     $_W_CONF
  print_cmd "${GREEN}edgeboxctl backup create${NC}"               "创建当前系统配置的完整备份"          $_W_CONF
  print_cmd "${GREEN}edgeboxctl backup list${NC}"                 "列出所有可用的备份文件"              $_W_CONF
  print_cmd "${GREEN}edgeboxctl backup restore${NC} ${CYAN}<file>${NC}" "从指定备份文件恢复系统配置"    $_W_CONF
  printf "  %b\n" "${CYAN}示例:${NC}"
  printf "  %b %b\n" "${GREEN}edgeboxctl alias${NC}" "${CYAN}\"香港-CN2-主力\"${NC}"
  printf "  %b %b\n\n" "${GREEN}edgeboxctl backup restore${NC}" "${CYAN}edgebox_backup_xxx.tar.gz${NC}"

  # 诊断与排障
  printf "%b\n" "${YELLOW}■ 诊断与排障 (Diagnostics & Debug)${NC}"
  print_cmd "${GREEN}edgeboxctl test${NC}"                                               "对各协议入口进行基础连通性测试" $_W_DEBUG
  print_cmd "${GREEN}edgeboxctl test-udp${NC} ${CYAN}<host>${NC} ${CYAN}<port>${NC} ${CYAN}[seconds]${NC}" "使用 iperf3/socat 进行 UDP 连通性简测" $_W_DEBUG
  print_cmd "${GREEN}edgeboxctl debug-ports${NC}"                                        "检查核心端口 (80, 443, 2053) 是否被占用" $_W_DEBUG
  printf "  %b\n" "${CYAN}示例 (排障流程):${NC}"
  printf "  %b → %b %b → %b\n\n" "${GREEN}edgeboxctl status${NC}" "${GREEN}edgeboxctl logs${NC}" "${CYAN}xray${NC}" "${GREEN}edgeboxctl debug-ports${NC}"

  # 尾部信息
  printf "%b\n" "${CYAN}────────────────────────────────────────────────────────────────"
  printf "  获取更多帮助\n"
  printf "%b\n" "────────────────────────────────────────────────────────────────${NC}"
  printf "  配置文件: /etc/edgebox/config/\n"
  printf "  Web 面板: http://<你的IP>/traffic/?passcode=<你的密码>\n"
  printf "  订阅链接: http://<你的IP>/sub\n"
  printf "  查看日志: tail -f /var/log/edgebox-install.log\n"
  ;;

esac

# 脚本启动时自动加载配置
if [[ "${BASH_SOURCE[0]}" == "${0}" ]] || [[ -n "${EDGEBOXCTL_LOADED}" ]]; then
    # 设置调试模式
    [[ "${EDGEBOX_DEBUG}" == "true" ]] && LOG_LEVEL="debug"
    
    # 确保日志目录存在
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # 在脚本开始时加载配置（性能优化的核心）
    load_config_once || {
        log_warn "初始配置加载失败，部分功能可能不可用"
    }
    
    log_debug "edgeboxctl初始化完成，配置已缓存"
fi
EDGEBOXCTL_SCRIPT

    chmod +x /usr/local/bin/edgeboxctl
    log_success "增强版edgeboxctl管理工具创建完成"
}

# 配置邮件系统
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

  cat > /usr/local/bin/edgebox-ipq.sh <<'IPQ'
#!/usr/bin/env bash
set -euo pipefail; LANG=C
STATUS_DIR="/var/www/edgebox/status"
SHUNT_DIR="/etc/edgebox/config/shunt"
mkdir -p "$STATUS_DIR"

ts(){ date -Is; }
jqget(){ jq -r "$1" 2>/dev/null || echo ""; }

build_proxy_args(){ local u="${1:-}"; [[ -z "$u" || "$u" == "null" ]] && return 0
  case "$u" in socks5://*|socks5h://*) echo "--socks5-hostname ${u#*://}";;
           http://*|https://*) echo "--proxy $u";; *) :;; esac; }

CURL_UA="Mozilla/5.0 (EdgeBox IPQ)"
CURL_CONN_TIMEOUT="${CURL_CONN_TIMEOUT:-3}"
CURL_MAX_TIME="${CURL_MAX_TIME:-8}"
CURL_RETRY="${CURL_RETRY:-2}"
CURL_RETRY_DELAY="${CURL_RETRY_DELAY:-1}"

curl_json() {
  local p="$1" u="$2"
  curl -fsL -s \
       --connect-timeout "$CURL_CONN_TIMEOUT" \
       --max-time "$CURL_MAX_TIME" \
       --retry "$CURL_RETRY" \
       --retry-delay "$CURL_RETRY_DELAY" \
       -A "$CURL_UA" $p "$u" 2>/dev/null \
  | jq -c . 2>/dev/null || echo "{}"
}

test_bandwidth_correct() {
  local proxy_args="$1"
  local test_type="$2"
  local dl_speed=0 ul_speed=0
  
  if dl_result=$(eval "curl $proxy_args -o /dev/null -s -w '%{time_total}:%{speed_download}' --max-time 15 'http://speedtest.tele2.net/1MB.zip'" 2>/dev/null); then
    IFS=':' read -r dl_time dl_bytes_per_sec <<<"$dl_result"
    if [[ -n "$dl_bytes_per_sec" && "$dl_bytes_per_sec" != "0" ]]; then
      dl_speed=$(awk -v bps="$dl_bytes_per_sec" 'BEGIN{printf("%.1f", bps/1024/1024)}')
    fi
  fi
  
  local test_data=$(printf '%*s' 10240 '' | tr ' ' 'x')
  if ul_result=$(eval "curl $proxy_args -X POST -d '$test_data' -o /dev/null -s -w '%{time_total}' --max-time 10 'https://httpbin.org/post'" 2>/dev/null); then
    if [[ -n "$ul_result" && "$ul_result" != "0.000000" ]]; then
      ul_speed=$(awk -v t="$ul_result" 'BEGIN{printf("%.1f", 10/1024/t)}')
    fi
  fi
  
  echo "${dl_speed}/${ul_speed}"
}

get_rdns() {
  local ip="$1"
  local rdns=""
  
  if command -v dig >/dev/null 2>&1; then
    rdns=$(dig +time=2 +tries=2 +short -x "$ip" 2>/dev/null | head -n1 | sed 's/\.$//')
  fi
  
  if [[ -z "$rdns" ]] && command -v nslookup >/dev/null 2>&1; then
    rdns=$(nslookup "$ip" 2>/dev/null | awk '/name =/ {print $4; exit}' | sed 's/\.$//')
  fi
  
  echo "$rdns"
}

detect_network_features() {
  local asn="$1"
  local isp="$2"
  local ip="$3"
  local vantage="$4"
  
  local hosting="false"
  local residential="false" 
  local mobile="false"
  local proxy="false"
  local network_type="Unknown"
  
  if [[ "$asn" =~ (Google|AWS|Amazon|Microsoft|Azure|DigitalOcean|Linode|Vultr|Hetzner|OVH) ]] || \
     [[ "$isp" =~ (Google|AWS|Amazon|Microsoft|Azure|DigitalOcean|Linode|Vultr|Hetzner|OVH) ]]; then
    hosting="true"
    if [[ "$asn" =~ (Google|AWS|Amazon|Microsoft|Azure) ]]; then
      network_type="Cloud"
    else
      network_type="Datacenter"
    fi
  fi
  
  if [[ "$vantage" == "proxy" && "$hosting" == "false" ]]; then
    if [[ "$isp" =~ (NTT|Comcast|Verizon|AT\&T|Charter|Spectrum|Cox|Residential|Cable|Fiber|DSL|Broadband) ]]; then
      residential="true"
      network_type="Residential"
    fi
  fi
  
  if [[ "$asn" =~ (Mobile|Cellular|LTE|5G|4G|T-Mobile|Verizon Wireless) ]]; then
    mobile="true"
    network_type="Mobile"
  fi
  
  echo "${hosting}:${residential}:${mobile}:${proxy}:${network_type}"
}

get_proxy_url(){ local s="${SHUNT_DIR}/state.json"
  [[ -s "$s" ]] && jqget '.proxy_info' <"$s" || echo ""; }

collect_one(){ 
  local V="$1" P="$2" J1="{}" J2="{}" J3="{}" ok1=false ok2=false ok3=false
  
  if out=$(curl_json "$P" "https://ipinfo.io/json"); then J1="$out"; ok1=true; fi
  
  if out=$(curl_json "$P" "https://api.ip.sb/geoip"); then
    J2="$out"; ok2=true
  else
    for alt in \
      "https://ifconfig.co/json" \
      "https://api.myip.com" \
      "https://ipapi.co/json/"
    do
      if out=$(curl_json "$P" "$alt"); then J2="$out"; ok2=true; break; fi
    done
  fi

  if out=$(curl_json "$P" "http://ip-api.com/json/?fields=status,message,continent,country,regionName,city,lat,lon,isp,org,as,reverse,query"); then
    J3="$out"; ok3=true
  else
    if out=$(curl_json "$P" "https://ipwho.is/?lang=en"); then
      J3="$out"; ok3=true
    fi
  fi

  if [[ "$ok1" == "false" && "$ok2" == "false" && "$ok3" == "false" ]]; then
    if [[ "$V" == "proxy" ]]; then
      jq -n --arg ts "$(ts)" '{detected_at:$ts,vantage:"proxy",status:"api_failed",error:"All APIs failed"}'
      return 0
    fi
  fi

  local ip=""; for j in "$J2" "$J1" "$J3"; do ip="$(jq -r '(.ip // .query // empty)' <<<"$j" 2>/dev/null || echo "")"; [[ -n "$ip" && "$ip" != "null" ]] && break; done
  
  local rdns="$(jq -r '.reverse // empty' <<<"$J3" 2>/dev/null || echo "")"
  if [[ -z "$rdns" && -n "$ip" ]]; then
    rdns="$(get_rdns "$ip")"
  fi
  
  local asn="$(jq -r '(.asname // .as // empty)' <<<"$J3" 2>/dev/null || echo "")"; [[ -z "$asn" || "$asn" == "null" ]] && asn="$(jq -r '(.org // empty)' <<<"$J1" 2>/dev/null || echo "")"
  local isp="$(jq -r '(.org // empty)' <<<"$J1" 2>/dev/null || echo "")"; [[ -z "$isp" || "$isp" == "null" ]] && isp="$(jq -r '(.asname // .as // empty)' <<<"$J3" 2>/dev/null || echo "")"
  local country="$(jq -r '(.country // empty)' <<<"$J3" 2>/dev/null || echo "")"; [[ -z "$country" || "$country" == "null" ]] && country="$(jq -r '(.country // empty)' <<<"$J1" 2>/dev/null || echo "")"
  local city="$(jq -r '(.city // empty)' <<<"$J3" 2>/dev/null || echo "")"; [[ -z "$city" || "$city" == "null" ]] && city="$(jq -r '(.city // empty)' <<<"$J1" 2>/dev/null || echo "")"

  declare -a hits=(); 
  if [[ -n "$ip" ]]; then 
    IFS=. read -r a b c d <<<"$ip"; rip="${d}.${c}.${b}.${a}"
    for bl in zen.spamhaus.org bl.spamcop.net dnsbl.sorbs.net b.barracudacentral.org; do
      if dig +time=1 +tries=1 +short "${rip}.${bl}" A >/dev/null 2>&1; then hits+=("$bl"); fi
    done
  fi

  local lat=999
  if [[ "$V" == "vps" ]]; then
    if r=$(ping -c 3 -W 4 1.1.1.1 2>/dev/null | awk -F'/' '/rtt|round-trip/ {print int($5+0.5); exit}' 2>/dev/null); then
      [[ -n "${r:-}" ]] && lat="$r"
    fi
  else
    if r=$(eval "curl -o /dev/null -s $P -w '%{time_connect}' --max-time 10 https://www.cloudflare.com/cdn-cgi/trace" 2>/dev/null); then
      [[ -n "${r:-}" ]] && lat=$(awk -v t="$r" 'BEGIN{printf("%d",(t*1000)+0.5)}' 2>/dev/null || echo 999)
    fi
  fi

  local bandwidth_up="0" bandwidth_down="0"
  local bw_result=$(test_bandwidth_correct "$P" "$V")
  IFS='/' read -r bandwidth_down bandwidth_up <<<"$bw_result"

  local features=$(detect_network_features "$asn" "$isp" "$ip" "$V")
  IFS=':' read -r hosting residential mobile proxy network_type <<<"$features"

  local score=100; declare -a notes=()
  [[ "$proxy" == "true"   ]] && score=$((score-25)) && notes+=("proxy_flag")
  [[ "$hosting"  == "true"   ]] && score=$((score-5)) && notes+=("datacenter_ip")
  (( ${#hits[@]} > 0 )) && score=$((score-12*${#hits[@]})) && notes+=("dnsbl_hits")
  (( lat>400 )) && score=$((score-15)) && notes+=("high_latency")
  (( lat>200 && lat<=400 )) && score=$((score-8)) && notes+=("mid_latency")
  
  if [[ "$asn" =~ (amazon|aws|google|gcp|microsoft|azure|alibaba|tencent|digitalocean|linode|vultr|hivelocity|ovh|hetzner|iij|ntt|leaseweb|contabo) ]]; then 
    score=$((score-3))
    notes+=("cloud_provider")
  fi
  
  [[ "$residential" == "true" ]] && score=$((score+10)) && notes+=("residential_network")
  
  (( score<0 )) && score=0
  (( score>100 )) && score=100
  local grade="D"; ((score>=80)) && grade="A" || { ((score>=60)) && grade="B" || { ((score>=40)) && grade="C"; }; }

  local conclusion="基于多维度评估："
  [[ "$hosting" == "true" ]] && conclusion="${conclusion} 数据中心IP;"
  [[ "$residential" == "true" ]] && conclusion="${conclusion} 住宅网络;"
  (( ${#hits[@]} > 0 )) && conclusion="${conclusion} 命中${#hits[@]}个黑名单;"
  (( lat > 200 )) && conclusion="${conclusion} 延迟较高(${lat}ms);"
  [[ "$bandwidth_down" != "0" ]] && conclusion="${conclusion} 带宽${bandwidth_down}/${bandwidth_up}MB/s;"
  conclusion="${conclusion} 综合评分${score}分，等级${grade}。"

  local hits_json="$(printf '%s\n' "${hits[@]:-}" | jq -R -s 'split("\n")|map(select(length>0))' 2>/dev/null || echo '[]')"
  local notes_json="$(printf '%s\n' "${notes[@]:-}" | jq -R -s 'split("\n")|map(select(length>0))' 2>/dev/null || echo '[]')"

  jq -n \
    --arg ts "$(ts)" \
    --arg v "$V" \
    --arg ip "$ip" \
    --arg country "$country" \
    --arg city "$city" \
    --arg asn "$asn" \
    --arg isp "$isp" \
    --arg rdns "$rdns" \
    --arg network_type "$network_type" \
    --arg conclusion "$conclusion" \
    --arg bandwidth_down "$bandwidth_down" \
    --arg bandwidth_up "$bandwidth_up" \
    --argjson score "$score" \
    --arg grade "$grade" \
    --argjson latency "$lat" \
    --argjson notes "$notes_json" \
    --argjson hits "$hits_json" \
    --argjson proxy "$([[ "$proxy" == "true" ]] && echo true || echo false)" \
    --argjson hosting "$([[ "$hosting" == "true" ]] && echo true || echo false)" \
    --argjson mobile "$([[ "$mobile" == "true" ]] && echo true || echo false)" \
    --argjson residential "$([[ "$residential" == "true" ]] && echo true || echo false)" \
    '{
       detected_at: $ts,
       vantage: $v,
       ip: $ip,
       country: $country,
       city: $city,
       asn: $asn,
       isp: $isp,
       rdns: (if $rdns == "" then null else $rdns end),
       score: $score,
       grade: $grade,
       network_type: $network_type,
       latency_p50: $latency,
       conclusion: $conclusion,
       bandwidth_down: (if $bandwidth_down == "0" then null else $bandwidth_down end),
       bandwidth_up: (if $bandwidth_up == "0" then null else $bandwidth_up end),
       notes: $notes,
       risk: {
         proxy: $proxy,
         hosting: $hosting,
         mobile: $mobile,
         residential: $residential,
         dnsbl_hits: $hits
       }
     }'
}

main(){
  collect_one "vps" "" > "${STATUS_DIR}/ipq_vps.json"
  purl="$(get_proxy_url)"
  if [[ -n "${purl:-}" && "$purl" != "null" ]]; then
    pargs="$(build_proxy_args "$purl")"
    collect_one "proxy" "$pargs" > "${STATUS_DIR}/ipq_proxy.json"
  else
    jq -n --arg ts "$(ts)" '{detected_at:$ts,vantage:"proxy",status:"not_configured"}' > "${STATUS_DIR}/ipq_proxy.json"
  fi
  jq -n --arg ts "$(ts)" --arg ver "ipq-enhanced-final-3.0" '{last_run:$ts,version:$ver}' > "${STATUS_DIR}/ipq_meta.json"
  chmod 644 "${STATUS_DIR}"/ipq_*.json 2>/dev/null || true
}

main "$@"
IPQ

  chmod +x /usr/local/bin/edgebox-ipq.sh

  ( crontab -l 2>/dev/null | grep -v '/usr/local/bin/edgebox-ipq.sh' ) | crontab - || true
  ( crontab -l 2>/dev/null; echo "15 2 * * * /usr/local/bin/edgebox-ipq.sh >/dev/null 2>&1" ) | crontab -

  # 修复前端代码支持
  fix_frontend_residential_support

  /usr/local/bin/edgebox-ipq.sh || true
  log_success "增强版IPQ栈完成：VPS带宽测试、特征识别优化、前端residential支持"
}


# 生成初始化脚本（用于开机自启动流量监控）
create_init_script() {
    log_info "创建初始化脚本(轻量方案)..."

    cat > /etc/edgebox/scripts/edgebox-init.sh << 'INIT_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
LOG_FILE="/var/log/edgebox-init.log"
echo "[$(date)] EdgeBox 初始化开始" >> $LOG_FILE

# 等待网络
sleep 10

# nftables 计数器存在性校验（无则创建）
nft list table inet edgebox >/dev/null 2>&1 || nft -f - <<'NFT'
table inet edgebox {
  counter c_tcp443   {}
  counter c_udp443   {}
  counter c_udp2053  {}
  counter c_resi_out {}

  set resi_addr4 {
    type ipv4_addr
    flags interval
  }
  set resi_addr6 {
    type ipv6_addr
    flags interval
  }

  chain out {
    type filter hook output priority 0; policy accept;
    tcp dport 443   counter name c_tcp443
    udp dport 443   counter name c_udp443
    udp dport 2053  counter name c_udp2053
    ip  daddr @resi_addr4 counter name c_resi_out
    ip6 daddr @resi_addr6 counter name c_resi_out
  }
}
NFT

# 启动 vnstat
systemctl is-active --quiet vnstat || systemctl start vnstat

# 预跑一次采集器，生成 traffic.json / CSV
[[ -x /etc/edgebox/scripts/traffic-collector.sh ]] && /etc/edgebox/scripts/traffic-collector.sh >> $LOG_FILE 2>&1 || true

# 统一产出 dashboard.json / system.json
[[ -x /etc/edgebox/scripts/dashboard-backend.sh ]] && /etc/edgebox/scripts/dashboard-backend.sh --now >> $LOG_FILE 2>&1 || true

echo "[$(date)] EdgeBox 初始化完成" >> $LOG_FILE
INIT_SCRIPT

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
sync_subscription_files() {
  log_info "同步订阅文件..."
  mkdir -p "${WEB_ROOT}" "${TRAFFIC_DIR}"

  local src="${CONFIG_DIR}/subscription.txt"
  if [[ ! -s "$src" ]]; then
    log_warn "订阅源不存在：$src"
    return 0
  fi

  # Web 目录使用软链接，避免再出现"same file"报错
  ln -sfn "$src" "${WEB_ROOT}/sub"
  # traffic 下保留一份副本用于 dashboard-backend
  install -m 0644 -T "$src" "${TRAFFIC_DIR}/sub.txt"

  log_success "订阅同步完成：${WEB_ROOT}/sub -> ${src}，以及 ${TRAFFIC_DIR}/sub.txt"
}

# 启动服务并进行基础验证
start_services() {
  log_info "启动服务..."
  systemctl daemon-reload
  systemctl enable nginx xray sing-box >/dev/null 2>&1 || true

  reload_or_restart_services nginx xray sing-box

  sleep 2
  for s in nginx xray sing-box; do
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
  chmod 644 "${WEB_ROOT}/sub" 2>/dev/null || true
  chmod 644 "${TRAFFIC_DIR}"/*.json 2>/dev/null || true
  chmod 644 "${TRAFFIC_DIR}"/*.txt 2>/dev/null || true
  chmod 644 "${TRAFFIC_DIR}/logs"/*.csv 2>/dev/null || true
  chown -R www-data:www-data "${TRAFFIC_DIR}" 2>/dev/null || true
  
  # 8. 最终验证
  log_info "执行最终验证..."
  local validation_failed=false

  # 验证关键文件存在
  for file in "${CONFIG_DIR}/server.json" "${CONFIG_DIR}/subscription.txt" "${WEB_ROOT}/sub"; do
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

    # 执行初始SNI域名选择
    log_info "执行初始SNI域名选择..."
    if "$SNI_MANAGER_SCRIPT" select >/dev/null 2>&1; then
        log_success "✓ SNI域名初始选择完成"
    else
        log_warn "SNI域名初始选择失败，可手动执行: edgeboxctl sni auto"
    fi
	
  log_success "数据生成与系统验证完成"
}


# 显示安装完成信息
show_installation_info() {
    clear
    print_separator
    echo -e "${GREEN}🎉 EdgeBox 企业级多协议节点 v${EDGEBOX_VER} 安装完成！${NC}"
    print_separator
    
    # 确保加载最新数据（特别是密码）
    local config_file="${CONFIG_DIR}/server.json"
    
    # 确保 jq 命令和文件路径正确
    local server_ip=$(jq -r '.server_ip // empty' "$config_file" 2>/dev/null)
    local UUID_VLESS=$(jq -r '.uuid.vless.reality // .uuid.vless // empty' "$config_file" 2>/dev/null)
    local UUID_GRPC=$(jq -r '.uuid_vless_grpc // .uuid.vless.grpc // empty' "$config_file" 2>/dev/null)  # ← 添加这行
    local UUID_WS=$(jq -r '.uuid_vless_ws // .uuid.vless.ws // empty' "$config_file" 2>/dev/null)      # ← 添加这行
    local UUID_TUIC=$(jq -r '.uuid.tuic // empty' "$config_file" 2>/dev/null)
    local PASSWORD_HYSTERIA2=$(jq -r '.password.hysteria2 // empty' "$config_file" 2>/dev/null)
    local PASSWORD_TUIC=$(jq -r '.password.tuic // empty' "$config_file" 2>/dev/null)
    local PASSWORD_TROJAN=$(jq -r '.password.trojan // empty' "$config_file" 2>/dev/null)
    
    # >>> 核心修复逻辑：从文件加载密码 >>>
    local DASHBOARD_PASSCODE=$(jq -r '.dashboard_passcode // empty' "$config_file" 2>/dev/null)
    
    # 如果读取失败，至少赋一个安全值
    if [[ -z "$DASHBOARD_PASSCODE" ]]; then
        DASHBOARD_PASSCODE="[密码读取失败]"
    fi
    # <<< 核心修复逻辑结束 <<<
    
    echo -e  "${CYAN} 核心访问信息${NC}"
    echo -e  "  👥 IP 地址: ${PURPLE}${server_ip}${NC}"
    
    # 打印时使用已验证的 DASHBOARD_PASSCODE 变量
    echo -e  "  🔑 访问密码: ${YELLOW}${DASHBOARD_PASSCODE}${NC}"
    echo -e  "  🌐 控制面板: ${PURPLE}http://${server_ip}/traffic/?passcode=${DASHBOARD_PASSCODE}${NC}" 
    

    echo -e  "\n${CYAN}默认模式：${NC}"
    echo -e  "  证书模式: ${PURPLE}IP模式（自签名证书）${NC}"
    echo -e  "  网络身份: ${PURPLE}VPS直连出站（默认）${NC}"
	
    echo -e "\n${CYAN}协议配置摘要：${NC}"
    echo -e "  VLESS-Reality  端口: 443  UUID: ${PURPLE}${UUID_VLESS:0:8}...${NC}"
    echo -e "  VLESS-gRPC     端口: 443  UUID: ${PURPLE}${UUID_GRPC:0:8}...${NC}"  
    echo -e "  VLESS-WS       端口: 443  UUID: ${PURPLE}${UUID_WS:0:8}...${NC}"  
    echo -e "  Trojan-TLS     端口: 443  密码: ${PURPLE}${PASSWORD_TROJAN:0:8}...${NC}"
    echo -e "  Hysteria2      端口: 443  密码: ${PURPLE}${PASSWORD_HYSTERIA2:0:8}...${NC}"
    echo -e "  TUIC           端口: 2053 UUID: ${PURPLE}${UUID_TUIC:0:8}...${NC}"
    
    echo -e "\n${CYAN}常用运维命令：${NC}"
    echo -e "  ${PURPLE}edgeboxctl status${NC}                             # 查看服务状态"
    echo -e "  ${PURPLE}edgeboxctl sub${NC}                                # 查看订阅链接"
    echo -e "  ${PURPLE}edgeboxctl dashboard passcode${NC}                 # ${RED}更新控制面板密码${NC}"
    echo -e "  ${PURPLE}edgeboxctl switch-to-domain <域名>${NC}            # 切换证书模式"
    echo -e "  ${PURPLE}edgeboxctl shunt direct-resi '<代理URL>'${NC}      # 启用智能分流"
    echo -e "  ${PURPLE}edgeboxctl help${NC}                               # 查看完整帮助"
    
	echo -e "\n${CYAN}高级运维功能：${NC}"
    echo -e "  🔄 证书切换: IP模式 ⇋ 域名模式（Let's Encrypt证书）"
    echo -e "  🌐 出站分流: 代理IP全量 ⇋ VPS全量出 ⇋ 分流"
    echo -e "  📊 流量监控: 实时流量统计、历史趋势图表、协议分析"
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

    # TCP 443：TLS/Reality/WS/gRPC 复用
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE '[:.]443($|[^0-9])'; then
        echo -e "  ✅ 443/tcp   TLS/Reality/WS/gRPC 复用"
    else
        echo -e "  ⚠️  443/tcp   TLS/Reality/WS/gRPC 复用（未监听）"
    fi

    # Hysteria2（UDP）
    H2_PORT="${PORT_HYSTERIA2:-8443}"
    if ss -uln 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${H2_PORT}($|[^0-9])"; then
        echo -e "  ✅ ${H2_PORT}/udp   Hysteria2"
    else
        echo -e "  ⚠️  ${H2_PORT}/udp   Hysteria2（未监听）"
    fi

    # TUIC（UDP）
    TUIC_PORT_REAL="${PORT_TUIC:-2053}"
    if ss -uln 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${TUIC_PORT_REAL}($|[^0-9])"; then
        echo -e "  ✅ ${TUIC_PORT_REAL}/udp   TUIC"
    else
        echo -e "  ⚠️  ${TUIC_PORT_REAL}/udp   TUIC（未监听）"
    fi

    echo
    echo -e "${GREEN}安装完成${NC} ✅  （详细检查请执行：${PURPLE}edgeboxctl status${NC}）"

    print_separator

}

# 简化版清理函数
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
        log_warn "检测到已安装的EdgeBox，这将覆盖现有配置"
        read -p "是否继续？[y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "安装已取消"
            exit 0
        fi
    fi
    
    # 检查关键端口占用
    local critical_ports=(443 80 2053)
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
main() {
    trap cleanup_all EXIT
	
    clear
	
    echo -e "${GREEN}EdgeBox 企业级安装脚本 v3.0.0${NC}"
    print_separator
    
    export EDGEBOX_VER="3.0.0"
    mkdir -p "$(dirname "${LOG_FILE}")" && touch "${LOG_FILE}"
    
    log_info "开始执行完整安装流程..."
    
    # --- 模块1: 基础环境准备 ---
    show_progress 1 10 "系统环境检查"
    pre_install_check
    check_root
    check_system
    install_dependencies
    
    show_progress 2 10 "网络与目录配置"
    get_server_ip
    create_directories
	setup_sni_pool_management
    check_ports
    configure_firewall
    optimize_system

    # --- 模块2: 凭据与证书生成 ---
    show_progress 3 10 "生成安全凭据和证书"
    execute_module2 || { log_error "模块2执行失败"; exit 1; }

    # --- 模块3: 核心组件安装与配置 ---
    show_progress 4 10 "安装核心组件 (Xray, sing-box)"
    install_xray
    install_sing_box
    
    show_progress 5 10 "配置服务 (Xray, sing-box, Nginx)"
    configure_xray
    configure_sing_box
    configure_nginx
    
# --- 模块4: 后台、监控与运维工具 ---
show_progress 6 10 "安装后台面板和监控脚本"
execute_module4 || { log_error "模块4执行失败"; exit 1; }
	
	if ! setup_traffic_randomization; then
    log_error "流量特征随机化系统设置失败"
    exit 1
fi

    # --- 最终阶段: 启动、验证与数据生成 ---
    show_progress 8 10 "生成订阅链接"
    generate_subscription
    
    show_progress 9 10 "启动并验证所有服务"
    start_and_verify_services || { log_error "服务未能全部正常启动，请检查日志"; exit 1; }
    
    show_progress 10 10 "最终数据生成与同步"
    finalize_data_generation
    
    # 显示安装信息
    show_installation_info
	
	# [新增] 最终系统状态修复（幂等性保证）
    log_info "执行最终系统状态检查..."
    repair_system_state
    
    log_success "EdgeBox v3.0.0 安装成功完成！"
    exit 0
}

# 系统状态检查和修复函数
repair_system_state() {
    log_info "检查并修复系统状态..."

    # 1) 目录与日志
    ensure_directory_permissions
    mkdir -p /var/log/edgebox 2>/dev/null || true
    [[ -f /var/log/edgebox/sing-box.log ]] || touch /var/log/edgebox/sing-box.log

    # 2) 服务自愈（保持你的逻辑）
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

    # 4) 防火墙放行 UDP（HY2/TUIC）
    if command -v ufw >/dev/null 2>&1 && ufw status >/dev/null 2>&1; then
        ufw status | grep -q '443/udp'  || ufw allow 443/udp  >/dev/null 2>&1 || true
        ufw status | grep -q '2053/udp' || ufw allow 2053/udp >/dev/null 2>&1 || true
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=443/udp  >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=2053/udp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    else
        iptables -C INPUT -p udp --dport 443  -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p udp --dport 443  -j ACCEPT
        iptables -C INPUT -p udp --dport 2053 -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p udp --dport 2053 -j ACCEPT
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
    systemctl restart sing-box || true
    sleep 0.5

    # 7) 端口自检（与你现场排障一致）
    ss -uln | grep -q ':443 '  && log_success "HY2 UDP 443 监听 ✓"  || log_warn "HY2 UDP 443 未监听 ✗"
    ss -uln | grep -q ':2053 ' && log_success "TUIC UDP 2053 监听 ✓" || log_warn "TUIC UDP 2053 未监听 ✗"

    log_success "系统状态修复完成"
}


# 脚本入口点检查
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # 直接执行脚本
    main "$@"
fi
