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

# 以 root 运行到这里；如果是从临时文件重启的，退出时自动清理
trap '[[ -n "${EB_TMP:-}" ]] && rm -f "$EB_TMP"' EXIT

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
# 目录结构定义
#############################################

# 主安装目录
INSTALL_DIR="/etc/edgebox"
CERT_DIR="${INSTALL_DIR}/cert"
CONFIG_DIR="${INSTALL_DIR}/config"
TRAFFIC_DIR="${INSTALL_DIR}/traffic"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"

# 其他重要目录
BACKUP_DIR="/root/edgebox-backup"
LOG_FILE="/var/log/edgebox-install.log"
WEB_ROOT="/var/www/html"

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

# 安装系统依赖包
install_dependencies() {
    log_info "安装系统依赖包..."
    
    # 更新包管理器
    if command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu系统
        DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
        PKG_MANAGER="apt-get"
        INSTALL_CMD="DEBIAN_FRONTEND=noninteractive apt-get install -y"
    elif command -v yum >/dev/null 2>&1; then
        # CentOS/RHEL系统
        yum update -y >/dev/null 2>&1 || true
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora/新版CentOS
        dnf update -y >/dev/null 2>&1 || true
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
    else
        log_error "不支持的包管理器，无法安装依赖"
        exit 1
    fi

    # 必要的依赖包列表
    local base_packages=(
        curl wget unzip gawk ca-certificates 
        jq bc uuid-runtime dnsutils openssl
        tar cron
    )
    
    # 网络和防火墙包
    local network_packages=(
        vnstat nftables
    )
    
    # Web服务器包
    local web_packages=(
        nginx
    )
    
    # 证书和邮件包
    local cert_mail_packages=(
        certbot msmtp-mta bsd-mailx
    )
    
    # 系统工具包
    local system_packages=(
        dmidecode htop iotop
    )

    # 根据系统类型调整包名
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        # Debian/Ubuntu特有包
        network_packages+=(libnginx-mod-stream)
        cert_mail_packages+=(python3-certbot-nginx)
    elif [[ "$PKG_MANAGER" =~ ^(yum|dnf)$ ]]; then
        # RHEL/CentOS特有包
        base_packages+=(epel-release)
        cert_mail_packages+=(python3-certbot-nginx)
    fi

    # 合并所有包
    local all_packages=(
        "${base_packages[@]}" 
        "${network_packages[@]}" 
        "${web_packages[@]}" 
        "${cert_mail_packages[@]}"
        "${system_packages[@]}"
    )
    
    # 安装依赖包
    local failed_packages=()
    for pkg in "${all_packages[@]}"; do
        if ! dpkg -l 2>/dev/null | grep -q "^ii.*${pkg}" && ! rpm -q "$pkg" >/dev/null 2>&1; then
            log_info "安装 ${pkg}..."
            if eval "$INSTALL_CMD $pkg" >/dev/null 2>&1; then
                log_success "${pkg} 安装成功"
            else
                log_warn "${pkg} 安装失败，将跳过"
                failed_packages+=("$pkg")
            fi
        else
            log_info "${pkg} 已安装"
        fi
    done
    
    # 检查关键包是否安装成功
    local critical_packages=(jq curl wget nginx)
    for pkg in "${critical_packages[@]}"; do
        if ! command -v "$pkg" >/dev/null 2>&1; then
            log_error "关键依赖 $pkg 安装失败，无法继续安装"
            return 1
        fi
    done

    # 启用和启动基础服务
    log_info "启用基础服务..."
    
    # vnstat（网络流量统计）
    if command -v vnstat >/dev/null 2>&1; then
        systemctl enable vnstat >/dev/null 2>&1 || true
        systemctl start vnstat >/dev/null 2>&1 || true
        log_success "vnstat服务已启动"
    fi

    # nftables（网络过滤）
    if command -v nft >/dev/null 2>&1; then
        systemctl enable nftables >/dev/null 2>&1 || true
        systemctl start nftables >/dev/null 2>&1 || true
        log_success "nftables服务已启动"
    fi

    # 输出安装总结
    if [[ ${#failed_packages[@]} -eq 0 ]]; then
        log_success "所有依赖包安装完成"
    else
        log_warn "以下包安装失败: ${failed_packages[*]}"
        log_info "这些包不影响核心功能，安装将继续"
    fi
    
    return 0
}

# 创建目录结构
create_directories() {
    log_info "创建目录结构..."

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
    )

    # 创建所有必要目录
    for dir in "${directories[@]}"; do
        if mkdir -p "$dir" 2>/dev/null; then
            log_success "目录创建成功: $dir"
        else
            log_error "目录创建失败: $dir"
            return 1
        fi
    done

# 设置目录权限
chmod 755 "${INSTALL_DIR}" "${CONFIG_DIR}" "${SCRIPTS_DIR}"
# 证书目录：仅 root 与 nobody 所在组可访问
chmod 750 "${CERT_DIR}"
# 把证书目录的 group 调整为 nobody 对应的组（Debian 为 nogroup，RHEL 系为 nobody）
NOBODY_GRP="$(id -gn nobody 2>/dev/null || echo nogroup)"
chgrp "${NOBODY_GRP}" "${CERT_DIR}" || true

    
    log_success "目录结构创建完成"
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

# 配置防火墙规则
configure_firewall() {
    log_info "配置防火墙规则..."
    
    # 检测防火墙类型并配置
    if command -v ufw >/dev/null 2>&1; then
        # Ubuntu/Debian UFW
        log_info "检测到UFW防火墙，正在配置..."
        
        # 重置并配置UFW
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        
        # 允许SSH（保持连接）
        ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1
        
        # 允许EdgeBox端口
        ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1
        ufw allow 443/tcp comment 'EdgeBox TCP' >/dev/null 2>&1
        ufw allow 443/udp comment 'EdgeBox Hysteria2' >/dev/null 2>&1
        ufw allow 2053/udp comment 'EdgeBox TUIC' >/dev/null 2>&1
        
        # 启用UFW
        ufw --force enable >/dev/null 2>&1
        log_success "UFW防火墙配置完成"
        
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # CentOS/RHEL FirewallD
        log_info "检测到FirewallD防火墙，正在配置..."
        
        # 配置防火墙规则
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=2053/udp >/dev/null 2>&1
        
        # 重新加载规则
        firewall-cmd --reload >/dev/null 2>&1
        log_success "FirewallD防火墙配置完成"
        
    elif command -v iptables >/dev/null 2>&1; then
        # 传统iptables
        log_info "使用iptables配置防火墙..."
        
        # 基本iptables规则
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        iptables -A INPUT -p udp --dport 443 -j ACCEPT
        iptables -A INPUT -p udp --dport 2053 -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        
        # 保存iptables规则（如果有保存命令）
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        
        log_success "iptables防火墙配置完成"
    else
        log_warn "未检测到支持的防火墙软件"
        log_info "请手动配置防火墙，开放端口: 80/tcp, 443/tcp, 443/udp, 2053/udp"
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
cleanup_on_error() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        log_error "安装过程中发生错误，退出码: $exit_code"
        log_info "正在清理临时文件..."
        
        # 清理可能的临时文件
        rm -f /tmp/edgebox_* 2>/dev/null || true
        rm -f /tmp/sing-box* 2>/dev/null || true
        
        log_info "清理完成。详细错误信息请查看: $LOG_FILE"
    fi
    
    exit $exit_code
}

# 设置错误处理
trap cleanup_on_error EXIT

#############################################
# 模块1初始化完成标记
#############################################

log_success "模块1：脚本头部+基础函数 - 初始化完成"



#############################################
# EdgeBox 企业级多协议节点部署脚本 v3.0.0
# 模块2：系统信息收集+凭据生成
# 
# 功能说明：
# - 自动检测云厂商和硬件规格
# - 生成所有协议的UUID和密码
# - 生成Reality密钥对
# - 保存完整配置到server.json
# - 对齐控制面板数据口径
#############################################

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
        
        # CPU型号信息
        local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^[[:space:]]*//' 2>/dev/null || echo "Unknown CPU")
        
        # CPU架构
        local cpu_arch=$(uname -m 2>/dev/null || echo "unknown")
        
        # 组合CPU信息：核心数/线程数 型号
        echo "${physical_cores}C/${logical_threads}T ${cpu_model} (${cpu_arch})"
    }
    
    # 获取内存详细信息
    get_memory_info() {
        # 读取内存信息（KB转换为GB）
        local total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
        local total_gb=$(( total_kb / 1024 / 1024 ))
        
        # 读取交换分区信息
        local swap_kb=$(awk '/SwapTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
        local swap_gb=$(( swap_kb / 1024 / 1024 ))
        
        # 格式化输出
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
            echo "${total}GiB (已用: ${used}GiB, 可用: ${available}GiB)"
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
        elif [[ -f /etc/vultr ]] || curl -fsS --max-time 2 http://169.254.169.254/v1.json | grep -q vultr 2>/dev/null; then
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
    
    # 检查UUID生成工具
    if ! command -v uuidgen >/dev/null 2>&1; then
        log_error "uuidgen工具未安装，无法生成UUID"
        log_info "尝试安装uuid-runtime包..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get install -y uuid-runtime >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y util-linux >/dev/null 2>&1
        fi
        
        # 再次检查
        if ! command -v uuidgen >/dev/null 2>&1; then
            log_error "UUID生成工具安装失败，无法继续"
            return 1
        fi
    fi
    
    # 检查密码生成工具
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "openssl工具未找到，无法生成密码"
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

#############################################
# 配置信息保存函数
#############################################

# 保存完整配置信息到server.json（对齐控制面板数据口径）
save_config_info() {
    log_info "保存配置信息到server.json..."
    
    # 确保配置目录存在
    mkdir -p "${CONFIG_DIR}"
    
    # 准备基础变量（带默认值）
    local server_ip="${SERVER_IP:-127.0.0.1}"
    local version="${EDGEBOX_VER:-3.0.0}"
    local install_date="$(date +%Y-%m-%d)"
    local updated_at="$(date -Is)"
    
    # 系统信息变量（带默认值）
    local cloud_provider="${CLOUD_PROVIDER:-Unknown}"
    local cloud_region="${CLOUD_REGION:-Unknown}"
    local instance_id="${INSTANCE_ID:-Unknown}"
    local hostname="${HOSTNAME:-$(hostname)}"
    local user_alias=""  # 用户可后续自定义
    local cpu_spec="${CPU_SPEC:-Unknown}"
    local memory_spec="${MEMORY_SPEC:-Unknown}"
    local disk_spec="${DISK_SPEC:-Unknown}"
    
    # 协议凭据变量（必须有值）
    if [[ -z "$UUID_VLESS_REALITY" || -z "$PASSWORD_TROJAN" || -z "$PASSWORD_HYSTERIA2" ]]; then
        log_error "关键凭据缺失，无法保存配置"
        log_debug "VLESS Reality UUID: ${UUID_VLESS_REALITY:-空}"
        log_debug "Trojan密码: ${PASSWORD_TROJAN:-空}"
        log_debug "Hysteria2密码: ${PASSWORD_HYSTERIA2:-空}"
        return 1
    fi
    
    # 检查服务器IP有效性
    if [[ ! "$server_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "服务器IP格式无效: $server_ip"
        return 1
    fi
    
    log_info "生成server.json配置文件..."
    
    # 生成完整的server.json配置（对齐控制面板数据结构）
    if ! jq -n \
        --arg ts "$updated_at" \
        --arg ip "$server_ip" \
        --arg eip "" \
        --arg vm "$version" \
        --arg inst "$install_date" \
        --arg cloud_provider "$cloud_provider" \
        --arg cloud_region "$cloud_region" \
        --arg instance_id "$instance_id" \
        --arg hostname "$hostname" \
        --arg user_alias "$user_alias" \
        --arg cpu_spec "$cpu_spec" \
        --arg memory_spec "$memory_spec" \
        --arg disk_spec "$disk_spec" \
        --arg vr "$UUID_VLESS_REALITY" \
        --arg vg "$UUID_VLESS_GRPC" \
        --arg vw "$UUID_VLESS_WS" \
        --arg tu "$UUID_TUIC" \
        --arg tru "$UUID_TROJAN" \
        --arg tt "$PASSWORD_TROJAN" \
        --arg tp "$PASSWORD_TUIC" \
        --arg hy "$PASSWORD_HYSTERIA2" \
        --arg rpub "$REALITY_PUBLIC_KEY" \
        --arg rpri "$REALITY_PRIVATE_KEY" \
        --arg rsid "$REALITY_SHORT_ID" \
        '{
            server_ip: $ip,
            eip: $eip,
            version: $vm,
            install_date: $inst,
            updated_at: $ts,
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
            },
            uuid: {
                vless: {
                    reality: $vr,
                    grpc: $vg,
                    ws: $vw
                },
                tuic: $tu,
                trojan: $tru
            },
            password: {
                trojan: $tt,
                tuic: $tp,
                hysteria2: $hy
            },
            reality: {
                public_key: $rpub,
                private_key: $rpri,
                short_id: $rsid
            },
            cert: {
                mode: "self-signed",
                domain: "",
                expires_at: ""
            }
        }' > "${CONFIG_DIR}/server.json"; then
        log_error "server.json生成失败"
        return 1
    fi
    
if ! jq '.' "${CONFIG_DIR}/server.json" >/dev/null 2>&1; then
       log_error "server.json验证失败"
       return 1
   fi
    
    # 设置文件权限（只有root可读写）
    chmod 600 "${CONFIG_DIR}/server.json"
    chown root:root "${CONFIG_DIR}/server.json"
    
    log_success "server.json配置文件保存完成"
    
    # 显示配置摘要（不显示敏感信息）
    log_info "配置摘要："
    jq -r '
        "├─ 服务器IP: " + .server_ip,
        "├─ 云厂商: " + .cloud.provider + "/" + .cloud.region,
        "├─ 实例ID: " + .instance_id,
        "├─ 主机名: " + .hostname,
        "├─ CPU规格: " + .spec.cpu,
        "├─ 内存规格: " + .spec.memory,
        "├─ 磁盘规格: " + .spec.disk,
        "├─ Reality公钥: " + (.reality.public_key[0:16] + "..."),
        "└─ 配置版本: " + .version
    ' "${CONFIG_DIR}/server.json" | while read -r line; do
        log_info "$line"
    done
    
    return 0
}

# 生成自签名证书（基础版本，模块3会有完整版本）
generate_self_signed_cert() {
    log_info "生成自签名证书..."
    
    # 确保证书目录存在
    mkdir -p "${CERT_DIR}"
    
    # 清理可能存在的旧证书
    rm -f "${CERT_DIR}"/self-signed.{key,pem}
    rm -f "${CERT_DIR}"/current.{key,pem}
    
    # 检查openssl可用性
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "openssl未安装，无法生成证书"
        return 1
    fi
    
    # 生成ECC私钥和自签名证书（推荐secp384r1曲线）
    if ! openssl ecparam -genkey -name secp384r1 -out "${CERT_DIR}/self-signed.key" 2>/dev/null; then
        log_error "生成ECC私钥失败"
        return 1
    fi
    
    # 生成自签名证书（有效期10年）
    if ! openssl req -new -x509 \
        -key "${CERT_DIR}/self-signed.key" \
        -out "${CERT_DIR}/self-signed.pem" \
        -days 3650 \
        -subj "/C=US/ST=California/L=San Francisco/O=EdgeBox/CN=${SERVER_IP}" \
        >/dev/null 2>&1; then
        log_error "生成自签名证书失败"
        return 1
    fi
    
    # 创建当前证书软链接（统一接口）
    ln -sf "${CERT_DIR}/self-signed.key" "${CERT_DIR}/current.key"
    ln -sf "${CERT_DIR}/self-signed.pem" "${CERT_DIR}/current.pem"
    
# —— 原来有的 —— 
chown root:root "${CERT_DIR}"/*.{key,pem}
# 私钥严格权限、证书可读
chmod 600 "${CERT_DIR}"/*.key
chmod 644 "${CERT_DIR}"/*.pem

# —— 追加（修复 nobody 无法读的问题）——
NOBODY_GRP="$(id -gn nobody 2>/dev/null || echo nogroup)"
# 让 nobody 所在组能“穿目录 + 读私钥”
chgrp "${NOBODY_GRP}" "${CERT_DIR}" || true
chgrp "${NOBODY_GRP}" "${CERT_DIR}"/self-signed.key "${CERT_DIR}"/self-signed.pem || true
# 私钥改 640（root 可读写，组可读），证书仍 644
chmod 640 "${CERT_DIR}"/self-signed.key
# 软链指向的目标权限已覆盖；无需再对 symlink 本身 chmod
    
    # 验证证书有效性
    if openssl x509 -in "${CERT_DIR}/current.pem" -noout -text >/dev/null 2>&1 && \
       openssl ec -in "${CERT_DIR}/current.key" -noout -text >/dev/null 2>&1; then
        log_success "自签名证书生成完成并验证通过"
        
        # 保存证书模式状态
        echo "self-signed" > "${CONFIG_DIR}/cert_mode"
        
        # 显示证书信息
        local cert_subject cert_not_after
        cert_subject=$(openssl x509 -in "${CERT_DIR}/current.pem" -noout -subject 2>/dev/null | sed 's/subject=//')
        cert_not_after=$(openssl x509 -in "${CERT_DIR}/current.pem" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
        
        log_info "证书详情："
        log_info "├─ 主体: ${cert_subject}"
        log_info "├─ 有效期至: ${cert_not_after}"
        log_info "├─ 证书文件: ${CERT_DIR}/current.pem"
        log_info "└─ 私钥文件: ${CERT_DIR}/current.key"
        
        return 0
    else
        log_error "证书验证失败"
        return 1
    fi
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
    
    # 任务3：生成Reality密钥（可能延迟到模块3）
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
    
    # 任务5：保存配置信息
    if save_config_info; then
        log_success "✓ 配置信息保存完成"
    else
        log_error "✗ 配置信息保存失败"
        return 1
    fi
    
    # 任务6：验证数据完整性
    if verify_module2_data; then
        log_success "✓ 数据完整性验证通过"
    else
        log_warn "数据完整性验证发现问题，但安装将继续"
    fi
	
	# 导出变量供后续模块使用
export UUID_VLESS_REALITY UUID_VLESS_GRPC UUID_VLESS_WS
export UUID_TUIC PASSWORD_HYSTERIA2 PASSWORD_TUIC PASSWORD_TROJAN
export REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY REALITY_SHORT_ID
export SERVER_IP

log_info "已导出所有必要变量供后续模块使用"
    
    log_success "======== 模块2执行完成 ========"
    log_info "已生成："
    log_info "├─ 系统信息（云厂商、硬件规格）"
    log_info "├─ 所有协议的UUID和密码"
    log_info "├─ Reality密钥对"
    log_info "├─ 自签名证书"
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

# 重新生成指定类型的凭据（用于故障恢复）
regenerate_credentials() {
    local cred_type="$1"
    
    case "$cred_type" in
        "uuid")
            log_info "重新生成所有UUID..."
            generate_credentials
            ;;
        "reality")
            log_info "重新生成Reality密钥..."
            generate_reality_keys
            ;;
        "cert")
            log_info "重新生成自签名证书..."
            generate_self_signed_cert
            ;;
        "all")
            log_info "重新生成所有凭据..."
            generate_credentials && generate_reality_keys && generate_self_signed_cert
            ;;
        *)
            log_error "未知的凭据类型: $cred_type"
            log_info "支持的类型: uuid, reality, cert, all"
            return 1
            ;;
    esac
    
    # 重新保存配置
    save_config_info
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
        
        # 询问是否重新安装（在自动安装中默认跳过）
        log_info "跳过Xray重新安装，使用现有版本"
    else
        log_info "从官方仓库下载并安装Xray..."
        
        # 使用官方安装脚本
        if curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash; then
            log_success "Xray安装完成"
        else
            log_error "Xray安装失败"
            return 1
        fi
    fi
    
    # 停用官方的systemd服务（使用自定义配置）
    systemctl disable --now xray >/dev/null 2>&1 || true
    rm -rf /etc/systemd/system/xray.service.d 2>/dev/null || true
    
    # 验证安装
    if command -v xray >/dev/null 2>&1; then
        local xray_version
        xray_version=$(xray version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_success "Xray验证通过，版本: ${xray_version:-未知}"
        
        # 创建日志目录
        mkdir -p /var/log/xray
        chown nobody:nogroup /var/log/xray 2>/dev/null || chown nobody:nobody /var/log/xray 2>/dev/null || true
        
        return 0
    else
        log_error "Xray安装验证失败"
        return 1
    fi
}

#############################################
# sing-box 安装函数
#############################################

# 安装sing-box核心程序
install_sing_box() {
    log_info "安装sing-box核心程序..."
    
    # 检查是否已安装
    if command -v sing-box >/dev/null 2>&1 || command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
        local current_version
        if command -v sing-box >/dev/null 2>&1; then
            current_version=$(sing-box version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        else
            current_version=$(/usr/local/bin/sing-box version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        fi
        log_info "检测到已安装的sing-box版本: ${current_version:-未知}"
        log_info "跳过sing-box重新安装，使用现有版本"
    else
        # 从GitHub下载sing-box
        local version="${SING_BOX_VERSION:-1.12.4}"
        local arch="$(uname -m)"
        local arch_tag=""
        
        # 架构映射
        case "$arch" in
            x86_64|amd64)   arch_tag="amd64" ;;
            aarch64|arm64)  arch_tag="arm64" ;;
            armv7l)         arch_tag="armv7" ;;
            armv6l)         arch_tag="armv6" ;;
            i386|i686)      arch_tag="386" ;;
            *)
                log_error "不支持的CPU架构: $arch"
                return 1
                ;;
        esac
        
        local pkg_name="sing-box-${version}-linux-${arch_tag}.tar.gz"
        local download_url="https://github.com/SagerNet/sing-box/releases/download/v${version}/${pkg_name}"
        local temp_file="/tmp/${pkg_name}"
        
        log_info "下载sing-box v${version} (${arch_tag})..."
        log_debug "下载URL: $download_url"
        
        # 下载文件
        rm -f "$temp_file"
        if ! curl -fL --connect-timeout 15 --retry 3 --retry-delay 2 -o "$temp_file" "$download_url"; then
            log_error "下载失败: $download_url"
            return 1
        fi
        
        # 验证下载文件
        if [[ ! -f "$temp_file" || ! -s "$temp_file" ]]; then
            log_error "下载的文件无效或为空"
            return 1
        fi
        
        log_info "解压并安装sing-box..."
        
        # 创建临时解压目录
        local temp_dir
        temp_dir="$(mktemp -d)"
        
        # 解压文件
        if ! tar -xzf "$temp_file" -C "$temp_dir" 2>/dev/null; then
            log_error "解压sing-box失败"
            rm -rf "$temp_dir" "$temp_file"
            return 1
        fi
        
        # 查找sing-box二进制文件
        local sing_box_binary
        sing_box_binary=$(find "$temp_dir" -name "sing-box" -type f -executable | head -1)
        
        if [[ -z "$sing_box_binary" || ! -f "$sing_box_binary" ]]; then
            log_error "解压后未找到sing-box二进制文件"
            rm -rf "$temp_dir" "$temp_file"
            return 1
        fi
        
        # 安装到系统目录
        if install -m 0755 -o root -g root "$sing_box_binary" /usr/local/bin/sing-box; then
            log_success "sing-box安装到 /usr/local/bin/sing-box"
        else
            log_error "sing-box安装失败"
            rm -rf "$temp_dir" "$temp_file"
            return 1
        fi
        
        # 清理临时文件
        rm -rf "$temp_dir" "$temp_file"
    fi
    
    # 验证安装
    local sing_box_cmd=""
    if command -v sing-box >/dev/null 2>&1; then
        sing_box_cmd="sing-box"
    elif command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
        sing_box_cmd="/usr/local/bin/sing-box"
    fi
    
    if [[ -n "$sing_box_cmd" ]] && $sing_box_cmd version >/dev/null 2>&1; then
        local version_info
        version_info=$($sing_box_cmd version 2>/dev/null | head -1)
        log_success "sing-box验证通过: $version_info"
        
        # 如果模块2中Reality密钥生成失败，在这里重新生成
        if [[ "$REALITY_PUBLIC_KEY" == "temp_public_key_will_be_replaced" ]]; then
            log_info "使用安装完成的sing-box重新生成Reality密钥..."
            if generate_reality_keys; then
                log_success "Reality密钥重新生成完成"
                # 更新server.json
                save_config_info
            else
                log_warn "Reality密钥重新生成失败，将使用临时密钥"
            fi
        fi
        
        return 0
    else
        log_error "sing-box安装验证失败"
        return 1
    fi
}

#############################################
# Nginx 配置函数
#############################################

# 配置Nginx（SNI定向 + ALPN兜底架构）
configure_nginx() {
    log_info "配置Nginx（SNI定向 + ALPN兜底架构）..."
    
    # 备份原始配置
    if [[ -f /etc/nginx/nginx.conf ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%s)
        log_info "已备份原始Nginx配置"
    fi
    
    # 生成新的Nginx配置
    cat > /etc/nginx/nginx.conf << 'NGINX_CONFIG'
# EdgeBox Nginx 配置文件
# 架构：SNI定向 + ALPN兜底 + 单端口复用

user www-data;
worker_processes auto;
pid /run/nginx.pid;

# 加载必要模块
include /etc/nginx/modules-enabled/*.conf;

# 事件处理
events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

# HTTP 服务器配置
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    # 日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
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
        
        # 订阅链接服务
        location = /sub {
            default_type text/plain;
            add_header Cache-Control "no-store, no-cache, must-revalidate";
            add_header Pragma "no-cache";
            root /var/www/html;
            try_files /sub =404;
        }
        
        # 控制面板和数据API
        location ^~ /traffic/ {
            alias /etc/edgebox/traffic/;
            index index.html;
            autoindex off;
            
            # 缓存控制
            add_header Cache-Control "no-store, no-cache, must-revalidate";
            add_header Pragma "no-cache";
            
            # 文件类型
            location ~* \.(html|htm)$ {
                add_header Content-Type "text/html; charset=utf-8";
            }
            location ~* \.(json)$ {
                add_header Content-Type "application/json; charset=utf-8";
            }
            location ~* \.(txt)$ {
                add_header Content-Type "text/plain; charset=utf-8";
            }
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
    # 日志配置
    error_log /var/log/nginx/stream.log warn;
    
    # SNI 映射规则（基于域名分流）
    map $ssl_preread_server_name $backend_pool {
        # Reality 伪装域名
        ~^(www\.cloudflare\.com|www\.apple\.com|www\.microsoft\.com)$ reality;
        
        # Trojan 专用子域
        ~*^trojan\. trojan;
        
        # 内部服务域名（用于gRPC和WebSocket）
        grpc.edgebox.internal grpc;
        ws.edgebox.internal ws;
        
        # 默认后端
        default "";
    }
    
    # ALPN 协议映射（基于应用层协议分流）
    map $ssl_preread_alpn_protocols $backend_alpn {
        ~\bh2\b            grpc;      # HTTP/2 -> gRPC
        ~\bhttp/1\.1\b     websocket; # HTTP/1.1 -> WebSocket
        default            reality;   # 默认 -> Reality
    }
    
    # 后端服务器映射
    map $backend_pool $upstream_server {
        reality   127.0.0.1:11443;  # Reality 内部端口
        trojan    127.0.0.1:10143;  # Trojan 内部端口
        grpc      127.0.0.1:10085;  # gRPC 内部端口
        websocket 127.0.0.1:10086;  # WebSocket 内部端口
        default   "";
    }
    
    # ALPN 后端映射（SNI 未命中时的兜底）
    map $backend_alpn $upstream_alpn {
        grpc      127.0.0.1:10085;  # gRPC
        websocket 127.0.0.1:10086;  # WebSocket
        reality   127.0.0.1:11443;  # Reality
        default   127.0.0.1:11443;  # 默认 Reality
    }
    
    # 最终上游选择（SNI 优先，ALPN 兜底）
    map $upstream_server $final_upstream {
        ""      $upstream_alpn;     # SNI 未命中，使用 ALPN
        default $upstream_server;   # SNI 命中，使用 SNI 结果
    }
    
    # TCP/443 端口监听和分流
    server {
        listen 443 reuseport;                    # 仅监听 TCP，UDP 443 留给 sing-box
        ssl_preread on;                          # 启用 SSL 预读取
        proxy_pass $final_upstream;             # 代理到最终上游
        proxy_timeout 300s;                     # 代理超时
        proxy_connect_timeout 5s;               # 连接超时
        proxy_protocol_timeout 5s;              # 协议超时
        
        # 错误处理
        proxy_responses 1;
        proxy_next_upstream_tries 1;
    }
}
NGINX_CONFIG
    
# 验证Nginx配置
log_info "验证Nginx配置..."
if nginx -t 2>/dev/null; then
    log_success "Nginx配置验证通过"
else
    log_error "Nginx配置验证失败"
    nginx -t  # 显示详细错误信息
    return 1
fi
    
log_success "Nginx配置文件创建完成"
return 0
}

#############################################
# Xray 配置函数
#############################################

# 使用安全的sed替换方法，避免特殊字符问题
escape_for_sed() {
    local input="$1"
    # 转义 & / \ $ ^ * [ ] . 等特殊字符
    echo "$input" | sed 's/[[\.*^$()+?{|\\]/\\&/g'
}

# 配置Xray服务
configure_xray() {
    log_info "配置Xray多协议服务..."
	
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
    
    log_info "生成Xray配置文件..."
    
    # 生成Xray配置
    cat > "${CONFIG_DIR}/xray.json" << 'XRAY_CONFIG'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "vless-reality",
      "listen": "127.0.0.1",
      "port": 11443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "__UUID_VLESS_REALITY__",
            "flow": "xtls-rprx-vision",
            "email": "reality@edgebox.local"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.cloudflare.com:443",
          "xver": 0,
          "serverNames": [
            "www.cloudflare.com",
            "www.microsoft.com",
            "www.apple.com"
          ],
          "privateKey": "__REALITY_PRIVATE_KEY__",
          "shortIds": [
            "__REALITY_SHORT_ID__"
          ]
        }
      }
    },
    {
      "tag": "vless-grpc",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "__UUID_VLESS_GRPC__",
            "email": "grpc@edgebox.local"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2"],
          "certificates": [
            {
              "certificateFile": "__CERT_PEM__",
              "keyFile": "__CERT_KEY__"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "grpc",
          "multiMode": true
        }
      }
    },
    {
      "tag": "vless-websocket",
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "__UUID_VLESS_WS__",
            "email": "websocket@edgebox.local"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [
            {
              "certificateFile": "__CERT_PEM__",
              "keyFile": "__CERT_KEY__"
            }
          ]
        },
        "wsSettings": {
          "path": "/ws"
        }
      }
    },
    {
      "tag": "trojan-tls",
      "listen": "127.0.0.1",
      "port": 10143,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "__PASSWORD_TROJAN__",
            "email": "trojan@edgebox.local"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1", "h2"],
          "certificates": [
            {
              "certificateFile": "__CERT_PEM__",
              "keyFile": "__CERT_KEY__"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }
    ]
  }
}
XRAY_CONFIG
    
# 替换配置文件中的占位符 (修复版)
log_info "应用Xray配置参数..."

# 确保所有必要变量都已设置，如果没有则从server.json重新加载
if [[ -z "$UUID_VLESS_REALITY" || -z "$REALITY_PRIVATE_KEY" ]]; then
    log_warn "检测到变量缺失，从server.json重新加载..."
    if [[ -f "${CONFIG_DIR}/server.json" ]]; then
        UUID_VLESS_REALITY=$(jq -r '.uuid.vless.reality // .uuid.vless' "${CONFIG_DIR}/server.json" 2>/dev/null)
        UUID_VLESS_GRPC=$(jq -r '.uuid.vless.grpc // .uuid.vless' "${CONFIG_DIR}/server.json" 2>/dev/null)
        UUID_VLESS_WS=$(jq -r '.uuid.vless.ws // .uuid.vless' "${CONFIG_DIR}/server.json" 2>/dev/null)
        REALITY_PRIVATE_KEY=$(jq -r '.reality.private_key' "${CONFIG_DIR}/server.json" 2>/dev/null)
        REALITY_SHORT_ID=$(jq -r '.reality.short_id' "${CONFIG_DIR}/server.json" 2>/dev/null)
        PASSWORD_TROJAN=$(jq -r '.password.trojan' "${CONFIG_DIR}/server.json" 2>/dev/null)
        log_info "已重新加载变量"
    fi
fi

# 设置证书路径
CERT_DIR="/etc/edgebox/cert"

# 显示将要替换的变量（调试用）
log_info "配置变量检查:"
log_info "├─ UUID_VLESS_REALITY: ${UUID_VLESS_REALITY:0:8}..."
log_info "├─ REALITY_PRIVATE_KEY: ${REALITY_PRIVATE_KEY:0:8}..."
log_info "├─ REALITY_SHORT_ID: $REALITY_SHORT_ID"
log_info "├─ PASSWORD_TROJAN: ${PASSWORD_TROJAN:0:8}..."
log_info "└─ CERT_DIR: $CERT_DIR"

# 执行替换 (修复特殊字符处理)
log_info "开始替换配置文件占位符..."

# 安全替换各个变量
local safe_uuid_reality=$(escape_for_sed "$UUID_VLESS_REALITY")
local safe_uuid_grpc=$(escape_for_sed "$UUID_VLESS_GRPC")
local safe_uuid_ws=$(escape_for_sed "$UUID_VLESS_WS")
local safe_reality_private=$(escape_for_sed "$REALITY_PRIVATE_KEY")
local safe_reality_short=$(escape_for_sed "$REALITY_SHORT_ID")
local safe_password_trojan=$(escape_for_sed "$PASSWORD_TROJAN")
local safe_cert_pem=$(escape_for_sed "${CERT_DIR}/current.pem")
local safe_cert_key=$(escape_for_sed "${CERT_DIR}/current.key")

# 执行安全的替换操作
sed -i \
    -e "s#__UUID_VLESS_REALITY__#${safe_uuid_reality}#g" \
    -e "s#__UUID_VLESS_GRPC__#${safe_uuid_grpc}#g" \
    -e "s#__UUID_VLESS_WS__#${safe_uuid_ws}#g" \
    -e "s#__REALITY_PRIVATE_KEY__#${safe_reality_private}#g" \
    -e "s#__REALITY_SHORT_ID__#${safe_reality_short}#g" \
    -e "s#__CERT_PEM__#${safe_cert_pem}#g" \
    -e "s#__CERT_KEY__#${safe_cert_key}#g" \
    -e "s#__PASSWORD_TROJAN__#${safe_password_trojan}#g" \
    "${CONFIG_DIR}/xray.json"

log_success "配置文件占位符替换完成"

# 验证替换结果
local unreplaced_vars=$(grep -o "__[A-Z_]*__" "${CONFIG_DIR}/xray.json" || true)
if [[ -n "$unreplaced_vars" ]]; then
    log_error "配置文件中仍存在未替换的变量: $unreplaced_vars"
    return 1
else
    log_success "所有配置变量替换完成"
fi
    
# 验证JSON格式和配置内容
if ! jq '.' "${CONFIG_DIR}/xray.json" >/dev/null 2>&1; then
    log_error "Xray配置JSON格式错误"
    return 1
fi

# 调试：显示实际生成的配置片段
log_info "验证Xray配置文件..."
if ! grep -q "127.0.0.1" "${CONFIG_DIR}/xray.json"; then
    log_error "Xray配置中缺少监听地址"
    return 1
fi

# 检查变量是否正确替换
local unreplaced_vars=$(grep -o "__[A-Z_]*__" "${CONFIG_DIR}/xray.json" || true)
if [[ -n "$unreplaced_vars" ]]; then
    log_error "Xray配置中存在未替换的变量: $unreplaced_vars"
    return 1
fi
 
log_success "Xray配置文件验证通过"
    
    log_info "创建Xray系统服务..."
cat > /etc/systemd/system/xray.service << XRAY_SERVICE
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
Group=${NOBODY_GRP}
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
XRAY_SERVICE
    
    # 重新加载systemd，以便后续服务可以启动
    systemctl daemon-reload
    log_success "Xray服务文件创建完成"
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
    
    log_info "生成sing-box配置文件..."
    
    # 生成sing-box配置
    cat > "${CONFIG_DIR}/sing-box.json" << SINGBOX_CONFIG
{
  "log": {
    "level": "warn",
    "timestamp": true,
    "output": "/var/log/edgebox/sing-box.log"
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "password": "${PASSWORD_HYSTERIA2}"
        }
      ],
      "masquerade": "https://www.bing.com",
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "${CERT_DIR}/current.pem",
        "key_path": "${CERT_DIR}/current.key"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": 2053,
      "users": [
        {
          "uuid": "${UUID_TUIC}",
          "password": "${PASSWORD_TUIC}"
        }
      ],
      "congestion_control": "bbr",
      "auth_timeout": "3s",
      "zero_rtt_handshake": false,
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "${CERT_DIR}/current.pem",
        "key_path": "${CERT_DIR}/current.key"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
"route": {
  "rules": [
    {
      "ip_cidr": [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10"
      ],
      "outbound": "direct"
    }
  ]
}
}
SINGBOX_CONFIG
    
    # 验证JSON格式
    if ! jq '.' "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
        log_error "sing-box配置JSON格式错误"
        return 1
    fi
    
# 创建sing-box systemd服务
log_info "创建sing-box系统服务..."
# ... (cat > /etc/systemd/system/sing-box.service) ...

    # 重新加载systemd
    systemctl daemon-reload
    log_success "sing-box服务文件创建完成"
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
    
    # 生成协议链接
    local subscription_links=""
    
    # 1. VLESS-Reality
    if [[ -n "$uuid_reality" && -n "$reality_public_key" && -n "$reality_short_id" ]]; then
        subscription_links+="vless://${uuid_reality}@${server_ip}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${reality_public_key}&sid=${reality_short_id}&type=tcp#EdgeBox-REALITY\n"
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
        subscription_links+="trojan://${encoded_trojan_password}@${server_ip}:443?security=tls&sni=trojan.edgebox.internal&alpn=http%2F1.1&fp=chrome&allowInsecure=1#EdgeBox-TROJAN\n"
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

# 启动所有服务并验证
start_and_verify_services() {
    log_info "统一启动并验证所有EdgeBox核心服务..."
    
    local services=(xray sing-box nginx) # 启动顺序：后端 -> 前端
    
    # 1. 重新加载daemon并启用所有服务
    systemctl daemon-reload
    for service in "${services[@]}"; do
        systemctl enable "$service" >/dev/null 2>&1
    done

    # 2. 启动所有服务
    local all_started=true
    for service in "${services[@]}"; do
        if systemctl restart "$service"; then
            log_success "✓ $service 服务已发出启动命令"
        else
            log_error "✗ $service 服务启动命令失败"
            systemctl status "$service" --no-pager -l
            all_started=false
        fi
    done
    [[ "$all_started" == "false" ]] && return 1

    log_info "等待服务稳定并开始验证 (最多等待15秒)..."

    # 3. 循环验证，解决竞态条件
    local attempts=0
    local max_attempts=15
    while [[ $attempts -lt $max_attempts ]]; do
        attempts=$((attempts + 1))
        
        # 定义需要检查的所有端口和服务
        local required_ports=(
            "tcp:80:nginx" 
            "tcp:443:nginx" 
            "udp:443:sing-box" 
            "udp:2053:sing-box"
            "tcp:127.0.0.1:11443:xray" # Reality
            "tcp:127.0.0.1:10085:xray" # gRPC
            "tcp:127.0.0.1:10086:xray" # WS
            "tcp:127.0.0.1:10143:xray" # Trojan
        )
        
        local listening_count=0
        local services_active_count=0
        
        # 检查服务状态
        for service in "${services[@]}"; do
            systemctl is-active --quiet "$service" && services_active_count=$((services_active_count + 1))
        done
        
        # 检查端口监听 (使用更精确的 ss 命令)
        for p_info in "${required_ports[@]}"; do
            IFS=':' read -r proto addr port proc <<< "$p_info"
            local cmd=""
            if [[ "$addr" == "127.0.0.1" ]]; then
                cmd="ss -H -tlnp sport = :$port and src = $addr" # 仅限TCP和本地回环地址
            elif [[ "$proto" == "tcp" ]]; then
                cmd="ss -H -tlnp sport = :$port"
            else
                cmd="ss -H -ulnp sport = :$port"
            fi

            if $cmd | grep -q "$proc"; then
                listening_count=$((listening_count + 1))
            fi
        done
        
        # 如果全部成功，则跳出循环
        if [[ $services_active_count -eq ${#services[@]} && $listening_count -eq ${#required_ports[@]} ]]; then
            log_success "所有服务 (${#services[@]}) 和端口 (${#required_ports[@]}) 验证通过！"
            return 0
        fi

        log_info "验证中... (尝试 $attempts/$max_attempts, 服务: $services_active_count/${#services[@]}, 端口: $listening_count/${#required_ports[@]})"
        sleep 1
    done

    # 4. 如果超时，报告详细的失败信息
    log_error "服务启动验证超时！"
    log_info "请检查以下未通过的项目："
    
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            log_error "✗ 服务 $service 状态: $(systemctl is-active "$service")"
            journalctl -u "$service" -n 10 --no-pager
        fi
    done
    
    for p_info in "${required_ports[@]}"; do
        IFS=':' read -r proto addr port proc <<< "$p_info"
        local cmd=""
        if [[ "$addr" == "127.0.0.1" ]]; then
            cmd="ss -H -tlnp sport = :$port and src = $addr"
        elif [[ "$proto" == "tcp" ]]; then
            cmd="ss -H -tlnp sport = :$port"
        else
            cmd="ss -H -ulnp sport = :$port"
        fi
        if ! $cmd | grep -q "$proc"; then
            log_error "✗ 端口 $proto:$addr:$port ($proc) 未监听到"
        fi
    done
    
    return 1
}

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
        if systemctl restart "$service"; then
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

# 获取系统负载信息
get_system_metrics() {
    local cpu_percent=0
    local memory_percent=0
    local disk_percent=0
    
    # CPU使用率计算（两次采样）
    if [[ -r /proc/stat ]]; then
        read _ user1 nice1 system1 idle1 _ < /proc/stat
        sleep 1
        read _ user2 nice2 system2 idle2 _ < /proc/stat
        
        local total1=$((user1 + nice1 + system1 + idle1))
        local total2=$((user2 + nice2 + system2 + idle2))
        local idle_diff=$((idle2 - idle1))
        local total_diff=$((total2 - total1))
        
        if [[ $total_diff -gt 0 ]]; then
            cpu_percent=$(( (total_diff - idle_diff) * 100 / total_diff ))
        fi
    fi
    
    # 内存使用率
    if [[ -r /proc/meminfo ]]; then
        local mem_total mem_available
        mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
        mem_available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
        
        if [[ $mem_total -gt 0 && $mem_available -ge 0 ]]; then
            memory_percent=$(( (mem_total - mem_available) * 100 / mem_total ))
        fi
    fi
    
    # 磁盘使用率（根分区）
    if command -v df >/dev/null 2>&1; then
        local disk_info
        disk_info=$(df / 2>/dev/null | tail -1)
        if [[ -n "$disk_info" ]]; then
            disk_percent=$(echo "$disk_info" | awk '{print $5}' | sed 's/%//')
        fi
    fi
    
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

# 获取证书信息
get_certificate_info() {
    local cert_mode="self-signed"
    local cert_domain=""
    local cert_expires_at=""
    local cert_renewal_type="manual"
    
    # 读取证书模式
    if [[ -f "${CONFIG_DIR}/cert_mode" ]]; then
        cert_mode=$(cat "${CONFIG_DIR}/cert_mode")
    fi
    
    # 如果是Let's Encrypt证书
    if [[ "$cert_mode" =~ ^letsencrypt ]]; then
        cert_domain="${cert_mode#letsencrypt:}"
        cert_renewal_type="auto"
        
        # 获取证书到期时间
        local cert_file="/etc/letsencrypt/live/${cert_domain}/cert.pem"
        if [[ -f "$cert_file" ]] && command -v openssl >/dev/null 2>&1; then
            cert_expires_at=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | \
                            cut -d= -f2 | xargs -I {} date -d "{}" -Is 2>/dev/null || echo "")
        fi
    fi
    
    # 输出证书信息JSON
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

# 获取协议配置状态
get_protocols_status() {
    # 检查端口监听状态
    local tcp443_status="未监听"
    local udp443_status="未监听"
    local udp2053_status="未监听"
    
    if ss -tlnp 2>/dev/null | grep -q ":443.*nginx"; then
        tcp443_status="监听中"
    fi
    
    if ss -ulnp 2>/dev/null | grep -q ":443.*sing-box"; then
        udp443_status="监听中"
    fi
    
    if ss -ulnp 2>/dev/null | grep -q ":2053.*sing-box"; then
        udp2053_status="监听中"
    fi
    
    # 检查Xray内部端口
    local reality_status grpc_status ws_status trojan_status
    reality_status="未监听"
    grpc_status="未监听"
    ws_status="未监听"
    trojan_status="未监听"
    
    if ss -tlnp 2>/dev/null | grep -q ":11443.*xray"; then
        reality_status="监听中"
    fi
    
    if ss -tlnp 2>/dev/null | grep -q ":10085.*xray"; then
        grpc_status="监听中"
    fi
    
    if ss -tlnp 2>/dev/null | grep -q ":10086.*xray"; then
        ws_status="监听中"
    fi
    
    if ss -tlnp 2>/dev/null | grep -q ":10143.*xray"; then
        trojan_status="监听中"
    fi
    
    # 输出协议状态数组
    jq -n \
        --arg tcp443_status "$tcp443_status" \
        --arg udp443_status "$udp443_status" \
        --arg udp2053_status "$udp2053_status" \
        --arg reality_status "$reality_status" \
        --arg grpc_status "$grpc_status" \
        --arg ws_status "$ws_status" \
        --arg trojan_status "$trojan_status" \
        '[
            {
                name: "VLESS-Reality",
                protocol: "tcp",
                port: 11443,
                status: $reality_status,
                description: "VLESS with Reality (伪装真实网站)"
            },
            {
                name: "VLESS-gRPC",
                protocol: "tcp",
                port: 10085,
                status: $grpc_status,
                description: "VLESS over gRPC (HTTP/2传输)"
            },
            {
                name: "VLESS-WebSocket",
                protocol: "tcp",
                port: 10086,
                status: $ws_status,
                description: "VLESS over WebSocket (WS传输)"
            },
            {
                name: "Trojan-TLS",
                protocol: "tcp",
                port: 10143,
                status: $trojan_status,
                description: "Trojan over TLS (伪装HTTPS)"
            },
            {
                name: "Hysteria2",
                protocol: "udp",
                port: 443,
                status: $udp443_status,
                description: "Hysteria2 (高性能UDP协议)"
            },
            {
                name: "TUIC",
                protocol: "udp",
                port: 2053,
                status: $udp2053_status,
                description: "TUIC (现代UDP协议)"
            }
        ]'
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
    
    # 读取白名单
    local whitelist_file="${SHUNT_DIR}/whitelist.txt"
    if [[ -f "$whitelist_file" ]]; then
        whitelist_json=$(awk 'NF' "$whitelist_file" | jq -R -s 'split("\n")|map(select(length>0))' 2>/dev/null || echo '[]')
    fi
    
    # 确保whitelist_json是有效JSON
    if ! echo "$whitelist_json" | jq . >/dev/null 2>&1; then
        whitelist_json='[]'
    fi
    
    # 输出分流状态JSON
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
# 主数据生成函数
#############################################

# 生成完整的dashboard.json
generate_dashboard_data() {
    log_info "开始生成Dashboard数据..."
    
    # 确保目录存在
    mkdir -p "$TRAFFIC_DIR"
    
    # 获取各模块数据
    local timestamp system_info cert_info services_info protocols_info shunt_info subscription_info secrets_info
    
    timestamp=$(date -Is)
    system_info=$(get_system_info)
    cert_info=$(get_certificate_info)
    services_info=$(get_services_status)
    protocols_info=$(get_protocols_status)
    shunt_info=$(get_shunt_status)
    subscription_info=$(get_subscription_info)
    secrets_info=$(get_secrets_info)
    
    # 合并所有数据生成dashboard.json
    jq -n \
        --arg timestamp "$timestamp" \
        --argjson system "$system_info" \
        --argjson cert "$cert_info" \
        --argjson services "$services_info" \
        --argjson protocols "$protocols_info" \
        --argjson shunt "$shunt_info" \
        --argjson subscription "$subscription_info" \
        --argjson secrets "$secrets_info" \
        '{
            updated_at: $timestamp,
            server: ($system + {cert: $cert}),
            services: $services,
            protocols: $protocols,
            shunt: $shunt,
            subscription: $subscription,
            secrets: $secrets
        }' > "${TRAFFIC_DIR}/dashboard.json.tmp"
    
    # 原子替换，避免读取时文件不完整
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
# 定时任务管理
#############################################

# 设置定时任务
setup_cron_jobs() {
    log_info "设置Dashboard定时任务..."
    
    # 移除可能存在的旧定时任务
    (crontab -l 2>/dev/null | grep -vE '/dashboard-backend\.sh\b') | crontab - || true
    
    # 添加新的定时任务（每2分钟执行一次）
    (crontab -l 2>/dev/null; echo "*/2 * * * * bash -lc '${SCRIPTS_DIR}/dashboard-backend.sh --now >/dev/null 2>&1'") | crontab -
    
    log_info "已设置定时任务：每2分钟刷新一次Dashboard数据"
}

#############################################
# 主执行逻辑
#############################################

# 主函数
main() {
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
}

# 执行主函数
main "$@"
DASHBOARD_BACKEND_SCRIPT

    # 设置脚本权限
    chmod +x "${SCRIPTS_DIR}/dashboard-backend.sh"
    
    log_success "Dashboard后端脚本生成完成: ${SCRIPTS_DIR}/dashboard-backend.sh"
    
    return 0
}

#############################################
# 流量监控系统设置
#############################################

# 设置流量采集和监控系统
setup_traffic_monitoring() {
    log_info "设置流量监控系统..."
    
    # 确保目录存在
    mkdir -p "${TRAFFIC_DIR}/logs"
    mkdir -p /var/www/edgebox/status
    
    # 创建软链接供Web访问
    ln -sfn "${TRAFFIC_DIR}" /var/www/html/traffic 2>/dev/null || true
    ln -sfn /var/www/edgebox/status /var/www/html/status 2>/dev/null || true
    
    # 初始化nftables计数器
    setup_nftables_counters
    
    # 生成流量采集脚本
    create_traffic_collector
    
    # 生成预警脚本
    create_traffic_alert_system
    
    # 初始化CSV文件
    initialize_traffic_logs
    
    log_success "流量监控系统设置完成"
}

# 设置nftables计数器
setup_nftables_counters() {
    log_info "配置nftables流量计数器..."
    
    # 检查nftables是否可用
    if ! command -v nft >/dev/null 2>&1; then
        log_warn "nftables未安装，跳过计数器设置"
        return 0
    fi
    
    # 创建nftables规则
    nft -f - << 'NFT_RULES' || true
table inet edgebox {
    counter c_tcp443 {}
    counter c_udp443 {}
    counter c_udp2053 {}
    counter c_resi_out {}

    set resi_addr4 {
        type ipv4_addr
        flags interval
    }

    set resi_addr6 {
        type ipv6_addr
        flags interval
    }

    chain output {
        type filter hook output priority 0; policy accept;
        tcp dport 443 counter name c_tcp443
        udp dport 443 counter name c_udp443
        udp dport 2053 counter name c_udp2053
        ip daddr @resi_addr4 counter name c_resi_out
        ip6 daddr @resi_addr6 counter name c_resi_out
    }
}
NFT_RULES

    log_success "nftables计数器配置完成"
}

# 创建流量采集脚本
create_traffic_collector() {
    log_info "生成流量采集脚本..."
    
    cat > "${SCRIPTS_DIR}/traffic-collector.sh" << 'TRAFFIC_COLLECTOR'
#!/usr/bin/env bash
set -euo pipefail

TRAFFIC_DIR="/etc/edgebox/traffic"
LOG_DIR="${TRAFFIC_DIR}/logs"
STATE_FILE="${TRAFFIC_DIR}/.state"

# 确保目录存在
mkdir -p "$LOG_DIR"

# 识别主要网卡
get_main_interface() {
    ip route | awk '/default/ {print $5; exit}' || \
    ip -o -4 addr show scope global | awk '{print $2; exit}' || \
    echo "eth0"
}

# 获取当前流量统计
get_current_stats() {
    local interface="$1"
    local tx_bytes rx_bytes
    
    if [[ -f "/sys/class/net/$interface/statistics/tx_bytes" ]]; then
        tx_bytes=$(cat "/sys/class/net/$interface/statistics/tx_bytes")
        rx_bytes=$(cat "/sys/class/net/$interface/statistics/rx_bytes")
    else
        tx_bytes=0
        rx_bytes=0
    fi
    
    echo "$tx_bytes $rx_bytes"
}

# 获取住宅代理流量（从nftables计数器）
get_residential_traffic() {
    if ! command -v nft >/dev/null 2>&1; then
        echo "0"
        return
    fi
    
    local resi_bytes
    resi_bytes=$(nft list counter inet edgebox c_resi_out 2>/dev/null | \
                awk '/bytes/ {print $2; exit}' || echo "0")
    echo "${resi_bytes:-0}"
}

# 主执行函数
main() {
    local interface today
    interface=$(get_main_interface)
    today=$(date +%Y-%m-%d)
    
    # 获取当前统计
    read current_tx current_rx < <(get_current_stats "$interface")
    local current_resi
    current_resi=$(get_residential_traffic)
    
    # 读取上次状态
    local prev_tx=0 prev_rx=0 prev_resi=0
    if [[ -f "$STATE_FILE" ]]; then
        source "$STATE_FILE"
    fi
    
    # 计算增量
    local delta_tx delta_rx delta_resi delta_vps
    
    if [[ $current_tx -ge $prev_tx ]]; then
        delta_tx=$((current_tx - prev_tx))
    else
        delta_tx=0  # 处理计数器重置情况
    fi
    
    if [[ $current_rx -ge $prev_rx ]]; then
        delta_rx=$((current_rx - prev_rx))
    else
        delta_rx=0
    fi
    
    if [[ $current_resi -ge $prev_resi ]]; then
        delta_resi=$((current_resi - prev_resi))
    else
        delta_resi=0
    fi
    
    # VPS出站 = 总出站 - 住宅出站
    delta_vps=$delta_tx
    if [[ $delta_resi -le $delta_tx ]]; then
        delta_vps=$((delta_tx - delta_resi))
    fi
    
    # 更新日志文件
    update_daily_log "$today" "$delta_vps" "$delta_resi" "$delta_tx" "$delta_rx"
    
    # 生成月度统计
    generate_monthly_stats
    
    # 生成traffic.json
    generate_traffic_json
    
    # 保存当前状态
    cat > "$STATE_FILE" << EOF
prev_tx=$current_tx
prev_rx=$current_rx
prev_resi=$current_resi
EOF
}

# 更新日志文件
update_daily_log() {
    local date="$1" vps="$2" resi="$3" tx="$4" rx="$5"
    local daily_csv="${LOG_DIR}/daily.csv"
    
    # 确保CSV头存在
    if [[ ! -f "$daily_csv" ]]; then
        echo "date,vps,resi,tx,rx" > "$daily_csv"
    fi
    
    # 更新或添加今日数据
    local temp_file
    temp_file=$(mktemp)
    
    awk -F',' -v d="$date" -v v="$vps" -v r="$resi" -v t="$tx" -v x="$rx" '
        BEGIN { OFS=","; updated=0 }
        NR==1 { print; next }
        $1==d { $2+= v; $3+= r; $4+= t; $5+= x; updated=1 }
        { print }
        END { if (!updated) print d,v,r,t,x }
    ' "$daily_csv" > "$temp_file"
    
    mv "$temp_file" "$daily_csv"
    
    # 保留最近90天数据
    if [[ $(wc -l < "$daily_csv") -gt 91 ]]; then
        local header_and_recent
        header_and_recent=$(mktemp)
        head -n1 "$daily_csv" > "$header_and_recent"
        tail -n90 "$daily_csv" | grep -v '^date,' >> "$header_and_recent"
        mv "$header_and_recent" "$daily_csv"
    fi
}

# 生成月度统计
generate_monthly_stats() {
    local daily_csv="${LOG_DIR}/daily.csv"
    local monthly_csv="${LOG_DIR}/monthly.csv"
    
    if [[ ! -f "$daily_csv" ]]; then
        return
    fi
    
    # 生成月度统计
    awk -F',' '
        NR > 1 {
            month = substr($1, 1, 7)
            vps[month] += $2
            resi[month] += $3
            tx[month] += $4
            rx[month] += $5
        }
        END {
            print "month,vps,resi,total,tx,rx"
            for (m in vps) {
                total = vps[m] + resi[m]
                print m "," vps[m] "," resi[m] "," total "," tx[m] "," rx[m]
            }
        }
    ' "$daily_csv" | sort -t',' -k1,1 > "$monthly_csv"
}

# 生成traffic.json
generate_traffic_json() {
    local daily_csv="${LOG_DIR}/daily.csv"
    local monthly_csv="${LOG_DIR}/monthly.csv"
    local traffic_json="${TRAFFIC_DIR}/traffic.json"
    
    # 读取最近30天数据
    local last30d_json="[]"
    if [[ -f "$daily_csv" ]]; then
        last30d_json=$(tail -n30 "$daily_csv" | grep -v '^date,' | \
            awk -F',' '{printf("{\"date\":\"%s\",\"vps\":%s,\"resi\":%s,\"tx\":%s,\"rx\":%s}\n", $1,$2,$3,$4,$5)}' | \
            jq -s '.')
    fi
    
    # 读取月度数据
    local monthly_json="[]"
    if [[ -f "$monthly_csv" ]]; then
        monthly_json=$(tail -n12 "$monthly_csv" | grep -v '^month,' | \
            awk -F',' '{printf("{\"month\":\"%s\",\"vps\":%s,\"resi\":%s,\"total\":%s,\"tx\":%s,\"rx\":%s}\n", $1,$2,$3,$4,$5,$6)}' | \
            jq -s '.')
    fi
    
    # 生成完整的traffic.json
    jq -n \
        --arg updated_at "$(date -Is)" \
        --argjson last30d "$last30d_json" \
        --argjson monthly "$monthly_json" \
        '{
            updated_at: $updated_at,
            last30d: $last30d,
            monthly: $monthly
        }' > "$traffic_json"
}

# 执行主函数
main "$@"
TRAFFIC_COLLECTOR

    chmod +x "${SCRIPTS_DIR}/traffic-collector.sh"
    log_success "流量采集脚本生成完成"
}

# 创建流量预警系统
create_traffic_alert_system() {
    log_info "生成流量预警系统..."
    
    # 创建预警配置文件
    cat > "${TRAFFIC_DIR}/alert.conf" << 'ALERT_CONFIG'
# EdgeBox 流量预警配置
# 月度预算（GiB）
ALERT_MONTHLY_GIB=100

# Telegram Bot配置
ALERT_TG_BOT_TOKEN=
ALERT_TG_CHAT_ID=

# Discord Webhook
ALERT_DISCORD_WEBHOOK=

# 微信推送（PushPlus）
ALERT_PUSHPLUS_TOKEN=

# 通用Webhook
ALERT_WEBHOOK=
ALERT_WEBHOOK_FORMAT=raw

# 预警阈值（百分比，逗号分隔）
ALERT_STEPS=30,60,90
ALERT_CONFIG

    # 创建预警脚本
    cat > "${SCRIPTS_DIR}/traffic-alert.sh" << 'TRAFFIC_ALERT'
#!/usr/bin/env bash
set -euo pipefail

TRAFFIC_DIR="/etc/edgebox/traffic"
LOG_DIR="${TRAFFIC_DIR}/logs"
CONF_FILE="${TRAFFIC_DIR}/alert.conf"
STATE_FILE="${TRAFFIC_DIR}/alert.state"
LOG_FILE="/var/log/edgebox-traffic-alert.log"

# 读取配置
if [[ ! -f "$CONF_FILE" ]]; then
    echo "配置文件不存在: $CONF_FILE"
    exit 1
fi

source "$CONF_FILE"

# 获取当前月份和用量
current_month=$(date +%Y-%m)
monthly_csv="${LOG_DIR}/monthly.csv"

if [[ ! -f "$monthly_csv" ]]; then
    echo "月度统计文件不存在: $monthly_csv"
    exit 0
fi

# 读取当前月份数据
month_data=$(grep "^${current_month}," "$monthly_csv" 2>/dev/null || echo "")

if [[ -z "$month_data" ]]; then
    echo "当前月份无数据: $current_month"
    exit 0
fi

# 解析数据（格式：month,vps,resi,total,tx,rx）
IFS=',' read -r _ vps_bytes resi_bytes total_bytes tx_bytes rx_bytes <<< "$month_data"

# 计算预算和使用率
budget_bytes=$(( ${ALERT_MONTHLY_GIB:-100} * 1024 * 1024 * 1024 ))
used_bytes=$total_bytes
usage_percent=$(( used_bytes * 100 / budget_bytes ))

# 读取已发送的预警
sent_alerts=""
if [[ -f "$STATE_FILE" ]]; then
    sent_alerts=$(cat "$STATE_FILE")
fi

# 发送通知函数
send_notification() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 记录日志
    echo "[$timestamp] $message" >> "$LOG_FILE"
    
    # Telegram通知
    if [[ -n "${ALERT_TG_BOT_TOKEN:-}" && -n "${ALERT_TG_CHAT_ID:-}" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${ALERT_TG_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${ALERT_TG_CHAT_ID}" \
            -d "text=EdgeBox流量预警: $message" >/dev/null 2>&1 || true
    fi
    
    # Discord通知
    if [[ -n "${ALERT_DISCORD_WEBHOOK:-}" ]]; then
        local payload
        payload=$(jq -n --arg content "EdgeBox流量预警: $message" '{content: $content}')
        curl -s -X POST "${ALERT_DISCORD_WEBHOOK}" \
            -H "Content-Type: application/json" \
            -d "$payload" >/dev/null 2>&1 || true
    fi
    
    # 微信PushPlus通知
    if [[ -n "${ALERT_PUSHPLUS_TOKEN:-}" ]]; then
        curl -s -X POST "http://www.pushplus.plus/send" \
            -H "Content-Type: application/json" \
            -d "{\"token\":\"${ALERT_PUSHPLUS_TOKEN}\",\"title\":\"EdgeBox流量预警\",\"content\":\"$message\"}" >/dev/null 2>&1 || true
    fi
    
    # 通用Webhook通知
    if [[ -n "${ALERT_WEBHOOK:-}" ]]; then
        local webhook_payload
        case "${ALERT_WEBHOOK_FORMAT:-raw}" in
            "slack")
                webhook_payload=$(jq -n --arg text "EdgeBox流量预警: $message" '{text: $text}')
                ;;
            "discord")
                webhook_payload=$(jq -n --arg content "EdgeBox流量预警: $message" '{content: $content}')
                ;;
            *)
                webhook_payload=$(jq -n --arg message "$message" '{message: $message}')
                ;;
        esac
        
        curl -s -X POST "${ALERT_WEBHOOK}" \
            -H "Content-Type: application/json" \
            -d "$webhook_payload" >/dev/null 2>&1 || true
    fi
}

# 检查预警阈值
IFS=',' read -ra alert_steps <<< "${ALERT_STEPS:-30,60,90}"
new_sent_alerts="$sent_alerts"

for step in "${alert_steps[@]}"; do
    step=$(echo "$step" | tr -d ' ')  # 去除空格
    
    # 检查是否达到阈值且未发送过
    if [[ $usage_percent -ge $step ]] && [[ "$sent_alerts" != *"$step"* ]]; then
        local used_gib rx_gib
        used_gib=$(echo "scale=2; $used_bytes / 1024 / 1024 / 1024" | bc)
        rx_gib=$(echo "scale=2; $rx_bytes / 1024 / 1024 / 1024" | bc)
        
        local alert_message
        alert_message="本月流量已达 ${usage_percent}%（${used_gib}GB/${ALERT_MONTHLY_GIB}GB），触发 ${step}% 预警阈值。下载流量：${rx_gib}GB"
        
        send_notification "$alert_message"
        
        # 更新已发送状态
        if [[ -z "$new_sent_alerts" ]]; then
            new_sent_alerts="$step"
        else
            new_sent_alerts="${new_sent_alerts},$step"
        fi
    fi
done

# 保存已发送状态
echo "$new_sent_alerts" > "$STATE_FILE"
TRAFFIC_ALERT

    chmod +x "${SCRIPTS_DIR}/traffic-alert.sh"
    log_success "流量预警系统生成完成"
}

# 初始化流量日志文件
initialize_traffic_logs() {
    log_info "初始化流量日志文件..."
    
    local log_dir="${TRAFFIC_DIR}/logs"
    mkdir -p "$log_dir"
    
    # 初始化daily.csv
    if [[ ! -f "${log_dir}/daily.csv" ]]; then
        echo "date,vps,resi,tx,rx" > "${log_dir}/daily.csv"
    fi
    
    # 初始化monthly.csv
    if [[ ! -f "${log_dir}/monthly.csv" ]]; then
        echo "month,vps,resi,total,tx,rx" > "${log_dir}/monthly.csv"
    fi
    
    # 设置权限
    chmod 644 "${log_dir}"/*.csv
    
    log_success "流量日志文件初始化完成"
}

#############################################
# 定时任务设置
#############################################

# 设置所有定时任务
setup_cron_jobs() {
    log_info "设置定时任务..."
    
    # 移除可能存在的旧任务
    (crontab -l 2>/dev/null | grep -vE '/edgebox/scripts/(dashboard-backend|traffic-collector|traffic-alert)\.sh') | crontab - || true

    # 添加新的定时任务
    (crontab -l 2>/dev/null; cat << 'CRON_JOBS'
# EdgeBox 定时任务
*/2 * * * * bash -lc '/etc/edgebox/scripts/dashboard-backend.sh --now >/dev/null 2>&1'
0 * * * * bash -lc '/etc/edgebox/scripts/traffic-collector.sh >/dev/null 2>&1'
7 * * * * bash -lc '/etc/edgebox/scripts/traffic-alert.sh >/dev/null 2>&1'
CRON_JOBS
    ) | crontab -
    
    log_success "定时任务设置完成："
    log_info "├─ Dashboard数据刷新: 每2分钟"
    log_info "├─ 流量数据采集: 每小时"
    log_info "└─ 流量预警检查: 每小时"
}

#############################################
# 模块4主执行函数
#############################################

# 执行模块4的所有任务
execute_module4() {
    log_info "======== 开始执行模块4：Dashboard后端脚本生成 ========"
    
    # 任务1：生成Dashboard后端脚本
    if create_dashboard_backend; then
        log_success "✓ Dashboard后端脚本生成完成"
    else
        log_error "✗ Dashboard后端脚本生成失败"
        return 1
    fi
    
    # 任务2：设置流量监控系统
    if setup_traffic_monitoring; then
        log_success "✓ 流量监控系统设置完成"
    else
        log_error "✗ 流量监控系统设置失败"
        return 1
    fi
    
    # 任务3：设置定时任务
    if setup_cron_jobs; then
        log_success "✓ 定时任务设置完成"
    else
        log_error "✗ 定时任务设置失败"
        return 1
    fi
    
    # 任务4：首次执行数据生成
    log_info "首次执行数据生成..."
    if "${SCRIPTS_DIR}/dashboard-backend.sh" --now; then
        log_success "✓ 首次数据生成完成"
    else
        log_warn "首次数据生成失败，但定时任务将重试"
    fi
    
    # 任务5：初始化流量采集
    if "${SCRIPTS_DIR}/traffic-collector.sh"; then
        log_success "✓ 流量采集初始化完成"
    else
        log_warn "流量采集初始化失败，但定时任务将重试"
    fi
    
    log_success "======== 模块4执行完成 ========"
    log_info "已完成："
    log_info "├─ Dashboard后端数据采集脚本"
    log_info "├─ 流量监控和预警系统"
    log_info "├─ nftables计数器配置"
    log_info "├─ 定时任务设置"
    log_info "└─ 初始数据生成"
    
    return 0
}

#############################################
# 模块4导出函数（供其他模块调用）
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
    today_data=$(jq -r --arg today "$(date +%Y-%m-%d)" '.last30d[] | select(.date == $today) | "今日: VPS \(.vps)B, 住宅 \(.resi)B, 总计 \(.vps + .resi)B"' "$traffic_json" 2>/dev/null || echo "今日暂无数据")
    echo "  $today_data"
    
    # 显示本月流量
    local month_data
    month_data=$(jq -r --arg month "$(date +%Y-%m)" '.monthly[] | select(.month == $month) | "本月: VPS \(.vps)B, 住宅 \(.resi)B, 总计 \(.total)B"' "$traffic_json" 2>/dev/null || echo "本月暂无数据")
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

read _ a b c idle rest < /proc/stat
t1=$((a+b+c+idle)); i1=$idle
sleep 1
read _ a b c idle rest < /proc/stat
t2=$((a+b+c+idle)); i2=$idle
dt=$((t2-t1)); di=$((i2-i1))
cpu=$(( dt>0 ? (100*(dt-di) + dt/2) / dt : 0 ))

mt=$(awk '/MemTotal/{print $2}' /proc/meminfo)
ma=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
mem=$(( mt>0 ? (100*(mt-ma) + mt/2) / mt : 0 ))

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

# 住宅出口计数（nftables 计数器 c_resi_out）
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

# 7) 保存状态
printf 'PREV_TX=%s\nPREV_RX=%s\nPREV_RESI=%s\n' "$TX_CUR" "$RX_CUR" "$RESI_CUR" > "$STATE"
COLLECTOR
chmod +x "${SCRIPTS_DIR}/traffic-collector.sh"

# 3. 预警配置（默认）
cat > "${TRAFFIC_DIR}/alert.conf" <<'CONF'
# 月度预算（GiB）
ALERT_MONTHLY_GIB=100
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

# 模块7 控制面板HTML
cat > "$TRAFFIC_DIR/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EdgeBox 控制面板</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
<style>
        :root {
            --card: #fff;
            --border: #e2e8f0;
            --bg: #f8fafc;
            --muted: #64748b;
            --shadow: 0 4px 6px -1px rgba(0,0,0,.1);
            --primary: #3b82f6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
        }

        * { box-sizing: border-box; }
        
        body {
            font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
            background: var(--bg);
            color: #334155;
            margin: 0;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .grid {
            display: grid;
            gap: 16px;
            margin-bottom: 16px;
        }

        .grid-full { grid-template-columns: 1fr; }
        .grid-4-8 { 
            grid-template-columns: 1fr 2fr;
        }
        
        @media(max-width:980px) {
            .grid-4-8 { grid-template-columns: 1fr; }
        }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: var(--shadow);
            overflow: hidden;
            position: relative;
        }

        .card h3 {
            margin: 0;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 1.5rem;
            font-weight: 700;
            color: #0f172a;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .info-block h4,
        .command-section h4,
        .chart-title {
            margin: 0 0 8px 0;
            font-size: 1.125rem;
            font-weight: 600;
            color: #1e293b;
        }

        .chart-title {
            text-align: center;
            margin: 0 0 10px 0;
        }

        .chart-title .unit {
            font-size: .875rem;
            font-weight: 400;
            color: #64748b;
        }

        .card .content { padding: 16px; }

        .table th {
            font-size: 1rem;
            font-weight: 600;
            color: #374151;
        }

        .table {
            width: 100%;
            border-collapse: collapse;
        }

        .table th {
            text-align: left;
            padding: 12px 8px;
            border-bottom: 1px solid var(--border);
        }

        .table th:last-child {
            text-align: center;
        }

        .table td {
            font-size: .875rem;
            font-weight: 400;
            color: #64748b;
            padding: 12px 8px;
            border-bottom: 1px solid #e2e8f0;
        }

        .table td:last-child {
            text-align: center;
        }

        .system-progress-bar {
            display: inline-flex;
            align-items: center;
            width: 80px;
            height: 20px;
            background: #e2e8f0;
            border-radius: 10px;
            overflow: hidden;
            margin-left: 8px;
            position: relative;
        }

        .system-progress-fill {
            height: 100%;
            background: #10b981;
            border-radius: 10px;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            min-width: 20px;
        }

        .system-progress-text {
            position: absolute;
            left: 50%;
            top: 50%;
            transform: translate(-50%, -50%);
            color: white;
            font-size: .75rem;
            font-weight: 600;
            text-shadow: 0 1px 2px rgba(0,0,0,0.3);
            z-index: 1;
        }

        .progress-bar {
            width: 100%;
            height: 20px;
            background: #e2e8f0;
            border-radius: 8px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: #10b981;
            border-radius: 8px;
            transition: width 0.3s;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .progress-percentage {
            position: absolute;
            color: white;
            font-size: .75rem;
            font-weight: 600;
            text-shadow: 0 1px 2px rgba(0,0,0,0.3);
        }

        .protocol-status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: .75rem;
            font-weight: 600;
            background: #10b981;
            color: white;
            border: none;
        }

        .service-status-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 10px;
            font-size: .75rem;
            font-weight: 600;
            background: #10b981;
            color: white;
            border: none;
        }

        .service-status-badge.inactive {
            background: #6b7280;
        }

        .status-badge {
            padding: 4px 10px;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            background: #e2e8f0;
            color: #64748b;
            white-space: nowrap;
            font-size: 1rem;
            font-weight: 600;
            height: 28px;
            display: inline-flex;
            align-items: center;
            line-height: 1;
        }

        .status-badge.active {
            background: #10b981;
            color: white;
            border-color: #10b981;
        }

        .small,
        .info-block .value,
        .btn,
        .badge,
        .notification-bell,
        .notification-item,
        .sub-label,
        .sub-input,
        .sub-copy-btn,
        .command-list,
        .config-note {
            font-size: .875rem;
            font-weight: 400;
            color: #64748b;
        }

        .detail-link {
            color: var(--primary);
            cursor: pointer;
            text-decoration: underline;
            font-size: .875rem;
            font-weight: 400;
        }

        .detail-link:hover { color: #2563eb; }

        .status-running {
            color: #10b981 !important;
            font-size: .875rem;
            font-weight: 600 !important;
        }

        .btn {
            padding: 8px 16px;
            border: 1px solid var(--border);
            background: #f1f5f9;
            border-radius: 6px;
            cursor: pointer;
            white-space: nowrap;
        }

        .btn:hover { background: #e2e8f0; }

        .info-blocks {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }

        .info-block {
            padding: 12px;
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 8px;
        }

        .info-block .value {
            margin-bottom: 2px;
        }

        .notification-bell {
            position: relative;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 4px 8px;
            border-radius: 6px;
            background: #f1f5f9;
        }

        .notification-bell:hover { background: #e2e8f0; }
        .notification-bell.has-alerts { color: var(--warning); background: #fef3c7; }

        .notification-popup {
            position: absolute;
            top: 100%;
            right: 0;
            background: white;
            border: 1px solid var(--border);
            border-radius: 8px;
            box-shadow: var(--shadow);
            width: 300px;
            max-height: 200px;
            overflow-y: auto;
            z-index: 100;
            display: none;
        }

        .notification-popup.show { display: block; }

        .notification-item {
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
        }

        .notification-item:last-child { border-bottom: none; }

        .cert-status {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }

        .network-status {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }

        .network-blocks {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 12px;
            margin-top: 12px;
        }
        
        @media(max-width:980px) {
            .network-blocks { grid-template-columns: 1fr; }
        }
        
        .network-block {
            padding: 12px;
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 8px;
        }
        
        .network-block h5 {
            margin: 0 0 8px 0;
            font-size: 1rem;
            font-weight: 600;
            color: #1e293b;
        }

        .network-note {
            margin-top: 16px;
            padding: 8px;
            border-top: 1px solid var(--border);
            background: linear-gradient(180deg, rgba(248,250,252,0.6), rgba(248,250,252,1));
            border-radius: 4px;
            font-size: .75rem;
            line-height: 1.4;
            color: #64748b;
        }

        .sub-row {
            display: flex;
            gap: 8px;
            align-items: stretch;
            margin-bottom: 8px;
            height: 32px;
        }

        .sub-input {
            flex: 1;
            height: 100%;
            padding: 6px 10px;
            box-sizing: border-box;
            border: 1px solid var(--border);
            border-radius: 4px;
            font-family: monospace;
            background: #fff;
            font-size: .875rem;
            line-height: 20px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            resize: none;
            display: inline-block;
            vertical-align: middle;
            color: #64748b;
        }

        .sub-copy-btn {
            min-width: 80px;
            padding: 6px 12px;
            border: 1px solid var(--border);
            background: #f1f5f9;
            border-radius: 4px;
            cursor: pointer;
            font-size: .875rem;
            color: #64748b;
            font-weight: 400;
            height: 100%;
            box-sizing: border-box;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }

        .sub-copy-btn:hover { 
            background: #e2e8f0; 
        }

        .traffic-card { position: relative; }

        .traffic-progress-container {
            position: absolute;
            top: 16px;
            right: 16px;
            width: 390px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .progress-wrapper {
            flex: 1;
            position: relative;
        }

        .progress-budget {
            white-space: nowrap;
            font-size: .75rem;
        }

        .progress-label {
            white-space: nowrap;
            font-size: 1rem;
            font-weight: 600;
            color: #374151;
        }

        .traffic-charts {
            display: grid;
            grid-template-columns: 1fr 400px;
            gap: 16px;
            margin-top: 50px;
        }

        @media(max-width:980px) {
            .traffic-charts { 
                grid-template-columns: 1fr; 
                margin-top: 20px;
            }
            .traffic-progress-container {
                position: static;
                width: 100%;
                margin-bottom: 16px;
            }
        }

        .chart-container {
            position: relative;
            height: 360px;
            width: 100%;
        }

        @media(max-width:768px) {
            .chart-container {
                height: 280px;
            }
        }

        .commands-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        @media(max-width:768px) {
            .commands-grid { grid-template-columns: 1fr; }
        }

        .command-section {
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
        }

        .command-section h4 {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .command-list {
            line-height: 1.6;
        }

        .command-list code {
            background: #e2e8f0;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: .75rem;
            color: #1e293b;
        }

        .command-list span {
            color: var(--muted);
            margin-left: 8px;
        }

        .command-list small {
            display: block;
            margin-top: 2px;
            color: var(--muted);
            font-style: normal;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }

        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: white;
            border-radius: 12px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1);
        }

        .modal-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h3 {
            margin: 0;
            font-size: 1.1rem;
            font-weight: 600;
            color: #374151;
        }

        .modal-close {
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--muted);
            line-height: 1;
        }

        .modal-close:hover { color: #1e293b; }

        .modal-body { padding: 20px; }

        .config-item {
            margin-bottom: 16px;
            padding: 12px;
            background: #f8fafc;
            border-radius: 8px;
        }

        .config-item h4 {
            margin: 0 0 8px 0;
            font-size: 1rem;
            font-weight: 600;
            color: #374151;
        }

        .config-item code {
            display: block;
            background: #1e293b;
            color: #10b981;
            padding: 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: .875rem;
            word-break: break-all;
            margin: 4px 0;
        }

        .config-note {
            color: var(--warning);
            margin-top: 4px;
        }

        .whitelist-content {
            max-height: 3em;
            overflow: hidden;
            position: relative;
        }

        .whitelist-content.expanded {
            max-height: none;
        }

        .whitelist-content::after {
            content: "";
            position: absolute;
            left: 0; right: 0; bottom: 0;
            height: 24px;
            background: linear-gradient(180deg, rgba(255,255,255,0), rgba(255,255,255,1));
        }

        .whitelist-content.expanded::after {
            display: none;
        }
    </style>
</head>
<body>
<div class="container">

  <!-- 第一行：概览信息 -->
  <div class="grid grid-full">
    <div class="card">
      <h3 class="main-title">
        🌐EdgeBox-企业级多协议节点 (Control Panel)
        <div class="notification-bell" id="notif-bell" onclick="toggleNotifications()">
          🔔 <span id="notif-count">0</span>
          <div class="notification-popup" id="notif-popup">
            <div id="notif-list">暂无通知</div>
          </div>
        </div>
      </h3>
      <div class="content">
        <div class="info-blocks">
          <div class="info-block">
            <h4>📊 服务器信息</h4>
            <div class="value">用户备注名: <span id="user-alias">—</span></div>
            <div class="value">云厂商/区域: <span id="cloud-provider">—</span></div>
            <div class="value">Instance ID: <span id="instance-id">—</span></div>
            <div class="value">主机名: <span id="hostname">—</span></div>
          </div>
          
          <div class="info-block">
            <h4>⚙️ 服务器配置</h4>
            <div class="value">
              CPU: 
              <span class="system-progress-bar">
                <div class="system-progress-fill" id="cpu-progress-fill" style="width: 0%"></div>
                <span class="system-progress-text" id="cpu-progress-text">0%</span>
              </span>
              <span class="small" id="cpu-detail">—</span>
            </div>
            <div class="value">
              内存: 
              <span class="system-progress-bar">
                <div class="system-progress-fill" id="mem-progress-fill" style="width: 0%"></div>
                <span class="system-progress-text" id="mem-progress-text">0%</span>
              </span>
              <span class="small" id="mem-detail">—</span>
            </div>
            <div class="value">
              磁盘: 
              <span class="system-progress-bar">
                <div class="system-progress-fill" id="disk-progress-fill" style="width: 0%"></div>
                <span class="system-progress-text" id="disk-progress-text">0%</span>
              </span>
              <span class="small" id="disk-detail">—</span>
            </div>
          </div>
          
          <div class="info-block">
            <h4>🔧 核心服务</h4>
            <div class="value">Nginx: <span id="nginx-status">—</span> <span class="small" id="nginx-version">—</span></div>
            <div class="value">Xray: <span id="xray-status">—</span> <span class="small" id="xray-version">—</span></div>
            <div class="value">Sing-box: <span id="singbox-status">—</span> <span class="small" id="singbox-version">—</span></div>
          </div>
        </div>
        <div class="small">版本号: <span id="ver">—</span> | 安装日期: <span id="inst">—</span> | 更新时间: <span id="updated">—</span></div>
      </div>
    </div>
  </div>

  <!-- 第二行：证书切换 + 网络身份配置 -->
  <div class="grid grid-4-8">
    <!-- 证书切换 -->
    <div class="card">
      <h3>🔐 证书切换</h3>
      <div class="content">
<div class="cert-status">
  <span class="status-badge active" id="cert-status-self">自签证书</span>
  <span class="status-badge" id="cert-status-ca">CA证书</span>
</div>
        <div>
          <div class="small">证书类型: <span id="cert-type">—</span></div>
          <div class="small">绑定域名: <span id="cert-domain">—</span></div>
          <div class="small">续期方式: <span id="cert-renewal">—</span></div>
          <div class="small">到期日期: <span id="cert-expire">—</span></div>
        </div>
      </div>
    </div>

    <!-- 网络身份配置 -->
    <div class="card">
      <h3>🌐 网络身份配置</h3>
      <div class="content">
<div class="network-status">
  <span class="status-badge active">VPS出站IP</span>
  <span class="status-badge">代理出站IP</span>
  <span class="status-badge">分流出站</span>
</div>
        
        <!-- 三个区块并排显示 -->
        <div class="network-blocks">
          <!-- VPS出站IP内容 -->
          <div class="network-block">
            <h5>📡 VPS出站IP</h5>
            <div class="small">公网身份: <span class="status-running">直连</span></div>
            <div class="small">VPS出站IP: <span id="vps-out-ip">—</span></div>
            <div class="small">Geo: <span id="vps-geo">—</span></div>
            <div class="small">IP质量检测: <span id="vps-quality">—</span> <span class="detail-link" onclick="showIPQDetails('vps')">详情</span></div>
          </div>
          
          <!-- 代理出站IP内容 -->
          <div class="network-block">
            <h5>🔄 代理出站IP</h5>
            <div class="small">代理身份: <span class="status-running">全代理</span></div>
            <div class="small">代理出站IP: <span id="proxy-out-ip">—</span></div>
            <div class="small">Geo: <span id="proxy-geo">—</span></div>
            <div class="small">IP质量检测: <span id="proxy-quality">—</span> <span class="detail-link" onclick="showIPQDetails('proxy')">详情</span></div>
          </div>
          
          <!-- 分流出站内容 -->
          <div class="network-block">
            <h5>🔀 分流出站</h5>
            <div class="small">混合身份: <span class="status-running">VPS直连 + 代理</span></div>
            <div class="small">白名单: 
              <div class="whitelist-content" id="whitelist-content">
                <span id="whitelist-text">—</span>
              </div>
              <span class="detail-link" id="whitelist-toggle" onclick="toggleWhitelist()">查看全部</span>
            </div>
          </div>
        </div>
        
        <div class="network-note">
          注：HY2/TUIC 为 UDP通道，VPS直连，不走代理分流
        </div>
      </div>
    </div>
  </div>

  <!-- 第三行：协议配置 -->
  <div class="grid grid-full">
    <div class="card">
      <h3>📡 协议配置</h3>
      <div class="content">
        <table class="table" id="proto">
          <thead><tr><th>协议名称</th><th>网络</th><th>伪装效果</th><th>适用场景</th><th>运行状态</th><th>客户端配置</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- 订阅链接 -->
  <div class="grid grid-full">
    <div class="card">
      <h3>📋 订阅链接</h3>
      <div class="content">
        <div class="sub-row">
          <div class="sub-label">明文链接:</div>
          <textarea id="sub-plain" class="sub-input" readonly></textarea>
          <button class="sub-copy-btn" onclick="copySub('plain')">复制</button>
        </div>
		
		<div class="sub-row">
          <div class="sub-label">B64换行:</div>
          <textarea id="sub-b64lines" class="sub-input" readonly></textarea>
          <button class="sub-copy-btn" onclick="copySub('b64lines')">复制</button>
        </div>
		
        <div class="sub-row">
          <div class="sub-label">Base64:</div>
          <textarea id="sub-b64" class="sub-input" readonly></textarea>
          <button class="sub-copy-btn" onclick="copySub('b64')">复制</button>
        </div>

      </div>
    </div>
  </div>

  <!-- 流量统计 -->
  <div class="grid grid-full">
    <div class="card traffic-card">
      <h3>📊 流量统计
        <div class="traffic-progress-container">
          <span class="progress-label">本月累计/阈值:</span>
          <div class="progress-wrapper">
            <div class="progress-bar">
              <div class="progress-fill" id="progress-fill" style="width:0%">
                <span class="progress-percentage" id="progress-percentage">0%</span>
              </div>
            </div>
          </div>
          <span class="progress-budget" id="progress-budget">0/100GiB</span>
        </div>
      </h3>
      <div class="content">
        <div class="traffic-charts">
          <div class="chart-container">
            <h4 class="chart-title">近30日出站流量 <span class="unit">(GiB)</span></h4>
            <canvas id="traffic"></canvas>
          </div>
          <div class="chart-container">
            <h4 class="chart-title">近12个月累计流量 <span class="unit">(GiB)</span></h4>
            <canvas id="monthly-chart"></canvas>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 运维管理 -->
  <div class="grid grid-full">
    <div class="card"><h3>🔧 运维管理</h3>
      <div class="content">
        <div class="commands-grid">
          <div class="command-section">
            <h4>🔧 基础操作</h4>
            <div class="command-list">
              <code>edgeboxctl sub</code> <span># 动态生成当前模式下的订阅链接</span><br>
              <code>edgeboxctl logs &lt;svc&gt;</code> <span># 查看指定服务的实时日志</span><br>
              <code>edgeboxctl status</code> <span># 查看所有核心服务运行状态</span><br>
              <code>edgeboxctl restart</code> <span># 安全地重启所有服务</span><br>
            </div>
          </div>
          
          <div class="command-section">
            <h4>🔐 证书管理</h4>
            <div class="command-list">
              <code>edgeboxctl switch-to-domain &lt;your_domain&gt;</code> <span># 切换到域名模式，申请证书</span><br>
              <code>edgeboxctl switch-to-ip</code> <span># 回退到IP模式，使用自签名证书</span><br>
              <code>edgeboxctl cert status</code> <span># 检查当前证书的到期日期和类型</span><br>
              <code>edgeboxctl cert renew</code> <span># 手动续期Let's Encrypt证书</span>
            </div>
          </div>
          
          <div class="command-section">
            <h4>🔀 出站分流</h4>
            <div class="command-list">
              <code>edgeboxctl shunt vps</code> <span> # 切换至VPS全量出站</span><br>
              <code>edgeboxctl shunt resi &lt;URL&gt;</code> <span> # 配置并切换至住宅IP全量出站</span><br>
              <code>edgeboxctl shunt direct-resi &lt;URL&gt;</code> <span> # 配置并切换至白名单智能分流状态</span><br>
              <code>edgeboxctl shunt whitelist &lt;add|remove|list&gt;</code> <span> # 管理白名单域名</span><br>
              <code>代理URL格式:</code><br>
              <code>http://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;</code><br>
              <code>https://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;?sni=</code><br>
              <code>socks5://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;</code><br>
              <code>socks5s://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;?sni=</code><br>
              <code>示例：edgeboxctl shunt resi 'socks5://user:pass@111.222.333.444:11324'</code>
            </div>
          </div>
          
          <div class="command-section">
            <h4>📊 流量统计与预警</h4>
            <div class="command-list">
              <code>edgeboxctl traffic show</code> <span># 在终端中查看流量统计数据</span><br>
              <code>edgeboxctl traffic reset</code> <span># 重置流量计数器</span><br>
              <code>edgeboxctl alert &lt;command&gt;</code> <span># 管理流量预警设置</span><br>
              <code>edgeboxctl alert monthly</code> <span># 设置月度阈值</span><br>
              <code>edgeboxctl alert steps 30,60,90</code> <span># 设置预警阈值</span><br>
              <code>edgeboxctl alert telegram &lt;bot_token&gt; &lt;chat_id&gt;</code> <span># 配置Telegram机器人</span><br>
              <code>edgeboxctl alert discord &lt;webhook_url&gt;</code> <span># 配置Discord通知</span><br>
              <code>edgeboxctl alert wechat &lt;pushplus_token&gt;</code> <span># 配置微信通知</span><br>
              <code>edgeboxctl alert webhook [raw|slack|discord]</code> <span># 配置通用Webhook</span><br>
              <code>edgeboxctl alert test</code> <span># 测试预警系统</span>
            </div>
          </div>
          
          <div class="command-section">
            <h4>⚙️ 配置管理</h4>
            <div class="command-list">
              <code>edgeboxctl config show</code> <span># 显示所有服务的核心配置信息</span><br>
              <code>edgeboxctl config regenerate-uuid</code> <span># 为所有协议重新生成新的UUID</span><br>
              <code>edgeboxctl test</code> <span># 测试所有协议的连接是否正常</span><br>
              <code>edgeboxctl debug-ports</code> <span># 调试关键端口的监听状态</span>
            </div>
          </div>
          
          <div class="command-section">
            <h4>💾 系统维护</h4>
            <div class="command-list">
              <code>edgeboxctl update</code> <span># 自动更新EdgeBox脚本和核心组件</span><br>
              <code>edgeboxctl backup create</code> <span># 手动创建一个系统备份</span><br>
              <code>edgeboxctl backup list</code> <span># 列出所有可用的备份</span><br>
              <code>edgeboxctl backup restore &lt;DATE&gt;</code> <span># 恢复到指定日期的备份状态</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- 协议详情模态框 -->
<div id="protocol-modal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h3 id="modal-title">协议配置详情</h3>
      <span class="modal-close" onclick="closeModal()">&times;</span>
    </div>
    <div class="modal-body" id="modal-body">
      <!-- 动态内容 -->
    </div>
  </div>
</div>

<script>
// ==========================================
// 模块7.3：图表和可视化组件 (Chart.js集成)
// EdgeBox控制面板 - 图表渲染和数据可视化
// ==========================================

/**
 * 图表配置和主题设置
 */
const ChartConfig = {
    // 全局主题色彩
    colors: {
        primary: '#3b82f6',      // 主要蓝色
        secondary: '#f59e0b',    // 警告橙色  
        success: '#10b981',      // 成功绿色
        danger: '#ef4444',       // 危险红色
        muted: '#64748b',        // 静音灰色
        background: '#f8fafc'    // 背景色
    },
    
    // 通用图表配置
    defaults: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: true,
                position: 'bottom',
                labels: {
                    padding: 20,
                    usePointStyle: true,
                    font: {
                        size: 12,
                        family: 'system-ui, -apple-system, sans-serif'
                    }
                }
            },
            tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                titleColor: '#fff',
                bodyColor: '#fff',
                borderColor: '#e2e8f0',
                borderWidth: 1,
                cornerRadius: 8,
                displayColors: true,
                intersect: false,
                mode: 'index'
            }
        },
        layout: {
            padding: { bottom: 28 }
        },
        interaction: {
            mode: 'index',
            intersect: false
        }
    }
};

/**
 * 数据格式化工具类
 */
class DataFormatter {
    static formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
    
    static formatGiB(bytes, decimals = 1) {
        const GiB = 1024 ** 3;
        return Math.round((bytes / GiB) * Math.pow(10, decimals)) / Math.pow(10, decimals);
    }
    
    static formatDate(dateStr) {
        try {
            const date = new Date(dateStr);
            return date.toLocaleDateString('zh-CN', { 
                month: 'short', 
                day: 'numeric' 
            });
        } catch {
            return dateStr;
        }
    }
    
    static formatMonth(monthStr) {
        try {
            // 处理 "2024-09" 格式
            const [year, month] = monthStr.split('-');
            return `${year}年${month}月`;
        } catch {
            return monthStr;
        }
    }
}

/**
 * 流量图表类 - 近30日趋势图
 */
class TrafficChart {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        this.chart = null;
        this.data = null;
    }
    
    /**
     * 渲染流量趋势图
     * @param {Object} trafficData - 包含 last30d 数组的流量数据
     */
    render(trafficData) {
        if (!this.canvas || !trafficData || !trafficData.last30d) {
            console.warn('TrafficChart: 无效的画布或数据');
            return;
        }
        
        // 销毁现有图表
        if (this.chart) {
            this.chart.destroy();
            this.chart = null;
        }
        
        const data = trafficData.last30d;
        if (!Array.isArray(data) || data.length === 0) {
            console.warn('TrafficChart: 空的流量数据');
            return;
        }
        
        // 数据处理
        const labels = data.map(item => DataFormatter.formatDate(item.date));
        const vpsData = data.map(item => DataFormatter.formatGiB(item.vps || 0));
        const resiData = data.map(item => DataFormatter.formatGiB(item.resi || 0));
        
        // 计算数据范围以优化Y轴
        const maxValue = Math.max(...vpsData, ...resiData);
        const yAxisMax = maxValue > 0 ? Math.ceil(maxValue * 1.1) : 10;
        
        // 创建图表
        this.chart = new Chart(this.canvas, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'VPS 直连',
                        data: vpsData,
                        borderColor: ChartConfig.colors.primary,
                        backgroundColor: ChartConfig.colors.primary + '20',
                        borderWidth: 2.5,
                        tension: 0.4,
                        fill: false,
                        pointBackgroundColor: ChartConfig.colors.primary,
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    },
                    {
                        label: '住宅代理',
                        data: resiData,
                        borderColor: ChartConfig.colors.secondary,
                        backgroundColor: ChartConfig.colors.secondary + '20',
                        borderWidth: 2.5,
                        tension: 0.4,
                        fill: false,
                        pointBackgroundColor: ChartConfig.colors.secondary,
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }
                ]
            },
            options: {
                ...ChartConfig.defaults,
                scales: {
                    x: {
                        title: {
                            display: false
                        },
                        grid: {
                            display: true,
                            color: '#f1f5f9',
                            drawBorder: false
                        },
                        ticks: {
                            font: { size: 11 },
                            color: ChartConfig.colors.muted
                        }
                    },
                    y: {
                        title: {
                            display: false
                        },
                        min: 0,
                        max: yAxisMax,
                        grid: {
                            display: true,
                            color: '#f1f5f9',
                            drawBorder: false
                        },
                        ticks: {
                            font: { size: 11 },
                            color: ChartConfig.colors.muted,
                            callback: function(value) {
                                return value.toFixed(1);
                            }
                        }
                    }
                },
                plugins: {
                    ...ChartConfig.defaults.plugins,
                    tooltip: {
                        ...ChartConfig.defaults.plugins.tooltip,
                        callbacks: {
                            title: function(context) {
                                // 显示完整日期
                                const index = context[0].dataIndex;
                                const originalDate = data[index]?.date;
                                if (originalDate) {
                                    return new Date(originalDate).toLocaleDateString('zh-CN');
                                }
                                return context[0].label;
                            },
                            label: function(context) {
                                const label = context.dataset.label;
                                const value = context.parsed.y;
                                return `${label}: ${value.toFixed(2)} GiB`;
                            },
                            afterBody: function(context) {
                                // 显示当日总流量
                                const index = context[0].dataIndex;
                                const vps = vpsData[index] || 0;
                                const resi = resiData[index] || 0;
                                const total = (vps + resi).toFixed(2);
                                return [``, `当日总计: ${total} GiB`];
                            }
                        }
                    }
                },
                elements: {
                    point: {
                        hoverBackgroundColor: '#fff'
                    }
                }
            }
        });
        
        this.data = trafficData;
        console.log('TrafficChart: 渲染完成', { dataPoints: data.length });
    }
    
    /**
     * 销毁图表
     */
    destroy() {
        if (this.chart) {
            this.chart.destroy();
            this.chart = null;
        }
    }
    
    /**
     * 更新数据（不重新创建图表）
     */
    updateData(trafficData) {
        if (!this.chart || !trafficData || !trafficData.last30d) return;
        
        const data = trafficData.last30d;
        this.chart.data.labels = data.map(item => DataFormatter.formatDate(item.date));
        this.chart.data.datasets[0].data = data.map(item => DataFormatter.formatGiB(item.vps || 0));
        this.chart.data.datasets[1].data = data.map(item => DataFormatter.formatGiB(item.resi || 0));
        this.chart.update('none'); // 无动画更新
    }
}

/**
 * 月度统计图表类 - 近12个月柱形图
 */
class MonthlyChart {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        this.chart = null;
        this.data = null;
    }
    
    /**
     * 渲染月度统计柱形图
     * @param {Object} trafficData - 包含 monthly 数组的流量数据
     */
    render(trafficData) {
        if (!this.canvas || !trafficData || !trafficData.monthly) {
            console.warn('MonthlyChart: 无效的画布或数据');
            return;
        }
        
        // 销毁现有图表
        if (this.chart) {
            this.chart.destroy();
            this.chart = null;
        }
        
        const data = trafficData.monthly;
        if (!Array.isArray(data) || data.length === 0) {
            console.warn('MonthlyChart: 空的月度数据');
            return;
        }
        
        // 取最近12个月
        const recentData = data.slice(-12);
        const labels = recentData.map(item => DataFormatter.formatMonth(item.month));
        const vpsData = recentData.map(item => DataFormatter.formatGiB(item.vps || 0));
        const resiData = recentData.map(item => DataFormatter.formatGiB(item.resi || 0));
        
        // 计算最大值用于Y轴优化
        const maxValue = Math.max(...vpsData.map((v, i) => v + resiData[i]));
        const yAxisMax = maxValue > 0 ? Math.ceil(maxValue * 1.1) : 100;
        
        // 创建图表
        this.chart = new Chart(this.canvas, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'VPS 直连',
                        data: vpsData,
                        backgroundColor: ChartConfig.colors.primary,
                        borderColor: ChartConfig.colors.primary,
                        borderWidth: 1,
                        borderRadius: 4,
                        borderSkipped: false,
                        stack: 'traffic'
                    },
                    {
                        label: '住宅代理',
                        data: resiData,
                        backgroundColor: ChartConfig.colors.secondary,
                        borderColor: ChartConfig.colors.secondary,
                        borderWidth: 1,
                        borderRadius: 4,
                        borderSkipped: false,
                        stack: 'traffic'
                    }
                ]
            },
            options: {
                ...ChartConfig.defaults,
                scales: {
                    x: {
                        stacked: true,
                        grid: {
                            display: false
                        },
                        ticks: {
                            font: { size: 11 },
                            color: ChartConfig.colors.muted,
                            maxRotation: 45
                        }
                    },
                    y: {
                        stacked: true,
                        min: 0,
                        max: yAxisMax,
                        grid: {
                            display: true,
                            color: '#f1f5f9',
                            drawBorder: false
                        },
                        ticks: {
                            font: { size: 11 },
                            color: ChartConfig.colors.muted,
                            callback: function(value) {
                                return value.toFixed(0);
                            }
                        }
                    }
                },
                plugins: {
                    ...ChartConfig.defaults.plugins,
                    tooltip: {
                        ...ChartConfig.defaults.plugins.tooltip,
                        callbacks: {
                            title: function(context) {
                                return context[0].label;
                            },
                            label: function(context) {
                                const label = context.dataset.label;
                                const value = context.parsed.y;
                                return `${label}: ${value.toFixed(2)} GiB`;
                            },
                            afterBody: function(context) {
                                // 显示月度总流量
                                const index = context[0].dataIndex;
                                const vps = vpsData[index] || 0;
                                const resi = resiData[index] || 0;
                                const total = (vps + resi).toFixed(2);
                                return [``, `月度总计: ${total} GiB`];
                            }
                        }
                    }
                }
            }
        });
        
        this.data = trafficData;
        console.log('MonthlyChart: 渲染完成', { dataPoints: recentData.length });
    }
    
    /**
     * 销毁图表
     */
    destroy() {
        if (this.chart) {
            this.chart.destroy();
            this.chart = null;
        }
    }
    
    /**
     * 更新数据（不重新创建图表）
     */
    updateData(trafficData) {
        if (!this.chart || !trafficData || !trafficData.monthly) return;
        
        const data = trafficData.monthly.slice(-12);
        this.chart.data.labels = data.map(item => DataFormatter.formatMonth(item.month));
        this.chart.data.datasets[0].data = data.map(item => DataFormatter.formatGiB(item.vps || 0));
        this.chart.data.datasets[1].data = data.map(item => DataFormatter.formatGiB(item.resi || 0));
        this.chart.update('none');
    }
}

/**
 * 流量进度条组件
 */
class TrafficProgressBar {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.fillElement = null;
        this.textElement = null;
        this.budgetElement = null;
        this.initElements();
    }
    
    initElements() {
        if (!this.container) return;
        
        this.fillElement = this.container.querySelector('#progress-fill');
        this.textElement = this.container.querySelector('#progress-percentage');
        this.budgetElement = this.container.querySelector('#progress-budget');
    }
    
    /**
     * 更新进度条
     * @param {number} used - 已使用流量 (GiB)
     * @param {number} budget - 月度预算 (GiB)
     */
    update(used, budget) {
        if (!this.fillElement || !this.textElement || !this.budgetElement) return;
        
        const percentage = Math.min((used / budget) * 100, 100);
        const percentageRounded = Math.round(percentage);
        
        // 更新进度条
        this.fillElement.style.width = `${percentage}%`;
        this.textElement.textContent = `${percentageRounded}%`;
        this.budgetElement.textContent = `${used.toFixed(1)}/${budget}GiB`;
        
        // 根据使用率调整颜色
        let color = ChartConfig.colors.success; // 绿色 < 70%
        if (percentage >= 90) {
            color = ChartConfig.colors.danger;   // 红色 >= 90%
        } else if (percentage >= 70) {
            color = ChartConfig.colors.secondary; // 橙色 >= 70%
        }
        
        this.fillElement.style.backgroundColor = color;
        
        console.log('TrafficProgressBar: 更新完成', { 
            used: used.toFixed(1), 
            budget, 
            percentage: percentageRounded 
        });
    }
}

/**
 * 图表管理器 - 统一管理所有图表
 */
class ChartManager {
    constructor() {
        this.trafficChart = null;
        this.monthlyChart = null;
        this.progressBar = null;
        this.isInitialized = false;
    }
    
    /**
     * 初始化所有图表组件
     */
    init() {
        if (this.isInitialized) return;
        
        try {
            this.trafficChart = new TrafficChart('traffic');
            this.monthlyChart = new MonthlyChart('monthly-chart');
            this.progressBar = new TrafficProgressBar('traffic-progress-container');
            
            this.isInitialized = true;
            console.log('ChartManager: 初始化完成');
        } catch (error) {
            console.error('ChartManager: 初始化失败', error);
        }
    }
    
    /**
     * 渲染所有图表
     * @param {Object} trafficData - 流量数据
     * @param {number} monthlyBudget - 月度预算 (GiB)
     */
    async renderAll(trafficData, monthlyBudget = 100) {
        if (!this.isInitialized) this.init();
        
        try {
            // 并行渲染图表
            const renderPromises = [];
            
            if (this.trafficChart && trafficData) {
                renderPromises.push(
                    Promise.resolve(this.trafficChart.render(trafficData))
                );
            }
            
            if (this.monthlyChart && trafficData) {
                renderPromises.push(
                    Promise.resolve(this.monthlyChart.render(trafficData))
                );
            }
            
            await Promise.allSettled(renderPromises);
            
            // 更新进度条
            this.updateProgressBar(trafficData, monthlyBudget);
            
            console.log('ChartManager: 所有图表渲染完成');
        } catch (error) {
            console.error('ChartManager: 渲染失败', error);
        }
    }
    
    /**
     * 更新进度条
     */
    updateProgressBar(trafficData, monthlyBudget) {
        if (!this.progressBar || !trafficData || !trafficData.monthly) return;
        
        const monthlyData = trafficData.monthly;
        if (monthlyData.length === 0) return;
        
        // 获取当月数据（最后一个月的数据）
        const currentMonth = monthlyData[monthlyData.length - 1];
        const usedGiB = DataFormatter.formatGiB((currentMonth.vps || 0) + (currentMonth.resi || 0));
        
        this.progressBar.update(usedGiB, monthlyBudget);
    }
    
    /**
     * 更新所有图表数据（轻量级更新，不重新创建）
     */
    updateAll(trafficData, monthlyBudget = 100) {
        if (!this.isInitialized) return;
        
        if (this.trafficChart) {
            this.trafficChart.updateData(trafficData);
        }
        
        if (this.monthlyChart) {
            this.monthlyChart.updateData(trafficData);
        }
        
        this.updateProgressBar(trafficData, monthlyBudget);
    }
    
    /**
     * 销毁所有图表
     */
    destroyAll() {
        if (this.trafficChart) {
            this.trafficChart.destroy();
            this.trafficChart = null;
        }
        
        if (this.monthlyChart) {
            this.monthlyChart.destroy();
            this.monthlyChart = null;
        }
        
        this.progressBar = null;
        this.isInitialized = false;
        
        console.log('ChartManager: 所有图表已销毁');
    }
    
    /**
     * 响应式处理
     */
    handleResize() {
        if (!this.isInitialized) return;
        
        // Chart.js 会自动处理响应式，这里可以添加自定义逻辑
        setTimeout(() => {
            if (this.trafficChart && this.trafficChart.chart) {
                this.trafficChart.chart.resize();
            }
            if (this.monthlyChart && this.monthlyChart.chart) {
                this.monthlyChart.chart.resize();
            }
        }, 100);
    }
}

/**
 * 导出图表管理器实例（单例模式）
 */
const chartManager = new ChartManager();

// 监听窗口大小变化
window.addEventListener('resize', () => {
    chartManager.handleResize();
});

// 导出供外部使用
window.ChartManager = ChartManager;
window.chartManager = chartManager;
window.DataFormatter = DataFormatter;

// 兼容性检查
if (typeof Chart === 'undefined') {
    console.error('Chart.js 未加载，图表功能将不可用');
} else {
    console.log('模块7.3：图表和可视化组件加载完成');
}

// ==========================================
// 原有的控制面板逻辑开始
// ==========================================

const GiB = 1024 ** 3;

// 数据获取工具函数
async function getJSON(url) {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error(`${url} ${r.status}`);
    return r.json();
  } catch (e) {
    console.warn(`Failed to fetch ${url}:`, e);
    return null;
  }
}

async function getTEXT(url) {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error(`${url} ${r.status}`);
    return r.text();
  } catch (e) {
    console.warn(`Failed to fetch ${url}:`, e);
    return '';
  }
}

// 全局变量
let serverConfig = {};
let _sysTicker = null;

// 移除原有的图表变量，使用模块7.3的图表管理器
// let _chartTraffic = null; 
// let _chartMonthly = null;

const clamp = (n, min=0, max=100) =>
  (Number.isFinite(+n) ? Math.max(min, Math.min(max, Math.round(+n))) : 0);

// 通知中心切换
function toggleNotifications() {
  const popup = document.getElementById('notif-popup');
  popup.classList.toggle('show');
}

// 关闭模态框
function closeModal() {
  document.getElementById('protocol-modal').classList.remove('show');
}

// 安全取值函数
function getSafe(obj, path, fallback = '') {
  try {
    let cur = obj;
    for (let i = 0; i < path.length; i++) {
      if (cur == null || !(path[i] in cur)) return fallback;
      cur = cur[path[i]];
    }
    return cur == null ? fallback : cur;
  } catch (_) {
    return fallback;
  }
}

// 显示协议详情
function showProtocolDetails(protocol) {
  const modal = document.getElementById('protocol-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalBody = document.getElementById('modal-body');

  const sc = window.serverConfig || {};
  const uuid = getSafe(sc, ['uuid', 'vless'], 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');
  const tuicUuid = getSafe(sc, ['uuid', 'tuic'], 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');
  const realityPK = getSafe(sc, ['reality', 'public_key'], 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
  const shortId = getSafe(sc, ['reality', 'short_id'], 'xxxxxxxxxxxxxxxx');
  const hy2Pass = getSafe(sc, ['password', 'hysteria2'], 'xxxxxxxxxxxx');
  const tuicPass = getSafe(sc, ['password', 'tuic'], 'xxxxxxxxxxxx');
  const trojanPwd = getSafe(sc, ['password', 'trojan'], 'xxxxxxxxxxxx');
  const server = getSafe(sc, ['server_ip'], window.location.hostname);

  const configs = {
    'VLESS-Reality': {
      title: 'VLESS-Reality 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: 'UUID', value: uuid },
        { label: '传输协议', value: 'tcp' },
        { label: '流控', value: 'xtls-rprx-vision' },
        { label: 'Reality配置', value: '公钥: ' + realityPK + '\nShortID: ' + shortId + '\nSNI: www.cloudflare.com', note: '支持SNI: cloudflare.com, microsoft.com, apple.com' }
      ]
    },
    'VLESS-gRPC': {
      title: 'VLESS-gRPC 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: 'UUID', value: uuid },
        { label: '传输协议', value: 'grpc' },
        { label: 'ServiceName', value: 'grpc' },
        { label: 'TLS设置', value: 'tls', note: 'IP模式需开启"跳过证书验证"' }
      ]
    },
    'VLESS-WS': {
      title: 'VLESS-WebSocket 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: 'UUID', value: uuid },
        { label: '传输协议', value: 'ws' },
        { label: 'Path', value: '/ws' },
        { label: 'TLS设置', value: 'tls', note: 'IP模式需开启"跳过证书验证"' }
      ]
    },
    'Trojan-TLS': {
      title: 'Trojan-TLS 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: '密码', value: trojanPwd },
        { label: 'SNI', value: 'trojan.edgebox.internal', note: 'IP模式需开启"跳过证书验证"' }
      ]
    },
    'Hysteria2': {
      title: 'Hysteria2 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: '密码', value: hy2Pass },
        { label: '协议', value: 'UDP/QUIC' },
        { label: '注意事项', value: '需要支持QUIC的网络环境', note: 'IP模式需开启"跳过证书验证"' }
      ]
    },
    'TUIC': {
      title: 'TUIC 配置',
      items: [
        { label: '服务器地址', value: server + ':2053' },
        { label: 'UUID', value: tuicUuid },
        { label: '密码', value: tuicPass },
        { label: '拥塞控制', value: 'bbr', note: 'IP模式需开启"跳过证书验证"' }
      ]
    }
  };

  const cfg = configs[protocol];
  if (!cfg) return;
  modalTitle.textContent = cfg.title;
  modalBody.innerHTML = cfg.items.map(function(it) {
    return '<div class="config-item"><h4>' + it.label + '</h4><code>' + it.value + '</code>' + (it.note ? '<div class="config-note">⚠️ ' + it.note + '</div>' : '') + '</div>';
  }).join('');
  modal.classList.add('show');
}

// 点击外部关闭
document.addEventListener('click', function(e) {
  if (!e.target.closest('.notification-bell')) {
    document.getElementById('notif-popup').classList.remove('show');
  }
  if (e.target.classList.contains('modal')) {
    e.target.classList.remove('show');
  }
});

// 读取服务器配置（统一从dashboard.json读取）
async function readServerConfig() {
  // 优先统一数据源：dashboard.json.secrets
  try {
    const d = await getJSON('./dashboard.json');
    if (!d) throw new Error('Dashboard data not available');
    
    const s = (d && d.secrets) || {};
    const cfg = {
      server_ip: (d && d.server && (d.server.eip || d.server.ip)) || window.location.hostname,
      uuid: {
        vless: s.vless && (s.vless.reality || s.vless.grpc || s.vless.ws) || ''
      },
      password: {
        hysteria2: (s.password && s.password.hysteria2) || '',
        tuic:      (s.password && s.password.tuic)      || '',
        trojan:    (s.password && s.password.trojan)    || ''
      },
      reality: {
        public_key: (s.reality && s.reality.public_key) || '',
        short_id:   (s.reality && s.reality.short_id)   || ''
      }
    };
    if (s.tuic_uuid) cfg.uuid.tuic = s.tuic_uuid;
    return cfg;
  } catch (_) {}

  // 兜底：从 /traffic/sub 或 /traffic/sub.txt 解析
  try {
    let txt = '';
    try { txt = await getTEXT('./sub'); } catch { txt = await getTEXT('./sub.txt'); }
    const lines = txt.split('\n').map(l => l.trim()).filter(Boolean);
    const cfg = { uuid:{}, password:{}, reality:{}, server_ip: window.location.hostname };
    const v = lines.find(l => l.startsWith('vless://'));
    if (v) {
      const m = v.match(/^vless:\/\/([^@]+)@([^:]+):\d+\?([^#]+)/i);
      if (m) {
        cfg.uuid.vless = m[1]; cfg.server_ip = m[2];
        const qs = new URLSearchParams(m[3].replace(/&amp;/g,'&'));
        cfg.reality.public_key = qs.get('pbk') || '';
        cfg.reality.short_id   = qs.get('sid') || '';
      }
    }
    for (const l of lines) {
      let m;
      if ((m = l.match(/^hysteria2:\/\/([^@]+)@/i))) cfg.password.hysteria2 = decodeURIComponent(m[1]);
      if ((m = l.match(/^tuic:\/\/([^:]+):([^@]+)@/i))) { cfg.uuid.tuic = m[1]; cfg.password.tuic = decodeURIComponent(m[2]); }
      if ((m = l.match(/^trojan:\/\/([^@]+)@/i))) cfg.password.trojan = decodeURIComponent(m[1]);
    }
    return cfg;
  } catch { 
    return {
      server_ip: window.location.hostname,
      uuid: { vless: '', tuic: '' },
      password: { hysteria2: '', tuic: '', trojan: '' },
      reality: { public_key: '', short_id: '' }
    };
  }
}

// 更新本月进度条 (使用模块7.3组件)
async function updateProgressBar() {
  try {
    const [trafficRes, alertRes] = await Promise.all([
      fetch('./traffic.json', { cache: 'no-store' }),
      fetch('./alert.conf', { cache: 'no-store' })
    ]);
    
    let budget = 100;
    if (alertRes && alertRes.ok) {
      const alertText = await alertRes.text();
      const match = alertText.match(/ALERT_MONTHLY_GIB=(\d+)/);
      if (match) budget = parseInt(match[1]);
    }
    
    if (trafficRes && trafficRes.ok) {
      const traffic = await trafficRes.json();
      if (traffic && chartManager.isInitialized) {
        chartManager.updateProgressBar(traffic, budget);
      } else {
        // 降级处理：直接更新DOM元素
        updateProgressBarDirect(traffic, budget);
      }
    }
  } catch (e) {
    console.warn('进度条更新失败:', e);
  }
}

// 直接更新进度条DOM的降级函数
function updateProgressBarDirect(traffic, budget) {
  if (!traffic || !traffic.monthly || traffic.monthly.length === 0) return;
  
  const current = traffic.monthly[traffic.monthly.length - 1];
  const used = ((current.vps || 0) + (current.resi || 0)) / (1024 ** 3);
  const pct = Math.min((used / budget) * 100, 100);
  
  const fillEl = document.getElementById('progress-fill');
  const textEl = document.getElementById('progress-percentage');
  const budgetEl = document.getElementById('progress-budget');
  
  if (fillEl) fillEl.style.width = pct + '%';
  if (textEl) textEl.textContent = pct.toFixed(0) + '%';
  if (budgetEl) budgetEl.textContent = used.toFixed(1) + '/' + budget + 'GiB';
}

// 主数据加载函数（统一从dashboard.json读取）
async function loadData() {
  console.log('开始加载数据...');
  
  try {
    // 统一数据源：只从 dashboard.json 读取
    const [dashboard, traffic, alerts, serverJson] = await Promise.all([
      getJSON('./dashboard.json'),
      getJSON('./traffic.json'),
      getJSON('./alerts.json').then(data => data || []),
      readServerConfig()
    ]);
    
    console.log('数据加载完成:', { dashboard: !!dashboard, traffic: !!traffic, alerts: alerts.length, serverJson: !!serverJson });
    
    // 保存服务器配置供协议详情使用
    window.serverConfig = serverJson || {};

    // 统一数据模型（基于dashboard.json）
    const model = dashboard ? {
      updatedAt: dashboard.updated_at,
      server: dashboard.server || {},
      system: { cpu: null, memory: null }, // 系统信息从system.json单独获取
      protocols: dashboard.protocols || [],
      shunt: dashboard.shunt || {},
      subscription: dashboard.subscription || { plain: '', base64: '', b64_lines: '' },
      services: dashboard.services || {}
    } : {
      // 兜底数据结构
      updatedAt: new Date().toISOString(),
      server: {},
      system: { cpu: null, memory: null },
      protocols: [],
      shunt: {},
      subscription: { plain: '', base64: '', b64_lines: '' },
      services: {}
    };

    // 渲染各个模块
    renderHeader(model);
    renderProtocols(model);
    renderTraffic(traffic);
    renderAlerts(alerts);

  } catch (e) {
    console.error('loadData failed:', e);
    // 在出错时显示基本界面
    renderHeader({
      updatedAt: new Date().toISOString(),
      server: {},
      services: {}
    });
  }
}

// 渲染基本信息
function renderHeader(model) {
  const ts = model.updatedAt || new Date().toISOString();
  document.getElementById('updated').textContent = new Date(ts).toLocaleString('zh-CN');
  const s = model.server || {}, svc = model.services || {};
  
  // 基本信息 - 修正DOM元素ID
  const userAlias = document.getElementById('user-alias');
  const cloudProvider = document.getElementById('cloud-provider');
  const instanceId = document.getElementById('instance-id');
  const hostname = document.getElementById('hostname');
  
  if (userAlias) userAlias.textContent = s.user_alias || '—';
  if (cloudProvider) cloudProvider.textContent = s.cloud_provider || '—';
  if (instanceId) instanceId.textContent = s.instance_id || '—';
  if (hostname) hostname.textContent = s.hostname || '—';
 
  // 证书 / 网络模式 & 续期方式
  const mode = s.cert_mode || 'self-signed';
  const renewal = mode === 'letsencrypt' ? '自动续期' : '手动续期';

  const certType = document.getElementById('cert-type');
  const certDomain = document.getElementById('cert-domain');
  const certRenewal = document.getElementById('cert-renewal');
  const certExpire = document.getElementById('cert-expire');

  if (certType) certType.textContent = mode === 'letsencrypt' ? "Let's Encrypt" : '自签名证书';
  if (certDomain) certDomain.textContent = s.cert_domain || '无';
  if (certRenewal) certRenewal.textContent = renewal;

  // 到期日期：处理无效值
  const expStr = (s.cert_expire || '').trim();
  const expDate = expStr ? new Date(expStr) : null;
  if (certExpire) {
    certExpire.textContent = (expDate && !isNaN(expDate)) ? expDate.toLocaleDateString('zh-CN') : '无';
  }

  const verEl = document.getElementById('ver');
  const instEl = document.getElementById('inst');
  if (verEl) verEl.textContent = s.version || '—';
  if (instEl) instEl.textContent = s.install_date || '—';
  
  // CPU/内存从system.json单独获取
  loadSystemStats();
  
  // 服务状态 - 添加状态样式类
  const nginxEl = document.getElementById('nginx-status');
  const xrayEl = document.getElementById('xray-status');
  const singboxEl = document.getElementById('singbox-status');

  if (nginxEl) {
    nginxEl.innerHTML = svc.nginx === 'active' 
      ? '<span class="service-status-badge">运行中</span>'
      : '<span class="service-status-badge inactive">已停止</span>';
  }

  if (xrayEl) {
    xrayEl.innerHTML = svc.xray === 'active'
      ? '<span class="service-status-badge">运行中</span>'
      : '<span class="service-status-badge inactive">已停止</span>';
  }

  if (singboxEl) {
    singboxEl.innerHTML = svc['sing-box'] === 'active'
      ? '<span class="service-status-badge">运行中</span>'
      : '<span class="service-status-badge inactive">已停止</span>';
  }
}

// 单独加载系统状态
async function loadSystemStats() {
  try {
    const sys = await getJSON('./system.json');
    if (!sys) throw new Error('System data not available');
    
    const cpuPercent = clamp(sys.cpu);
    const memPercent = clamp(sys.memory);
    const diskPercent = clamp(sys.disk);
    
    // 更新CPU进度条
    const cpuFill = document.getElementById('cpu-progress-fill');
    const cpuText = document.getElementById('cpu-progress-text');
    const cpuDetail = document.getElementById('cpu-detail');
    if (cpuFill) cpuFill.style.width = cpuPercent + '%';
    if (cpuText) cpuText.textContent = cpuPercent + '%';
    if (cpuDetail) cpuDetail.textContent = sys.cpu_info || '—';
    
    // 更新内存进度条
    const memFill = document.getElementById('mem-progress-fill');
    const memText = document.getElementById('mem-progress-text');
    const memDetail = document.getElementById('mem-detail');
    if (memFill) memFill.style.width = memPercent + '%';
    if (memText) memText.textContent = memPercent + '%';
    if (memDetail) memDetail.textContent = sys.memory_info || '—';
    
    // 更新磁盘进度条
    const diskFill = document.getElementById('disk-progress-fill');
    const diskText = document.getElementById('disk-progress-text');
    const diskDetail = document.getElementById('disk-detail');
    if (diskFill) diskFill.style.width = diskPercent + '%';
    if (diskText) diskText.textContent = diskPercent + '%';
    if (diskDetail) diskDetail.textContent = sys.disk_info || '—';
    
  } catch(_) {
    // 错误时显示默认状态
    const elements = [
      'cpu-progress-fill', 'cpu-progress-text', 'cpu-detail',
      'mem-progress-fill', 'mem-progress-text', 'mem-detail',
      'disk-progress-fill', 'disk-progress-text', 'disk-detail'
    ];
    elements.forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        if (id.includes('fill')) el.style.width = '0%';
        else el.textContent = id.includes('text') ? '-' : '—';
      }
    });
  }
  
  // 15s轮询系统状态
  clearInterval(_sysTicker);
  _sysTicker = setInterval(loadSystemStats, 15000);
}

// 渲染协议配置
function renderProtocols(model) {
  const tb = document.querySelector('#proto tbody');
  if (!tb) return;
  
  tb.innerHTML = '';
  
  const protocols = [
    { name: 'VLESS-Reality', network: 'TCP', disguise: '极佳', scenario: '强审查环境' },
    { name: 'VLESS-gRPC', network: 'TCP/H2', disguise: '极佳', scenario: '较严审查/走CDN' },
    { name: 'VLESS-WS', network: 'TCP/WS', disguise: '良好', scenario: '常规网络更稳' },
    { name: 'Trojan-TLS', network: 'TCP', disguise: '良好', scenario: '移动网络可靠' },
    { name: 'Hysteria2', network: 'UDP/QUIC', disguise: '良好', scenario: '大带宽/低时延' },
    { name: 'TUIC', network: 'UDP/QUIC', disguise: '好', scenario: '弱网/高丢包更佳' }
  ];
  
  protocols.forEach(function(p) {
    const tr = document.createElement('tr');
    tr.innerHTML = 
      '<td>' + p.name + '</td>' +
      '<td>' + p.network + '</td>' +
      '<td>' + p.disguise + '</td>' +
      '<td>' + p.scenario + '</td>' +
      '<td><span class="protocol-status-badge">✓ 运行</span></td>' +
      '<td><span class="detail-link" onclick="showProtocolDetails(\'' + p.name + '\')">详情>></span></td>';
    tb.appendChild(tr);
  });
  
  // 网络出站状态
  const sh = model.shunt || {};
  
  // 更新网络信息
  const vpsOutIp = document.getElementById('vps-out-ip');
  const vpsGeo = document.getElementById('vps-geo');
  const vpsQuality = document.getElementById('vps-quality');
  const proxyOutIp = document.getElementById('proxy-out-ip');
  const proxyGeo = document.getElementById('proxy-geo');
  const proxyQuality = document.getElementById('proxy-quality');
  
  if (vpsOutIp) vpsOutIp.textContent = (model.server && (model.server.eip || model.server.ip)) || '—';
  if (vpsGeo) vpsGeo.textContent = sh.vps_geo || '—';
  if (vpsQuality) vpsQuality.textContent = sh.vps_quality || '—';
  if (proxyOutIp) proxyOutIp.textContent = sh.proxy_info ? '已配置' : '未配置';
  if (proxyGeo) proxyGeo.textContent = sh.proxy_geo || '—';
  if (proxyQuality) proxyQuality.textContent = sh.proxy_quality || '—';
  
  // 修复白名单显示
  const whitelist = sh.whitelist || [];
  const whitelistText = Array.isArray(whitelist) && whitelist.length > 0 
    ? whitelist.slice(0, 8).join(', ') + (whitelist.length > 8 ? '...' : '')
    : '加载中...';
  const whitelistEl = document.getElementById('whitelist-text');
  if (whitelistEl) whitelistEl.textContent = whitelistText;

  // 渲染订阅链接
  const sub = model.subscription || {};
  const subPlain = document.getElementById('sub-plain');
  const subB64 = document.getElementById('sub-b64');
  const subB64Lines = document.getElementById('sub-b64lines');
  
  if (subPlain) subPlain.value = sub.plain || '';
  if (subB64) subB64.value = sub.base64 || '';
  if (subB64Lines) subB64Lines.value = sub.b64_lines || '';
}

// 渲染流量图表 (使用模块7.3图表组件)
async function renderTraffic(traffic) {
  if (!traffic) {
    console.warn('renderTraffic: 无流量数据');
    return;
  }
  
  try {
    // 获取月度预算配置
    let monthlyBudget = 100; // 默认100GiB
    try {
      const alertRes = await fetch('./alert.conf', { cache: 'no-store' });
      if (alertRes && alertRes.ok) {
        const alertText = await alertRes.text();
        const match = alertText.match(/ALERT_MONTHLY_GIB=(\d+)/);
        if (match) monthlyBudget = parseInt(match[1]);
      }
    } catch (e) {
      console.warn('获取预算配置失败，使用默认值:', e);
    }
    
    // 使用图表管理器渲染所有图表
    await chartManager.renderAll(traffic, monthlyBudget);
    
    console.log('renderTraffic: 图表渲染完成', {
      hasLast30d: !!(traffic.last30d && traffic.last30d.length),
      hasMonthly: !!(traffic.monthly && traffic.monthly.length),
      monthlyBudget
    });
    
  } catch (error) {
    console.error('renderTraffic: 渲染失败', error);
    
    // 降级处理：显示错误状态
    const trafficCanvas = document.getElementById('traffic');
    const monthlyCanvas = document.getElementById('monthly-chart');
    
    if (trafficCanvas) {
      const ctx = trafficCanvas.getContext('2d');
      ctx.clearRect(0, 0, trafficCanvas.width, trafficCanvas.height);
      ctx.fillStyle = '#64748b';
      ctx.font = '14px system-ui';
      ctx.textAlign = 'center';
      ctx.fillText('图表加载失败', trafficCanvas.width / 2, trafficCanvas.height / 2);
    }
    
    if (monthlyCanvas) {
      const ctx = monthlyCanvas.getContext('2d');
      ctx.clearRect(0, 0, monthlyCanvas.width, monthlyCanvas.height);
      ctx.fillStyle = '#64748b';
      ctx.font = '14px system-ui';
      ctx.textAlign = 'center';
      ctx.fillText('图表加载失败', monthlyCanvas.width / 2, monthlyCanvas.height / 2);
    }
  }
}

// 渲染通知中心
function renderAlerts(alerts) {
  const alertCount = (alerts || []).length;
  const notifCountEl = document.getElementById('notif-count');
  const notifBell = document.getElementById('notif-bell');
  
  if (notifCountEl) notifCountEl.textContent = alertCount;
  
  if (notifBell && alertCount > 0) {
    notifBell.classList.add('has-alerts');
    const span = notifBell.querySelector('span');
    if (span) span.textContent = alertCount + ' 条通知';
  }
  
  const notifList = document.getElementById('notif-list');
  if (notifList) {
    notifList.innerHTML = '';
    if (alertCount > 0) {
      alerts.slice(0, 10).forEach(function(a) {
        const div = document.createElement('div');
        div.className = 'notification-item';
        div.textContent = (a.ts || '') + ' ' + (a.msg || '');
        notifList.appendChild(div);
      });
    } else {
      notifList.textContent = '暂无通知';
    }
  }
}

// 复制订阅链接函数
function copySub(type) {
  const input = document.getElementById('sub-' + type);
  if (!input) return;
  
  input.select();
  document.execCommand('copy');
  
  const btn = input.nextElementSibling;
  if (btn) {
    const originalText = btn.textContent;
    btn.textContent = '已复制';
    btn.style.background = '#10b981';
    btn.style.color = 'white';
    setTimeout(function() {
      btn.textContent = originalText;
      btn.style.background = '';
      btn.style.color = '';
    }, 1000);
  }
}

// 白名单展开/收起功能
function toggleWhitelist() {
  const content = document.getElementById('whitelist-content');
  const toggle = document.getElementById('whitelist-toggle');
  
  if (content && toggle) {
    content.classList.toggle('expanded');
    toggle.textContent = content.classList.contains('expanded') ? '收起' : '查看全部';
  }
}

// IP质量详情显示功能
function showIPQDetails(type) {
  // 这里可以实现显示IP质量检测详情的功能
  alert('IP质量检测详情功能待实现 - ' + type);
}

// 白名单自动折叠功能
function initWhitelistCollapse() {
  document.querySelectorAll('.kv').forEach(function(kv){
    const v = kv.querySelector('.v');
    if(!v) return;
    
    // 检查内容是否超出3行高度
    const lineHeight = parseFloat(getComputedStyle(v).lineHeight) || 20;
    const maxHeight = lineHeight * 3;
    
    if(v.scrollHeight > maxHeight){
      kv.classList.add('v-collapsed');
      const btn = document.createElement('span');
      btn.className = 'detail-toggle';
      btn.innerText = '详情';
      btn.addEventListener('click', function(){
        kv.classList.toggle('v-collapsed');
        btn.innerText = kv.classList.contains('v-collapsed') ? '详情' : '收起';
      });
      kv.appendChild(btn);
    }
  });
}

// 启动
console.log('脚本开始执行');
document.addEventListener('DOMContentLoaded', function() {
  // 初始化图表管理器
  chartManager.init();
  
  // 加载数据
  loadData();
  initWhitelistCollapse();
  
  console.log('控制面板初始化完成');
});

// 定时刷新：每5分钟刷新一次数据，每小时刷新本月进度条
setInterval(() => {
  loadData();
}, 300000);

setInterval(() => {
  updateProgressBar();
}, 3600000);

// 页面卸载时清理图表
window.addEventListener('beforeunload', () => {
  chartManager.destroyAll();
});
</script>
</body>
</html>
HTML


log_success "流量监控系统设置完成：${TRAFFIC_DIR}/index.html"
}

# 设置定时任务
setup_cron_jobs() {
  log_info "配置定时任务..."

  # 预警配置
cat > /etc/edgebox/traffic/alert.conf <<'CONF'
# 月度预算（GiB）
ALERT_MONTHLY_GIB=100

# Telegram（@BotFather 获取 BotToken；ChatID 可用 @userinfobot）
ALERT_TG_BOT_TOKEN=
ALERT_TG_CHAT_ID=

# Discord（频道里添加 Incoming Webhook）
ALERT_DISCORD_WEBHOOK=

# 微信（个人可用的 PushPlus 转发）
ALERT_PUSHPLUS_TOKEN=

# （可选）通用 Webhook（HTTPS 443），FORMAT=raw|slack|discord
ALERT_WEBHOOK=
ALERT_WEBHOOK_FORMAT=raw

# 阈值（百分比，逗号分隔）
ALERT_STEPS=30,60,90
CONF

  # 预警脚本已在 setup_traffic_monitoring 中创建

  # 仅保留采集与预警；面板刷新由 dashboard-backend 统一维护
  ( crontab -l 2>/dev/null | grep -vE '/etc/edgebox/scripts/(traffic-collector\.sh|traffic-alert\.sh)\b' ) | crontab - || true
  ( crontab -l 2>/dev/null; \
    echo "0 * * * * /etc/edgebox/scripts/traffic-collector.sh"; \
    echo "7 * * * * /etc/edgebox/scripts/traffic-alert.sh" \
  ) | crontab -
  
  # 确保面板刷新任务存在
  /etc/edgebox/scripts/dashboard-backend.sh --schedule

  log_success "cron 已配置（每小时采集 + 刷新面板 + 阈值预警）"
}

# 创建完整的edgeboxctl管理工具
create_enhanced_edgeboxctl() {
    log_info "创建增强版edgeboxctl管理工具..."
    
    cat > /usr/local/bin/edgeboxctl << 'EDGEBOXCTL_SCRIPT'
#!/bin/bash
# EdgeBox 增强版控制脚本
# Version: 3.0.0 - 包含流量统计、预警、备份恢复等高级运维功能
VERSION="3.0.0"
CONFIG_DIR="/etc/edgebox/config"
CERT_DIR="/etc/edgebox/cert"
INSTALL_DIR="/etc/edgebox"
LOG_FILE="/var/log/edgebox.log"
SHUNT_CONFIG="${CONFIG_DIR}/shunt/state.json"
BACKUP_DIR="/root/edgebox-backup"
TRAFFIC_DIR="/etc/edgebox/traffic"
SCRIPTS_DIR="/etc/edgebox/scripts"
WHITELIST_DOMAINS="googlevideo.com,ytimg.com,ggpht.com,youtube.com,youtu.be,googleapis.com,gstatic.com"

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

# 兼容别名
log()      { log_info "$@"; }
log_ok()   { log_success "$@"; }
error()    { log_error "$@"; }

# 工具函数
get_current_cert_mode(){ [[ -f ${CONFIG_DIR}/cert_mode ]] && cat ${CONFIG_DIR}/cert_mode || echo "self-signed"; }
need(){ command -v "$1" >/dev/null 2>&1; }

get_server_info() {
  if [[ ! -f ${CONFIG_DIR}/server.json ]]; then log_error "配置文件不存在：${CONFIG_DIR}/server.json"; return 1; fi
  SERVER_IP=$(jq -r '.server_ip' ${CONFIG_DIR}/server.json 2>/dev/null)
  UUID_VLESS=$(jq -r '.uuid.vless.reality // .uuid.vless' ${CONFIG_DIR}/server.json 2>/dev/null)
  UUID_TUIC=$(jq -r '.uuid.tuic' ${CONFIG_DIR}/server.json 2>/dev/null)
  PASSWORD_HYSTERIA2=$(jq -r '.password.hysteria2' ${CONFIG_DIR}/server.json 2>/dev/null)
  PASSWORD_TUIC=$(jq -r '.password.tuic' ${CONFIG_DIR}/server.json 2>/dev/null)
  PASSWORD_TROJAN=$(jq -r '.password.trojan' ${CONFIG_DIR}/server.json 2>/dev/null)
  REALITY_PUBLIC_KEY=$(jq -r '.reality.public_key' ${CONFIG_DIR}/server.json 2>/dev/null)
  REALITY_SHORT_ID=$(jq -r '.reality.short_id' ${CONFIG_DIR}/server.json 2>/dev/null)
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
  # 已有订阅（安装时 generate_subscription() 写入）
  if [[ -s "${CONFIG_DIR}/subscription.txt" ]]; then
    cat "${CONFIG_DIR}/subscription.txt"
    return 0
  fi

  # 没有就按当前证书模式生成
  local mode
  mode="$(get_current_cert_mode 2>/dev/null || echo self-signed)"
  if [[ -f "${CONFIG_DIR}/server.json" ]]; then
    if [[ "$mode" == "self-signed" ]]; then
      regen_sub_ip
    else
      # letsencrypt:<domain>
      local domain="${mode##*:}"
      [[ -n "$domain" ]] && regen_sub_domain "$domain" || regen_sub_ip
    fi
    # 生成后必然存在
    [[ -s "${CONFIG_DIR}/subscription.txt" ]] && cat "${CONFIG_DIR}/subscription.txt"
  fi
}

show_sub(){
  ensure_traffic_dir

  # 优先从 dashboard.json 读取
  if [[ -s "${TRAFFIC_DIR}/dashboard.json" ]]; then
    local sub_plain sub_b64 sub_lines
    sub_plain=$(jq -r '.subscription.plain // empty' "${TRAFFIC_DIR}/dashboard.json" 2>/dev/null || true)
    sub_b64=$(jq -r '.subscription.base64 // empty' "${TRAFFIC_DIR}/dashboard.json" 2>/dev/null || true)
    sub_lines=$(jq -r '.subscription.b64_lines // empty' "${TRAFFIC_DIR}/dashboard.json" 2>/dev/null || true)

    if [[ -n "$sub_plain" ]]; then
      printf '%s\n' "$sub_plain"
      return 0
    elif [[ -n "$sub_lines" ]]; then
      printf '%s\n' "$sub_lines"
      return 0
    fi
  fi

  # 兜底：使用原有逻辑
  local payload; payload="$(build_sub_payload)"
  if [[ -z "$payload" ]]; then
    echo "订阅尚未生成，请运行 update-dashboard" >&2
    exit 1
  fi
  printf '%s\n' "$payload"
}

show_status() {
  echo -e "${CYAN}EdgeBox 服务状态（v${VERSION}）：${NC}"
  for svc in nginx xray sing-box; do
    systemctl is-active --quiet "$svc" && echo -e "  $svc: ${GREEN}运行中${NC}" || echo -e "  $svc: ${RED}已停止${NC}"
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
    systemctl restart "$s" && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAIL${NC}"; 
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
# 证书管理
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

  # 先检查 apex 是否解析；子域 trojan.<domain> 解析不到就先不申请它
  if ! getent hosts "$domain" >/dev/null; then
    log_error "${domain} 未解析到本机，无法申请证书"; return 1
  fi

  local trojan="trojan.${domain}"
  local args="-d ${domain}"
  local have_trojan=0
  if getent hosts "$trojan" >/dev/null; then
    args="${args} -d ${trojan}"
    have_trojan=1
  else
    log_warn "未检测到 ${trojan} 的 A/AAAA 记录，将先只为 ${domain} 申请证书。"
    log_warn "等你把 ${trojan} 解析到本机后，再运行同样命令会自动 --expand 加上子域。"
  fi

# 首选 nginx 插件（不停机），失败则回落 standalone（临停 80）
# 1) 组装域名参数
local cert_args=(-d "${domain}")
[[ ${have_trojan:-0} -eq 1 ]] && cert_args+=(-d "${trojan}")

# 2) 是否需要 --expand（已有同名证书时）
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

  systemctl reload nginx xray sing-box >/dev/null 2>&1 || systemctl restart nginx xray sing-box

  if [[ ${have_trojan} -eq 1 ]]; then
    log_success "Let's Encrypt 证书已生效（包含 trojan.${domain}）"
  else
    log_success "Let's Encrypt 证书已生效（仅 ${domain}；trojan 子域暂未包含）"
  fi
}

# 生成订阅（域名 / IP模式）
regen_sub_domain(){
  local domain=$1; get_server_info
  local HY2_PW_ENC TUIC_PW_ENC TROJAN_PW_ENC
  HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
  TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC"     | jq -rR @uri)
  TROJAN_PW_ENC=$(printf '%s' "$PASSWORD_TROJAN" | jq -rR @uri)

  local sub=$(
    cat <<PLAIN
vless://${UUID_VLESS}@${domain}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY
vless://${UUID_VLESS}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=h2&type=grpc&serviceName=grpc&fp=chrome#EdgeBox-gRPC
vless://${UUID_VLESS}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome#EdgeBox-WS
trojan://${TROJAN_PW_ENC}@${domain}:443?security=tls&sni=trojan.${domain}&alpn=http%2F1.1&fp=chrome#EdgeBox-TROJAN
hysteria2://${HY2_PW_ENC}@${domain}:443?sni=${domain}&alpn=h3#EdgeBox-HYSTERIA2
tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${domain}:2053?congestion_control=bbr&alpn=h3&sni=${domain}#EdgeBox-TUIC
PLAIN
  )

  _b64_line(){ if base64 --help 2>&1 | grep -q -- '-w'; then base64 -w0; else base64 | tr -d '\n'; fi; }
  _ensure_nl(){ sed -e '$a\'; }

  printf '%s\n' "$sub" > "${CONFIG_DIR}/subscription.txt"
  _ensure_nl <<<"$sub" | _b64_line > "${CONFIG_DIR}/subscription.base64"
  : > "${CONFIG_DIR}/subscription.b64lines"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    printf '%s\n' "$line" | _ensure_nl | _b64_line >> "${CONFIG_DIR}/subscription.b64lines"
    printf '\n' >> "${CONFIG_DIR}/subscription.b64lines"
  done <<<"$sub"

  mkdir -p /var/www/html
  {
    printf '%s\n\n' "$sub"
    echo "# Base64（逐行，每行一个链接；多数客户端不支持一次粘贴多行）"
    cat "${CONFIG_DIR}/subscription.b64lines"
    echo
    echo "# Base64（整包，单行）"
    cat "${CONFIG_DIR}/subscription.base64"
    echo
  } > /var/www/html/sub

  log_success "域名模式订阅已更新"
}

regen_sub_ip(){
  get_server_info
  local HY2_PW_ENC TUIC_PW_ENC TROJAN_PW_ENC
  HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
  TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC"     | jq -rR @uri)
  TROJAN_PW_ENC=$(printf '%s' "$PASSWORD_TROJAN" | jq -rR @uri)

  local sub=$(
    cat <<PLAIN
vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY
vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=grpc.edgebox.internal&alpn=h2&type=grpc&serviceName=grpc&fp=chrome&allowInsecure=1#EdgeBox-gRPC
vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=ws.edgebox.internal&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome&allowInsecure=1#EdgeBox-WS
trojan://${TROJAN_PW_ENC}@${SERVER_IP}:443?security=tls&sni=trojan.edgebox.internal&alpn=http%2F1.1&fp=chrome&allowInsecure=1#EdgeBox-TROJAN
hysteria2://${HY2_PW_ENC}@${SERVER_IP}:443?sni=${SERVER_IP}&alpn=h3&insecure=1#EdgeBox-HYSTERIA2
tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${SERVER_IP}:2053?congestion_control=bbr&alpn=h3&sni=${SERVER_IP}&allowInsecure=1#EdgeBox-TUIC
PLAIN
  )

  _b64_line(){ if base64 --help 2>&1 | grep -q -- '-w'; then base64 -w0; else base64 | tr -d '\n'; fi; }
  _ensure_nl(){ sed -e '$a\'; }

  printf '%s\n' "$sub" > "${CONFIG_DIR}/subscription.txt"
  _ensure_nl <<<"$sub" | _b64_line > "${CONFIG_DIR}/subscription.base64"
  : > "${CONFIG_DIR}/subscription.b64lines"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    printf '%s\n' "$line" | _ensure_nl | _b64_line >> "${CONFIG_DIR}/subscription.b64lines"
    printf '\n' >> "${CONFIG_DIR}/subscription.b64lines"
  done <<<"$sub"

  mkdir -p /var/www/html
  {
    printf '%s\n\n' "$sub"
    echo "# Base64（逐行，每行一个链接；多数客户端不支持一次粘贴多行）"
    cat "${CONFIG_DIR}/subscription.b64lines"
    echo
    echo "# Base64（整包，单行）"
    cat "${CONFIG_DIR}/subscription.base64"
    echo
  } > /var/www/html/sub

  log_success "IP 模式订阅已更新"
}

switch_to_domain(){
  local domain="$1"
  [[ -z "$domain" ]] && { echo "用法: edgeboxctl switch-to-domain <domain>"; return 1; }

  log_info "检查域名解析: ${domain}"
  if ! getent hosts "$domain" >/dev/null; then
    log_error "${domain} 未解析"; return 1
  fi
  log_success "域名解析通过"
  log_info "为 ${domain} 申请/扩展 Let's Encrypt 证书"
  request_letsencrypt_cert "$domain" || return 1
}

switch_to_ip(){
  get_server_info || return 1
  ln -sf ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
  ln -sf ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
  echo "self-signed" > ${CONFIG_DIR}/cert_mode
  regen_sub_ip
  systemctl restart xray sing-box >/dev/null 2>&1
  log_success "已切换到 IP 模式"
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

# 清空 nftables 的住宅采集集合（VPS 全量出站时用）
flush_nft_resi_sets() {
  nft flush set inet edgebox resi_addr4 2>/dev/null || true
  nft flush set inet edgebox resi_addr6 2>/dev/null || true
}

# 解析住宅代理 URL => 导出全局变量：
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

# 生成 Xray 的住宅代理 outbound JSON（单个）
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
            resi) echo -e "  当前模式: ${YELLOW}住宅IP全量出${NC}  代理: ${proxy_info}  健康: $health";;
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

    # === sing-box：恢复直连 ===
    cp ${CONFIG_DIR}/sing-box.json ${CONFIG_DIR}/sing-box.json.bak 2>/dev/null || true
    cat > ${CONFIG_DIR}/sing-box.json <<EOF
{"log":{"level":"warn","timestamp":true},
 "inbounds":[
  {"type":"hysteria2","tag":"hysteria2-in","listen":"::","listen_port":443,
   "users":[{"password":"${PASSWORD_HYSTERIA2}"}],
   "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${CERT_DIR}/current.pem","key_path":"${CERT_DIR}/current.key"}},
  {"type":"tuic","tag":"tuic-in","listen":"::","listen_port":2053,
   "users":[{"uuid":"${UUID_TUIC}","password":"${PASSWORD_TUIC}"}],
   "congestion_control":"bbr",
   "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${CERT_DIR}/current.pem","key_path":"${CERT_DIR}/current.key"}}],
 "outbounds":[{"type":"direct","tag":"direct"}]}
EOF

    # === Xray：恢复直连（删掉任何代理出站/路由） ===
    local xray_tmp="${CONFIG_DIR}/xray.json.tmp"
    jq '
      .outbounds = [ { "protocol":"freedom", "tag":"direct" } ] |
      .routing   = { "rules": [] }
    ' ${CONFIG_DIR}/xray.json > "$xray_tmp" && mv "$xray_tmp" ${CONFIG_DIR}/xray.json

    setup_shunt_directories
    update_shunt_state "vps" "" "healthy"
    systemctl restart xray sing-box && log_success "VPS全量出站模式配置成功" || { log_error "配置失败"; return 1; }
    flush_nft_resi_sets
}

# 住宅全量出站
setup_outbound_resi() {
  local url="$1"
  [[ -z "$url" ]] && { echo "用法: edgeboxctl shunt resi '<URL>'"; return 1; }

  log_info "配置住宅IP全量出站: ${url}"
  if ! check_proxy_health_url "$url"; then log_error "代理不可用：$url"; return 1; fi
  get_server_info || return 1
  parse_proxy_url "$url"

  # Xray: 所有 TCP/UDP 流量走住宅，53 直连
  local xob; xob="$(build_xray_resi_outbound)"
  jq --argjson ob "$xob" '
    .outbounds=[{"protocol":"freedom","tag":"direct"}, $ob] |
    .routing={
      "domainStrategy":"AsIs",
      "rules":[
        {"type":"field","port":"53","outboundTag":"direct"},
        {"type":"field","network":"tcp,udp","outboundTag":"resi-proxy"}
      ]
    }' ${CONFIG_DIR}/xray.json > ${CONFIG_DIR}/xray.json.tmp && mv ${CONFIG_DIR}/xray.json.tmp ${CONFIG_DIR}/xray.json

  # sing-box: 固定直连（HY2/TUIC 需要 UDP）
  cat > ${CONFIG_DIR}/sing-box.json <<EOF
{"log":{"level":"warn","timestamp":true},
 "inbounds":[
  {"type":"hysteria2","tag":"hysteria2-in","listen":"::","listen_port":443,
   "users":[{"password":"${PASSWORD_HYSTERIA2}"}],
   "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${CERT_DIR}/current.pem","key_path":"${CERT_DIR}/current.key"}},
  {"type":"tuic","tag":"tuic-in","listen":"::","listen_port":2053,
   "users":[{"uuid":"${UUID_TUIC}","password":"${PASSWORD_TUIC}"}],
   "congestion_control":"bbr",
   "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${CERT_DIR}/current.pem","key_path":"${CERT_DIR}/current.key"}}],
 "outbounds":[{"type":"direct","tag":"direct"}]}
EOF

  echo "$url" > "${CONFIG_DIR}/shunt/resi.conf"
  setup_shunt_directories
  update_shunt_state "resi(xray-only)" "$url" "healthy"
  systemctl restart xray sing-box && log_success "住宅全量出站已生效（Xray 分流，sing-box 直连）" || { log_error "失败"; return 1; }
}

# 智能分流
setup_outbound_direct_resi() {
  local url="$1"
  [[ -z "$url" ]] && { echo "用法: edgeboxctl shunt direct-resi '<URL>'"; return 1; }

  log_info "配置智能分流（白名单直连，其余住宅）: ${url}"
  if ! check_proxy_health_url "$url"; then log_error "代理不可用：$url"; return 1; fi
  get_server_info || return 1; setup_shunt_directories
  parse_proxy_url "$url"

  local xob wl; xob="$(build_xray_resi_outbound)"
  wl='[]'
  [[ -s "${CONFIG_DIR}/shunt/whitelist.txt" ]] && wl="$(cat "${CONFIG_DIR}/shunt/whitelist.txt" | jq -R -s 'split("\n")|map(select(length>0))|map("domain:"+.)')"

  jq --argjson ob "$xob" --argjson wl "$wl" '
    .outbounds=[{"protocol":"freedom","tag":"direct"}, $ob] |
    .routing={
      "domainStrategy":"AsIs",
      "rules":[
        {"type":"field","port":"53","outboundTag":"direct"},
        {"type":"field","domain":$wl,"outboundTag":"direct"},
        {"type":"field","network":"tcp,udp","outboundTag":"resi-proxy"}
      ]
    }' ${CONFIG_DIR}/xray.json > ${CONFIG_DIR}/xray.json.tmp && mv ${CONFIG_DIR}/xray.json.tmp ${CONFIG_DIR}/xray.json

  # sing-box: 固定直连
  cat > ${CONFIG_DIR}/sing-box.json <<EOF
{"log":{"level":"warn","timestamp":true},
 "inbounds":[
  {"type":"hysteria2","tag":"hysteria2-in","listen":"::","listen_port":443,
   "users":[{"password":"${PASSWORD_HYSTERIA2}"}],
   "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${CERT_DIR}/current.pem","key_path":"${CERT_DIR}/current.key"}},
  {"type":"tuic","tag":"tuic-in","listen":"::","listen_port":2053,
   "users":[{"uuid":"${UUID_TUIC}","password":"${PASSWORD_TUIC}"}],
   "congestion_control":"bbr",
   "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${CERT_DIR}/current.pem","key_path":"${CERT_DIR}/current.key"}}],
 "outbounds":[{"type":"direct","tag":"direct"}]}
EOF

  echo "$url" > "${CONFIG_DIR}/shunt/resi.conf"
  update_shunt_state "direct_resi(xray-only)" "$url" "healthy"
  systemctl restart xray sing-box && log_success "智能分流已生效（Xray 分流，sing-box 直连）" || { log_error "失败"; return 1; }
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

traffic_show(){
    echo -e "${CYAN}流量统计：${NC}"
    if need vnstat; then 
        local iface=$(ip route | awk '/default/{print $5; exit}')
        vnstat -i "$iface" --oneline 2>/dev/null | tail -1 | awk -F';' '{print "  今日: "$4" ↑, "$5" ↓\n  本月: "$8" ↑, "$9" ↓\n  总计: "$11" ↑, "$12" ↓"}' || echo "  vnStat 数据获取失败"
    else 
        echo "  vnStat 未安装"; 
    fi
    echo -e "\n${YELLOW}端口维度:${NC}"
    for kv in "tcp 443 Nginx" "udp 443 Hysteria2" "udp 2053 TUIC"; do 
        set -- $kv
        local line=$(iptables -L INPUT -v -n 2>/dev/null | grep "dpt:$2 " | grep $1 | head -1)
        [[ -n "$line" ]] && echo "  $1/$2 ($3): $(echo $line|awk '{print $1}') 包, $(format_bytes $(echo $line|awk '{print $2}'))" || echo "  $1/$2 ($3): 无数据"
    done
}

traffic_reset(){ 
    iptables -Z INPUT 2>/dev/null || true
    iptables -Z OUTPUT 2>/dev/null || true
    need vnstat && {
        local iface=$(ip route | awk '/default/{print $5; exit}')
        vnstat -i "$iface" --delete --force >/dev/null 2>&1 || true
    }
    log_success "流量统计已重置"
}

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
        systemctl restart nginx xray sing-box
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

regenerate_uuid(){
    log_info "重新生成UUID..."
    get_server_info || return 1
    
    # 生成新UUID
    local new_vless_uuid=$(uuidgen)
    local new_tuic_uuid=$(uuidgen)
    local new_trojan_uuid=$(uuidgen)
    local new_hy2_pass=$(openssl rand -base64 16)
    local new_tuic_pass=$(openssl rand -base64 16)
    local new_trojan_pass=$(openssl rand -base64 16)
    
    # 更新server.json
    jq --arg vless "$new_vless_uuid" \
       --arg tuic "$new_tuic_uuid" \
       --arg trojan "$new_trojan_uuid" \
       --arg hy2_pass "$new_hy2_pass" \
       --arg tuic_pass "$new_tuic_pass" \
       --arg trojan_pass "$new_trojan_pass" \
       '.uuid.vless.reality = $vless | .uuid.tuic = $tuic | .password.hysteria2 = $hy2_pass | .password.tuic = $tuic_pass | .password.trojan = $trojan_pass' \
       ${CONFIG_DIR}/server.json > ${CONFIG_DIR}/server.json.tmp && \
       mv ${CONFIG_DIR}/server.json.tmp ${CONFIG_DIR}/server.json
    
    # 更新配置文件
    sed -i "s/\"id\": \".*\"/\"id\": \"$new_vless_uuid\"/g" ${CONFIG_DIR}/xray.json
    sed -i "s/\"uuid\": \".*\"/\"uuid\": \"$new_tuic_uuid\"/g" ${CONFIG_DIR}/sing-box.json
    sed -i "s/\"password\": \".*\"/\"password\": \"$new_hy2_pass\"/g" ${CONFIG_DIR}/sing-box.json
    sed -i "s/\"password\": \".*\"/\"password\": \"$new_trojan_pass\"/g" ${CONFIG_DIR}/xray.json
    
    # 重新生成订阅
    local cert_mode=$(get_current_cert_mode)
    if [[ "$cert_mode" == "self-signed" ]]; then
        regen_sub_ip
    else
        local domain=${cert_mode##*:}
        regen_sub_domain "$domain"
    fi
    
    # 重启服务
    systemctl restart xray sing-box
    log_success "UUID重新生成完成"
    echo -e "${YELLOW}新的UUID：${NC}"
    echo -e "  VLESS: $new_vless_uuid"
    echo -e "  TUIC: $new_tuic_uuid"
    echo -e "  Hysteria2 密码: $new_hy2_pass"
    echo -e "  TUIC 密码: $new_tuic_pass"
    echo -e "  Trojan 密码: $new_trojan_pass"
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
        echo -e "  VLESS UUID: $(jq -r '.uuid.vless.reality // .uuid.vless' ${CONFIG_DIR}/server.json)"
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
# 主命令处理
#############################################

case "$1" in
  # 基础功能
  sub|subscription) show_sub ;;
  status) show_status ;;
  restart) restart_services ;;
  logs|log) show_logs "$2" ;;
  test) test_connection ;;
  debug-ports) debug_ports ;;
  
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
        systemctl reload nginx xray sing-box >/dev/null 2>&1 || systemctl restart nginx xray sing-box
        cert_status
        ;;
      *)
        echo "用法: edgeboxctl cert [status|renew]"
        ;;
    esac
    ;;
  fix-permissions) fix_permissions ;;
  cert-status) cert_status ;;                 # 兼容旧命令
  switch-to-domain) shift; switch_to_domain "$1" ;;
  switch-to-ip) switch_to_ip ;;
  
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

  # 流量统计
  traffic) 
    case "$2" in 
      show|"") traffic_show ;; 
      reset) traffic_reset ;; 
      *) echo "用法: edgeboxctl traffic [show|reset]";; 
    esac 
    ;;
  
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
    curl -fsSL https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/install.sh | bash
    ;;
  
  # 帮助信息
help|"") 
  cat <<HLP
${CYAN}EdgeBox 管理工具 v${VERSION}${NC}

${YELLOW}基础操作:${NC}
  edgeboxctl sub                                 显示订阅与面板链接
  edgeboxctl logs <svc> [nginx|xray|sing-box]     查看指定服务实时日志（Ctrl+C 退出）
  edgeboxctl status                              查看所有核心服务状态
  edgeboxctl restart                             优雅重启核心服务（修改配置后使用）
  edgeboxctl test                                测试各协议连通性
  edgeboxctl debug-ports                         调试 80/443/2053 等端口占用

${YELLOW}证书管理:${NC}
  edgeboxctl cert status                         查看证书状态（类型/到期）
  edgeboxctl cert renew                          立即续期证书并重载服务
  edgeboxctl fix-permissions                     修复证书/密钥文件权限
  edgeboxctl switch-to-domain <domain>           切换域名模式并申请证书
  edgeboxctl switch-to-ip                        切换到 IP 模式（自签证书）

${YELLOW}出站分流:${NC}
  edgeboxctl shunt resi '<代理URL>'               全量走住宅（仅 Xray 分流）
  edgeboxctl shunt direct-resi '<代理URL>'        智能分流（白名单直连，其余走住宅）
  edgeboxctl shunt vps                           VPS 全量出站
  edgeboxctl shunt whitelist [add|remove|list|reset] [domain]   管理白名单
  代理URL示例:
    http://user:pass@host:port
    https://user:pass@host:port?sni=example.com
    socks5://user:pass@host:port
    socks5s://user:pass@host:port?sni=example.com
  示例（全栈走住宅）: edgeboxctl shunt resi 'socks5://u:p@111.222.333.444:11324'

${YELLOW}流量统计和预警:${NC}
  edgeboxctl traffic show                        查看流量统计
  edgeboxctl traffic reset                       重置流量计数
  edgeboxctl alert monthly <GiB>                 设置月度预算（GiB）
  edgeboxctl alert steps 30,60,90                设置触发阈值（百分比）
  edgeboxctl alert telegram <bot_token> <chat_id> 配置 Telegram 通知
  edgeboxctl alert discord <webhook_url>         配置 Discord 通知
  edgeboxctl alert wechat <pushplus_token>       配置微信 PushPlus 转发
  edgeboxctl alert webhook <url> [raw|slack|discord]  配置通用 Webhook
  edgeboxctl alert test [percent]                模拟触发（默认 40%），写入流量预警日志

${YELLOW}配置管理:${NC}
  edgeboxctl config show                         显示当前配置（UUID/Reality/端口等）
  edgeboxctl config regenerate-uuid              重新生成 UUID

${YELLOW}备份恢复:${NC}
  edgeboxctl backup create                       创建备份
  edgeboxctl backup list                         列出备份
  edgeboxctl backup restore <file>               恢复备份
HLP
  ;;
  
  *) 
    echo -e "${RED}未知命令: $1${NC}"
    echo "使用 'edgeboxctl help' 查看帮助"
    exit 1
    ;;
esac
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

# 安装IP质量评分系统
install_ipq_stack() {
  log_info "安装 IP 质量评分（IPQ）栈..."

  # 目录：按文档口径，物理目录放 /var/www/edgebox/status；映射到站点根 /status
  local WEB_STATUS_PHY="/var/www/edgebox/status"
  local WEB_STATUS_LINK="${WEB_ROOT:-/var/www/html}/status"
  mkdir -p "$WEB_STATUS_PHY" "${WEB_ROOT:-/var/www/html}"
  ln -sfn "$WEB_STATUS_PHY" "$WEB_STATUS_LINK" 2>/dev/null || true

  # 兜底依赖（dig 用于 rDNS）
  if ! command -v dig >/dev/null 2>&1; then
    if command -v apt >/dev/null 2>&1; then apt -y update && apt -y install dnsutils;
    elif command -v yum >/dev/null 2>&1; then yum -y install bind-utils; fi
  fi

  # 写入评分脚本：/usr/local/bin/edgebox-ipq.sh
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

curl_json(){ # $1 proxy-args  $2 url
  eval "curl -fsS --max-time 4 $1 \"$2\"" || return 1; }

get_proxy_url(){ local s="${SHUNT_DIR}/state.json"
  [[ -s "$s" ]] && jqget '.proxy_info' <"$s" || echo ""; }

collect_one(){ # $1 vantage vps|proxy  $2 proxy-args
  local V="$1" P="$2" J1="{}" J2="{}" J3="{}" ok1=false ok2=false ok3=false
  if out=$(curl_json "$P" "https://ipinfo.io/json"); then J1="$out"; ok1=true; fi
  if out=$(curl_json "$P" "https://ip.sb/api/json"); then J2="$out"; ok2=true; fi
  if out=$(curl_json "$P" "http://ip-api.com/json/?fields=status,message,country,city,as,asname,reverse,hosting,proxy,mobile,query"); then J3="$out"; ok3=true; fi

  local ip=""; for j in "$J2" "$J1" "$J3"; do ip="$(jq -r '(.ip // .query // empty)' <<<"$j")"; [[ -n "$ip" && "$ip" != "null" ]] && break; done
  local rdns="$(jq -r '.reverse // empty' <<<"$J3")"
  if [[ -z "$rdns" && -n "$ip" ]]; then rdns="$(dig +time=1 +tries=1 +short -x "$ip" 2>/dev/null | head -n1)"; fi
  local asn="$(jq -r '(.asname // .as // empty)' <<<"$J3")"; [[ -z "$asn" || "$asn" == "null" ]] && asn="$(jq -r '(.org // empty)' <<<"$J1")"
  local isp="$(jq -r '(.org // empty)' <<<"$J1")"; [[ -z "$isp" || "$isp" == "null" ]] && isp="$(jq -r '(.asname // .as // empty)' <<<"$J3")"
  local country="$(jq -r '(.country // empty)' <<<"$J3")"; [[ -z "$country" || "$country" == "null" ]] && country="$(jq -r '(.country // empty)' <<<"$J1")"
  local city="$(jq -r '(.city // empty)' <<<"$J3")"; [[ -z "$city" || "$city" == "null" ]] && city="$(jq -r '(.city // empty)' <<<"$J1")"
  local f_host="$(jq -r '(.hosting // false)' <<<"$J3")"; local f_proxy="$(jq -r '(.proxy // false)' <<<"$J3")"; local f_mob="$(jq -r '(.mobile // false)' <<<"$J3")"

  # DNSBL（轻量）
  declare -a hits=(); if [[ -n "$ip" ]]; then IFS=. read -r a b c d <<<"$ip"; rip="${d}.${c}.${b}.${a}"
    for bl in zen.spamhaus.org bl.spamcop.net dnsbl.sorbs.net b.barracudacentral.org; do
      if dig +time=1 +tries=1 +short "${rip}.${bl}" A >/dev/null 2>&1; then hits+=("$bl"); fi
    done
  fi

  # 延迟：vps→ping 1.1.1.1；proxy→TLS connect
  local lat=999
  if [[ "$V" == "vps" ]]; then
    r=$(ping -n -c 3 -w 4 1.1.1.1 2>/dev/null | awk -F'/' '/^rtt/ {print int($5+0.5)}'); [[ -n "${r:-}" ]] && lat="$r"
  else
    r=$(eval "curl -o /dev/null -s $P -w '%{time_connect}' https://www.cloudflare.com/cdn-cgi/trace" 2>/dev/null)
    [[ -n "${r:-}" ]] && lat=$(awk -v t="$r" 'BEGIN{printf("%d",(t*1000)+0.5)}')
  fi

  # 打分
  local score=100; declare -a notes=()
  [[ "$f_proxy" == "true"   ]] && score=$((score-50)) && notes+=("flag_proxy")
  [[ "$f_host"  == "true"   ]] && score=$((score-10)) && notes+=("datacenter_ip")
  (( ${#hits[@]} )) && score=$((score-20*${#hits[@]})) && notes+=("dnsbl")
  (( lat>400 )) && score=$((score-20)) && notes+=("high_latency")
  (( lat>200 && lat<=400 )) && score=$((score-10)) && notes+=("mid_latency")
  if [[ "$asn" =~ (amazon|aws|google|gcp|microsoft|azure|alibaba|tencent|digitalocean|linode|vultr|hivelocity|ovh|hetzner|iij|ntt|leaseweb|contabo) ]]; then score=$((score-2)); fi
  (( score<0 )) && score=0
  local grade="D"; ((score>=80)) && grade="A" || { ((score>=60)) && grade="B" || { ((score>=40)) && grade="C"; }; }

  jq -n --arg ts "$(ts)" --arg V "$V" --arg ip "${ip:-}" --arg c "${country:-}" --arg city "${city:-}" \
        --arg asn "${asn:-}" --arg isp "${isp:-}" --arg rdns "${rdns:-}" \
        --argjson flags "{\"ipinfo\":$ok1,\"ipsb\":$ok2,\"ipapi\":$ok3}" \
        --argjson risk "$(printf '%s\n' "${hits[@]:-}" | jq -R -s 'split(\"\\n\")|map(select(length>0))' | jq -n --argjson bl @- \
          --argjson p $([[ "$f_proxy" == "true" ]] && echo true || echo false) \
          --argjson h $([[ "$f_host"  == "true" ]] && echo true || echo false) \
          --argjson m $([[ "$f_mob"   == "true" ]] && echo true || echo false) \
          '{proxy:$p,hosting:$h,mobile:$m,dnsbl_hits:$bl,tor:false}')" \
        --argjson lat "${lat:-999}" --argjson score "$score" --arg grade "$grade" \
        --arg notes "$(IFS=,; echo "${notes[*]:-}")" '
  { detected_at:$ts,vantage:$V,ip:$ip,country:$c,city:$city,asn:$asn,isp:$isp,rdns:($rdns|select(.!="")),
    source_flags:$flags,risk:$risk,latency_ms:$lat,score:$score,grade:$grade,
    notes:( ($notes|length>0) and ($notes!="") ? ($notes|split(",")|map(select(length>0))) : [] ) }'
}

main(){
  # vps + proxy 都测；无代理则输出 not_configured
  collect_one "vps" "" | tee "${STATUS_DIR}/ipq_vps.json" >/dev/null
  purl="$(get_proxy_url)"
  if [[ -n "${purl:-}" && "$purl" != "null" ]]; then
    pargs="$(build_proxy_args "$purl")"
    collect_one "proxy" "$pargs" | tee "${STATUS_DIR}/ipq_proxy.json" >/dev/null
  else
    jq -n --arg ts "$(ts)" '{detected_at:$ts,vantage:"proxy",status:"not_configured"}' | tee "${STATUS_DIR}/ipq_proxy.json" >/dev/null
  fi
  jq -n --arg ts "$(ts)" --arg ver "ipq-1.0" '{last_run:$ts,version:$ver}' | tee "${STATUS_DIR}/ipq_meta.json" >/dev/null
  chmod 644 "${STATUS_DIR}"/ipq_*.json 2>/dev/null || true
}
main "$@"
IPQ
  chmod +x /usr/local/bin/edgebox-ipq.sh

  # systemd：监听分流状态变化触发 IPQ
  cat > /etc/systemd/system/edgebox-ipq.service <<'UNIT'
[Unit]
Description=EdgeBox IP Quality (IPQ) refresh
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/edgebox-ipq.sh
UNIT

  cat > /etc/systemd/system/edgebox-ipq.path <<'PATHU'
[Unit]
Description=Watch shunt state.json to refresh IPQ
[Path]
PathChanged=/etc/edgebox/config/shunt/state.json
Unit=edgebox-ipq.service
[Install]
WantedBy=multi-user.target
PATHU

  systemctl daemon-reload
  systemctl enable --now edgebox-ipq.path >/dev/null 2>&1 || true

  # Cron：每日 02:15 例行评分（与文档频次一致）
  ( crontab -l 2>/dev/null | grep -v '/usr/local/bin/edgebox-ipq.sh' ) | crontab - || true
  ( crontab -l 2>/dev/null; echo "15 2 * * * /usr/local/bin/edgebox-ipq.sh >/dev/null 2>&1" ) | crontab -

  # 首次即跑，给前端可用数据
  /usr/local/bin/edgebox-ipq.sh || true

  log_success "IPQ 栈就绪：/status/ipq_vps.json /status/ipq_proxy.json"
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

  systemctl restart nginx
  systemctl restart xray
  systemctl restart sing-box

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

  log_success "数据生成与系统验证完成"
}

# 显示安装完成信息
show_installation_info() {
    clear
    print_separator
    echo -e "${GREEN}🎉 EdgeBox 企业级多协议节点 v3.0.0 安装完成！${NC}"
    print_separator
    
    # 读取配置信息
    local server_ip config_file="${CONFIG_DIR}/server.json"
    if [[ -s "$config_file" ]]; then
        server_ip=$(jq -r '.server_ip // empty' "$config_file" 2>/dev/null)
        UUID_VLESS=$(jq -r '.uuid.vless.reality // .uuid.vless // empty' "$config_file" 2>/dev/null)
        UUID_TUIC=$(jq -r '.uuid.tuic // empty' "$config_file" 2>/dev/null)
        PASSWORD_HYSTERIA2=$(jq -r '.password.hysteria2 // empty' "$config_file" 2>/dev/null)
        PASSWORD_TUIC=$(jq -r '.password.tuic // empty' "$config_file" 2>/dev/null)
        PASSWORD_TROJAN=$(jq -r '.password.trojan // empty' "$config_file" 2>/dev/null)
    else
        server_ip="${SERVER_IP:-未知}"
    fi
    
    echo -e "${CYAN}服务器信息：${NC}"
    echo -e "  证书模式: ${PURPLE}IP模式（自签名证书）${NC}"
    echo -e "  IP地址: ${PURPLE}${server_ip}${NC}"
    echo -e "  版本号: ${PURPLE}EdgeBox v3.0.0 企业级完整版${NC}"

    echo -e "\n${CYAN}协议信息：${NC}"
    echo -e "  VLESS-Reality  端口: 443  UUID: ${PURPLE}${UUID_VLESS:0:8}...${NC}"
    echo -e "  VLESS-gRPC     端口: 443  UUID: ${PURPLE}${UUID_VLESS:0:8}...${NC}"  
    echo -e "  VLESS-WS       端口: 443  UUID: ${PURPLE}${UUID_VLESS:0:8}...${NC}"
    echo -e "  Trojan-TLS     端口: 443  密码: ${PURPLE}${PASSWORD_TROJAN:0:8}...${NC}"
    echo -e "  Hysteria2      端口: 443  密码: ${PURPLE}${PASSWORD_HYSTERIA2:0:8}...${NC}"
    echo -e "  TUIC           端口: 2053 UUID: ${PURPLE}${UUID_TUIC:0:8}...${NC}"
       
    echo -e "\n${CYAN}访问地址：${NC}"
    echo -e "  🌐 控制面板: ${PURPLE}http://${server_ip}/${NC}" 
    echo -e "  📋 订阅链接: ${PURPLE}http://${server_ip}/sub${NC}"
    echo -e "  📊 流量统计: ${PURPLE}http://${server_ip}/traffic/${NC}"
    
    echo -e "\n${CYAN}高级运维功能：${NC}"
    echo -e "  🔄 模式切换: IP模式 ⇋ 域名模式（Let's Encrypt证书）"
    echo -e "  🌐 出站分流: 住宅IP全量 ⇋ VPS全量出 ⇋ 白名单智能分流"
    echo -e "  📊 流量监控: 实时流量统计、历史趋势图表、协议分析"
    echo -e "  🔔 预警通知: 流量阈值告警（30%/60%/90%）多渠道推送"
    echo -e "  💾 自动备份: 配置文件定期备份、一键故障恢复"
    echo -e "  🔍 IP质量: 实时出口IP质量评分、黑名单检测"
    
    echo -e "\n${CYAN}常用管理命令：${NC}"
    echo -e "  ${PURPLE}edgeboxctl status${NC}                        # 查看服务状态"
    echo -e "  ${PURPLE}edgeboxctl sub${NC}                           # 查看订阅链接"
    echo -e "  ${PURPLE}edgeboxctl switch-to-domain <域名>${NC}        # 切换到域名模式"
    echo -e "  ${PURPLE}edgeboxctl shunt direct-resi '<代理URL>'${NC}  # 配置智能分流"
    echo -e "  ${PURPLE}edgeboxctl traffic show${NC}                  # 查看流量统计"
    echo -e "  ${PURPLE}edgeboxctl alert monthly <GiB>${NC}           # 设置月度预算"
    echo -e "  ${PURPLE}edgeboxctl backup create${NC}                 # 手动备份"
    echo -e "  ${PURPLE}edgeboxctl help${NC}                          # 查看完整帮助"
    
    echo -e "\n${CYAN}智能分流示例：${NC}"
    echo -e "  # 住宅代理全量出站"
    echo -e "  ${PURPLE}edgeboxctl shunt resi 'socks5://user:pass@proxy.example.com:1080'${NC}"
    echo -e "  "
    echo -e "  # 智能分流（白名单VPS直连，其他走代理）"
    echo -e "  ${PURPLE}edgeboxctl shunt direct-resi 'http://user:pass@proxy.example.com:8080'${NC}"
    echo -e "  "
    echo -e "  # 白名单管理"
    echo -e "  ${PURPLE}edgeboxctl shunt whitelist add youtube.com${NC}"
    echo -e "  ${PURPLE}edgeboxctl shunt whitelist list${NC}"
    
    echo -e "\n${CYAN}流量预警配置：${NC}"
    echo -e "  ${PURPLE}edgeboxctl alert monthly 500${NC}               # 设置月度500GiB预算"
    echo -e "  ${PURPLE}edgeboxctl alert telegram <token> <chat_id>${NC} # 配置Telegram通知"
    echo -e "  ${PURPLE}edgeboxctl alert discord <webhook_url>${NC}      # 配置Discord通知"
    echo -e "  ${PURPLE}edgeboxctl alert test 80${NC}                    # 模拟80%用量测试"
    
    echo -e "\n${YELLOW}重要提醒：${NC}"
    echo -e "  1. 当前为IP模式，VLESS/Trojan协议需在客户端开启'跳过证书验证'"
    echo -e "  2. 使用 switch-to-domain 可获得受信任的Let's Encrypt证书"
    echo -e "  3. 流量预警配置文件: ${TRAFFIC_DIR}/alert.conf"
    echo -e "  4. 完整安装日志: ${LOG_FILE}"
    echo -e "  5. 系统备份位置: /root/edgebox-backup/"
    echo -e " "
    
    # 显示服务状态摘要
    echo -e "${CYAN}当前服务状态：${NC}"
    local service_ok=0
    for svc in nginx xray sing-box; do
        if systemctl is-active --quiet "$svc"; then
            echo -e "  ✅ $svc: ${GREEN}运行正常${NC}"
            ((service_ok++))
        else
            echo -e "  ❌ $svc: ${RED}服务异常${NC}"
        fi
    done
    
    if [[ $service_ok -eq 3 ]]; then
        echo -e "\n${GREEN}🎊 所有服务运行正常，EdgeBox已就绪！${NC}"
    else
        echo -e "\n${YELLOW}⚠️  部分服务异常，请运行 edgeboxctl status 检查详情${NC}"
    fi
    
    print_separator
}

# 清理函数
cleanup() {
  local rc=$?
  # 只有真错误（rc!=0）才报错
  if (( rc != 0 )); then
    log_error "安装脚本异常退出，退出码: ${rc}。请查看日志：${LOG_FILE}"
    echo -e "\n${RED}安装失败！${NC}"
    echo -e "${YELLOW}故障排除建议：${NC}"
    echo -e "  1. 检查网络连接是否正常"
    echo -e "  2. 确认系统版本支持（Ubuntu 18.04+, Debian 10+）"
    echo -e "  3. 查看详细日志：cat ${LOG_FILE}"
    echo -e "  4. 重试安装：curl -fsSL <安装脚本URL> | bash"
    echo -e "  5. 手动清理：rm -rf /etc/edgebox /var/www/html/traffic"
  fi
  exit $rc
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
        read -p "是否继续？[y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "安装已取消"
            exit 0
        fi
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
    # 设置错误处理
    trap cleanup EXIT
    
    clear
    print_separator
    echo -e "${GREEN}EdgeBox 企业级安装脚本 v3.0.0${NC}"
    echo -e "${CYAN}完整版：SNI定向 + 证书切换 + 出站分流 + 流量统计 + 流量预警 + 备份恢复${NC}"
    print_separator
    
    # 设置版本号环境变量
    export EDGEBOX_VER="3.0.0"
    
    # 创建日志文件
    mkdir -p $(dirname "${LOG_FILE}")
    touch "${LOG_FILE}"
    
    echo -e "${BLUE}正在执行完整安装流程...${NC}"
    
    # 预安装检查
    show_progress 1 20 "执行预安装检查"
    pre_install_check
    
    # 基础安装步骤（模块1）
    show_progress 2 20 "检查系统环境"
    check_root
    check_system  
    
    show_progress 3 20 "获取服务器信息"
    get_server_ip
    
    show_progress 4 20 "安装系统依赖"
    install_dependencies
    
    show_progress 5 20 "生成安全凭据"
    generate_credentials        # 确保在这里生成所有UUID和密码
    
    show_progress 6 20 "创建目录结构"
    create_directories
    
    show_progress 7 20 "配置系统环境"
    check_ports
    configure_firewall
    optimize_system
    
    show_progress 8 20 "生成安全证书"
    generate_self_signed_cert
    
    show_progress 9 20 "安装核心组件"
    install_sing_box
    install_xray
    generate_reality_keys      # 生成Reality密钥
    
    show_progress 10 20 "保存配置信息"
    save_config_info          # 保存所有配置到JSON
    
    show_progress 11 20 "配置网络服务"
    configure_nginx
    configure_xray
    configure_sing_box
    
    # 高级功能安装（模块3-5）
    show_progress 12 20 "安装后台脚本"
    create_dashboard_backend
    
    show_progress 13 20 "配置流量监控"
    setup_traffic_monitoring
    
    show_progress 14 20 "设置定时任务"
    setup_cron_jobs
    
    show_progress 15 20 "配置邮件系统"
    setup_email_system
    
    show_progress 16 20 "创建管理工具"
    create_enhanced_edgeboxctl
    
    show_progress 17 20 "安装初始化服务"
    create_init_script
    
    # 数据生成和服务启动
    show_progress 18 20 "生成订阅配置"
    generate_subscription     # 现在有完整的配置数据
    
    show_progress 19 20 "启动核心服务"
    start_services
    install_ipq_stack
    
    # 启动初始化服务
    systemctl start edgebox-init.service >/dev/null 2>&1 || true
    
    # 等待服务稳定
    sleep 3
    
    show_progress 20 20 "完成数据初始化"
    # 运行一次数据初始化（统一由 dashboard-backend 生成 dashboard/system）
    /etc/edgebox/scripts/traffic-collector.sh || true
    /etc/edgebox/scripts/dashboard-backend.sh --now || true
    
    # 收尾：订阅 + 首刷 + 定时
    finalize_data_generation
    
    # 显示安装信息
    show_installation_info
    
    # 成功退出
    log_success "EdgeBox v3.0.0 安装完成！"
    exit 0
}

# 脚本入口点检查
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # 直接执行脚本
    main "$@"
fi
