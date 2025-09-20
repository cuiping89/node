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
        
# 使用官方安装脚本（多源回退，修复 404）
if curl -fsSL --retry 3 --retry-delay 2 -A "Mozilla/5.0" \
    https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash; then
    log_success "Xray安装完成"
elif curl -fsSL --retry 3 --retry-delay 2 -A "Mozilla/5.0" \
    https://fastly.jsdelivr.net/gh/XTLS/Xray-install@main/install-release.sh | bash; then
    log_success "Xray安装完成（jsdelivr镜像）"
elif curl -fsSL --retry 3 --retry-delay 2 -A "Mozilla/5.0" \
    https://ghproxy.com/https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash; then
    log_success "Xray安装完成（ghproxy镜像）"
else
    log_error "Xray安装失败（安装脚本 404/不可达）"
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
# 解析架构 → sing-box 资产名
local arch="$(uname -m)"
local arch_tag=""
case "$arch" in
  x86_64|amd64)   arch_tag="amd64" ;;
  aarch64|arm64)  arch_tag="arm64" ;;
  armv7l)         arch_tag="armv7" ;;
  armv6l)         arch_tag="armv6" ;;
  i386|i686)      arch_tag="386"  ;;
  *) log_warn "未知架构: $arch，尝试使用 amd64"; arch_tag="amd64" ;;
esac

# 版本优先级：
# 1) 若传入 SING_BOX_VERSION（可带/不带 v），则用它
# 2) 否则 GitHub API releases/latest -> tag_name
# 3) API 不通则解析 releases/latest 页面
# 4) 仍失败回退到保守版本
local ver_raw=""
if [[ -n "${SING_BOX_VERSION:-}" ]]; then
  ver_raw="${SING_BOX_VERSION#v}"
else
  ver_raw="$(
    curl -fsSL \
      -H 'Accept: application/vnd.github+json' \
      -H 'User-Agent: EdgeBox/3.0 (installer)' \
      'https://api.github.com/repos/SagerNet/sing-box/releases/latest' \
      2>/dev/null | jq -r '.tag_name' 2>/dev/null | sed 's/^v//'
  )"
  if [[ -z "$ver_raw" || "$ver_raw" == "null" ]]; then
    ver_raw="$(
      curl -fsSL -H 'User-Agent: Mozilla/5.0 (EdgeBox)' \
        'https://github.com/SagerNet/sing-box/releases/latest' 2>/dev/null \
      | grep -oE 'sing-box-[0-9][0-9.]*-linux-' \
      | head -1 | sed -E 's/sing-box-([0-9.]+)-linux-.*/\1/'
    )"
  fi
  [[ -z "$ver_raw" ]] && ver_raw="1.8.10"
fi
local version="$ver_raw"

# 组合资产与候选 URL（官方 tag、latest/download 双兜底）
local asset="sing-box-${version}-linux-${arch_tag}.tar.gz"
local urls=(
  "https://github.com/SagerNet/sing-box/releases/download/v${version}/${asset}"
  "https://github.com/SagerNet/sing-box/releases/latest/download/${asset}"
)

# 支持可选代理（如果你设置了 GH_PROXY=你的中转前缀）
if [[ -n "${GH_PROXY:-}" ]]; then
  urls=("${GH_PROXY%/}/SagerNet/sing-box/releases/download/v${version}/${asset}" \
        "${GH_PROXY%/}/SagerNet/sing-box/releases/latest/download/${asset}" \
        "${urls[@]}")
fi

# 下载（多地址重试）
local temp_file="/tmp/${asset}"
rm -f "$temp_file"
local ok=0
for u in "${urls[@]}"; do
  log_info "下载 sing-box: $u"
  if curl -fL -A "Mozilla/5.0 (EdgeBox Installer)" --retry 3 --retry-delay 2 -o "$temp_file" "$u"; then
    ok=1; break
  else
    log_warn "下载失败: $u"
  fi
done
[[ "$ok" -ne 1 ]] && { log_error "所有 sing-box 下载地址均失败"; return 1; }

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
  "tcp::80:nginx"
  "tcp::443:nginx"
  "udp::443:sing-box"
  "udp::2053:sing-box"
  "tcp:127.0.0.1:11443:xray"  # Reality
  "tcp:127.0.0.1:10085:xray"  # gRPC
  "tcp:127.0.0.1:10086:xray"  # WS
  "tcp:127.0.0.1:10143:xray"  # Trojan
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
    # [FIX:PORT_PARSE_COMPAT] 支持三段式 “tcp:80:nginx” → 四段含义
    if [[ -z "$proc" ]]; then
        proc="$port"; port="$addr"; addr="";
    fi

    local cmd=""
    if [[ "$addr" == "127.0.0.1" ]]; then
        cmd="ss -H -tlnp sport = :$port and src = $addr" # 仅限TCP和本地回环
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
    # [FIX:PORT_PARSE_COMPAT] 同上：三段式兼容
    if [[ -z "$proc" ]]; then
        proc="$port"; port="$addr"; addr="";
    fi

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
    # 获取服务器信息和订阅链接
    local server_ip cert_mode domain
    server_ip=$(safe_jq '.server_ip' "$SERVER_JSON" "")
    cert_mode=$(get_current_cert_mode 2>/dev/null || echo "self-signed")
    
    if [[ "$cert_mode" == "self-signed" ]]; then
        domain="$server_ip"
    else
        domain="${cert_mode##*:}"
    fi
    
    # 获取凭据信息
    local uuid_vless reality_public_key reality_short_id
    local uuid_tuic password_hysteria2 password_tuic password_trojan
    
    uuid_vless=$(safe_jq '.uuid.vless.reality // .uuid.vless' "$SERVER_JSON" "")
    uuid_tuic=$(safe_jq '.uuid.tuic' "$SERVER_JSON" "")
    password_hysteria2=$(safe_jq '.password.hysteria2' "$SERVER_JSON" "")
    password_tuic=$(safe_jq '.password.tuic' "$SERVER_JSON" "")
    password_trojan=$(safe_jq '.password.trojan' "$SERVER_JSON" "")
    reality_public_key=$(safe_jq '.reality.public_key' "$SERVER_JSON" "")
    reality_short_id=$(safe_jq '.reality.short_id' "$SERVER_JSON" "")
    
    # URL编码密码
    local hy2_pw_enc tuic_pw_enc trojan_pw_enc
    hy2_pw_enc=$(printf '%s' "$password_hysteria2" | jq -rR @uri)
    tuic_pw_enc=$(printf '%s' "$password_tuic" | jq -rR @uri)
    trojan_pw_enc=$(printf '%s' "$password_trojan" | jq -rR @uri)
    
    # 检查端口监听状态（保持原有逻辑）
    local reality_status="未监听" grpc_status="未监听" ws_status="未监听" trojan_status="未监听"
    local udp443_status="未监听" udp2053_status="未监听"
    
    ss -tlnp 2>/dev/null | grep -q ":11443.*xray" && reality_status="运行中"
    ss -tlnp 2>/dev/null | grep -q ":10085.*xray" && grpc_status="运行中"  
    ss -tlnp 2>/dev/null | grep -q ":10086.*xray" && ws_status="运行中"
    ss -tlnp 2>/dev/null | grep -q ":10143.*xray" && trojan_status="运行中"
    ss -ulnp 2>/dev/null | grep -q ":443.*sing-box" && udp443_status="运行中"
    ss -ulnp 2>/dev/null | grep -q ":2053.*sing-box" && udp2053_status="运行中"
    
    # 生成协议数组，包含share_link
    cat <<EOF
[
  {
    "name": "VLESS-Reality",
    "scenario": "抗审查",
    "camouflage": "真实网站",
    "status": "$reality_status",
    "port": 443,
    "network": "tcp",
    "share_link": "vless://${uuid_vless}@${server_ip}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&pbk=${reality_public_key}&sid=${reality_short_id}&type=tcp#EdgeBox-REALITY"
  },
  {
    "name": "VLESS-gRPC",
    "scenario": "CDN加速",
    "camouflage": "HTTP/2",
    "status": "$grpc_status",
    "port": 443,
    "network": "tcp",
    "share_link": "vless://${uuid_vless}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=h2&type=grpc&serviceName=grpc&fp=chrome#EdgeBox-gRPC"
  },
  {
    "name": "VLESS-WebSocket",
    "scenario": "CDN加速",
    "camouflage": "WebSocket",
    "status": "$ws_status",
    "port": 443,
    "network": "tcp",
    "share_link": "vless://${uuid_vless}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome#EdgeBox-WS"
  },
  {
    "name": "Trojan-TLS",
    "scenario": "经典伪装",
    "camouflage": "HTTPS",
    "status": "$trojan_status",
    "port": 443,
    "network": "tcp",
    "share_link": "trojan://${trojan_pw_enc}@${domain}:443?security=tls&sni=trojan.${domain}&alpn=http%2F1.1&fp=chrome#EdgeBox-TROJAN"
  },
  {
    "name": "Hysteria2",
    "scenario": "高性能",
    "camouflage": "QUIC",
    "status": "$udp443_status",
    "port": 443,
    "network": "udp",
    "share_link": "hysteria2://${hy2_pw_enc}@${domain}:443?sni=${domain}&alpn=h3#EdgeBox-HYSTERIA2"
  },
  {
    "name": "TUIC",
    "scenario": "低延迟",
    "camouflage": "QUIC",
    "status": "$udp2053_status",
    "port": 2053,
    "network": "udp",
    "share_link": "tuic://${uuid_tuic}:${tuic_pw_enc}@${domain}:2053?congestion_control=bbr&alpn=h3&sni=${domain}#EdgeBox-TUIC"
  }
]
EOF
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
        # 直接用 system.server_ip 拼接订阅地址（80端口走HTTP）
        subscription_url: ("http://" + $system.server_ip + "/sub"),
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
	
# 创建favicon.ico避免404错误
touch "${WEB_ROOT:-/var/www/html}/favicon.ico"
    
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
	
	# 添加示例数据避免图表空白
for i in {6..0}; do
    echo "$(date -d "$i days ago" '+%Y-%m-%d'),0.1,0.05,0.15,0.08" >> "${log_dir}/daily.csv"
done
echo "$(date '+%Y-%m'),2.1,1.5,3.6,1.8" >> "${log_dir}/monthly.csv"
    
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
    
	# 修复favicon.ico 404错误
touch "/var/www/html/favicon.ico"
log_info "已创建favicon.ico文件"

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

  # ========== 创建外置的CSS文件 ==========
  log_info "创建外置CSS文件..."
  cat > "${TRAFFIC_DIR}/assets/edgebox-panel.css" <<'EXTERNAL_CSS'
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: #f3f4f6;
  min-height: 100vh;
  padding: 20px;
  color: #1f2937;
}

.container {
  max-width: 1400px;
  margin: 0 auto;
}

/* === 文字系统（严格遵循规范）=== */
h1 {
  font-size: 23px;
  font-weight: 700;
  color: #1f2937;
  line-height: 32px;
}

h2 {
  font-size: 18px;
  font-weight: 600;
  color: #1f2937;
  line-height: 26px;
}

h3 {
  font-size: 15px;
  font-weight: 600;
  color: #1f2937;
  line-height: 22px;
}

h4 {
  font-size: 14px;
  font-weight: 500;
  color: #1f2937;
  line-height: 20px;
}

body, p, span, td, div {
  font-size: 13px;
  font-weight: 500;
  color: #1f2937;
  line-height: 20px;
}

.text-muted {
  color: #6b7280;
}

.text-secondary {
  color: #4b5563;
}

/* === 卡片系统（增强层次感）=== */
.main-card {
  background: #ffffff;
  border: 1px solid #d1d5db;
  border-radius: 10px;
  box-shadow: 0 2px 6px rgba(0,0,0,0.08);
  overflow: hidden;
}

.main-header {
  background: linear-gradient(135deg, #5e72e4 0%, #825ee4 100%);
  color: white;
  padding: 20px 30px;
  text-align: center;
}

.main-header h1 {
  color: white;
  margin: 0;
}

.main-content {
  padding: 20px;
}

.card {
  background: #ffffff;
  border: 1px solid #d1d5db;
  border-radius: 10px;
  box-shadow: 0 2px 6px rgba(0,0,0,0.08);
  padding: 20px;
  margin-bottom: 20px;
  transition: box-shadow 0.2s;
}

.card:hover {
  box-shadow: 0 4px 8px rgba(0,0,0,0.08);
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
}

.card-note {
  font-size: 11px;
  color: #6b7280;
  font-weight: 400;
}

/* === 内层区块（更新背景色）=== */
.inner-block {
  background: #f5f5f5;
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  padding: 15px;
  margin-bottom: 15px;
}

.inner-block:last-child {
  margin-bottom: 0;
}

.inner-block h3 {
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid #e5e7eb;
}

/* === 网格系统 === */
.grid {
  display: grid;
  gap: 20px;
}

.grid-3 {
  grid-template-columns: repeat(3, 1fr);
}

.grid-1-2 {
  grid-template-columns: 1fr 2fr;
}

/* === 信息项 === */
.info-item {
  display: flex;
  padding: 6px 0;
  align-items: flex-start;
}

.info-item label {
  color: #6b7280;
  min-width: 70px;
  flex-shrink: 0;
}

.info-item value {
  color: #1f2937;
  font-weight: 500;
  flex: 1;
  display: block;
}

/* === 进度条 === */
.progress-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}

.progress-label {
  min-width: 40px;
  color: #4b5563;
}

.progress-bar {
  flex: 1;
  height: 18px;
  background: #e5e7eb;
  border-radius: 9px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: #10b981;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 11px;
  transition: width 0.3s;
}

.progress-info {
  min-width: 80px;
  text-align: right;
  color: #6b7280;
  font-size: 12px;
}

/* === 服务状态 === */
.service-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
}

.service-status {
  display: flex;
  align-items: center;
  gap: 8px;
}

.status-badge {
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  background: #f3f4f6;
  color: #6b7280;
}

.status-running {
  background: #d1fae5;
  color: #10b981;
}

.version {
  color: #6b7280;
  font-size: 11px;
}

/* === 证书切换 === */
.cert-modes {
  display: flex;
  gap: 5px;
  margin-bottom: 2px;
}

.cert-mode-tab {
  flex: 1;
  padding: 10px;
  background: #f5f5f5;
  border: 1px solid #e5e7eb;
  color: #6b7280;
  text-align: center;
  border-radius: 8px;
  cursor: default;
}

.cert-mode-tab.active {
  background: #10b981;
  color: white;
  border-color: #10b981;
}

/* === 网络身份配置 === */
.network-blocks {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 15px;
}

.network-block {
  background: #f5f5f5;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 12px;
  position: relative;
}

.network-block h3 {
  margin: -12px -12px 12px -12px;
  padding: 10px;
  background: #f3f4f6;
  color: #6b7280;
  border-radius: 8px 8px 0 0;
  text-align: center;
  border: none;
}

.network-block.active h3 {
  background: #10b981;
  color: white;
}

.note-udp {
  font-size: 11px;
  font-weight: 400;
  color: #6b7280;
  white-space: nowrap;
  margin-left: 8px;
}

/* === 白名单专用样式 === */
.whitelist-container {
  position: relative;
  width: 100%;
}

.whitelist-preview {
  position: relative;
  line-height: 22px;
  max-height: 66px;
  overflow: hidden;
  padding-right: 90px;
}

.whitelist-text {
  font-size: 13px;
  line-height: 22px;
  color: #374151;
  word-break: break-word;
  display: inline;
}

.whitelist-more {
  position: absolute;
  right: 0;
  bottom: 0;
  height: 28px;
  line-height: 26px;
  padding: 0 12px;
  font-size: 12px;
  background: #ffffff;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  color: #2563eb;
  cursor: pointer;
  transition: all 0.2s;
}

.whitelist-more:hover {
  background: #f3f4f6;
  border-color: #9ca3af;
  color: #1d4ed8;
}

/* === 统一的按钮样式 === */
.btn-link,
.link {
  display: inline-block;
  height: 28px;
  line-height: 26px;
  padding: 0 12px;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  background: #ffffff;
  font-size: 12px;
  color: #2563eb;
  cursor: pointer;
  text-decoration: none;
  transition: all 0.2s;
}

.btn-link:hover,
.link:hover {
  background: #f3f4f6;
  border-color: #9ca3af;
  color: #1d4ed8;
}

/* === 表格 === */
.data-table {
  width: 100%;
  border-collapse: collapse;
}

.data-table th {
  background: #f5f5f5;
  color: #4b5563;
  font-weight: 500;
  padding: 10px;
  text-align: left;
  font-size: 12px;
  border-bottom: 1px solid #e5e7eb;
}

.data-table td {
  padding: 10px;
  border-bottom: 1px solid #f3f4f6;
  font-size: 12px;
}

.data-table td:nth-child(4),
.data-table td:nth-child(5),
.data-table td:nth-child(6) {
  text-align: center;
}

.data-table th:nth-child(4),
.data-table th:nth-child(5),
.data-table th:nth-child(6) {
  text-align: center;
}

.data-table tr:hover td {
  background: #f5f5f5;
}

.data-table tr.subs-row td {
  background: #f5f5f5;
}

/* === 流量统计 === */
.traffic-card {
  position: relative;
}

.traffic-progress-container {
  position: absolute;
  top: 16px;
  right: 16px;
  width: 320px;
  font-size: .75rem;
  display: flex;
  align-items: center;
  gap: 8px;
}

.progress-label {
  color: #6b7280;
  white-space: nowrap;
}

.progress-wrapper {
  flex: 1;
  position: relative;
}

.progress-bar {
  width: 100%;
  height: 22px;
  background: #e2e8f0;
  border-radius: 8px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: #10b981;
  border-radius: 8px;
  transition: width .3s;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

.progress-percentage {
  position: absolute;
  color: #fff;
  font-size: .65rem;
  font-weight: 600;
}

.progress-budget {
  color: #6b7280;
  white-space: nowrap;
  font-size: .7rem;
}

.traffic-charts {
  display: grid;
  grid-template-columns: 7fr 3fr;
  gap: 16px;
  margin-top: 50px;
}

.chart-container {
  position: relative;
  height: 360px;
}

@media (max-width: 980px) {
  .traffic-charts {
    grid-template-columns: 1fr;
  }
  .traffic-progress-container {
    position: static;
    width: 100%;
    margin-bottom: 16px;
  }
}

/* === 运维管理 === */
.commands-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
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

.command-section h4 {
  margin: 0 0 8px 0;
  font-size: .9rem;
  font-weight: 600;
  color: #1e293b;
  display: flex;
  align-items: center;
  gap: 6px;
}

.command-list {
  font-size: .8rem;
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
  color: #6b7280;
  margin-left: 8px;
}

/* === 按钮系统 === */
.btn {
  padding: 8px 16px;
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.2s;
  background: #10b981;
  color: white;
}

.btn:hover {
  background: #0ea37a;
}

.btn-sm {
  padding: 5px 10px;
  font-size: 11px;
}

.btn-secondary {
  background: white;
  color: #1f2937;
  border-color: #d1d5db;
}

.btn-secondary:hover {
  background: #f3f4f6;
}

/* === 统一的弹窗样式 === */
.modal {
  display: none;
  position: fixed;
  z-index: 1000;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.5);
}

.modal-content {
  background-color: #fff;
  margin: 5% auto;
  padding: 0;
  border: 1px solid #d1d5db;
  border-radius: 12px;
  width: 720px;
  max-width: 92%;
  box-shadow: 0 12px 24px rgba(0, 0, 0, 0.14);
}

.modal-header {
  padding: 20px;
  border-bottom: 1px solid #e5e7eb;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.modal-header h3 {
  margin: 0;
  border: none;
  padding: 0;
}

.close-btn {
  font-size: 16px;
  color: #64748b;
  cursor: pointer;
  width: 28px;
  height: 28px;
  line-height: 28px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
  border: 1px solid #e5e7eb;
  background: #fff;
  transition: all 0.2s;
}

.close-btn:hover {
  background: #f8fafc;
  color: #0f172a;
}

.modal-body {
  padding: 20px;
  max-height: 560px;
  overflow: auto;
}

.modal-footer {
  padding: 15px 20px;
  border-top: 1px solid #e5e7eb;
  text-align: right;
}

.modal-body::-webkit-scrollbar {
  width: 8px;
}

.modal-body::-webkit-scrollbar-track {
  background: #f1f1f1;
  border-radius: 4px;
}

.modal-body::-webkit-scrollbar-thumb {
  background: #888;
  border-radius: 4px;
}

.modal-body::-webkit-scrollbar-thumb:hover {
  background: #555;
}

body.modal-open {
  overflow: hidden;
}

/* === 其他组件 === */
.ipq-link {
  color: #3b82f6;
  cursor: pointer;
  margin-left: 10px;
}

.ipq-link:hover {
  text-decoration: underline;
}

.whitelist-item {
  background: white;
  padding: 5px 10px;
  margin: 2px 0;
  border-radius: 4px;
  font-family: monospace;
  font-size: 12px;
}

/* === 管理命令 === */
.management-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 20px;
}

.management-commands {
  background: #f5f5f5;
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  padding: 15px;
}

.command-item {
  margin-bottom: 10px;
  font-size: 12px;
}

.command-item code {
  background: #1f2937;
  color: #10b981;
  padding: 3px 8px;
  border-radius: 4px;
  font-family: monospace;
  display: inline-block;
  margin-bottom: 2px;
}

/* === 流量统计 === */
.traffic-summary {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 15px;
  margin-bottom: 20px;
}

.traffic-stat {
  background: #f5f5f5;
  padding: 15px;
  border-radius: 8px;
  text-align: center;
}

.traffic-stat h4 {
  margin-bottom: 8px;
}

.traffic-stat .value {
  font-size: 24px;
  font-weight: bold;
  color: #1f2937;
}

.traffic-stat .unit {
  font-size: 14px;
  color: #6b7280;
}

/* === 配置详情 === */
.config-section {
  margin-bottom: 20px;
}

.config-section h4 {
  margin-bottom: 12px;
}

.config-code {
  background: #f5f5f5;
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  padding: 12px;
  font-family: monospace;
  font-size: 12px;
  color: #1f2937;
  word-break: break-all;
  line-height: 1.6;
}

.config-help {
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  padding: 12px;
  font-size: 12px;
  line-height: 1.8;
  color: #4b5563;
}

.json-config {
  background: #f5f5f5;
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  padding: 12px;
}

.json-line {
  font-family: monospace;
  font-size: 12px;
  line-height: 1.8;
  display: flex;
  justify-content: space-between;
  padding: 2px 0;
}

.json-key {
  color: #3b82f6;
}

.json-value {
  color: #10b981;
}

.json-comment {
  color: #6b7280;
  font-style: italic;
}

.qr-container {
  text-align: center;
  padding: 20px;
  background: #f5f5f5;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.qr-placeholder {
  width: 256px;
  height: 256px;
  margin: 0 auto;
  background: white;
  border: 1px solid #e5e7eb;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #6b7280;
}

/* 轻提示 toast */
.toast {
  position: fixed;
  left: 50%;
  bottom: 60px;
  transform: translateX(-50%);
  background: rgba(0, 0, 0, .75);
  color: #fff;
  padding: 10px 16px;
  border-radius: 8px;
  font-size: 13px;
  opacity: 0;
  transition: opacity .2s ease, transform .2s ease;
  pointer-events: none;
  z-index: 2000;
}

.toast.show {
  opacity: 1;
  transform: translateX(-50%) translateY(0);
}

.toast-warn {
  background: rgba(220, 38, 38, .9);
}

/* 响应式 */
@media (max-width: 1024px) {
  .grid-3,
  .grid-1-2 {
    grid-template-columns: 1fr;
  }
  
  .network-blocks {
    grid-template-columns: 1fr;
  }
  
  .traffic-charts {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 768px) {
  .traffic-summary {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .management-grid {
    grid-template-columns: 1fr;
  }
  
  .modal-content {
    width: 95%;
    margin: 10px auto;
  }
}
EXTERNAL_CSS

  # ========== 创建外置的JavaScript文件 ==========
  log_info "创建外置JavaScript文件..."

cat > "${TRAFFIC_DIR}/assets/edgebox-panel.js" <<'EXTERNAL_JS'
// =================================================================
// EdgeBox Panel v3.0 - Fixed JavaScript 
// =================================================================

// --- Global State ---
let dashboardData = {};
let trafficData = {};
let systemData = {};
let overviewTimer = null;
const GiB = 1024 ** 3;

// --- Chart.js Y轴单位插件 ---
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

// --- Utility Functions ---
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

function safeGet(obj, path, fallback = '—') {
  const value = path.split('.').reduce((acc, part) => acc && acc[part], obj);
  return value !== null && value !== undefined && value !== '' ? value : fallback;
}

function escapeHtml(s = '') {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function notify(msg, type = 'ok', ms = 1500) {
  const host = document.querySelector('#configModal.modal[style*="block"] .modal-content') || document.body;
  const tip = document.createElement('div');
  tip.className = `toast toast-${type}`;
  tip.textContent = msg;
  host.appendChild(tip);
  requestAnimationFrame(() => tip.classList.add('show'));
  setTimeout(() => {
    tip.classList.remove('show');
    setTimeout(() => tip.remove(), 300);
  }, ms);
}

// --- UI Rendering Functions ---

// 修复 renderOverview 函数中的服务状态渲染
function renderOverview() {
  const server = dashboardData.server || {};
  const services = dashboardData.services || {};
  
  // Server Info
  const serverNameEl = document.getElementById('server-name');
  const cloudInfoEl = document.getElementById('cloud-info');
  const instanceIdEl = document.getElementById('instance-id');
  const hostnameEl = document.getElementById('hostname');
  
  if (serverNameEl) serverNameEl.textContent = safeGet(server, 'user_alias', '(未设置)');
  if (cloudInfoEl) cloudInfoEl.textContent = `${safeGet(server, 'cloud.provider', '—')} | ${safeGet(server, 'cloud.region', '—')}`;
  if (instanceIdEl) instanceIdEl.textContent = safeGet(server, 'instance_id', '—');
  if (hostnameEl) hostnameEl.textContent = safeGet(server, 'hostname', '—');

  // Server Spec & System Metrics
  const spec = server.spec || {};
  const cpuInfoEl = document.getElementById('cpu-info');
  const memInfoEl = document.getElementById('mem-info');
  const diskInfoEl = document.getElementById('disk-info');
  
  if (cpuInfoEl) cpuInfoEl.textContent = safeGet(spec, 'cpu', '—');
  if (memInfoEl) memInfoEl.textContent = safeGet(spec, 'memory', '—');
  if (diskInfoEl) diskInfoEl.textContent = safeGet(spec, 'disk', '—');
  
  const metrics = systemData || {};
  const cpuPct = metrics.cpu || 0;
  const memPct = metrics.memory || 0;
  const diskPct = metrics.disk || 0;
  
  const cpuProgress = document.getElementById('cpu-progress');
  const memProgress = document.getElementById('mem-progress');
  const diskProgress = document.getElementById('disk-progress');
  
  if (cpuProgress) {
    cpuProgress.style.width = `${cpuPct}%`;
    cpuProgress.textContent = `${cpuPct}%`;
  }
  if (memProgress) {
    memProgress.style.width = `${memPct}%`;
    memProgress.textContent = `${memPct}%`;
  }
  if (diskProgress) {
    diskProgress.style.width = `${diskPct}%`;
    diskProgress.textContent = `${diskPct}%`;
  }

  // Services - 修复服务状态显示
  const serviceMap = {
    'nginx': 'nginx',
    'xray': 'xray',
    'sing-box': 'singbox'  // sing-box 映射到 singbox
  };
  
  Object.entries(serviceMap).forEach(([svcKey, elemId]) => {
    const status = safeGet(services, `${svcKey}.status`, 'inactive');
    const version = safeGet(services, `${svcKey}.version`, '—');
    
    const statusEl = document.getElementById(`${elemId}-status`);
    const versionEl = document.getElementById(`${elemId}-version`);
    
    if (statusEl) {
      statusEl.textContent = status === 'active' ? '运行中' : '已停止';
      statusEl.className = status === 'active' ? 'status-badge status-running' : 'status-badge';
    }
    if (versionEl) {
      versionEl.textContent = version;
    }
  });

  // Footer Info
  const versionEl = document.getElementById('version');
  const installDateEl = document.getElementById('install-date');
  const updateTimeEl = document.getElementById('update-time');
  
  if (versionEl) versionEl.textContent = safeGet(server, 'version', '—');
  if (installDateEl) installDateEl.textContent = safeGet(server, 'install_date', '—');
  if (updateTimeEl) {
    const updateTime = dashboardData.updated_at ? new Date(dashboardData.updated_at) : new Date();
    updateTimeEl.textContent = updateTime.toLocaleString('zh-CN');
  }
}


function renderCertificateAndNetwork() {
    const cert = dashboardData.server?.cert || {};
    const shunt = dashboardData.shunt || {};

    // Certificate 部分保持不变
    const certMode = safeGet(cert, 'mode', 'self-signed');
    document.getElementById('cert-self').classList.toggle('active', certMode === 'self-signed');
    document.getElementById('cert-ca').classList.toggle('active', certMode.startsWith('letsencrypt'));
    document.getElementById('cert-type').textContent = certMode.startsWith('letsencrypt') ? "Let's Encrypt" : "自签名";
    document.getElementById('cert-domain').textContent = safeGet(cert, 'domain', '(无)');
    document.getElementById('cert-renewal').textContent = certMode.startsWith('letsencrypt') ? '自动' : '手动';
    document.getElementById('cert-expiry').textContent = safeGet(cert, 'expires_at') ? new Date(cert.expires_at).toLocaleDateString() : '—';

    // Network Identity 部分保持不变
    const shuntMode = String(safeGet(shunt, 'mode', 'vps')).toLowerCase();
    
    ['net-vps', 'net-proxy', 'net-shunt'].forEach(id => {
        const elem = document.getElementById(id);
        if (elem) elem.classList.remove('active');
    });
    
    if (shuntMode === 'vps') {
        const elem = document.getElementById('net-vps');
        if (elem) elem.classList.add('active');
    } else if (shuntMode.includes('resi') && !shuntMode.includes('direct')) {
        const elem = document.getElementById('net-proxy');
        if (elem) elem.classList.add('active');
    } else if (shuntMode.includes('direct')) {
        const elem = document.getElementById('net-shunt');
        if (elem) elem.classList.add('active');
    } else {
        const elem = document.getElementById('net-vps');
        if (elem) elem.classList.add('active');
    }
    
    // 更新IP和其他信息
    const vpsIpEl = document.getElementById('vps-ip');
    const proxyIpEl = document.getElementById('proxy-ip');
    if (vpsIpEl) vpsIpEl.textContent = safeGet(dashboardData, 'server.eip') || safeGet(dashboardData, 'server.server_ip', '—');
    if (proxyIpEl) proxyIpEl.textContent = safeGet(shunt, 'proxy_info', '(未配置)');
    
    // 修复白名单显示 - 关键部分
    const whitelist = shunt.whitelist || [];
    const previewEl = document.getElementById('whitelistPreview');
    
    if (previewEl) {
        if (whitelist.length > 0) {
            // 将所有白名单项用逗号连接
            const allItems = whitelist.join(', ');
            
            // 创建HTML内容
            let htmlContent = `<span class="whitelist-text">${escapeHtml(allItems)}</span>`;
            
            // 添加查看全部按钮
            htmlContent += `<button class="whitelist-more" data-action="open-modal" data-modal="whitelist">查看全部(${whitelist.length})</button>`;
            
            previewEl.innerHTML = htmlContent;
        } else {
            previewEl.innerHTML = '<span class="whitelist-text">暂无白名单</span>';
        }
    }
}


function renderProtocolTable() {
    const protocols = dashboardData.protocols || [];
    const tbody = document.getElementById('protocol-tbody');
    if (!tbody) return;

    const rows = protocols.map(p => `
        <tr>
            <td>${escapeHtml(p.name)}</td>
            <td>${escapeHtml(p.scenario)}</td>
            <td>${escapeHtml(p.camouflage)}</td>
            <td><span class="status-badge ${p.status === '运行中' ? 'status-running' : ''}">${p.status}</span></td>
            <td><button class="btn btn-sm btn-link" data-action="open-modal" data-modal="config" data-protocol="${escapeHtml(p.name)}">查看配置</button></td>
        </tr>
    `).join('');

    const subRow = `
        <tr class="subs-row">
            <td style="font-weight:500;">整包订阅链接</td>
            <td>所有协议</td>
            <td>通用</td>
            <td></td>
            <td><button class="btn btn-sm btn-link" data-action="open-modal" data-modal="config" data-protocol="__SUBS__">查看/复制</button></td>
        </tr>
    `;

    tbody.innerHTML = rows + subRow;
}

function renderTrafficCharts() {
    if (!trafficData || !window.Chart) return;
    
    // Traffic progress bar
    const monthly = trafficData.monthly || [];
    const currentMonth = new Date().toISOString().slice(0, 7);
    const thisMonth = monthly.find(m => m.month === currentMonth);
    
    if (thisMonth) {
        const budget = 100; // GiB
        const used = (thisMonth.total || 0) / GiB;
        const percentage = Math.min(100, Math.round((used / budget) * 100));
        
        const fillEl = document.getElementById('progress-fill');
        const pctEl = document.getElementById('progress-percentage');
        const budgetEl = document.getElementById('progress-budget');
        
        if (fillEl) {
            fillEl.style.width = `${percentage}%`;
            if (percentage >= 90) fillEl.style.background = '#ef4444';
            else if (percentage >= 60) fillEl.style.background = '#f59e0b';
            else fillEl.style.background = '#10b981';
        }
        if (pctEl) pctEl.textContent = `${percentage}%`;
        if (budgetEl) budgetEl.textContent = `${used.toFixed(1)}/${budget}GiB`;
    }
    
    // Clear existing charts
    ['traffic', 'monthly-chart'].forEach(id => {
        const chartInstance = Chart.getChart(id);
        if (chartInstance) chartInstance.destroy();
    });

    const daily = trafficData.last30d || [];

    // 30-day Chart
    if (daily.length) {
        new Chart('traffic', {
            type: 'line',
            data: {
                labels: daily.map(d => d.date.slice(5)),
                datasets: [
                    { label: 'VPS 出口', data: daily.map(d => d.vps / GiB), borderColor: '#3b82f6', tension: 0.3 },
                    { label: '住宅出口', data: daily.map(d => d.resi / GiB), borderColor: '#f59e0b', tension: 0.3 }
                ]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } },
            plugins: [ebYAxisUnitTop]
        });
    }

    // 12-month Chart
    if (monthly.length) {
        const recentMonthly = monthly.slice(-12);
        new Chart('monthly-chart', {
            type: 'bar',
            data: {
                labels: recentMonthly.map(m => m.month),
                datasets: [
                    { label: 'VPS出口', data: recentMonthly.map(m => m.vps / GiB), backgroundColor: '#3b82f6', stack: 'a' },
                    { label: '住宅出口', data: recentMonthly.map(m => m.resi / GiB), backgroundColor: '#f59e0b', stack: 'a' }
                ]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } }, scales: { x: { stacked: true }, y: { stacked: true } } },
            plugins: [ebYAxisUnitTop]
        });
    }
}

// --- Modal and Interaction Logic ---

function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        document.body.classList.add('modal-open');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        document.body.classList.remove('modal-open');
    }
}

// 点击遮罩关闭
window.addEventListener('click', (e) => {
  if (e.target && e.target.classList && e.target.classList.contains('modal')) {
    closeModal(e.target.id);
  }
});

function showWhitelistModal() {
    const list = document.getElementById('whitelistList');
    const whitelist = dashboardData.shunt?.whitelist || [];
    
    if (list) {
        if (whitelist.length > 0) {
            // 将白名单显示为逗号分隔的连续文本
            list.innerHTML = `
                <div class="config-section">
                    <div class="config-code" style="white-space: normal; word-break: break-word;">
                        ${escapeHtml(whitelist.join(', '))}
                    </div>
                </div>
            `;
        } else {
            list.innerHTML = '<p style="text-align: center; color: #6b7280;">暂无白名单数据</p>';
        }
    }
    
    showModal('whitelistModal');
}

// 完整修复的showConfigModal函数
function showConfigModal(key) {
  const modal = document.getElementById('configModal');
  const title = document.getElementById('configModalTitle');
  const details = document.getElementById('configDetails');
  if (!modal || !title || !details) return;

  // 清空内容
  details.innerHTML = '';

  if (key === '__SUBS__') {
    // 整包订阅
    const sub = dashboardData.subscription || {};
    const plainLinks = sub.plain || '';
    const base64All = sub.base64 || '';
    const base64Lines = sub.b64_lines || '';
    const subUrl = dashboardData.subscription_url || `http://${dashboardData.server?.server_ip}/sub`;
    
    title.textContent = '整包订阅链接 - 客户端配置详情';
    
    details.innerHTML = `
      <div class="config-section">
        <h4>订阅地址</h4>
        <div class="config-code" id="sub-url">${escapeHtml(subUrl)}</div>
      </div>
      
      <div class="config-section">
        <h4>明文链接（6个协议）</h4>
        <div class="config-code" id="plain-link" style="white-space: pre-wrap;">${escapeHtml(plainLinks)}</div>
      </div>

      <div class="config-section">
        <h4>Base64编码（整包）</h4>
        <div class="config-code" id="base64-link" style="word-break: break-all;">${escapeHtml(base64All)}</div>
      </div>

      <div class="config-section">
        <h4>Base64编码（逐行）</h4>
        <div class="config-code" id="b64lines-link" style="white-space: pre-wrap;">${escapeHtml(base64Lines)}</div>
      </div>

      <div class="config-section">
        <h4>二维码</h4>
        <div class="qr-container" id="qrcode"></div>
      </div>

      <div class="config-section">
        <h4>使用说明</h4>
        <div class="config-help">
          1. 推荐复制"订阅地址"到客户端订阅功能<br>
          2. 或复制"明文链接"逐个导入<br>
          3. 支持 V2rayN、Clash、Shadowrocket、Surge 等主流客户端<br>
          4. 自签证书需在客户端开启"跳过证书验证"<br>
          5. UDP协议（Hysteria2/TUIC）固定走VPS直连
        </div>
      </div>
    `;
    
    // 生成订阅地址的二维码
    setTimeout(() => {
      const qrEl = document.getElementById('qrcode');
      if (qrEl && subUrl && window.QRCode) {
        qrEl.innerHTML = '';
        new QRCode(qrEl, {
          text: subUrl,
          width: 256,
          height: 256,
          colorDark: "#000000",
          colorLight: "#ffffff",
          correctLevel: QRCode.CorrectLevel.H
        });
      }
    }, 100);
    
  } else {
    // 单个协议
    const protocols = dashboardData.protocols || [];
    const protocol = protocols.find(p => p.name === key);
    if (!protocol) {
      notify('未找到协议配置', 'warn');
      return;
    }
    
    title.textContent = `${protocol.name} - 客户端配置详情`;
    
    const shareLink = protocol.share_link || '';
    const jsonConfig = generateProtocolJSON(protocol);
    const base64Link = shareLink ? btoa(shareLink) : '';
    
    details.innerHTML = `
      <div class="config-section">
        <h4>明文链接</h4>
        <div class="config-code" id="plain-link" style="word-break: break-all;">${escapeHtml(shareLink)}</div>
      </div>

      <div class="config-section">
        <h4>JSON配置（V2ray格式）</h4>
        <div class="config-code" id="json-code" style="white-space: pre-wrap;">${escapeHtml(jsonConfig)}</div>
      </div>

      <div class="config-section">
        <h4>Base64编码</h4>
        <div class="config-code" id="base64-link" style="word-break: break-all;">${escapeHtml(base64Link)}</div>
      </div>

      <div class="config-section">
        <h4>二维码</h4>
        <div class="qr-container" id="qrcode"></div>
      </div>

      <div class="config-section">
        <h4>使用说明</h4>
        <div class="config-help">
          协议: ${protocol.name}<br>
          端口: ${protocol.port} (${protocol.network})<br>
          场景: ${protocol.scenario}<br>
          伪装: ${protocol.camouflage}<br>
          <br>
          1. 复制"明文链接"导入客户端<br>
          2. 或使用JSON配置手动添加<br>
          3. 移动端可扫描二维码导入
        </div>
      </div>
    `;
    
    // 生成二维码
    setTimeout(() => {
      const qrEl = document.getElementById('qrcode');
      if (qrEl && shareLink && window.QRCode) {
        qrEl.innerHTML = '';
        new QRCode(qrEl, {
          text: shareLink,
          width: 256,
          height: 256,
          colorDark: "#000000",
          colorLight: "#ffffff",
          correctLevel: QRCode.CorrectLevel.H
        });
      }
    }, 100);
  }

  showModal('configModal');
}

// 生成协议JSON配置
function generateProtocolJSON(protocol) {
  const server = dashboardData.server || {};
  const secrets = dashboardData.secrets || {};
  const serverIp = server.server_ip || '127.0.0.1';
  
  try {
    switch(protocol.name) {
      case 'VLESS-Reality':
        return JSON.stringify({
          "v": "2",
          "ps": "EdgeBox-REALITY",
          "add": serverIp,
          "port": 443,
          "id": secrets.vless?.reality || '',
          "aid": 0,
          "net": "tcp",
          "type": "none",
          "tls": "reality",
          "sni": "www.cloudflare.com",
          "fp": "chrome",
          "pbk": secrets.reality?.public_key || '',
          "sid": secrets.reality?.short_id || '',
          "flow": "xtls-rprx-vision"
        }, null, 2);
        
      case 'VLESS-gRPC':
        return JSON.stringify({
          "v": "2",
          "ps": "EdgeBox-gRPC",
          "add": serverIp,
          "port": 443,
          "id": secrets.vless?.grpc || secrets.vless?.reality || '',
          "aid": 0,
          "net": "grpc",
          "type": "none",
          "tls": "tls",
          "sni": server.cert?.domain || "grpc.edgebox.internal",
          "alpn": "h2",
          "path": "grpc"
        }, null, 2);
        
      case 'VLESS-WebSocket':
        return JSON.stringify({
          "v": "2",
          "ps": "EdgeBox-WS",
          "add": serverIp,
          "port": 443,
          "id": secrets.vless?.ws || secrets.vless?.reality || '',
          "aid": 0,
          "net": "ws",
          "type": "none",
          "tls": "tls",
          "sni": server.cert?.domain || "ws.edgebox.internal",
          "path": "/ws"
        }, null, 2);
        
      case 'Trojan-TLS':
        return JSON.stringify({
          "type": "trojan",
          "tag": "EdgeBox-TROJAN",
          "server": serverIp,
          "server_port": 443,
          "password": secrets.password?.trojan || '',
          "tls": {
            "enabled": true,
            "server_name": server.cert?.domain || "trojan.edgebox.internal",
            "insecure": true
          }
        }, null, 2);
        
      case 'Hysteria2':
        return JSON.stringify({
          "type": "hysteria2",
          "tag": "EdgeBox-HYSTERIA2",
          "server": serverIp,
          "server_port": 443,
          "password": secrets.password?.hysteria2 || '',
          "tls": {
            "enabled": true,
            "server_name": server.cert?.domain || serverIp,
            "insecure": true,
            "alpn": ["h3"]
          }
        }, null, 2);
        
      case 'TUIC':
        return JSON.stringify({
          "type": "tuic",
          "tag": "EdgeBox-TUIC",
          "server": serverIp,
          "server_port": 2053,
          "uuid": secrets.tuic_uuid || '',
          "password": secrets.password?.tuic || '',
          "congestion_control": "bbr",
          "tls": {
            "enabled": true,
            "server_name": server.cert?.domain || serverIp,
            "insecure": true,
            "alpn": ["h3"]
          }
        }, null, 2);
        
      default:
        return '{}';
    }
  } catch (e) {
    console.error('生成JSON配置失败:', e);
    return '{}';
  }
}

async function copyText(text) {
    if (!text || text === '—') {
        notify('没有可复制的内容', 'warn');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(text);
        notify('已复制到剪贴板');
    } catch (e) {
        // Fallback方法
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            notify('已复制到剪贴板');
        } catch (err) {
            notify('复制失败，请手动复制', 'warn');
        }
        document.body.removeChild(textarea);
    }
}

// --- Main Application Logic ---

async function refreshAllData() {
    const [dash, sys, traf] = await Promise.all([
        fetchJSON('/traffic/dashboard.json'),
        fetchJSON('/traffic/system.json'),
        fetchJSON('/traffic/traffic.json')
    ]);

    if (dash) dashboardData = dash;
    if (sys) systemData = sys;
    if (traf) trafficData = traf;
    
    window.dashboardData = dashboardData; // For debugging

    renderOverview();
    renderCertificateAndNetwork();
    renderProtocolTable();
    renderTrafficCharts();
}

function setupEventListeners() {
  document.addEventListener('click', (e) => {
    const target = e.target.closest('[data-action]');
    if (!target) return;

    const { action, modal, protocol, ipq, type } = target.dataset;

    switch (action) {
      case 'open-modal': {
        if (modal === 'whitelist') return showWhitelistModal();
        if (modal === 'config') return showConfigModal(protocol || '__SUBS__');
        if (modal === 'ipq') return showIPQDetails(ipq || 'vps');
        break;
      }
      case 'close-modal': {
        if (modal) closeModal(modal);
        break;
      }
      case 'copy': {
        const subUrlEl = document.getElementById('sub-url');
        const plainEl = document.getElementById('plain-link');
        const jsonEl = document.getElementById('json-code');
        const base64El = document.getElementById('base64-link');
        const b64linesEl = document.getElementById('b64lines-link');

        if (type === 'sub' && subUrlEl) return copyText(subUrlEl.textContent.trim());
        if (type === 'plain' && plainEl) return copyText(plainEl.textContent.trim());
        if (type === 'json' && jsonEl) return copyText(jsonEl.textContent.trim());
        if (type === 'base64' && base64El) return copyText(base64El.textContent.trim());
        if (type === 'b64lines' && b64linesEl) return copyText(b64linesEl.textContent.trim());
        if (type === 'qr') {
          const canvas = document.querySelector('#qrcode canvas');
          if (canvas && canvas.toBlob) {
            canvas.toBlob(async (blob) => {
              try {
                await navigator.clipboard.write([new ClipboardItem({ [blob.type]: blob })]);
                notify('二维码已复制');
              } catch {
                notify('请右键保存二维码', 'warn');
              }
            });
          } else {
            notify('未找到二维码', 'warn');
          }
          return;
        }
        break;
      }
    }
  });
}

async function showIPQDetails(which) {
  const modal   = document.getElementById('ipqModal');
  const titleEl = document.getElementById('ipqModalTitle');
  const body    = document.getElementById('ipqDetails');
  if (!modal || !titleEl || !body) return;

  const titleMap = { vps: 'VPS IP质量检测详情', proxy: '代理IP质量检测详情' };
  titleEl.textContent = titleMap[which] || 'IP质量检测详情';
  body.innerHTML = '<div class="config-section"><div class="config-code">加载中...</div></div>';

  // 读取目标数据（与 09-20 安装脚本的 edgebox-ipq.sh 对应：/status/ipq_vps.json / ipq_proxy.json）
  const data = await fetchJSON(`/status/ipq_${which}.json`);

  if (data && typeof data === 'object') {
    const score   = data.score ?? '—';
    const grade   = data.grade ?? '—';
    const when    = data.detected_at || data.test_time || '—';
    const ip      = data.ip || '—';
    const asn     = data.asn || '—';
    const isp     = data.isp || '—';
    const country = data.country || '—';
    const city    = data.city || '—';
    const rdns    = data.rdns || '—';
    const latency = (data.latency !== undefined && data.latency !== null) ? `${data.latency} ms` : '—';

    // 风险标志：兼容 {risk:{proxy,hosting,mobile,...}} 或 notes 数组
    let riskFlags = [];
    if (data.risk && typeof data.risk === 'object') {
      for (const k of ['proxy','hosting','mobile','tor']) {
        if (data.risk[k] === true) riskFlags.push(k);
      }
      if (Array.isArray(data.risk.dnsbl_hits) && data.risk.dnsbl_hits.length) {
        riskFlags.push(`dnsbl:${data.risk.dnsbl_hits.length}`);
      }
    }
    if (Array.isArray(data.notes) && data.notes.length) {
      riskFlags = riskFlags.concat(data.notes);
    }
    const riskText = riskFlags.length ? riskFlags.join(', ') : '—';

    // 网络类型（尽量还原旧版字段名；没有就从 vantage 推断）
    const networkType = data.network_type || (data.vantage === 'vps' ? '数据中心 / 自建VPS' :
                           data.vantage === 'proxy' ? '代理 / 住宅' : '—');

    // 黑名单命中数：优先 risk.dnsbl_hits 长度
    const blCount = (data.risk && Array.isArray(data.risk.dnsbl_hits)) ? data.risk.dnsbl_hits.length :
                    (typeof data.blacklist_count === 'number' ? data.blacklist_count : 0);

    body.innerHTML = `
      <div class="config-section">
        <h4>总览</h4>
        <div class="info-item">
          <label>分数:</label><value>${score} (${grade})</value>
        </div>
        <div class="info-item">
          <label>检测时间:</label><value>${when}</value>
        </div>
        <div class="info-item">
          <label>风险标志:</label><value>${escapeHtml(riskText)}</value>
        </div>
      </div>

      <div class="config-section">
        <h4>身份信息</h4>
        <div class="info-item">
          <label>IP地址:</label><value>${ip}</value>
        </div>
        <div class="info-item">
          <label>ASN/ISP:</label><value>${escapeHtml(asn)} / ${escapeHtml(isp)}</value>
        </div>
        <div class="info-item">
          <label>位置:</label><value>${escapeHtml(country)}, ${escapeHtml(city)}</value>
        </div>
        <div class="info-item">
          <label>反向域名:</label><value>${escapeHtml(rdns)}</value>
        </div>
      </div>

      <div class="config-section">
        <h4>质量评估</h4>
        <div class="info-item">
          <label>网络类型:</label><value>${escapeHtml(networkType)}</value>
        </div>
        <div class="info-item">
          <label>黑名单:</label><value>${blCount} 个命中</value>
        </div>
        <div class="info-item">
          <label>延迟:</label><value>${latency}</value>
        </div>
      </div>
    `;
  } else {
    // 兜底：没有详情数据时，仍给出上次采集时间
    const meta = await fetchJSON('/status/ipq_meta.json');
    const hint = meta && meta.last_run ? `（上次采集：${new Date(meta.last_run).toLocaleString()}）` : '';
    body.innerHTML = `<div class="config-section"><div class="info-item"><label>状态:</label><value>暂无IP质量数据 ${hint}</value></div></div>`;
  }

  showModal('ipqModal');
}



// --- Initialization ---

document.addEventListener('DOMContentLoaded', () => {
    refreshAllData();
    
    // Set up periodic refresh
    overviewTimer = setInterval(refreshAllData, 30000); // 30 seconds
    
    // Set up event delegation
    setupEventListeners();
});
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
      <h1>🚀 EdgeBox - 企业级多协议节点管理系统 (Control Panel)</h1>
    </div>
    
    <div class="main-content">
      <div class="card">
        <div class="card-header"><h2>📊 系统概览</h2></div>
        <div class="grid grid-3">
          <div class="inner-block">
            <h3>服务器信息</h3>
            <div class="info-item"><label>用户备注名:</label><value id="server-name">—</value></div>
            <div class="info-item"><label>云厂商/区域:</label><value id="cloud-info">—</value></div>
            <div class="info-item"><label>Instance ID:</label><value id="instance-id">—</value></div>
            <div class="info-item"><label>主机名:</label><value id="hostname">—</value></div>
          </div>
          <div class="inner-block">
            <h3>服务器配置</h3>
            <div class="progress-row"><span class="progress-label">CPU:</span><div class="progress-bar"><div class="progress-fill" id="cpu-progress" style="width: 0%">0%</div></div><span class="progress-info" id="cpu-info">—</span></div>
            <div class="progress-row"><span class="progress-label">内存:</span><div class="progress-bar"><div class="progress-fill" id="mem-progress" style="width: 0%">0%</div></div><span class="progress-info" id="mem-info">—</span></div>
            <div class="progress-row"><span class="progress-label">磁盘:</span><div class="progress-bar"><div class="progress-fill" id="disk-progress" style="width: 0%">0%</div></div><span class="progress-info" id="disk-info">—</span></div>
          </div>
          <div class="inner-block">
            <h3>核心服务</h3>
            <div class="service-item"><span>Nginx</span><div class="service-status"><span class="status-badge" id="nginx-status">—</span><span class="version" id="nginx-version"></span></div></div>
            <div class="service-item"><span>Xray</span><div class="service-status"><span class="status-badge" id="xray-status">—</span><span class="version" id="xray-version"></span></div></div>
            <div class="service-item"><span>Sing-box</span><div class="service-status"><span class="status-badge" id="singbox-status">—</span><span class="version" id="singbox-version"></span></div></div>
          </div>
        </div>
        <div style="text-align: center; padding-top: 15px; border-top: 1px solid #e5e7eb; margin-top: 15px;">
          <span class="text-secondary">版本号: <span id="version">—</span> | 安装日期: <span id="install-date">—</span> | 更新时间: <span id="update-time">—</span></span>
        </div>
      </div>

      <div class="grid grid-1-2">
        <div class="card">
          <div class="card-header"><h2>🔒 证书切换</h2></div>
          <div class="cert-modes">
            <div class="cert-mode-tab" id="cert-self">自签证书</div>
            <div class="cert-mode-tab" id="cert-ca">CA证书</div>
          </div>
          <div class="inner-block">
            <div class="info-item"><label>证书类型:</label><value id="cert-type">—</value></div>
            <div class="info-item"><label>绑定域名:</label><value id="cert-domain">—</value></div>
            <div class="info-item"><label>续期方式:</label><value id="cert-renewal">—</value></div>
            <div class="info-item"><label>到期日期:</label><value id="cert-expiry">—</value></div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><h2>🌐 网络身份配置 <span class="note-udp">注：HY2/TUIC为UDP通道，VPS直连，不走代理分流. </span></h2></div>
<!-- 网络身份配置卡片 - 确保有正确的ID -->
<div class="network-blocks">
  <div class="network-block" id="net-vps">
    <h3>📡 VPS出站IP</h3>
    <div class="info-item"><label>公网身份:</label><value>直连</value></div>
    <div class="info-item"><label>VPS出站IP:</label><value id="vps-ip">—</value></div>
    <div class="info-item"><label>Geo:</label><value id="vps-geo">—</value></div>
    <div class="info-item">
      <label>IP质量:</label>
      <value>
        <span id="vps-ipq-score">—</span>
        <button class="btn-link" data-action="open-modal" data-modal="ipq" data-ipq="vps">查看详情</button>
      </value>
    </div>
  </div>

  <div class="network-block" id="net-proxy">
    <h3>🔄 代理出站IP</h3>
    <div class="info-item"><label>代理身份:</label><value>全代理</value></div>
    <div class="info-item"><label>代理IP:</label><value id="proxy-ip">—</value></div>
    <div class="info-item"><label>Geo:</label><value id="proxy-geo">—</value></div>
    <div class="info-item">
      <label>IP质量:</label>
      <value>
        <span id="proxy-ipq-score">—</span>
        <button class="btn-link" data-action="open-modal" data-modal="ipq" data-ipq="proxy">查看详情</button>
      </value>
    </div>
  </div>

<!-- 智能分流卡片中的白名单部分 -->
<div class="network-block" id="net-shunt">
  <h3>🔀 智能分流<span class="note-udp">(UDP走VPS)</span></h3>
  <div class="info-item"><label>TCP身份:</label><value>代理出站</value></div>
  <div class="info-item"><label>UDP身份:</label><value>VPS出站</value></div>
  <div class="info-item">
    <label>白名单:</label>
    <value style="flex: 1;">
      <div class="whitelist-container">
        <div class="whitelist-preview" id="whitelistPreview">
          <span class="whitelist-text">暂无白名单</span>
        </div>
      </div>
    </value>
  </div>
</div>

      <div class="card">
        <div class="card-header"><h2>📡 协议配置</h2></div>
        <table class="data-table">
          <thead><tr><th>协议名称</th><th>使用场景</th><th>伪装效果</th><th>运行状态</th><th>客户端配置</th></tr></thead>
          <tbody id="protocol-tbody"></tbody>
        </table>
      </div>

<!-- 流量统计（照搬原版布局） -->
<div class="card traffic-card">
  <h2>📊 流量统计
    <div class="traffic-progress-container">
      <span class="progress-label">本月进度</span>
      <div class="progress-wrapper">
        <div class="progress-bar">
          <div class="progress-fill" id="progress-fill" style="width:0%">
            <span class="progress-percentage" id="progress-percentage">0%</span>
          </div>
        </div>
      </div>
      <span class="progress-budget" id="progress-budget">0/100GiB</span>
    </div>
  </h2>
  <div class="traffic-charts">
    <div class="chart-container">
      <h4 style="text-align:center;margin:0 0 10px 0;color:#64748b">近30日出站流量</h4>
      <canvas id="traffic" style="height:300px"></canvas>
    </div>
    <div class="chart-container">
      <h4 style="text-align:center;margin:0 0 10px 0;color:#64748b">近12个月累计流量</h4>
      <canvas id="monthly-chart" style="height:300px"></canvas>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-header">
    <h2>⚙️ 运维管理</h2>
  </div>
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
      <h4>🌐 证书管理</h4>
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
        <code>edgeboxctl shunt vps</code> <span># 切换至VPS全量出站</span><br>
        <code>edgeboxctl shunt resi &lt;URL&gt;</code> <span># 配置并切换至住宅IP全量出站</span><br>
        <code>edgeboxctl shunt direct-resi &lt;URL&gt;</code> <span># 配置并切换至白名单智能分流状态</span><br>
        <code>edgeboxctl shunt whitelist &lt;add|remove|list&gt;</code> <span># 管理白名单域名</span><br>
        <code>代理URL格式:</code><br>
        <code>http://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;</code><br>
        <code>https://user:pass@&lt;域名&gt;:&lt;端口&gt;?sni=</code><br>
        <code>socks5://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;</code><br>
        <code>socks5s://user:pass@&lt;域名&gt;:&lt;端口&gt;?sni=</code><br>
        <code>示例：edgeboxctl shunt resi 'socks5://user:pass@111.222.333.444:11324'</code> <span># 全栈走住宅</span>
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

<!-- 白名单弹窗 -->
<div id="whitelistModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>白名单完整列表</h3>
      <button class="close-btn" data-action="close-modal" data-modal="whitelistModal">×</button>
    </div>
    <div class="modal-body">
      <div id="whitelistList"></div>
    </div>
  </div>
</div>

<!-- IP质量详情弹窗 -->
<div id="ipqModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h3 id="ipqModalTitle">IP质量检测详情</h3>
      <button class="close-btn" data-action="close-modal" data-modal="ipqModal">×</button>
    </div>
    <div class="modal-body">
      <div id="ipqDetails"></div>
    </div>
  </div>
</div>

<!-- 配置弹窗保持不变 -->
<div id="configModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h3 id="configModalTitle">客户端配置详情</h3>
      <button class="close-btn" data-action="close-modal" data-modal="configModal">×</button>
    </div>
    <div class="modal-body">
      <div id="configDetails"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-sm" data-action="copy" data-type="sub">复制订阅地址</button>
      <button class="btn btn-sm" data-action="copy" data-type="plain">复制明文链接</button>
      <button class="btn btn-sm" data-action="copy" data-type="json">复制JSON配置</button>
      <button class="btn btn-sm" data-action="copy" data-type="base64">复制Base64链接</button>
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
    curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/install.sh | bash
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
# 安装IP质量评分系统 (已修复jq错误)
install_ipq_stack() {
  log_info "安装 IP 质量评分（IPQ）栈..."

  local WEB_STATUS_PHY="/var/www/edgebox/status"
  local WEB_STATUS_LINK="${WEB_ROOT:-/var/www/html}/status"
  mkdir -p "$WEB_STATUS_PHY" "${WEB_ROOT:-/var/www/html}"
  ln -sfn "$WEB_STATUS_PHY" "$WEB_STATUS_LINK" 2>/dev/null || true

  if ! command -v dig >/dev/null 2>&1; then
    if command -v apt >/dev/null 2>&1; then apt -y update && apt -y install dnsutils;
    elif command -v yum >/dev/null 2>&1; then yum -y install bind-utils; fi
  fi

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
  eval "curl -fL -A 'Mozilla/5.0' -sS --max-time 4 $1 \"$2\"" || return 1; }

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

  declare -a hits=(); if [[ -n "$ip" ]]; then IFS=. read -r a b c d <<<"$ip"; rip="${d}.${c}.${b}.${a}"
    for bl in zen.spamhaus.org bl.spamcop.net dnsbl.sorbs.net b.barracudacentral.org; do
      if dig +time=1 +tries=1 +short "${rip}.${bl}" A >/dev/null 2>&1; then hits+=("$bl"); fi
    done
  fi

  local lat=999
  if [[ "$V" == "vps" ]]; then
    r=$(ping -n -c 3 -w 4 1.1.1.1 2>/dev/null | awk -F'/' '/^rtt/ {print int($5+0.5)}'); [[ -n "${r:-}" ]] && lat="$r"
  else
    r=$(eval "curl -o /dev/null -s $P -w '%{time_connect}' https://www.cloudflare.com/cdn-cgi/trace" 2>/dev/null)
    [[ -n "${r:-}" ]] && lat=$(awk -v t="$r" 'BEGIN{printf("%d",(t*1000)+0.5)}')
  fi

  local score=100; declare -a notes=()
  [[ "$f_proxy" == "true"   ]] && score=$((score-50)) && notes+=("flag_proxy")
  [[ "$f_host"  == "true"   ]] && score=$((score-10)) && notes+=("datacenter_ip")
  (( ${#hits[@]} )) && score=$((score-20*${#hits[@]})) && notes+=("dnsbl")
  (( lat>400 )) && score=$((score-20)) && notes+=("high_latency")
  (( lat>200 && lat<=400 )) && score=$((score-10)) && notes+=("mid_latency")
  if [[ "$asn" =~ (amazon|aws|google|gcp|microsoft|azure|alibaba|tencent|digitalocean|linode|vultr|hivelocity|ovh|hetzner|iij|ntt|leaseweb|contabo) ]]; then score=$((score-2)); fi
  (( score<0 )) && score=0
  local grade="D"; ((score>=80)) && grade="A" || { ((score>=60)) && grade="B" || { ((score>=40)) && grade="C"; }; }

# --- JQ FIX: Use --slurpfile to read blacklist hits safely ---
# [ANCHOR:JQ_BLACKLIST_BLOCK] Read DNSBL hits from plain-text via --rawfile (safe)
local hits_file; hits_file=$(mktemp)
printf '%s\n' "${hits[@]:-}" > "$hits_file"

# 用 --rawfile 把纯文本读入为字符串，再在 jq 里 split("\n")
local risk_json; risk_json=$(
  jq -n -R -s \
     --rawfile bl "$hits_file" \
     --argjson p $([[ "$f_proxy" == "true" ]] && echo true || echo false) \
     --argjson h $([[ "$f_host"  == "true" ]] && echo true || echo false) \
     --argjson m $([[ "$f_mob"   == "true" ]] && echo true || echo false) \
     '{proxy:$p,hosting:$h,mobile:$m,dnsbl_hits:($bl|split("\n")|map(select(. != ""))),tor:false}'
)
rm -f "$hits_file"

# [PATCH:JQ_NOTES_SAFE] —— 先把 notes 文本安全转为 JSON 数组
# 假设 bash 变量：$ts $vantage $ip $country $city $asn $isp $rdns 以及 $notes
notes_json="$(printf '%s\n' "${notes:-}" | tr ',' '\n' | awk 'NF' | jq -R -s 'split("\n")|map(select(length>0))' 2>/dev/null || echo '[]')"

# 统一用 --arg（字符串）和 --argjson（已经是 JSON 的）传参，避免引号嵌套地狱
jq -n \
  --arg ts   "${ts:-}" \
  --arg v    "${vantage:-}" \
  --arg ip   "${ip:-}" \
  --arg c    "${country:-}" \
  --arg city "${city:-}" \
  --arg asn  "${asn:-}" \
  --arg isp  "${isp:-}" \
  --arg rdns "${rdns:-}" \
  --argjson notes "${notes_json}" \
  '{
     detected_at: $ts,
     vantage: $v,
     ip: $ip,
     country: $c,
     city: $city,
     asn: $asn,
     isp: $isp,
     rdns: (if $rdns == "" then null else $rdns end),
     notes: $notes
   }' > "/var/www/edgebox/status/ipq_vps.json"
}

main(){
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

  ( crontab -l 2>/dev/null | grep -v '/usr/local/bin/edgebox-ipq.sh' ) | crontab - || true
  ( crontab -l 2>/dev/null; echo "15 2 * * * /usr/local/bin/edgebox-ipq.sh >/dev/null 2>&1" ) | crontab -

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
# 主安装流程 (v3 优化版)
main() {
    trap cleanup EXIT
    
    clear
    print_separator
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
    
    # --- 模块4 & 5: 后台、监控与运维工具 ---
    show_progress 6 10 "安装后台面板和监控脚本"
    create_dashboard_backend
    setup_traffic_monitoring
    
    show_progress 7 10 "创建管理工具和初始化服务"
    create_enhanced_edgeboxctl
    setup_email_system
    install_ipq_stack
    create_init_script

    # --- 最终阶段: 启动、验证与数据生成 ---
    show_progress 8 10 "生成订阅链接"
    generate_subscription
    
    show_progress 9 10 "启动并验证所有服务"
    start_and_verify_services || { log_error "服务未能全部正常启动，请检查日志"; exit 1; }
    
    show_progress 10 10 "最终数据生成与同步"
    finalize_data_generation
    
    # 显示安装信息
    show_installation_info
    
    log_success "EdgeBox v3.0.0 安装成功完成！"
    exit 0
}

# 脚本入口点检查
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # 直接执行脚本
    main "$@"
fi
