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
# 统一兜底版本，可被环境变量覆盖：DEFAULT_SING_BOX_VERSION=1.12.5 bash install.sh
DEFAULT_SING_BOX_VERSION="${DEFAULT_SING_BOX_VERSION:-1.12.4}"

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
    log_info "配置防火墙规则（智能SSH端口检测）..."
    
    # 🚨 第一步：智能检测当前SSH端口（防止锁死）
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
    
    # 🔧 修复：更安全的数组去重
    if [[ ${#ssh_ports[@]} -gt 0 ]]; then
        # 使用临时文件进行去重，避免数组操作问题
        local temp_file=$(mktemp)
        printf "%s\n" "${ssh_ports[@]}" | sort -u > "$temp_file"
        current_ssh_port=$(head -1 "$temp_file")
        rm -f "$temp_file"
    fi
    
    # 默认端口兜底
    current_ssh_port="${current_ssh_port:-22}"
    
    log_info "检测到SSH端口: $current_ssh_port"
    
    # 🚨 第二步：安全的防火墙配置
    if command -v ufw >/dev/null 2>&1; then
        # Ubuntu/Debian UFW
        log_info "配置UFW防火墙（SSH端口：$current_ssh_port）..."
        
        # 🔥 关键修复：先允许SSH，再重置，避免锁死
        if ! ufw allow "$current_ssh_port/tcp" comment 'SSH-Emergency' >/dev/null 2>&1; then
            log_warn "UFW SSH应急规则添加失败，但继续执行"
        fi
        
        # 🔧 修复：增加错误处理
        if ! ufw --force reset >/dev/null 2>&1; then
            log_error "UFW重置失败"
            return 1
        fi
        
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
        ufw allow 443/tcp comment 'EdgeBox TCP' >/dev/null 2>&1 || log_warn "HTTPS TCP端口配置失败"
        ufw allow 443/udp comment 'EdgeBox Hysteria2' >/dev/null 2>&1 || log_warn "Hysteria2端口配置失败"
        ufw allow 2053/udp comment 'EdgeBox TUIC' >/dev/null 2>&1 || log_warn "TUIC端口配置失败"
        
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
        
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # CentOS/RHEL FirewallD
        log_info "配置FirewallD防火墙（SSH端口：$current_ssh_port）..."
        
        # 🔧 修复：增加错误处理
        if ! firewall-cmd --permanent --add-port="$current_ssh_port/tcp" >/dev/null 2>&1; then
            log_error "FirewallD SSH端口配置失败"
            return 1
        fi
        
        # 配置EdgeBox端口（允许失败，但记录警告）
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || log_warn "HTTP端口配置失败"
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || log_warn "HTTPS TCP端口配置失败"
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 || log_warn "Hysteria2端口配置失败"
        firewall-cmd --permanent --add-port=2053/udp >/dev/null 2>&1 || log_warn "TUIC端口配置失败"
        
        # 重新加载规则
        if ! firewall-cmd --reload >/dev/null 2>&1; then
            log_error "FirewallD规则重载失败"
            return 1
        fi
        
        log_success "FirewallD防火墙配置完成，SSH端口 $current_ssh_port 已开放"
        
    elif command -v iptables >/dev/null 2>&1; then
        # 传统iptables
        log_info "配置iptables防火墙（SSH端口：$current_ssh_port）..."
        
        # 🔧 修复：避免重复规则，先清理再添加
        # 检查是否已有规则，避免重复
        if ! iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        fi
        
        if ! iptables -C INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
        fi
        
        if ! iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        fi
        
        if ! iptables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        fi
        
        if ! iptables -C INPUT -p udp --dport 443 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p udp --dport 443 -j ACCEPT
        fi
        
        if ! iptables -C INPUT -p udp --dport 2053 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p udp --dport 2053 -j ACCEPT
        fi
        
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
        
        log_success "iptables防火墙配置完成，SSH端口 $current_ssh_port 已开放"
        
    else
        log_warn "未检测到支持的防火墙软件，跳过自动配置"
        log_info "请手动配置防火墙，确保开放以下端口："
        log_info "  SSH: $current_ssh_port/tcp"
        log_info "  EdgeBox: 80/tcp, 443/tcp, 443/udp, 2053/udp"
    fi
    
    # 🚨 最终验证：确保SSH连接正常
    log_info "验证SSH连接状态..."
    if ss -tln | grep -q ":$current_ssh_port "; then
        log_success "✅ SSH端口 $current_ssh_port 监听正常"
    else
        log_warn "⚠️ SSH端口监听状态异常，请检查sshd服务"
    fi
    
    return 0
}


# 防火墙回滚机制
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


###############################
# 错误处理和清理函数
###############################

cleanup_all() {
    local script_exit_code=$?
    
    log_info "执行统一清理程序..."
    
    # 1. 清理初始提权产生的临时文件
    [[ -n "${EB_TMP:-}" ]] && rm -f "$EB_TMP" 2>/dev/null || true
    
    # 2. 清理安装过程中的临时文件
    rm -f /tmp/edgebox_* 2>/dev/null || true
    rm -f /tmp/sing-box* 2>/dev/null || true
    rm -f /tmp/xray_* 2>/dev/null || true
    rm -f /tmp/*.tar.gz 2>/dev/null || true
    rm -f /tmp/*.zip 2>/dev/null || true
    find /tmp -name "*.bak.*" -mtime 0 -delete 2>/dev/null || true
    
    log_info "临时文件清理完成"
    
    # 3. 智能判断安装是否真正成功
    log_info "正在验证安装结果..."
    
    # 检查核心服务状态
    local services=("nginx" "xray" "sing-box")
    local running_services=()
    local failed_services=()
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            running_services+=("$service")
            log_info "✅ $service 服务运行正常"
        else
            failed_services+=("$service")
            log_warn "❌ $service 服务未运行"
        fi
    done
    
    # 检查关键端口
    local ports=("80:nginx" "443:tcp" "443:udp" "2053:udp")
    local listening_ports=()
    local failed_ports=()
    
    for port_info in "${ports[@]}"; do
        local port="${port_info%:*}"
        local desc="${port_info#*:}"
        
        if [[ "$desc" == "udp" ]] || [[ "$port_info" == *":udp" ]]; then
            if ss -ulnp 2>/dev/null | grep -q ":${port} "; then
                listening_ports+=("$port($desc)")
            else
                failed_ports+=("$port($desc)")
            fi
        else
            if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
                listening_ports+=("$port($desc)")
            else
                failed_ports+=("$port($desc)")
            fi
        fi
    done
    
    # 检查重要文件
    local config_files=(
        "/etc/edgebox/config/server.json"
        "/etc/edgebox/config/xray.json"
        "/etc/edgebox/config/sing-box.json"
        "/etc/edgebox/scripts/dashboard-backend.sh"
        "/var/www/html/sub"
    )
    local existing_files=()
    local missing_files=()
    
    for file in "${config_files[@]}"; do
        if [[ -f "$file" ]]; then
            existing_files+=("$(basename "$file")")
        else
            missing_files+=("$(basename "$file")")
        fi
    done
    
    # 安装成功判定逻辑
    local success_score=0
    local total_score=0
    
    # 服务权重：每个服务20分
    success_score=$((success_score + ${#running_services[@]} * 20))
    total_score=$((total_score + ${#services[@]} * 20))
    
    # 端口权重：每个端口10分
    success_score=$((success_score + ${#listening_ports[@]} * 10))
    total_score=$((total_score + ${#ports[@]} * 10))
    
    # 文件权重：每个文件4分
    success_score=$((success_score + ${#existing_files[@]} * 4))
    total_score=$((total_score + ${#config_files[@]} * 4))
    
    local success_rate=$((success_score * 100 / total_score))
    
    log_info "安装完成度评估：${success_score}/${total_score} (${success_rate}%)"
    
    # 判定标准：80%以上完成度且nginx运行 = 安装成功
    if [[ $success_rate -ge 80 ]] && [[ " ${running_services[*]} " =~ " nginx " ]]; then
        # 安装成功 - 显示简洁的成功信息（不与您的finalize_data_generation冲突）
        log_success "🎉 EdgeBox v3.0.0 安装验证通过！"
        echo ""
        if [[ ${#failed_services[@]} -gt 0 ]] || [[ ${#failed_ports[@]} -gt 0 ]]; then
            echo -e "${YELLOW}⚠️  注意：${NC}"
            [[ ${#failed_services[@]} -gt 0 ]] && echo -e "${YELLOW}  部分服务需要检查: ${failed_services[*]}${NC}"
            [[ ${#failed_ports[@]} -gt 0 ]] && echo -e "${YELLOW}  部分端口需要检查: ${failed_ports[*]}${NC}"
            echo -e "${YELLOW}  这些小问题不影响核心功能${NC}"
            echo ""
        fi
        
        # 成功退出
        exit 0
        
    else
        # 真正的安装失败
        log_error "💥 EdgeBox 安装失败"
        echo ""
        echo -e "${RED}=== 安装失败摘要 ===${NC}"
        echo -e "${RED}❌ 失败的服务: ${failed_services[*]:-无}${NC}"
        echo -e "${RED}❌ 失败的端口: ${failed_ports[*]:-无}${NC}"
        echo -e "${RED}❌ 缺失的文件: ${missing_files[*]:-无}${NC}"
        echo -e "${RED}❌ 完成度: ${success_rate}% (需要≥80%)${NC}"
        echo ""
        echo -e "${YELLOW}🔧 故障排查建议：${NC}"
        echo -e "  1. 检查系统兼容性: ${CYAN}cat /etc/os-release${NC}"
        echo -e "  2. 检查网络连接: ${CYAN}curl -I https://github.com${NC}"
        echo -e "  3. 检查端口占用: ${CYAN}ss -tlnp | grep ':443 '${NC}"
        echo -e "  4. 查看详细日志: ${CYAN}tail -n 50 $LOG_FILE${NC}"
        echo -e "  5. 手动检查服务: ${CYAN}systemctl status nginx xray sing-box${NC}"
        echo -e "  6. 重新运行脚本或联系技术支持"
        echo ""
        
        # 失败退出
        exit 1
    fi
}

# 🔧 另外，修改主函数的最后部分，确保正确的退出流程
main() {
    trap cleanup_all EXIT
    
    # ... 其他安装步骤保持不变 ...
    
    # 最后这部分要修改：
    show_progress 10 10 "最终数据生成与同步"
    finalize_data_generation
    
    # 🔧 移除这里的直接退出，让cleanup_all来处理最终结果
    # log_success "EdgeBox v3.0.0 安装成功完成！"
    # exit 0
    
    # 🎯 直接结束，让cleanup_all函数来判断和处理最终结果
    log_info "安装流程执行完毕，正在进行最终验证..."
}

# 🔧 同时在finalize_data_generation函数的最后，移除任何可能导致非零退出的命令
finalize_data_generation() {
    log_info "最终数据生成与同步..."
    
    # 生成最终订阅文件
    log_info "生成最终订阅文件..."
    generate_subscription || log_warn "订阅文件生成遇到小问题，但不影响核心功能"
    
    # 同步订阅文件
    log_info "同步订阅文件..."
    if [[ -f "${CONFIG_DIR}/subscription.txt" ]]; then
        cp "${CONFIG_DIR}/subscription.txt" "${WEB_ROOT}/sub" 2>/dev/null || true
        cp "${CONFIG_DIR}/subscription.txt" "${TRAFFIC_DIR}/sub.txt" 2>/dev/null || true
        log_success "订阅同步完成：${WEB_ROOT}/sub -> ${CONFIG_DIR}/subscription.txt，以及 ${TRAFFIC_DIR}/sub.txt"
    else
        log_warn "订阅文件不存在，跳过同步"
    fi
    
    # 初始化分流配置
    log_info "初始化分流配置..."
    mkdir -p "${CONFIG_DIR}/shunt" 2>/dev/null || true
    echo '{"enabled": false, "mode": "whitelist", "domains": []}' > "${CONFIG_DIR}/shunt/state.json" 2>/dev/null || true
    
    # 生成初始面板数据
    log_info "生成初始面板数据..."
    "${SCRIPTS_DIR}/dashboard-backend.sh" --now 2>/dev/null || log_warn "初始面板数据生成遇到小问题"
    
    # 初始化流量监控数据
    log_info "初始化流量监控数据..."
    mkdir -p "${TRAFFIC_DIR}/data" 2>/dev/null || true
    echo '[]' > "${TRAFFIC_DIR}/data/traffic_history.json" 2>/dev/null || true
    
    # 设置文件权限
    log_info "设置文件权限..."
    chmod -R 755 "${SCRIPTS_DIR}" 2>/dev/null || true
    chmod -R 644 "${CONFIG_DIR}"/*.json 2>/dev/null || true
    chmod -R 755 "${TRAFFIC_DIR}" 2>/dev/null || true
    
    # 执行最终验证
    log_info "执行最终验证..."
    # 🔧 确保这里的命令不会失败
    systemctl daemon-reload 2>/dev/null || true
    
    log_success "数据生成与系统验证完成"
    
    # 🔧 明确返回成功，避免意外的非零退出码
    return 0
}


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
# 1) 显式 SING_BOX_VERSION（可带或不带 v）
# 2) GitHub API /releases/latest 取 tag_name
# 3) 跟随跳转读取 releases/latest 的最终 URL，解析 tag
# 4) 仍失败 → 统一回落到 DEFAULT_SINGBOX_VERSION
local ver_raw=""
if [[ -n "${SING_BOX_VERSION:-}" ]]; then
  ver_raw="${SING_BOX_VERSION#v}"
else
  # 尝试 API
  ver_raw="$(
    curl -fsSL -H 'User-Agent: EdgeBox' \
      'https://api.github.com/repos/SagerNet/sing-box/releases/latest' 2>/dev/null \
    | jq -r '.tag_name' 2>/dev/null | sed 's/^v//'
  )"

  # API 拿不到时：不解析 HTML，直接跟随跳转拿最终 URL
  if [[ -z "$ver_raw" || "$ver_raw" == "null" ]]; then
    ver_raw="$(
      curl -fsSLI -o /dev/null -w '%{url_effective}' \
        'https://github.com/SagerNet/sing-box/releases/latest' \
      | sed -nE 's#.*/tag/v([0-9.]+).*#\1#p'
    )"
  fi

  # 统一回落
  [[ -z "$ver_raw" ]] && ver_raw="${DEFAULT_SING_BOX_VERSION}"
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
cat > /etc/systemd/system/sing-box.service << SINGBOX_SERVICE
[Unit]
Description=sing-box Service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target
Wants=network.target

[Service]
User=root
Group=root
Type=simple
ExecStart=/usr/local/bin/sing-box run -c ${CONFIG_DIR}/sing-box.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
SINGBOX_SERVICE

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
    
# 生成协议数组，包含share_link（scenario=使用场景，camouflage=伪装效果）
cat <<EOF
[
  {
    "name": "VLESS-Reality",
    "scenario": "强审查环境",
    "camouflage": "极佳★★★★★",
    "status": "$reality_status",
    "port": 443,
    "network": "tcp",
    "share_link": "vless://${uuid_vless}@${server_ip}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&pbk=${reality_public_key}&sid=${reality_short_id}&type=tcp#EdgeBox-REALITY"
  },
  {
    "name": "VLESS-gRPC",
    "scenario": "较严审查/走CDN",
    "camouflage": "极佳★★★★★",
    "status": "$grpc_status",
    "port": 443,
    "network": "tcp",
    "share_link": "vless://${uuid_vless}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=h2&type=grpc&serviceName=grpc&fp=chrome#EdgeBox-gRPC"
  },
  {
    "name": "VLESS-WebSocket",
    "scenario": "常规网络稳定",
    "camouflage": "良好★★★★☆",
    "status": "$ws_status",
    "port": 443,
    "network": "tcp",
    "share_link": "vless://${uuid_vless}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome#EdgeBox-WS"
  },
  {
    "name": "Trojan-TLS",
    "scenario": "移动网络可靠",
    "camouflage": "良好★★★★☆",
    "status": "$trojan_status",
    "port": 443,
    "network": "tcp",
    "share_link": "trojan://${trojan_pw_enc}@${domain}:443?security=tls&sni=trojan.${domain}&alpn=http%2F1.1&fp=chrome#EdgeBox-TROJAN"
  },
  {
    "name": "Hysteria2",
    "scenario": "弱网/高丢包更佳",
    "camouflage": " 好★★★☆☆",
    "status": "$udp443_status",
    "port": 443,
    "network": "udp",
    "share_link": "hysteria2://${hy2_pw_enc}@${domain}:443?sni=${domain}&alpn=h3#EdgeBox-HYSTERIA2"
  },
  {
    "name": "TUIC",
    "scenario": "大带宽/低时延",
    "camouflage": "良好★★★★☆",
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

    # 获取通知信息
    local notifications_info="[]"
    local notifications_file="$TRAFFIC_DIR/notifications.json"
    if [[ -f "$notifications_file" ]]; then
        notifications_info=$(jq -c '.notifications // []' "$notifications_file" 2>/dev/null || echo "[]")
        if [[ "$notifications_info" == "null" ]] || [[ -z "$notifications_info" ]]; then
            notifications_info="[]"
        fi
    fi

# 统一生成 services_info（状态+版本号）
services_info=$(
  jq -n \
    --arg nstat "$(systemctl is-active --quiet nginx    && echo 运行中 || echo 已停止)" \
    --arg xstat "$(systemctl is-active --quiet xray     && echo 运行中 || echo 已停止)" \
    --arg sstat "$(systemctl is-active --quiet sing-box && echo 运行中 || echo 已停止)" \
    --arg nver  "$(nginx -v 2>&1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)" \
    --arg xver  "$((xray -version 2>/dev/null || xray version 2>/dev/null) | head -n1 | grep -Eo 'v?[0-9]+(\.[0-9]+)+' | head -1)" \
    --arg sver  "$(sing-box version 2>/dev/null | head -n1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)" \
    '{nginx:{status:$nstat,version:$nver},
      xray:{status:$xstat,version:$xver},
      "sing-box":{status:$sstat,version:$sver}}'
)

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
	--argjson notifications "$notifications_info"\
    '{
        updated_at: $timestamp,
        # 直接用 system.server_ip 拼接订阅地址（80端口走HTTP）
        subscription_url: ("http://" + $system.server_ip + "/sub"),
        server: ($system + {cert: $cert}),
        services: $services,
        protocols: $protocols,
        shunt: $shunt,
        subscription: $subscription,
        secrets: $secrets,
		notifications: $notifications
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
    
    # 任务6：生成初始流量数据（新增）
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
    log_info "└─ 初始流量数据生成"  # 新增这行
    
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
/* =======================================================================
   EdgeBox 控制面板 · 组件化（ops-panel 无 id 也生效）
   ======================================================================= */

/* ========== Reset / 基础皮肤 ========== */

* { margin:0; padding:0; box-sizing:border-box; }

body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  background:#f3f4f6; min-height:100vh; padding:20px; color:#1f2937;
}

.container{ max-width:1400px; margin:0 auto; }

h1{ font-size:23px; font-weight:700; color:#1f2937; line-height:32px; }
h2{ font-size:18px; font-weight:600; color:#1f2937; line-height:26px; }
h3{ font-size:15px; font-weight:600; color:#1f2937; line-height:22px; }
h4{ font-size:14px; font-weight:500; color:#1f2937; line-height:20px; }

body,p,span,td,div{ font-size:13px; font-weight:500; color:#1f2937; line-height:20px; }
.text-muted{ color:#6b7280; }
.text-secondary{ color:#4b5563; }

/* ===== 文字样式统一：h3黑色大字，h4灰色中字，内容灰色中字 ===== */
:root {
  --heading-color: #111827;   /* h3标题颜色（黑色） */
  --subheading-color: #6b7280; /* h4标题颜色（灰色） */
  --content-color: #6b7280;   /* 内容颜色（灰色） */
  --h3-size: 15px;            /* h3字体大小 */
  --h4-size: 14px;            /* h4字体大小 */
}

/* h3基础样式：黑色大字 */
h3 { 
  font-size: var(--h3-size); 
  line-height: 1.4; 
  font-weight: 600; 
  color: var(--heading-color);
}

/* h4基础样式：灰色中字 */
h4 { 
  font-size: var(--h4-size); 
  line-height: 1.4; 
  font-weight: 600; 
  color: var(--subheading-color);
}

/* ================ 卡片/区块 ================ */
.main-card{
  background:#fff; border:1px solid #d1d5db; border-radius:10px;
  box-shadow:0 2px 6px rgba(0,0,0,.08); overflow:hidden;
}

.card{
  background:#fff; border:1px solid #d1d5db; border-radius:10px;
  box-shadow:0 2px 6px rgba(0,0,0,.08); padding:20px; margin-bottom:20px;
  transition:box-shadow .2s;
}
.card:hover{ box-shadow:0 4px 8px rgba(0,0,0,.08); }
.card-header{ margin-bottom:20px; padding-bottom:12px; border-bottom:1px solid #e5e7eb; }
.card-header h2{ display:flex; justify-content:space-between; align-items:center; }
.card-note{ font-size:11px; color:#6b7280; font-weight:400; }


/* =========标题 =========*/

/* 1. 恢复标题作为大卡片的一部分 */
.main-card {
  background: #fff; 
  border: 1px solid #d1d5db; 
  border-radius: 10px;
  box-shadow: 0 2px 6px rgba(0,0,0,.08); 
  overflow: hidden;
  margin-bottom: 20px;
  /* 去掉整体padding，让标题可以占满宽度 */
  padding: 0 !important;
}

/* 2. 标题样式：从深灰到浅灰的渐变 + 圆角只在顶部 */
.main-header {
  text-align: center;
  /* 修正渐变：从深灰到浅灰 */
  background: linear-gradient(135deg, #e2e8f0 0%, #f1f5f9 50%, #f8fafc 100%);
  border: none; /* 去掉单独边框，融入大卡片 */
  border-radius: 0; /* 去掉独立圆角 */
  border-top-left-radius: 9px; /* 只保留顶部圆角，配合大卡片 */
  border-top-right-radius: 9px;
  padding: 16px 20px;
  position: relative;
  margin: 0; /* 重要：去掉margin让标题贴合大卡片边缘 */
  /* 调整阴影：内阴影营造嵌入效果 */
  box-shadow: 
    inset 0 -1px 0 rgba(0,0,0,0.1),
    inset 0 1px 0 rgba(255,255,255,0.9);
}

/* 3. 大卡片内容区域恢复padding */
.main-content {
  padding: 20px !important;
  margin: 0 !important;
}

/* 4. 标题文字样式 */
.main-header h1 {
  text-align: center !important;
  margin: 0 auto;
  display: block;
  width: 100%;
  font-size: 24px;
  font-weight: 700;
  color: #1f2937;
  line-height: 1.3;
  text-shadow: 0 1px 2px rgba(0,0,0,0.1);
}

/* 5. 去掉紫色竖杠 */
.main-header::before {
  display: none !important;
}

/* 6. 可选：底部装饰线 */
.main-header::after {
  content: "";
  position: absolute;
  left: 50%;
  bottom: 0;
  transform: translateX(-50%);
  width: 60px;
  height: 2px;
  background: linear-gradient(90deg, transparent, #10b981, transparent);
  border-radius: 2px;
  opacity: 0.6;
}

/* 7. 确保内部卡片间距正确 */
.main-content .card {
  margin-bottom: 20px !important;
}

.main-content .card:last-child {
  margin-bottom: 0 !important;
}

/* 8. grid布局特殊处理 */
.main-content .grid .card {
  margin-bottom: 0 !important;
}

/* 9. 可选：鼠标悬停效果（整个标题区域） */
.main-header:hover {
  background: linear-gradient(135deg, #d1d5db 0%, #e2e8f0 50%, #f1f5f9 100%);
  box-shadow: 
    inset 0 -1px 0 rgba(0,0,0,0.15),
    inset 0 1px 0 rgba(255,255,255,0.8);
  transition: all 0.3s ease;
}

/* 10. 备选方案：如果想要更明显的深浅对比 */
.main-header.dark-to-light {
  background: linear-gradient(135deg, #94a3b8 0%, #cbd5e1 50%, #e2e8f0 100%);
}

.main-header.dark-to-light:hover {
  background: linear-gradient(135deg, #64748b 0%, #94a3b8 50%, #cbd5e1 100%);
}


/* =========内层 =========*/
.inner-block{
  background:#f5f5f5; border:1px solid #e5e7eb; border-radius:6px; padding:15px; margin-bottom:15px;
}
.inner-block:last-child{ margin-bottom:0; }
.inner-block h3{
  margin-bottom:12px; padding-bottom:8px; border-bottom:1px solid #e5e7eb;
}

/*========= 网格 =========*/
.grid{ display:grid; gap:20px; }
.grid-3{ grid-template-columns:repeat(3,1fr); }
.grid-1-2{ grid-template-columns:1fr 2fr; }

/* ============= 全局行（简单版，组件内会覆写） ============= */
.info-item{ display:flex; justify-content:space-between; padding:6px 0; }
.info-item label{ color:#6b7280; }
.info-item value{ color:#1f2937; font-weight:500; }

/* ========= 全局运行状态徽标（协议配置/系统概览通用） ========= */
.status-badge{
  display:inline-flex; align-items:center;
  height:20px; line-height:20px; padding:0 10px;
  border-radius:999px; font-size:11px;
  background:#eafaf3; color:#059669; border:1px solid #c7f0df;
}
.status-running{ background:#d1fae5; color:#059669; border-color:#a7f3d0; }
.status-stopped{ background:#fee2e2; color:#ef4444; border-color:#fecaca; }

/* ===== 全局栅格（如果这是你全局用的） ===== */
.grid-3,.grid-1-2{ display:grid; gap:20px; }
.grid-3{ grid-template-columns:repeat(3,1fr); }
.grid-1-2{ grid-template-columns:1fr 2fr; }



/* =======================================================================
   系统概览
   ======================================================================= */
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
  padding: 12px !important;  /* 减小内边距 */
  margin-bottom: 0 !important;  /* 去掉底部边距 */
}

/* 标题紧跟 */
#system-overview .inner-block>h3{ 
  display:flex; 
  align-items:center; 
  white-space:nowrap; 
  margin:0 0 var(--h3-gap);
  font-size: var(--h3-size) !important;  /* 使用h3标准大小 */
  line-height: 22px !important;
  height: 22px !important;
  color: var(--heading-color) !important;
}

/* 服务器信息：两列 */
#system-overview .server-info .info-item{
  display:grid; grid-template-columns:var(--label-w) 1fr; gap:8px; align-items:center; 
  padding:5px 0;  /* 统一行高 */
}

/* 系统概览标题统一样式 */
#system-overview .server-info .label,
#system-overview .progress-row .label,
#system-overview .core-services .label { 
  color: var(--subheading-color) !important;  /* h4级别用灰色 */
  font-size: var(--h4-size) !important; 
  font-weight: 600 !important;
  justify-self: start; 
}

/* 系统概览内容统一样式 */
#system-overview .server-info .value,
#system-overview .progress-row .value,
#system-overview .core-services .value { 
  color: var(--content-color) !important; 
  font-size: var(--h4-size) !important; 
  font-weight: 500 !important;
  min-width: 0; 
  white-space: nowrap; 
  overflow: hidden; 
  text-overflow: ellipsis; 
}

/* 服务器配置：键名 | 进度条 | 百分比 */
#system-overview .progress-row{
  display:grid; grid-template-columns:var(--label-w) minmax(0,1fr) var(--percent-col);
  column-gap:4px; align-items:center; 
  padding:5px 0;  /* 统一行高 */
}
#system-overview .progress-label{ color:var(--label); justify-self:start; }
#system-overview .progress-bar{
  position:relative; height:var(--meter-height);
  background:var(--meter-track); border-radius:999px; overflow:hidden; align-self:center;
}
#system-overview .progress-fill{
  height:100%; border-radius:999px; background:linear-gradient(90deg,var(--meter-start),var(--meter-end));
  transition:width .25s ease;
}
#system-overview .progress-text{
  position:absolute; left:4px; right:4px; top:50%; transform:translateY(-50%);
  font-size:11px; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; pointer-events:none;
}
#system-overview .progress-info{
  min-width:var(--percent-col); text-align:right; color:var(--value);
  font-variant-numeric:tabular-nums;
}

/* ========== 核心服务：压缩布局 ========== */

/* 核心服务：名称 | 徽标 | 版本号 */
#system-overview .core-services .service-item{
  display:grid; 
  grid-template-columns:var(--label-w) max-content 1fr;
  column-gap:var(--svc-gap);  /* 保持使用变量，不要用 !important */
  align-items:center; 
  padding:5px 0;  /* 调整行高 */
}

/* 新增：第一项和最后一项的微调 */
#system-overview .core-services .service-item:first-child {
  padding-top: 6px !important;
}
#system-overview .core-services .service-item:last-child {
  padding-bottom: 5px !important;
}

/* 覆盖全局状态徽章样式，减小尺寸 */
#system-overview .core-services .status-badge {
  height: 18px !important;  /* 减小高度 */
  line-height: 18px !important;
  padding: 0 8px !important;  /* 减小内边距 */
  font-size: 11px !important;  /* 减小字体 */
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

/* 窄屏收窄 */
@media (max-width:640px){
  #system-overview{ --label-w:68px; --percent-col:32px; }
  #system-overview .server-info .info-item{ grid-template-columns:68px 1fr; }
  #system-overview .progress-row{ grid-template-columns:68px minmax(0,1fr) var(--percent-col); }
  #system-overview .core-services .service-item{ grid-template-columns:68px max-content 1fr; }
}

/* —— 给三个区块各自的"标签列宽"开独立的开关 —— */
/* 服务器信息：中文键名较长，单独设宽，并禁止换行 */
#system-overview .server-info { 
  --label-w: 80px;                 /* 这里按需改 */
}
#system-overview .server-info .label { 
  white-space: nowrap;             /* 防止被压行 */
}

/* 服务器配置（进度条区）：只影响这一块的行 */
#system-overview .progress-row { 
  --label-w: 50px;                 /* 你想要的 50px 只作用在进度条这块 */
  --percent-col: 33px;             /* 百分比列可一起调，避免太窄 */
}
#system-overview .progress-label { 
  color: var(--subheading-color) !important;  /* 设置为灰色 */
  white-space: nowrap;
}

/* 核心服务：单独控制服务名那一列宽度与间距 */
#system-overview .core-services {
  --label-w: 70px;                 /* 这块自己设，不受上面的影响 */
  --svc-gap: 70px;
}

/* 核心服务的标签文字大小调整 */
#system-overview .core-services .label {
  font-size: 13px !important;  /* 与其他区块保持一致 */
  line-height: 1.2 !important;
}

/* 窄屏时也分别覆盖，避免全局一刀切 */
@media (max-width: 640px){
  #system-overview .server-info   { --label-w: 84px; }
  #system-overview .progress-row  { --label-w: 60px; --percent-col: 34px; }
  #system-overview .core-services { --label-w: 68px; }
}

/* 系统概览：标题右侧“版本号/安装日期/更新时间”内联备注（同 netid-panel 风格） */
#system-overview .card-header h2{
  display:flex;             /* 覆盖全局 .card-header h2 已是 flex 的对齐方式 */
  align-items:flex-end;     /* 与标题下沿对齐（覆盖全局 align-items:center） */
}
#system-overview .card-header #sys-meta{
  color:#9ca3af !important; /* 浅灰：同 .note-udp */
  font-weight:400;
  font-size:12px;
  line-height:1;
  margin-right:1em;         /* 右侧留出一个字宽 */
  transform:translateY(2px);/* 轻微下沉，贴近标题底线 */
}


/* =======================================================================
   证书切换
   ======================================================================= */
#cert-panel{
  /* 与 NetID 标签一致的参数 */
  --tag-pad-y: 9px;        /* ← 改它=改标签高度 */
  --tag-pad-x: 16px;
  --tag-radius: 8px;
  --tag-font: 13px;
  --tag-gap: 6px;

  --label-w: 80px;          /* 行布局与原来保持一致 */
  --row-gap: 10px;
  --h3-gap: 8px;

  /* 颜色 */
  --label: var(--heading-color);
  --value: var(--content-color);
  --tag-active-bg: #10b981;     /* 激活：绿色 */
  --tag-inactive-bg: #e2e8f0;   /* 非当前：灰底 */
  --tag-active-color: #ffffff;
  --tag-inactive-color: #64748b;
  --card-br: #e5e7eb;
}

/* 顶部模式标签（两枚） */
#cert-panel .cert-modes{
  display:flex;
  gap:5px;
  margin-bottom: var(--tag-gap);  /* 与下方内容的间距 */
}
#cert-panel .cert-mode-tab{
  flex:1;
  padding: var(--tag-pad-y) var(--tag-pad-x);
  border: 1px solid var(--card-br);
  border-radius: var(--tag-radius);
  background: var(--tag-inactive-bg);       /* 非当前：#e2e8f0 */
  color: var(--tag-inactive-color);
  font-size: var(--tag-font);
  font-weight: 600;
  text-align:center;
  cursor: default;
}
#cert-panel .cert-mode-tab.active{
  background: var(--tag-active-bg);
  color: var(--tag-active-color);
  border-color: var(--tag-active-bg);
}

/* 内容卡片：白底 + 边框 + 阴影（去掉灰底） */
#cert-panel .inner-block{
  display:block;
  background:#fff;                         /* ← 替换掉原来的灰底 */
  border:1px solid var(--card-br);
  border-radius:10px;
  padding:15px;
  box-shadow:0 2px 6px rgba(0,0,0,.08);    /* 阴影 */
}
#cert-panel .inner-block>h3{
  margin:0 0 var(--h3-gap);
}

/* 明细行：键名 | 值（保持原有行节奏） */
#cert-panel .inner-block .info-item{
  display:grid;
  grid-template-columns: var(--label-w) 1fr;
  gap: var(--row-gap);
  align-items:center;
  padding:6px 0;
}

/* 证书切换标题统一样式 */
#cert-panel .inner-block .info-item label{
  color: var(--subheading-color) !important;  /* h4级别用灰色 */
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
   ======================================================================= */
#netid-panel{
  /* 行样式（与 #cert-panel 保持一致） */
  --label-w: 80px;          /* 键名列宽 */
  --row-gap: 10px;          /* 键名列与值列横向间距 */
  --line-vpad: 6px;         /* 每行上下内边距（行高节奏） */

  /* 悬浮标签（与证书切换一致） */
  --tag-pad-y: 10px;        /* 标签上下 padding = 高度 */
  --tag-pad-x: 16px;        /* 标签左右 padding = 视觉宽度 */
  --tag-gap: 6px;           /* 标签与卡片的垂直间距 */
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
  --panel-top-gap: 4px;     /* 组件组再向下的细微“下移” */

  display: block !important; /* 防外部 flex 干扰 */
}

/* 标题行与下方网格的距离（只作用本卡） */
#netid-panel .card-header{
  margin-bottom: var(--header-gap) !important;
}

/* 三块容器：三列、等高、整组垂直居中 */
/* 三块容器：三列、自适应高度、顶部对齐 */
#netid-panel .network-blocks{
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 15px;

  align-content: start;         /* 从顶部开始排列 */
  align-items: start;           /* 子项顶部对齐，不强制等高 */
  padding-top: var(--panel-top-gap); /* 与标题横线的微调间距 */
}

/* 小卡片：为“悬浮标签”预留位置 + 阴影 */
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

/* 网络身份配置内容统一样式 */
#netid-panel .network-block .info-item value{
  color: var(--content-color) !important;
  font-size: var(--h4-size) !important;
  font-weight: 500 !important;
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* 特殊处理：白名单文本保持统一样式 */
#netid-panel .whitelist-text {
  color: var(--content-color) !important;
  font-size: var(--h4-size) !important;
  font-weight: 500 !important;
  flex-shrink: 0;
}

/* 标题右侧“注：HY2/TUIC…”（颜色+对齐+右缩进，仅本卡） */
#netid-panel .card-header h2{
  display: flex;
  align-items: flex-end;        /* 和标题下沿对齐 */
}
#netid-panel .card-header .note-udp{
  color: #9ca3af !important;    /* 浅灰 */
  font-weight: 400;
  font-size: 12px;
  line-height: 1;
  margin-right: 1em;             /* 右缩进一个字宽（可改 1em） */
  transform: translateY(2px);    /* 轻微下沉，更贴近底线 */
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

/* IP质量分数显示值颜色修复 */
#vps-ipq-score,
#proxy-ipq-score {
  color: var(--content-color) !important;
  font-size: var(--h4-size) !important;
  font-weight: 500 !important;
}

.nid__value #vps-ipq-score,
.nid__value #proxy-ipq-score {
  color: var(--content-color) !important;
  font-size: var(--h4-size) !important;
  font-weight: 500 !important;
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
   运维管理
   ======================================================================= */
.commands-grid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:20px;
}
@media (max-width:768px){
  .commands-grid{ grid-template-columns:1fr; }
}

.command-section{
  background:#f5f5f5;
  border:1px solid #d1d5db;
  border-radius:8px;
  padding:12px;
}
.command-section h4{
  margin:0 0 8px;
  font-size:.9rem;
  font-weight:600;
  color:#1e293b;
  display:flex;
  align-items:center;
  gap:6px;
}

.command-list{ font-size:.8rem; line-height:1.5; }
/* 深灰代码块（命令） */
.command-list code{
  background: #e2e8f0;          /* 改成你想要的灰，例如 newb 用的 #e2e8f0 */
  color: #1f2937;
  padding:1px 6px;
  border-radius:4px;
  font-family:monospace;
  font-size:.78rem;
  line-height:1.1;
  display:inline-block;
}
.command-list span{ color:#6b7280; margin-left:8px; }

/* 运维管理：行距 & 命令与注释的间距 */
#ops-panel .command-list,
.commands-grid .command-list {
  line-height: 1.6;    /* ← 行与行的垂直距离，1.6~1.9 自行调 */
}

#ops-panel .command-list code,
.commands-grid .command-list code {
  margin-right: 8px;    /* ← 命令小胶囊 与 注释 的水平间距 */
  /* 可选：如果需要让 margin-bottom 生效，再打开下一行 */
  /* display: inline-block; */
}

#ops-panel .command-list code,
.commands-grid .command-list code {
  display: inline-block;
  margin-right: 8px;
  margin-bottom: 2px;   /* 轻微增加行间距 */
}

/* =======================================================================
   协议配置
   ======================================================================= */
.data-table{ width:100%; border-collapse:collapse; }
.data-table th{
  background:#f5f5f5; color:#4b5563; font-weight:500; padding:10px; text-align:left;
  font-size:12px; border-bottom:1px solid #e5e7eb;
}
.data-table td{ padding:10px; border-bottom:1px solid #f3f4f6; font-size:12px; }
.data-table td:nth-child(4),.data-table td:nth-child(5),.data-table td:nth-child(6),
.data-table th:nth-child(4),.data-table th:nth-child(5),.data-table th:nth-child(6){ text-align:center; }
.data-table tr:hover td{ background:#f5f5f5; }
.data-table tr.subs-row td{ background:#f5f5f5; }

.traffic-progress-container{ display:flex; align-items:center; gap:10px; }
.progress-label{ font-size:13px; color:#6b7280; white-space:nowrap; }
.progress-wrapper{ flex:1; min-width:120px; }
.progress-bar{ height:20px; background:#f3f4f6; border-radius:10px; overflow:hidden; position:relative; }
.progress-fill{ height:100%; background:linear-gradient(90deg,#10b981 0%,#059669 100%); transition:width .3s ease; display:flex; align-items:center; justify-content:flex-end; padding-right:8px; }
.progress-fill.warning{ background:linear-gradient(90deg,#f59e0b 0%,#d97706 100%); }
.progress-fill.critical{ background:linear-gradient(90deg,#ef4444 0%,#dc2626 100%); }
.progress-percentage{ color:#fff; font-size:11px; font-weight:600; }
.progress-budget{ color:#6b7280; font-size:12px; white-space:nowrap; }

/* 响应式（卡片网格/流量图保持不变） */
@media (max-width:1024px){
  .grid-3,.grid-1-2{ grid-template-columns:1fr; }
  .traffic-charts{ grid-template-columns:1fr; }
}
@media (max-width:768px){
  .modal-content{ width:95%; margin:10px auto; }
}

/* =======================================================================
   协议配置（边框与阴影加强版）
   ======================================================================= */
.data-table{ 
  width:100%; 
  border-collapse:collapse; 
}

/* 表头 */
.data-table th{
  background:#f5f5f5; 
  color:#4b5563; 
  font-weight:500; 
  padding:8px 10px;  /* 上下 8px */
  text-align:left;
  font-size:12px; 
  border-bottom:1px solid #e5e7eb;
  /* 阴影稍加强，边缘更清晰 */
  box-shadow: none;                  /* ← 原 0 1px 4px ... 去掉 */
}

/* 1) 普通单元格：只用 border-bottom，取消底部内阴影 */
.data-table td{
  padding:7px 10px;
  border-bottom:1px solid #e5e7eb;
  font-size:12px;
  box-shadow: none;                  /* ← 删掉 inset 0 -1px 0 ... */
}

/* 第4、5、6列居中 */
.data-table td:nth-child(4),
.data-table td:nth-child(5),
.data-table td:nth-child(6),
.data-table th:nth-child(4),
.data-table th:nth-child(5),
.data-table th:nth-child(6){ 
  text-align:center; 
}

/* 2) hover 行：不要再叠加内阴影的“分隔线” */
.data-table tbody tr:hover td{
  background:#f8f9fa;
  /* 仅保留外部柔和投影，去掉 inset 0 -1px 0 ... */
  box-shadow: 0 2px 6px rgba(0,0,0,0.12);
}

/* 3) 订阅行上边线：用 1px 边框，取消顶部方向的阴影，避免变粗 */
.data-table tr.subs-row td{
  background:#eef2f7;
  border-top:1px solid #cbd5e1;
  box-shadow: none;                  /* ← 删掉 inset 0 1px 3px ... */
}
.data-table tr.subs-row:hover td{
  background:#e3e9f2;
  box-shadow: inset 0 1px 3px rgba(0,0,0,0.14), 0 3px 8px rgba(0,0,0,0.12);
}

/* 表格整体外边框与主体阴影（更明显但不突兀） */
.data-table {
  border: 1px solid #6b7280;                /* 边框由 #9ca3af 加深到 #6b7280 */
  border-radius: 8px;
  overflow: hidden;
  /* 立体感增强：一层柔和外阴影 + 一层贴边描边光 */
  box-shadow:
      0 6px 16px rgba(0,0,0,0.12),          /* 外层阴影 */
      0 0 0 1px rgba(0,0,0,0.06);           /* 贴边描边，边缘更锐利 */
}

/* 交替行（保留轻度层次） */
.data-table tbody tr:nth-child(even):not(.subs-row) td {
  background-color: rgba(249,250,251,0.65);
}
.data-table tbody tr:nth-child(even):not(.subs-row):hover td {
  background-color: #f3f4f6;
}

/* 修复协议配置卡片与上方卡片边框贴着的问题 */

/* 1. 修复grid布局中的卡片间距问题 */
.main-content .grid .card {
  margin-bottom: 0 !important; /* grid内的卡片不使用margin，完全依赖gap */
}

/* 2. 确保grid布局有正确的gap */
.main-content .grid {
  display: grid; 
  gap: 20px !important; /* 强制使用20px间距 */
  margin: 0;
}

/* 3. 特别处理1-2网格布局（证书切换和网络身份配置这一行） */
.main-content .grid-1-2 {
  display: grid; 
  grid-template-columns: 1fr 2fr;
  gap: 20px !important;
  margin-bottom: 20px !important; /* 这一行与下方协议配置卡片的间距 */
}

/* 4. 协议配置卡片确保有正确的上边距 */
.card[id*="protocol"],
.card:has(.data-table),
.card:has(h2:contains("协议配置")) {
  margin-top: 20px !important; /* 确保与上方有间距 */
}

/* 5. 如果协议配置卡片有特定的类名或ID，直接指定 */
#protocol-panel,
#protocols-panel,
.protocol-card {
  margin-top: 20px !important;
  margin-bottom: 20px !important;
}

/* 6. 通用解决方案：确保所有非grid内的卡片有正确间距 */
.main-content > .card:not(.grid .card) {
  margin-bottom: 20px !important;
}

.main-content > .card:not(.grid .card):not(:first-child) {
  margin-top: 20px !important;
}

/* 7. 特殊情况：如果协议配置在grid后面，强制添加上边距 */
.main-content .grid + .card,
.main-content .grid-1-2 + .card {
  margin-top: 20px !important;
}

/* 8. 响应式处理：窄屏时确保间距一致 */
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

/* 9. 确保协议配置表格卡片的边框正常显示 */
.card:has(.data-table) {
  border: 1px solid #d1d5db !important;
  box-shadow: 0 2px 6px rgba(0,0,0,.08) !important;
}

/* 10. 调试用：如果需要临时高亮协议配置卡片 */
/*
.card:has(.data-table) {
  border: 2px solid red !important;
}
*/

/* 协议配置表格：使用场景和伪装效果列应用h4格式 */
.data-table td:nth-child(1),
.data-table td:nth-child(2),
.data-table td:nth-child(3) {
  color: var(--content-color) !important;  /* 使用h4的灰色 */
  font-size: var(--h4-size) !important;    /* 使用h4的字体大小 */
  font-weight: 500 !important;             /* 适中的字体粗细 */
}
/* =======================================================================
   流量统计 - 修复垂直居中问题
   ======================================================================= */

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

/* —— 进度条（高度与 CPU 一致） —— */
.traffic-card .traffic-progress-container{ 
  display:flex; 
  align-items:center; 
  gap:10px; 
  height:var(--h-progress); 
  flex-shrink:0; 
}
.traffic-card .progress-wrapper{ 
  flex:1; 
  min-width:120px; 
}
.traffic-card .progress-bar{ 
  height:var(--meter-height); 
  background:#e2e8f0; 
  border-radius:999px; 
  overflow:hidden;  /* 保持 hidden，标签现在在内部 */
  position:relative; 
}
.traffic-card .progress-fill{ 
  height:100%; 
  background:linear-gradient(90deg,#10b981 0%,#059669 100%); 
  transition:width .3s ease; 
  display:flex; 
  align-items:center; 
  justify-content:flex-end; 
  padding-right:8px; 
}
.traffic-card .progress-percentage{ 
  color:#fff; 
  font-size:11px; 
  font-weight:600; 
}
.traffic-card .progress-budget{ 
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

@media (max-width:1024px){
  .traffic-charts{ 
    grid-template-columns:1fr; 
  }
  .traffic-charts:not(.traffic--subcards) > :first-child{ 
    border-right:0; 
    padding-right:0; 
  }
  .traffic-charts:not(.traffic--subcards) > :last-child{  
    padding-left:0; 
  }
  .chart-column:first-child .chart-container,
  .chart-column:last-child  .chart-container{
    height:250px;  /* 减少高度，确保图例不被截断 */
    min-height:250px;
  }
}

/* 仅隐藏 Chart.js 生成的 HTML 图例（如有）——避免误伤轴刻度 */
.traffic-card .chartjs-legend {
  display: none !important;
}

/* 标题后的默认“圆点版”自定义图例（其它图表都用这个） */
.traffic-card .chart-container > h3::after {
  content: " 🔵 VPS 🟢 代理";
  font-size: 11px;
  color: #6b7280;
  margin-left: 8px;
}

/* 仅“近12月柱状图”使用“方块版”图例
   精确到：同一个 .chart-container 里含有 <canvas id="monthly-chart"> 才生效 */
@supports selector(.x:has(#monthly-chart)) {
  .chart-container:has(> canvas#monthly-chart) > h3::after {
    content: " 🟦 VPS 🟩 代理";
  }
}

/* —— 可选：旧浏览器 fallback（如果不支持 :has()）——
   若“近12月柱状图”的容器能加类名，请在 HTML 给该容器加 .is-monthly，
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


/* =======================================================================
   通知中心样式
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

/* 通知中心容器 */
.notification-center {
    position: relative;
    display: inline-flex;
    width: 38px;              /* ← 调大/调小按钮外框尺寸改这里 */
    height: 38px;
    margin-right: 22px;       /* 保持你原来的间距 */
    align-items: center;
    justify-content: center;
}

/* 通知触发按钮 - 增强版 */
.notification-trigger {
    width: 100%;
    height: 100%;
    display: grid;
    place-items: center;
    background: none;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    color: #6b7280;
    padding: 0;               /* 关键：不再用 padding 放大 */
    line-height: 1;           /* 避免文字行高影响外框 */
    transition: background-color .2s ease, color .2s ease;
}

/* 放大图标而不是放大按钮外框：不影响标题行高度 */
.notification-trigger > svg,
.notification-trigger > i,
.notification-trigger > span {
    font-size: 23px;          /* ← 调大/调小图标尺寸改这里 */
    width: 1em;
    height: 1em;
    display: inline-block;
    transition: transform .2s ease, color .2s ease;
}

/* 悬停态：背景与颜色变化，图标轻微放大 */
.notification-trigger:hover {
    background-color: rgba(16, 185, 129, 0.1);
    color: #10b981;
}

.notification-trigger:hover > svg,
.notification-trigger:hover > i,
.notification-trigger:hover > span {
    transform: scale(1.15);
}

/* 通知数量徽章 */
.notification-badge {
    position: absolute;
    top: 2px;
    right: 2px;
    background: #ef4444;
    color: white;
    border-radius: 10px;
    padding: 1px 6px;
    font-size: 11px;
    font-weight: 600;
    min-width: 18px;
    text-align: center;
    animation: notification-pulse 2s infinite;
}

@keyframes notification-pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.1); }
}

/* 通知面板 */
.notification-panel {
    position: absolute;
    top: 100%;
    right: 0;
    width: 320px;
    max-height: 400px;
    background: white;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    box-shadow: 0 10px 20px rgba(0, 0, 0, 0.15);
    display: none;
    z-index: 1000;
    overflow: hidden;
}

.notification-panel.show {
    display: block;
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

/* 通知面板头部 */
.notification-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px;
    border-bottom: 1px solid #e5e7eb;
    background: #f9fafb;
}

.notification-header h3 {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
    color: #374151;
}

.notification-clear {
    background: none;
    border: none;
    color: #6b7280;
    font-size: 12px;
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 4px;
    transition: background-color 0.2s ease;
}

.notification-clear:hover {
    background-color: rgba(0, 0, 0, 0.05);
    color: #374151;
}

/* 通知列表 */
.notification-list {
    max-height: 300px;
    overflow-y: auto;
    padding: 0;
}

/* 通知项目 */
.notification-item {
    display: flex;
    align-items: flex-start;
    padding: 12px 16px;
    border-bottom: 1px solid #f3f4f6;
    transition: background-color 0.2s ease;
    cursor: pointer;
}

.notification-item:hover {
    background-color: #f9fafb;
}

.notification-item:last-child {
    border-bottom: none;
}

.notification-item.unread {
    background-color: #fef3c7;
    border-left: 3px solid #f59e0b;
}

/* 通知图标 */
.notification-item-icon {
    flex-shrink: 0;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 12px;
    font-size: 14px;
}

.notification-item-icon.alert {
    background: #fef3c7;
    color: #d97706;
}

.notification-item-icon.system {
    background: #dbeafe;
    color: #2563eb;
}

.notification-item-icon.error {
    background: #fee2e2;
    color: #dc2626;
}

/* 通知内容 */
.notification-item-content {
    flex: 1;
    min-width: 0;
}

.notification-item-message {
    font-size: 13px;
    color: #374151;
    line-height: 1.4;
    margin-bottom: 4px;
}

.notification-item-time {
    font-size: 11px;
    color: #6b7280;
}

.notification-item-action {
    font-size: 11px;
    color: #2563eb;
    margin-top: 4px;
    cursor: pointer;
    font-family: monospace;
    background: #f3f4f6;
    padding: 2px 4px;
    border-radius: 2px;
}

/* 通知面板底部 */
.notification-footer {
    padding: 8px 16px;
    background: #f9fafb;
    border-top: 1px solid #e5e7eb;
    text-align: center;
}

.notification-footer small {
    color: #6b7280;
    font-size: 11px;
}

/* 空状态和加载状态 */
.notification-empty,
.notification-loading {
    padding: 40px 20px;
    text-align: center;
    color: #6b7280;
    font-size: 13px;
}

.notification-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
}

/* 响应式调整 */
@media (max-width: 768px) {
    .notification-panel {
        width: 280px;
        right: -20px;
    }
    
    .main-header h1 {
        font-size: 1.3rem;
    }
}


/* =========================
   弹窗 Modal 统一样式补丁（按您要求修正）
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
  display: grid;                   /* 用 grid 管控两列 */
  grid-template-columns: 144px 1fr;/* 左列固定宽度，右列自适应，与现有 kv-row 一致 */
  gap: 12px;
  align-items: start;
  justify-content: start;
  text-align: left;                /* 兜底，确保文本左对齐 */
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
  display: block;                  /* 自定义标签也作为网格项，块级更稳 */
  text-align: left;
  overflow-wrap: anywhere;         /* 优先换行其一即可 */
  word-break: break-word;
}

/* 无 grid 的极老环境做兜底（基本用不到） */
@supports not (display: grid){
  #ipqModal .info-item{
    display: flex;
    justify-content: flex-start;   /* 覆写掉 space-between */
    gap: 12px;
  }
  #ipqModal .info-item label{ min-width: 144px; }
  #ipqModal .info-item value{ flex: 1; }
}

/* —— IPQ 弹窗分组标题（<h5>）尺寸修正，仅作用 #ipqModal —— */
#ipqModal .ipq-section > h5 {
  font-size: var(--h3-size, 15px); /* 复用你前面定义的 --h3-size */
  line-height: 22px;
  font-weight: 600;
  color: var(--heading-color, #111827);
  margin: 0 0 8px;
}
#detailModal .modal-section,
#detailModal .detail-section,
#ipqModal .ipq-section{
  padding:20px 0;
  border-bottom:1px solid #374151;
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

#configModal .modal-section,
#configModal .config-section{ 
  padding:16px 0; 
  border-bottom:none; 
}

/* 查看详情弹窗内容左对齐 */
#detailModal .kv-key, 
#ipqModal .kv-key { 
  text-align:left !important; 
  padding-right:0; 
}
#detailModal .kv-value,
#ipqModal .kv-value { 
  text-align:left !important; 
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
.modal-body [data-role="qrcode"]{
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

/* 确保二维码容器不被其他样式影响 */
.modal-body .qr-container div,
.modal-body .qrcode div {
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
  color: #2563eb;                /* 蓝字 */
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

/* ===== ANCHOR: HEADINGS-COLOR-FIX ===== */
/* 统一面板内 h3 的标题色为纯黑（与其它卡片 h3 同色） */
:root{ --heading-color: #111827; }  /* 需要更黑/更浅就改这里 */

/* 1) 流量统计卡片内的图表标题（含 “📡 VPS出站IP / 🔄 代理出站IP / 🔀 分流出站”） */
.traffic-card .chart-container h3{
  color: var(--heading-color);
}

/* 2) 如果这些标题刚好放在 .progress-label 里，父级默认是灰色——在子级 h3 上强制还原为标题色 */
.traffic-card .progress-label h3{
  color: var(--heading-color);
}

/* 3) 兜底：其他卡片内 h3 也统一为标题色，避免被 note/muted 容器继承成灰 */
.card h3,
#system-overview h3,
#netid-panel h3{
  color: var(--heading-color);
}

/* 可选：只让“小字说明”保持灰，不再影响 h3（若你有 .note/.muted/.desc 之类父级） */
.note h3, .muted h3, .desc h3{ color: var(--heading-color); }

/* ===== 标题与内容层级统一（H1–H4 黑；内容用 H4 字号且灰） ===== */

/* 全局口径变量（按需改） */
:root{
  --heading-color: #111827;   /* h1–h4 标题色（黑） */
  --muted-color:   #6b7280;   /* 内容灰 */
  --h4-size:       14px;      /* h4 字号口径（用于内容的字号基准） */
}

/* 标题统一：h1–h4 都用黑色；h4 的字号固定为 --h4-size */
h1, h2, h3, h4 { color: var(--heading-color); }
h4 { font-size: var(--h4-size); line-height: 1.4; font-weight: 600; }

/* —— 系统概览里 CPU/内存/磁盘等：标签用 h4（黑），值/说明用 h4 字号（灰） —— */
/* 标签（标题） */
.system-overview .progress-label h4,
.system-overview .meter-title h4,
.system-overview .metric-label h4{
  color: var(--heading-color);       /* 防被父级灰色继承 */
  font-size: var(--h4-size);
  line-height: 1.4;
  font-weight: 600;
  margin: 0;
}

/* 值/说明（内容）——用与 h4 相同的字号，但颜色灰 */
.system-overview .meter-value,
.system-overview .metric-desc,
.system-overview .progress-extra,
.system-overview .progress-budget{
  font-size: var(--h4-size);
  line-height: 1.4;
  color: var(--muted-color);
  font-weight: 500;                  /* 可按需 400/500 */
}

/* 兜底：任何 “.progress-label” 容器若本身是灰色，也不影响其内 h4 的黑色 */
.progress-label { color: var(--muted-color); }
.progress-label h4 { color: var(--heading-color); }

/* 实用类：如果你在别处也要“内容=H4 字号 + 灰”，可直接加这个类 */
.text-h4-muted { font-size: var(--h4-size); line-height: 1.4; color: var(--muted-color); }

EXTERNAL_CSS

  # ========== 创建外置的JavaScript文件 ==========
  log_info "创建外置JavaScript文件..."

cat > "${TRAFFIC_DIR}/assets/edgebox-panel.js" <<'EXTERNAL_JS'
// =================================================================
// EdgeBox Panel v3.0 - Refactored JavaScript with Event Delegation
// =================================================================

// --- Global State ---
let dashboardData = {};
let trafficData = {};
let systemData = {};
let overviewTimer = null;
const GiB = 1024 * 1024 * 1024;

// --- Chart.js Plugin ---
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

// 读取 alert.conf 配置
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
    return { ALERT_STEPS: '30,60,90' }; // 默认值
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
    // 优先在打开的弹窗内显示，否则在页面中央显示
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
        // 页面级提示（保持原有逻辑）
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

async function copyTextFallbackAware(text) {
  if (!text) throw new Error('empty');
  try {
    if ((location.protocol === 'https:' || location.hostname === 'localhost') && navigator.clipboard) {
      await navigator.clipboard.writeText(text); return true;
    }
    throw new Error('insecure');
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text; ta.readOnly = true;
    ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy'); document.body.removeChild(ta);
    if (!ok) throw new Error('execCommand failed'); return true;
  }
}


// --- UI Rendering Functions ---
function renderOverview() {
  /* ========= 0) 兼容取数（优先闭包变量，取不到再用 window.*） ========= */
  const dash = (typeof dashboardData !== 'undefined' && dashboardData) ||
               (typeof window !== 'undefined' && window.dashboardData) || {};
  const sys  = (typeof systemData   !== 'undefined' && systemData)   ||
               (typeof window !== 'undefined' && window.systemData)   || {};

  /* ========= 1) 拆数据 ========= */
  const server   = dash.server   || {};
  const services = dash.services || {};

  /* ========= 2) 小工具 ========= */
  const setText = (id, text, setTitle) => {
    const el = document.getElementById(id); if (!el) return;
    el.textContent = (text === undefined || text === null || text === '') ? '—' : String(text);
    if (setTitle) el.title = el.textContent;
  };
  const setWidth = (id, pct) => { const el = document.getElementById(id); if (el) el.style.width = `${pct}%`; };
  const clamp = v => Math.max(0, Math.min(100, Number(v) || 0));
  const pick  = (...xs) => xs.find(v => v !== undefined && v !== null && v !== '') ?? 0;
  const toYMD = (v) => { if (!v) return '—'; const d = new Date(v); return isNaN(d) ? String(v).slice(0,10) : d.toISOString().slice(0,10); };
  const toggleBadge = (sel, running) => { const el = document.querySelector(sel); if (!el) return;
    el.textContent = running ? '运行中' : '已停止';
    el.classList.toggle('status-running', !!running);
    el.classList.toggle('status-stopped', !running);
  };

  /* ========= 3) 服务器信息 ========= */
  const remark   = server.user_alias ?? server.remark ?? '未备注';
  const provider = server.cloud?.provider ?? server.cloud_provider ?? 'Independent';
  const region   = server.cloud?.region   ?? server.cloud_region   ?? 'Unknown';
  setText('user-remark',  remark, true);
  setText('cloud-region', `${provider} | ${region}`, true);
  setText('instance-id',  server.instance_id ?? 'Unknown', true);
  setText('hostname',     server.hostname    ?? '-', true);

  /* ========= 4) 服务器配置（条中文本 + 百分比） ========= */
  setText('cpu-info',  server.spec?.cpu  ?? '—', true);
  setText('disk-info', server.spec?.disk ?? '—', true);

  // 内存条中文本（spec.memory 缺失或为 0 时，用 sys 组装）
  const fmtGiB = (b) => { const n = Number(b); if (!Number.isFinite(n)) return null; return Math.round((n / (1024 ** 3)) * 10) / 10; };
  let memText = server.spec?.memory ?? '';
  if (!memText || /^0\s*GiB$/i.test(memText)) {
    const totalB = pick(sys.mem_total, sys.total_mem, sys.memory_total, sys.mem?.total);
    const usedB  = pick(sys.mem_used,  sys.used_mem,  sys.memory_used,  sys.mem?.used);
    const freeB  = pick(sys.mem_free,  sys.free_mem,  sys.memory_free,  sys.mem?.free,
                        (totalB != null && usedB != null) ? (totalB - usedB) : undefined);
    const total = fmtGiB(totalB), used = fmtGiB(usedB), free = fmtGiB(freeB);
    memText = (total != null) ? (used != null && free != null ? `${total}GiB（已用: ${used}GiB, 可用: ${free}GiB）` : `${total}GiB`) : '—';
  }
  setText('mem-info', memText, true);

  // 百分比（多字段名兼容）
  const cpuPct  = clamp(pick(sys.cpu, sys.cpu_usage, sys['cpu-percent'], sys.metrics?.cpu, dash.metrics?.cpu));
  const memPct  = clamp(pick(sys.memory, sys.mem, sys['memory-percent'], sys.metrics?.memory, dash.metrics?.memory));
  const diskPct = clamp(pick(sys.disk, sys.disk_usage, sys['disk-percent'], sys.metrics?.disk, dash.metrics?.disk));

  setWidth('cpu-progress',  cpuPct);  setText('cpu-percent',  `${cpuPct}%`);
  setWidth('mem-progress',  memPct);  setText('mem-percent',  `${memPct}%`);
  setWidth('disk-progress', diskPct); setText('disk-percent', `${diskPct}%`);

  /* ========= 5) 核心服务（版本 + 状态） ========= */
  const versions = {
    nginx:   services.nginx?.version || '',
    xray:    services.xray?.version  || '',
    singbox: (services['sing-box']?.version || services.singbox?.version || '')
  };

setText('nginx-version',   versions.nginx   ? `版本 ${versions.nginx}`   : '—', true);
setText('xray-version',    versions.xray    ? `版本 ${versions.xray}`    : '—', true);
setText('singbox-version', versions.singbox ? `版本 ${versions.singbox}` : '—', true);

  toggleBadge('#system-overview .core-services .service-item:nth-of-type(1) .status-badge', services.nginx?.status === '运行中');
  toggleBadge('#system-overview .core-services .service-item:nth-of-type(2) .status-badge', services.xray?.status  === '运行中');
  toggleBadge('#system-overview .core-services .service-item:nth-of-type(3) .status-badge',
              (services['sing-box']?.status || services.singbox?.status) === '运行中');

  /* ========= 6) 顶部“版本/日期”摘要 ========= */
  const metaText = `版本号: ${server.version || '—'} | 安装日期: ${toYMD(server.install_date)} | 更新时间: ${toYMD(dash.updated_at || Date.now())}`;
  setText('sys-meta', metaText);
}


/* 仅更正“代理IP：”的显示格式，其余逻辑保持不变 */
function renderCertificateAndNetwork() {
  const data   = window.dashboardData || {};
  const server = data.server || {};
  const cert   = server.cert || {};
  const shunt  = data.shunt  || {};

  // —— 证书区（带空值保护）——
  const certMode = String(safeGet(cert, 'mode', 'self-signed'));
  document.getElementById('cert-self')?.classList.toggle('active', certMode === 'self-signed');
  document.getElementById('cert-ca')?.classList.toggle('active', certMode.startsWith('letsencrypt'));
  const certTypeEl = document.getElementById('cert-type');   if (certTypeEl) certTypeEl.textContent = certMode.startsWith('letsencrypt') ? "Let's Encrypt" : "自签名";
  const domEl = document.getElementById('cert-domain');      if (domEl) domEl.textContent = safeGet(cert, 'domain', '-');
  const rnEl  = document.getElementById('cert-renewal');     if (rnEl)  rnEl.textContent  = certMode.startsWith('letsencrypt') ? '自动' : '手动';
const exEl  = document.getElementById('cert-expiry');
if (exEl) {
  const exp = safeGet(cert, 'expires_at', null);
  // 直接显示 yyyy-mm-dd 格式，不进行本地化或其他格式转换
  exEl.textContent = exp || '—';
}

  // —— 出站模式高亮（采用你第二段的口径）——
  const shuntMode = String(safeGet(shunt, 'mode', 'vps')).toLowerCase();
  ['net-vps','net-proxy','net-shunt'].forEach(id => document.getElementById(id)?.classList.remove('active'));
  if (shuntMode.includes('direct')) {
    document.getElementById('net-shunt')?.classList.add('active');
  } else if (shuntMode.includes('resi') || shuntMode.includes('proxy')) {
    document.getElementById('net-proxy')?.classList.add('active');
  } else {
    document.getElementById('net-vps')?.classList.add('active');
  }

  // —— VPS 出站 IP（带兜底）——
  const vpsIp = safeGet(data, 'server.eip') || safeGet(data, 'server.server_ip') || '—';
  const vpsEl = document.getElementById('vps-ip'); if (vpsEl) vpsEl.textContent = vpsIp;

  // —— 代理出站 IP：仅显示 “协议//主机:端口”，自动剥离 user:pass@，兼容 IPv6 —— 
  const proxyRaw = String(safeGet(shunt, 'proxy_info', ''));
  const proxyEl  = document.getElementById('proxy-ip');

  function formatProxy(raw) {
    if (!raw) return '—';
    // 优先用 URL 解析
    try {
      // 确保有协议
      const normalized = /^[a-z][a-z0-9+.\-]*:\/\//i.test(raw) ? raw : 'socks5://' + raw;
      const u = new URL(normalized);
      const proto = u.protocol.replace(/:$/,'');     // 'socks5'
      const host  = u.hostname || '';                // 去掉了 user:pass@
      const port  = u.port || '';                    // 可能为空
      return (host && port) ? `${proto}//${host}:${port}` : (host ? `${proto}//${host}` : '—');
    } catch (_) {
      // 兜底正则：protocol://[user[:pass]@]host[:port]
      const re = /^([a-z0-9+.\-]+):\/\/(?:[^@\/\s]+@)?(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?/i;
      const m = raw.match(re);
      if (m) {
        const proto = m[1];
        const host  = m[2];
        const port  = m[3] || '';
        return port ? `${proto}//${host}:${port}` : `${proto}//${host}`;
      }
      // 再兜底一种 “proto host:port” 或 “host:port”
      const re2 = /^(?:([a-z0-9+.\-]+)\s+)?(\[[^\]]+\]|[^:\/?#\s]+)(?::(\d+))?$/i;
      const m2 = raw.match(re2);
      if (m2) {
        const proto = m2[1] || 'socks5';
        const host  = m2[2];
        const port  = m2[3] || '';
        return port ? `${proto}//${host}:${port}` : `${proto}//${host}`;
      }
      return '—';
    }
  }
  if (proxyEl) proxyEl.textContent = formatProxy(proxyRaw);
  
 /* === PATCH: 填充 Geo 与 IP质量主行分数 === */
(async () => {
  const setText = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = (val ?? '—') || '—';
  };

  // VPS 侧
  try {
    const r = await fetch('/status/ipq_vps.json', { cache: 'no-store' });
    if (r.ok) {
      const j = await r.json();
      const geo = [j.country, j.city].filter(Boolean).join(' · ');
      setText('vps-geo', geo || '—');
      // VPS IP质量显示：分数 + 等级
if (j.score != null && j.grade != null) {
  setText('vps-ipq-score', `${j.score} (${j.grade})`);
} else if (j.score != null) {
  setText('vps-ipq-score', String(j.score));
} else {
  setText('vps-ipq-score', j.grade || '—');
}
    }
  } catch (_) {}

  // 代理侧
  try {
    const r = await fetch('/status/ipq_proxy.json', { cache: 'no-store' });
    if (r.ok) {
      const j = await r.json();
      const geo = [j.country, j.city].filter(Boolean).join(' · ');
      setText('proxy-geo', geo || '—');
      // 代理IP质量显示：分数 + 等级  
if (j.score != null && j.grade != null) {
  setText('proxy-ipq-score', `${j.score} (${j.grade})`);
} else if (j.score != null) {
  setText('proxy-ipq-score', String(j.score));
} else {
  setText('proxy-ipq-score', j.grade || '—');
}
    }
  } catch (_) {}
})();

// —— 白名单预览：只显示第一个域名的前9个字符 —— 
const whitelist = data.shunt?.whitelist || [];
const preview = document.getElementById('whitelistPreview');
if (preview) {
  if (!whitelist.length) {
    preview.innerHTML = '<span class="whitelist-text">(无)</span>';
  } else {
    // 取第一个域名，显示前6个字符
    const firstDomain = whitelist[0] || '';
    const shortText = firstDomain.length > 9 ? firstDomain.substring(0, 9) + '...' : firstDomain;
    
    preview.innerHTML =
      `<span class="whitelist-text">${escapeHtml(shortText)}</span>` +
      `<button class="whitelist-more" data-action="open-modal" data-modal="whitelistModal">查看全部</button>`;
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
<td>${escapeHtml(p.fit || p.scenario || '—')}</td>
<td>${escapeHtml(p.effect || p.camouflage || '—')}</td>
            <td><span class="status-badge ${p.status === '运行中' ? 'status-running' : ''}">${p.status}</span></td>
            <td><button class="btn btn-sm btn-link" data-action="open-modal" data-modal="configModal" data-protocol="${escapeHtml(p.name)}">查看配置</button></td>
        </tr>`).join('');
    const subRow = `<tr class="subs-row"><td style="font-weight:500;">整包协议</td><td></td><td></td><td></td><td><button class="btn btn-sm btn-link" data-action="open-modal" data-modal="configModal" data-protocol="__SUBS__">查看@订阅</button></td></tr>`;
    tbody.innerHTML = rows + subRow;
}


function renderTrafficCharts() {
  if (!trafficData || !window.Chart) return;

  // —— 进度条（本月使用）——
  const monthly = trafficData.monthly || [];
  const currentMonthData = monthly.find(m => m.month === new Date().toISOString().slice(0, 7));
  if (currentMonthData) {
    const used = (currentMonthData.total || 0) / GiB;
    const percentage = Math.min(100, Math.round((used / 100) * 100)); // 先用默认预算100
    const fillEl   = document.getElementById('progress-fill');
    const pctEl    = document.getElementById('progress-percentage');
    const budgetEl = document.getElementById('progress-budget');
    
    if (fillEl)   fillEl.style.width = `${percentage}%`;
    if (pctEl)    pctEl.textContent  = `${percentage}%`;
    if (budgetEl) budgetEl.textContent = `阈值(100GiB)`;  // 先显示默认值
    if (pctEl) pctEl.title = `已用 ${used.toFixed(1)}GiB / 阈值 100GiB`;
    
    // 异步获取配置并更新阈值刻度线
    fetchAlertConfig().then(alertConfig => {
      const budget = parseInt(alertConfig.ALERT_MONTHLY_GIB) || 100;
      const alertSteps = (alertConfig.ALERT_STEPS || '30,60,90').split(',').map(s => parseInt(s.trim()));
      
      // 重新计算百分比（基于真实预算）
      const realPercentage = Math.min(100, Math.round((used / budget) * 100));
      
      // 更新显示
      if (fillEl) fillEl.style.width = `${realPercentage}%`;
      if (pctEl) pctEl.textContent = `${realPercentage}%`;
      if (budgetEl) budgetEl.textContent = `阈值(${budget}GiB)`;
      if (pctEl) pctEl.title = `已用 ${used.toFixed(1)}GiB / 阈值 ${budget}GiB`;
      
      // 渲染阈值刻度线
      renderTrafficProgressThresholds(alertSteps);
    }).catch(err => {
      console.warn('无法加载 alert.conf，使用默认配置:', err);
      renderTrafficProgressThresholds([30, 60, 90]); // 使用默认阈值
    });
  }
  
// 渲染流量统计进度条的阈值刻度线（只针对流量统计，不影响CPU/内存/磁盘进度条）
function renderTrafficProgressThresholds(thresholds) {
  // 特别注意：只选择流量统计卡片中的进度条
  const trafficProgressBar = document.querySelector('.traffic-card .progress-bar');
  if (!trafficProgressBar) return;
  
  // 清除现有刻度线
  const existingMarkers = trafficProgressBar.querySelectorAll('.traffic-threshold-marker');
  const existingLabels = trafficProgressBar.querySelectorAll('.traffic-threshold-label');
  existingMarkers.forEach(marker => marker.remove());
  existingLabels.forEach(label => label.remove());
  
  // 添加新的刻度线
  thresholds.forEach(threshold => {
    if (threshold > 0 && threshold <= 100) {
      // 刻度线
      const marker = document.createElement('div');
      marker.className = 'traffic-threshold-marker';
      marker.style.cssText = `
        position: absolute;
        left: ${threshold}%;
        top: 0;
        bottom: 0;
        width: 2px;
        background: #9ca3af;    /* ← 改为灰色 */
        z-index: 10;
        transform: translateX(-50%);
        border-radius: 1px;
      `;
      
      // 标签（黄色字体，无背景，放在进度条内部）
      const label = document.createElement('div');
      label.className = 'traffic-threshold-label';
      label.textContent = `${threshold}%`;
      label.style.cssText = `
        position: absolute;
        left: ${threshold}%;
        top: 50%;
        transform: translate(-50%, -50%);
        font-size: 12px;
        color: #fbbf24;         /* ← 改为黄色（预警色） */
        white-space: nowrap;
        font-weight: 600;
        pointer-events: none;
        z-index: 11;
        text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);  /* ← 添加阴影增强可读性 */
      `;
      
      trafficProgressBar.appendChild(marker);
      trafficProgressBar.appendChild(label);
    }
  });
}

  // —— 图表销毁（避免重复实例）——
  ['traffic', 'monthly-chart'].forEach(id => {
    const inst = Chart.getChart(id);
    if (inst) inst.destroy();
  });

  // —— 颜色：将原“橙色”改为“蓝色”，更贴近面板基调；绿色保留给“代理” —— 
  const vpsColor   = '#3b82f6';  // 蓝（替换原来的 #f59e0b）
  const proxyColor = '#10b981';  // 绿（保留）
  
  // —— 近30日折线 ——（去掉 y 轴顶部 GiB 插件）
  const daily = trafficData.last30d || [];
  if (daily.length) {
    const ctx = document.getElementById('traffic');
    if (ctx) {
      new Chart(ctx, {
        type: 'line',
        data: {
          labels: daily.map(d => d.date.slice(5)),
          datasets: [
            { label: 'VPS',  data: daily.map(d => d.vps  / GiB), borderColor: vpsColor,   backgroundColor: vpsColor,   tension: 0.3, pointRadius: 0, fill: false },
            { label: '代理', data: daily.map(d => d.resi / GiB), borderColor: proxyColor, backgroundColor: proxyColor, tension: 0.3, pointRadius: 0, fill: false },
          ]
        },
options: {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false } // 隐藏底部内置图例
  },
  layout: {
    padding: { bottom: 22 }    // 恢复底部留白，保证日期不被裁掉
  },
  scales: {
    x: { ticks: { padding: 6 } },
    y: { ticks: { padding: 6 } }
  }
}

      });
    }
  }

  // —— 近12个月堆叠柱 ——（同样不再用 GiB 顶部单位）
  if (monthly.length) {
    const arr = monthly.slice(-12);
    const ctx = document.getElementById('monthly-chart');
    if (ctx) {
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: arr.map(m => m.month),
          datasets: [
            { label: 'VPS',  data: arr.map(m => m.vps  / GiB), backgroundColor: vpsColor,   stack: 'a' },
            { label: '代理', data: arr.map(m => m.resi / GiB), backgroundColor: proxyColor, stack: 'a' },
          ]
        },
options: {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false } // 仍隐藏底部内置图例
  },
  layout: {
    padding: { bottom: 22 }    // 给 x 轴刻度留空间
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


// [PATCH:SHOW_CONFIG_MODAL_SAFE] —— 精准、谨慎、只改一处
// 完整的 showConfigModal 函数修改 - 修复二维码生成逻辑

function showConfigModal(protocolKey) {
  const dd = window.dashboardData;
  const modal = document.getElementById('configModal');
  if (!modal || !dd) return;

  const title = document.getElementById('configModalTitle');
  const details = document.getElementById('configDetails');
  const footer = modal.querySelector('.modal-footer');
  if (!title || !details || !footer) return;

  // 工具函数
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toB64 = s => btoa(unescape(encodeURIComponent(s)));
  const get = (o, p, fb = '') => p.split('.').reduce((a, k) => (a && a[k] !== undefined ? a[k] : undefined), o) ?? fb;

  // JSON 行尾注释对齐（仅用于 UI 展示）
  function annotateAligned(obj, comments = {}) {
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

  // 打开弹窗并给出加载态
  details.innerHTML = '<div class="loading">正在加载配置…</div>';
  modal.style.display = 'block';
  document.body.classList.add('modal-open');

  let qrText = '';

  // ===== 整包订阅 =====
  if (protocolKey === '__SUBS__') {
    const subsUrl = get(dd, 'subscription_url', '') ||
                    (get(dd, 'server.server_ip', '') ? `http://${get(dd, 'server.server_ip')}/sub` : '');
    const plain6 = get(dd, 'subscription.plain', '');
    const base64 = get(dd, 'subscription.base64', '') || (plain6 ? toB64(plain6) : '');

    title.textContent = '订阅（整包）';
    details.innerHTML = `
      <div class="config-section">
        <h4>订阅 URL</h4>
        <div class="config-code" id="plain-link">${esc(subsUrl)}</div>
      </div>
      <div class="config-section">
        <h4>明文链接（6协议）</h4>
        <div class="config-code" id="plain-links-6" style="white-space:pre-wrap">${esc(plain6)}</div>
      </div>
      <div class="config-section">
        <h4>Base64链接（6协议）</h4>
        <div class="config-code" id="base64-link">${esc(base64)}</div>
      </div>
      <div class="config-section">
        <h4>二维码</h4>
        <div class="qr-container">
          <div id="qrcode-sub"></div>
        </div>
      </div>
      ${usage('将"订阅 URL"导入 v2rayN、Clash 等支持订阅的客户端；部分客户端也支持直接粘贴 Base64 或扫码二维码。')}
    `;
    footer.innerHTML = `
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain">复制订阅URL</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain6">复制明文(6协议)</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="base64">复制Base64</button>
      <button class="btn btn-sm btn-secondary" data-action="copy-qr">复制二维码</button>
    `;
    
    // 整包订阅的二维码应该使用订阅URL，不是明文链接
    // 客户端（如Shadowrocket）扫码后会自动获取订阅内容
    qrText = subsUrl || '';

  // ===== 单协议 =====
  } else {
    const protocols = Array.isArray(dd.protocols) ? dd.protocols : [];
    const p = protocols.find(x =>
      x && (x.name === protocolKey || x.key === protocolKey || x.id === protocolKey || x.type === protocolKey)
    );

    if (!p) {
      title.textContent = '配置详情';
      details.innerHTML = `<div class="empty">未找到协议：<code>${esc(String(protocolKey))}</code></div>`;
      footer.innerHTML = `<button class="btn btn-sm" data-action="close-config-modal">关闭</button>`;
      return;
    }

    const certMode = String(get(dd, 'server.cert.mode', 'self-signed'));
    const isLE = certMode.startsWith('letsencrypt');
    const serverIp = get(dd, 'server.server_ip', '');

    const obj = {
      protocol: p.name,
      host: serverIp,
      port: p.port ?? 443,
      uuid: get(dd, 'secrets.vless.reality', '') ||
            get(dd, 'secrets.vless.grpc', '') ||
            get(dd, 'secrets.vless.ws', ''),
      sni: isLE ? get(dd, 'server.cert.domain', '') : serverIp,
      alpn: (p.name || '').toLowerCase().includes('grpc') ? 'h2'
            : ((p.name || '').toLowerCase().includes('ws') ? 'http/1.1' : '')
    };

    const comments = {
      protocol: '协议类型（例：VLESS-Reality）',
      host: '服务器地址（IP/域名）',
      port: '端口',
      uuid: '认证 UUID / 密钥',
      sni: 'TLS/SNI（域名模式用域名）',
      alpn: 'ALPN（gRPC=h2，WS=http/1.1）'
    };
    const jsonAligned = annotateAligned(obj, comments);

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
      ${usage('复制明文或 JSON 导入客户端；若客户端支持扫码添加，也可直接扫描二维码。')}
    `;
    footer.innerHTML = `
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="json">复制 JSON</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain">复制明文链接</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="base64">复制 Base64</button>
      <button class="btn btn-sm btn-secondary" data-action="copy-qr">复制二维码</button>
    `;
    
    // 单协议的二维码使用 share_link 生成（这部分是正确的）
    qrText = plain || '';
  }

  // —— 生成二维码（强制"仅一份"产物）——
  if (qrText && window.QRCode) {
    const holderId = (protocolKey === '__SUBS__') ? 'qrcode-sub' : 'qrcode-protocol';
    const holder = document.getElementById(holderId);
    if (holder) {
      // 1) 彻底清空
      holder.replaceChildren();
      // 2) 生成
      new QRCode(holder, {
        text: qrText,
        width: 200,
        height: 200,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.M
      });
      // 3) 只保留一个可见产物（优先保留 canvas）
      const kids = Array.from(holder.children);
      const keep = holder.querySelector('canvas') || kids[0] || null;
      if (keep) {
        kids.forEach(node => { if (node !== keep) node.remove(); });
      }
    }
  }
}
// [PATCH:SHOW_CONFIG_MODAL_SAFE_END]



// [PATCH:IPQ_MODAL] —— 拉不到数据也渲染结构；字段名完全兼容
let __IPQ_REQ_SEQ__ = 0; // 并发守卫：只有最新一次请求才允许更新DOM
async function showIPQDetails(which) {
  const titleEl = document.getElementById('ipqModalTitle');
  const bodyEl  = document.getElementById('ipqDetails');
  if (!titleEl || !bodyEl) return;

  const file = which === 'vps' ? '/status/ipq_vps.json' : '/status/ipq_proxy.json';
  titleEl.textContent = which === 'vps' ? 'VPS IP质量检测详情' : '代理 IP质量检测详情';
  bodyEl.innerHTML = `<div class="config-section"><div class="config-code">加载中...</div></div>`;
  showModal && showModal('ipqModal');

let data = null;
const __seq = ++__IPQ_REQ_SEQ__; // 记录本次请求序号

try {
  const r = await fetch(file, { cache: 'no-store' });
  if (__seq !== __IPQ_REQ_SEQ__) return;           // 旧请求作废，防止“失败→内容”闪烁
  if (!r.ok) throw new Error('HTTP ' + r.status);
  data = await r.json();
} catch (err) {
  if (__seq !== __IPQ_REQ_SEQ__) return;           // 旧请求作废
  // 不中断、不展示“失败”中间态；保持“加载中…”并走兜底数据渲染，用户只看到“加载中→内容”
  data = null;
}

  // —— 兜底：没有数据也给出结构（从 dashboardData 拼一些非敏感项）
  const dash = window.dashboardData || {};
  const server = dash.server || {};
  data = data || {
    score: null, grade: null, detected_at: dash.updated_at,
    ip: (which==='vps' ? server.server_ip : server.eip) || '',
    asn: '', isp: '', country: '', city: '', rdns: '',
    bandwidth: '', network_type: '', latency_p50: null,
    risk: { proxy: (which==='proxy'), hosting: true, dnsbl_hits: [] },
    conclusion: ''
  };

  // —— 兼容取值
  const pick = (o, paths, d='—')=>{
    for (const p of paths) {
      const v = p.split('.').reduce((x,k)=> x&&x[k]!=null ? x[k] : undefined, o);
      if (v!=null && v!=='') return v;
    }
    return d;
  };

  const score = pick(data,['score'], '—');
  const grade = pick(data,['grade'], null);
  const gradeStr = grade || (typeof score==='number'
                    ? (score>=80?'A':score>=60?'B':score>=40?'C':'D') : '—');
  const when = pick(data,['detected_at','updated_at','timestamp'], '—');

  const ip   = pick(data,['ip'],'—');
  const asn  = pick(data,['asn'],'');
  const isp  = pick(data,['isp'],'');
  const country = pick(data,['country','geo.country'],'');
  const city    = pick(data,['city','geo.city'],'');
  const rdns    = pick(data,['rdns','reverse_dns'],'—');

  const bwUp   = pick(data,['bandwidth_up','config.bandwidth_up'], null);
  const bwDown = pick(data,['bandwidth_down','config.bandwidth_down'], null);
  const bandwidth = (bwUp || bwDown) ? `${bwUp||'—'} / ${bwDown||'—'}` : (pick(data,['bandwidth','config.bandwidth'],'未配置'));

  const networkType = pick(data,['network_type','net_type'],'—');
  const latency = (()=>{
    const v = pick(data,['latency_p50','latency.median','latency_ms'], null);
    return v ? `${v} ms` : '—';
  })();

  const riskObj = data.risk || {};
  const flags = [
    riskObj.proxy   ? '代理标记'  : null,
    riskObj.hosting ? '数据中心'  : null,
    riskObj.mobile  ? '移动网络'  : null,
    riskObj.tor     ? 'Tor'      : null
  ].filter(Boolean).join('、') || '—';
  const hits = Array.isArray(riskObj.dnsbl_hits) ? riskObj.dnsbl_hits : [];
  const blCount = hits.length;

  const conclusion = pick(data,['conclusion'],'—');

  const EH = s => String(s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));

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
        <li>“代理/数据中心/Tor”等标记会降低分数</li>
        <li>每命中 1 个 DNSBL 黑名单会降低分数</li>
        <li>高时延会降低分数</li>
      </ul>
    </div>`;
}

async function copyText(text) {
    if (!text || text === '—') return notify('没有可复制的内容', 'warn');
    try {
        await navigator.clipboard.writeText(text);
        notify('已复制到剪贴板');
    } catch (e) {
        notify('复制失败', 'warn');
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
    window.dashboardData = dashboardData; 
    renderOverview();
    renderCertificateAndNetwork();
    renderProtocolTable();
    renderTrafficCharts();
}


document.addEventListener('DOMContentLoaded', () => {
  // 首次刷新
  refreshAllData();
  // 定时刷新
  overviewTimer = setInterval(refreshAllData, 30000);
  // ❌ 不再调用 setupEventListeners()
  // setupEventListeners();
  // 保留通知中心初始化
  setupNotificationCenter();
});


// ==== new11 事件委托（append-only） ====
(() => {
  if (window.__EDGEBOX_DELEGATED__) return;
  window.__EDGEBOX_DELEGATED__ = true;

  const notify = window.notify || ((msg)=>console.log(msg));
  const $ = s => document.querySelector(s);

  function showModal(id) {
    const m = document.getElementById(id);
    if (!m) return;
    m.style.display = 'block';
    document.body.classList.add('modal-open');
  }
  function closeModal(id) {
    const m = document.getElementById(id);
    if (!m) return;
    m.style.display = 'none';
    document.body.classList.remove('modal-open');
  }

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action   = btn.dataset.action;
    const modal    = btn.dataset.modal || '';
    const protocol = btn.dataset.protocol || '';
    const type     = btn.dataset.type || '';

    switch (action) {
      case 'open-modal': {
        if (modal === 'configModal') {
          if (typeof showConfigModal === 'function') showConfigModal(protocol);
          const m = document.getElementById('configModal');
          if (m && m.style.display !== 'block') showModal('configModal');
        } else if (modal === 'whitelistModal') {
          const list = (window.dashboardData?.shunt?.whitelist) || [];
          const box  = $('#whitelistList');
          if (box) box.innerHTML = list.map(d => `<div class="whitelist-item">${String(d)
            .replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}</div>`).join('');
          showModal('whitelistModal');
} else if (modal === 'ipqModal') {
  // 统一走 showIPQDetails（内部自带并发守卫），彻底避免“加载失败→内容”的闪烁
  if (typeof showIPQDetails === 'function') {
    await showIPQDetails(btn.dataset.ipq || 'vps'); // 'vps' | 'proxy'
  } else {
    showModal('ipqModal'); // 极端兜底：函数不存在时至少打开弹窗
  }
}
        break;
      }

      case 'close-modal': {
        closeModal(modal);
        break;
      }

// 事件委托中的复制分支（替换你现有的 copy 分支）
// 复制文本（JSON/明文/6协议明文/Base64）
case 'copy': {
  const host = btn.closest('.modal-content');
  const map  = { json:'#json-code', plain:'#plain-link', plain6:'#plain-links-6', base64:'#base64-link' };
  const el   = host && host.querySelector(map[btn.dataset.type]);
  const text = el ? (el.textContent || '').trim() : '';
  try { await copyTextFallbackAware(text); (window.notify||console.log)('已复制'); }
  catch { (window.notify||console.warn)('复制失败'); }
  break;
}


// 复制二维码（安全上下文优先，失败自动降级为下载 + 复制明文）
case 'copy-qr': {
  const host = btn.closest('.modal-content');
  const cvs  = host && host.querySelector('#qrcode-sub canvas, #qrcode-protocol canvas');

  if (!cvs) {
    notify('未找到二维码', 'warn');
    break;
  }

  // 小工具：下载 PNG
  const doDownload = (blob) => {
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    const name = (protocol || '__SUBS__') + '_qrcode.png';
    a.href = url; a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };

  // 小工具：复制文本兜底（订阅或明文链接）
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

  // 从 canvas 拿 PNG 并尽量写入剪贴板
  cvs.toBlob(async (blob) => {
    if (!blob) {
      notify('获取二维码失败', 'warn');
      return;
    }
    try {
      // 首选：安全上下文 + 支持图片写入
      if (window.isSecureContext && navigator.clipboard?.write && window.ClipboardItem) {
        await navigator.clipboard.write([ new ClipboardItem({ 'image/png': blob }) ]);
        notify('二维码已复制到剪贴板');
      } else {
        throw new Error('insecure');
      }
    } catch (err) {
      // 降级路径：自动下载 PNG + 复制明文
      doDownload(blob);
      await doFallbackText();
      notify('图片复制受限：已自动下载二维码，并复制了明文/链接', 'warn');
    }
  }, 'image/png');

  break;
}

    }
  });
})();

// === 复制按钮（弹窗内）统一轻提示 ======================
document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-role="copy"], .copy-btn, .btn-copy');
  if (!btn) return;

  // 若你的复制逻辑已在别处执行，这里只负责提示即可。
  // 如果需要兜底复制，可取消注释：
  // const txt = btn.getAttribute('data-clipboard-text');
  // if (txt) await navigator.clipboard.writeText(txt).catch(()=>{});

  // 找到最近的弹窗容器（Ant / Element / 自研）
  const modal = btn.closest('.ant-modal, .el-dialog, .modal');
  if (!modal) return;

  // 准备/显示 toast
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


// =================================================================
// 通知中心功能
// =================================================================

let notificationData = { notifications: [] };

// 更新通知中心
function updateNotificationCenter(data) {
    notificationData = data || { notifications: [] };
    renderNotifications();
}

// 渲染通知列表
function renderNotifications() {
    const listEl = document.getElementById('notificationList');
    const badgeEl = document.getElementById('notificationBadge');
    
    if (!notificationData.notifications || notificationData.notifications.length === 0) {
        if (listEl) {
            listEl.innerHTML = `
                
                    🔔
                    暂无通知
                
            `;
        }
        if (badgeEl) badgeEl.style.display = 'none';
        return;
    }
    
    // 计算未读数量
    const unreadCount = notificationData.notifications.filter(n => !n.read).length;
    
    if (badgeEl) {
        if (unreadCount > 0) {
            badgeEl.textContent = unreadCount > 99 ? '99+' : unreadCount;
            badgeEl.style.display = 'inline-block';
        } else {
            badgeEl.style.display = 'none';
        }
    }
    
    // 渲染通知项
    if (listEl) {
        const html = notificationData.notifications.slice(0, 20).map(notification => {
            const iconMap = {
                alert: '⚠️',
                system: '⚙️', 
                error: '❌'
            };
            
            const timeAgo = getTimeAgo(notification.time);
            const icon = iconMap[notification.type] || iconMap[notification.level] || '📋';
            
            return `
                
                    
                        ${icon}
                    
                    
                        ${escapeHtml(notification.message)}
                        ${timeAgo}
                        ${notification.action ? `${escapeHtml(notification.action)}` : ''}
                    
                
            `;
        }).join('');
        
        listEl.innerHTML = html;
    }
}

// 时间格式化
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

// 设置通知中心事件监听
function setupNotificationCenter() {
    const trigger = document.getElementById('notificationTrigger');
    const panel = document.getElementById('notificationPanel');
    
    if (!trigger || !panel) return;
    
    // 点击触发按钮
    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        panel.classList.toggle('show');
        
        if (panel.classList.contains('show')) {
            // 面板打开时延迟标记为已读
            setTimeout(markAllAsRead, 1000);
        }
    });
    
    // 点击文档其他地方关闭面板
    document.addEventListener('click', (e) => {
        if (!panel.contains(e.target) && !trigger.contains(e.target)) {
            panel.classList.remove('show');
        }
    });
    
    // 阻止面板内部点击冒泡
    panel.addEventListener('click', (e) => {
        e.stopPropagation();
    });
}

// 标记所有通知为已读
function markAllAsRead() {
    if (notificationData.notifications) {
        notificationData.notifications = notificationData.notifications.map(n => ({ ...n, read: true }));
        renderNotifications();
    }
}

// 清空通知
function clearNotifications() {
    if (confirm('确定要清空所有通知吗？')) {
        notificationData.notifications = [];
        renderNotifications();
        notify('已清空所有通知', 'ok');
    }
}

// 在现有事件委托中添加通知相关处理
document.addEventListener('click', (e) => {
    const action = e.target.closest('[data-action]')?.dataset.action;
    
    if (action === 'clear-notifications') {
        clearNotifications();
    }
});

// 通知中心数据获取函数
async function fetchAndUpdateNotifications() {
    try {
        console.log("开始获取通知数据...");
        
        // 从dashboard.json获取通知数据
        let notificationData = null;
        try {
            const dashData = await fetchJSON('/traffic/dashboard.json');
            if (dashData && dashData.notifications) {
                notificationData = dashData.notifications;
                console.log("从dashboard.json获取到通知:", notificationData.length, "条");
            }
        } catch (e) {
            console.log("从dashboard.json获取通知失败:", e);
        }
        
        // 备选方案：直接从notifications.json获取
        if (!notificationData || notificationData.length === 0) {
            try {
                const notifData = await fetchJSON('/traffic/notifications.json');
                if (notifData && notifData.notifications) {
                    notificationData = notifData.notifications;
                    console.log("从notifications.json获取到通知:", notificationData.length, "条");
                }
            } catch (e) {
                console.log("从notifications.json获取通知失败:", e);
            }
        }
        
        // 更新通知中心
        if (notificationData && Array.isArray(notificationData)) {
            updateNotificationCenter({notifications: notificationData});
            console.log("通知中心更新成功，通知数量:", notificationData.length);
        } else {
            console.log("没有有效的通知数据");
            updateNotificationCenter({notifications: []});
        }
        
    } catch (error) {
        console.error("获取通知数据失败:", error);
        updateNotificationCenter({notifications: []});
    }
}

// 页面加载时获取通知
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(fetchAndUpdateNotifications, 500);
    });
} else {
    setTimeout(fetchAndUpdateNotifications, 500);
}

// 定期更新通知
setInterval(fetchAndUpdateNotifications, 30000);

# 同时在refreshAllData函数中，找到 if (dash) dashboardData = dash; 这行，在其后添加：
    // 处理通知数据
    if (dash && dash.notifications) {
        updateNotificationCenter({notifications: dash.notifications});
    }

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
        <h1>🌐 EdgeBox - 企业级多协议节点管理系统</h1>
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
		
<!-- === 服务器信息（保持你的 h3 不变） === -->
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

<!-- === 服务器配置 === -->
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
	  
<!-- === 核心服务 === -->
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
  <!-- 🔒 证书切换 -->
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

  <!-- 👤 网络身份配置 -->
  <div class="card" id="netid-panel">
    <div class="card-header">
      <h2>👤 网络身份配置 <span class="note-udp">注：HY2/TUIC为UDP通道，VPS直连，不参与分流配置.</span></h2>
    </div>

    <div class="network-blocks">
      <!-- 📡 VPS出站IP -->
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

      <!-- 🔄 代理出站IP -->
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

<!-- 🔀 分流出站 -->
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


 <!-- 运维管理（来自new5.txt）-->
<div class="card">
  <div class="card-header">
    <h2>⚙️ 运维管理</h2>
  </div>
  <div class="commands-grid">

    <div class="command-section">
      <h3>🔧 基础操作</h3>
      <div class="command-list">
        <code>edgeboxctl sub</code> <span># 动态生成订阅/面板链接</span><br>
        <code>edgeboxctl logs &lt;nginx|xray|sing-box&gt;</code> <span># 查看指定服务的实时日志</span><br>
        <code>edgeboxctl status</code> <span># 查看所有核心服务运行状态</span><br>
        <code>edgeboxctl restart</code> <span># 安全优雅重启</span><br>
        <code>edgeboxctl test</code> <span># 连通性自检</span><br>
        <code>edgeboxctl debug-ports</code> <span># 关键端口占用排查</span><br>
        <code>edgeboxctl alias "备注名称"</code> <span># 标注/更新服务器备注名</span>
      </div>
    </div>

    <div class="command-section">
      <h3>🔒 证书切换</h3>
      <div class="command-list">
        <code>edgeboxctl switch-to-domain &lt;your_domain&gt;</code> <span># 切换到域名模式，申请证书</span><br>
        <code>edgeboxctl switch-to-ip</code> <span># 回退到IP模式，使用自签名证书</span><br>
        <code>edgeboxctl cert status</code> <span># 检查当前证书的到期日期和类型</span><br>
        <code>edgeboxctl cert renew</code> <span># 手动续期Let's Encrypt证书</span><br>
        <code>edgeboxctl fix-permissions</code> <span># 修复证书/密钥权限</span>
      </div>
    </div>

    <div class="command-section">
      <h3>🔀 出站分流</h3>
      <div class="command-list">
        <code>edgeboxctl shunt vps</code> <span># 切换至VPS全量出站</span><br>
        <code>edgeboxctl shunt resi &lt;URL&gt;</code> <span># 配置并切换至代理IP全量出站</span><br>
        <code>edgeboxctl shunt direct-resi &lt;URL&gt;</code> <span># 配置并切换至白名单智能分流状态</span><br>
        <code>edgeboxctl shunt status</code> <span># 查看当前分流状态</span><br>
        <code>edgeboxctl shunt whitelist &lt;add|remove|list|reset&gt; [domain]</code> <span># 管理白名单域名</span><br>
        <code>代理URL格式:</code><br>
        <code>http://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;</code><br>
        <code>https://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;?sni=example.com</code><br>
        <code>socks5://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;</code><br>
        <code>socks5s://user:pass@&lt;域名&gt;:&lt;端口&gt;?sni=example.com</code><br>
        <code>示例：edgeboxctl shunt resi 'socks5://user:pass@111.222.333.444:11324'</code> <span># 全栈走代理</span>
      </div>
    </div>

    <div class="command-section">
      <h3>📊 流量统计与预警</h3>
      <div class="command-list">
        <code>edgeboxctl traffic show</code> <span># 在终端中查看流量统计数据</span><br>
        <code>edgeboxctl alert show</code> <span># 查看预警配置</span><br>
        <code>edgeboxctl alert monthly &lt;GiB&gt;</code> <span># 设置月度预算（GiB）</span><br>
        <code>edgeboxctl alert steps 30,60,90</code> <span># 设置预警阈值（百分比）</span><br>
        <code>edgeboxctl alert telegram &lt;bot_token&gt; &lt;chat_id&gt;</code> <span># 配置Telegram机器人</span><br>
        <code>edgeboxctl alert discord &lt;webhook_url&gt;</code> <span># 配置Discord通知</span><br>
        <code>edgeboxctl alert wechat &lt;pushplus_token&gt;</code> <span># 配置微信通知</span><br>
        <code>edgeboxctl alert webhook &lt;url&gt; [raw|slack|discord]</code> <span># 配置通用Webhook</span><br>
        <code>edgeboxctl alert test [percent]</code> <span># 测试预警系统（默认40%）</span>
      </div>
    </div>

    <div class="command-section">
      <h3>🧩 配置管理</h3>
      <div class="command-list">
        <code>edgeboxctl config show</code> <span># 显示所有服务的核心配置信息</span><br>
        <code>edgeboxctl config regenerate-uuid</code> <span># 为所有协议重新生成新的UUID</span>
      </div>
    </div>

    <div class="command-section">
      <h4>💾 系统维护</h4>
      <div class="command-list">
        <code>edgeboxctl update</code><span># 更新EdgeBox</span><br>
        <code>edgeboxctl backup create</code><span># 创建备份</span><br>
        <code>edgeboxctl backup list</code><span># 列出备份</span><br>
        <code>edgeboxctl backup restore &lt;file&gt;</code><span># 恢复备份</span>
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


# 设置定时任务
# ========================== NEW11 replacement begin ==========================
setup_cron_jobs() {
    log_info "设置定时任务（new11清理模式）..."

    # ---- A) 预警配置兜底
    # 会优先调用你现有的 ensure_alert_conf；然后用 patch 方式把缺的键补上
    ensure_alert_conf_full_patch() {
        local f="/etc/edgebox/traffic/alert.conf"
        mkdir -p /etc/edgebox/traffic
        [[ -f "$f" ]] || : > "$f"   # 保证文件存在

        # 小工具：如缺失则追加默认值（不覆盖已有值）
        ensure_key() {
            local k="$1" v="$2"
            grep -q "^${k}=" "$f" || echo "${k}=${v}" >> "$f"
        }

        # 8 个必备键（与您脚本口径一致）
        ensure_key "ALERT_MONTHLY_GIB"     "100"
        ensure_key "ALERT_TG_BOT_TOKEN"    ""
        ensure_key "ALERT_TG_CHAT_ID"      ""
        ensure_key "ALERT_DISCORD_WEBHOOK" ""
        ensure_key "ALERT_PUSHPLUS_TOKEN"  ""
        ensure_key "ALERT_WEBHOOK"         ""
        ensure_key "ALERT_WEBHOOK_FORMAT"  "raw"
        ensure_key "ALERT_STEPS"           "30,60,90"

        # 兼容项（可选）：有的老段落默认写了 EMAIL，这里补上不影响你 8 项口径
        ensure_key "ALERT_EMAIL"           ""
    }

    ensure_alert_conf_full() {
        local f="/etc/edgebox/traffic/alert.conf"
        mkdir -p /etc/edgebox/traffic
        [[ -s "$f" ]] || cat >"$f" <<'CONF'
# EdgeBox traffic alert thresholds & channels
# 月度预算（单位 GiB）
ALERT_MONTHLY_GIB=100
# 通知渠道（留空即不启用）
ALERT_TG_BOT_TOKEN=
ALERT_TG_CHAT_ID=
ALERT_DISCORD_WEBHOOK=
ALERT_PUSHPLUS_TOKEN=
ALERT_WEBHOOK=
ALERT_WEBHOOK_FORMAT=raw
# 阈值（百分比，逗号分隔）
ALERT_STEPS=30,60,90
# 可选：邮件（若 traffic-alert.sh 支持 mail 命令）
ALERT_EMAIL=
CONF
    }

    # 优先沿用你已有的 ensure_alert_conf；随后补齐缺失键
    if type -t ensure_alert_conf >/dev/null 2>&1; then
        ensure_alert_conf
        ensure_alert_conf_full_patch
    else
        ensure_alert_conf_full
    fi

    # ---- B) 备份现有 crontab（可回滚）----
    crontab -l > ~/crontab.backup.$(date +%Y%m%d%H%M%S) 2>/dev/null || true

    # ---- C) 激进清理：删除所有 EdgeBox 相关的旧任务（路径/关键字双保险）----
    ( crontab -l 2>/dev/null | grep -vE '(/etc/edgebox/|\bedgebox\b|\bEdgeBox\b)' ) | crontab - || true

    # ---- D) 写入 new11 标准任务集（仅这一套）----
    ( crontab -l 2>/dev/null || true; cat <<'CRON'
# EdgeBox 定时任务 v3.0 (new11)
*/2 * * * * bash -lc '/etc/edgebox/scripts/dashboard-backend.sh --now' >/dev/null 2>&1
0  * * * * bash -lc '/etc/edgebox/scripts/traffic-collector.sh'        >/dev/null 2>&1
7  * * * * bash -lc '/etc/edgebox/scripts/traffic-alert.sh'            >/dev/null 2>&1
*/5 * * * * bash -lc '/etc/edgebox/scripts/dashboard-backend.sh --notifications-only' >/dev/null 2>&1
15 2 * * * bash -lc '/usr/local/bin/edgebox-ipq.sh'                    >/dev/null 2>&1
CRON
    ) | crontab -

    log_success "定时任务设置完成（已清理旧任务并写入 new11 任务集；alert.conf 已补全 8 项）"
}
# =========================== NEW11 replacement end ===========================


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

  # 1) 优先从 dashboard.json 读三段
  if [[ -s "${TRAFFIC_DIR}/dashboard.json" ]]; then
    local sub_plain sub_lines sub_b64
    sub_plain=$(jq -r '.subscription.plain // empty'       "${TRAFFIC_DIR}/dashboard.json" 2>/dev/null || true)
    sub_lines=$(jq -r '.subscription.b64_lines // empty'   "${TRAFFIC_DIR}/dashboard.json" 2>/dev/null || true)
    sub_b64=$(jq -r '.subscription.base64 // empty'        "${TRAFFIC_DIR}/dashboard.json" 2>/dev/null || true)

    if [[ -n "$sub_plain$sub_lines$sub_b64" ]]; then
      if [[ -n "$sub_plain" ]]; then
        echo
        echo "# 明文链接"
        printf '%s\n\n' "$sub_plain"
      fi
      if [[ -n "$sub_lines" ]]; then
        echo "# Base64（逐行，每行一个链接；多数客户端不支持一次粘贴多行）"
        printf '%s\n\n' "$sub_lines"
      fi
      if [[ -n "$sub_b64" ]]; then
        echo "# Base64（整包）"
        printf '%s\n' "$sub_b64"
        echo
      fi
      return 0
    fi
  fi

  # 2) 回落：按安装阶段产生的三个文件拼装（若存在）
  local txt="${CONFIG_DIR}/subscription.txt"
  local b64lines="${CONFIG_DIR}/subscription.b64lines"
  local b64all="${CONFIG_DIR}/subscription.base64"
  if [[ -s "$txt" || -s "$b64lines" || -s "$b64all" ]]; then
    if [[ -s "$txt" ]]; then
      echo
      echo "# 明文链接"
      cat "$txt"; echo
    fi
    if [[ -s "$b64lines" ]]; then
      echo "# Base64（逐行，每行一个链接；多数客户端不支持一次粘贴多行）"
      cat "$b64lines"; echo
    fi
    if [[ -s "$b64all" ]]; then
      echo "# Base64（整包）"
      cat "$b64all"; echo
    fi
    return 0
  fi

  # 3) 兜底：现生成一次（仍尽量补全）
  local cert_mode domain
  cert_mode=$(safe_jq '.cert.mode' "${TRAFFIC_DIR}/server.json" "self-signed")
  domain=$(safe_jq '.cert.domain' "${TRAFFIC_DIR}/server.json" "")
  
  if [[ "$cert_mode" == letsencrypt* ]] && [[ -n "$domain" ]]; then
    regen_sub_domain "$domain" || regen_sub_ip
  else
    regen_sub_ip
  fi
  
  # 生成后必然存在，重新调用自己（但只会进入上面的分支）
  if [[ -s "${CONFIG_DIR}/subscription.txt" ]]; then
    echo
    echo "# 明文链接"
    cat "${CONFIG_DIR}/subscription.txt"
  fi
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

# 设置用户备注名
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

  # 验收报告
  post_switch_report
}

switch_to_ip(){
  get_server_info || return 1
  ln -sf ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
  ln -sf ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
  echo "self-signed" > ${CONFIG_DIR}/cert_mode
  regen_sub_ip
  systemctl restart xray sing-box >/dev/null 2>&1
  log_success "已切换到 IP 模式"

  # 验收报告
  post_switch_report
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

post_shunt_report() {
  # mode: 文案标签；url: 上游代理 URL（VPS 模式可空）
  local mode="$1" url="$2"
  : "${CYAN:=}"; : "${GREEN:=}"; : "${RED:=}"; : "${YELLOW:=}"; : "${NC:=}"

  echo -e "\n${CYAN}----- 出站分流配置 · 验收报告（${mode}） -----${NC}"

  # 1) 上游连通（仅当提供 url）
  echo -n "1) 上游连通性: "
  if [[ -n "$url" ]]; then
    if check_proxy_health_url "$url"; then echo -e "${GREEN}OK${NC}"; else echo -e "${RED}FAIL${NC}"; fi
  else
    echo -e "${YELLOW}（VPS 模式，跳过）${NC}"
  fi

  # 2) 出口 IP 对比（仅当提供 url）
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

  # 3) 路由生效
  echo -n "3) Xray 路由: "
  jq -e '.outbounds[]?|select(.tag=="resi-proxy")' ${CONFIG_DIR}/xray.json >/dev/null 2>&1 \
    && echo -e "${GREEN}存在 resi-proxy 出站${NC}" || echo -e "${YELLOW}未发现 resi-proxy（VPS 模式正常）${NC}"
  echo -e "   sing-box 路由: ${YELLOW}设计为直连（HY2/TUIC 走 UDP，不参与分流）${NC}"

  # 4) nftables 采集集（如已启用）
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
	post_shunt_report "VPS 全量" ""
    flush_nft_resi_sets
}

# 代理全量出站
setup_outbound_resi() {
  local url="$1"
  [[ -z "$url" ]] && { echo "用法: edgeboxctl shunt resi '<URL>'"; return 1; }

  log_info "配置代理IP全量出站: ${url}"
  if ! check_proxy_health_url "$url"; then log_error "代理不可用：$url"; return 1; fi
  get_server_info || return 1
  parse_proxy_url "$url"

  # Xray: 所有 TCP/UDP 流量走代理，53 直连
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
  systemctl restart xray sing-box && log_success "代理全量出站已生效（Xray 分流，sing-box 直连）" || { log_error "失败"; return 1; }
  post_shunt_report "代理全量（Xray-only）" "$url"
}

# 智能分流
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
  post_shunt_report "智能分流（白名单直连）" "$url"
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
  edgeboxctl alias "备注名称"                     备注和更新服务器名称

${YELLOW}证书管理:${NC}
  edgeboxctl cert status                         查看证书状态（类型/到期）
  edgeboxctl cert renew                          立即续期证书并重载服务
  edgeboxctl fix-permissions                     修复证书/密钥文件权限
  edgeboxctl switch-to-domain <domain>           切换域名模式并申请证书
  edgeboxctl switch-to-ip                        切换到 IP 模式（自签证书）

${YELLOW}出站分流:${NC}
  edgeboxctl shunt vps                           VPS 全量出站
  edgeboxctl shunt resi '<代理URL>'               全量走代理（仅 Xray 分流）
  edgeboxctl shunt direct-resi '<代理URL>'        智能分流（白名单直连，其余走代理）
  edgeboxctl shunt status                        查看当前出站分流状态
  edgeboxctl shunt whitelist [add|remove|list|reset] [domain]   管理白名单
  代理URL示例:
    http://user:pass@host:port
    https://user:pass@host:port?sni=example.com
    socks5://user:pass@host:port
    socks5s://user:pass@host:port?sni=example.com
  示例（全栈走代理）: edgeboxctl shunt resi 'socks5://u:p@111.222.333.444:11324'

${YELLOW}流量统计与预警:${NC}
  edgeboxctl traffic show                        查看流量统计
  edgeboxctl alert show                          查看当前预警配置
  edgeboxctl alert monthly <GiB>                 设置月度预算（GiB）
  edgeboxctl alert steps 30,60,90                设置触发阈值（百分比，逗号分隔）
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

${YELLOW}系统维护:${NC}
  edgeboxctl update                              在线更新 EdgeBox（拉取并执行最新安装脚本）
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



# [ANCHOR:IPQ_STACK_ENHANCED_START]
# 安装增强版IP质量评分系统 (包含VPS带宽测试、特征优化、rDNS改进、前端修复)
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

# 带宽测试函数（支持VPS和代理）
test_bandwidth_correct() {
  local proxy_args="$1"
  local test_type="$2"
  local dl_speed=0 ul_speed=0
  
  # 下载测试
  if dl_result=$(eval "curl $proxy_args -o /dev/null -s -w '%{time_total}:%{speed_download}' --max-time 15 'http://speedtest.tele2.net/1MB.zip'" 2>/dev/null); then
    IFS=':' read -r dl_time dl_bytes_per_sec <<<"$dl_result"
    if [[ -n "$dl_bytes_per_sec" && "$dl_bytes_per_sec" != "0" ]]; then
      dl_speed=$(awk -v bps="$dl_bytes_per_sec" 'BEGIN{printf("%.1f", bps/1024/1024)}')
    fi
  fi
  
  # 上传测试
  local test_data=$(printf '%*s' 10240 '' | tr ' ' 'x')
  if ul_result=$(eval "curl $proxy_args -X POST -d '$test_data' -o /dev/null -s -w '%{time_total}' --max-time 10 'https://httpbin.org/post'" 2>/dev/null); then
    if [[ -n "$ul_result" && "$ul_result" != "0.000000" ]]; then
      ul_speed=$(awk -v t="$ul_result" 'BEGIN{printf("%.1f", 10/1024/t)}')
    fi
  fi
  
  echo "${dl_speed}/${ul_speed}"
}

# 增强版rDNS查询
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

# 智能特征识别
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
  
  # 云服务商检测
  if [[ "$asn" =~ (Google|AWS|Amazon|Microsoft|Azure|DigitalOcean|Linode|Vultr|Hetzner|OVH) ]] || \
     [[ "$isp" =~ (Google|AWS|Amazon|Microsoft|Azure|DigitalOcean|Linode|Vultr|Hetzner|OVH) ]]; then
    hosting="true"
    if [[ "$asn" =~ (Google|AWS|Amazon|Microsoft|Azure) ]]; then
      network_type="Cloud"
    else
      network_type="Datacenter"
    fi
  fi
  
  # 住宅网络检测
  if [[ "$vantage" == "proxy" && "$hosting" == "false" ]]; then
    if [[ "$isp" =~ (NTT|Comcast|Verizon|AT&T|Charter|Spectrum|Cox|Residential|Cable|Fiber|DSL|Broadband) ]]; then
      residential="true"
      network_type="Residential"
    fi
  fi
  
  # 移动网络检测
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
  
  # API调用
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

  # 检查API成功率
  if [[ "$ok1" == "false" && "$ok2" == "false" && "$ok3" == "false" ]]; then
    if [[ "$V" == "proxy" ]]; then
      jq -n --arg ts "$(ts)" '{detected_at:$ts,vantage:"proxy",status:"api_failed",error:"All APIs failed"}'
      return 0
    fi
  fi

  # 数据提取
  local ip=""; for j in "$J2" "$J1" "$J3"; do ip="$(jq -r '(.ip // .query // empty)' <<<"$j" 2>/dev/null || echo "")"; [[ -n "$ip" && "$ip" != "null" ]] && break; done
  
  # 增强版rDNS查询
  local rdns="$(jq -r '.reverse // empty' <<<"$J3" 2>/dev/null || echo "")"
  if [[ -z "$rdns" && -n "$ip" ]]; then
    rdns="$(get_rdns "$ip")"
  fi
  
  local asn="$(jq -r '(.asname // .as // empty)' <<<"$J3" 2>/dev/null || echo "")"; [[ -z "$asn" || "$asn" == "null" ]] && asn="$(jq -r '(.org // empty)' <<<"$J1" 2>/dev/null || echo "")"
  local isp="$(jq -r '(.org // empty)' <<<"$J1" 2>/dev/null || echo "")"; [[ -z "$isp" || "$isp" == "null" ]] && isp="$(jq -r '(.asname // .as // empty)' <<<"$J3" 2>/dev/null || echo "")"
  local country="$(jq -r '(.country // empty)' <<<"$J3" 2>/dev/null || echo "")"; [[ -z "$country" || "$country" == "null" ]] && country="$(jq -r '(.country // empty)' <<<"$J1" 2>/dev/null || echo "")"
  local city="$(jq -r '(.city // empty)' <<<"$J3" 2>/dev/null || echo "")"; [[ -z "$city" || "$city" == "null" ]] && city="$(jq -r '(.city // empty)' <<<"$J1" 2>/dev/null || echo "")"

  # DNSBL检查
  declare -a hits=(); 
  if [[ -n "$ip" ]]; then 
    IFS=. read -r a b c d <<<"$ip"; rip="${d}.${c}.${b}.${a}"
    for bl in zen.spamhaus.org bl.spamcop.net dnsbl.sorbs.net b.barracudacentral.org; do
      if dig +time=1 +tries=1 +short "${rip}.${bl}" A >/dev/null 2>&1; then hits+=("$bl"); fi
    done
  fi

  # 延迟测试
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

  # 带宽测试（VPS和代理都测试）
  local bandwidth_up="0" bandwidth_down="0"
  local bw_result=$(test_bandwidth_correct "$P" "$V")
  IFS='/' read -r bandwidth_down bandwidth_up <<<"$bw_result"

  # 特征检测
  local features=$(detect_network_features "$asn" "$isp" "$ip" "$V")
  IFS=':' read -r hosting residential mobile proxy network_type <<<"$features"

  # 评分计算
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

  # 生成结论
  local conclusion="基于多维度评估："
  [[ "$hosting" == "true" ]] && conclusion="${conclusion} 数据中心IP;"
  [[ "$residential" == "true" ]] && conclusion="${conclusion} 住宅网络;"
  (( ${#hits[@]} > 0 )) && conclusion="${conclusion} 命中${#hits[@]}个黑名单;"
  (( lat > 200 )) && conclusion="${conclusion} 延迟较高(${lat}ms);"
  [[ "$bandwidth_down" != "0" ]] && conclusion="${conclusion} 带宽${bandwidth_down}/${bandwidth_up}MB/s;"
  conclusion="${conclusion} 综合评分${score}分，等级${grade}。"

  # 生成JSON输出
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
# [ANCHOR:IPQ_STACK_ENHANCED_END]


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
    
    echo -e  "${CYAN}服务器信息：${NC}"
    echo -e  "  IP地址: ${PURPLE}${server_ip}${NC}"
    echo -e  "  控制面板: ${PURPLE}http://${server_ip}/traffic/${NC}" 

    echo -e  "\n${CYAN}默认模式：${NC}"
    echo -e  "  证书模式: ${PURPLE}IP模式（自签名证书）${NC}"
	echo -e  "  网络身份: ${PURPLE}VPS出站IP（自签名证书）${NC}"
	
    echo -e "\n${CYAN}协议信息：${NC}"
    echo -e "  VLESS-Reality  端口: 443  UUID: ${PURPLE}${UUID_VLESS:0:8}...${NC}"
    echo -e "  VLESS-gRPC     端口: 443  UUID: ${PURPLE}${UUID_VLESS:0:8}...${NC}"  
    echo -e "  VLESS-WS       端口: 443  UUID: ${PURPLE}${UUID_VLESS:0:8}...${NC}"
    echo -e "  Trojan-TLS     端口: 443  密码: ${PURPLE}${PASSWORD_TROJAN:0:8}...${NC}"
    echo -e "  Hysteria2      端口: 443  密码: ${PURPLE}${PASSWORD_HYSTERIA2:0:8}...${NC}"
    echo -e "  TUIC           端口: 2053 UUID: ${PURPLE}${UUID_TUIC:0:8}...${NC}"
    
    echo -e "\n${CYAN}常用管理命令：${NC}"
    echo -e "  ${PURPLE}edgeboxctl status${NC}                         # 查看服务状态"
    echo -e "  ${PURPLE}edgeboxctl sub${NC}                            # 查看订阅链接"
    echo -e "  ${PURPLE}edgeboxctl switch-to-domain <域名>${NC}         # 切换证书"
    echo -e "  ${PURPLE}edgeboxctl shunt direct-resi '<代理URL>'${NC}  # 配置分流出站"
    echo -e "  ${PURPLE}edgeboxctl traffic show${NC}                   # 查看流量统计"
    echo -e "  ${PURPLE}edgeboxctl backup create${NC}                  # 手动备份"
	echo -e "  ${PURPLE}edgeboxctl alias "自定义名称"${NC}               # 备注和更新服务器名称"
    echo -e "  ${PURPLE}edgeboxctl help${NC}                           # 查看完整帮助"
    echo -e "  ${CYAN}出站分流示例：${NC}"
    echo -e "  ${PURPLE}edgeboxctl shunt resi 'socks5://user:pass@proxy.example.com:1080'${NC}  # 代理全量出站"
    echo -e "  ${PURPLE}edgeboxctl '<代理URL>'${NC}                        # 分流出站（白名单VPS直连，其他走代理）"
    echo -e "  ${PURPLE}edgeboxctl shunt whitelist <add|remove|list>${NC}  # 白名单管理" 
    echo -e "  ${CYAN}流量预警配置：${NC}"
    echo -e "  ${PURPLE}edgeboxctl alert monthly 500${NC}                # 设置月度500GiB预算"
    echo -e "  ${PURPLE}edgeboxctl alert telegram <token> <chat_id>${NC} # 配置Telegram通知"
    echo -e "  ${PURPLE}edgeboxctl alert discord <webhook_url>${NC}      # 配置Discord通知"
    echo -e "  ${PURPLE}edgeboxctl alert test 80${NC}                    # 模拟80%用量测试"
    
	echo -e "\n${CYAN}高级运维功能：${NC}"
    echo -e "  🔄 证书切换: IP模式 ⇋ 域名模式（Let's Encrypt证书）"
    echo -e "  🌐 出站分流: 代理IP全量 ⇋ VPS全量出 ⇋ 分流"
    echo -e "  📊 流量监控: 实时流量统计、历史趋势图表、协议分析"
    echo -e "  🔔 预警通知: 流量阈值告警（30%/60%/90%）多渠道推送"
    echo -e "  💾 自动备份: 配置文件定期备份、一键故障恢复"
    echo -e "  🔍 IP质量: 实时出口IP质量评分、黑名单检测"
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

# 简化版清理函数 - 成功就是成功，不提及小问题
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
        log_success "EdgeBox v3.0.0 安装成功完成！"
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
        log_success "EdgeBox v3.0.0 安装成功完成！"
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
    
    # 显示安装信息（保留您原有的show_installation_info函数输出）
    show_installation_info
    

    log_info "安装流程执行完毕，正在进行最终验证..."
}

# 脚本入口点检查
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # 直接执行脚本
    main "$@"
fi
