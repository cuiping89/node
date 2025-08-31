debug_ports() {
    echo -e "${CYAN}端口调试信息（单端口复用架构）：${NC}"
    
    echo -e "\n${YELLOW}1. 端口契约检查：${NC}"
    echo "  TCP/443 (Xray单一入口): $(ss -tln | grep -q ":443 " && echo "✓" || echo "✗")"
    echo "  UDP/443 (Hysteria2): $(ss -uln | grep -q ":443 " && echo "✓" || echo "✗")"
    echo "  UDP/2053 (TUIC): $(ss -uln | grep -q ":2053 " && echo "✓" || echo "✗")" 
    echo "  TCP/10085 (gRPC内部): $(ss -tln | grep -q "127.0.0.1:10085 " && echo "✓" || echo "✗")"
    echo "  TCP/10086 (WS内部): $(ss -tln | grep -q "127.0.0.1:10086 " && echo "✓" || echo "✗")"
    
    echo -e "\n${YELLOW}2. 详细端口信息：${NC}"
    echo "TCP端口："
    ss -tlnp 2>/dev/null | grep -E ":(443|10085|10086) " | while read line; do
        echo "  $line"
    done
    
    echo "UDP端口："
    ss -ulnp 2>/dev/null | grep -E ":(443|2053) " | while read line; do
        echo "  $line"  
    done
    
    echo -e "\n${YELLOW}3. 进程检查：${NC}"
    for service in xray sing-box; do
        if pgrep -f $service >/dev/null 2>&1; then
            echo -e "  $service: ${GREEN}运行中${NC}"
        else
            echo -e "  $service: ${RED}未运行${NC}"
        fi
    done
}

test_connection() {
    echo -e "${CYAN}连接测试（单端口复用架构）：${NC}"
    
    local server_ip
    server_ip=$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null) || {
        echo -e "${RED}无法获取服务器IP${NC}"
        return 1
    }
    
    echo -e "\n${YELLOW}公网端口测试：${NC}"
    
    # TCP 443测试（Xray单一入口）
    echo -n "  TCP 443端口（Xray单一入口）: "
    if timeout 3 bash -c "echo >/dev/tcp/${server_ip}/443" 2>/dev/null; then
        echo -e "${GREEN}开放${NC}"
    else
        echo -e "${RED}关闭${NC}"
    fi
    
    # UDP端口测试（较难准确测试）
    echo -n "  UDP 443端口（Hysteria2）: "
    if command -v nc >/dev/null 2>&1 && timeout 2 nc -u -z ${server_ip} 443 2>/dev/null; then
        echo -e "${GREEN}开放${NC}"
    else
        echo -e "${YELLOW}无法确定（UDP测试限制）${NC}"
    fi
    
    echo -n "  UDP 2053端口（TUIC）: "
    if command -v nc >/dev/null 2>&1 && timeout 2 nc -u -z ${server_ip} 2053 2>/dev/null; then
        echo -e "${GREEN}开放${NC}"
    else
        echo -e "${YELLOW}无法确定（UDP测试限制）${NC}"
    fi
    
    echo -e "\n${YELLOW}内部服务测试：${NC}"
    echo -n "  gRPC内部处理 (127.0.0.1:10085): "
    if timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/10085" 2>/dev/null; then
        echo -e "${GREEN}正常${NC}"
    else
        echo -e "${RED}无法连接${NC}"
    fi
    
    echo -n "  WS内部处理 (127.0.0.1:10086): "
    if timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/10086" 2>/dev/null; then
        echo -e "${GREEN}正常${NC}"
    else
        echo -e "${RED}无法连接${NC}"
    fi
}#!/bin/bash

#############################################
# EdgeBox 一站式多协议节点部署脚本
# Version: 2.0.0
# Description: 非交互式IP模式安装
# Protocols: VLESS-Reality, VLESS-gRPC, VLESS-WS, Hysteria2, TUIC
#############################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
INSTALL_DIR="/etc/edgebox"
CERT_DIR="${INSTALL_DIR}/cert"
CONFIG_DIR="${INSTALL_DIR}/config"
BACKUP_DIR="/root/edgebox-backup"
LOG_FILE="/var/log/edgebox-install.log"

# 服务器信息
SERVER_IP=""
SERVER_DOMAIN=""
INSTALL_MODE="ip" # 默认IP模式

# UUID生成
UUID_VLESS=""
UUID_HYSTERIA2=""
UUID_TUIC=""

# Reality密钥
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
REALITY_SHORT_ID=""

# 密码生成
PASSWORD_HYSTERIA2=""
PASSWORD_TUIC=""

# 端口配置
PORT_REALITY=443
PORT_HYSTERIA2=443
PORT_TUIC=2053
PORT_NGINX_STREAM=10443
PORT_GRPC=10085
PORT_WS=10086

#############################################
# 工具函数
#############################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a ${LOG_FILE}
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a ${LOG_FILE}
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a ${LOG_FILE}
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a ${LOG_FILE}
}

print_separator() {
    echo -e "${BLUE}========================================${NC}"
}
# 兼容别名（避免示例块里的 log/log_ok/error 报错）
log()      { log_info "$@"; }
log_ok()   { log_success "$@"; }
error()    { log_error "$@"; }

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以root权限运行"
        exit 1
    fi
}

# 检查系统
check_system() {
    log_info "检查系统兼容性..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "无法确定操作系统类型"
        exit 1
    fi
    
    # 支持的系统版本
    SUPPORTED=false
    
    case "$OS" in
        ubuntu)
            # 提取主版本号
            MAJOR_VERSION=$(echo "$VERSION" | cut -d. -f1)
            if [ "$MAJOR_VERSION" -ge 18 ] 2>/dev/null; then
                SUPPORTED=true
            fi
            ;;
        debian)
            # Debian版本通常是整数
            if [ "$VERSION" -ge 10 ] 2>/dev/null; then
                SUPPORTED=true
            fi
            ;;
        *)
            SUPPORTED=false
            ;;
    esac
    
    if [ "$SUPPORTED" = "true" ]; then
        log_success "系统检查通过: $OS $VERSION"
    else
        log_error "不支持的系统: $OS $VERSION"
        log_info "支持的系统: Ubuntu 18.04+, Debian 10+"
        exit 1
    fi
}

# 获取服务器IP
get_server_ip() {
    log_info "获取服务器公网IP..."
    
    # 尝试多个服务获取IP
    IP_SERVICES=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ipecho.net/plain"
        "https://api.ip.sb/ip"
    )
    
    for service in "${IP_SERVICES[@]}"; do
        SERVER_IP=$(curl -s --max-time 5 $service 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1)
        if [[ -n "$SERVER_IP" ]]; then
            log_success "获取到服务器IP: $SERVER_IP"
            return 0
        fi
    done
    
    log_error "无法获取服务器公网IP"
    exit 1
}

# 检查并安装依赖
install_dependencies() {
    log_info "更新软件源..."
    apt-get update -qq
    
    log_info "安装必要依赖..."
    
    # 基础工具
    PACKAGES="curl wget unzip tar net-tools openssl jq"
    
    # UUID生成工具
    PACKAGES="$PACKAGES uuid-runtime"
    
    # 网络监控工具
    PACKAGES="$PACKAGES vnstat iftop"
    
# 删除HTTP服务器相关的依赖安装
    # 删除了 certbot python3-certbot-nginx（IP模式不需要）
    
# 删除Nginx相关的依赖安装
    # PACKAGES="$PACKAGES nginx libnginx-mod-stream"
    
    for pkg in $PACKAGES; do
        if ! dpkg -l | grep -q "^ii.*$pkg"; then
            log_info "安装 $pkg..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg >/dev/null 2>&1 || {
                log_warn "$pkg 安装失败，尝试继续..."
            }
        else
            log_info "$pkg 已安装"
        fi
    done
    
    # 启用vnstat
    systemctl enable vnstat >/dev/null 2>&1
    systemctl start vnstat >/dev/null 2>&1
    
    log_success "依赖安装完成"
}

# 生成UUID和密码
generate_credentials() {
    log_info "生成UUID和密码..."
    
    # 生成UUID
    UUID_VLESS=$(uuidgen)
    UUID_HYSTERIA2=$(uuidgen)
    UUID_TUIC=$(uuidgen)
    
    # Reality shortId（握手匹配用，长度 8~16 的十六进制；这里生成 16 个 hex）
    REALITY_SHORT_ID="$(openssl rand -hex 8)"

    # 生成密码
    PASSWORD_HYSTERIA2=$(openssl rand -base64 16)
    PASSWORD_TUIC=$(openssl rand -base64 16)
    
    log_success "凭证生成完成"
}

# 创建目录结构
create_directories() {
    log_info "创建目录结构..."
    
    mkdir -p ${INSTALL_DIR}/{cert,config,templates,scripts}
    mkdir -p ${BACKUP_DIR}
    mkdir -p /var/log/edgebox
    mkdir -p /var/log/xray
    
    log_success "目录结构创建完成"
}

# 检查端口占用
check_ports() {
    log_info "检查端口占用情况..."
    
    local ports=(443 10085 10086 10443 2053)
    local occupied=false
    
    for port in "${ports[@]}"; do
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            log_warn "端口 $port 已被占用"
            # 如果是nginx占用443，这是可以的
            if [[ $port == 443 ]] && systemctl is-active --quiet nginx; then
                log_info "端口 443 被nginx占用，将在配置时处理"
            else
                occupied=true
            fi
        fi
    done
    
    if [[ "$occupied" == true ]]; then
        log_warn "某些端口已被占用，可能需要调整配置"
    else
        log_success "端口检查通过"
    fi
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙规则..."
    
    if command -v ufw &> /dev/null; then
        # 配置UFW
        ufw --force disable >/dev/null 2>&1
        
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        
        ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1
        ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1
        ufw allow 443/tcp comment 'EdgeBox TCP' >/dev/null 2>&1
        ufw allow 443/udp comment 'EdgeBox Hysteria2' >/dev/null 2>&1
        ufw allow 2053/udp comment 'EdgeBox TUIC' >/dev/null 2>&1
        
        ufw --force enable >/dev/null 2>&1
        log_success "UFW防火墙规则配置完成"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=2053/udp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        log_success "Firewalld防火墙规则配置完成"
    else
        log_warn "未检测到防火墙软件，请手动配置"
    fi
}

# 优化系统参数
optimize_system() {
    log_info "优化系统参数..."
    
    # 备份原始配置
    if [[ ! -f /etc/sysctl.conf.bak ]]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
    fi
    
    # 检查是否已经优化过
    if grep -q "EdgeBox Optimizations" /etc/sysctl.conf; then
        log_info "系统参数已优化"
        return
    fi
    
    cat >> /etc/sysctl.conf << 'EOF'

# EdgeBox Optimizations
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65000
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
EOF
    
    sysctl -p >/dev/null 2>&1
    log_success "系统参数优化完成"
}

# 生成自签名证书
generate_self_signed_cert() {
    log_info "生成自签名证书..."
    
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) \
        -keyout ${CERT_DIR}/self-signed.key \
        -out ${CERT_DIR}/self-signed.pem \
        -days 3650 \
        -subj "/C=US/ST=California/L=San Francisco/O=EdgeBox/CN=${SERVER_IP}" >/dev/null 2>&1
    
    # 创建软链接
rm -f ${CERT_DIR}/current.key ${CERT_DIR}/current.pem
ln -s ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
ln -s ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
chmod 600 ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
chmod 644 ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
    
    # 设置权限
    chmod 600 ${CERT_DIR}/*.key
    chmod 644 ${CERT_DIR}/*.pem

  # —— 追加的配对校验 —— #
  # 比对证书与私钥的公钥指纹，不一致则重新生成一对并覆盖 current.*
  local cert_pub tmp_pub
  cert_pub="$(openssl x509 -in ${CERT_DIR}/current.pem -pubkey -noout 2>/dev/null | openssl sha256 2>/dev/null)"
  tmp_pub="$(openssl pkey -in ${CERT_DIR}/current.key -pubout 2>/dev/null | openssl sha256 2>/dev/null || true)"
  if [[ -z "$cert_pub" || -z "$tmp_pub" || "$cert_pub" != "$tmp_pub" ]]; then
      log_warn "检测到 current.pem 与 current.key 不匹配，重新生成自签名证书..."
      openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) \
        -keyout ${CERT_DIR}/self-signed.key \
        -out ${CERT_DIR}/self-signed.pem \
        -days 3650 \
        -subj "/C=US/ST=California/L=San Francisco/O=EdgeBox/CN=${SERVER_IP}" >/dev/null 2>&1
      ln -sf ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
      ln -sf ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
      chmod 600 ${CERT_DIR}/*.key
      chmod 644 ${CERT_DIR}/*.pem
      log_success "已重新配对自签名证书与私钥"
  fi

    log_success "自签名证书生成完成"
}

# 生成Reality密钥对
generate_reality_keys() {
  log_info "生成Reality密钥对..."

  # 1) 优先用 sing-box 生成（新版有 reality-keypair，旧版是 reality-key）
  if command -v sing-box >/dev/null 2>&1; then
    local out
    out="$(sing-box generate reality-keypair 2>/dev/null || sing-box generate reality-key 2>/dev/null || true)"
    REALITY_PRIVATE_KEY="$(echo "$out" | awk -F': ' '/Private/{print $2}')"
    REALITY_PUBLIC_KEY="$(echo "$out"  | awk -F': ' '/Public/{print  $2}')"
    if [[ -n "$REALITY_PRIVATE_KEY" && -n "$REALITY_PUBLIC_KEY" ]]; then
      log_success "Reality密钥对生成完成（sing-box）"
      return 0
    fi
  fi

  # 2) 回退：下载 Xray 再生成（不再用 GitHub API）
  local tmp dir tag url ok=""
  dir="$(mktemp -d)"; pushd "$dir" >/dev/null

  # 不走 API，直接跟随 /releases/latest 的 302 拿真实 tag；再兜底一个固定版本
  tag="$(curl -sIL -o /dev/null -w '%{url_effective}' https://github.com/XTLS/Xray-core/releases/latest | awk -F/ '{print $NF}')"
  [[ -z "$tag" ]] && tag="v1.8.11"

  for base in \
    "https://github.com/XTLS/Xray-core/releases/download" \
    "https://ghproxy.com/https://github.com/XTLS/Xray-core/releases/download"
  do
    url="${base}/${tag}/Xray-linux-64.zip"
    if wget -q --tries=3 --timeout=20 "$url" -O Xray-linux-64.zip; then ok=1; break; fi
  done
  if [[ -z "$ok" ]]; then
    log_error "下载Xray失败"; popd >/dev/null; rm -rf "$dir"; return 1
  fi

  unzip -q Xray-linux-64.zip
  local keys; keys="$(./xray x25519)"
  REALITY_PRIVATE_KEY="$(echo "$keys" | awk '/Private key/{print $3}')"
  REALITY_PUBLIC_KEY="$(echo  "$keys" | awk '/Public key/{print  $3}')"

  popd >/dev/null; rm -rf "$dir"
  [[ -n "$REALITY_PRIVATE_KEY" && -n "$REALITY_PUBLIC_KEY" ]] && log_success "Reality密钥对生成完成" || { log_error "生成Reality密钥失败"; return 1; }
}

# 安装Xray
install_xray() {
  log_info "安装Xray..."

  if command -v xray &>/dev/null; then
    log_info "Xray已安装，跳过"
  else
    # 官方安装（仅用于放二进制），不让它留下"活跃"的 unit
    bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null 2>&1 \
      || { log_error "Xray安装失败"; exit 1; }
  fi

  # 彻底停用并清掉官方的 unit / drop-in，防止它抢占 ExecStart
  systemctl disable --now xray >/dev/null 2>&1 || true
  rm -rf /etc/systemd/system/xray.service.d 2>/dev/null || true
  # 有些版本会把 unit 写成不可变，统一覆盖掉
  : > /etc/systemd/system/xray.service

  log_success "Xray安装完成"
}

# 安装sing-box
install_sing_box() {
  log_info "安装sing-box..."

  if [[ -f /usr/local/bin/sing-box ]]; then
    log_info "sing-box已安装，跳过"
  else
    # 跟随 /releases/latest 的 302 拿真实 tag；失败兜底固定版本
    local tag latest ver ok=""
    latest="$(curl -sIL -o /dev/null -w '%{url_effective}' https://github.com/SagerNet/sing-box/releases/latest | awk -F/ '{print $NF}')"
    ver="$(echo "$latest" | sed 's/^v//')"
    [[ -z "$ver" ]] && ver="1.12.4"

    for base in \
      "https://github.com/SagerNet/sing-box/releases/download" \
      "https://ghproxy.com/https://github.com/SagerNet/sing-box/releases/download"
    do
      url="${base}/v${ver}/sing-box-${ver}-linux-amd64.tar.gz"
      log_info "下载 ${url}"
      if wget -q --tries=3 --timeout=25 "$url" -O "/tmp/sing-box-${ver}.tar.gz"; then ok=1; break; fi
    done
    [[ -z "$ok" ]] && { log_error "下载sing-box失败"; exit 1; }

    tar -xzf "/tmp/sing-box-${ver}.tar.gz" -C /tmp
    install -m 0755 "/tmp/sing-box-${ver}-linux-amd64/sing-box" /usr/local/bin/sing-box
    rm -rf "/tmp/sing-box-${ver}.tar.gz" "/tmp/sing-box-${ver}-linux-amd64"
  fi

  # 创建 systemd
  cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c ${CONFIG_DIR}/sing-box.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  log_success "sing-box安装完成"
}


# 删除了configure_http_subscription函数，不再需要HTTP服务器

# 配置Xray（单端口复用架构）
configure_xray() {
  log "配置 Xray（单端口复用架构）..."

  cat > ${CONFIG_DIR}/xray.json <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error":  "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "VLESS-MultiProtocol",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${UUID_VLESS}", "flow": "xtls-rprx-vision", "email": "reality@edgebox" },
          { "id": "${UUID_VLESS}", "email": "grpc@edgebox" },
          { "id": "${UUID_VLESS}", "email": "ws@edgebox" }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "name": "grpc.edgebox.local",
            "alpn": "h2",
            "path": "/grpc",
            "dest": 10085,
            "xver": 1
          },
          {
            "name": "www.edgebox.local", 
            "alpn": "http/1.1",
            "path": "/ws",
            "dest": 10086,
            "xver": 1
          },
          {
            "alpn": "h2",
            "dest": 10085,
            "xver": 1
          },
          {
            "dest": 10086,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.cloudflare.com:443",
          "xver": 0,
          "serverNames": ["www.cloudflare.com","www.microsoft.com","www.apple.com"],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": ["${REALITY_SHORT_ID}"]
        }
      }
    },
    {
      "tag": "VLESS-gRPC-Internal",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${UUID_VLESS}", "email": "grpc-internal@edgebox" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": { "serviceName": "grpc" }
      }
    },
    {
      "tag": "VLESS-WS-Internal", 
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${UUID_VLESS}", "email": "ws-internal@edgebox" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/ws" }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "settings": {} } ],
  "routing": { "rules": [] }
}
EOF

  cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service (EdgeBox)
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -c /etc/edgebox/config/xray.json
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now xray
  log_ok "Xray 配置完成（单端口复用架构）"
}

# 配置sing-box
configure_sing_box() {
  log "配置 sing-box..."

  cat > ${CONFIG_DIR}/sing-box.json <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [
    {
      "type": "hysteria2", "tag": "hysteria2-in",
      "listen": "::", "listen_port": 443,
      "users": [ { "name": "user", "password": "${PASSWORD_HYSTERIA2}" } ],
      "masquerade": "https://www.cloudflare.com",
      "tls": { "enabled": true, "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key" }
    },
    {
      "type": "tuic", "tag": "tuic-in",
      "listen": "::", "listen_port": 2053,
      "users": [ { "uuid": "${UUID_TUIC}", "password": "${PASSWORD_TUIC}" } ],
      "congestion_control": "bbr",
      "tls": { "enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key" }
    }
  ],
  "outbounds": [ { "type": "direct" } ]
}
EOF

  systemctl daemon-reload
  log_ok "sing-box 配置完成"
}

# 保存配置信息
save_config_info() {
    log_info "保存配置信息..."
    
    cat > ${CONFIG_DIR}/server.json << EOF
{
  "server_ip": "${SERVER_IP}",
  "install_mode": "${INSTALL_MODE}",
  "install_date": "$(date +%Y-%m-%d)",
  "uuid": {
    "vless": "${UUID_VLESS}",
    "hysteria2": "${UUID_HYSTERIA2}",
    "tuic": "${UUID_TUIC}"
  },
  "password": {
    "hysteria2": "${PASSWORD_HYSTERIA2}",
    "tuic": "${PASSWORD_TUIC}"
  },
  "reality": {
    "public_key": "${REALITY_PUBLIC_KEY}",
    "private_key": "${REALITY_PRIVATE_KEY}",
    "short_id": "${REALITY_SHORT_ID}"
  },
  "ports": {
    "reality": ${PORT_REALITY},
    "hysteria2": ${PORT_HYSTERIA2},
    "tuic": ${PORT_TUIC},
    "grpc": ${PORT_GRPC},
    "ws": ${PORT_WS},
    "nginx_stream": ${PORT_NGINX_STREAM}
  }
}
EOF
    
    chmod 600 ${CONFIG_DIR}/server.json
    log_success "配置信息保存完成"
}

# 启动服务
start_services() {
  log_info "启动所有服务..."

  systemctl daemon-reload

  systemctl enable xray sing-box >/dev/null 2>&1 || true

  systemctl restart xray   >/dev/null 2>&1
  systemctl restart sing-box >/dev/null 2>&1

  sleep 2

  for s in xray sing-box; do
    if systemctl is-active --quiet "$s"; then
      log_success "$s 运行正常"
    else
      log_error "$s 启动失败（详见 ${LOG_FILE}）"
      journalctl -u "$s" -n 50 --no-pager >> ${LOG_FILE}
    fi
  done
}

# 生成订阅链接（统一兼容 v2rayN / ShadowRocket / Clash Meta）
generate_subscription() {
  log_info "生成订阅链接..."

  # 通用变量
  local ip="${SERVER_IP}"
  local uuid="${UUID_VLESS}"
  local ws_path="/ws"

  # ★ 对可能含有 +/= 等保留字符的密码做 URL 编码，保证客户端能正确解析
  local HY2_PW_ENC TUIC_PW_ENC
  HY2_PW_ENC=$(jq -rn --arg v "$PASSWORD_HYSTERIA2" '$v|@uri')
  TUIC_PW_ENC=$(jq -rn --arg v "$PASSWORD_TUIC"     '$v|@uri')

  # 当前模式：有 LE 证书则域名模式，否则 IP 模式
  local domain=""
  if [[ -n "${EDGEBOX_DOMAIN:-}" && -f "/etc/letsencrypt/live/${EDGEBOX_DOMAIN}/fullchain.pem" && -f "/etc/letsencrypt/live/${EDGEBOX_DOMAIN}/privkey.pem" ]]; then
    domain="${EDGEBOX_DOMAIN}"
  fi

  # 分流所需的主机名（与 Nginx 自适应/SNI 规则一致）
  local grpc_host ws_host quic_sni
  if [[ -n "$domain" ]]; then
    grpc_host="grpc.${domain}"
    ws_host="www.${domain}"
    quic_sni="${domain}"
  else
    grpc_host="grpc.edgebox.local"
    ws_host="www.edgebox.local"
    quic_sni="www.edgebox.local"
  fi

  # 1) VLESS Reality
  local r_addr="${domain:-$ip}"
  local r_sni="www.cloudflare.com"
  local reality_link="vless://${uuid}@${r_addr}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${r_sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&spx=%2F#EdgeBox-REALITY"

  # 2) VLESS gRPC —— 强制 h2（IP 模式再加 allowInsecure=1）
  local grpc_addr="${domain:-$ip}"
  local grpc_tail="&alpn=h2&type=grpc&serviceName=grpc"
  [[ -z "$domain" ]] && grpc_tail="${grpc_tail}&allowInsecure=1"
  local grpc_link="vless://${uuid}@${grpc_addr}:443?encryption=none&security=tls&sni=${grpc_host}${grpc_tail}#EdgeBox-gRPC"

  # 3) VLESS WS —— 显式 http/1.1（IP 模式加 allowInsecure=1）
  local ws_addr="${domain:-$ip}"
  local ws_tail="&alpn=http/1.1&type=ws&host=${ws_host}&path=${ws_path}"
  [[ -z "$domain" ]] && ws_tail="${ws_tail}&allowInsecure=1"
  local ws_link="vless://${uuid}@${ws_addr}:443?encryption=none&security=tls&sni=${ws_host}${ws_tail}#EdgeBox-WS"

  # 4) Hysteria2 —— alpn=h3；IP 模式 insecure=1（密码已 URL 编码）
  local hy2_addr="${domain:-$ip}"
  local hy2_tail
  if [[ -n "$domain" ]]; then
    hy2_tail="?sni=${quic_sni}&alpn=h3"
  else
    hy2_tail="?sni=${quic_sni}&insecure=1&alpn=h3"
  fi
  local hy2_link="hysteria2://${HY2_PW_ENC}@${hy2_addr}:443${hy2_tail}#EdgeBox-HYSTERIA2"

  # 5) TUIC v5 —— alpn=h3；IP 模式 allowInsecure=1（密码已 URL 编码）
  local tuic_addr="${domain:-$ip}"
  local tuic_tail
  if [[ -n "$domain" ]]; then
    tuic_tail="?congestion_control=bbr&alpn=h3&sni=${quic_sni}"
  else
    tuic_tail="?congestion_control=bbr&alpn=h3&sni=${quic_sni}&allowInsecure=1"
  fi
  local tuic_link="tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${tuic_addr}:2053${tuic_tail}#EdgeBox-TUIC"

  # 输出订阅
  local plain="${reality_link}\n${grpc_link}\n${ws_link}\n${hy2_link}\n${tuic_link}\n"
  echo -e "${plain}" > "${CONFIG_DIR}/subscription.txt"

  # 极简站点暴露 /sub（仅 80 端口）
  mkdir -p /var/www/html
  printf '%s' "$(echo -e "${plain}" | base64 -w0)" > /var/www/html/sub

  log_success "订阅已生成：${CONFIG_DIR}/subscription.txt 以及 http://${ip}/sub"
}

# 创建edgeboxctl基础框架（增加调试功能）
create_edgeboxctl() {
    log_info "创建管理工具..."
    
    cat > /usr/local/bin/edgeboxctl << 'EOFCTL'
#!/bin/bash

# EdgeBox Control Script
VERSION="2.0.0"
CONFIG_DIR="/etc/edgebox/config"
CERT_DIR="/etc/edgebox/cert"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    echo -e "${CYAN}EdgeBox 管理工具 v${VERSION}${NC}"
    echo ""
    echo "用法: edgeboxctl [命令] [选项]"
    echo ""
    echo "命令:"
    echo "  sub             显示订阅链接"
    echo "  status          显示服务状态"
    echo "  restart         重启所有服务"
    echo "  show-config     显示当前配置"
    echo "  logs [service]  查看服务日志"
    echo "  test            测试连接"
            echo "  debug-stream    调试单端口复用"
    echo "  fix-permissions 修复证书权限"
    echo "  help            显示帮助信息"
}

show_sub() {
    if [[ ! -f ${CONFIG_DIR}/server.json ]]; then
        echo -e "${RED}配置文件不存在${NC}"
        exit 1
    fi
    
    local server_ip=$(cat ${CONFIG_DIR}/server.json | jq -r .server_ip)
    
    echo -e "${CYAN}订阅链接：${NC}"
    echo -e "${GREEN}http://${server_ip}/sub${NC}"
    echo ""
    echo -e "${CYAN}节点链接：${NC}"
    if [[ -f ${CONFIG_DIR}/subscription.txt ]]; then
        cat ${CONFIG_DIR}/subscription.txt
    fi
}

show_status() {
    echo -e "${CYAN}服务状态：${NC}"
    
    for service in nginx xray sing-box; do
        if systemctl is-active --quiet $service; then
            echo -e "  $service: ${GREEN}运行中${NC}"
        else
            echo -e "  $service: ${RED}已停止${NC}"
        fi
    done
    
    echo ""
    echo -e "${CYAN}端口监听：${NC}"
    ss -tlnp 2>/dev/null | grep -E ":(443|80)" | awk '{print "  TCP: "$4" ("$7")"}'
    ss -ulnp 2>/dev/null | grep -E ":(443|2053)" | awk '{print "  UDP: "$4" ("$7")"}'
    
    echo ""
    echo -e "${CYAN}内部服务状态：${NC}"
    if netstat -tln 2>/dev/null | grep -q "127.0.0.1:10085"; then
        echo -e "  gRPC 内部端口: ${GREEN}正常${NC}"
    else
        echo -e "  gRPC 内部端口: ${RED}异常${NC}"
    fi
    
    if netstat -tln 2>/dev/null | grep -q "127.0.0.1:10086"; then
        echo -e "  WS 内部端口: ${GREEN}正常${NC}"
    else
        echo -e "  WS 内部端口: ${RED}异常${NC}"
    fi
}

restart_services() {
    echo -e "${CYAN}重启所有服务...${NC}"
    
    # 按顺序重启，确保依赖关系
    services=("sing-box" "xray" "nginx")
    
    for service in "${services[@]}"; do
        echo -n "  重启 $service..."
        systemctl restart $service
        sleep 2
        if systemctl is-active --quiet $service; then
            echo -e " ${GREEN}成功${NC}"
        else
            echo -e " ${RED}失败${NC}"
            echo -e "    ${YELLOW}错误详情：${NC}"
            journalctl -u $service -n 5 --no-pager | sed 's/^/    /'
        fi
    done
    
    echo ""
    echo -e "${CYAN}服务重启完成，等待 5 秒后检查状态...${NC}"
    sleep 5
    show_status
}

show_config() {
    if [[ ! -f ${CONFIG_DIR}/server.json ]]; then
        echo -e "${RED}配置文件不存在${NC}"
        exit 1
    fi
    
    echo -e "${CYAN}当前配置：${NC}"
    cat ${CONFIG_DIR}/server.json | jq '.' 2>/dev/null || cat ${CONFIG_DIR}/server.json
}

show_logs() {
    local service=$1
    if [[ -z "$service" ]]; then
        echo "用法: edgeboxctl logs [nginx|xray|sing-box|stream]"
        echo ""
        echo "可用的日志文件："
        echo "  - nginx: systemd 日志"
        echo "  - xray: systemd + /var/log/xray/"
        echo "  - sing-box: systemd 日志"
        echo "  - stream: Xray 单端口复用日志"
        return
    fi
    
    case "$service" in
        nginx)
            echo -e "${CYAN}Nginx 系统日志：${NC}"
            journalctl -u nginx -n 30 --no-pager
            
            if [[ -f /var/log/nginx/edgebox_stream_access.log ]]; then
                echo -e "\n${CYAN}Nginx 分流访问日志（最近10条）：${NC}"
                tail -n 10 /var/log/nginx/edgebox_stream_access.log
            fi
            
            if [[ -f /var/log/nginx/edgebox_stream_error.log ]]; then
                echo -e "\n${CYAN}Nginx 分流错误日志：${NC}"
                tail -n 20 /var/log/nginx/edgebox_stream_error.log
            fi
            ;;
        xray)
            echo -e "${CYAN}Xray 系统日志：${NC}"
            journalctl -u xray -n 30 --no-pager
            
            if [[ -f /var/log/xray/access.log ]]; then
                echo -e "\n${CYAN}Xray 访问日志（最近10条）：${NC}"
                tail -n 10 /var/log/xray/access.log
            fi
            
            if [[ -f /var/log/xray/error.log ]]; then
                echo -e "\n${CYAN}Xray 错误日志：${NC}"
                tail -n 20 /var/log/xray/error.log
            fi
            ;;
        sing-box)
            echo -e "${CYAN}sing-box 系统日志：${NC}"
            journalctl -u sing-box -n 50 --no-pager
            ;;
        stream)
            debug_nginx_stream
            ;;
        *)
            echo -e "${RED}未知服务: $service${NC}"
            ;;
    esac
}

debug_nginx_stream() {
    echo -e "${CYAN}单端口复用架构状态：${NC}"
    
    # 检查 Xray 配置
    echo -e "\n${YELLOW}1. 检查 Xray 单端口配置：${NC}"
    if [[ -f /etc/edgebox/config/xray.json ]]; then
        echo "Xray 配置文件存在"
        
        # 显示关键配置段
        echo -e "\n${YELLOW}主入站端口：${NC}"
        grep -A 5 '"port": 443' /etc/edgebox/config/xray.json
        
        echo -e "\n${YELLOW}Fallbacks 配置：${NC}"
        grep -A 15 '"fallbacks"' /etc/edgebox/config/xray.json
    else
        echo -e "${RED}Xray配置文件不存在！${NC}"
        return 1
    fi
    
    # 检查端口监听
    echo -e "\n${YELLOW}2. 检查端口监听状态：${NC}"
    echo "公网端口 (443):"
    ss -tln | grep ":443" || echo "未监听"
    echo "gRPC 内部端口 (10085):"
    ss -tln | grep ":10085" || echo "未监听"
    echo "WS 内部端口 (10086):"
    ss -tln | grep ":10086" || echo "未监听"
    
    # 检查 Xray 日志
    echo -e "\n${YELLOW}3. 最近的 Xray 日志：${NC}"
    if [[ -f /var/log/xray/access.log ]]; then
        echo "访问日志（最近5条）："
        tail -n 5 /var/log/xray/access.log | while read line; do
            echo "  $line"
        done
    else
        echo "无访问日志"
    fi
    
    if [[ -f /var/log/xray/error.log ]]; then
        echo "错误日志："
        tail -n 10 /var/log/xray/error.log | while read line; do
            echo "  $line"
        done
    else
        echo "无错误日志"
    fi
}

test_connection() {
    echo -e "${CYAN}测试连接...${NC}"
    
    local server_ip=$(cat ${CONFIG_DIR}/server.json | jq -r .server_ip)
    
    # 测试HTTP订阅
    echo -n "  HTTP订阅服务: "
    if curl -s -o /dev/null -w "%{http_code}" http://${server_ip}/sub | grep -q "200"; then
        echo -e "${GREEN}正常${NC}"
    else
        echo -e "${RED}异常${NC}"
    fi
    
    # 测试TCP 443（单端口复用）
    echo -n "  TCP 443端口（单端口复用）: "
    if timeout 3 bash -c "echo >/dev/tcp/${server_ip}/443" 2>/dev/null; then
        echo -e "${GREEN}开放${NC}"
    else
        echo -e "${RED}关闭${NC}"
    fi
    
    # 测试UDP端口
    echo -n "  UDP 443端口（Hysteria2）: "
    if timeout 2 nc -u -z ${server_ip} 443 2>/dev/null; then
        echo -e "${GREEN}开放${NC}"
    else
        echo -e "${YELLOW}未知（UDP难以准确测试）${NC}"
    fi
    
    echo -n "  UDP 2053端口（TUIC）: "
    if timeout 2 nc -u -z ${server_ip} 2053 2>/dev/null; then
        echo -e "${GREEN}开放${NC}"
    else
        echo -e "${YELLOW}未知（UDP难以准确测试）${NC}"
    fi
    
    # 测试内部服务（单端口复用架构的内部处理）
    echo -e "\n${CYAN}内部服务测试（单端口复用架构）：${NC}"
    echo -n "  gRPC 内部处理 (10085): "
    if timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/10085" 2>/dev/null; then
        echo -e "${GREEN}正常${NC}"
    else
        echo -e "${RED}无法连接${NC}"
    fi
    
    echo -n "  WS 内部处理 (10086): "
    if timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/10086" 2>/dev/null; then
        echo -e "${GREEN}正常${NC}"
    else
        echo -e "${RED}无法连接${NC}"
    fi
}e "${YELLOW}未知（UDP难以准确测试）${NC}"
    fi
    
    # 测试内部端口连通性
    echo -e "\n${CYAN}内部服务测试：${NC}"
    echo -n "  gRPC 后端 (10085): "
    if timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/10085" 2>/dev/null; then
        echo -e "${GREEN}正常${NC}"
    else
        echo -e "${RED}无法连接${NC}"
    fi
    
    echo -n "  WS 后端 (10086): "
    if timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/10086" 2>/dev/null; then
        echo -e "${GREEN}正常${NC}"
    else
        echo -e "${RED}无法连接${NC}"
    fi
    
    echo -n "  Nginx 分流 (10443): "
    if timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/10443" 2>/dev/null; then
        echo -e "${GREEN}正常${NC}"
    else
        echo -e "${RED}无法连接${NC}"
    fi
}

fix_permissions() {
    echo -e "${CYAN}修复证书权限...${NC}"
    
    if [[ -d ${CERT_DIR} ]]; then
        chown -R root:root ${CERT_DIR}
        chmod 755 ${CERT_DIR}
        chmod 600 ${CERT_DIR}/*.key 2>/dev/null || true
        chmod 644 ${CERT_DIR}/*.pem 2>/dev/null || true
        echo -e "${GREEN}证书权限修复完成${NC}"
    else
        echo -e "${RED}证书目录不存在${NC}"
    fi
}

case "$1" in
    sub)
        show_sub
        ;;
    status)
        show_status
        ;;
    restart)
        restart_services
        ;;
    show-config|config)
        show_config
        ;;
    logs|log)
        show_logs $2
        ;;
    test)
        test_connection
        ;;
    debug-ports)
        debug_ports
        ;;
    fix-permissions)
        fix_permissions
        ;;
    help|*)
        show_help
        ;;
esac
EOFCTL
    
    chmod +x /usr/local/bin/edgeboxctl
    log_success "管理工具创建完成"
}

# 显示安装信息
show_installation_info() {
    clear
    print_separator
    echo -e "${GREEN}EdgeBox 安装完成！${NC}"
    print_separator
    
    echo -e "${CYAN}服务器信息：${NC}"
    echo -e "  IP地址: ${GREEN}${SERVER_IP}${NC}"
    echo -e "  模式: ${YELLOW}IP模式（自签名证书）${NC}"
    
    echo -e "\n${CYAN}协议信息：${NC}"
    echo -e "  ${PURPLE}[1] VLESS-Reality${NC}"
    echo -e "      端口: 443"
    echo -e "      UUID: ${UUID_VLESS}"
    echo -e "      公钥: ${REALITY_PUBLIC_KEY}"
    
    echo -e "\n  ${PURPLE}[2] VLESS-gRPC${NC}"
    echo -e "      端口: 443"
    echo -e "      UUID: ${UUID_VLESS}"
    echo -e "      SNI: grpc.edgebox.local"
    
    echo -e "\n  ${PURPLE}[3] VLESS-WS${NC}"
    echo -e "      端口: 443"
    echo -e "      UUID: ${UUID_VLESS}"
    echo -e "      路径: /ws"
    
    echo -e "\n  ${PURPLE}[4] Hysteria2${NC}"
    echo -e "      端口: 443 (UDP)"
    echo -e "      密码: ${PASSWORD_HYSTERIA2}"
    
    echo -e "\n  ${PURPLE}[5] TUIC${NC}"
    echo -e "      端口: 2053 (UDP)"
    echo -e "      UUID: ${UUID_TUIC}"
    echo -e "      密码: ${PASSWORD_TUIC}"
    
    echo -e "\n${CYAN}订阅链接：${NC}"
    echo -e "  ${GREEN}http://${SERVER_IP}/sub${NC}"
    
    echo -e "\n${CYAN}管理命令：${NC}"
    echo -e "  ${YELLOW}edgeboxctl sub${NC}        # 查看订阅链接"
    echo -e "  ${YELLOW}edgeboxctl status${NC}     # 查看服务状态"
    echo -e "  ${YELLOW}edgeboxctl restart${NC}    # 重启所有服务"
    echo -e "  ${YELLOW}edgeboxctl test${NC}       # 测试连接"
    echo -e "  ${YELLOW}edgeboxctl debug-ports${NC}   # 调试端口状态"
    echo -e "  ${YELLOW}edgeboxctl logs xray${NC}  # 查看日志"
    
    echo -e "\n${YELLOW}⚠️  注意事项：${NC}"
    echo -e "  1. 当前为IP模式，使用自签名证书"
    echo -e "  2. 客户端需要开启'跳过证书验证'选项"
    echo -e "  3. Reality协议不需要跳过证书验证"
    echo -e "  4. 防火墙已配置，请确保云服务商防火墙也开放相应端口"
    echo -e "  5. 订阅链接已保存到本地文件，使用 ${YELLOW}edgeboxctl sub${NC} 查看"
    
    print_separator
}
}

# 清理函数
cleanup() {
    log_info "清理临时文件..."
    rm -f /tmp/Xray-linux-64.zip
    rm -f /tmp/sing-box-*.tar.gz
}

# 主安装流程
main() {
    clear
    print_separator
    echo -e "${GREEN}EdgeBox 安装脚本 v2.0.0${NC}"
    echo -e "${CYAN}开始非交互式IP模式安装...${NC}"
    print_separator
    
    # 创建日志文件
    mkdir -p $(dirname ${LOG_FILE})
    touch ${LOG_FILE}
    
    # 设置错误处理
    trap cleanup EXIT
    
    # 执行安装步骤
check_root
check_system
get_server_ip
install_dependencies
generate_credentials
create_directories
check_ports
configure_firewall
optimize_system
generate_self_signed_cert
install_sing_box          # ← 提前
generate_reality_keys     # ← 现在可以稳定用 sing-box 直接出 key
install_xray
configure_xray
configure_sing_box
save_config_info
start_services
generate_subscription
create_edgeboxctl
    
    # 显示安装信息
    show_installation_info
    
    log_success "EdgeBox安装完成！"
    log_info "安装日志: ${LOG_FILE}"
    echo ""
    echo -e "${GREEN}配置已保存，您可以随时使用 edgeboxctl 命令管理服务${NC}"
}

# 执行主函数
main "$@"
