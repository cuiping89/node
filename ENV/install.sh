#!/bin/bash

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
    
    # 证书工具
    PACKAGES="$PACKAGES certbot python3-certbot-nginx"
    
    # Nginx
    PACKAGES="$PACKAGES nginx libnginx-mod-stream"
    
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
    ln -sf ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
    ln -sf ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
    
    # 设置权限
    chmod 600 ${CERT_DIR}/*.key
    chmod 644 ${CERT_DIR}/*.pem
    
    log_success "自签名证书生成完成"
}

# 生成Reality密钥对
generate_reality_keys() {
    log_info "生成Reality密钥对..."
    
    # 下载最新的xray来生成密钥
    local temp_dir=$(mktemp -d)
    cd $temp_dir
    
    # 获取最新版本
    local latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d '"' -f4)
    
    wget -q --show-progress "https://github.com/XTLS/Xray-core/releases/download/${latest_version}/Xray-linux-64.zip" || {
        log_error "下载Xray失败"
        rm -rf $temp_dir
        exit 1
    }
    
    unzip -q Xray-linux-64.zip
    
    # 生成密钥对
    local keys=$(./xray x25519)
    REALITY_PRIVATE_KEY=$(echo "$keys" | grep "Private key:" | cut -d' ' -f3)
    REALITY_PUBLIC_KEY=$(echo "$keys" | grep "Public key:" | cut -d' ' -f3)
    
    # 生成短ID
    REALITY_SHORT_ID=$(openssl rand -hex 8)
    
    cd - > /dev/null
    rm -rf $temp_dir
    
    log_success "Reality密钥对生成完成"
}

# 安装Xray
install_xray() {
    log_info "安装Xray..."
    
    # 检查是否已安装
    if command -v xray &> /dev/null; then
        log_info "Xray已安装，跳过"
        systemctl stop xray >/dev/null 2>&1
        return
    fi
    
    # 下载并安装Xray
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null 2>&1 || {
        log_error "Xray安装失败"
        exit 1
    }
    
    # 停止默认服务
    systemctl stop xray >/dev/null 2>&1
    
    log_success "Xray安装完成"
}

# 安装sing-box
install_sing_box() {
    log_info "安装sing-box..."
    
    # 检查是否已安装
    if [[ -f /usr/local/bin/sing-box ]]; then
        log_info "sing-box已安装，跳过"
        return
    fi
    
    # 获取最新版本
    local latest_version=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')
    
    if [[ -z "$latest_version" ]]; then
        log_error "无法获取sing-box版本信息"
        exit 1
    fi
    
    log_info "下载sing-box ${latest_version}..."
    
    # 下载二进制文件
    wget -q --show-progress "https://github.com/SagerNet/sing-box/releases/download/v${latest_version}/sing-box-${latest_version}-linux-amd64.tar.gz" || {
        log_error "下载sing-box失败"
        exit 1
    }
    
    tar -xzf "sing-box-${latest_version}-linux-amd64.tar.gz"
    
    # 安装二进制文件
    cp "sing-box-${latest_version}-linux-amd64/sing-box" /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # 清理
    rm -rf sing-box-*

# 禁用掉官方安装的 xray 服务，避免和我们自定义的冲突
systemctl disable --now xray.service >/dev/null 2>&1 || true
systemctl disable --now 'xray@*'    >/dev/null 2>&1 || true

# 创建 systemd 服务文件
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

# 配置Nginx
configure_nginx() {
    log_info "配置Nginx..."
    
    # 停止nginx以便修改配置
    systemctl stop nginx >/dev/null 2>&1
    
    # 备份原始配置
    if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    fi
    
    # 创建stream配置目录
    mkdir -p /etc/nginx/stream.d
    
    # 创建stream配置
    cat > /etc/nginx/stream.d/edgebox.conf << 'EOF'
# EdgeBox Stream Configuration
upstream grpc_backend {
    server 127.0.0.1:10085;
}

upstream ws_backend {
    server 127.0.0.1:10086;
}

map $ssl_preread_alpn_protocols $upstream {
    ~\bh2\b         grpc_backend;
    default         ws_backend;
}

server {
    listen 127.0.0.1:10443;
    ssl_preread on;
    proxy_pass $upstream;
    proxy_protocol off;
}
EOF
    
    # 创建新的nginx.conf
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;
include /etc/nginx/modules-enabled/*.conf;  # << 新增这一行

events { worker_connections 1024; }

# HTTP配置
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    access_log /var/log/nginx/access.log;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

# Stream配置
stream {
    include /etc/nginx/stream.d/*.conf;
}
EOF
    
    # 测试配置
    nginx -t >/dev/null 2>&1 || {
        log_error "Nginx配置测试失败"
        exit 1
    }
    
    log_success "Nginx配置完成"
}

# 配置Xray
configure_xray() {
    log_info "配置Xray..."
    
    cat > ${CONFIG_DIR}/xray.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "VLESS-Reality",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS}",
            "flow": "xtls-rprx-vision",
            "email": "reality@edgebox"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": "127.0.0.1:10443",
            "xver": 0
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "127.0.0.1:10443",
          "xver": 0,
          "serverNames": [
            "www.cloudflare.com",
            "www.microsoft.com",
            "www.apple.com"
          ],
          "privateKey": "${REALITY_PRIVATE_KEY}",
"shortIds": ["${REALITY_SHORT_ID}"]
        }
      }
    },
    {
      "tag": "VLESS-gRPC",
      "port": 10085,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS}",
            "email": "grpc@edgebox"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "${CERT_DIR}/current.pem",
              "keyFile": "${CERT_DIR}/current.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "grpc"
        }
      }
    },
    {
      "tag": "VLESS-WS",
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS}",
            "email": "ws@edgebox"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "${CERT_DIR}/current.pem",
              "keyFile": "${CERT_DIR}/current.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/ws",
          "headers": {}
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ],
  "routing": {
    "rules": []
  }
}
EOF
    
    # 创建Xray systemd配置
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -c ${CONFIG_DIR}/xray.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    
    log_success "Xray配置完成"
}

# 配置sing-box
configure_sing_box() {
    log_info "配置sing-box..."
    
    cat > ${CONFIG_DIR}/sing-box.json << EOF
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "name": "user",
          "password": "${PASSWORD_HYSTERIA2}"
        }
      ],
      "masquerade": "https://www.cloudflare.com",
      "tls": {
        "enabled": true,
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
          "name": "user",
          "uuid": "${UUID_TUIC}",
          "password": "${PASSWORD_TUIC}"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
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
  ]
}
EOF
    
    log_success "sing-box配置完成"
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
    
    # 重启Nginx
    systemctl restart nginx >/dev/null 2>&1
    systemctl enable nginx >/dev/null 2>&1
    
    # 启动Xray
    systemctl restart xray >/dev/null 2>&1
    systemctl enable xray >/dev/null 2>&1
    
    # 启动sing-box
    systemctl restart sing-box >/dev/null 2>&1
    systemctl enable sing-box >/dev/null 2>&1
    
    # 等待服务启动
    sleep 3
    
    # 检查服务状态
    local all_running=true
    
    for service in nginx xray sing-box; do
        if systemctl is-active --quiet $service; then
            log_success "$service 运行正常"
        else
            log_error "$service 启动失败"
            journalctl -u $service -n 20 --no-pager >> ${LOG_FILE}
            all_running=false
        fi
    done
    
    if [[ "$all_running" == true ]]; then
        log_success "所有服务启动成功"
    else
        log_warn "部分服务启动失败，请检查日志: ${LOG_FILE}"
    fi
}

# 生成订阅链接（统一兼容 v2rayN / ShadowRocket / Clash Meta）
generate_subscription() {
  log_info "生成订阅链接..."

  # --- 小工具：URL 编码 ---
  urlenc() {
    # 用 Python 做标准 URL 编码，避免 bash 转义坑
    python3 - <<'PY' "$1"
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
  }

  # 通用变量
  local ip="${SERVER_IP}"
  local uuid="${UUID_VLESS}"              # 注意：这里用 UUID_VLESS（脚本里就叫这个）
  local grpc_host="grpc.edgebox.local"
  local ws_host="www.edgebox.local"
  local ws_path="/ws"

  # 对可能含有 + / = 的密码进行 URL 编码
  local hy2_pwd_enc tuic_pwd_enc
  hy2_pwd_enc="$(urlenc "${PASSWORD_HYSTERIA2}")"
  tuic_pwd_enc="$(urlenc "${PASSWORD_TUIC}")"

  # 判断是否域名模式（虽然当前是 IP 模式，也兼容以后扩展）
  local domain=""
  if [[ -n "${EDGEBOX_DOMAIN:-}" && -f "/etc/letsencrypt/live/${EDGEBOX_DOMAIN}/fullchain.pem" && -f "/etc/letsencrypt/live/${EDGEBOX_DOMAIN}/privkey.pem" ]]; then
    domain="${EDGEBOX_DOMAIN}"
  fi

  # ========== 1) VLESS Reality（直连 443/TCP，xray）==========
  # Reality 不需要 allowInsecure
  local r_addr r_sni
  r_addr="${domain:-$ip}"
  r_sni="www.cloudflare.com"
  local reality_link="vless://${uuid}@${r_addr}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${r_sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&spx=%2F#EdgeBox-REALITY"

  # ========== 2) VLESS gRPC (TLS，经 Nginx stream 回落到 127.0.0.1:10085) ==========
  local grpc_addr="${domain:-$ip}"
  local grpc_tail
  if [[ -n "$domain" ]]; then
    grpc_tail="&alpn=h2&type=grpc&serviceName=grpc"
  else
    grpc_tail="&alpn=h2&type=grpc&serviceName=grpc&allowInsecure=1"
  fi
  local grpc_link="vless://${uuid}@${grpc_addr}:443?encryption=none&security=tls&sni=${grpc_host}${grpc_tail}#EdgeBox-gRPC"

  # ========== 3) VLESS WS (TLS，经 Nginx stream 回落到 127.0.0.1:10086) ==========
  local ws_addr="${domain:-$ip}"
  local ws_tail
  if [[ -n "$domain" ]]; then
    ws_tail="&type=ws&host=${ws_host}&path=${ws_path}"
  else
    ws_tail="&type=ws&host=${ws_host}&path=${ws_path}&allowInsecure=1"
  fi
  local ws_link="vless://${uuid}@${ws_addr}:443?encryption=none&security=tls&sni=${ws_host}${ws_tail}#EdgeBox-WS"

  # ========== 4) Hysteria2 (UDP/443，sing-box) ==========
  # IP 模式：客户端需要 ?insecure=1&sni=<你的IP>；域名模式可省略
  local hy2_addr="${domain:-$ip}"
  local hy2_tail
  if [[ -n "$domain" ]]; then
    hy2_tail=""               # 有域名有正规证书可不加
  else
    hy2_tail="?insecure=1&sni=${ip}"
  fi
  local hy2_link="hysteria2://${hy2_pwd_enc}@${hy2_addr}:443${hy2_tail}#EdgeBox-HYSTERIA2"

  # ========== 5) TUIC v5 (UDP/2053，sing-box) ==========
  # 关键点：大量客户端识别的是 allowInsecure=1（不是 insecure=1）
  local tuic_addr="${domain:-$ip}"
  local tuic_tail
  if [[ -n "$domain" ]]; then
    tuic_tail="?congestion_control=bbr&alpn=h3"
  else
    tuic_tail="?congestion_control=bbr&alpn=h3&allowInsecure=1"
  fi
  local tuic_link="tuic://${UUID_TUIC}:${tuic_pwd_enc}@${tuic_addr}:2053${tuic_tail}#EdgeBox-TUIC"

  # ========== 写出纯文本订阅（每行一个节点）==========
  local plain="${reality_link}\n${grpc_link}\n${ws_link}\n${hy2_link}\n${tuic_link}\n"
  mkdir -p "${CONFIG_DIR}" /var/www/html
  echo -e "${plain}" > "${CONFIG_DIR}/subscription.txt"

  # ========== 同步到 http 订阅（base64）==========
  printf '%s' "$(echo -e "${plain}" | base64 -w0)" > /var/www/html/sub

  # ========== Nginx 站点：用静态文件方式提供 /sub ==========
  cat > /etc/nginx/sites-available/edgebox-sub << 'NGX'
server {
    listen 80;
    server_name _;
    default_type text/plain;

    # 直接把 /var/www/html/sub 这个文件作为 /sub 返回
    location = /sub {
        types { }
        default_type text/plain;
        alias /var/www/html/sub;
        add_header Content-Type "text/plain; charset=utf-8";
    }

    # 其它路径给个简单说明（可选）
    location / {
        return 200 "EdgeBox subscription available at /sub\n";
    }
}
NGX
  ln -sf /etc/nginx/sites-available/edgebox-sub /etc/nginx/sites-enabled/edgebox-sub
  # 移除默认站点，避免冲突
  rm -f /etc/nginx/sites-enabled/default
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1

  log_success "订阅已生成并发布： http://${SERVER_IP}/sub"
  echo "${reality_link}"
  echo "${grpc_link}"
  echo "${ws_link}"
  echo "${hy2_link}"
  echo "${tuic_link}"
}

# 创建edgeboxctl基础框架
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
    ss -tlnp 2>/dev/null | grep -E ":(443|10085|10086|10443)" | awk '{print "  TCP: "$4}'
    ss -ulnp 2>/dev/null | grep -E ":(443|2053)" | awk '{print "  UDP: "$4}'
}

restart_services() {
    echo -e "${CYAN}重启所有服务...${NC}"
    
    for service in nginx xray sing-box; do
        echo -n "  重启 $service..."
        systemctl restart $service
        if systemctl is-active --quiet $service; then
            echo -e " ${GREEN}成功${NC}"
        else
            echo -e " ${RED}失败${NC}"
        fi
    done
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
        echo "用法: edgeboxctl logs [nginx|xray|sing-box]"
        return
    fi
    
    echo -e "${CYAN}查看 $service 日志：${NC}"
    journalctl -u $service -n 50 --no-pager
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
    
    # 测试TCP 443
    echo -n "  TCP 443端口: "
    if timeout 2 bash -c "echo >/dev/tcp/${server_ip}/443" 2>/dev/null; then
        echo -e "${GREEN}开放${NC}"
    else
        echo -e "${RED}关闭${NC}"
    fi
    
    # 测试UDP 2053
    echo -n "  UDP 2053端口: "
    if timeout 2 nc -u -z ${server_ip} 2053 2>/dev/null; then
        echo -e "${GREEN}开放${NC}"
    else
        echo -e "${YELLOW}未知（UDP难以准确测试）${NC}"
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
    echo -e "  ${YELLOW}edgeboxctl logs xray${NC}  # 查看日志"
    
    echo -e "\n${YELLOW}⚠️  注意事项：${NC}"
    echo -e "  1. 当前为IP模式，使用自签名证书"
    echo -e "  2. 客户端需要开启'跳过证书验证'选项"
    echo -e "  3. Reality协议不需要跳过证书验证"
    echo -e "  4. 防火墙已配置，请确保云服务商防火墙也开放相应端口"
    
    print_separator
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
    generate_reality_keys
    install_xray
    install_sing_box
    configure_nginx
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
main "$@"}
