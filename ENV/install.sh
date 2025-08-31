#!/bin/bash

#############################################
# EdgeBox 一站式多协议节点部署脚本
# Version: 2.0.0 
# Description: 非交互式IP模式安装 - 模块1：核心基础
# Protocols: VLESS-Reality, VLESS-gRPC, VLESS-WS, Hysteria2, TUIC
# Architecture: 单端口复用 + 本地订阅文件
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

# 端口配置（单端口复用架构）
PORT_REALITY=11443      # 内部回环 (Xray Reality)
PORT_HYSTERIA2=443    # UDP
PORT_TUIC=2053        # UDP
PORT_GRPC=10085       # 内部回环
PORT_WS=10086         # 内部回环

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

# 兼容别名
log() { log_info "$@"; }
log_ok() { log_success "$@"; }
error() { log_error "$@"; }

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
    
    # 基础工具（最小化依赖）
    PACKAGES="curl wget unzip tar net-tools openssl jq uuid-runtime vnstat iftop"
    
    # 添加Nginx和stream模块
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
    
    UUID_VLESS=$(uuidgen)
    UUID_HYSTERIA2=$(uuidgen)
    UUID_TUIC=$(uuidgen)
    
    REALITY_SHORT_ID="$(openssl rand -hex 8)"
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
    
    local ports=(443 2053)
    local occupied=false
    
    for port in "${ports[@]}"; do
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            log_warn "端口 $port 已被占用"
            occupied=true
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
    
    if [[ ! -f /etc/sysctl.conf.bak ]]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
    fi
    
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

# 生成自签名证书（修复EC证书验证）
generate_self_signed_cert() {
    log_info "生成自签名证书..."
    
    # 确保目录存在
    mkdir -p ${CERT_DIR}
    
    # 删除旧的证书文件
    rm -f ${CERT_DIR}/self-signed.key ${CERT_DIR}/self-signed.pem
    rm -f ${CERT_DIR}/current.key ${CERT_DIR}/current.pem
    
    # 生成新的证书和私钥
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) \
        -keyout ${CERT_DIR}/self-signed.key \
        -out ${CERT_DIR}/self-signed.pem \
        -days 3650 \
        -subj "/C=US/ST=California/L=San Francisco/O=EdgeBox/CN=${SERVER_IP}" >/dev/null 2>&1
    
    # 创建软链接
    ln -sf ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
    ln -sf ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
    
    # 设置正确的权限
    chown root:root ${CERT_DIR}/*.key ${CERT_DIR}/*.pem
    chmod 600 ${CERT_DIR}/*.key
    chmod 644 ${CERT_DIR}/*.pem

    # 最终验证（仅验证文件格式，不比对modulus）
    if openssl x509 -in ${CERT_DIR}/current.pem -noout -text >/dev/null 2>&1 && \
       openssl ec -in ${CERT_DIR}/current.key -noout -text >/dev/null 2>&1; then
        log_success "自签名证书生成完成并验证通过"
    else
        log_error "证书验证失败"
        return 1
    fi
}

# 生成Reality密钥对
generate_reality_keys() {
    log_info "生成Reality密钥对..."

    # 优先用 sing-box 生成
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

    # 回退：下载 Xray 生成
    local tmp_dir tag url ok=""
    tmp_dir="$(mktemp -d)"
    pushd "$tmp_dir" >/dev/null

    tag="$(curl -sIL -o /dev/null -w '%{url_effective}' https://github.com/XTLS/Xray-core/releases/latest | awk -F/ '{print $NF}')"
    [[ -z "$tag" ]] && tag="v1.8.11"

    for base in \
      "https://github.com/XTLS/Xray-core/releases/download" \
      "https://ghproxy.com/https://github.com/XTLS/Xray-core/releases/download"
    do
      url="${base}/${tag}/Xray-linux-64.zip"
      if wget -q --tries=3 --timeout=20 "$url" -O Xray-linux-64.zip; then 
          ok=1
          break
      fi
    done
    
    if [[ -z "$ok" ]]; then
        log_error "下载Xray失败"
        popd >/dev/null
        rm -rf "$tmp_dir"
        return 1
    fi

    unzip -q Xray-linux-64.zip
    local keys
    keys="$(./xray x25519)"
    REALITY_PRIVATE_KEY="$(echo "$keys" | awk '/Private key/{print $3}')"
    REALITY_PUBLIC_KEY="$(echo  "$keys" | awk '/Public key/{print  $3}')"

    popd >/dev/null
    rm -rf "$tmp_dir"
    
    if [[ -n "$REALITY_PRIVATE_KEY" && -n "$REALITY_PUBLIC_KEY" ]]; then
        log_success "Reality密钥对生成完成"
    else
        log_error "生成Reality密钥失败"
        return 1
    fi
}

# 安装Xray
install_xray() {
    log_info "安装Xray..."

    if command -v xray &>/dev/null; then
        log_info "Xray已安装，跳过"
    else
        bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null 2>&1 || {
            log_error "Xray安装失败"
            exit 1
        }
    fi

    # 停用官方的 systemd 服务
    systemctl disable --now xray >/dev/null 2>&1 || true
    rm -rf /etc/systemd/system/xray.service.d 2>/dev/null || true

    log_success "Xray安装完成"
}

# 安装sing-box
install_sing_box() {
    log_info "安装sing-box..."

    if [[ -f /usr/local/bin/sing-box ]]; then
        log_info "sing-box已安装，跳过"
    else
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
          if wget -q --tries=3 --timeout=25 "$url" -O "/tmp/sing-box-${ver}.tar.gz"; then 
              ok=1
              break
          fi
        done
        
        if [[ -z "$ok" ]]; then
            log_error "下载sing-box失败"
            exit 1
        fi

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

# 配置Xray（Reality + Fallback to Nginx）
configure_xray() {
    log_info "配置 Xray（内部服务，无fallbacks）..."

    cat > ${CONFIG_DIR}/xray.json <<XRAY_CONFIG
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "VLESS-Reality",
      "listen": "127.0.0.1",
      "port": 11443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { 
            "id": "${UUID_VLESS}", 
            "flow": "xtls-rprx-vision", 
            "email": "reality@edgebox" 
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
        "clients": [ 
          { 
            "id": "${UUID_VLESS}", 
            "email": "grpc-internal@edgebox" 
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
              "certificateFile": "${CERT_DIR}/current.pem", 
              "keyFile": "${CERT_DIR}/current.key" 
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
      "tag": "VLESS-WS-Internal", 
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "vless",
      "settings": {
        "clients": [ 
          { 
            "id": "${UUID_VLESS}", 
            "email": "ws-internal@edgebox" 
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
              "certificateFile": "${CERT_DIR}/current.pem", 
              "keyFile": "${CERT_DIR}/current.key" 
            } 
          ]
        },
        "wsSettings": { 
          "path": "/ws",
          "headers": {
            "Host": "ws.edgebox.local"
          }
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
XRAY_CONFIG

    cat >/etc/systemd/system/xray.service <<'XRAY_SERVICE'
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
XRAY_SERVICE

    systemctl daemon-reload
    log_success "Xray 配置完成"
}

# 配置Nginx（stream模块 + ALPN分流）
configure_nginx() {
    log_info "配置 Nginx（Nginx-first 单端口复用架构）..."
    
    # 停止 Nginx 避免冲突
    systemctl stop nginx >/dev/null 2>&1 || true
    
    # 检查并加载stream模块
    if [ -f /usr/share/nginx/modules-available/mod-stream.conf ]; then
        mkdir -p /etc/nginx/modules-enabled
        ln -sf /usr/share/nginx/modules-available/mod-stream.conf /etc/nginx/modules-enabled/50-mod-stream.conf 2>/dev/null || true
    fi
    
    # 备份原配置
    if [ -f /etc/nginx/nginx.conf ] && [ ! -f /etc/nginx/nginx.conf.bak ]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    fi

    # 创建正确的Nginx-first配置
    cat > /etc/nginx/nginx.conf <<'NGINX_FIRST_END'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

# 加载stream模块
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        root /var/www/html;
        
        location / {
            try_files $uri $uri/ =404;
        }
        
        location = /sub {
            default_type text/plain;
            root /var/www/html;
        }
    }
}

stream {
    # SNI 是否伪装站：命中则走 Reality
    map $ssl_preread_server_name $is_reality {
        ~^(www\.cloudflare\.com|www\.apple\.com|www\.microsoft\.com)$ 1;
        default 0;
    }

    # 非 Reality 时再看 ALPN 分流
    map $ssl_preread_alpn_protocols $alpn {
        ~\bhttp/1\.1\b  ws;
        ~\bh2\b         grpc;
        default           ws;
    }

    # 组合路由：优先 Reality，其次 ALPN
    map "$is_reality:$alpn" $upstream {
        "~^1:"      127.0.0.1:11443; # Reality
        "~^0:grpc$" 127.0.0.1:10085; # gRPC
        "~^0:ws$"   127.0.0.1:10086; # WS
        default     127.0.0.1:10086; # 兜底防回环
    }

    server {
        listen 0.0.0.0:443;
        ssl_preread on;
        proxy_pass $upstream;
        proxy_timeout 15s;
        proxy_connect_timeout 5s;
    }
}
NGINX_FIRST_END

    # 创建web目录
    mkdir -p /var/www/html
    
    # 测试配置
    if nginx -t >/dev/null 2>&1; then
        log_info "Nginx 配置测试通过"
    else
        log_error "Nginx 配置测试失败，尝试修复..."
        # 如果失败，尝试不使用stream模块
        cat > /etc/nginx/nginx.conf <<'NGINX_SIMPLE'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    server {
        listen 80;
        server_name _;
        root /var/www/html;
        
        location = /sub {
            default_type text/plain;
        }
    }
}
NGINX_SIMPLE
        log_warn "使用简化的Nginx配置（无stream模块）"
    fi

    # 启动Nginx
    systemctl daemon-reload
    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx >/dev/null 2>&1 || {
        log_warn "Nginx 启动失败，但继续安装"
    }
    
    log_success "Nginx 配置完成"
}

# 配置sing-box（Hysteria2 + TUIC）
configure_sing_box() {
    log_info "配置sing-box（Hysteria2 + TUIC）..."
    
    cat > ${CONFIG_DIR}/sing-box.json <<SINGBOX_CONFIG
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
          "password": "${PASSWORD_HYSTERIA2}"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
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
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
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
SINGBOX_CONFIG
    
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
    "ws": ${PORT_WS}
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
    systemctl enable nginx xray sing-box >/dev/null 2>&1 || true

    systemctl restart nginx >/dev/null 2>&1
    systemctl restart xray >/dev/null 2>&1
    systemctl restart sing-box >/dev/null 2>&1

    sleep 2

    for s in nginx xray sing-box; do
        if systemctl is-active --quiet "$s"; then
            log_success "$s 运行正常"
        else
            log_error "$s 启动失败（详见 ${LOG_FILE}）"
            journalctl -u "$s" -n 50 --no-pager >> ${LOG_FILE}
        fi
    done
}

# 生成订阅链接（单端口复用 - 443）
generate_subscription() {
    log_info "生成订阅链接（Nginx-first 架构）..."

    local ip="${SERVER_IP}"
    local uuid="${UUID_VLESS}"

    # URL编码密码
    local HY2_PW_ENC TUIC_PW_ENC
    HY2_PW_ENC=$(jq -rn --arg v "$PASSWORD_HYSTERIA2" '$v|@uri')
    TUIC_PW_ENC=$(jq -rn --arg v "$PASSWORD_TUIC" '$v|@uri')

    # 1) VLESS Reality - 443端口，SNI使用伪装域名
    local reality_link="vless://${uuid}@${ip}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY"

    # 2) VLESS gRPC - 443端口，通过Nginx分流，SNI使用服务域名
    local grpc_link="vless://${uuid}@${ip}:443?encryption=none&security=tls&sni=grpc.edgebox.local&alpn=h2&type=grpc&serviceName=grpc&alpn=h2&fp=chrome&allowInsecure=1#EdgeBox-gRPC"

    # 3) VLESS WS - 443端口，通过Nginx分流，SNI使用服务域名  
    local ws_link="vless://${uuid}@${ip}:443?encryption=none&security=tls&sni=ws.edgebox.local&alpn=http%2F1.1&type=ws&path=/ws&alpn=http/1.1&fp=chrome&allowInsecure=1#EdgeBox-WS"

    # 4) Hysteria2 - 443端口(UDP)
    local hy2_link="hysteria2://${HY2_PW_ENC}@${ip}:443?insecure=1&sni=${ip}&alpn=h3#EdgeBox-HYSTERIA2"

    # 5) TUIC v5 - 2053端口
    local tuic_link="tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${ip}:2053?congestion_control=bbr&alpn=h3&sni=${ip}&allowInsecure=1#EdgeBox-TUIC"

    # 输出订阅
    local plain="${reality_link}
${grpc_link}
${ws_link}
${hy2_link}
${tuic_link}"
    
    echo -e "${plain}" > "${CONFIG_DIR}/subscription.txt"
    echo -e "${plain}" | base64 -w0 > "${CONFIG_DIR}/subscription.base64"

    # 创建HTTP订阅服务
    mkdir -p /var/www/html
    echo -e "${plain}" | base64 -w0 > /var/www/html/sub
    
    log_success "订阅已生成（Nginx-first架构）"
    log_success "HTTP订阅地址：http://${ip}/sub"
}
# 创建edgeboxctl管理工具（模块1：核心基础）
create_edgeboxctl() {
    log_info "创建管理工具..."
    
    cat > /usr/local/bin/edgeboxctl << 'EOFCTL'
#!/bin/bash

# EdgeBox Control Script - Module 1: Core Foundation
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
    echo -e "${YELLOW}模块1：核心基础功能${NC}"
    echo ""
    echo "用法: edgeboxctl [命令] [选项]"
    echo ""
    echo "基础服务管理:"
    echo "  status          显示服务状态"
    echo "  restart         重启所有服务" 
    echo "  logs [service]  查看服务日志"
    echo ""
    echo "配置管理:"
    echo "  show-config     显示当前配置"
    echo "  sub             显示订阅链接"
    echo ""
    echo "调试工具:"
    echo "  test            测试连接"
    echo "  debug-ports     调试端口状态"
    echo "  fix-permissions 修复证书权限"
    echo ""
    echo "  help            显示帮助信息"
    echo ""
    echo -e "${YELLOW}注：高级功能（模式切换、证书管理、分流等）将在模块2中实现${NC}"
}

show_sub() {
    if [[ ! -f ${CONFIG_DIR}/server.json ]]; then
        echo -e "${RED}配置文件不存在${NC}"
        exit 1
    fi
    
    echo -e "${CYAN}订阅链接（本地文件模式）：${NC}"
    echo ""
    
    if [[ -f ${CONFIG_DIR}/subscription.txt ]]; then
        echo -e "${YELLOW}明文链接：${NC}"
        cat ${CONFIG_DIR}/subscription.txt
        echo ""
    fi
    
    if [[ -f ${CONFIG_DIR}/subscription.base64 ]]; then
        echo -e "${YELLOW}Base64订阅：${NC}"
        cat ${CONFIG_DIR}/subscription.base64
        echo ""
    fi
    
    echo -e "${CYAN}说明：${NC}"
    echo "- 订阅链接已保存到本地文件，请手动导入到客户端"
    echo "- 明文链接位置：${CONFIG_DIR}/subscription.txt"
    echo "- Base64订阅位置：${CONFIG_DIR}/subscription.base64"
}

show_status() {
    echo -e "${CYAN}服务状态（单端口复用架构）：${NC}"
    
    for service in xray sing-box; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo -e "  $service: ${GREEN}运行中${NC}"
        else
            echo -e "  $service: ${RED}已停止${NC}"
        fi
    done
    
    echo ""
    echo -e "${CYAN}端口监听状态：${NC}"
    echo -e "${YELLOW}公网端口：${NC}"
    ss -tlnp 2>/dev/null | grep ":443 " && echo -e "  TCP/443: ${GREEN}正常${NC}" || echo -e "  TCP/443: ${RED}异常${NC}"
    ss -ulnp 2>/dev/null | grep ":443 " && echo -e "  UDP/443: ${GREEN}正常${NC}" || echo -e "  UDP/443: ${RED}异常${NC}"
    ss -ulnp 2>/dev/null | grep ":2053 " && echo -e "  UDP/2053: ${GREEN}正常${NC}" || echo -e "  UDP/2053: ${RED}异常${NC}"
    
    echo -e "${YELLOW}内部回环端口：${NC}"
    ss -tlnp 2>/dev/null | grep "127.0.0.1:10085 " && echo -e "  gRPC内部: ${GREEN}正常${NC}" || echo -e "  gRPC内部: ${RED}异常${NC}"
    ss -tlnp 2>/dev/null | grep "127.0.0.1:10086 " && echo -e "  WS内部: ${GREEN}正常${NC}" || echo -e "  WS内部: ${RED}异常${NC}"
}

restart_services() {
    echo -e "${CYAN}重启所有服务...${NC}"
    
    services=("sing-box" "xray")
    
    for service in "${services[@]}"; do
        echo -n "  重启 $service..."
        if systemctl restart $service 2>/dev/null; then
            sleep 1
            if systemctl is-active --quiet $service; then
                echo -e " ${GREEN}成功${NC}"
            else
                echo -e " ${RED}失败${NC}"
            fi
        else
            echo -e " ${RED}失败${NC}"
        fi
    done
    
    sleep 2
    show_status
}

show_config() {
    if [[ ! -f ${CONFIG_DIR}/server.json ]]; then
        echo -e "${RED}配置文件不存在${NC}"
        exit 1
    fi
    
    echo -e "${CYAN}当前配置：${NC}"
    if command -v jq >/dev/null 2>&1; then
        jq '.' ${CONFIG_DIR}/server.json
    else
        cat ${CONFIG_DIR}/server.json
    fi
}

show_logs() {
    local service=$1
    if [[ -z "$service" ]]; then
        echo "用法: edgeboxctl logs [xray|sing-box]"
        return
    fi
    
    case "$service" in
        xray)
            echo -e "${CYAN}Xray 系统日志：${NC}"
            journalctl -u xray -n 30 --no-pager 2>/dev/null || echo "无法获取日志"
            ;;
        sing-box)
            echo -e "${CYAN}sing-box 系统日志：${NC}"
            journalctl -u sing-box -n 30 --no-pager 2>/dev/null || echo "无法获取日志"
            ;;
        *)
            echo -e "${RED}未知服务: $service${NC}"
            ;;
    esac
}

debug_ports() {
    echo -e "${CYAN}端口调试信息（单端口复用架构）：${NC}"
    
    echo -e "\n${YELLOW}端口检查：${NC}"
    echo "  TCP/443 (Nginx单一入口): $(ss -tln | grep -q ":443 " && echo "✓" || echo "✗")"
    echo "  UDP/443 (Hysteria2): $(ss -uln | grep -q ":443 " && echo "✓" || echo "✗")"
    echo "  UDP/2053 (TUIC): $(ss -uln | grep -q ":2053 " && echo "✓" || echo "✗")" 
    echo "  TCP/10085 (gRPC内部): $(ss -tln | grep -q "127.0.0.1:10085 " && echo "✓" || echo "✗")"
    echo "  TCP/10086 (WS内部): $(ss -tln | grep -q "127.0.0.1:10086 " && echo "✓" || echo "✗")"
}

test_connection() {
    echo -e "${CYAN}连接测试（单端口复用架构）：${NC}"
    
    local server_ip
    server_ip=$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null) || {
        echo -e "${RED}无法获取服务器IP${NC}"
        return 1
    }
    
    echo -n "  TCP 443端口（Nginx单一入口）: "
    if timeout 3 bash -c "echo >/dev/tcp/${server_ip}/443" 2>/dev/null; then
        echo -e "${GREEN}开放${NC}"
    else
        echo -e "${RED}关闭${NC}"
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
    sub) show_sub ;;
    status) show_status ;;
    restart) restart_services ;;
    show-config|config) show_config ;;
    logs|log) show_logs $2 ;;
    test) test_connection ;;
    debug-ports) debug_ports ;;
    fix-permissions) fix_permissions ;;
    help|*) show_help ;;
esac
EOFCTL
    
    chmod +x /usr/local/bin/edgeboxctl
    log_success "管理工具创建完成（模块1：核心契约已建立）"
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
    echo -e "      SNI: www.cloudflare.com"
    
    echo -e "\n  ${PURPLE}[2] VLESS-gRPC${NC}"
    echo -e "      端口: 443（Nginx 分流）"
    echo -e "      UUID: ${UUID_VLESS}"
    echo -e "      SNI: grpc.edgebox.local"
    echo -e "      serviceName: grpc"
    
    echo -e "\n  ${PURPLE}[3] VLESS-WS${NC}"
    echo -e "      端口: 443（Nginx 分流）"
    echo -e "      UUID: ${UUID_VLESS}"
    echo -e "      SNI: ws.edgebox.local"
    echo -e "      路径: /ws"
    
    echo -e "\n  ${PURPLE}[4] Hysteria2${NC}"
    echo -e "      端口: 443 (UDP)"
    echo -e "      密码: ${PASSWORD_HYSTERIA2}"
    
    echo -e "\n  ${PURPLE}[5] TUIC${NC}"
    echo -e "      端口: 2053 (UDP)"
    echo -e "      UUID: ${UUID_TUIC}"
    echo -e "      密码: ${PASSWORD_TUIC}"
    
    echo -e "\n${CYAN}管理命令：${NC}"
    echo -e "  ${YELLOW}edgeboxctl sub${NC}        # 查看订阅链接（本地文件）"
    echo -e "  ${YELLOW}edgeboxctl status${NC}     # 查看服务状态"
    echo -e "  ${YELLOW}edgeboxctl restart${NC}    # 重启所有服务"
    echo -e "  ${YELLOW}edgeboxctl test${NC}       # 测试连接"
    echo -e "  ${YELLOW}edgeboxctl debug-ports${NC}   # 调试端口状态"
    echo -e "  ${YELLOW}edgeboxctl logs xray${NC}  # 查看日志"
    
    echo -e "\n${YELLOW}注意事项：${NC}"
    echo -e "  1. 当前为IP模式，使用自签名证书"
    echo -e "  2. 客户端需要开启'跳过证书验证'选项"
    echo -e "  3. Reality协议不需要跳过证书验证"
    echo -e "  4. 防火墙已配置，请确保云服务商防火墙也开放相应端口"
    echo -e "  5. 订阅链接已保存到本地文件，使用 ${YELLOW}edgeboxctl sub${NC} 查看"
    
    print_separator
}

# 清理函数
cleanup() {
    if [ "$?" -eq 0 ]; then
        log_info "清理临时文件..."
        rm -f /tmp/Xray-linux-64.zip 2>/dev/null || true
        rm -f /tmp/sing-box-*.tar.gz 2>/dev/null || true
    fi
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
    install_sing_box
    generate_reality_keys
    install_xray
    configure_nginx        # 必须配置Nginx
    configure_xray         # 使用原来的双层分流方案
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
