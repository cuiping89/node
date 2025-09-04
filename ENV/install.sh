#!/bin/bash

#############################################
# EdgeBox 企业级多协议节点部署脚本 - 完全增强版
# Version: 3.0.0 - 模块1+2+3完整版
# Description: 包含流量统计、预警、备份恢复、出站分流等高级运维功能
# Protocols: VLESS-Reality, VLESS-gRPC, VLESS-WS, Hysteria2, TUIC
# Architecture: SNI定向 + ALPN兜底 + 智能分流 + 流量监控
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
TRAFFIC_DIR="${INSTALL_DIR}/traffic"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"
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
    
    # 基础工具（完整依赖）
    PACKAGES="curl wget unzip tar net-tools openssl jq uuid-runtime vnstat iftop certbot bc"
    
    # 添加Nginx和stream模块
    PACKAGES="$PACKAGES nginx libnginx-mod-stream"
    
    # Python和科学计算包（用于图表生成）
    PACKAGES="$PACKAGES python3 python3-pip python3-matplotlib python3-pandas"
    
    # 邮件发送工具
    PACKAGES="$PACKAGES msmtp msmtp-mta mailutils"
    
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
    
    # 安装Python依赖包
    log_info "安装Python依赖包..."
    pip3 install matplotlib pandas numpy >/dev/null 2>&1 || {
        log_warn "Python包安装失败，流量图表功能可能无法使用"
    }
    
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
    log_info "VLESS UUID: $UUID_VLESS"
    log_info "TUIC UUID: $UUID_TUIC"
    log_info "Hysteria2 密码: $PASSWORD_HYSTERIA2"
}

# 创建目录结构
create_directories() {
    log_info "创建完整目录结构..."
    
    mkdir -p ${INSTALL_DIR}/{cert,config,templates,scripts}
    mkdir -p ${TRAFFIC_DIR}/{logs,charts}
    mkdir -p ${CONFIG_DIR}/shunt
    mkdir -p ${BACKUP_DIR}
    mkdir -p /var/log/edgebox
    mkdir -p /var/log/xray
    mkdir -p /var/www/html
    
    log_success "目录结构创建完成"
}

# 检查端口占用
check_ports() {
    log_info "检查端口占用情况..."
    
    local ports=(443 2053 80)
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

# 生成自签名证书
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
    
    # 创建软链接（契约接口）
    ln -sf ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
    ln -sf ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
    
    # 设置正确的权限
    chown root:root ${CERT_DIR}/*.key ${CERT_DIR}/*.pem
    chmod 600 ${CERT_DIR}/*.key
    chmod 644 ${CERT_DIR}/*.pem

    # 最终验证
    if openssl x509 -in ${CERT_DIR}/current.pem -noout -text >/dev/null 2>&1 && \
       openssl ec -in ${CERT_DIR}/current.key -noout -text >/dev/null 2>&1; then
        log_success "自签名证书生成完成并验证通过"
        
        # 设置初始证书模式（契约状态）
        echo "self-signed" > ${CONFIG_DIR}/cert_mode
    else
        log_error "证书验证失败"
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

    log_success "sing-box安装完成"
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
            log_info "Reality公钥: $REALITY_PUBLIC_KEY"
            return 0
        fi
    fi

    # 回退：使用 Xray 生成
    if command -v xray >/dev/null 2>&1; then
        local keys
        keys="$(xray x25519)"
        REALITY_PRIVATE_KEY="$(echo "$keys" | awk '/Private key/{print $3}')"
        REALITY_PUBLIC_KEY="$(echo  "$keys" | awk '/Public key/{print  $3}')"
        if [[ -n "$REALITY_PRIVATE_KEY" && -n "$REALITY_PUBLIC_KEY" ]]; then
            log_success "Reality密钥对生成完成（xray）"
            log_info "Reality公钥: $REALITY_PUBLIC_KEY"
            return 0
        fi
    fi

    log_error "生成Reality密钥失败"
    return 1
}

# 配置Nginx（SNI定向 + ALPN兜底架构）
configure_nginx() {
  log_info "配置 Nginx（SNI 定向 + ALPN 兜底）..."

  # 停服务，避免端口/旧配置冲突
  systemctl stop nginx >/dev/null 2>&1 || true

  # 确保 stream 模块已加载
  if [ -f /usr/share/nginx/modules-available/mod-stream.conf ]; then
    mkdir -p /etc/nginx/modules-enabled
    ln -sf /usr/share/nginx/modules-available/mod-stream.conf \
           /etc/nginx/modules-enabled/50-mod-stream.conf 2>/dev/null || true
  fi

  # 备份一次原配置
  if [ -f /etc/nginx/nginx.conf ] && [ ! -f /etc/nginx/nginx.conf.bak ]; then
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
  fi

  # 写入带 stream 的主配置（SNI 优先 + ALPN 兜底）
  cat > /etc/nginx/nginx.conf <<'NGINX_CONF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

# 加载动态模块（包含 stream）
include /etc/nginx/modules-enabled/*.conf;

events { worker_connections 1024; use epoll; }

http {
  sendfile on; tcp_nopush on; types_hash_max_size 2048;
  include /etc/nginx/mime.types; default_type application/octet-stream;
  access_log /var/log/nginx/access.log;

  server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/html;
    index index.html;
    
    # 静态文件缓存控制
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    
    location / { 
      try_files $uri $uri/ =404; 
    }
    
    # 订阅接口
    location = /sub { 
      default_type text/plain; 
      root /var/www/html; 
    }
    
    # 流量统计页面
    location /traffic {
      alias /etc/edgebox/traffic;
      autoindex on;
    }
  }
}

stream {
  # 1) SNI 显式路由（Reality 伪装域名直送 Reality；IP 模式用内部标识）
  map $ssl_preread_server_name $svc {
    ~^(www\.cloudflare\.com|www\.apple\.com|www\.microsoft\.com)$  reality;
    grpc.edgebox.internal  grpc;
    ws.edgebox.internal    ws;
    default "";
  }

  # 2) ALPN 兜底（h2 -> gRPC；http/1.1 -> WS）
  map $ssl_preread_alpn_protocols $by_alpn {
    ~\bh2\b          127.0.0.1:10085;
    ~\bhttp/1\.1\b   127.0.0.1:10086;
    default          127.0.0.1:10086;
  }

  # 3) SNI 命中优先
  map $svc $upstream_sni {
    reality  127.0.0.1:11443;
    grpc     127.0.0.1:10085;
    ws       127.0.0.1:10086;
    default  "";
  }

  # 4) 最终决策：SNI 优先，未命中走 ALPN
  map $upstream_sni $upstream {
    ~.+     $upstream_sni;
    default $by_alpn;
  }

  server {
    listen 0.0.0.0:443;
    ssl_preread on;
    proxy_pass $upstream;
    proxy_connect_timeout 5s;
    proxy_timeout 15s;
    proxy_protocol off;
  }
}
NGINX_CONF

  # 语法校验
  if ! nginx -t >/dev/null 2>&1; then
    log_error "Nginx 配置测试失败，请检查 /etc/nginx/nginx.conf"
    return 1
  fi

  # 用 enable + restart（不要 reload）
  systemctl daemon-reload
  systemctl enable nginx >/dev/null 2>&1 || true
  if systemctl restart nginx >/dev/null 2>&1; then
    log_success "Nginx 已启动（SNI 定向 + ALPN 兜底架构生效）"
  else
    log_error "Nginx 启动失败，最近日志："
    journalctl -u nginx -n 50 --no-pager | tail -n 20
    return 1
  fi
}

# 配置Xray
configure_xray() {
    log_info "配置 Xray..."

    # 验证必要变量
    if [[ -z "$UUID_VLESS" || -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_SHORT_ID" ]]; then
        log_error "必要的配置变量未设置"
        return 1
    fi

    # 生成配置文件
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
          "path": "/ws"
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

    # 验证配置文件
    if ! jq '.' ${CONFIG_DIR}/xray.json >/dev/null 2>&1; then
        log_error "Xray 配置JSON语法错误"
        return 1
    fi

    # 创建systemd服务
    cat > /etc/systemd/system/xray.service << 'XRAY_SERVICE'
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

# 配置sing-box
configure_sing_box() {
    log_info "配置sing-box..."
    
    # 验证必要变量
    if [[ -z "$PASSWORD_HYSTERIA2" || -z "$UUID_TUIC" || -z "$PASSWORD_TUIC" ]]; then
        log_error "必要的配置变量未设置"
        return 1
    fi

    # 生成配置文件
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
EOF

    # 验证配置文件
    if ! jq '.' ${CONFIG_DIR}/sing-box.json >/dev/null 2>&1; then
        log_error "sing-box 配置JSON语法错误"
        return 1
    fi

    # 创建systemd服务
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
  "version": "3.0.0",
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
  systemctl restart xray  >/dev/null 2>&1
  systemctl restart sing-box >/dev/null 2>&1

  sleep 2
  for s in nginx xray sing-box; do
    if systemctl is-active --quiet "$s"; then
      log_success "$s 运行正常"
    else
      log_error "$s 启动失败"
      journalctl -u "$s" -n 30 --no-pager | tail -n 20
    fi
  done
}

# 生成订阅链接
generate_subscription() {
    log_info "生成订阅链接..."

    # 验证必要变量
    if [[ -z "$SERVER_IP" || -z "$UUID_VLESS" || -z "$REALITY_PUBLIC_KEY" ]]; then
        log_error "必要的配置变量未设置，无法生成订阅"
        return 1
    fi

    local address="${SERVER_IP}"
    local uuid="${UUID_VLESS}"
    local allowInsecure_param="&allowInsecure=1"
    local insecure_param="&insecure=1"
    local WS_SNI="ws.edgebox.internal"

    # URL编码密码
    local HY2_PW_ENC TUIC_PW_ENC
    HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
    TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC" | jq -rR @uri)

    # 生成订阅链接
    local reality_link="vless://${uuid}@${address}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY"

    local grpc_link="vless://${uuid}@${address}:443?encryption=none&security=tls&sni=grpc.edgebox.internal&alpn=h2&type=grpc&serviceName=grpc&fp=chrome${allowInsecure_param}#EdgeBox-gRPC"

    local ws_link="vless://${uuid}@${address}:443?encryption=none&security=tls&sni=${WS_SNI}&host=${WS_SNI}&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome${allowInsecure_param}#EdgeBox-WS"
    
    local hy2_link="hysteria2://${HY2_PW_ENC}@${address}:443?sni=${address}&alpn=h3${insecure_param}#EdgeBox-HYSTERIA2"

    local tuic_link="tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${address}:2053?congestion_control=bbr&alpn=h3&sni=${address}${allowInsecure_param}#EdgeBox-TUIC"

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
    
    log_success "订阅已生成"
    log_success "HTTP订阅地址: http://${address}/sub"
}

#############################################
# 模块3：高级运维功能安装
#############################################

# 设置流量监控系统
setup_traffic_monitoring() {
    log_info "设置流量监控系统..."
    
    # 创建流量采集脚本
    cat > "${SCRIPTS_DIR}/traffic-collector.sh" <<'COLLECTOR_SCRIPT'
#!/bin/bash
# EdgeBox 流量采集器
TRAFFIC_DIR="/etc/edgebox/traffic"
DAILY_CSV="${TRAFFIC_DIR}/logs/daily.csv"
MONTHLY_CSV="${TRAFFIC_DIR}/logs/monthly.csv"

# 创建日志目录
mkdir -p "${TRAFFIC_DIR}/logs"

# 获取当前日期
DATE=$(date +%Y-%m-%d)
MONTH=$(date +%Y-%m)
HOUR=$(date +%H)

# 创建CSV表头（如果文件不存在）
if [[ ! -f "$DAILY_CSV" ]]; then
    echo "date,hour,total_rx,total_tx,tcp443_rx,tcp443_tx,udp443_rx,udp443_tx,udp2053_rx,udp2053_tx" > "$DAILY_CSV"
fi

if [[ ! -f "$MONTHLY_CSV" ]]; then
    echo "month,total_rx,total_tx,tcp443_rx,tcp443_tx,udp443_rx,udp443_tx,udp2053_rx,udp2053_tx" > "$MONTHLY_CSV"
fi

# 获取网络接口
IFACE=$(ip route | awk '/default/{print $5; exit}')

# 获取总流量（vnStat）
if command -v vnstat >/dev/null 2>&1; then
    VNSTAT_OUTPUT=$(vnstat -i "$IFACE" --oneline 2>/dev/null | tail -1)
    if [[ -n "$VNSTAT_OUTPUT" ]]; then
        # 解析vnstat输出格式
        TOTAL_RX=$(echo "$VNSTAT_OUTPUT" | awk -F';' '{print $9}' | grep -oE '[0-9.]+' | head -1)
        TOTAL_TX=$(echo "$VNSTAT_OUTPUT" | awk -F';' '{print $10}' | grep -oE '[0-9.]+' | head -1)
        # 转换为字节
        TOTAL_RX=$(echo "${TOTAL_RX:-0} * 1024 * 1024" | bc 2>/dev/null || echo "0")
        TOTAL_TX=$(echo "${TOTAL_TX:-0} * 1024 * 1024" | bc 2>/dev/null || echo "0")
    else
        TOTAL_RX=0
        TOTAL_TX=0
    fi
else
    TOTAL_RX=0
    TOTAL_TX=0
fi

# 获取端口流量（iptables）
get_port_traffic() {
    local proto=$1
    local port=$2
    
    # 创建iptables规则（如果不存在）
    iptables -C INPUT -p $proto --dport $port -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p $proto --dport $port -j ACCEPT
    iptables -C OUTPUT -p $proto --sport $port -j ACCEPT 2>/dev/null || \
        iptables -I OUTPUT -p $proto --sport $port -j ACCEPT
    
    local rx=$(iptables -L INPUT -v -n 2>/dev/null | grep "dpt:$port " | grep $proto | head -1 | awk '{print $2}' || echo "0")
    local tx=$(iptables -L OUTPUT -v -n 2>/dev/null | grep "spt:$port " | grep $proto | head -1 | awk '{print $2}' || echo "0")
    
    # 转换单位为字节
    rx=$(echo "$rx" | sed 's/K/*1024/g; s/M/*1048576/g; s/G/*1073741824/g' | bc 2>/dev/null || echo "0")
    tx=$(echo "$tx" | sed 's/K/*1024/g; s/M/*1048576/g; s/G/*1073741824/g' | bc 2>/dev/null || echo "0")
    
    echo "$rx,$tx"
}

# 获取各端口流量
TCP443_DATA=$(get_port_traffic tcp 443)
UDP443_DATA=$(get_port_traffic udp 443)
UDP2053_DATA=$(get_port_traffic udp 2053)

# 写入日流量数据
echo "$DATE,$HOUR,$TOTAL_RX,$TOTAL_TX,${TCP443_DATA},${UDP443_DATA},${UDP2053_DATA}" >> "$DAILY_CSV"

# 数据清理：保留最近90天
tail -n 2160 "$DAILY_CSV" > "${DAILY_CSV}.tmp" && mv "${DAILY_CSV}.tmp" "$DAILY_CSV"

# 月度汇总（每日23点执行）
if [[ "$HOUR" == "23" ]]; then
    # 计算当月累计
    MONTH_RX=$(awk -F',' -v month="$MONTH" '$1 ~ month {sum+=$3} END {print sum+0}' "$DAILY_CSV")
    MONTH_TX=$(awk -F',' -v month="$MONTH" '$1 ~ month {sum+=$4} END {print sum+0}' "$DAILY_CSV")
    MONTH_TCP443_RX=$(awk -F',' -v month="$MONTH" '$1 ~ month {sum+=$5} END {print sum+0}' "$DAILY_CSV")
    MONTH_TCP443_TX=$(awk -F',' -v month="$MONTH" '$1 ~ month {sum+=$6} END {print sum+0}' "$DAILY_CSV")
    MONTH_UDP443_RX=$(awk -F',' -v month="$MONTH" '$1 ~ month {sum+=$7} END {print sum+0}' "$DAILY_CSV")
    MONTH_UDP443_TX=$(awk -F',' -v month="$MONTH" '$1 ~ month {sum+=$8} END {print sum+0}' "$DAILY_CSV")
    MONTH_UDP2053_RX=$(awk -F',' -v month="$MONTH" '$1 ~ month {sum+=$9} END {print sum+0}' "$DAILY_CSV")
    MONTH_UDP2053_TX=$(awk -F',' -v month="$MONTH" '$1 ~ month {sum+=$10} END {print sum+0}' "$DAILY_CSV")
    
    # 更新或添加月度记录
    if grep -q "^$MONTH," "$MONTHLY_CSV"; then
        sed -i "s/^$MONTH,.*/$MONTH,$MONTH_RX,$MONTH_TX,$MONTH_TCP443_RX,$MONTH_TCP443_TX,$MONTH_UDP443_RX,$MONTH_UDP443_TX,$MONTH_UDP2053_RX,$MONTH_UDP2053_TX/" "$MONTHLY_CSV"
    else
        echo "$MONTH,$MONTH_RX,$MONTH_TX,$MONTH_TCP443_RX,$MONTH_TCP443_TX,$MONTH_UDP443_RX,$MONTH_UDP443_TX,$MONTH_UDP2053_RX,$MONTH_UDP2053_TX" >> "$MONTHLY_CSV"
    fi
    
    # 保留最近24个月
    tail -n 25 "$MONTHLY_CSV" > "${MONTHLY_CSV}.tmp" && mv "${MONTHLY_CSV}.tmp" "$MONTHLY_CSV"
fi
COLLECTOR_SCRIPT

    chmod +x "${SCRIPTS_DIR}/traffic-collector.sh"
    
    # 创建图表生成脚本
    cat > "${SCRIPTS_DIR}/generate-charts.py" <<'CHART_SCRIPT'
#!/usr/bin/env python3
# EdgeBox 图表生成器
import os
import sys
import csv
import json
import subprocess
from datetime import datetime, timedelta
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from pathlib import Path

# 配置路径
TRAFFIC_DIR = "/etc/edgebox/traffic"
CHARTS_DIR = f"{TRAFFIC_DIR}/charts"
LOGS_DIR = f"{TRAFFIC_DIR}/logs"
CONFIG_DIR = "/etc/edgebox/config"

# 设置中文字体支持
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'SimHei']
plt.rcParams['axes.unicode_minus'] = False

# 确保目录存在
Path(CHARTS_DIR).mkdir(parents=True, exist_ok=True)

def format_bytes(bytes_val):
    """格式化字节数"""
    try:
        bytes_val = float(bytes_val)
        if bytes_val >= 1024**3:
            return f"{bytes_val/1024**3:.1f}GB"
        elif bytes_val >= 1024**2:
            return f"{bytes_val/1024**2:.1f}MB"
        elif bytes_val >= 1024:
            return f"{bytes_val/1024:.1f}KB"
        else:
            return f"{bytes_val:.0f}B"
    except:
        return "0B"

def read_daily_data():
    """读取日流量数据"""
    daily_file = f"{LOGS_DIR}/daily.csv"
    data = []
    
    if not os.path.exists(daily_file):
        return data
    
    try:
        with open(daily_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    date = datetime.strptime(row['date'], '%Y-%m-%d')
                    total_rx = int(float(row.get('total_rx', 0) or 0))
                    total_tx = int(float(row.get('total_tx', 0) or 0))
                    tcp443_rx = int(float(row.get('tcp443_rx', 0) or 0))
                    tcp443_tx = int(float(row.get('tcp443_tx', 0) or 0))
                    udp443_rx = int(float(row.get('udp443_rx', 0) or 0))
                    udp443_tx = int(float(row.get('udp443_tx', 0) or 0))
                    
                    data.append({
                        'date': date,
                        'total': total_rx + total_tx,
                        'tcp443': tcp443_rx + tcp443_tx,
                        'udp443': udp443_rx + udp443_tx
                    })
                except (ValueError, KeyError):
                    continue
    except Exception:
        return data
    
    # 按日期聚合
    daily_sum = {}
    for item in data:
        date_key = item['date'].strftime('%Y-%m-%d')
        if date_key not in daily_sum:
            daily_sum[date_key] = {'date': item['date'], 'total': 0, 'tcp443': 0, 'udp443': 0}
        daily_sum[date_key]['total'] += item['total']
        daily_sum[date_key]['tcp443'] += item['tcp443']
        daily_sum[date_key]['udp443'] += item['udp443']
    
    return sorted(daily_sum.values(), key=lambda x: x['date'])

def read_monthly_data():
    """读取月流量数据"""
    monthly_file = f"{LOGS_DIR}/monthly.csv"
    data = []
    
    if not os.path.exists(monthly_file):
        return data
    
    try:
        with open(monthly_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    month = datetime.strptime(row['month'], '%Y-%m')
                    total_rx = int(float(row.get('total_rx', 0) or 0))
                    total_tx = int(float(row.get('total_tx', 0) or 0))
                    
                    data.append({
                        'month': month,
                        'total': total_rx + total_tx
                    })
                except (ValueError, KeyError):
                    continue
    except Exception:
        return data
    
    return sorted(data, key=lambda x: x['month'])

def generate_daily_chart():
    """生成日流量图表"""
    data = read_daily_data()
    if not data:
        return
    
    # 获取最近30天数据
    recent_data = data[-30:] if len(data) > 30 else data
    
    dates = [item['date'] for item in recent_data]
    totals = [item['total'] for item in recent_data]
    tcp443s = [item['tcp443'] for item in recent_data]
    udp443s = [item['udp443'] for item in recent_data]
    
    plt.figure(figsize=(12, 6))
    plt.plot(dates, totals, label='总流量', linewidth=2, marker='o')
    plt.plot(dates, tcp443s, label='TCP/443', linewidth=1.5, marker='s')
    plt.plot(dates, udp443s, label='UDP/443', linewidth=1.5, marker='^')
    
    plt.title('EdgeBox 日流量统计 (最近30天)')
    plt.xlabel('日期')
    plt.ylabel('流量')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # 设置日期格式
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
    plt.gca().xaxis.set_major_locator(mdates.DayLocator(interval=5))
    plt.xticks(rotation=45)
    
    # 设置Y轴格式
    ax = plt.gca()
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: format_bytes(x)))
    
    plt.tight_layout()
    plt.savefig(f"{CHARTS_DIR}/daily.png", dpi=150, bbox_inches='tight')
    plt.close()

def generate_monthly_chart():
    """生成月度流量图表"""
    data = read_monthly_data()
    if not data:
        return
    
    # 获取最近12个月数据
    recent_data = data[-12:] if len(data) > 12 else data
    
    months = [item['month'].strftime('%Y-%m') for item in recent_data]
    totals = [item['total'] for item in recent_data]
    
    plt.figure(figsize=(12, 6))
    bars = plt.bar(months, totals, alpha=0.7, color='steelblue')
    
    # 在柱子上显示数值
    for bar, total in zip(bars, totals):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                format_bytes(total), ha='center', va='bottom')
    
    plt.title('EdgeBox 月度流量统计 (最近12个月)')
    plt.xlabel('月份')
    plt.ylabel('流量')
    plt.grid(True, alpha=0.3, axis='y')
    
    # 设置Y轴格式
    ax = plt.gca()
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: format_bytes(x)))
    
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f"{CHARTS_DIR}/monthly.png", dpi=150, bbox_inches='tight')
    plt.close()

def get_subscription_content():
    """获取订阅内容"""
    try:
        with open(f"{CONFIG_DIR}/subscription.txt", 'r') as f:
            return f.read().strip()
    except:
        return "订阅文件未找到"

def generate_index_page():
    """生成首页HTML"""
    subscription = get_subscription_content()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 读取服务器信息
    try:
        with open(f"{CONFIG_DIR}/server.json", 'r') as f:
            server_info = json.load(f)
        server_ip = server_info.get('server_ip', 'Unknown')
        version = server_info.get('version', '3.0.0')
    except:
        server_ip = 'Unknown'
        version = '3.0.0'
    
    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EdgeBox 控制面板</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
               line-height: 1.6; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; 
                     border-radius: 10px; box-shadow: 0 2px 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                  color: white; padding: 30px; border-radius: 10px 10px 0 0; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #333; border-bottom: 2px solid #667eea; 
                      padding-bottom: 10px; }}
        .subscription-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; 
                            border-left: 4px solid #667eea; margin: 15px 0; }}
        .subscription-content {{ font-family: monospace; font-size: 12px; 
                               background: white; padding: 15px; border-radius: 5px; 
                               border: 1px solid #dee2e6; word-break: break-all; 
                               max-height: 200px; overflow-y: auto; }}
        .charts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); 
                  gap: 20px; margin: 20px 0; }}
        .chart {{ text-align: center; background: #f8f9fa; padding: 15px; 
                 border-radius: 8px; }}
        .chart img {{ max-width: 100%; height: auto; border-radius: 5px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                     gap: 15px; }}
        .info-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; }}
        .footer {{ text-align: center; padding: 20px; color: #666; 
                  border-top: 1px solid #dee2e6; }}
        .btn {{ display: inline-block; padding: 8px 16px; background: #667eea; 
               color: white; text-decoration: none; border-radius: 5px; 
               margin: 5px; }}
        .btn:hover {{ background: #5a6fd8; }}
        .copy-btn {{ background: #28a745; cursor: pointer; }}
        .copy-btn:hover {{ background: #218838; }}
        @media (max-width: 768px) {{ 
            .charts {{ grid-template-columns: 1fr; }}
            .info-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 EdgeBox 控制面板</h1>
            <p>企业级多协议节点部署方案 v{version}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 服务器信息</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <strong>服务器IP:</strong><br>{server_ip}
                    </div>
                    <div class="info-card">
                        <strong>版本:</strong><br>EdgeBox v{version}
                    </div>
                    <div class="info-card">
                        <strong>更新时间:</strong><br>{current_time}
                    </div>
                    <div class="info-card">
                        <strong>协议支持:</strong><br>Reality, gRPC, WS, Hysteria2, TUIC
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>📱 订阅链接</h2>
                <div class="subscription-box">
                    <p><strong>HTTP订阅地址:</strong></p>
                    <div class="subscription-content">http://{server_ip}/sub</div>
                    <a href="/sub" class="btn" target="_blank">📥 获取订阅</a>
                    <span class="btn copy-btn" onclick="copyToClipboard('http://{server_ip}/sub')">📋 复制链接</span>
                </div>
                
                <div class="subscription-box">
                    <p><strong>节点链接详情:</strong></p>
                    <div class="subscription-content">{subscription.replace(chr(10), '<br>')}</div>
                    <span class="btn copy-btn" onclick="copySubscription()">📋 复制所有节点</span>
                </div>
            </div>
            
            <div class="section">
                <h2>📈 流量统计</h2>
                <div class="charts">"""
    
    # 添加图表
    for chart_name, chart_title in [('daily', '日流量趋势'), ('monthly', '月度流量对比')]:
        chart_path = f"{CHARTS_DIR}/{chart_name}.png"
        if os.path.exists(chart_path):
            html_content += f"""
                    <div class="chart">
                        <h3>{chart_title}</h3>
                        <img src="/traffic/charts/{chart_name}.png" alt="{chart_title}">
                    </div>"""
    
    html_content += f"""
                </div>
            </div>
            
            <div class="section">
                <h2>⚡ 快速操作</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <strong>管理命令:</strong><br>
                        <code>edgeboxctl status</code><br>
                        <code>edgeboxctl restart</code><br>
                        <code>edgeboxctl logs xray</code>
                    </div>
                    <div class="info-card">
                        <strong>证书管理:</strong><br>
                        <code>edgeboxctl switch-to-domain domain.com</code><br>
                        <code>edgeboxctl switch-to-ip</code>
                    </div>
                    <div class="info-card">
                        <strong>分流配置:</strong><br>
                        <code>edgeboxctl shunt vps</code><br>
                        <code>edgeboxctl shunt direct-resi IP:PORT</code>
                    </div>
                    <div class="info-card">
                        <strong>流量统计:</strong><br>
                        <code>edgeboxctl traffic show</code><br>
                        <code>edgeboxctl traffic reset</code>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>EdgeBox 企业级多协议节点部署方案 | 最后更新: {current_time}</p>
        </div>
    </div>
    
    <script>
        function copyToClipboard(text) {{
            navigator.clipboard.writeText(text).then(function() {{
                alert('已复制到剪贴板!');
            }}, function(err) {{
                console.error('复制失败: ', err);
                alert('复制失败，请手动复制');
            }});
        }}
        
        function copySubscription() {{
            var content = `{subscription}`;
            copyToClipboard(content);
        }}
    </script>
</body>
</html>"""
    
    # 写入HTML文件
    with open('/var/www/html/index.html', 'w', encoding='utf-8') as f:
        f.write(html_content)

def main():
    """主函数"""
    try:
        generate_daily_chart()
        generate_monthly_chart() 
        generate_index_page()
        print("图表和首页生成成功")
    except Exception as e:
        print(f"生成失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
CHART_SCRIPT

    chmod +x "${SCRIPTS_DIR}/generate-charts.py"
    
    # 创建流量预警脚本
    cat > "${SCRIPTS_DIR}/traffic-alert.sh" <<'ALERT_SCRIPT'
#!/bin/bash
# EdgeBox 流量预警脚本
TRAFFIC_DIR="/etc/edgebox/traffic"
ALERT_CONFIG="${TRAFFIC_DIR}/alert.conf"
ALERT_STATE="${TRAFFIC_DIR}/alert.state"
LOG_FILE="/var/log/edgebox-alert.log"

# 创建默认配置文件
if [[ ! -f "$ALERT_CONFIG" ]]; then
    mkdir -p "$TRAFFIC_DIR"
    cat > "$ALERT_CONFIG" <<EOF
# EdgeBox 流量预警配置
ALERT_MONTHLY_GIB=100
ALERT_EMAIL=admin@example.com
ALERT_WEBHOOK=
EOF
fi

# 读取配置
source "$ALERT_CONFIG"

# 创建状态文件
[[ ! -f "$ALERT_STATE" ]] && echo "0" > "$ALERT_STATE"

# 获取当前月份和流量
CURRENT_MONTH=$(date +%Y-%m)
MONTHLY_CSV="${TRAFFIC_DIR}/logs/monthly.csv"

if [[ ! -f "$MONTHLY_CSV" ]]; then
    echo "[$(date)] 月度流量文件不存在" >> "$LOG_FILE"
    exit 0
fi

# 获取当月总流量（GB）
CURRENT_USAGE=$(awk -F',' -v month="$CURRENT_MONTH" '$1 == month {print ($2+$3)/1024/1024/1024}' "$MONTHLY_CSV" | tail -1)
CURRENT_USAGE=${CURRENT_USAGE:-0}

# 计算使用百分比
if (( $(echo "$ALERT_MONTHLY_GIB > 0" | bc -l) )); then
    USAGE_PERCENT=$(echo "scale=1; $CURRENT_USAGE * 100 / $ALERT_MONTHLY_GIB" | bc -l)
else
    exit 0
fi

# 读取已发送的警告级别
SENT_ALERTS=$(cat "$ALERT_STATE")

# 检查需要发送的警告
send_alert() {
    local threshold=$1
    local message="EdgeBox 流量警告: 本月流量使用已达 ${USAGE_PERCENT}% (${CURRENT_USAGE}GB/${ALERT_MONTHLY_GIB}GB)"
    
    # 发送邮件
    if [[ -n "$ALERT_EMAIL" ]] && command -v mail >/dev/null 2>&1; then
        echo "$message" | mail -s "EdgeBox 流量警告 ${threshold}%" "$ALERT_EMAIL"
    fi
    
    # 发送Webhook（如果配置了）
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        curl -s -X POST "$ALERT_WEBHOOK" \
             -H "Content-Type: application/json" \
             -d "{\"text\":\"$message\"}" >/dev/null 2>&1
    fi
    
    echo "[$(date)] 已发送 ${threshold}% 警告" >> "$LOG_FILE"
}

# 检查各个阈值
for threshold in 30 60 90; do
    if (( $(echo "$USAGE_PERCENT >= $threshold" | bc -l) )) && (( $SENT_ALERTS < $threshold )); then
        send_alert $threshold
        echo "$threshold" > "$ALERT_STATE"
        break
    fi
done

# 如果进入新月份，重置状态
LAST_MONTH=$(date -d "last month" +%Y-%m)
if [[ "$CURRENT_MONTH" != "$LAST_MONTH" ]]; then
    echo "0" > "$ALERT_STATE"
fi
ALERT_SCRIPT

    chmod +x "${SCRIPTS_DIR}/traffic-alert.sh"
    
    # 创建默认的分流配置
    mkdir -p "${CONFIG_DIR}/shunt"
    echo "googlevideo.com
ytimg.com
ggpht.com
youtube.com
youtu.be
googleapis.com
gstatic.com" > "${CONFIG_DIR}/shunt/whitelist.txt"
    
    echo '{"mode":"vps","proxy_info":"","last_check":"","health":"unknown"}' > "${CONFIG_DIR}/shunt/state.json"
    
    # 创建默认预警配置
    mkdir -p "${TRAFFIC_DIR}"
    cat > "${TRAFFIC_DIR}/alert.conf" <<EOF
# EdgeBox 流量预警配置
ALERT_MONTHLY_GIB=100
ALERT_EMAIL=admin@example.com
ALERT_WEBHOOK=
EOF
    
    log_success "流量监控系统设置完成"
}

# 设置定时任务
setup_cron_jobs() {
    log_info "设置定时任务..."
    
    # 检查现有的cron任务
    if crontab -l 2>/dev/null | grep -q "edgebox"; then
        log_info "EdgeBox定时任务已存在，跳过设置"
        return
    fi
    
    # 创建新的cron任务
    (crontab -l 2>/dev/null; cat <<EOF
# EdgeBox 定时任务
# 每小时采集流量数据
0 * * * * ${SCRIPTS_DIR}/traffic-collector.sh >/dev/null 2>&1

# 每日生成图表和首页
10 0 * * * ${SCRIPTS_DIR}/generate-charts.py >/dev/null 2>&1

# 每小时检查流量预警
7 * * * * ${SCRIPTS_DIR}/traffic-alert.sh >/dev/null 2>&1

# 每日自动备份
30 3 * * * /usr/local/bin/edgeboxctl backup create >/dev/null 2>&1
EOF
    ) | crontab -
    
    log_success "定时任务设置完成"
}

# 创建完整的edgeboxctl管理工具
create_enhanced_edgeboxctl() {
    log_info "创建增强版edgeboxctl管理工具..."
    
    cat > /usr/local/bin/edgeboxctl << 'EDGEBOXCTL_SCRIPT'
#!/bin/bash
# EdgeBox 增强版控制脚本 - 模块1+2+3完整版
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

# 颜色定义
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; 
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# 日志函数
log_info(){ echo -e "${GREEN}[INFO]${NC} $1" | tee -a ${LOG_FILE} 2>/dev/null || echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn(){ echo -e "${YELLOW}[WARN]${NC} $1" | tee -a ${LOG_FILE} 2>/dev/null || echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error(){ echo -e "${RED}[ERROR]${NC} $1" | tee -a ${LOG_FILE} 2>/dev/null || echo -e "${RED}[ERROR]${NC} $1"; }
log_success(){ echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a ${LOG_FILE} 2>/dev/null || echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# 工具函数
get_current_cert_mode(){ [[ -f ${CONFIG_DIR}/cert_mode ]] && cat ${CONFIG_DIR}/cert_mode || echo "self-signed"; }
need(){ command -v "$1" >/dev/null 2>&1; }

get_server_info() {
  if [[ ! -f ${CONFIG_DIR}/server.json ]]; then log_error "配置文件不存在：${CONFIG_DIR}/server.json"; return 1; fi
  SERVER_IP=$(jq -r '.server_ip' ${CONFIG_DIR}/server.json 2>/dev/null)
  UUID_VLESS=$(jq -r '.uuid.vless' ${CONFIG_DIR}/server.json 2>/dev/null)
  UUID_TUIC=$(jq -r '.uuid.tuic' ${CONFIG_DIR}/server.json 2>/dev/null)
  PASSWORD_HYSTERIA2=$(jq -r '.password.hysteria2' ${CONFIG_DIR}/server.json 2>/dev/null)
  PASSWORD_TUIC=$(jq -r '.password.tuic' ${CONFIG_DIR}/server.json 2>/dev/null)
  REALITY_PUBLIC_KEY=$(jq -r '.reality.public_key' ${CONFIG_DIR}/server.json 2>/dev/null)
  REALITY_SHORT_ID=$(jq -r '.reality.short_id' ${CONFIG_DIR}/server.json 2>/dev/null)
}

#############################################
# 基础功能
#############################################

show_sub() {
  if [[ ! -f ${CONFIG_DIR}/server.json ]]; then echo -e "${RED}配置文件不存在${NC}"; exit 1; fi
  local cert_mode=$(get_current_cert_mode)
  echo -e "${CYAN}EdgeBox 订阅链接（证书模式: ${cert_mode}）：${NC}\n"
  [[ -f ${CONFIG_DIR}/subscription.txt ]] && { echo -e "${YELLOW}节点链接：${NC}"; cat ${CONFIG_DIR}/subscription.txt; echo ""; }
  [[ -f ${CONFIG_DIR}/subscription.base64 ]] && { echo -e "${YELLOW}Base64订阅：${NC}"; cat ${CONFIG_DIR}/subscription.base64; echo ""; }
  local server_ip=$(jq -r '.server_ip' ${CONFIG_DIR}/server.json)
  echo -e "${CYAN}HTTP订阅地址：${NC}"; echo "http://${server_ip}/sub"; echo ""
  echo -e "${CYAN}控制面板：${NC}"; echo "http://${server_ip}/"; echo ""
  echo -e "${CYAN}说明：${NC}"
  echo "- 使用 *.edgebox.internal 作为内部标识避免证书冲突"
  echo "- SNI定向 + ALPN兜底，解决 gRPC/WS 摇摆"
  echo "- 当前证书模式: ${cert_mode}"
  echo "- 支持协议: Reality, gRPC, WS, Hysteria2, TUIC"
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
  local domain=$1; log_info "为域名 $domain 申请Let's Encrypt证书"
  mkdir -p ${CERT_DIR}; systemctl stop nginx >/dev/null 2>&1
  if certbot certonly --standalone --non-interactive --agree-tos --email "admin@${domain}" --domains "$domain" --preferred-challenges http --http-01-port 80; then
    log_success "证书申请成功"
  else
    log_error "证书申请失败"; systemctl start nginx >/dev/null 2>&1; return 1
  fi
  systemctl start nginx >/dev/null 2>&1
  [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]] || { log_error "证书文件不存在"; return 1; }
  log_success "证书文件验证通过"
}

post_switch_report(){
  echo -e "\n${CYAN}=== 切换后自动验收报告 ===${NC}"
  echo -n "1) Nginx 配置测试: "; nginx -t >/dev/null 2>&1 && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAIL${NC}"
  echo -n "2) 服务可用性: "
  local bad=0
  for s in nginx xray sing-box; do systemctl is-active --quiet "$s" || bad=1; done
  [[ $bad -eq 0 ]] && echo -e "${GREEN}nginx/xray/sing-box 全部正常${NC}" || echo -e "${RED}存在异常，建议 edgeboxctl logs <svc>${NC}"
  echo -n "3) 订阅文件: "; local ip=$(jq -r .server_ip ${CONFIG_DIR}/server.json); curl -fsS "http://${ip}/sub" >/dev/null && echo -e "${GREEN}可访问${NC}" || echo -e "${RED}不可访问${NC}"
  echo -n "4) 证书软链: "; [[ -L ${CERT_DIR}/current.pem && -L ${CERT_DIR}/current.key ]] && echo -e "${GREEN}存在${NC}" || echo -e "${RED}缺失${NC}"
  echo -n "5) 证书权限: "; stat -L -c '%a' ${CERT_DIR}/current.key 2>/dev/null | grep -qE '600|640' && echo -e "${GREEN}已收紧${NC}" || echo -e "${YELLOW}建议运行 edgeboxctl fix-permissions${NC}"
  echo -e "${CYAN}====================${NC}\n"
}

# 生成订阅（域名 / IP模式）
regen_sub_domain(){
  local domain=$1; get_server_info
  local HY2_PW_ENC TUIC_PW_ENC
  HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
  TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC" | jq -rR @uri)
  local sub="vless://${UUID_VLESS}@${domain}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY
vless://${UUID_VLESS}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=h2&type=grpc&serviceName=grpc&fp=chrome#EdgeBox-gRPC
vless://${UUID_VLESS}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome#EdgeBox-WS
hysteria2://${HY2_PW_ENC}@${domain}:443?sni=${domain}&alpn=h3#EdgeBox-HYSTERIA2
tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${domain}:2053?congestion_control=bbr&alpn=h3&sni=${domain}#EdgeBox-TUIC"
  echo -e "${sub}" > "${CONFIG_DIR}/subscription.txt"
  echo -e "${sub}" | base64 -w0 > "${CONFIG_DIR}/subscription.base64"
  mkdir -p /var/www/html; echo -e "${sub}" | base64 -w0 > /var/www/html/sub
  log_success "域名模式订阅已更新"
}

regen_sub_ip(){
  get_server_info
  local HY2_PW_ENC TUIC_PW_ENC
  HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
  TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC" | jq -rR @uri)
  local sub="vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY
vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=grpc.edgebox.internal&alpn=h2&type=grpc&serviceName=grpc&fp=chrome&allowInsecure=1#EdgeBox-gRPC
vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=ws.edgebox.internal&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome&allowInsecure=1#EdgeBox-WS
hysteria2://${HY2_PW_ENC}@${SERVER_IP}:443?sni=${SERVER_IP}&alpn=h3&insecure=1#EdgeBox-HYSTERIA2
tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${SERVER_IP}:2053?congestion_control=bbr&alpn=h3&sni=${SERVER_IP}&allowInsecure=1#EdgeBox-TUIC"
  echo -e "${sub}" > "${CONFIG_DIR}/subscription.txt"
  echo -e "${sub}" | base64 -w0 > "${CONFIG_DIR}/subscription.base64"
  mkdir -p /var/www/html; echo -e "${sub}" | base64 -w0 > /var/www/html/sub
  log_success "IP模式订阅已更新"
}

switch_to_domain(){
  local domain="$1"; [[ -z "$domain" ]] && { echo "用法: edgeboxctl switch-to-domain <domain>"; return 1; }
  get_server_info || return 1
  check_domain_resolution "$domain" || return 1
  request_letsencrypt_cert "$domain" || return 1
  ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem" ${CERT_DIR}/current.key
  ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" ${CERT_DIR}/current.pem
  echo "letsencrypt:${domain}" > ${CONFIG_DIR}/cert_mode
  regen_sub_domain "$domain"
  systemctl restart xray sing-box >/dev/null 2>&1
  setup_auto_renewal "$domain"
  log_success "已切换到域名模式：$domain"
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

setup_auto_renewal(){
  local domain=$1
  cat > /etc/edgebox/scripts/cert-renewal.sh <<'RSH'
#!/bin/bash
LOG_FILE="/var/log/edgebox-renewal.log"
echo "[$(date)] 开始证书续期检查" >> $LOG_FILE
systemctl stop nginx >> $LOG_FILE 2>&1
if certbot renew --quiet >> $LOG_FILE 2>&1; then
  echo "[$(date)] 证书续期成功" >> $LOG_FILE
  systemctl start nginx >> $LOG_FILE 2>&1
  systemctl restart xray sing-box >> $LOG_FILE 2>&1
  echo "[$(date)] 服务重启完成" >> $LOG_FILE
else
  echo "[$(date)] 证书续期失败" >> $LOG_FILE
  systemctl start nginx >> $LOG_FILE 2>&1
fi
RSH
  chmod +x /etc/edgebox/scripts/cert-renewal.sh
  crontab -l 2>/dev/null | grep -q cert-renewal.sh || (crontab -l 2>/dev/null; echo "0 3 * * * /etc/edgebox/scripts/cert-renewal.sh") | crontab -
  log_success "自动续期任务已设置（每日 03:00）"
}

#############################################
# 出站分流系统
#############################################

setup_shunt_directories() {
    mkdir -p "${CONFIG_DIR}/shunt" 2>/dev/null || true
    if [[ ! -f "${CONFIG_DIR}/shunt/whitelist.txt" ]]; then
        echo "$WHITELIST_DOMAINS" | tr ',' '\n' > "${CONFIG_DIR}/shunt/whitelist.txt"
    fi
    if [[ ! -f "$SHUNT_CONFIG" ]]; then
        echo '{"mode":"vps","proxy_info":"","last_check":"","health":"unknown"}' > "$SHUNT_CONFIG"
    fi
}

check_proxy_health() {
    local proxy_info="$1"
    [[ -z "$proxy_info" ]] && return 1
    local host port; IFS=':' read -r host port _ <<< "$proxy_info"
    timeout 8 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
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
    setup_shunt_directories
    update_shunt_state "vps" "" "healthy"
    systemctl restart sing-box && log_success "VPS全量出站模式配置成功" || { log_error "配置失败，已保留备份"; return 1; }
}

setup_outbound_resi() {
    local proxy_addr="$1"
    [[ -z "$proxy_addr" ]] && { echo "用法: edgeboxctl shunt resi IP:PORT[:USER:PASS]"; return 1; }
    log_info "配置住宅IP全量出站模式: $proxy_addr"
    if ! check_proxy_health "$proxy_addr"; then log_error "代理 $proxy_addr 连接失败"; return 1; fi
    get_server_info || return 1
    local host port user pass; IFS=':' read -r host port user pass <<< "$proxy_addr"
    cp ${CONFIG_DIR}/sing-box.json ${CONFIG_DIR}/sing-box.json.bak 2>/dev/null || true
    local auth_json=""; [[ -n "$user" && -n "$pass" ]] && auth_json=",\"username\":\"$user\",\"password\":\"$pass\""
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
 "outbounds":[
  {"type":"http","tag":"resi-proxy","server":"${host}","server_port":${port}${auth_json}},
  {"type":"direct","tag":"direct"}],
 "route":{"rules":[
  {"protocol":"dns","outbound":"direct"},
  {"port":53,"outbound":"direct"},
  {"outbound":"resi-proxy"}]}}
EOF
    echo "$proxy_addr" > "${CONFIG_DIR}/shunt/resi.conf"
    setup_shunt_directories
    update_shunt_state "resi" "$proxy_addr" "healthy"
    systemctl restart sing-box && log_success "住宅IP全量出站模式配置成功" || { log_error "配置失败"; return 1; }
}

setup_outbound_direct_resi() {
    local proxy_addr="$1"
    [[ -z "$proxy_addr" ]] && { echo "用法: edgeboxctl shunt direct-resi IP:PORT[:USER:PASS]"; return 1; }
    log_info "配置智能分流模式: $proxy_addr"
    if ! check_proxy_health "$proxy_addr"; then log_error "代理 $proxy_addr 连接失败"; return 1; fi
    get_server_info || return 1
    setup_shunt_directories
    local host port user pass; IFS=':' read -r host port user pass <<< "$proxy_addr"
    cp ${CONFIG_DIR}/sing-box.json ${CONFIG_DIR}/sing-box.json.bak 2>/dev/null || true
    local auth_json=""; [[ -n "$user" && -n "$pass" ]] && auth_json=",\"username\":\"$user\",\"password\":\"$pass\""
    local whitelist_json
    if [[ -f "${CONFIG_DIR}/shunt/whitelist.txt" ]]; then
        whitelist_json=$(cat "${CONFIG_DIR}/shunt/whitelist.txt" | jq -R -s 'split("\n") | map(select(length > 0))' | jq -c .)
    else
        whitelist_json='["googlevideo.com","ytimg.com","ggpht.com","youtube.com","youtu.be"]'
    fi
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
 "outbounds":[
  {"type":"direct","tag":"direct"},
  {"type":"http","tag":"resi-proxy","server":"${host}","server_port":${port}${auth_json}}],
 "route":{"rules":[
  {"protocol":"dns","outbound":"direct"},
  {"port":53,"outbound":"direct"},
  {"domain_suffix":${whitelist_json},"outbound":"direct"},
  {"outbound":"resi-proxy"}]}}
EOF
    echo "$proxy_addr" > "${CONFIG_DIR}/shunt/resi.conf"
    update_shunt_state "direct_resi" "$proxy_addr" "healthy"
    systemctl restart sing-box && log_success "智能分流模式配置成功" || { log_error "配置失败"; return 1; }
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
    local new_hy2_pass=$(openssl rand -base64 16)
    local new_tuic_pass=$(openssl rand -base64 16)
    
    # 更新server.json
    jq --arg vless "$new_vless_uuid" \
       --arg tuic "$new_tuic_uuid" \
       --arg hy2_pass "$new_hy2_pass" \
       --arg tuic_pass "$new_tuic_pass" \
       '.uuid.vless = $vless | .uuid.tuic = $tuic | .password.hysteria2 = $hy2_pass | .password.tuic = $tuic_pass' \
       ${CONFIG_DIR}/server.json > ${CONFIG_DIR}/server.json.tmp && \
       mv ${CONFIG_DIR}/server.json.tmp ${CONFIG_DIR}/server.json
    
    # 更新配置文件
    sed -i "s/\"id\": \".*\"/\"id\": \"$new_vless_uuid\"/g" ${CONFIG_DIR}/xray.json
    sed -i "s/\"uuid\": \".*\"/\"uuid\": \"$new_tuic_uuid\"/g" ${CONFIG_DIR}/sing-box.json
    sed -i "s/\"password\": \".*\"/\"password\": \"$new_hy2_pass\"/g" ${CONFIG_DIR}/sing-box.json
    
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
        echo -e "  VLESS UUID: $(jq -r '.uuid.vless' ${CONFIG_DIR}/server.json)"
        echo -e "  TUIC UUID: $(jq -r '.uuid.tuic' ${CONFIG_DIR}/server.json)"  
        echo -e "  Hysteria2 密码: $(jq -r '.password.hysteria2' ${CONFIG_DIR}/server.json)"
        echo -e "  TUIC 密码: $(jq -r '.password.tuic' ${CONFIG_DIR}/server.json)"
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
  fix-permissions) fix_permissions ;;
  cert-status) cert_status ;;
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
  status          查看服务状态
  restart         重启所有服务  
  sub             查看订阅链接
  logs <svc>      查看服务日志 [nginx|xray|sing-box]
  test            测试连接
  debug-ports     调试端口状态

${YELLOW}证书管理:${NC}
  cert-status                   查看证书状态
  fix-permissions               修复证书权限
  switch-to-domain <domain>     切换到域名模式
  switch-to-ip                  切换到IP模式

${YELLOW}配置管理:${NC}
  config show                   显示当前配置
  config regenerate-uuid        重新生成UUID

${YELLOW}出站分流:${NC}
  shunt vps                     VPS全量出站
  shunt resi IP:PORT[:USER:PASS] 住宅IP全量出站
  shunt direct-resi IP:PORT[:USER:PASS] 智能分流模式
  shunt status                  查看分流状态
  shunt whitelist [add|remove|list|reset] [domain] 管理白名单

${YELLOW}流量统计:${NC}
  traffic show                  查看流量统计
  traffic reset                 重置流量计数

${YELLOW}备份恢复:${NC}
  backup create                 创建备份
  backup list                   列出备份
  backup restore <file>         恢复备份

${YELLOW}系统:${NC}
  update                        更新EdgeBox
  help                          显示此帮助

${CYAN}EdgeBox 企业级多协议节点部署方案${NC}
控制面板: http://$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null || echo "YOUR_IP")/
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

# 生成初始化脚本（用于开机自启动流量监控）
create_init_script() {
    log_info "创建初始化脚本..."
    
    cat > /etc/edgebox/scripts/edgebox-init.sh << 'INIT_SCRIPT'
#!/bin/bash
# EdgeBox 初始化脚本 - 确保所有功能正常启动
LOG_FILE="/var/log/edgebox-init.log"

echo "[$(date)] EdgeBox 初始化开始" >> $LOG_FILE

# 等待网络就绪
sleep 10

# 确保iptables规则存在（用于流量统计）
iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 443 -j ACCEPT  
iptables -C INPUT -p udp --dport 2053 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 2053 -j ACCEPT
iptables -C OUTPUT -p tcp --sport 443 -j ACCEPT 2>/dev/null || iptables -I OUTPUT -p tcp --sport 443 -j ACCEPT
iptables -C OUTPUT -p udp --sport 443 -j ACCEPT 2>/dev/null || iptables -I OUTPUT -p udp --sport 443 -j ACCEPT
iptables -C OUTPUT -p udp --sport 2053 -j ACCEPT 2>/dev/null || iptables -I OUTPUT -p udp --sport 2053 -j ACCEPT

# 启动vnstat（如果需要）
systemctl is-active --quiet vnstat || systemctl start vnstat

# 生成初始图表（如果Python可用）
if command -v python3 >/dev/null 2>&1 && [[ -f /etc/edgebox/scripts/generate-charts.py ]]; then
    /etc/edgebox/scripts/generate-charts.py >> $LOG_FILE 2>&1
fi

echo "[$(date)] EdgeBox 初始化完成" >> $LOG_FILE
INIT_SCRIPT

    chmod +x /etc/edgebox/scripts/edgebox-init.sh
    
    # 创建systemd服务
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

# 创建卸载脚本
create_uninstall_script() {
    log_info "创建卸载脚本..."
    
    cat > /usr/local/bin/edgebox-uninstall << 'UNINSTALL_SCRIPT'
#!/bin/bash
# EdgeBox 完整卸载脚本
# Version: 3.0.0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}EdgeBox 卸载脚本${NC}"
echo -e "${YELLOW}这将完全移除 EdgeBox 及其所有组件${NC}"
echo ""

read -p "确认卸载？这个操作无法撤销 [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 0
fi

echo -e "${GREEN}开始卸载 EdgeBox...${NC}"

# 停止并禁用服务
echo "停止服务..."
for service in nginx xray sing-box edgebox-init; do
    systemctl stop $service 2>/dev/null || true
    systemctl disable $service 2>/dev/null || true
done

# 移除systemd服务文件
echo "移除服务文件..."
rm -f /etc/systemd/system/xray.service
rm -f /etc/systemd/system/sing-box.service  
rm -f /etc/systemd/system/edgebox-init.service
systemctl daemon-reload

# 移除程序文件
echo "移除程序文件..."
rm -f /usr/local/bin/xray
rm -f /usr/local/bin/sing-box
rm -f /usr/local/bin/edgeboxctl
rm -f /usr/local/bin/edgebox-uninstall

# 清理配置目录
echo "清理配置文件..."
rm -rf /etc/edgebox
rm -rf /var/log/edgebox*
rm -rf /var/log/xray

# 恢复nginx配置
echo "恢复Nginx配置..."
if [[ -f /etc/nginx/nginx.conf.bak ]]; then
    mv /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
    systemctl restart nginx 2>/dev/null || true
else
    # 重置为默认配置
    apt-get install --reinstall -y nginx >/dev/null 2>&1 || true
fi

# 清理Web文件
rm -f /var/www/html/sub
rm -f /var/www/html/index.html

# 清理定时任务
echo "清理定时任务..."
crontab -l 2>/dev/null | grep -v "edgebox" | crontab - 2>/dev/null || true

# 清理防火墙规则
echo "清理防火墙规则..."
if command -v ufw >/dev/null 2>&1; then
    ufw delete allow 443/tcp 2>/dev/null || true
    ufw delete allow 443/udp 2>/dev/null || true
    ufw delete allow 2053/udp 2>/dev/null || true
fi

# 清理iptables规则（流量统计相关）
iptables -D INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p udp --dport 2053 -j ACCEPT 2>/dev/null || true
iptables -D OUTPUT -p tcp --sport 443 -j ACCEPT 2>/dev/null || true
iptables -D OUTPUT -p udp --sport 443 -j ACCEPT 2>/dev/null || true
iptables -D OUTPUT -p udp --sport 2053 -j ACCEPT 2>/dev/null || true

# 清理备份文件
echo "清理备份文件..."
rm -rf /root/edgebox-backup

# 清理Let's Encrypt证书（可选）
read -p "是否删除 Let's Encrypt 证书？[y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /etc/letsencrypt
fi

# 清理邮件配置
rm -f /etc/msmtprc

# 恢复系统配置
echo "恢复系统配置..."
if [[ -f /etc/sysctl.conf.bak ]]; then
    mv /etc/sysctl.conf.bak /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
fi

echo -e "${GREEN}EdgeBox 卸载完成！${NC}"
echo "建议重启系统以确保所有更改生效"
echo ""
echo "感谢使用 EdgeBox！"
UNINSTALL_SCRIPT

    chmod +x /usr/local/bin/edgebox-uninstall
    log_success "卸载脚本创建完成 (/usr/local/bin/edgebox-uninstall)"
}

#############################################
# 完整安装流程
#############################################

# 显示安装信息
show_installation_info() {
    clear
    print_separator
    echo -e "${GREEN}🎉 EdgeBox v3.0.0 安装完成！${NC}"
    print_separator
    
    echo -e "${CYAN}服务器信息：${NC}"
    echo -e "  IP地址: ${GREEN}${SERVER_IP}${NC}"
    echo -e "  模式: ${YELLOW}IP模式（自签名证书）${NC}"
    echo -e "  版本: ${YELLOW}EdgeBox v3.0.0 企业级完整版${NC}"
    
    echo -e "\n${CYAN}协议信息：${NC}"
    echo -e "  ${PURPLE}[1] VLESS-Reality${NC}  端口: 443  UUID: ${UUID_VLESS}"
    echo -e "  ${PURPLE}[2] VLESS-gRPC${NC}     端口: 443  UUID: ${UUID_VLESS}"  
    echo -e "  ${PURPLE}[3] VLESS-WS${NC}       端口: 443  UUID: ${UUID_VLESS}"
    echo -e "  ${PURPLE}[4] Hysteria2${NC}      端口: 443  密码: ${PASSWORD_HYSTERIA2}"
    echo -e "  ${PURPLE}[5] TUIC${NC}           端口: 2053 UUID: ${UUID_TUIC}"
       
    echo -e "\n${CYAN}访问地址：${NC}"
    echo -e "  🌐 控制面板: ${YELLOW}http://${SERVER_IP}/${NC}"
    echo -e "  📱 订阅链接: ${YELLOW}http://${SERVER_IP}/sub${NC}"
    echo -e "  📊 流量统计: 控制面板内置图表"
    
    echo -e "\n${YELLOW}✨ v3.0.0 新增功能：${NC}"
    echo -e "  🎯 智能出站分流：支持VPS直出/住宅IP/智能分流三种模式"
    echo -e "  📈 流量统计图表：自动生成日/月流量趋势图，集成控制面板"
    echo -e "  📧 流量预警系统：支持邮件/Webhook通知，可配置阈值"
    echo -e "  💾 自动备份恢复：每日自动备份，支持一键恢复"
    echo -e "  🎨 Web控制面板：订阅+统计+操作指南一体化界面"
    
    echo -e "\n${CYAN}管理命令：${NC}"
    echo -e "  ${YELLOW}edgeboxctl status${NC}                  # 查看服务状态"
    echo -e "  ${YELLOW}edgeboxctl sub${NC}                     # 查看订阅链接"
    echo -e "  ${YELLOW}edgeboxctl switch-to-domain <域名>${NC} # 切换到域名模式"
    echo -e "  ${YELLOW}edgeboxctl shunt direct-resi IP:PORT${NC} # 智能分流"
    echo -e "  ${YELLOW}edgeboxctl traffic show${NC}            # 查看流量统计"
    echo -e "  ${YELLOW}edgeboxctl backup create${NC}           # 手动备份"
    echo -e "  ${YELLOW}edgeboxctl help${NC}                    # 查看完整帮助"
    
    echo -e "\n${CYAN}高级运维：${NC}"
    echo -e "  🔄 出站分流: 支持住宅IP代理，降低VPS出站成本"
    echo -e "  📊 流量监控: 实时图表展示，支持端口维度统计"
    echo -e "  ⚠️  预警通知: 流量阈值告警，避免超额费用"
    echo -e "  🛡️  自动备份: 配置自动备份，故障快速恢复"
    
    echo -e "\n${YELLOW}⚠️  重要提醒：${NC}"
    echo -e "  1. 当前为IP模式，VLESS协议需在客户端开启'跳过证书验证'"
    echo -e "  2. 使用 switch-to-domain 可获得受信任证书"
    echo -e "  3. 流量预警配置: ${TRAFFIC_DIR}/alert.conf"
    echo -e "  4. 完整卸载命令: edgebox-uninstall"

    print_separator
    echo -e "${GREEN}🚀 EdgeBox v3.0.0 企业级多协议节点部署完成！${NC}"
    echo -e "${CYAN}控制面板: http://${SERVER_IP}/${NC}"
    print_separator
}

# 清理函数
cleanup() {
    if [ "$?" -ne 0 ]; then
        log_error "安装过程中出现错误，请检查日志: ${LOG_FILE}"
        echo -e "${YELLOW}如需重新安装，请先运行: edgebox-uninstall${NC}"
    fi
    rm -f /tmp/Xray-linux-64.zip 2>/dev/null || true
    rm -f /tmp/sing-box-*.tar.gz 2>/dev/null || true
}

# 主安装流程
main() {
    clear
    print_separator
    echo -e "${GREEN}EdgeBox 企业级安装脚本 v3.0.0${NC}"
    echo -e "${CYAN}模块1+2+3完整版：SNI定向 + 智能分流 + 流量统计 + 备份恢复${NC}"
    print_separator
    
    # 创建日志文件
    mkdir -p $(dirname ${LOG_FILE})
    touch ${LOG_FILE}
    
    # 设置错误处理
    trap cleanup EXIT
    
    echo -e "${BLUE}正在执行完整安装流程...${NC}"
    
    # 基础安装步骤（模块1）
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
    install_xray
    generate_reality_keys
    configure_nginx
    configure_xray
    configure_sing_box
    save_config_info
    start_services
    generate_subscription
    
    # 高级功能安装（模块3）
    setup_traffic_monitoring
    setup_cron_jobs
    setup_email_system
    create_init_script
    
    # 管理工具（模块2+3完整版）
    create_enhanced_edgeboxctl
    create_uninstall_script
    
    # 启动初始化服务
    systemctl start edgebox-init.service >/dev/null 2>&1 || true
    
    # 等待服务稳定
    sleep 3
    
    # 生成初始图表和首页
    if [[ -x "${SCRIPTS_DIR}/generate-charts.py" ]]; then
        log_info "生成初始控制面板..."
        "${SCRIPTS_DIR}/generate-charts.py" >/dev/null 2>&1 || log_warn "图表生成失败，请稍后访问控制面板"
    fi
    
    # 运行一次流量采集初始化
    if [[ -x "${SCRIPTS_DIR}/traffic-collector.sh" ]]; then
        "${SCRIPTS_DIR}/traffic-collector.sh" >/dev/null 2>&1 || true
    fi
    
    # 显示安装信息
    show_installation_info
    
    log_success "EdgeBox v3.0.0 企业级部署完成！"
    log_info "安装日志: ${LOG_FILE}"
    log_info "卸载命令: edgebox-uninstall"
    echo ""
    echo -e "${GREEN}🎯 立即体验：访问 http://${SERVER_IP}/ 查看控制面板${NC}"
    echo -e "${BLUE}📚 完整文档：edgeboxctl help${NC}"
}

# 执行主函数
main "$@"
