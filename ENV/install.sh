#!/bin/bash

# --- auto-elevate to root (works with bash <(curl ...)) ---
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
# EdgeBox 企业级多协议节点部署脚本 - 完全增强版
# Version: 3.0.0 - 模块1+2+3完整版 + Trojan-TLS
# Description: 包含流量统计、预警、备份恢复、出站分流等高级运维功能
# Protocols: VLESS-Reality, VLESS-gRPC, VLESS-WS, Hysteria2, TUIC, Trojan-TLS
# Architecture: SNI定向 + ALPN兜底 + 智能分流 + 流量监控
#############################################

set -e

# 颜色定义
ESC=$'\033'
BLUE="${ESC}[0;34m"
PURPLE="${ESC}[0;35m"
CYAN="${ESC}[0;36m"
YELLOW="${ESC}[1;33m"
GREEN="${ESC}[0;32m"
RED="${ESC}[0;31m"
NC="${ESC}[0m"

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
UUID_TROJAN=""  # 新增

# Reality密钥
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
REALITY_SHORT_ID=""

# 密码生成
PASSWORD_HYSTERIA2=""
PASSWORD_TUIC=""
PASSWORD_TROJAN=""  # 新增

# 端口配置（单端口复用架构）
PORT_REALITY=11443      # 内部回环 (Xray Reality)
PORT_HYSTERIA2=443    # UDP
PORT_TUIC=2053        # UDP
PORT_GRPC=10085       # 内部回环
PORT_WS=10086         # 内部回环
PORT_TROJAN=10143     # 内部回环 (新增)

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
    log_info "安装依赖..."
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true

    # 必要包
local pkgs=(curl wget unzip ca-certificates jq bc uuid-runtime dnsutils openssl \
            vnstat nginx libnginx-mod-stream nftables certbot python3-certbot-nginx \
            msmtp-mta bsd-mailx cron tar)
    for pkg in "${pkgs[@]}"; do
      if ! dpkg -l | grep -q "^ii.*${pkg}"; then
        log_info "安装 ${pkg}..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}" >/dev/null 2>&1 || {
          log_warn "${pkg} 安装失败，尝试继续..."
        }
      else
        log_info "${pkg} 已安装"
      fi
    done

    systemctl enable vnstat >/dev/null 2>&1 || true
    systemctl start  vnstat  >/dev/null 2>&1 || true

    systemctl enable nftables >/dev/null 2>&1 || true
    systemctl start  nftables  >/dev/null 2>&1 || true

    log_success "依赖安装完成（已移除 Python 科学栈）"
}

# 生成UUID和密码
generate_credentials() {
    log_info "生成UUID和密码..."
    
    UUID_VLESS=$(uuidgen)
    UUID_HYSTERIA2=$(uuidgen)
    UUID_TUIC=$(uuidgen)
    UUID_TROJAN=$(uuidgen)  # 新增
    
    REALITY_SHORT_ID="$(openssl rand -hex 8)"
    PASSWORD_HYSTERIA2=$(openssl rand -base64 16)
    PASSWORD_TUIC=$(openssl rand -base64 16)
    PASSWORD_TROJAN=$(openssl rand -base64 16)  # 新增
    
    log_success "凭证生成完成"
    log_info "VLESS UUID: $UUID_VLESS"
    log_info "TUIC UUID: $UUID_TUIC"
    log_info "Trojan UUID: $UUID_TROJAN"  # 新增
    log_info "Hysteria2 密码: $PASSWORD_HYSTERIA2"
    log_info "Trojan 密码: $PASSWORD_TROJAN"  # 新增
}

# 创建目录结构
create_directories() {
    log_info "创建目录..."

    mkdir -p "${INSTALL_DIR}"/{cert,config,templates,scripts}
    mkdir -p "${CONFIG_DIR}/shunt"
    mkdir -p /var/log/{edgebox,xray}

    # Web 根与数据
    mkdir -p "${TRAFFIC_DIR}/logs"
    mkdir -p "${TRAFFIC_DIR}/assets/js"

    # 保持兼容：若历史版本使用 /var/www/html，可做一次性迁移或软链（按需）
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
    # 版本可用环境变量覆盖：SING_BOX_VERSION=1.12.4 bash install.sh
    local ver="${SING_BOX_VERSION:-1.12.4}"
    local arch="$(uname -m)"
    local arch_tag=
    case "$arch" in
      x86_64|amd64)   arch_tag="amd64" ;;
      aarch64|arm64)  arch_tag="arm64" ;;
      armv7l)         arch_tag="armv7" ;;
      *) log_error "不支持的 CPU 架构: $arch"; return 1 ;;
    esac

    local pkg="sing-box-${ver}-linux-${arch_tag}.tar.gz"
    local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/${pkg}"
    local tmp="/tmp/${pkg}"

    log_info "下载 sing-box v${ver} (${arch_tag}) ..."
    rm -f "$tmp"
    if ! curl -fL --connect-timeout 15 --retry 3 --retry-delay 2 -o "$tmp" "$url"; then
        log_error "下载失败：$url"; return 1
    fi

    log_info "解包并安装..."
    local tmpdir; tmpdir="$(mktemp -d)"
    tar -xzf "$tmp" -C "$tmpdir"
    install -m 0755 -o root -g root "$tmpdir"/sing-box*/sing-box /usr/local/bin/sing-box

    # 清理
    rm -rf "$tmpdir" "$tmp"

    # 校验
    if /usr/local/bin/sing-box version >/dev/null 2>&1; then
        log_success "sing-box 安装完成"
    else
        log_error "sing-box 安装失败"; return 1
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
  log_info "配置 Nginx（Nginx-first · SNI+ALPN 分流）..."

  [[ -f /etc/nginx/nginx.conf ]] && cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak

  cat > /etc/nginx/nginx.conf <<'NGINX_CONF'
# 加载动态模块（必须有，才会启用 stream / ssl_preread / stream_map 等）
include /etc/nginx/modules-enabled/*.conf;
include /usr/share/nginx/modules/*.conf;

user  www-data;
worker_processes  auto;
pid /run/nginx.pid;

events { worker_connections 1024; }

http {
  include       /etc/nginx/mime.types;
  default_type  application/octet-stream;
  sendfile on;
  access_log /var/log/nginx/access.log;
  error_log  /var/log/nginx/error.log warn;

  server {
    listen 0.0.0.0:80 default_server;
    listen [::]:80   default_server;
    server_name _;

    location = / { return 302 /traffic/; }
    location = /sub { default_type text/plain; root /var/www/html; }
    location ^~ /traffic/ { alias /etc/edgebox/traffic/; autoindex off; }
  }
}

# === TCP/443：SNI + ALPN 分流（不终止 TLS）===
stream {
  map $ssl_preread_server_name $svc {
    ~^(www\.cloudflare\.com|www\.apple\.com|www\.microsoft\.com)$  reality;
    ~^trojan\.  trojan;
    grpc.edgebox.internal  grpc;
    ws.edgebox.internal    ws;
    default "";
  }

  map $ssl_preread_alpn_protocols $by_alpn {
    ~\bh2\b          127.0.0.1:10085;  # gRPC
    ~\bhttp/1\.1\b   127.0.0.1:10086;  # WebSocket
    default          127.0.0.1:11443;  # Reality
  }

  map $svc $upstream_sni {
    reality  127.0.0.1:11443;
    trojan   127.0.0.1:10143;
    grpc     127.0.0.1:10085;
    ws       127.0.0.1:10086;
    default  "";
  }

  # SNI 命中则用 SNI；否则回落到 ALPN
  map $upstream_sni $upstream {
    ""      $by_alpn;
    default $upstream_sni;
  }

  server {
    listen 0.0.0.0:443 reuseport;
    ssl_preread on;
    proxy_pass $upstream;
    proxy_connect_timeout 5s;
    proxy_timeout 60s;
  }
}
NGINX_CONF

  if ! nginx -t >/dev/null 2>&1; then
    log_error "Nginx 配置测试失败，请检查 /etc/nginx/nginx.conf"
    return 1
  fi
  systemctl daemon-reload
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx
  log_success "Nginx 配置完成（443 单端口复用 · SNI+ALPN 分流，80 提供 /traffic 与 /sub）"
}

# 配置Xray
configure_xray() {
    log_info "配置 Xray..."

    # 验证必要变量
    if [[ -z "$UUID_VLESS" || -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_SHORT_ID" || -z "$UUID_TROJAN" || -z "$PASSWORD_TROJAN" ]]; then
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
    },
    {
      "tag": "Trojan-TLS-Internal",
      "listen": "127.0.0.1",
      "port": 10143,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${PASSWORD_TROJAN}",
            "email": "trojan-internal@edgebox"
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
              "certificateFile": "${CERT_DIR}/current.pem",
              "keyFile": "${CERT_DIR}/current.key"
            }
          ]
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
    "tuic": "${UUID_TUIC}",
    "trojan": "${UUID_TROJAN}"
  },
  "password": {
    "hysteria2": "${PASSWORD_HYSTERIA2}",
    "tuic": "${PASSWORD_TUIC}",
    "trojan": "${PASSWORD_TROJAN}"
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
    "trojan": ${PORT_TROJAN}
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

# 生成订阅链接（安装时）
generate_subscription() {
    log_info "生成订阅链接..."

    # 校验
    if [[ -z "$SERVER_IP" || -z "$UUID_VLESS" || -z "$REALITY_PUBLIC_KEY" || -z "$UUID_TROJAN" || -z "$PASSWORD_TROJAN" ]]; then
        log_error "必要的配置变量未设置，无法生成订阅"; return 1
    fi

    local addr="$SERVER_IP" uuid="$UUID_VLESS" trojan_uuid="$UUID_TROJAN"
    local WS_SNI="ws.edgebox.internal"
    local TROJAN_SNI="trojan.edgebox.internal"
    local allowInsecure="&allowInsecure=1"   # IP 模式：gRPC/WS/TUIC/Trojan 关闭校验
    local insecure="&insecure=1"             # IP 模式：HY2 关闭校验

    # URL 编码密码
    local HY2_PW_ENC TUIC_PW_ENC TROJAN_PW_ENC
    HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
    TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC"     | jq -rR @uri)
    TROJAN_PW_ENC=$(printf '%s' "$PASSWORD_TROJAN" | jq -rR @uri)

    # 明文 6 条（⚠️ 无注释、每行一条，放在文件最前面，保证粘贴导入稳定）
    local plain=$(
      cat <<PLAIN
vless://${uuid}@${addr}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY
vless://${uuid}@${addr}:443?encryption=none&security=tls&sni=grpc.edgebox.internal&alpn=h2&type=grpc&serviceName=grpc&fp=chrome${allowInsecure}#EdgeBox-gRPC
vless://${uuid}@${addr}:443?encryption=none&security=tls&sni=${WS_SNI}&host=${WS_SNI}&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome${allowInsecure}#EdgeBox-WS
trojan://${TROJAN_PW_ENC}@${addr}:443?security=tls&sni=${TROJAN_SNI}&alpn=http%2F1.1&fp=chrome${allowInsecure}#EdgeBox-TROJAN
hysteria2://${HY2_PW_ENC}@${addr}:443?sni=${addr}&alpn=h3${insecure}#EdgeBox-HYSTERIA2
tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${addr}:2053?congestion_control=bbr&alpn=h3&sni=${addr}${allowInsecure}#EdgeBox-TUIC
PLAIN
    )

    # Base64 工具
    _b64_line(){ if base64 --help 2>&1 | grep -q -- '-w'; then base64 -w0; else base64 | tr -d '\n'; fi; }
    _ensure_nl(){ sed -e '$a\'; }

    # 写配置目录（给 CLI 兼容）
    printf '%s\n' "$plain" > "${CONFIG_DIR}/subscription.txt"
    _ensure_nl <<<"$plain" | _b64_line > "${CONFIG_DIR}/subscription.base64"

    : > "${CONFIG_DIR}/subscription.b64lines"
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      printf '%s\n' "$line" | _ensure_nl | _b64_line >> "${CONFIG_DIR}/subscription.b64lines"
      printf '\n' >> "${CONFIG_DIR}/subscription.b64lines"
    done <<<"$plain"

    # 控制面板文件：第一部分就是纯链接（没有任何注释）
    mkdir -p /var/www/html
    {
      printf '%s\n\n' "$plain"
      echo "# Base64逐行【每行一个协议，多数客户端不支持一次复制导入】"
      cat "${CONFIG_DIR}/subscription.b64lines"
      echo
      echo "# Base64整包【六协议一起导入，iOS 常用】"
      cat "${CONFIG_DIR}/subscription.base64"
      echo
    } > /var/www/html/sub

    log_success "订阅已生成"
    log_success "HTTP 订阅地址: http://${addr}/sub"
}

#############################################
# 模块3：高级运维功能安装
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

# 流量采集器：每小时增量 → 聚合 → traffic.json
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
    nft list counter inet edgebox c_resi_out 2>/dev/null | awk '/bytes/ {print $2;exit}'
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
awk -F, 'NR>1{m=substr($1,1,7); vps[m]+=$2; resi[m]+=$3; tx[m]+=$4; rx[m]+=$5}
END{
  print "month,vps,resi,total,tx,rx";
  n=asorti(vps, ks);
  for(i=1;i<=n;i++){ m=ks[i]; t=vps[m]+resi[m]; print m","vps[m]","resi[m]","t","tx[m]","rx[m] }
}' "$LOG_DIR/daily.csv" > "$LOG_DIR/monthly.csv.tmp"
{ head -n1 "$LOG_DIR/monthly.csv.tmp"; tail -n 18 "$LOG_DIR/monthly.csv.tmp" | grep -v '^month,'; } \
  > "$LOG_DIR/monthly.csv"

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

  # 面板数据刷新（自包含版本，不依赖外部函数）
cat > "${SCRIPTS_DIR}/panel-refresh.sh" <<'PANEL'
#!/bin/bash
set -euo pipefail
TRAFFIC_DIR="/etc/edgebox/traffic"
SCRIPTS_DIR="/etc/edgebox/scripts"
SHUNT_DIR="/etc/edgebox/shunt"
CONFIG_DIR="/etc/edgebox/config"
mkdir -p "$TRAFFIC_DIR"

# --- 基本信息 ---
srv_json="${CONFIG_DIR}/server.json"
server_ip="$( (jq -r '.server_ip' "$srv_json" 2>/dev/null) || hostname -I | awk '{print $1}' )"
version="$( (jq -r '.version' "$srv_json" 2>/dev/null) || echo 'v3.0.0')"
install_date="$( (jq -r '.install_date' "$srv_json" 2>/dev/null) || date +%F)"
# 证书模式/域名/到期
cert_domain=""
cert_mode="self-signed"
cert_expire=""
if ls /etc/letsencrypt/live/*/fullchain.pem >/dev/null 2>&1; then
  cert_mode="letsencrypt"
  cert_domain="$(basename /etc/letsencrypt/live/* 2>/dev/null || true)"
  pem="/etc/letsencrypt/live/${cert_domain}/cert.pem"
  if [[ -f "$pem" ]] && command -v openssl >/dev/null 2>&1; then
    cert_expire="$(openssl x509 -enddate -noout -in "$pem" 2>/dev/null | cut -d= -f2)"
  fi
fi

# 当前出口 IP（尽量轻量：2s 超时，多源兜底）
get_eip() {
  (curl -fsS --max-time 2 https://api.ip.sb/ip 2>/dev/null) \
  || (curl -fsS --max-time 2 https://ifconfig.me 2>/dev/null) \
  || (dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null) \
  || echo ""
}
eip="$(get_eip)"

# --- 分流状态 ---
state_json="${SHUNT_DIR}/state.json"
mode="vps"; proxy=""; health="unknown"; wl_count=0; whitelist_json='[]'
if [[ -s "$state_json" ]]; then
  mode="$(jq -r '.mode' "$state_json")"
  proxy="$(jq -r '.proxy_info // ""' "$state_json")"
  health="$(jq -r '.health // "unknown"' "$state_json")"
fi
if [[ -s "${SHUNT_DIR}/whitelist.txt" ]]; then
  wl_count="$(grep -cve '^\s*$' "${SHUNT_DIR}/whitelist.txt" || true)"
  whitelist_json="$(jq -R -s 'split("\n")|map(select(length>0))' "${SHUNT_DIR}/whitelist.txt")"
fi

# --- 协议配置（检测监听端口/进程，做成一览表） ---
# 目标：符合 README 的“左侧 70% 协议配置卡片”，至少给出协议名/端口/进程与说明【协议清单见 README】。
# 数据来源：ss/ps 检测（健壮且不依赖具体实现），缺少时标注“未监听/未配置”。
SS="$(ss -H -lnptu 2>/dev/null || true)"
add_proto() {  # name proto port proc note
  local name="$1" proto="$2" port="$3" proc="$4" note="$5"
  jq -n --arg name "$name" --arg proto "$proto" --argjson port "$port" \
        --arg proc "$proc" --arg note "$note" \
     '{name:$name, proto:$proto, port:$port, proc:$proc, note:$note}'
}
has_listen() { # proto port keyword_in_process
  local proto="$1" port="$2" kw="$3"
  grep -E "(^| )$proto .*:$port " <<<"$SS" | grep -qi "$kw"
}
protos=()

# Xray / sing-box on 443 (Reality / VLESS-WS / VLESS-gRPC / Trojan-TLS 等)
if has_listen tcp 443 "xray|sing-box|trojan"; then
  protos+=( "$(add_proto 'VLESS/Trojan (443/TCP)' 'tcp' 443 "$(grep -E 'tcp .*:443 ' <<<"$SS" | awk -F',' '/users/ {print $2;exit}' | sed 's/\"//g')" 'Reality/WS/gRPC/TLS 同端口，多协议复用')" )
else
  protos+=( "$(add_proto 'VLESS/Trojan (443/TCP)' 'tcp' 443 '未监听' '未检测到 443 TCP')" )
fi

# Hysteria2（常见 UDP 端口：8443/443）
if has_listen udp 8443 "hysteria|sing-box"; then
  protos+=( "$(add_proto 'Hysteria2' 'udp' 8443 'hysteria/sing-box' '高性能 UDP 通道（直连，不参与分流）')" )
elif has_listen udp 443 "hysteria|sing-box"; then
  protos+=( "$(add_proto 'Hysteria2' 'udp' 443 'hysteria/sing-box' '高性能 UDP 通道（直连，不参与分流）')" )
else
  protos+=( "$(add_proto 'Hysteria2' 'udp' 0 '未监听' '未检测到常见端口 8443/443')" )
fi

# TUIC（常见 UDP 端口：2053）
if has_listen udp 2053 "tuic|sing-box"; then
  protos+=( "$(add_proto 'TUIC' 'udp' 2053 'tuic/sing-box' '高性能 UDP 通道（直连，不参与分流）')" )
else
  protos+=( "$(add_proto 'TUIC' 'udp' 2053 '未监听' '未检测到 2053 UDP')" )
fi

# 汇总为 JSON 数组
protocols_json="$(jq -s '.' <<<"${protos[*]:-[]}")"

# --- 写 panel.json ---
jq -n \
 --arg updated "$(date -Is)" \
 --arg ip "$server_ip" \
 --arg eip "$eip" \
 --arg version "$version" \
 --arg install_date "$install_date" \
 --arg cert_mode "$cert_mode" \
 --arg cert_domain "$cert_domain" \
 --arg cert_expire "$cert_expire" \
 --arg mode "$mode" \
 --arg proxy "$proxy" \
 --arg health "$health" \
 --argjson whitelist "$whitelist_json" \
 --argjson protocols "$protocols_json" \
 '{
   updated_at:$updated,
   server:{ip:$ip,eip:($eip|select(length>0)),version:$version,install_date:$install_date,
           cert_mode:$cert_mode,cert_domain:($cert_domain|select(length>0)),cert_expire:($cert_expire|select(length>0))},
   protocols:$protocols,
   shunt:{mode:$mode,proxy_info:$proxy,health:$health,whitelist:$whitelist}
 }' > "${TRAFFIC_DIR}/panel.json"

# 写订阅复制链接
proto="http"; addr="$server_ip"
if [[ "$cert_mode" == "letsencrypt" && -n "$cert_domain" ]]; then proto="https"; addr="$cert_domain"; fi
echo "${proto}://${addr}/sub" > "${TRAFFIC_DIR}/sub.txt"
PANEL
chmod +x "${SCRIPTS_DIR}/panel-refresh.sh"

  # 预警配置（默认）
  cat > "${TRAFFIC_DIR}/alert.conf" <<'CONF'
# 月度预算（GiB）
ALERT_MONTHLY_GIB=100
# 邮件/Hook（可留空）
ALERT_EMAIL=
ALERT_WEBHOOK=
# 阈值（百分比，逗号分隔）
ALERT_STEPS=30,60,90
CONF

  # 预警脚本（读取 monthly.csv 与 alert.conf，阈值去重）
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

# 控制面板（卡片式 UI，读取 /traffic/sub.txt 与 /traffic/traffic.json）
cat > "${TRAFFIC_DIR}/index.html" <<'HTML'
<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>EdgeBox 控制面板</title>
<style>
:root{--card:#fff;--border:#e2e8f0;--bg:#f8fafc;--muted:#64748b;--shadow:0 4px 6px -1px rgba(0,0,0,.1)}
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:#334155;margin:0}
.container{max-width:1200px;margin:0 auto;padding:16px}
.grid{display:grid;gap:16px}
.grid-full{grid-template-columns:1fr}
.grid-70-30{grid-template-columns:7fr 3fr}@media(max-width:980px){.grid-70-30{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);overflow:hidden}
.card h3{margin:0;padding:12px 16px;border-bottom:1px solid var(--border);font-size:1rem}
.card .content{padding:16px}
.small{color:var(--muted);font-size:.9rem}
.table{width:100%;border-collapse:collapse}.table th,.table td{padding:8px 10px;border-bottom:1px solid var(--border);font-size:.9rem;text-align:left}
.copy{display:flex;gap:8px}.copy input{flex:1;padding:8px;border:1px solid var(--border);border-radius:8px}
.btn{padding:8px 12px;border:1px solid var(--border);background:#f1f5f9;border-radius:8px;cursor:pointer}
.badge{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:2px 8px;font-size:.8rem;margin-right:6px}
.chart{position:relative;height:320px}
.notice{margin:0;padding-left:18px}.notice li{margin:6px 0}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
</head><body>
<div class="container">

  <!-- 通知中心（全宽） -->
  <div class="grid grid-full">
    <div class="card">
      <h3>通知中心</h3>
      <div class="content">
        <ul class="notice" id="alerts"><li class="small">暂无通知</li></ul>
        <div class="small">注：展示最近 10 条预警；更多见 <code>/traffic/alerts.json</code>。</div>
      </div>
    </div>
  </div>

  <!-- 第1行：基本信息 -->
  <div class="grid grid-full">
    <div class="card">
      <h3>基本信息</h3>
      <div class="content">
        <div class="small">服务器地址：<span id="srv-addr">-</span></div>
        <div class="small">当前出口 IP：<span id="eip">-</span></div>
        <div class="small">证书：<span id="cert-mode">-</span> <span id="cert-exp"> </span></div>
        <div class="small">安装版本：<span id="ver">-</span>，安装日期：<span id="inst">-</span></div>
        <div class="small">数据更新时间：<span id="updated">-</span></div>
      </div>
    </div>
  </div>

  <!-- 第2行：左 70% 协议配置 + 右 30% 分流状态 -->
  <div class="grid grid-70-30">
    <div class="card">
      <h3>协议配置（关键参数一览）</h3>
      <div class="content">
        <table class="table" id="proto">
          <thead><tr><th>协议</th><th>网络</th><th>端口</th><th>进程/状态</th><th>说明</th></tr></thead>
          <tbody></tbody>
        </table>
        <div class="small">注：HY2/TUIC 为 UDP 通道，直连不参与分流；VLESS/Trojan 由 Xray/sing-box 在 443/TCP 复用。</div>
      </div>
    </div>
    <div class="card">
      <h3>出站分流状态（Xray-only）</h3>
      <div class="content">
        <div style="margin-bottom:8px">
          <span class="badge" id="tag-vps">vps</span>
          <span class="badge" id="tag-resi">resi</span>
          <span class="badge" id="tag-direct">direct-resi</span>
        </div>
        <div class="small">当前模式：<span id="mode">-</span></div>
        <div class="small">上游：<span id="proxy">-</span></div>
        <div class="small">健康：<span id="health">-</span></div>
        <div class="small">白名单：<span id="wln">-</span></div>
      </div>
    </div>
  </div>

  <!-- 第3行：订阅链接 -->
  <div class="grid grid-full">
    <div class="card"><h3>订阅链接</h3><div class="content">
      <div class="copy"><input id="sub" readonly><button class="btn" onclick="copySub()">复制</button></div>
    </div></div>
  </div>

  <!-- 第4行：流量统计 -->
  <div class="grid grid-full">
    <div class="card"><h3>近30天流量趋势</h3><div class="content"><canvas id="traffic" class="chart"></canvas></div></div>
  </div>

  <!-- 第5行：管理命令 -->
  <div class="grid grid-full">
    <div class="card"><h3>常用管理命令</h3>
      <div class="content">
<pre>
# 出站分流（Xray-only）
edgeboxctl shunt vps
edgeboxctl shunt resi '&lt;URL&gt;'
edgeboxctl shunt direct-resi '&lt;URL&gt;'
edgeboxctl shunt whitelist add|remove|list|reset &lt;domain&gt;

# 域名/IP 模式切换
edgeboxctl switch-to-domain &lt;your_domain&gt;
edgeboxctl switch-to-ip

# 订阅
edgeboxctl sub
</pre>
      </div>
    </div>
  </div>
</div>

<script>
const GiB = 1024**3; const el = id => document.getElementById(id);
const fmtGiB = b => (b/GiB).toFixed(2)+' GiB';
function paintBadges(mode){ ['vps','resi','direct'].forEach(x=>{ const id=x==='direct'?'tag-direct':'tag-'+x; const n=el(id); n.style.background=((x==='direct'?'direct-resi':x)===mode)?'#e2fbe2':'#f1f5f9'; });}
function li(text){ const li=document.createElement('li'); li.textContent=text; return li;}

async function boot(){
  const [subTxt, panel, tjson, alerts] = await Promise.all([
    fetch('/traffic/sub.txt',{cache:'no-store'}).then(r=>r.text()).catch(()=>''), 
    fetch('/traffic/panel.json',{cache:'no-store'}).then(r=>r.json()).catch(()=>null),
    fetch('/traffic/traffic.json',{cache:'no-store'}).then(r=>r.json()).catch(()=>null),
    fetch('/traffic/alerts.json',{cache:'no-store'}).then(r=>r.json()).catch(()=>[])
  ]);

  // 通知中心
  const ul = el('alerts'); ul.innerHTML='';
  (alerts||[]).slice(0,10).forEach(a=> ul.appendChild(li((a.ts||'')+'  '+(a.msg||''))) );
  if(ul.children.length===0) ul.appendChild(li('暂无通知'));

  // 订阅
  el('sub').value = (subTxt||'').trim();

  // 基本信息 & 协议配置 & 分流状态
  if(panel){
    const ts = panel.updated_at || new Date().toISOString();
    el('updated').textContent = new Date(ts).toLocaleString();
    const s=panel.server||{}, sh=panel.shunt||{}, protos=panel.protocols||[];
    el('srv-addr').textContent = (s.cert_domain||s.ip||'-');
    el('eip').textContent = s.eip || '(获取中/不可用)';
    el('cert-mode').textContent = s.cert_mode || '-';
    el('cert-exp').textContent = s.cert_expire ? '（到期：'+s.cert_expire+'）' : '';
    el('ver').textContent = s.version || '-'; el('inst').textContent = s.install_date || '-';
    const tb = document.querySelector('#proto tbody'); tb.innerHTML='';
    protos.forEach(p=>{ const tr=document.createElement('tr');
      tr.innerHTML=`<td>${p.name||'-'}</td><td>${p.proto||'-'}</td><td>${p.port||'-'}</td><td>${p.proc||'-'}</td><td>${p.note||''}</td>`; tb.appendChild(tr); });
    const mode = sh.mode||'-'; el('mode').textContent = mode; paintBadges(mode);
    el('proxy').textContent = sh.proxy_info || '(未配置)'; el('health').textContent = (sh.health||'unknown'); el('wln').textContent = Array.isArray(sh.whitelist)?(sh.whitelist.length+' 项'):'-';
  }

  // 流量统计
  if(tjson){
    const labels = (tjson.last30d||[]).map(x=>x.date);
    const vps = (tjson.last30d||[]).map(x=>x.vps);
    const resi= (tjson.last30d||[]).map(x=>x.resi);
    new Chart(el('traffic'),{
      type:'line', data:{labels,datasets:[
        {label:'VPS 出口', data:vps, tension:.3, borderWidth:2},
        {label:'住宅出口', data:resi, tension:.3, borderWidth:2}
      ]}, options:{responsive:true,maintainAspectRatio:false,
        scales:{y:{ticks:{callback:v=>(v/GiB).toFixed(1)+' GiB'}}}}
    );
  }
}
function copySub(){ const x=el('sub'); x.select(); document.execCommand('copy'); }
boot();
</script>
</body></html>
HTML

# 网站根目录映射 + 首次刷新
mkdir -p "${TRAFFIC_DIR}" /var/www/html
ln -sfn "${TRAFFIC_DIR}" /var/www/html/traffic
# 先跑一次采集与面板生成
"${SCRIPTS_DIR}/traffic-collector.sh" || true
"${SCRIPTS_DIR}/panel-refresh.sh" || true
log_success "流量监控系统设置完成：${TRAFFIC_DIR}/index.html"
}

# 设置定时任务
# 设置定时任务
setup_cron_jobs() {
  log_info "配置定时任务..."

  # 1) 写入/覆盖 预警配置
cat > /etc/edgebox/traffic/alert.conf <<'CONF'
# 月度预算（GiB）
ALERT_MONTHLY_GIB=100

# Telegram（@BotFather 获取 BotToken；ChatID 可用 @userinfobot）
ALERT_TG_BOT_TOKEN=
ALERT_TG_CHAT_ID=

# Discord（频道里添加 Incoming Webhook）
ALERT_DISCORD_WEBHOOK=

# 微信（个人可用的 PushPlus 转发）
# https://www.pushplus.plus/ 里获取 token
ALERT_PUSHPLUS_TOKEN=

# （可选）通用 Webhook（HTTPS 443），FORMAT=raw|slack|discord
ALERT_WEBHOOK=
ALERT_WEBHOOK_FORMAT=raw

# 阈值（百分比，逗号分隔）
ALERT_STEPS=30,60,90
CONF

  # 2) 写入/覆盖 预警脚本（按当月 total 达到阈值去重告警）
cat > /etc/edgebox/scripts/traffic-alert.sh <<'ALERT'
#!/bin/bash
set -euo pipefail
TRAFFIC_DIR="/etc/edgebox/traffic"
LOG_DIR="$TRAFFIC_DIR/logs"
CONF="$TRAFFIC_DIR/alert.conf"
STATE="$TRAFFIC_DIR/alert.state"
LOG="/var/log/edgebox-traffic-alert.log"
ALERTS_JSON="$TRAFFIC_DIR/alerts.json"   # 面板“通知中心”读取

[[ -r "$CONF" ]] || { echo "[$(date -Is)] no alert.conf" >> "$LOG"; exit 0; }
# shellcheck source=/dev/null
. "$CONF"

month="$(date +%Y-%m)"
row="$(grep "^${month}," "$LOG_DIR/monthly.csv" 2>/dev/null || true)"
[[ -z "$row" ]] && { echo "[$(date -Is)] monthly.csv no row for ${month}" >> "$LOG"; exit 0; }

# CSV: month,vps,resi,total,tx,rx
IFS=',' read -r _ vps resi total tx rx <<<"$row"
budget_bytes=$(( ${ALERT_MONTHLY_GIB:-100} * 1024 * 1024 * 1024 ))
used=$total
pct=$(( budget_bytes>0 ? used * 100 / budget_bytes : 0 ))

sent=""; [[ -f "$STATE" ]] && sent="$(cat "$STATE")"

# 写本地通知（保留50条，最新在前）
persist_local() {
  local msg="$1" ts="$(date -Is)"
  local cur; cur="$(cat "$ALERTS_JSON" 2>/dev/null || echo '[]')"
  printf '%s' "$cur" | jq --arg ts "$ts" --arg m "$msg" \
    '([{"ts":$ts,"msg":$m}] + .) | .[:50]' > "${ALERTS_JSON}.tmp" && mv "${ALERTS_JSON}.tmp" "$ALERTS_JSON"
}

# 并发广播：配置了哪个就发哪个；失败不影响其它
notify() {
  local msg="$1"
  echo "[$(date -Is)] $msg" | tee -a "$LOG" >/dev/null
  persist_local "$msg"

  # Telegram
  if [[ -n "${ALERT_TG_BOT_TOKEN:-}" && -n "${ALERT_TG_CHAT_ID:-}" ]]; then
    curl -m 8 -sS "https://api.telegram.org/bot${ALERT_TG_BOT_TOKEN}/sendMessage" \
      -d "chat_id=${ALERT_TG_CHAT_ID}" -d "text=${msg}" >/dev/null 2>&1 || true
  fi

  # Discord
  if [[ -n "${ALERT_DISCORD_WEBHOOK:-}" ]]; then
    curl -m 8 -sS -H 'Content-Type: application/json' -X POST \
      -d "$(jq -n --arg t "$msg" '{content:$t}')" \
      "$ALERT_DISCORD_WEBHOOK" >/dev/null 2>&1 || true
  fi

  # 微信 PushPlus
  if [[ -n "${ALERT_PUSHPLUS_TOKEN:-}" ]]; then
    curl -m 8 -sS -H 'Content-Type: application/json' -X POST \
      -d "$(jq -n --arg tk "$ALERT_PUSHPLUS_TOKEN" --arg t "EdgeBox 预警" --arg c "$msg" \
            '{token:$tk,title:$t,content:$c}')" \
      "https://www.pushplus.plus/send" >/dev/null 2>&1 || true
  fi

  # 通用 Webhook
  if [[ -n "${ALERT_WEBHOOK:-}" ]]; then
    case "${ALERT_WEBHOOK_FORMAT:-raw}" in
      discord) body="$(jq -n --arg t "$msg" '{content:$t}')" ;;
      slack)   body="$(jq -n --arg t "$msg" '{text:$t}')" ;;
      *)       body="$(jq -n --arg t "$msg" '{text:$t}')" ;;
    esac
    curl -m 8 -sS -H 'Content-Type: application/json' -X POST \
      -d "$body" "$ALERT_WEBHOOK" >/dev/null 2>&1 || true
  fi
}

# 阈值触发（去重）
new_sent="$sent"
IFS=',' read -ra STEPS <<<"${ALERT_STEPS:-30,60,90}"
for s in "${STEPS[@]}"; do
  if [[ "$pct" -ge "$s" ]] && ! grep -q "(^|,)$s(,|$)" <<<",$sent,"; then
    human_used="$(awk -v b="$used" 'BEGIN{printf "%.2f GiB", b/1024/1024/1024}')"
    human_budget="$(awk -v b="$budget_bytes" 'BEGIN{printf "%.0f GiB", b/1024/1024/1024}')"
    notify "本月用量 ${human_used}（${pct}% / 预算 ${human_budget}），触达 ${s}% 阈值。"
    new_sent="${new_sent:+${new_sent},}${s}"
  fi
done
echo "$new_sent" > "$STATE"
ALERT
chmod +x /etc/edgebox/scripts/traffic-alert.sh

  # 3) 三条 cron（每小时：采集 → 刷面板 → 预警）
  (
    crontab -l 2>/dev/null | grep -vE '/etc/edgebox/scripts/(traffic-collector\.sh|panel-refresh\.sh|traffic-alert\.sh)'
    echo "0 * * * * /etc/edgebox/scripts/traffic-collector.sh"
    echo "5 * * * * /etc/edgebox/scripts/panel-refresh.sh"
    echo "7 * * * * /etc/edgebox/scripts/traffic-alert.sh"
  ) | crontab - 2>/dev/null || true

  log_success "cron 已配置（每小时采集 + 刷新面板 + 阈值预警）"
}

# 解析住宅代理 URL => 导出全局变量：
# PROXY_SCHEME(http|socks) PROXY_HOST PROXY_PORT PROXY_USER PROXY_PASS PROXY_TLS(0/1) PROXY_SNI
parse_proxy_url() {
  local url="$(printf '%s' "$1" | tr -d '\r' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
  [[ -z "$url" ]] && { echo "空代理地址"; return 1; }

  local scheme="${url%%://*}"; scheme="${scheme%:*}"
  local rest="${url#*://}"

  local auth hostport query user="" pass="" host="" port="" tls=0 sni=""
  # 拆 query
  if [[ "$rest" == *\?* ]]; then query="${rest#*\?}"; rest="${rest%%\?*}"; fi
  # 拆 auth@host:port
  if [[ "$rest" == *@* ]]; then auth="${rest%@*}"; hostport="${rest#*@}"
     user="${auth%%:*}"; pass="${auth#*:}"; [[ "$pass" == "$auth" ]] && pass=""
  else hostport="$rest"; fi
  host="${hostport%%:*}"; port="${hostport##*:}"

  # 标准化
  case "$scheme" in
    http)   tls=0 ;;
    https)  scheme="http"; tls=1 ;;
    socks5|socks) scheme="socks"; tls=0 ;;
    socks5s)      scheme="socks"; tls=1 ;; # 罕见：SOCKS over TLS
    *) echo "不支持的代理协议: $scheme"; return 1 ;;
  esac

  # 解析 query
  if [[ -n "$query" ]]; then
    local kv k v
    IFS='&' read -r -a kv <<<"$query"
    for k in "${kv[@]}"; do
      v="${k#*=}"; k="${k%%=*}"
      [[ "$k" == "sni" ]] && sni="$v"
    done
  fi

  # 导出
  PROXY_SCHEME="$scheme"; PROXY_HOST="$host"; PROXY_PORT="$port"
  PROXY_USER="$user"; PROXY_PASS="$pass"; PROXY_TLS="$tls"; PROXY_SNI="$sni"
}

# 用 curl 健康检查（http/https/socks 都支持）
check_proxy_health_url() {
  parse_proxy_url "$1" || return 1
  local proxy_uri auth=""
  [[ -n "$PROXY_USER" ]] && auth="${PROXY_USER}:${PROXY_PASS}@"

  if [[ "$PROXY_SCHEME" == "http" ]]; then
    local scheme="http"; [[ "$PROXY_TLS" -eq 1 ]] && scheme="https"
    proxy_uri="${scheme}://${auth}${PROXY_HOST}:${PROXY_PORT}"
  else
    # socks5h 确保域名解析走代理端
    proxy_uri="socks5h://${auth}${PROXY_HOST}:${PROXY_PORT}"
  fi

  curl -fsS --max-time 6 --connect-timeout 4 --proxy "$proxy_uri" http://www.gstatic.com/generate_204 >/dev/null
}

# 生成 Xray 的住宅代理 outbound JSON（单个）
build_xray_resi_outbound() {
  # 依赖 parse_proxy_url 产生的全局变量
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

# 生成 sing-box 的住宅代理 outbound JSON（可按需让 HY2/TUIC 也走住宅）
build_singbox_resi_outbound() {
  local auth='' tls=''
  [[ -n "$PROXY_USER" ]] && auth=",\"username\":\"$PROXY_USER\",\"password\":\"$PROXY_PASS\""
  if [[ "$PROXY_TLS" -eq 1 ]]; then
    tls=",\"tls\":{\"enabled\":true$( [[ -n "$PROXY_SNI" ]] && echo ",\"server_name\":\"$PROXY_SNI\"" )}"
  fi
  if [[ "$PROXY_SCHEME" == "http" ]]; then
    cat <<JSON
{"type":"http","tag":"resi-proxy","server":"$PROXY_HOST","server_port":$PROXY_PORT$auth$tls}
JSON
  else
    cat <<JSON
{"type":"socks","tag":"resi-proxy","server":"$PROXY_HOST","server_port":$PROXY_PORT$auth$tls}
JSON
  fi
}

# 创建完整的edgeboxctl管理工具
create_enhanced_edgeboxctl() {
    log_info "创建增强版edgeboxctl管理工具..."
    
    cat > /usr/local/bin/edgeboxctl << 'EDGEBOXCTL_SCRIPT'
#!/bin/bash
# EdgeBox 增强版控制脚本 - 模块1+2+3完整版 + Trojan-TLS
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

# 颜色定义（使用 ANSI C 风格的转义）
ESC=$'\033'
RED="${ESC}[0;31m"; GREEN="${ESC}[0;32m"; YELLOW="${ESC}[1;33m"
BLUE="${ESC}[0;34m"; CYAN="${ESC}[0;36m"; NC="${ESC}[0m"

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
  UUID_TROJAN=$(jq -r '.uuid.trojan' ${CONFIG_DIR}/server.json 2>/dev/null)
  PASSWORD_HYSTERIA2=$(jq -r '.password.hysteria2' ${CONFIG_DIR}/server.json 2>/dev/null)
  PASSWORD_TUIC=$(jq -r '.password.tuic' ${CONFIG_DIR}/server.json 2>/dev/null)
  PASSWORD_TROJAN=$(jq -r '.password.trojan' ${CONFIG_DIR}/server.json 2>/dev/null)
  REALITY_PUBLIC_KEY=$(jq -r '.reality.public_key' ${CONFIG_DIR}/server.json 2>/dev/null)
  REALITY_SHORT_ID=$(jq -r '.reality.short_id' ${CONFIG_DIR}/server.json 2>/dev/null)
}

#############################################
# 基础功能
#############################################

show_sub() {
  if [[ ! -f ${CONFIG_DIR}/server.json ]]; then echo -e "${RED}配置文件不存在${NC}"; exit 1; fi
  local cert_mode=$(get_current_cert_mode)
  local server_ip=$(jq -r '.server_ip' ${CONFIG_DIR}/server.json)
  echo ""
  if [[ -s /var/www/html/sub ]]; then
    echo -e "${CYAN}订阅内容【与控制台一致】：${NC}"
    cat /var/www/html/sub
  else
    # 回退：旧文件
    [[ -s ${CONFIG_DIR}/subscription.txt ]] && { echo -e "${CYAN}# 明文：${NC}"; cat ${CONFIG_DIR}/subscription.txt; echo; }
    [[ -s ${CONFIG_DIR}/subscription.base64 ]] && { echo -e "${CYAN}# Base64(整包)：${NC}"; cat ${CONFIG_DIR}/subscription.base64; echo; }
  fi
  echo -e "\n${CYAN}控制面板：${NC}http://${server_ip}/\n"
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

post_switch_report() {
  # 颜色变量若未定义，避免报错
  : "${CYAN:=}" "${GREEN:=}" "${RED:=}" "${YELLOW:=}" "${NC:=}"

  echo -e "\n${CYAN}---切换证书模式后自动验收报告---${NC}"

  # 1) Nginx 配置测试
  echo -e "${CYAN}1) Nginx 配置测试 · 详细输出:${NC}"
  local _nginx_out _rc
  _nginx_out="$(nginx -t 2>&1)"; _rc=$?
  echo "${_nginx_out}" | sed 's/^/   | /'
  echo -n "   => 结果: "
  [[ $_rc -eq 0 ]] && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAIL${NC}"

  # 2) 服务可用性
  echo -e "${CYAN}2) 服务可用性 · 详细输出:${NC}"
  local bad=0 s st
  for s in nginx xray sing-box; do
    st="$(systemctl is-active "$s" 2>&1)"
    echo "   | $s : ${st}"
    [[ "$st" == "active" ]] || bad=1
  done
  echo -n "   => 结果: "
  [[ $bad -eq 0 ]] && \
    echo -e "${GREEN}nginx/xray/sing-box 全部正常${NC}" || \
    echo -e "${RED}存在异常，建议 edgeboxctl logs <svc>${NC}"

  # 3) 订阅文件可访问性（避免把 Base64 全量打屏，仅显示状态码/大小/耗时）
  echo -e "${CYAN}3) 订阅文件 · 详细输出:${NC}"
  local ip code size time_total
  ip="$(jq -r .server_ip "${CONFIG_DIR}/server.json" 2>/dev/null)"
  read -r code size time_total < <(curl -sS -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' "http://${ip}/sub" || echo "000 0 0")
  echo "   | URL: http://${ip}/sub"
  echo "   | HTTP: ${code}   Size: ${size}B   Time: ${time_total}s"
  echo -n "   => 结果: "
  if [[ "$code" =~ ^[23][0-9]{2}$ ]] || { [[ "$code" -ge 200 ]] && [[ "$code" -lt 400 ]]; }; then
    echo -e "${GREEN}可访问${NC}"
  else
    echo -e "${RED}不可访问${NC}"
  fi

  # 4) 证书软链
  echo -e "${CYAN}4) 证书软链 · 详细输出:${NC}"
  ls -l "${CERT_DIR}/current.pem" "${CERT_DIR}/current.key" 2>/dev/null | sed 's/^/   | /' || true
  echo -n "   => 结果: "
  [[ -L ${CERT_DIR}/current.pem && -L ${CERT_DIR}/current.key ]] && \
    echo -e "${GREEN}存在${NC}" || echo -e "${RED}缺失${NC}"

  # 5) 证书权限
  echo -e "${CYAN}5) 证书权限 · 详细输出:${NC}"
  local perm_line perm
  perm_line="$(stat -L -c '%a %U:%G %n' "${CERT_DIR}/current.key" 2>/dev/null || true)"
  [[ -n "$perm_line" ]] && echo "   | $perm_line"
  perm="$(printf '%s\n' "$perm_line" | awk '{print $1}')"
  echo -n "   => 结果: "
  if [[ "$perm" == "600" || "$perm" == "640" ]]; then
    echo -e "${GREEN}已收紧${NC}"
  else
    echo -e "${YELLOW}建议运行 edgeboxctl fix-permissions${NC}"
  fi

  echo -e "${CYAN}--------------------------------${NC}\n"
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
  log_info "为 ${domain} 申请/扩展 Let's Encrypt 证书（含 trojan 子域）"
  request_letsencrypt_cert "$domain" || return 1

  # 可选验收报告
  type post_switch_report >/dev/null 2>&1 && post_switch_report
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

# 清空 nftables 的住宅采集集合（VPS 全量出站时用）
flush_nft_resi_sets() {
  nft flush set inet edgebox resi_addr4 2>/dev/null || true
  nft flush set inet edgebox resi_addr6 2>/dev/null || true
}

# VPS 出站后的快速验收
post_vps_report() {
  echo -e "\n${CYAN}-----分流配置验收报告（VPS 全量出站）-----${NC}"
  # 1) 出口 IP
  local via_vps; via_vps=$(curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)
  echo -e "1) 出口 IP: ${via_vps:-?}"

  # 2) Xray 路由是否只有 direct
  echo -n "2) Xray 路由: "
  if jq -e '.outbounds[]?|select(.tag=="resi-proxy")' ${CONFIG_DIR}/xray.json >/dev/null 2>&1; then
    echo -e "${RED}发现 resi-proxy 出站（不应存在）${NC}"
  else
    echo -e "${GREEN}仅 direct（符合预期）${NC}"
  fi

  # 3) nft 采集集是否已清空
  local set4 set6
  set4=$(nft list set inet edgebox resi_addr4 2>/dev/null | sed -n 's/.*elements = {\(.*\)}/\1/p' | xargs)
  set6=$(nft list set inet edgebox resi_addr6 2>/dev/null | sed -n 's/.*elements = {\(.*\)}/\1/p' | xargs)
  if [[ -z "$set4$set6" ]]; then
    echo -e "3) 采集集: ${GREEN}已清空${NC}"
  else
    echo -e "3) 采集集: IPv4={${set4:-}}  IPv6={${set6:-}} ${YELLOW}(建议清空)${NC}"
  fi
  echo -e "${CYAN}------------------------------------------${NC}\n"
}

# 白名单操作后的轻验收（可选传入一个域名做存在性校验）
post_whitelist_report() {
  local action="$1"; shift || true
  local test_domain="$1"

  echo -e "\n${CYAN}-----白名单变更验收（${action}）-----${NC}"
  local count=0
  [[ -s "${CONFIG_DIR}/shunt/whitelist.txt" ]] && count=$(wc -l < "${CONFIG_DIR}/shunt/whitelist.txt" | tr -d ' ')
  echo -e "1) 白名单条数：${count}"

  # 展示前 10 条
  if [[ "$count" -gt 0 ]]; then
    echo -e "2) 样例（前 10 条）："
    nl -ba "${CONFIG_DIR}/shunt/whitelist.txt" | head -n 10
  else
    echo -e "2) 样例：<空>"
  fi

# 3) Xray 路由同步
echo -n "3) Xray 路由直连规则："
if jq -e '.routing.rules[]?|select(.outboundTag=="resi-proxy")' ${CONFIG_DIR}/xray.json >/dev/null 2>&1; then
  # 智能分流/住宅模式：检查是否存在 direct 的 domain 规则
  if jq -e '.routing.rules[]?|select(.outboundTag=="direct")|select(has("domain"))' ${CONFIG_DIR}/xray.json >/dev/null 2>&1; then
    echo -e "${GREEN}已同步${NC}"
  else
    echo -e "${YELLOW}未检测到白名单直连规则（请在智能分流模式下使用）${NC}"
  fi
else
  echo -e "${YELLOW}当前为 VPS 全量出站模式，此项不适用${NC}"
fi

  # 可选：对指定域名做"是否在白名单文件中"的校验与解析
  if [[ -n "$test_domain" ]]; then
    echo -n "4) 域名存在性："
    if grep -Fxq "$test_domain" "${CONFIG_DIR}/shunt/whitelist.txt" 2>/dev/null; then
      echo -e "${GREEN}${test_domain} 在白名单文件中${NC}"
    else
      echo -e "${RED}${test_domain} 不在白名单文件中${NC}"
    fi
    local ip4 ip6
    ip4=$(getent ahostsv4 "$test_domain" | awk '{print $1; exit}' || true)
    ip6=$(getent ahostsv6 "$test_domain" | awk '{print $1; exit}' || true)
    echo -e "5) 解析结果：IPv4=${ip4:-?}  IPv6=${ip6:-?}"
  fi
  echo -e "${CYAN}------------------------------------------${NC}\n"
}

# 把解析后的 PROXY_* 变量拼成 curl 可用的代理 URI
format_curl_proxy_uri() {
  local __retvar="$1" auth=""
  [[ -n "$PROXY_USER" ]] && auth="${PROXY_USER}:${PROXY_PASS}@"
  local uri
  if [[ "$PROXY_SCHEME" == "http" ]]; then
    local scheme="http"; [[ "$PROXY_TLS" -eq 1 ]] && scheme="https"
    uri="${scheme}://${auth}${PROXY_HOST}:${PROXY_PORT}"
  else
    # socks5h: 让域名解析也走代理端
    uri="socks5h://${auth}${PROXY_HOST}:${PROXY_PORT}"
  fi
  printf -v "$__retvar" '%s' "$uri"
}

# 用代理主机的 IP 更新 nftables 采集集合（供流量面板统计）
update_nft_resi_set() {
  local host="$1"
  local ip4 ip6
  ip4="$(getent ahostsv4 "$host" | awk '{print $1; exit}')" || true
  ip6="$(getent ahostsv6 "$host" | awk '{print $1; exit}')" || true
  nft flush set inet edgebox resi_addr4 2>/dev/null || true
  nft flush set inet edgebox resi_addr6 2>/dev/null || true
  [[ -n "$ip4" ]] && nft add element inet edgebox resi_addr4 { ${ip4} } 2>/dev/null || true
  [[ -n "$ip6" ]] && nft add element inet edgebox resi_addr6 { ${ip6} } 2>/dev/null || true
}

# 分流配置后的自动验收报告
post_shunt_report() {
  local mode="$1" url="$2"
  echo -e "\n${CYAN}-----分流配置验收报告（${mode}）-----${NC}"

  # 1) 上游连通
  echo -n "1) 上游连通性: "
  if check_proxy_health_url "$url"; then echo -e "${GREEN}OK${NC}"; else echo -e "${RED}FAIL${NC}"; fi

  # 2) 出口 IP 对比
  local via_vps via_resi proxy_uri
  via_vps=$(curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)
  parse_proxy_url "$url" >/dev/null 2>&1 || true
  format_curl_proxy_uri proxy_uri
  via_resi=$(curl -fsS --max-time 8 --proxy "$proxy_uri" https://api.ipify.org 2>/dev/null || true)
  echo -e "2) 出口 IP: VPS=${via_vps:-?}  上游=${via_resi:-?}"
  if [[ -n "$via_vps" && -n "$via_resi" && "$via_vps" != "$via_resi" ]]; then
    echo -e "   ${GREEN}判定：出口已切换/可用${NC}"
  else
    echo -e "   ${YELLOW}判定：出口未变化或上游未通${NC}"
  fi

  # 3) 路由生效
  echo -n "3) Xray 路由: "
  jq -e '.outbounds[]?|select(.tag=="resi-proxy")' ${CONFIG_DIR}/xray.json >/dev/null 2>&1 \
    && echo -e "${GREEN}存在 resi-proxy 出站${NC}" || echo -e "${RED}未发现 resi-proxy 出站${NC}"
  echo -e "3b) sing-box 路由: ${YELLOW}设计为直连（HY2/TUIC 走 UDP，不参与分流）${NC}"

  # 4) nftables 采集集
  local set4 set6
  set4=$(nft list set inet edgebox resi_addr4 2>/dev/null | sed -n 's/.*elements = {\(.*\)}/\1/p' | xargs)
  set6=$(nft list set inet edgebox resi_addr6 2>/dev/null | sed -n 's/.*elements = {\(.*\)}/\1/p' | xargs)
  echo -e "4) 采集集: IPv4={${set4:-}}  IPv6={${set6:-}}"
  echo -e "${CYAN}--------------------------------------${NC}\n"
}

# === 住宅代理解析 + 健康检查 + JSON 构造 ===
# 支持的 URL 形式：
#   http://[user:pass@]host:port
#   https://[user:pass@]host:port           # HTTP 代理 + TLS
#   socks5://[user:pass@]host:port
#   socks5s://[user:pass@]host:port?sni=..  # SOCKS over TLS，可选 ?sni
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

# 用 curl 做 204 探测，能通就认为健康
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

# 生成 Xray 的住宅代理 outbound
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

# 生成 sing-box 的住宅代理 outbound（如需让 HY2/TUIC 也走住宅可用）
build_singbox_resi_outbound() {
  local auth='' tls=''
  [[ -n "$PROXY_USER" ]] && auth=",\"username\":\"$PROXY_USER\",\"password\":\"$PROXY_PASS\""
  if [[ "$PROXY_TLS" -eq 1 ]]; then
    tls=",\"tls\":{\"enabled\":true$( [[ -n "$PROXY_SNI" ]] && echo ",\"server_name\":\"$PROXY_SNI\"" )}"
  fi
  if [[ "$PROXY_SCHEME" == "http" ]]; then
    cat <<JSON
{"type":"http","tag":"resi-proxy","server":"$PROXY_HOST","server_port":$PROXY_PORT$auth$tls}
JSON
  else
    cat <<JSON
{"type":"socks","tag":"resi-proxy","server":"$PROXY_HOST","server_port":$PROXY_PORT$auth$tls}
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
post_vps_report
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
  update_nft_resi_set "$PROXY_HOST"
  post_shunt_report "住宅全量（Xray-only）" "$url"
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
  update_nft_resi_set "$PROXY_HOST"
  post_shunt_report "智能分流（Xray-only）" "$url"
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
				post_whitelist_report "add" "$domain"
            else
                log_warn "域名已存在于白名单: $domain"
            fi
            ;;
        remove)
            [[ -z "$domain" ]] && { echo "用法: edgeboxctl shunt whitelist remove domain.com"; return 1; }
            if sed -i "/^${domain}$/d" "${CONFIG_DIR}/shunt/whitelist.txt" 2>/dev/null; then
                log_success "已从白名单移除域名: $domain"
				post_whitelist_report "remove" "$domain"     # ← 新增
            else
                log_error "移除失败或域名不存在: $domain"
            fi
            ;;
        list)
            echo -e "${CYAN}白名单域名：${NC}"
            if [[ -f "${CONFIG_DIR}/shunt/whitelist.txt" ]]; then
                cat "${CONFIG_DIR}/shunt/whitelist.txt" | nl -w2 -s'. '
				post_whitelist_report "list" 
            else
                echo "  无白名单文件"
            fi
            ;;
        reset)
            echo "$WHITELIST_DOMAINS" | tr ',' '\n' > "${CONFIG_DIR}/shunt/whitelist.txt"
            log_success "已重置白名单为默认值"
			post_whitelist_report "reset"                    # ← 新增
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
       '.uuid.vless = $vless | .uuid.tuic = $tuic | .uuid.trojan = $trojan | .password.hysteria2 = $hy2_pass | .password.tuic = $tuic_pass | .password.trojan = $trojan_pass' \
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
    echo -e "  Trojan: $new_trojan_uuid"
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
        echo -e "  VLESS UUID: $(jq -r '.uuid.vless' ${CONFIG_DIR}/server.json)"
        echo -e "  TUIC UUID: $(jq -r '.uuid.tuic' ${CONFIG_DIR}/server.json)"
        echo -e "  Trojan UUID: $(jq -r '.uuid.trojan' ${CONFIG_DIR}/server.json)"
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
控制面板: http://$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null || echo "YOUR_IP")/
${YELLOW}基础操作:${NC}
  edgeboxctl status          查看服务状态
  edgeboxctl restart         重启所有服务  
  edgeboxctl sub             查看订阅链接
  edgeboxctl logs <svc>      查看服务日志 [nginx|xray|sing-box]
  edgeboxctl test            测试连接
  edgeboxctl debug-ports     调试端口状态

${YELLOW}证书管理:${NC}
  edgeboxctl cert-status                   查看证书状态
  edgeboxctl fix-permissions               修复证书权限
  edgeboxctl switch-to-domain <domain>     切换到域名模式
  edgeboxctl switch-to-ip                  切换到IP模式

${YELLOW}配置管理:${NC}
  edgeboxctl config show                   显示当前配置
  edgeboxctl config regenerate-uuid        重新生成UUID

${YELLOW}出站分流:${NC}
  edgeboxctl shunt resi '<代理URL>'                             # 全量走住宅（仅Xray分流）
  edgeboxctl shunt direct-resi '<代理URL>'                      # 智能分流（白名单直连，其余走住宅）
  edgeboxctl shunt vps                                         # VPS全量出站
  edgeboxctl shunt whitelist [add|remove|list|reset] [domain]  # 管理白名单

${YELLOW}流量统计:${NC}
  edgeboxctl traffic show                  查看流量统计
  edgeboxctl traffic reset                 重置流量计数

${YELLOW}流量预警（精简版）:${NC}
  edgeboxctl alert show
  edgeboxctl alert monthly <GiB>
  edgeboxctl alert steps 30,60,90
  edgeboxctl alert telegram <bot_token> <chat_id>
  edgeboxctl alert discord <webhook_url>
  edgeboxctl alert wechat <pushplus_token>
  edgeboxctl alert webhook <url> [raw|slack|discord]
  edgeboxctl alert test <percent>

${YELLOW}备份恢复:${NC}
  edgeboxctl backup create                 创建备份
  edgeboxctl backup list                   列出备份
  edgeboxctl backup restore <file>         恢复备份

${YELLOW}系统:${NC}
  edgeboxctl update                        更新EdgeBox
  edgeboxctl help                          显示此帮助

${CYAN}EdgeBox 企业级多协议节点部署方案（含 Trojan-TLS）${NC}
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

# 预跑一次面板数据
[[ -x /etc/edgebox/scripts/panel-refresh.sh ]] && /etc/edgebox/scripts/panel-refresh.sh >> $LOG_FILE 2>&1 || true

# 预跑一次采集器，生成 JSON 和 CSV
[[ -x /etc/edgebox/scripts/traffic-collector.sh ]] && /etc/edgebox/scripts/traffic-collector.sh >> $LOG_FILE 2>&1 || true

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
# 完整安装流程
#############################################

# 显示安装信息
show_installation_info() {
    clear
    print_separator
    echo -e "${GREEN}🎉 EdgeBox 企业级多协议节点 v3.0.0 安装完成！${NC}"
    print_separator
    
    echo -e "${CYAN}服务器信息：${NC}"
	echo -e "  证书模式: ${PURPLE}IP模式（自签名证书）${NC}"
    echo -e "  IP地址: ${PURPLE}${SERVER_IP}${NC}"
    echo -e "  版本号: ${PURPLE}EdgeBox v3.0.0 企业级完整版（含 Trojan-TLS）${NC}"

    echo -e "\n${CYAN}协议信息：${NC}"
    echo -e "  VLESS-Reality  端口: 443  UUID: ${PURPLE}${UUID_VLESS}${NC}"
    echo -e "  VLESS-gRPC     端口: 443  UUID: ${PURPLE}${UUID_VLESS}${NC}"  
    echo -e "  VLESS-WS       端口: 443  UUID: ${PURPLE}${UUID_VLESS}${NC}"
    echo -e "  Trojan-TLS     端口: 443  密码: ${PURPLE}${PASSWORD_TROJAN}${NC}"
    echo -e "  Hysteria2      端口: 443  密码: ${PURPLE}${PASSWORD_HYSTERIA2}${NC}"
    echo -e "  TUIC           端口: 2053 UUID: ${PURPLE}${UUID_TUIC}${NC}"
       
    echo -e "\n${CYAN}访问地址：${NC}"
    echo -e "  🌐 控制面板: ${PURPLE}http://${SERVER_IP}/${NC}" #订阅链接\流量统计\运维命令
    
    echo -e "\n${CYAN}高级运维：${NC}"
	echo -e "  模式切换: IP模式 ⇋ 域名模式"
    echo -e "  出站分流: 住宅IP全量 ⇋ VPS全量出 ⇋ 白名单VPS出+非白名单住宅IP出"
    echo -e "  流量监控: 日分流出站曲线图，日高流量协议/端口曲线图，月累计图"
    echo -e "  预警通知: 流量阈值分级30%、60%、90%告警"
    echo -e "  自动备份: 每日自动备份，故障快速恢复"
    
    echo -e "\n${CYAN}管理命令：${NC}"
    echo -e "  ${PURPLE}edgeboxctl status${NC}                     # 查看服务状态"
    echo -e "  ${PURPLE}edgeboxctl sub${NC}                        # 查看订阅链接"
    echo -e "  ${PURPLE}edgeboxctl switch-to-domain <域名> ${NC}    # 切换到域名模式"
    echo -e "  ${PURPLE}edgeboxctl shunt direct-resi IP:PORT${NC}  # 智能分流"
    echo -e "  ${PURPLE}edgeboxctl traffic show${NC}               # 查看流量统计"
    echo -e "  ${PURPLE}edgeboxctl backup create${NC}              # 手动备份"
    echo -e "  ${PURPLE}edgeboxctl help${NC}                       # 查看完整帮助"
    
    echo -e "\n${YELLOW}重要提醒：${NC}"
    echo -e "  1. 当前为IP模式，VLESS/Trojan协议需在客户端开启'跳过证书验证'"
    echo -e "  2. 使用 switch-to-domain 可获得受信任证书（含 trojan 子域名）"
    echo -e "  3. 流量预警配置: ${TRAFFIC_DIR}/alert.conf"
    echo -e "  4. 安装日志: ${LOG_FILE}"
	echo -e " "
}

# 清理函数
cleanup() {
    if [ "$?" -ne 0 ]; then
        log_error "安装过程中出现错误，请检查日志: ${LOG_FILE}"
        echo -e "${YELLOW}如需重新安装，请先运行: bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/uninstall.sh)${NC}"
    fi
    rm -f /tmp/Xray-linux-64.zip 2>/dev/null || true
    rm -f /tmp/sing-box-*.tar.gz 2>/dev/null || true
}

# 主安装流程
main() {
    clear
    print_separator
    echo -e "${GREEN}EdgeBox 企业级安装脚本 v3.0.0${NC}"
    echo -e "${CYAN}完整版：SNI定向 + 证书切换 + 出站分流 + 流量统计 + 流量预警 + 备份恢复 + Trojan-TLS${NC}"
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
	create_enhanced_edgeboxctl
    create_init_script

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
	
	# 在安装收尾输出总结信息（原来没调用）
    show_installation_info
}

# 执行主函数
main "$@"
