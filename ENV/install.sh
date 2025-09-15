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
# EdgeBox 企业级多协议节点部署脚本
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

log_debug() {
    echo -e "${RED}[DEBUG]${NC} $1" | tee -a ${LOG_FILE}
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
    log_info "正在安装系统依赖..."
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true

    # 必要包
    local pkgs=(curl wget unzip gawk ca-certificates jq bc uuid-runtime dnsutils openssl \
              vnstat nginx libnginx-mod-stream nftables certbot python3-certbot-nginx \
              msmtp-mta bsd-mailx cron tar)
    
    for pkg in "${pkgs[@]}"; do
        if ! dpkg -l | grep -q "^ii.*${pkg}"; then
            log_info "安装 ${pkg}..."
            # 修正：移除静默处理，确保能看到具体错误
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}"
        else
            log_info "${pkg} 已安装"
        fi
    done
    
    # 新增：在安装后再次检查 jq 是否存在
    if ! command -v jq &> /dev/null; then
        log_error "jq 安装失败，无法继续。请检查您的网络连接或软件源。"
        return 1
    fi

    # 启用和启动服务
    systemctl enable vnstat >/dev/null 2>&1 || true
    systemctl start  vnstat  >/dev/null 2>&1 || true

    systemctl enable nftables >/dev/null 2>&1 || true
    systemctl start  nftables  >/dev/null 2>&1 || true

    log_success "依赖安装完成。"
    return 0
}

# 修复后的 generate_credentials 函数
generate_credentials() {
    log_info "正在生成 UUID 和密码..."
    if ! command -v uuidgen &> /dev/null; then
        log_error "uuidgen 未安装，请先安装: apt-get install -y uuid-runtime"
        return 1
    fi
    
    # 为每种协议生成独立的 UUID
    UUID_VLESS_REALITY=$(uuidgen)
    UUID_VLESS_GRPC=$(uuidgen)
    UUID_VLESS_WS=$(uuidgen)
    UUID_HYSTERIA2=$(uuidgen)
    UUID_TUIC=$(uuidgen)
    UUID_TROJAN=$(uuidgen)

    # 为了兼容性，保留通用UUID变量
    UUID_VLESS="$UUID_VLESS_REALITY"

    # 生成密码
    PASSWORD_TROJAN=$(openssl rand -base64 24)
    PASSWORD_TUIC=$(openssl rand -base64 24)
    PASSWORD_HYSTERIA2=$(openssl rand -base64 24)

    # 验证生成结果
    if [[ -z "$UUID_VLESS_REALITY" || -z "$PASSWORD_TROJAN" || -z "$PASSWORD_HYSTERIA2" ]]; then
        log_error "UUID 或密码生成失败！"
        return 1
    fi

    log_success "凭据生成完成："
    log_success "VLESS-REALITY: ${UUID_VLESS_REALITY}"
    log_success "VLESS-gRPC   : ${UUID_VLESS_GRPC}"
    log_success "VLESS-WS     : ${UUID_VLESS_WS}"
    log_success "TUIC UUID    : ${UUID_TUIC}"
    log_success "Trojan 密码  : ${PASSWORD_TROJAN:0:8}..."
    log_success "Hysteria2    : ${PASSWORD_HYSTERIA2:0:8}..."
    log_success "TUIC 密码    : ${PASSWORD_TUIC:0:8}..."
    
    return 0
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

# 生成Reality密钥对（含 shortId）
generate_reality_keys() {
  log_info "正在生成 Reality 密钥对..."
  local out
  out="$(sing-box generate reality-keypair)" || { log_error "Reality 密钥生成失败！"; return 1; }

  # 提取私钥、公钥
  REALITY_PRIVATE_KEY="$(printf '%s\n' "$out" | grep -oP 'PrivateKey: \K[a-zA-Z0-9_-]+')"
  REALITY_PUBLIC_KEY="$(printf '%s\n' "$out" | grep -oP 'PublicKey: \K[a-zA-Z0-9_-]+')"

  # 生成 shortId（8~16 个十六进制，Reality 推荐 8 或 10）
  # 用 openssl 更稳：确保十六进制
  REALITY_SHORT_ID="$(openssl rand -hex 8 | cut -c1-8)"

  if [[ -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_PUBLIC_KEY" || -z "$REALITY_SHORT_ID" ]]; then
    log_error "Reality 关键信息生成不完整(PRI/PUB/shortId)，中止。"
    return 1
  fi

  log_success "Reality 密钥对生成完成，shortId=${REALITY_SHORT_ID}"
}

# 配置Nginx（SNI定向 + ALPN兜底架构）
configure_nginx() {
  log_info "配置 Nginx（Nginx-first · SNI+ALPN 分流）..."

  [[ -f /etc/nginx/nginx.conf ]] && cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak

  cat > /etc/nginx/nginx.conf <<'NGINX_CONF'
# ----- 全局/模块 -----
user  www-data;
worker_processes  auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events { worker_connections 1024; }

http {
  include       /etc/nginx/mime.types;
  default_type  application/octet-stream;
  sendfile      on;
  access_log    /var/log/nginx/access.log;
  error_log     /var/log/nginx/error.log warn;

  server {
    listen 0.0.0.0:80  default_server;
    listen [::]:80     default_server;
    server_name _;

    # 根路径跳转到面板
    location = / { return 302 /traffic/; }

    # 只保留一个 /sub
    location = /sub {
      default_type text/plain;
      add_header Cache-Control "no-store" always;
      root /var/www/html;
    }

    # 控制面板与数据
    location ^~ /traffic/ {
      alias /etc/edgebox/traffic/;
      index  index.html;
      autoindex off;
      add_header Cache-Control "no-store" always;
      types { text/html html; application/json json; text/plain txt; }
    }

    # IP 质量状态（与文档口径一致：/status/ipq_*.json）
    location ^~ /status/ {
      alias /var/www/edgebox/status/;
      autoindex off;
      add_header Cache-Control "no-store" always;
      types { application/json json; text/plain txt; }
    }
  }
}

# ===== TCP/443：SNI + ALPN 分流（不终止 TLS）=====
stream {
  # 1) SNI 分类（Reality 伪装域名 / trojan 子域 / 内部占位域名）
  map $ssl_preread_server_name $svc {
    ~^(www\.cloudflare\.com|www\.apple\.com|www\.microsoft\.com)$  reality;
    ~*^trojan\.                                       trojan;
    grpc\.edgebox\.internal                           grpc;
    ws\.edgebox\.internal                             ws;
    default "";
  }

  # 2) ALPN -> 上游端口（gRPC/WS/Reality）
  map $ssl_preread_alpn_protocols $by_alpn {
    ~\bh2\b            127.0.0.1:10085;   # gRPC
    ~\bhttp/1\.1\b     127.0.0.1:10086;   # WebSocket
    default            127.0.0.1:11443;   # Reality
  }

  # 3) SNI 命中则用 SNI 对应端口，否则回落到 ALPN
  map $svc $upstream_sni {
    reality   127.0.0.1:11443;
    trojan    127.0.0.1:10143;
    grpc      127.0.0.1:10085;
    ws        127.0.0.1:10086;
    default   "";
  }
  map $upstream_sni $upstream { "" $by_alpn; default $upstream_sni; }

  server {
    listen 0.0.0.0:443 reuseport;  # 仅 TCP；UDP 443 留给 HY2
    ssl_preread on;
    proxy_pass $upstream;
    proxy_connect_timeout 5s;
    proxy_timeout 60s;
  }
}
NGINX_CONF

  nginx -t || return 1
  systemctl enable --now nginx
}

# 配置Xray
configure_xray() {
  log_info "配置 Xray..."

  # 校验必须变量
  if [[ -z "$UUID_VLESS_REALITY" || -z "$UUID_VLESS_GRPC" || -z "$UUID_VLESS_WS" || -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_SHORT_ID" || -z "$PASSWORD_TROJAN" ]]; then
    log_error "必要的配置变量未设置"
    return 1
  fi

  cat > "${CONFIG_DIR}/xray.json" <<'EOF'
{
  "log": { "loglevel": "warning", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log" },
  "inbounds": [
    {
      "tag": "VLESS-Reality",
      "listen": "127.0.0.1",
      "port": 11443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "__UUID_VLESS_REALITY__", "flow": "xtls-rprx-vision", "email": "reality@edgebox" }
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
          "serverNames": ["www.cloudflare.com","www.microsoft.com","www.apple.com"],
          "privateKey": "__REALITY_PRIVATE_KEY__",
          "shortIds": ["__REALITY_SHORT_ID__"]
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
          { "id": "__UUID_VLESS_GRPC__", "email": "grpc-internal@edgebox" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": { "alpn": ["h2"], "certificates": [{ "certificateFile": "__CERT_PEM__", "keyFile": "__CERT_KEY__" }] },
        "grpcSettings": { "serviceName": "grpc", "multiMode": true }
      }
    },
    {
      "tag": "VLESS-WS-Internal",
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "__UUID_VLESS_WS__", "email": "ws-internal@edgebox" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": { "alpn": ["http/1.1"], "certificates": [{ "certificateFile": "__CERT_PEM__", "keyFile": "__CERT_KEY__" }] },
        "wsSettings": { "path": "/ws" }
      }
    },
    {
      "tag": "Trojan-TLS-Internal",
      "listen": "127.0.0.1", "port": 10143, "protocol": "trojan",
      "settings": { "clients": [{ "password": "__PASSWORD_TROJAN__", "email": "trojan-internal@edgebox" }] },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": { "alpn": ["http/1.1","h2"], "certificates": [{ "certificateFile": "__CERT_PEM__", "keyFile": "__CERT_KEY__" }] }
      }
    }
  ],
  "outbounds": [{ "protocol": "freedom", "settings": {} }],
  "routing": { "rules": [] }
}
EOF

  # 替换占位符
  sed -i \
    -e "s#__UUID_VLESS_REALITY__#${UUID_VLESS_REALITY}#g" \
    -e "s#__UUID_VLESS_GRPC__#${UUID_VLESS_GRPC}#g" \
    -e "s#__UUID_VLESS_WS__#${UUID_VLESS_WS}#g" \
    -e "s#__REALITY_PRIVATE_KEY__#${REALITY_PRIVATE_KEY}#g" \
    -e "s#__REALITY_SHORT_ID__#${REALITY_SHORT_ID}#g" \
    -e "s#__CERT_PEM__#${CERT_DIR}/current.pem#g" \
    -e "s#__CERT_KEY__#${CERT_DIR}/current.key#g" \
    -e "s#__PASSWORD_TROJAN__#${PASSWORD_TROJAN}#g" \
    "${CONFIG_DIR}/xray.json"
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
# 修复后的 save_config_info 函数
save_config_info() {
    log_info "保存配置信息..."
    mkdir -p "${CONFIG_DIR}"

    # 确保所有必要变量都有值
    local server_ip="${SERVER_IP:-}"
    local version="${EDGEBOX_VER:-3.0.0}"
    local install_date="$(date +%Y-%m-%d)"
    
    # UUID变量检查和默认值
    local vless_reality="${UUID_VLESS_REALITY:-$UUID_VLESS}"
    local vless_grpc="${UUID_VLESS_GRPC:-$UUID_VLESS}"
    local vless_ws="${UUID_VLESS_WS:-$UUID_VLESS}"
    local tuic_uuid="${UUID_TUIC:-}"
    
    # 密码变量检查
    local trojan_pass="${PASSWORD_TROJAN:-}"
    local tuic_pass="${PASSWORD_TUIC:-}"
    local hy2_pass="${PASSWORD_HYSTERIA2:-}"
    
    # Reality变量检查
    local reality_pub="${REALITY_PUBLIC_KEY:-}"
    local reality_pri="${REALITY_PRIVATE_KEY:-}"
    local reality_sid="${REALITY_SHORT_ID:-}"

    # 验证关键字段
    if [[ -z "$server_ip" ]]; then
        log_error "SERVER_IP 为空"
        return 1
    fi

    # 生成配置JSON
    jq -n \
      --arg ip "$server_ip" \
      --arg vm "$version" \
      --arg inst "$install_date" \
      --arg vr "$vless_reality" \
      --arg vg "$vless_grpc" \
      --arg vw "$vless_ws" \
      --arg tu "$tuic_uuid" \
      --arg tt "$trojan_pass" \
      --arg tp "$tuic_pass" \
      --arg hy "$hy2_pass" \
      --arg rpub "$reality_pub" \
      --arg rpri "$reality_pri" \
      --arg rsid "$reality_sid" \
      '{
        server_ip: $ip,
        version: $vm,
        install_date: $inst,
        uuid: {
          vless: {
            reality: $vr,
            grpc: $vg,
            ws: $vw
          },
          tuic: $tu
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
        }
      }' > "${CONFIG_DIR}/server.json"

    # 验证生成的JSON
    if ! jq '.' "${CONFIG_DIR}/server.json" >/dev/null 2>&1; then
        log_error "生成的 server.json 格式错误"
        return 1
    fi

    log_success "配置已写入 ${CONFIG_DIR}/server.json"
    log_debug "server_ip: $server_ip, reality_key: ${reality_pub:0:20}..."
}

# 安全同步订阅文件：/var/www/html/sub 做符号链接；traffic 下保留一份副本
sync_subscription_files() {
  log_info "同步订阅文件..."
  mkdir -p "${WEB_ROOT}" "${TRAFFIC_DIR}"

  local src="${CONFIG_DIR}/subscription.txt"
  if [[ ! -s "$src" ]]; then
    log_warn "订阅源不存在：$src"
    return 0
  fi

  # Web 目录使用软链接，避免再出现“same file”报错
  ln -sfn "$src" "${WEB_ROOT}/sub"
  # traffic 下保留一份副本用于 dashboard-backend
  install -m 0644 -T "$src" "${TRAFFIC_DIR}/sub.txt"

  log_success "订阅同步完成：${WEB_ROOT}/sub -> ${src}，以及 ${TRAFFIC_DIR}/sub.txt"
}

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

# 修复后的 generate_subscription 函数
generate_subscription() {
  local cfg="${CONFIG_DIR}/server.json"
  [[ -s "$cfg" ]] || { log_error "缺少 ${cfg}"; return 1; }

  # 确保 server.json 存在且格式正确
  if ! jq '.' "$cfg" >/dev/null 2>&1; then
    log_error "server.json 格式错误"
    return 1
  fi

  local j='jq -r'
  local ip reality_pbk reality_sid
  local uuid_reality uuid_grpc uuid_ws uuid_tuic
  local trojan_pw hy2_pw tuic_pw

  # 读取基础信息
  ip=$($j '.server_ip // empty' "$cfg")
  [[ -z "$ip" || "$ip" == "null" ]] && ip="$SERVER_IP"
  
  # 读取 Reality 配置
  reality_pbk=$($j '.reality.public_key // empty' "$cfg")
  reality_sid=$($j '.reality.short_id // empty' "$cfg")

  # 读取 UUID - 支持新旧格式
  uuid_reality=$($j '.uuid.vless.reality // .uuid.vless // empty' "$cfg")
  uuid_grpc=$($j '.uuid.vless.grpc // .uuid.vless // empty' "$cfg")  
  uuid_ws=$($j '.uuid.vless.ws // .uuid.vless // empty' "$cfg")
  uuid_tuic=$($j '.uuid.tuic // empty' "$cfg")

  # 如果分别的UUID为空，使用通用UUID
  [[ -z "$uuid_reality" ]] && uuid_reality="${UUID_VLESS_REALITY:-$UUID_VLESS}"
  [[ -z "$uuid_grpc" ]] && uuid_grpc="${UUID_VLESS_GRPC:-$UUID_VLESS}"
  [[ -z "$uuid_ws" ]] && uuid_ws="${UUID_VLESS_WS:-$UUID_VLESS}"

  # 读取密码
  trojan_pw=$($j '.password.trojan // empty' "$cfg")
  hy2_pw=$($j '.password.hysteria2 // empty' "$cfg")
  tuic_pw=$($j '.password.tuic // empty' "$cfg")

  # 如果JSON中没有，使用全局变量
  [[ -z "$trojan_pw" ]] && trojan_pw="$PASSWORD_TROJAN"
  [[ -z "$hy2_pw" ]] && hy2_pw="$PASSWORD_HYSTERIA2"
  [[ -z "$tuic_pw" ]] && tuic_pw="$PASSWORD_TUIC"
  [[ -z "$reality_pbk" ]] && reality_pbk="$REALITY_PUBLIC_KEY"
  [[ -z "$reality_sid" ]] && reality_sid="$REALITY_SHORT_ID"

  # 验证必要字段
  if [[ -z "$ip" ]]; then
    log_error "服务器IP为空"
    return 1
  fi

  # URL 编码函数
  uri() { 
    local str="$1"
    printf '%s' "$str" | jq -nr --arg s "$str" '$s|@uri'
  }

  # 生成订阅内容
  local plain=""
  
  # VLESS-Reality
  if [[ -n "$uuid_reality" && -n "$reality_pbk" && -n "$reality_sid" ]]; then
    plain+="vless://${uuid_reality}@${ip}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${reality_pbk}&sid=${reality_sid}&type=tcp#EdgeBox-REALITY\n"
  fi
  
  # VLESS-gRPC
  if [[ -n "$uuid_grpc" ]]; then
    plain+="vless://${uuid_grpc}@${ip}:443?encryption=none&security=tls&sni=grpc.edgebox.internal&alpn=h2&type=grpc&serviceName=grpc&fp=chrome&allowInsecure=1#EdgeBox-gRPC\n"
  fi
  
  # VLESS-WS
  if [[ -n "$uuid_ws" ]]; then
    plain+="vless://${uuid_ws}@${ip}:443?encryption=none&security=tls&sni=ws.edgebox.internal&host=ws.edgebox.internal&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome&allowInsecure=1#EdgeBox-WS\n"
  fi
  
  # Trojan
  if [[ -n "$trojan_pw" ]]; then
    plain+="trojan://$(uri "$trojan_pw")@${ip}:443?security=tls&sni=trojan.edgebox.internal&alpn=http%2F1.1&fp=chrome&allowInsecure=1#EdgeBox-TROJAN\n"
  fi
  
  # Hysteria2
  if [[ -n "$hy2_pw" ]]; then
    plain+="hysteria2://$(uri "$hy2_pw")@${ip}:443?sni=${ip}&alpn=h3&insecure=1#EdgeBox-HYSTERIA2\n"
  fi
  
  # TUIC
  if [[ -n "$uuid_tuic" && -n "$tuic_pw" ]]; then
    plain+="tuic://${uuid_tuic}:$(uri "$tuic_pw")@${ip}:2053?congestion_control=bbr&alpn=h3&sni=${ip}&allowInsecure=1#EdgeBox-TUIC\n"
  fi

  if [[ -z "$plain" ]]; then
    log_error "生成的订阅内容为空，请检查配置"
    return 1
  fi

  # 写入订阅文件
  printf "%b" "$plain" > "${CONFIG_DIR}/subscription.txt"
  
  # 确保目录存在
  mkdir -p "${TRAFFIC_DIR}" "${WEB_ROOT}"
  
  # 同步到各个位置
  install -m0644 -T "${CONFIG_DIR}/subscription.txt" "${TRAFFIC_DIR}/sub.txt"
  install -m0644 -T "${CONFIG_DIR}/subscription.txt" "${WEB_ROOT}/sub"
  
  log_success "订阅已生成：${#plain} 字符，包含 $(printf "%b" "$plain" | grep -c '^[a-z]') 个协议"
  log_debug "订阅内容预览：$(printf "%b" "$plain" | head -n 2)"
}

# >>> 修复后的 install_scheduled_dashboard_backend 函数 >>>
install_scheduled_dashboard_backend() {
  mkdir -p /etc/edgebox/scripts /etc/edgebox/traffic /etc/edgebox/config

  cat >/etc/edgebox/scripts/dashboard-backend.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

TRAFFIC_DIR=/etc/edgebox/traffic
CONF_DIR=/etc/edgebox/config
SHUNT_DIR=$CONF_DIR/shunt
STATUS_DIR=/var/www/edgebox/status

OUT_DASH=$TRAFFIC_DIR/dashboard.json
OUT_SYS=$TRAFFIC_DIR/system.json

ts(){ date -Is; }
jqr(){ jq -r "$1" 2>/dev/null || true; }

# ---------- 读取服务器侧静态信息（如有） ----------
SERVER_JSON="$CONF_DIR/server.json"
USER_ALIAS=$( [ -s "$SERVER_JSON" ] && jqr '.user_alias // .alias // .name // empty' < "$SERVER_JSON" || echo "" )
CLOUD_VENDOR=$( [ -s "$SERVER_JSON" ] && jqr '.cloud.vendor // .cloud_provider // .provider // empty' < "$SERVER_JSON" || echo "" )
CLOUD_REGION=$( [ -s "$SERVER_JSON" ] && jqr '.cloud.region // .region // empty' < "$SERVER_JSON" || echo "" )
INSTANCE_ID=$( [ -s "$SERVER_JSON" ] && jqr '.instance_id // .instance // .id // empty' < "$SERVER_JSON" || echo "" )
HOSTNAME=$( [ -s "$SERVER_JSON" ] && jqr '.hostname // .host // empty' < "$SERVER_JSON" || hostname )

VERSION_FILE=/etc/edgebox/version
VERSION=$( [ -s "$VERSION_FILE" ] && cat "$VERSION_FILE" || echo "3.0.0" )
INSTALLED_AT_FILE=/etc/edgebox/installed_at
[ -s "$INSTALLED_AT_FILE" ] || date -Is > "$INSTALLED_AT_FILE"
INSTALLED_AT=$(cat "$INSTALLED_AT_FILE")

# ---------- 公网 IP（优先用 IPQ 的 vps 出口） ----------
PUBIP=""
[ -s "$STATUS_DIR/ipq_vps.json" ] && PUBIP=$(jq -r '.ip // empty' "$STATUS_DIR/ipq_vps.json")
[ -n "$PUBIP" ] || PUBIP=$(curl -fsS --max-time 4 https://ipinfo.io/ip || true)

# ---------- 服务状态 & 版本 ----------
svc_status(){ systemctl is-active --quiet "$1" && echo "active" || echo "inactive"; }
svc_ver_nginx(){ nginx -v 2>&1 | sed -n 's#.*nginx/##p'; }
svc_ver_xray(){ xray -version 2>/dev/null | awk 'NR==1{print $2}'; }
svc_ver_sing(){ sing-box version 2>/dev/null | awk 'NR==1{print $2}'; }

NGINX_STATUS=$(svc_status nginx || true)
XRAY_STATUS=$(svc_status xray || true)
SING_STATUS=$(svc_status sing-box || svc_status singbox || true)

NGINX_VER=$(svc_ver_nginx || true)
XRAY_VER=$(svc_ver_xray || true)
SING_VER=$(svc_ver_sing || true)

# ---------- 分流信息 ----------
WHITELIST_FILE="$SHUNT_DIR/whitelist.txt"
STATE_JSON="$SHUNT_DIR/state.json"

WHITELIST=$([ -s "$WHITELIST_FILE" ] \
  && jq -R -s 'split("\n")|map(select(length>0))' "$WHITELIST_FILE" \
  || echo '[]')
SHUNT_MODE=$([ -s "$STATE_JSON" ] && jq -r '.mode // empty' "$STATE_JSON" || echo "")
PROXY_INFO=$([ -s "$STATE_JSON" ] && jq -r '.proxy_info // empty' "$STATE_JSON" || echo "")

# ---------- 订阅 ----------
SUB_FILE="$TRAFFIC_DIR/sub"
PLAIN=$([ -s "$SUB_FILE" ] && cat "$SUB_FILE" || echo "")
B64_LINES=$([ -s "$SUB_FILE" ] && base64 -w 76 "$SUB_FILE" || echo "")
B64_ALL=$([ -s "$SUB_FILE" ] && base64 -w 0 "$SUB_FILE" || echo "")

# ---------- 协议（有 protocols.json 就用；否则兜底三行） ----------
PROTOS="[]"
if [ -s "$CONF_DIR/protocols.json" ]; then
  PROTOS=$(cat "$CONF_DIR/protocols.json")
else
  PROTOS=$(jq -n '
  [
    {name:"VLESS/Trojan (443/TCP)", proto:"TCP", disguise:"SNI/ALPN 分流", scene:"通用",  proc:(env.NGINX_STATUS=="active"?"listening":"stopped")},
    {name:"Hysteria2",              proto:"UDP", disguise:"QUIC",        scene:"弱网/移动", proc:(env.SING_STATUS=="active"?"listening":"stopped")},
    {name:"TUIC",                   proto:"UDP", disguise:"QUIC",        scene:"弱网/移动", proc:(env.SING_STATUS=="active"?"listening":"stopped")}
  ]')
fi

# ---------- 输出 dashboard.json ----------
jq -n \
  --arg updated_at "$(ts)" \
  --arg ua "$USER_ALIAS" \
  --arg cv "$CLOUD_VENDOR" \
  --arg cr "$CLOUD_REGION" \
  --arg iid "$INSTANCE_ID" \
  --arg hn "$HOSTNAME" \
  --arg ver "$VERSION" \
  --arg inst "$INSTALLED_AT" \
  --arg pubip "$PUBIP" \
  --arg nginx_s "$NGINX_STATUS" --arg xray_s "$XRAY_STATUS" --arg sing_s "$SING_STATUS" \
  --arg nginx_v "$NGINX_VER" --arg xray_v "$XRAY_VER" --arg sing_v "$SING_VER" \
  --argjson whitelist "$WHITELIST" \
  --arg mode "$SHUNT_MODE" \
  --arg proxy "$PROXY_INFO" \
  --arg plain "$PLAIN" --arg b64 "$B64_ALL" --arg b64l "$B64_LINES" \
  --argjson protocols "$PROTOS" '
{
  updated_at: $updated_at,
  server: {
    user_alias: $ua,
    cloud: { vendor: $cv, region: $cr },
    instance_id: $iid,
    hostname: $hn,
    version: $ver,
    installed_at: $inst,
    public_ip: $pubip
  },
  services: {
    nginx: $nginx_s,
    xray: $xray_s,
    "sing-box": $sing_s,
    versions: { nginx: $nginx_v, xray: $xray_v, "sing-box": $sing_v }
  },
  protocols: $protocols,
  shunt: { mode: $mode, whitelist: $whitelist, proxy_info: ($proxy|select(.!="")) },
  subscription: { plain: $plain, base64: $b64, b64_lines: $b64l }
}' > "$OUT_DASH"

# ---------- 输出 system.json ----------
cpu_pct(){
  read -r c1 i1 < <(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
  sleep 0.3
  read -r c2 i2 < <(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
  awk -v a=$c1 -v b=$c2 -v x=$i1 -v y=$i2 'BEGIN{u=((b-a)-(y-x))*100/(b-a); if(u<0)u=0; if(u>100)u=100; printf("%.0f",u)}'
}
MEM_PCT=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2} END{if(t>0){printf("%.0f",(t-a)*100/t)}else{print 0}}' /proc/meminfo)
DISK_PCT=$(df -P / | awk 'NR==2{gsub("%","");print $5}')
CPU_PCT=$(cpu_pct)

CPU_INFO=$(lscpu 2>/dev/null | awk -F: '/Model name|Socket|Core|Thread/{gsub(/^ +/,"",$2);print}' | paste -sd' / ' - 2>/dev/null || echo "$(nproc) vCPU")
MEM_INFO=$(free -h --si | awk '/Mem:/{print $2" 总内存"}')
DISK_INFO=$(df -h -P / | awk 'NR==2{print $2" 总量"}')

jq -n --argjson cpu "$CPU_PCT" \
      --argjson memory "$MEM_PCT" \
      --argjson disk "$DISK_PCT" \
      --arg cpu_info "$CPU_INFO" \
      --arg memory_info "$MEM_INFO" \
      --arg disk_info "$DISK_INFO" \
      '{cpu: $cpu, memory: $memory, disk: $disk, cpu_info: $cpu_info, memory_info: $memory_info, disk_info: $disk_info}' \
      > "$OUT_SYS"
EOF

  chmod +x /etc/edgebox/scripts/dashboard-backend.sh
  log_success "dashboard-backend.sh 已写入并可执行"
}

#############################################
# 模块3：高级运维功能安装
#############################################

# 设置流量监控系统
#!/bin/bash
# 修复后的流量监控设置函数

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

# 3. 面板数据刷新（修复订阅和白名单数据获取）
cat > "${SCRIPTS_DIR}/panel-refresh.sh" <<'PANEL'
#!/bin/bash
set -euo pipefail
TRAFFIC_DIR="/etc/edgebox/traffic"
SCRIPTS_DIR="/etc/edgebox/scripts"
SHUNT_DIR="/etc/edgebox/config/shunt"
CONFIG_DIR="/etc/edgebox/config"
mkdir -p "$TRAFFIC_DIR"

# --- 基本信息 ---
srv_json="${CONFIG_DIR}/server.json"
if [[ -s "$srv_json" ]]; then
  server_ip="$(jq -r '.server_ip // empty' "$srv_json" 2>/dev/null)"
  version="$(jq -r '.version // empty' "$srv_json" 2>/dev/null)"
  install_date="$(jq -r '.install_date // empty' "$srv_json" 2>/dev/null)"
else
  server_ip="$(hostname -I | awk '{print $1}' || echo '127.0.0.1')"
  version="v3.0.0"
  install_date="$(date +%F)"
fi

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
  mode="$(jq -r '.mode // "vps"' "$state_json" 2>/dev/null)"
  proxy="$(jq -r '.proxy_info // ""' "$state_json" 2>/dev/null)"
  health="$(jq -r '.health // "unknown"' "$state_json" 2>/dev/null)"
fi
# 修复白名单数据获取
if [[ -s "${SHUNT_DIR}/whitelist.txt" ]]; then
  wl_count="$(wc -l < "${SHUNT_DIR}/whitelist.txt" 2>/dev/null || echo 0)"
  whitelist_json="$(cat "${SHUNT_DIR}/whitelist.txt" | jq -R -s 'split("\n")|map(select(length>0))' 2>/dev/null || echo '[]')"
else
  # 创建默认白名单
  mkdir -p "${SHUNT_DIR}"
  echo -e "googlevideo.com\nytimg.com\nggpht.com\nyoutube.com\nyoutu.be\ngoogleapis.com\ngstatic.com" > "${SHUNT_DIR}/whitelist.txt"
  wl_count=7
  whitelist_json='["googlevideo.com","ytimg.com","ggpht.com","youtube.com","youtu.be","googleapis.com","gstatic.com"]'
fi

# --- 协议配置（检测监听端口/进程，做成一览表） ---
SS="$(ss -H -lnptu 2>/dev/null || true)"
has_listen() { # proto port keyword_in_process
  local proto="$1" port="$2" kw="$3"
  echo "$SS" | grep -E "(^| )$proto .*:$port " | grep -qi "$kw"
}

# 检查各协议状态
has_tcp443="false"; has_hy2="false"; has_tuic="false"
has_listen tcp 443 "nginx" && has_tcp443="true"
(has_listen udp 443 "sing-box" || has_listen udp 8443 "sing-box" || has_listen udp 443 "hysteria") && has_hy2="true"
has_listen udp 2053 "sing-box" && has_tuic="true"

# --- 订阅数据获取（修复数据获取问题） ---
sub_plain=""
sub_b64=""
sub_b64_lines=""

# 优先从权威订阅文件读取
if [[ -s "${CONFIG_DIR}/subscription.txt" ]]; then
  sub_plain="$(cat "${CONFIG_DIR}/subscription.txt")"
elif [[ -s "/var/www/html/sub" ]]; then
  sub_plain="$(cat "/var/www/html/sub")"
elif [[ -s "${TRAFFIC_DIR}/sub.txt" ]]; then
  sub_plain="$(cat "${TRAFFIC_DIR}/sub.txt")"
fi

# 生成 base64 编码
if [[ -n "$sub_plain" ]]; then
  if base64 --help 2>&1 | grep -q -- ' -w'; then
    sub_b64="$(printf '%s\n' "$sub_plain" | base64 -w0)"
  else
    sub_b64="$(printf '%s\n' "$sub_plain" | base64 | tr -d '\n')"
  fi
  
  # 生成逐行 base64
  temp_file="$(mktemp)"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if base64 --help 2>&1 | grep -q -- ' -w'; then
      printf '%s' "$line" | sed -e '$a\' | base64 -w0
    else
      printf '%s' "$line" | sed -e '$a\' | base64 | tr -d '\n'
    fi
    printf '\n'
  done <<<"$sub_plain" > "$temp_file"
  sub_b64_lines="$(cat "$temp_file")"
  rm -f "$temp_file"
  
  # 确保订阅文件同步
  [[ ! -s "${TRAFFIC_DIR}/sub.txt" ]] && printf '%s\n' "$sub_plain" > "${TRAFFIC_DIR}/sub.txt"
  [[ ! -s "/var/www/html/sub" ]] && printf '%s\n' "$sub_plain" > "/var/www/html/sub"
fi

# --- 从 server.json 提取敏感字段，生成 secrets 对象 ---
secrets_json="{}"
if [[ -s "$srv_json" ]]; then
  secrets_json="$(jq -c '{
    vless:{
      reality: (.uuid.vless.reality // .uuid.vless // ""),
      grpc:    (.uuid.vless.grpc    // .uuid.vless // ""),
      ws:      (.uuid.vless.ws      // .uuid.vless // "")
    },
    tuic_uuid: (.uuid.tuic // ""),
    password:{
      trojan:     (.password.trojan     // ""),
      hysteria2:  (.password.hysteria2  // ""),
      tuic:       (.password.tuic       // "")
    },
    reality:{
      public_key: (.reality.public_key // ""),
      short_id:   (.reality.short_id   // "")
    }
  }' "$srv_json" 2>/dev/null || echo "{}")"
fi

# --- 写 dashboard.json（统一数据源） ---
jq -n \
  --arg ts "$(date -Is)" \
  --arg ip "$server_ip" --arg eip "$eip" \
  --arg ver "$version" --arg inst "$install_date" \
  --arg cm "$cert_mode" --arg cd "$cert_domain" --arg ce "$cert_expire" \
  --arg mode "$mode" --arg proxy_info "$proxy" --arg health "$health" \
  --argjson whitelist "$whitelist_json" \
  --arg b1 "$has_tcp443" --arg b2 "$has_hy2" --arg b3 "$has_tuic" \
  --arg sub_p "$sub_plain" --arg sub_b "$sub_b64" --arg sub_l "$sub_b64_lines" \
  --argjson secrets "$secrets_json" \
  '{
    updated_at: $ts,
    server: {
      ip: $ip,
      eip: (if $eip=="" then null else $eip end),
      version: $ver,
      install_date: $inst,
      cert_mode: $cm,
      cert_domain: (if $cd=="" then null else $cd end),
      cert_expire: (if $ce=="" then null else $ce end)
    },
    protocols: [
      {name:"VLESS/Trojan (443/TCP)", proto:"tcp",  port:443,  proc:(if $b1=="true" then "listening" else "未监听" end), note:"443 端口状态"},
      {name:"Hysteria2",              proto:"udp",  port:0,    proc:(if $b2=="true" then "listening" else "未监听" end), note:"8443/443"},
      {name:"TUIC",                   proto:"udp",  port:2053, proc:(if $b3=="true" then "listening" else "未监听" end), note:"2053"}
    ],
    services: {
      nginx: "'$(systemctl is-active nginx 2>/dev/null || echo "inactive")'",
      xray: "'$(systemctl is-active xray 2>/dev/null || echo "inactive")'",
      "sing-box": "'$(systemctl is-active sing-box 2>/dev/null || echo "inactive")'"
    },
    shunt: {
      mode: $mode, 
      proxy_info: $proxy_info, 
      health: $health,
      whitelist: $whitelist    # 确保这里是 whitelist 而不是其他字段名
    },
    subscription: { plain: $sub_p, base64: $sub_b, b64_lines: $sub_l },
    secrets: $secrets
  }' > "${TRAFFIC_DIR}/dashboard.json"

# 写订阅复制链接
proto="http"; addr="$server_ip"
if [[ "$cert_mode" == "letsencrypt" && -n "$cert_domain" ]]; then proto="https"; addr="$cert_domain"; fi
echo "${proto}://${addr}/sub" > "${TRAFFIC_DIR}/sub.link"
PANEL
chmod +x "${SCRIPTS_DIR}/panel-refresh.sh"

# 4. 预警配置（默认）
cat > "${TRAFFIC_DIR}/alert.conf" <<'CONF'
# 月度预算（GiB）
ALERT_MONTHLY_GIB=100
# 邮件/Hook（可留空）
ALERT_EMAIL=
ALERT_WEBHOOK=
# 阈值（百分比，逗号分隔）
ALERT_STEPS=30,60,90
CONF

# 5. 预警脚本（读取 monthly.csv 与 alert.conf，阈值去重）
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

# 生成修复后的控制面板HTML
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
            <div class="small">公网身份: <span>代理</span></div>
            <div class="small">代理出站IP: <span id="proxy-out-ip">—</span></div>
            <div class="small">Geo: <span id="proxy-geo">—</span></div>
            <div class="small">IP质量检测: <span id="proxy-quality">—</span> <span class="detail-link" onclick="showIPQDetails('proxy')">详情</span></div>
          </div>
          
          <!-- 分流出站内容 -->
          <div class="network-block">
            <h5>🔀 分流出站</h5>
            <div class="small">混合身份: <span class="status-running">白名单VPS直连 + 其它代理</span></div>
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
let _chartTraffic = null;
let _chartMonthly = null;
let _sysTicker = null;

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

// 更新本月进度条
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
      if (traffic && traffic.monthly && traffic.monthly.length > 0) {
        const current = traffic.monthly[traffic.monthly.length - 1];
        const used = (current.total || 0) / GiB;
        const pct = Math.min((used / budget) * 100, 100);
        
        document.getElementById('progress-fill').style.width = pct + '%';
        document.getElementById('progress-percentage').textContent = pct.toFixed(0) + '%';
        document.getElementById('progress-budget').textContent = used.toFixed(1) + '/' + budget + 'GiB';
      }
    }
  } catch (e) {
    console.warn('进度条更新失败:', e);
  }
}

// 主数据加载函数（统一从 dashboard.json / system.json / IPQ 读取）
async function loadData() {
  try {
    const [dashboard, traffic, alerts] = await Promise.all([
      getJSON('./dashboard.json'),
      getJSON('./traffic.json'),
      getJSON('./alerts.json').then(d => d || [])
    ]);

    // 服务器配置（供协议详情弹窗）
    const serverJson = await readServerConfig();
    window.serverConfig = serverJson || {};

    // 系统指标单独取
    const sys = await getJSON('./system.json');

    // IP 质量（与文档口径一致：/status/ipq_*.json）
    const [ipqVps, ipqProxy] = await Promise.all([
      getJSON('/status/ipq_vps.json').catch(() => null),
      getJSON('/status/ipq_proxy.json').catch(() => null),
    ]);

    // 统一模型
    const model = {
      updatedAt: dashboard?.updated_at || new Date().toISOString(),
      server: dashboard?.server || {},
      services: dashboard?.services || {},
      protocols: dashboard?.protocols || [],
      shunt: dashboard?.shunt || {},
      subscription: dashboard?.subscription || { plain: '', base64: '', b64_lines: '' },
      system: sys || {},
      ipq: { vps: ipqVps, proxy: ipqProxy }
    };

    renderHeader(model);
    renderProtocols(model);
    renderTraffic(traffic);
    renderAlerts(alerts);
  } catch (e) {
    console.error('loadData failed:', e);
    renderHeader({
      updatedAt: new Date().toISOString(),
      server: {},
      services: {},
      system: {}
    });
  }
}

// 渲染基本信息（兼容多口径）
function renderHeader(model) {
  const ts = model.updatedAt || new Date().toISOString();
  document.getElementById('updated').textContent = new Date(ts).toLocaleString('zh-CN');

  const s = model.server || {};
  const svc = model.services || {};
  const sys = model.system || {};

  // ---- 服务器信息：多口径兜底 ----
  const userAlias = s.user_alias || s.alias || s.name || '';
  const cloudVendor = s.cloud?.vendor || s.cloud_provider || s.provider || '';
  const cloudRegion = s.cloud?.region || s.region || '';
  const instanceId = s.instance_id || s.instance || s.id || '';
  const hostname = s.hostname || s.host || window.location.hostname;

  const cloudText = [cloudVendor, cloudRegion].filter(Boolean).join('/');
  document.getElementById('user-alias').textContent = userAlias || '—';
  document.getElementById('cloud-provider').textContent = cloudText || '—';
  document.getElementById('instance-id').textContent = instanceId || '—';
  document.getElementById('hostname').textContent = hostname || '—';

  // ---- 证书信息：兼容 server.cert.*
  const cert = s.cert || {};
  const mode = cert.mode || s.cert_mode || 'self-signed';
  const domain = cert.domain || s.cert_domain || '';
  const expire = cert.expires_at || cert.expire || s.cert_expire || '';

  document.getElementById('cert-type').textContent = (mode === 'letsencrypt') ? "Let's Encrypt" : '自签名证书';
  document.getElementById('cert-domain').textContent = domain || '无';
  document.getElementById('cert-renewal').textContent = (mode === 'letsencrypt') ? '自动续期' : '手动续期';
  document.getElementById('cert-expire').textContent =
    (expire && !isNaN(new Date(expire))) ? new Date(expire).toLocaleDateString('zh-CN') : '无';

  // ---- 版本与安装时间（兼容 meta/server 多口径）
  const ver = s.version || model.meta?.version || '';
  const inst = s.install_date || s.installed_at || model.meta?.installed_at || '';
  if (document.getElementById('ver'))  document.getElementById('ver').textContent = ver || '—';
  if (document.getElementById('inst')) document.getElementById('inst').textContent = inst || '—';

  // ---- 服务状态 + 版本（多口径）
  const getStatus = (obj) => (obj === 'active' || obj === 'running' || obj === true) ? 'active' : 'inactive';
  const getVersion = (name) => (
      svc?.versions?.[name] ||
      svc?.[name]?.version ||
      svc?.[`${name}_version`] ||
      ''
  );

  const renderSvc = (name, idStatus, idVer) => {
    const st = getStatus(svc[name] || svc?.[name]?.status);
    const el = document.getElementById(idStatus);
    if (el) el.innerHTML = st === 'active'
      ? '<span class="service-status-badge">运行中</span>'
      : '<span class="service-status-badge inactive">已停止</span>';
    const ve = document.getElementById(idVer);
    const v = getVersion(name);
    if (ve) ve.textContent = v ? ('v' + v) : '—';
  };

  renderSvc('nginx', 'nginx-status', 'nginx-version');
  renderSvc('xray', 'xray-status', 'xray-version');
  renderSvc('sing-box', 'singbox-status', 'singbox-version');

  // ---- CPU/内存/磁盘：直接用 model.system（已在 loadData 拉到）
  updateSystemBars(sys);
}

// 仅负责把 system 指标渲染到进度条（兼容多口径）
function updateSystemBars(sys) {
  const pickPct = (o, keys) => {
    for (const k of keys) {
      const v = o?.[k];
      if (Number.isFinite(+v)) return +v;
    }
    return 0;
  };
  const pickInfo = (o, keys) => {
    for (const k of keys) {
      const v = o?.[k];
      if (v) return v;
    }
    return '—';
  };

  const cpuPercent = Math.max(0, Math.min(100, Math.round(pickPct(sys, ['cpu','cpu_percent','cpu_usage']))));
  const memPercent = Math.max(0, Math.min(100, Math.round(pickPct(sys, ['memory','mem_percent','ram_percent']))));
  const diskPercent = Math.max(0, Math.min(100, Math.round(pickPct(sys, ['disk','disk_percent','fs_percent']))));

  const cpuDetail = pickInfo(sys, ['cpu_info','spec_cpu','cpu_spec']);
  const memDetail = pickInfo(sys, ['memory_info','spec_mem','mem_spec']);
  const diskDetail = pickInfo(sys, ['disk_info','spec_disk','disk_spec']);

  // CPU
  document.getElementById('cpu-progress-fill').style.width = cpuPercent + '%';
  document.getElementById('cpu-progress-text').textContent = cpuPercent + '%';
  document.getElementById('cpu-detail').textContent = cpuDetail;

  // MEM
  document.getElementById('mem-progress-fill').style.width = memPercent + '%';
  document.getElementById('mem-progress-text').textContent = memPercent + '%';
  document.getElementById('mem-detail').textContent = memDetail;

  // DISK
  document.getElementById('disk-progress-fill').style.width = diskPercent + '%';
  document.getElementById('disk-progress-text').textContent = diskPercent + '%';
  document.getElementById('disk-detail').textContent = diskDetail;
}

// 渲染协议区块 + 网络/IPQ/白名单/订阅
function renderProtocols(model) {
  // ---- 网络出站与 IPQ ----
  const ipqV = model.ipq?.vps || null;
  const ipqP = model.ipq?.proxy || null;

  // VPS 出站
  const vpsOutIp = document.getElementById('vps-out-ip');
  const vpsGeo = document.getElementById('vps-geo');
  const vpsQuality = document.getElementById('vps-quality');

  if (vpsOutIp) vpsOutIp.textContent = ipqV?.ip || model.server?.eip || model.server?.ip || '—';
  if (vpsGeo) vpsGeo.textContent = (ipqV && (ipqV.country || ipqV.city)) ? [ipqV.country, ipqV.city].filter(Boolean).join('-') : (model.shunt?.vps_geo || '—');
  if (vpsQuality) vpsQuality.textContent = (ipqV?.score != null) ? `${ipqV.grade || ''} (${ipqV.score})` : '—';

  // 代理出站
  const proxyOutIp = document.getElementById('proxy-out-ip');
  const proxyGeo = document.getElementById('proxy-geo');
  const proxyQuality = document.getElementById('proxy-quality');

  if (ipqP && !ipqP.status) {
    if (proxyOutIp) proxyOutIp.textContent = ipqP.ip || '—';
    if (proxyGeo) proxyGeo.textContent = (ipqP.country || ipqP.city) ? [ipqP.country, ipqP.city].filter(Boolean).join('-') : (model.shunt?.proxy_geo || '—');
    if (proxyQuality) proxyQuality.textContent = (ipqP?.score != null) ? `${ipqP.grade || ''} (${ipqP.score})` : '—';
  } else {
    if (proxyOutIp) proxyOutIp.textContent = '未配置';
    if (proxyGeo) proxyGeo.textContent = '—';
    if (proxyQuality) proxyQuality.textContent = '—';
  }

  // 白名单
  const whitelist = model.shunt?.whitelist || [];
  const whitelistText = Array.isArray(whitelist) && whitelist.length > 0
    ? whitelist.slice(0, 8).join(', ') + (whitelist.length > 8 ? '...' : '')
    : '(无)';
  const whitelistEl = document.getElementById('whitelist-text');
  if (whitelistEl) whitelistEl.textContent = whitelistText;

  // 订阅链接
  const sub = model.subscription || {};
  if (document.getElementById('sub-plain'))    document.getElementById('sub-plain').value = sub.plain || '';
  if (document.getElementById('sub-b64'))      document.getElementById('sub-b64').value = sub.base64 || '';
  if (document.getElementById('sub-b64lines')) document.getElementById('sub-b64lines').value = sub.b64_lines || '';

  // ---- 协议表格 ----
  const tbody = document.querySelector('#proto tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  // 优先使用后端下发的 protocols；没有就按服务状态兜底构造三行
  const svc = model.services || {};
  const list = Array.isArray(model.protocols) && model.protocols.length ? model.protocols : [
    { name: 'VLESS/Trojan (443/TCP)', proto: 'TCP',  disguise: 'SNI/ALPN 分流', scene: '通用',   proc: (svc.nginx==='active'?'listening':'未监听') },
    { name: 'Hysteria2',              proto: 'UDP',  disguise: 'QUIC',         scene: '弱网/移动', proc: (svc['sing-box']==='active'?'listening':'未监听') },
    { name: 'TUIC',                   proto: 'UDP',  disguise: 'QUIC',         scene: '弱网/移动', proc: (svc['sing-box']==='active'?'listening':'未监听') }
  ];

  list.forEach(p => {
    const running = (p.proc === 'listening' || p.status === 'active' || p.running === true);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${p.name || '—'}</td>
      <td>${p.proto || p.network || '—'}</td>
      <td>${p.disguise || p.note || '—'}</td>
      <td>${p.scene || '—'}</td>
      <td>${running ? '<span class="protocol-status-badge">监听中</span>' : '<span class="protocol-status-badge" style="background:#6b7280">未监听</span>'}</td>
      <td><button class="btn" onclick="showProtocolDetails('${(p.name||'').split(' ')[0] || 'VLESS-Reality'}')">查看配置</button></td>
    `;
    tbody.appendChild(tr);
  });
}

// 渲染流量图表
function renderTraffic(traffic) {
  if (!traffic) return;
  if (_chartTraffic) { _chartTraffic.destroy();  _chartTraffic = null; }
  if (_chartMonthly) { _chartMonthly.destroy();  _chartMonthly = null; }

  // 近30天流量图表
  if (traffic.last30d && traffic.last30d.length > 0) {
    const labels = traffic.last30d.map(function(x) { return x.date; });
    const vps = traffic.last30d.map(function(x) { return (x.vps || 0) / GiB; });
    const resi = traffic.last30d.map(function(x) { return (x.resi || 0) / GiB; });
    
    const trafficCanvas = document.getElementById('traffic');
    if (trafficCanvas) {
      _chartTraffic = new Chart(trafficCanvas, {
        type: 'line', 
        data: {
          labels: labels,
          datasets: [
            { label: 'VPS 出口', data: vps, tension: .3, borderWidth: 2, borderColor: '#3b82f6' },
            { label: '住宅出口', data: resi, tension: .3, borderWidth: 2, borderColor: '#f59e0b' }
          ]
        }, 
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: true,
              position: 'bottom',
              labels: {
                padding: 20,
                usePointStyle: true
              }
            }
          },
          scales: {
            x: { title: { display: false } },
            y: { 
              title: { display: false },
              ticks: {
                callback: function(v) { return Math.round(v * 10) / 10; }
              }
            }
          },
          layout: {
            padding: { bottom: 28 }
          }
        }
      });
    }
  }
  
  // 月累计柱形图
  if (traffic.monthly && traffic.monthly.length > 0) {
    const recentMonthly = traffic.monthly.slice(-12);
    const monthLabels = recentMonthly.map(function(item) { return item.month; });
    const vpsData = recentMonthly.map(function(item) { return (item.vps || 0) / GiB; });
    const resiData = recentMonthly.map(function(item) { return (item.resi || 0) / GiB; });
    
    const monthlyCanvas = document.getElementById('monthly-chart');
    if (monthlyCanvas) {
      _chartMonthly = new Chart(monthlyCanvas, {
        type: 'bar',
        data: {
          labels: monthLabels,
          datasets: [
            {
              label: 'VPS出口',
              data: vpsData,
              backgroundColor: '#3b82f6',
              borderColor: '#3b82f6',
              borderWidth: 1,
              stack: 'stack1'
            },
            {
              label: '住宅出口',
              data: resiData,
              backgroundColor: '#f59e0b',
              borderColor: '#f59e0b',
              borderWidth: 1,
              stack: 'stack1'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            tooltip: {
              callbacks: {
                label: function(context) {
                  const label = context.dataset.label || '';
                  const value = context.parsed.y.toFixed(2);
                  return label + ': ' + value + ' GiB';
                },
                afterLabel: function(context) {
                  const dataIndex = context.dataIndex;
                  const vpsValue = vpsData[dataIndex] || 0;
                  const resiValue = resiData[dataIndex] || 0;
                  const total = (vpsValue + resiValue).toFixed(2);
                  return '总流量: ' + total + ' GiB';
                }
              }
            },
            legend: {
              display: true,
              position: 'bottom',
              labels: {
                padding: 20,
                usePointStyle: true
              }
            }
          },
          scales: {
            x: {
              stacked: true,
              grid: { display: false }
            },
            y: {
              stacked: true,
              grid: { display: true, color: '#f1f5f9' },
              ticks: {
                callback: function(value) {
                  return Math.round(value * 10) / 10;
                }
              }
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
      });
    }
  }
  
  // 更新本月进度条
  updateProgressBar();
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
  loadData();
  initWhitelistCollapse();
});

// 定时刷新：每5分钟刷新一次数据，每小时刷新本月进度条
setInterval(loadData, 300000);
setInterval(updateProgressBar, 3600000);
</script>
</body>
</html>
HTML

# 网站根目录映射 + 首次刷新
mkdir -p "${TRAFFIC_DIR}" /var/www/html
ln -sfn "${TRAFFIC_DIR}" /var/www/html/traffic

# 首次出全量 JSON：traffic.json + dashboard.json/system.json
"${SCRIPTS_DIR}/traffic-collector.sh" || true
"${SCRIPTS_DIR}/dashboard-backend.sh" --now || true

log_success "流量监控系统设置完成：${TRAFFIC_DIR}/index.html"
}

TRAFFIC_DIR=/etc/edgebox/traffic
SCRIPTS_DIR=/etc/edgebox/scripts
CONFIG_DIR=/etc/edgebox/config
WEB_ROOT=/var/www/html

mkdir -p "$TRAFFIC_DIR" "$WEB_ROOT"
# 订阅文件：优先用已有的 subscription.txt，没有就让 edgeboxctl 现生
if [[ -s ${CONFIG_DIR}/subscription.txt ]]; then
  # 若 /var/www/html/sub 已存在且指向同一文件，跳过；否则原子替换
  if [[ -e ${WEB_ROOT}/sub ]] && \
     [[ "$(readlink -f ${WEB_ROOT}/sub 2>/dev/null)" == "$(readlink -f ${CONFIG_DIR}/subscription.txt 2>/dev/null)" ]]; then
    : # same file → do nothing
  else
    # 用 install 替换目标（会先移除已有文件/软链，避免 “are the same file”）
    install -m 0644 -T "${CONFIG_DIR}/subscription.txt" "${WEB_ROOT}/sub"
  fi
else
  /usr/local/bin/edgeboxctl sub >/dev/null 2>&1 || true
  [[ -s ${WEB_ROOT}/sub ]] || : > "${WEB_ROOT}/sub"
fi

# 先跑一遍三件套，保证页面初次打开就有内容
${SCRIPTS_DIR}/system-stats.sh  || true
${SCRIPTS_DIR}/traffic-collector.sh || true
${SCRIPTS_DIR}/panel-refresh.sh || true

# 权限（让 nginx 可读）
chmod 644 ${WEB_ROOT}/sub 2>/dev/null || true
find ${TRAFFIC_DIR} -type f -exec chmod 644 {} \; 2>/dev/null || true

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
  log_info "为 ${domain} 申请/扩展 Let's Encrypt 证书"
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
  edgeboxctl service status                       查看所有核心服务状态
  edgeboxctl service restart                      优雅重启核心服务（修改配置后使用）
  edgeboxctl test                                 测试各协议连通性
  edgeboxctl debug-ports                          调试 80/443/2053 等端口占用

${YELLOW}证书管理:${NC}
  edgeboxctl cert status                          查看证书状态（类型/到期）
  edgeboxctl cert renew                           立即续期证书并重载服务
  edgeboxctl fix-permissions                      修复证书/密钥文件权限
  edgeboxctl change-to-domain <domain>            切换域名模式并申请证书
  edgeboxctl change-to-ip                         切换到 IP 模式（自签证书）

${YELLOW}出站分流:${NC}
  edgeboxctl shunt resi '<代理URL>'               全量走住宅（仅 Xray 分流）
  edgeboxctl shunt direct-resi '<代理URL>'        智能分流（白名单直连，其余走住宅）
  edgeboxctl shunt vps                            VPS 全量出站
  edgeboxctl shunt whitelist [add|remove|list|reset] [domain]   管理白名单
  代理URL示例:
    http://user:pass@host:port
    https://user:pass@host:port?sni=example.com
    socks5://user:pass@host:port
    socks5s://user:pass@host:port?sni=example.com
  示例（全栈走住宅）: edgeboxctl shunt resi 'socks5://u:p@111.222.333.444:11324'

${YELLOW}流量统计和预警:${NC}
  edgeboxctl traffic show                         查看流量统计
  edgeboxctl traffic reset                        重置流量计数
  edgeboxctl alert monthly <GiB>                  设置月度预算（GiB）
  edgeboxctl alert steps 30,60,90                 设置触发阈值（百分比）
  edgeboxctl alert telegram <bot_token> <chat_id> 配置 Telegram 通知
  edgeboxctl alert discord <webhook_url>          配置 Discord 通知
  edgeboxctl alert wechat <pushplus_token>        配置微信 PushPlus 转发
  edgeboxctl alert webhook <url> [raw|slack|discord]  配置通用 Webhook
  edgeboxctl alert test [percent]                 模拟触发（默认 40%），写入 /etc/edgebox/traffic/alerts.json

${YELLOW}配置管理:${NC}
  edgeboxctl config show                          显示当前配置（UUID/Reality/端口等）
  edgeboxctl config regenerate-uuid               重新生成 UUID

${YELLOW}备份恢复:${NC}
  edgeboxctl backup create                        创建备份
  edgeboxctl backup list                          列出备份
  edgeboxctl backup restore <file>                恢复备份
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

# ===== 收尾：生成订阅、同步、首次生成 dashboard =====
finalize_install() {
  # 基础环境
  export CONFIG_DIR="/etc/edgebox/config"
  export TRAFFIC_DIR="/etc/edgebox/traffic"
  export WEB_ROOT="/var/www/html"
  export SCRIPTS_DIR="/etc/edgebox/scripts"
  export SUB_CACHE="${TRAFFIC_DIR}/sub.txt"

  log_info "收尾：生成订阅并同步..."
  generate_subscription       || true
  sync_subscription_files     || true

  # 立即生成首版面板数据 + 写入定时
  if [[ -x "${SCRIPTS_DIR}/dashboard-backend.sh" ]]; then
    log_info "生成初始面板数据..."
    "${SCRIPTS_DIR}/dashboard-backend.sh" --now      >/dev/null 2>&1 || log_warn "首刷失败，稍后由定时任务再试"
    "${SCRIPTS_DIR}/dashboard-backend.sh" --schedule >/dev/null 2>&1 || true
  fi

  # 健康检查：若 subscription 仍为空，兜底再刷一次
  if ! jq -e '.subscription.plain|length>0' "${TRAFFIC_DIR}/dashboard.json" >/dev/null 2>&1; then
    install -m 0644 -T "${CONFIG_DIR}/subscription.txt" "${TRAFFIC_DIR}/sub.txt"
    [[ -x "${SCRIPTS_DIR}/dashboard-backend.sh" ]] && "${SCRIPTS_DIR}/dashboard-backend.sh" --now >/dev/null 2>&1 || true
  fi
  
  # 可选清理：下线旧版面板脚本，避免未来误调用
rm -f /etc/edgebox/scripts/panel-refresh.sh 2>/dev/null || true
rm -f /etc/edgebox/scripts/system-stats.sh 2>/dev/null || true
}
# ===== /finalize_install =====


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
    echo -e "  版本号: ${PURPLE}EdgeBox v3.0.0 企业级完整版${NC}"

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
    echo -e "  2. 使用 switch-to-domain 可获得受信任证书"
    echo -e "  3. 流量预警配置: ${TRAFFIC_DIR}/alert.conf"
    echo -e "  4. 安装日志: ${LOG_FILE}"
	echo -e " "
}

# 清理函数
cleanup() {
  local rc=$?
  # 只有真错误（rc!=0）才报
  if (( rc != 0 )); then
    log_error "安装脚本异常退出，退出码: ${rc}。请查看日志：${LOG_FILE}"
  fi
  exit $rc
}
trap cleanup EXIT
# --- /cleanup ---

# 主安装流程
# 在 main() 函数的开始部分添加版本号设置
main() {
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
    
    # 设置错误处理
    trap cleanup EXIT
    
    echo -e "${BLUE}正在执行完整安装流程...${NC}"
    
    # 基础安装步骤（模块1）
    check_root
    check_system  
    get_server_ip
    install_dependencies
    generate_credentials        # 确保在这里生成所有UUID和密码
    create_directories
    check_ports
    configure_firewall
    optimize_system
    generate_self_signed_cert
    install_sing_box
    install_xray
    generate_reality_keys      # 生成Reality密钥
    save_config_info          # 保存所有配置到JSON
    configure_nginx
    configure_xray
    configure_sing_box
    
    # 高级功能安装（模块3）- 先安装后台脚本
    install_scheduled_dashboard_backend
    setup_traffic_monitoring
    setup_cron_jobs
    setup_email_system
    create_enhanced_edgeboxctl
    create_init_script

    # 生成订阅并启动服务
    generate_subscription     # 现在有完整的配置数据
    start_services
	install_ipq_stack
	
    # 启动初始化服务
    systemctl start edgebox-init.service >/dev/null 2>&1 || true
    
    # 等待服务稳定
    sleep 3
    
# 运行一次数据初始化（统一由 dashboard-backend 生成 dashboard/system）
/etc/edgebox/scripts/traffic-collector.sh || true
/etc/edgebox/scripts/dashboard-backend.sh --now || true
    
    # 收尾：订阅 + 首刷 + 定时
    finalize_install
    
    # 显示安装信息
    show_installation_info
    exit 0
}

# 执行主函数
main "$@"
