#!/usr/bin/env bash
set -Eeuo pipefail

# =========
# 常量与目录
# =========
CONFIG_DIR="/etc/edgebox/config"
CERT_DIR="/etc/edgebox/cert"
LOG_DIR_XRAY="/var/log/xray"
STREAM_PORT="10443"        # Nginx stream 本地回环入口
GRPC_PORT="10085"          # VLESS-gRPC (TLS) 本地回环
WS_PORT="10086"            # VLESS-WS (TLS) 本地回环
HY2_PORT="443"             # Hysteria2 对外 UDP/443
TUIC_PORT="2053"           # TUIC 对外 UDP/2053

# 占位 SNI（无域名阶段用于精准回落）
SNI_GRPC="grpc.edgebox.local"
SNI_WS="www.edgebox.local"

# 伪装目标（Reality）
REALITY_SNIS=("www.cloudflare.com" "www.microsoft.com" "www.apple.com")
REALITY_DEST="www.cloudflare.com:443"

# =========
# 日志
# =========
log_info()    { echo -e "\033[1;34m[INFO]\033[0m $*"; }
log_warn()    { echo -e "\033[1;33m[WARN]\033[0m $*"; }
log_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $*"; }
log_error()   { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

# =========
# 前置检查
# =========
require_root() { [[ $EUID -eq 0 ]] || { log_error "请用 root 运行"; exit 1; }; }

detect_ip() {
  curl -fsSL --max-time 5 https://ipinfo.io/ip || curl -fsSL --max-time 5 https://api.ipify.org || true
}

# =========
# 依赖安装
# =========
install_deps() {
  log_info "安装必要依赖..."
  apt-get update -y
  apt-get install -y curl wget unzip tar jq uuid-runtime openssl vnstat iftop ufw \
    nginx libnginx-mod-stream certbot python3-certbot-nginx
  log_success "依赖安装完成"
}

# =========
# 目录与证书
# =========
prepare_dirs_and_cert() {
  log_info "创建目录与证书软链..."
  mkdir -p "$CONFIG_DIR" "$CERT_DIR" "$LOG_DIR_XRAY"
  # 自签证书不存在则生成（含 IP SAN）
  if [[ ! -f "$CERT_DIR/self-signed.pem" || ! -f "$CERT_DIR/self-signed.key" ]]; then
    local ip="${SERVER_IP:-$(detect_ip)}"
    ip="${ip:-127.0.0.1}"
    log_info "生成自签名证书 (SAN=IP:$ip)..."
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout "$CERT_DIR/self-signed.key" -out "$CERT_DIR/self-signed.pem" \
      -subj "/CN=$ip" \
      -addext "subjectAltName = IP:$ip" >/dev/null 2>&1
  fi
  ln -sf "$CERT_DIR/self-signed.pem" "$CERT_DIR/current.pem"
  ln -sf "$CERT_DIR/self-signed.key" "$CERT_DIR/current.key"
  chmod 640 "$CERT_DIR"/self-signed.* "$CERT_DIR"/current.*
  log_success "证书与目录准备完成"
}

# =========
# 安装 Xray
# =========
install_xray() {
  log_info "安装 Xray..."
  if ! command -v xray >/dev/null 2>&1; then
    local ver latest
    latest=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name | sed 's/^v//')
    ver="${latest:-1.8.11}"
    wget -q https://github.com/XTLS/Xray-core/releases/download/v${ver}/Xray-linux-64.zip
    unzip -q Xray-linux-64.zip xray geoip.dat geosite.dat
    install -m 755 xray /usr/local/bin/xray
    install -m 644 geoip.dat /usr/local/share/xray/geoip.dat || true
    install -m 644 geosite.dat /usr/local/share/xray/geosite.dat || true
    rm -f Xray-linux-64.zip xray geoip.dat geosite.dat
  fi

  # 生成 Reality 密钥（若不存在）
  if [[ ! -f "$CONFIG_DIR/reality.key" || ! -f "$CONFIG_DIR/reality.pub" ]]; then
    readarray -t kp < <(/usr/local/bin/xray x25519)
    # 输出两行：Private key: xxx / Public key: yyy
    echo "${kp[0]##*: }" > "$CONFIG_DIR/reality.key"
    echo "${kp[1]##*: }" > "$CONFIG_DIR/reality.pub"
  fi

  # 停用系统自带 xray 单元并写入我们自己的（ExecStart 指向 ${CONFIG_DIR}/xray.json）
  systemctl disable --now xray@.service 2>/dev/null || true
  systemctl disable --now xray.service 2>/dev/null || true
  rm -f /etc/systemd/system/xray@.service /etc/systemd/system/xray.service 2>/dev/null || true

  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -c ${CONFIG_DIR}/xray.json
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  log_success "Xray 安装完成（service 就绪）"
}

# =========
# 安装 sing-box
# =========
install_sing_box() {
  log_info "安装 sing-box..."
  if ! command -v sing-box >/dev/null 2>&1; then
    local latest
    latest=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name | sed 's/^v//')
    latest="${latest:-1.12.4}"
    wget -q "https://github.com/SagerNet/sing-box/releases/download/v${latest}/sing-box-${latest}-linux-amd64.tar.gz"
    tar -xzf "sing-box-${latest}-linux-amd64.tar.gz"
    install -m 755 "sing-box-${latest}-linux-amd64/sing-box" /usr/local/bin/sing-box
    rm -rf "sing-box-${latest}-linux-amd64" "sing-box-${latest}-linux-amd64.tar.gz"
  fi

  cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c ${CONFIG_DIR}/sing-box.json
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  log_success "sing-box 安装完成（service 就绪）"
}

# =========
# 配置 Nginx（stream 分流）
# =========
configure_nginx() {
  log_info "配置 Nginx（stream 分流）..."
  systemctl stop nginx >/dev/null 2>&1 || true

  # 备份一次主配置
  [[ -f /etc/nginx/nginx.conf && ! -f /etc/nginx/nginx.conf.bak ]] && cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak

  mkdir -p /etc/nginx/stream.d

  # 按 ALPN 分流：h2 → gRPC，其余（含 http/1.1）→ WS
  cat > /etc/nginx/stream.d/edgebox.conf <<'EOF'
# EdgeBox Stream Configuration
upstream grpc_backend { server 127.0.0.1:10085; }
upstream ws_backend   { server 127.0.0.1:10086; }

# 按 ALPN 分流：h2 -> gRPC，其它 -> WS
map $ssl_preread_alpn_protocols $stream_backend {
    ~\bh2\b  grpc_backend;
    default  ws_backend;
}

server {
    listen 127.0.0.1:10443;
    ssl_preread on;
    proxy_pass $stream_backend;
}
EOF

  # 主配置：加载 modules-enabled（包含 stream/ssl_preread 动态模块），纳入 stream.d
  cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

# 加载所有动态模块（包含 stream / ssl_preread）
include /etc/nginx/modules-enabled/*.conf;

events { worker_connections 1024; }

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    sendfile on; tcp_nopush on; tcp_nodelay on;
    keepalive_timeout 65; types_hash_max_size 2048;

    access_log /var/log/nginx/access.log;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

# Stream（gRPC/WS 分流入口）
stream { include /etc/nginx/stream.d/*.conf; }
EOF

  nginx -t
  systemctl enable --now nginx
  log_success "Nginx stream 配置完成（监听 127.0.0.1:${STREAM_PORT}）"
}

# =========
# 写 Xray 配置（Reality@443 + 精准 fallbacks → Nginx(stream@10443) → gRPC/WS）
# =========
write_xray_config() {
  log_info "写入 Xray 配置..."
  local uuid_vless reality_priv reality_pub shortid1 shortid2
  uuid_vless=$(cat /proc/sys/kernel/random/uuid)
  reality_priv=$(<"$CONFIG_DIR/reality.key")
  reality_pub=$(<"$CONFIG_DIR/reality.pub")
  shortid1="$(openssl rand -hex 4)"
  shortid2="$(openssl rand -hex 8)"

  cat > "${CONFIG_DIR}/xray.json" <<EOF
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
          { "id": "${uuid_vless}", "flow": "xtls-rprx-vision", "email": "reality@edgebox" }
        ],
        "decryption": "none",
        "fallbacks": [
          { "name": "${SNI_GRPC}", "alpn": "h2",        "dest": "127.0.0.1:${STREAM_PORT}", "xver": 0 },
          { "name": "${SNI_WS}",   "alpn": "http/1.1",  "dest": "127.0.0.1:${STREAM_PORT}", "xver": 0 }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_DEST}",
          "xver": 0,
          "serverNames": ["${REALITY_SNIS[0]}","${REALITY_SNIS[1]}","${REALITY_SNIS[2]}"],
          "privateKey": "${reality_priv}",
          "shortIds": ["${shortid1}","${shortid2}"]
        }
      }
    },
    {
      "tag": "VLESS-gRPC",
      "port": ${GRPC_PORT},
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${uuid_vless}", "email": "grpc@edgebox" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [ { "certificateFile": "${CERT_DIR}/current.pem", "keyFile": "${CERT_DIR}/current.key" } ]
        },
        "grpcSettings": { "serviceName": "grpc" }
      }
    },
    {
      "tag": "VLESS-WS",
      "port": ${WS_PORT},
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${uuid_vless}", "email": "ws@edgebox" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [ { "certificateFile": "${CERT_DIR}/current.pem", "keyFile": "${CERT_DIR}/current.key" } ]
        },
        "wsSettings": { "path": "/ws" }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {}, "tag": "direct" },
    { "protocol": "blackhole", "settings": {}, "tag": "blocked" }
  ]
}
EOF

  # 预检
  /usr/local/bin/xray -test -config "${CONFIG_DIR}/xray.json" >/dev/null
  log_success "Xray 配置写入完成"
}

# =========
# 写 sing-box 配置（Hy2@udp/443、TUIC@udp/2053）
# =========
write_singbox_config() {
  log_info "写入 sing-box 配置..."
  local tuic_uuid tuic_pwd hy2_pwd
  tuic_uuid=$(cat /proc/sys/kernel/random/uuid)
  tuic_pwd=$(openssl rand -hex 8)
  hy2_pwd=$(openssl rand -hex 10)

  cat > "${CONFIG_DIR}/sing-box.json" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "hysteria2",
      "listen": "::",
      "listen_port": ${HY2_PORT},
      "users": [ { "name": "hy2", "password": "${hy2_pwd}" } ],
      "tls": { "enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key" },
      "masquerade": "https://${REALITY_SNIS[0]}/"
    },
    {
      "type": "tuic",
      "listen": "::",
      "listen_port": ${TUIC_PORT},
      "users": [ { "uuid": "${tuic_uuid}", "password": "${tuic_pwd}" } ],
      "congestion_control": "bbr",
      "udp_relay_mode": "native",
      "tls": { "enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key" }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF

  /usr/local/bin/sing-box check -c "${CONFIG_DIR}/sing-box.json" >/dev/null
  log_success "sing-box 配置写入完成"
}

# =========
# 防火墙
# =========
open_firewall() {
  log_info "设置 UFW 规则..."
  ufw allow 22/tcp >/dev/null || true
  ufw allow 443/tcp >/dev/null || true
  ufw allow ${HY2_PORT}/udp >/dev/null || true
  ufw allow ${TUIC_PORT}/udp >/dev/null || true
  # 8443 不是当前方案需要，主动关闭
  ufw deny 8443/tcp >/dev/null || true
  ufw --force enable || true
  log_success "UFW 已配置（tcp/443, udp/443, udp/2053 放行）"
}

# =========
# edgeboxctl（证书切换 + 订阅导出）
# =========
install_edgeboxctl() {
cat >/usr/local/bin/edgeboxctl <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
CONFIG_DIR="/etc/edgebox/config"
CERT_DIR="/etc/edgebox/cert"

die(){ echo "ERR: $*" >&2; exit 1; }
reload(){ systemctl daemon-reload; systemctl restart xray sing-box nginx; }

case "${1:-}" in
  change-to-domain)
    domain="${2:-}"; [[ -n "$domain" ]] || die "用法: edgeboxctl change-to-domain <domain>"
    apt-get install -y certbot >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    systemctl stop nginx || true
    certbot certonly --standalone -d "$domain" --non-interactive --agree-tos -m admin@"$domain"
    ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" "${CERT_DIR}/current.pem"
    ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem"   "${CERT_DIR}/current.key"
    systemctl start nginx
    reload
    echo "OK: 切换到域名模式: $domain"
    ;;
  change-to-ip)
    # 切回自签
    ln -sf "${CERT_DIR}/self-signed.pem" "${CERT_DIR}/current.pem"
    ln -sf "${CERT_DIR}/self-signed.key" "${CERT_DIR}/current.key"
    reload
    echo "OK: 切回 IP 模式（自签证书）"
    ;;
  cert)
    case "${2:-}" in
      status)
        tgt="$(readlink -f ${CERT_DIR}/current.pem || true)"
        echo "当前证书: ${tgt:-unknown}"
        if [[ "$tgt" == *"/etc/letsencrypt/"* ]]; then
          echo "类型: Let's Encrypt"
        else
          echo "类型: 自签名"
        fi
        ;;
      renew)
        certbot renew || true
        reload
        echo "OK: 已尝试续期并重载服务"
        ;;
      upload)
        fc="${3:-}"; fk="${4:-}"
        [[ -f "$fc" && -f "$fk" ]] || die "用法: edgeboxctl cert upload <fullchain> <privkey>"
        install -m 640 "$fc" "${CERT_DIR}/custom.pem"
        install -m 640 "$fk" "${CERT_DIR}/custom.key"
        ln -sf "${CERT_DIR}/custom.pem" "${CERT_DIR}/current.pem"
        ln -sf "${CERT_DIR}/custom.key" "${CERT_DIR}/current.key"
        reload
        echo "OK: 已切换到自定义证书"
        ;;
      *) echo "用法: edgeboxctl cert {status|renew|upload <fullchain> <key>}"; exit 1;;
    esac
    ;;
  sub)
    mode="ip"
    if [[ -e /etc/letsencrypt/live ]]; then mode="domain"; fi
    host="$(curl -fsSL https://ipinfo.io/ip || echo 127.0.0.1)"
    if [[ "$mode" == "domain" ]]; then host="${2:-$host}"; fi
    # 读取 Xray 与 sing-box 配置，拼接示例链接（最简示例）
    uuid=$(jq -r '.inbounds[]|select(.tag=="VLESS-WS").settings.clients[0].id' ${CONFIG_DIR}/xray.json)
    tuic_u=$(jq -r '.inbounds[]|select(.type=="tuic").users[0].uuid' ${CONFIG_DIR}/sing-box.json)
    tuic_p=$(jq -r '.inbounds[]|select(.type=="tuic").users[0].password' ${CONFIG_DIR}/sing-box.json)
    hy2_p=$(jq -r '.inbounds[]|select(.type=="hysteria2").users[0].password' ${CONFIG_DIR}/sing-box.json)
    if [[ "$mode" == "ip" ]]; then
      echo "vless://${uuid}@${host}:443?type=grpc&serviceName=grpc&security=tls&sni=grpc.edgebox.local&alpn=h2&allowInsecure=1#VLESS-gRPC"
      echo "vless://${uuid}@${host}:443?type=ws&path=/ws&security=tls&sni=www.edgebox.local&allowInsecure=1#VLESS-WS"
      echo "vless://${uuid}@${host}:443?security=reality&sni=www.cloudflare.com&fp=chrome&pbk=$(jq -r '.inbounds[]|select(.tag=="VLESS-Reality").streamSettings.realitySettings.publicKey // empty' ${CONFIG_DIR}/xray.json 2>/dev/null || echo '')#VLESS-Reality"
      echo "hysteria2://${hy2_p}@${host}:${HY2_PORT}?insecure=1#Hy2"
      echo "tuic://${tuic_u}:${tuic_p}@${host}:${TUIC_PORT}?congestion=bbr&alpn=h3&disable-sni=1&skip-cert-verify=1#TUIC"
    else
      dom="${2:-$host}"
      echo "vless://${uuid}@${dom}:443?type=grpc&serviceName=grpc&security=tls&sni=${dom}&alpn=h2#VLESS-gRPC"
      echo "vless://${uuid}@${dom}:443?type=ws&path=/ws&security=tls&sni=${dom}#VLESS-WS"
      echo "vless://${uuid}@${dom}:443?security=reality&sni=www.cloudflare.com#VLESS-Reality"
      echo "hysteria2://${hy2_p}@${dom}:${HY2_PORT}#Hy2"
      echo "tuic://${tuic_u}:${tuic_p}@${dom}:${TUIC_PORT}?congestion=bbr&alpn=h3#TUIC"
    fi
    ;;
  service)
    case "${2:-}" in
      status) systemctl --no-pager --type=service --state=running | grep -E 'xray|nginx|sing-box' || true ;;
      restart) systemctl restart xray sing-box nginx; echo "OK: 已重启 xray/sing-box/nginx" ;;
      logs) journalctl -u xray -u sing-box -u nginx -n 100 --no-pager ;;
      *) echo "用法: edgeboxctl service {status|restart|logs}"; exit 1;;
    esac
    ;;
  *)
    cat <<USAGE
用法:
  edgeboxctl change-to-domain <domain>   切换到域名模式（Let's Encrypt）
  edgeboxctl change-to-ip                切回 IP 模式（自签证书）
  edgeboxctl cert {status|renew|upload <fullchain> <key>}
  edgeboxctl sub [domain]                输出当前模式下的五协议订阅行
  edgeboxctl service {status|restart|logs}
USAGE
    ;;
esac
BASH
  chmod +x /usr/local/bin/edgeboxctl
  log_success "edgeboxctl 安装完成"
}

# =========
# 启动服务
# =========
start_services() {
  log_info "检查配置并启动服务..."
  /usr/local/bin/xray -test -config "${CONFIG_DIR}/xray.json" >/dev/null
  /usr/local/bin/sing-box check -c "${CONFIG_DIR}/sing-box.json" >/dev/null
  nginx -t >/dev/null

  systemctl enable --now xray sing-box nginx
  sleep 0.5
  systemctl --no-pager --type=service --state=running | grep -E 'xray|nginx|sing-box' || true
  log_success "服务已启动"
}

# =========
# 主流程
# =========
main() {
  require_root
  SERVER_IP="${SERVER_IP:-$(detect_ip)}"
  log_info "EdgeBox 安装脚本 v2.1 | 服务器 IP: ${SERVER_IP:-unknown}"
  install_deps
  prepare_dirs_and_cert
  install_xray
  install_sing_box
  configure_nginx
  write_xray_config
  write_singbox_config
  open_firewall
  install_edgeboxctl
  start_services

  echo
  log_success "安装完成！非交互式 IP 模式已就绪。"
  echo "快速检查：edgeboxctl service status"
  echo "切换域名： edgeboxctl change-to-domain your.domain"
  echo "切回自签： edgeboxctl change-to-ip"
  echo "订阅导出： edgeboxctl sub [your.domain]"
}
main "$@"
