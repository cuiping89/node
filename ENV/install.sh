#!/usr/bin/env bash
set -euo pipefail

# =========================
# EdgeBox Install v2 (Fixed)
# =========================
EB_DIR="/etc/edgebox"
CFG_DIR="$EB_DIR/config"
CRT_DIR="$EB_DIR/cert"
BIN_DIR="/usr/local/bin"
SYS_DIR="/etc/systemd/system"

XRAY_VER="v25.8.3"
SBOX_VER="1.12.4"

# 默认占位 SNI（IP 模式用于 Reality 回落匹配）
PLACE_SNI_GRPC="grpc.edgebox.local"
PLACE_SNI_WS="www.edgebox.local"
# 伪装站（Reality）
REALITY_SNIS=("www.cloudflare.com" "www.microsoft.com" "www.apple.com")

# 默认 WS/GRPC 参数
GRPC_SVC="edgebox-grpc"
WS_PATH="/edgebox-ws"

# hy2/tuic 认证
HY2_USER="edge"
HY2_PASS="$(openssl rand -hex 8)"
TUIC_PASS="$(openssl rand -hex 8)"

# ------- utils -------
log(){ printf "%s %s\n" "[$1]" "${2:-}"; }
ok(){ log "SUCCESS" "$1"; }
info(){ log "INFO" "$1"; }
warn(){ log "WARN" "$1"; }
err(){ log "ERROR" "$1"; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || { err "missing $1"; exit 1; }; }

get_ip(){
  curl -fsS --max-time 3 https://api.ipify.org || curl -fsS --max-time 3 ifconfig.me || echo ""
}

# ------- preflight -------
info "系统与依赖检查..."
if ! grep -qiE "ubuntu (22|24)\.04" /etc/os-release; then
  warn "未检测到 Ubuntu 22.04/24.04，继续但不保证兼容。"
fi

apt-get update -y
DEBIANS="curl wget unzip tar jq uuid-runtime ca-certificates openssl net-tools gnupg"
DEBIANS="$DEBIANS nginx libnginx-mod-stream certbot python3-certbot-nginx"
apt-get install -y $DEBIANS

# 确保 stream 模块加载
mkdir -p /etc/nginx/modules-enabled
ln -sf /usr/share/nginx/modules-available/mod-stream.conf /etc/nginx/modules-enabled/50-mod-stream.conf

ok "依赖安装完成"

# ------- dirs & secrets -------
info "准备目录与凭证..."
mkdir -p "$CFG_DIR" "$CRT_DIR"
chmod 700 "$EB_DIR" "$CRT_DIR"

# UUID 供三路 VLESS 复用
if [[ ! -f "$EB_DIR/uuid" ]]; then
  uuidgen | tr 'A-Z' 'a-z' > "$EB_DIR/uuid"
fi
UUID="$(cat "$EB_DIR/uuid")"

# Reality 密钥对
if [[ ! -f "$EB_DIR/reality_privkey" || ! -f "$EB_DIR/reality_pubkey" ]]; then
  "$BIN_DIR/xray" x25519 >/dev/null 2>&1 || true
  if ! "$BIN_DIR/xray" x25519 >/dev/null 2>&1; then
    # 临时下载 xray 只为生成密钥
    curl -L -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip"
    unzip -oq /tmp/xray.zip -d /tmp/xray
    /tmp/xray/xray x25519 > /tmp/x25519.txt
    REAL_PRIV="$(awk '/Private key/{print $3}' /tmp/x25519.txt)"
    REAL_PUB="$(awk '/Public key/{print $3}'  /tmp/x25519.txt)"
    rm -rf /tmp/xray /tmp/xray.zip /tmp/x25519.txt
  else
    /usr/local/bin/xray x25519 > /tmp/x25519.txt
    REAL_PRIV="$(awk '/Private key/{print $3}' /tmp/x25519.txt)"
    REAL_PUB="$(awk '/Public key/{print $3}'  /tmp/x25519.txt)"
    rm -f /tmp/x25519.txt
  fi
  echo "$REAL_PRIV" > "$EB_DIR/reality_privkey"
  echo "$REAL_PUB"  > "$EB_DIR/reality_pubkey"
fi
REAL_PRIV="$(cat "$EB_DIR/reality_privkey")"
REAL_PUB="$(cat "$EB_DIR/reality_pubkey")"
SHORT_ID="$(openssl rand -hex 8)"

# 自签证书（IP 模式默认）
if [[ ! -f "$CRT_DIR/self-signed.pem" ]]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$CRT_DIR/self-signed.key" \
    -out "$CRT_DIR/self-signed.pem" \
    -subj "/CN=$(get_ip || echo 127.0.0.1)"
fi
ln -sf "$CRT_DIR/self-signed.pem" "$CRT_DIR/current.pem"
ln -sf "$CRT_DIR/self-signed.key" "$CRT_DIR/current.key"
chmod 640 "$CRT_DIR"/*

ok "凭证与证书准备完成"

# ------- install xray -------
if ! command -v xray >/dev/null 2>&1; then
  info "安装 Xray ${XRAY_VER}..."
  curl -L -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip"
  unzip -oq /tmp/xray.zip -d /tmp/xray
  install -m 755 /tmp/xray/xray "$BIN_DIR/xray"
  install -m 644 /tmp/xray/geoip.dat /tmp/xray/geosite.dat /usr/local/share/
  rm -rf /tmp/xray /tmp/xray.zip
  ok "Xray 安装完成"
fi

# systemd (xray)
cat > "$SYS_DIR/xray.service" <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/xray -config $CFG_DIR/xray.json
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# ------- install sing-box -------
if ! command -v sing-box >/dev/null 2>&1; then
  info "安装 sing-box ${SBOX_VER}..."
  curl -L -o /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${SBOX_VER}/sing-box-${SBOX_VER}-linux-amd64.tar.gz"
  mkdir -p /tmp/sb && tar -xzf /tmp/sb.tar.gz -C /tmp/sb --strip-components=1
  install -m 755 /tmp/sb/sing-box "$BIN_DIR/sing-box"
  rm -rf /tmp/sb /tmp/sb.tar.gz
  ok "sing-box 安装完成"
fi

# systemd (sing-box)
cat > "$SYS_DIR/sing-box.service" <<EOF
[Unit]
Description=sing-box service
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/sing-box run -c $CFG_DIR/sing-box.json
Restart=always
RestartSec=2s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# ------- Nginx stream (ALPN 分流) -------
info "配置 Nginx (stream 分流)..."
mkdir -p /etc/nginx/stream.d
cat > /etc/nginx/stream.d/edgebox.conf <<'EOF'
upstream grpc_backend { server 127.0.0.1:10085; }
upstream ws_backend   { server 127.0.0.1:10086; }

map $ssl_preread_alpn_protocols $stream_backend {
    ~\bh2\b  grpc_backend;
    default  ws_backend;
}

server {
    listen 127.0.0.1:10443;
    proxy_pass $stream_backend;
    ssl_preread on;
}
EOF

# 主配置，确保包含 stream
cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;
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

stream {
    include /etc/nginx/stream.d/*.conf;
}
EOF

nginx -t
systemctl enable nginx >/dev/null 2>&1 || true
systemctl restart nginx
ok "Nginx stream 配置完成（监听 127.0.0.1:10443）"

# ------- Xray 配置 -------
info "写入 Xray 配置..."
SNI_CF="${REALITY_SNIS[0]}"
SNI_MS="${REALITY_SNIS[1]}"
SNI_AP="${REALITY_SNIS[2]}"

cat > "$CFG_DIR/xray.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "reality-in",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${UUID}", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none",
        "fallbacks": [
          { "sni": "${PLACE_SNI_GRPC}", "alpn": "h2", "dest": "127.0.0.1:10443", "xver": 0 },
          { "sni": "${PLACE_SNI_WS}",   "dest": "127.0.0.1:10443", "xver": 0 }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${SNI_CF}:443",
          "xver": 0,
          "serverNames": ["${SNI_CF}", "${SNI_MS}", "${SNI_AP}"],
          "privateKey": "${REAL_PRIV}",
          "shortIds": ["${SHORT_ID}"],
          "spiderX": "/"
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["tls","http"] }
    },
    {
      "tag": "vless-grpc-in",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "${UUID}" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2"],
          "certificates": [{ "certificateFile": "$CRT_DIR/current.pem", "keyFile": "$CRT_DIR/current.key" }]
        },
        "grpcSettings": { "serviceName": "${GRPC_SVC}", "multiMode": true }
      }
    },
    {
      "tag": "vless-ws-in",
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "${UUID}" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [{ "certificateFile": "$CRT_DIR/current.pem", "keyFile": "$CRT_DIR/current.key" }]
        },
        "wsSettings": { "path": "${WS_PATH}" }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
EOF
ok "Xray 配置完成"

# ------- sing-box 配置（Hy2@udp/443, TUIC@udp/2053） -------
info "写入 sing-box 配置..."
cat > "$CFG_DIR/sing-box.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": 443,
      "users": [{ "name": "${HY2_USER}", "password": "${HY2_PASS}" }],
      "tls": {
        "enabled": true,
        "alpn": ["h3","h2","http/1.1"],
        "certificate_path": "$CRT_DIR/current.pem",
        "key_path": "$CRT_DIR/current.key"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": 2053,
      "users": [{ "uuid": "${UUID}", "password": "${TUIC_PASS}" }],
      "tls": {
        "enabled": true,
        "alpn": ["h3","h2","http/1.1"],
        "certificate_path": "$CRT_DIR/current.pem",
        "key_path": "$CRT_DIR/current.key"
      }
    }
  ]
}
EOF
ok "sing-box 配置完成"

# ------- 校验并启动 -------
info "校验配置..."
$BIN_DIR/xray -test -config "$CFG_DIR/xray.json" >/dev/null
$BIN_DIR/sing-box check -c "$CFG_DIR/sing-box.json" >/dev/null
nginx -t >/dev/null

systemctl daemon-reload
systemctl enable xray sing-box >/dev/null 2>&1 || true
systemctl restart xray sing-box nginx

ok "安装完成！非交互 IP 模式已就绪。"

# ------- edgeboxctl 命令行 -------
cat > "$BIN_DIR/edgeboxctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
EB_DIR="/etc/edgebox"
CFG_DIR="$EB_DIR/config"
CRT_DIR="$EB_DIR/cert"

uuid(){ cat "$EB_DIR/uuid"; }
pbk(){ cat "$EB_DIR/reality_pubkey"; }

ip_now(){
  curl -fsS --max-time 3 https://api.ipify.org || curl -fsS --max-time 3 ifconfig.me || echo ""
}

has_le_cert(){
  local d="${1:-}"
  [[ -n "$d" && -f "/etc/letsencrypt/live/$d/fullchain.pem" && -f "/etc/letsencrypt/live/$d/privkey.pem" ]]
}

status(){
  echo "=== EdgeBox 服务状态 ==="
  systemctl --no-pager --type=service --state=active,activating | grep -E 'nginx|xray|sing-box' || true
}

restart_all(){ systemctl restart nginx xray sing-box && status; }

logs(){
  echo "--- xray ---"; journalctl -u xray -n 50 --no-pager || true
  echo "--- sing-box ---"; journalctl -u sing-box -n 50 --no-pager || true
  echo "--- nginx ---"; journalctl -u nginx -n 50 --no-pager || true
}

doctor(){
  echo "检查配置与监听..."
  xray -test -config "$CFG_DIR/xray.json" || true
  sing-box check -c "$CFG_DIR/sing-box.json" || true
  nginx -t || true
  ss -lntup | grep -E ':443\b|:2053\b|:1008[56]\b|:10443\b' || true
  status
}

# 生成五协议链接
sub(){
  local use_domain="${1:-}"
  local addr sni grpc_host ws_host insecure_q tuic_q hy2_q
  local UUID="$(uuid)"
  local PBK="$(pbk)"
  local SHORT_ID="$(cat "$EB_DIR/reality_privkey" >/dev/null 2>&1 && cat "$EB_DIR/reality_privkey" >/dev/null 2>&1; true;)"
  # 从 xray.json 取 shortIds（懒法：grep）
  SHORT_ID="$(grep -oE '"shortIds": \["[0-9a-f]+"\]' "$CFG_DIR/xray.json" | grep -oE '[0-9a-f]+' | head -n1)"

  local WS_PATH="/edgebox-ws"
  local GRPC_SVC="edgebox-grpc"

  if [[ -n "$use_domain" ]]; then
    addr="$use_domain"
    sni="$use_domain"
    grpc_host="$use_domain"
    ws_host="$use_domain"
    insecure_q=""
    hy2_q=""
    tuic_q=""
  else
    addr="$(ip_now)"
    sni="www.cloudflare.com"
    grpc_host="grpc.edgebox.local"
    ws_host="www.edgebox.local"
    insecure_q="&allowInsecure=1"
    hy2_q="?insecure=1&sni=$sni"
    tuic_q="?alpn=h3&skip-cert-verify=true&sni=$sni"
  fi

  echo "=== 订阅链接（${addr}） ==="
  echo "1) VLESS-Reality"
  echo "vless://${UUID}@${addr}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${PBK}&sid=${SHORT_ID}&spx=%2F#EB-REALITY"

  echo "2) VLESS-gRPC (TLS)"
  echo "vless://${UUID}@${addr}:443?type=grpc&security=tls&alpn=h2&serviceName=${GRPC_SVC}&sni=${grpc_host}&encryption=none${insecure_q}#EB-gRPC"

  echo "3) VLESS-WS (TLS)"
  echo "vless://${UUID}@${addr}:443?type=ws&security=tls&path=${WS_PATH}&sni=${ws_host}&host=${ws_host}&alpn=http/1.1&encryption=none${insecure_q}#EB-WS"

  echo "4) Hysteria2"
  echo "hysteria2://${HY2_USER}:${HY2_PASS}@${addr}:443/${hy2_q}#EB-Hy2"

  echo "5) TUIC"
  echo "tuic://${UUID}:${TUIC_PASS}@${addr}:2053${tuic_q}#EB-TUIC"
}

change_to_domain(){
  local domain="${1:-}"
  [[ -z "$domain" ]] && { echo "用法: edgeboxctl change-to-domain <domain>"; exit 1; }
  echo "申请/切换到域名模式: $domain"
  certbot certonly --standalone -d "$domain" --agree-tos -n -m admin@"$domain" || true
  if has_le_cert "$domain"; then
    ln -sf "/etc/letsencrypt/live/$domain/fullchain.pem" "$CRT_DIR/current.pem"
    ln -sf "/etc/letsencrypt/live/$domain/privkey.pem"  "$CRT_DIR/current.key"
    systemctl restart xray sing-box
    echo "OK: 切换到域名模式: $domain"
  else
    echo "证书申请失败，请检查 DNS 解析与防火墙。"
    exit 1
  fi
}

change_to_ip(){
  ln -sf "$CRT_DIR/self-signed.pem" "$CRT_DIR/current.pem"
  ln -sf "$CRT_DIR/self-signed.key" "$CRT_DIR/current.key"
  systemctl restart xray sing-box
  echo "OK: 已切回 IP 模式（自签）"
}

case "${1:-}" in
  status) status;;
  restart) restart_all;;
  logs) logs;;
  doctor) doctor;;
  sub) shift; sub "${1:-}";;
  change-to-domain) shift; change_to_domain "${1:-}";;
  change-to-ip) change_to_ip;;
  *) cat <<USAGE
EdgeBox 管理工具
用法: edgeboxctl [命令]

可用命令：
  status            查看服务状态
  restart           重启全部服务
  logs              查看最近日志
  doctor            体检（配置校验+端口监听）
  sub [domain]      输出 5 协议订阅/链接（留空=IP模式）
  change-to-domain <domain> 切换到域名模式（证书自动申请）
  change-to-ip      切回 IP 模式（自签证书）
USAGE
;;
esac
EOF

chmod +x "$BIN_DIR/edgeboxctl"
ok "edgeboxctl 已安装（/usr/local/bin/edgeboxctl）"

echo
echo "========================================"
echo "安装完成！非交互式 IP 模式"
echo "快速检查： edgeboxctl doctor"
echo "订阅/链接： edgeboxctl sub"
echo "切到域名： edgeboxctl change-to-domain your.domain"
echo "切回自签： edgeboxctl change-to-ip"
echo "========================================"
