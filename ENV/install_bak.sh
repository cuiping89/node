#!/usr/bin/env bash
# EdgeBox 一键安装（模块1：核心基础安装，IP模式，自签名证书）
# - Nginx stream + ssl_preread 作为回落入口：127.0.0.1:10443 => SNI 分流到 Xray gRPC/WS
# - Xray: Reality(443) + VLESS/gRPC(10085-tls h2) + VLESS/WS(10086-tls http/1.1)
# - sing-box: Hysteria2(udp/443) + TUIC v5(udp/2053)
# - 订阅：/sub（Base64-plain）
# - 所有关键参数持久化：/etc/edgebox/config/server.json，二次执行**复用**（不改变 pbk/sid/UUID/密码）

set -Eeuo pipefail

# ========= 基础变量 =========
CONFIG_DIR=/etc/edgebox/config
CERT_DIR=/etc/edgebox/cert
SB_DIR=/etc/edgebox
NGINX_STREAM_DIR=/etc/nginx/stream.d
NGINX_MODS_ENABLED=/etc/nginx/modules-enabled
WWW_ROOT=/var/www/html

# 颜色日志
c_ok="\e[32m"; c_warn="\e[33m"; c_err="\e[31m"; c_inf="\e[36m"; c_end="\e[0m"
log() { echo -e "${c_inf}[INFO]${c_end} $*"; }
ok()  { echo -e "${c_ok}[SUCCESS]${c_end} $*"; }
warn(){ echo -e "${c_warn}[WARN]${c_end} $*"; }
err() { echo -e "${c_err}[ERROR]${c_end} $*"; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || err "请用 root 运行"; }

# ========= 工具与依赖 =========
install_deps() {
  log "安装基础依赖..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nginx libnginx-mod-stream jq uuid-runtime curl openssl iproute2 ca-certificates

  # xray / sing-box 若已装则跳过（你环境通常已装）
  if ! command -v xray >/dev/null 2>&1; then
    warn "未检测到 xray，尝试在线安装..."
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install \
      || err "xray 安装失败，请检查网络后重试"
  fi

  if ! command -v sing-box >/dev/null 2>&1; then
    warn "未检测到 sing-box，尝试在线安装..."
    bash <(curl -fsSL https://raw.githubusercontent.com/SagerNet/sing-box/refs/heads/main/release/install_sh.sh) \
      || warn "sing-box 安装脚本执行失败（忽略，若你已手动安装则无影响）"
  fi
}

# ========= 工具函数 =========
get_ip() {
  local ip
  ip=$(curl -fsS --max-time 6 https://api.ipify.org || true)
  [[ -z "$ip" ]] && ip=$(curl -fsS --max-time 6 https://ifconfig.me || true)
  [[ -z "$ip" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "${ip:-0.0.0.0}"
}

json_get() { jq -r "$1 // empty" 2>/dev/null; }

# ========= 持久化参数 =========
load_or_init_state() {
  mkdir -p "$CONFIG_DIR" "$CERT_DIR"
  local state="${CONFIG_DIR}/server.json"
  local changed=0

  if [[ -f "$state" ]]; then
    SERVER_IP=$(jq -r .server_ip "$state")
    UUID_VLESS=$(jq -r .uuid_vless "$state")
    UUID_TUIC=$(jq -r .uuid_tuic "$state")
    PASSWORD_TUIC=$(jq -r .password_tuic "$state")
    PASSWORD_HYSTERIA2=$(jq -r .password_hysteria2 "$state")
    REALITY_PUBLIC_KEY=$(jq -r .reality.public_key "$state")
    REALITY_PRIVATE_KEY=$(jq -r .reality.private_key "$state")
    REALITY_SHORT_ID=$(jq -r .reality.short_id "$state")
  fi

  [[ -z "${SERVER_IP:-}" ]] && SERVER_IP=$(get_ip) && changed=1
  [[ -z "${UUID_VLESS:-}" ]] && UUID_VLESS=$(uuidgen) && changed=1
  [[ -z "${UUID_TUIC:-}"  ]] && UUID_TUIC=$(uuidgen) && changed=1
  [[ -z "${PASSWORD_TUIC:-}" ]] && PASSWORD_TUIC=$(openssl rand -base64 16) && changed=1
  [[ -z "${PASSWORD_HYSTERIA2:-}" ]] && PASSWORD_HYSTERIA2=$(openssl rand -base64 16) && changed=1

  # Reality 密钥对：若存在就复用（避免“重装就变”）
  if [[ -z "${REALITY_PRIVATE_KEY:-}" || -z "${REALITY_PUBLIC_KEY:-}" ]]; then
    log "生成 Reality X25519 密钥对（仅首次）..."
    local out
    out=$(xray x25519)
    REALITY_PRIVATE_KEY=$(printf '%s\n' "$out" | awk '/Private/{print $3}')
    REALITY_PUBLIC_KEY=$(printf '%s\n' "$out" | awk '/Public/{print $3}')
    changed=1
  fi
  [[ -z "${REALITY_SHORT_ID:-}" ]] && REALITY_SHORT_ID=$(openssl rand -hex 8) && changed=1

  if [[ ! -f "$state" || $changed -eq 1 ]]; then
    jq -n --arg ip "$SERVER_IP" \
          --arg u1 "$UUID_VLESS" --arg u2 "$UUID_TUIC" \
          --arg pt "$PASSWORD_TUIC" --arg ph "$PASSWORD_HYSTERIA2" \
          --arg pbk "$REALITY_PUBLIC_KEY" --arg pvk "$REALITY_PRIVATE_KEY" --arg sid "$REALITY_SHORT_ID" '
    {
      server_ip: $ip,
      uuid_vless: $u1,
      uuid_tuic:  $u2,
      password_tuic: $pt,
      password_hysteria2: $ph,
      reality: { public_key: $pbk, private_key: $pvk, short_id: $sid }
    }' >"$state"
    ok "参数已写入/更新：$state"
  else
    ok "复用现有参数：$state"
  fi
}

# ========= 自签证书（供内部 TLS 与 sing-box） =========
ensure_self_signed_cert() {
  if [[ -f "$CERT_DIR/current.pem" && -f "$CERT_DIR/current.key" ]]; then
    ok "检测到自签证书，复用。"
    return
  fi
  log "生成自签 ECDSA 证书（CN=$SERVER_IP，有效期 3 年）..."
  openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/current.key"
  openssl req -new -x509 -days 1095 -key "$CERT_DIR/current.key" \
    -subj "/C=US/ST=California/L=San Francisco/O=EdgeBox/CN=$SERVER_IP" \
    -out "$CERT_DIR/current.pem"
  ok "证书生成：$CERT_DIR/current.{pem,key}"
}

# ========= Nginx (stream + ssl_preread) =========
configure_nginx() {
  log "配置 Nginx（stream 回落）..."
  systemctl stop nginx >/dev/null 2>&1 || true
  mkdir -p "$NGINX_STREAM_DIR" "$NGINX_MODS_ENABLED" /etc/nginx/conf.d /etc/nginx/sites-enabled
  find -L /etc/nginx/sites-enabled -type l -delete 2>/dev/null || true

  # 加载 stream 动态模块（Ubuntu/Debian 官方包）
  cat >"$NGINX_MODS_ENABLED/50-mod-stream.conf" <<'EOF'
load_module modules/ngx_stream_module.so;
EOF

  # 主配置（http 仅用于 /sub）
  cat >/etc/nginx/nginx.conf <<'NGINX'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

include /etc/nginx/modules-enabled/*.conf;

events { worker_connections 1024; }

http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /var/log/nginx/access.log;
  include /etc/nginx/conf.d/*.conf;
  include /etc/nginx/sites-enabled/*;
}

stream {
  include /etc/nginx/stream.d/*.conf;
}
NGINX

  # stream 分流：SNI 决定 gRPC/WS，默认 WS
  cat >"$NGINX_STREAM_DIR/edgebox.conf" <<'EOF'
# EdgeBox stream 分流
upstream grpc_backend { server 127.0.0.1:10085; }
upstream ws_backend   { server 127.0.0.1:10086; }

map $ssl_preread_server_name $edgebox_upstream {
    grpc.edgebox.local  grpc_backend;
    www.edgebox.local   ws_backend;
    default             ws_backend;
}

server {
    listen 127.0.0.1:10443 reuseport;
    proxy_pass $edgebox_upstream;
    ssl_preread on;
    proxy_connect_timeout 3s;
    proxy_timeout 60s;
}
EOF

  nginx -t || { nginx -t; err "Nginx 配置测试失败"; }
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx
  ok "Nginx 就绪。"
}

# ========= Xray =========
configure_xray() {
  log "配置 Xray..."

  cat >"$CONFIG_DIR/xray.json" <<EOF
{
  "log": { "loglevel": "warning",
           "access": "/var/log/xray/access.log",
           "error":  "/var/log/xray/error.log" },
  "inbounds": [
    {
      "tag": "VLESS-Reality",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${UUID_VLESS}", "flow": "xtls-rprx-vision", "email": "reality@edgebox" } ],
        "decryption": "none",
        "fallbacks": [ { "dest": "127.0.0.1:10443", "xver": 0 } ]
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
      "tag": "VLESS-gRPC",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "${UUID_VLESS}", "email": "grpc@edgebox" } ], "decryption": "none" },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2"],
          "certificates": [ { "certificateFile": "${CERT_DIR}/current.pem", "keyFile": "${CERT_DIR}/current.key" } ]
        },
        "grpcSettings": { "serviceName": "grpc" }
      }
    },
    {
      "tag": "VLESS-WS",
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "${UUID_VLESS}", "email": "ws@edgebox" } ], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [ { "certificateFile": "${CERT_DIR}/current.pem", "keyFile": "${CERT_DIR}/current.key" } ]
        },
        "wsSettings": { "path": "/ws", "headers": {} }
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

  xray run -test -c "$CONFIG_DIR/xray.json" >/dev/null
  systemctl daemon-reload
  systemctl enable --now xray
  ok "Xray 就绪。"
}

# ========= sing-box（Hysteria2 + TUIC）=========
configure_singbox() {
  if ! command -v sing-box >/dev/null 2>&1; then
    warn "未安装 sing-box，跳过 Hysteria2/TUIC 配置。"
    return
  fi
  log "配置 sing-box（Hysteria2+TUIC）..."
  cat >"$CONFIG_DIR/sing-box.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    {
      "type": "hysteria2",
      "listen": ":443",
      "users": [ { "password": "${PASSWORD_HYSTERIA2}" } ],
      "tls": { "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key", "alpn": ["h3"] }
    },
    {
      "type": "tuic",
      "listen": ":2053",
      "users": [ { "uuid": "${UUID_TUIC}", "password": "${PASSWORD_TUIC}" } ],
      "congestion_control": "bbr",
      "tls": { "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key", "alpn": ["h3"] }
    }
  ],
  "outbounds": [ { "type": "direct" } ]
}
EOF

  cat >/etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box Service (EdgeBox)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/edgebox/config/sing-box.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  sing-box run -c "$CONFIG_DIR/sing-box.json" -T >/dev/null || err "sing-box 配置测试失败"
  systemctl daemon-reload
  systemctl enable --now sing-box
  ok "sing-box 就绪。"
}

# ========= 订阅 =========
generate_subscription() {
  log "生成订阅..."

  local ip="$SERVER_IP"
  local uuid="$UUID_VLESS"
  local grpc_host="grpc.edgebox.local"
  local ws_host="www.edgebox.local"
  local ws_path="/ws"

  # Reality
  local reality="vless://${uuid}@${ip}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&spx=%2F#EdgeBox-REALITY"

  # gRPC（IP模式需 allowInsecure=1）
  local grpc="vless://${uuid}@${ip}:443?encryption=none&security=tls&sni=${grpc_host}&alpn=h2&type=grpc&serviceName=grpc&allowInsecure=1#EdgeBox-gRPC"

  # WS（IP模式需 allowInsecure=1）
  local ws="vless://${uuid}@${ip}:443?encryption=none&security=tls&sni=${ws_host}&alpn=http/1.1&type=ws&host=${ws_host}&path=${ws_path}&allowInsecure=1#EdgeBox-WS"

  # Hysteria2（IP模式：insecure=1）
  local hy2="hysteria2://${PASSWORD_HYSTERIA2}@${ip}:443?sni=${ws_host}&insecure=1&alpn=h3#EdgeBox-HYSTERIA2"

  # TUIC v5（很多客户端是 allowInsecure=1）
  local tuic="tuic://${UUID_TUIC}:${PASSWORD_TUIC}@${ip}:2053?congestion_control=bbr&alpn=h3&sni=${ws_host}&allowInsecure=1#EdgeBox-TUIC"

  mkdir -p "$WWW_ROOT"
  {
    echo "$reality"
    echo "$grpc"
    echo "$ws"
    echo "$hy2"
    echo "$tuic"
  } >"$CONFIG_DIR/subscription.txt"

  printf '%s' "$(base64 -w0 <"$CONFIG_DIR/subscription.txt")" >"$WWW_ROOT/sub"

  # 极简站点：暴露 /sub
  cat >/etc/nginx/sites-enabled/edgebox-sub <<'EOF'
server {
  listen 80;
  server_name _;
  root /var/www/html;
  default_type text/plain;
  location = /sub { try_files /sub =404; }
}
EOF
  systemctl reload nginx || true

  ok "订阅（纯文本）：$CONFIG_DIR/subscription.txt"
  ok "订阅 URL： http://${SERVER_IP}/sub"
}

# ========= 验证与摘要 =========
show_summary() {
  echo
  ok "安装完成！关键信息："
  echo "  IP:                 ${SERVER_IP}"
  echo "  VLESS UUID:         ${UUID_VLESS}"
  echo "  Reality pbk/sid:    ${REALITY_PUBLIC_KEY} / ${REALITY_SHORT_ID}"
  echo "  Hysteria2 密码:     ${PASSWORD_HYSTERIA2}"
  echo "  TUIC UUID/密码:     ${UUID_TUIC} / ${PASSWORD_TUIC}"
  echo "  订阅链接:           http://${SERVER_IP}/sub"
  echo
  log "端口监听（期望）："
  ss -tulpen | egrep '(:443\b|:2053\b|127\.0\.0\.1:10443)' || true
  echo
}

main() {
  need_root
  install_deps
  load_or_init_state
  ensure_self_signed_cert
  configure_nginx
  configure_xray
  configure_singbox
  generate_subscription
  show_summary
}

main "$@"
