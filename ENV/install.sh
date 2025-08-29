#!/usr/bin/env bash
set -Eeuo pipefail
trap 'err "第 ${BASH_LINENO[0]} 行命令失败：$BASH_COMMAND"' ERR

VERSION="2.1.0"

# ====== 颜色 & 日志 ======
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log()       { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()        { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
warn()      { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()       { echo -e "${RED}[ERROR]${NC} $*"; }

# ====== 路径 & 常量 ======
BASE_DIR="/etc/edgebox"
CFG_DIR="$BASE_DIR/config"
META_DIR="$BASE_DIR/meta"
CERT_DIR="$BASE_DIR/cert"
BIN_DIR="/usr/local/bin"
XRAY_BIN="$BIN_DIR/xray"
SING_BOX_BIN="$BIN_DIR/sing-box"

XRAY_CFG="$CFG_DIR/xray.json"
SB_CFG="$CFG_DIR/sing-box.json"

# 外部端口（固定）
TCP_443=443
HY2_UDP=443
TUIC_UDP=2053

# 内部回环端口（固定，仅本机）
STREAM_PORT=10443
GRPC_PORT=10085
WS_PORT=10086

# WS/GRPC 标识
WS_PATH="/edgebox-ws"
GRPC_SVC="edgebox-grpc"

# 伪装 SNI 备选
REALI_SNI="www.cloudflare.com"
REALI_SNI2="www.microsoft.com"
REALI_SNI3="www.apple.com"

# ====== 工具函数 ======
need_root() { [[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }; }
get_ip() { curl -fsS --max-time 3 https://api.ipify.org || curl -4fsS ifconfig.me || echo "0.0.0.0"; }

apt_install() {
  log "安装依赖..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget jq unzip tar openssl uuid-runtime vnstat iftop \
    nginx libnginx-mod-stream certbot python3-certbot-nginx
  ok "依赖安装完成"
}

prepare_dirs() {
  log "创建目录..."
  mkdir -p "$CFG_DIR" "$META_DIR" "$CERT_DIR" /etc/nginx/stream.d
  chmod -R 755 "$BASE_DIR"
  ok "目录就绪"
}

gen_self_signed() {
  log "生成自签证书..."
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -subj "/CN=edgebox.local" \
    -keyout "$CERT_DIR/self-signed.key" \
    -out    "$CERT_DIR/self-signed.pem" >/dev/null 2>&1
  ln -sf "$CERT_DIR/self-signed.pem" "$CERT_DIR/current.pem"
  ln -sf "$CERT_DIR/self-signed.key" "$CERT_DIR/current.key"
  chmod 640 "$CERT_DIR"/self-signed.* "$CERT_DIR"/current.*
  ok "自签证书 OK（软链已指向自签）"
}

install_xray() {
  log "安装 Xray..."
  # 固定到较新稳定版，避免上游变动导致参数失配
  local ver="v25.8.3"
  local zip="/tmp/Xray-linux-64.zip"
  wget -qO "$zip" "https://github.com/XTLS/Xray-core/releases/download/${ver}/Xray-linux-64.zip"
  unzip -o "$zip" xray geoip.dat geosite.dat -d /usr/local/bin >/dev/null
  chmod +x "$XRAY_BIN"
  # systemd
  cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network-online.target

[Service]
Type=simple
LimitNOFILE=1048576
ExecStart=$XRAY_BIN run -config $XRAY_CFG
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  ok "Xray 安装完成"
}

install_singbox() {
  log "安装 sing-box..."
  local ver="1.12.4"
  local tgz="/tmp/sing-box-${ver}-linux-amd64.tar.gz"
  wget -qO "$tgz" "https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-amd64.tar.gz"
  tar -xzf "$tgz" -C /tmp
  install -m 0755 "/tmp/sing-box-${ver}-linux-amd64/sing-box" "$SING_BOX_BIN"
  # systemd
  cat >/etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
After=network-online.target

[Service]
Type=simple
LimitNOFILE=1048576
ExecStart=$SING_BOX_BIN run -c $SB_CFG
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  ok "sing-box 安装完成"
}

gen_credentials() {
  log "生成通行凭据..."
  local UUID HY2_USER HY2_PASS TUIC_UUID TUIC_PASS pk pub sid

  UUID="$(uuidgen)"
  HY2_USER="$(openssl rand -hex 4)"     # 8
  HY2_PASS="$(openssl rand -hex 7)"     # 14
  TUIC_UUID="$(uuidgen)"
  TUIC_PASS="$(openssl rand -hex 8)"    # 16

  # —— 稳健获取 Reality 密钥对
  local k
  k="$("$XRAY_BIN" x25519 2>/dev/null || true)"
  pk="$(printf '%s\n' "$k" | awk -F': *' '/Private/{print $2}')"
  pub="$(printf '%s\n' "$k" | awk -F': *' '/Public/{print $2}')"
  if [[ -z "${pk:-}" || -z "${pub:-}" ]]; then
    err "生成 Reality 密钥失败（xray x25519 无输出）"
    exit 1
  fi

  sid="$(openssl rand -hex 4)"          # 8

  cat >"$META_DIR/config.env" <<EOF
# === EdgeBox 元数据（勿手改） ===
EB_UUID="$UUID"

REALITY_PRIVATE="$pk"
REALITY_PUBLIC="$pub"
SHORT_ID="$sid"

HY2_USER="$HY2_USER"
HY2_PASS="$HY2_PASS"

TUIC_UUID="$TUIC_UUID"
TUIC_PASS="$TUIC_PASS"

WS_PATH="$WS_PATH"
GRPC_SVC="$GRPC_SVC"
EOF
  chmod 600 "$META_DIR/config.env"
  ok "凭据已写入 $META_DIR/config.env"
}

load_env() { set -a; source "$META_DIR/config.env"; set +a; }

write_nginx_stream() {
  log "写 Nginx stream 分流..."
  # 主配置确保加载动态模块
  cat >/etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events { worker_connections 1024; }

http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on; tcp_nopush on; tcp_nodelay on;
  keepalive_timeout 65;
  access_log /var/log/nginx/access.log;
  error_log  /var/log/nginx/error.log warn;

  include /etc/nginx/conf.d/*.conf;
  include /etc/nginx/sites-enabled/*;
}

# 关键：加载动态模块
include /etc/nginx/modules-enabled/*.conf;

stream { include /etc/nginx/stream.d/*.conf; }
EOF

  # 分流配置
  cat >/etc/nginx/stream.d/edgebox.conf <<EOF
upstream grpc_backend { server 127.0.0.1:${GRPC_PORT}; }
upstream ws_backend   { server 127.0.0.1:${WS_PORT}; }

map \$ssl_preread_alpn_protocols \$stream_backend {
    ~\\bh2\\b  grpc_backend;
    default   ws_backend;
}

server {
    listen 127.0.0.1:${STREAM_PORT};
    ssl_preread on;
    proxy_pass \$stream_backend;
}
EOF

  nginx -t
  systemctl enable --now nginx
  ok "Nginx stream 配置完成（监听 127.0.0.1:${STREAM_PORT}）"
}

write_xray_cfg() {
  load_env
  log "写 Xray 配置..."

  cat >"$XRAY_CFG" <<EOF
{
  "log": { "level": "warning" },
  "inbounds": [
    {
      "tag": "vless-reality-in",
      "listen": "::",
      "port": ${TCP_443},
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [{ "id": "${EB_UUID}", "flow": "xtls-rprx-vision" }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALI_SNI}:443",
          "serverNames": ["${REALI_SNI}", "${REALI_SNI2}", "${REALI_SNI3}"],
          "privateKey": "${REALITY_PRIVATE}",
          "shortIds": ["${SHORT_ID}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["tls","http"] },
      "fallbacks": [
        { "alpn": "h2",       "dest": "127.0.0.1:${STREAM_PORT}", "xver": 0 },
        { "alpn": "http/1.1", "dest": "127.0.0.1:${STREAM_PORT}", "xver": 0 }
      ]
    },

    {
      "tag": "vless-grpc-in",
      "listen": "127.0.0.1",
      "port": ${GRPC_PORT},
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [{ "id": "${EB_UUID}" }]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "grpcSettings": { "serviceName": "${GRPC_SVC}" },
        "tlsSettings": {
          "alpn": ["h2"],
          "certificates": [
            { "certificateFile": "${CERT_DIR}/current.pem", "keyFile": "${CERT_DIR}/current.key" }
          ]
        }
      }
    },

    {
      "tag": "vless-ws-in",
      "listen": "127.0.0.1",
      "port": ${WS_PORT},
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [{ "id": "${EB_UUID}" }]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "wsSettings": { "path": "${WS_PATH}" },
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [
            { "certificateFile": "${CERT_DIR}/current.pem", "keyFile": "${CERT_DIR}/current.key" }
          ]
        }
      }
    }
  ],
  "outbounds": [{ "protocol": "freedom" }, { "protocol": "blackhole", "tag": "blocked" }]
}
EOF

  ok "Xray 配置完成"
}

write_singbox_cfg() {
  load_env
  log "写 sing-box 配置..."

  cat >"$SB_CFG" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "0.0.0.0",
      "listen_port": ${HY2_UDP},
      "users": [{ "username": "${HY2_USER}", "password": "${HY2_PASS}" }],
      "tls": {
        "alpn": ["h3"],
        "certificate_path": "${CERT_DIR}/current.pem",
        "key_path": "${CERT_DIR}/current.key"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "0.0.0.0",
      "listen_port": ${TUIC_UDP},
      "users": [{ "uuid": "${TUIC_UUID}", "password": "${TUIC_PASS}" }],
      "tls": {
        "alpn": ["h3"],
        "certificate_path": "${CERT_DIR}/current.pem",
        "key_path": "${CERT_DIR}/current.key"
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF

  ok "sing-box 配置完成"
}

create_edgeboxctl() {
  log "安装管理工具 edgeboxctl..."

  cat >"$BIN_DIR/edgeboxctl" <<'EOFCTL'
#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_DIR="/etc/edgebox/config"
CERT_DIR="/etc/edgebox/cert"
META_DIR="/etc/edgebox/meta"
XRAY_CFG="$CONFIG_DIR/xray.json"
SB_CFG="$CONFIG_DIR/sing-box.json"

# 读元数据
if [[ -f "$META_DIR/config.env" ]]; then
  set -a; source "$META_DIR/config.env"; set +a
fi

color() { local c="$1"; shift; printf "\033[%sm%s\033[0m\n" "$c" "$*"; }
ok()    { color "0;32" "$@"; }
info()  { color "0;34" "$@"; }
warn()  { color "1;33" "$@"; }
err()   { color "0;31" "$@"; }

get_ip() { curl -fsS --max-time 3 https://api.ipify.org || echo "0.0.0.0"; }
has_le() { [[ -n "${1:-}" && -f "/etc/letsencrypt/live/$1/fullchain.pem" && -f "/etc/letsencrypt/live/$1/privkey.pem" ]]; }

reload_all() {
  systemctl daemon-reload
  systemctl restart xray sing-box nginx
}

usage() {
cat <<'EOT'
EdgeBox 管理工具
用法: edgeboxctl <命令>

命令：
  status                查看服务状态
  doctor                快速检查配置/监听
  restart               重启全部服务
  logs                  查看最近日志（简）
  sub [domain]          输出 5 协议订阅链接（可选覆写域名）
  change-to-domain <d>  切换到域名模式（自动申请证书）
  change-to-ip          切换回 IP 模式（自签证书）

EOT
}

status() {
  echo "=== EdgeBox 服务状态 ==="
  systemctl --no-pager --type=service --state=running,failed,activating | grep -E 'xray|sing-box|nginx' || true
}

doctor() {
  echo "检查配置与监听..."
  xray -test -config "$XRAY_CFG" || true
  nginx -t || true
  sing-box check -c "$SB_CFG" || true
  ss -lntup | grep -E ':443\b|:2053\b|:10443\b|:1008[56]\b' || true
  status
}

sub() {
  local domain="${1:-}"
  local ip="$(get_ip)"
  local addr sni grpc_sni ws_sni insecure tuic_flag

  if [[ -n "$domain" && "$(has_le "$domain"; echo $?)" -eq 0 ]]; then
    addr="$domain"; sni="$domain"; grpc_sni="$domain"; ws_sni="$domain"; insecure=""
  else
    addr="$ip"; sni="www.cloudflare.com"; grpc_sni="grpc.edgebox.local"; ws_sni="www.edgebox.local"; insecure="&allowInsecure=1"
  fi

  echo "=== 订阅链接（$addr） ==="
  echo "1) VLESS-Reality"
  echo "vless://${EB_UUID}@${addr}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&spx=%2F#EB-REALITY"
  echo "2) VLESS-gRPC (TLS)"
  echo "vless://${EB_UUID}@${addr}:443?type=grpc&security=tls&alpn=h2&serviceName=${GRPC_SVC}&sni=${grpc_sni}&encryption=none${insecure}#EB-gRPC"
  echo "3) VLESS-WS (TLS)"
  echo "vless://${EB_UUID}@${addr}:443?type=ws&security=tls&path=${WS_PATH}&sni=${ws_sni}&host=${ws_sni}&alpn=http/1.1&encryption=none${insecure}#EB-WS"
  echo "4) Hysteria2"
  if [[ -n "$insecure" ]]; then
    echo "hy2://${HY2_USER}:${HY2_PASS}@${addr}:443/?insecure=1&sni=${sni}#EB-HY2"
  else
    echo "hy2://${HY2_USER}:${HY2_PASS}@${addr}:443/?sni=${sni}#EB-HY2"
  fi
  echo "5) TUIC"
  if [[ -n "$insecure" ]]; then
    echo "tuic://${TUIC_UUID}:${TUIC_PASS}@${addr}:2053?alpn=h3&congestion=bbr&allow_insecure=1&sni=${sni}#EB-TUIC"
  else
    echo "tuic://${TUIC_UUID}:${TUIC_PASS}@${addr}:2053?alpn=h3&congestion=bbr&sni=${sni}#EB-TUIC"
  fi
}

change_to_domain() {
  local domain="${1:-}"
  [[ -z "$domain" ]] && { err "请提供域名"; exit 1; }
  info "申请 Let's Encrypt 证书：$domain"
  systemctl stop nginx xray sing-box || true
  certbot certonly --standalone -d "$domain" --agree-tos --register-unsafely-without-email --preferred-challenges http >/dev/null
  ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" "$CERT_DIR/current.pem"
  ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem"   "$CERT_DIR/current.key"
  echo "$domain" > "$META_DIR/domain.txt"
  reload_all
  ok "切换到域名模式：$domain"
}

change_to_ip() {
  info "切回自签证书（IP 模式）..."
  ln -sf "$CERT_DIR/self-signed.pem" "$CERT_DIR/current.pem"
  ln -sf "$CERT_DIR/self-signed.key" "$CERT_DIR/current.key"
  : > "$META_DIR/domain.txt" || true
  reload_all
  ok "已切换到 IP 模式"
}

logs() {
  journalctl -u xray -u sing-box -u nginx -n 120 --no-pager
}

case "${1:-}" in
  status) status ;;
  doctor) doctor ;;
  restart) reload_all ;;
  logs) logs ;;
  sub) sub "${2:-}" ;;
  change-to-domain) change_to_domain "${2:-}" ;;
  change-to-ip) change_to_ip ;;
  *) usage ;;
esac
EOFCTL

  chmod +x "$BIN_DIR/edgeboxctl"
  ok "edgeboxctl 安装完成"
}

open_firewall_hint() {
  warn "请确认 GCP 防火墙已放行：tcp/443, udp/443, udp/2053；其它多余端口可关闭。"
}

start_all() {
  log "启动服务..."
  systemctl enable --now nginx xray sing-box
  sleep 1
  ok "服务已启动"
}

final_tips() {
  local ip="$(get_ip)"
  cat <<EOF

========================================
EdgeBox 安装完成（v${VERSION}）
模式：IP 模式（自签，客户端需允许不安全）
服务器 IP：${ip}
----------------------------------------
常用命令：
  edgeboxctl status            # 查看状态
  edgeboxctl sub               # 输出订阅链接（IP 模式带 allowInsecure）
  edgeboxctl change-to-domain your.domain
  edgeboxctl change-to-ip
  edgeboxctl doctor
  edgeboxctl logs
========================================
EOF
}

# ====== 执行顺序 ======
need_root
log "EdgeBox 安装脚本 ${VERSION} —— 开始"
apt_install
prepare_dirs
gen_self_signed
install_xray
install_singbox
gen_credentials
write_nginx_stream
write_xray_cfg
write_singbox_cfg
create_edgeboxctl
open_firewall_hint
start_all
final_tips
