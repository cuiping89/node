#!/usr/bin/env bash
# EdgeBox 安装脚本 v2.2.0（非交互 IP 模式，五协议即装即用）
# 端口：TCP/443（Reality直连+回落到Nginx:10443→Xray:10085/10086），UDP/443(Hy2), UDP/2053(TUIC)

set -Eeuo pipefail

# ===== 通用变量 =====
XRAY_BIN="/usr/local/bin/xray"
SBOX_BIN="/usr/local/bin/sing-box"
EB_DIR="/etc/edgebox"
CFG_DIR="$EB_DIR/config"
CERT_DIR="$EB_DIR/cert"
META_DIR="$EB_DIR/meta"
BIN_DIR="$EB_DIR/bin"
LOG_DIR="/var/log/edgebox"

WS_PATH="/edgebox-ws"
GRPC_SVC="edgebox-grpc"

# ===== 日志工具 =====
c_ok="\033[1;32m[SUCCESS]\033[0m"
c_info="\033[1;34m[INFO]\033[0m"
c_err="\033[1;31m[ERROR]\033[0m"

ok(){   echo -e "$c_ok $*"; }
log(){  echo -e "$c_info $*"; }
err(){  echo -e "$c_err $*" >&2; }

# ===== 基础检查与安装 =====
need_root(){ [[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }; }
need_os(){
  . /etc/os-release
  case "${ID}-${VERSION_ID}" in
    ubuntu-22.04|ubuntu-24.04) ok "系统检查通过: $PRETTY_NAME" ;;
    *) err "仅支持 Ubuntu 22.04/24.04（当前 $PRETTY_NAME）"; exit 1 ;;
  esac
}

apt_install(){
  log "安装依赖..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl wget jq unzip tar openssl uuid-runtime vnstat iftop \
    nginx libnginx-mod-stream certbot python3-certbot-nginx
  ok "依赖安装完成"
}

mk_dirs(){
  log "创建目录结构..."
  install -d -m 755 "$CFG_DIR" "$CERT_DIR" "$META_DIR" "$BIN_DIR" "$LOG_DIR" /etc/nginx/stream.d
  ok "目录就绪"
}

get_ip(){ curl -fsS --max-time 3 https://api.ipify.org || true; }

# ===== 凭据生成（无管道，避免 pipefail 问题） =====
gen_credentials(){
  log "生成凭据..."
  local UUID HY2_USER HY2_PASS TUIC_UUID TUIC_PASS sid k pk pub
  UUID="$(uuidgen)"
  HY2_USER="$(openssl rand -hex 4)"     # 8位
  HY2_PASS="$(openssl rand -hex 7)"     # 14位
  TUIC_UUID="$(uuidgen)"
  TUIC_PASS="$(openssl rand -hex 8)"    # 16位

  # Reality 密钥对
  k="$("$XRAY_BIN" x25519 2>/dev/null || true)"
  pk="$(printf '%s\n' "$k" | awk -F': *' '/Private/{print $2}')"
  pub="$(printf '%s\n' "$k" | awk -F': *' '/Public/{print $2}')"
  [[ -n "${pk:-}" && -n "${pub:-}" ]] || { err "Reality密钥生成失败"; exit 1; }
  sid="$(openssl rand -hex 4)"

  cat >"$META_DIR/config.env" <<EOF
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

# ===== 证书：自签 & 动态软链 =====
self_signed(){
  log "生成自签证书..."
  local pem="$CERT_DIR/self-signed.pem" key="$CERT_DIR/self-signed.key"
  [[ -f $pem && -f $key ]] || \
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=edgebox.local" \
    -keyout "$key" -out "$pem" >/dev/null 2>&1
  ln -sf "$pem" "$CERT_DIR/current.pem"
  ln -sf "$key" "$CERT_DIR/current.key"
  chmod 640 "$CERT_DIR"/self-signed.* "$CERT_DIR"/current.*
  ok "自签证书已就绪并指向 current.*"
}

# ===== 安装 Xray / sing-box =====
install_xray(){
  log "安装 Xray..."
  bash <(curl -fsSL https://raw.githubusercontent.com/xtls/Xray-install/main/install-release.sh) >/dev/null 2>&1 || true
  command -v xray >/dev/null || { err "Xray 安装失败"; exit 1; }
  ok "Xray 安装完成（service 就绪）"
}

install_singbox(){
  log "安装 sing-box..."
  local v="1.12.4"  # 稳定版
  cd /tmp
  curl -fsSLO "https://github.com/SagerNet/sing-box/releases/download/v${v}/sing-box-${v}-linux-amd64.tar.gz"
  tar -zxf "sing-box-${v}-linux-amd64.tar.gz"
  install -m 755 "sing-box-${v}-linux-amd64/sing-box" /usr/local/bin/sing-box
  ok "sing-box 安装完成"
}

# ===== 写 Nginx（修复 load_module too late） =====
write_nginx(){
  log "配置 Nginx（stream 分流）..."
  # 1) stream 分流
  cat > /etc/nginx/stream.d/edgebox.conf <<'EOF'
upstream grpc_backend { server 127.0.0.1:10085; }
upstream ws_backend   { server 127.0.0.1:10086; }

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

  # 2) 主配置 —— 把 modules-enabled 放在**首行**，彻底避免“load_module too late”
  cat > /etc/nginx/nginx.conf <<'EOF'
include /etc/nginx/modules-enabled/*.conf;

user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

events { worker_connections 1024; }

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    sendfile on; tcp_nopush on; tcp_nodelay on;
    keepalive_timeout 65; types_hash_max_size 2048;
}

stream {
    include /etc/nginx/stream.d/*.conf;
}
EOF

  nginx -t
  systemctl enable --now nginx >/dev/null 2>&1 || true
  ok "Nginx stream 配置完成（监听 127.0.0.1:10443）"
}

# ===== 写 Xray / sing-box 配置 =====
write_xray_cfg(){
  # shellcheck disable=SC1091
  . "$META_DIR/config.env"
  local IP
  IP="$(get_ip)"
  log "写入 Xray 配置..."
  cat > "$CFG_DIR/xray.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-reality-in",
      "port": 443,
      "listen": "::",
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$EB_UUID", "flow": "xtls-rprx-vision" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$IP:443",
          "xver": 0,
          "serverNames": ["www.cloudflare.com","www.microsoft.com","www.apple.com"],
          "privateKey": "$REALITY_PRIVATE",
          "shortIds": ["$SHORT_ID"]
        }
      },
      "sniffing": { "enabled": false }
    },
    {
      "tag": "vless-grpc-in",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$EB_UUID" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": { "serviceName": "$GRPC_SVC" },
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2"],
          "certificates": [{
            "certificateFile": "$CERT_DIR/current.pem",
            "keyFile": "$CERT_DIR/current.key"
          }]
        }
      }
    },
    {
      "tag": "vless-ws-in",
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$EB_UUID" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "$WS_PATH" },
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [{
            "certificateFile": "$CERT_DIR/current.pem",
            "keyFile": "$CERT_DIR/current.key"
          }]
        }
      }
    }
  ],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

  # 覆盖 systemd，使用我们的路径
  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
ExecStart=$XRAY_BIN -config $CFG_DIR/xray.json
Restart=always
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  ok "Xray 配置完成"
}

write_singbox_cfg(){
  # shellcheck disable=SC1091
  . "$META_DIR/config.env"
  log "写入 sing-box 配置..."
  cat > "$CFG_DIR/sing-box.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": 443,
      "users": [{ "name": "$HY2_USER", "password": "$HY2_PASS" }],
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/current.pem",
        "key_path": "$CERT_DIR/current.key",
        "alpn": ["h3"]
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": 2053,
      "users": [{ "uuid": "$TUIC_UUID", "password": "$TUIC_PASS" }],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/current.pem",
        "key_path": "$CERT_DIR/current.key",
        "alpn": ["h3"]
      }
    }
  ]
}
EOF

  cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
After=network.target

[Service]
Type=simple
ExecStart=$SBOX_BIN run -c $CFG_DIR/sing-box.json
Restart=always
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  ok "sing-box 配置完成"
}

# ===== 管理工具 =====
install_edgeboxctl(){
  log "安装 edgeboxctl 管理工具..."
  cat > /usr/local/bin/edgeboxctl <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
EB_DIR="/etc/edgebox"
CFG_DIR="$EB_DIR/config"
CERT_DIR="$EB_DIR/cert"
META="$EB_DIR/meta/config.env"

# 颜色
g="\033[1;32m"; b="\033[1;34m"; r="\033[1;31m"; z="\033[0m"
ok(){   echo -e "${g}[OK]${z} $*"; }
info(){ echo -e "${b}[INFO]${z} $*"; }
err(){  echo -e "${r}[ERR]${z} $*" >&2; }

get_ip(){ curl -fsS --max-time 3 https://api.ipify.org || true; }
has_le_cert(){ [[ -n "${1:-}" && -f "/etc/letsencrypt/live/$1/fullchain.pem" && -f "/etc/letsencrypt/live/$1/privkey.pem" ]]; }

load_env(){ # shellcheck disable=SC1091
  . "$META"
}

cmd_help(){
  cat <<H
EdgeBox 管理工具
用法: edgeboxctl <命令>

可用命令：
  status             查看服务状态
  restart            重启全部服务
  logs               查看最近日志

  sub [domain]       输出 5 协议订阅/链接（可选覆盖域名）
  change-to-domain <domain>   切换到域名模式（申请/切换证书）
  change-to-ip       切回 IP 模式（自签证书）
  doctor             快速体检（配置与监听检查）
H
}

cmd_status(){
  echo "=== EdgeBox 服务状态 ==="
  systemctl --no-pager --type=service --state=running | grep -E 'nginx|xray|sing-box' || true
}

cmd_restart(){
  systemctl restart nginx xray sing-box
  ok "已重启 nginx/xray/sing-box"
}

cmd_logs(){
  journalctl -u xray -n 50 --no-pager || true
  journalctl -u sing-box -n 50 --no-pager || true
}

cmd_sub(){
  load_env
  local d="${1:-}"
  local addr insecure
  if [[ -n "$d" ]] && has_le_cert "$d"; then
    addr="$d"; insecure=""
    local grpc_sni="$d" ws_sni="$d"
    local sni_real="www.cloudflare.com"
  else
    addr="$(get_ip)"; insecure="&allowInsecure=1"
    local grpc_sni="grpc.edgebox.local" ws_sni="www.edgebox.local"
    local sni_real="www.cloudflare.com"
  fi

  echo "=== 订阅/链接（$addr） ==="
  # Reality
  echo "1) VLESS-Reality"
  echo "vless://$EB_UUID@$addr:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$sni_real&fp=chrome&pbk=$REALITY_PUBLIC&sid=$SHORT_ID&spx=%2F#EB-REALITY"
  # gRPC
  echo "2) VLESS-gRPC (TLS)"
  echo "vless://$EB_UUID@$addr:443?type=grpc&security=tls&alpn=h2&serviceName=$GRPC_SVC&sni=$grpc_sni&encryption=none${insecure}#EB-gRPC"
  # WS
  echo "3) VLESS-WS (TLS)"
  echo "vless://$EB_UUID@$addr:443?type=ws&security=tls&path=$WS_PATH&sni=$ws_sni&host=$ws_sni&alpn=http/1.1&encryption=none${insecure}#EB-WS"
  # Hysteria2
  echo "4) Hysteria2"
  # 常见URL：hy2://user:pass@host:port/?sni=xxx&insecure=1
  local hy2_insec
  if [[ -n "$d" ]] && has_le_cert "$d"; then hy2_insec="0"; else hy2_insec="1"; fi
  echo "hy2://$HY2_USER:$HY2_PASS@$addr:443/?sni=$sni_real&insecure=$hy2_insec#EB-HY2"
  # TUIC
  echo "5) TUIC"
  # 常见URL：tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&allow_insecure=1
  local tuic_insec
  if [[ -n "$d" ]] && has_le_cert "$d"; then tuic_insec="0"; else tuic_insec="1"; fi
  echo "tuic://$TUIC_UUID:$TUIC_PASS@$addr:2053?congestion_control=bbr&alpn=h3&allow_insecure=$tuic_insec#EB-TUIC"
}

cmd_change_to_domain(){
  local d="${1:-}"; [[ -n "$d" ]] || { err "用法: edgeboxctl change-to-domain <domain>"; exit 1; }
  info "申请 Let's Encrypt 证书: $d"
  systemctl stop nginx || true
  certbot certonly --standalone -d "$d" --agree-tos --register-unsafely-without-email -n || { err "证书申请失败"; exit 1; }
  ln -sf "/etc/letsencrypt/live/$d/fullchain.pem" "$CERT_DIR/current.pem"
  ln -sf "/etc/letsencrypt/live/$d/privkey.pem"   "$CERT_DIR/current.key"
  systemctl start nginx
  systemctl restart xray sing-box
  ok "切换到域名模式: $d"
}

cmd_change_to_ip(){
  ln -sf "$CERT_DIR/self-signed.pem" "$CERT_DIR/current.pem"
  ln -sf "$CERT_DIR/self-signed.key" "$CERT_DIR/current.key"
  systemctl restart xray sing-box
  ok "已切回 IP 模式（自签证书）"
}

cmd_doctor(){
  echo "检查配置与监听..."
  $XRAY_BIN -test -config "$CFG_DIR/xray.json" || true
  nginx -t || true
  $SBOX_BIN check -c "$CFG_DIR/sing-box.json" || true
  ss -lntup | grep -E ':443\b|:2053\b|:10443\b|:10085\b|:10086\b' || true
  systemctl --no-pager --type=service | grep -E 'nginx|xray|sing-box' || true
}

case "${1:-}" in
  status)  cmd_status ;;
  restart) cmd_restart ;;
  logs)    cmd_logs ;;
  sub)     shift; cmd_sub "${1:-}" ;;
  change-to-domain) shift; cmd_change_to_domain "${1:-}" ;;
  change-to-ip) cmd_change_to_ip ;;
  doctor)  cmd_doctor ;;
  ""|-h|--help) cmd_help ;;
  *) err "未知命令：$1"; cmd_help; exit 1 ;;
esac
EOF
  chmod +x /usr/local/bin/edgeboxctl
  ok "edgeboxctl 已安装"
}

# ===== 启动服务 =====
start_all(){
  systemctl enable --now xray sing-box >/dev/null 2>&1 || true
  systemctl restart nginx xray sing-box
  ok "服务已启动：nginx/xray/sing-box"
}

# ===== 主流程 =====
main(){
  echo "========================================"
  echo "EdgeBox 安装脚本 v2.2.0"
  echo "非交互式 IP 模式安装 —— 开始"
  echo "========================================"
  need_root
  need_os
  apt_install
  mk_dirs
  # 若 xray 尚未装，先装；用于生成 reality 密钥
  command -v xray >/dev/null || install_xray
  gen_credentials
  self_signed
  install_singbox
  write_nginx
  write_xray_cfg
  write_singbox_cfg
  install_edgeboxctl
  start_all
  echo
  ok "安装完成！默认 IP 模式已就绪。"
  echo "常用命令："
  echo "  edgeboxctl status         # 查看服务状态"
  echo "  edgeboxctl sub            # 输出 5 协议的链接"
  echo "  edgeboxctl change-to-domain your.domain   # 切到域名模式（申请并切换证书）"
  echo "  edgeboxctl change-to-ip   # 切回 IP 模式（自签证书）"
  echo "  edgeboxctl doctor         # 体检"
}
main "$@"
