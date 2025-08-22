#!/usr/bin/env bash
# EdgeBox Installer: Five-in-one node (VLESS-gRPC/WS + Reality + HY2 + TUIC)
# OS: Debian/Ubuntu (root)
set -Eeuo pipefail

# ---------- Configurable defaults ----------
SBOX_VER="${SBOX_VER:-1.12.2}"     # sing-box pinned version (your stable pick)
GRPC_PORT=8443                     # external TCP via Nginx
WS_PATH="/ws"                      # default WS path (可改)
HY2_PORT_DEFAULT=443               # HY2 UDP default port (443 or 8443)
TUIC_PORT=2053                     # TUIC UDP port
XRAY_GRPC_BACKEND=127.0.0.1:3001   # Xray inbounds (internal)
XRAY_WS_BACKEND=127.0.0.1:3002
CRT=/etc/nginx/ssl/edgebox.crt
KEY=/etc/nginx/ssl/edgebox.key
SUB_FILE=/var/lib/sb-sub/urls.txt
NGX_SUB=/var/www/html/sub/urls.txt
SB_CFG=/etc/sing-box/config.json
XRAY_CFG=/usr/local/etc/xray/config.json

# ---------- Helpers ----------
color() { local c="$1"; shift; printf "\033[%sm%s\033[0m\n" "$c" "$*"; }
info(){ color '1;36' "➤ $*"; }
ok(){ color '1;32' "✓ $*"; }
warn(){ color '1;33' "⚠ $*"; }
err(){ color '1;31' "✗ $*"; }
ask_yn(){ local q="$1" d="${2:-y}" a; read -rp "$q [y/N] (default:$d) " a || true; a="${a:-$d}"; [[ "$a" =~ ^[Yy]$ ]]; }
ask_def(){ local q="$1" d="${2:-}" a; read -rp "$q (default:${d:-空}) " a || true; echo "${a:-$d}"; }

need_root(){ [[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }; }
need_root

# ---------- Packages ----------
info "安装依赖..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl wget unzip jq socat openssl ufw nginx

mkdir -p /etc/nginx/ssl /var/lib/sb-sub /var/www/html/sub

# ---------- Install Xray ----------
if ! command -v xray >/dev/null 2>&1; then
  info "安装 Xray..."
  bash -c 'curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- --force'
fi
ok "Xray: $(xray -version 2>/dev/null | head -n1 || echo installed)"

# ---------- Install sing-box (pinned) ----------
if ! command -v sing-box >/dev/null 2>&1 || ! sing-box version 2>/dev/null | grep -q "$SBOX_VER"; then
  info "安装 sing-box v$SBOX_VER..."
  tmp=$(mktemp -d)
  pushd "$tmp" >/dev/null
  url="https://github.com/SagerNet/sing-box/releases/download/v${SBOX_VER}/sing-box-${SBOX_VER}-linux-amd64.tar.gz"
  curl -fL "$url" -o sb.tar.gz
  tar -xzf sb.tar.gz
  install -m755 "sing-box-${SBOX_VER}-linux-amd64/sing-box" /usr/local/bin/sing-box
  popd >/dev/null
  rm -rf "$tmp"
fi
ok "sing-box: $(sing-box version | head -n1)"

# ---------- Interact ----------
ip_pub=$(curl -fsSL https://ifconfig.me || curl -fsSL https://ipinfo.io/ip || echo "")
echo
info "域名与证书"
DOMAIN=$(ask_def "输入域名（留空=用自签证书，可用 IP 访问订阅；填写=自动申请 ACME 真证书）" "")
[[ -z "$DOMAIN" ]] && ok "使用自签证书，订阅将可通过 http://$ip_pub/sub/urls.txt 访问"

echo
info "协议选择（y=启用 / n=关闭）"
ENABLE_GRPC=$(ask_def "启用 VLESS-gRPC(8443/tcp，经 Nginx) ? [y/n]" "y")
ENABLE_WS=$(ask_def   "启用 VLESS-WS(8443/tcp，经 Nginx) ? [y/n]" "y")
ENABLE_REALITY=$(ask_def "启用 VLESS-Reality(443/tcp) ? [y/n]" "y")
ENABLE_HY2=$(ask_def "启用 Hysteria2(udp 443 或 8443) ? [y/n]" "y")
ENABLE_TUIC=$(ask_def "启用 TUIC(udp 2053) ? [y/n]" "n")

if [[ "$ENABLE_HY2" =~ ^[Yy]$ ]]; then
  hp=$(ask_def "HY2 端口 (443/8443)" "$HY2_PORT_DEFAULT")
  [[ "$hp" != "443" && "$hp" != "8443" ]] && hp="$HY2_PORT_DEFAULT"
  HY2_PORT="$hp"
else
  HY2_PORT=""
fi

echo
info "分流策略"
cat <<'EOT'
1) 全部直出（direct）【默认】
2) 绝大多数走住宅HTTP代理，仅 googlevideo / ytimg / ggpht 直出
EOT
ROUTE_OPT=$(ask_def "选择 (1/2)" "1")
HOME_HOST=""; HOME_PORT=""; HOME_USER=""; HOME_PASS=""
if [[ "$ROUTE_OPT" == "2" ]]; then
  HOME_HOST=$(ask_def "住宅HTTP代理 host/IP")
  HOME_PORT=$(ask_def "住宅HTTP代理 port")
  HOME_USER=$(ask_def "住宅HTTP代理 用户名(可空)" "")
  HOME_PASS=$(ask_def "住宅HTTP代理 密码(可空)" "")
  if [[ -z "$HOME_HOST" || -z "$HOME_PORT" ]]; then
    warn "住宅代理信息不完整，自动回退到【全部直出】"
    ROUTE_OPT="1"
  fi
fi

# ---------- Certs ----------
issue_self_signed() {
  warn "生成自签证书（客户端需允许不安全证书/skip verify）"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -subj "/CN=${DOMAIN:-edgebox.local}" \
    -keyout "$KEY" -out "$CRT" >/dev/null 2>&1
}
if [[ -n "$DOMAIN" ]]; then
  info "申请 ACME 证书（$DOMAIN）"
  # 最简 ACME via nginx
  curl -fsSL https://get.acme.sh | sh -s email=admin@"$DOMAIN" >/dev/null 2>&1 || true
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  # 临时 server 配合验证
  cat >/etc/nginx/conf.d/edgebox-acme.conf <<NG
server {
  listen 80;
  server_name $DOMAIN;
  location / { return 200 'OK'; add_header Content-Type text/plain; }
}
NG
  nginx -t && systemctl reload nginx || true
  if ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --nginx >/dev/null 2>&1; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
      --fullchain-file "$CRT" --key-file "$KEY" >/dev/null 2>&1
    ok "ACME 证书已安装"
  else
    warn "ACME 失败，回退自签证书"
    issue_self_signed
  fi
  rm -f /etc/nginx/conf.d/edgebox-acme.conf
else
  issue_self_signed
fi
chmod 600 "$KEY"; chmod 644 "$CRT"

# ---------- IDs / keys ----------
UUID=$(cat /proc/sys/kernel/random/uuid)
VR_UUID=$(cat /proc/sys/kernel/random/uuid)
HY2_PWD=$(head -c 12 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 12)
TUIC_UUID=$(cat /proc/sys/kernel/random/uuid)
TUIC_PWD=$(head -c 16 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 16)
# Reality keypair
read PRIV PBK < <(sing-box generate reality-keypair | awk '/Private/{p=$3}/Public/{print p,$3}')
SID=$(openssl rand -hex 4)
SNI="www.cloudflare.com"

# ---------- Xray config (gRPC/WS backends) ----------
mkdir -p /usr/local/etc/xray
cat >"$XRAY_CFG" <<JSON
{
  "inbounds": [
    $( [[ "$ENABLE_GRPC" =~ ^[Yy]$ ]] && cat <<GRPC
    {
      "port": ${XRAY_GRPC_BACKEND##*:},
      "listen": "${XRAY_GRPC_BACKEND%%:*}",
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$UUID" } ], "decryption": "none" },
      "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "@grpc" } }
    }$( [[ "$ENABLE_WS" =~ ^[Yy]$ ]] && echo , || true)
GRPC
)
    $( [[ "$ENABLE_WS" =~ ^[Yy]$ ]] && cat <<WS
    {
      "port": ${XRAY_WS_BACKEND##*:},
      "listen": "${XRAY_WS_BACKEND%%:*}",
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$UUID" } ], "decryption": "none" },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "$WS_PATH" } }
    }
WS
)
  ],
  "outbounds": [ { "protocol": "freedom" }, { "protocol": "blackhole", "tag": "blocked" } ]
}
JSON

# ---------- Nginx (TLS 8443 -> Xray) ----------
cat >/etc/nginx/conf.d/edgebox.conf <<NGX
# Subscription file
location = /sub/urls.txt { alias $NGX_SUB; default_type text/plain; }

# HTTPS for gRPC + WS
server {
  listen ${GRPC_PORT} ssl http2;
  server_name ${DOMAIN:-_};
  ssl_certificate     $CRT;
  ssl_certificate_key $KEY;
  ssl_protocols TLSv1.2 TLSv1.3;

  # gRPC
  location /@grpc {
    grpc_read_timeout 3600s;
    grpc_send_timeout 3600s;
    grpc_set_header X-Real-IP \$remote_addr;
    grpc_pass grpc://$XRAY_GRPC_BACKEND;
  }

  # WebSocket (VLESS-WS)
  location $WS_PATH {
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_pass http://$XRAY_WS_BACKEND;
  }

  # health
  location = /healthz { return 200 'ok'; add_header Content-Type text/plain; }
}
NGX
nginx -t && systemctl reload nginx

# ---------- sing-box config ----------
# outbounds
ROUTE_JSON_FINAL='"direct"'
HOME_OUTBOUND=''
if [[ "$ROUTE_OPT" == "2" ]]; then
  HOME_OUTBOUND=$(jq -n --arg host "$HOME_HOST" --argjson port "$HOME_PORT" \
    --arg user "$HOME_USER" --arg pass "$HOME_PASS" '
    {
      "type":"http",
      "tag":"home_http",
      "server":$host,
      "server_port":($port|tonumber),
      "username": ( ($user|length)>0 ? $user : null ),
      "password": ( ($pass|length)>0 ? $pass : null )
    }' )
  ROUTE_JSON_FINAL='"home_http"'
fi

# rules
if [[ "$ROUTE_OPT" == "2" ]]; then
  RULES=$(jq -n '
    [{"domain":["domain:googlevideo.com","domain:ytimg.com","domain:ggpht.com"],"outbound":"direct"}]')
else
  RULES="[]"
fi

# inbounds list
SB_INBOUNDS=()

if [[ "$ENABLE_REALITY" =~ ^[Yy]$ ]]; then
  SB_INBOUNDS+=("$(jq -n --arg uuid "$VR_UUID" --arg priv "$PRIV" --arg sid "$SID" --arg sni "$SNI" '
  {
    "type":"vless","tag":"vless-reality","listen":"::","listen_port":443,
    "users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],
    "tls":{"enabled":true,"reality":{"enabled":true,"private_key":$priv,"short_id":[ $sid ],"handshake":{"server":$sni,"server_port":443}}}
  }')")
fi

if [[ "$ENABLE_HY2" =~ ^[Yy]$ ]]; then
  SB_INBOUNDS+=("$(jq -n --argjson port "$HY2_PORT" --arg pwd "$HY2_PWD" --arg crt "$CRT" --arg key "$KEY" '
  {
    "type":"hysteria2","tag":"hy2","listen":"::","listen_port":($port|tonumber),
    "users":[{"password":$pwd}],
    "tls":{"enabled":true,"certificate_path":$crt,"key_path":$key,"alpn":["h3"]}
  }')")
fi

if [[ "$ENABLE_TUIC" =~ ^[Yy]$ ]]; then
  SB_INBOUNDS+=("$(jq -n --argjson port "$TUIC_PORT" --arg uuid "$TUIC_UUID" --arg pwd "$TUIC_PWD" --arg crt "$CRT" --arg key "$KEY" '
  {
    "type":"tuic","tag":"tuic","listen":"::","listen_port":($port|tonumber),
    "users":[{"uuid":$uuid,"password":$pwd}],
    "tls":{"enabled":true,"certificate_path":$crt,"key_path":$key}
  }')")
fi

# assemble sing-box config
jq -n \
  --argjson inbounds "$(printf '%s\n' "${SB_INBOUNDS[@]}" | jq -s '.')" \
  --argjson rules "$RULES" \
  --argjson final "$ROUTE_JSON_FINAL" \
  --argjson home_outbound "${HOME_OUTBOUND:-null}" '
{
  "log":{"level":"info"},
  "inbounds": $inbounds,
  "outbounds": (
     [ {"type":"direct","tag":"direct"}, {"type":"block","tag":"block"} ] +
     ( $home_outbound|type=="object" ? [ $home_outbound ] : [] )
  ),
  "route": { "rules": $rules, "final": $final }
}' >"$SB_CFG"

# ---------- systemd units ----------
cat >/etc/systemd/system/xray.service <<'UNIT'
[Unit]
Description=Xray Service
After=network.target

[Service]
User=nobody
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=always
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=sing-box unified service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now xray
systemctl enable --now sing-box

# ---------- Firewall (UFW) ----------
info "配置 UFW 放行..."
ufw allow "${GRPC_PORT}/tcp" >/dev/null 2>&1 || true
[[ "$ENABLE_REALITY" =~ ^[Yy]$ ]] && ufw allow 443/tcp >/dev/null 2>&1 || true
[[ "$ENABLE_HY2" =~ ^[Yy]$ && -n "$HY2_PORT" ]] && ufw allow "${HY2_PORT}/udp" >/dev/null 2>&1 || true
[[ "$ENABLE_TUIC" =~ ^[Yy]$ ]] && ufw allow "${TUIC_PORT}/udp" >/dev/null 2>&1 || true

# ---------- Subscription ----------
ln -sf "$SUB_FILE" "$NGX_SUB"
: >"$SUB_FILE"

# gRPC
if [[ "$ENABLE_GRPC" =~ ^[Yy]$ ]]; then
  printf 'vless://%s@%s:%s?encryption=none&security=tls&type=grpc&serviceName=@grpc&fp=chrome#VLESS-gRPC@%s\n' \
    "$UUID" "${DOMAIN:-$ip_pub}" "$GRPC_PORT" "${DOMAIN:-$ip_pub}" >>"$SUB_FILE"
fi
# WS
if [[ "$ENABLE_WS" =~ ^[Yy]$ ]]; then
  printf 'vless://%s@%s:%s?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n' \
    "$UUID" "${DOMAIN:-$ip_pub}" "$GRPC_PORT" "$WS_PATH" "${DOMAIN:-$ip_pub}" "${DOMAIN:-$ip_pub}" >>"$SUB_FILE"
fi
# Reality
if [[ "$ENABLE_REALITY" =~ ^[Yy]$ ]]; then
  printf 'vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n' \
    "$VR_UUID" "${DOMAIN:-$ip_pub}" "$SNI" "$PBK" "$SID" "${DOMAIN:-$ip_pub}" >>"$SUB_FILE"
fi
# HY2
if [[ "$ENABLE_HY2" =~ ^[Yy]$ && -n "$HY2_PORT" ]]; then
  printf 'hysteria2://%s@%s:%s?alpn=h3#HY2@%s\n' "$HY2_PWD" "${DOMAIN:-$ip_pub}" "$HY2_PORT" "${DOMAIN:-$ip_pub}" >>"$SUB_FILE"
fi
# TUIC
if [[ "$ENABLE_TUIC" =~ ^[Yy]$ ]]; then
  printf 'tuic://%s:%s@%s:%s?congestion=bbr&alpn=h3#TUIC@%s\n' \
    "$TUIC_UUID" "$TUIC_PWD" "${DOMAIN:-$ip_pub}" "$TUIC_PORT" "${DOMAIN:-$ip_pub}" >>"$SUB_FILE"
fi

# ---------- Health / Output ----------
sleep 1
info "监听端口（tcp/udp）："
ss -lnptu | egrep ':443|:'"$GRPC_PORT"'|:'"$TUIC_PORT"'' || true

ok "订阅链接： http://${DOMAIN:-$ip_pub}/sub/urls.txt"
nl -ba "$SUB_FILE" | sed -n '1,120p'

info "服务状态（如有异常可查看日志）："
systemctl --no-pager -l status xray | sed -n '1,20p'
systemctl --no-pager -l status sing-box | sed -n '1,20p'
