#!/usr/bin/env bash
set -Eeuo pipefail

# ===== 提权（兼容 curl|bash / 进程替换）=====
if [[ $EUID -ne 0 ]]; then
  if [[ -r "/proc/$$/fd/0" ]]; then
    T="$(mktemp -t edgebox-install.XXXXXX.sh)"; cat "/proc/$$/fd/0" >"$T"
    exec sudo -E bash "$T" "$@"
  else
    exec sudo -E bash "$0" "$@"
  fi
fi

ok(){   printf "\033[32m[OK]\033[0m   %s\n" "$*"; }
step(){ printf "\n\033[1;34m[STEP]\033[0m %s\n" "$*"; }
warn(){ printf "\033[33m[WARN]\033[0m %s\n" "$*"; }
err(){  printf "\033[31m[ERR]\033[0m  %s\n" "$*"; }
q(){ "$@" >/dev/null 2>&1 || true; }

# ===== 常量 =====
XR_CFG="/usr/local/etc/xray/config.json"
SB_CFG="/etc/sing-box/config.json"
SSL_DIR="/etc/ssl/edgebox"
SUB_DIR="/var/lib/sb-sub"
SUB_FILE="$SUB_DIR/urls.txt"

SB_VER="1.12.2"
PORT_HTTP_TLS_LOOP=8443
PORT_REALITY_LOOP=14443
PORT_SNI_OUT=443
PORT_HY2_UDP=443
PORT_TUIC_UDP=2053
SNI_CF="www.cloudflare.com"

# 随机量
UUID_ALL="$(cat /proc/sys/kernel/random/uuid)"
UUID_VMESS="$(cat /proc/sys/kernel/random/uuid)"
WS_PATH="/$(openssl rand -hex 3)"
VMESS_PATH="/$(openssl rand -hex 3)vm"
GRPC_SVC="@grpc"
SID="$(openssl rand -hex 4)"
HY2_PWD="$(openssl rand -hex 12)"
TUIC_UUID="$(cat /proc/sys/kernel/random/uuid)"
TUIC_PWD="$(openssl rand -hex 12)"

cat <<'BANNER'
[INFO] 端口放行：tcp/443、udp/443(HY2)、udp/2053(TUIC)；可选 udp/8443（备用）。
[INFO] 请在云防火墙/安全组 + 本机(UFW/iptables) 同时放行。
BANNER

# ===== 依赖 =====
step "安装依赖（jq/openssl/socat/nginx/ufw/tar/unzip/file 等）"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y --no-install-recommends \
  ca-certificates curl wget openssl jq unzip tar gzip socat ufw nginx coreutils file >/dev/null

mkdir -p "$(dirname "$XR_CFG")" "$(dirname "$SB_CFG")" "$SUB_DIR" /var/www/html/sub "$SSL_DIR" /etc/nginx/stream.d

# ===== 交互 =====
read -rp "域名（留空=用自签证书；填入=自动 ACME）: " DOMAIN
read -rp "住宅代理（HOST:PORT[:USER[:PASS]]，留空=不用）: " HOME_LINE || true

HOME_HOST=""; HOME_PORT=""; HOME_USER=""; HOME_PASS=""
if [[ -n "${HOME_LINE:-}" ]]; then
  IFS=':' read -r HOME_HOST HOME_PORT HOME_USER HOME_PASS <<<"$HOME_LINE"
  if [[ -z "${HOME_HOST:-}" || -z "${HOME_PORT:-}" ]]; then
    warn "住宅代理信息不完整，回退为直出"; HOME_LINE=""
  fi
fi

# ===== 安装 Xray 并写配置 =====
step "安装 Xray（若已装则跳过）"
if ! command -v xray >/dev/null 2>&1; then
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null || true
fi
step "写入 Xray 配置（回环 11800/11801/11802）"
cat >"$XR_CFG" <<JSON
{
  "inbounds": [
    { "listen":"127.0.0.1","port":11800,"protocol":"vless",
      "settings":{"clients":[{"id":"$UUID_ALL"}],"decryption":"none"},
      "streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"$GRPC_SVC"}}},
    { "listen":"127.0.0.1","port":11801,"protocol":"vless",
      "settings":{"clients":[{"id":"$UUID_ALL"}],"decryption":"none"},
      "streamSettings":{"network":"ws","wsSettings":{"path":"$WS_PATH","headers":{"Host":"${DOMAIN:-localhost}"}}}},
    { "listen":"127.0.0.1","port":11802,"protocol":"vmess",
      "settings":{"clients":[{"id":"$UUID_VMESS"}]},
      "streamSettings":{"network":"ws","wsSettings":{"path":"$VMESS_PATH","headers":{"Host":"${DOMAIN:-localhost}"}}}}
  ],
  "outbounds":[{"protocol":"freedom"}]
}
JSON
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray || true

# ===== 证书 =====
CRT="$SSL_DIR/fullchain.crt"
KEY="$SSL_DIR/private.key"
issue_self(){
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$KEY" -out "$CRT" -subj "/CN=${DOMAIN:-edgebox.local}" >/dev/null 2>&1
}
if [[ -n "${DOMAIN:-}" ]]; then
  step "申请 ACME 证书：$DOMAIN（失败将回退自签）"
  q systemctl stop nginx
  if ! ~/.acme.sh/acme.sh -v >/dev/null 2>&1; then
    curl -fsSL https://get.acme.sh | sh -s email=admin@"${DOMAIN}" >/dev/null 2>&1 || true
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 >/dev/null 2>&1; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
      --fullchain-file "$CRT" --key-file "$KEY" >/dev/null 2>&1 || issue_self
  else
    warn "ACME 失败，使用自签"; issue_self
  fi
else
  step "未填域名，生成自签证书"; issue_self
fi

# ===== Nginx：彻底修复 stream 作用域 =====
step "清理历史 stream 残留并正确装配 stream 包装"
# 1) 删除任何历史 stream.d 配置，避免被错误位置 include
rm -f /etc/nginx/stream.d/*.conf || true

# 2) 从所有 nginx 配置中移除任何旧的 include /etc/nginx/stream.d/*.conf;
grep -RIl --exclude-dir=modules-enabled --exclude-dir=sites-enabled 'include.*/etc/nginx/stream\.d/.*\.conf;' /etc/nginx \
  | while read -r F; do sed -i '/include[[:space:]]\+\/etc\/nginx\/stream\.d\/.*\.conf;[[:space:]]*$/d' "$F"; done

# 3) 写入顶层包装文件，并确保在 nginx.conf 顶层 include 它
cat >/etc/nginx/edgebox_stream.conf <<'WRAP'
stream {
  # 仅从这里统一包含 stream 规则
  include /etc/nginx/stream.d/*.conf;
}
WRAP
if ! grep -q 'include /etc/nginx/edgebox_stream.conf;' /etc/nginx/nginx.conf; then
  cp /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.bak.$(date +%s)"
  # 放到第一行，保证顶层作用域
  sed -i '1i include /etc/nginx/edgebox_stream.conf;' /etc/nginx/nginx.conf
fi

# 4) 写入 http 反代（仅本机 8443）
cat >/etc/nginx/conf.d/edgebox-https.conf <<NG1
server {
  listen 127.0.0.1:${PORT_HTTP_TLS_LOOP} ssl http2;
  server_name ${DOMAIN:-_};
  ssl_certificate     ${CRT};
  ssl_certificate_key ${KEY};

  location /${GRPC_SVC} {
    grpc_set_header X-Real-IP \$remote_addr;
    grpc_pass grpc://127.0.0.1:11800;
  }
  location ${WS_PATH} {
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_pass http://127.0.0.1:11801;
  }
  location ${VMESS_PATH} {
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_pass http://127.0.0.1:11802;
  }
}
NG1

# 5) 写入真正的 stream SNI 分流
cat >/etc/nginx/stream.d/edgebox-sni.conf <<NG2
map \$ssl_preread_server_name \$edgebox_up {
  ${DOMAIN:-_}  grpcws;
  default       reality;
}
upstream grpcws { server 127.0.0.1:${PORT_HTTP_TLS_LOOP}; }
upstream reality{ server 127.0.0.1:${PORT_REALITY_LOOP}; }

server {
  listen ${PORT_SNI_OUT} reuseport;
  proxy_connect_timeout 3s;
  proxy_timeout 1h;
  ssl_preread on;
  proxy_pass \$edgebox_up;
}
NG2

# 6) 校验 & 启动/重载
nginx -t >/dev/null || { err "nginx 配置测试失败"; exit 1; }
systemctl restart nginx
systemctl enable nginx >/dev/null 2>&1 || true
ok "nginx stream 装配完成"

# ===== Reality 密钥（双兜底）=====
step "生成 Reality 密钥对"
PRIV=""; PBK=""
read PRIV PBK < <( (sing-box generate reality-keypair 2>/dev/null || true) | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}')
if [[ -z "${PRIV:-}" || -z "${PBK:-}" ]]; then
  read PRIV PBK < <( (xray x25519 2>/dev/null || true) | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}')
fi
[[ -z "${PRIV:-}" || -z "${PBK:-}" ]] && { err "Reality 密钥生成失败"; exit 1; }
ok "Reality PBK: $PBK"

# ===== 安装 sing-box（tgz→zip 兜底）=====
step "安装 sing-box v${SB_VER}"
SB_TGZ_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-amd64.tar.gz"
SB_ZIP_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-amd64.zip"
DL="/tmp/sb.pkg"; q rm -f "$DL"

if curl -fsSL "$SB_TGZ_URL" -o "$DL"; then
  if tar -tzf "$DL" >/dev/null 2>&1; then
    tar -xzf "$DL" -C /tmp
    cp -f /tmp/sing-box-${SB_VER}-linux-amd64/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
  else
    warn "tgz 校验失败，尝试 zip 包"
    curl -fsSL "$SB_ZIP_URL" -o "$DL"
    unzip -qo "$DL" -d /tmp
    cp -f /tmp/sing-box-${SB_VER}-linux-amd64/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
  fi
else
  err "下载 sing-box 失败"; exit 1
fi
ok "sing-box: $(sing-box version | head -n1)"

# ===== 写入 sing-box 配置 =====
step "写入 sing-box（Reality@${PORT_REALITY_LOOP} / HY2@udp:${PORT_HY2_UDP} / TUIC@udp:${PORT_TUIC_UDP}）"
HOME_OB=""
if [[ -n "${HOME_LINE:-}" ]]; then
  HOME_OB=$(jq -n --arg h "$HOME_HOST" --arg p "$HOME_PORT" \
             '{type:"http",tag:"home_http",server:$h,server_port:($p|tonumber)}')
  [[ -n "${HOME_USER:-}" ]] && HOME_OB=$(jq --arg u "$HOME_USER" '.username=$u' <<<"$HOME_OB")
  [[ -n "${HOME_PASS:-}" ]] && HOME_OB=$(jq --arg pw "$HOME_PASS" '.password=$pw' <<<"$HOME_OB")
fi

IN=()
IN+=("{
  \"type\":\"vless\",\"tag\":\"vless-reality\",\"listen\":\"127.0.0.1\",\"listen_port\":${PORT_REALITY_LOOP},
  \"users\":[{\"uuid\":\"${UUID_ALL}\",\"flow\":\"xtls-rprx-vision\"}],
  \"tls\":{
    \"enabled\":true,
    \"server_name\":\"${SNI_CF}\",
    \"reality\":{
      \"enabled\":true,
      \"private_key\":\"${PRIV}\",
      \"short_id\":[\"${SID}\"],
      \"handshake\":{\"server\":\"${SNI_CF}\",\"server_port\":443}
    }
  }
}")
IN+=("{
  \"type\":\"hysteria2\",\"tag\":\"hy2\",\"listen\":\"::\",\"listen_port\":${PORT_HY2_UDP},
  \"users\":[{\"password\":\"${HY2_PWD}\"}],
  \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
}")
IN+=("{
  \"type\":\"tuic\",\"tag\":\"tuic\",\"listen\":\"::\",\"listen_port\":${PORT_TUIC_UDP},
  \"users\":[{\"uuid\":\"${TUIC_UUID}\",\"password\":\"${TUIC_PWD}\"}],
  \"congestion_control\":\"bbr\",
  \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
}")

OB=('{"type":"direct","tag":"direct"}')
[[ -n "$HOME_OB" ]] && OB+=("$HOME_OB")
OB+=('{"type":"block","tag":"block"}')

ROUTE_JSON='"final":"direct"'
[[ -n "$HOME_OB" ]] && ROUTE_JSON='"rules":[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"}],"final":"home_http"'

jq -n --argjson in "[$(IFS=,; echo "${IN[*]}")]" \
      --argjson ob "[$(IFS=,; echo "${OB[*]}")]" \
      --argjson route "{${ROUTE_JSON}}" \
      '{log:{level:"info"},inbounds:$in,outbounds:$ob,route:$route}' \
  >"$SB_CFG"

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
systemctl enable --now sing-box

# ===== UFW 放行 =====
step "UFW 放行"
q ufw allow ${PORT_SNI_OUT}/tcp
q ufw allow ${PORT_HY2_UDP}/udp
q ufw allow ${PORT_TUIC_UDP}/udp
q ufw reload

# ===== 聚合订阅 & 管理器 =====
HOST="${DOMAIN:-$(curl -fsS https://api.ipify.org || hostname -I | awk '{print $1}')}"
ln -sf "$SUB_FILE" /var/www/html/sub/urls.txt
: >"$SUB_FILE"
printf "vless://%s@%s:443?encryption=none&security=tls&type=grpc&serviceName=%s&fp=chrome#VLESS-gRPC@%s\n" \
  "$UUID_ALL" "$HOST" "$GRPC_SVC" "$HOST" >>"$SUB_FILE"
printf "vless://%s@%s:443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n" \
  "$UUID_ALL" "$HOST" "$WS_PATH" "$HOST" "$HOST" >>"$SUB_FILE"
printf "vmess://%s\n" \
  "$(jq -nc --arg v '2' --arg add "$HOST" --arg path "$VMESS_PATH" --arg id "$UUID_VMESS" \
         --arg ps "VMess-WS@$HOST" \
         '{v:$v,ps:$ps,add:$add,port:"443",id:$id,aid:"0",scy:"none",net:"ws",type:"",host:$add,path:$path,tls:"tls",sni:$add,alpn:""}' | base64 -w0)" >>"$SUB_FILE"
printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" \
  "$UUID_ALL" "$HOST" "$SNI_CF" "$PBK" "$SID" "$HOST" >>"$SUB_FILE"
printf "hysteria2://%s@%s:%s?alpn=h3#HY2@%s\n" \
  "$HY2_PWD" "$HOST" "${PORT_HY2_UDP}" "$HOST" >>"$SUB_FILE"
printf "tuic://%s:%s@%s:%s?congestion=bbr&alpn=h3#TUIC@%s\n" \
  "$TUIC_UUID" "$TUIC_PWD" "$HOST" "${PORT_TUIC_UDP}" "$HOST" >>"$SUB_FILE"

cat >/usr/local/bin/edgeboxctl <<"CTL"
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
  status)
    echo "[nginx]";  systemctl --no-pager -l status nginx | sed -n '1,18p'; echo "---"
    echo "[xray]";   systemctl --no-pager -l status xray  | sed -n '1,18p'; echo "---"
    echo "[sing-box]"; systemctl --no-pager -l status sing-box | sed -n '1,18p'
    echo; echo "[ports]"; ss -lnptu | egrep ':443|:2053' || true
    echo; echo "[subs]"; nl -ba /var/lib/sb-sub/urls.txt | sed -n '1,80p'
    ;;
  regen)
    systemctl restart xray || true
    systemctl restart sing-box
    echo "[OK] 已重载 sing-box / xray"
    ;;
  *)
    echo "用法：edgeboxctl {status|regen}"
    ;;
esac
CTL
chmod +x /usr/local/bin/edgeboxctl

ok "安装完成"
echo "订阅链接： http://${HOST}/sub/urls.txt"
[[ -z "${DOMAIN:-}" ]] && echo "注意：使用自签证书，客户端需勾选“跳过证书验证/allowInsecure”。"
echo; echo "[端口快照]"; ss -lnptu | egrep ':443|:2053' || true
echo; echo "[快捷管理] edgeboxctl status | edgeboxctl regen"
