#!/usr/bin/env bash
set -Eeuo pipefail

# ========== 前言/检查 ==========
if [[ $EUID -ne 0 ]]; then exec sudo -E bash "$0" "$@"; fi

echo -e "\n\033[1;36m[INFO]\033[0m 端口放行要求：tcp/443, udp/443(HY2), udp/2053(TUIC)；可选 udp/8443（备用）。\n云防火墙/安全组 + 本机(UFW/iptables) 都需放行。\n"

# 固定版本（稳定）
SB_VER="1.12.2"

# 简单日志函数
step(){ printf "\n\033[1;34m[STEP]\033[0m %s\n" "$*"; }
ok(){   printf   "\033[1;32m[OK]\033[0m   %s\n" "$*"; }
warn(){ printf   "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err(){  printf   "\033[1;31m[ERR]\033[0m  %s\n" "$*"; }

trap 'err "出错，最近日志："; journalctl -u xray -u sing-box --no-pager -n 50 || true' ERR

# ========== 安装依赖 ==========
step "安装依赖（jq/openssl/socat/nginx/ufw 等）"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y --no-install-recommends ca-certificates curl wget openssl jq unzip socat ufw nginx >/dev/null

# 目录
mkdir -p /etc/sing-box /usr/local/etc/xray /var/lib/sb-sub /var/www/html/sub /etc/ssl/edgebox
touch /etc/nginx/stream.conf

# ========== 交互：域名 与 住宅代理 ==========
echo
read -r -p "域名（留空=用自签证书；填入=自动 ACME）：" DOMAIN || true
echo
read -r -p "住宅代理（HOST:PORT[:USER[:PASS]]，留空=不用）： " HOME_LINE || true

HOME_HOST=""; HOME_PORT=""; HOME_USER=""; HOME_PASS=""
if [[ -n "${HOME_LINE:-}" ]]; then
  IFS=':' read -r HOME_HOST HOME_PORT HOME_USER HOME_PASS <<<"$HOME_LINE"
  if [[ -z "${HOME_HOST:-}" || -z "${HOME_PORT:-}" ]]; then
    warn "住宅代理未给全，已忽略，默认直出"
    HOME_HOST=""; HOME_PORT=""
  fi
fi
[[ -n "${DOMAIN:-}" ]] && echo -n "$DOMAIN" >/etc/edgebox-domain || true

# ========== 安装 Xray ==========
step "安装 Xray"
bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null
systemctl enable --now xray >/dev/null 2>&1 || true

# 统一随机
UUID_ALL="$(cat /proc/sys/kernel/random/uuid)"
UUID_VM="$(cat /proc/sys/kernel/random/uuid)"
WS_PATH="/$(openssl rand -hex 3)"
VM_PATH="/$(openssl rand -hex 3)vm"
GRPC_SVC="@grpc"
SNI_CF="www.cloudflare.com"
SID="$(openssl rand -hex 4)"
HY2_PWD="$(openssl rand -hex 12)"
TUIC_UUID="$(cat /proc/sys/kernel/random/uuid)"
TUIC_PWD="$(openssl rand -hex 12)"

PORT_GRPC=11800
PORT_WS=11801
PORT_VM=11802
PORT_REAL=14443
PORT_HY2=443
PORT_TUIC=2053

# 写 Xray 配置（grpc/ws/vmess 均回环监听）
step "写入 Xray 配置"
XRAY_CFG="/usr/local/etc/xray/config.json"
cat >"$XRAY_CFG" <<JSON
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": $PORT_GRPC,
      "protocol": "vless",
      "settings": { "clients": [{ "id": "$UUID_ALL" }], "decryption": "none" },
      "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "$GRPC_SVC" } }
    },
    {
      "listen": "127.0.0.1",
      "port": $PORT_WS,
      "protocol": "vless",
      "settings": { "clients": [{ "id": "$UUID_ALL" }], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "$WS_PATH", "headers": { "Host": "${DOMAIN:-localhost}" } }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": $PORT_VM,
      "protocol": "vmess",
      "settings": { "clients": [{ "id": "$UUID_VM" }] },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "$VM_PATH", "headers": { "Host": "${DOMAIN:-localhost}" } }
      }
    }
  ],
  "outbounds": [{ "protocol": "freedom" }]
}
JSON
systemctl restart xray

# ========== 证书：ACME→自签兜底 ==========
CRT="/etc/ssl/edgebox/fullchain.crt"
KEY="/etc/ssl/edgebox/private.key"
issue_self(){
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$KEY" -out "$CRT" -subj "/CN=${DOMAIN:-edgebox.local}" >/dev/null 2>&1
  ok "已生成自签证书（客户端需允许不安全证书/skip verify）"
}

if [[ -n "${DOMAIN:-}" ]]; then
  step "申请 ACME 证书：$DOMAIN（失败会回退自签）"
  if ! ~/.acme.sh/acme.sh -v >/dev/null 2>&1; then
    curl -fsSL https://get.acme.sh | sh -s email=admin@${DOMAIN} >/dev/null 2>&1 || true
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  NGINX_WAS_ACTIVE=0
  if systemctl is-active --quiet nginx; then systemctl stop nginx; NGINX_WAS_ACTIVE=1; fi
  if ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" --keylength ec-256 >/dev/null 2>&1; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
      --fullchain-file "$CRT" --key-file "$KEY" >/dev/null 2>&1 || issue_self
    ok "ACME 成功"
  else
    warn "ACME 失败，改用自签"
    issue_self
  fi
  [[ $NGINX_WAS_ACTIVE -eq 1 ]] && systemctl start nginx
else
  step "未填域名，生成自签证书"
  issue_self
fi

# ========== 生成 Reality 密钥（双路兜底） ==========
step "生成 Reality 密钥对"
read PRIV PBK < <( (sing-box generate reality-keypair 2>/dev/null || true) | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}')
if [[ -z "${PRIV:-}" || -z "${PBK:-}" ]]; then
  read PRIV PBK < <( (xray x25519 2>/dev/null || true) | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}')
fi
[[ -z "${PRIV:-}" || -z "${PBK:-}" ]] && { err "Reality 密钥生成失败"; exit 1; }
ok "Reality PBK: $PBK"

# ========== Nginx：HTTP(回环8443) + STREAM(443 分流) ==========
step "写入 Nginx 配置并加载"
cat >/etc/nginx/conf.d/edgebox-https.conf <<NG1
server {
  listen 127.0.0.1:8443 ssl http2;
  server_name ${DOMAIN:-_};

  ssl_certificate     ${CRT};
  ssl_certificate_key ${KEY};

  # gRPC
  location /${GRPC_SVC} {
    grpc_set_header X-Real-IP \$remote_addr;
    grpc_pass grpc://127.0.0.1:${PORT_GRPC};
  }

  # VLESS-WS
  location ${WS_PATH} {
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_pass http://127.0.0.1:${PORT_WS};
  }

  # VMess-WS
  location ${VM_PATH} {
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_pass http://127.0.0.1:${PORT_VM};
  }
}
NG1

cat >/etc/nginx/stream.conf <<NG2
stream {
  map \$ssl_preread_server_name \$edgebox_up {
    ${DOMAIN:-_}  grpcws;
    default       reality;
  }
  upstream grpcws { server 127.0.0.1:8443; }
  upstream reality{ server 127.0.0.1:${PORT_REAL}; }

  server {
    listen 443 reuseport;
    proxy_connect_timeout 3s;
    proxy_timeout 1h;
    ssl_preread on;
    proxy_pass \$edgebox_up;
  }
}
NG2

nginx -t && systemctl reload nginx

# ========== sing-box：Reality / HY2 / TUIC + 路由 ==========
step "写入 sing-box 配置"
SB_CFG="/etc/sing-box/config.json"

ROUTE_JSON='"final":"direct"'
HOME_OB=""
if [[ -n "${HOME_HOST:-}" && -n "${HOME_PORT:-}" ]]; then
  HOME_OB=$(jq -n --arg h "$HOME_HOST" --argjson p "$HOME_PORT" \
               --arg u "${HOME_USER:-}" --arg pw "${HOME_PASS:-}" '{
      "type":"http","tag":"home_http",
      "server":$h,"server_port":($p|tonumber),
      "username":( ($u|length)>0 ? $u : null ),
      "password":( ($pw|length)>0 ? $pw : null )
    }')
  ROUTE_JSON='"rules":[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"}],"final":"home_http"'
fi

jq -n \
 --arg uuid "$UUID_ALL" \
 --arg sni  "$SNI_CF" \
 --arg priv "$PRIV" \
 --arg sid  "$SID" \
 --arg crt  "$CRT" \
 --arg key  "$KEY" \
 --argjson route "{${ROUTE_JSON}}" \
 --argjson homeob "${HOME_OB:-null}" \
 '
 {
   log:{level:"info"},
   inbounds: [
     {
       type:"vless", tag:"vless-reality",
       listen:"127.0.0.1", listen_port:'"$PORT_REAL"',
       users:[{uuid:$uuid, flow:"xtls-rprx-vision"}],
       tls:{
         enabled:true, server_name:$sni,
         reality:{enabled:true, private_key:$priv, short_id:[$sid],
                  handshake:{server:$sni, server_port:443}}
       }
     },
     {
       type:"hysteria2", tag:"hy2", listen:"::", listen_port:'"$PORT_HY2"',
       users:[{password:"'"$HY2_PWD"'"}],
       tls:{enabled:true, alpn:["h3"], certificate_path:$crt, key_path:$key}
     },
     {
       type:"tuic", tag:"tuic", listen:"::", listen_port:'"$PORT_TUIC"',
       users:[{uuid:"'"$TUIC_UUID"'", password:"'"$TUIC_PWD"'"}],
       congestion_control:"bbr",
       tls:{enabled:true, alpn:["h3"], certificate_path:$crt, key_path:$key}
     }
   ],
   outbounds: ([{type:"direct",tag:"direct"}] + ( $homeob| if . then [.] else [] end ) + [{type:"block",tag:"block"}]),
   route: $route
 }
 ' >"$SB_CFG"

# systemd
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

# 安装 sing-box（固定版本）
step "安装 sing-box v${SB_VER}"
curl -fsSL -o /tmp/sb.zip "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-amd64.zip"
unzip -qo /tmp/sb.zip -d /tmp/sb && install -m 0755 /tmp/sb/sing-box /usr/local/bin/sing-box
systemctl daemon-reload
systemctl enable --now sing-box

# ========== UFW 放行 ==========
step "放行 UFW 端口（未启用时会静默跳过）"
(ufw allow 443/tcp  || true)
(ufw allow 443/udp  || true)
(ufw allow 2053/udp || true)
# 备选备用
# (ufw allow 8443/udp || true)
(ufw reload || true)

# ========== 生成订阅 ==========
HOST="${DOMAIN:-$(curl -fsS https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')}"
SUB="/var/lib/sb-sub/urls.txt"
: >"$SUB"
printf "vless://%s@%s:443?encryption=none&security=tls&type=grpc&serviceName=%s&fp=chrome#VLESS-gRPC@%s\n" "$UUID_ALL" "$HOST" "$GRPC_SVC" "$HOST" >>"$SUB"
printf "vless://%s@%s:443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n" "$UUID_ALL" "$HOST" "$WS_PATH" "$HOST" "$HOST" >>"$SUB"
printf "vmess://%s\n" "$(jq -nc --arg v '2' --arg add "$HOST" --arg path "$VM_PATH" --arg id "$UUID_VM" --arg tls 'tls' --arg type 'ws' --arg sni "$HOST" --arg ps "VMess-WS@$HOST" '{v:$v,ps:$ps,add:$add,port:"443",id:$id,aid:"0",scy:"none",net:$type,type:"",host:$add,path:$path,tls:$tls,sni:$sni,alpn:""}' | base64 -w0)" >>"$SUB"
printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" "$UUID_ALL" "$HOST" "$SNI_CF" "$PBK" "$SID" "$HOST" >>"$SUB"
printf "hysteria2://%s@%s:443?alpn=h3#HY2@%s\n" "$HY2_PWD" "$HOST" "$HOST" >>"$SUB"
printf "tuic://%s:%s@%s:%s?congestion=bbr&alpn=h3#TUIC@%s\n" "$TUIC_UUID" "$TUIC_PWD" "$HOST" "$PORT_TUIC" "$HOST" >>"$SUB"
ln -sf "$SUB" /var/www/html/sub/urls.txt

# ========== 安装管理脚本 edgeboxctl ==========
step "安装管理脚本 edgeboxctl（启用/禁用/加人/订阅）"
tee /usr/local/bin/edgeboxctl >/dev/null <<'CTL'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -ne 0 ]] && exec sudo -E "$0" "$@"

SB_CFG="/etc/sing-box/config.json"
XR_CFG="/usr/local/etc/xray/config.json"
SUB_OUT="/var/lib/sb-sub/urls.txt"
CRT="/etc/ssl/edgebox/fullchain.crt"
KEY="/etc/ssl/edgebox/private.key"
DOMAIN_FILE="/etc/edgebox-domain"
HOST_DEFAULT="$(curl -fsS https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
SNI_CF="www.cloudflare.com"
GRPC_SVC="@grpc"
PORT_GRPC=11800; PORT_WS=11801; PORT_VM=11802; PORT_REAL=14443; PORT_HY2=443; PORT_TUIC=2053

json(){ jq -r "$1" "$2" 2>/dev/null || true; }

restart(){ case "$1" in sb) systemctl restart sing-box;; xr) systemctl restart xray;; esac; }

usage(){ cat <<EOF
用法:
  edgeboxctl enable  <grpc|ws|vmess|reality|hy2|tuic> [--port N]
  edgeboxctl disable <grpc|ws|vmess|reality|hy2|tuic>
  edgeboxctl add-user <grpc|ws|vmess|reality|hy2|tuic> [--count N]
  edgeboxctl sub [--protos grpc,ws,reality,hy2,tuic,vmess]
EOF
}

enable(){
  local p="$1" port="${2:-}"
  case "$p" in
    grpc)
      local uuid; uuid=$(json '..|.id? // .uuid? // empty' "$XR_CFG" | head -n1); [[ -z "$uuid" ]] && uuid=$(cat /proc/sys/kernel/random/uuid)
      jq ".inbounds += [{\"listen\":\"127.0.0.1\",\"port\":$PORT_GRPC,\"protocol\":\"vless\",\"settings\":{\"clients\":[{\"id\":\"$uuid\"}],\"decryption\":\"none\"},\"streamSettings\":{\"network\":\"grpc\",\"grpcSettings\":{\"serviceName\":\"$GRPC_SVC\"}}}]" "$XR_CFG" | sponge "$XR_CFG"
      restart xr;;
    ws)
      local uuid path="/$(openssl rand -hex 3)"; uuid=$(json '..|.id? // .uuid? // empty' "$XR_CFG" | head -n1); [[ -z "$uuid" ]] && uuid=$(cat /proc/sys/kernel/random/uuid)
      jq ".inbounds += [{\"listen\":\"127.0.0.1\",\"port\":$PORT_WS,\"protocol\":\"vless\",\"settings\":{\"clients\":[{\"id\":\"$uuid\"}],\"decryption\":\"none\"},\"streamSettings\":{\"network\":\"ws\",\"wsSettings\":{\"path\":\"$path\",\"headers\":{\"Host\":\"$(cat $DOMAIN_FILE 2>/dev/null || echo localhost)\"}}}}]" "$XR_CFG" | sponge "$XR_CFG"
      restart xr;;
    vmess)
      local uuid path="/$(openssl rand -hex 3)vm"; uuid=$(json '..|.id? // .uuid? // empty' "$XR_CFG" | sed -n '2p'); [[ -z "$uuid" ]] && uuid=$(cat /proc/sys/kernel/random/uuid)
      jq ".inbounds += [{\"listen\":\"127.0.0.1\",\"port\":$PORT_VM,\"protocol\":\"vmess\",\"settings\":{\"clients\":[{\"id\":\"$uuid\"}]},\"streamSettings\":{\"network\":\"ws\",\"wsSettings\":{\"path\":\"$path\",\"headers\":{\"Host\":\"$(cat $DOMAIN_FILE 2>/dev/null || echo localhost)\"}}}}]" "$XR_CFG" | sponge "$XR_CFG"
      restart xr;;
    reality)
      local uuid priv pbk sid; uuid=$(json '..|.uuid? // empty' "$SB_CFG" | head -n1); [[ -z "$uuid" ]] && uuid=$(cat /proc/sys/kernel/random/uuid)
      priv=$(json '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.private_key // empty' "$SB_CFG")
      pbk=$(json  '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.public_key // empty' "$SB_CFG")
      sid=$(json  '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.short_id[0] // empty' "$SB_CFG")
      if [[ -z "$priv" || -z "$pbk" ]]; then read priv pbk < <( (sing-box generate reality-keypair 2>/dev/null || true) | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}'); fi
      [[ -z "${sid:-}" ]] && sid=$(openssl rand -hex 4)
      jq ".inbounds += [{\"type\":\"vless\",\"tag\":\"vless-reality\",\"listen\":\"127.0.0.1\",\"listen_port\":$PORT_REAL,\"users\":[{\"uuid\":\"$uuid\",\"flow\":\"xtls-rprx-vision\"}],\"tls\":{\"enabled\":true,\"server_name\":\"$SNI_CF\",\"reality\":{\"enabled\":true,\"private_key\":\"$priv\",\"short_id\":[\"$sid\"],\"handshake\":{\"server\":\"$SNI_CF\",\"server_port\":443}}}}]" "$SB_CFG" | sponge "$SB_CFG"
      restart sb;;
    hy2)
      local hp="${port:-$PORT_HY2}" pwd; pwd=$(openssl rand -hex 12)
      jq ".inbounds += [{\"type\":\"hysteria2\",\"tag\":\"hy2\",\"listen\":\"::\",\"listen_port\":$hp,\"users\":[{\"password\":\"$pwd\"}],\"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"$CRT\",\"key_path\":\"$KEY\"}}]" "$SB_CFG" | sponge "$SB_CFG"
      restart sb;;
    tuic)
      local tp="${port:-$PORT_TUIC}" uid pwd; uid=$(cat /proc/sys/kernel/random/uuid); pwd=$(openssl rand -hex 12)
      jq ".inbounds += [{\"type\":\"tuic\",\"tag\":\"tuic\",\"listen\":\"::\",\"listen_port\":$tp,\"users\":[{\"uuid\":\"$uid\",\"password\":\"$pwd\"}],\"congestion_control\":\"bbr\",\"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"$CRT\",\"key_path\":\"$KEY\"}}]" "$SB_CFG" | sponge "$SB_CFG"
      restart sb;;
    *) echo "unknown proto"; exit 2;;
  esac
}

disable(){
  local p="$1"
  case "$p" in
    grpc)  jq ".inbounds |= map(select(.port!=$PORT_GRPC))" "$XR_CFG" | sponge "$XR_CFG"; restart xr;;
    ws)    jq ".inbounds |= map(select(.port!=$PORT_WS))" "$XR_CFG"   | sponge "$XR_CFG"; restart xr;;
    vmess) jq ".inbounds |= map(select(.port!=$PORT_VM))" "$XR_CFG"   | sponge "$XR_CFG"; restart xr;;
    reality) jq ".inbounds |= map(select(.listen_port!=$PORT_REAL))" "$SB_CFG" | sponge "$SB_CFG"; restart sb;;
    hy2)     jq ".inbounds |= map(select(.type!=\"hysteria2\"))" "$SB_CFG"      | sponge "$SB_CFG"; restart sb;;
    tuic)    jq ".inbounds |= map(select(.type!=\"tuic\"))" "$SB_CFG"           | sponge "$SB_CFG"; restart sb;;
  esac
}

add_user(){
  local p="$1" n="${2:-1}"
  case "$p" in
    grpc|ws) for _ in $(seq 1 "$n"); do u=$(cat /proc/sys/kernel/random/uuid); jq "(.inbounds[]|select(.protocol==\"vless\").settings.clients)+=[{\"id\":\"$u\"}]" "$XR_CFG" | sponge "$XR_CFG"; done; restart xr;;
    vmess)   for _ in $(seq 1 "$n"); do u=$(cat /proc/sys/kernel/random/uuid); jq "(.inbounds[]|select(.protocol==\"vmess\").settings.clients)+=[{\"id\":\"$u\"}]" "$XR_CFG" | sponge "$XR_CFG"; done; restart xr;;
    reality) for _ in $(seq 1 "$n"); do u=$(cat /proc/sys/kernel/random/uuid); jq "(.inbounds[]|select(.type==\"vless\" and .listen_port==$PORT_REAL).users)+=[{\"uuid\":\"$u\",\"flow\":\"xtls-rprx-vision\"}]" "$SB_CFG" | sponge "$SB_CFG"; done; restart sb;;
    hy2)     for _ in $(seq 1 "$n"); do p2=$(openssl rand -hex 12); jq "(.inbounds[]|select(.type==\"hysteria2\").users)+=[{\"password\":\"$p2\"}]" "$SB_CFG" | sponge "$SB_CFG"; done; restart sb;;
    tuic)    for _ in $(seq 1 "$n"); do u=$(cat /proc/sys/kernel/random/uuid); p2=$(openssl rand -hex 12); jq "(.inbounds[]|select(.type==\"tuic\").users)+=[{\"uuid\":\"$u\",\"password\":\"$p2\"}]" "$SB_CFG" | sponge "$SB_CFG"; done; restart sb;;
  esac
}

sub(){
  local host; host="$(cat "$DOMAIN_FILE" 2>/dev/null || echo "$HOST_DEFAULT")"
  local protos="${1:-grpc,ws,reality,hy2,tuic,vmess}"; : >"$SUB_OUT"
  local uuid ws_path vm_path pbk sid hy2_pwd tuic_port tuic_uuid tuic_pwd
  uuid=$(json '..|.id? // .uuid? // empty' "$XR_CFG" | head -n1)
  ws_path=$(json ".inbounds[]|select(.port==$PORT_WS).streamSettings.wsSettings.path // empty" "$XR_CFG")
  vm_path=$(json ".inbounds[]|select(.port==$PORT_VM).streamSettings.wsSettings.path // empty" "$XR_CFG")
  pbk=$(json '.inbounds[]|select(.type=="vless" and .listen_port=='"$PORT_REAL"').tls.reality.public_key // empty' "$SB_CFG")
  sid=$(json '.inbounds[]|select(.type=="vless" and .listen_port=='"$PORT_REAL"').tls.reality.short_id[0] // empty' "$SB_CFG")
  hy2_pwd=$(json '.inbounds[]|select(.type=="hysteria2").users[0].password // empty' "$SB_CFG")
  tuic_port=$(json '.inbounds[]|select(.type=="tuic").listen_port // empty' "$SB_CFG")
  tuic_uuid=$(json '.inbounds[]|select(.type=="tuic").users[0].uuid // empty' "$SB_CFG")
  tuic_pwd=$(json  '.inbounds[]|select(.type=="tuic").users[0].password // empty' "$SB_CFG")

  IFS=, read -ra P <<< "$protos"
  for p in "${P[@]}"; do
    case "$p" in
      grpc)   [[ -n "$uuid" ]] && printf "vless://%s@%s:443?encryption=none&security=tls&type=grpc&serviceName=%s&fp=chrome#VLESS-gRPC@%s\n" "$uuid" "$host" "$GRPC_SVC" "$host" >>"$SUB_OUT";;
      ws)     [[ -n "$uuid" && -n "$ws_path" ]] && printf "vless://%s@%s:443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n" "$uuid" "$host" "$ws_path" "$host" "$host" >>"$SUB_OUT";;
      vmess)  if [[ -n "$vm_path" ]]; then vm=$(jq -nc --arg v '2' --arg add "$host" --arg path "$vm_path" --arg id "$(cat /proc/sys/kernel/random/uuid)" --arg tls 'tls' --arg type 'ws' --arg sni "$host" --arg ps "VMess-WS@$host" '{v:$v,ps:$ps,add:$add,port:"443",id:$id,aid:"0",scy:"none",net:$type,type:"",host:$add,path:$path,tls:$tls,sni:$sni,alpn:""}' | base64 -w0); printf "vmess://%s\n" "$vm" >>"$SUB_OUT"; fi ;;
      reality) [[ -n "$pbk" && -n "$sid" ]] && printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" "$(cat /proc/sys/kernel/random/uuid)" "$host" "$SNI_CF" "$pbk" "$sid" "$host" >>"$SUB_OUT";;
      hy2)    [[ -n "$hy2_pwd" ]] && printf "hysteria2://%s@%s:443?alpn=h3#HY2@%s\n" "$hy2_pwd" "$host" "$host" >>"$SUB_OUT";;
      tuic)   if [[ -n "$tuic_uuid" && -n "$tuic_pwd" ]]; then tp="${tuic_port:-$PORT_TUIC}"; printf "tuic://%s:%s@%s:%s?congestion=bbr&alpn=h3#TUIC@%s\n" "$tuic_uuid" "$tuic_pwd" "$host" "$tp" "$host" >>"$SUB_OUT"; fi;;
    esac
  done
  cat "$SUB_OUT"; echo "订阅链接：http://$host/sub/urls.txt"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  enable)   p="${1:?proto}"; shift || true; [[ "${1:-}" == "--port" ]] && port="${2:?}" || port=""; enable "$p" "${port:-}";;
  disable)  p="${1:?proto}"; disable "$p";;
  add-user) p="${1:?proto}"; shift || true; cnt=1; [[ "${1:-}" == "--count" ]] && cnt="${2:?}"; add_user "$p" "$cnt";;
  sub)      prot=""; [[ "${1:-}" == "--protos" ]] && prot="${2:?}"; sub "${prot:-grpc,ws,reality,hy2,tuic,vmess}";;
  *)        usage; exit 1;;
esac
CTL
chmod +x /usr/local/bin/edgeboxctl

# ========== 完成输出 ==========
step "安装完成"
HOST_SHOW="$HOST"
echo "订阅链接： http://$HOST_SHOW/sub/urls.txt"
[[ -z "${DOMAIN:-}" ]] && echo "提示：你使用自签证书，客户端需勾选“跳过证书验证/allowInsecure”。"
echo
echo "[端口快照]"; ss -lnptu | egrep ':443|:2053|:8443' || true
echo
echo "[服务摘要]"
systemctl --no-pager -l status nginx    | sed -n '1,16p'; echo "---"
systemctl --no-pager -l status xray     | sed -n '1,16p'; echo "---"
systemctl --no-pager -l status sing-box | sed -n '1,16p'
