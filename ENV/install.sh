#!/usr/bin/env bash
# EdgeBox 五协议一体安装器（443 端口复用：gRPC/WS/VMess 走 Nginx；Reality/HY2/TUIC 走 sing-box）
set -Eeuo pipefail

# ---------- 提权（兼容管道/无TTY） ----------
if [[ $EUID -ne 0 ]]; then
  if [[ ! -t 0 ]]; then
    tmp="$(mktemp -t edgebox-install.XXXXXX)"; cat >"$tmp"
    exec sudo -E bash "$tmp" "$@"
  else
    exec sudo -E bash "$0" "$@"
  fi
fi

info(){ printf "\n\033[1;34m[STEP]\033[0m %s\n" "$*"; }
ok(){   printf "\033[1;32m[OK]\033[0m   %s\n" "$*"; }
warn(){ printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err(){  printf "\033[1;31m[ERR]\033[0m  %s\n" "$*"; }

# ---------- 读取输入：stdin -> /dev/tty -> 默认 ----------
get_input(){ local p="$1" var="$2" def="${3-}" ans=""
  if [ -t 0 ]; then read -r -p "$p" ans || true
  elif [ -r /dev/tty ]; then read -r -p "$p" ans </dev/tty || true
  else ans="$def"; fi
  [[ -z "${ans:-}" ]] && ans="$def"; printf -v "$var" "%s" "$ans"
}

echo -e "\n[INFO] 端口放行要求：tcp/443, udp/443(HY2), udp/2053(TUIC)；可选 udp/8443（备用）。"
echo -e   "[INFO] 云防火墙/安全组 + 本机(UFW/iptables) 都需放行。\n"

SB_VER="1.12.2"      # sing-box 稳定版
PORT_REAL=14443      # Reality 回环，Nginx stream 分流到此
PORT_HY2=443         # HY2 对外 UDP 443
PORT_TUIC=2053       # TUIC 对外 UDP 2053

DOMAIN=""; HOME_LINE=""
get_input "域名（留空=自签；填入=ACME）：" DOMAIN ""
get_input "住宅代理（HOST:PORT[:USER[:PASS]]，留空=不用）：" HOME_LINE ""

HOME_HOST=""; HOME_PORT=""; HOME_USER=""; HOME_PASS=""
if [[ -n "${HOME_LINE:-}" ]]; then
  IFS=':' read -r HOME_HOST HOME_PORT HOME_USER HOME_PASS <<<"$HOME_LINE" || true
  if [[ -z "${HOME_HOST:-}" || -z "${HOME_PORT:-}" ]]; then
    warn "住宅代理信息不完整，回退直出"; HOME_LINE=""
  fi
fi

# ---------- 依赖 ----------
info "安装依赖（jq/openssl/socat/nginx/ufw 等）"
apt-get update -y >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl wget openssl jq unzip tar socat ufw nginx >/dev/null

mkdir -p /etc/sing-box /usr/local/etc/xray /var/lib/sb-sub /var/www/html/sub /etc/ssl/edgebox
echo -n "${DOMAIN:-}" >/etc/edgebox-domain

# ---------- 随机材料 ----------
UUID_ALL="$(cat /proc/sys/kernel/random/uuid)"
UUID_VMESS="$(cat /proc/sys/kernel/random/uuid)"
WS_PATH="/$(openssl rand -hex 3)"
VMESS_PATH="/$(openssl rand -hex 3)vm"
GRPC_SVC="@grpc"
SNI_CF="www.cloudflare.com"
SID="$(openssl rand -hex 4)"
HY2_PWD="$(openssl rand -hex 12)"
TUIC_UUID="$(cat /proc/sys/kernel/random/uuid)"
TUIC_PWD="$(openssl rand -hex 12)"

# ---------- Xray：先停→写配置→启 ----------
info "安装 Xray"
bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null
systemctl stop xray || true
XRAY_CFG="/usr/local/etc/xray/config.json"
info "写入 Xray 配置（回环监听 11800/11801/11802）"
cat >"$XRAY_CFG" <<JSON
{
  "inbounds": [
    {
      "listen":"127.0.0.1","port":11800,"protocol":"vless",
      "settings":{"clients":[{"id":"$UUID_ALL"}],"decryption":"none"},
      "streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"$GRPC_SVC"}}
    },
    {
      "listen":"127.0.0.1","port":11801,"protocol":"vless",
      "settings":{"clients":[{"id":"$UUID_ALL"}],"decryption":"none"},
      "streamSettings":{"network":"ws","wsSettings":{"path":"$WS_PATH","headers":{"Host":"${DOMAIN:-localhost}"}}}
    },
    {
      "listen":"127.0.0.1","port":11802,"protocol":"vmess",
      "settings":{"clients":[{"id":"$UUID_VMESS"}]},
      "streamSettings":{"network":"ws","wsSettings":{"path":"$VMESS_PATH","headers":{"Host":"${DOMAIN:-localhost}"}}}
    }
  ],
  "outbounds":[{"protocol":"freedom"}]
}
JSON
systemctl enable --now xray >/dev/null 2>&1 || true
sleep 1

# ---------- 证书 ACME→自签兜底 ----------
CRT="/etc/ssl/edgebox/fullchain.crt"; KEY="/etc/ssl/edgebox/private.key"
issue_self(){ openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$KEY" -out "$CRT" -subj "/CN=${DOMAIN:-edgebox.local}" >/dev/null 2>&1; }
if [[ -n "${DOMAIN:-}" ]]; then
  info "申请 ACME 证书：$DOMAIN（失败回退自签）"
  if ! ~/.acme.sh/acme.sh -v >/dev/null 2>&1; then
    curl -fsSL https://get.acme.sh | sh -s email=admin@"${DOMAIN}" >/dev/null 2>&1 || true
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" --keylength ec-256 >/dev/null 2>&1; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
      --fullchain-file "$CRT" --key-file "$KEY" >/dev/null 2>&1 || issue_self
    ok "ACME 成功"
  else warn "ACME 失败，改用自签"; issue_self; fi
else info "未填域名，生成自签证书（客户端需允许不安全证书/skip verify）"; issue_self; fi

# ---------- Nginx：HTTP(127.0.0.1:8443) + STREAM(443) ----------
info "写入 Nginx（http 反代 WS/GRPC；stream:443 SNI→8443/14443）"
cat >/etc/nginx/conf.d/edgebox-https.conf <<NG1
server {
  listen 127.0.0.1:8443 ssl http2;
  server_name ${DOMAIN:-_};
  ssl_certificate     ${CRT};
  ssl_certificate_key ${KEY};
  location /${GRPC_SVC} { grpc_set_header X-Real-IP \$remote_addr; grpc_pass grpc://127.0.0.1:11800; }
  location ${WS_PATH}  { proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; proxy_pass http://127.0.0.1:11801; }
  location ${VMESS_PATH} { proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; proxy_pass http://127.0.0.1:11802; }
}
NG1
cat >/etc/nginx/stream.conf <<'NG2'
stream {
  map $ssl_preread_server_name $edgebox_up {
    default       reality;
    ~.*           grpcws;
  }
  upstream grpcws { server 127.0.0.1:8443; }
  upstream reality{ server 127.0.0.1:14443; }
  server {
    listen 443 reuseport;
    proxy_connect_timeout 3s;
    proxy_timeout 1h;
    ssl_preread on;
    proxy_pass $edgebox_up;
  }
}
NG2
nginx -t >/dev/null && systemctl reload nginx || { err "Nginx 配置有误"; exit 1; }

# ---------- Reality 密钥双兜底 ----------
gen_reality(){ local out priv pbk
  out="$(sing-box generate reality-keypair 2>/dev/null || true)"
  if [[ "$out" == *"Private"* && "$out" == *"Public"* ]]; then
    read -r priv pbk <<<"$(awk -F': *' '/Private/{p=$2}/Public/{print p,$2}' <<<"$out")"
  else
    read -r priv pbk <<<"$(xray x25519 | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}')"
  fi
  [[ -n "${priv:-}" && -n "${pbk:-}" ]] || return 1
  echo "$priv $pbk"
}
info "生成 Reality 密钥对"
read -r PRIV PBK <<<"$(gen_reality)" || { err "Reality 密钥生成失败"; exit 1; }
ok "Reality PBK: $PBK"

# ---------- sing-box 安装（多候选 URL + 自动识别压缩格式） ----------
install_singbox() {
  local urls=(
    "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-amd64.tar.gz"
    "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box_${SB_VER}_linux_amd64.tar.gz"
    "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-amd64.zip"
    "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box_${SB_VER}_linux_amd64.zip"
    "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-linux-amd64-v${SB_VER}.tar.gz"
  )
  local got=""
  for u in "${urls[@]}"; do
    if curl -fSL -o /tmp/sb.pkg "$u" >/dev/null 2>&1; then got="$u"; break; fi
  done
  [[ -n "$got" ]] || { err "下载 sing-box v${SB_VER} 失败（多源均不可用）"; return 1; }
  rm -rf /tmp/sb-ex && mkdir -p /tmp/sb-ex
  if file /tmp/sb.pkg | grep -qi 'gzip'; then tar -xzf /tmp/sb.pkg -C /tmp/sb-ex >/dev/null
  elif file /tmp/sb.pkg | grep -qi 'zip'; then unzip -qo /tmp/sb.pkg -d /tmp/sb-ex >/dev/null
  else err "未知压缩格式"; return 1; fi
  local bin; bin="$(find /tmp/sb-ex -type f -name sing-box | head -n1)"
  [[ -x "$bin" ]] || { err "未找到 sing-box 可执行文件"; return 1; }
  install -m0755 "$bin" /usr/local/bin/sing-box
  ok "sing-box $(/usr/local/bin/sing-box version | awk '{print $3}') 安装完成"
}
info "安装 sing-box v${SB_VER}"
install_singbox

# ---------- sing-box 配置 ----------
SB_CFG="/etc/sing-box/config.json"
info "写入 sing-box 配置（Reality@${PORT_REAL} / HY2@udp:${PORT_HY2} / TUIC@udp:${PORT_TUIC}）"
cat >"$SB_CFG" <<JSON
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type":"vless","tag":"vless-reality","listen":"127.0.0.1","listen_port": ${PORT_REAL},
      "users":[{"uuid":"${UUID_ALL}","flow":"xtls-rprx-vision"}],
      "tls":{"enabled":true,"server_name":"${SNI_CF}","reality":{"enabled":true,"private_key":"${PRIV}","short_id":["${SID}"],"handshake":{"server":"${SNI_CF}","server_port":443}}}
    },
    {
      "type":"hysteria2","tag":"hy2","listen":"::","listen_port": ${PORT_HY2},
      "users":[{"password":"${HY2_PWD}"}],
      "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${CRT}","key_path":"${KEY}"}
    },
    {
      "type":"tuic","tag":"tuic","listen":"::","listen_port": ${PORT_TUIC},
      "users":[{"uuid":"${TUIC_UUID}","password":"${TUIC_PWD}"}],
      "congestion_control":"bbr",
      "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${CRT}","key_path":"${KEY}"}
    }
  ],
  "outbounds": [
    $( if [[ -n "$HOME_LINE" ]]; then
         jq -nc --arg h "$HOME_HOST" --argjson p "$HOME_PORT" \
               --arg u "${HOME_USER:-}" --arg pw "${HOME_PASS:-}" \
               '{"type":"http","tag":"home_http","server":$h,"server_port":($p|tonumber),
                 "username":( ($u|length)>0 ? $u : null ),
                 "password":( ($pw|length)>0 ? $pw : null ) }' ;
       else echo '{"type":"direct","tag":"direct"}' ; fi ),
    {"type":"block","tag":"block"}
  ],
  "route": {
    $( if [[ -n "$HOME_LINE" ]]; then
         echo '"rules":[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"}], "final":"home_http"';
       else
         echo '"final":"direct"';
       fi )
  }
}
JSON

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

# ---------- UFW 放行 ----------
if command -v ufw >/dev/null 2>&1; then
  ufw allow 443/tcp  >/dev/null 2>&1 || true
  ufw allow 443/udp  >/dev/null 2>&1 || true
  ufw allow ${PORT_TUIC}/udp >/dev/null 2>&1 || true
  ufw reload >/dev/null 2>&1 || true
fi

# ---------- 订阅 & ENV & 管理脚本（edgeboxctl） ----------
HOST="${DOMAIN:-$(curl -fsS https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')}"
SUB="/var/lib/sb-sub/urls.txt"; : >"$SUB"
printf "vless://%s@%s:443?encryption=none&security=tls&type=grpc&serviceName=%s&fp=chrome#VLESS-gRPC@%s\n" "$UUID_ALL" "$HOST" "$GRPC_SVC" "$HOST" >>"$SUB"
printf "vless://%s@%s:443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n"   "$UUID_ALL" "$HOST" "$WS_PATH" "$HOST" "$HOST" >>"$SUB"
printf "vmess://%s\n" "$(jq -nc --arg v '2' --arg add "$HOST" --arg path "$VMESS_PATH" \
  --arg id "$UUID_VMESS" --arg tls 'tls' --arg type 'ws' --arg sni "$HOST" \
  --arg ps "VMess-WS@$HOST" \
  '{v:$v,ps:$ps,add:$add,port:"443",id:$id,aid:"0",scy:"none",net:$type,type:"",
    host:$add,path:$path,tls:$tls,sni:$sni,alpn:""}' | base64 -w0)" >>"$SUB"
printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" "$UUID_ALL" "$HOST" "$SNI_CF" "$PBK" "$SID" "$HOST" >>"$SUB"
printf "hysteria2://%s@%s:443?alpn=h3#HY2@%s\n" "$HY2_PWD" "$HOST" "$HOST" >>"$SUB"
printf "tuic://%s:%s@%s:%s?congestion=bbr&alpn=h3#TUIC@%s\n" "$TUIC_UUID" "$TUIC_PWD" "$HOST" "$PORT_TUIC" "$HOST" >>"$SUB"
ln -sf "$SUB" /var/www/html/sub/urls.txt

ENVF="/etc/edgebox/env"
cat >"$ENVF" <<ENV
DOMAIN="$DOMAIN"
HOST="$HOST"
CRT="$CRT"
KEY="$KEY"
UUID_ALL="$UUID_ALL"
UUID_VMESS="$UUID_VMESS"
WS_PATH="$WS_PATH"
VMESS_PATH="$VMESS_PATH"
GRPC_SVC="$GRPC_SVC"
SNI_CF="$SNI_CF"
SID="$SID"
PRIV="$PRIV"
PBK="$PBK"
HY2_PWD="$HY2_PWD"
TUIC_UUID="$TUIC_UUID"
TUIC_PWD="$TUIC_PWD"
PORT_REAL=$PORT_REAL
PORT_HY2=$PORT_HY2
PORT_TUIC=$PORT_TUIC
HOME_LINE="$HOME_LINE"
HOME_HOST="$HOME_HOST"
HOME_PORT="$HOME_PORT"
HOME_USER="$HOME_USER"
HOME_PASS="$HOME_PASS"
EN_GRPC=1
EN_WS=1
EN_VMESS=1
EN_REAL=1
EN_HY2=1
EN_TUIC=1
ENV

cat >/usr/local/bin/edgeboxctl <<'CTL'
#!/usr/bin/env bash
set -Eeuo pipefail
ENVF="/etc/edgebox/env"; SB="/etc/sing-box/config.json"; XR="/usr/local/etc/xray/config.json"
[[ -f "$ENVF" ]] || { echo "env not found: $ENVF"; exit 1; }
. "$ENVF"
usage(){ cat <<USG
edgeboxctl：
  status            - 查看服务摘要
  sub               - 打印订阅链接并预览
  enable  <proto>   - 启用协议（grpc|ws|vmess|reality|hy2|tuic）
  disable <proto>   - 禁用协议
  regen             - 按 env 重建配置并重启
USG
}
toggle(){ case "$1" in
  grpc) sed -i "s/^EN_GRPC=.*/EN_GRPC=$2/"   "$ENVF" ;;
  ws)   sed -i "s/^EN_WS=.*/EN_WS=$2/"       "$ENVF" ;;
  vmess)sed -i "s/^EN_VMESS=.*/EN_VMESS=$2/" "$ENVF" ;;
  reality)sed -i "s/^EN_REAL=.*/EN_REAL=$2/" "$ENVF" ;;
  hy2)  sed -i "s/^EN_HY2=.*/EN_HY2=$2/"     "$ENVF" ;;
  tuic) sed -i "s/^EN_TUIC=.*/EN_TUIC=$2/"   "$ENVF" ;;
  *) echo "unknown proto: $1"; exit 1;; esac; }
regen(){
  . "$ENVF"
  { echo '{ "inbounds": ['; first=1
    if [[ "${EN_GRPC:-0}" -eq 1 ]]; then [[ $first -eq 0 ]] && echo ','; first=0; cat <<JSON
{"listen":"127.0.0.1","port":11800,"protocol":"vless","settings":{"clients":[{"id":"'$UUID_ALL'"}],"decryption":"none"},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"'$GRPC_SVC'"}}}
JSON
    fi
    if [[ "${EN_WS:-0}" -eq 1 ]]; then [[ $first -eq 0 ]] && echo ','; first=0; cat <<JSON
{"listen":"127.0.0.1","port":11801,"protocol":"vless","settings":{"clients":[{"id":"'$UUID_ALL'"}],"decryption":"none"},"streamSettings":{"network":"ws","wsSettings":{"path":"'$WS_PATH'","headers":{"Host":"'${DOMAIN:-localhost}'"}}}}
JSON
    fi
    if [[ "${EN_VMESS:-0}" -eq 1 ]]; then [[ $first -eq 0 ]] && echo ','; first=0; cat <<JSON
{"listen":"127.0.0.1","port":11802,"protocol":"vmess","settings":{"clients":[{"id":"'$UUID_VMESS'"}]},"streamSettings":{"network":"ws","wsSettings":{"path":"'$VMESS_PATH'","headers":{"Host":"'${DOMAIN:-localhost}'"}}}}
JSON
    fi
    echo '], "outbounds":[{"protocol":"freedom"}]}'
  } >"$XR"; systemctl restart xray

  IN=()
  if [[ "${EN_REAL:-0}" -eq 1 ]]; then IN+=("{
    \"type\":\"vless\",\"tag\":\"vless-reality\",\"listen\":\"127.0.0.1\",\"listen_port\": ${PORT_REAL},
    \"users\":[{\"uuid\":\"${UUID_ALL}\",\"flow\":\"xtls-rprx-vision\"}],
    \"tls\":{\"enabled\":true,\"server_name\":\"${SNI_CF}\",\"reality\":{\"enabled\":true,\"private_key\":\"${PRIV}\",\"short_id\":[\"${SID}\"],\"handshake\":{\"server\":\"${SNI_CF}\",\"server_port\":443}}}
  }"); fi
  if [[ "${EN_HY2:-0}" -eq 1 ]]; then IN+=("{
    \"type\":\"hysteria2\",\"tag\":\"hy2\",\"listen\":\"::\",\"listen_port\": ${PORT_HY2},
    \"users\":[{\"password\":\"${HY2_PWD}\"}],
    \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
  }"); fi
  if [[ "${EN_TUIC:-0}" -eq 1 ]]; then IN+=("{
    \"type\":\"tuic\",\"tag\":\"tuic\",\"listen\":\"::\",\"listen_port\": ${PORT_TUIC},
    \"users\":[{\"uuid\":\"${TUIC_UUID}\",\"password\":\"${TUIC_PWD}\"}],
    \"congestion_control\":\"bbr\",
    \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
  }"); fi

  OB=('{"type":"direct","tag":"direct"}'); ROUTE='"final":"direct"'
  if [[ -n "${HOME_LINE:-}" ]]; then
    OB=($(jq -nc --arg h "$HOME_HOST" --argjson p "$HOME_PORT" --arg u "${HOME_USER:-}" --arg pw "${HOME_PASS:-}" \
        '{"type":"http","tag":"home_http","server":$h,"server_port":($p|tonumber),
          "username":( ($u|length)>0 ? $u : null ),"password":( ($pw|length)>0 ? $pw : null ) }'))
    ROUTE='"rules":[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"}],"final":"home_http"'
  fi
  jq -n --argjson in "[$(IFS=,; echo "${IN[*]-[]}")]" \
        --argjson ob "[$(IFS=,; echo "${OB[*]}")]" \
        --argjson r "{${ROUTE}}" \
        '{log:{level:"info"},inbounds:$in,outbounds:$ob,route:$r}' >"$SB"
  systemctl restart sing-box
}
case "${1:-}" in
  status) systemctl --no-pager -l status nginx | sed -n "1,16p"; echo "---"; systemctl --no-pager -l status xray | sed -n "1,16p"; echo "---"; systemctl --no-pager -l status sing-box | sed -n "1,16p" ;;
  sub)    echo "订阅：http://$HOST/sub/urls.txt"; nl -ba /var/lib/sb-sub/urls.txt | sed -n "1,60p" ;;
  enable) [[ $# -eq 2 ]] || { usage; exit 1; }; toggle "$2" 1; regen ;;
  disable)[[ $# -eq 2 ]] || { usage; exit 1; }; toggle "$2" 0; regen ;;
  regen)  regen ;;
  *) usage ;;
esac
CTL
chmod +x /usr/local/bin/edgeboxctl

echo
ok "安装完成"
echo "订阅链接： http://$HOST/sub/urls.txt"
[[ -z "${DOMAIN:-}" ]] && echo "注意：你使用的是自签证书，客户端需勾选“跳过证书验证/allowInsecure”。"
echo
echo "[端口快照]" && ss -lnptu | egrep ':443|:2053' || true
echo
echo "[服务概要]"
systemctl --no-pager -l status nginx | sed -n '1,16p'; echo "---"
systemctl --no-pager -l status xray  | sed -n '1,16p'; echo "---"
systemctl --no-pager -l status sing-box | sed -n '1,16p'
