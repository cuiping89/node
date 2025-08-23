#!/usr/bin/env bash
# EdgeBox 五协议一体安装器（443 端口复用，SNI/HTTP分流）
# - 协议：VLESS-gRPC / VLESS-WS / VMess-WS / VLESS-Reality / HY2(udp/443) / TUIC(udp/2053)
# - ACME→自签兜底；Reality 密钥双路兜底
# - 生成 edgeboxctl 管理工具：enable/disable/regen/sub/status
set -Eeuo pipefail

########################
# 通用输出
########################
info(){ printf "\n\033[1;34m[STEP]\033[0m %s\n" "$*"; }
ok(){   printf "\033[1;32m[OK]\033[0m   %s\n" "$*"; }
warn(){ printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err(){  printf "\033[1;31m[ERR]\033[0m  %s\n" "$*"; }

# 自动提权
if [[ $EUID -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

echo -e "\n[INFO] 端口放行要求：tcp/443, udp/443(HY2), udp/2053(TUIC)；可选 udp/8443（备用）。"
echo -e     "[INFO] 云防火墙/安全组 + 本机(UFW/iptables) 都需放行。\n"

# 版本钉死（稳定可回溯）
SB_VER="1.12.2"

########################
# 交互（尽量少）
########################
read -r -p "域名（留空=用自签证书；填入=自动 ACME）：" DOMAIN || true
read -r -p "住宅代理（HOST:PORT[:USER[:PASS]]，留空=不用）： " HOME_LINE || true

# 解析住宅代理
HOME_HOST=""; HOME_PORT=""; HOME_USER=""; HOME_PASS=""
if [[ -n "${HOME_LINE:-}" ]]; then
  IFS=':' read -r HOME_HOST HOME_PORT HOME_USER HOME_PASS <<<"$HOME_LINE"
  [[ -z "${HOME_HOST:-}" || -z "${HOME_PORT:-}" ]] && { warn "住宅代理信息不完整，回退直出"; HOME_LINE=""; }
fi

########################
# 依赖
########################
info "安装依赖（jq/openssl/socat/nginx/ufw 等）"
apt-get update -y >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl wget openssl jq unzip socat ufw nginx >/dev/null

mkdir -p /etc/sing-box /usr/local/etc/xray /var/lib/sb-sub /var/www/html/sub /etc/ssl/edgebox
echo -n "${DOMAIN:-}" >/etc/edgebox-domain

########################
# 随机材料
########################
UUID_ALL="$(cat /proc/sys/kernel/random/uuid)"
UUID_VMESS="$(cat /proc/sys/kernel/random/uuid)"
WS_PATH="/$(openssl rand -hex 3)"         # 例如 /a1b2c3
VMESS_PATH="/$(openssl rand -hex 3)vm"    # 例如 /d4e5f6vm
GRPC_SVC="@grpc"
SNI_CF="www.cloudflare.com"
SID="$(openssl rand -hex 4)"              # Reality 短ID
HY2_PWD="$(openssl rand -hex 12)"
TUIC_UUID="$(cat /proc/sys/kernel/random/uuid)"
TUIC_PWD="$(openssl rand -hex 12)"
PORT_REAL=14443   # sing-box 回环 Reality
PORT_HY2=443      # HY2 udp/443
PORT_TUIC=2053    # TUIC udp/2053

########################
# 安装 Xray
########################
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

########################
# 证书：ACME → 自签兜底
########################
CRT="/etc/ssl/edgebox/fullchain.crt"
KEY="/etc/ssl/edgebox/private.key"

issue_self(){
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$KEY" -out "$CRT" -subj "/CN=${DOMAIN:-edgebox.local}" >/dev/null 2>&1
}

if [[ -n "${DOMAIN:-}" ]]; then
  info "申请 ACME 证书：$DOMAIN（失败会回退自签）"
  if ! ~/.acme.sh/acme.sh -v >/dev/null 2>&1; then
    curl -fsSL https://get.acme.sh | sh -s email=admin@"${DOMAIN}" >/dev/null 2>&1 || true
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" --keylength ec-256 >/dev/null 2>&1; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
      --fullchain-file "$CRT" --key-file "$KEY" >/dev/null 2>&1 || issue_self
    ok "ACME 成功"
  else
    warn "ACME 失败，改用自签"
    issue_self
  fi
else
  info "未填域名，生成自签证书（客户端需允许不安全证书/skip verify）"
  issue_self
fi

########################
# Nginx：HTTP(回环8443) + STREAM(443) 分流
########################
info "写入 Nginx（http:127.0.0.1:8443 反代 WS/GRPC；stream:443 SNI 分流到 8443/14443）"

# HTTP：反代 gRPC/WS/VMess-WS（仅回环监听）
cat >/etc/nginx/conf.d/edgebox-https.conf <<NG1
server {
  listen 127.0.0.1:8443 ssl http2;
  server_name ${DOMAIN:-_};

  ssl_certificate     ${CRT};
  ssl_certificate_key ${KEY};

  # gRPC
  location /${GRPC_SVC} {
    grpc_set_header X-Real-IP \$remote_addr;
    grpc_pass grpc://127.0.0.1:11800;
  }

  # VLESS-WS
  location ${WS_PATH} {
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_pass http://127.0.0.1:11801;
  }

  # VMess-WS
  location ${VMESS_PATH} {
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_pass http://127.0.0.1:11802;
  }
}
NG1

# STREAM：对外 443 → SNI map：域名=grpcws，其他=reality
cat >/etc/nginx/stream.conf <<'NG2'
# 由 install.sh 生成。不要手改；使用 edgeboxctl regen。
stream {
  map $ssl_preread_server_name $edgebox_up {
    # 运行时由 edgeboxctl 注入 server_name；初始放通所有到 grpcws
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

########################
# Reality 密钥双路兜底
########################
gen_reality() {
  local out priv pbk
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

########################
# 安装 sing-box & 配置
########################
info "安装 sing-box v${SB_VER}"
curl -fsSL -o /tmp/sb.zip "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-amd64.zip"
unzip -qo /tmp/sb.zip -d /tmp/sb && install -m0755 /tmp/sb/sing-box /usr/local/bin/sing-box

SB_CFG="/etc/sing-box/config.json"
info "写入 sing-box 配置（Reality@127.0.0.1:${PORT_REAL} / HY2@udp/443 / TUIC@udp/${PORT_TUIC}）"
cat >"$SB_CFG" <<JSON
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type":"vless","tag":"vless-reality",
      "listen":"127.0.0.1","listen_port": ${PORT_REAL},
      "users":[{"uuid":"${UUID_ALL}","flow":"xtls-rprx-vision"}],
      "tls":{
        "enabled":true,"server_name":"${SNI_CF}",
        "reality":{
          "enabled":true,"private_key":"${PRIV}","short_id":["${SID}"],
          "handshake":{"server":"${SNI_CF}","server_port":443}
        }
      }
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

systemctl daemon-reload
systemctl enable --now sing-box

########################
# UFW 端口放行（静默）
########################
if command -v ufw >/dev/null 2>&1; then
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw allow 443/udp >/dev/null 2>&1 || true
  ufw allow ${PORT_TUIC}/udp >/dev/null 2>&1 || true
  ufw reload >/dev/null 2>&1 || true
fi

########################
# 订阅聚合 & ENV 保存
########################
HOST="${DOMAIN:-$(curl -fsS https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')}"
SUB="/var/lib/sb-sub/urls.txt"
: >"$SUB"
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

# 环境存档（供 edgeboxctl 使用）
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

########################
# 管理脚本 edgeboxctl
########################
cat >/usr/local/bin/edgeboxctl <<'CTL'
#!/usr/bin/env bash
set -Eeuo pipefail
ENVF="/etc/edgebox/env"
SB="/etc/sing-box/config.json"
XR="/usr/local/etc/xray/config.json"
[[ -f "$ENVF" ]] || { echo "env not found: $ENVF"; exit 1; }
# shellcheck disable=SC1090
. "$ENVF"

usage(){
  cat <<USG
edgeboxctl 命令：
  status            - 查看 Nginx/Xray/sing-box 简要状态
  sub               - 打印订阅链接并预览前几行
  enable  <proto>   - 启用协议（grpc|ws|vmess|reality|hy2|tuic）
  disable <proto>   - 禁用协议
  regen             - 按 env 重建配置并重启
USG
}

toggle(){
  local p="$1" v="$2"
  case "$p" in
    grpc)   sed -i "s/^EN_GRPC=.*/EN_GRPC=$v/"   "$ENVF" ;;
    ws)     sed -i "s/^EN_WS=.*/EN_WS=$v/"       "$ENVF" ;;
    vmess)  sed -i "s/^EN_VMESS=.*/EN_VMESS=$v/" "$ENVF" ;;
    reality)sed -i "s/^EN_REAL=.*/EN_REAL=$v/"   "$ENVF" ;;
    hy2)    sed -i "s/^EN_HY2=.*/EN_HY2=$v/"     "$ENVF" ;;
    tuic)   sed -i "s/^EN_TUIC=.*/EN_TUIC=$v/"   "$ENVF" ;;
    *) echo "unknown proto: $p"; exit 1;;
  esac
}

regen(){
  . "$ENVF"
  # XRAY（根据 EN_* 决定是否写入对应 inbound）
  {
    echo '{ "inbounds": ['
    first=1
    if [[ "${EN_GRPC:-0}" -eq 1 ]]; then
      [[ $first -eq 0 ]] && echo ','
      first=0
      cat <<JSON
{"listen":"127.0.0.1","port":11800,"protocol":"vless",
 "settings":{"clients":[{"id":"'$UUID_ALL'"}],"decryption":"none"},
 "streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"'$GRPC_SVC'"}}}
JSON
    fi
    if [[ "${EN_WS:-0}" -eq 1 ]]; then
      [[ $first -eq 0 ]] && echo ','
      first=0
      cat <<JSON
{"listen":"127.0.0.1","port":11801,"protocol":"vless",
 "settings":{"clients":[{"id":"'$UUID_ALL'"}],"decryption":"none"},
 "streamSettings":{"network":"ws","wsSettings":{"path":"'$WS_PATH'","headers":{"Host":"'${DOMAIN:-localhost}'"}}}}
JSON
    fi
    if [[ "${EN_VMESS:-0}" -eq 1 ]]; then
      [[ $first -eq 0 ]] && echo ','
      first=0
      cat <<JSON
{"listen":"127.0.0.1","port":11802,"protocol":"vmess",
 "settings":{"clients":[{"id":"'$UUID_VMESS'"}]},
 "streamSettings":{"network":"ws","wsSettings":{"path":"'$VMESS_PATH'","headers":{"Host":"'${DOMAIN:-localhost}'"}}}}
JSON
    fi
    echo '], "outbounds":[{"protocol":"freedom"}]}'
  } >"$XR"
  systemctl restart xray

  # SING-BOX
  IN=()
  if [[ "${EN_REAL:-0}" -eq 1 ]]; then
    IN+=("{
      \"type\":\"vless\",\"tag\":\"vless-reality\",
      \"listen\":\"127.0.0.1\",\"listen_port\": ${PORT_REAL},
      \"users\":[{\"uuid\":\"${UUID_ALL}\",\"flow\":\"xtls-rprx-vision\"}],
      \"tls\":{\"enabled\":true,\"server_name\":\"${SNI_CF}\",
        \"reality\":{\"enabled\":true,\"private_key\":\"${PRIV}\",
          \"short_id\":[\"${SID}\"],
          \"handshake\":{\"server\":\"${SNI_CF}\",\"server_port\":443}}}
    }")
  fi
  if [[ "${EN_HY2:-0}" -eq 1 ]]; then
    IN+=("{
      \"type\":\"hysteria2\",\"tag\":\"hy2\",\"listen\":\"::\",\"listen_port\": ${PORT_HY2},
      \"users\":[{\"password\":\"${HY2_PWD}\"}],
      \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
    }")
  fi
  if [[ "${EN_TUIC:-0}" -eq 1 ]]; then
    IN+=("{
      \"type\":\"tuic\",\"tag\":\"tuic\",\"listen\":\"::\",\"listen_port\": ${PORT_TUIC},
      \"users\":[{\"uuid\":\"${TUIC_UUID}\",\"password\":\"${TUIC_PWD}\"}],
      \"congestion_control\":\"bbr\",
      \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
    }")
  fi

  OB=('{"type":"direct","tag":"direct"}')
  if [[ -n "${HOME_LINE:-}" ]]; then
    OB=()
    OB+=($(jq -nc --arg h "$HOME_HOST" --argjson p "$HOME_PORT" \
              --arg u "${HOME_USER:-}" --arg pw "${HOME_PASS:-}" \
              '{"type":"http","tag":"home_http","server":$h,"server_port":($p|tonumber),
                "username":( ($u|length)>0 ? $u : null ),
                "password":( ($pw|length)>0 ? $pw : null ) }'))
    ROUTE='"rules":[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"}],"final":"home_http"'
  else
    ROUTE='"final":"direct"'
  fi
  jq -n --argjson in "[$(IFS=,; echo "${IN[*]-[]}")]" \
        --argjson ob "[$(IFS=,; echo "${OB[*]}")]" \
        --argjson r "{${ROUTE}}" \
        '{log:{level:"info"},inbounds:$in,outbounds:$ob,route:$r}' >"$SB"
  systemctl restart sing-box
}

case "${1:-}" in
  status)
    systemctl --no-pager -l status nginx | sed -n "1,16p"
    echo "---"; systemctl --no-pager -l status xray | sed -n "1,16p"
    echo "---"; systemctl --no-pager -l status sing-box | sed -n "1,16p"
    ;;
  sub)
    echo "订阅：http://$HOST/sub/urls.txt"
    nl -ba /var/lib/sb-sub/urls.txt | sed -n "1,60p"
    ;;
  enable)   [[ $# -eq 2 ]] || { usage; exit 1; }; toggle "$2" 1; regen; ;;
  disable)  [[ $# -eq 2 ]] || { usage; exit 1; }; toggle "$2" 0; regen; ;;
  regen)    regen ;;
  *) usage ;;
esac
CTL
chmod +x /usr/local/bin/edgeboxctl

########################
# 完成信息
########################
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
