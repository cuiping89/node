#!/usr/bin/env bash
set -Eeuo pipefail

# --- 自动提权 ---
if [[ $EUID -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

log(){ printf "\n\033[1;34m[STEP]\033[0m %s\n" "$*"; }

# 版本固定（稳定）
SB_VER="1.12.2"

log "安装基础依赖"
apt-get update -y >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl wget openssl jq unzip socat ufw nginx >/dev/null

mkdir -p /etc/sing-box /usr/local/etc/xray /var/lib/sb-sub /var/www/html/sub /etc/ssl/edgebox

# ===== 交互 =====
echo
read -r -p "域名（留空=自签证书；填入=自动 ACME）： " DOMAIN || true
echo

yn() { # $1 varname $2 prompt $3 default(y|n)
  local v="$1" p="$2" d="$3" ans
  read -r -p "${p} [y/n]（默认：${d}）： " ans || true
  [[ -z "${ans:-}" ]] && ans="$d"
  printf -v "$v" "%s" "$ans"
}

yn EN_GRPC "启用 VLESS-gRPC（走 443，经 Nginx）：" y
yn EN_WS   "启用 VLESS-WS（走 443，经 Nginx）："   y
yn EN_VMESS "启用 VMess-WS（走 443，经 Nginx）："  n
yn EN_REAL "启用 VLESS-Reality（走 443，经 stream→sing-box）：" y
yn EN_HY2  "启用 Hysteria2（udp 443）：" y
yn EN_TUIC "启用 TUIC（udp 2053；若 HY2 关闭可改为 443）：" n

echo
echo "分流策略："
echo "  1) 全部直出（direct）"
echo "  2) 绝大多数走住宅HTTP代理，仅 googlevideo/ytimg/ggpht 直出"
read -r -p "选择（1/2，默认：1）： " ROUTE_MODE || true
[[ -z "${ROUTE_MODE:-}" ]] && ROUTE_MODE="1"

HOME_HOST=""; HOME_PORT=""; HOME_USER=""; HOME_PASS=""
if [[ "$ROUTE_MODE" == "2" ]]; then
  read -r -p "住宅HTTP代理 host/IP（必填）： " HOME_HOST
  read -r -p "住宅HTTP代理 port（必填）： "    HOME_PORT
  read -r -p "住宅HTTP代理 用户名（可空）： "  HOME_USER || true
  read -r -p "住宅HTTP代理 密码（可空）： "    HOME_PASS || true
  if [[ -z "$HOME_HOST" || -z "$HOME_PORT" ]]; then
    echo "[WARN] 代理信息不完整，回退为直出"
    ROUTE_MODE="1"
  fi
fi

# ===== 安装 Xray（承载 gRPC/WS/VMess，均回环监听）=====
log "安装 Xray"
bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null
systemctl enable --now xray >/dev/null 2>&1 || true

# 统一随机
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

# ----- Xray 配置到 127.0.0.1:118xx -----
log "生成 Xray 配置（回环监听，供 443/stream 分流到 Nginx→Xray）"
XRAY_CFG="/usr/local/etc/xray/config.json"
{
  echo '{ "inbounds": ['
  first=1
  if [[ "$EN_GRPC" == "y" ]]; then
    [[ $first -eq 0 ]] && echo ','
    first=0
    cat <<JSON
{
  "listen": "127.0.0.1",
  "port": 11800,
  "protocol": "vless",
  "settings": { "clients": [{ "id": "${UUID_ALL}" }], "decryption": "none" },
  "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "${GRPC_SVC}" } }
}
JSON
  fi
  if [[ "$EN_WS" == "y" ]]; then
    [[ $first -eq 0 ]] && echo ','
    first=0
    cat <<JSON
{
  "listen": "127.0.0.1",
  "port": 11801,
  "protocol": "vless",
  "settings": { "clients": [{ "id": "${UUID_ALL}" }], "decryption": "none" },
  "streamSettings": {
    "network": "ws",
    "wsSettings": { "path": "${WS_PATH}", "headers": { "Host": "${DOMAIN:-localhost}" } }
  }
}
JSON
  fi
  if [[ "$EN_VMESS" == "y" ]]; then
    [[ $first -eq 0 ]] && echo ','
    first=0
    cat <<JSON
{
  "listen": "127.0.0.1",
  "port": 11802,
  "protocol": "vmess",
  "settings": { "clients": [{ "id": "${UUID_VMESS}" }] },
  "streamSettings": {
    "network": "ws",
    "wsSettings": { "path": "${VMESS_PATH}", "headers": { "Host": "${DOMAIN:-localhost}" } }
  }
}
JSON
  fi
  echo '], "outbounds": [{ "protocol": "freedom" }] }'
} >"$XRAY_CFG"
systemctl restart xray

# ===== 证书（ACME→自签兜底）=====
CRT="/etc/ssl/edgebox/fullchain.crt"
KEY="/etc/ssl/edgebox/private.key"
issue_self(){
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$KEY" -out "$CRT" -subj "/CN=${DOMAIN:-edgebox.local}" >/dev/null 2>&1
}

if [[ -n "${DOMAIN:-}" ]]; then
  log "申请 ACME 证书：$DOMAIN（失败将回退自签）"
  if ! ~/.acme.sh/acme.sh -v >/dev/null 2>&1; then
    curl -fsSL https://get.acme.sh | sh -s email=admin@${DOMAIN} >/dev/null 2>&1 || true
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" --keylength ec-256 >/dev/null 2>&1; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
      --fullchain-file "$CRT" --key-file "$KEY" >/dev/null 2>&1 || issue_self
  else
    echo "[WARN] ACME 失败，使用自签"
    issue_self
  fi
else
  log "未填域名，生成自签证书"
  issue_self
fi

# ===== Reality 密钥双路兜底 =====
log "生成 Reality 密钥对（sing-box→xray 双路兜底）"
read PRIV PBK < <( (sing-box generate reality-keypair 2>/dev/null || true) | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}')
if [[ -z "${PRIV:-}" || -z "${PBK:-}" ]]; then
  read PRIV PBK < <( (xray x25519 2>/dev/null || true) | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}')
fi
if [[ -z "${PRIV:-}" || -z "${PBK:-}" ]]; then
  echo "[FATAL] Reality 密钥生成失败"; exit 1
fi
echo "[OK] Reality PBK: $PBK"

# ===== Nginx：HTTP层(回环8443) + STREAM层(对外443) =====
log "写入 Nginx (HTTP 8443/loopback) 与 STREAM(443) 配置"
# 8443 只在本机监听，TLS 终止 → 反代 11800/11801/11802
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

# STREAM：443 SNI 分流 → 8443 或 14443
cat >/etc/nginx/stream.conf <<NG2
stream {
  map \$ssl_preread_server_name \$edgebox_up {
    ${DOMAIN:-_}  grpcws;
    default       reality;
  }
  upstream grpcws { server 127.0.0.1:8443; }
  upstream reality{ server 127.0.0.1:14443; }

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

# ===== sing-box：Reality on 127.0.0.1:14443；HY2 udp/443；TUIC 逻辑 =====
log "生成 sing-box 配置"
SB_CFG="/etc/sing-box/config.json"

# 路由/出站
ROUTE_JSON='"final":"direct"'
HOME_OB=""
if [[ "$ROUTE_MODE" == "2" ]]; then
  HOME_OB=$(jq -n --arg h "$HOME_HOST" --argjson p "$HOME_PORT" \
               --arg u "$HOME_USER" --arg pw "$HOME_PASS" '{
      "type":"http","tag":"home_http",
      "server":$h,"server_port":($p|tonumber),
      "username":( ($u|length)>0 ? $u : null ),
      "password":( ($pw|length)>0 ? $pw : null )
    }')
  ROUTE_JSON='"rules":[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"}],"final":"home_http"'
fi

IN=()

# Reality via stream fallback → 本机 14443
if [[ "$EN_REAL" == "y" ]]; then
IN+=("{
  \"type\":\"vless\",\"tag\":\"vless-reality\",\"listen\":\"127.0.0.1\",\"listen_port\":14443,
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
fi

# HY2 优先占用 udp/443
if [[ "$EN_HY2" == "y" ]]; then
IN+=("{
  \"type\":\"hysteria2\",\"tag\":\"hy2\",\"listen\":\"::\",\"listen_port\":443,
  \"users\":[{\"password\":\"${HY2_PWD}\"}],
  \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
}")
fi

# TUIC：若 HY2 已占用 443，则退到 2053/udp
TUIC_PORT=443
if [[ "$EN_HY2" == "y" && "$EN_TUIC" == "y" ]]; then
  TUIC_PORT=2053
  echo "[WARN] HY2 已占用 UDP/443，TUIC 自动改用 UDP/2053"
elif [[ "$EN_TUIC" == "y" && "$EN_HY2" != "y" ]]; then
  TUIC_PORT=443
fi
if [[ "$EN_TUIC" == "y" ]]; then
IN+=("{
  \"type\":\"tuic\",\"tag\":\"tuic\",\"listen\":\"::\",\"listen_port\":${TUIC_PORT},
  \"users\":[{\"uuid\":\"${TUIC_UUID}\",\"password\":\"${TUIC_PWD}\"}],
  \"congestion_control\":\"bbr\",
  \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
}")
fi

OB=('{"type":"direct","tag":"direct"}')
[[ -n "$HOME_OB" ]] && OB+=("$HOME_OB")
OB+=('{"type":"block","tag":"block"}')

jq -n --argjson in "[$(IFS=,; echo "${IN[*]-[]}")]" \
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

# ===== UFW 端口放行（仅 443/tcp 必开；udp 视协议）=====
log "放行 UFW 端口（若未安装/未启用将自动忽略）"
run_quiet ufw allow 443/tcp
[[ "$EN_HY2" == "y" ]] && run_quiet ufw allow 443/udp
if [[ "$EN_TUIC" == "y" ]]; then
  run_quiet ufw allow ${TUIC_PORT}/udp
fi
run_quiet ufw reload

# ===== 生成聚合订阅（全部对外 443）=====
HOST="${DOMAIN:-$(curl -fsS https://api.ipify.org || hostname -I | awk '{print $1}')}"
SUB="/var/lib/sb-sub/urls.txt"
: >"$SUB"
[[ "$EN_GRPC" == "y" ]] && printf "vless://%s@%s:443?encryption=none&security=tls&type=grpc&serviceName=%s&fp=chrome#VLESS-gRPC@%s\n" "$UUID_ALL" "$HOST" "$GRPC_SVC" "$HOST" >>"$SUB"
[[ "$EN_WS"   == "y" ]] && printf "vless://%s@%s:443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n" "$UUID_ALL" "$HOST" "$WS_PATH" "$HOST" "$HOST" >>"$SUB"
[[ "$EN_VMESS"== "y" ]] && printf "vmess://%s\n" "$(jq -nc --arg v '2' --arg add 'none' --arg host "$HOST" --arg path "$VMESS_PATH" --arg id "$UUID_VMESS" --arg tls 'tls' --arg type 'ws' --arg sni "$HOST" --arg ps "VMess-WS@$HOST" '{v:$v,ps:$ps,add:$host,port:"443",id:$id,aid:"0",scy:$add,net:$type,type:"",host:$host,path:$path,tls:$tls,sni:$sni,alpn:""}' | base64 -w0)" >>"$SUB"
[[ "$EN_REAL" == "y" ]] && printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" "$UUID_ALL" "$HOST" "$SNI_CF" "$PBK" "$SID" "$HOST" >>"$SUB"
[[ "$EN_HY2"  == "y" ]] && printf "hysteria2://%s@%s:443?alpn=h3#HY2@%s\n" "$HY2_PWD" "$HOST" "$HOST" >>"$SUB"
if [[ "$EN_TUIC" == "y" ]]; then
  printf "tuic://%s:%s@%s:%s?congestion=bbr&alpn=h3#TUIC@%s\n" "$TUIC_UUID" "$TUIC_PWD" "$HOST" "$TUIC_PORT" "$HOST" >>"$SUB"
fi
ln -sf "$SUB" /var/www/html/sub/urls.txt

log "完成。订阅链接： http://$HOST/sub/urls.txt"
echo "若用自签证书，请在客户端勾选“跳过证书验证/allowInsecure”。"
echo
echo "[端口快照]"
ss -lnptu | egrep ':443|:2053' || true
echo
echo "[服务概要]"
systemctl --no-pager -l status nginx | sed -n '1,18p'
echo "---"
systemctl --no-pager -l status xray | sed -n '1,18p'
echo "---"
systemctl --no-pager -l status sing-box | sed -n '1,18p'
