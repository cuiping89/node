#!/usr/bin/env bash
set -Eeuo pipefail

### ===== 共用输出 =====
if [[ $EUID -ne 0 ]]; then exec sudo -E bash "$0" "$@"; fi
log(){ printf "\n\033[1;34m[STEP]\033[0m %s\n" "$*"; }
ok(){  printf "\033[1;32m[OK]\033[0m %s\n" "$*"; }
warn(){printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err(){ printf "\033[1;31m[ERR]\033[0m %s\n" "$*"; }

on_fail(){
  err "安装出错。摘录最近日志帮助排查："
  journalctl -u nginx -u xray -u sing-box -b --no-pager -n 80 || true
}
trap on_fail ERR

echo "[INFO] 需放行端口：tcp/443, udp/8443(HY2), udp/2053(TUIC)，建议额外放开 udp/443(备)。"
echo "       云防火墙/安全组 + 本机(UFW) 都要放行。"

### ===== 依赖 =====
apt-get update -y >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl wget openssl jq unzip socat ufw nginx >/dev/null

install -d /etc/sing-box /usr/local/etc/xray /var/lib/sb-sub /var/www/html/sub /etc/ssl/edgebox

### ===== 交互：域名 & 住宅代理一次粘贴 =====
read -r -p "域名（留空=自签；填入=自动 ACME）：" DOMAIN || true
read -r -p "住宅代理（HOST:PORT[:USER[:PASS]]，留空=不用）：" PROXY_FULL || true
HOME_HOST=""; HOME_PORT=""; HOME_USER=""; HOME_PASS=""
if [[ -n "${PROXY_FULL:-}" ]]; then IFS=: read -r HOME_HOST HOME_PORT HOME_USER HOME_PASS <<<"$PROXY_FULL"; fi

### ===== BBR+fq 与 2GB swap =====
log "开启 BBR+fq、准备 2GB swap（若不存在）"
sysctl -w net.core.default_qdisc=fq >/dev/null
sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
if ! swapon --show | grep -q '^'; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
fi
ok "网络优化与 swap 就绪"

### ===== Xray（承载 gRPC/WS）=====
log "安装 Xray"
bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null || true
systemctl enable --now xray >/dev/null 2>&1 || true

### ===== sing-box（取 GitHub 最新 release）=====
log "安装 sing-box（最新 release）"
TMP=$(mktemp -d)
DL=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest \
  | jq -r '.assets[]|select(.name|test("linux-amd64.tar.gz$")).browser_download_url')
curl -fsSL "$DL" | tar -xz -C "$TMP"
install -m755 "$TMP"/sing-box*/sing-box /usr/local/bin/sing-box
rm -rf "$TMP"
ok "$(sing-box version | head -n1)"

### ===== 证书：ACME 优先，失败自签 =====
CRT="/etc/ssl/edgebox/fullchain.crt"
KEY="/etc/ssl/edgebox/private.key"
issue_self(){ openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
  -keyout "$KEY" -out "$CRT" -subj "/CN=${DOMAIN:-edgebox.local}" >/dev/null 2>&1; ok "自签证书已生成"; }
if [[ -n "${DOMAIN:-}" ]]; then
  log "申请 ACME 证书：$DOMAIN（失败自动自签）"
  systemctl stop nginx || true
  if ! ~/.acme.sh/acme.sh -v >/dev/null 2>&1; then
    curl -fsSL https://get.acme.sh | sh -s email=admin@"${DOMAIN}" >/dev/null 2>&1 || true
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" --keylength ec-256 >/dev/null 2>&1; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc --fullchain-file "$CRT" --key-file "$KEY" >/dev/null 2>&1 || issue_self
  else warn "ACME 失败，改用自签"; issue_self; fi
  systemctl start nginx || true
else
  log "未填域名，使用自签证书"; issue_self
fi

### ===== 幂等参数生成/读取 =====
XRAY_CFG="/usr/local/etc/xray/config.json"
SB_CFG="/etc/sing-box/config.json"
json_get(){ jq -r "$1 // empty" "$2" 2>/dev/null || true; }
rand_hex(){ openssl rand -hex "$1"; }

UUID_ALL=$(json_get '..|.id? // .uuid? // empty' "$XRAY_CFG" | head -n1)
UUID_ALL=${UUID_ALL:-$(cat /proc/sys/kernel/random/uuid)}
WS_PATH=$(json_get '.inbounds[]?|select(.streamSettings.wsSettings.path!=null).streamSettings.wsSettings.path' "$XRAY_CFG" | head -n1)
WS_PATH=${WS_PATH:-"/$(rand_hex 3)"}
GRPC_SVC="grpc"

PRIV=$(json_get '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.private_key' "$SB_CFG" | head -n1)
PBK=$(json_get  '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.public_key'  "$SB_CFG" | head -n1)
if [[ -z "${PRIV:-}" || -z "${PBK:-}" ]]; then
  log "生成 Reality 密钥对（sing-box 优先，xray 兜底）"
  read PRIV PBK < <( (sing-box generate reality-keypair 2>/dev/null || true) | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}')
  if [[ -z "${PRIV:-}" || -z "${PBK:-}" ]]; then
    read PRIV PBK < <( (xray x25519 2>/dev/null || true) | awk -F': *' '/Private/{p=$2}/Public/{print p,$2}')
  fi
fi
[[ -z "${PRIV:-}" || -z "${PBK:-}" ]] && { err "Reality 密钥生成失败"; exit 1; }
SID=$(json_get '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.short_id[0]' "$SB_CFG" | head -n1)
SID=${SID:-$(rand_hex 4)}
SNI_CF="www.cloudflare.com"

HY2_PWD=$(json_get '.inbounds[]?|select(.type=="hysteria2").users[0].password' "$SB_CFG" | head -n1)
HY2_PWD=${HY2_PWD:-$(rand_hex 12)}
TUIC_UUID=$(json_get '.inbounds[]?|select(.type=="tuic").users[0].uuid' "$SB_CFG" | head -n1)
TUIC_UUID=${TUIC_UUID:-$(cat /proc/sys/kernel/random/uuid)}
TUIC_PWD=$(json_get '.inbounds[]?|select(.type=="tuic").users[0].password' "$SB_CFG" | head -n1)
TUIC_PWD=${TUIC_PWD:-$(rand_hex 12)}

### ===== Xray：回环 gRPC/WS，供 HTTPS 反代 =====
log "写入 Xray 配置（127.0.0.1:11800 gRPC / 11801 WS）"
cat >"$XRAY_CFG" <<JSON
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 11800,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$UUID_ALL" } ], "decryption": "none" },
      "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "$GRPC_SVC" } }
    },
    {
      "listen": "127.0.0.1",
      "port": 11801,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$UUID_ALL" } ], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "$WS_PATH", "headers": { "Host": "${DOMAIN:-localhost}" } }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom" } ]
}
JSON
systemctl restart xray

### ===== Nginx：HTTPS(回环8443) + STREAM(443 SNI分流) =====
log "配置 Nginx（HTTPS 8443 内部终止 + 443 SNI 分流）"
# HTTPS: 仅本机监听，TLS 终止，再反代 gRPC/WS
cat >/etc/nginx/conf.d/edgebox-https.conf <<NG1
server {
  listen 127.0.0.1:8443 ssl http2;
  server_name ${DOMAIN:-_};

  ssl_certificate     ${CRT};
  ssl_certificate_key ${KEY};

  # gRPC
  location /$GRPC_SVC {
    grpc_set_header X-Real-IP \$remote_addr;
    grpc_pass grpc://127.0.0.1:11800;
  }

  # VLESS-WS
  location $WS_PATH {
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_pass http://127.0.0.1:11801;
  }
}
NG1

# STREAM：把 www.cloudflare.com 等默认 SNI 走 reality；访问你的域名走 8443
ensure_stream_include(){
  if ! grep -q 'include /etc/nginx/stream.conf;' /etc/nginx/nginx.conf; then
    # 插到 modules-enabled 之后（主上下文）
    sed -i '/modules-enabled\/\*\.conf\;/a include \/etc\/nginx\/stream.conf;' /etc/nginx/nginx.conf
  fi
}
ensure_stream_include

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

### ===== sing-box：Reality(14443) + HY2(8443/443) + TUIC(2053) + 路由 =====
log "写入 sing-box 配置"
ROUTE_JSON='"final":"direct"'
HOME_OB=""
if [[ -n "${HOME_HOST:-}" && -n "${HOME_PORT:-}" ]]; then
  HOME_OB=$(jq -n --arg h "$HOME_HOST" --argjson p "$HOME_PORT" \
              --arg u "${HOME_USER:-}" --arg pw "${HOME_PASS:-}" '{
    type:"http", tag:"home_http",
    server:$h, server_port:($p|tonumber),
    username:(($u|length)>0?$u:null),
    password:(($pw|length)>0?$pw:null)
  }')
  ROUTE_JSON='"rules":[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"}],"final":"home_http"'
fi

read -r -d '' SB_INB <<'JSON' || true
[]
JSON
add_in(){ local obj="$1"; SB_INB=$(jq --argjson o "$obj" '. + [$o]' <<<"$SB_INB"); }

# Reality via 127.0.0.1:14443
add_in "$(jq -n --arg uuid "$UUID_ALL" --arg sni "$SNI_CF" --arg pk "$PRIV" --arg sid "$SID" '{
  type:"vless", tag:"vless-reality", listen:"127.0.0.1", listen_port:14443,
  users:[{uuid:$uuid, flow:"xtls-rprx-vision"}],
  tls:{enabled:true, server_name:$sni,
       reality:{enabled:true, private_key:$pk, short_id:[$sid],
                handshake:{server:$sni, server_port:443}}}
}')"

# HY2: udp/8443 + udp/443（并存）
for p in 8443 443; do
  add_in "$(jq -n --arg pwd "$HY2_PWD" --arg crt "$CRT" --arg key "$KEY" --argjson lp "$p" '{
    type:"hysteria2", tag:("hy2-"+($lp|tostring)), listen:"::", listen_port:$lp,
    users:[{password:$pwd}],
    tls:{enabled:true, alpn:["h3"], certificate_path:$crt, key_path:$key}
  }')"
done

# TUIC: udp/2053
add_in "$(jq -n --arg uuid "$TUIC_UUID" --arg pwd "$TUIC_PWD" --arg crt "$CRT" --arg key "$KEY" '{
  type:"tuic", tag:"tuic-2053", listen:"::", listen_port:2053,
  users:[{uuid:$uuid, password:$pwd}],
  congestion_control:"bbr",
  tls:{enabled:true, alpn:["h3"], certificate_path:$crt, key_path:$key}
}')"

OB='[{"type":"direct","tag":"direct"}'
[[ -n "$HOME_OB" ]] && OB="$OB, $HOME_OB"
OB="$OB, {\"type\":\"block\",\"tag\":\"block\"}]"

jq -n --argjson in "$SB_INB" --argjson ob "$OB" --argjson route "{${ROUTE_JSON}}" \
  '{log:{level:"info"}, inbounds:$in, outbounds:$ob, route:$route}' >"$SB_CFG"

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

### ===== UFW 放行（不强制启用）=====
log "UFW 放行端口（未启用则忽略）"
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw allow 443/udp >/dev/null 2>&1 || true   # HY2 备
ufw allow 8443/udp >/dev/null 2>&1 || true  # HY2 主
ufw allow 2053/udp >/dev/null 2>&1 || true  # TUIC
ufw reload >/dev/null 2>&1 || true

### ===== 订阅聚合 =====
HOST="${DOMAIN:-$(curl -fsS https://api.ipify.org || hostname -I | awk '{print $1}')}"
SUB="/var/lib/sb-sub/urls.txt"; : >"$SUB"

printf "vless://%s@%s:443?encryption=none&security=tls&type=grpc&serviceName=%s&fp=chrome#VLESS-gRPC@%s\n" \
  "$UUID_ALL" "$HOST" "$GRPC_SVC" "$HOST" >>"$SUB"
printf "vless://%s@%s:443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n" \
  "$UUID_ALL" "$HOST" "$WS_PATH" "$HOST" "$HOST" >>"$SUB"
printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" \
  "$UUID_ALL" "$HOST" "$SNI_CF" "$PBK" "$SID" "$HOST" >>"$SUB"
printf "hysteria2://%s@%s:8443?alpn=h3#HY2-8443@%s\n" "$HY2_PWD" "$HOST" "$HOST" >>"$SUB"
printf "hysteria2://%s@%s:443?alpn=h3#HY2-443@%s\n"   "$HY2_PWD" "$HOST" "$HOST" >>"$SUB"
printf "tuic://%s:%s@%s:2053?congestion=bbr&alpn=h3#TUIC-2053@%s\n" \
  "$TUIC_UUID" "$TUIC_PWD" "$HOST" "$HOST" >>"$SUB"

ln -sf "$SUB" /var/www/html/sub/urls.txt

### ===== 管理脚本：edgeboxctl =====
log "安装管理脚本 /usr/local/bin/edgeboxctl"
cat >/usr/local/bin/edgeboxctl <<'CTL'
#!/usr/bin/env bash
set -Eeuo pipefail
SUB="/var/lib/sb-sub/urls.txt"
XRAY_CFG="/usr/local/etc/xray/config.json"
SB_CFG="/etc/sing-box/config.json"
CRT="/etc/ssl/edgebox/fullchain.crt"; KEY="/etc/ssl/edgebox/private.key"

json(){ jq -r "$1 // empty" "$2" 2>/dev/null || true; }

cmd=${1:-help}; shift || true
case "$cmd" in
  help|-h|--help)
    cat <<'H'
edgeboxctl 命令：
  status              - 查看服务状态与端口
  reload              - reload nginx；restart xray/sing-box
  logs [nginx|xray|sing-box] [-n 200] - 看日志
  sub                 - 显示订阅链接与内容片段
  regen-sub           - 从现有配置重新生成订阅
  reality             - 打印 Reality 的 PBK/SID/SNI/UUID
  versions            - 打印 Xray / sing-box 版本
H
  ;;
  status)
    echo "[系统服务]"; systemctl --no-pager -l status nginx | sed -n '1,10p'; echo "---"
    systemctl --no-pager -l status xray | sed -n '1,10p'; echo "---"
    systemctl --no-pager -l status sing-box | sed -n '1,10p'
    echo; echo "[端口监听]"; ss -lnptu | egrep ':443|:8443|:2053' || true
    ;;
  reload)
    nginx -t && systemctl reload nginx
    systemctl restart xray sing-box
    echo "[OK] 已重载。"
    ;;
  logs)
    svc="${1:-sing-box}"; shift || true
    journalctl -u "$svc" -b --no-pager ${*:- -n 200}
    ;;
  sub)
    host="$(hostname -f 2>/dev/null || true)"
    echo "订阅链接： http://${host}/sub/urls.txt"
    nl -ba "$SUB" | sed -n '1,200p'
    ;;
  regen-sub)
    host="$(hostname -f 2>/dev/null || true)"
    UUID_ALL="$(json '..|.id? // .uuid? // empty' "$XRAY_CFG" | head -n1)"
    WS_PATH="$(json '.inbounds[]?|select(.streamSettings.wsSettings.path!=null).streamSettings.wsSettings.path' "$XRAY_CFG" | head -n1)"
    GRPC_SVC="grpc"
    PBK="$(json '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.public_key' "$SB_CFG" | head -n1)"
    SID="$(json '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.short_id[0]' "$SB_CFG" | head -n1)"
    SNI="www.cloudflare.com"
    HY2_PWD="$(json '.inbounds[]?|select(.type=="hysteria2").users[0].password' "$SB_CFG" | head -n1)"
    TUIC_UUID="$(json '.inbounds[]?|select(.type=="tuic").users[0].uuid' "$SB_CFG" | head -n1)"
    TUIC_PWD="$(json '.inbounds[]?|select(.type=="tuic").users[0].password' "$SB_CFG" | head -n1)"
    : >"$SUB"
    [[ -n "$UUID_ALL" ]] && printf "vless://%s@%s:443?encryption=none&security=tls&type=grpc&serviceName=%s&fp=chrome#VLESS-gRPC@%s\n" "$UUID_ALL" "$host" "$GRPC_SVC" "$host" >>"$SUB"
    [[ -n "$UUID_ALL" && -n "$WS_PATH" ]] && printf "vless://%s@%s:443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n" "$UUID_ALL" "$host" "$WS_PATH" "$host" "$host" >>"$SUB"
    [[ -n "$UUID_ALL" && -n "$PBK" && -n "$SID" ]] && printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" "$UUID_ALL" "$host" "$SNI" "$PBK" "$SID" "$host" >>"$SUB"
    [[ -n "$HY2_PWD" ]] && {
      printf "hysteria2://%s@%s:8443?alpn=h3#HY2-8443@%s\n" "$HY2_PWD" "$host" "$host" >>"$SUB"
      printf "hysteria2://%s@%s:443?alpn=h3#HY2-443@%s\n"   "$HY2_PWD" "$host" "$host" >>"$SUB"
    }
    [[ -n "$TUIC_UUID" && -n "$TUIC_PWD" ]] && printf "tuic://%s:%s@%s:2053?congestion=bbr&alpn=h3#TUIC-2053@%s\n" "$TUIC_UUID" "$TUIC_PWD" "$host" "$host" >>"$SUB"
    echo "[OK] 已重建：$SUB"
    ;;
  reality)
    PBK="$(json '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.public_key' "$SB_CFG" | head -n1)"
    SID="$(json '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.short_id[0]' "$SB_CFG" | head -n1)"
    UUID_ALL="$(json '..|.id? // .uuid? // empty' "$XRAY_CFG" | head -n1)"
    echo "UUID: $UUID_ALL"
    echo "PBK : $PBK"
    echo "SID : $SID"
    echo "SNI : www.cloudflare.com"
    ;;
  versions)
    xray -version 2>/dev/null | head -n1 || true
    sing-box version 2>/dev/null | head -n1 || true
    ;;
  *)
    echo "未知命令：$cmd。用法：edgeboxctl help"
    exit 1
    ;;
esac
CTL
chmod +x /usr/local/bin/edgeboxctl

### ===== 汇总输出 =====
echo
ok "安装完成。订阅链接： http://$HOST/sub/urls.txt"
echo "如使用自签证书（常见于 HY2/TUIC），客户端需勾选“跳过证书验证/allowInsecure”。"
echo
echo "[端口监听]"
ss -lnptu | egrep ':443|:8443|:2053' || true
echo
echo "[服务状态]"
systemctl --no-pager -l status nginx | sed -n '1,12p'; echo "---"
systemctl --no-pager -l status xray | sed -n '1,12p';  echo "---"
systemctl --no-pager -l status sing-box | sed -n '1,12p'
echo
echo "[管理脚本]"
echo "  edgeboxctl status      # 查看状态与端口"
echo "  edgeboxctl sub         # 查看订阅链接与条目"
echo "  edgeboxctl reload      # 重载 Nginx，重启 Xray/sing-box"
echo "  edgeboxctl logs xray   # 看某服务日志"
echo "  edgeboxctl reality     # 打印 PBK/SID/SNI/UUID"
echo "  edgeboxctl regen-sub   # 订阅重建（从现有配置）"
