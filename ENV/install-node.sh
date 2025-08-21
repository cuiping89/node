#!/usr/bin/env bash
set -euo pipefail

# ============ 基本参数 ============
SBOX_VER="1.13.3"         # 固定一版稳定可用（避免未来配置项突变）
XRAY_VER="25.8.3"         # 只做内网入站（grpc/ws）并走 127.0.0.1:11080 -> sing-box 出口策略
WORKDIR="/opt/edgebox"
CONF_SB="/etc/sing-box/config.json"
CONF_XR="/etc/xray/config.json"
SUB_DIR="/var/lib/sb-sub"
SUB_FILE="${SUB_DIR}/urls.txt"
SUB_URL_PATH="/sub/urls.txt"     # Nginx 静态路径
LOCAL_SOCKS_PORT=11080           # Xray 出口 -> sing-box 本地 SOCKS
INTERNAL_WS_PORT=10080           # Xray vless-ws 内网口
INTERNAL_GRPC_PORT=10085         # Xray vless-grpc 内网口

# ============ 颜色输出 ============
ce(){ printf "\033[1;32m%s\033[0m\n" "$*"; }
we(){ printf "\033[1;33m%s\033[0m\n" "$*"; }
fe(){ printf "\033[1;31m%s\033[0m\n" "$*"; }

# ============ 依赖 ============
[ "$EUID" -eq 0 ] || { fe "请用 root 运行"; exit 1; }
apt-get update -y
apt-get install -y curl wget jq unzip tar ufw nginx

# ============ 交互：域名/端口/开关 ============
read -rp "用于 gRPC/WS 的域名（建议指向本机公网IP；仅启用 gRPC/WS 时必填，空则生成自签证书）： " DOMAIN || true
read -rp "HY2 端口（udp），回车用 443（可填 8443）: " HY2PORT || true
HY2PORT=${HY2PORT:-443}

read -rp "启用 VLESS-gRPC(443/tcp)? [y/N]: " ON_GRPC || true
read -rp "启用 VLESS-WS(+TLS)? [y/N]: " ON_WS || true
read -rp "启用 VLESS-Reality(443/tcp)? [y/N]: " ON_REALITY || true
read -rp "启用 Hysteria2(udp:${HY2PORT})? [Y/n]: " ON_HY2 || true
read -rp "启用 TUIC(udp:2053)? [y/N]: " ON_TUIC || true
ON_HY2=${ON_HY2:-Y}

# 冲突处理：Reality(443/tcp) 与 Nginx(443/tcp) 不能共存
if [[ "${ON_REALITY,,}" == y && ( "${ON_GRPC,,}" == y || "${ON_WS,,}" == y ) ]]; then
  we "Reality(443/tcp) 与 Nginx(443/tcp) 冲突；将自动把 Nginx 的 gRPC/WS 迁到 8443。"
  NGINX_TLS_PORT=8443
else
  NGINX_TLS_PORT=443
fi

# HY2 与 Nginx QUIC 冲突
if [[ "${ON_HY2,,}" == y && "${HY2PORT}" == "443" ]]; then
  we "将禁用 Nginx QUIC(HTTP/3)，避免与 HY2 占用 UDP:443 冲突。"
fi

# 出口分流策略
echo
ce "出口分流策略："
echo "1) 全部直出 VPS (direct)"
echo "2) 走你的静态住宅 HTTP 代理（仅 googlevideo/ytimg/ggpht 直出）"
read -rp "选择 [1/2]，默认 1: " ROUTE_MODE || true
ROUTE_MODE=${ROUTE_MODE:-1}
if [[ "$ROUTE_MODE" == "2" ]]; then
  read -rp "住宅 HTTP 代理地址（host）: " RES_HOST
  read -rp "住宅 HTTP 代理端口（port）: " RES_PORT
  read -rp "住宅 HTTP 代理用户名（可空）: " RES_USER || true
  read -rp "住宅 HTTP 代理密码（可空）: " RES_PASS || true
fi

# ============ 系统优化：BBR+fq、Swap、UFW ============

# BBR + fq
sysctl -w net.core.default_qdisc=fq >/dev/null
sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
grep -q "tcp_congestion_control" /etc/sysctl.conf || cat >>/etc/sysctl.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl -p >/dev/null || true
ce "BBR + fq 已应用"

# 2G swap（若无）
if ! swapon --show | grep -q '^'; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo "/swapfile none swap sw 0 0" >> /etc/fstab
  ce "已创建 2G swap"
else
  we "已存在 swap，跳过"
fi

# UFW
ufw allow 22/tcp >/dev/null || true
[[ "${ON_GRPC,,}" == y || "${ON_WS,,}" == y ]] && ufw allow ${NGINX_TLS_PORT}/tcp >/dev/null || true
[[ "${ON_REALITY,,}" == y ]] && ufw allow 443/tcp >/dev/null || true
[[ "${ON_HY2,,}" == y ]] && ufw allow ${HY2PORT}/udp >/dev/null || true
[[ "${ON_TUIC,,}" == y ]] && ufw allow 2053/udp >/dev/null || true
ufw --force enable >/dev/null || true
ce "UFW 端口规则已配置"

# ============ 安装 sing-box ============
mkdir -p "$WORKDIR"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) SB_ASSET="sing-box-${SBOX_VER}-linux-amd64.tar.gz" ;;
  aarch64|arm64) SB_ASSET="sing-box-${SBOX_VER}-linux-arm64.tar.gz" ;;
  *) fe "不支持的体系结构: $ARCH"; exit 1;;
esac
cd "$WORKDIR"
wget -q "https://github.com/SagerNet/sing-box/releases/download/v${SBOX_VER}/${SB_ASSET}"
tar xf "${SB_ASSET}"
install -m 755 "sing-box-${SBOX_VER}-linux-"*/sing-box /usr/local/bin/sing-box
setcap cap_net_bind_service=+ep /usr/local/bin/sing-box || true

# ============ 安装 Xray（仅承载 ws/grpc 内网口） ============
if [[ "${ON_GRPC,,}" == y || "${ON_WS,,}" == y ]]; then
  wget -qO - https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- --version v${XRAY_VER}
fi

# ============ 证书（自签） ============
CERT_DIR="/etc/ssl/certs"
KEY_DIR="/etc/ssl/private"
mkdir -p "$CERT_DIR" "$KEY_DIR"
CERT_FILE="${CERT_DIR}/${DOMAIN:-self}.crt"
KEY_FILE="${KEY_DIR}/${DOMAIN:-self}.key"
if [[ -n "${DOMAIN}" ]]; then
  # 自签也可；若你要 LE，可改用 acme.sh 自取证书
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=${DOMAIN}" >/dev/null 2>&1
else
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=self.local" >/dev/null 2>&1
fi

# ============ 统一账户/密钥 ============
UUID=$(cat /proc/sys/kernel/random/uuid)
HY2_PASS=$(openssl rand -hex 16)
TUIC_PASS=$(openssl rand -hex 16)

# Reality 密钥
PK_JSON=$(sing-box generate reality-keypair)
PRIV=$(echo "$PK_JSON" | jq -r '.private_key')
PUBK=$(echo "$PK_JSON" | jq -r '.public_key')
SID="a0235dcd"  # 4~8 hex，客户端和服务端一致

# 选择 Reality 的伪装 SNI（默认 www.cloudflare.com）
HSNI=${HSNI:-"www.cloudflare.com"}

# ============ 生成 sing-box 配置 ============
mkdir -p "$(dirname "$CONF_SB")"

# DNS：使用现代 DoH，避免 legacy 警告
DNS_BLOCK='{"tag":"block","address":"rcode://success"}'
DNS_GOOGLE='{"tag":"doh-google","address":"https://dns.google/dns-query"}'
DNS_LOCAL='{"tag":"local","address":"local"}'

# 出口：住宅 HTTP 代理或 direct
if [[ "$ROUTE_MODE" == "2" ]]; then
  OUT_RES=$(jq -n --arg h "$RES_HOST" --argjson p ${RES_PORT:-80} \
                  --arg u "${RES_USER:-}" --arg pw "${RES_PASS:-}" \
                  '{type:"http", server:$h, server_port:$p, username:$u, password:$pw, tag:"resproxy"}')
  DEFAULT_OUT="resproxy"
else
  OUT_RES=""
  DEFAULT_OUT="direct"
fi

# inbounds（按开关拼装）
INBS=()

# 统一本地 SOCKS（给 Xray 出口用）
INBS+=('{"type":"socks","listen":"127.0.0.1","listen_port":'"${LOCAL_SOCKS_PORT}"',"sniff":true,"set_system_proxy":false}')

# HY2
if [[ "${ON_HY2,,}" == y ]]; then
INBS+=('{
  "type":"hysteria2","listen":"::","listen_port":'"${HY2PORT}"',
  "users":[{"name":"u","password":"'"${HY2_PASS}"'"}],
  "up_mbps":1000,"down_mbps":1000,
  "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"'"${CERT_FILE}"'","key_path":"'"${KEY_FILE}"'","insecure":true}
}')
fi

# TUIC
if [[ "${ON_TUIC,,}" == y ]]; then
INBS+=('{
  "type":"tuic","listen":"::","listen_port":2053,
  "users":[{"uuid":"'"${UUID}"'","password":"'"${TUIC_PASS}"'"}],
  "congestion_control":"bbr",
  "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"'"${CERT_FILE}"'","key_path":"'"${KEY_FILE}"'","insecure":true}
}')
fi

# Reality
if [[ "${ON_REALITY,,}" == y ]]; then
INBS+=('{
  "type":"vless","listen":"::","listen_port":443,
  "users":[{"uuid":"'"${UUID}"'"}],
  "tls":{"enabled":true,"server_name":"'"${HSNI}"'",
    "reality":{"enabled":true,"private_key":"'"${PRIV}"'","short_id":["'"${SID}"'"]}
  },
  "transport":{"type":"tcp"}
}')
fi

# 拼装 inbounds JSON
JOIN_INBS=$(printf ",%s" "${INBS[@]}"); JOIN_INBS="[${JOIN_INBS:1}]"

# outbounds
OUTS='[
  {"type":"direct","tag":"direct"},
  {"type":"block","tag":"block"},
  {"type":"dns","tag":"dns-out"}
'
if [[ -n "${OUT_RES}" ]]; then
  OUTS="${OUTS},${OUT_RES}"
fi
OUTS="${OUTS}]"

# route 规则
ROUTE_RULES='[
  {"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com","gstatic.com","googleusercontent.com"],"outbound":"direct"},
  {"protocol":["dns"],"outbound":"dns-out"}
]'
ROUTE=$(jq -n --arg def "$DEFAULT_OUT" --argjson rules "${ROUTE_RULES}" \
        '{auto_detect_interface:true, rules:$rules, final:$def}')

# 写入 sing-box 配置
jq -n \
  --argjson inb "${JOIN_INBS}" \
  --argjson outs "${OUTS}" \
  --argjson dns '{
    servers:['"${DNS_GOOGLE},${DNS_LOCAL},${DNS_BLOCK}"'],
    strategy:"prefer_ipv4"
  }' \
  --argjson route "${ROUTE}" \
  '{log:{level:"info"}, dns:$dns, inbounds:$inb, outbounds:$outs, route:$route}' > "${CONF_SB}"

# ============ 生成 Xray 配置（仅 ws/grpc 内网口） ============
if [[ "${ON_GRPC,,}" == y || "${ON_WS,,}" == y ]]; then
  mkdir -p /etc/xray
  cat > "${CONF_XR}" <<XR
{
  "inbounds": [
    ${
      [[ "${ON_WS,,}" == y ]] && cat <<'W1'
      {
        "tag": "vless-ws",
        "listen": "127.0.0.1",
        "port": 10080,
        "protocol": "vless",
        "settings": {
          "decryption": "none",
          "clients": [{"id": "UUID_REPLACE"}]
        },
        "streamSettings": {
          "network": "ws",
          "wsSettings": {"path": "/ws"}
        }
      },
W1
    }
    ${
      [[ "${ON_GRPC,,}" == y ]] && cat <<'G1'
      {
        "tag": "vless-grpc",
        "listen": "127.0.0.1",
        "port": 10085,
        "protocol": "vless",
        "settings": {
          "decryption": "none",
          "clients": [{"id": "UUID_REPLACE"}]
        },
        "streamSettings": {
          "network": "grpc",
          "grpcSettings": {"serviceName": "grpc"}
        }
      }
G1
    }
  ],
  "outbounds": [
    {
      "protocol": "socks",
      "settings": { "servers": [ { "address": "127.0.0.1", "port": LOCAL_SOCKS_PORT_REPLACE } ] }
    }
  ]
}
XR
  sed -i "s/UUID_REPLACE/${UUID}/g" "${CONF_XR}"
  sed -i "s/LOCAL_SOCKS_PORT_REPLACE/${LOCAL_SOCKS_PORT}/g" "${CONF_XR}"
fi

# ============ Nginx 反代（禁用 QUIC，http2 on） ============
if [[ "${ON_GRPC,,}" == y || "${ON_WS,,}" == y ]]; then
  cat >/etc/nginx/sites-available/edgebox.conf <<NG
server {
    listen ${NGINX_TLS_PORT} ssl http2;
    server_name ${DOMAIN:-_};
    ssl_certificate ${CERT_FILE};
    ssl_certificate_key ${KEY_FILE};
    # 禁用 QUIC，避免占用 443/udp
    # (未显式写 quic; 若 nginx 全局有 http3_on，请确保关闭)
    location / {
        return 200 "ok\n";
        add_header Content-Type text/plain;
    }
    ${ON_WS,,} && cat <<'WSBLOC'
    location /ws {
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_pass http://127.0.0.1:10080;
    }
WSBLOC
    ${ON_GRPC,,} && cat <<'GRPCLOC'
    location /grpc {
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
        grpc_pass grpc://127.0.0.1:10085;
    }
GRPCLOC
}
NG
  ln -sf /etc/nginx/sites-available/edgebox.conf /etc/nginx/sites-enabled/edgebox.conf
  # 关闭可能的 http3/quic 指令
  sed -i 's/listen 443 .*quic;//g' /etc/nginx/nginx.conf || true
  nginx -t && systemctl restart nginx
fi

# ============ systemd ============
cat >/etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=sing-box unified service
After=network.target
Wants=network.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=3s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable sing-box
systemctl restart sing-box

if [[ "${ON_GRPC,,}" == y || "${ON_WS,,}" == y ]]; then
  systemctl enable xray
  systemctl restart xray
fi

# ============ 生成订阅（单链接） ============
mkdir -p "${SUB_DIR}"

HOST="${DOMAIN:-$(curl -s4 ifconfig.me)}"
HY2_HOST="${HOST}"
REAL_SNI="${HSNI}"

URLS=()

# VLESS-WS
if [[ "${ON_WS,,}" == y ]]; then
  URLS+=("vless://${UUID}@${HOST}:${NGINX_TLS_PORT}?type=ws&path=%2Fws&security=tls&sni=${HOST}&fp=chrome#VLESS-WS-${NGINX_TLS_PORT}")
fi

# VLESS-gRPC
if [[ "${ON_GRPC,,}" == y ]]; then
  URLS+=("vless://${UUID}@${HOST}:${NGINX_TLS_PORT}?type=grpc&serviceName=grpc&security=tls&sni=${HOST}&fp=chrome#VLESS-gRPC-${NGINX_TLS_PORT}")
fi

# Reality
if [[ "${ON_REALITY,,}" == y ]]; then
  URLS+=("vless://${UUID}@${HOST}:443?security=reality&encryption=none&flow=xtls-rprx-vision&type=tcp&pbk=${PUBK}&sid=${SID}&sni=${REAL_SNI}&fp=chrome#VLESS-Reality-443")
fi

# HY2
if [[ "${ON_HY2,,}" == y ]]; then
  URLS+=("hysteria2://u:${HY2_PASS}@${HY2_HOST}:${HY2PORT}?sni=${HOST}&insecure=1#HY2-${HY2PORT}")
fi

# TUIC
if [[ "${ON_TUIC,,}" == y ]]; then
  URLS+=("tuic://$UUID:${TUIC_PASS}@${HOST}:2053?congestion_control=bbr&alpn=h3&sni=${HOST}&insecure=1#TUIC-2053")
fi

printf "%s\n" "${URLS[@]}" > "${SUB_FILE}"

# 让 Nginx 作为订阅静态文件托管（若没启 Nginx，也给出 file:// 路径）
if [[ "${ON_GRPC,,}" == y || "${ON_WS,,}" == y ]]; then
  mkdir -p /var/www/html/sub
  ln -sf "${SUB_FILE}" "/var/www/html${SUB_URL_PATH}"
  SUB_LINK="https://${HOST}:${NGINX_TLS_PORT}${SUB_URL_PATH}"
else
  SUB_LINK="file://${SUB_FILE}"
fi

# ============ 生成 sing-box 客户端模板（含 urltest） ============
CLT_JSON="/var/lib/sb-sub/client_singbox_template.json"
jq -n --arg host "$HOST" --arg uuid "$UUID" --arg hy2 "$HY2_PASS" --arg pubk "$PUBK" --arg sid "$SID" --arg sni "$REAL_SNI" --arg port "$NGINX_TLS_PORT" --arg hy2p "$HY2PORT" '
{
  log:{level:"info"},
  dns:{servers:[{address:"https://dns.google/dns-query"}],strategy:"prefer_ipv4"},
  inbounds:[{type:"socks",listen:"127.0.0.1",listen_port:10808}],
  outbounds:[
    {tag:"grpc", type:"vless", server:$host, server_port:( $port|tonumber ),
      uuid:$uuid, flow:"none",
      tls:{enabled:true,server_name:$host,utls:{enabled:true,fingerprint:"chrome"}},
      transport:{type:"grpc",service_name:"grpc"}
    },
    {tag:"ws", type:"vless", server:$host, server_port:( $port|tonumber ),
      uuid:$uuid, flow:"none",
      tls:{enabled:true,server_name:$host,utls:{enabled:true,fingerprint:"chrome"}},
      transport:{type:"ws",path:"/ws"}
    },
    {tag:"reality", type:"vless", server:$host, server_port:443, uuid:$uuid, flow:"xtls-rprx-vision",
      tls:{enabled:true,server_name:$sni,reality:{enabled:true,public_key:$pubk,short_id:[$sid]},utls:{enabled:true,fingerprint:"chrome"}},
      transport:{type:"tcp"}
    },
    {tag:"hy2", type:"hysteria2", server:$host, server_port:( $hy2p|tonumber ),
      password:$hy2, tls:{enabled:true,server_name:$host,insecure:true}
    },
    {tag:"urltest", type:"urltest", outbounds:["hy2","grpc","ws","reality"],
      url:"https://www.gstatic.com/generate_204", interval:"10s", tolerance:50
    }
  ]
}' > "$CLT_JSON"

ce "================= 安装完成 ================="
echo "UUID:        ${UUID}"
echo "HY2 PASS:    ${HY2_PASS}"
echo "TUIC PASS:   ${TUIC_PASS}"
echo "Reality PBK: ${PUBK}"
echo "Reality SID: ${SID}"
echo
echo "订阅链接（一个就够）： ${SUB_LINK}"
echo "客户端模板（sing-box/NekoBox 可导入）： ${CLT_JSON}"
echo
echo "服务管理： systemctl status sing-box    | systemctl restart sing-box"
[[ "${ON_GRPC,,}" == y || "${ON_WS,,}" == y ]] && echo "            systemctl status xray        | systemctl restart xray"
echo
[[ "${ON_HY2,,}" == y ]] && echo "注意：HY2 域名需灰云直连；不要走 Cloudflare 橙云。"
[[ "${ON_GRPC,,}" == y || "${ON_WS,,}" == y ]] && echo "注意：gRPC/WS 由 Nginx 反代，证书为自签。客户端需 allowInsecure/跳过证书验证 或自行换成正规证书。"
[[ "${ON_REALITY,,}" == y ]] && echo "注意：Reality 与 443/tcp 站点互斥（本脚本遇冲突会把站点挪到 8443）。"
