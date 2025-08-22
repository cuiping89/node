#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo; echo "[ERROR] 第 $LINENO 行命令失败：${BASH_COMMAND}"; exit 1' ERR

# ---------- 基础工具 ----------
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget unzip jq openssl ufw nginx socat

# ---------- 变量/函数 ----------
WORK=/root/edgebox
SB_DIR=/etc/sing-box
XR_DIR=/usr/local/etc/xray
SUB_DIR=/var/lib/sb-sub
WEB_ROOT=/var/www/html
CERT_DIR=/etc/ssl/edgebox
mkdir -p "$WORK" "$SB_DIR" "$XR_DIR" "$SUB_DIR" "$WEB_ROOT/sub" "$CERT_DIR"

_color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
ok() { _color "32;1" "[OK] $1"; echo; }
warn() { _color "33;1" "[WARN] $1"; echo; }
info() { _color "36;1" "[INFO] $1"; echo; }

# 读入：有默认值时回车取默认
ask() {
  # $1: 变量名  $2: 提示  $3: 默认
  local __var="$1" __tip="$2" __def="${3-}"
  if [[ -n "$__def" ]]; then
    read -r -p "$__tip（默认：$__def）： " __ans || true
    printf -v "$__var" "%s" "${__ans:-$__def}"
  else
    read -r -p "$__tip： " __ans || true
    printf -v "$__var" "%s" "$__ans"
  fi
}

# yes/no（y/n），默认 y
ask_yn() {
  local __var="$1" __tip="$2" __def="${3-y}"
  read -r -p "$__tip [y/n]（默认：$__def）： " __ans || true
  __ans="${__ans:-$__def}"
  case "${__ans,,}" in y|yes) printf -v "$__var" "y";; *) printf -v "$__var" "n";; esac
}

# 生成随机量
uuid()  { cat /proc/sys/kernel/random/uuid; }
hex8()  { openssl rand -hex 4; }             # 8位短ID
rand12(){ openssl rand -hex 12; }
randpath(){ echo "/$(openssl rand -hex 3)"; }

# 公网IP（订阅回退用）
PUB_IP="$(curl -fsS --max-time 5 https://api.ipify.org || true)"
[[ -z "$PUB_IP" ]] && PUB_IP="$(curl -fsS --max-time 5 http://ipv4.icanhazip.com || true)"
[[ -z "$PUB_IP" ]] && PUB_IP="$(hostname -I | awk '{print $1}')"

# ---------- 交互 ----------
echo
info "协议/证书/分流 交互配置"

ask DOMAIN "输入域名（留空=使用自签证书，可用 IP 访问订阅）" ""
ask_yn EN_GRPC "启用 VLESS-gRPC(8443/tcp，经 Nginx)？" y
ask_yn EN_WS   "启用 VLESS-WS(8443/tcp，经 Nginx)？" y
ask_yn EN_VR   "启用 VLESS-Reality(443/tcp)？" y
ask_yn EN_HY2  "启用 Hysteria2(udp 443 或 8443)？" y
ask_yn EN_TUIC "启用 TUIC(udp 2053)？" n

HY2_PORT=443
if [[ "$EN_HY2" == "y" ]]; then
  read -r -p "HY2 端口（443/8443，默认：443）： " _p || true
  [[ -n "${_p:-}" ]] && HY2_PORT="${_p}"
fi

echo
echo "分流策略："
echo "1) 全部直出（direct）"
echo "2) 绝大多数走住宅HTTP代理，仅 googlevideo/ytimg/ggpht 直出"
ask MODE "选择（1/2）" "1"
HOME_HOST=""; HOME_PORT=""; HOME_USER=""; HOME_PASS=""
if [[ "$MODE" == "2" ]]; then
  ask HOME_HOST "住宅HTTP代理 host/IP" ""
  ask HOME_PORT "住宅HTTP代理 port" ""
  ask HOME_USER "住宅HTTP代理 用户名（可空）" ""
  ask HOME_PASS "住宅HTTP代理 密码（可空）" ""
  # 如未填完整 host/port，则回退为直出
  if [[ -z "$HOME_HOST" || -z "$HOME_PORT" ]]; then
    warn "未提供完整 HTTP 代理信息，自动回退为【全部直出】"
    MODE="1"
  fi
fi

# ---------- 安装内核优化 & 2GB swap ----------
if ! sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
  cat >/etc/sysctl.d/99-bbr-fq.conf <<'SYS'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
SYS
  sysctl --system >/dev/null 2>&1 || true
  ok "已应用 BBR + fq"
fi

if ! swapon --show | grep -q ^; then
  fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >>/etc/fstab
  ok "已创建 2GB swap"
fi

# ---------- 安装 Xray ----------
info "安装 Xray..."
bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null
systemctl enable --now xray

# ---------- 安装 sing-box v1.12.2 ----------
info "安装 sing-box v1.12.2..."
SB_VER=v1.12.2
ARCH=amd64
URL="https://github.com/SagerNet/sing-box/releases/download/${SB_VER}/sing-box-$(echo ${SB_VER} | tr -d v)-linux-${ARCH}.tar.gz"
TMP=$(mktemp -d)
curl -fsSL "$URL" | tar -xz -C "$TMP"
install -m 0755 "$TMP"/sing-box*/sing-box /usr/local/bin/sing-box
rm -rf "$TMP"
ok "$(sing-box version || true)"

# ---------- 生成密钥/ID ----------
UUID_ALL="$(uuid)"                 # 给 WS/gRPC/VLESS/Reality 共用
SID="$(hex8)"                      # Reality 短ID
SNI="www.cloudflare.com"           # Reality 伪装域名
WS_PATH="$(randpath)"
HY2_PWD="$(rand12)"
TUIC_UUID="$(uuid)"
TUIC_PWD="$(rand12)"

# Reality 密钥对
PRIV="$(sing-box generate reality-keypair | awk '/Private key/ {print $3}')"
PBK="$( sing-box generate reality-keypair | awk '/Public key/  {print $3}')"  # 生成两次避免并发读
# 若第二次没取到，则再取一次完整对
if [[ -z "$PRIV" || -z "$PBK" ]]; then
  read -r PRIV PBK < <(sing-box generate reality-keypair | awk '/Private/{p=$3}/Public/{print p,$3}')
fi
[[ -z "$PRIV" || -z "$PBK" ]] && { echo "[ERROR] Reality 密钥生成失败"; exit 1; }

# ---------- 准备证书 ----------
install -d "$CERT_DIR"
if [[ -n "${DOMAIN:-}" ]]; then
  info "尝试为 ${DOMAIN} 申请 ACME 证书（失败将回退自签）..."
  curl -fsSL https://get.acme.sh | sh -s email=admin@$DOMAIN >/dev/null 2>&1 || true
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if ~/.acme.sh/acme.sh --issue --nginx -d "$DOMAIN" --keylength ec-256 >/dev/null 2>&1; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
      --key-file       "$CERT_DIR/private.key" \
      --fullchain-file "$CERT_DIR/fullchain.crt" \
      --reloadcmd      "systemctl reload nginx" >/dev/null 2>&1 || true
    ok "ACME 成功"
  else
    warn "ACME 失败，使用自签证书（客户端需 Skip Verify）"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout "$CERT_DIR/private.key" -out "$CERT_DIR/fullchain.crt" \
      -subj "/CN=$DOMAIN" >/dev/null 2>&1
  fi
else
  warn "未提供域名，使用自签证书（客户端需 Skip Verify）"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$CERT_DIR/private.key" -out "$CERT_DIR/fullchain.crt" \
    -subj "/CN=$PUB_IP" >/dev/null 2>&1
fi

# ---------- Nginx 反代（仅 gRPC/WS 需要） ----------
if [[ "$EN_GRPC" == "y" || "$EN_WS" == "y" ]]; then
  cat >/etc/nginx/conf.d/edgebox.conf <<'NG'
# generated by edgebox
server {
    listen 8443 ssl http2;
    server_name _;

    ssl_certificate     /etc/ssl/edgebox/fullchain.crt;
    ssl_certificate_key /etc/ssl/edgebox/private.key;

    # gRPC 转发到本机 10085
    # （按需启用：安装脚本会替换开关）
}
NG

  # 动态追加 location（用单引号 heredoc 防止 $http_upgrade 被 shell 展开）
  if [[ "$EN_GRPC" == "y" ]]; then
    cat >>/etc/nginx/conf.d/edgebox.conf <<'NG'
    location /@grpc {
        grpc_pass grpc://127.0.0.1:10085;
        client_max_body_size 0;
        grpc_read_timeout 7d;
        grpc_send_timeout 7d;
    }
NG
  fi

  if [[ "$EN_WS" == "y" ]]; then
    cat >>/etc/nginx/conf.d/edgebox.conf <<NG
    location ${WS_PATH} {
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_pass http://127.0.0.1:10086;
    }
NG
  fi

  echo "}" >>/etc/nginx/conf.d/edgebox.conf

  nginx -t
  systemctl reload nginx || systemctl restart nginx
fi

# ---------- Xray 配置（gRPC/WS） ----------
XR_INS=()
if [[ "$EN_GRPC" == "y" ]]; then
  XR_INS+=("{
    \"listen\": \"127.0.0.1\",
    \"port\": 10085,
    \"protocol\": \"vless\",
    \"settings\": {\"clients\":[{\"id\":\"$UUID_ALL\",\"level\":0}]},
    \"streamSettings\": {\"network\":\"grpc\",\"grpcSettings\":{\"serviceName\":\"@grpc\"}},
    \"tag\":\"vless-grpc-in\"
  }")
fi
if [[ "$EN_WS" == "y" ]]; then
  XR_INS+=("{
    \"listen\": \"127.0.0.1\",
    \"port\": 10086,
    \"protocol\": \"vless\",
    \"settings\": {\"clients\":[{\"id\":\"$UUID_ALL\",\"level\":0}]},
    \"streamSettings\": {\"network\":\"ws\",\"wsSettings\":{\"path\":\"$WS_PATH\",\"headers\":{\"Host\":\"${DOMAIN:-$PUB_IP}\"}}},
    \"tag\":\"vless-ws-in\"
  }")
fi
XR_JSON_IN="$(IFS=,; echo "${XR_INS[*]-}")"

cat >"$XR_DIR/config.json" <<XR
{
  "log": {"loglevel": "warning"},
  "inbounds": [ $XR_JSON_IN ],
  "outbounds": [
    {"protocol":"freedom","tag":"direct"},
    {"protocol":"blackhole","tag":"block"}
  ]
}
XR

jq . "$XR_DIR/config.json" >/dev/null
systemctl enable --now xray

# ---------- sing-box 配置（Reality/HY2/TUIC + 分流） ----------
SB_INS=()

if [[ "$EN_VR" == "y" ]]; then
  SB_INS+=("{
    \"type\": \"vless\",
    \"listen\": \"::\",
    \"listen_port\": 443,
    \"users\": [{\"uuid\": \"$UUID_ALL\", \"flow\": \"xtls-rprx-vision\"}],
    \"tls\": {
      \"enabled\": true,
      \"server_name\": \"$SNI\",
      \"reality\": {
        \"enabled\": true,
        \"private_key\": \"$PRIV\",
        \"short_id\": [\"$SID\"],
        \"handshake\": {\"server\":\"$SNI\",\"server_port\":443}
      }
    },
    \"tag\": \"vless-reality-in\"
  }")
fi

if [[ "$EN_HY2" == "y" ]]; then
  SB_INS+=("{
    \"type\": \"hysteria2\",
    \"listen\": \"::\",
    \"listen_port\": $HY2_PORT,
    \"users\": [{\"password\": \"$HY2_PWD\"}],
    \"tls\": {
      \"enabled\": true,
      \"alpn\": [\"h3\"],
      \"certificate_path\": \"$CERT_DIR/fullchain.crt\",
      \"key_path\": \"$CERT_DIR/private.key\"
    },
    \"tag\": \"hy2-in\"
  }")
fi

if [[ "$EN_TUIC" == "y" ]]; then
  SB_INS+=("{
    \"type\": \"tuic\",
    \"listen\": \"::\",
    \"listen_port\": 2053,
    \"users\": [{\"uuid\":\"$TUIC_UUID\",\"password\":\"$TUIC_PWD\"}],
    \"congestion_control\": \"bbr\",
    \"tls\": {
      \"enabled\": true,
      \"alpn\": [\"h3\"],
      \"certificate_path\": \"$CERT_DIR/fullchain.crt\",
      \"key_path\": \"$CERT_DIR/private.key\"
    },
    \"tag\": \"tuic-in\"
  }")
fi

SB_JSON_IN="$(IFS=,; echo "${SB_INS[*]-}")"

# 出口与分流
SB_OUTS=(
  "{\"type\":\"direct\",\"tag\":\"direct\"}"
  "{\"type\":\"block\",\"tag\":\"block\"}"
)

FINAL_TAG="direct"
if [[ "$MODE" == "2" ]]; then
  # 可选用户名/密码项：仅在非空时写入
  EXTRA=""
  [[ -n "$HOME_USER" ]] && EXTRA="$EXTRA, \"username\":\"$HOME_USER\""
  [[ -n "$HOME_PASS" ]] && EXTRA="$EXTRA, \"password\":\"$HOME_PASS\""
  SB_OUTS+=("{\"type\":\"http\",\"tag\":\"home_http\",\"server\":\"$HOME_HOST\",\"server_port\":$HOME_PORT$EXTRA}")
  FINAL_TAG="home_http"
fi
SB_JSON_OUT="$(IFS=,; echo "${SB_OUTS[*]}")"

# 分流规则：googlevideo/ytimg/ggpht 直出
SB_ROUTE=$(cat <<ROUTE
{
  "rules": [
    {"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"], "outbound":"direct"}
  ],
  "final": "$FINAL_TAG",
  "auto_detect_interface": true
}
ROUTE
)

cat >"$SB_DIR/config.json" <<SB
{
  "log": {"level":"info"},
  "inbounds": [ $SB_JSON_IN ],
  "outbounds": [ $SB_JSON_OUT ],
  "route": $SB_ROUTE
}
SB

jq . "$SB_DIR/config.json" >/dev/null

# systemd for sing-box
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

# ---------- 订阅生成 ----------
SUB_FILE="$SUB_DIR/urls.txt"
SUB_HOST="${DOMAIN:-$PUB_IP}"
: >"$SUB_FILE"

if [[ "$EN_GRPC" == "y" ]]; then
  printf "vless://%s@%s:8443?encryption=none&security=tls&type=grpc&serviceName=@grpc&fp=chrome#VLESS-gRPC@%s\n" \
    "$UUID_ALL" "$SUB_HOST" "$SUB_HOST" >>"$SUB_FILE"
fi
if [[ "$EN_WS" == "y" ]]; then
  printf "vless://%s@%s:8443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n" \
    "$UUID_ALL" "$SUB_HOST" "$WS_PATH" "$SUB_HOST" "$SUB_HOST" >>"$SUB_FILE"
fi
if [[ "$EN_VR" == "y" ]]; then
  printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" \
    "$UUID_ALL" "$SUB_HOST" "$SNI" "$PBK" "$SID" "$SUB_HOST" >>"$SUB_FILE"
fi
if [[ "$EN_HY2" == "y" ]]; then
  printf "hysteria2://%s@%s:%s?alpn=h3#HY2@%s\n" \
    "$HY2_PWD" "$SUB_HOST" "$HY2_PORT" "$SUB_HOST" >>"$SUB_FILE"
fi
if [[ "$EN_TUIC" == "y" ]]; then
  printf "tuic://%s:%s@%s:%s?congestion=bbr&alpn=h3#TUIC@%s\n" \
    "$TUIC_UUID" "$TUIC_PWD" "$SUB_HOST" "2053" "$SUB_HOST" >>"$SUB_FILE"
fi

ln -sf "$SUB_FILE" "$WEB_ROOT/sub/urls.txt"

# ---------- UFW （本机） ----------
ufw allow 8443/tcp >/dev/null 2>&1 || true
[[ "$EN_VR" == "y" ]]  && ufw allow 443/tcp  >/dev/null 2>&1 || true
[[ "$EN_HY2" == "y" ]] && ufw allow ${HY2_PORT}/udp >/dev/null 2>&1 || true
[[ "$EN_TUIC" == "y" ]] && ufw allow 2053/udp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true

echo
ok "安装完成"
echo "订阅链接：$(_color 36;1)http${DOMAIN:+s}://${SUB_HOST}/sub/urls.txt$(_color 0 "")"
echo
echo "当前监听端口（示例）："
ss -lntup | egrep ':443|:8443|:2053' || true

echo
warn "请同时确认云厂商（GCP/阿里云等）的安全组也已放行相应端口。"
