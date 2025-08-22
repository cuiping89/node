#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# EdgeBox 五协议一体安装脚本（稳定版）
# 组件：
# - Nginx(8443/tcp)：TLS 终止 + 反代 VLESS-gRPC / VLESS-WS
# - Xray         ：承载 gRPC/WS (回环 127.0.0.1)
# - sing-box 1.12.2：承载 VLESS-Reality(443/tcp) + HY2(udp 443/8443) + TUIC(udp 2053)
# - 订阅输出：/var/lib/sb-sub/urls.txt （映射到 http://<域名或IP>/sub/urls.txt）
#
# 兼容性/健壮性：
# - Reality 密钥生成双路兜底：优先 sing-box generate，失败自动 xray x25519
# - ACME 失败自动回落自签证书（客户端需允许不安全证书）
# - UFW 端口按启用协议自动放行（不存在 UFW 不报错）
# - 所有 Nginx heredoc 已转义变量（\$xxx），避免 shell 抢先展开
#
# 作者提示：
# - 你可以多次重复执行本脚本；配置会覆盖更新，服务会平滑重启
# - 若需要卸载，使用我们配套的“无交互通用卸载脚本”即可
# =========================

# --------- 基础准备 ---------
need_cmd() { command -v "$1" >/dev/null 2>&1; }
run_quiet() { "$@" >/dev/null 2>&1 || true; }

if [[ $EUID -ne 0 ]]; then
  echo "请使用 root 运行。可先执行：sudo -i"
  exit 1
fi

echo "➤ 安装依赖..."
apt-get update -y >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl wget openssl jq unzip socat ufw nginx >/dev/null

mkdir -p /etc/sing-box /usr/local/etc/xray /var/lib/sb-sub /var/www/html/sub /etc/ssl/edgebox

# --------- 交互：协议/证书/分流 ---------
echo
read -r -p "输入访问域名（留空＝自签证书，可用公网 IP 访问订阅）： " DOMAIN || true
echo

yn_default() {  # $1 varname  $2 prompt  $3 default[y|n]
  local _v _p _d ; _v="$1"; _p="$2"; _d="$3"
  local defc="y" ; [[ "$_d" == "n" ]] && defc="n"
  read -r -p "${_p} [y/n]（默认：${defc}）： " ans || true
  if [[ -z "${ans:-}" ]]; then ans="$defc"; fi
  printf -v "$_v" "%s" "$ans"
}

yn_default EN_GRPC   "启用 VLESS-gRPC（8443/tcp，经 Nginx）：" y
yn_default EN_WS     "启用 VLESS-WS（8443/tcp，经 Nginx）："     y
yn_default EN_REAL   "启用 VLESS-Reality（443/tcp）："            y
yn_default EN_HY2    "启用 Hysteria2（udp 443 或 8443）："        y
yn_default EN_TUIC   "启用 TUIC（udp 2053）："                    n

HY2_PORT="443"
if [[ "$EN_HY2" == "y" ]]; then
  read -r -p "HY2 端口（443/8443，默认：443）： " HY2_PORT || true
  [[ -z "${HY2_PORT:-}" ]] && HY2_PORT="443"
  [[ "${HY2_PORT}" != "443" && "${HY2_PORT}" != "8443" ]] && HY2_PORT="443"
fi

echo
echo "分流策略："
echo "  1) 全部直出（direct）"
echo "  2) 绝大多数走住宅 HTTP 代理，仅 googlevideo/ytimg/ggpht 直出"
read -r -p "选择（1/2，默认：1）： " ROUTE_MODE || true
[[ -z "${ROUTE_MODE:-}" ]] && ROUTE_MODE="1"

HOME_HOST=""; HOME_PORT=""; HOME_USER=""; HOME_PASS=""
if [[ "$ROUTE_MODE" == "2" ]]; then
  read -r -p "住宅 HTTP 代理 host/IP（必填）： " HOME_HOST
  read -r -p "住宅 HTTP 代理 port（必填）： "    HOME_PORT
  read -r -p "住宅 HTTP 代理 用户名（可空）： "  HOME_USER || true
  read -r -p "住宅 HTTP 代理 密码（可空）： "    HOME_PASS || true
  if [[ -z "$HOME_HOST" || -z "$HOME_PORT" ]]; then
    echo "[WARN] 住宅代理信息不完整，回退为：全部直出"
    ROUTE_MODE="1"
  fi
fi

# --------- 安装 Xray（仅做 gRPC/WS） ---------
echo "➤ 安装 Xray..."
bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null
systemctl enable --now xray >/dev/null 2>&1 || true

# --------- 安装 sing-box v1.12.2 （固定稳定版）---------
echo "➤ 安装 sing-box v1.12.2..."
SB_VER="1.12.2"
SB_FILE="sing-box-${SB_VER}-linux-amd64.tar.gz"
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/${SB_FILE}"
TMPD="$(mktemp -d)"
curl -fL "$SB_URL" -o "${TMPD}/${SB_FILE}"
tar -xzf "${TMPD}/${SB_FILE}" -C "${TMPD}"
install -m 0755 "${TMPD}/sing-box-${SB_VER}-linux-amd64/sing-box" /usr/local/bin/sing-box
rm -rf "$TMPD"
echo "[OK] sing-box 版本：$(sing-box version | head -n1)"

# --------- 统一生成随机参数 ----------
UUID_ALL="$(cat /proc/sys/kernel/random/uuid)"
SID="$(openssl rand -hex 4)"                 # Reality 短 ID
WS_PATH="/$(openssl rand -hex 3)"
GRPC_SVC="@grpc"                              # gRPC serviceName
HY2_PWD="$(openssl rand -hex 12)"
TUIC_UUID="$(cat /proc/sys/kernel/random/uuid)"
TUIC_PWD="$(openssl rand -hex 12)"
SNI="www.cloudflare.com"                      # Reality 伪装域名

# --------- 证书准备（ACME→自签兜底）---------
CRT="/etc/ssl/edgebox/fullchain.crt"
KEY="/etc/ssl/edgebox/private.key"

issue_self_signed() {
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$KEY" -out "$CRT" -subj "/CN=${DOMAIN:-edgebox.local}" >/dev/null 2>&1
}

if [[ -n "${DOMAIN:-}" ]]; then
  echo "➤ 申请 ACME 证书（${DOMAIN}）..."
  # 临时开放 80 端口（如有 UFW）
  run_quiet ufw allow 80/tcp
  # 安装/更新 acme.sh
  if ! need_cmd ~/.acme.sh/acme.sh; then
    curl -fsSL https://get.acme.sh | sh -s email=admin@${DOMAIN} >/dev/null 2>&1 || true
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" --keylength ec-256 >/dev/null 2>&1; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
      --ecc --fullchain-file "$CRT" --key-file "$KEY" >/dev/null 2>&1 || issue_self_signed
  else
    echo "[WARN] ACME 失败，回退自签证书"
    issue_self_signed
  fi
else
  echo "➤ 生成自签证书（未填写域名）..."
  issue_self_signed
fi

# --------- Reality 密钥对（双路兜底）---------
have_sb_reality() { sing-box version 2>/dev/null | grep -qi 'with_reality'; }
gen_sb_keys() { have_sb_reality && sing-box generate reality-keypair 2>/dev/null || true; }

# 一次解析私钥+公钥
read PRIV PBK < <(gen_sb_keys | awk -F': *' '/Private/{priv=$2}/Public/{print priv,$2}')
if [[ -z "${PRIV:-}" || -z "${PBK:-}" ]]; then
  read PRIV PBK < <(xray x25519 2>/dev/null | awk -F': *' '/Private/{priv=$2}/Public/{print priv,$2}')
fi
if [[ -z "${PRIV:-}" || -z "${PBK:-}" ]]; then
  echo "[FATAL] Reality 密钥生成失败（sing-box 与 xray 均不可用）"; exit 1
fi
echo "[OK] Reality 公钥：$PBK"

# --------- Xray 配置（仅 gRPC/WS on loopback）---------
XRAY_CFG="/usr/local/etc/xray/config.json"
cat >"$XRAY_CFG" <<JSON
{
  "inbounds": [
    ${
      [[ "$EN_GRPC" == "y" ]] && cat <<'G' | sed "s/@UUID@/${UUID_ALL}/g"
      {
        "listen": "127.0.0.1",
        "port": 11800,
        "protocol": "vless",
        "settings": { "clients": [{ "id": "@UUID@" }], "decryption": "none" },
        "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "@grpc" } }
      }G
    }
    ${
      [[ "$EN_GRPC" == "y" && "$EN_WS" == "y" ]] && echo ','
    }
    ${
      [[ "$EN_WS" == "y" ]] && cat <<'W' | sed -e "s/@UUID@/${UUID_ALL}/g" -e "s#@PATH@#${WS_PATH}#g" -e "s/@HOST@/${DOMAIN:-localhost}/g"
      {
        "listen": "127.0.0.1",
        "port": 11801,
        "protocol": "vless",
        "settings": { "clients": [{ "id": "@UUID@" }], "decryption": "none" },
        "streamSettings": {
          "network": "ws",
          "wsSettings": { "path": "@PATH@", "headers": { "Host": "@HOST@" } }
        }
      }W
    }
  ],
  "outbounds": [{ "protocol": "freedom" }]
}
JSON

systemctl restart xray

# --------- Nginx 8443 反代（gRPC + WS）---------
NGX="/etc/nginx/conf.d/edgebox.conf"
cat >"$NGX" <<NGINX
server {
  listen 8443 ssl http2;
  server_name ${DOMAIN:-_};

  ssl_certificate     ${CRT};
  ssl_certificate_key ${KEY};

  # gRPC
  location /${GRPC_SVC} {
    grpc_set_header X-Real-IP \$remote_addr;
    grpc_pass grpc://127.0.0.1:11800;
  }

  # WebSocket
  location ${WS_PATH} {
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_pass http://127.0.0.1:11801;
  }
}
NGINX

nginx -t
systemctl reload nginx

# --------- sing-box 配置（Reality / HY2 / TUIC + 路由）---------
SB_CFG="/etc/sing-box/config.json"

# 路由与出站
ROUTE_JSON='"final":"direct"'
HOME_OB=""

if [[ "$ROUTE_MODE" == "2" ]]; then
  HOME_OB=$(jq -n --arg h "$HOME_HOST" --argjson p "$HOME_PORT" \
               --arg u "$HOME_USER" --arg pw "$HOME_PASS" '{
      "type":"http","tag":"home_http",
      "server":$h,"server_port":($p|tonumber),
      "username": ( ($u|length)>0 ? $u : null ),
      "password": ( ($pw|length)>0 ? $pw : null )
    }')
  ROUTE_JSON='"rules":[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"}],"final":"home_http"'
fi

# inbounds 组装
IN_ARR=()

if [[ "$EN_REAL" == "y" ]]; then
  IN_ARR+=("{
    \"type\":\"vless\",\"tag\":\"vless-reality\",\"listen\":\"::\",\"listen_port\":443,
    \"users\":[{\"uuid\":\"${UUID_ALL}\",\"flow\":\"xtls-rprx-vision\"}],
    \"tls\":{
      \"enabled\":true,
      \"server_name\":\"${SNI}\",
      \"reality\":{
        \"enabled\":true,
        \"private_key\":\"${PRIV}\",
        \"short_id\":[\"${SID}\"],
        \"handshake\":{\"server\":\"${SNI}\",\"server_port\":443}
      }
    }
  }")
fi

if [[ "$EN_HY2" == "y" ]]; then
  IN_ARR+=("{
    \"type\":\"hysteria2\",\"tag\":\"hy2\",\"listen\":\"::\",\"listen_port\":${HY2_PORT},
    \"users\":[{\"password\":\"${HY2_PWD}\"}],
    \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
  }")
fi

if [[ "$EN_TUIC" == "y" ]]; then
  IN_ARR+=("{
    \"type\":\"tuic\",\"tag\":\"tuic\",\"listen\":\"::\",\"listen_port\":2053,
    \"users\":[{\"uuid\":\"${TUIC_UUID}\",\"password\":\"${TUIC_PWD}\"}],
    \"congestion_control\":\"bbr\",
    \"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"${CRT}\",\"key_path\":\"${KEY}\"}
  }")
fi

# outbounds 组装
OB_ARR=()
OB_ARR+=('{"type":"direct","tag":"direct"}')
if [[ -n "$HOME_OB" ]]; then OB_ARR+=("$HOME_OB"); fi
OB_ARR+=('{"type":"block","tag":"block"}')

# 写入 sing-box 配置
jq -n --argjson in "[$(IFS=,; echo "${IN_ARR[*]-[]}")]" \
      --argjson ob "[$(IFS=,; echo "${OB_ARR[*]}")]" \
      --argjson route "{${ROUTE_JSON}}" \
      '{log: {level:"info"}, inbounds:$in, outbounds:$ob, route:$route}' | \
  tee "$SB_CFG" >/dev/null

# systemd 单元
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

# --------- UFW 端口放行（静默，不存在即跳过）---------
run_quiet ufw allow 8443/tcp
[[ "$EN_REAL" == "y" ]] && run_quiet ufw allow 443/tcp
[[ "$EN_HY2"  == "y" ]] && run_quiet ufw allow "${HY2_PORT}"/udp
[[ "$EN_TUIC" == "y" ]] && run_quiet ufw allow 2053/udp
run_quiet ufw reload

# --------- 生成聚合订阅 ---------
HOST="${DOMAIN:-$(curl -fsS https://api.ipify.org || hostname -I | awk '{print $1}')}"
SUB="/var/lib/sb-sub/urls.txt"
: >"$SUB"

# gRPC
if [[ "$EN_GRPC" == "y" ]]; then
  printf "vless://%s@%s:8443?encryption=none&security=tls&type=grpc&serviceName=%s&fp=chrome#VLESS-gRPC@%s\n" \
    "$UUID_ALL" "$HOST" "$GRPC_SVC" "$HOST" >>"$SUB"
fi
# WS
if [[ "$EN_WS" == "y" ]]; then
  printf "vless://%s@%s:8443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n" \
    "$UUID_ALL" "$HOST" "$WS_PATH" "$HOST" "$HOST" >>"$SUB"
fi
# Reality
if [[ "$EN_REAL" == "y" ]]; then
  printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" \
    "$UUID_ALL" "$HOST" "$SNI" "$PBK" "$SID" "$HOST" >>"$SUB"
fi
# HY2
if [[ "$EN_HY2" == "y" ]]; then
  printf "hysteria2://%s@%s:%s?alpn=h3#HY2@%s\n" \
    "$HY2_PWD" "$HOST" "$HY2_PORT" "$HOST" >>"$SUB"
fi
# TUIC
if [[ "$EN_TUIC" == "y" ]]; then
  printf "tuic://%s:%s@%s:%s?congestion=bbr&alpn=h3#TUIC@%s\n" \
    "$TUIC_UUID" "$TUIC_PWD" "$HOST" "2053" "$HOST" >>"$SUB"
fi

ln -sf "$SUB" /var/www/html/sub/urls.txt

# --------- 汇总输出 ---------
echo
echo "================ 安装完成 ================"
echo "订阅链接（可导入 v2rayN / Clash 等）： http://${HOST}/sub/urls.txt"
echo "注意：若使用自签证书，客户端需开启“跳过证书验证/allowInsecure”。"
echo
echo "正在查看端口："
ss -lnptu | egrep ':443|:8443|:2053' || true
echo
echo "[服务状态（节选）]"
systemctl status nginx --no-pager -l | sed -n '1,20p'
echo "----"
systemctl status xray  --no-pager -l | sed -n '1,20p'
echo "----"
systemctl status sing-box --no-pager -l | sed -n '1,20p'
echo "=========================================="
