#!/usr/bin/env bash
# Five-in-one node installer: VLESS-gRPC / VLESS-WS(+TLS) / VLESS-Reality / Hysteria2 / TUIC
# Author: you & ChatGPT
# Tested on: Ubuntu 20.04/22.04/24.04 LTS (amd64)
# ---------------------------------------------------------------------------------------

set -euo pipefail

# ====== 可调版本 ======
SBOX_VER="${SBOX_VER:-1.8.10}"     # sing-box 采用稳定可用的 1.8.x 系列
XRAY_INSTALL_SH="${XRAY_INSTALL_SH:-https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh}"

# ====== 颜色 ======
c_green='\033[0;32m'; c_yellow='\033[0;33m'; c_red='\033[0;31m'; c_end='\033[0m'

log()   { echo -e "${c_green}[OK]${c_end} $*"; }
warn()  { echo -e "${c_yellow}[WARN]${c_end} $*"; }
err()   { echo -e "${c_red}[ERR]${c_end} $*" >&2; }
askyn() { local p="$1"; local d="${2:-y}"; read -rp "$p [$d/N]: " a; a="${a:-$d}"; [[ "${a,,}" == y ]]; }

need_root() { [[ "$(id -u)" -eq 0 ]] || { err "请用 root 运行"; exit 1; }; }

# ====== 环境准备 ======
prep_env() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    curl wget jq unzip tar ufw nginx openssl ca-certificates moreutils \
    xz-utils iproute2 net-tools
  log "依赖安装完成"

  # BBR + fq
  if ! sysctl net.ipv4.tcp_congestion_control | grep -qi bbr; then
    cat >/etc/sysctl.d/99-bbr-fq.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system >/dev/null || true
    log "已开启 BBR + fq"
  else
    log "BBR + fq 已启用"
  fi

  # 2G swap
  if ! swapon --show | grep -q 'swapfile'; then
    fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
    chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    log "已创建 2G swap"
  else
    log "swap 已存在"
  fi

  mkdir -p /etc/sing-box /etc/xray /var/lib/sb-sub /var/www/html/sub
  touch /var/lib/sb-sub/urls.txt
  ln -sf /var/lib/sb-sub/urls.txt /var/www/html/sub/urls.txt
}

# ====== 交互项 ======
ask_inputs() {
  echo
  echo -e "${c_green}=== 协议启用选择（Y=启用 / 回车默认） ===${c_end}"
  ON_GRPC=$(askyn "启用 VLESS-gRPC(443/tcp)?" y && echo y || echo n)
  ON_WS=$(askyn   "启用 VLESS-WS(+TLS)?" y && echo y || echo n)
  ON_REA=$(askyn  "启用 VLESS-Reality(443/tcp)?" y && echo y || echo n)
  ON_HY2=$(askyn  "启用 Hysteria2(udp:443 或 8443)?" y && echo y || echo n)
  ON_TUIC=$(askyn "启用 TUIC(udp:2053)?" y && echo y || echo n)

  # gRPC/WS 所需域名（可留空＝生成自签）
  DOMAIN=""
  if [[ "$ON_GRPC" == y || "$ON_WS" == y ]]; then
    read -rp "用于 gRPC/WS 的域名(建议灰云指向本机IP；留空=使用自签证书): " DOMAIN
    DOMAIN="${DOMAIN,,}"
  fi

  # HY2 端口
  HY2PORT=443
  if [[ "$ON_HY2" == y ]]; then
    read -rp "HY2 端口(443/8443，默认443): " t; HY2PORT="${t:-443}"
    [[ "$HY2PORT" =~ ^(443|8443)$ ]] || { err "HY2 端口仅支持 443/8443"; exit 1; }
  fi

  # 出口分流
  echo
  echo -e "${c_green}=== 出口分流策略 ===${c_end}"
  echo "  1) 全部直出 VPS (direct)"
  echo "  2) 走你的静态住宅 HTTP 代理(仅 googlevideo/ytimg/ggpht/gstatic/googleusercontent 直出)"
  read -rp "选择(1/2，默认1): " OUT
  OUT="${OUT:-1}"
  if [[ "$OUT" == 2 ]]; then
    read -rp "住宅 HTTP 代理地址(host): " RHOST
    read -rp "住宅 HTTP 代理端口(port): " RPORT
    read -rp "住宅 HTTP 代理用户名(可空): " RUSER
    read -rp "住宅 HTTP 代理密码(可空): " RPASS
  fi

  # UUID / 密码
  UUID="$(cat /proc/sys/kernel/random/uuid)"
  HY2_PASS="$(openssl rand -base64 12 | tr -d '=+/')"
  TUIC_PWD="$(openssl rand -hex 8)"
  SNI_REA="www.cloudflare.com"   # Reality 伪装 SNI
  # 证书位置（WS/gRPC/HY2/TUIC 共用）
  CERT_FILE="/etc/ssl/certs/edgebox.crt"
  KEY_FILE="/etc/ssl/private/edgebox.key"

  # 443 冲突：Reality 使用 443/tcp；若同时开 gRPC/WS 就把站点迁到 8443
  NGINX_TLS_PORT=443
  if [[ "$ON_REA" == y && ( "$ON_GRPC" == y || "$ON_WS" == y ) ]]; then
    NGINX_TLS_PORT=8443
    warn "Reality 与 gRPC/WS 端口冲突：将自动把 Nginx 的 gRPC/WS 迁到 ${NGINX_TLS_PORT}"
  fi

  # tuic 端口
  TUIC_PORT=2053
}

# ====== 安装二进制 ======
install_singbox() {
  local url="https://github.com/SagerNet/sing-box/releases/download/v${SBOX_VER}/sing-box-${SBOX_VER}-linux-amd64.tar.gz"
  rm -rf /tmp/sb.tgz /tmp/sb
  if ! curl -fsSL -o /tmp/sb.tgz "$url"; then
    warn "下载 v${SBOX_VER} 失败，尝试最新版本"
    local latest
    latest="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name | sed 's/^v//')"
    curl -fsSL -o /tmp/sb.tgz "https://github.com/SagerNet/sing-box/releases/download/v${latest}/sing-box-${latest}-linux-amd64.tar.gz"
  fi
  mkdir -p /tmp/sb && tar -xzf /tmp/sb.tgz -C /tmp/sb
  install -m 0755 /tmp/sb/sing-box*/sing-box /usr/local/bin/sing-box
  log "sing-box 已安装：$(/usr/local/bin/sing-box version || true)"
}

install_xray() {
  bash <(curl -fsSL "$XRAY_INSTALL_SH") >/dev/null 2>&1 || true
  if ! command -v xray >/dev/null 2>&1; then
    err "Xray 安装失败，请检查网络后重试"
    exit 1
  fi
  log "Xray 已安装：$(xray -version | head -n1)"
}

# ====== 证书（若 DOMAIN 为空则自签） ======
gen_cert() {
  if [[ -n "${DOMAIN}" ]]; then
    # 简化：仍然生成自签（如需要可自行换成 ACME）
    warn "未自动申请 ACME，临时用自签证书（客户端需 allowInsecure）"
  fi
  mkdir -p /etc/ssl/private /etc/ssl/certs
  if [[ ! -s "$CERT_FILE" || ! -s "$KEY_FILE" ]]; then
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 36500 -nodes \
      -subj "/CN=${DOMAIN:-localhost}"
    log "自签证书生成完成"
  fi
}

# ====== Nginx（按需） ======
make_nginx() {
  if [[ "$ON_GRPC" == y || "$ON_WS" == y ]]; then
    cat >/etc/nginx/sites-available/edgebox.conf <<EOF
server {
    listen ${NGINX_TLS_PORT} ssl http2;
    server_name ${DOMAIN:-_};
    ssl_certificate     ${CERT_FILE};
    ssl_certificate_key ${KEY_FILE};

    # 基础探活
    location = / { return 200 "ok\n"; add_header Content-Type text/plain; }

    # 订阅
    location /sub/ { alias /var/www/html/sub/; autoindex on; }
}
EOF
    # 追加 WS
    if [[ "$ON_WS" == y ]]; then
      awk -v blk='
    location /ws {
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_pass http://127.0.0.1:10080;
    }' '/^}/{print blk}1' /etc/nginx/sites-available/edgebox.conf \
      > /tmp/edgebox.conf && mv /tmp/edgebox.conf /etc/nginx/sites-available/edgebox.conf
    fi
    # 追加 gRPC
    if [[ "$ON_GRPC" == y ]]; then
      awk -v blk='
    location /grpc {
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
        grpc_pass grpc://127.0.0.1:10085;
    }' '/^}/{print blk}1' /etc/nginx/sites-available/edgebox.conf \
      > /tmp/edgebox.conf && mv /tmp/edgebox.conf /etc/nginx/sites-available/edgebox.conf
    fi

    ln -sf /etc/nginx/sites-available/edgebox.conf /etc/nginx/sites-enabled/edgebox.conf
    nginx -t && systemctl restart nginx
    log "Nginx 已配置并启动 (443=${NGINX_TLS_PORT})"
  else
    # 不用 Nginx 也保持默认站点
    systemctl enable --now nginx >/dev/null 2>&1 || true
  fi
}

# ====== Xray（按需：gRPC 与 WS） ======
make_xray_conf() {
  if [[ "$ON_GRPC" != y && "$ON_WS" != y ]]; then
    systemctl disable --now xray >/dev/null 2>&1 || true
    return
  fi

  local cfg=/etc/xray/config.json
  local uuid="$UUID"
  local local_socks_port=10808

  # 基础骨架
  cat >"$cfg" <<JSON
{
  "inbounds": [],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" }
  ]
}
JSON

  # 追加 WS
  if [[ "$ON_WS" == y ]]; then
    jq --arg uuid "$uuid" '.inbounds += [{
      "tag":"vless-ws","listen":"127.0.0.1","port":10080,"protocol":"vless",
      "settings":{"decryption":"none","clients":[{"id":$uuid}]},
      "streamSettings":{"network":"ws","wsSettings":{"path":"/ws"}}
    }]' "$cfg" | sponge "$cfg"
  fi

  # 追加 gRPC
  if [[ "$ON_GRPC" == y ]]; then
    jq --arg uuid "$uuid" '.inbounds += [{
      "tag":"vless-grpc","listen":"127.0.0.1","port":10085,"protocol":"vless",
      "settings":{"decryption":"none","clients":[{"id":$uuid}]},
      "streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"grpc"}}
    }]' "$cfg" | sponge "$cfg"
  fi

  # systemd 已由官方脚本写好，直接启/重启
  systemctl enable --now xray
  systemctl restart xray
  sleep 1
  systemctl --no-pager -l status xray | sed -n '1,8p' || true
  log "Xray (WS/gRPC) 已启动"
}

# ====== sing-box（Reality / HY2 / TUIC + 路由） ======
make_singbox_conf() {
  local need_sb="n"
  [[ "$ON_REA" == y || "$ON_HY2" == y || "$ON_TUIC" == y ]] && need_sb="y"
  if [[ "$need_sb" != y ]]; then
    systemctl disable --now sing-box >/dev/null 2>&1 || true
    return
  fi

  # 生成 Reality 密钥对（server 私钥 + client 公钥）
  local SB_PRIV SB_PUB SID
  SID="$(openssl rand -hex 4)"
  if command -v sing-box >/dev/null 2>&1; then
    mapfile -t kv < <(sing-box generate reality-keypair 2>/dev/null | sed -n 's/^.*: //p')
    SB_PRIV="${kv[0]}"
    SB_PUB="${kv[1]}"
  else
    # 退化方案：用 xray 计算
    mapfile -t kv < <(xray x25519 2>/dev/null | sed -n 's/^.*: //p')
    SB_PRIV="${kv[0]}"; SB_PUB="${kv[1]}"
  fi

  # 出口
  local ROUTE_FINAL="direct"
  local ROUTE_RULES='[]'
  local RESJSON=''
  if [[ "${OUT}" == "2" ]]; then
    ROUTE_FINAL="resproxy"
    ROUTE_RULES='[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com","gstatic.com","googleusercontent.com"],"outbound":"direct"}]'
    RESJSON=$(jq -nc --arg h "$RHOST" --argjson p "$RPORT" --arg u "${RUSER:-}" --arg pw "${RPASS:-}" \
      '{ "type":"http","tag":"resproxy","server":$h,"server_port":$p|tonumber,
         "username":$u,"password":$pw }')
  fi

  # 组装 sing-box 配置
  local cfg=/etc/sing-box/config.json
  jq -nc \
    --argjson need_rea $( [[ "$ON_REA" == y ]] && echo true || echo false ) \
    --argjson need_hy2 $( [[ "$ON_HY2" == y ]] && echo true || echo false ) \
    --argjson need_tuic $( [[ "$ON_TUIC" == y ]] && echo true || echo false ) \
    --arg uuid "$UUID" \
    --arg sni  "$SNI_REA" \
    --arg priv "$SB_PRIV" \
    --arg sid  "$SID" \
    --arg cert "$CERT_FILE" \
    --arg key  "$KEY_FILE" \
    --argjson hy2port "$HY2PORT" \
    --arg tuicpwd "$TUIC_PWD" \
    --argjson tuicport "$TUIC_PORT" \
    --argjson rules "$ROUTE_RULES" \
    --arg final "$ROUTE_FINAL" \
    --argjson resout "${RESJSON:-null}" '
{
  "log": { "level": "info" },
  "dns": { "servers": [ { "tag":"local", "address":"local" } ], "strategy":"prefer_ipv4" },
  "inbounds": [],
  "outbounds": [ { "type":"direct", "tag":"direct" }, { "type":"block", "tag":"block"} ],
  "route": { "rules": $rules, "final": $final }
}
| if $need_rea then
    .inbounds += [{
      "type":"vless","tag":"vless-reality","listen":"0.0.0.0","listen_port":443,
      "users":[{"uuid":$uuid}],
      "tls":{
        "enabled":true,
        "server_name":$sni,
        "reality":{
          "enabled":true,
          "handshake":{"server":$sni,"server_port":443},
          "private_key":$priv,
          "short_id":[$sid]
        }
      },
      "transport":{"type":"tcp"}
    }]
  else . end
| if $need_hy2 then
    .inbounds += [{
      "type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":$hy2port,
      "users":[{"password":"'"$HY2_PASS"'"}],
      "tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key},
      "masquerade":"https://www.cloudflare.com/"
    }]
  else . end
| if $need_tuic then
    .inbounds += [{
      "type":"tuic","tag":"tuic-in","listen":"0.0.0.0","listen_port":$tuicport,
      "users":[{"uuid":$uuid,"password":$tuicpwd}],
      "tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}
    }]
  else . end
| if $resout != null then .outbounds += [ $resout ] else . end
' > "$cfg"

  # systemd
  cat >/etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box unified service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sing-box -D /etc/sing-box -c /etc/sing-box/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now sing-box
  sleep 1
  systemctl --no-pager -l status sing-box | sed -n '1,8p' || true

  # 输出给订阅的 Reality 公钥
  echo "$SB_PRIV" > /etc/sing-box/reality_server_priv.key
  echo "$SID"     > /etc/sing-box/reality_sid.txt
  if command -v xray >/dev/null 2>&1; then
    SB_PUB="$(xray x25519 -i "$SB_PRIV" 2>/dev/null | sed -n 's/^.*: //p' | tail -n1)"
  fi
  echo "$SB_PUB"  > /etc/sing-box/reality_client_pub.key
  export SB_PUB
  log "sing-box 已配置并启动"
}

# ====== 防火墙 ======
set_firewall() {
  ufw allow 22/tcp >/dev/null 2>&1 || true
  [[ "$ON_GRPC" == y || "$ON_WS" == y ]] && ufw allow ${NGINX_TLS_PORT}/tcp >/dev/null 2>&1 || true
  [[ "$ON_HY2" == y ]] && ufw allow ${HY2PORT}/udp >/dev/null 2>&1 || true
  [[ "$ON_TUIC" == y ]] && ufw allow ${TUIC_PORT}/udp >/dev/null 2>&1 || true
  yes | ufw enable >/dev/null 2>&1 || true
  log "UFW 端口规则已配置"
}

# ====== 生成订阅与“实值 URL” ======
gen_subscription() {
  local host
  host="$(hostname -I | awk '{print $1}')"
  local base_host="${DOMAIN:-$host}"

  : > /var/lib/sb-sub/urls.txt

  # VLESS-WS
  if [[ "$ON_WS" == y ]]; then
    echo "vless://${UUID}@${base_host}:${NGINX_TLS_PORT}?encryption=none&security=tls&type=ws&host=${DOMAIN:-$base_host}&sni=${DOMAIN:-$base_host}&path=%2Fws&fp=chrome#VLESS-WS(${NGINX_TLS_PORT})" >> /var/lib/sb-sub/urls.txt
  fi
  # VLESS-gRPC
  if [[ "$ON_GRPC" == y ]]; then
    echo "vless://${UUID}@${base_host}:${NGINX_TLS_PORT}?encryption=none&security=tls&type=grpc&serviceName=grpc&sni=${DOMAIN:-$base_host}&fp=chrome#VLESS-gRPC(${NGINX_TLS_PORT})" >> /var/lib/sb-sub/urls.txt
  fi
  # Reality
  if [[ "$ON_REA" == y ]]; then
    local pbk="$SB_PUB"; local sid="$(cat /etc/sing-box/reality_sid.txt)"
    echo "vless://${UUID}@${base_host}:443?security=reality&encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=${pbk}&sid=${sid}&sni=${SNI_REA}&type=tcp#VLESS-Reality-443" >> /var/lib/sb-sub/urls.txt
  fi
  # HY2
  if [[ "$ON_HY2" == y ]]; then
    echo "hy2://${HY2_PASS}@${base_host}:${HY2PORT}/?sni=${DOMAIN:-$base_host}&alpn=h3#HY2-${HY2PORT}" >> /var/lib/sb-sub/urls.txt
  fi
  # TUIC
  if [[ "$ON_TUIC" == y ]]; then
    echo "tuic://${UUID}:${TUIC_PWD}@${base_host}:${TUIC_PORT}/?congestion=cubic&alpn=h3&sni=${DOMAIN:-$base_host}#TUIC-2053" >> /var/lib/sb-sub/urls.txt
  fi

  log "已生成订阅文件：/var/lib/sb-sub/urls.txt"
  echo -e "${c_green}订阅 HTTP 地址：${c_end}http://${base_host}/sub/urls.txt"
}

# ====== 收尾检查 ======
post_checks() {
  echo
  log "服务状态（如失败请贴出 status）："
  systemctl --no-pager -l status sing-box | sed -n '1,6p' || true
  systemctl --no-pager -l status xray     | sed -n '1,6p' || true
  systemctl --no-pager -l status nginx    | sed -n '1,6p' || true

  echo
  log "监听端口："
  ss -lnptu | grep -E ':443|:8443|:2053' || true

  echo
  if [[ "$ON_REA" == y && ( "$ON_GRPC" == y || "$ON_WS" == y ) ]]; then
    warn "因 Reality 占用 443/tcp，gRPC/WS 已迁移至 ${NGINX_TLS_PORT}/tcp"
  fi
  [[ "$OUT" == 2 ]] && log "出口分流：默认走住宅 HTTP 代理，仅 {googlevideo/ytimg/ggpht/gstatic/googleusercontent} 直出。"
}

# ====== 主流程 ======
main() {
  need_root
  prep_env
  ask_inputs
  install_singbox
  install_xray
  gen_cert
  make_nginx
  make_xray_conf
  make_singbox_conf
  set_firewall
  gen_subscription
  post_checks

  echo
  log "安装完成。你可以在 v2rayN/sing-box 客户端用订阅导入，或直接粘贴“实值 URL”。"
}

main "$@"
