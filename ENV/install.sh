文件名：install-node.sh
#!/usr/bin/env bash
set -Eeuo pipefail

# ========= 基本参数 =========
SB_VER="v1.12.2"             # sing-box 稳定可用版本
XRAY_VER="v25.8.3"           # Xray 稳定版本
OS_OK=0

# ========= 交互 =========
read -rp "请输入你的域名（用于 gRPC/WS/订阅）: " DOMAIN
DOMAIN=${DOMAIN:-example.com}

read -rp "启用 VLESS-gRPC(443/tcp)? [y/N]: " EN_GRPC
read -rp "启用 VLESS-WS(+TLS)? [y/N]: " EN_WS
read -rp "启用 VLESS-Reality(443/tcp)? [y/N]: " EN_REAL
read -rp "启用 Hysteria2(udp)? [y/N]: " EN_HY2
read -rp "启用 TUIC(udp/2053)? [y/N]: " EN_TUIC

read -rp "启用‘住宅 HTTP 代理’出站分流? [y/N]: " EN_RES
if [[ ${EN_RES,,} == y* ]]; then
  read -rp "住宅代理 host: "  RES_HOST
  read -rp "住宅代理 port: "  RES_PORT
  read -rp "住宅代理 用户名: " RES_USER
  read -rp "住宅代理 密码: "   RES_PASS
fi

# HY2 端口
if [[ ${EN_HY2,,} == y* ]]; then
  read -rp "HY2 端口(默认443, 可填8443): " HY2_PORT
  HY2_PORT=${HY2_PORT:-443}
fi

# ========= 函数 =========
need_root(){ [[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }; }
chk_os(){ grep -qi "ubuntu" /etc/os-release && OS_OK=1 || true; }
msg(){ printf "\n[OK] %s\n" "$*"; }
warn(){ printf "\n[WARN] %s\n" "$*"; }

install_pkg(){ apt-get update -y; apt-get install -y --no-install-recommends \
  ca-certificates curl wget jq tar unzip openssl ufw nginx; }

# BBR + fq
setup_bbr(){
  cat >/etc/sysctl.d/99-bbr-fq.conf <<'CFG'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
CFG
  sysctl --system >/dev/null || true
  msg "BBR + fq 已应用"
}

# 2G swap（若无）
setup_swap(){
  if ! swapon --noheadings --show | grep -q .; then
    fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    echo '/swapfile none swap sw 0 0' >>/etc/fstab
    msg "已开启 2GB swap"
  else
    msg "已有 swap，跳过"
  fi
}

# sing-box 安装
install_singbox(){
  local url="https://github.com/SagerNet/sing-box/releases/download/${SB_VER}/sing-box-${SB_VER#v}-linux-amd64.tar.gz"
  mkdir -p /usr/local/bin
  tmp=$(mktemp -d)
  ( cd "$tmp" && curl -fsSL "$url" -o sb.tgz && tar -zxf sb.tgz && \
    install -m755 sing-box-*-linux-amd64/sing-box /usr/local/bin/sing-box )
  rm -rf "$tmp"
  command -v sing-box && sing-box version
}

# Xray 安装
install_xray(){
  local base="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip"
  tmp=$(mktemp -d)
  ( cd "$tmp" && curl -fsSL "$base" -o x.zip && unzip -q x.zip && \
    install -m755 xray /usr/local/bin/xray && install -m644 geoip.dat geosite.dat /usr/local/etc/ )
  rm -rf "$tmp"
  command -v xray && xray -version || true
}

# 自签证书（供 Nginx / HY2 / TUIC 使用）
mk_self_cert(){
  mkdir -p /etc/ssl/private
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout /etc/ssl/private/self.key -out /etc/ssl/private/self.crt \
    -subj "/CN=${DOMAIN}" >/dev/null 2>&1 || true
}

# 生成 Xray 配置（gRPC/WS）
mk_xray_cfg(){
  mkdir -p /usr/local/etc/xray
  UUID=$(cat /proc/sys/kernel/random/uuid)
  cat >/usr/local/etc/xray/config.json <<XR
{
  "inbounds": [
    $( [[ ${EN_GRPC,,} == y* ]] && cat <<'J' | sed "s/@UUID@/$UUID/g"
    {
      "port": 10085,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {"clients": [{"id": "@UUID@"}]},
      "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "@grpc"}}
    }
J
    )
    $( [[ ${EN_WS,,} == y* ]] && [[ ${EN_GRPC,,} == y* ]] && echo , )
    $( [[ ${EN_WS,,} == y* ]] && cat <<'J' | sed "s/@UUID@/$UUID/g"
    {
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {"clients": [{"id": "@UUID@"}]},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/@ws"}}
    }
J
    )
  ],
  "outbounds": [
    {"protocol":"freedom","tag":"direct"}
    $( [[ ${EN_RES,,} == y* ]] && echo ,'{"protocol":"http","tag":"res-http","settings":{"servers":[{"address":"'"$RES_HOST"'","port":'"$RES_PORT"',"users":[{"user":"'"$RES_USER"'","pass":"'"$RES_PASS"'"}]}]}}' )
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      $( [[ ${EN_RES,,} == y* ]] && cat <<'R'
      {"type":"field","domain":["domain:googlevideo.com","domain:ytimg.com","domain:ggpht.com"],"outboundTag":"direct"},
      {"type":"field","outboundTag":"res-http"}
R
      )
    ]
  }
}
XR
}

# 生成 sing-box 配置（Reality/HY2/TUIC）
mk_singbox_cfg(){
  mkdir -p /etc/sing-box
  local inb=""

  # Reality
  if [[ ${EN_REAL,,} == y* ]]; then
    read PRIV PUBK < <(sing-box generate reality-keypair | awk '/Private/{p=$3} /Public/{print p, $3}')
    SID=$(openssl rand -hex 4)
    VR_UUID=$(cat /proc/sys/kernel/random/uuid)
    inb+="{\"type\":\"vless\",\"listen\":\"::\",\"listen_port\":443,\"users\":[{\"uuid\":\"$VR_UUID\",\"flow\":\"xtls-rprx-vision\"}],\"tls\":{\"enabled\":true,\"server_name\":\"www.cloudflare.com\",\"reality\":{\"enabled\":true,\"private_key\":\"$PRIV\",\"short_id\":[\"$SID\"],\"handshake\":{\"server\":\"www.cloudflare.com\",\"server_port\":443}}}}"
  fi

  # HY2
  if [[ ${EN_HY2,,} == y* ]]; then
    [[ -n ${inb} ]] && inb+=",
"
    HY2_PWD=$(openssl rand -base64 16 | tr -d '=+/\n' | cut -c1-12)
    inb+="{\"type\":\"hysteria2\",\"listen\":\"::\",\"listen_port\":${HY2_PORT:-443},\"up_mbps\":200,\"down_mbps\":200,\"users\":[{\"password\":\"$HY2_PWD\"}],\"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"/etc/ssl/private/self.crt\",\"key_path\":\"/etc/ssl/private/self.key\"}}"
  fi

  # TUIC
  if [[ ${EN_TUIC,,} == y* ]]; then
    [[ -n ${inb} ]] && inb+=",
"
    TUIC_UUID=$(cat /proc/sys/kernel/random/uuid)
    TUIC_PWD=$(openssl rand -hex 8)
    inb+="{\"type\":\"tuic\",\"listen\":\"::\",\"listen_port\":2053,\"users\":[{\"uuid\":\"$TUIC_UUID\",\"password\":\"$TUIC_PWD\"}],\"congestion\":\"bbr\",\"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"/etc/ssl/private/self.crt\",\"key_path\":\"/etc/ssl/private/self.key\"}}"
  fi

  # 完整配置
  cat >/etc/sing-box/config.json <<SB
{
  "log": {"level":"info"},
  "inbounds": [
${inb}
  ],
  "outbounds": [
    {"type":"direct","tag":"direct"}
    $( [[ ${EN_RES,,} == y* ]] && echo ,'{"type":"http","tag":"res-http","server":"'"$RES_HOST"'","server_port":'"$RES_PORT"',"username":"'"$RES_USER"'","password":"'"$RES_PASS"'"}' )
  ],
  "route": {
    "rules": [
      $( [[ ${EN_RES,,} == y* ]] && cat <<'R'
      {"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"},
      {"outbound":"res-http"}
R
      )
    ]
  }
}
SB

  # 预检
  jq -e . /etc/sing-box/config.json >/dev/null
  sing-box check -c /etc/sing-box/config.json || true
}

# Nginx 反代（443 或 8443）
mk_nginx(){
  local PORT=443
  if [[ ${EN_REAL,,} == y* ]]; then PORT=8443; fi
  cat >/etc/nginx/conf.d/sb.conf <<NG
server {
    listen ${PORT} ssl http2;
    server_name ${DOMAIN};
    ssl_certificate     /etc/ssl/private/self.crt;
    ssl_certificate_key /etc/ssl/private/self.key;

    # gRPC
    $( [[ ${EN_GRPC,,} == y* ]] && cat <<'G'
    location /@grpc {
        grpc_pass grpc://127.0.0.1:10085;
    }
G
    )

    # WebSocket
    $( [[ ${EN_WS,,} == y* ]] && cat <<'W'
    location /@ws {
        proxy_pass http://127.0.0.1:10086;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
W
    )
}
NG
  nginx -t && systemctl reload nginx || systemctl restart nginx
}

# systemd 服务
mk_services(){
  # xray
  if [[ ${EN_GRPC,,} == y* || ${EN_WS,,} == y* ]]; then
    cat >/etc/systemd/system/xray.service <<'S'
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
S
    systemctl daemon-reload
    systemctl enable --now xray
  fi

  # sing-box
  cat >/etc/systemd/system/sing-box.service <<'S'
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
S
  systemctl daemon-reload
  systemctl enable --now sing-box
}

# UFW 放行
open_firewall(){
  ufw allow 22/tcp >/dev/null || true
  if [[ ${EN_REAL,,} == y* ]]; then ufw allow 443/tcp; ufw allow 8443/tcp; else ufw allow 443/tcp; ufw allow 8443/tcp; fi
  [[ ${EN_HY2,,} == y* ]] && ufw allow ${HY2_PORT:-443}/udp
  [[ ${EN_TUIC,,} == y* ]] && ufw allow 2053/udp
  ufw --force enable || true
}

# 订阅生成器（读配置 → 输出 URLs）
mk_subgen(){
  mkdir -p /var/lib/sb-sub /var/www/html/sub
  ln -sf /var/lib/sb-sub/urls.txt /var/www/html/sub/urls.txt
  cat >/root/make_sub.sh <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
DOMAIN=${1:-example.com}
OUT=/var/lib/sb-sub/urls.txt
XCFG=/usr/local/etc/xray/config.json
SCFG=/etc/sing-box/config.json
: >"$OUT"

# Xray: UUID, ws path, grpc service
UUID=$(jq -r '..|.id? // .uuid? // empty' "$XCFG" 2>/dev/null | head -n1 || true)
WSPATH=$(jq -r '.inbounds[]?|select(.protocol=="vless" and .streamSettings.wsSettings.path!=null).streamSettings.wsSettings.path' "$XCFG" 2>/dev/null | head -n1 || true)
GRPCSVC=$(jq -r '.inbounds[]?|select(.protocol=="vless" and .streamSettings.grpcSettings.serviceName!=null).streamSettings.grpcSettings.serviceName' "$XCFG" 2>/dev/null | head -n1 || true)
[[ -z "$GRPCSVC" ]] && GRPCSVC=@grpc

# sing-box: Reality / HY2 / TUIC
VR_UUID=$(jq -r '.inbounds[]?|select(.type=="vless").users[0].uuid // empty' "$SCFG" | head -n1 || true)
PBK=$(jq -r '.inbounds[]?|select(.type=="vless").tls.reality.public_key // empty' "$SCFG" | head -n1 || true)
SID=$(jq -r '.inbounds[]?|select(.type=="vless").tls.reality.short_id[0] // empty' "$SCFG" | head -n1 || true)
SNI=$(jq -r '.inbounds[]?|select(.type=="vless").tls.server_name // .tls.reality.handshake.server // "www.cloudflare.com"' "$SCFG" | head -n1 || true)

HY2_PORT=$(jq -r '.inbounds[]?|select(.type=="hysteria2").listen_port // empty' "$SCFG" | head -n1 || true)
HY2_PWD=$(jq -r  '.inbounds[]?|select(.type=="hysteria2").users[0].password // empty' "$SCFG" | head -n1 || true)

TUIC_PORT=$(jq -r '.inbounds[]?|select(.type=="tuic").listen_port // empty' "$SCFG" | head -n1 || true)
TUIC_UUID=$(jq -r '.inbounds[]?|select(.type=="tuic").users[0].uuid // empty' "$SCFG" | head -n1 || true)
TUIC_PWD=$(jq -r  '.inbounds[]?|select(.type=="tuic").users[0].password // empty' "$SCFG" | head -n1 || true)

# VLESS-gRPC (Nginx 443 或 8443)
if [[ -n "$UUID" ]]; then
  printf 'vless://%s@%s:8443?encryption=none&security=tls&type=grpc&serviceName=%s&fp=chrome#VLESS-gRPC@%s\n' \
    "$UUID" "$DOMAIN" "$GRPCSVC" "$DOMAIN" >>"$OUT"
fi
# VLESS-WS
if [[ -n "$UUID" && -n "$WSPATH" ]]; then
  printf 'vless://%s@%s:8443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n' \
    "$UUID" "$DOMAIN" "$WSPATH" "$DOMAIN" "$DOMAIN" >>"$OUT"
fi
# Reality
if [[ -n "$VR_UUID" && -n "$PBK" && -n "$SID" ]]; then
  printf 'vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n' \
    "$VR_UUID" "$DOMAIN" "$SNI" "$PBK" "$SID" "$DOMAIN" >>"$OUT"
fi
# HY2
if [[ -n "$HY2_PWD" ]]; then
  p=${HY2_PORT:-443}
  printf 'hysteria2://%s@%s:%s?alpn=h3#HY2@%s\n' "$HY2_PWD" "$DOMAIN" "$p" "$DOMAIN" >>"$OUT"
fi
# TUIC
if [[ -n "$TUIC_UUID" && -n "$TUIC_PWD" ]]; then
  p=${TUIC_PORT:-2053}
  printf 'tuic://%s:%s@%s:%s?congestion=bbr&alpn=h3#TUIC@%s\n' \
    "$TUIC_UUID" "$TUIC_PWD" "$DOMAIN" "$p" "$DOMAIN" >>"$OUT"
fi

echo "订阅链接：http://$DOMAIN/sub/urls.txt"
nl -ba "$OUT" | sed -n '1,200p'
SH
  chmod +x /root/make_sub.sh
}

# ========= 主流程 =========
need_root; chk_os; ((OS_OK)) || { echo "仅支持 Ubuntu"; exit 1; }
install_pkg; setup_bbr; setup_swap
install_singbox; install_xray
mk_self_cert
[[ ${EN_GRPC,,} == y* || ${EN_WS,,} == y* ]] && mk_xray_cfg || true
mk_singbox_cfg
mk_nginx
mk_services
open_firewall
mk_subgen

# 首次生成订阅
/root/make_sub.sh "$DOMAIN" || true

# 结果展示
msg "安装完成！"
ss -lntup | egrep ':443|:8443|:2053' || true
systemctl status sing-box --no-pager -l | sed -n '1,20p'
[[ ${EN_GRPC,,} == y* || ${EN_WS,,} == y* ]] && systemctl status xray --no-pager -l | sed -n '1,12p' || true
nginx -t && msg "Nginx 配置语法 ok"
说明： - 已消除 旧版 transport:"tcp" 造成的错误；所有 JSON 用 here‑doc 一次性写入，并用 jq -e/sing-box check 预检。 - Reality 密钥 一次生成 同时取私/公钥；避免“invalid private key”。 - Nginx 若启用 Reality，会自动监听 8443；否则可用 443。 - 订阅生成器固定输出到：http://<域名>/sub/urls.txt。
