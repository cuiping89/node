#!/usr/bin/env bash
set -euo pipefail

cecho(){ printf "\033[1;32m%s\033[0m\n" "$*"; }
wecho(){ printf "\033[1;33m%s\033[0m\n" "$*"; }
fecho(){ printf "\033[1;31m%s\033[0m\n" "$*"; }

cecho "== System & Kernel =="
uname -a
lsb_release -a 2>/dev/null || true

cecho "== Root & Package =="
[ "$EUID" -eq 0 ] || { fecho "请用 root 运行"; exit 1; }
command -v ss >/dev/null || apt-get update -y && apt-get install -y iproute2
command -v jq >/dev/null || apt-get install -y jq
command -v ufw >/dev/null || apt-get install -y ufw

cecho "== BBR/FQ 状态 =="
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc

cecho "== Swap 检查（建议 >= 2GB） =="
free -h

cecho "== 端口占用检查 =="
ss -lntup | awk 'NR==1 || /:443/ || /:8443/ || /:2053/'
wecho "说明：443/tcp=Nginx/Reality；443/udp=HY2；2053/udp=TUIC；8443/udp=HY2 备用"

cecho "== Nginx/QUIC 冲突检查 =="
if command -v nginx >/dev/null; then
  if nginx -T 2>/dev/null | grep -qE 'listen\s+443.*quic'; then
    fecho "检测到 Nginx 启用 QUIC(HTTP/3)。这会占用 UDP:443，与 HY2 冲突。安装时会自动关闭。"
  else
    cecho "Nginx 未启用 QUIC，和 HY2 不冲突。"
  fi
else
  wecho "未检测到 Nginx。"
fi

cecho "== UFW/GCP 防火墙建议 =="
wecho "本机 UFW 建议放行：22/tcp, 443/tcp(若用), 443/udp(若用HY2), 8443/udp(若用HY2), 2053/udp(若用TUIC)。"
wecho "GCP VPC 防火墙同样需要放行以上端口（方向：Ingress）。"

cecho "== OK：体检完成 =="
