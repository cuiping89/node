cat >/root/edgebox-uninstall.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[ "${EUID:-$(id -u)}" -eq 0 ] || { echo "请用 root 运行"; exit 1; }

TS="$(date +%F-%H%M%S)"
BKDIR="/root/sb-backups"; mkdir -p "$BKDIR"
BK="$BKDIR/edgebox-$TS.tgz"

echo "[*] 备份配置到 $BK"
tar -czf "$BK" \
  /usr/local/etc/xray 2>/dev/null || true
tar -rzf "$BK" \
  /etc/sing-box 2>/dev/null || true
tar -rzf "$BK" \
  /etc/nginx/sites-available/edgebox.conf \
  /etc/nginx/sites-enabled/edgebox.conf \
  /etc/nginx/ssl/edgebox.crt /etc/nginx/ssl/edgebox.key 2>/dev/null || true
tar -rzf "$BK" /var/lib/sb-sub/urls.txt 2>/dev/null || true

echo "[*] 停止并禁用服务"
systemctl disable --now sing-box 2>/dev/null || true
systemctl disable --now xray     2>/dev/null || true

echo "[*] 移除文件（保留 Nginx 包，仅删站点/证书/订阅页）"
rm -f /etc/nginx/sites-enabled/edgebox.conf
rm -f /etc/nginx/sites-available/edgebox.conf
rm -f /var/www/html/sub/urls.txt
rm -f /var/lib/sb-sub/urls.txt
rm -f /etc/nginx/ssl/edgebox.crt /etc/nginx/ssl/edgebox.key
nginx -t && systemctl reload nginx || true

read -rp "是否移除 Xray 与 sing-box 程序本体？[y/N]: " RMCORE
if [ "${RMCORE^^}" = "Y" ]; then
  rm -f /usr/local/bin/xray /usr/local/bin/sing-box 2>/dev/null || true
  rm -rf /usr/local/share/xray /usr/local/share/sing-box 2>/dev/null || true
  rm -rf /usr/local/etc/xray /etc/sing-box 2>/dev/null || true
  rm -f /etc/systemd/system/xray.service /etc/systemd/system/sing-box.service 2>/dev/null || true
  systemctl daemon-reload
fi

read -rp "是否一并清理 UFW 放行（443/tcp,8443/tcp,HY2/TUIC UDP）？[y/N]: " RMUFW
if [ "${RMUFW^^}" = "Y" ]; then
  ufw delete allow 8443/tcp 2>/dev/null || true
  ufw delete allow 443/tcp  2>/dev/null || true
  ufw delete allow 2053/udp 2>/dev/null || true
  for p in 443 8443; do ufw delete allow "${p}/udp" 2>/dev/null || true; done
  ufw reload || true
fi

read -rp "是否删除脚本创建的 2GB swap？[y/N]: " RMSWAP
if [ "${RMSWAP^^}" = "Y" ]; then
  swapoff /swapfile-edgebox 2>/dev/null || true
  sed -i '/\/swapfile-edgebox/d' /etc/fstab || true
  rm -f /swapfile-edgebox
fi

read -rp "是否移除 BBR/fq sysctl 调优？[y/N]: " RMSYS
if [ "${RMSYS^^}" = "Y" ]; then
  rm -f /etc/sysctl.d/99-edgebox.conf
  sysctl --system >/dev/null || true
fi

read -rp "是否卸载安装时新增的小工具(jq/unzip等)？[y/N]: " RMPKG
if [ "${RMPKG^^}" = "Y" ]; then
  apt-get purge -y jq unzip qrencode socat || true
  apt-get autoremove -y --purge || true
fi

echo "[OK] 卸载完成。备份文件：$BK"
echo "如需恢复：  tar -xzf $BK -C / && systemctl daemon-reload && systemctl restart nginx xray sing-box"
EOF

bash /root/edgebox-uninstall.sh
