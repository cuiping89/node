#!/usr/bin/env bash
# sb-uninstall.sh - 卸载/清理 sing-box 三协议部署
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }

systemctl disable --now sing-box 2>/dev/null || true
rm -f /usr/local/bin/sing-box
rm -f /etc/systemd/system/sing-box.service
rm -rf /etc/sing-box
rm -rf /var/lib/sb-sub
systemctl daemon-reload
echo "卸载完成（保留了网络优化与 swap、UFW 规则）。"
