#!/usr/bin/env bash
# =====================================================================================
# EdgeBox / node 项目 —— 终版通用卸载脚本（无交互，一把梭）
#
# 幂等设计：存在即删 / 不存在忽略。默认做这些事：
# 1) 停用并删除：sing-box.service（若有）、xray.service（若有）
# 2) 删除这些路径/文件（若有）：
#    - /etc/sing-box
#    - /usr/local/bin/sing-box
#    - /usr/local/etc/xray/config.json
#    - /etc/nginx/conf.d/edgebox.conf
#    - /etc/nginx/sites-available/edgebox  /etc/nginx/sites-enabled/edgebox
#    - /etc/ssl/edgebox
#    - /var/lib/sb-sub
#    - /var/www/html/sub     （订阅页）
# 3) 清理 UFW 放行：443/tcp、8443/tcp、443/udp、8443/udp、2053/udp（不存在会自动忽略），并 ufw reload
# 4) 移除我们加的 sysctl 调优文件与脚本创建的 swap（带标记/约定命名）
# 5) 卸掉安装时拉的工具（jq / unzip / socat / qrencode），并 apt autoremove（若系统是 Debian/Ubuntu）
# 6) 不卸载 Nginx 包，只删站点/订阅页，避免影响以后重装
#
# 自检（脚本结尾会自动执行并给提示）：
#  - ss -lntup | egrep ':443|:8443|:2053'     # 输出为空 ≈ 相关端口都未占用（理想状态）
#  - systemctl status sing-box xray nginx     # sing-box/xray 若显示 inactive/not-found 即已卸；nginx active 也OK
#  - nginx -t                                 # 若仍安装 nginx，应显示 syntax is ok / test is successful
# =====================================================================================

set -Eeuo pipefail

# --- 自动提权：若不是 root，用 sudo -i 重新执行本脚本 ---
if [[ $EUID -ne 0 ]]; then
  exec sudo -i bash "$0" "$@"
fi

# ---------- 常量 ----------
BACKUP_DIR="/root/sb-backups"
TS="$(date +%F-%H%M%S)"
mkdir -p "$BACKUP_DIR"
BACKUP_TGZ="$BACKUP_DIR/edgebox-$TS.tgz"

# 服务/文件路径（与安装脚本约定一致）
SB_SVC="/etc/systemd/system/sing-box.service"
SB_DIR="/etc/sing-box"
SB_BIN="/usr/local/bin/sing-box"

XRAY_SVC="/etc/systemd/system/xray.service"
XRAY_CFG="/usr/local/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

SUB_DIR="/var/lib/sb-sub"
SUB_LINK="/var/www/html/sub"
CERT_DIR="/etc/ssl/edgebox"

NGX_CONF_D_FILE="/etc/nginx/conf.d/edgebox.conf"
NGX_SITE_AVAIL="/etc/nginx/sites-available/edgebox"
NGX_SITE_ENABL="/etc/nginx/sites-enabled/edgebox"

# 我们创建的 sysctl 与 swap 标记/命名
SYSCTL_TUNE_GLOB="/etc/sysctl.d/*sb*{tune,bbr,fq}*.conf"
FSTAB_TAG="# sb-swap"
SB_SWAP_PATHS=(
  "/swapfile-sb"
  "/swap_sb"
)

echo "[*] 备份相关文件到：$BACKUP_TGZ"
tar -czf "$BACKUP_TGZ" \
  --ignore-failed-read \
  "$SB_DIR" "$XRAY_CFG" "$NGX_CONF_D_FILE" \
  "$NGX_SITE_AVAIL" "$NGX_SITE_ENABL" \
  "$CERT_DIR" "$SUB_DIR" "$SUB_LINK" 2>/dev/null || true

echo "[*] 停止并禁用服务（若存在）"
systemctl disable --now sing-box 2>/dev/null || true
systemctl disable --now xray     2>/dev/null || true

echo "[*] 删除 sing-box / xray 配置与二进制（若存在）"
rm -rf "$SB_DIR"              2>/dev/null || true
rm -f  "$SB_SVC"              2>/dev/null || true
rm -f  "$SB_BIN"              2>/dev/null || true
rm -f  "$XRAY_CFG"            2>/dev/null || true
rm -f  "$XRAY_BIN"            2>/dev/null || true

echo "[*] 删除订阅页与证书目录（若存在）"
rm -rf "$SUB_DIR" "$SUB_LINK" "$CERT_DIR" 2>/dev/null || true

echo "[*] 清理 Nginx 站点（不卸 nginx 包）"
rm -f "$NGX_CONF_D_FILE" 2>/dev/null || true
rm -f "$NGX_SITE_AVAIL" "$NGX_SITE_ENABL" 2>/dev/null || true
# 兜底：清理任何 edgebox* 命名的站点文件
find /etc/nginx -type f -maxdepth 2 -regex '.*/\(conf\.d\|sites-available\|sites-enabled\)/edgebox.*' -print0 2>/dev/null \
  | xargs -0r rm -f || true

echo "[*] 重载 systemd"
systemctl daemon-reload 2>/dev/null || true

echo "[*] 清理 UFW 放行（若安装过 ufw）"
if command -v ufw >/dev/null 2>&1; then
  ufw --force delete allow 443/tcp  2>/dev/null || true
  ufw --force delete allow 8443/tcp 2>/dev/null || true
  ufw --force delete allow 443/udp  2>/dev/null || true
  ufw --force delete allow 8443/udp 2>/dev/null || true
  ufw --force delete allow 2053/udp 2>/dev/null || true
  ufw reload 2>/dev/null || true
fi

echo "[*] 移除我们加的 sysctl 调优（若存在）"
shopt -s nullglob
for f in $SYSCTL_TUNE_GLOB; do
  rm -f "$f" 2>/dev/null || true
done
sysctl --system >/dev/null 2>&1 || true

echo "[*] 移除脚本创建的 swap（仅删除带标记或约定命名的）"
# 1) fstab 中带标记的 swap
if grep -q "$FSTAB_TAG" /etc/fstab 2>/dev/null; then
  while IFS= read -r line; do
    path=$(awk '{print $1}' <<<"$line")
    swapoff "$path" 2>/dev/null || true
    sed -i "\|${path}.*${FSTAB_TAG}|d" /etc/fstab 2>/dev/null || true
    rm -f "$path" 2>/dev/null || true
  done < <(grep "$FSTAB_TAG" /etc/fstab || true)
fi
# 2) 约定命名的 swap 文件
for s in "${SB_SWAP_PATHS[@]}"; do
  if [[ -e "$s" ]]; then
    swapoff "$s" 2>/dev/null || true
    sed -i "\|^$s |d" /etc/fstab 2>/dev/null || true
    rm -f "$s" 2>/dev/null || true
  fi
done

echo "[*] 卸载安装时拉的工具（若存在且系统为 Debian/Ubuntu）"
if command -v apt >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt purge -y jq unzip socat qrencode 2>/dev/null || true
  DEBIAN_FRONTEND=noninteractive apt autoremove -y 2>/dev/null || true
fi

# Nginx 存在则测试并重载（删了站点但不卸包）
if command -v nginx >/dev/null 2>&1; then
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx 2>/dev/null || true
  fi
fi

echo "[OK] 卸载完成。备份文件：$BACKUP_TGZ"
echo "如需恢复：  tar -xzf $BACKUP_TGZ -C / && systemctl daemon-reload && systemctl restart nginx xray sing-box"

# ========================== 自检（只读提示，不是报错） ==========================
echo
echo "=== 自检（只读提示）==="
echo "- 端口占用检查（期望：无输出或与本项目无关的服务）："
ss -lntup | egrep ':443|:8443|:2053' || true
echo
echo "- 服务状态（期望：sing-box/xray inactive 或 not-found；nginx active 即可）："
systemctl status sing-box xray nginx --no-pager -l || true
echo
if command -v nginx >/dev/null 2>&1; then
  echo "- nginx 配置测试（期望：syntax is ok / test is successful）："
  nginx -t || true
fi
echo "================================================================"
exit 0
