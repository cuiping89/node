#!/usr/bin/env bash
# sb-uninstall.sh - 卸载/清理 sing-box 三协议部署（带可选彻底清理）
# 用法：
#   bash sb-uninstall.sh                    # 仅卸载 sing-box 与配置（保留 BBR/fq、swap、UFW/Nginx、订阅网页）
#   bash sb-uninstall.sh --purge-nginx      # 额外移除订阅网页与 Nginx 站点（不卸载 Nginx 包）
#   bash sb-uninstall.sh --purge-net        # 额外移除端口开放、sysctl 优化与 swap（如果是脚本创建的）
#   bash sb-uninstall.sh --purge-packages   # 顺带清理安装时的常用依赖包（jq/unzip 可选，按需改）
#   bash sb-uninstall.sh -y                 # 非交互
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }

YES=false
PURGE_NGINX=false
PURGE_NET=false
PURGE_PKGS=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) YES=true ;;
    --purge-nginx) PURGE_NGINX=true ;;
    --purge-net)   PURGE_NET=true ;;
    --purge-packages) PURGE_PKGS=true ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
  shift
done

SVC=sing-box
BIN=/usr/local/bin/sing-box
CFG=/etc/sing-box
SUB=/var/lib/sb-sub
SYSUNIT=/etc/systemd/system/sing-box.service
SYSOVR=/etc/systemd/system/sing-box.service.d
WWW_SUB=/var/www/html/sub
NGX_AV=/etc/nginx/sites-available/sb-sub.conf
NGX_EN=/etc/nginx/sites-enabled/sb-sub.conf
SYSCTL_TUNE=/etc/sysctl.d/99-sb-tune.conf     # 你的安装脚本里用于 BBR+fq 的文件名（按需改）
SWAP_TAG="# sb-swap"                           # fstab 里标记行（安装脚本写入时请带这个注释）

say() { printf '%s\n' "$*"; }
ask() {
  $YES && return 0
  read -r -p "$1 [y/N] " x; [[ ${x,,} == y ]]
}

# 0) 备份（安全兜底）
TS=$(date +%F-%H%M%S)
BACKUP_DIR=/root/sb-backups
mkdir -p "$BACKUP_DIR"
tar_items=()
[[ -d $CFG ]] && tar_items+=("$CFG")
[[ -d $SUB ]] && tar_items+=("$SUB")
[[ -f $NGX_AV ]] && tar_items+=("$NGX_AV")
[[ -f $NGX_EN ]] && tar_items+=("$NGX_EN")
[[ -d $WWW_SUB ]] && tar_items+=("$WWW_SUB")
if ((${#tar_items[@]})); then
  tar -czf "$BACKUP_DIR/sb-uninstall-$TS.tgz" "${tar_items[@]}" 2>/dev/null || true
  say "已备份到 $BACKUP_DIR/sb-uninstall-$TS.tgz"
fi

# 1) 停服务、清 systemd 残留
if systemctl list-unit-files | grep -q "^$SVC\\.service"; then
  systemctl disable --now "$SVC" || true
  systemctl reset-failed "$SVC" || true
fi
pkill -x sing-box 2>/dev/null || true

# 2) 删除文件与目录
rm -f "$BIN"
rm -f "$SYSUNIT"
rm -rf "$SYSOVR"
rm -rf "$CFG"
rm -rf "$SUB"
systemctl daemon-reload

# 3) 可选：清理 Nginx 的订阅站点与文件（不卸载 Nginx 包）
if $PURGE_NGINX || ask "要清理订阅网页与 Nginx 站点吗？(不卸载 Nginx 包)"; then
  rm -f "$NGX_EN" "$NGX_AV" || true
  rm -f "$WWW_SUB/urls.txt"  || true
  rmdir  "$WWW_SUB" 2>/dev/null || true
  command -v nginx >/dev/null && nginx -t && systemctl reload nginx || true
fi

# 4) 可选：清理防火墙与内核优化、swap（仅移除脚本创建的项）
if $PURGE_NET || ask "要连同端口放行、BBR/fq/sysctl 与脚本创建的 swap 一起清理吗？"; then
  if command -v ufw >/dev/null 2>&1; then
    for r in "443/tcp" "443/udp" "8443/udp" "2053/udp"; do ufw delete allow "$r" >/dev/null 2>&1 || true; done
  fi
  [[ -f $SYSCTL_TUNE ]] && rm -f "$SYSCTL_TUNE" && sysctl --system || true

  # 仅当 /etc/fstab 中带有我们安装时写入的标记行才移除 swap
  if grep -q "$SWAP_TAG" /etc/fstab 2>/dev/null; then
    swapoff -a || true
    sed -i "\|$SWAP_TAG|d" /etc/fstab || true
    [[ -f /swapfile ]] && rm -f /swapfile || true
  fi
fi

# 5) 可选：顺带清理安装依赖（按需）
if $PURGE_PKGS || ask "要顺带清理安装依赖（jq/unzip 等）吗？"; then
  apt-get -y purge jq unzip >/dev/null 2>&1 || true
  apt-get -y autoremove >/dev/null 2>&1 || true
fi

say "✅ 卸载完成。"
say "检查端口：ss -lntup | egrep ':(443|8443|2053)' || true"
say "如需恢复备份：tar -xzf $BACKUP_DIR/sb-uninstall-$TS.tgz -C /"
