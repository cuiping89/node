#!/usr/bin/env bash
# =====================================================================================
# EdgeBox/node项目 通用卸载脚本（幂等、可软卸载/硬卸载）：兼容大多数 VPS/VM（Ubuntu/Debian 系适配最好）
#
# 此卸载脚本是幂等的，按 “存在即删，不存在忽略” 的方式处理，默认会做这些事：
#
# 1) 停用并删除：sing-box.service（必有）、xray.service（有就停、没有就跳过）
# 2) 删除文件夹/文件：
#    - /etc/sing-box
#    - /usr/local/bin/sing-box
#    - /usr/local/etc/xray/config.json
#    - /etc/nginx/conf.d/edgebox.conf
#    - /etc/ssl/edgebox
#    - /var/lib/sb-sub
#    - /var/www/html/sub         （订阅页）
# 3) 清理 UFW：放行规则 8443/tcp、443/tcp、2053/udp（不存在会自动忽略），然后 ufw reload
# 4) 不卸载 Nginx 包，只是删站点文件，避免影响以后重装
#
# 交互与选项（两种方式，二选一）：
# - 默认“软卸载”：仅移除 sing-box 与其配置/订阅，保留 BBR/fq、swap、UFW 与 Nginx（适合马上重装）
# - 可选项：
#   --purge-nginx     额外清理订阅网页与 Nginx 站点（无论 conf.d 还是 sites-available 布局均覆盖）
#   --purge-net       一并清掉端口放行、sysctl 优化、脚本创建的 swap，系统回到“素净”状态
#   --purge-packages  卸掉安装时拉的工具（jq / unzip / socat / qrencode 等，若存在）
#   --all             等价于 --purge-nginx --purge-net --purge-packages
#
# 脚本操作顺序：
#   1) 备份当前配置；2) 运行本卸载脚本；3) 自检；
#
# 说明：
# - ACME 账户与其它系统级组件（如 ~/.acme.sh）不会强制清除，便于后续复用。
# - 仅删除我们创建/约定位置的 swap（命名/标记），不会误删系统原生 swap。
# =====================================================================================

set -Eeuo pipefail

# ---------- 常量 ----------
BACKUP_DIR="/root/sb-backups"
TS="$(date +%F-%H%M%S)"

# 服务/文件路径（与安装脚本保持一致）
SB_SVC="/etc/systemd/system/sing-box.service"
SB_DIR="/etc/sing-box"
SB_BIN="/usr/local/bin/sing-box"

XRAY_SVC="/etc/systemd/system/xray.service"
XRAY_CFG="/usr/local/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

SUB_DIR="/var/lib/sb-sub"
SUB_LINK="/var/www/html/sub"
CERT_DIR="/etc/ssl/edgebox"

# Nginx 站点（两种布局都处理）
NGX_CONF_D_FILE="/etc/nginx/conf.d/edgebox.conf"
NGX_SITE_AVAIL="/etc/nginx/sites-available/edgebox"
NGX_SITE_ENABL="/etc/nginx/sites-enabled/edgebox"

# 我们创建的 sysctl 与 swap 标记
SYSCTL_TUNE_GLOB="/etc/sysctl.d/*sb*{tune,bbr,fq}*.conf"
FSTAB_TAG="# sb-swap"
SB_SWAP_PATHS=(
  "/swapfile-sb"
  "/swap_sb"
)

# ---------- 选项解析 ----------
PURGE_NGINX=0
PURGE_NET=0
PURGE_PKGS=0
REMOVE_BIN=1   # 默认移除 sing-box/xray 程序本体（与之前行为一致）

usage() {
  cat <<EOF
用法: sudo bash $0 [--purge-nginx] [--purge-net] [--purge-packages] [--all] [--keep-bin]

  --purge-nginx     额外清理订阅网页与 Nginx 站点文件
  --purge-net       端口放行/sysctl优化/脚本创建的 swap 一并清理
  --purge-packages  卸载安装时拉的工具包（jq/unzip/socat/qrencode 等）
  --all             等价于 --purge-nginx --purge-net --purge-packages
  --keep-bin        保留 /usr/local/bin/xray 与 /usr/local/bin/sing-box

若不带参数，将进入交互式“软卸载”（默认保留 Nginx/UFW/调优/swap，适合立刻重装）。
EOF
}

if [[ $# -gt 0 ]]; then
  for arg in "$@"; do
    case "$arg" in
      --purge-nginx) PURGE_NGINX=1 ;;
      --purge-net) PURGE_NET=1 ;;
      --purge-packages) PURGE_PKGS=1 ;;
      --all) PURGE_NGINX=1; PURGE_NET=1; PURGE_PKGS=1 ;;
      --keep-bin) REMOVE_BIN=0 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "未知参数: $arg"; usage; exit 2 ;;
    esac
  done
else
  # 交互式（软卸载为默认）
  read -r -p "是否额外清理订阅网页与 Nginx 站点？[y/N]: " a
  [[ "${a:-}" =~ ^[Yy]$ ]] && PURGE_NGINX=1 || true

  read -r -p "是否一并清理端口放行、sysctl 调优、脚本创建的 swap？[y/N]: " b
  [[ "${b:-}" =~ ^[Yy]$ ]] && PURGE_NET=1 || true

  read -r -p "是否卸载安装时新增的小工具包（jq/unzip/socat/qrencode）？[y/N]: " c
  [[ "${c:-}" =~ ^[Yy]$ ]] && PURGE_PKGS=1 || true

  read -r -p "是否移除 Xray 与 sing-box 程序本体？[Y/n]: " d
  REMOVE_BIN=1
  [[ "${d:-Y}" =~ ^[Nn]$ ]] && REMOVE_BIN=0 || true
fi

# ---------- 前置检查 ----------
[[ $EUID -eq 0 ]] || { echo "请用 root 运行。"; exit 1; }

mkdir -p "$BACKUP_DIR"
BACKUP_TGZ="$BACKUP_DIR/edgebox-$TS.tgz"

# ---------- 备份（尽力而为） ----------
echo "[*] 备份配置到 $BACKUP_TGZ"
tar -czf "$BACKUP_TGZ" \
  --ignore-failed-read \
  "$SB_DIR" "$XRAY_CFG" "$NGX_CONF_D_FILE" \
  "$NGX_SITE_AVAIL" "$NGX_SITE_ENABL" \
  "$CERT_DIR" "$SUB_DIR" "$SUB_LINK" 2>/dev/null || true

# ---------- 停服务 ----------
echo "[*] 停止并禁用服务"
systemctl disable --now sing-box 2>/dev/null || true
systemctl disable --now xray     2>/dev/null || true

# ---------- 删除配置与二进制 ----------
echo "[*] 移除配置文件与可执行文件（保留 Nginx 包，仅删站点/证书/订阅页）"

# sing-box
rm -rf "$SB_DIR" 2>/dev/null || true
rm -f  "$SB_SVC" 2>/dev/null || true
[[ $REMOVE_BIN -eq 1 ]] && rm -f "$SB_BIN" 2>/dev/null || true

# xray（仅清理配置，二进制按选项决定）
rm -f "$XRAY_CFG" 2>/dev/null || true
[[ $REMOVE_BIN -eq 1 ]] && rm -f "$XRAY_BIN" 2>/dev/null || true

# 订阅目录/证书
rm -rf "$SUB_DIR" "$SUB_LINK" "$CERT_DIR" 2>/dev/null || true

# Nginx 站点（软卸默认也清理 edgebox 站点；若不想清理，可改为放入 PURGE_NGINX 分支）
rm -f "$NGX_CONF_D_FILE" 2>/dev/null || true
rm -f "$NGX_SITE_ENABL" "$NGX_SITE_AVAIL" 2>/dev/null || true

# ---------- 额外：NGINX 全面清理（仅在选择 --purge-nginx 时做“拓展覆盖”） ----------
if [[ $PURGE_NGINX -eq 1 ]]; then
  # 若其它 edgebox* 命名的残留站点，一并尝试清理
  find /etc/nginx -type f -maxdepth 2 -regex '.*/\(conf\.d\|sites-available\|sites-enabled\)/edgebox.*' -print0 2>/dev/null \
    | xargs -0r rm -f || true
  # 订阅页与证书已经在上面删过，这里兜底再来一次
  rm -rf "$SUB_DIR" "$SUB_LINK" "$CERT_DIR" 2>/dev/null || true
fi

# ---------- systemd 重载 ----------
systemctl daemon-reload 2>/dev/null || true

# ---------- 网络/内核/防火墙 清理 ----------
if [[ $PURGE_NET -eq 1 ]]; then
  echo "[*] 清理 UFW 放行与网络调优、swap"

  # UFW 端口
  if command -v ufw >/dev/null 2>&1; then
    ufw --force delete allow 443/tcp 2>/dev/null || true
    ufw --force delete allow 8443/tcp 2>/dev/null || true
    ufw --force delete allow 443/udp 2>/dev/null || true
    ufw --force delete allow 8443/udp 2>/dev/null || true
    ufw --force delete allow 2053/udp 2>/dev/null || true
    ufw reload 2>/dev/null || true
  fi

  # sysctl 调优（仅删除我们加的文件）
  # 常见命名：/etc/sysctl.d/60-sb-bbr-fq.conf 或 99-sb-tune.conf 等
  shopt -s nullglob
  for f in $SYSCTL_TUNE_GLOB; do
    rm -f "$f" 2>/dev/null || true
  done
  sysctl --system >/dev/null 2>&1 || true

  # swap（仅删除我们加的，带标记或特定命名）
  # 1) fstab 标记
  if grep -q "$FSTAB_TAG" /etc/fstab 2>/dev/null; then
    # 取路径列（第1列）
    while IFS= read -r line; do
      path=$(awk '{print $1}' <<<"$line")
      swapoff "$path" 2>/dev/null || true
      sed -i "\|${path}.*${FSTAB_TAG}|d" /etc/fstab 2>/dev/null || true
      rm -f "$path" 2>/dev/null || true
    done < <(grep "$FSTAB_TAG" /etc/fstab || true)
  fi
  # 2) 约定命名
  for s in "${SB_SWAP_PATHS[@]}"; do
    if [[ -e "$s" ]]; then
      swapoff "$s" 2>/dev/null || true
      sed -i "\|^$s |d" /etc/fstab 2>/dev/null || true
      rm -f "$s" 2>/dev/null || true
    fi
  done
fi

# ---------- 可选：卸载小工具 ----------
if [[ $PURGE_PKGS -eq 1 ]]; then
  if command -v apt >/dev/null 2>&1; then
    echo "[*] 卸载工具包（若存在）"
    DEBIAN_FRONTEND=noninteractive apt purge -y jq unzip socat qrencode 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt autoremove -y 2>/dev/null || true
  fi
fi

# ---------- Nginx 测试并重载（若仍在） ----------
if command -v nginx >/dev/null 2>&1; then
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx 2>/dev/null || true
  fi
fi

echo "[OK] 卸载完成。备份文件：$BACKUP_TGZ"
echo "如需恢复：  tar -xzf $BACKUP_TGZ -C / && systemctl daemon-reload && systemctl restart nginx xray sing-box"

# 最后提示：自检指令
cat <<'EOF'

自检建议：
  ss -lntup | egrep ':443|:8443|:2053' || true
  systemctl status sing-box xray nginx --no-pager -l
  command -v nginx >/dev/null && nginx -t || true

EOF

exit 0
