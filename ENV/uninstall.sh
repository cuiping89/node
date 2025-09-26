# --- 自动提权到root (兼容 bash <(curl ...)) ---
if [[ $EUID -ne 0 ]]; then
  # 把当前脚本内容拷到临时文件，再以 root 重启执行（兼容 /dev/fd/63）
  _EB_TMP="$(mktemp)"
  # shellcheck disable=SC2128
  cat "${BASH_SOURCE:-/proc/self/fd/0}" > "$_EB_TMP"
  chmod +x "$_EB_TMP"

  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E EB_TMP="$_EB_TMP" bash "$_EB_TMP" "$@"
  else
    exec su - root -c "EB_TMP='$_EB_TMP' bash '$_EB_TMP' $*"
  fi
fi

# 以 root 运行到这里；如果是从临时文件重启的，退出时自动清理
trap '[[ -n "${EB_TMP:-}" ]] && rm -f "$EB_TMP"' EXIT


#!/usr/bin/env bash
# ===========================================================
# EdgeBox Uninstall (idempotent, verbose)  —  with cache-busting rollback
# ===========================================================
set -Eeuo pipefail

# ---------- UI helpers ----------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
skip() { echo -e "  ${YELLOW}↷ 跳过${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }
hr()   { echo -e "${CYAN}------------------------------------------------------------${NC}"; }

title(){ echo -e "\n${CYAN}==> $*${NC}"; }

has_cmd(){ command -v "$1" >/dev/null 2>&1; }

# ---------- Small utils ----------
systemd_safe(){
  local action="${1:-}"; shift || true
  local unit="${1:-}"; shift || true
  if ! has_cmd systemctl; then return 0; fi
  systemctl "${action}" "${unit}" >/dev/null 2>&1 || true
}

list_listeners(){
  has_cmd ss || return 0
  ss -lntup 2>/dev/null | egrep ':(443|2053|11443|10085|10086)\b' || true
}

kill_listeners(){
  has_cmd ss || return 0
  local ports="443 2053 11443 10085 10086"
  for p in $ports; do
    # tcp
    ss -lntup 2>/dev/null \
      | awk -v P=":$p" '$4 ~ P {print $NF}' \
      | sed -E 's#.*/([0-9]+)\).*/\1#\1#' \
      | sort -u | xargs -r kill -9 2>/dev/null || true
    # udp
    ss -lnuap 2>/dev/null \
      | awk -v P=":$p" '$5 ~ P {print $NF}' \
      | sed -E 's#.*/([0-9]+)\).*/\1#\1#' \
      | sort -u | xargs -r kill -9 2>/dev/null || true
  done
}

remove_paths(){
  local any=0
  for p in "$@"; do
    [[ -z "${p}" ]] && continue
    if [[ -e "$p" || -L "$p" ]]; then
      rm -rf -- "$p" && ok "已删除：$p" && any=1
    else
      skip "不存在：$p"
    fi
  done
  ((any==0)) && true
}

purge_cron_edgebox(){
  crontab -l 2>/dev/null \
    | sed -e '/edgebox\/scripts\/dashboard-backend\.sh/d' \
          -e '/edgebox\/scripts\/traffic-collector\.sh/d' \
          -e '/edgebox\/scripts\/traffic-alert\.sh/d' \
          -e ':/usr/local/bin/edgebox-ipq\.sh:d' \
    | crontab - 2>/dev/null || true
  ok "已清理相关 crontab"
}

nft_cleanup(){
  if has_cmd nft && nft list table inet edgebox >/dev/null 2>&1; then
    info "删除 nftables 表 inet edgebox ..."
    nft flush table inet edgebox 2>/dev/null || true
    nft delete table inet edgebox 2>/dev/null || true
    ok "nftables: 已清理 inet edgebox"
  else
    skip "nftables: 未检测到 inet edgebox 表"
  fi
}

restore_kernel_tuning(){
  local SCTL="/etc/sysctl.conf" LIMS="/etc/security/limits.conf"
  local SCTL_BAK="${SCTL}.bak" LIMS_BAK="${LIMS}.bak"
  [[ -f "$SCTL_BAK" ]] && install -m 0644 -T "$SCTL_BAK" "$SCTL" && ok "已回滚 $SCTL" || true
  [[ -f "$LIMS_BAK" ]] && install -m 0644 -T "$LIMS_BAK" "$LIMS" && ok "已回滚 $LIMS" || true
  has_cmd sysctl && sysctl -p >/dev/null 2>&1 || true
}

restore_nginx(){
  if has_cmd nginx; then
    # 恢复站点/配置备份（若存在）
    for f in /etc/nginx/nginx.conf /etc/nginx/conf.d/edgebox.conf; do
      [[ -f "${f}.bak" ]] && install -m 0644 -T "${f}.bak" "$f" && ok "已回滚 $f"
    done
    nginx -t && systemd_safe reload nginx || true
  else
    skip "未安装 nginx"
  fi
}

# ---------- Cache-busting rollback (HTML ?v=VERSION 清理) ----------
# 你的前端根目录（如有环境变量 WEB_ROOT 将优先使用）
PANEL_ROOT="${WEB_ROOT:-/var/www/html}"

# 入口页（有 <link>/<script> 的页面）；按需追加更多路径
HTML_FILES=(
  "${PANEL_ROOT}/index.html"
  "${PANEL_ROOT}/panel/index.html"
)

# 要剥离 ?v= 的资源（正则，包含常见路径）
ASSETS_REGEX='(app\.css|app\.js|assets/[A-Za-z0-9._-]+\.css|assets/[A-Za-z0-9._-]+\.js|static/[A-Za-z0-9/_.-]+\.css|static/[A-Za-z0-9/_.-]+\.js)'

strip_file_version_from_html() {
  local f="$1"
  [[ -f "$f" ]] || { skip "HTML 不存在：$f"; return 0; }

  # 1) 清理目标资源后的 ?v=xxx
  sed -E -i "s#(${ASSETS_REGEX})\\?v=[^\"')]+#\\1#g" "$f"

  # 2) 移除我们可能注入过的热点修复样式（如 id="hotfix-whitelist-*"）
  sed -E -i '/<style[^>]*id="hotfix-whitelist[^"]*"[^>]*>/I,/<\/style>/Id' "$f"

  ok "已剥离版本号/热修样式：$f"
}

uninstall_cache_busting() {
  title "回滚前端 cache-busting（移除 ?v=VERSION）"
  local found=0
  for f in "${HTML_FILES[@]}"; do
    if [[ -f "${f}.bak" ]]; then
      install -m 0644 -T "${f}.bak" "$f" && ok "已还原备份：${f}.bak -> ${f}"
      found=1
    elif [[ -f "$f" ]]; then
      strip_file_version_from_html "$f"
      found=1
    fi
  done
  ((found==0)) && skip "未发现入口 HTML，跳过 cache-busting 回滚"
}

# 可选：卸载时顺带删静态目录，重装再铺（防旧文件残留）
clean_static_dirs(){
  local root="${PANEL_ROOT}"
  remove_paths "${root}/assets" "${root}/static"
}

# ---------- Main ----------
main(){
  title "停止并禁用相关服务"
  for s in xray sing-box nginx; do
    systemd_safe stop "$s"
    systemd_safe disable "$s"
  done
  hr

  title "强制释放端口（443/2053/11443/10085/10086）"
  list_listeners || true
  kill_listeners || true
  hr

  title "删除程序/配置/数据文件"
  # 按你的实际安装路径增减
  remove_paths \
    /usr/local/bin/edgebox-ipq.sh \
    /usr/local/bin/edgeboxctl \
    /etc/edgebox \
    /etc/xray /usr/local/etc/xray \
    /etc/sing-box /usr/local/etc/sing-box \
    /var/log/edgebox \
    /var/lib/edgebox
  hr

  title "删除 Web 资源与链接（/status, /traffic, 日志）"
  WEB_ROOT="${PANEL_ROOT}"
  WEB_STATUS_LINK="${WEB_ROOT}/status"
  WEB_STATUS_PHY="/var/www/edgebox-status"
  TRAFFIC_LINK="${WEB_ROOT}/traffic"
  TRAFFIC_DIR="/var/www/edgebox-traffic"
  LOG_DIR="${WEB_ROOT}/logs"
  INSTALL_LOG="/var/log/edgebox-install.log"
  remove_paths "$WEB_STATUS_LINK" "$WEB_STATUS_PHY" "$TRAFFIC_LINK" "$TRAFFIC_DIR" "$LOG_DIR" "$INSTALL_LOG"
  hr

  # ★★ 版本号清理（HTML 中去除 ?v=...） ★★
  uninstall_cache_busting
  # ★★ 如要更干净，顺带删除静态目录（可注释） ★★
  clean_static_dirs
  hr

  title "清理 crontab / nftables / 内核参数 回滚"
  purge_cron_edgebox
  nft_cleanup
  restore_kernel_tuning
  hr

  title "回滚 nginx 配置并重载"
  restore_nginx
  hr

  title "残留检查"
  local leftovers=()
  for p in /etc/edgebox /etc/xray /usr/local/etc/xray /etc/sing-box /usr/local/etc/sing-box /var/www/edgebox-*; do
    [[ -e "$p" ]] && leftovers+=("$p")
  done
  if ((${#leftovers[@]}==0)); then
    ok "系统已清理完成。"
  else
    echo -e "\n${YELLOW}⚠️ 卸载完成（存在残留或运行中的服务）。${NC}"
    printf '  残留路径：\n'; printf '    - %s\n' "${leftovers[@]}"
  fi

  echo "下一步建议："
  echo "  1) 若要立刻重装，可直接运行你的安装命令（幂等安装）。"
  echo "  2) 验证命令："
  echo "     - ss -lntup | egrep ':443|:2053|:11443|:10085|:10086'"
  echo "     - systemctl status xray sing-box nginx --no-pager"
  echo -e "${CYAN}============================================================${NC}"
}

main "$@"
