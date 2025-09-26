#!/usr/bin/env bash
# =====================================================================
# EdgeBox 一键卸载脚本（单次交互版：确认后卸载且保留流量数据）
# - 仅交互一次：提示输入 Y/y 才会继续
# - 默认保留“流量数据”目录；清理页面/样式/链接，避免 Web 残留
# - 尽量不破坏系统其它组件；失败不报错退出，而是尽力清理
# =====================================================================

set -euo pipefail

# --- 自动提权到 root（兼容 bash <(curl ...) 场景） -------------------
if [[ ${EUID:-0} -ne 0 ]]; then
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
# 清理临时副本
trap '[[ -n "${EB_TMP:-}" && -f "$EB_TMP" ]] && rm -f -- "$EB_TMP" || true' EXIT

# --- 颜色 & 输出 ------------------------------------------------------
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; CYAN="\033[36m"; NC="\033[0m"
title(){ echo -e "\n${CYAN}==> $*${NC}"; }
ok(){ echo -e "${GREEN}✔ $*${NC}"; }
warn(){ echo -e "${YELLOW}⚠ $*${NC}"; }
err(){ echo -e "${RED}✘ $*${NC}"; }
hr(){ echo -e "${CYAN}------------------------------------------------------------${NC}"; }

# --- 小工具 -----------------------------------------------------------
systemd_safe(){
  local act="$1"; shift
  for s in "$@"; do
    if systemctl list-unit-files | grep -qE "^${s}\.service"; then
      systemctl "$act" "$s" >/dev/null 2>&1 || true
    fi
  done
}

remove_paths(){ # 安全 rm -rf（按需列出）
  local p
  for p in "$@"; do
    [[ -z "${p:-}" ]] && continue
    if [[ -L "$p" || -e "$p" ]]; then
      rm -rf -- "$p" 2>/dev/null || true
      ok "removed: $p"
    fi
  done
}

# 猜测 Web 根；优先环境变量，其次常见路径
detect_panel_root(){
  if [[ -n "${PANEL_ROOT:-}" && -d "$PANEL_ROOT" ]]; then
    echo "$PANEL_ROOT"; return
  fi
  local cands=(/var/www/html /usr/share/nginx/html)
  local d; for d in "${cands[@]}"; do [[ -d "$d" ]] && { echo "$d"; return; }; done
  # 兜底仍返回 /var/www/html（若不存在也可创建/忽略）
  echo "/var/www/html"
}

# 识别“真实流量数据目录”，并区分“对外暴露/链接”
detect_traffic_real(){
  # 1) 若 /var/www/html/traffic 是链接，解析真实目录
  if [[ -L /var/www/html/traffic ]]; then
    readlink -f /var/www/html/traffic 2>/dev/null && return 0
  fi
  # 2) 常见真实存放路径
  [[ -d /etc/edgebox/traffic ]] && { echo /etc/edgebox/traffic; return 0; }
  [[ -d /var/www/edgebox-traffic ]] && { echo /var/www/edgebox-traffic; return 0; }
  # 3) 未找到则为空
  echo ""
}

# 确认提示（单次交互）
confirm_once(){
  echo -e "${YELLOW}本操作将卸载 EdgeBox，停止相关服务，并清理页面/样式/链接。${NC}"
  echo -e "${YELLOW}注意：流量数据文件将被【保留】。${NC}"
  read -r -p "确认继续？输入 Y 确认（y/N）: " ans
  if [[ ! "${ans:-}" =~ ^[Yy]$ ]]; then
    echo "已取消。"; exit 0
  fi
}

# --- 主逻辑 -----------------------------------------------------------
main(){
  confirm_once
  hr

  # 记录关键路径
  PANEL_ROOT="$(detect_panel_root)"
  TRAFFIC_REAL="$(detect_traffic_real)"

  title "停止并禁用相关服务"
  systemd_safe stop xray sing-box nginx
  systemd_safe disable xray sing-box nginx
  ok "已尝试停止/禁用 xray, sing-box, nginx（如存在）。"
  hr

  title "删除程序/配置（保留流量数据目录）"
  # 核心二进制/工具
  remove_paths \
    /usr/local/bin/edgeboxctl \
    /usr/local/bin/edgebox-ipq.sh

  # 配置/状态/数据库（不包含 traffic 真实目录）
  # 先处理 /etc/edgebox：仅删除除流量目录外的所有内容
  if [[ -d /etc/edgebox ]]; then
    shopt -s dotglob nullglob
    for p in /etc/edgebox/*; do
      [[ -n "$TRAFFIC_REAL" && "$p" == "$TRAFFIC_REAL" ]] && continue
      rm -rf -- "$p" 2>/dev/null || true
    done
    ok "已清理 /etc/edgebox（已保留：${TRAFFIC_REAL:-无}）。"
  fi

  # 其它典型路径
  remove_paths \
    /etc/xray /usr/local/etc/xray \
    /etc/sing-box /usr/local/etc/sing-box \
    /var/lib/edgebox \
    /var/log/edgebox

  # 如果 /etc/edgebox 现在为空目录，顺带删除（但若其本身就是 traffic 真实目录则不删）
  if [[ -d /etc/edgebox ]]; then
    if [[ -n "$TRAFFIC_REAL" && "$TRAFFIC_REAL" == "/etc/edgebox" ]]; then
      : # /etc/edgebox 自身就是流量目录，不能删
    else
      rmdir /etc/edgebox 2>/dev/null || true
    fi
  fi
  hr

  title "删除 Web 资源与链接（避免样式/页面残留）"
  WEB_ROOT="$PANEL_ROOT"
  WEB_STATUS_LINK="${WEB_ROOT}/status"
  WEB_STATUS_PHY="/var/www/edgebox-status"
  TRAFFIC_LINK="${WEB_ROOT}/traffic"
  TRAFFIC_DIR="/var/www/edgebox-traffic"
  LOG_DIR="${WEB_ROOT}/logs"
  INSTALL_LOG="/var/log/edgebox-install.log"

  # 删除状态页/日志/安装日志
  remove_paths "$WEB_STATUS_LINK" "$WEB_STATUS_PHY" "$LOG_DIR" "$INSTALL_LOG"

  # 删除 traffic 链接/对外暴露，但保留真实数据目录
  remove_paths "$TRAFFIC_LINK"

  # 若真实数据目录就是 /var/www/edgebox-traffic，则为了避免“样式残留”，
  # 我们仅删除其中可能的页面文件（index.html/css/js），保留纯数据（常见为 .json/.csv/.db 等）
  if [[ -n "$TRAFFIC_REAL" && "$TRAFFIC_REAL" == "$TRAFFIC_DIR" && -d "$TRAFFIC_DIR" ]]; then
    find "$TRAFFIC_DIR" -maxdepth 1 -type f \
      \( -name 'index.html' -o -name '*.html' -o -name '*.css' -o -name '*.js' \) \
      -print -exec rm -f {} \; 2>/dev/null || true
    ok "已移除 /var/www/edgebox-traffic 中的样式/页面文件，仅保留数据文件。"
  else
    # 如果真实目录不在 /var/www/edgebox-traffic，且该目录存在，直接删除它避免样式残留
    if [[ -d "$TRAFFIC_DIR" && "$TRAFFIC_DIR" != "$TRAFFIC_REAL" ]]; then
      rm -rf -- "$TRAFFIC_DIR" 2>/dev/null || true
      ok "已删除 /var/www/edgebox-traffic（未触碰真实数据目录：${TRAFFIC_REAL:-无}）。"
    fi
  fi
  hr

  title "关闭残留监听端口（如有）"
  # 常见端口：443(https/reality/grpc/ws)、2053(TUIC)、8443(Hysteria2)、10085/10086(示例)
  # 这里只提示，具体释放随服务停止而完成
  ss -lntup | egrep ':443|:2053|:8443|:10085|:10086' || true
  hr

  title "卸载完成（已保留流量数据）"
  echo -e "Web 残留：已移除 status/logs 以及 traffic 链接；不再有样式/页面。"
  if [[ -n "$TRAFFIC_REAL" && -d "$TRAFFIC_REAL" ]]; then
    echo -e "已保留的流量数据目录：${GREEN}${TRAFFIC_REAL}${NC}"
  else
    echo -e "未检测到可保留的流量数据目录。"
  fi
  hr

  echo "后续可执行："
  echo "  - 重新安装：直接运行你的安装脚本（幂等）。"
  echo "  - 验证服务：systemctl status xray sing-box nginx --no-pager"
}

main "$@"
