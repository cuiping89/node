#!/usr/bin/env bash
# =====================================================================
# EdgeBox 一键卸载脚本（最终通用版）
# - 仅交互一次：按下 Y/y 立即继续（无需回车）；其它键取消
# - 默认保留【流量数据目录】（/etc/edgebox/traffic 或由 /var/www/html/traffic 指向的真实目录）
# - 清除 Web 端“样式/页面/链接”残留（删除 HTML/CSS/JS 与 /status、/traffic 链接）
# - 停止并禁用 EdgeBox 相关服务，移除 systemd 单元、定时任务、工具脚本
# - 恢复 Nginx 原始配置（如存在 /etc/nginx/nginx.conf.bak.* 备份）
# - 还原/清理 EdgeBox 专用 nftables 计数表
# - 若安装脚本优化过 sysctl，存在备份则恢复
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
# 退出时清理临时副本
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
  local act="$1"; shift || true
  for s in "$@"; do
    [[ -z "${s:-}" ]] && continue
    if systemctl list-unit-files | grep -qE "^${s}\.service"; then
      systemctl "$act" "$s" >/dev/null 2>&1 || true
    fi
  done
}

remove_paths(){ # 安全 rm -rf（仅在目标存在时）
  local p
  for p in "$@"; do
    [[ -z "${p:-}" ]] && continue
    if [[ -L "$p" || -e "$p" ]]; then
      rm -rf -- "$p" 2>/dev/null || true
      ok "removed: $p"
    fi
  done
}

detect_panel_root(){
  if [[ -n "${PANEL_ROOT:-}" && -d "$PANEL_ROOT" ]]; then
    echo "$PANEL_ROOT"; return
  fi
  local cands=(/var/www/html /usr/share/nginx/html)
  local d; for d in "${cands[@]}"; do [[ -d "$d" ]] && { echo "$d"; return; }; done
  echo "/var/www/html"
}

# 返回真实“流量数据目录”（若无则返回空串）
detect_traffic_real(){
  if [[ -L /var/www/html/traffic ]]; then
    readlink -f /var/www/html/traffic 2>/dev/null && return 0
  fi
  [[ -d /etc/edgebox/traffic ]] && { echo /etc/edgebox/traffic; return 0; }
  [[ -d /var/www/edgebox-traffic ]] && { echo /var/www/edgebox-traffic; return 0; }
  echo ""
}

# 读取单个按键（Y/y 继续），无需回车
confirm_once(){
  echo -e "${YELLOW}本操作将卸载 EdgeBox：${NC}"
  echo -e "${YELLOW}- 停止并禁用相关服务，移除 systemd 单元与定时任务${NC}"
  echo -e "${YELLOW}- 恢复 Nginx 配置与 Web 链接，清除页面/样式残留${NC}"
  echo -e "${YELLOW}- 【保留】流量数据目录（JSON/CSV/DB等数据文件）${NC}"
  echo -ne "确认继续？按 ${GREEN}Y${NC}/${GREEN}y${NC} 立即执行（任意其它键取消）："
  # shellcheck disable=SC2162
  read -r -n 1 ans || true
  echo
  if [[ ! "${ans:-}" =~ ^[Yy]$ ]]; then
    echo "已取消。"; exit 0
  fi
}

# --- 主逻辑 -----------------------------------------------------------
main(){
  confirm_once
  hr

  local WEB_ROOT TRAFFIC_REAL
  WEB_ROOT="$(detect_panel_root)"
  TRAFFIC_REAL="$(detect_traffic_real)"

  title "停止并禁用 EdgeBox 相关服务"
  systemd_safe stop xray sing-box edgebox-init
  systemd_safe disable xray sing-box edgebox-init
  ok "已尝试停止/禁用 xray、sing-box、edgebox-init（如存在）。"
  hr

  title "移除 systemd 单元文件并重载"
  remove_paths /etc/systemd/system/xray.service \
               /etc/systemd/system/sing-box.service \
               /etc/systemd/system/edgebox-init.service
  systemctl daemon-reload >/dev/null 2>&1 || true
  ok "systemd 已重载。"
  hr

  title "清理 crontab 中的 EdgeBox 相关定时任务"
  # 过滤掉包含 /etc/edgebox 或 edgebox 关键字的行（含 edgebox-ipq.sh）
  if command -v crontab >/dev/null 2>&1; then
    ( crontab -l 2>/dev/null | grep -vE '(/etc/edgebox/|\bedgebox\b|\bEdgeBox\b)' ) | crontab - 2>/dev/null || true
    ok "crontab 规则已清理。"
  else
    warn "系统未安装 crontab，跳过。"
  fi
  hr

  title "删除工具与配置（保留流量数据目录）"
  # 工具
  remove_paths /usr/local/bin/edgeboxctl /usr/local/bin/edgebox-ipq.sh

  # /etc/edgebox 下仅保留流量数据目录，删除其余内容
  if [[ -d /etc/edgebox ]]; then
    shopt -s dotglob nullglob
    for p in /etc/edgebox/*; do
      if [[ -n "$TRAFFIC_REAL" && "$p" == "$TRAFFIC_REAL" ]]; then continue; fi
      if [[ "$p" == "/etc/edgebox/traffic" && -n "$TRAFFIC_REAL" && "$TRAFFIC_REAL" != "/etc/edgebox/traffic" ]]; then
        # 若真实目录不在 /etc/edgebox/traffic，则可以安全删除这个目录（通常是陈旧或空壳）
        rm -rf -- "$p" 2>/dev/null || true
        continue
      fi
      rm -rf -- "$p" 2>/dev/null || true
    done
    ok "已清理 /etc/edgebox（保留：${TRAFFIC_REAL:-无}）。"
  fi

  # 删除其它典型配置/状态目录
  remove_paths /etc/xray /usr/local/etc/xray \
               /etc/sing-box /usr/local/etc/sing-box \
               /var/lib/edgebox \
               /var/log/edgebox /var/log/edgebox-install.log /var/log/edgebox-traffic-alert.log
  hr

  title "恢复 Nginx & 清理 Web 残留（避免样式/页面残留）"
  local WEB_STATUS_LINK="${WEB_ROOT}/status"
  local WEB_STATUS_PHY="/var/www/edgebox/status"
  local TRAFFIC_LINK="${WEB_ROOT}/traffic"
  local TRAFFIC_DIR="/var/www/edgebox-traffic"
  local WEB_LOGS="${WEB_ROOT}/logs"

  # 1) 移除对外链接
  remove_paths "$WEB_STATUS_LINK" "$TRAFFIC_LINK" "$WEB_LOGS"

  # 2) 移除状态页物理目录
  remove_paths "$WEB_STATUS_PHY"

  # 3) 若存在旧版物理 traffic 目录且不是“真实数据目录”，则删除（避免重复/残留）
  if [[ -d "$TRAFFIC_DIR" && ( -z "$TRAFFIC_REAL" || "$TRAFFIC_REAL" != "$TRAFFIC_DIR" ) ]]; then
    rm -rf -- "$TRAFFIC_DIR" 2>/dev/null || true
    ok "已删除旧版 Web 物理目录：$TRAFFIC_DIR"
  fi

  # 4) 在“真实数据目录”内，移除前端样式/页面文件，仅保留数据（json/csv/db等）
  if [[ -n "$TRAFFIC_REAL" && -d "$TRAFFIC_REAL" ]]; then
    find "$TRAFFIC_REAL" -maxdepth 1 -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name 'index.html' \) -print -exec rm -f {} \; 2>/dev/null || true
    # 常见样式目录
    rm -rf -- "${TRAFFIC_REAL}/assets" 2>/dev/null || true
    ok "已清除 ${TRAFFIC_REAL} 内的 HTML/CSS/JS/资产文件，保留数据文件。"
  else
    warn "未检测到可保留的流量数据目录（可能之前未初始化流量模块）。"
  fi

  # 5) 恢复 Nginx 备份（若存在）并重载
  if [[ -f /etc/nginx/nginx.conf ]]; then
    # 优先恢复最新的 *.bak.* 备份
    local latest_bak
    latest_bak="$(ls -t /etc/nginx/nginx.conf.bak.* 2>/dev/null | head -n1 || true)"
    if [[ -n "$latest_bak" && -f "$latest_bak" ]]; then
      cp -f "$latest_bak" /etc/nginx/nginx.conf
      ok "已恢复 Nginx 配置：$latest_bak → /etc/nginx/nginx.conf"
      systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
    else
      # 若不存在备份但当前配置包含 EdgeBox 标记，则写入一份最小默认配置
      if grep -q 'EdgeBox Nginx 配置文件' /etc/nginx/nginx.conf 2>/dev/null; then
        cat > /etc/nginx/nginx.conf <<'NGINX_MIN'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 1024; }
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;
  keepalive_timeout 65;
  server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/html;
    index index.html;
    location / { try_files $uri $uri/ =404; }
  }
}
NGINX_MIN
        ok "已写入最小默认 nginx.conf（因未发现备份且检测到 EdgeBox 配置标记）。"
        systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
      else
        ok "保留现有 Nginx 配置（未检测到 EdgeBox 标记或备份）。"
      fi
    fi
  fi
  hr

  title "移除 EdgeBox 专用 nftables 表（如存在）"
  if command -v nft >/dev/null 2>&1; then
    if nft list table inet edgebox >/dev/null 2>&1; then
      nft delete table inet edgebox >/dev/null 2>&1 || true
      ok "已删除 nftables: table inet edgebox"
    else
      ok "未检测到 nftables: table inet edgebox"
    fi
  else
    warn "系统无 nft 命令，跳过。"
  fi
  hr

  title "还原 sysctl（若存在安装时备份）"
  if [[ -f /etc/sysctl.conf.bak ]]; then
    cp -f /etc/sysctl.conf.bak /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true
    ok "已从 /etc/sysctl.conf.bak 还原并加载内核参数。"
  else
    ok "未发现 /etc/sysctl.conf.bak，保持现状。"
  fi
  hr

  title "卸载完成（已保留流量数据）"
  if [[ -n "$TRAFFIC_REAL" && -d "$TRAFFIC_REAL" ]]; then
    echo -e "已保留的流量数据目录：${GREEN}${TRAFFIC_REAL}${NC}"
  else
    echo -e "未检测到流量数据目录，无需保留。"
  fi
  echo -e "Web 残留：已移除 /status、/traffic 链接与样式文件；Nginx 已恢复/重载（若存在备份）。"
  hr
}

main "$@"
