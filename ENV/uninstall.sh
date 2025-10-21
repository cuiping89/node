#!/usr/bin/env bash
# =====================================================================
# EdgeBox 一键卸载脚本 (最终完善版)
#
# 功能特性:
# - 交互友好: 仅需按一次 Y/y 键即可确认，无需回车。
# - 保留数据: 默认安全保留流量数据目录，避免数据丢失。
# - 清理彻底: 移除服务、配置、定时任务、工具、Web文件及链接。
# - 智能恢复: 自动从备份恢复 Nginx, sysctl, limits.conf 配置。
# - 安全第一: 明确不处理防火墙规则，避免用户SSH失联。
# =====================================================================

# === 卸载行为开关（可通过环境变量覆盖） ===
# NGINX_RESTORE_MODE=minimal|stop|restore|keep
#  - minimal: 写入最小默认配置（建议默认）
#  - stop:    不写配置，停止服务，留给下一次安装接管
#  - restore: 若有备份才恢复；无备份不动
#  - keep:    完全不动 Nginx 主配置（不推荐）
NGINX_RESTORE_MODE="${NGINX_RESTORE_MODE:-minimal}"

# 是否恢复 sysctl / limits 的备份（yes|no），默认不恢复
RESTORE_SYSCTL="${RESTORE_SYSCTL:-no}"
RESTORE_LIMITS="${RESTORE_LIMITS:-no}"

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

# --- 颜色 & 输出函数 --------------------------------------------------
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; CYAN="\033[36m"; NC="\033[0m"
title(){ echo -e "\n${CYAN}==> $1${NC}"; }
ok(){ echo -e "${GREEN}✔ $1${NC}"; }
warn(){ echo -e "${YELLOW}⚠ $1${NC}"; }
err(){ echo -e "${RED}✘ $1${NC}"; }
hr(){ echo -e "${BLUE}------------------------------------------------------------${NC}"; }

# --- 工具函数 ---------------------------------------------------------

# 安全地停止和禁用 systemd 服务
systemd_safe(){
  local action="$1"; shift || true
  for service in "$@"; do
    [[ -z "${service:-}" ]] && continue
    # 仅当服务单元文件存在时才操作
    if systemctl list-unit-files | grep -qE "^${service}\.service"; then
      systemctl "$action" "$service" >/dev/null 2>&1 || true
    fi
  done
}

# 安全地删除文件或目录（仅在存在时操作）
remove_paths(){
  local path
  for path in "$@"; do
    [[ -z "${path:-}" ]] && continue
    if [[ -L "$path" || -e "$path" ]]; then
      rm -rf -- "$path"
      ok "已移除: $path"
    fi
  done
}

# 探测 Web 服务器根目录
detect_web_root(){
  local candidates=(/var/www/html /usr/share/nginx/html)
  local dir
  for dir in "${candidates[@]}"; do
    if [[ -d "$dir" ]]; then
      echo "$dir"
      return
    fi
  done
  echo "/var/www/html" # 默认值
}

# 探测真实的流量数据目录路径
detect_traffic_real_path(){
  if [[ -L /var/www/html/traffic ]]; then
    readlink -f /var/www/html/traffic 2>/dev/null && return 0
  fi
  # 兼容不同版本可能的位置
  for path in /etc/edgebox/traffic /var/www/edgebox-traffic; do
    if [[ -d "$path" ]]; then
      echo "$path"
      return 0
    fi
  done
  echo "" # 未找到则返回空
}

# --- 卸载流程函数 -----------------------------------------------------

# 步骤1: 预检查与用户确认
run_pre_checks_and_confirm(){
  echo -e "${YELLOW}本操作将从您的系统中卸载 EdgeBox 及其相关组件。${NC}"
  echo
  echo -e "将执行以下操作:"
  echo -e "  - ${RED}停止并禁用${NC} Nginx, Xray, sing-box 等相关服务。"
  echo -e "  - ${RED}移除${NC} systemd 单元文件、crontab 定时任务和 edgeboxctl 工具。"
  echo -e "  - ${RED}删除${NC} EdgeBox 的配置文件、日志和 Web 资产文件。"
  echo -e "  - 处理 Nginx 主配置：模式 ${GREEN}${NGINX_RESTORE_MODE}${NC}（可用 NGINX_RESTORE_MODE 覆盖）"
  echo -e "  - sysctl / limits.conf：默认${YELLOW}不恢复备份${NC}（RESTORE_SYSCTL/RESTORE_LIMITS=yes 可开启）"
  echo
  echo -e "为保护您的数据，以下内容将${GREEN}被保留${NC}:"
  echo -e "  - ✅ 流量统计数据目录 (${YELLOW}$(detect_traffic_real_path)${NC})"
  echo
  echo -e "为保障您的服务器安全，以下内容将${YELLOW}不会被修改${NC}:"
  echo -e "  - 🛡️ 防火墙 (ufw, firewalld) 规则。"
  echo
  echo -ne "确认继续？按 ${GREEN}Y${NC} 或 ${GREEN}y${NC} 键立即执行（按任意其它键取消）: "
  # shellcheck disable=SC2162
  read -r -n 1 ans || true
  echo
  if [[ ! "${ans:-}" =~ ^[Yy]$ ]]; then
    echo "操作已取消。"
    exit 0
  fi
}

# 步骤2: 停止服务
stop_and_disable_services(){
  title "正在停止并禁用 EdgeBox 相关服务..."
  systemd_safe stop nginx xray sing-box edgebox-init
  systemd_safe disable xray sing-box edgebox-init
  ok "已处理 xray, sing-box, edgebox-init 服务。"
  # Nginx 仅停止，不禁用，因为可能是系统通用服务
  systemd_safe stop nginx
  ok "已停止 Nginx 服务。"
}

# 步骤3: 移除系统集成（服务单元、定时任务、可执行文件）
remove_system_integration(){
  title "正在移除系统集成组件..."
  # 移除 systemd 单元文件
  remove_paths /etc/systemd/system/xray.service \
               /etc/systemd/system/sing-box.service \
               /etc/systemd/system/edgebox-init.service
  systemctl daemon-reload >/dev/null 2>&1 || true
  ok "Systemd 配置已重载。"

  # 清理 crontab
  if command -v crontab >/dev/null 2>&1; then
    ( crontab -l 2>/dev/null | grep -vE '(/etc/edgebox/|\bedgebox\b|\bEdgeBox\b)' ) | crontab - 2>/dev/null || true
    ok "Crontab 定时任务已清理。"
  else
    warn "未找到 crontab 命令，跳过定时任务清理。"
  fi
  
  # 移除可执行文件
  remove_paths /usr/local/bin/edgeboxctl \
               /usr/local/bin/edgebox-ipq.sh \
               /usr/local/bin/xray \
               /usr/local/bin/sing-box
}

# 步骤4: 清理文件系统
clean_filesystem(){
  title "正在清理文件系统（将保留流量数据）..."
  local WEB_ROOT TRAFFIC_REAL_PATH
  WEB_ROOT="$(detect_web_root)"
  TRAFFIC_REAL_PATH="$(detect_traffic_real_path)"

  # 清理 /etc/edgebox，但保留流量数据目录
  if [[ -d /etc/edgebox ]]; then
    shopt -s dotglob nullglob
    for item in /etc/edgebox/*; do
      if [[ -n "$TRAFFIC_REAL_PATH" && "$item" == "$TRAFFIC_REAL_PATH" ]]; then
        continue
      fi
      rm -rf -- "$item"
    done
    shopt -u dotglob nullglob
    ok "已清理 /etc/edgebox/ 目录（保留流量数据）。"
  fi

  # 清理其他相关目录
  remove_paths /etc/xray /usr/local/etc/xray \
               /etc/sing-box /usr/local/etc/sing-box \
               /var/lib/edgebox \
               /var/log/edgebox /var/log/xray \
               /var/log/edgebox-install.log /var/log/edgebox-traffic-alert.log

  # 清理 Web 目录下的链接和残留文件（补齐订阅路径）
  remove_paths "${WEB_ROOT}/status" "${WEB_ROOT}/traffic"
  # 订阅：兼容早期 /sub 与新版 /sub-<token>
  remove_paths "${WEB_ROOT}/sub"
  # 注意：glob 可能匹配不到时不报错
  for f in "${WEB_ROOT}"/sub-*; do
    [[ -e "$f" ]] && rm -f -- "$f" && ok "已移除: $f"
  done

  if [[ -n "$TRAFFIC_REAL_PATH" && -d "$TRAFFIC_REAL_PATH" ]]; then
    find "$TRAFFIC_REAL_PATH" -maxdepth 1 -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' \) -exec rm -f {} \; 2>/dev/null || true
    remove_paths "${TRAFFIC_REAL_PATH}/assets"
    ok "已清理流量目录中的前端页面与样式文件。"
  fi

  # 额外清理 EdgeBox 的 Nginx 片段（不会动你自有片段的前提：只删我们命名的文件）
  remove_paths /etc/nginx/conf.d/edgebox_stream_map.conf \
               /etc/nginx/conf.d/edgebox_passcode.conf \
               /etc/nginx/stream.d/edgebox_stream_map.conf

  # 可选：清理 EdgeBox 的邮件配置（只在识别到 EdgeBox 标记时删除，避免误删自有配置）
  if [[ -f /etc/msmtprc ]] && grep -q 'EdgeBox 邮件配置' /etc/msmtprc 2>/dev/null; then
    rm -f /etc/msmtprc && ok "已移除 EdgeBox 邮件配置 /etc/msmtprc"
  fi
  remove_paths /etc/edgebox/config/email-setup.md
}


# 步骤5: 恢复系统配置
restore_system_configs(){
  title "正在恢复系统配置..."

  # ---------- Nginx 主配置 ----------
  case "$NGINX_RESTORE_MODE" in
    restore)
      local latest_nginx_bak
      latest_nginx_bak="$(ls -t /etc/nginx/nginx.conf.bak.* 2>/dev/null | head -n1 || true)"
      if [[ -f "$latest_nginx_bak" ]]; then
        cp -f "$latest_nginx_bak" /etc/nginx/nginx.conf
        ok "已从 $latest_nginx_bak 恢复 Nginx 配置。"
      else
        ok "未找到 Nginx 备份，保持现状（不写入历史配置）。"
      fi
      ;;
    keep)
      ok "按 keep 模式：保留现有 Nginx 配置，不做改动。"
      ;;
    stop)
      systemctl stop nginx >/dev/null 2>&1 || true
      ok "按 stop 模式：已停止 Nginx 服务，不写入配置。"
      ;;
    minimal|*)
      # 仅当当前文件标记为 EdgeBox 生成 或 内容缺失时，才写最小默认配置
      if grep -q 'EdgeBox Nginx 配置文件' /etc/nginx/nginx.conf 2>/dev/null \
         || [[ ! -s /etc/nginx/nginx.conf ]]; then
        cat > /etc/nginx/nginx.conf <<'NGINX_MINIMAL_CONFIG'
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
NGINX_MINIMAL_CONFIG
        ok "已写入最小化 Nginx 默认配置（minimal）。"
      else
        ok "检测到非 EdgeBox 的现有 Nginx 配置，按 minimal 模式保持不动。"
      fi
      ;;
  esac

  # 清掉 EdgeBox 专属片段与 override（不碰用户自有片段）
  remove_paths /etc/nginx/conf.d/edgebox_stream_map.conf \
               /etc/nginx/conf.d/edgebox_passcode.conf \
               /etc/nginx/stream.d/edgebox_stream_map.conf \
               /etc/systemd/system/nginx.service.d/edgebox*.conf
  systemctl daemon-reload >/dev/null 2>&1 || true

  # 重载/重启（仅在 minimal|restore|keep 模式下尝试；stop 模式跳过）
  if [[ "$NGINX_RESTORE_MODE" != "stop" ]]; then
    systemctl reload nginx >/dev/null 2>&1 \
      || systemctl restart nginx >/dev/null 2>&1 \
      || warn "Nginx 重载/重启失败，请手动检查（先运行 'nginx -t'）。"
    ok "Nginx 服务已尝试重载。"
  fi

  # ---------- sysctl.conf ----------
  if [[ "${RESTORE_SYSCTL}" == "yes" && -f /etc/sysctl.conf.bak ]]; then
    cp -f /etc/sysctl.conf.bak /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true
    ok "已从备份恢复 sysctl.conf。"
  else
    # 只删除 EdgeBox 标记段，避免带回历史调优
    if [[ -f /etc/sysctl.conf ]]; then
      sed -i '/^# *EdgeBox .* BEGIN/,/^# *EdgeBox .* END/d' /etc/sysctl.conf || true
      sysctl -p >/dev/null 2>&1 || true
      ok "已清理 sysctl 中 EdgeBox 标记段（未恢复备份）。"
    fi
  fi

  # ---------- limits.conf ----------
  if [[ "${RESTORE_LIMITS}" == "yes" && -f /etc/security/limits.conf.bak ]]; then
    cp -f /etc/security/limits.conf.bak /etc/security/limits.conf
    ok "已从备份恢复 limits.conf。"
  else
    if [[ -f /etc/security/limits.conf ]]; then
      sed -i '/^# *EdgeBox .* BEGIN/,/^# *EdgeBox .* END/d' /etc/security/limits.conf || true
      ok "已清理 limits.conf 中 EdgeBox 标记段（未恢复备份）。"
    fi
  fi
}

# 步骤6: 清理网络配置（nftables）
remove_network_configs(){
  title "正在清理网络配置..."
  # 清理 nftables
  if command -v nft >/dev/null 2>&1; then
    if nft list table inet edgebox >/dev/null 2>&1; then
      nft delete table inet edgebox >/dev/null 2>&1 || true
      ok "已删除 nftables 表: table inet edgebox"
    else
      ok "未检测到 EdgeBox 的 nftables 表，无需清理。"
    fi
  else
    warn "未找到 nft 命令，跳过 nftables 清理。"
  fi
  # 明确告知用户防火墙规则未动
  warn "防火墙规则未被修改。请根据需要手动检查并清理 EdgeBox 相关规则。"
}

# 步骤7: 显示最终摘要
print_final_summary(){
  local TRAFFIC_REAL_PATH
  TRAFFIC_REAL_PATH="$(detect_traffic_real_path)"
  hr
  title "EdgeBox 卸载完成"
  echo -e "所有 EdgeBox 相关服务、配置和工具均已移除。"
  if [[ -n "$TRAFFIC_REAL_PATH" && -d "$TRAFFIC_REAL_PATH" ]]; then
    echo -e "${GREEN}✔ 已成功保留您的流量数据，位于: ${TRAFFIC_REAL_PATH}${NC}"
  else
    echo -e "${YELLOW}ℹ 未检测到流量数据目录，无可保留的数据。${NC}"
  fi
  echo -e "建议您重启服务器以确保所有更改完全生效。"
  hr
}

# --- 主执行逻辑 -------------------------------------------------------
main(){
  run_pre_checks_and_confirm
  hr
  stop_and_disable_services
  hr
  remove_system_integration
  hr
  clean_filesystem
  hr
  restore_system_configs
  hr
  remove_network_configs
  hr
  print_final_summary
}

# 脚本入口
main "$@"
