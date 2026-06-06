#!/usr/bin/env bash
# =====================================================================
# EdgeBox 一键卸载脚本 (v2 - 可配置恢复模式)
#
# 功能特性:
# - 交互友好: 仅需按一次 Y/y 键即可确认，无需回车。
# - 保留数据: 默认安全保留流量数据目录，避免数据丢失。
# - 清理彻底: 移除服务、配置、定时任务、工具、Web文件及链接、Nginx片段、Systemd覆盖。
# - 智能恢复(可选): 可配置 Nginx, sysctl, limits.conf 的恢复模式。
# - 安全第一: 默认仅移除 EdgeBox 修改，不恢复旧配置。不处理防火墙/DNS规则。
# =====================================================================

set -euo pipefail

# --- 配置恢复模式 (通过环境变量设置) ---
# Nginx 恢复模式:
#   cleanup (默认): 移除 EdgeBox 的 include 和 stream map 配置，尝试保留其他设置。
#   minimal: 写入一个最小化的 Nginx 默认配置。
#   stop: 停止并禁用 Nginx 服务。
#   restore: 从最新的 .bak.* 文件恢复 Nginx 配置。
#   keep: 保留当前的 Nginx 配置不变。
: "${EB_NGINX_RESTORE_MODE:=cleanup}"
# 是否恢复 sysctl.conf: yes / no (默认)
: "${EB_RESTORE_SYSCTL:=no}"
# 是否恢复 limits.conf: yes / no (默认)
: "${EB_RESTORE_LIMITS:=no}"

# --- 自动提权到 root ---
if [[ ${EUID:-0} -ne 0 ]]; then
  _EB_TMP="$(mktemp)"
  # shellcheck disable=SC2128
  cat "${BASH_SOURCE:-/proc/self/fd/0}" > "$_EB_TMP"
  chmod +x "$_EB_TMP"
  _EB_ENV_ARGS="EB_NGINX_RESTORE_MODE='${EB_NGINX_RESTORE_MODE}' "
  _EB_ENV_ARGS+="EB_RESTORE_SYSCTL='${EB_RESTORE_SYSCTL}' "
  _EB_ENV_ARGS+="EB_RESTORE_LIMITS='${EB_RESTORE_LIMITS}' "
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E EB_TMP="$_EB_TMP" bash -c "${_EB_ENV_ARGS} bash '$_EB_TMP' $*"
  else
    exec su - root -c "EB_TMP='$_EB_TMP' ${_EB_ENV_ARGS} bash '$_EB_TMP' $*"
  fi
fi
trap '[[ -n "${EB_TMP:-}" && -f "$EB_TMP" ]] && rm -f -- "$EB_TMP" || true' EXIT

# --- 颜色 & 输出函数 ---
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; CYAN="\033[36m"; NC="\033[0m"
title(){ echo -e "\n${CYAN}==> $1${NC}"; }
ok(){ echo -e "${GREEN}✔ $1${NC}"; }
warn(){ echo -e "${YELLOW}⚠ $1${NC}"; }
err(){ echo -e "${RED}✘ $1${NC}"; }
hr(){ echo -e "${BLUE}------------------------------------------------------------${NC}"; }

# --- 工具函数 ---
systemd_safe(){
  local action="$1"; shift || true
  for service in "$@"; do
    [[ -z "${service:-}" ]] && continue
    # v4.7.0 修复: list-unit-files|grep -q 在 set -o pipefail 下会因 grep 提前退出触发 SIGPIPE 误判，
    #   可能漏掉本应停止/禁用的服务。改用 systemctl cat（无管道，单元存在返回 0）。
    if systemctl cat "${service}.service" >/dev/null 2>&1; then
      systemctl "$action" "$service" >/dev/null 2>&1 || true
    fi
  done
}

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

detect_web_root(){
  local candidates=(/var/www/html /usr/share/nginx/html)
  local dir
  for dir in "${candidates[@]}"; do
    if [[ -d "$dir" ]]; then
      echo "$dir"
      return
    fi
  done
  echo "/var/www/html"
}

detect_traffic_real_path(){
    local link_target=""
    # 优先检查 /var/www/html/traffic 是否是链接
    if [[ -L /var/www/html/traffic ]]; then
        link_target=$(readlink -f /var/www/html/traffic 2>/dev/null)
        if [[ -n "$link_target" && -d "$link_target" ]]; then
            echo "$link_target"
            return 0
        fi
    fi
    # 其次检查 /etc/edgebox/traffic 是否存在且是目录 (可能不是链接的目标)
    if [[ -d /etc/edgebox/traffic ]]; then
        echo "/etc/edgebox/traffic"
        return 0
    fi
    # 再次检查 /var/www/edgebox-traffic (旧版本兼容)
    if [[ -d /var/www/edgebox-traffic ]]; then
         echo "/var/www/edgebox-traffic"
         return 0
    fi
    # 最后检查链接指向的目录是否在 /etc/edgebox 下 (防止误删其他目录)
    if [[ -n "$link_target" && "$link_target" == /etc/edgebox/* && -d "$link_target" ]]; then
        echo "$link_target"
        return 0
    fi
    echo "" # 未找到则返回空
}

# --- 卸载流程函数 ---

run_pre_checks_and_confirm(){
  local traffic_path
  traffic_path="$(detect_traffic_real_path)"
  [[ -z "$traffic_path" ]] && traffic_path="(未检测到)"

  echo -e "${YELLOW}本操作将从您的系统中卸载 EdgeBox 及其相关组件。${NC}"
  echo
  echo -e "将执行以下操作:"
  echo -e "  - ${RED}停止并禁用${NC} Nginx(根据选项), Xray, sing-box, edgebox-init, edgebox-reverse-ssh 服务。"
  echo -e "  - ${RED}移除${NC} systemd 单元文件、覆盖配置、crontab 定时任务和 edgeboxctl 等工具。"
  echo -e "  - ${RED}删除${NC} EdgeBox 的配置文件、日志、Web 资产文件、Nginx 片段及相关链接。"
  echo -e "  - ${YELLOW}默认仅清理${NC} Nginx, sysctl, limits.conf 中 EdgeBox 添加的部分。"
  echo
  echo -e "为保护您的数据，以下内容将${GREEN}被保留${NC}:"
  echo -e "  - ✅ 流量统计数据目录 (${YELLOW}${traffic_path}${NC})"
  echo
  echo -e "为保障您的服务器安全，以下内容将${YELLOW}不会被修改${NC}:"
  echo -e "  - 🛡️ 防火墙 (ufw, firewalld) 规则。"
  echo -e "  - 🛡️ DNS 配置 (/etc/resolv.conf, /etc/systemd/resolved.conf)。"
  echo
  echo -e "恢复选项 (当前设置):"
  echo -e "  - Nginx 恢复模式: ${CYAN}${EB_NGINX_RESTORE_MODE}${NC}"
  echo -e "  - 恢复 sysctl.conf 备份: ${CYAN}${EB_RESTORE_SYSCTL}${NC}"
  echo -e "  - 恢复 limits.conf 备份: ${CYAN}${EB_RESTORE_LIMITS}${NC}"
  echo -e "  (可通过环境变量 EB_NGINX_RESTORE_MODE, EB_RESTORE_SYSCTL, EB_RESTORE_LIMITS 修改)"
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

stop_and_disable_services(){
  title "正在停止并禁用 EdgeBox 相关服务..."
  # 停止并禁用 EdgeBox 自身的服务
  systemd_safe stop edgebox-init edgebox-reverse-ssh xray sing-box
  systemd_safe disable edgebox-init edgebox-reverse-ssh xray sing-box
  ok "已处理 edgebox-init, edgebox-reverse-ssh, xray, sing-box 服务。"

  # 根据 Nginx 恢复模式处理 Nginx
  case "$EB_NGINX_RESTORE_MODE" in
    stop)
      systemd_safe stop nginx
      systemd_safe disable nginx
      ok "已停止并禁用 Nginx 服务。"
      ;;
    keep|cleanup|minimal|restore)
      systemd_safe stop nginx
      ok "已停止 Nginx 服务 (稍后将根据模式 ${EB_NGINX_RESTORE_MODE} 处理)。"
      ;;
    *)
      warn "未知的 Nginx 恢复模式 '$EB_NGINX_RESTORE_MODE'，仅停止 Nginx。"
      systemd_safe stop nginx
      ;;
  esac
}

remove_system_integration(){
  title "正在移除系统集成组件..."
  # 移除 systemd 单元文件和覆盖配置
  remove_paths /etc/systemd/system/xray.service \
               /etc/systemd/system/sing-box.service \
               /etc/systemd/system/edgebox-init.service \
               /etc/systemd/system/edgebox-reverse-ssh.service \
               /etc/systemd/system/nginx.service.d/edgebox-deps.conf \
               /etc/systemd/system/nginx.service.d # 清理目录本身
  systemctl daemon-reload >/dev/null 2>&1 || true
  ok "Systemd 配置已重载。"

  # 清理 crontab
  if command -v crontab >/dev/null 2>&1; then
    ( crontab -l 2>/dev/null | grep -vE '(/etc/edgebox/|\bedgebox\b|\bEdgeBox\b|edgebox-ipq\.sh)' ) | crontab - 2>/dev/null || true
    ok "Crontab 定时任务已清理。"
  else
    warn "未找到 crontab 命令，跳过定时任务清理。"
  fi

  # 移除可执行文件和 geo data
  remove_paths /usr/local/bin/edgeboxctl \
               /usr/local/bin/edgebox-ipq.sh \
               /usr/local/bin/xray \
               /usr/local/bin/sing-box \
               /usr/local/share/geoip.dat \
               /usr/local/share/geosite.dat

  # 移除 certbot 钩子
  remove_paths /etc/letsencrypt/renewal-hooks/deploy/edgebox-reload.sh
}

clean_filesystem(){
  title "正在清理文件系统（将保留流量数据）..."
  local WEB_ROOT TRAFFIC_REAL_PATH
  WEB_ROOT="$(detect_web_root)"
  TRAFFIC_REAL_PATH="$(detect_traffic_real_path)"

  # 清理 /etc/edgebox，但保留流量数据目录和其内容
  if [[ -d /etc/edgebox ]]; then
    shopt -s dotglob nullglob
    for item in /etc/edgebox/*; do
      # 如果当前项是真实的流量数据目录，则跳过
      if [[ -n "$TRAFFIC_REAL_PATH" && "$item" == "$TRAFFIC_REAL_PATH" ]]; then
        ok "保留流量数据目录: $item"
        continue
      fi
      # 移除其他所有文件和目录
      rm -rf -- "$item"
      ok "已移除: $item"
    done
    shopt -u dotglob nullglob
    # 检查 /etc/edgebox 目录是否为空，如果为空则删除 (如果流量目录不在里面)
    if [[ "$TRAFFIC_REAL_PATH" != "/etc/edgebox" && -z "$(ls -A /etc/edgebox)" ]]; then
       rmdir /etc/edgebox 2>/dev/null && ok "已移除空目录: /etc/edgebox" || true
    fi
    ok "已清理 /etc/edgebox/ 目录（保留流量数据）。"
  fi

  # 清理其他相关配置/数据目录
  remove_paths /etc/xray /usr/local/etc/xray \
               /etc/sing-box /usr/local/etc/sing-box \
               /var/lib/edgebox \
               /etc/msmtprc # Email config

  # 清理 Nginx 片段
  remove_paths /etc/nginx/conf.d/edgebox_passcode.conf \
               /etc/nginx/conf.d/edgebox_stream_map.conf

  # 清理 Web 目录下的链接和残留文件
  remove_paths "${WEB_ROOT}/status" "${WEB_ROOT}/traffic" \
               "${WEB_ROOT}/favicon.ico" \
               "${WEB_ROOT}/share"
  # 使用通配符清理 sub-<token> 链接
  find "$WEB_ROOT" -maxdepth 1 -type l -name 'sub-*' -exec rm -f {} \; 2>/dev/null || true
  ok "已清理 Web 目录下的 EdgeBox 相关链接和文件。"
  remove_paths "/var/www/edgebox/status" # 清理 IPQ 数据目录

  # v4.7.0: 清理 health monitor 运行态（/run 为 tmpfs，重启即清，但仍主动移除）
  remove_paths /run/edgebox

  # 清理日志文件 (更全面)
  remove_paths /var/log/edgebox \
               /var/log/xray \
               /var/log/msmtp.log \
               /var/log/edgebox-*.log # 通配符匹配

  # 清理流量目录中的前端页面与样式文件（保留数据）
  if [[ -n "$TRAFFIC_REAL_PATH" && -d "$TRAFFIC_REAL_PATH" ]]; then
    # 清理非数据文件/目录
    find "$TRAFFIC_REAL_PATH" -mindepth 1 -maxdepth 1 \
        ! -name 'logs' ! -name '.state' ! -name 'alert.*' \
        -exec rm -rf {} \; 2>/dev/null || true
    ok "已清理流量目录中的前端页面与脚本（保留 logs, .state, alert.*）。"
  fi
}

restore_system_configs(){
  title "正在恢复/清理系统配置..."

  # --- 处理 Nginx ---
  local nginx_conf="/etc/nginx/nginx.conf"
  local latest_nginx_bak
  latest_nginx_bak="$(ls -t /etc/nginx/nginx.conf.bak.* 2>/dev/null | head -n1 || true)"

  case "$EB_NGINX_RESTORE_MODE" in
    restore)
      if [[ -f "$latest_nginx_bak" ]]; then
        cp -f "$latest_nginx_bak" "$nginx_conf"
        ok "已从 $latest_nginx_bak 恢复 Nginx 配置。"
        systemctl restart nginx >/dev/null 2>&1 || warn "Nginx 重启失败。"
      else
        warn "未找到 Nginx 备份 ($latest_nginx_bak)，执行 cleanup 操作。"
        # Fallback to cleanup
        sed -i '/# EdgeBox Nginx 配置文件/,+1d' "$nginx_conf" 2>/dev/null || true # 移除标记行
        sed -i '/include \/etc\/nginx\/conf\.d\/edgebox_passcode\.conf;/d' "$nginx_conf" 2>/dev/null || true
        sed -i '/stream {/,/}/ { /include \/etc\/nginx\/conf\.d\/edgebox_stream_map\.conf;/d; }' "$nginx_conf" 2>/dev/null || true
        # 移除 stream {} 块如果它是由 EdgeBox 添加的 (需要更智能的判断，或假定是)
        # 简化：仅移除 include，保留 stream 块
        systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || warn "Nginx 重载/重启失败。"
        ok "已尝试清理 Nginx 配置中的 EdgeBox 相关 include。"
      fi
      ;;
    minimal)
      cat > "$nginx_conf" <<'NGINX_MINIMAL_CONFIG'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
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
    index index.html index.htm;
    location / { try_files $uri $uri/ =404; }
  }
}
NGINX_MINIMAL_CONFIG
      ok "已写入最小化的 Nginx 默认配置。"
      systemctl restart nginx >/dev/null 2>&1 || warn "Nginx 重启失败。"
      ;;
    stop)
      ok "Nginx 服务已在先前步骤停止并禁用。"
      # 不需要重启
      ;;
    keep)
      ok "保留当前 Nginx 配置。"
      # 尝试重载以防万一有未清理的引用
      systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || warn "Nginx 重载/重启失败。"
      ;;
    cleanup|*) # Default cleanup
      if [[ -f "$nginx_conf" ]]; then
         # 移除 EdgeBox 添加的标记行和 includes
        sed -i '/# EdgeBox Nginx 配置文件/d' "$nginx_conf" 2>/dev/null || true
        sed -i '/include \/etc\/nginx\/conf\.d\/edgebox_passcode\.conf;/d' "$nginx_conf" 2>/dev/null || true
        sed -i '/include \/etc\/nginx\/conf\.d\/edgebox_stream_map\.conf;/d' "$nginx_conf" 2>/dev/null || true
        # 尝试重载/重启
        systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || warn "Nginx 重载/重启失败。"
        ok "已尝试清理 Nginx 配置中的 EdgeBox 相关 include。"
      else
         warn "Nginx 配置文件不存在，无需清理。"
      fi
      ;;
  esac

  # --- 处理 sysctl.conf ---
  local sysctl_conf="/etc/sysctl.conf"
  if [[ "$EB_RESTORE_SYSCTL" == "yes" ]]; then
    if [[ -f /etc/sysctl.conf.bak ]]; then
      cp -f /etc/sysctl.conf.bak "$sysctl_conf"
      sysctl -p >/dev/null 2>&1 || true
      ok "已从 /etc/sysctl.conf.bak 恢复内核参数。"
    else
      warn "未找到 sysctl.conf 备份，执行清理操作。"
      # Fallback to cleanup
      sed -i '/# EdgeBox 网络优化参数/,/vm\.dirty_ratio = 15/d' "$sysctl_conf" 2>/dev/null || true
      sysctl -p >/dev/null 2>&1 || true
      ok "已尝试移除 sysctl.conf 中的 EdgeBox 优化参数。"
    fi
  else # Default cleanup
     if [[ -f "$sysctl_conf" ]]; then
       sed -i '/# EdgeBox 网络优化参数/,/vm\.dirty_ratio = 15/d' "$sysctl_conf" 2>/dev/null || true
       sysctl -p >/dev/null 2>&1 || true
       ok "已尝试移除 sysctl.conf 中的 EdgeBox 优化参数。"
     fi
  fi

  # --- 处理 limits.conf ---
  local limits_conf="/etc/security/limits.conf"
  if [[ "$EB_RESTORE_LIMITS" == "yes" ]]; then
    if [[ -f /etc/security/limits.conf.bak ]]; then
      cp -f /etc/security/limits.conf.bak "$limits_conf"
      ok "已从 /etc/security/limits.conf.bak 恢复文件描述符限制。"
    else
      warn "未找到 limits.conf 备份，执行清理操作。"
      # Fallback to cleanup
      sed -i '/# EdgeBox 文件描述符限制优化/,/root hard nofile 1000000/d' "$limits_conf" 2>/dev/null || true
      ok "已尝试移除 limits.conf 中的 EdgeBox 优化参数。"
    fi
  else # Default cleanup
    if [[ -f "$limits_conf" ]]; then
      sed -i '/# EdgeBox 文件描述符限制优化/,/root hard nofile 1000000/d' "$limits_conf" 2>/dev/null || true
      ok "已尝试移除 limits.conf 中的 EdgeBox 优化参数。"
    fi
  fi
}

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
  # 明确告知用户防火墙/DNS规则未动
  warn "防火墙规则未被修改。请根据需要手动检查并清理 EdgeBox 相关规则。"
  warn "DNS 配置未被修改。请根据需要手动检查。"
}

print_final_summary(){
  local TRAFFIC_REAL_PATH
  TRAFFIC_REAL_PATH="$(detect_traffic_real_path)"
  hr
  title "EdgeBox 卸载完成"
  echo -e "所有 EdgeBox 相关服务、配置和工具均已移除。"
  echo -e "系统配置 (Nginx, sysctl, limits.conf) 已按模式 ${CYAN}${EB_NGINX_RESTORE_MODE}, ${EB_RESTORE_SYSCTL}, ${EB_RESTORE_LIMITS}${NC} 处理。"
  if [[ -n "$TRAFFIC_REAL_PATH" && -d "$TRAFFIC_REAL_PATH" ]]; then
    echo -e "${GREEN}✔ 已成功保留您的流量数据，位于: ${TRAFFIC_REAL_PATH}${NC}"
  else
    echo -e "${YELLOW}ℹ 未检测到或无法识别流量数据目录，无可保留的数据。${NC}"
  fi
  echo -e "${YELLOW}提醒:${NC} 防火墙规则和 DNS 配置未修改，请按需手动检查。"
  echo -e "建议您重启服务器以确保所有更改完全生效。"
  hr
}

# --- 主执行逻辑 ---
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

main "$@"
