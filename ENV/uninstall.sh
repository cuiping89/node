#!/usr/bin/env bash
# EdgeBox 卸载脚本（保留彩色输出 + 自动提权 + 最小增强）
# - 默认不恢复历史配置；仅撤销 EdgeBox 改动，避免重装遇到“脏环境”
# - 可通过环境变量切换行为：
#     NGINX_RESTORE_MODE=minimal|stop|restore|keep
#     RESTORE_SYSCTL=yes|no
#     RESTORE_LIMITS=yes|no

set -euo pipefail

# ========== 自动提权（保留老板版的提权体验） ==========
if [ "${EUID:-0}" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$@"
  elif command -v su >/dev/null 2>&1; then
    exec su - -c "bash '$0' $*"
  else
    echo "✘ 请以 root 身份运行（sudo 或 su）" >&2
    exit 1
  fi
fi

# ========== 行为开关 ==========
: "${NGINX_RESTORE_MODE:=minimal}"   # minimal|stop|restore|keep
: "${RESTORE_SYSCTL:=no}"            # yes|no
: "${RESTORE_LIMITS:=no}"            # yes|no

# ========== 彩色输出 ==========
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); CYAN=$(printf '\033[36m'); BOLD=$(printf '\033[1m'); NC=$(printf '\033[0m')
title() { echo -e "\n${CYAN}${BOLD}==>${NC} ${CYAN}$*${NC}"; }
ok()    { echo -e "${GREEN}✔${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
err()   { echo -e "${RED}✘${NC} $*"; }
info()  { echo -e "[INFO] $*"; }

# （兼容你脚本里可能用到的 log_* 名称）
log_success(){ ok "$@"; }
log_warn(){ warn "$@"; }
log_error(){ err "$@"; }
log_info(){ info "$@"; }

# ========== 小工具 ==========
remove_paths() {
  local p
  for p in "$@"; do
    [[ -z "$p" ]] && continue
    if [[ -e "$p" || -L "$p" ]]; then
      rm -rf -- "$p" && ok "已移除: $p" || warn "移除失败: $p"
    fi
  done
}

detect_web_root() {
  if [[ -d /var/www/html ]]; then
    printf '%s' "/var/www/html"
  elif [[ -d /usr/share/nginx/html ]]; then
    printf '%s' "/usr/share/nginx/html"
  else
    printf '%s' "/var/www/html"
  fi
}

detect_traffic_real_path() {
  local d="/etc/edgebox/traffic"
  if [[ -L "$d" ]]; then
    readlink -f "$d" || true
  elif [[ -d "$d" ]]; then
    printf '%s' "$d"
  else
    printf '%s' ""
  fi
}

pause_confirm() {
cat <<'PLAN'
本操作将从您的系统中卸载 EdgeBox 及其相关组件。

将执行以下操作:
  - 停止并禁用 Nginx、Xray、sing-box 等相关服务。
  - 移除 systemd 单元文件、crontab 定时任务和 edgeboxctl 工具。
  - 删除 EdgeBox 的配置文件、日志和 Web 资产（含 /sub 与 /sub-<token> 软链）。
  - 清理 EdgeBox 专属 Nginx 片段与 override
    （/etc/nginx/conf.d/edgebox_*.conf、/etc/systemd/system/nginx.service.d/edgebox*.conf）。
  - 处理 Nginx 主配置（见下方模式说明）。
  - 移除 nftables 中的 table inet edgebox（不修改 ufw/firewalld 规则）。
  - （如有）移除 EdgeBox 邮件配置 /etc/msmtprc。

为保护您的数据，以下内容将被保留:
  - ✅ 流量统计数据目录 (/etc/edgebox/traffic)

为保障您的服务器安全，以下内容将不会被自动修改:
  - 🛡️ 系统防火墙（ufw、firewalld）规则
PLAN

  echo -e "Nginx 主配置处理模式：${GREEN}${NGINX_RESTORE_MODE}${NC}（可用 NGINX_RESTORE_MODE=minimal|stop|restore|keep 覆盖）"
  echo -e "sysctl / limits.conf：默认${YELLOW}不恢复备份${NC}（RESTORE_SYSCTL/RESTORE_LIMITS=yes 可开启）"
  echo
  read -r -p "确认继续？按 Y 或 y 执行（任意其它键取消）: " ans
  if [[ ! "${ans:-}" =~ ^[Yy]$ ]]; then
    warn "用户取消"
    exit 0
  fi
}

stop_disable_services() {
  title "正在停止并禁用 EdgeBox 相关服务..."
  local svcs=(xray sing-box edgebox-init)
  for s in "${svcs[@]}"; do
    systemctl stop "$s" >/dev/null 2>&1 || true
    systemctl disable "$s" >/dev/null 2>&1 || true
  done
  systemctl stop nginx >/dev/null 2>&1 || true
  ok "已处理 xray, sing-box, edgebox-init 服务。"
  ok "已停止 Nginx 服务。"
}

remove_system_integration() {
  title "正在移除系统集成组件..."
  remove_paths /etc/systemd/system/xray.service \
               /etc/systemd/system/sing-box.service \
               /etc/systemd/system/edgebox-init.service
  systemctl daemon-reload >/dev/null 2>&1 || true
  ok "Systemd 配置已重载。"

  if command -v crontab >/dev/null 2>&1 && crontab -l >/dev/null 2>&1; then
    crontab -l | sed '/edgebox\|EdgeBox/d' | crontab - || true
    ok "Crontab 定时任务已清理。"
  fi

  remove_paths /usr/local/bin/edgeboxctl /usr/local/bin/xray /usr/local/bin/sing-box
}

clean_filesystem() {
  title "正在清理文件系统（将保留流量数据）..."
  local WEB_ROOT TRAFFIC_REAL_PATH
  WEB_ROOT="$(detect_web_root)"
  TRAFFIC_REAL_PATH="$(detect_traffic_real_path)"

  # /etc/edgebox 内除流量目录外清理
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

  # 其他目录
  remove_paths /etc/xray /usr/local/etc/xray \
               /etc/sing-box /usr/local/etc/sing-box \
               /var/log/edgebox /var/log/xray \
               /var/log/edgebox-install.log /var/log/edgebox-traffic-alert.log

  # Web：状态/订阅/可视化
  remove_paths "${WEB_ROOT}/status" "${WEB_ROOT}/traffic" "${WEB_ROOT}/sub"
  for f in "${WEB_ROOT}"/sub-*; do [[ -e "$f" ]] && rm -f -- "$f" && ok "已移除: $f"; done

  # 流量目录页面文件与 assets（保留原始数据文件）
  if [[ -n "$TRAFFIC_REAL_PATH" && -d "$TRAFFIC_REAL_PATH" ]]; then
    find "$TRAFFIC_REAL_PATH" -maxdepth 1 -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' \) -exec rm -f {} \; 2>/dev/null || true
    remove_paths "${TRAFFIC_REAL_PATH}/assets"
    ok "已清理流量目录中的前端页面与样式文件。"
  fi

  # Nginx 片段与 override（只清 EdgeBox 命名）
  remove_paths /etc/nginx/conf.d/edgebox_stream_map.conf \
               /etc/nginx/conf.d/edgebox_passcode.conf \
               /etc/nginx/stream.d/edgebox_stream_map.conf \
               /etc/systemd/system/nginx.service.d/edgebox-deps.conf \
               /etc/systemd/system/nginx.service.d/edgebox*.conf
  systemctl daemon-reload >/dev/null 2>&1 || true

  # 邮件配置（带 EdgeBox 标记才删）
  if [[ -f /etc/msmtprc ]] && grep -q 'EdgeBox 邮件配置' /etc/msmtprc 2>/dev/null; then
    rm -f /etc/msmtprc && ok "已移除 EdgeBox 邮件配置 /etc/msmtprc"
  fi
  remove_paths /etc/edgebox/config/email-setup.md
}

restore_system_configs() {
  title "正在处理系统配置..."

  # ---- Nginx 主配置 ----
  case "$NGINX_RESTORE_MODE" in
    restore)
      local bak
      bak="$(ls -t /etc/nginx/nginx.conf.bak.* 2>/dev/null | head -n1 || true)"
      [[ -z "$bak" && -f /etc/nginx/nginx.conf.bak ]] && bak="/etc/nginx/nginx.conf.bak"
      if [[ -n "$bak" && -f "$bak" ]]; then
        cp -f "$bak" /etc/nginx/nginx.conf
        ok "已从备份恢复 Nginx 配置：$bak"
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
      # 仅当当前文件疑似 EdgeBox 生成或文件缺失时，写入最小默认配置
      if grep -qiE 'edgebox|edge-box' /etc/nginx/nginx.conf 2>/dev/null \
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

  # 再清一次 EdgeBox 片段与 override，确保干净
  remove_paths /etc/nginx/conf.d/edgebox_stream_map.conf \
               /etc/nginx/conf.d/edgebox_passcode.conf \
               /etc/nginx/stream.d/edgebox_stream_map.conf \
               /etc/systemd/system/nginx.service.d/edgebox-deps.conf \
               /etc/systemd/system/nginx.service.d/edgebox*.conf
  systemctl daemon-reload >/dev/null 2>&1 || true

  # reload/restart（stop 模式跳过）
  if [[ "$NGINX_RESTORE_MODE" != "stop" ]]; then
    if ! (nginx -t >/dev/null 2>&1); then
      warn "nginx -t 未通过，请检查 /etc/nginx/nginx.conf 与 conf.d 残留引用。"
    fi
    systemctl reload nginx >/dev/null 2>&1 \
      || systemctl restart nginx >/dev/null 2>&1 \
      || warn "Nginx 重载/重启失败，请手动检查（先运行 'nginx -t'）。"
    ok "Nginx 服务已尝试重载。"
  fi

  # ---- sysctl.conf ----
  if [[ "$RESTORE_SYSCTL" == "yes" && -f /etc/sysctl.conf.bak ]]; then
    cp -f /etc/sysctl.conf.bak /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true
    ok "已从备份恢复 sysctl.conf。"
  else
    if [[ -f /etc/sysctl.conf ]]; then
      sed -i '/^# *EdgeBox .* BEGIN/,/^# *EdgeBox .* END/d' /etc/sysctl.conf || true
      sysctl -p >/dev/null 2>&1 || true
      ok "已清理 sysctl 中 EdgeBox 标记段（未恢复备份）。"
    fi
  fi

  # ---- limits.conf ----
  if [[ "$RESTORE_LIMITS" == "yes" && -f /etc/security/limits.conf.bak ]]; then
    cp -f /etc/security/limits.conf.bak /etc/security/limits.conf
    ok "已从备份恢复 limits.conf。"
  else
    if [[ -f /etc/security/limits.conf ]]; then
      sed -i '/^# *EdgeBox .* BEGIN/,/^# *EdgeBox .* END/d' /etc/security/limits.conf || true
      ok "已清理 limits.conf 中 EdgeBox 标记段（未恢复备份）。"
    fi
  fi
}

clean_network_config() {
  title "正在清理网络配置..."
  if command -v nft >/dev/null 2>&1; then
    if nft list table inet edgebox >/dev/null 2>&1; then
      if nft delete table inet edgebox >/dev/null 2>&1; then
        ok "已删除 nftables 表: table inet edgebox"
      else
        warn "删除 nftables 表失败（可能已不存在）。"
      fi
    fi
  fi
  warn "防火墙规则未被自动修改。请按需手动检查并清理（ufw/firewalld）。"
}

summary() {
  echo "------------------------------------------------------------"
  title "EdgeBox 卸载完成"
  echo "所有 EdgeBox 相关服务、配置和工具均已移除。"
  if [[ -d /etc/edgebox/traffic ]]; then
    ok "已成功保留您的流量数据，位于: /etc/edgebox/traffic"
  fi
  echo "建议您重启服务器以确保所有更改完全生效。"
  echo "------------------------------------------------------------"
}

main() {
  pause_confirm
  stop_disable_services
  remove_system_integration
  clean_filesystem
  restore_system_configs
  clean_network_config
  summary
}

main "$@"
