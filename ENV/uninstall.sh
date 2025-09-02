#!/usr/bin/env bash
# ===========================================================
# EdgeBox / node —— 一键卸载与回滚脚本（幂等、无交互）
# 作用：
#  1) 停止并禁用 xray / sing-box；移除二进制与配置
#  2) 回滚 Nginx（如存在我们生成的备份则恢复）
#  3) 移除订阅文件、证书软链接、自动续期任务等
#  4) 最后做一次自检与提示
# ===========================================================

set -Eeuo pipefail

# —— 目录与文件约定（与你当前安装脚本的落地路径一致）——
INSTALL_DIR="/etc/edgebox"
CONFIG_DIR="${INSTALL_DIR}/config"
CERT_DIR="${INSTALL_DIR}/cert"
SCRIPT_DIR="${INSTALL_DIR}/scripts"

XRAY_BIN="/usr/local/bin/xray"
XRAY_SVC="/etc/systemd/system/xray.service"
XRAY_LOG_DIR="/var/log/xray"

SBOX_BIN="/usr/local/bin/sing-box"
SBOX_SVC="/etc/systemd/system/sing-box.service"

# 我们接管的 nginx 主配置（安装时会备份一份 *.bak）
NGX_MAIN="/etc/nginx/nginx.conf"
NGX_MAIN_BAK="/etc/nginx/nginx.conf.bak"
NGX_MOD_ENABLED_DIR="/etc/nginx/modules-enabled"
NGX_MOD_STREAM_LINK="${NGX_MOD_ENABLED_DIR}/50-mod-stream.conf"

# 订阅文件发布位置
SUB_FILE="/var/www/html/sub"

# 自动续期
CRON_MARK="cert-renewal.sh"
RENEW_SH="${SCRIPT_DIR}/cert-renewal.sh"
RENEW_LOG="/var/log/edgebox-renewal.log"

# —— 输出着色 —— 
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
msg()   { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }

# —— 工具函数 —— 
safe_disable_stop() {
  local svc="$1"
  if systemctl list-unit-files | grep -q "^${svc}.service"; then
    systemctl disable --now "${svc}" >/dev/null 2>&1 || true
    ok "服务已停止并禁用：${svc}"
  fi
}

safe_rm() {
  # 可传多个参数
  for p in "$@"; do
    if [[ -e "$p" || -L "$p" ]]; then
      rm -rf -- "$p" 2>/dev/null || true
      ok "已删除：$p"
    fi
  done
}

cron_purge_line_contains() {
  local mark="$1"
  local tmp
  tmp="$(mktemp)"
  crontab -l 2>/dev/null | sed "/${mark//\//\\/}/d" >"$tmp" || true
  crontab "$tmp" 2>/dev/null || true
  rm -f "$tmp"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# —— 1) 停服务与禁用 —— 
msg "停止并禁用相关服务..."
safe_disable_stop "xray"
safe_disable_stop "sing-box"

# —— 2) 移除 systemd 单元与二进制 —— 
msg "移除 systemd 单元与二进制..."
safe_rm "$XRAY_SVC" "$SBOX_SVC"
safe_rm "$XRAY_BIN" "$SBOX_BIN"
systemctl daemon-reload || true

# —— 3) 移除项目配置/证书/脚本/日志/订阅 —— 
msg "移除 EdgeBox 配置与文件..."
safe_rm "$CONFIG_DIR"              # /etc/edgebox/config
safe_rm "$SCRIPT_DIR"              # /etc/edgebox/scripts
safe_rm "$XRAY_LOG_DIR"            # /var/log/xray
safe_rm "$SUB_FILE"                # /var/www/html/sub

# 证书：只删除软链接和我们生成的自签名，不碰 /etc/letsencrypt
if [[ -d "$CERT_DIR" ]]; then
  # 仅删除 current.* 软链接与自签名，保守一些
  safe_rm "${CERT_DIR}/current.key" "${CERT_DIR}/current.pem"
  safe_rm "${CERT_DIR}/self-signed.key" "${CERT_DIR}/self-signed.pem"
  # 若目录空了，可一并移除
  rmdir "$CERT_DIR" 2>/dev/null || true
fi

# —— 4) 回滚 nginx 主配置（若有备份）并移除我们加载的 stream 模块软链 —— 
if [[ -f "$NGX_MAIN_BAK" ]]; then
  msg "检测到 nginx 备份，准备回滚..."
  cp -f "$NGX_MAIN_BAK" "$NGX_MAIN"
  ok "已回滚 nginx 主配置"
fi

if [[ -L "$NGX_MOD_STREAM_LINK" ]]; then
  safe_rm "$NGX_MOD_STREAM_LINK"
fi

# 尝试重启 nginx（若安装在系统中）
if need_cmd nginx; then
  if nginx -t >/dev/null 2>&1; then
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || true
    ok "nginx 已可用"
  else
    warn "nginx 配置自检失败：$(nginx -t 2>&1 | tail -n1)"
  fi
fi

# —— 5) 移除自动续期与相关日志 —— 
msg "清理证书自动续期任务..."
cron_purge_line_contains "$CRON_MARK"
safe_rm "$RENEW_SH" "$RENEW_LOG"

# —— 6) 友好自检 —— 
echo
echo "================ 自检（只读）================"
echo "- 端口占用（理想：不再由 xray/sing-box 占用 443/2053）："
ss -lntup 2>/dev/null | egrep ':443|:2053' || true
echo
echo "- 服务状态（理想：xray/sing-box inactive 或 not-found，nginx active 可选）："
systemctl status xray sing-box nginx --no-pager -l 2>/dev/null | sed -n '1,120p' || true
echo
if need_cmd nginx; then
  echo "- nginx 配置测试（理想：syntax is ok / test is successful）："
  nginx -t || true
fi
echo "============================================="
echo -e "${GREEN}卸载流程已完成。${NC}"

# —— 7) 补充提示 —— 
echo
echo "提示："
echo "1) 若你还修改过防火墙（ufw/firewalld）端口策略，可按需手动回滚。"
echo "2) 若要彻底删除 /etc/edgebox 目录（上面已尽量清理），可手动： rm -rf /etc/edgebox"
echo "3) 如打算重新安装，建议先重启系统，确保端口与 systemd 干净。"
