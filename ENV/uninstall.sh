#!/usr/bin/env bash
# ===========================================================
# EdgeBox / Xray / sing-box 可读性强的卸载脚本（强反馈）
# - 幂等：重复执行安全
# - 卸载：过程简明详细
# - 容错：systemd/nginx 缺失不致命，但会解释原因
# ===========================================================
set -Eeuo pipefail

# ---------- 样式 ----------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
skip() { echo -e "  ${YELLOW}↷ 跳过${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }
hr()   { echo -e "${CYAN}------------------------------------------------------------${NC}"; }
title(){ echo -e "\n${CYAN}==> $*${NC}"; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    err "请用 root 运行：sudo bash $0"
    exit 1
  fi
}

has_cmd(){ command -v "$1" >/dev/null 2>&1; }

# ---------- 路径约定（与安装脚本一致） ----------
INSTALL_DIR="/etc/edgebox"
CONFIG_DIR="${INSTALL_DIR}/config"
CERT_DIR="${INSTALL_DIR}/cert"
SCRIPT_DIR="${INSTALL_DIR}/scripts"

XRAY_BIN="/usr/local/bin/xray"
XRAY_SVC="/etc/systemd/system/xray.service"
XRAY_LOG="/var/log/xray"

SBOX_BIN="/usr/local/bin/sing-box"
SBOX_SVC="/etc/systemd/system/sing-box.service"

NGX_MAIN="/etc/nginx/nginx.conf"
NGX_BAK="/etc/nginx/nginx.conf.bak"

SUB_FILE="/var/www/html/sub"
RENEW_SH="${SCRIPT_DIR}/cert-renewal.sh"
RENEW_LOG="/var/log/edgebox-renewal.log"
CRON_MARK="cert-renewal.sh"

PORTS=(443 2053 11443 10085 10086)

# ---------- 统计辅助 ----------
count_existing(){
  local n=0
  for p in "$@"; do [[ -e $p || -L $p ]] && ((n++)) || true; done
  echo "$n"
}

remove_paths(){
  local removed=0
  for p in "$@"; do
    if [[ -e $p || -L $p ]]; then
      rm -rf -- "$p" && ok "删除 $p" && ((removed++)) || warn "删除失败 $p"
    else
      skip "$p 不存在"
    fi
  done
  return $removed
}

systemd_safe(){
  if has_cmd systemctl; then
    systemctl "$@" >/dev/null 2>&1 || true
  fi
}

list_listeners(){
  ss -lntup 2>/dev/null | awk 'NR==1 || $5 ~ /:(443|2053|11443|10085|10086)$/'
}

kill_listeners(){
  local killed=0
  for p in "${PORTS[@]}"; do
    # tcp + udp
    mapfile -t pids < <(ss -lpnH "( sport = :$p )" 2>/dev/null | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)
    for pid in "${pids[@]:-}"; do
      if kill -TERM "$pid" 2>/dev/null; then
        ok "结束监听进程 pid=$pid (port $p)"
        ((killed++))
      fi
    done
  done
  [[ $killed -gt 0 ]] || skip "未发现需结束的监听进程"
}

purge_cron_mark(){
  local before after
  before=$(crontab -l 2>/dev/null | grep -c "$CRON_MARK" || true)
  if [[ $before -gt 0 ]]; then
    crontab -l 2>/dev/null | sed "/${CRON_MARK//\//\\/}/d" | crontab - 2>/dev/null || true
    after=$(crontab -l 2>/dev/null | grep -c "$CRON_MARK" || true)
    ok "清理 crontab: ${before} → ${after}"
  else
    skip "未发现续期任务（crontab）"
  fi
}

restore_nginx(){
  if [[ -f $NGX_BAK ]]; then
    info "检测到 nginx 备份：$NGX_BAK"
    # 去不可变位（若有）
    has_cmd chattr && chattr -i "$NGX_MAIN" 2>/dev/null || true
    chmod u+w "$NGX_MAIN" 2>/dev/null || true
    # 原子覆盖
    install -m 644 "$NGX_BAK" "$NGX_MAIN" 2>/dev/null || cp -f "$NGX_BAK" "$NGX_MAIN"
    ok "已还原 $NGX_MAIN"
    if has_cmd nginx; then
      if nginx -t >/dev/null 2>&1; then
        systemd_safe restart nginx
        ok "nginx 配置测试通过并已重启"
      else
        warn "nginx -t 语法测试失败（但已还原到备份），请手动检查 nginx 配置"
      fi
    else
      skip "系统未安装 nginx 命令，仅完成文件还原"
    fi
  else
    skip "未发现 $NGX_BAK，nginx 不需要回退"
  fi
}

main(){
  need_root

  title "环境信息"
  echo -n "  系统："; (lsb_release -ds 2>/dev/null || cat /etc/os-release | sed -n 's/^PRETTY_NAME=//p' | tr -d '"') || echo "Unknown"
  echo -n "  内核："; uname -r
  echo -n "  systemd："; if has_cmd systemctl; then systemctl --version | sed -n '1p'; else echo "不可用（可能是容器或最小系统）"; fi
  hr

  title "卸载前监听端口快照"
  list_listeners || true
  hr

  title "停止与禁用服务"
  if has_cmd systemctl; then
    for s in xray sing-box; do
      state=$(systemctl is-active "$s" 2>/dev/null || true)
      echo -n "  $s: 当前状态 $state，执行 stop/disable ... "
      systemd_safe stop "$s"
      systemd_safe disable "$s"
      echo -e "${GREEN}完成${NC}"
    done
  else
    skip "systemd 不可用，跳过 stop/disable"
  fi
  hr

  title "结束残留监听进程（443/2053/11443/10085/10086）"
  kill_listeners
  hr

  title "移除 systemd 单元与二进制"
  remove_paths "$XRAY_SVC" "$SBOX_SVC"
  has_cmd systemctl && (systemctl daemon-reload >/dev/null 2>&1 && ok "daemon-reload" || warn "daemon-reload 失败（忽略）")
  remove_paths "$XRAY_BIN" "$SBOX_BIN"
  hr

  title "清理 EdgeBox 配置/证书/脚本/日志/订阅"
  remove_paths "$CONFIG_DIR" "$SCRIPT_DIR" "$XRAY_LOG" "$SUB_FILE"
  # 证书：仅删软链与自签名（保留 /etc/letsencrypt）
  remove_paths "$CERT_DIR/current.key" "$CERT_DIR/current.pem" "$CERT_DIR/self-signed.key" "$CERT_DIR/self-signed.pem"
  # 目录空了尝试移除
  [[ -d $CERT_DIR ]] && rmdir "$CERT_DIR" 2>/dev/null && ok "移除空目录 $CERT_DIR" || true
  hr

  title "清理证书自动续期（crontab & 脚本）"
  purge_cron_mark
  remove_paths "$RENEW_SH" "$RENEW_LOG"
  hr

  title "回退 nginx（若有备份）"
  restore_nginx
  hr

  title "卸载后监听端口快照"
  list_listeners || true
  hr

  title "残留检查"
  leftover=0
  for p in "$INSTALL_DIR" "$XRAY_LOG" "$XRAY_BIN" "$SBOX_BIN" "$XRAY_SVC" "$SBOX_SVC" "$SUB_FILE"; do
    if [[ -e $p || -L $p ]]; then
      echo -e "  ${RED}! 残留：$p${NC}"
      leftover=1
    fi
  done
  if [[ $leftover -eq 0 ]]; then
    ok "未发现可识别的残留"
  else
    warn "存在残留，已高亮列出（可手动删除）"
  fi

  echo -e "\n${GREEN}✅ 卸载完成。${NC}"
  echo "下一步建议："
  echo "  1) 若要立刻重装，可直接运行你的安装命令（幂等安装）。"
  echo "  2) 如需手动验证，请执行："
  echo "     - ss -lntup | egrep ':443|:2053|:11443|:10085|:10086'  # 端口应无残留"
  echo "     - systemctl status xray sing-box nginx --no-pager      # xray/sing-box应显示：inactive 或 not-found"
  echo -e "${CYAN}============================================================${NC}\n"
}

main "$@"
