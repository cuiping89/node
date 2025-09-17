#!/usr/bin/env bash
# ===========================================================
# EdgeBox Uninstall (idempotent, verbose)
# - Keeps original uninstall flow, plus cleans recent install assets
# - Safe to run multiple times
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

need_root() {
  if [[ ${EUID:-0} -ne 0 ]]; then
    err "请用 root 运行：sudo bash $0"
    exit 1
  fi
}

# ---------- Paths (aligned with install) ----------
INSTALL_DIR="/etc/edgebox"
CONFIG_DIR="${INSTALL_DIR}/config"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"
CERT_DIR="${INSTALL_DIR}/cert"
TRAFFIC_DIR="${INSTALL_DIR}/traffic"
WEB_ROOT="/var/www/html"
WEB_STATUS_PHY="/var/www/edgebox/status"
WEB_STATUS_LINK="${WEB_ROOT}/status"
TRAFFIC_LINK="${WEB_ROOT}/traffic"
LOG_DIR="/var/log/edgebox"
INSTALL_LOG="/var/log/edgebox-install.log"

# one-shot init unit from latest installer
INIT_SVC="/etc/systemd/system/edgebox-init.service"
INIT_SCRIPT="${SCRIPTS_DIR}/edgebox-init.sh"

# IP quality scoring helper
IPQ_BIN="/usr/local/bin/edgebox-ipq.sh"

# nginx main conf (for restore)
NGX_MAIN="/etc/nginx/nginx.conf"

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
    if ss -lntup 2>/dev/null | awk -v P=":$p" '$4 ~ P {print $NF}' | sed 's/.*pid=\([0-9]\+\).*/\1/' | sort -u | xargs -r kill -9 2>/dev/null; then :; fi
    # udp
    if ss -lnuap 2>/dev/null | awk -v P=":$p" '$5 ~ P {print $NF}' | sed 's/.*pid=\([0-9]\+\).*/\1/' | sort -u | xargs -r kill -9 2>/dev/null; then :; fi
  done
}

remove_paths(){
  local any=0
  for p in "$@"; do
    [[ -z "${p}" ]] && continue
    if [[ -e "$p" || -L "$p" ]]; then
      rm -rf --one-file-system "$p" 2>/dev/null || rm -rf "$p" 2>/dev/null || true
      ok "已删除 $p"; any=1
    else
      skip "不存在：$p"
    fi
  done
  return $any
}

restore_nginx() {
  title "回退 nginx（若有备份）"
  local cand latest
  if [[ -f "$NGX_MAIN" ]]; then
    cp -f "$NGX_MAIN" "${NGX_MAIN}.uninstall.bak.$(date +%s)" || true
  fi
  mapfile -t cand < <(ls -1t \
      /etc/nginx/nginx.conf.bak* \
      /etc/nginx/nginx.conf.*.bak 2>/dev/null || true)
  if [[ -n "${cand[*]:-}" ]]; then
    latest="${cand[0]}"
    info "发现备份：$latest，执行回滚..."
    if install -m 0644 -T "$latest" "$NGX_MAIN"; then
      ok "已回滚到：$latest"
      if has_cmd nginx && nginx -t >/dev/null 2>&1; then
        systemd_safe restart nginx
      fi
    else
      warn "回滚失败：$latest"
    fi
  else
    skip "未发现可用的 nginx.conf 备份，跳过回滚"
  fi
}

purge_cron_mark(){
  # 兼容旧逻辑：清理旧证书续期标记任务
  local CRON_MARK="cert-renewal.sh"
  crontab -l 2>/dev/null | sed "/${CRON_MARK//\//\\/}/d" | crontab - 2>/dev/null || true
}

purge_cron_edgebox(){
  # 清理 EdgeBox 创建的 cron
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
  # 若存在备份则回滚 sysctl / limits
  local SCTL="/etc/sysctl.conf" LIMS="/etc/security/limits.conf"
  local SCTL_BAK="${SCTL}.bak" LIMS_BAK="${LIMS}.bak"
  [[ -f "$SCTL_BAK" ]] && install -m 0644 -T "$SCTL_BAK" "$SCTL" && ok "已回滚 $SCTL" || true
  [[ -f "$LIMS_BAK" ]] && install -m 0644 -T "$LIMS_BAK" "$LIMS" && ok "已回滚 $LIMS" || true
}

# ---------- Main ----------
main(){
  need_root
  echo -e "${CYAN}============================================================${NC}"
  echo "EdgeBox 卸载程序（幂等）"
  echo -n "  系统："; (lsb_release -ds 2>/dev/null || grep -hs ^PRETTY_NAME= /etc/os-release | sed -n 's/^PRETTY_NAME=//p' | tr -d '"') || echo "Unknown"
  echo -n "  内核："; uname -r
  echo -n "  systemd："; if has_cmd systemctl; then systemctl --version | sed -n '1p'; else echo "不可用（可能是容器或最小系统）"; fi
  hr

  title "卸载前监听端口快照"
  list_listeners || true
  hr

  title "停止与禁用服务（xray / sing-box / edgebox-init）"
  if has_cmd systemctl; then
    for s in xray sing-box edgebox-init; do
      state="$(systemctl is-active "$s" 2>/dev/null || echo unknown)"
      printf "  %s: 当前状态 %s，执行 stop/disable ... " "$s" "$state"
      systemd_safe stop "$s"; systemd_safe disable "$s"; echo -e "${GREEN}完成${NC}"
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
  else
    skip "systemd 不可用，跳过 stop/disable"
  fi
  hr

  title "结束残留监听进程（443/2053/11443/10085/10086）"
  kill_listeners || true
  hr

  title "清理 crontab（安装与评分相关）"
  purge_cron_mark
  purge_cron_edgebox
  hr

  title "删除 Web 资源与链接（/status, /traffic, 日志）"
  remove_paths "$WEB_STATUS_LINK" "$WEB_STATUS_PHY" "$TRAFFIC_LINK" "$TRAFFIC_DIR" "$LOG_DIR" "$INSTALL_LOG"
  hr

  title "删除 IPQ 评分脚本与一次性初始化服务/脚本"
  remove_paths "$IPQ_BIN" "$INIT_SCRIPT" "$INIT_SVC"
  has_cmd systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
  hr

  title "删除 EdgeBox 目录（/etc/edgebox）"
  remove_paths "$INSTALL_DIR"
  hr

  title "清理 nftables（inet edgebox）"
  nft_cleanup
  hr

  title "回退内核/limits 调优（若存在备份）"
  restore_kernel_tuning
  hr

  restore_nginx

  hr
  title "卸载后监听端口快照"
  list_listeners || true
  hr

  # 状态汇总
  local bad=0
  if has_cmd systemctl; then
    for s in xray sing-box; do
      if systemctl is-active --quiet "$s"; then
        warn "$s 仍在运行"
        bad=1
      fi
    done
  fi

  # Web 残留检查
  local leftovers=()
  for p in "$WEB_STATUS_LINK" "$WEB_STATUS_PHY" "$TRAFFIC_LINK" "$TRAFFIC_DIR" "$INSTALL_DIR" "$IPQ_BIN"; do
    [[ -e "$p" || -L "$p" ]] && leftovers+=("$p")
  done

  if [[ $bad -eq 0 && ${#leftovers[@]} -eq 0 ]]; then
    echo -e "\n${GREEN}✅ 卸载完成。${NC}"
  else
    echo -e "\n${YELLOW}⚠️ 卸载完成（存在残留或运行中的服务）。${NC}"
    ((${#leftovers[@]})) && printf '  残留路径：\n    - %s\n' "${leftovers[@]}"
  fi

  echo "下一步建议："
  echo "  1) 若要立刻重装，可直接运行你的安装命令（幂等安装）。"
  echo "  2) 验证命令："
  echo "     - ss -lntup | egrep ':443|:2053|:11443|:10085|:10086'"
  echo "     - systemctl status xray sing-box nginx --no-pager"
  echo -e "${CYAN}============================================================${NC}"
}

main "$@"
