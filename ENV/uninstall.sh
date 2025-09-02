#!/bin/bash
set -euo pipefail

# ===== pretty log =====
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()   { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    err "请用 root 运行：sudo bash $0"
    exit 1
  fi
}

safe_systemctl() {
  # 在某些环境（容器 / 无 systemd）或权限不足时不致命
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl "$@" >/dev/null 2>&1 || true
}

kill_listeners() {
  # 结束可能残留的监听进程（仅限我们用到的端口）
  for p in 443 2053 11443 10085 10086; do
    # tcp/udp 都试一下
    for proto in tcp udp; do
      mapfile -t pids < <(ss -lpnH "sport = :$p" 2>/dev/null | awk '{print $NF}' | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)
      for pid in "${pids[@]:-}"; do
        kill -TERM "$pid" 2>/dev/null || true
      done
    done
  done
  sleep 0.5
}

restore_nginx_conf() {
  # 尝试把 nginx 恢复到系统默认/备份状态
  if [[ -f /etc/nginx/nginx.conf.bak ]]; then
    log "检测到 /etc/nginx/nginx.conf.bak，准备还原"
    # 去不可变位（若存在）
    if command -v chattr >/dev/null 2>&1; then chattr -i /etc/nginx/nginx.conf 2>/dev/null || true; fi
    chmod u+w /etc/nginx/nginx.conf 2>/dev/null || true
    # 用 install 原子覆盖，避免“先删后写”的权限问题
    install -m 644 /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf 2>/dev/null || cp -f /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
    # 语法校验 + 尝试重载
    if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
      safe_systemctl restart nginx
      log "nginx 已恢复并重启"
    else
      warn "nginx 未安装或配置测试失败，已跳过重启"
    fi
  else
    warn "未发现 /etc/nginx/nginx.conf.bak，跳过还原"
  fi
}

purge_files() {
  # 停止/禁用服务
  log "停止并禁用服务..."
  for s in xray sing-box nginx; do
    safe_systemctl stop "$s"
    safe_systemctl disable "$s"
  done

  # 移除我们创建的 unit
  log "移除 systemd 单元与二进制..."
  rm -f /etc/systemd/system/xray.service
  rm -f /etc/systemd/system/sing-box.service
  safe_systemctl daemon-reload

  # 删除二进制（仅我们放在 /usr/local/bin 的）
  rm -f /usr/local/bin/xray /usr/local/bin/sing-box

  # EdgeBox 目录 & 日志 & 订阅文件
  log "清理配置与文件..."
  rm -rf /etc/edgebox
  rm -rf /var/log/xray /var/log/edgebox* 2>/dev/null || true
  rm -f /var/www/html/sub 2>/dev/null || true

  # 证书软链接与自签（保留 Let's Encrypt 系统目录；如需彻底清除可加 --purge-le）
  rm -f /etc/edgebox/cert/current.key /etc/edgebox/cert/current.pem 2>/dev/null || true
  rm -f /etc/edgebox/cert/self-signed.key /etc/edgebox/cert/self-signed.pem 2>/dev/null || true
}

purge_le_if_required() {
  if [[ "${1:-}" == "--purge-le" ]]; then
    log "按要求清理 Let's Encrypt 证书（/etc/letsencrypt）"
    safe_systemctl stop nginx
    rm -rf /etc/letsencrypt/live /etc/letsencrypt/archive /etc/letsencrypt/renewal 2>/dev/null || true
  fi
}

summary() {
  echo
  echo -e "${GREEN}清理完成。${NC}"
  echo "可以现在重新执行你的安装脚本（幂等安装）进行全新部署。"
}

main() {
  need_root
  log "开始 EdgeBox 卸载与清理（安全/幂等）..."
  kill_listeners
  purge_files
  restore_nginx_conf
  purge_le_if_required "${1:-}"
  summary
}

main "$@"
