#!/usr/bin/env bash
# =====================================================================================
# EdgeBox 一键卸载脚本
# 功能：完全清理 EdgeBox 相关的所有配置、服务和文件
# 使用：bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/EdgeBox/main/uninstall.sh)
# =====================================================================================

set -euo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/edgebox-uninstall.log"
readonly BACKUP_DIR="/root/edgebox-backup"

# === 颜色输出 ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# === 工具函数 ===
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${GREEN}[INFO]${NC} $*"
    log "[INFO] $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
    log "[WARN] $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    log "[ERROR] $*"
}

check_root() {
    [[ $EUID -eq 0 ]] || exec sudo -E bash "$0" "$@"
}

# === 确认卸载 ===
confirm_uninstall() {
    echo "================================================================"
    echo "EdgeBox 卸载脚本 v${SCRIPT_VERSION}"
    echo "================================================================"
    echo
    echo -e "${YELLOW}警告: 此操作将完全移除 EdgeBox 及其所有配置！${NC}"
    echo
    echo "将要删除："
    echo "  • 所有 EdgeBox 服务 (sing-box, xray)"
    echo "  • 配置文件和证书"
    echo "  • Nginx 虚拟主机配置"
    echo "  • 防火墙规则"
    echo "  • 管理工具"
    echo "  • 系统优化设置"
    echo
    echo -e "${GREEN}备份将保存到: $BACKUP_DIR${NC}"
    echo
    
    read -rp "确认卸载 EdgeBox？[y/N]: " confirm
    if [[ ${confirm,,} != y* ]]; then
        echo "卸载已取消"
        exit 0
    fi
}

# === 创建备份 ===
create_final_backup() {
    info "创建最终备份..."
    
    mkdir -p "$BACKUP_DIR"
    local backup_file="$BACKUP_DIR/final-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    tar -czf "$backup_file" \
        --ignore-failed-read \
        /opt/edgebox \
        /etc/sing-box \
        /usr/local/etc/xray \
        /etc/nginx/conf.d/edgebox.conf \
        /etc/ssl/edgebox \
        /var/www/html/sub \
        /etc/systemd/system/sing-box.service \
        /etc/systemd/system/xray.service \
        2>/dev/null || true
    
    info "备份已创建: $backup_file"
}

# === 停止服务 ===
stop_services() {
    info "停止 EdgeBox 服务..."
    
    # 停止并禁用服务
    systemctl disable --now sing-box 2>/dev/null || true
    systemctl disable --now xray 2>/dev/null || true
    
    # 等待服务完全停止
    sleep 2
    
    # 强制杀死可能残留的进程
    pkill -f "sing-box" 2>/dev/null || true
    pkill -f "xray" 2>/dev/null || true
    
    info "服务已停止"
}

# === 删除服务文件 ===
remove_services() {
    info "删除系统服务..."
    
    # 删除 systemd 服务文件
    rm -f /etc/systemd/system/sing-box.service
    rm -f /etc/systemd/system/xray.service
    
    # 重载 systemd
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    
    info "系统服务已删除"
}

# === 删除二进制文件 ===
remove_binaries() {
    info "删除二进制文件..."
    
    rm -f /usr/local/bin/sing-box
    rm -f /usr/local/bin/xray
    rm -f /usr/local/bin/edgeboxctl
    rm -f /usr/local/bin/edgebox-gensub
    
    info "二进制文件已删除"
}

# === 删除配置文件 ===
remove_configs() {
    info "删除配置文件..."
    
    # 删除主要配置目录
    rm -rf /opt/edgebox
    rm -rf /etc/sing-box
    rm -rf /usr/local/etc/xray
    
    # 删除证书
    rm -rf /etc/ssl/edgebox
    
    # 删除订阅页面
    rm -rf /var/www/html/sub
    
    # 删除 Nginx 虚拟主机配置
    rm -f /etc/nginx/conf.d/edgebox.conf
    rm -f /etc/nginx/sites-available/edgebox*
    rm -f /etc/nginx/sites-enabled/edgebox*
    
    # 删除数据目录
    rm -rf /var/lib/edgebox
    rm -rf /var/lib/sb-sub
    
    info "配置文件已删除"
}

# === 清理防火墙规则 ===
cleanup_firewall() {
    info "清理防火墙规则..."
    
    if command -v ufw >/dev/null; then
        # 删除 EdgeBox 相关端口规则
        ufw --force delete allow 443/tcp 2>/dev/null || true
        ufw --force delete allow 8443/tcp 2>/dev/null || true
        ufw --force delete allow 443/udp 2>/dev/null || true
        ufw --force delete allow 8443/udp 2>/dev/null || true
        ufw --force delete allow 2053/udp 2>/dev/null || true
        
        # 重载防火墙
        ufw reload 2>/dev/null || true
        
        info "防火墙规则已清理"
    fi
}

# === 清理系统优化设置 ===
cleanup_system_optimizations() {
    info "清理系统优化设置..."
    
    # 删除 sysctl 配置文件
    rm -f /etc/sysctl.d/99-edgebox-bbr.conf
    rm -f /etc/sysctl.d/*edgebox*.conf
    rm -f /etc/sysctl.d/*sb*.conf
    
    # 重新加载 sysctl 设置
    sysctl --system >/dev/null 2>&1 || true
    
    info "系统优化设置已清理"
}

# === 删除 swap 文件 ===
remove_swap() {
    info "删除 EdgeBox 创建的 swap 文件..."
    
    # EdgeBox 创建的 swap 文件
    local swap_files=(
        "/swapfile-edgebox"
        "/swapfile-sb" 
        "/swap_sb"
    )
    
    for swap_file in "${swap_files[@]}"; do
        if [[ -f "$swap_file" ]]; then
            # 关闭 swap
            swapoff "$swap_file" 2>/dev/null || true
            
            # 从 fstab 删除条目
            sed -i "\|^$swap_file|d" /etc/fstab 2>/dev/null || true
            sed -i "\|edgebox-swap|d" /etc/fstab 2>/dev/null || true
            
            # 删除文件
            rm -f "$swap_file"
            
            info "已删除 swap 文件: $swap_file"
        fi
    done
}

# === 清理 crontab 任务 ===
cleanup_crontab() {
    info "清理 crontab 任务..."
    
    # 删除订阅生成任务
    (crontab -l 2>/dev/null | grep -v "edgebox-gensub" | crontab -) 2>/dev/null || true
    (crontab -l 2>/dev/null | grep -v "EdgeBox" | crontab -) 2>/dev/null || true
    
    info "crontab 任务已清理"
}

# === 卸载软件包 ===
remove_packages() {
    info "卸载相关软件包..."
    
    if command -v apt >/dev/null; then
        # 仅卸载可能专门为 EdgeBox 安装的包
        DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y \
            vnstat 2>/dev/null || true
        
        # 自动清理
        DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get autoclean 2>/dev/null || true
    fi
    
    info "软件包清理完成"
}

# === 重载 Nginx ===
reload_nginx() {
    info "重新配置 Nginx..."
    
    if command -v nginx >/dev/null; then
        # 测试 Nginx 配置
        if nginx -t 2>/dev/null; then
            systemctl reload nginx 2>/dev/null || true
            info "Nginx 配置已重载"
        else
            warn "Nginx 配置有错误，请手动检查"
        fi
    fi
}

# === 清理日志文件 ===
cleanup_logs() {
    info "清理日志文件..."
    
    # 清理 EdgeBox 相关的日志
    rm -f /var/log/edgebox*.log
    
    # 清理 systemd 日志中的相关条目
    journalctl --rotate 2>/dev/null || true
    journalctl --vacuum-time=1s 2>/dev/null || true
    
    info "日志文件已清理"
}

# === 最终检查 ===
final_check() {
    info "执行最终检查..."
    
    echo
    echo "=== 卸载后系统状态 ==="
    
    # 检查端口占用
    echo "端口监听检查（应该无相关端口）:"
    ss -lntup | egrep ':443|:8443|:2053' || echo "  ✓ 无相关端口监听"
    
    echo
    
    # 检查服务状态
    echo "服务状态检查:"
    if systemctl list-unit-files | grep -q sing-box; then
        echo "  ✗ sing-box 服务文件仍存在"
    else
        echo "  ✓ sing-box 服务已清理"
    fi
    
    if systemctl list-unit-files | grep -q "xray"; then
        echo "  ✗ xray 服务文件仍存在"
    else
        echo "  ✓ xray 服务已清理"
    fi
    
    echo
    
    # 检查 Nginx 状态
    if command -v nginx >/dev/null; then
        if nginx -t >/dev/null 2>&1; then
            echo "  ✓ Nginx 配置正常"
        else
            echo "  ✗ Nginx 配置有问题，请检查"
        fi
    fi
    
    echo
}

# === 显示卸载结果 ===
show_uninstall_result() {
    echo
    echo "================================================================"
    echo "🗑️  EdgeBox 卸载完成！"
    echo "================================================================"
    echo
    echo "已删除的内容："
    echo "  ✓ 所有服务和进程"
    echo "  ✓ 配置文件和证书"  
    echo "  ✓ 二进制程序"
    echo "  ✓ 系统优化设置"
    echo "  ✓ 防火墙规则"
    echo "  ✓ 管理工具"
    echo "  ✓ 订阅系统"
    echo
    echo "保留的内容："
    echo "  • Nginx (仅删除了 EdgeBox 配置)"
    echo "  • 系统基础软件包"
    echo "  • 备份文件 ($BACKUP_DIR)"
    echo
    echo "💾 如需恢复，请使用最新的备份文件"
    echo "🗂️  备份位置: $BACKUP_DIR"
    echo
    
    if [[ -n "$(ls -A $BACKUP_DIR 2>/dev/null || true)" ]]; then
        echo "可用的备份文件："
        ls -la "$BACKUP_DIR" | tail -n +2 | awk '{print "   " $9 " (" $5 " bytes, " $6 " " $7 " " $8 ")"}'
    fi
    
    echo
    echo "================================================================"
    echo "EdgeBox 已完全卸载。感谢您的使用！"
    echo "================================================================"
}

# === 主卸载流程 ===
main() {
    echo "开始卸载 EdgeBox..." > "$LOG_FILE"
    
    # 权限检查
    check_root
    
    # 确认卸载
    confirm_uninstall
    
    # 执行卸载步骤
    create_final_backup
    stop_services
    remove_services
    remove_binaries
    remove_configs
    cleanup_firewall
    cleanup_system_optimizations
    remove_swap
    cleanup_crontab
    remove_packages
    reload_nginx
    cleanup_logs
    
    # 最终检查
    final_check
    
    # 显示结果
    show_uninstall_result
    
    log "EdgeBox 卸载完成"
}

# === 执行主函数 ===
main "$@"
