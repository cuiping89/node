#!/usr/bin/env bash
# =====================================================================================
# EdgeBox 高级管理工具 - 支持热更新、配置管理、智能重装
# =====================================================================================

set -euo pipefail

# === 常量定义 ===
readonly WORK_DIR="/opt/edgebox"
readonly BACKUP_DIR="/root/edgebox-backup"
readonly CONFIG_DIR="/etc/sing-box"
readonly XRAY_CONFIG="/usr/local/etc/xray/config.json"
readonly NGINX_CONF="/etc/nginx/conf.d/edgebox.conf"
readonly LOG_FILE="/var/log/edgebox.log"
readonly VERSION="2.0.0"

# === 颜色输出 ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# === 工具函数 ===
log() { echo -e "${GREEN}[INFO]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"; exit 1; }
success() { echo -e "${GREEN}✓${NC} $*"; }

check_root() {
    [[ $EUID -eq 0 ]] || exec sudo -E bash "$0" "$@"
}

# === 配置管理函数 ===
load_config() {
    if [[ -f "$WORK_DIR/config.json" ]]; then
        source <(jq -r 'to_entries[] | "export \(.key)=\"\(.value)\""' "$WORK_DIR/config.json" 2>/dev/null || echo "")
    fi
}

save_config() {
    local key="$1"
    local value="$2"
    
    # 确保配置文件存在
    [[ -f "$WORK_DIR/config.json" ]] || echo '{}' > "$WORK_DIR/config.json"
    
    # 更新配置
    jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$WORK_DIR/config.json" > "$WORK_DIR/config.json.tmp"
    mv "$WORK_DIR/config.json.tmp" "$WORK_DIR/config.json"
}

# === 服务状态管理 ===
show_status() {
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   EdgeBox 服务状态                       ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    
    # 核心服务状态
    echo "║ 核心服务:                                                ║"
    for service in sing-box xray nginx; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            if systemctl is-active --quiet "$service"; then
                printf "║   %-12s: ${GREEN}● 运行中${NC}                            ║\n" "$service"
            else
                printf "║   %-12s: ${RED}○ 已停止${NC}                            ║\n" "$service"
            fi
        fi
    done
    
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ 端口监听:                                                ║"
    
    # 端口检查
    local ports=("443/tcp" "443/udp" "8443/tcp" "8443/udp" "2053/udp")
    for port in "${ports[@]}"; do
        local proto="${port#*/}"
        local portnum="${port%/*}"
        if ss -ln"${proto:0:1}" | grep -q ":$portnum "; then
            printf "║   %-10s: ${GREEN}✓ 监听中${NC}                             ║\n" "$port"
        else
            printf "║   %-10s: ${YELLOW}- 未监听${NC}                             ║\n" "$port"
        fi
    done
    
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ 协议状态:                                                ║"
    
    # 协议状态检查
    check_protocol_status
    
    echo "╚══════════════════════════════════════════════════════════╝"
}

# === 备份恢复 ===
create_backup() {
    local backup_name="${1:-manual}"
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_file="$BACKUP_DIR/backup-${backup_name}-${timestamp}.tar.gz"
    
    mkdir -p "$BACKUP_DIR"
    
    log "创建备份: $backup_file"
    
    tar -czf "$backup_file" \
        "$WORK_DIR" \
        "$CONFIG_DIR" \
        "$XRAY_CONFIG" \
        "$NGINX_CONF" \
        /etc/ssl/edgebox \
        2>/dev/null || true
    
    # 保留最近15个备份
    ls -t "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null | tail -n +16 | xargs -r rm -f
    
    success "备份已创建: $backup_file"
    return 0
}

restore_backup() {
    local backup_file="$1"
    
    if [[ -z "$backup_file" ]]; then
        # 显示可用备份
        echo "可用备份列表:"
        ls -lt "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null | head -10 | awk '{print NR". "$NF}'
        read -rp "请选择备份编号: " num
        backup_file=$(ls -t "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null | sed -n "${num}p")
    fi
    
    if [[ ! -f "$backup_file" ]]; then
        error "备份文件不存在: $backup_file"
    fi
    
    warn "恢复备份将覆盖当前配置"
    read -rp "确定要继续吗？[y/N]: " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "操作已取消"
        return
    fi
    
    # 先创建当前配置的备份
    create_backup "before-restore"
    
    log "恢复备份: $backup_file"
    
    # 停止服务
    systemctl stop sing-box xray nginx 2>/dev/null || true
    
    # 恢复文件
    tar -xzf "$backup_file" -C / 2>/dev/null
    
    # 重启服务
    restart_all_services
    
    success "备份已恢复"
}

# === 服务管理 ===
restart_all_services() {
    log "重启所有服务..."
    
    local failed_services=()
    
    # 重启 Nginx
    if systemctl restart nginx 2>/dev/null; then
        success "Nginx 已重启"
    else
        failed_services+=("nginx")
    fi
    
    # 重启 Xray（如果存在）
    if systemctl list-unit-files | grep -q "^xray.service"; then
        if systemctl restart xray 2>/dev/null; then
            success "Xray 已重启"
        else
            failed_services+=("xray")
        fi
    fi
    
    # 重启 sing-box
    if systemctl restart sing-box 2>/dev/null; then
        success "sing-box 已重启"
    else
        failed_services+=("sing-box")
    fi
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        error "以下服务重启失败: ${failed_services[*]}"
    fi
    
    success "所有服务已重启"
}

show_logs() {
    local service="${1:-all}"
    local lines="${2:-50}"
    
    case $service in
        all)
            echo "=== 所有服务日志 ==="
            for svc in sing-box xray nginx; do
                if systemctl list-unit-files | grep -q "^${svc}.service"; then
                    echo
                    echo "--- $svc 日志 ---"
                    journalctl -u "$svc" -n "$lines" --no-pager
                fi
            done
            ;;
        sing-box|xray|nginx)
            echo "=== $service 日志 ==="
            journalctl -u "$service" -n "$lines" --no-pager
            ;;
        error)
            echo "=== 错误日志 ==="
            journalctl -p err -n "$lines" --no-pager
            ;;
        *)
            error "支持的服务: all, sing-box, xray, nginx, error"
            ;;
    esac
}

# === 故障诊断 ===
diagnose() {
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                      系统诊断                            ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    
    local issues=0
    
    # 检查服务状态
    echo "║ 服务检查:                                                ║"
    for service in sing-box xray nginx; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            if systemctl is-active --quiet "$service"; then
                printf "║   %-12s: ${GREEN}✓ 正常${NC}                              ║\n" "$service"
            else
                printf "║   %-12s: ${RED}✗ 异常${NC}                              ║\n" "$service"
                ((issues++))
            fi
        fi
    done
    
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ 端口检查:                                                ║"
    
    # 检查关键端口
    local ports=("443" "8443" "2053")
    for port in "${ports[@]}"; do
        if ss -lnt | grep -q ":$port "; then
            printf "║   端口 %-6s: ${GREEN}✓ 监听中${NC}                            ║\n" "$port"
        else
            printf "║   端口 %-6s: ${YELLOW}⚠ 未监听${NC}                            ║\n" "$port"
            ((issues++))
        fi
    done
    
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ 配置检查:                                                ║"
    
    # 检查配置文件
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        if /usr/local/bin/sing-box check -c "$CONFIG_DIR/config.json" 2>/dev/null; then
            printf "║   sing-box配置: ${GREEN}✓ 正常${NC}                             ║\n"
        else
            printf "║   sing-box配置: ${RED}✗ 错误${NC}                             ║\n"
            ((issues++))
        fi
    fi
    
    if [[ -f "$XRAY_CONFIG" ]]; then
        if /usr/local/bin/xray run -test -config "$XRAY_CONFIG" 2>/dev/null; then
            printf "║   xray配置:     ${GREEN}✓ 正常${NC}                             ║\n"
        else
            printf "║   xray配置:     ${RED}✗ 错误${NC}                             ║\n"
            ((issues++))
        fi
    fi
    
    if nginx -t 2>/dev/null; then
        printf "║   nginx配置:    ${GREEN}✓ 正常${NC}                             ║\n"
    else
        printf "║   nginx配置:    ${RED}✗ 错误${NC}                             ║\n"
        ((issues++))
    fi
    
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ 证书检查:                                                ║"
    
    if [[ -f "/etc/ssl/edgebox/cert.pem" ]]; then
        local expiry=$(openssl x509 -in /etc/ssl/edgebox/cert.pem -noout -enddate 2>/dev/null | cut -d= -f2)
        local days_left=$(( ($(date -d "$expiry" +%s) - $(date +%s)) / 86400 ))
        
        if [[ $days_left -gt 30 ]]; then
            printf "║   证书有效期:   ${GREEN}✓ 剩余 %d 天${NC}                      ║\n" "$days_left"
        elif [[ $days_left -gt 0 ]]; then
            printf "║   证书有效期:   ${YELLOW}⚠ 剩余 %d 天${NC}                      ║\n" "$days_left"
        else
            printf "║   证书有效期:   ${RED}✗ 已过期${NC}                          ║\n"
            ((issues++))
        fi
    else
        printf "║   证书状态:     ${RED}✗ 未找到证书${NC}                        ║\n"
        ((issues++))
    fi
    
    echo "╠══════════════════════════════════════════════════════════╣"
    
    if [[ $issues -eq 0 ]]; then
        echo "║ ${GREEN}诊断结果: 系统运行正常${NC}                                  ║"
    else
        echo "║ ${RED}诊断结果: 发现 $issues 个问题${NC}                                    ║"
        echo "╠══════════════════════════════════════════════════════════╣"
        echo "║ 建议操作:                                                ║"
        echo "║   1. 查看日志: edgeboxctl logs error                     ║"
        echo "║   2. 重启服务: edgeboxctl restart                        ║"
        echo "║   3. 智能修复: edgeboxctl repair                         ║"
    fi
    
    echo "╚══════════════════════════════════════════════════════════╝"
}

# === 智能修复 ===
smart_repair() {
    log "开始智能修复..."
    
    local fixed=0
    
    # 修复停止的服务
    for service in sing-box xray nginx; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            if ! systemctl is-active --quiet "$service"; then
                log "尝试启动 $service..."
                if systemctl start "$service" 2>/dev/null; then
                    success "$service 已启动"
                    ((fixed++))
                else
                    warn "$service 启动失败，尝试修复配置..."
                    repair_service_config "$service"
                fi
            fi
        fi
    done
    
    # 修复证书
    if [[ ! -f "/etc/ssl/edgebox/cert.pem" ]]; then
        log "证书缺失，生成自签名证书..."
        generate_self_signed_cert
        ((fixed++))
    fi
    
    # 修复防火墙
    log "检查防火墙规则..."
    ufw allow 22/tcp >/dev/null 2>&1
    ufw allow 443/tcp >/dev/null 2>&1
    ufw allow 443/udp >/dev/null 2>&1
    ufw allow 8443/tcp >/dev/null 2>&1
    ufw allow 2053/udp >/dev/null 2>&1
    
    if [[ $fixed -gt 0 ]]; then
        success "修复完成，已解决 $fixed 个问题"
    else
        log "未发现需要修复的问题"
    fi
    
    # 重新诊断
    echo
    diagnose
}

repair_service_config() {
    local service="$1"
    
    case $service in
        sing-box)
            if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
                warn "sing-box 配置缺失，需要重新安装"
                suggest_reinstall
            else
                # 尝试修复配置语法
                local temp_config="/tmp/sing-box-test.json"
                jq '.' "$CONFIG_DIR/config.json" > "$temp_config" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    mv "$temp_config" "$CONFIG_DIR/config.json"
                    systemctl restart sing-box
                fi
            fi
            ;;
        xray)
            if [[ ! -f "$XRAY_CONFIG" ]]; then
                warn "Xray 配置缺失，需要重新安装"
                suggest_reinstall
            else
                # 尝试修复配置语法
                local temp_config="/tmp/xray-test.json"
                jq '.' "$XRAY_CONFIG" > "$temp_config" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    mv "$temp_config" "$XRAY_CONFIG"
                    systemctl restart xray
                fi
            fi
            ;;
        nginx)
            nginx -t 2>/dev/null || {
                warn "Nginx 配置错误，尝试使用默认配置"
                mv "$NGINX_CONF" "${NGINX_CONF}.broken" 2>/dev/null
                systemctl restart nginx
            }
            ;;
    esac
}

# === 智能重装 ===
smart_reinstall() {
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                    智能重装向导                          ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ 此操作将:                                                ║"
    echo "║   1. 备份当前配置                                        ║"
    echo "║   2. 保留可用的服务                                      ║"
    echo "║   3. 仅重装损坏的组件                                    ║"
    echo "║   4. 更新域名和代理配置（如需要）                        ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo
    
    read -rp "是否继续？[y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "操作已取消"
        return
    fi
    
    # 备份当前配置
    create_backup "before-reinstall"
    
    # 询问是否更新域名
    read -rp "是否更新域名？[y/N]: " update_domain_choice
    if [[ "$update_domain_choice" == "y" || "$update_domain_choice" == "Y" ]]; then
        read -rp "请输入新域名: " new_domain
        if [[ -n "$new_domain" ]]; then
            update_domain "$new_domain"
        fi
    fi
    
    # 询问是否更新代理
    read -rp "是否更新代理配置？[y/N]: " update_proxy_choice
    if [[ "$update_proxy_choice" == "y" || "$update_proxy_choice" == "Y" ]]; then
        echo "代理配置格式: HOST:PORT:USER:PASS 或 HOST:PORT"
        echo "留空则使用直连模式"
        read -rp "请输入代理配置: " proxy_config
        if [[ -n "$proxy_config" ]]; then
            update_proxy set "$proxy_config"
        else
            update_proxy remove
        fi
    fi
    
    # 检查并重装损坏的组件
    log "检查组件状态..."
    
    # 检查 sing-box
    if ! /usr/local/bin/sing-box version >/dev/null 2>&1; then
        log "重新安装 sing-box..."
        reinstall_singbox
    fi
    
    # 检查 Xray
    if ! /usr/local/bin/xray version >/dev/null 2>&1; then
        log "重新安装 Xray..."
        reinstall_xray
    fi
    
    # 重新生成配置
    log "重新生成配置文件..."
    regenerate_all_configs
    
    # 重启所有服务
    restart_all_services
    
    success "智能重装完成"
    
    # 显示订阅信息
    echo
    show_subscription
}

reinstall_singbox() {
    local version="${SING_BOX_VERSION:-v1.11.7}"
    local url="https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box-${version#v}-linux-amd64.tar.gz"
    local temp_dir=$(mktemp -d)
    
    cd "$temp_dir"
    curl -fsSL "$url" -o sing-box.tar.gz
    tar -xzf sing-box.tar.gz
    install -m755 sing-box-*/sing-box /usr/local/bin/sing-box
    rm -rf "$temp_dir"
    
    /usr/local/bin/sing-box version
}

reinstall_xray() {
    local version="${XRAY_VERSION:-v1.8.24}"
    local url="https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip"
    local temp_dir=$(mktemp -d)
    
    cd "$temp_dir"
    curl -fsSL "$url" -o xray.zip
    unzip -q xray.zip
    install -m755 xray /usr/local/bin/xray
    mkdir -p /usr/local/etc/xray
    install -m644 geoip.dat geosite.dat /usr/local/etc/xray/
    rm -rf "$temp_dir"
    
    /usr/local/bin/xray version
}

regenerate_all_configs() {
    # 这里调用安装脚本中的配置生成函数
    # 或者直接从备份恢复
    if [[ -f "$BACKUP_DIR/backup-before-reinstall-"*.tar.gz ]]; then
        local latest_backup=$(ls -t "$BACKUP_DIR"/backup-before-reinstall-*.tar.gz | head -1)
        tar -xzf "$latest_backup" -C / --wildcards '*/opt/edgebox/*' 2>/dev/null
    fi
}

suggest_reinstall() {
    echo
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   需要重新安装                           ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ 检测到关键组件缺失或损坏，建议执行:                      ║"
    echo "║                                                          ║"
    echo "║   1. 智能重装: edgeboxctl reinstall                      ║"
    echo "║      (保留可用服务，仅修复损坏部分)                      ║"
    echo "║                                                          ║"
    echo "║   2. 完全重装:                                           ║"
    echo "║      bash <(curl -fsSL .../uninstall.sh)                 ║"
    echo "║      bash <(curl -fsSL .../install.sh)                   ║"
    echo "║      (完全卸载后重新安装)                                ║"
    echo "╚══════════════════════════════════════════════════════════╝"
}

# === 版本信息 ===
show_version() {
    echo "EdgeBox 管理工具 v${VERSION}"
    echo
    echo "组件版本:"
    
    if [[ -f "/usr/local/bin/sing-box" ]]; then
        /usr/local/bin/sing-box version 2>/dev/null | head -1 || echo "sing-box: 版本未知"
    else
        echo "sing-box: 未安装"
    fi
    
    if [[ -f "/usr/local/bin/xray" ]]; then
        /usr/local/bin/xray version 2>/dev/null | head -1 || echo "xray: 版本未知"
    else
        echo "xray: 未安装"
    fi
    
    nginx -v 2>&1 | head -1 || echo "nginx: 未安装"
    
    echo
    echo "配置信息:"
    echo "  工作目录: $WORK_DIR"
    echo "  备份目录: $BACKUP_DIR"
    echo "  日志文件: $LOG_FILE"
}

# === 使用帮助 ===
show_usage() {
    cat << 'USAGE'
EdgeBox 管理工具 v2.0.0

用法:
  edgeboxctl <命令> [选项]

核心命令:
  status              显示服务状态和端口监听
  restart             重启所有服务
  diagnose            系统诊断，检查问题
  repair              智能修复常见问题
  reinstall           智能重装（保留可用服务）

配置管理:
  domain <new-domain> 更新域名和证书
  proxy set <config>  设置代理 (HOST:PORT:USER:PASS)
  proxy remove        移除代理，使用直连
  proxy status        显示代理状态

订阅管理:
  sub                 显示所有订阅链接
  sub-regen           重新生成UUID和密码

日志查看:
  logs [service]      查看日志 (all|sing-box|xray|nginx|error)

备份恢复:
  backup              创建配置备份
  restore [file]      恢复配置

其他命令:
  traffic             显示流量统计
  version             显示版本信息
  help                显示此帮助

示例:
  edgeboxctl status                          # 查看状态
  edgeboxctl domain example.com              # 更新域名
  edgeboxctl proxy set proxy.com:8080:u:p    # 设置代理
  edgeboxctl diagnose                        # 诊断问题
  edgeboxctl repair                          # 自动修复

故障排除:
  1. 服务无法启动: edgeboxctl diagnose → edgeboxctl repair
  2. 需要更换域名: edgeboxctl domain new-domain.com
  3. 切换代理模式: edgeboxctl proxy set/remove
  4. 查看错误日志: edgeboxctl logs error
  5. 完全重装: 先运行卸载脚本，再运行安装脚本

报告问题: https://github.com/your-repo/issues
USAGE
}

# === 主程序入口 ===
main() {
    check_root
    
    # 确保工作目录存在
    mkdir -p "$WORK_DIR" "$BACKUP_DIR"
    
    # 加载配置
    load_config
    
    # 解析命令
    case "${1:-help}" in
        status)
            show_status
            ;;
        restart)
            restart_all_services
            ;;
        diagnose)
            diagnose
            ;;
        repair)
            smart_repair
            ;;
        reinstall)
            smart_reinstall
            ;;
        domain)
            update_domain "${2:-}"
            ;;
        proxy)
            update_proxy "${2:-status}" "${3:-}"
            ;;
        sub)
            show_subscription
            ;;
        sub-regen)
            regenerate_credentials
            ;;
        logs)
            show_logs "${2:-all}" "${3:-50}"
            ;;
        backup)
            create_backup "${2:-manual}"
            ;;
        restore)
            restore_backup "${2:-}"
            ;;
        traffic)
            show_traffic
            ;;
        version)
            show_version
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            error "未知命令: $1 (使用 'edgeboxctl help' 查看帮助)"
            ;;
    esac
}

# 执行主程序
main "$@"

check_protocol_status() {
    local protocols=("grpc" "ws" "reality" "hy2" "tuic")
    
    for proto in "${protocols[@]}"; do
        case $proto in
            grpc|ws)
                if [[ -f "$XRAY_CONFIG" ]] && grep -q "$proto" "$XRAY_CONFIG" 2>/dev/null; then
                    printf "║   %-10s: ${GREEN}✓ 已启用${NC}                             ║\n" "VLESS-${proto^^}"
                else
                    printf "║   %-10s: ${YELLOW}○ 未启用${NC}                             ║\n" "VLESS-${proto^^}"
                fi
                ;;
            reality|hy2|tuic)
                if [[ -f "$CONFIG_DIR/config.json" ]] && grep -q "$proto" "$CONFIG_DIR/config.json" 2>/dev/null; then
                    local name="Reality"
                    [[ "$proto" == "hy2" ]] && name="Hysteria2"
                    [[ "$proto" == "tuic" ]] && name="TUIC"
                    printf "║   %-10s: ${GREEN}✓ 已启用${NC}                             ║\n" "$name"
                else
                    local name="Reality"
                    [[ "$proto" == "hy2" ]] && name="Hysteria2"
                    [[ "$proto" == "tuic" ]] && name="TUIC"
                    printf "║   %-10s: ${YELLOW}○ 未启用${NC}                             ║\n" "$name"
                fi
                ;;
        esac
    done
}

# === 代理配置管理（热更新）===
update_proxy() {
    local action="$1"
    shift
    
    case $action in
        set)
            local proxy_config="$1"
            if [[ -z "$proxy_config" ]]; then
                error "请提供代理配置，格式: HOST:PORT:USER:PASS 或 HOST:PORT"
            fi
            
            # 解析代理配置
            IFS=':' read -r PROXY_HOST PROXY_PORT PROXY_USER PROXY_PASS <<< "$proxy_config"
            
            if [[ -z "$PROXY_HOST" || -z "$PROXY_PORT" ]]; then
                error "代理配置格式错误"
            fi
            
            log "正在更新代理配置..."
            
            # 保存配置
            save_config "proxy_host" "$PROXY_HOST"
            save_config "proxy_port" "$PROXY_PORT"
            [[ -n "$PROXY_USER" ]] && save_config "proxy_user" "$PROXY_USER"
            [[ -n "$PROXY_PASS" ]] && save_config "proxy_pass" "$PROXY_PASS"
            save_config "use_proxy" "true"
            
            # 热更新配置
            update_xray_proxy "$PROXY_HOST" "$PROXY_PORT" "$PROXY_USER" "$PROXY_PASS"
            update_singbox_proxy "$PROXY_HOST" "$PROXY_PORT" "$PROXY_USER" "$PROXY_PASS"
            
            # 重载服务
            systemctl reload-or-restart xray 2>/dev/null || true
            systemctl reload-or-restart sing-box 2>/dev/null || true
            
            success "代理配置已更新: ${PROXY_HOST}:${PROXY_PORT}"
            ;;
            
        remove)
            log "移除代理配置，切换到直连模式..."
            
            save_config "use_proxy" "false"
            
            # 更新为直连模式
            update_xray_direct
            update_singbox_direct
            
            # 重载服务
            systemctl reload-or-restart xray 2>/dev/null || true
            systemctl reload-or-restart sing-box 2>/dev/null || true
            
            success "已切换到直连模式"
            ;;
            
        status)
            load_config
            if [[ "${use_proxy:-false}" == "true" ]]; then
                echo "代理状态: ${GREEN}已启用${NC}"
                echo "代理服务器: ${proxy_host:-}:${proxy_port:-}"
                [[ -n "${proxy_user:-}" ]] && echo "认证用户: ${proxy_user}"
            else
                echo "代理状态: ${YELLOW}未启用（直连模式）${NC}"
            fi
            ;;
            
        *)
            error "未知操作: $action"
            ;;
    esac
}

update_xray_proxy() {
    local host="$1" port="$2" user="$3" pass="$4"
    
    [[ ! -f "$XRAY_CONFIG" ]] && return
    
    # 创建新的出站配置
    local proxy_outbound=$(cat << EOF
{
    "protocol": "http",
    "tag": "proxy",
    "settings": {
        "servers": [{
            "address": "$host",
            "port": $port$(
            if [[ -n "$user" && -n "$pass" ]]; then
                echo ",
            \"users\": [{
                \"user\": \"$user\",
                \"pass\": \"$pass\"
            }]"
            fi
            )
        }]
    }
}
EOF
    )
    
    # 使用 jq 更新配置
    jq --argjson proxy "$proxy_outbound" '
        .outbounds = [.outbounds[0], $proxy] |
        .routing.rules = [
            {
                "type": "field",
                "domain": ["domain:googlevideo.com", "domain:ytimg.com", "domain:ggpht.com"],
                "outboundTag": "direct"
            },
            {
                "type": "field",
                "outboundTag": "proxy"
            }
        ]
    ' "$XRAY_CONFIG" > "$XRAY_CONFIG.tmp"
    
    mv "$XRAY_CONFIG.tmp" "$XRAY_CONFIG"
}

update_xray_direct() {
    [[ ! -f "$XRAY_CONFIG" ]] && return
    
    # 移除代理出站和路由规则
    jq '
        .outbounds = [.outbounds[0]] |
        .routing.rules = []
    ' "$XRAY_CONFIG" > "$XRAY_CONFIG.tmp"
    
    mv "$XRAY_CONFIG.tmp" "$XRAY_CONFIG"
}

update_singbox_proxy() {
    local host="$1" port="$2" user="$3" pass="$4"
    
    [[ ! -f "$CONFIG_DIR/config.json" ]] && return
    
    # 创建代理出站
    local proxy_outbound=$(cat << EOF
{
    "type": "http",
    "tag": "proxy",
    "server": "$host",
    "server_port": $port$(
        if [[ -n "$user" && -n "$pass" ]]; then
            echo ",
    \"username\": \"$user\",
    \"password\": \"$pass\""
        fi
    )
}
EOF
    )
    
    # 使用 jq 更新配置
    jq --argjson proxy "$proxy_outbound" '
        .outbounds = [.outbounds[0], $proxy] |
        .route = {
            "rules": [
                {
                    "domain_suffix": ["googlevideo.com", "ytimg.com", "ggpht.com"],
                    "outbound": "direct"
                },
                {
                    "outbound": "proxy"
                }
            ]
        }
    ' "$CONFIG_DIR/config.json" > "$CONFIG_DIR/config.json.tmp"
    
    mv "$CONFIG_DIR/config.json.tmp" "$CONFIG_DIR/config.json"
}

update_singbox_direct() {
    [[ ! -f "$CONFIG_DIR/config.json" ]] && return
    
    # 移除代理出站和路由
    jq '
        .outbounds = [.outbounds[0]] |
        del(.route)
    ' "$CONFIG_DIR/config.json" > "$CONFIG_DIR/config.json.tmp"
    
    mv "$CONFIG_DIR/config.json.tmp" "$CONFIG_DIR/config.json"
}

# === 协议管理（热启用/禁用）===
manage_protocol() {
    local action="$1"
    local protocol="$2"
    
    case $action in
        enable)
            enable_protocol "$protocol"
            ;;
        disable)
            disable_protocol "$protocol"
            ;;
        list)
            list_protocols
            ;;
        *)
            error "未知操作: $action"
            ;;
    esac
}

enable_protocol() {
    local protocol="$1"
    
    case $protocol in
        grpc|ws)
            log "启用 VLESS-${protocol^^} 协议..."
            
            # 确保 Xray 已安装
            if [[ ! -f "/usr/local/bin/xray" ]]; then
                warn "Xray 未安装，正在安装..."
                install_xray_component
            fi
            
            # 更新 Xray 配置
            enable_xray_protocol "$protocol"
            
            # 更新 Nginx 配置
            update_nginx_for_protocol "$protocol" "enable"
            
            # 重启服务
            systemctl restart xray nginx
            
            success "VLESS-${protocol^^} 协议已启用"
            ;;
            
        reality|hy2|tuic)
            log "启用 ${protocol} 协议..."
            
            # 更新 sing-box 配置
            enable_singbox_protocol "$protocol"
            
            # 如果启用 Reality，需要调整 Nginx 端口
            if [[ "$protocol" == "reality" ]]; then
                update_nginx_port 8443
            fi
            
            # 重启服务
            systemctl restart sing-box
            [[ "$protocol" == "reality" ]] && systemctl restart nginx
            
            success "${protocol} 协议已启用"
            ;;
            
        *)
            error "未知协议: $protocol"
            ;;
    esac
}

disable_protocol() {
    local protocol="$1"
    
    # 检查是否为最后一个协议
    if is_last_protocol; then
        warn "这是最后一个启用的协议，无法禁用"
        warn "请先启用其他协议后再禁用此协议"
        return 1
    fi
    
    case $protocol in
        grpc|ws)
            log "禁用 VLESS-${protocol^^} 协议..."
            
            # 更新配置
            disable_xray_protocol "$protocol"
            update_nginx_for_protocol "$protocol" "disable"
            
            # 重启服务
            systemctl restart xray nginx
            
            success "VLESS-${protocol^^} 协议已禁用"
            ;;
            
        reality|hy2|tuic)
            log "禁用 ${protocol} 协议..."
            
            # 更新配置
            disable_singbox_protocol "$protocol"
            
            # 如果禁用 Reality，恢复 Nginx 端口
            if [[ "$protocol" == "reality" ]]; then
                update_nginx_port 443
            fi
            
            # 重启服务
            systemctl restart sing-box
            [[ "$protocol" == "reality" ]] && systemctl restart nginx
            
            success "${protocol} 协议已禁用"
            ;;
            
        *)
            error "未知协议: $protocol"
            ;;
    esac
}

is_last_protocol() {
    local enabled_count=0
    
    # 统计启用的协议数量
    if [[ -f "$XRAY_CONFIG" ]]; then
        grep -q "grpc" "$XRAY_CONFIG" 2>/dev/null && ((enabled_count++))
        grep -q "ws" "$XRAY_CONFIG" 2>/dev/null && ((enabled_count++))
    fi
    
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        grep -q "reality" "$CONFIG_DIR/config.json" 2>/dev/null && ((enabled_count++))
        grep -q "hysteria2" "$CONFIG_DIR/config.json" 2>/dev/null && ((enabled_count++))
        grep -q "tuic" "$CONFIG_DIR/config.json" 2>/dev/null && ((enabled_count++))
    fi
    
    [[ $enabled_count -le 1 ]]
}

# === 域名和证书管理 ===
update_domain() {
    local new_domain="$1"
    
    if [[ -z "$new_domain" ]]; then
        read -rp "请输入新域名: " new_domain
    fi
    
    if [[ ! "$new_domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9]$ ]]; then
        error "域名格式不正确"
    fi
    
    log "更新域名为: $new_domain"
    
    # 保存新域名
    echo "$new_domain" > "$WORK_DIR/domain"
    save_config "domain" "$new_domain"
    
    # 申请新证书
    log "申请新证书..."
    if request_certificate "$new_domain"; then
        success "证书申请成功"
    else
        warn "证书申请失败，使用自签名证书"
        generate_self_signed_cert "$new_domain"
    fi
    
    # 更新 Nginx 配置
    update_nginx_domain "$new_domain"
    
    # 重启服务
    systemctl restart nginx sing-box
    
    success "域名已更新为: $new_domain"
    
    # 显示新的订阅链接
    echo
    show_subscription
}

request_certificate() {
    local domain="$1"
    
    # 检查域名解析
    local domain_ip=$(dig +short "$domain" 2>/dev/null | tail -n1)
    local server_ip=$(curl -s https://ipv4.icanhazip.com/ 2>/dev/null)
    
    if [[ -z "$domain_ip" || "$domain_ip" != "$server_ip" ]]; then
        warn "域名未正确解析到本机"
        return 1
    fi
    
    # 确保80端口开放
    ufw allow 80/tcp >/dev/null 2>&1
    
    # 申请证书
    if certbot certonly --nginx --non-interactive --agree-tos \
       --email "admin@${domain}" -d "$domain" 2>/dev/null; then
        
        # 链接证书
        ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" /etc/ssl/edgebox/cert.pem
        ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem" /etc/ssl/edgebox/key.pem
        
        return 0
    fi
    
    return 1
}

generate_self_signed_cert() {
    local domain="${1:-edgebox.local}"
    
    mkdir -p /etc/ssl/edgebox
    
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout /etc/ssl/edgebox/key.pem \
        -out /etc/ssl/edgebox/cert.pem \
        -subj "/CN=${domain}" 2>/dev/null
}

# === 订阅管理 ===
show_subscription() {
    local domain=$(cat "$WORK_DIR/domain" 2>/dev/null || echo "edgebox.local")
    local server_ip=$(curl -s https://ipv4.icanhazip.com/ 2>/dev/null || hostname -I | awk '{print $1}')
    
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                    订阅链接信息                          ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    
    # 如果域名是默认的，使用IP
    if [[ "$domain" == "edgebox.local" ]]; then
        domain="$server_ip"
    fi
    
    # VLESS-gRPC
    if [[ -f "$WORK_DIR/xray-uuid" ]] && grep -q "grpc" "$XRAY_CONFIG" 2>/dev/null; then
        local uuid=$(cat "$WORK_DIR/xray-uuid")
        echo "║ VLESS-gRPC:                                              ║"
        echo "║ vless://${uuid}@${domain}:8443?encryption=none&security=tls&type=grpc&serviceName=edgebox-grpc&fp=chrome#EdgeBox-gRPC"
        echo "╠══════════════════════════════════════════════════════════╣"
    fi
    
    # VLESS-WebSocket
    if [[ -f "$WORK_DIR/xray-uuid" ]] && grep -q "ws" "$XRAY_CONFIG" 2>/dev/null; then
        local uuid=$(cat "$WORK_DIR/xray-uuid")
        echo "║ VLESS-WebSocket:                                         ║"
        echo "║ vless://${uuid}@${domain}:8443?encryption=none&security=tls&type=ws&path=/edgebox-ws&host=${domain}&fp=chrome#EdgeBox-WS"
        echo "╠══════════════════════════════════════════════════════════╣"
    fi
    
    # VLESS-Reality
    if [[ -f "$WORK_DIR/reality-uuid" ]] && grep -q "reality" "$CONFIG_DIR/config.json" 2>/dev/null; then
        local uuid=$(cat "$WORK_DIR/reality-uuid")
        local pubkey=$(cat "$WORK_DIR/reality-public-key")
        local sid=$(cat "$WORK_DIR/reality-short-id")
        echo "║ VLESS-Reality:                                           ║"
        echo "║ vless://${uuid}@${domain}:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=www.cloudflare.com&pbk=${pubkey}&sid=${sid}&type=tcp#EdgeBox-Reality"
        echo "╠══════════════════════════════════════════════════════════╣"
    fi
    
    # Hysteria2
    if [[ -f "$WORK_DIR/hy2-password" ]] && grep -q "hysteria2" "$CONFIG_DIR/config.json" 2>/dev/null; then
        local password=$(cat "$WORK_DIR/hy2-password")
        echo "║ Hysteria2:                                               ║"
        echo "║ hysteria2://${password}@${domain}:443/?insecure=1#EdgeBox-Hysteria2"
        echo "╠══════════════════════════════════════════════════════════╣"
    fi
    
    # TUIC
    if [[ -f "$WORK_DIR/tuic-uuid" ]] && grep -q "tuic" "$CONFIG_DIR/config.json" 2>/dev/null; then
        local uuid=$(cat "$WORK_DIR/tuic-uuid")
        local password=$(cat "$WORK_DIR/tuic-password")
        echo "║ TUIC:                                                    ║"
        echo "║ tuic://${uuid}:${password}@${domain}:2053?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#EdgeBox-TUIC"
        echo "╠══════════════════════════════════════════════════════════╣"
    fi
    
    echo "║ 聚合订阅: http://${domain}:8080/sub                      ║"
    echo "╚══════════════════════════════════════════════════════════╝"
}

regenerate_credentials() {
    warn "此操作将重新生成所有UUID和密码，客户端需要重新配置"
    read -rp "确定要继续吗？[y/N]: " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "操作已取消"
        return
    fi
    
    log "重新生成凭据..."
    
    # 备份当前配置
    create_backup
    
    # 生成新的 UUID 和密码
    local new_xray_uuid=$(uuidgen)
    local new_reality_uuid=$(uuidgen)
    local new_hy2_password=$(openssl rand -base64 16 | tr -d '=+/\n' | cut -c1-12)
    local new_tuic_uuid=$(uuidgen)
    local new_tuic_password=$(openssl rand -hex 8)
    
    # 保存新凭据
    echo "$new_xray_uuid" > "$WORK_DIR/xray-uuid"
    echo "$new_reality_uuid" > "$WORK_DIR/reality-uuid"
    echo "$new_hy2_password" > "$WORK_DIR/hy2-password"
    echo "$new_tuic_uuid" > "$WORK_DIR/tuic-uuid"
    echo "$new_tuic_password" > "$WORK_DIR/tuic-password"
    
    # 更新配置文件
    if [[ -f "$XRAY_CONFIG" ]]; then
        jq --arg uuid "$new_xray_uuid" '
            .inbounds[].settings.clients[0].id = $uuid
        ' "$XRAY_CONFIG" > "$XRAY_CONFIG.tmp"
        mv "$XRAY_CONFIG.tmp" "$XRAY_CONFIG"
    fi
    
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        jq --arg reality_uuid "$new_reality_uuid" \
           --arg hy2_pass "$new_hy2_password" \
           --arg tuic_uuid "$new_tuic_uuid" \
           --arg tuic_pass "$new_tuic_password" '
            .inbounds |= map(
                if .type == "vless" then .users[0].uuid = $reality_uuid
                elif .type == "hysteria2" then .users[0].password = $hy2_pass
                elif .type == "tuic" then .users[0] = {uuid: $tuic_uuid, password: $tuic_pass}
                else . end
            )
        ' "$CONFIG_DIR/config.json" > "$CONFIG_DIR/config.json.tmp"
        mv "$CONFIG_DIR/config.json.tmp" "$CONFIG_DIR/config.json"
    fi
    
    # 重启服务
    restart_all_services
    
    success "凭据已重新生成"
    
    # 显示新的订阅链接
    echo
    show_subscription
}

# === 流量统计 ===
show_traffic() {
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                      流量统计                            ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    
    # 系统流量统计
    if command -v vnstat >/dev/null; then
        local iface=$(ip route | awk '/default/ { print $5 }' | head -n1)
        echo "║ 系统流量 (${iface}):                                     ║"
        vnstat -i "$iface" --oneline | awk -F';' '{
            printf "║   今日: ↓%s ↑%s                                         ║\n", $4, $5
            printf "║   本月: ↓%s ↑%s                                         ║\n", $9, $10
        }'
    fi
    
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ 实时连接:                                                ║"
    
    # 实时连接统计
    local conn_443=$(ss -tn state established '( sport = :443 )' | wc -l)
    local conn_8443=$(ss -tn state established '( sport = :8443 )' | wc -l)
    local conn_2053=$(ss -un state established '( sport = :2053 )' | wc -l)
    
    printf "║   TCP/443:  %-3d 个连接                                  ║\n" "$((conn_443-1))"
    printf "║   TCP/8443: %-3d 个连接                                  ║\n" "$((conn_8443-1))"
    printf "║   UDP/2053: %-3d 个连接                                  ║\n" "$((conn_2053-1))"
    
    echo "╚══════════════════════════════════════════════
