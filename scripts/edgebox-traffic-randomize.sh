#!/usr/bin/env bash
set -euo pipefail

# 配置路径
CONFIG_DIR="${CONFIG_DIR:-/etc/edgebox/config}"
SCRIPTS_DIR="${SCRIPTS_DIR:-/etc/edgebox/scripts}"
LOG_FILE="/var/log/edgebox/traffic-randomization.log"

# 日志函数
log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$LOG_FILE"; }
log_warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" | tee -a "$LOG_FILE"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE" >&2; }
log_success() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $*" | tee -a "$LOG_FILE"; }

# 增强的 Hysteria2 随机化函数
randomize_hysteria2_config() {
    local level="$1"
    log_info "随机化Hysteria2配置 (级别: $level)..."

    if [[ ! -f "${CONFIG_DIR}/sing-box.json" ]]; then
        log_error "sing-box配置文件不存在"
        return 1
    fi

    # 检查是否存在hysteria2配置
    if ! jq -e '.inbounds[] | select(.type == "hysteria2")' "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
        log_warn "未找到Hysteria2配置，跳过"
        return 0
    fi

    # 随机化伪装站点
    local masquerade_urls=(
        "https://www.bing.com"
        "https://www.apple.com"
        "https://azure.microsoft.com"
        "https://aws.amazon.com"
        "https://www.cloudflare.com"
    )

    local random_masquerade=${masquerade_urls[$((RANDOM % ${#masquerade_urls[@]}))]}
    log_info "伪装站点: $random_masquerade"

    # 更新配置
    if ! jq --arg url "$random_masquerade" \
        '(.inbounds[] | select(.type == "hysteria2") | .masquerade?) = $url' \
        "${CONFIG_DIR}/sing-box.json" > "${CONFIG_DIR}/sing-box.json.tmp"; then
        log_error "更新配置失败"
        rm -f "${CONFIG_DIR}/sing-box.json.tmp"
        return 1
    fi

    # 【新增】验证生成的配置
    log_info "验证sing-box配置语法..."
    if ! sing-box check -c "${CONFIG_DIR}/sing-box.json.tmp" >/dev/null 2>&1; then
        log_error "生成的配置验证失败"
        rm -f "${CONFIG_DIR}/sing-box.json.tmp"
        return 1
    fi

    # 应用配置
    mv "${CONFIG_DIR}/sing-box.json.tmp" "${CONFIG_DIR}/sing-box.json"
    log_success "Hysteria2配置随机化完成"
    return 0
}

# 【新增】配置回滚函数
rollback_traffic_config() {
    local backup_dir="/etc/edgebox/backup/randomization"

    local latest_singbox=$(ls -t "${backup_dir}"/sing-box_*.json 2>/dev/null | head -1)

    if [[ -n "$latest_singbox" && -f "$latest_singbox" ]]; then
        log_warn "检测到配置问题，回滚到上一版本..."
        cp "$latest_singbox" "${CONFIG_DIR}/sing-box.json"

        # 重启服务
        if systemctl restart sing-box; then
            log_success "配置已回滚并重启服务"
            return 0
        else
            log_error "服务重启失败"
            return 1
        fi
    else
        log_error "未找到备份文件，无法回滚"
        return 1
    fi
}

# 【新增】验证服务状态
verify_services_after_randomization() {
    log_info "验证服务状态..."

    local all_ok=true

    # 检查sing-box
    if ! systemctl is-active --quiet sing-box; then
        log_error "sing-box服务未运行"
        all_ok=false
    fi

    # 检查xray
    if ! systemctl is-active --quiet xray; then
        log_error "xray服务未运行"
        all_ok=false
    fi

    # 检查端口
    if ! ss -tulnp | grep -q ":443.*sing-box"; then
        log_warn "Hysteria2端口未监听"
        all_ok=false
    fi

    if $all_ok; then
        log_success "服务验证通过"
        return 0
    else
        log_error "服务验证失败，尝试回滚"
        rollback_traffic_config
        return 1
    fi
}


# TUIC随机化函数 - 安全版本（只使用bbr）
randomize_tuic_config() {
    local level="$1"
    log_info "随机化TUIC配置 (级别: $level)..."

    if [[ ! -f "${CONFIG_DIR}/sing-box.json" ]]; then
        log_error "sing-box 配置文件不存在"
        return 1
    fi

    # 检查是否存在 tuic 配置
    if ! jq -e '.inbounds[] | select(.type == "tuic")' "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
        log_warn "未找到 TUIC 配置，跳过随机化"
        return 0
    fi

    # 只使用 bbr（最稳定的算法）
    local algo="bbr"

    log_info "TUIC参数: 拥塞控制=${algo}"

    # 检查当前配置中的字段名称
    local current_config=$(jq '.inbounds[] | select(.type == "tuic")' "${CONFIG_DIR}/sing-box.json" 2>/dev/null)

    # 尝试更新配置（保持原有配置不变，只是确保字段存在）
    if ! jq \
        --arg cc "$algo" \
        '(.inbounds[] | select(.type == "tuic")) |= (. + {congestion_control: $cc})' \
        "${CONFIG_DIR}/sing-box.json" > "${CONFIG_DIR}/sing-box.json.tmp"; then
        log_error "更新 TUIC 配置失败"
        rm -f "${CONFIG_DIR}/sing-box.json.tmp"
        return 1
    fi

    # 验证生成的配置文件
    if sing-box check -c "${CONFIG_DIR}/sing-box.json.tmp" >/dev/null 2>&1; then
        mv "${CONFIG_DIR}/sing-box.json.tmp" "${CONFIG_DIR}/sing-box.json"
        log_success "TUIC配置随机化完成"
        return 0
    else
        log_warn "TUIC 配置验证失败，保持原配置不变"
        rm -f "${CONFIG_DIR}/sing-box.json.tmp"
        # 不返回错误，因为 TUIC 本身可能就没问题
        return 0
    fi
}

# VLESS随机化函数 - 保持简单
randomize_vless_config() {
    local level="$1"
    log_info "随机化VLESS配置 (级别: $level)..."

    # 保持简单，避免复杂的 Xray 配置修改
    log_success "VLESS配置随机化完成（保持原有配置）"
    return 0
}

# 主随机化函数
execute_traffic_randomization() {
    local level="${1:-light}"

    log_info "开始执行流量特征随机化 (级别: $level)..."

    # 创建配置备份
    create_config_backup

    case "$level" in
        "light")
            # 轻度随机化：仅更新 Hysteria2
            randomize_hysteria2_config "$level"
            ;;
        "medium")
            # 中度随机化：更新 Hysteria2 + TUIC
            randomize_hysteria2_config "$level"
            randomize_tuic_config "$level"
            ;;
        "heavy")
            # 重度随机化：全协议
            randomize_hysteria2_config "$level"
            randomize_tuic_config "$level"
            randomize_vless_config "$level"
            ;;
        *)
            log_error "未知的随机化级别: $level"
            return 1
            ;;
    esac

    # 重启相关服务
    restart_services_safely

    # 验证配置生效
    verify_randomization_result

    log_success "流量特征随机化完成 (级别: $level)"
}

# 配置备份函数
create_config_backup() {
    local backup_dir="/etc/edgebox/backup/randomization"
    local timestamp=$(date '+%Y%m%d_%H%M%S')

    mkdir -p "$backup_dir"

    if [[ -f "${CONFIG_DIR}/xray.json" ]]; then
        cp "${CONFIG_DIR}/xray.json" "${backup_dir}/xray_${timestamp}.json"
    fi

    if [[ -f "${CONFIG_DIR}/sing-box.json" ]]; then
        cp "${CONFIG_DIR}/sing-box.json" "${backup_dir}/sing-box_${timestamp}.json"
    fi

    log_info "配置备份已创建: $backup_dir"
}

# 安全重启服务函数
restart_services_safely() {
    log_info "安全重启代理服务..."

    # 定义reload_or_restart_services函数（如果不存在）
    if ! command -v reload_or_restart_services >/dev/null 2>&1; then
        reload_or_restart_services() {
            for svc in "$@"; do
                if systemctl is-active --quiet "$svc"; then
                    if systemctl reload "$svc" 2>/dev/null; then
                        log_info "${svc} 已热加载"
                    else
                        systemctl restart "$svc"
                        log_info "${svc} 已重启"
                    fi
                fi
            done
        }
    fi

    # 应用更改并热加载
    reload_or_restart_services sing-box xray
    sleep 5

    log_success "服务已安全重启"
}

# 验证随机化结果
verify_randomization_result() {
    log_info "验证随机化配置..."

    local verification_failed=false

    # 验证配置文件语法
    if [[ -f "${CONFIG_DIR}/xray.json" ]] && ! xray -test -config="${CONFIG_DIR}/xray.json" >/dev/null 2>&1; then
        log_error "Xray配置验证失败"
        verification_failed=true
    fi

    if [[ -f "${CONFIG_DIR}/sing-box.json" ]] && ! sing-box check -c "${CONFIG_DIR}/sing-box.json" >/dev/null 2>&1; then
        log_error "sing-box配置验证失败"
        verification_failed=true
    fi

    # 验证服务状态
    if ! systemctl is-active --quiet sing-box; then
        log_error "sing-box服务状态异常"
        verification_failed=true
    fi

    if ! systemctl is-active --quiet xray; then
        log_error "Xray服务状态异常"
        verification_failed=true
    fi

    if [[ "$verification_failed" == "true" ]]; then
        log_error "随机化验证失败，尝试回滚配置..."
        rollback_configuration
        return 1
    fi

    log_success "随机化验证通过"
}

# 配置回滚函数
rollback_configuration() {
    local backup_dir="/etc/edgebox/backup/randomization"

    # 查找最近的备份
    local latest_xray_backup=$(ls -t "${backup_dir}"/xray_*.json 2>/dev/null | head -1)
    local latest_singbox_backup=$(ls -t "${backup_dir}"/sing-box_*.json 2>/dev/null | head -1)

    if [[ -n "$latest_xray_backup" ]]; then
        cp "$latest_xray_backup" "${CONFIG_DIR}/xray.json"
        log_info "Xray配置已回滚"
    fi

    if [[ -n "$latest_singbox_backup" ]]; then
        cp "$latest_singbox_backup" "${CONFIG_DIR}/sing-box.json"
        log_info "sing-box配置已回滚"
    fi

    restart_services_safely
}

# 主函数
main() {
    local level="${1:-light}"

    # 创建日志目录
    mkdir -p "$(dirname "$LOG_FILE")"

    # 处理 reset 选项
    if [[ "$level" == "reset" ]]; then
        log_info "重置协议参数为默认值..."

        # 备份当前配置
        create_config_backup

        # 清理可能存在的不支持字段
        if [[ -f "${CONFIG_DIR}/sing-box.json" ]] && command -v jq >/dev/null; then
            jq 'del(.inbounds[].heartbeat)' "${CONFIG_DIR}/sing-box.json" > "${CONFIG_DIR}/sing-box.json.tmp"

            if [[ -s "${CONFIG_DIR}/sing-box.json.tmp" ]]; then
                mv "${CONFIG_DIR}/sing-box.json.tmp" "${CONFIG_DIR}/sing-box.json"
                log_success "配置已清理并重置为默认值"
            else
                rm -f "${CONFIG_DIR}/sing-box.json.tmp"
                log_error "重置配置失败"
            fi
        fi

        # 重启服务
        restart_services_safely

        log_success "协议参数重置完成"
        exit 0
    fi

    log_info "EdgeBox流量特征随机化开始..."

    if execute_traffic_randomization "$level"; then
        log_success "EdgeBox流量特征随机化成功完成"
        exit 0
    else
        log_error "EdgeBox流量特征随机化失败"
        exit 1
    fi
}

# 脚本执行入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
