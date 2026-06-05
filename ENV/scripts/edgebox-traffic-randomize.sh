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
    chmod 600 "${CONFIG_DIR}/sing-box.json"
    chown root:root "${CONFIG_DIR}/sing-box.json"
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

    # v4.6.0-rc4 (审核 P1#4): 逐步检查返回值，任一步失败立即返回非零，
    #   否则即使 verify_randomization_result 已失败回滚，仍会误报"完成"并 rc=0。
    create_config_backup || { log_error "配置备份失败"; return 1; }

    case "$level" in
        "light")
            # 轻度随机化：仅更新 Hysteria2
            randomize_hysteria2_config "$level" || return 1
            ;;
        "medium"|"heavy")
            # 中度/重度随机化：Hysteria2 + VLESS (v4.7.0: Reality + HY2)
            randomize_hysteria2_config "$level" || return 1
            randomize_vless_config "$level" || return 1
            ;;
        *)
            log_error "未知的随机化级别: $level"
            return 1
            ;;
    esac

    # 重启相关服务
    restart_services_safely || return 1

    # 验证配置生效
    verify_randomization_result || return 1

    log_success "流量特征随机化完成 (级别: $level)"
    return 0
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

    # v4.7.0 (审核 #2): 不再跳过 inactive 服务。
    #   旧逻辑用 `if systemctl is-active` 守卫，导致已停止的服务被直接跳过、
    #   既不重启也不计失败 → reset 在服务异常时仍假成功。
    #   现在：总是尝试 reload→restart，两者都失败即记失败；并校验最终在运行。
    local failed=0 svc
    for svc in sing-box xray; do
        if systemctl reload "$svc" 2>/dev/null; then
            log_info "${svc} 已热加载"
        elif systemctl restart "$svc" 2>/dev/null; then
            log_info "${svc} 已重启"
        else
            log_error "${svc} 重载/重启失败"
            failed=1
            continue
        fi

        if ! systemctl is-active --quiet "$svc"; then
            log_error "${svc} 重启后仍未运行"
            failed=1
        fi
    done

    sleep 3

    if [[ "$failed" -eq 0 ]]; then
        log_success "服务已安全重启"
    else
        log_error "服务重启失败"
    fi
    return "$failed"
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
        if ! create_config_backup; then
            log_error "重置失败：配置备份未成功，已中止"
            exit 1
        fi

        # 清理可能存在的不支持字段
        if [[ -f "${CONFIG_DIR}/sing-box.json" ]] && command -v jq >/dev/null; then
            if jq 'del(.inbounds[].heartbeat)' "${CONFIG_DIR}/sing-box.json" > "${CONFIG_DIR}/sing-box.json.tmp" \
               && [[ -s "${CONFIG_DIR}/sing-box.json.tmp" ]]; then
                mv "${CONFIG_DIR}/sing-box.json.tmp" "${CONFIG_DIR}/sing-box.json"
                chmod 600 "${CONFIG_DIR}/sing-box.json"
                chown root:root "${CONFIG_DIR}/sing-box.json"
                log_success "配置已清理并重置为默认值"
            else
                rm -f "${CONFIG_DIR}/sing-box.json.tmp"
                log_error "重置配置失败：sing-box.json 清理未成功，已中止"
                exit 1
            fi
        fi

        # 重启服务（失败必须传播，不能假成功）
        if ! restart_services_safely; then
            log_error "重置失败：服务重启未成功"
            exit 1
        fi

        # 重置后校验配置语法 + 服务状态（失败会回滚并退出非零）
        if ! verify_randomization_result; then
            log_error "重置后配置/服务校验失败"
            exit 1
        fi

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
