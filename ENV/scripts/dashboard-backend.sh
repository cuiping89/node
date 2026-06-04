#!/usr/bin/env bash
#############################################
# EdgeBox Dashboard 后端数据采集脚本
# 版本: 4.0.0
# 功能: 统一采集系统状态、服务状态、配置信息
# 输出: dashboard.json、system.json
#############################################

set -euo pipefail
export LANG=C LC_ALL=C

# 解析当前脚本所在目录，并为 SCRIPTS_DIR 提供默认值
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
: "${SCRIPTS_DIR:=${SCRIPT_DIR}}"

#############################################
# 配置和路径定义
#############################################

TRAFFIC_DIR="${TRAFFIC_DIR:-/etc/edgebox/traffic}"
CONFIG_DIR="${CONFIG_DIR:-/etc/edgebox/config}"
CERT_DIR="${CERT_DIR:-/etc/edgebox/cert}"
SERVER_JSON="${SERVER_JSON:-${CONFIG_DIR}/server.json}"
SHUNT_DIR="${CONFIG_DIR}/shunt"

# 日志函数
log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"; }
log_warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }



#############################################
# 安全数据获取函数
#############################################

# 安全的jq取值函数，避免空值和null导致的错误
safe_jq() {
    local query="$1"
    local file="$2"
    local default="${3:-}"

    if [[ ! -f "$file" ]]; then
        echo "$default"
        return
    fi

    local result
    result=$(jq -r "$query // empty" "$file" 2>/dev/null || echo "")

    if [[ -z "$result" || "$result" == "null" ]]; then
        echo "$default"
    else
        echo "$result"
    fi
}

# 安全读取列表文件：去BOM/CR、去首尾空白、过滤空行与#注释，输出JSON数组
jq_safe_list() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo '[]'
    return
  fi
  jq -n --rawfile RAW "$file" '
    ($RAW
     | gsub("^\uFEFF"; "")
     | split("\n")
     | map(.
         | gsub("\r"; "")
         | gsub("(^[[:space:]]+|[[:space:]]+$)"; ""))   # 去首尾空白
     | map(select(. != "" and (startswith("#") | not)))
    )'
}


# 获取系统负载信息
get_system_metrics() {
    local cpu_percent=0
    local memory_percent=0
    local disk_percent=0

    # 改进的CPU使用率计算
    if [[ -r /proc/stat ]]; then
        read _ user1 nice1 system1 idle1 iowait1 irq1 softirq1 _ < /proc/stat

        sleep 2

        read _ user2 nice2 system2 idle2 iowait2 irq2 softirq2 _ < /proc/stat

        local user_diff=$((user2 - user1))
        local nice_diff=$((nice2 - nice1))
        local system_diff=$((system2 - system1))
        local idle_diff=$((idle2 - idle1))
        local iowait_diff=$((iowait2 - iowait1))
        local irq_diff=$((irq2 - irq1))
        local softirq_diff=$((softirq2 - softirq1))

        local total_diff=$((user_diff + nice_diff + system_diff + idle_diff + iowait_diff + irq_diff + softirq_diff))
        local active_diff=$((total_diff - idle_diff))

        if [[ $total_diff -gt 0 ]]; then
            cpu_percent=$(( (active_diff * 1000) / total_diff ))
            cpu_percent=$((cpu_percent / 10))
            # 设置最小值为1%
            if [[ $cpu_percent -lt 1 ]]; then
                cpu_percent=1
            fi
        else
            cpu_percent=1
        fi
    fi

    # 内存使用率计算保持不变
    if [[ -r /proc/meminfo ]]; then
        local mem_total mem_available
        mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
        mem_available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)

        if [[ $mem_total -gt 0 && $mem_available -ge 0 ]]; then
            memory_percent=$(( (mem_total - mem_available) * 100 / mem_total ))
        fi
    fi

    # 磁盘使用率计算保持不变
    if command -v df >/dev/null 2>&1; then
        local disk_info
        disk_info=$(df / 2>/dev/null | tail -1)
        if [[ -n "$disk_info" ]]; then
            disk_percent=$(echo "$disk_info" | awk '{print $5}' | sed 's/%//')
        fi
    fi

    # 确保所有值在合理范围内
    cpu_percent=$(( cpu_percent > 100 ? 100 : cpu_percent ))
    cpu_percent=$(( cpu_percent < 1 ? 1 : cpu_percent ))
    memory_percent=$(( memory_percent > 100 ? 100 : memory_percent ))
    memory_percent=$(( memory_percent < 0 ? 0 : memory_percent ))
    disk_percent=$(( disk_percent > 100 ? 100 : disk_percent ))
    disk_percent=$(( disk_percent < 0 ? 0 : disk_percent ))

    # 输出JSON格式
    jq -n \
        --argjson cpu "$cpu_percent" \
        --argjson memory "$memory_percent" \
        --argjson disk "$disk_percent" \
        --arg timestamp "$(date -Is)" \
        '{
            updated_at: $timestamp,
            cpu: $cpu,
            memory: $memory,
            disk: $disk
        }'
}


# 获取系统详细信息
get_system_info() {
    # 从server.json读取基础信息
    local server_ip eip version install_date
    local cloud_provider cloud_region instance_id hostname user_alias
    local cpu_spec memory_spec disk_spec

    server_ip=$(safe_jq '.server_ip' "$SERVER_JSON" "127.0.0.1")
    eip=$(safe_jq '.eip' "$SERVER_JSON" "")
    version=$(safe_jq '.version' "$SERVER_JSON" "4.6.0-rc2")
    install_date=$(safe_jq '.install_date' "$SERVER_JSON" "")
    cloud_provider=$(safe_jq '.cloud.provider' "$SERVER_JSON" "Unknown")
    cloud_region=$(safe_jq '.cloud.region' "$SERVER_JSON" "Unknown")
    instance_id=$(safe_jq '.instance_id' "$SERVER_JSON" "Unknown")
    hostname=$(safe_jq '.hostname' "$SERVER_JSON" "$(hostname)")
    user_alias=$(safe_jq '.user_alias' "$SERVER_JSON" "")
    cpu_spec=$(safe_jq '.spec.cpu' "$SERVER_JSON" "Unknown")
    memory_spec=$(safe_jq '.spec.memory' "$SERVER_JSON" "Unknown")
    disk_spec=$(safe_jq '.spec.disk' "$SERVER_JSON" "Unknown")

    # 获取当前出口IP（尽量轻量）
    if [[ -z "$eip" ]]; then
        eip=$(curl -fsS --max-time 3 https://api.ip.sb/ip 2>/dev/null || \
              curl -fsS --max-time 3 https://ifconfig.me 2>/dev/null || \
              echo "")
    fi

    # 输出服务器信息JSON
    jq -n \
        --arg ip "$server_ip" \
        --arg eip "$eip" \
        --arg version "$version" \
        --arg install_date "$install_date" \
        --arg cloud_provider "$cloud_provider" \
        --arg cloud_region "$cloud_region" \
        --arg instance_id "$instance_id" \
        --arg hostname "$hostname" \
        --arg user_alias "$user_alias" \
        --arg cpu_spec "$cpu_spec" \
        --arg memory_spec "$memory_spec" \
        --arg disk_spec "$disk_spec" \
        '{
            server_ip: $ip,
            eip: (if $eip == "" then null else $eip end),
            version: $version,
            install_date: $install_date,
            cloud: {
                provider: $cloud_provider,
                region: $cloud_region
            },
            instance_id: $instance_id,
            hostname: $hostname,
            user_alias: $user_alias,
            spec: {
                cpu: $cpu_spec,
                memory: $memory_spec,
                disk: $disk_spec
            }
        }'
}

# 获取证书信息（Let’s Encrypt 与 自签名均可解析，expires_at => yyyy-mm-dd）
get_certificate_info() {
    local cert_mode="self-signed"
    local cert_domain=""
    local cert_expires_at=""
    local cert_renewal_type="manual"

    # 保持英文月份，避免本地化解析问题
    export LC_ALL=C

    # 读取证书模式
    if [[ -f "${CONFIG_DIR}/cert_mode" ]]; then
        cert_mode=$(cat "${CONFIG_DIR}/cert_mode")
    fi

    # 便携式解析：把 "notAfter=Sep 25 12:34:56 2026 GMT" → "2026-09-25"
    _parse_expire_date_portable() {
        local pem="$1"
        [[ -f "$pem" ]] || return 1

        # 读出 notAfter 原始字符串
        local raw_end
        raw_end=$(openssl x509 -enddate -noout -in "$pem" 2>/dev/null) || return 1
        raw_end=${raw_end#notAfter=}                         # 去掉前缀
        raw_end=$(printf '%s\n' "$raw_end" | awk '{$1=$1;print}')  # 压缩多空格

        # 期望形如：Mon DD HH:MM:SS YYYY TZ
        # 取出月份、日、年
        local mon dd yyyy
        mon=$(printf '%s\n' "$raw_end" | awk '{print $1}')
        dd=$( printf '%s\n' "$raw_end" | awk '{print $2}')
        yyyy=$(printf '%s\n' "$raw_end" | awk '{print $4}')

        # 月份映射
        local mm
        case "$mon" in
            Jan) mm=01 ;; Feb) mm=02 ;; Mar) mm=03 ;; Apr) mm=04 ;;
            May) mm=05 ;; Jun) mm=06 ;; Jul) mm=07 ;; Aug) mm=08 ;;
            Sep) mm=09 ;; Oct) mm=10 ;; Nov) mm=11 ;; Dec) mm=12 ;;
            *)   return 1 ;;
        esac

        # 日补零
        if [[ "$dd" =~ ^[0-9]$ ]]; then
            dd="0$dd"
        fi

        # 基本校验
        [[ -n "$yyyy" && -n "$mm" && -n "$dd" ]] || return 1

        printf '%s-%s-%s' "$yyyy" "$mm" "$dd"
        return 0
    }

    # 确定证书文件路径（两类都处理好）
    local cert_file=""
    if [[ "$cert_mode" =~ ^letsencrypt ]]; then
        # ---- Let's Encrypt ----
        cert_domain="${cert_mode#letsencrypt:}"
        cert_renewal_type="auto"

        if [[ -n "$cert_domain" ]]; then
            if [[ -f "/etc/letsencrypt/live/${cert_domain}/cert.pem" ]]; then
                cert_file="/etc/letsencrypt/live/${cert_domain}/cert.pem"
            elif [[ -f "/etc/letsencrypt/live/${cert_domain}/fullchain.pem" ]]; then
                cert_file="/etc/letsencrypt/live/${cert_domain}/fullchain.pem"
            fi
        fi

        # 兜底：未指定域名时，尝试 live 目录下的第一个证书
        if [[ -z "$cert_file" && -d /etc/letsencrypt/live ]]; then
            local first_live
            first_live=$(find /etc/letsencrypt/live -maxdepth 1 -mindepth 1 -type d | head -n1)
            if [[ -n "$first_live" ]]; then
                cert_domain="${first_live##*/}"
                if [[ -f "${first_live}/cert.pem" ]]; then
                    cert_file="${first_live}/cert.pem"
                elif [[ -f "${first_live}/fullchain.pem" ]]; then
                    cert_file="${first_live}/fullchain.pem"
                fi
            fi
        fi
    else
        # ---- 自签名 ----
        cert_file="${CERT_DIR}/current.pem"
        [[ -f "$cert_file" ]] || cert_file="${CERT_DIR}/self-signed.pem"
    fi

    # 解析到期时间（统一用便携式解析）
    if [[ -n "$cert_file" ]]; then
        cert_expires_at="$(_parse_expire_date_portable "$cert_file")" || cert_expires_at=""
    fi

    # 输出 JSON（空串转 null）
    jq -n \
      --arg mode "$cert_mode" \
      --arg domain "$cert_domain" \
      --arg expires_at "$cert_expires_at" \
      --arg renewal_type "$cert_renewal_type" \
      '{
          mode: $mode,
          domain: (if $domain == "" then null else $domain end),
          expires_at: (if $expires_at == "" then null else $expires_at end),
          renewal_type: $renewal_type
      }'
}


# 获取服务状态
get_services_status() {
    local nginx_status xray_status singbox_status

    # 检查服务状态
    nginx_status=$(systemctl is-active nginx 2>/dev/null || echo "inactive")
    xray_status=$(systemctl is-active xray 2>/dev/null || echo "inactive")
    singbox_status=$(systemctl is-active sing-box 2>/dev/null || echo "inactive")

    # 获取服务版本（可选）
    local nginx_version xray_version singbox_version
    nginx_version=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    xray_version=$(xray version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")

    if command -v sing-box >/dev/null 2>&1; then
        singbox_version=$(sing-box version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    elif command -v /usr/local/bin/sing-box >/dev/null 2>&1; then
        singbox_version=$(/usr/local/bin/sing-box version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    else
        singbox_version=""
    fi

    # 输出服务状态JSON
    jq -n \
        --arg nginx_status "$nginx_status" \
        --arg xray_status "$xray_status" \
        --arg singbox_status "$singbox_status" \
        --arg nginx_version "$nginx_version" \
        --arg xray_version "$xray_version" \
        --arg singbox_version "$singbox_version" \
        '{
            nginx: {
                status: $nginx_status,
                version: (if $nginx_version == "" then null else $nginx_version end)
            },
            xray: {
                status: $xray_status,
                version: (if $xray_version == "" then null else $xray_version end)
            },
            "sing-box": {
                status: $singbox_status,
                version: (if $singbox_version == "" then null else $singbox_version end)
            }
        }'
}


# 获取协议配置状态 (最终修正版 - 动态主机名 + 动态SNI)
get_protocols_status() {
    local health_report_file="${TRAFFIC_DIR}/protocol-health.json"
    local server_config_file="${CONFIG_DIR}/server.json"
    local xray_config_file="${CONFIG_DIR}/xray.json"

    # Dynamically determine to use domain or IP
    local host_or_ip
    local cert_mode_file="${CONFIG_DIR}/cert_mode"
    if [[ -f "$cert_mode_file" ]] && grep -q "letsencrypt:" "$cert_mode_file"; then
        host_or_ip=$(cat "$cert_mode_file" | cut -d: -f2)
    else
        host_or_ip=$(jq -r '.server_ip // "127.0.0.1"' "$server_config_file" 2>/dev/null || echo "127.0.0.1")
    fi

    # Dynamically read the current Reality SNI from xray.json
    local reality_sni
    reality_sni="$(jq -r 'first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.serverNames[0]) // (first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.dest) | split(":")[0]) // empty' "$xray_config_file" 2>/dev/null)"
    : "${reality_sni:=www.microsoft.com}" # Fallback to a default

    local health_data="[]"
    if [[ -s "$health_report_file" ]]; then
        health_data=$(jq -c '.protocols // []' "$health_report_file" 2>/dev/null || echo "[]")
    fi

    local server_config="{}"
    if [[ -s "$server_config_file" ]]; then
        server_config=$(jq -c '.' "$server_config_file" 2>/dev/null || echo "{}")
    fi

    # v4.6.0-rc1: 检测 CDN 模式
    # CDN 模式下 Reality 和 Hysteria2 已被禁用，dashboard 不应显示它们
    local cdn_enabled cdn_host
    cdn_enabled=$(jq -r '.cdn.enabled // false' "$server_config_file" 2>/dev/null)
    cdn_host=$(jq -r '.cdn.host // empty' "$server_config_file" 2>/dev/null)

    # 三协议架构
    local protocol_order=()
    declare -A protocol_meta
    if [[ "$cdn_enabled" == "true" && -n "$cdn_host" && "$cdn_host" != "null" ]]; then
        # CDN 模式：仅 VLESS-WS
        protocol_order=("VLESS-WebSocket")
        protocol_meta["VLESS-WebSocket"]="ws|CDN 中继模式，VPS IP 已隐藏|良好★★★★☆|443|tcp"
    else
        # 直连 3 协议
        protocol_order=("VLESS-Reality" "Hysteria2" "VLESS-WebSocket")
        protocol_meta["VLESS-Reality"]="reality|抗审查/伪装访问，主用通道|极佳★★★★★|443|tcp"
        protocol_meta["Hysteria2"]="hysteria2|UDP回退通道(QUIC)，TCP干扰时备用|良好★★★★☆|443|udp"
        protocol_meta["VLESS-WebSocket"]="ws|IP封禁回退通道，可挂CDN|良好★★★★☆|443|tcp"
    fi

    local final_protocols="[]"

    # v4.6.0-rc2 (审核 P1#3): share_link 不再自己拼接
    # 改为从 subscription.txt 读取 — 由 lib/subscription.sh 统一生成，逻辑正确
    # (IP 模式自带 insecure=1, WS 用 ws.edgebox.internal SNI, CDN 模式用 cdn.host)
    local subscription_txt="${CONFIG_DIR}/subscription.txt"
    declare -A links_by_protocol
    if [[ -s "$subscription_txt" ]]; then
        # v4.6.0-rc2: 兼容文件末尾无换行符的情况
        # `while read` 默认会丢弃最后一个无换行符的行；用 `|| [[ -n "$line" ]]` 兜底
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" ]] && continue
            # 识别协议：通过 URI 末尾 #EdgeBox-XXX 标签
            case "$line" in
                *"#EdgeBox-REALITY"*)   links_by_protocol["VLESS-Reality"]="$line"   ;;
                *"#EdgeBox-HYSTERIA2"*) links_by_protocol["Hysteria2"]="$line"       ;;
                *"#EdgeBox-WS-CDN"*)    links_by_protocol["VLESS-WebSocket"]="$line" ;;
                *"#EdgeBox-WS"*)        links_by_protocol["VLESS-WebSocket"]="$line" ;;
            esac
        done < "$subscription_txt"
    fi

    for name in "${protocol_order[@]}"; do
        IFS='|' read -r key scenario camouflage port network <<< "${protocol_meta[$name]}"

        local share_link="${links_by_protocol[$name]:-}"

        local static_info
        static_info=$(jq -n \
            --arg name "$name" --arg key "$key" --arg scenario "$scenario" \
            --arg camouflage "$camouflage" --argjson port "$port" --arg network "$network" \
            --arg share_link "$share_link" \
            '{name: $name, protocol: $key, scenario: $scenario, camouflage: $camouflage, port: $port, network: $network, share_link: $share_link}')

        local dynamic_info
        dynamic_info=$(echo "$health_data" | jq -c --arg key "$key" --arg fullname "$name" '.[] | select(.protocol == $key or .protocol == $fullname)')

        if [[ -z "$dynamic_info" || "$dynamic_info" == "null" ]]; then
            dynamic_info='{
                "status": "待检测", "status_badge": "⚪ 待检测", "health_score": 0, "response_time": -1,
                "detail_message": "等待健康检查...", "recommendation": "none", "recommendation_badge": ""
            }'
        fi

        local full_protocol_info
        full_protocol_info=$(jq -n --argjson s "$static_info" --argjson d "$dynamic_info" '$s + $d')

        final_protocols=$(echo "$final_protocols" | jq --argjson item "$full_protocol_info" '. += [$item]')
    done

    echo "$final_protocols"
}


# 获取分流配置状态
get_shunt_status() {
    local mode="vps"
    local proxy_info=""
    local health="unknown"
    local whitelist_json='[]'

    # 读取分流状态
    local state_file="${SHUNT_DIR}/state.json"
    if [[ -f "$state_file" ]]; then
        mode=$(safe_jq '.mode' "$state_file" "vps")
        proxy_info=$(safe_jq '.proxy_info' "$state_file" "")
        health=$(safe_jq '.health' "$state_file" "unknown")
    fi

    # 读取白名单（new11 安全读写）
    local whitelist_file="${SHUNT_DIR}/whitelist.txt"
    whitelist_json="$(jq_safe_list "$whitelist_file")"

    # 确保 whitelist_json 是有效 JSON（兜底）
    if ! echo "$whitelist_json" | jq . >/dev/null 2>&1; then
        whitelist_json='[]'
    fi

    # 输出分流状态JSON（口径不变）
    jq -n \
        --arg mode "$mode" \
        --arg proxy_info "$proxy_info" \
        --arg health "$health" \
        --argjson whitelist "$whitelist_json" \
        '{
            mode: $mode,
            proxy_info: $proxy_info,
            health: $health,
            whitelist: $whitelist
        }'
}


# 获取订阅信息
get_subscription_info() {
    local sub_plain=""
    local sub_b64=""
    local sub_b64_lines=""

    # 按优先级查找订阅文件
    local subscription_sources=(
        "${CONFIG_DIR}/subscription.txt"
        "${TRAFFIC_DIR}/sub.txt"
        "/var/www/html/sub"
    )

    for sub_file in "${subscription_sources[@]}"; do
        if [[ -s "$sub_file" ]]; then
            sub_plain=$(cat "$sub_file")
            break
        fi
    done

    # 生成Base64编码
    if [[ -n "$sub_plain" ]]; then
        if base64 --help 2>&1 | grep -q -- ' -w'; then
            sub_b64=$(printf '%s\n' "$sub_plain" | base64 -w0)
        else
            sub_b64=$(printf '%s\n' "$sub_plain" | base64 | tr -d '\n')
        fi

        # 生成逐行Base64
        local temp_file
        temp_file=$(mktemp)
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if base64 --help 2>&1 | grep -q -- ' -w'; then
                printf '%s' "$line" | sed -e '$a\' | base64 -w0
            else
                printf '%s' "$line" | sed -e '$a\' | base64 | tr -d '\n'
            fi
            printf '\n'
        done <<<"$sub_plain" > "$temp_file"
        sub_b64_lines=$(cat "$temp_file")
        rm -f "$temp_file"
    fi

    # 输出订阅信息JSON
    jq -n \
        --arg plain "$sub_plain" \
        --arg base64 "$sub_b64" \
        --arg b64_lines "$sub_b64_lines" \
        '{
            plain: $plain,
            base64: $base64,
            b64_lines: $b64_lines
        }'
}

# 获取敏感凭据信息（从server.json提取）
get_secrets_info() {
    local secrets_json="{}"

    if [[ -f "$SERVER_JSON" ]]; then
        # v4.6.0-rc1 fixes:
        # - Remove private_key from dashboard.json (NEVER expose Reality private key over HTTP)
        # - Remove v3 residue: grpc/tuic_uuid/password.trojan/password.tuic
        # - Fix jq syntax: missing comma before master_sub_token + trailing comma
        secrets_json=$(jq -c '{
            vless: {
                reality: (.uuid.vless.reality // ""),
                ws:      (.uuid.vless.ws // "")
            },
            password: {
                hysteria2: (.password.hysteria2 // "")
            },
            reality: {
                public_key: (.reality.public_key // ""),
                short_id:   (.reality.short_id // "")
            },
            ws: {
                path: (.ws.path // "/ws")
            },
            master_sub_token: (.master_sub_token // "")
        }' "$SERVER_JSON" 2>/dev/null || echo "{}")
    fi

    echo "$secrets_json"
}


#############################################
# 通知收集函数（修复版）
#############################################

collect_notifications() {
    local notifications_json="$TRAFFIC_DIR/notifications.json"
    local temp_notifications="[]"
    local alert_log="/var/log/edgebox-traffic-alert.log"

    log_info "收集系统通知..."

    # 收集预警通知（最近10条）
    if [[ -f "$alert_log" ]] && [[ -r "$alert_log" ]]; then
        local alert_notifications
        alert_notifications=$(tail -n 10 "$alert_log" 2>/dev/null | grep -E '^\[[0-9-T:Z+]+\]' | \
        awk 'BEGIN{print "["}
        {
            gsub(/^\[/, "", $1)  # 移除开头的 [
            gsub(/\]/, "", $1)   # 移除结尾的 ]
            msg = $0
            gsub(/^\[[^\]]+\]\s*/, "", msg)  # 移除时间戳部分
            gsub(/"/, "\\\"", msg)  # 转义双引号
            if(NR>1) print ","
            printf "{\"id\":\"alert_%s\",\"type\":\"alert\",\"level\":\"warning\",\"time\":\"%s\",\"message\":\"%s\",\"read\":false}",
                   NR, $1, msg
        }
        END{print "]"}' 2>/dev/null || echo "[]")
        temp_notifications="$alert_notifications"
    fi

    # 收集系统状态通知
    local system_notifications="[]"
    local nginx_status=$(systemctl is-active nginx 2>/dev/null || echo "inactive")
    local xray_status=$(systemctl is-active xray 2>/dev/null || echo "inactive")
    local singbox_status=$(systemctl is-active sing-box 2>/dev/null || echo "inactive")

    # 生成系统状态通知
    local sys_notifs="["
    local has_notif=false
    local current_time=$(date -Is)
    local timestamp=$(date +%s)

    if [[ "$nginx_status" != "active" ]]; then
        if [[ "$has_notif" == "true" ]]; then sys_notifs+=","; fi
        sys_notifs+="{\"id\":\"sys_nginx_${timestamp}\",\"type\":\"system\",\"level\":\"error\",\"time\":\"${current_time}\",\"message\":\"Nginx 服务已停止运行\",\"action\":\"systemctl start nginx\",\"read\":false}"
        has_notif=true
    fi

    if [[ "$xray_status" != "active" ]]; then
        if [[ "$has_notif" == "true" ]]; then sys_notifs+=","; fi
        sys_notifs+="{\"id\":\"sys_xray_${timestamp}\",\"type\":\"system\",\"level\":\"error\",\"time\":\"${current_time}\",\"message\":\"Xray 服务已停止运行\",\"action\":\"systemctl start xray\",\"read\":false}"
        has_notif=true
    fi

    if [[ "$singbox_status" != "active" ]]; then
        if [[ "$has_notif" == "true" ]]; then sys_notifs+=","; fi
        sys_notifs+="{\"id\":\"sys_singbox_${timestamp}\",\"type\":\"system\",\"level\":\"error\",\"time\":\"${current_time}\",\"message\":\"sing-box 服务已停止运行\",\"action\":\"systemctl start sing-box\",\"read\":false}"
        has_notif=true
    fi

    sys_notifs+="]"
    system_notifications="$sys_notifs"

    # 读取已有通知并合并
    local existing_notifications="[]"
    if [[ -f "$notifications_json" ]]; then
        existing_notifications=$(jq '.notifications // []' "$notifications_json" 2>/dev/null || echo "[]")
    fi

    # 合并所有通知，去重并限制数量
    local cutoff_date=$(date -d '7 days ago' -Is)

    # 使用更安全的jq命令
    {
        echo "{"
        echo "  \"updated_at\": \"$(date -Is)\","
        echo "  \"notifications\": []"
        echo "}"
    } > "$notifications_json.tmp"

    # 如果jq可用，使用复杂合并；否则使用简单版本
    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --argjson existing "$existing_notifications" \
            --argjson alerts "$temp_notifications" \
            --argjson systems "$system_notifications" \
            --arg updated "$(date -Is)" \
            --arg cutoff "$cutoff_date" \
            '{
                updated_at: $updated,
                notifications: ([$alerts[], $systems[], $existing[]] |
                               unique_by(.id) |
                               map(select(.time > $cutoff)) |
                               sort_by(.time) |
                               reverse |
                               .[0:50])
            }' > "$notifications_json.tmp" 2>/dev/null || {
            # 如果jq复杂操作失败，使用简单版本
            echo "{\"updated_at\":\"$(date -Is)\",\"notifications\":${system_notifications}}" > "$notifications_json.tmp"
        }
    else
        # 如果没有jq，创建基本结构
        echo "{\"updated_at\":\"$(date -Is)\",\"notifications\":${system_notifications}}" > "$notifications_json.tmp"
    fi

    # 原子性替换
    mv "$notifications_json.tmp" "$notifications_json"
    chmod 644 "$notifications_json" 2>/dev/null || true

    log_info "通知数据收集完成"
}


#############################################
# 主数据生成函数
#############################################

# 生成完整的dashboard.json
generate_dashboard_data() {
    log_info "开始生成Dashboard数据..."

    local host_or_ip
    local cert_mode_file="${CONFIG_DIR}/cert_mode"
    if [[ -f "$cert_mode_file" ]] && grep -q "letsencrypt:" "$cert_mode_file"; then
        host_or_ip=$(cat "$cert_mode_file" | cut -d: -f2)
    else
        host_or_ip=$(jq -r '.server_ip // "127.0.0.1"' "${CONFIG_DIR}/server.json" 2>/dev/null || echo "127.0.0.1")
    fi

	local master_sub_token
    master_sub_token=$(jq -r '.master_sub_token // empty' "${CONFIG_DIR}/server.json" 2>/dev/null)

    if [[ -x "${SCRIPTS_DIR}/protocol-health-monitor.sh" ]]; then
        log_info "正在刷新协议健康状态..."
        "${SCRIPTS_DIR}/protocol-health-monitor.sh" >/dev/null 2>&1 || log_warn "协议健康检查失败"
    fi

    mkdir -p "$TRAFFIC_DIR"

    local timestamp system_info cert_info services_info protocols_info shunt_info subscription_info secrets_info

    timestamp=$(date -Is)
    system_info=$(get_system_info)
    cert_info=$(get_certificate_info)
    services_info=$(get_services_status)
    protocols_info=$(get_protocols_status)
    shunt_info=$(get_shunt_status)
    subscription_info=$(get_subscription_info)
    secrets_info=$(get_secrets_info)

    services_info=$(
      jq -n \
        --arg nstat "$(systemctl is-active --quiet nginx    && echo '运行中 √' || echo '已停止')" \
        --arg xstat "$(systemctl is-active --quiet xray     && echo '运行中 √' || echo '已停止')" \
        --arg sstat "$(systemctl is-active --quiet sing-box && echo '运行中 √' || echo '已停止')" \
        --arg nver  "$(nginx -v 2>&1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)" \
        --arg xver  "$((xray -version 2>/dev/null || xray version 2>/dev/null) | head -n1 | grep -Eo 'v?[0-9]+(\.[0-9]+)+' | head -1)" \
        --arg sver  "$(sing-box version 2>/dev/null | head -n1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)" \
        '{nginx:{status:$nstat,version:$nver},
          xray:{status:$xstat,version:$xver},
          "sing-box":{status:$sstat,version:$sver}}'
    )

    # --- 修复点：将 C 风格的三元运算符 A ? B : C 改为 jq 的 if-then-else-end ---
    jq -n \
        --arg timestamp "$timestamp" \
        --argjson system "$system_info" \
        --argjson cert "$cert_info" \
        --argjson services "$services_info" \
        --argjson protocols "$protocols_info" \
        --argjson shunt "$shunt_info" \
        --argjson subscription "$subscription_info" \
        --argjson secrets "$secrets_info" \
        --arg host_or_ip "$host_or_ip" \
		--arg master_sub_token "$master_sub_token" \
        '{
            updated_at: $timestamp,
            subscription_url: (
                if ($master_sub_token | length) > 0
                then ("http://" + $host_or_ip + "/sub-" + $master_sub_token)
                else ("http://" + $host_or_ip + "/sub")
                end
            ),
            server: ($system + {cert: $cert}),
            services: $services,
            protocols: $protocols,
            shunt: $shunt,
            subscription: $subscription,
            secrets: $secrets
        }' > "${TRAFFIC_DIR}/dashboard.json.tmp"
    # --- 修复结束 ---

    if [[ -s "${TRAFFIC_DIR}/dashboard.json.tmp" ]]; then
        mv "${TRAFFIC_DIR}/dashboard.json.tmp" "${TRAFFIC_DIR}/dashboard.json"
        chmod 644 "${TRAFFIC_DIR}/dashboard.json"
        log_info "dashboard.json 生成完成"
    else
        log_error "dashboard.json 生成失败"
        rm -f "${TRAFFIC_DIR}/dashboard.json.tmp"
        return 1
    fi
}

# 生成system.json（系统监控数据）
generate_system_data() {
    log_info "生成系统监控数据..."

    local system_metrics
    system_metrics=$(get_system_metrics)

    echo "$system_metrics" > "${TRAFFIC_DIR}/system.json.tmp"

    if [[ -s "${TRAFFIC_DIR}/system.json.tmp" ]]; then
        mv "${TRAFFIC_DIR}/system.json.tmp" "${TRAFFIC_DIR}/system.json"
        chmod 644 "${TRAFFIC_DIR}/system.json"
        log_info "system.json 生成完成"
    else
        log_error "system.json 生成失败"
        rm -f "${TRAFFIC_DIR}/system.json.tmp"
        return 1
    fi
}


#############################################
# 主执行逻辑
#############################################

# 主函数
main() {
    if [[ "${1:-}" == "--notifications-only" ]]; then
        collect_notifications
        exit 0
    fi

    case "${1:-}" in
        --now|--once|update)
            # 立即执行数据生成
            generate_dashboard_data
            generate_system_data
            ;;
        --schedule|--install)
            # 设置定时任务
            setup_cron_jobs
            ;;
        --help|-h)
            echo "用法: $0 [选项]"
            echo "选项:"
            echo "  --now, --once    立即生成Dashboard数据"
            echo "  --schedule       设置定时任务"
            echo "  --help          显示帮助信息"
            ;;
        *)
            # 默认执行数据生成
            generate_dashboard_data
            generate_system_data
            ;;
    esac
	# 在最后添加通知收集
    collect_notifications
}

# 执行主函数
main "$@"
