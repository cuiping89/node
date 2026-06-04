#!/bin/bash
set -euo pipefail
TRAFFIC_DIR="/etc/edgebox/traffic"
mkdir -p "$TRAFFIC_DIR"

# 改进的CPU使用率计算
get_cpu_usage() {
    local cpu_percent=0

    if [[ -r /proc/stat ]]; then
        read _ user1 nice1 system1 idle1 iowait1 irq1 softirq1 _ < /proc/stat

        # 增加采样时间到2秒，获得更准确的数据
        sleep 2

        read _ user2 nice2 system2 idle2 iowait2 irq2 softirq2 _ < /proc/stat

        # 计算差值
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
            # 使用更精确的计算
            cpu_percent=$(( (active_diff * 1000) / total_diff ))
            cpu_percent=$((cpu_percent / 10))
            # 设置最小值为1%，避免显示0%
            if [[ $cpu_percent -lt 1 ]]; then
                cpu_percent=1
            fi
        else
            cpu_percent=1
        fi
    fi

    # 确保值在合理范围
    cpu_percent=$(( cpu_percent > 100 ? 100 : cpu_percent ))
    cpu_percent=$(( cpu_percent < 1 ? 1 : cpu_percent ))

    echo $cpu_percent
}

# 获取CPU和内存使用率
cpu=$(get_cpu_usage)
mt=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo "0")
ma=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo "0")
mem=$(( mt > 0 ? (100 * (mt - ma)) / mt : 0 ))

# 生成JSON
jq -n --arg ts "$(date -Is)" --argjson cpu "$cpu" --argjson memory "$mem" \
  '{updated_at:$ts,cpu:$cpu,memory:$memory}' > "${TRAFFIC_DIR}/system.json"
