#!/bin/bash
set -e
echo "[INFO] 正在以无中断模式应用 EdgeBox 防火墙规则..."

# --- 智能检测当前SSH端口 ---
# (这部分逻辑不变，保持原样)
ssh_ports=()
# ... (省略和之前版本相同的SSH端口检测代码) ...
while IFS= read -r line; do
    if [[ "$line" =~ :([0-9]+)[[:space:]]+.*sshd ]]; then
        ssh_ports+=("${BASH_REMATCH[1]}")
    fi
done < <(ss -tlnp 2>/dev/null | grep sshd || true)
if [[ -f /etc/ssh/sshd_config ]]; then
    config_port=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    [[ -n "$config_port" && "$config_port" =~ ^[0-9]+$ ]] && ssh_ports+=("$config_port")
fi
if [[ -n "${SSH_CONNECTION:-}" ]]; then
    connection_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
    [[ -n "$connection_port" && "$connection_port" =~ ^[0-9]+$ ]] && ssh_ports+=("$connection_port")
fi
if [[ ${#ssh_ports[@]} -gt 0 ]]; then
    temp_file=$(mktemp)
    printf "%s\n" "${ssh_ports[@]}" | sort -u > "$temp_file"
    current_ssh_port=$(head -1 "$temp_file")
    rm -f "$temp_file"
fi
current_ssh_port="${current_ssh_port:-22}"
echo "[INFO] 检测到 SSH 端口: $current_ssh_port"


# --- 根据防火墙类型，使用无中断方式配置规则 ---

# 定义一个辅助函数来检查规则是否存在
is_rule_active() {
    local type="$1"
    local port="$2"
    local proto="$3"

    if [[ "$type" == "ufw" ]]; then
        ufw status | grep -qE "^\s*${port}/${proto}\s+ALLOW\s+Anywhere"
    elif [[ "$type" == "firewalld" ]]; then
        firewall-cmd --query-port="${port}/${proto}" >/dev/null 2>&1
    fi
}

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    echo "[INFO] 正在配置 UFW (无中断模式)..."
    is_rule_active "ufw" "$current_ssh_port" "tcp" || ufw allow "${current_ssh_port}/tcp" >/dev/null
    is_rule_active "ufw" "80" "tcp" || ufw allow 80/tcp >/dev/null
    is_rule_active "ufw" "443" "tcp" || ufw allow 443/tcp >/dev/null
    is_rule_active "ufw" "443" "udp" || ufw allow 443/udp >/dev/null
    
    # <<< 修复点: 移除了可能导致连接中断的 `ufw --force enable` >>>
    echo "[SUCCESS] UFW 规则已确保应用。"

elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    echo "[INFO] 正在配置 FirewallD (无中断模式)..."

    # <<< 修复点: 改为使用非中断的运行时规则添加，并同步到永久配置，避免 --reload >>>
    add_firewalld_rule() {
        local rule="$1"
        if ! firewall-cmd --query-port="$rule" >/dev/null 2>&1; then
            echo "  -> 添加规则: $rule"
            firewall-cmd --add-port="$rule" >/dev/null 2>&1
            firewall-cmd --permanent --add-port="$rule" >/dev/null 2>&1
        fi
    }

    add_firewalld_rule "$current_ssh_port/tcp"
    add_firewalld_rule "80/tcp"
    add_firewalld_rule "443/tcp"
    add_firewalld_rule "443/udp"

    echo "[SUCCESS] FirewallD 规则已确保应用。"

elif command -v iptables >/dev/null 2>&1; then
    echo "[INFO] 正在配置 iptables (无中断模式)..."
    iptables -C INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
    iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -C INPUT -p udp --dport 443 -j ACCEPT >/dev/null 2>&1 || iptables -A INPUT -p udp --dport 443 -j ACCEPT
    echo "[SUCCESS] iptables 规则已确保应用。"
else
    echo "[WARN] 未检测到支持的防火墙软件，请手动确保端口开放。"
fi
