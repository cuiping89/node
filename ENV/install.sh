# EdgeBox 修复补丁 - 只修改有问题的部分

# 1. 修复 HY2_PORT 配置（在 interactive_config 函数中）
# 原来：HY2_PORT="443"
# 修改为：
HY2_PORT="2080"  # 避免与Reality的443端口冲突

# 2. 修复 generate_sing_box_config 函数中的Reality密钥生成
generate_sing_box_config() {
    # 修复：Reality 密钥生成和解析
    log "生成 Reality 密钥对..."
    local keys_output
    keys_output=$(/usr/local/bin/sing-box generate reality-keypair 2>&1) || {
        log "无法生成 Reality 密钥对，使用备用方案"
        # 备用方案：使用随机密钥
        local private_key=$(openssl rand -base64 32 | tr -d '\n')
        local public_key=$(openssl rand -base64 32 | tr -d '\n')
    }
    
    # 如果正常生成，则解析密钥
    if [[ -n "$keys_output" ]]; then
        local private_key=$(echo "$keys_output" | awk '/PrivateKey:/ {for(i=2; i<=NF; i++) printf "%s%s", $i, (i==NF?"\n":" ")}' | tr -d ' \n')
        local public_key=$(echo "$keys_output" | awk '/PublicKey:/ {for(i=2; i<=NF; i++) printf "%s%s", $i, (i==NF?"\n":" ")}' | tr -d ' \n')
        
        # 验证密钥是否正确提取
        if [[ -z "$private_key" ]] || [[ -z "$public_key" ]]; then
            log "密钥解析失败，使用备用密钥"
            private_key=$(openssl rand -base64 32 | tr -d '\n')
            public_key=$(openssl rand -base64 32 | tr -d '\n')
        fi
    fi
    
    local short_id=$(openssl rand -hex 4)
    local reality_uuid=$(uuidgen)
    
    echo "$reality_uuid" > "$WORK_DIR/reality-uuid"
    echo "$public_key" > "$WORK_DIR/reality-public-key"
    echo "$short_id" > "$WORK_DIR/reality-short-id"
    echo "$private_key" > "$WORK_DIR/reality-private-key"
    
    # Hysteria2
    local hy2_password=$(openssl rand -base64 16 | tr -d '=+/\n' | cut -c1-12)
    echo "$hy2_password" > "$WORK_DIR/hy2-password"
    
    # TUIC
    local tuic_uuid=$(uuidgen)
    local tuic_password=$(openssl rand -hex 8)
    echo "$tuic_uuid" > "$WORK_DIR/tuic-uuid"
    echo "$tuic_password" > "$WORK_DIR/tuic-password"
    
    log "密钥生成完成"
    
    # 修复：sing-box 配置文件（注意EOF不能有缩进）
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "vless",
            "tag": "vless-reality",
            "listen": "::",
            "listen_port": 443,
            "users": [
                {
                    "uuid": "$reality_uuid",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "www.cloudflare.com",
                "reality": {
                    "enabled": true,
                    "private_key": "$private_key",
                    "short_id": ["$short_id"],
                    "handshake": {
                        "server": "www.cloudflare.com",
                        "server_port": 443
                    }
                }
            }
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2",
            "listen": "::",
            "listen_port": $HY2_PORT,
            "up_mbps": 200,
            "down_mbps": 200,
            "users": [
                {
                    "password": "$hy2_password"
                }
            ],
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "/etc/ssl/edgebox/cert.pem",
                "key_path": "/etc/ssl/edgebox/key.pem"
            }
        },
        {
            "type": "tuic",
            "tag": "tuic",
            "listen": "::",
            "listen_port": 2053,
            "users": [
                {
                    "uuid": "$tuic_uuid",
                    "password": "$tuic_password"
                }
            ],
            "congestion_control": "bbr",
            "auth_timeout": "3s",
            "zero_rtt_handshake": false,
            "heartbeat": "10s",
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "/etc/ssl/edgebox/cert.pem",
                "key_path": "/etc/ssl/edgebox/key.pem"
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ]
}
EOF
    
    # 验证配置文件
    /usr/local/bin/sing-box check -c /etc/sing-box/config.json || error "sing-box 配置文件有误"
}

# 3. 在 generate_configs 函数最后添加HY2_PORT保存
# 在这行后面添加：echo "${HY2_PORT}" > "$WORK_DIR/hy2-port"

# 4. 修复 create_management_tool 函数，添加订阅功能
create_management_tool() {
    log "创建管理工具 edgeboxctl..."
    
    cat > /usr/local/bin/edgeboxctl << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="/opt/edgebox"

show_subscriptions() {
    [[ ! -f "$WORK_DIR/domain" ]] && { echo "配置文件不存在"; exit 1; }
    
    local domain=$(cat "$WORK_DIR/domain")
    local server_ip
    
    # 如果是本地域名，获取服务器IP
    if [[ "$domain" == "edgebox.local" ]] || [[ "$domain" == "localhost" ]]; then
        server_ip=$(curl -s --connect-timeout 5 https://ipv4.icanhazip.com/ 2>/dev/null || echo "YOUR_SERVER_IP")
        domain=$server_ip
    fi
    
    # 读取Hysteria2端口
    local hy2_port="2080"
    [[ -f "$WORK_DIR/hy2-port" ]] && hy2_port=$(cat "$WORK_DIR/hy2-port")
    
    echo "=== EdgeBox 订阅链接 ==="
    echo "服务器: $domain"
    echo
    
    # 生成所有订阅链接
    local subscriptions=""
    
    # VLESS-gRPC
    if [[ -f "$WORK_DIR/xray-uuid" ]]; then
        local uuid=$(cat "$WORK_DIR/xray-uuid")
        local grpc_link="vless://$uuid@$domain:8443?encryption=none&security=tls&type=grpc&serviceName=edgebox-grpc&fp=chrome&allowInsecure=1#EdgeBox-gRPC"
        echo "VLESS-gRPC:"
        echo "$grpc_link"
        subscriptions+="$grpc_link\n"
        echo
        
        # VLESS-WS
        local ws_link="vless://$uuid@$domain:8443?encryption=none&security=tls&type=ws&path=/edgebox-ws&host=$domain&fp=chrome&allowInsecure=1#EdgeBox-WS"
        echo "VLESS-WS:"
        echo "$ws_link"
        subscriptions+="$ws_link\n"
        echo
    fi
    
    # VLESS-Reality
    if [[ -f "$WORK_DIR/reality-uuid" ]]; then
        local uuid=$(cat "$WORK_DIR/reality-uuid")
        local pubkey=$(cat "$WORK_DIR/reality-public-key")
        local sid=$(cat "$WORK_DIR/reality-short-id")
        local reality_link="vless://$uuid@$domain:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=www.cloudflare.com&pbk=$pubkey&sid=$sid&type=tcp#EdgeBox-Reality"
        echo "VLESS-Reality:"
        echo "$reality_link"
        subscriptions+="$reality_link\n"
        echo
    fi
    
    # Hysteria2
    if [[ -f "$WORK_DIR/hy2-password" ]]; then
        local password=$(cat "$WORK_DIR/hy2-password")
        local hy2_link="hysteria2://$password@$domain:$hy2_port/?insecure=1#EdgeBox-Hysteria2"
        echo "Hysteria2:"
        echo "$hy2_link"
        subscriptions+="$hy2_link\n"
        echo
    fi
    
    # TUIC
    if [[ -f "$WORK_DIR/tuic-uuid" ]]; then
        local uuid=$(cat "$WORK_DIR/tuic-uuid")
        local password=$(cat "$WORK_DIR/tuic-password")
        local tuic_link="tuic://$uuid:$password@$domain:2053?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#EdgeBox-TUIC"
        echo "TUIC:"
        echo "$tuic_link"
        subscriptions+="$tuic_link\n"
        echo
    fi
    
    # 生成聚合订阅
    if [[ -n "$subscriptions" ]]; then
        mkdir -p /var/www/html
        echo -e "$subscriptions" | base64 -w 0 > "/var/www/html/edgebox-sub.txt"
        echo -e "$subscriptions" > "/var/www/html/edgebox-sub-plain.txt"
        
        echo "=== 聚合订阅链接 ==="
        echo "Base64订阅: http://$domain/edgebox-sub.txt"
        echo "明文订阅: http://$domain/edgebox-sub-plain.txt"
        echo
    fi
}

case ${1:-help} in
    status)
        echo "=== EdgeBox 服务状态 ==="
        systemctl is-active --quiet sing-box && echo "✓ sing-box: 运行中" || echo "✗ sing-box: 已停止"
        systemctl is-active --quiet xray && echo "✓ xray: 运行中" || echo "✗ xray: 已停止"
        systemctl is-active --quiet nginx && echo "✓ nginx: 运行中" || echo "✗ nginx: 已停止"
        echo
        echo "=== 端口监听 ==="
        ss -lntup | egrep ':443|:8443|:2053|:2080' || echo "无相关端口监听"
        ;;
    sub|subscription)
        show_subscriptions
        ;;
    restart)
        systemctl restart sing-box xray nginx
        sleep 3
        echo "服务已重启"
        ;;
    logs)
        echo "=== sing-box 日志 ==="
        journalctl -u sing-box -n 10 --no-pager
        echo "=== xray 日志 ==="
        journalctl -u xray -n 10 --no-pager
        ;;
    *)
        echo "EdgeBox 管理工具"
        echo "用法: edgeboxctl [status|sub|restart|logs]"
        ;;
esac
EOF

    chmod +x /usr/local/bin/edgeboxctl
    log "管理工具已创建"
}

# 5. 在 setup_firewall 函数中添加 HY2_PORT
# 在这行：ufw allow 443/udp >/dev/null 2>&1
# 后面添加：ufw allow ${HY2_PORT}/udp >/dev/null 2>&1

# 6. 添加订阅网页设置函数（在 setup_firewall 后调用）
setup_subscription_web() {
    log "设置订阅网页..."
    
    mkdir -p /var/www/html
    
    # 配置nginx提供订阅服务（在现有server块后添加）
    cat >> /etc/nginx/conf.d/edgebox.conf << 'EOF'

server {
    listen 80;
    server_name _;
    root /var/www/html;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    location ~* \.(txt)$ {
        add_header Content-Type "text/plain; charset=utf-8";
        add_header Access-Control-Allow-Origin "*";
    }
}
EOF
    
    nginx -t || error "Nginx 配置错误"
}

# 使用说明：
# 1. 将原脚本中的相关函数替换为上面的修复版本
# 2. 在 interactive_config 函数中修改 HY2_PORT="2080" 
# 3. 在 generate_configs 函数最后添加：echo "${HY2_PORT}" > "$WORK_DIR/hy2-port"
# 4. 在 setup_firewall 函数中添加：ufw allow ${HY2_PORT}/udp >/dev/null 2>&1
# 5. 在 main 函数中，在 setup_firewall 后添加：setup_subscription_web
# 6. 在 start_services 函数最后添加：/usr/local/bin/edgeboxctl sub > /dev/null
