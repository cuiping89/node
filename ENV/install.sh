#!/usr/bin/env bash
# =====================================================================================
# EdgeBox - 一站式多协议节点部署工具
# 支持：VLESS-gRPC, VLESS-WS, VLESS-Reality, Hysteria2, TUIC
# 系统要求：Ubuntu 18.04+ / Debian 10+
# =====================================================================================

set -euo pipefail

# === 检查 root 权限 ===
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "此脚本需要 root 权限运行"
        echo "请先切换到 root 用户："
        echo "  sudo su -"
        exit 1
    fi
}

# === 版本配置 ===
readonly SING_BOX_VERSION="v1.11.7"
readonly XRAY_VERSION="v1.8.24"
readonly SCRIPT_VERSION="1.0.2"

# === 路径常量 ===
readonly WORK_DIR="/opt/edgebox"
readonly BACKUP_DIR="/root/edgebox-backup"
readonly LOG_FILE="/var/log/edgebox.log"

# === 全局变量 ===
DOMAIN=""
PROTOCOLS=()
USE_PROXY=false
PROXY_HOST=""
PROXY_PORT=""
PROXY_USER=""
PROXY_PASS=""

# === 工具函数 ===
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

check_os() {
    if ! grep -qiE "ubuntu|debian" /etc/os-release; then
        error "不支持的系统。仅支持 Ubuntu 18.04+ 或 Debian 10+"
    fi
    log "系统检查通过：$(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
}

check_requirements() {
    log "检查系统要求..."
    
    # 检查内存
    local mem_mb=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $mem_mb -lt 400 ]]; then
        log "内存不足 ${mem_mb}MB，创建 2GB swap..."
        create_swap
    fi
    
    # 检查磁盘空间
    local disk_gb=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')
    [[ $disk_gb -lt 5 ]] && error "磁盘空间不足，至少需要 5GB"
    
    log "系统要求检查完成"
}

create_swap() {
    if [[ $(swapon --show | wc -l) -eq 0 ]]; then
        fallocate -l 2G /swapfile-edgebox
        chmod 600 /swapfile-edgebox
        mkswap /swapfile-edgebox
        swapon /swapfile-edgebox
        echo '/swapfile-edgebox none swap sw 0 0 # edgebox-swap' >> /etc/fstab
        log "已创建 2GB swap 文件"
    fi
}

install_packages() {
    log "安装依赖包..."
    export DEBIAN_FRONTEND=noninteractive
    
    # 清理旧配置
    rm -f /etc/nginx/conf.d/edgebox*.conf 2>/dev/null || true
    rm -f /etc/nginx/sites-available/edgebox* 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/edgebox* 2>/dev/null || true
    
    # 修复 nginx.conf
    if [[ -f /etc/nginx/nginx.conf ]]; then
        sed -i '/edgebox/d' /etc/nginx/nginx.conf 2>/dev/null || true
    fi
    
    systemctl stop nginx 2>/dev/null || true
    dpkg --configure -a 2>/dev/null || true
    
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        ca-certificates curl wget jq tar unzip openssl \
        nginx ufw vnstat cron logrotate uuid-runtime \
        certbot python3-certbot-nginx dnsutils
    
    log "依赖包安装完成"
}

optimize_system() {
    log "优化系统参数..."
    
    cat > /etc/sysctl.d/99-edgebox-bbr.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 65536 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
EOF
    
    sysctl -p /etc/sysctl.d/99-edgebox-bbr.conf >/dev/null 2>&1
    log "系统优化完成"
}

# === 交互配置 ===
interactive_config() {
    echo "=== EdgeBox 配置向导 ==="
    echo
    
    echo "使用默认配置进行安装..."
    DOMAIN=""
    echo "✓ 将使用自签名证书"
    
    PROTOCOLS=("grpc" "ws" "reality" "hy2" "tuic")
    echo "✓ 将安装所有协议: VLESS-gRPC, VLESS-WS, VLESS-Reality, Hysteria2, TUIC"
    
    USE_PROXY=false
    echo "✓ 将使用全直出模式（所有流量直连）"
    
    echo
    echo "开始安装..."
    sleep 2
}

# === 软件安装 ===
install_sing_box() {
    log "安装 sing-box ${SING_BOX_VERSION}..."
    
    local url="https://github.com/SagerNet/sing-box/releases/download/${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION#v}-linux-amd64.tar.gz"
    local temp_dir=$(mktemp -d)
    
    cd "$temp_dir"
    curl -fsSL "$url" -o sing-box.tar.gz
    tar -xzf sing-box.tar.gz
    install -m755 sing-box-*/sing-box /usr/local/bin/sing-box
    rm -rf "$temp_dir"
    
    /usr/local/bin/sing-box version
    log "sing-box 安装完成"
}

install_xray() {
    log "安装 Xray ${XRAY_VERSION}..."
    
    local url="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"
    local temp_dir=$(mktemp -d)
    
    cd "$temp_dir"
    curl -fsSL "$url" -o xray.zip
    unzip -q xray.zip
    install -m755 xray /usr/local/bin/xray
    mkdir -p /usr/local/etc/xray
    install -m644 geoip.dat geosite.dat /usr/local/etc/xray/
    rm -rf "$temp_dir"
    
    /usr/local/bin/xray version
    log "Xray 安装完成"
}

# === 证书管理 ===
setup_certificates() {
    log "配置证书..."
    mkdir -p /etc/ssl/edgebox
    
    if [[ -n "$DOMAIN" ]]; then
        local domain_ip=$(dig +short "$DOMAIN" 2>/dev/null | tail -n1)
        local server_ip=$(curl -s https://ipv4.icanhazip.com/ 2>/dev/null)
        
        if [[ -n "$domain_ip" && "$domain_ip" == "$server_ip" ]]; then
            log "域名解析正确，尝试申请 Let's Encrypt 证书"
            ufw allow 80/tcp >/dev/null 2>&1
            
            if certbot certonly --nginx --non-interactive --agree-tos \
               --email "admin@${DOMAIN}" -d "$DOMAIN" 2>/dev/null; then
                ln -sf "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" /etc/ssl/edgebox/cert.pem
                ln -sf "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" /etc/ssl/edgebox/key.pem
                log "证书申请成功"
            else
                log "证书申请失败，使用自签名证书"
                DOMAIN="edgebox.local"
                generate_self_signed_cert
            fi
        else
            log "域名未解析到本机，使用自签名证书"
            DOMAIN="edgebox.local"
            generate_self_signed_cert
        fi
    else
        DOMAIN="edgebox.local"
        generate_self_signed_cert
    fi
}

generate_self_signed_cert() {
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout /etc/ssl/edgebox/key.pem \
        -out /etc/ssl/edgebox/cert.pem \
        -subj "/CN=${DOMAIN}" 2>/dev/null
    log "已生成自签名证书"
}

# === 配置生成 ===
generate_configs() {
    log "生成配置文件..."
    mkdir -p "$WORK_DIR" /etc/sing-box /usr/local/etc/xray
    
    # 保存配置信息
    echo "${DOMAIN:-edgebox.local}" > "$WORK_DIR/domain"
    echo "${PROTOCOLS[*]}" > "$WORK_DIR/protocols"
    [[ "$USE_PROXY" == true ]] && echo "${PROXY_HOST}:${PROXY_PORT}:${PROXY_USER}:${PROXY_PASS}" > "$WORK_DIR/proxy"
    
    generate_xray_config
    generate_sing_box_config
    generate_nginx_config
}

generate_xray_config() {
    local uuid=$(uuidgen)
    echo "$uuid" > "$WORK_DIR/xray-uuid"
    
    # Xray配置 - 使用10085和10086端口
    local inbounds=$(cat << EOF
[
    {
        "port": 10085,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "settings": {
            "clients": [{"id": "$uuid"}],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "edgebox-grpc"
            }
        }
    },
    {
        "port": 10086,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "settings": {
            "clients": [{"id": "$uuid"}],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "wsSettings": {
                "path": "/edgebox-ws"
            }
        }
    }
]
EOF
    )
    
    # 构建出站 - 修复DNS问题
    local outbounds='[{"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIP"}}'
    if [[ "$USE_PROXY" == true && -n "$PROXY_HOST" && -n "$PROXY_PORT" ]]; then
        outbounds+=",$(cat << EOF
{
    "protocol": "http",
    "tag": "proxy",
    "settings": {
        "servers": [{
            "address": "$PROXY_HOST",
            "port": $PROXY_PORT$(
            [[ -n "$PROXY_USER" && -n "$PROXY_PASS" ]] && echo ",
            \"users\": [{
                \"user\": \"$PROXY_USER\",
                \"pass\": \"$PROXY_PASS\"
            }]" || echo ""
            )
        }]
    }
}
EOF
        )"
    fi
    outbounds+=']'
    
    # 路由和DNS配置
    local dns_config=''
    local routing=''
    
    if [[ "$USE_PROXY" == true ]]; then
        dns_config=$(cat << 'EOF'
"dns": {
    "servers": [
        {
            "address": "1.1.1.1",
            "domains": ["domain:googlevideo.com", "domain:ytimg.com", "domain:ggpht.com"],
            "port": 53
        },
        {
            "address": "8.8.8.8",
            "port": 53
        }
    ]
},
EOF
        )
        routing=$(cat << 'EOF'
{
    "domainStrategy": "IPIfNonMatch",
    "rules": [
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
}
EOF
        )
    else
        dns_config='"dns": {"servers": ["1.1.1.1", "8.8.8.8"]},'
        routing='{"domainStrategy": "IPIfNonMatch"}'
    fi
    
    cat > /usr/local/etc/xray/config.json << EOF
{
    "log": {"loglevel": "warning"},
    $dns_config
    "inbounds": $inbounds,
    "outbounds": $outbounds,
    "routing": $routing
}
EOF
    
    /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json || error "Xray 配置错误"
}

generate_sing_box_config() {
    log "生成 Reality 密钥对..."
    
    # 更可靠的密钥生成方法
    local keys_output=$(/usr/local/bin/sing-box generate reality-keypair)
    local private_key=$(echo "$keys_output" | grep "PrivateKey" | awk '{print $2}')
    local public_key=$(echo "$keys_output" | grep "PublicKey" | awk '{print $2}')
    
    # 验证密钥
    if [[ -z "$private_key" ]] || [[ -z "$public_key" ]]; then
        log "Reality 密钥生成失败，使用备用密钥"
        # 使用已知可用的密钥对（仅用于测试）
        private_key="2KZ4vaLxoFzuWYBOklJEkfWaOoc6iPhbG7BPWZSpB1I"
        public_key="MirYs3cXlK_BapbQR5SmWlCHXE7Y6fKhYIG7mVRzjQI"
    fi
    
    local short_id=$(openssl rand -hex 8)
    local reality_uuid=$(uuidgen)
    
    echo "$reality_uuid" > "$WORK_DIR/reality-uuid"
    echo "$public_key" > "$WORK_DIR/reality-public-key"
    echo "$short_id" > "$WORK_DIR/reality-short-id"
    echo "$private_key" > "$WORK_DIR/reality-private-key"
    
    # Hysteria2 密码 - 使用简单格式
    local hy2_password=$(openssl rand -hex 16)
    echo "$hy2_password" > "$WORK_DIR/hy2-password"
    
    # TUIC - 使用简单密码
    local tuic_uuid=$(uuidgen)
    local tuic_password=$(openssl rand -hex 16)
    echo "$tuic_uuid" > "$WORK_DIR/tuic-uuid"
    echo "$tuic_password" > "$WORK_DIR/tuic-password"
    
    # sing-box 配置 - Reality使用端口443，其他协议避免冲突
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "level": "warn",
        "timestamp": true
    },
    "dns": {
        "servers": [
            {
                "tag": "dns_direct",
                "address": "1.1.1.1",
                "address_resolver": "dns_resolver"
            },
            {
                "tag": "dns_resolver",
                "address": "223.5.5.5"
            }
        ],
        "rules": [
            {
                "outbound": "any",
                "server": "dns_direct"
            }
        ],
        "strategy": "prefer_ipv4"
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
                    "short_id": ["$short_id", ""],
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
            "listen_port": 8444,
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
    
    /usr/local/bin/sing-box check -c /etc/sing-box/config.json || error "sing-box 配置文件有误"
}
            "congestion_control": "bbr",
            "auth_timeout": "3s",
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
    
    /usr/local/bin/sing-box check -c /etc/sing-box/config.json || error "sing-box 配置文件有误"
}

generate_nginx_config() {
    # 修复：Nginx 监听 8443 端口，并正确代理到 Xray
    cat > /etc/nginx/conf.d/edgebox.conf << EOF
# TCP/8443 - HTTPS with gRPC and WebSocket
server {
    listen 8443 ssl http2;
    listen [::]:8443 ssl http2;
    server_name ${DOMAIN:-_};
    
    ssl_certificate /etc/ssl/edgebox/cert.pem;
    ssl_certificate_key /etc/ssl/edgebox/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS;
    
    # gRPC - 代理到 Xray 10085 端口
    location /edgebox-grpc {
        grpc_pass grpc://127.0.0.1:10085;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # WebSocket - 代理到 Xray 10086 端口
    location /edgebox-ws {
        proxy_pass http://127.0.0.1:10086;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location / {
        return 200 "EdgeBox is running";
        add_header Content-Type text/plain;
    }
}

# HTTP/80 - 订阅页面
server {
    listen 80;
    listen [::]:80;
    server_name _;
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~* \.(txt)$ {
        add_header Content-Type "text/plain; charset=utf-8";
        add_header Access-Control-Allow-Origin "*";
    }
}
EOF
    
    nginx -t || error "Nginx 配置错误"
}

# === 服务配置 ===
setup_services() {
    log "配置系统服务..."
    
    # sing-box 服务
    cat > /etc/systemd/system/sing-box.service << 'EOF'
[Unit]
Description=sing-box service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # Xray 服务
    cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
}

# === 防火墙配置 ===
setup_firewall() {
    log "配置防火墙..."
    
    ufw allow 22/tcp >/dev/null 2>&1    # SSH
    ufw allow 80/tcp >/dev/null 2>&1    # HTTP
    ufw allow 443/tcp >/dev/null 2>&1   # Reality TCP
    ufw allow 443/udp >/dev/null 2>&1   # Reality UDP (可选)
    ufw allow 8443/tcp >/dev/null 2>&1  # Nginx HTTPS
    ufw allow 8444/udp >/dev/null 2>&1  # Hysteria2 (修改端口)
    ufw allow 2053/udp >/dev/null 2>&1  # TUIC
    
    echo "y" | ufw enable >/dev/null 2>&1
    ufw status
}

# === 管理工具 ===
create_management_tool() {
    log "创建管理工具 edgeboxctl..."
    
    cat > /usr/local/bin/edgeboxctl << 'EOFCTL'
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
    
    echo "=== EdgeBox 订阅链接 ==="
    echo "服务器: $domain"
    echo
    
    # 生成所有订阅链接
    local subscriptions=""
    
    # VLESS-gRPC
    if [[ -f "$WORK_DIR/xray-uuid" ]]; then
        local uuid=$(cat "$WORK_DIR/xray-uuid")
        local grpc_link="vless://$uuid@$domain:8443?encryption=none&security=tls&type=grpc&serviceName=edgebox-grpc&fp=chrome&allowInsecure=1#EdgeBox-gRPC"
        subscriptions+="$grpc_link\n"
        
        # VLESS-WS
        local ws_link="vless://$uuid@$domain:8443?encryption=none&security=tls&type=ws&path=/edgebox-ws&host=$domain&fp=chrome&allowInsecure=1#EdgeBox-WS"
        subscriptions+="$ws_link\n"
    fi
    
    # VLESS-Reality
    if [[ -f "$WORK_DIR/reality-uuid" ]]; then
        local uuid=$(cat "$WORK_DIR/reality-uuid")
        local pubkey=$(cat "$WORK_DIR/reality-public-key")
        local sid=$(cat "$WORK_DIR/reality-short-id")
        local reality_link="vless://$uuid@$domain:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&pbk=$pubkey&sid=$sid&type=tcp&headerType=none&fp=chrome#EdgeBox-Reality"
        subscriptions+="$reality_link\n"
    fi
    
    # Hysteria2
    if [[ -f "$WORK_DIR/hy2-password" ]]; then
        local password=$(cat "$WORK_DIR/hy2-password")
        local hy2_link="hy2://$password@$domain:8444?insecure=1&sni=$domain#EdgeBox-Hysteria2"
        subscriptions+="$hy2_link\n"
    fi
    
    # TUIC v5 - 修复链接格式
    if [[ -f "$WORK_DIR/tuic-uuid" ]]; then
        local uuid=$(cat "$WORK_DIR/tuic-uuid")
        local password=$(cat "$WORK_DIR/tuic-password")
        local tuic_link="tuic://$uuid:$password@$domain:2053?congestion_control=bbr&alpn=h3&udp_relay_mode=native&allow_insecure=true&sni=$domain#EdgeBox-TUIC"
        subscriptions+="$tuic_link\n"
    fi
    
    # 生成聚合订阅文件（需要root权限）
    if [[ -n "$subscriptions" ]]; then
        # 确保目录存在且有正确权限
        sudo mkdir -p /var/www/html
        sudo chown -R www-data:www-data /var/www/html
        
        local base64_sub=$(echo -e "$subscriptions" | base64 -w 0)
        echo "$base64_sub" | sudo tee "/var/www/html/edgebox-sub.txt" > /dev/null
        echo -e "$subscriptions" | sudo tee "/var/www/html/edgebox-sub-plain.txt" > /dev/null
        
        # 生成HTML页面
        generate_subscription_page "$domain" "$subscriptions"
        
        # 简化输出 - 只显示网页版和Base64订阅
        echo "网页版: http://$domain"  
        echo "Base64订阅: http://$domain/edgebox-sub.txt"
    fi
}

generate_subscription_page() {
    local domain="$1"
    local links="$2"
    
    sudo cat > /var/www/html/index.html << HTMLEOF
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EdgeBox 节点订阅</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; font-size: 2em; }
        .section { background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .section h2 { color: #667eea; margin-top: 0; }
        .link-box { background: white; padding: 15px; border-radius: 8px; margin: 10px 0; border: 1px solid #e0e0e0; word-break: break-all; font-family: monospace; font-size: 12px; }
        .copy-btn { background: #667eea; color: white; border: none; padding: 8px 16px; border-radius: 5px; cursor: pointer; font-size: 12px; margin-left: 10px; }
        .copy-btn:hover { background: #5a67d8; }
        .success { color: #48bb78; font-weight: bold; }
        .protocol-badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; margin-right: 5px; }
        .badge-grpc { background: #4caf50; color: white; }
        .badge-ws { background: #2196f3; color: white; }
        .badge-reality { background: #ff9800; color: white; }
        .badge-hy2 { background: #9c27b0; color: white; }
        .badge-tuic { background: #f44336; color: white; }
        textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-family: monospace; font-size: 12px; resize: vertical; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 EdgeBox 多协议节点</h1>
        
        <div class="section">
            <h2>📋 服务器信息</h2>
            <p><strong>地址:</strong> $domain</p>
            <p><strong>支持协议:</strong> 
                <span class="protocol-badge badge-grpc">gRPC</span>
                <span class="protocol-badge badge-ws">WebSocket</span>
                <span class="protocol-badge badge-reality">Reality</span>
                <span class="protocol-badge badge-hy2">Hysteria2</span>
                <span class="protocol-badge badge-tuic">TUIC</span>
            </p>
        </div>

        <div class="section">
            <h2>📄 订阅内容</h2>
            <h3>Base64 编码:</h3>
            <textarea id="base64-content" rows="4" readonly></textarea>
            <button class="copy-btn" onclick="copyText('base64-content')">复制</button>
            
            <h3 style="margin-top: 20px;">明文链接:</h3>
            <textarea id="plain-content" rows="8" readonly></textarea>
            <button class="copy-btn" onclick="copyText('plain-content')">复制</button>
        </div>

        <div class="section">
            <h2>📱 支持的客户端</h2>
            <ul>
                <li><strong>Windows/Mac:</strong> v2rayN, Clash Meta, sing-box</li>
                <li><strong>Android:</strong> v2rayNG, Clash Meta, sing-box</li>
                <li><strong>iOS:</strong> Shadowrocket, Quantumult X, Surge</li>
            </ul>
        </div>
    </div>

    <script>
        function copyText(elementId) {
            const element = document.getElementById(elementId);
            if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
                element.select();
                document.execCommand('copy');
            } else {
                const text = element.innerText;
                navigator.clipboard.writeText(text);
            }
            
            // 显示复制成功提示
            const btn = event.target;
            const originalText = btn.innerText;
            btn.innerText = '✓ 已复制';
            btn.style.background = '#48bb78';
            setTimeout(() => {
                btn.innerText = originalText;
                btn.style.background = '';
            }, 2000);
        }

        // 加载订阅内容
        fetch('/edgebox-sub.txt')
            .then(r => r.text())
            .then(data => document.getElementById('base64-content').value = data)
            .catch(err => document.getElementById('base64-content').value = '加载失败');

        fetch('/edgebox-sub-plain.txt')
            .then(r => r.text())
            .then(data => {
                document.getElementById('plain-content').value = data;
            })
            .catch(err => document.getElementById('plain-content').value = '加载失败');
    </script>
</body>
</html>
HTMLEOF
    
    sudo chown www-data:www-data /var/www/html/index.html
}

debug_reality() {
    echo "=== Reality 调试信息 ==="
    if [[ -f "$WORK_DIR/reality-uuid" ]]; then
        echo "UUID: $(cat $WORK_DIR/reality-uuid)"
        echo "PublicKey: $(cat $WORK_DIR/reality-public-key)"
        echo "PrivateKey: $(cat $WORK_DIR/reality-private-key | head -c 20)..."
        echo "ShortID: $(cat $WORK_DIR/reality-short-id)"
    else
        echo "Reality 配置文件不存在"
    fi
    echo
    echo "=== 检查 sing-box Reality 配置 ==="
    sudo grep -A 20 "vless-reality" /etc/sing-box/config.json 2>/dev/null || echo "配置文件读取失败"
}

case ${1:-help} in
    status)
        echo "=== EdgeBox 服务状态 ==="
        systemctl is-active --quiet sing-box && echo "✓ sing-box: 运行中" || echo "✗ sing-box: 已停止"
        systemctl is-active --quiet xray && echo "✓ xray: 运行中" || echo "✗ xray: 已停止"
        systemctl is-active --quiet nginx && echo "✓ nginx: 运行中" || echo "✗ nginx: 已停止"
        echo
        echo "=== 端口监听 ==="
        echo "TCP 端口:"
        ss -lntp 2>/dev/null | grep -E ':80|:443|:8443|:10085|:10086' || echo "需要root权限查看"
        echo
        echo "UDP 端口:"
        ss -lnup 2>/dev/null | grep -E ':443|:8444|:2053' || echo "需要root权限查看"
        ;;
    sub|subscription)
        show_subscriptions
        ;;
    restart)
        echo "正在重启服务..."
        sudo systemctl restart sing-box xray nginx
        sleep 3
        echo "服务已重启"
        ;;
    logs)
        echo "=== sing-box 日志 ==="
        sudo journalctl -u sing-box -n 10 --no-pager
        echo
        echo "=== xray 日志 ==="
        sudo journalctl -u xray -n 10 --no-pager
        echo
        echo "=== nginx 日志 ==="
        sudo journalctl -u nginx -n 10 --no-pager
        ;;
    debug)
        case ${2:-all} in
            reality)
                debug_reality
                ;;
            *)
                debug_reality
                echo "=== 证书信息 ==="
                sudo openssl x509 -in /etc/ssl/edgebox/cert.pem -noout -subject -dates 2>/dev/null || echo "证书读取失败"
                echo
                echo "=== 配置文件 ==="
                ls -la $WORK_DIR/ 2>/dev/null || echo "需要权限"
                ;;
        esac
        ;;
    *)
        echo "EdgeBox 管理工具"
        echo "用法: edgeboxctl [命令]"
        echo
        echo "可用命令:"
        echo "  status      - 查看服务状态"
        echo "  sub         - 显示订阅链接"
        echo "  restart     - 重启所有服务"
        echo "  logs        - 查看服务日志"
        echo "  debug       - 调试信息"
        echo "    debug reality - Reality 调试信息"
        ;;
esac
EOFCTL

    chmod +x /usr/local/bin/edgeboxctl
    log "管理工具已创建"
}

# === 启动服务 ===
start_services() {
    log "启动服务..."
    
    systemctl restart nginx
    sleep 2
    
    systemctl enable --now sing-box
    sleep 2
    
    systemctl enable --now xray
    sleep 2
    
    # 生成订阅页面（使用root权限）
    local domain="${DOMAIN:-edgebox.local}"
    if [[ "$domain" == "edgebox.local" ]]; then
        local server_ip=$(curl -s --connect-timeout 5 https://ipv4.icanhazip.com/ 2>/dev/null || echo "YOUR_SERVER_IP")
        domain=$server_ip
    fi
    
    # 调用 edgeboxctl 生成订阅
    /usr/local/bin/edgeboxctl sub >/dev/null 2>&1 || true
    
    log "服务启动完成"
}

# === 安装完成信息 ===
show_complete() {
    local domain="${DOMAIN:-edgebox.local}"
    local server_ip
    
    if [[ "$domain" == "edgebox.local" ]]; then
        server_ip=$(curl -s --connect-timeout 5 https://ipv4.icanhazip.com/ 2>/dev/null || echo "YOUR_SERVER_IP")
        domain=$server_ip
    fi
    
    echo
    echo "================================================================"
    echo "🎉 EdgeBox 安装完成！"
    echo "================================================================"
    echo
    echo "✅ 服务器地址: $domain"
    echo "✅ 已安装协议: VLESS-gRPC, VLESS-WS, Reality, Hysteria2, TUIC"
    echo "✅ 端口分配:"
    echo "   - Reality: 443/tcp (sing-box 直连)"
    echo "   - gRPC/WS: 8443/tcp (Nginx → Xray)"
    echo "   - Hysteria2: 8444/udp (sing-box)"
    echo "   - TUIC: 2053/udp (sing-box)"
    echo "   - HTTP: 80/tcp (订阅页面)"
    echo
    echo "📊 服务状态:"
    systemctl is-active --quiet sing-box && echo "  ✓ sing-box: 运行中" || echo "  ✗ sing-box: 异常"
    systemctl is-active --quiet xray && echo "  ✓ xray: 运行中" || echo "  ✗ xray: 异常"
    systemctl is-active --quiet nginx && echo "  ✓ nginx: 运行中" || echo "  ✗ nginx: 异常"
    echo
    echo "🔧 管理命令:"
    echo "  查看状态: edgeboxctl status"
    echo "  查看订阅: edgeboxctl sub"
    echo "  重启服务: edgeboxctl restart"
    echo "  查看日志: edgeboxctl logs"
    echo
    echo "🌐 订阅链接:"
    echo "  网页版: http://$domain"
    echo "  明文版: http://$domain/edgebox-sub-plain.txt"
    echo
    echo "================================================================"
    echo "安装日志: $LOG_FILE"
    echo "配置目录: $WORK_DIR"
    echo "================================================================"
    echo
    echo "🚀 开始使用:"
    echo "1. 复制订阅链接到客户端"
    echo "2. 更新订阅获取所有节点"
    echo "3. 选择合适协议连接"
    echo
}

# === 主安装流程 ===
main() {
    check_root
    
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "EdgeBox 安装开始: $(date)" > "$LOG_FILE"
    
    log "EdgeBox v${SCRIPT_VERSION} 安装程序启动"
    
    # 清理旧环境
    log "清理旧环境..."
    rm -f /etc/nginx/conf.d/edgebox*.conf 2>/dev/null || true
    rm -f /etc/nginx/sites-*/edgebox* 2>/dev/null || true
    systemctl stop sing-box 2>/dev/null || true
    systemctl stop xray 2>/dev/null || true
    
    # 基础检查
    check_os
    check_requirements
    
    # 交互配置
    interactive_config
    
    # 系统准备
    install_packages
    optimize_system
    
    # 软件安装
    install_sing_box
    install_xray
    
    # 证书配置
    setup_certificates
    
    # 配置生成
    generate_configs
    
    # 服务配置
    setup_services
    
    # 防火墙配置
    setup_firewall
    
    # 管理工具
    create_management_tool
    
    # 启动服务
    start_services
    
    # 显示完成信息
    show_complete
    
    log "EdgeBox 安装成功完成"
}

# === 执行主函数 ===
main "$@"
        
            "
