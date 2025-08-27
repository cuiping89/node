#!/usr/bin/env bash
# =====================================================================================
# EdgeBox - 一站式多协议节点部署工具 (Reality修复版)
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
readonly SCRIPT_VERSION="1.1.0"

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
    echo "✔ 将使用自签名证书"
    
    PROTOCOLS=("grpc" "ws" "reality" "hy2" "tuic")
    echo "✔ 将安装所有协议: VLESS-gRPC, VLESS-WS, VLESS-Reality, Hysteria2, TUIC"
    
    USE_PROXY=false
    echo "✔ 将使用全直出模式（所有流量直连）"
    
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
    
    # 使用正确的端口 10085 和 10086
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
    
    # 构建出站
    local outbounds='[{"protocol": "freedom", "tag": "direct"}'
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
    
    # 路由规则
    local routing=""
    if [[ "$USE_PROXY" == true ]]; then
        routing=$(cat << 'EOF'
{
    "domainStrategy": "AsIs",
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
        routing='{"domainStrategy": "AsIs"}'
    fi
    
    cat > /usr/local/etc/xray/config.json << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": $outbounds,
    "routing": $routing
}
EOF
    
    /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json || error "Xray 配置错误"
}

generate_sing_box_config() {
    log "生成 Reality 密钥对..."
    
    # 生成 Reality 密钥对 - 使用更可靠的方法
    local temp_keys=$(/usr/local/bin/sing-box generate reality-keypair 2>/dev/null || echo "")
    
    if [[ -n "$temp_keys" ]]; then
        local private_key=$(echo "$temp_keys" | grep "PrivateKey" | awk '{print $2}' | tr -d '\r\n ')
        local public_key=$(echo "$temp_keys" | grep "PublicKey" | awk '{print $2}' | tr -d '\r\n ')
    fi
    
    # 验证密钥，如果为空则使用备用方法
    if [[ -z "$private_key" ]] || [[ -z "$public_key" ]]; then
        log "主方法失败，使用备用方法生成密钥..."
        # 直接调用 sing-box 生成并保存到文件
        /usr/local/bin/sing-box generate reality-keypair > /tmp/reality-keys.txt 2>&1
        private_key=$(grep "PrivateKey" /tmp/reality-keys.txt | awk '{print $2}' | tr -d '\r\n ')
        public_key=$(grep "PublicKey" /tmp/reality-keys.txt | awk '{print $2}' | tr -d '\r\n ')
        rm -f /tmp/reality-keys.txt
    fi
    
    # 如果还是失败，使用已知可用的密钥对（仅用于紧急情况）
    if [[ -z "$private_key" ]] || [[ -z "$public_key" ]]; then
        log "密钥生成失败，使用备用密钥对..."
        private_key="2KZ4vaLxoFzuWYBOklJEkfWaOoc6iPhbG7BPWZSpB1I"
        public_key="MirYs3cXlK_BapbQR5SmWlCHXE7Y6fKhYIG7mVRzjQI"
    fi
    
    local short_id=$(openssl rand -hex 8)
    local reality_uuid=$(uuidgen)
    
    # 保存 Reality 配置
    echo "$reality_uuid" > "$WORK_DIR/reality-uuid"
    echo "$public_key" > "$WORK_DIR/reality-public-key"
    echo "$short_id" > "$WORK_DIR/reality-short-id"
    echo "$private_key" > "$WORK_DIR/reality-private-key"
    
    # 创建公钥文件供客户端使用
    mkdir -p /etc/s-box
    echo "$public_key" > /etc/s-box/public.key
    chmod 644 /etc/s-box/public.key
    
    # Hysteria2 密码
    local hy2_password=$(openssl rand -hex 16)
    echo "$hy2_password" > "$WORK_DIR/hy2-password"
    
    # TUIC 配置
    local tuic_uuid=$(uuidgen)
    local tuic_password=$(openssl rand -hex 16)
    echo "$tuic_uuid" > "$WORK_DIR/tuic-uuid"
    echo "$tuic_password" > "$WORK_DIR/tuic-password"
    
    # 修复：Reality 配置结构
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
                    "handshake": {
                        "server": "www.cloudflare.com",
                        "server_port": 443
                    },
                    "private_key": "$private_key",
                    "short_id": ["$short_id"]
                }
            }
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2",
            "listen": "::",
            "listen_port": 8443,
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
    
    # 验证配置
    if ! /usr/local/bin/sing-box check -c /etc/sing-box/config.json; then
        log "sing-box 配置验证失败，尝试修复..."
        # 如果验证失败，使用更简单的配置
        generate_simple_sing_box_config "$reality_uuid" "$private_key" "$public_key" "$short_id" "$hy2_password" "$tuic_uuid" "$tuic_password"
    fi
    
    log "Reality 配置生成完成"
    log "PublicKey: $public_key"
    log "ShortID: $short_id"
}

generate_simple_sing_box_config() {
    local reality_uuid=$1
    local private_key=$2
    local public_key=$3
    local short_id=$4
    local hy2_password=$5
    local tuic_uuid=$6
    local tuic_password=$7
    
    # 生成简化配置
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
                    "flow": ""
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "www.cloudflare.com",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "www.cloudflare.com",
                        "server_port": 443
                    },
                    "private_key": "$private_key",
                    "short_id": ["$short_id"]
                }
            }
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2",
            "listen": "::",
            "listen_port": 8443,
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
    
    /usr/local/bin/sing-box check -c /etc/sing-box/config.json || log "警告：配置验证失败，但将继续"
}

generate_nginx_config() {
    # Nginx 监听 8443 端口，并正确代理到 Xray
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
    ufw allow 8443/udp >/dev/null 2>&1  # Hysteria2
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
    
    # VLESS-Reality - 修复：正确读取密钥和参数
    if [[ -f "$WORK_DIR/reality-uuid" ]]; then
        local uuid=$(cat "$WORK_DIR/reality-uuid" | tr -d '\r\n ')
        local pubkey=$(cat "$WORK_DIR/reality-public-key" | tr -d '\r\n ')
        local sid=$(cat "$WORK_DIR/reality-short-id" | tr -d '\r\n ')
        local sni="www.cloudflare.com"
        
        # 检查是否使用 flow
        local flow_param=""
        if grep -q '"flow": "xtls-rprx-vision"' /etc/sing-box/config.json 2>/dev/null; then
            flow_param="&flow=xtls-rprx-vision"
        fi
        
        local reality_link="vless://$uuid@$domain:443?security=reality&encryption=none${flow_param}&sni=$sni&fp=chrome&pbk=$pubkey&sid=$sid&type
