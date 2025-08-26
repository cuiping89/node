#!/usr/bin/env bash
# =====================================================================================
# EdgeBox - 一站式多协议节点部署工具
# 支持：VLESS-gRPC, VLESS-WS, VLESS-Reality, Hysteria2, TUIC
# 系统要求：Ubuntu 18.04+ / Debian 10+
# 使用方法：
#   切换到 root: sudo su -
#   运行脚本: bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/install.sh)
# =====================================================================================

set -euo pipefail

# === 检查 root 权限 ===
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "此脚本需要 root 权限运行"
        echo "请先切换到 root 用户："
        echo "  sudo su -"
        echo "然后运行："
        echo "  bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/install.sh)"
        exit 1
    fi
}

# === 版本配置 ===
readonly SING_BOX_VERSION="v1.11.7"
readonly XRAY_VERSION="v1.8.24"
readonly SCRIPT_VERSION="1.0.1"

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
HY2_PORT="2080"  # 修复：避免与Reality的443端口冲突

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
    
    # 检查网络
    if ! curl -m 10 -s https://www.google.com >/dev/null; then
        log "警告：网络连接可能有问题，但继续安装..."
    fi
    
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
    
    # 先彻底清理可能存在的旧配置
    log "清理旧的 EdgeBox 配置..."
    rm -f /etc/nginx/edgebox*.conf 2>/dev/null || true
    rm -f /etc/nginx/conf.d/edgebox*.conf 2>/dev/null || true
    rm -f /etc/nginx/sites-available/edgebox* 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/edgebox* 2>/dev/null || true
    
    # 清理默认站点可能的冲突
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    
    # 修复 nginx.conf 中的错误引用
    if [[ -f /etc/nginx/nginx.conf ]]; then
        # 移除对 edgebox 相关的引用
        sed -i '/edgebox/d' /etc/nginx/nginx.conf 2>/dev/null || true
        
        # 如果 nginx.conf 被破坏，恢复默认配置
        if ! nginx -t 2>/dev/null; then
            log "恢复 nginx 默认配置..."
            if [[ -f /etc/nginx/nginx.conf.dpkg-dist ]]; then
                cp /etc/nginx/nginx.conf.dpkg-dist /etc/nginx/nginx.conf
            else
                # 创建最小可用配置
                cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    
    access_log /var/log/nginx/access.log;
    
    gzip on;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
            fi
        fi
    fi
    
    # 确保 nginx 服务停止
    systemctl stop nginx 2>/dev/null || true
    
    # 修复 dpkg 状态
    dpkg --configure -a 2>/dev/null || true
    
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        ca-certificates curl wget jq tar unzip openssl \
        nginx ufw vnstat cron logrotate uuid-runtime \
        certbot python3-certbot-nginx dnsutils
    
    # 确保 nginx 能正常启动
    nginx -t && systemctl restart nginx || {
        log "nginx 启动失败，尝试修复..."
        systemctl status nginx --no-pager >> "$LOG_FILE" 2>&1
        journalctl -xeu nginx -n 20 --no-pager >> "$LOG_FILE" 2>&1
    }
    
    log "依赖包安装完成"
}

optimize_system() {
    log "优化系统参数..."
    
    # 启用 BBR
    cat > /etc/sysctl.d/99-edgebox-bbr.conf << 'EOF'
# EdgeBox Network Optimization
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 65536 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
EOF
    
    sysctl -p /etc/sysctl.d/99-edgebox-bbr.conf
    log "系统优化完成"
}

# === 交互配置 ===
interactive_config() {
    echo "=== EdgeBox 配置向导 ==="
    echo
    
    # 使用默认配置，避免交互问题
    echo "使用默认配置进行安装..."
    DOMAIN=""
    echo "✓ 将使用自签名证书"
    
    # 固定安装所有协议
    PROTOCOLS=("grpc" "ws" "reality" "hy2" "tuic")
    HY2_PORT="2080"  # 修复：使用非443端口避免冲突
    echo "✓ 将安装所有协议: VLESS-gRPC, VLESS-WS, VLESS-Reality, Hysteria2, TUIC"
    echo "✓ Hysteria2 将使用端口 $HY2_PORT"
    
    # 默认直出模式
    USE_PROXY=false
    echo "✓ 将使用全直出模式（所有流量直连）"
    
    echo
    echo "提示：安装完成后可使用 edgeboxctl 管理工具配置域名和代理"
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
        # 检查域名解析
        local domain_ip=$(dig +short "$DOMAIN" 2>/dev/null | tail -n1)
        local server_ip=$(curl -s https://ipv4.icanhazip.com/ 2>/dev/null)
        
        if [[ -n "$domain_ip" && "$domain_ip" == "$server_ip" ]]; then
            log "域名解析正确，尝试申请 Let's Encrypt 证书"
            
            # 确保80端口开放
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
    echo "${HY2_PORT}" > "$WORK_DIR/hy2-port"  # 修复：保存HY2端口
    [[ "$USE_PROXY" == true ]] && echo "${PROXY_HOST}:${PROXY_PORT}:${PROXY_USER}:${PROXY_PASS}" > "$WORK_DIR/proxy"
    
    # 保存JSON配置
    cat > "$WORK_DIR/config.json" << EOF
{
    "domain": "${DOMAIN:-edgebox.local}",
    "use_proxy": ${USE_PROXY,,},
    "proxy_host": "${PROXY_HOST}",
    "proxy_port": "${PROXY_PORT}",
    "proxy_user": "${PROXY_USER}",
    "proxy_pass": "${PROXY_PASS}",
    "hysteria2_port": "${HY2_PORT}"
}
EOF
    
    generate_xray_config
    generate_sing_box_config
    generate_nginx_config
}

generate_xray_config() {
    local uuid=$(uuidgen)
    echo "$uuid" > "$WORK_DIR/xray-uuid"
    
    # 构建入站 - 修复端口分配
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
    # 修复：Reality 密钥生成和解析
    log "生成 Reality 密钥对..."
    local keys_output
    keys_output=$(/usr/local/bin/sing-box generate reality-keypair 2>&1)
    
    local private_key=""
    local public_key=""
    
    # 改进的密钥解析方法
    if [[ -n "$keys_output" ]]; then
        # 方法1：使用sed提取
        private_key=$(echo "$keys_output" | sed -n 's/^PrivateKey: *//p' | tr -d ' \n')
        public_key=$(echo "$keys_output" | sed -n 's/^PublicKey: *//p' | tr -d ' \n')
        
        # 方法2：如果方法1失败，尝试awk
        if [[ -z "$private_key" ]] || [[ -z "$public_key" ]]; then
            private_key=$(echo "$keys_output" | awk '/PrivateKey:/ {print $2}' | tr -d '\n')
            public_key=$(echo "$keys_output" | awk '/PublicKey:/ {print $2}' | tr -d '\n')
        fi
    fi
    
    # 验证密钥长度（Reality密钥通常是44字符）
    if [[ ${#private_key} -lt 20 ]] || [[ ${#public_key} -lt 20 ]]; then
        log "密钥无效，重新生成..."
        # 使用sing-box内置命令再次尝试
        keys_output=$(/usr/local/bin/sing-box generate reality-keypair)
        private_key=$(echo "$keys_output" | grep PrivateKey | cut -d' ' -f2-)
        public_key=$(echo "$keys_output" | grep PublicKey | cut -d' ' -f2-)
    fi
    
    local short_id=$(openssl rand -hex 8)  # 修复：Reality短ID改为8位
    local reality_uuid=$(uuidgen)
    
    echo "$reality_uuid" > "$WORK_DIR/reality-uuid"
    echo "$public_key" > "$WORK_DIR/reality-public-key"
    echo "$short_id" > "$WORK_DIR/reality-short-id"
    echo "$private_key" > "$WORK_DIR/reality-private-key"
    
    # Hysteria2 - 修复协议格式和参数
    local hy2_password=$(openssl rand -hex 32)  # 改为hex格式
    echo "$hy2_password" > "$WORK_DIR/hy2-password"
    
    # TUIC - 简化密码生成
    local tuic_uuid=$(uuidgen)
    local tuic_password=$(openssl rand -hex 32)
    echo "$tuic_uuid" > "$WORK_DIR/tuic-uuid"
    echo "$tuic_password" > "$WORK_DIR/tuic-password"
    
    log "Reality密钥: private_key=${private_key:0:10}..., public_key=${public_key:0:10}..."
    
    # 修复：sing-box 配置文件，增加更多Reality配置选项
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
                "server_name": "www.microsoft.com",
                "reality": {
                    "enabled": true,
                    "private_key": "$private_key",
                    "short_id": ["$short_id", ""],
                    "handshake": {
                        "server": "www.microsoft.com",
                        "server_port": 443
                    },
                    "max_time_difference": "1m"
                }
            },
            "multiplex": {
                "enabled": false
            }
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2",
            "listen": "::",
            "listen_port": 443,
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
    
    # 验证配置文件
    /usr/local/bin/sing-box check -c /etc/sing-box/config.json || error "sing-box 配置文件有误"
}

generate_nginx_config() {
    local listen_port=8443  # Reality 占用 443，Nginx 用 8443
    
    cat > /etc/nginx/conf.d/edgebox.conf << EOF
server {
    listen $listen_port ssl http2;
    server_name ${DOMAIN:-_};
    
    ssl_certificate /etc/ssl/edgebox/cert.pem;
    ssl_certificate_key /etc/ssl/edgebox/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS;
    
    location / {
        return 200 "EdgeBox is running";
        add_header Content-Type text/plain;
    }
    
    location /edgebox-grpc {
        grpc_pass grpc://127.0.0.1:10085;
        grpc_set_header Host \$host;
    }
    
    location /edgebox-ws {
        proxy_pass http://127.0.0.1:10086;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}

server {
    listen 80 default_server;
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
    
    ufw allow 22/tcp >/dev/null 2>&1
    ufw allow 443/tcp >/dev/null 2>&1
    ufw allow 443/udp >/dev/null 2>&1
    ufw allow 8443/tcp >/dev/null 2>&1
    ufw allow 2053/udp >/dev/null 2>&1
    ufw allow 80/tcp >/dev/null 2>&1
    ufw allow ${HY2_PORT}/udp >/dev/null 2>&1  # 修复：添加HY2端口
    
    echo "y" | ufw enable >/dev/null 2>&1
    ufw status
}

# === 管理工具 ===
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
        local reality_link="vless://$uuid@$domain:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=www.microsoft.com&pbk=$pubkey&sid=$sid&type=tcp#EdgeBox-Reality"
        echo "VLESS-Reality:"
        echo "$reality_link"
        subscriptions+="$reality_link\n"
        echo
    fi
    
    # Hysteria2 - 修复回443端口
    if [[ -f "$WORK_DIR/hy2-password" ]]; then
        local password=$(cat "$WORK_DIR/hy2-password")
        local hy2_link="hysteria2://$password@$domain:443?insecure=1#EdgeBox-Hysteria2"
        echo "Hysteria2:"
        echo "$hy2_link"
        subscriptions+="$hy2_link\n"
        echo
    fi
    
    # TUIC - 修复链接格式
    if [[ -f "$WORK_DIR/tuic-uuid" ]]; then
        local uuid=$(cat "$WORK_DIR/tuic-uuid")
        local password=$(cat "$WORK_DIR/tuic-password")
        local tuic_link="tuic://$uuid:$password@$domain:2053?congestion_control=bbr&alpn=h3&allow_insecure=1#EdgeBox-TUIC"
        echo "TUIC:"
        echo "$tuic_link"
        subscriptions+="$tuic_link\n"
        echo
    fi
    
    # 生成聚合订阅
    if [[ -n "$subscriptions" ]]; then
        mkdir -p /var/www/html
        local base64_sub=$(echo -e "$subscriptions" | base64 -w 0)
        echo "$base64_sub" > "/var/www/html/edgebox-sub.txt"
        echo -e "$subscriptions" > "/var/www/html/edgebox-sub-plain.txt"
        
        echo "=== 聚合订阅链接 ==="
        echo "Base64订阅: http://$domain/edgebox-sub.txt"
        echo "明文订阅: http://$domain/edgebox-sub-plain.txt"
        echo
        echo "=== Base64订阅内容 ==="
        echo "$base64_sub"
        echo
        echo "提示: 将订阅链接添加到客户端即可使用所有协议"
    fi
}

generate_subscription_page() {
    local domain="$1"
    local page_file="/var/www/html/index.html"
    
    cat > "$page_file" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EdgeBox 节点订阅</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1000px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .subscription { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .link { word-break: break-all; font-family: monospace; background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 3px; margin: 5px 0; font-size: 12px; }
        .btn { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }
        .btn:hover { background: #0056b3; }
        .copy-btn { background: #28a745; padding: 5px 10px; font-size: 12px; }
        textarea { font-family: monospace; resize: vertical; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 EdgeBox 多协议节点</h1>
        
        <div class="info">
            <h3>📋 服务器信息</h3>
            <p><strong>地址:</strong> DOMAIN_PLACEHOLDER</p>
            <p><strong>支持协议:</strong> VLESS-gRPC, VLESS-WS, VLESS-Reality, Hysteria2, TUIC</p>
            <p><strong>更新时间:</strong> TIME_PLACEHOLDER</p>
        </div>

        <div class="subscription">
            <h3>🔗 聚合订阅链接</h3>
            <div style="margin-bottom: 15px;">
                <p><strong>一键订阅所有协议：</strong></p>
                <div class="link">http://DOMAIN_PLACEHOLDER/edgebox-sub.txt</div>
                <a href="/edgebox-sub.txt" class="btn" target="_blank">📥 Base64订阅</a>
                <a href="/edgebox-sub-plain.txt" class="btn" target="_blank">📄 明文订阅</a>
            </div>
            
            <div style="margin-bottom: 20px;">
                <h4>📋 Base64订阅内容：</h4>
                <textarea id="base64Content" readonly style="width: 100%; height: 80px; font-family: monospace; font-size: 12px; margin-bottom: 10px;"></textarea>
                <button class="btn copy-btn" onclick="copyContent('base64Content')">复制Base64</button>
            </div>
            
            <div>
                <h4>📝 明文订阅内容：</h4>
                <textarea id="plainContent" readonly style="width: 100%; height: 150px; font-family: monospace; font-size: 12px; margin-bottom: 10px;"></textarea>
                <button class="btn copy-btn" onclick="copyContent('plainContent')">复制明文</button>
            </div>
        </div>

        <div class="subscription">
            <h3>🎯 单个协议链接</h3>
            <div id="singleLinks" style="font-family: monospace; font-size: 12px; line-height: 1.8;">
                <p>加载中...</p>
            </div>
        </div>

        <div class="subscription">
            <h3>📱 支持的客户端</h3>
            <ul>
                <li><strong>Android:</strong> v2rayNG, Clash Meta, sing-box</li>
                <li><strong>iOS:</strong> Shadowrocket, Quantumult X, sing-box</li>
                <li><strong>Windows:</strong> v2rayN, Clash Verge, sing-box</li>
                <li><strong>macOS:</strong> ClashX Pro, sing-box</li>
            </ul>
        </div>

        <div class="subscription">
            <h3>⚙️ 使用说明</h3>
            <ol>
                <li>复制上方订阅链接</li>
                <li>在客户端中添加订阅</li>
                <li>更新订阅获取所有节点</li>
                <li>选择适合的协议连接</li>
            </ol>
        </div>
    </div>

    <script>
        function copyContent(elementId) {
            const element = document.getElementById(elementId);
            element.select();
            document.execCommand('copy');
            
            const btn = event.target;
            const originalText = btn.textContent;
            btn.textContent = '已复制!';
            setTimeout(() => {
                btn.textContent = originalText;
            }, 2000);
        }
        
        function copySingleLink(link) {
            navigator.clipboard.writeText(link).then(() => {
                // 临时显示复制成功
                const tempSpan = document.createElement('span');
                tempSpan.textContent = ' ✅已复制';
                tempSpan.style.color = '#28a745';
                event.target.parentNode.appendChild(tempSpan);
                setTimeout(() => {
                    tempSpan.remove();
                }, 2000);
            });
        }
        
        // 页面加载时加载所有订阅内容
        window.onload = function() {
            // 加载Base64内容
            fetch('/edgebox-sub.txt')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('base64Content').value = data;
                })
                .catch(err => {
                    document.getElementById('base64Content').value = '加载失败，请刷新页面重试';
                });
                
            // 加载明文内容并解析单个链接
            fetch('/edgebox-sub-plain.txt')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('plainContent').value = data;
                    
                    // 解析并显示单个协议链接
                    const links = data.trim().split('\n').filter(line => line.trim());
                    const singleLinksDiv = document.getElementById('singleLinks');
                    
                    if (links.length > 0) {
                        let html = '';
                        links.forEach(link => {
                            const protocolMatch = link.match(/^(\w+):\/\//);
                            const nameMatch = link.match(/#(.+)$/);
                            const protocol = protocolMatch ? protocolMatch[1].toUpperCase() : '未知';
                            const name = nameMatch ? nameMatch[1] : protocol;
                            
                            html += `
                                <div style="margin-bottom: 15px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 5px;">
                                    <div style="margin-bottom: 5px;">
                                        <strong>${name}</strong>
                                        <button onclick="copySingleLink('${link}')" style="float: right; padding: 2px 8px; font-size: 11px; background: #17a2b8; color: white; border: none; border-radius: 3px; cursor: pointer;">复制</button>
                                    </div>
                                    <div style="word-break: break-all; color: #666; font-size: 11px;">${link}</div>
                                </div>
                            `;
                        });
                        singleLinksDiv.innerHTML = html;
                    } else {
                        singleLinksDiv.innerHTML = '<p>没有找到协议链接</p>';
                    }
                })
                .catch(err => {
                    document.getElementById('plainContent').value = '加载失败，请刷新页面重试';
                    document.getElementById('singleLinks').innerHTML = '<p>加载失败</p>';
                });
        };
    </script>
</body>
</html>
HTMLEOF
    
    # 替换占位符
    sed -i "s/DOMAIN_PLACEHOLDER/$domain/g" "$page_file"
    sed -i "s/TIME_PLACEHOLDER/$(date '+%Y-%m-%d %H:%M:%S')/g" "$page_file"
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
        echo "正在重启服务..."
        systemctl restart sing-box xray nginx
        sleep 3
        echo "服务已重启"
        ;;
    logs)
        echo "=== sing-box 日志 ==="
        journalctl -u sing-box -n 10 --no-pager
        echo
        echo "=== xray 日志 ==="
        journalctl -u xray -n 10 --no-pager
        echo
        echo "=== nginx 日志 ==="
        journalctl -u nginx -n 10 --no-pager
        ;;
    update-sub)
        show_subscriptions > /dev/null
        echo "订阅文件已更新"
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
        echo "  update-sub  - 更新订阅文件"
        echo
        ;;
esac
EOF

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
    
    # 生成订阅页面和文件
    local domain="${DOMAIN:-edgebox.local}"
    if [[ "$domain" == "edgebox.local" ]]; then
        local server_ip=$(curl -s --connect-timeout 5 https://ipv4.icanhazip.com/ 2>/dev/null || echo "YOUR_SERVER_IP")
        domain=$server_ip
    fi
    
    # 确保目录存在
    mkdir -p /var/www/html
    
    # 生成订阅页面
    generate_subscription_page "$domain"
    
    # 生成订阅文件
    /usr/local/bin/edgeboxctl show_subscriptions &>/dev/null || {
        log "初始订阅生成失败，手动生成..."
        show_subscriptions &>/dev/null || true
    }
    
    # 检查服务状态
    if ! systemctl is-active --quiet sing-box; then
        log "sing-box 启动失败"
        journalctl -u sing-box -n 20 --no-pager >> "$LOG_FILE"
    fi
    
    if ! systemctl is-active --quiet xray; then
        log "xray 启动失败"
        journalctl -u xray -n 20 --no-pager >> "$LOG_FILE"
    fi
    
    if ! systemctl is-active --quiet nginx; then
        log "nginx 启动失败"
        journalctl -u nginx -n 20 --no-pager >> "$LOG_FILE"
    fi
    
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
    echo "   - Reality: 443 (TCP/UDP)"
    echo "   - gRPC/WS: 8443 (TCP, via Nginx)"
    echo "   - Hysteria2: $HY2_PORT (UDP)"
    echo "   - TUIC: 2053 (UDP)"
    [[ "$USE_PROXY" == true ]] && echo "✅ 住宅代理: ${PROXY_HOST}:${PROXY_PORT}" || echo "✅ 出站模式: 全直出"
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
    echo "  Base64: http://$domain/edgebox-sub.txt"
    echo "  明文版: http://$domain/edgebox-sub-plain.txt"
    echo
    echo "📱 快速获取:"
    echo "  执行命令: edgeboxctl sub"
    echo "  或访问: http://$domain"
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
    echo "4. 享受高速网络体验！"
    echo
}

# === 主安装流程 ===
main() {
    # 检查 root 权限
    check_root
    
    # 创建日志文件
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "EdgeBox 安装开始: $(date)" > "$LOG_FILE"
    
    log "EdgeBox v${SCRIPT_VERSION} 安装程序启动"
    
    # 先清理旧环境
    log "清理旧环境..."
    rm -f /etc/nginx/edgebox*.conf 2>/dev/null || true
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
