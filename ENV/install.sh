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
readonly SCRIPT_VERSION="1.0.0"

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
HY2_PORT="443"

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
    
    # 先清理可能存在的旧配置
    log "清理旧的 nginx 配置..."
    rm -f /etc/nginx/edgebox*.conf 2>/dev/null || true
    rm -f /etc/nginx/conf.d/edgebox*.conf 2>/dev/null || true
    rm -f /etc/nginx/sites-available/edgebox* 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/edgebox* 2>/dev/null || true
    
    # 修复 nginx.conf 中的错误引用
    if [[ -f /etc/nginx/nginx.conf ]]; then
        # 移除对 edgebox_stream.conf 的引用
        sed -i '/edgebox_stream\.conf/d' /etc/nginx/nginx.conf 2>/dev/null || true
        sed -i '/include.*edgebox/d' /etc/nginx/nginx.conf 2>/dev/null || true
        
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
    HY2_PORT="443"
    echo "✓ 将安装所有协议: VLESS-gRPC, VLESS-WS, VLESS-Reality, Hysteria2, TUIC"
    
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
    [[ "$USE_PROXY" == true ]] && echo "${PROXY_HOST}:${PROXY_PORT}:${PROXY_USER}:${PROXY_PASS}" > "$WORK_DIR/proxy"
    
    # 保存JSON配置
    cat > "$WORK_DIR/config.json" << EOF
{
    "domain": "${DOMAIN:-edgebox.local}",
    "use_proxy": ${USE_PROXY,,},
    "proxy_host": "${PROXY_HOST}",
    "proxy_port": "${PROXY_PORT}",
    "proxy_user": "${PROXY_USER}",
    "proxy_pass": "${PROXY_PASS}"
}
EOF
    
    generate_xray_config
    generate_sing_box_config
    generate_nginx_config
}

generate_xray_config() {
    local uuid=$(uuidgen)
    echo "$uuid" > "$WORK_DIR/xray-uuid"
    
    # 构建入站
    local inbounds=$(cat << EOF
[
    {
        "port": 10001,
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
        "port": 10002,
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
    # Reality 密钥生成
    local keys=$(/usr/local/bin/sing-box generate reality-keypair)
    # 正确提取密钥（冒号后的所有内容）
    local private_key=$(echo "$keys" | grep "^PrivateKey:" | sed 's/^PrivateKey: *//')
    local public_key=$(echo "$keys" | grep "^PublicKey:" | sed 's/^PublicKey: *//')
    
    # 如果密钥为空，尝试其他方法
    if [[ -z "$private_key" ]] || [[ -z "$public_key" ]]; then
        private_key=$(echo "$keys" | awk '/^PrivateKey:/ {print substr($0, index($0,$2))}')
        public_key=$(echo "$keys" | awk '/^PublicKey:/ {print substr($0, index($0,$2))}')
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
    
    # 调试输出
    log "Reality private key: $private_key"
    log "Reality public key: $public_key"
    
    # 生成配置文件
    cat > /etc/sing-box/config.json << EOF
{
    "log": {"level": "info"},
    "inbounds": [
        {
            "type": "vless",
            "tag": "vless-reality",
            "listen": "::",
            "listen_port": 443,
            "users": [{
                "uuid": "$reality_uuid",
                "flow": "xtls-rprx-vision"
            }],
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
            "users": [{
                "password": "$hy2_password"
            }],
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
            "users": [{
                "uuid": "$tuic_uuid",
                "password": "$tuic_password"
            }],
            "congestion_control": "bbr",
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
    
    /usr/local/bin/sing-box check -c /etc/sing-box/config.json || error "sing-box 配置错误"
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
        return 200 "Hello World";
        add_header Content-Type text/plain;
    }
    
    location /edgebox-grpc {
        grpc_pass grpc://127.0.0.1:10001;
        grpc_set_header Host \$host;
    }
    
    location /edgebox-ws {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
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
    
    echo "y" | ufw enable >/dev/null 2>&1
    ufw status
}

# === 管理工具（先创建简化版）===
create_management_tool() {
    log "创建管理工具 edgeboxctl..."
    
    # 先写入简化版管理工具，后续可以更新
    cat > /usr/local/bin/edgeboxctl << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="/opt/edgebox"

case ${1:-help} in
    status)
        echo "=== EdgeBox 服务状态 ==="
        systemctl is-active --quiet sing-box && echo "✓ sing-box: 运行中" || echo "✗ sing-box: 已停止"
        systemctl is-active --quiet xray && echo "✓ xray: 运行中" || echo "✗ xray: 已停止"
        systemctl is-active --quiet nginx && echo "✓ nginx: 运行中" || echo "✗ nginx: 已停止"
        echo
        echo "=== 端口监听 ==="
        ss -lntup | egrep ':443|:8443|:2053' || echo "无相关端口监听"
        ;;
    sub)
        [[ ! -f "$WORK_DIR/domain" ]] && { echo "配置文件不存在"; exit 1; }
        domain=$(cat "$WORK_DIR/domain")
        [[ "$domain" == "edgebox.local" ]] && domain=$(curl -s https://ipv4.icanhazip.com/)
        
        echo "=== 订阅链接 ==="
        if [[ -f "$WORK_DIR/xray-uuid" ]]; then
            uuid=$(cat "$WORK_DIR/xray-uuid")
            echo "VLESS-gRPC:"
            echo "vless://$uuid@$domain:8443?encryption=none&security=tls&type=grpc&serviceName=edgebox-grpc&fp=chrome#EdgeBox-gRPC"
            echo
            echo "VLESS-WS:"
            echo "vless://$uuid@$domain:8443?encryption=none&security=tls&type=ws&path=/edgebox-ws&host=$domain&fp=chrome#EdgeBox-WS"
            echo
        fi
        
        if [[ -f "$WORK_DIR/reality-uuid" ]]; then
            uuid=$(cat "$WORK_DIR/reality-uuid")
            pubkey=$(cat "$WORK_DIR/reality-public-key")
            sid=$(cat "$WORK_DIR/reality-short-id")
            echo "VLESS-Reality:"
            echo "vless://$uuid@$domain:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=www.cloudflare.com&pbk=$pubkey&sid=$sid&type=tcp#EdgeBox-Reality"
            echo
        fi
        
        if [[ -f "$WORK_DIR/hy2-password" ]]; then
            password=$(cat "$WORK_DIR/hy2-password")
            echo "Hysteria2:"
            echo "hysteria2://$password@$domain:443/?insecure=1#EdgeBox-Hysteria2"
            echo
        fi
        
        if [[ -f "$WORK_DIR/tuic-uuid" ]]; then
            uuid=$(cat "$WORK_DIR/tuic-uuid")
            password=$(cat "$WORK_DIR/tuic-password")
            echo "TUIC:"
            echo "tuic://$uuid:$password@$domain:2053?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#EdgeBox-TUIC"
        fi
        ;;
    restart)
        systemctl restart sing-box xray nginx
        echo "服务已重启"
        ;;
    *)
        echo "用法: edgeboxctl [status|sub|restart]"
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
    echo
    echo "================================================================"
    echo "🎉 EdgeBox 安装完成！"
    echo "================================================================"
    echo
    echo "✅ 已安装协议: VLESS-gRPC, VLESS-WS, Reality, Hysteria2, TUIC"
    echo "✅ 域名配置: ${DOMAIN:-edgebox.local}"
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
    echo
    echo "📱 快速获取订阅链接:"
    echo "  执行命令: edgeboxctl sub"
    echo
    echo "================================================================"
    echo "安装日志: $LOG_FILE"
    echo "================================================================"
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
