#!/bin/bash

#############################################
# EdgeBox 一站式多协议节点部署脚本
# Version: 1.0.0
# Description: 非交互式IP模式安装
# Protocols: VLESS-Reality, VLESS-gRPC, VLESS-WS, Hysteria2, TUIC
#############################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
INSTALL_DIR="/etc/edgebox"
CERT_DIR="${INSTALL_DIR}/cert"
CONFIG_DIR="${INSTALL_DIR}/config"
BACKUP_DIR="/root/edgebox-backup"
LOG_FILE="/var/log/edgebox-install.log"

# 服务器信息
SERVER_IP=""
SERVER_DOMAIN=""
INSTALL_MODE="ip" # 默认IP模式

# UUID生成
UUID_VLESS=$(uuidgen)
UUID_HYSTERIA2=$(uuidgen)
UUID_TUIC=$(uuidgen)

# Reality密钥
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""

# 密码生成
PASSWORD_HYSTERIA2=$(openssl rand -base64 16)
PASSWORD_TUIC=$(openssl rand -base64 16)

# 端口配置
PORT_REALITY=443
PORT_HYSTERIA2=443
PORT_TUIC=2053
PORT_NGINX_STREAM=10443
PORT_GRPC=10085
PORT_WS=10086

#############################################
# 工具函数
#############################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a ${LOG_FILE}
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a ${LOG_FILE}
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a ${LOG_FILE}
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a ${LOG_FILE}
}

print_separator() {
    echo -e "${BLUE}========================================${NC}"
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以root权限运行"
        exit 1
    fi
}

# 检查系统
check_system() {
    log_info "检查系统兼容性..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "无法确定操作系统类型"
        exit 1
    fi
    
    if [[ "$OS" == "ubuntu" && $(echo "$VERSION >= 18.04" | bc -l) -eq 1 ]] || \
       [[ "$OS" == "debian" && $(echo "$VERSION >= 10" | bc -l) -eq 1 ]]; then
        log_success "系统检查通过: $OS $VERSION"
    else
        log_error "不支持的系统: $OS $VERSION"
        exit 1
    fi
}

# 获取服务器IP
get_server_ip() {
    log_info "获取服务器公网IP..."
    
    # 尝试多个服务获取IP
    IP_SERVICES=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ipecho.net/plain"
        "https://api.ip.sb/ip"
    )
    
    for service in "${IP_SERVICES[@]}"; do
        SERVER_IP=$(curl -s --max-time 5 $service | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1)
        if [[ -n "$SERVER_IP" ]]; then
            log_success "获取到服务器IP: $SERVER_IP"
            return 0
        fi
    done
    
    log_error "无法获取服务器公网IP"
    exit 1
}

# 检查并安装依赖
install_dependencies() {
    log_info "安装必要依赖..."
    
    apt-get update
    
    PACKAGES="curl wget unzip tar nginx certbot python3-certbot-nginx vnstat iftop net-tools uuid-runtime openssl bc jq"
    
    for pkg in $PACKAGES; do
        if ! dpkg -l | grep -q "^ii.*$pkg"; then
            log_info "安装 $pkg..."
            apt-get install -y $pkg
        else
            log_info "$pkg 已安装"
        fi
    done
    
    # 启用vnstat
    systemctl enable vnstat
    systemctl start vnstat
}

# 创建目录结构
create_directories() {
    log_info "创建目录结构..."
    
    mkdir -p ${INSTALL_DIR}/{cert,config,templates,scripts}
    mkdir -p ${BACKUP_DIR}
    mkdir -p /var/log/edgebox
    
    log_success "目录结构创建完成"
}

# 检查端口占用
check_ports() {
    log_info "检查端口占用情况..."
    
    local ports=(443 10085 10086 10443 2053)
    local occupied=false
    
    for port in "${ports[@]}"; do
        if ss -tuln | grep -q ":${port} "; then
            log_warn "端口 $port 已被占用"
            occupied=true
        fi
    done
    
    if [[ "$occupied" == true ]]; then
        log_warn "某些端口已被占用，可能需要调整配置"
        # 不退出，继续安装，让nginx等服务自行处理
    else
        log_success "所有端口检查通过"
    fi
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙规则..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 443/tcp comment 'EdgeBox TCP'
        ufw allow 443/udp comment 'EdgeBox Hysteria2'
        ufw allow 2053/udp comment 'EdgeBox TUIC'
        ufw allow 22/tcp comment 'SSH'
        
        # 确保内部端口不对外开放
        ufw deny 10085/tcp
        ufw deny 10086/tcp
        ufw deny 10443/tcp
        
        ufw --force enable
        log_success "UFW防火墙规则配置完成"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=443/udp
        firewall-cmd --permanent --add-port=2053/udp
        firewall-cmd --reload
        log_success "Firewalld防火墙规则配置完成"
    else
        log_warn "未检测到防火墙软件，请手动配置"
    fi
}

# 优化系统参数
optimize_system() {
    log_info "优化系统参数..."
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d)
    
    cat >> /etc/sysctl.conf << EOF

# EdgeBox Optimizations
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65000
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
EOF
    
    sysctl -p
    log_success "系统参数优化完成"
}

# 生成自签名证书
generate_self_signed_cert() {
    log_info "生成自签名证书..."
    
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) \
        -keyout ${CERT_DIR}/self-signed.key \
        -out ${CERT_DIR}/self-signed.pem \
        -days 3650 \
        -subj "/C=US/ST=California/L=San Francisco/O=EdgeBox/CN=${SERVER_IP}"
    
    # 创建软链接
    ln -sf ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
    ln -sf ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
    
    log_success "自签名证书生成完成"
}

# 生成Reality密钥对
generate_reality_keys() {
    log_info "生成Reality密钥对..."
    
    # 下载最新的xray来生成密钥
    local temp_dir=$(mktemp -d)
    cd $temp_dir
    
    wget -q https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
    unzip -q Xray-linux-64.zip
    
    # 生成密钥对
    local keys=$(./xray x25519)
    REALITY_PRIVATE_KEY=$(echo "$keys" | grep "Private key:" | cut -d' ' -f3)
    REALITY_PUBLIC_KEY=$(echo "$keys" | grep "Public key:" | cut -d' ' -f3)
    
    cd - > /dev/null
    rm -rf $temp_dir
    
    log_success "Reality密钥对生成完成"
}

# 安装Xray
install_xray() {
    log_info "安装Xray..."
    
    # 下载并安装Xray
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
    
    # 停止默认服务
    systemctl stop xray
    
    log_success "Xray安装完成"
}

# 安装sing-box
install_sing_box() {
    log_info "安装sing-box..."
    
    # 获取最新版本
    local latest_version=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')
    
    # 下载二进制文件
    wget -q "https://github.com/SagerNet/sing-box/releases/download/v${latest_version}/sing-box-${latest_version}-linux-amd64.tar.gz"
    tar -xzf "sing-box-${latest_version}-linux-amd64.tar.gz"
    
    # 安装二进制文件
    cp "sing-box-${latest_version}-linux-amd64/sing-box" /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # 清理
    rm -rf sing-box-*
    
    # 创建systemd服务文件
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c ${CONFIG_DIR}/sing-box.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_success "sing-box安装完成"
}

# 配置Nginx
configure_nginx() {
    log_info "配置Nginx..."
    
    # 备份原始配置
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%Y%m%d)
    
    # 创建stream配置
    cat > /etc/nginx/modules-enabled/stream.conf << 'EOF'
stream {
    map $ssl_preread_alpn_protocols $backend {
        ~\bh2\b         127.0.0.1:10085;  # gRPC
        default         127.0.0.1:10086;  # WebSocket
    }
    
    server {
        listen 127.0.0.1:10443;
        ssl_preread on;
        proxy_pass $backend;
        proxy_protocol off;
    }
}
EOF
    
    # 修改主配置文件，添加stream模块
    if ! grep -q "load_module.*ngx_stream_module.so" /etc/nginx/nginx.conf; then
        sed -i '1i load_module /usr/lib/nginx/modules/ngx_stream_module.so;' /etc/nginx/nginx.conf
    fi
    
    # 在events块后添加include
    if ! grep -q "include.*modules-enabled/stream.conf" /etc/nginx/nginx.conf; then
        sed -i '/^events {/,/^}/a\\ninclude /etc/nginx/modules-enabled/stream.conf;' /etc/nginx/nginx.conf
    fi
    
    # 测试配置
    nginx -t
    
    log_success "Nginx配置完成"
}

# 配置Xray
configure_xray() {
    log_info "配置Xray..."
    
    cat > ${CONFIG_DIR}/xray.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "VLESS-Reality",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS}",
            "flow": "xtls-rprx-vision",
            "email": "reality@edgebox"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": "127.0.0.1:10443",
            "xver": 0
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.cloudflare.com:443",
          "xver": 0,
          "serverNames": [
            "www.cloudflare.com",
            "www.microsoft.com",
            "www.apple.com"
          ],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": [
            "",
            "6ba85179e30d4fc2"
          ]
        }
      }
    },
    {
      "tag": "VLESS-gRPC",
      "port": 10085,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS}",
            "email": "grpc@edgebox"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "${CERT_DIR}/current.pem",
              "keyFile": "${CERT_DIR}/current.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "grpc"
        }
      }
    },
    {
      "tag": "VLESS-WS",
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS}",
            "email": "ws@edgebox"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "${CERT_DIR}/current.pem",
              "keyFile": "${CERT_DIR}/current.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/ws",
          "headers": {}
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ],
  "routing": {
    "rules": []
  }
}
EOF
    
    log_success "Xray配置完成"
}

# 配置sing-box
configure_sing_box() {
    log_info "配置sing-box..."
    
    cat > ${CONFIG_DIR}/sing-box.json << EOF
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "name": "user",
          "password": "${PASSWORD_HYSTERIA2}"
        }
      ],
      "masquerade": "https://www.cloudflare.com",
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/current.pem",
        "key_path": "${CERT_DIR}/current.key"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": 2053,
      "users": [
        {
          "name": "user",
          "uuid": "${UUID_TUIC}",
          "password": "${PASSWORD_TUIC}"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/current.pem",
        "key_path": "${CERT_DIR}/current.key"
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
    
    log_success "sing-box配置完成"
}

# 保存配置信息
save_config_info() {
    log_info "保存配置信息..."
    
    cat > ${CONFIG_DIR}/server.json << EOF
{
  "server_ip": "${SERVER_IP}",
  "install_mode": "${INSTALL_MODE}",
  "install_date": "$(date +%Y-%m-%d)",
  "uuid": {
    "vless": "${UUID_VLESS}",
    "hysteria2": "${UUID_HYSTERIA2}",
    "tuic": "${UUID_TUIC}"
  },
  "password": {
    "hysteria2": "${PASSWORD_HYSTERIA2}",
    "tuic": "${PASSWORD_TUIC}"
  },
  "reality": {
    "public_key": "${REALITY_PUBLIC_KEY}",
    "private_key": "${REALITY_PRIVATE_KEY}"
  },
  "ports": {
    "reality": ${PORT_REALITY},
    "hysteria2": ${PORT_HYSTERIA2},
    "tuic": ${PORT_TUIC},
    "grpc": ${PORT_GRPC},
    "ws": ${PORT_WS}
  }
}
EOF
    
    chmod 600 ${CONFIG_DIR}/server.json
    log_success "配置信息保存完成"
}

# 启动服务
start_services() {
    log_info "启动所有服务..."
    
    # 重启Nginx
    systemctl restart nginx
    systemctl enable nginx
    
    # 启动Xray
    systemctl restart xray
    systemctl enable xray
    
    # 启动sing-box
    systemctl restart sing-box
    systemctl enable sing-box
    
    # 等待服务启动
    sleep 3
    
    # 检查服务状态
    local all_running=true
    
    for service in nginx xray sing-box; do
        if systemctl is-active --quiet $service; then
            log_success "$service 运行正常"
        else
            log_error "$service 启动失败"
            all_running=false
        fi
    done
    
    if [[ "$all_running" == true ]]; then
        log_success "所有服务启动成功"
    else
        log_warn "部分服务启动失败，请检查日志"
    fi
}

# 生成订阅链接
generate_subscription() {
    log_info "生成订阅链接..."
    
    local sub_content=""
    
    # VLESS-Reality
    local reality_link="vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&pbk=${REALITY_PUBLIC_KEY}&type=tcp&headerType=none#EdgeBox-Reality"
    sub_content="${sub_content}${reality_link}\n"
    
    # VLESS-gRPC
    local grpc_link="vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=grpc.edgebox.local&type=grpc&serviceName=grpc&allowInsecure=1#EdgeBox-gRPC"
    sub_content="${sub_content}${grpc_link}\n"
    
    # VLESS-WS
    local ws_link="vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=www.edgebox.local&type=ws&path=/ws&allowInsecure=1#EdgeBox-WS"
    sub_content="${sub_content}${ws_link}\n"
    
    # Hysteria2
    local hysteria2_link="hysteria2://${PASSWORD_HYSTERIA2}@${SERVER_IP}:443?insecure=1#EdgeBox-Hysteria2"
    sub_content="${sub_content}${hysteria2_link}\n"
    
    # TUIC
    local tuic_link="tuic://${UUID_TUIC}:${PASSWORD_TUIC}@${SERVER_IP}:2053?congestion_control=bbr&alpn=h3&insecure=1#EdgeBox-TUIC"
    sub_content="${sub_content}${tuic_link}\n"
    
    # 保存订阅内容
    echo -e "$sub_content" > ${CONFIG_DIR}/subscription.txt
    
    # Base64编码
    local sub_base64=$(echo -e "$sub_content" | base64 -w 0)
    echo "$sub_base64" > ${CONFIG_DIR}/subscription.base64
    
    # 创建简单的HTTP服务配置
    cat > /etc/nginx/sites-available/edgebox-sub << EOF
server {
    listen 80;
    server_name _;
    
    location / {
        default_type text/plain;
        return 200 '${sub_base64}';
    }
    
    location /sub {
        default_type text/plain;
        return 200 '${sub_base64}';
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/edgebox-sub /etc/nginx/sites-enabled/
    systemctl reload nginx
    
    log_success "订阅链接生成完成"
}

# 创建edgeboxctl基础框架
create_edgeboxctl() {
    log_info "创建管理工具..."
    
    cat > /usr/local/bin/edgeboxctl << 'EOF'
#!/bin/bash

# EdgeBox Control Script
VERSION="1.0.0"
CONFIG_DIR="/etc/edgebox/config"

show_help() {
    echo "EdgeBox 管理工具 v${VERSION}"
    echo ""
    echo "用法: edgeboxctl [命令] [选项]"
    echo ""
    echo "命令:"
    echo "  sub             显示订阅链接"
    echo "  status          显示服务状态"
    echo "  restart         重启所有服务"
    echo "  show-config     显示当前配置"
    echo "  help            显示帮助信息"
}

show_sub() {
    echo "订阅链接："
    echo "http://$(cat ${CONFIG_DIR}/server.json | jq -r .server_ip)/sub"
    echo ""
    echo "节点链接："
    cat ${CONFIG_DIR}/subscription.txt
}

show_status() {
    echo "服务状态："
    for service in nginx xray sing-box; do
        if systemctl is-active --quiet $service; then
            echo "  $service: 运行中"
        else
            echo "  $service: 已停止"
        fi
    done
}

restart_services() {
    echo "重启所有服务..."
    systemctl restart nginx xray sing-box
    echo "完成"
}

show_config() {
    echo "当前配置："
    cat ${CONFIG_DIR}/server.json | jq .
}

case "$1" in
    sub)
        show_sub
        ;;
    status)
        show_status
        ;;
    restart)
        restart_services
        ;;
    show-config)
        show_config
        ;;
    help|*)
        show_help
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/edgeboxctl
    log_success "管理工具创建完成"
}

# 显示安装信息
show_installation_info() {
    print_separator
    echo -e "${GREEN}EdgeBox 安装完成！${NC}"
    print_separator
    
    echo -e "${CYAN}服务器信息：${NC}"
    echo -e "  IP地址: ${SERVER_IP}"
    echo -e "  模式: IP模式（自签名证书）"
    
    echo -e "\n${CYAN}协议信息：${NC}"
    echo -e "  ${PURPLE}VLESS-Reality${NC}"
    echo -e "    端口: 443"
    echo -e "    UUID: ${UUID_VLESS}"
    echo -e "    公钥: ${REALITY_PUBLIC_KEY}"
    
    echo -e "  ${PURPLE}VLESS-gRPC${NC}"
    echo -e "    端口: 443"
    echo -e "    UUID: ${UUID_VLESS}"
    echo -e "    SNI: grpc.edgebox.local"
    
    echo -e "  ${PURPLE}VLESS-WS${NC}"
    echo -e "    端口: 443"
    echo -e "    UUID: ${UUID_VLESS}"
    echo -e "    路径: /ws"
    
    echo -e "  ${PURPLE}Hysteria2${NC}"
    echo -e "    端口: 443 (UDP)"
    echo -e "    密码: ${PASSWORD_HYSTERIA2}"
    
    echo -e "  ${PURPLE}TUIC${NC}"
    echo -e "    端口: 2053 (UDP)"
    echo -e "    UUID: ${UUID_TUIC}"
    echo -e "    密码: ${PASSWORD_TUIC}"
    
    echo -e "\n${CYAN}订阅链接：${NC}"
    echo -e "  ${GREEN}http://${SERVER_IP}/sub${NC}"
    
    echo -e "\n${CYAN}管理命令：${NC}"
    echo -e "  edgeboxctl sub        # 查看订阅链接"
    echo -e "  edgeboxctl status     # 查看服务状态"
    echo -e "  edgeboxctl restart    # 重启所有服务"
    
    echo -e "\n${YELLOW}注意事项：${NC}"
    echo -e "  1. 当前为IP模式，使用自签名证书"
    echo -e "  2. 客户端需要开启'跳过证书验证'选项"
    echo -e "  3. 建议后续切换到域名模式以获得更好的安全性"
    
    print_separator
}

# 主安装流程
main() {
    clear
    print_separator
    echo -e "${GREEN}EdgeBox 安装脚本 v1.0.0${NC}"
    echo -e "${CYAN}开始非交互式IP模式安装...${NC}"
    print_separator
    
    # 创建日志文件
    mkdir -p $(dirname ${LOG_FILE})
    touch ${LOG_FILE}
    
    # 执行安装步骤
    check_root
    check_system
    get_server_ip
    install_dependencies
    create_directories
    check_ports
    configure_firewall
    optimize_system
    generate_self_signed_cert
    generate_reality_keys
    install_xray
    install_sing_box
    configure_nginx
    configure_xray
    configure_sing_box
    save_config_info
    start_services
    generate_subscription
    create_edgeboxctl
    
    # 显示安装信息
    show_installation_info
    
    log_success "EdgeBox安装完成！"
    log_info "安装日志: ${LOG_FILE}"
}

# 执行主函数
main "$@"
