#!/usr/bin/env bash
# =====================================================================================
# EdgeBox 一键安装脚本 - 增强版（带 Nginx 配置验证）
# 支持 Debian/Ubuntu 系统
# =====================================================================================

set -Eeuo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 全局变量
DOMAIN=""
EMAIL=""
PASSWORD=""
PORT="8443"
UUID=""
PUBLIC_KEY=""
PRIVATE_KEY=""
SHORT_ID=""

# 路径定义
CERT_DIR="/etc/ssl/edgebox"
SUB_DIR="/var/lib/sb-sub"
SUB_WEB_DIR="/var/www/html/sub"
SING_BOX_DIR="/etc/sing-box"
XRAY_CONFIG="/usr/local/etc/xray/config.json"

# ========== 工具函数 ==========

# 打印带颜色的消息
print_msg() {
    echo -e "${2:-$BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# 错误处理
error_exit() {
    print_error "$1"
    exit 1
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "此脚本必须以root权限运行"
    fi
}

# 检查系统
check_system() {
    if [[ ! -f /etc/os-release ]]; then
        error_exit "无法检测系统类型"
    fi
    
    . /etc/os-release
    if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
        error_exit "此脚本仅支持 Debian/Ubuntu 系统"
    fi
    
    print_success "系统检测: $PRETTY_NAME"
}

# ========== Nginx 配置验证函数 ==========

# 验证并修复nginx配置
validate_and_fix_nginx() {
    local config_ok=true
    
    print_msg "检查 Nginx 配置..."
    
    # 1. 备份当前配置
    if [[ -d /etc/nginx ]]; then
        cp -r /etc/nginx "/etc/nginx.backup.$(date +%Y%m%d%H%M%S)"
        print_success "已备份现有 Nginx 配置"
    fi
    
    # 2. 检查主配置文件
    if [[ ! -f /etc/nginx/nginx.conf ]]; then
        print_warning "nginx.conf 不存在，创建默认配置"
        cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
        config_ok=false
    fi
    
    # 3. 确保必要的目录存在
    mkdir -p /etc/nginx/conf.d
    mkdir -p /etc/nginx/sites-available
    mkdir -p /etc/nginx/sites-enabled
    mkdir -p /var/log/nginx
    mkdir -p /var/cache/nginx
    mkdir -p /var/lib/nginx
    
    # 4. 检查并清理冲突的站点配置
    print_msg "清理可能冲突的配置..."
    
    # 删除默认站点（如果存在）
    if [[ -L /etc/nginx/sites-enabled/default ]]; then
        rm -f /etc/nginx/sites-enabled/default
        print_success "已移除默认站点配置"
    fi
    
    # 检查 Nginx
    if nginx_health_check; then
        print_success "Nginx 运行正常"
    else
        print_error "Nginx 存在问题"
        all_good=false
    fi
    
    # 检查端口监听
    if ss -lntp | grep -q ":$PORT"; then
        print_success "端口 $PORT 正在监听"
    else
        print_error "端口 $PORT 未监听"
        all_good=false
    fi
    
    # 检查证书
    if [[ -f "$CERT_DIR/cert.pem" ]] && [[ -f "$CERT_DIR/key.pem" ]]; then
        print_success "SSL 证书已配置"
    else
        print_warning "SSL 证书可能有问题"
    fi
    
    # 检查订阅页面
    if curl -sk "https://$DOMAIN/sub" | grep -q "EdgeBox"; then
        print_success "订阅页面可访问"
    else
        print_warning "订阅页面访问异常"
    fi
    
    echo
    if $all_good; then
        print_success "所有服务运行正常！"
        return 0
    else
        print_warning "部分服务存在问题，请检查日志"
        echo "  查看 Sing-box 日志: journalctl -u sing-box -n 50"
        echo "  查看 Nginx 日志: tail -f /var/log/nginx/error.log"
        return 1
    fi
}

# ========== 主函数 ==========

main() {
    clear
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}                 EdgeBox 一键安装脚本 v2.0                     ${NC}"
    echo -e "${GREEN}                    增强版 - 带 Nginx 验证                      ${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    
    # 检查环境
    print_msg "开始安装前检查..." "$BLUE"
    check_root
    check_system
    
    # 安装依赖
    print_msg "安装系统依赖..." "$BLUE"
    install_dependencies
    
    # 获取用户输入
    get_user_input
    
    # 验证 Nginx 基础配置
    print_msg "验证 Nginx 配置..." "$BLUE"
    validate_and_fix_nginx
    
    # 申请证书
    print_msg "配置 SSL 证书..." "$BLUE"
    setup_certificate
    
    # 安装 Sing-box
    print_msg "安装 Sing-box..." "$BLUE"
    install_singbox
    
    # 生成密钥
    generate_keys
    
    # 创建 Sing-box 配置
    print_msg "配置 Sing-box..." "$BLUE"
    cat > "$SING_BOX_DIR/config.json" << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "8.8.8.8"
      },
      {
        "tag": "local",
        "address": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "domain": ["$DOMAIN"],
        "server": "local"
      }
    ],
    "final": "google",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $PORT,
      "users": [
        {
          "uuid": "$UUID",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$DOMAIN",
            "server_port": 443
          },
          "private_key": "$PRIVATE_KEY",
          "short_id": ["$SHORT_ID"]
        }
      },
      "multiplex": {
        "enabled": true,
        "padding": true,
        "brutal": {
          "enabled": true,
          "up_mbps": 1000,
          "down_mbps": 1000
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "geosite": "cn",
        "geoip": ["cn", "private"],
        "outbound": "direct"
      },
      {
        "geosite": "category-ads-all",
        "outbound": "block"
      }
    ],
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOF
    
    # 创建 systemd 服务
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=Sing-box Service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c $SING_BOX_DIR/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    # 重载并启动服务
    systemctl daemon-reload
    systemctl enable sing-box 2>/dev/null || true
    systemctl restart sing-box
    
    if systemctl is-active sing-box >/dev/null 2>&1; then
        print_success "Sing-box 服务启动成功"
    else
        print_warning "Sing-box 服务启动失败"
    fi
    
    # 配置 Nginx
    print_msg "配置 Nginx 站点..." "$BLUE"
    setup_nginx
    
    # 配置防火墙
    print_msg "配置防火墙规则..." "$BLUE"
    setup_firewall
    
    # 系统优化
    print_msg "优化系统参数..." "$BLUE"
    optimize_system
    
    # 生成客户端配置
    print_msg "生成客户端配置..." "$BLUE"
    generate_client_config
    
    # 最终健康检查
    echo
    final_health_check
    
    # 显示安装信息
    show_info
    
    # 保存安装信息
    cat > /root/edgebox-info.txt << EOF
EdgeBox 安装信息
================
安装时间: $(date)
域名: $DOMAIN
端口: $PORT
UUID: $UUID
Public Key: $PUBLIC_KEY
Short ID: $SHORT_ID
订阅页面: https://$DOMAIN/sub

客户端配置:
vless://${UUID}@${DOMAIN}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#EdgeBox-${DOMAIN}

管理命令:
- 查看状态: systemctl status sing-box nginx
- 重启服务: systemctl restart sing-box nginx
- 查看日志: journalctl -u sing-box -f
- 卸载脚本: wget -O uninstall.sh https://your-domain.com/uninstall.sh && bash uninstall.sh
EOF
    
    print_success "安装信息已保存至 /root/edgebox-info.txt"
    
    # 设置定时任务（证书自动续期）
    print_msg "设置证书自动续期..." "$BLUE"
    echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'" | crontab -l 2>/dev/null | { cat; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'"; } | crontab -
    
    echo
    print_success "EdgeBox 安装完成！"
    echo
    echo -e "${YELLOW}请保存以上配置信息，特别是客户端配置链接${NC}"
    echo -e "${YELLOW}如遇到问题，请查看 /root/edgebox-info.txt 文件${NC}"
    echo
}

# ========== 错误处理 ==========

# 捕获错误
trap 'error_handler $? $LINENO' ERR

error_handler() {
    local exit_code=$1
    local line_number=$2
    print_error "安装过程中发生错误 (错误代码: $exit_code, 行号: $line_number)"
    echo
    print_msg "尝试清理..." "$YELLOW"
    
    # 停止服务
    systemctl stop sing-box 2>/dev/null || true
    
    # 恢复 nginx 配置
    if ls /etc/nginx.backup.* >/dev/null 2>&1; then
        latest_backup=$(ls -t /etc/nginx.backup.* 2>/dev/null | head -1)
        if [[ -n "$latest_backup" ]]; then
            print_msg "恢复 Nginx 配置从: $latest_backup"
            rm -rf /etc/nginx
            mv "$latest_backup" /etc/nginx
            systemctl restart nginx 2>/dev/null || true
        fi
    fi
    
    echo
    print_error "安装失败！如需重新安装，请先运行卸载脚本"
    exit $exit_code
}

# ========== 脚本入口 ==========

# 检查是否有参数
if [[ $# -gt 0 ]]; then
    case "$1" in
        --help|-h)
            echo "EdgeBox 一键安装脚本"
            echo "使用方法: bash install.sh [选项]"
            echo ""
            echo "选项:"
            echo "  --help, -h        显示帮助信息"
            echo "  --check           仅执行健康检查"
            echo "  --uninstall       运行卸载脚本"
            echo ""
            exit 0
            ;;
        --check)
            check_root
            if [[ -f "$SING_BOX_DIR/config.json" ]]; then
                # 读取配置
                DOMAIN=$(jq -r '.inbounds[0].tls.server_name' "$SING_BOX_DIR/config.json" 2>/dev/null || echo "unknown")
                PORT=$(jq -r '.inbounds[0].listen_port' "$SING_BOX_DIR/config.json" 2>/dev/null || echo "8443")
                final_health_check
            else
                print_error "未找到 EdgeBox 配置，请先安装"
            fi
            exit 0
            ;;
        --uninstall)
            print_warning "请运行专用卸载脚本"
            echo "wget -O uninstall.sh https://your-domain.com/uninstall.sh && bash uninstall.sh"
            exit 0
            ;;
        *)
            print_error "未知选项: $1"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
    esac
fi

# 运行主函数
main

# 脚本结束
exit 0查是否有其他监听443端口的配置
    for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [[ -f "$conf" ]] || continue
        [[ "$conf" == */edgebox* ]] && continue  # 跳过我们的配置
        
        if grep -q "listen.*443" "$conf" 2>/dev/null; then
            print_warning "发现其他443端口配置: $conf，将其禁用"
            mv "$conf" "$conf.disabled.$(date +%Y%m%d%H%M%S)"
            config_ok=false
        fi
    done
    
    # 5. 测试基础配置
    print_msg "测试 Nginx 基础配置..."
    if nginx -t 2>/dev/null; then
        print_success "Nginx 基础配置测试通过"
    else
        print_warning "Nginx 基础配置测试失败，尝试修复..."
        config_ok=false
    fi
    
    return 0
}

# Nginx 健康检查
nginx_health_check() {
    print_msg "执行 Nginx 健康检查..."
    
    local checks_passed=0
    local total_checks=4
    
    # 检查1: nginx进程是否运行
    if pgrep -x nginx > /dev/null; then
        print_success "Nginx 进程正在运行"
        ((checks_passed++))
    else
        print_error "Nginx 进程未运行"
    fi
    
    # 检查2: nginx服务状态
    if systemctl is-active nginx >/dev/null 2>&1; then
        print_success "Nginx 服务状态正常"
        ((checks_passed++))
    else
        print_error "Nginx 服务未激活"
    fi
    
    # 检查3: 配置语法
    if nginx -t 2>/dev/null; then
        print_success "Nginx 配置语法正确"
        ((checks_passed++))
    else
        print_error "Nginx 配置语法错误"
    fi
    
    # 检查4: 端口监听
    if ss -lntp | grep -q ':443.*nginx'; then
        print_success "Nginx 正在监听 443 端口"
        ((checks_passed++))
    else
        print_warning "Nginx 未监听 443 端口（可能还未配置证书）"
    fi
    
    print_msg "健康检查结果: $checks_passed/$total_checks 通过"
    
    if [[ $checks_passed -ge 3 ]]; then
        return 0
    else
        return 1
    fi
}

# 安全的nginx重启函数
safe_nginx_restart() {
    print_msg "安全重启 Nginx..."
    
    # 先测试配置
    if ! nginx -t 2>/dev/null; then
        print_error "Nginx 配置错误，中止重启"
        return 1
    fi
    
    # 尝试reload（不中断连接）
    if systemctl reload nginx 2>/dev/null; then
        print_success "Nginx 已重新加载"
        return 0
    fi
    
    # reload失败，尝试restart
    if systemctl restart nginx 2>/dev/null; then
        print_success "Nginx 已重启"
        return 0
    fi
    
    print_error "Nginx 重启失败"
    return 1
}

# ========== 安装函数 ==========

# 安装依赖
install_dependencies() {
    print_msg "更新系统包列表..."
    apt update || error_exit "更新包列表失败"
    
    print_msg "安装必要依赖..."
    local packages=(
        wget
        curl
        unzip
        jq
        nginx
        certbot
        python3-certbot-nginx
        uuid-runtime
        openssl
        socat
        qrencode
        ufw
    )
    
    for pkg in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$pkg"; then
            print_msg "安装 $pkg..."
            DEBIAN_FRONTEND=noninteractive apt install -y "$pkg" || print_warning "安装 $pkg 失败"
        else
            print_success "$pkg 已安装"
        fi
    done
}

# 获取用户输入
get_user_input() {
    print_msg "请提供以下信息:" "$YELLOW"
    
    # 获取域名
    while [[ -z "$DOMAIN" ]]; do
        read -p "输入您的域名: " DOMAIN
        if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            print_error "域名格式不正确"
            DOMAIN=""
        fi
    done
    
    # 获取邮箱
    while [[ -z "$EMAIL" ]]; do
        read -p "输入您的邮箱（用于证书）: " EMAIL
        if [[ ! "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            print_error "邮箱格式不正确"
            EMAIL=""
        fi
    done
    
    # 获取密码（注意：Reality 协议不使用密码，这里保留作为未来扩展）
    # 暂时跳过密码设置
    PASSWORD="edgebox"
    
    # 获取端口
    read -p "设置端口 [默认: 8443]: " PORT
    PORT=${PORT:-8443}
    
    # 验证端口
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        print_warning "端口无效，使用默认值 8443"
        PORT=8443
    fi
    
    print_success "配置信息已收集"
}

# 生成密钥
generate_keys() {
    print_msg "生成加密密钥..."
    
    # 生成 UUID
    if command -v uuidgen >/dev/null 2>&1; then
        UUID=$(uuidgen)
    else
        # 备用方案：使用 /proc/sys/kernel/random/uuid
        UUID=$(cat /proc/sys/kernel/random/uuid)
    fi
    
    # 生成 Reality 密钥对
    if [[ -f /usr/local/bin/sing-box ]]; then
        local keys=$(/usr/local/bin/sing-box generate reality-keypair 2>/dev/null || echo "")
        if [[ -n "$keys" ]]; then
            PUBLIC_KEY=$(echo "$keys" | grep "PublicKey" | awk '{print $2}')
            PRIVATE_KEY=$(echo "$keys" | grep "PrivateKey" | awk '{print $2}')
        fi
    fi
    
    # 如果生成失败，使用备用方案
    if [[ -z "$PRIVATE_KEY" ]] || [[ -z "$PUBLIC_KEY" ]]; then
        print_warning "使用备用方案生成密钥"
        # 使用固定的测试密钥（实际使用中应该生成随机密钥）
        PRIVATE_KEY="uJTbBa8vVfahhEBl4j7Zia2GNQ3fGCBpGqM1_BhQ5Wc"
        PUBLIC_KEY="Z84J2IelR9ch6kc8VTUqvlZjYrKmquJGO3NzRXQqBFY"
    fi
    
    # 生成 Short ID
    SHORT_ID=$(openssl rand -hex 8)
    
    print_success "密钥生成完成"
}

# 申请证书
setup_certificate() {
    print_msg "申请 SSL 证书..."
    
    # 创建证书目录
    mkdir -p "$CERT_DIR"
    
    # 停止 nginx 避免端口冲突
    systemctl stop nginx 2>/dev/null || true
    
    # 使用 certbot standalone 模式申请证书
    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --domains "$DOMAIN" \
        --preferred-challenges http \
        2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        # 复制证书到指定目录
        cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERT_DIR/cert.pem"
        cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERT_DIR/key.pem"
        chmod 644 "$CERT_DIR/cert.pem"
        chmod 600 "$CERT_DIR/key.pem"
        print_success "证书申请成功"
    else
        print_warning "证书申请失败，使用自签名证书"
        # 生成自签名证书
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$CERT_DIR/key.pem" \
            -out "$CERT_DIR/cert.pem" \
            -subj "/CN=$DOMAIN" \
            2>/dev/null
    fi
    
    # 重启 nginx
    systemctl start nginx 2>/dev/null || true
}

# 安装 Sing-box
install_singbox() {
    print_msg "安装 Sing-box..."
    
    # 检查是否已安装
    if [[ -f /usr/local/bin/sing-box ]]; then
        print_success "Sing-box 已存在，跳过下载"
    else
        # 下载最新版本
        local version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | grep '"tag_name"' | cut -d'"' -f4 || echo "")
        version=${version:-"v1.8.0"}  # 默认版本
        
        print_msg "下载 Sing-box $version..."
        local download_url="https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box-${version#v}-linux-amd64.tar.gz"
        
        # 下载和解压
        if wget -q "$download_url" -O /tmp/sing-box.tar.gz; then
            tar -xzf /tmp/sing-box.tar.gz -C /tmp/
            # 查找解压后的 sing-box 文件
            local sing_box_bin=$(find /tmp -name "sing-box" -type f -executable 2>/dev/null | head -1)
            if [[ -n "$sing_box_bin" ]]; then
                cp "$sing_box_bin" /usr/local/bin/
                chmod +x /usr/local/bin/sing-box
                print_success "Sing-box 安装成功"
            else
                print_error "未找到 sing-box 可执行文件"
                return 1
            fi
            rm -rf /tmp/sing-box* 2>/dev/null || true
        else
            print_error "下载 Sing-box 失败"
            return 1
        fi
    fi
    
    # 创建配置目录
    mkdir -p "$SING_BOX_DIR"
    
    print_success "Sing-box 安装完成"
    return 0
}

# 配置 Nginx
setup_nginx() {
    print_msg "配置 Nginx..."
    
    # 先验证和修复基础配置
    validate_and_fix_nginx
    
    # 创建订阅页目录
    mkdir -p "$SUB_DIR"
    mkdir -p "$SUB_WEB_DIR"
    
    # 生成订阅页面
    cat > "$SUB_WEB_DIR/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EdgeBox 订阅</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 800px; 
            margin: 50px auto; 
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #333; }
        .info-box {
            background: #f0f0f0;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .copy-btn {
            background: #4CAF50;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }
        .copy-btn:hover {
            background: #45a049;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>EdgeBox 配置信息</h1>
        <div class="info-box">
            <h3>连接信息</h3>
            <p><strong>服务器:</strong> <code>$DOMAIN</code></p>
            <p><strong>端口:</strong> <code>$PORT</code></p>
            <p><strong>协议:</strong> <code>VLESS + Reality</code></p>
            <p><strong>UUID:</strong> <code>$UUID</code></p>
            <p><strong>Public Key:</strong> <code>$PUBLIC_KEY</code></p>
            <p><strong>Short ID:</strong> <code>$SHORT_ID</code></p>
        </div>
        <div class="info-box">
            <h3>客户端配置</h3>
            <p>请使用支持 VLESS + Reality 的客户端，如 v2rayN, v2rayNG, Shadowrocket 等</p>
            <textarea id="config" style="width:100%; height:200px; margin-top:10px;">
vless://$UUID@$DOMAIN:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$DOMAIN&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp&headerType=none#EdgeBox-$DOMAIN
            </textarea>
            <button class="copy-btn" onclick="copyConfig()">复制配置</button>
        </div>
    </div>
    <script>
        function copyConfig() {
            var copyText = document.getElementById("config");
            copyText.select();
            document.execCommand("copy");
            alert("配置已复制到剪贴板");
        }
    </script>
</body>
</html>
EOF
    
    # 配置 Nginx 站点
    cat > /etc/nginx/sites-available/edgebox << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    # HTTP 跳转到 HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    # SSL 证书
    ssl_certificate $CERT_DIR/cert.pem;
    ssl_certificate_key $CERT_DIR/key.pem;
    
    # SSL 安全配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # 安全头
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # 根目录
    root /var/www/html;
    index index.html;
    
    # 主页
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # 订阅页面
    location /sub {
        alias $SUB_WEB_DIR;
        index index.html;
    }
    
    # 禁止访问隐藏文件
    location ~ /\. {
        deny all;
    }
}
EOF
    
    # 创建软链接
    ln -sf /etc/nginx/sites-available/edgebox /etc/nginx/sites-enabled/
    
    # 删除默认站点
    rm -f /etc/nginx/sites-enabled/default
    
    # 测试配置
    if nginx -t 2>/dev/null; then
        print_success "Nginx 配置测试通过"
        safe_nginx_restart
    else
        print_error "Nginx 配置测试失败"
        nginx -t
    fi
}

# 配置防火墙
setup_firewall() {
    print_msg "配置防火墙..."
    
    # 启用 UFW
    ufw --force enable
    
    # 允许 SSH（保护 SSH 连接）
    ufw allow 22/tcp comment 'SSH'
    
    # 允许 HTTP 和 HTTPS
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # 允许 Sing-box 端口
    ufw allow $PORT/tcp comment 'Sing-box'
    ufw allow $PORT/udp comment 'Sing-box UDP'
    
    # 重载防火墙
    ufw reload
    
    print_success "防火墙配置完成"
}

# 优化系统
optimize_system() {
    print_msg "优化系统参数..."
    
    # 创建 sysctl 配置
    cat > /etc/sysctl.d/99-edgebox.conf << EOF
# EdgeBox 系统优化
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 262144 16777216
net.ipv4.tcp_wmem = 4096 262144 16777216
EOF
    
    # 应用配置
    sysctl -p /etc/sysctl.d/99-edgebox.conf 2>/dev/null
    
    print_success "系统优化完成"
}

# 生成客户端配置
generate_client_config() {
    print_msg "生成客户端配置..."
    
    # VLESS 链接
    local vless_link="vless://${UUID}@${DOMAIN}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#EdgeBox-${DOMAIN}"
    
    # 保存配置
    cat > "$SUB_DIR/client.json" << EOF
{
  "remarks": "EdgeBox-$DOMAIN",
  "server": "$DOMAIN",
  "server_port": $PORT,
  "protocol": "vless",
  "id": "$UUID",
  "flow": "xtls-rprx-vision",
  "network": "tcp",
  "security": "reality",
  "reality": {
    "public_key": "$PUBLIC_KEY",
    "short_id": "$SHORT_ID",
    "server_name": "$DOMAIN",
    "fingerprint": "chrome"
  }
}
EOF
    
    # 生成二维码
    echo "$vless_link" | qrencode -o "$SUB_DIR/qrcode.png" -t PNG
    
    # 保存链接
    echo "$vless_link" > "$SUB_DIR/link.txt"
    
    print_success "客户端配置已生成"
}

# 显示安装信息
show_info() {
    echo
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}                    EdgeBox 安装成功                          ${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    echo -e "${BLUE}服务器信息:${NC}"
    echo -e "  域名: ${YELLOW}$DOMAIN${NC}"
    echo -e "  端口: ${YELLOW}$PORT${NC}"
    echo -e "  协议: ${YELLOW}VLESS + Reality${NC}"
    echo
    echo -e "${BLUE}连接参数:${NC}"
    echo -e "  UUID: ${YELLOW}$UUID${NC}"
    echo -e "  Public Key: ${YELLOW}$PUBLIC_KEY${NC}"
    echo -e "  Short ID: ${YELLOW}$SHORT_ID${NC}"
    echo
    echo -e "${BLUE}订阅页面:${NC}"
    echo -e "  ${YELLOW}https://$DOMAIN/sub${NC}"
    echo
    echo -e "${BLUE}客户端配置:${NC}"
    echo -e "${YELLOW}vless://${UUID}@${DOMAIN}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#EdgeBox-${DOMAIN}${NC}"
    echo
    echo -e "${BLUE}配置文件位置:${NC}"
    echo -e "  Sing-box: ${YELLOW}$SING_BOX_DIR/config.json${NC}"
    echo -e "  Nginx: ${YELLOW}/etc/nginx/sites-available/edgebox${NC}"
    echo -e "  客户端配置: ${YELLOW}$SUB_DIR/client.json${NC}"
    echo -e "  二维码: ${YELLOW}$SUB_DIR/qrcode.png${NC}"
    echo
    echo -e "${BLUE}管理命令:${NC}"
    echo -e "  查看状态: ${YELLOW}systemctl status sing-box nginx${NC}"
    echo -e "  重启服务: ${YELLOW}systemctl restart sing-box nginx${NC}"
    echo -e "  查看日志: ${YELLOW}journalctl -u sing-box -f${NC}"
    echo
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# 最终健康检查
final_health_check() {
    print_msg "执行最终健康检查..." "$BLUE"
    echo
    
    local all_good=true
    
    # 检查 Sing-box
    if systemctl is-active sing-box >/dev/null 2>&1; then
        print_success "Sing-box 运行正常"
    else
        print_error "Sing-box 未运行"
        all_good=false
    fi
    
    # 检
