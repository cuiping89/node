#!/bin/bash

# ========== Nginx 配置验证和修复函数 ==========
# 可以添加到您的安装脚本中，确保nginx配置正确

# 验证并修复nginx配置
validate_and_fix_nginx() {
    local config_ok=true
    
    echo "[*] 检查 Nginx 配置..."
    
    # 1. 备份当前配置
    if [[ -d /etc/nginx ]]; then
        cp -r /etc/nginx "/etc/nginx.backup.$(date +%Y%m%d%H%M%S)"
    fi
    
    # 2. 检查主配置文件
    if [[ ! -f /etc/nginx/nginx.conf ]]; then
        echo "[!] nginx.conf 不存在，尝试恢复默认配置"
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
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
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
    echo "[*] 清理可能冲突的配置..."
    
    # 删除默认站点（如果存在）
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    
    # 检查是否有其他监听443端口的配置
    for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [[ -f "$conf" ]] || continue
        [[ "$conf" == */edgebox* ]] && continue  # 跳过我们的配置
        
        if grep -q "listen.*443" "$conf" 2>/dev/null; then
            echo "[!] 发现其他443端口配置: $conf，将其禁用"
            mv "$conf" "$conf.disabled.$(date +%Y%m%d%H%M%S)"
            config_ok=false
        fi
    done
    
    # 5. 创建我们的nginx配置（如果不存在）
    if [[ ! -f /etc/nginx/sites-available/edgebox ]]; then
        echo "[*] 创建 EdgeBox nginx 配置..."
        cat > /etc/nginx/sites-available/edgebox << 'EOF'
server {
    listen 80;
    server_name _;
    
    # 强制跳转到 HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;
    
    # SSL 证书路径（安装时会更新）
    ssl_certificate /etc/ssl/edgebox/cert.pem;
    ssl_certificate_key /etc/ssl/edgebox/key.pem;
    
    # SSL 安全配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # 订阅页面位置
    location /sub {
        alias /var/www/html/sub;
        index index.html;
    }
    
    # 其他位置返回404
    location / {
        return 404;
    }
}
EOF
    fi
    
    # 6. 创建符号链接（如果不存在）
    if [[ ! -L /etc/nginx/sites-enabled/edgebox ]]; then
        ln -sf /etc/nginx/sites-available/edgebox /etc/nginx/sites-enabled/edgebox
    fi
    
    # 7. 测试配置
    echo "[*] 测试 Nginx 配置..."
    if nginx -t 2>/dev/null; then
        echo "[✓] Nginx 配置测试通过"
    else
        echo "[!] Nginx 配置测试失败，尝试修复..."
        
        # 临时移除我们的配置
        rm -f /etc/nginx/sites-enabled/edgebox
        
        # 再次测试基础配置
        if nginx -t 2>/dev/null; then
            echo "[*] 基础配置正常，问题在 EdgeBox 配置"
            # 这里可以尝试修复证书路径等问题
            config_ok=false
        else
            echo "[!] Nginx 基础配置有问题"
            config_ok=false
        fi
    fi
    
    # 8. 重载或重启nginx
    if $config_ok; then
        echo "[*] 重载 Nginx..."
        systemctl reload nginx 2>/dev/null || systemctl restart nginx
    else
        echo "[!] 配置有问题，尝试重启 Nginx..."
        systemctl restart nginx 2>/dev/null || {
            echo "[!] Nginx 重启失败"
            return 1
        }
    fi
    
    return 0
}

# 安装后的nginx健康检查
nginx_health_check() {
    echo "[*] 执行 Nginx 健康检查..."
    
    local checks_passed=0
    local total_checks=5
    
    # 检查1: nginx进程是否运行
    if pgrep -x nginx > /dev/null; then
        echo "  [✓] Nginx 进程正在运行"
        ((checks_passed++))
    else
        echo "  [✗] Nginx 进程未运行"
    fi
    
    # 检查2: nginx服务状态
    if systemctl is-active nginx >/dev/null 2>&1; then
        echo "  [✓] Nginx 服务状态正常"
        ((checks_passed++))
    else
        echo "  [✗] Nginx 服务未激活"
    fi
    
    # 检查3: 配置语法
    if nginx -t 2>/dev/null; then
        echo "  [✓] Nginx 配置语法正确"
        ((checks_passed++))
    else
        echo "  [✗] Nginx 配置语法错误"
    fi
    
    # 检查4: 端口监听
    if ss -lntp | grep -q ':443.*nginx'; then
        echo "  [✓] Nginx 正在监听 443 端口"
        ((checks_passed++))
    else
        echo "  [✗] Nginx 未监听 443 端口"
    fi
    
    # 检查5: 访问测试
    if curl -k https://localhost/sub -o /dev/null -s -w "%{http_code}" | grep -q "200\|301\|302"; then
        echo "  [✓] HTTPS 访问测试通过"
        ((checks_passed++))
    else
        echo "  [✗] HTTPS 访问测试失败"
    fi
    
    echo "[*] 健康检查结果: $checks_passed/$total_checks 通过"
    
    if [[ $checks_passed -eq $total_checks ]]; then
        return 0
    else
        return 1
    fi
}

# ========== 在安装脚本中使用示例 ==========
# 在您的安装脚本适当位置调用这些函数

# 1. 在配置nginx之前
validate_and_fix_nginx || {
    echo "[!] Nginx 配置验证失败，尝试继续..."
}

# 2. 在安装完成后
nginx_health_check || {
    echo "[!] Nginx 健康检查未完全通过，请检查日志"
    echo "    查看错误: journalctl -xeu nginx"
    echo "    查看日志: tail -f /var/log/nginx/error.log"
}

# ========== 安全的nginx重启函数 ==========
safe_nginx_restart() {
    echo "[*] 安全重启 Nginx..."
    
    # 先测试配置
    if ! nginx -t 2>/dev/null; then
        echo "[!] Nginx 配置错误，中止重启"
        return 1
    fi
    
    # 尝试reload（不中断连接）
    if systemctl reload nginx 2>/dev/null; then
        echo "[✓] Nginx 已重新加载"
        return 0
    fi
    
    # reload失败，尝试restart
    if systemctl restart nginx 2>/dev/null; then
        echo "[✓] Nginx 已重启"
        return 0
    fi
    
    echo "[!] Nginx 重启失败"
    return 1
}
