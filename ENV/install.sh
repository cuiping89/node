# 创建edgeboxctl管理工具（完整版，带验证）
create_edgeboxctl() {
    log_info "创建edgeboxctl管理工具..."
    
    cat > /usr/local/bin/edgeboxctl << 'EDGEBOXCTL_SCRIPT'
#!/bin/bash
# EdgeBox 控制脚本 v3.0.1
VERSION="3.0.1"
CONFIG_DIR="/etc/edgebox/config"
CERT_DIR="/etc/edgebox/cert"
INSTALL_DIR="/etc/edgebox"
LOG_FILE="/var/log/edgebox.log"
SHUNT_CONFIG="${CONFIG_DIR}/shunt/state.json"
BACKUP_DIR="/root/edgebox-backup"
TRAFFIC_DIR="/etc/edgebox/traffic"
SCRIPTS_DIR="/etc/edgebox/scripts"
WHITELIST_DOMAINS="googlevideo.com,ytimg.com,ggpht.com,youtube.com,youtu.be"

# 颜色定义
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; 
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# 日志函数
log_info(){ echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn(){ echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error(){ echo -e "${RED}[ERROR]${NC} $1"; }
log_success(){ echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# 获取服务器信息
get_server_info() {
    if [[ ! -f ${CONFIG_DIR}/server.json ]]; then
        log_error "配置文件不存在"
        return 1
    fi
    SERVER_IP=$(jq -r '.server_ip' ${CONFIG_DIR}/server.json 2>/dev/null)
    UUID_VLESS=$(jq -r '.uuid.vless' ${CONFIG_DIR}/server.json 2>/dev/null)
    UUID_TUIC=$(jq -r '.uuid.tuic' ${CONFIG_DIR}/server.json 2>/dev/null)
    PASSWORD_HYSTERIA2=$(jq -r '.password.hysteria2' ${CONFIG_DIR}/server.json 2>/dev/null)
    PASSWORD_TUIC=$(jq -r '.password.tuic' ${CONFIG_DIR}/server.json 2>/dev/null)
    REALITY_PUBLIC_KEY=$(jq -r '.reality.public_key' ${CONFIG_DIR}/server.json 2>/dev/null)
    REALITY_SHORT_ID=$(jq -r '.reality.short_id' ${CONFIG_DIR}/server.json 2>/dev/null)
}

# 显示订阅
show_sub() {
    echo -e "${CYAN}EdgeBox 订阅链接：${NC}\n"
    if [[ -f ${CONFIG_DIR}/subscription.txt ]]; then
        echo -e "${YELLOW}节点链接：${NC}"
        cat ${CONFIG_DIR}/subscription.txt
        echo ""
    fi
    if [[ -f ${CONFIG_DIR}/subscription.base64 ]]; then
        echo -e "${YELLOW}Base64订阅：${NC}"
        cat ${CONFIG_DIR}/subscription.base64
        echo ""
    fi
    local server_ip=$(jq -r '.server_ip' ${CONFIG_DIR}/server.json)
    echo -e "\n${CYAN}HTTP订阅地址：${NC} http://${server_ip}/sub"
    echo -e "${CYAN}控制面板：${NC} http://${server_ip}/"
}

# 显示状态
show_status() {
    echo -e "${CYAN}EdgeBox 服务状态：${NC}"
    for svc in nginx xray sing-box; do
        systemctl is-active --quiet "$svc" && echo -e "  $svc: ${GREEN}运行中${NC}" || echo -e "  $svc: ${RED}已停止${NC}"
    done
    
    echo -e "\n${CYAN}端口监听状态：${NC}"
    ss -tlnp 2>/dev/null | grep -q ":443 " && echo -e "  TCP/443: ${GREEN}正常${NC}" || echo -e "  TCP/443: ${RED}异常${NC}"
    ss -ulnp 2>/dev/null | grep -q ":443 " && echo -e "  UDP/443: ${GREEN}正常${NC}" || echo -e "  UDP/443: ${RED}异常${NC}"
    ss -ulnp 2>/dev/null | grep -q ":2053 " && echo -e "  UDP/2053: ${GREEN}正常${NC}" || echo -e "  UDP/2053: ${RED}异常${NC}"
    
    echo -e "\n${CYAN}分流状态：${NC}"
    if [[ -f "$SHUNT_CONFIG" ]]; then
        local mode=$(jq -r '.mode' "$SHUNT_CONFIG" 2>/dev/null || echo "vps")
        case "$mode" in
            vps) echo -e "  当前模式: ${GREEN}VPS全量出${NC}";;
            resi) echo -e "  当前模式: ${YELLOW}住宅IP全量出${NC}";;
            direct_resi) echo -e "  当前模式: ${BLUE}智能分流${NC}";;
        esac
    fi
}

# 重启服务
restart_services() {
    echo -e "${CYAN}重启EdgeBox服务...${NC}"
    for s in nginx xray sing-box; do
        echo -n "  重启 $s... "
        systemctl restart "$s" && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAIL${NC}"
    done
}

# 验证域名解析
validate_domain_resolution() {
    local domain=$1
    log_info "验证域名解析..."
    
    # 检查域名是否能解析
    if ! host "$domain" >/dev/null 2>&1; then
        log_error "域名无法解析: $domain"
        return 1
    fi
    
    # 获取解析的IP
    local resolved_ip=$(dig +short "$domain" 2>/dev/null | tail -n1)
    if [[ -z "$resolved_ip" ]]; then
        log_error "无法获取域名的IP地址"
        return 1
    fi
    
    # 验证解析的IP是否指向本机
    get_server_info
    if [[ "$resolved_ip" != "$SERVER_IP" ]]; then
        log_warn "域名解析IP ($resolved_ip) 与服务器IP ($SERVER_IP) 不匹配"
        echo -n "是否继续？这可能导致证书申请失败 [y/N]: "
        read -r answer
        if [[ ! "$answer" =~ ^[Yy]$ ]]; then
            return 1
        fi
    else
        log_success "域名解析验证通过"
    fi
    
    return 0
}

# 验证端口可达性
validate_port_accessibility() {
    log_info "验证端口可达性..."
    
    # 临时启动一个HTTP服务器用于验证
    python3 -m http.server 80 >/dev/null 2>&1 &
    local http_pid=$!
    sleep 2
    
    # 从外部验证80端口
    if curl -s --max-time 5 "http://${SERVER_IP}/" >/dev/null 2>&1; then
        log_success "80端口可达性验证通过"
        kill $http_pid 2>/dev/null
        return 0
    else
        log_error "80端口无法从外部访问，请检查防火墙设置"
        kill $http_pid 2>/dev/null
        return 1
    fi
}

# 验证证书状态
validate_certificate() {
    local domain=$1
    local cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
    
    if [[ ! -f "$cert_path" ]]; then
        log_warn "证书文件不存在"
        return 1
    fi
    
    # 检查证书有效期
    local expiry_date=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2)
    local expiry_timestamp=$(date -d "$expiry_date" +%s 2>/dev/null)
    local current_timestamp=$(date +%s)
    
    if [[ $expiry_timestamp -lt $current_timestamp ]]; then
        log_error "证书已过期"
        return 1
    fi
    
    local days_remaining=$(( ($expiry_timestamp - $current_timestamp) / 86400 ))
    if [[ $days_remaining -lt 7 ]]; then
        log_warn "证书将在 ${days_remaining} 天后过期"
    else
        log_success "证书有效，剩余 ${days_remaining} 天"
    fi
    
    return 0
}

# 验证服务配置
validate_service_configs() {
    log_info "验证服务配置..."
    
    # 验证Nginx配置
    if nginx -t >/dev/null 2>&1; then
        log_success "Nginx配置验证通过"
    else
        log_error "Nginx配置错误"
        return 1
    fi
    
    # 验证Xray配置
    if jq '.' ${CONFIG_DIR}/xray.json >/dev/null 2>&1; then
        log_success "Xray配置语法验证通过"
    else
        log_error "Xray配置JSON语法错误"
        return 1
    fi
    
    # 验证sing-box配置
    if jq '.' ${CONFIG_DIR}/sing-box.json >/dev/null 2>&1; then
        log_success "sing-box配置语法验证通过"
    else
        log_error "sing-box配置JSON语法错误"
        return 1
    fi
    
    return 0
}

# 切换到域名模式（带验证）
switch_to_domain() {
    local domain="$1"
    [[ -z "$domain" ]] && { echo "用法: edgeboxctl switch-to-domain <domain>"; return 1; }
    
    echo -e "${CYAN}========== 开始切换到域名模式 ==========${NC}"
    
    # 步骤1：验证域名解析
    echo -e "\n${YELLOW}[步骤 1/5] 验证域名解析${NC}"
    if ! validate_domain_resolution "$domain"; then
        log_error "域名解析验证失败，切换终止"
        return 1
    fi
    
    # 步骤2：验证端口可达性
    echo -e "\n${YELLOW}[步骤 2/5] 验证端口可达性${NC}"
    if ! validate_port_accessibility; then
        log_error "端口可达性验证失败，切换终止"
        return 1
    fi
    
    # 步骤3：申请证书
    echo -e "\n${YELLOW}[步骤 3/5] 申请Let's Encrypt证书${NC}"
    systemctl stop nginx >/dev/null 2>&1
    
    if certbot certonly --standalone --non-interactive --agree-tos \
        --email "admin@${domain}" --domains "$domain" \
        --preferred-challenges http --http-01-port 80; then
        log_success "证书申请成功"
    else
        log_error "证书申请失败"
        systemctl start nginx >/dev/null 2>&1
        return 1
    fi
    
    systemctl start nginx >/dev/null 2>&1
    
    # 验证证书
    if ! validate_certificate "$domain"; then
        log_error "证书验证失败"
        return 1
    fi
    
    # 步骤4：更新配置
    echo -e "\n${YELLOW}[步骤 4/5] 更新配置${NC}"
    get_server_info || return 1
    
    # 更新软链接
    ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem" ${CERT_DIR}/current.key
    ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" ${CERT_DIR}/current.pem
    echo "letsencrypt:${domain}" > ${CONFIG_DIR}/cert_mode
    log_success "证书配置已更新"
    
    # 重新生成订阅
    regenerate_subscription "$domain"
    log_success "订阅链接已更新"
    
    # 验证配置
    if ! validate_service_configs; then
        log_error "服务配置验证失败"
        return 1
    fi
    
    # 步骤5：重启服务
    echo -e "\n${YELLOW}[步骤 5/5] 重启服务${NC}"
    systemctl restart xray sing-box >/dev/null 2>&1
    
    # 验证服务状态
    sleep 2
    for svc in nginx xray sing-box; do
        if systemctl is-active --quiet "$svc"; then
            log_success "$svc 运行正常"
        else
            log_error "$svc 启动失败"
        fi
    done
    
    # 设置自动续期
    (crontab -l 2>/dev/null | grep -v "certbot renew"; echo "0 3 * * * certbot renew --quiet && systemctl restart xray sing-box") | crontab -
    log_success "自动续期任务已设置"
    
    echo -e "\n${GREEN}========== 切换完成 ==========${NC}"
    echo -e "域名: ${YELLOW}$domain${NC}"
    echo -e "控制面板: ${CYAN}http://$domain/${NC}"
    echo -e "订阅地址: ${CYAN}http://$domain/sub${NC}"
}

# 切换到IP模式（带验证）
switch_to_ip() {
    echo -e "${CYAN}========== 开始切换到IP模式 ==========${NC}"
    
    # 步骤1：验证自签名证书
    echo -e "\n${YELLOW}[步骤 1/4] 验证自签名证书${NC}"
    if [[ ! -f ${CERT_DIR}/self-signed.key || ! -f ${CERT_DIR}/self-signed.pem ]]; then
        log_warn "自签名证书不存在，重新生成..."
        
        openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) \
            -keyout ${CERT_DIR}/self-signed.key \
            -out ${CERT_DIR}/self-signed.pem \
            -days 3650 \
            -subj "/C=US/ST=California/L=San Francisco/O=EdgeBox/CN=${SERVER_IP}" >/dev/null 2>&1
        
        if [[ $? -eq 0 ]]; then
            log_success "自签名证书生成成功"
        else
            log_error "自签名证书生成失败"
            return 1
        fi
    else
        log_success "自签名证书存在"
    fi
    
    # 步骤2：更新配置
    echo -e "\n${YELLOW}[步骤 2/4] 更新配置${NC}"
    get_server_info || return 1
    
    ln -sf ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
    ln -sf ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
    echo "self-signed" > ${CONFIG_DIR}/cert_mode
    log_success "证书配置已更新"
    
    regenerate_subscription
    log_success "订阅链接已更新"
    
    # 步骤3：验证配置
    echo -e "\n${YELLOW}[步骤 3/4] 验证配置${NC}"
    if ! validate_service_configs; then
        log_error "服务配置验证失败"
        return 1
    fi
    
    # 步骤4：重启服务
    echo -e "\n${YELLOW}[步骤 4/4] 重启服务${NC}"
    systemctl restart xray sing-box >/dev/null 2>&1
    
    # 验证服务状态
    sleep 2
    for svc in nginx xray sing-box; do
        if systemctl is-active --quiet "$svc"; then
            log_success "$svc 运行正常"
        else
            log_error "$svc 启动失败"
        fi
    done
    
    echo -e "\n${GREEN}========== 切换完成 ==========${NC}"
    echo -e "模式: ${YELLOW}IP模式（自签名证书）${NC}"
    echo -e "控制面板: ${CYAN}http://${SERVER_IP}/${NC}"
    echo -e "订阅地址: ${CYAN}http://${SERVER_IP}/sub${NC}"
    echo -e "\n${YELLOW}注意：${NC}客户端需要开启'跳过证书验证'选项"
}

# 重新生成订阅
regenerate_subscription() {
    local domain="$1"
    get_server_info
    
    local HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
    local TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC" | jq -rR @uri)
    
    if [[ -n "$domain" ]]; then
        # 域名模式
        local sub="vless://${UUID_VLESS}@${domain}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY
vless://${UUID_VLESS}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=h2&type=grpc&serviceName=grpc&fp=chrome#EdgeBox-gRPC
vless://${UUID_VLESS}@${domain}:443?encryption=none&security=tls&sni=${domain}&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome#EdgeBox-WS
hysteria2://${HY2_PW_ENC}@${domain}:443?sni=${domain}&alpn=h3#EdgeBox-HYSTERIA2
tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${domain}:2053?congestion_control=bbr&alpn=h3&sni=${domain}#EdgeBox-TUIC"
    else
        # IP模式
        local sub="vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY
vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=grpc.edgebox.internal&alpn=h2&type=grpc&serviceName=grpc&fp=chrome&allowInsecure=1#EdgeBox-gRPC
vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=ws.edgebox.internal&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome&allowInsecure=1#EdgeBox-WS
hysteria2://${HY2_PW_ENC}@${SERVER_IP}:443?sni=${SERVER_IP}&alpn=h3&insecure=1#EdgeBox-HYSTERIA2
tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${SERVER_IP}:2053?congestion_control=bbr&alpn=h3&sni=${SERVER_IP}&allowInsecure=1#EdgeBox-TUIC"
    fi
    
    echo -e "${sub}" > "${CONFIG_DIR}/subscription.txt"
    echo -e "${sub}" | base64 -w0 > "${CONFIG_DIR}/subscription.base64"
    echo -e "${sub}" > "${TRAFFIC_DIR}/sub.txt"
}

# 流量统计
traffic_show() {
    echo -e "${CYAN}流量统计：${NC}"
    if command -v vnstat >/dev/null 2>&1; then
        local iface=$(ip route | awk '/default/{print $5; exit}')
        vnstat -i "$iface" --oneline 2>/dev/null | tail -1 | \
            awk -F';' '{print "  今日: "$4" ↑, "$5" ↓\n  本月: "$8" ↑, "$9" ↓"}'
    fi
    
    echo -e "\n${CYAN}端口流量：${NC}"
    if command -v nft >/dev/null 2>&1 && nft list table inet edgebox >/dev/null 2>&1; then
        local tcp443=$(nft list counter inet edgebox c_tcp443 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}' || echo "0")
        local udp443=$(nft list counter inet edgebox c_udp443 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}' || echo "0")
        local udp2053=$(nft list counter inet edgebox c_udp2053 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}' || echo "0")
        
        format_bytes() {
            local b=$1
            if (( b >= 1073741824 )); then
                echo "$(echo "scale=2; $b/1073741824" | bc)GB"
            elif (( b >= 1048576 )); then
                echo "$(echo "scale=2; $b/1048576" | bc)MB"
            else
                echo "${b}B"
            fi
        }
        
        echo "  TCP/443: $(format_bytes $tcp443)"
        echo "  UDP/443: $(format_bytes $udp443)"
        echo "  UDP/2053: $(format_bytes $udp2053)"
    fi
    
    echo -e "\n${CYAN}查看详细图表：${NC} http://$(jq -r .server_ip ${CONFIG_DIR}/server.json)/"
}

# 备份创建
backup_create() {
    local ts=$(date +%Y%m%d_%H%M%S)
    local file="${BACKUP_DIR}/edgebox_backup_${ts}.tar.gz"
    mkdir -p "${BACKUP_DIR}"
    
    log_info "创建备份..."
    tar -czf "$file" -C / \
        etc/edgebox \
        etc/nginx/nginx.conf \
        etc/systemd/system/xray.service \
        etc/systemd/system/sing-box.service \
        2>/dev/null
    
    if [[ -f "$file" ]]; then
        log_success "备份完成: $file"
        # 保留最近10个备份
        ls -t ${BACKUP_DIR}/e    <script>
        // 复制功能
        function copyToClipboard(element) {
            const text = element.textContent.replace(/\[.*?\]/, '').trim();
            navigator.clipboard.writeText(text).then(() => {
                showCopyHint();
            });
        }
        
        function copyCmd(element) {
            const text = element.textContent.replace(/&lt;/g, '<').replace(/&gt;/g, '>');
            navigator.clipboard.writeText(text).then(() => {
                showCopyHint();
            });
        }
        
        function showCopyHint() {
            const hint = document.getElementById('copyHint');
            hint.style.display = 'block';
            setTimeout(() => hint.style.display = 'none', 2000);
        }
        
        // 格式化字节
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // 加载流量数据并绘制图表
        async function loadTrafficData() {
            try {
                const response = await fetch('/api/traffic');
                const data = await response.json();
                
                // 绘制日分流曲线图
                drawShuntChart(data);
                
                // 绘制端口流量图
                drawPortsChart(data);
                
                // 更新月累计表格
                updateMonthlyTable(data);
                
            } catch (error) {
                console.error('加载流量数据失败:', error);
            }
        }
        
        // 绘制分流图表
        function drawShuntChart(data) {
            const ctx = document.getElementById('chart-shunt').getContext('2d');
            
            // 销毁旧图表
            if (window.shuntChart) {
                window.shuntChart.destroy();
            }
            
            window.shuntChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.daily ? data.daily.map(d => {
                        const time = d.time.split(' ')[1];
                        return time ? time.substring(0, 5) : '';
                    }) : [],
                    datasets: [{
                        label: 'VPS直出',
                        data: data.daily ? data.daily.map(d => d.vps_out / 1024 / 1024) : [],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4,
                        fill: true
                    }, {
                        label: '住宅IP',
                        data: data.daily ? data.daily.map(d => d.resi_out / 1024 / 1024) : [],
                        borderColor: '#764ba2',
                        backgroundColor: 'rgba(118, 75, 162, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { 
                            position: 'top',
                            labels: {#!/bin/bash

#############################################
# EdgeBox 企业级多协议节点部署脚本 - 轻量级优化版
# Version: 3.0.1 - 移除Python依赖，Chart.js前端渲染
# Description: vnStat + nftables采集 + Chart.js前端渲染 + 控制面板整合
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
TRAFFIC_DIR="${INSTALL_DIR}/traffic"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"
BACKUP_DIR="/root/edgebox-backup"
LOG_FILE="/var/log/edgebox-install.log"

# 服务器信息
SERVER_IP=""
SERVER_DOMAIN=""
INSTALL_MODE="ip" # 默认IP模式

# UUID生成
UUID_VLESS=""
UUID_HYSTERIA2=""
UUID_TUIC=""

# Reality密钥
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
REALITY_SHORT_ID=""

# 密码生成
PASSWORD_HYSTERIA2=""
PASSWORD_TUIC=""

# 端口配置（单端口复用架构）
PORT_REALITY=11443      # 内部回环 (Xray Reality)
PORT_HYSTERIA2=443    # UDP
PORT_TUIC=2053        # UDP
PORT_GRPC=10085       # 内部回环
PORT_WS=10086         # 内部回环

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
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "无法确定操作系统类型"
        exit 1
    fi
    
    SUPPORTED=false
    
    case "$OS" in
        ubuntu)
            MAJOR_VERSION=$(echo "$VERSION" | cut -d. -f1)
            if [ "$MAJOR_VERSION" -ge 18 ] 2>/dev/null; then
                SUPPORTED=true
            fi
            ;;
        debian)
            if [ "$VERSION" -ge 10 ] 2>/dev/null; then
                SUPPORTED=true
            fi
            ;;
        *)
            SUPPORTED=false
            ;;
    esac
    
    if [ "$SUPPORTED" = "true" ]; then
        log_success "系统检查通过: $OS $VERSION"
    else
        log_error "不支持的系统: $OS $VERSION"
        log_info "支持的系统: Ubuntu 18.04+, Debian 10+"
        exit 1
    fi
}

# 获取服务器IP
get_server_ip() {
    log_info "获取服务器公网IP..."
    
    IP_SERVICES=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ipecho.net/plain"
        "https://api.ip.sb/ip"
    )
    
    for service in "${IP_SERVICES[@]}"; do
        SERVER_IP=$(curl -s --max-time 5 $service 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1)
        if [[ -n "$SERVER_IP" ]]; then
            log_success "获取到服务器IP: $SERVER_IP"
            return 0
        fi
    done
    
    log_error "无法获取服务器公网IP"
    exit 1
}

# 安装依赖（移除Python包）
install_dependencies() {
    log_info "更新软件源..."
    apt-get update -qq
    
    log_info "安装必要依赖..."
    
    # 基础工具（移除Python绘图包）
    PACKAGES="curl wget unzip tar net-tools openssl jq uuid-runtime vnstat iftop certbot bc"
    
    # 添加Nginx和stream模块
    PACKAGES="$PACKAGES nginx libnginx-mod-stream"
    
    # nftables（用于分流统计）
    PACKAGES="$PACKAGES nftables"
    
    # 邮件发送工具
    PACKAGES="$PACKAGES msmtp msmtp-mta mailutils"
    
    for pkg in $PACKAGES; do
        if ! dpkg -l | grep -q "^ii.*$pkg"; then
            log_info "安装 $pkg..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg >/dev/null 2>&1 || {
                log_warn "$pkg 安装失败，尝试继续..."
            }
        else
            log_info "$pkg 已安装"
        fi
    done
    
    # 启用vnstat
    systemctl enable vnstat >/dev/null 2>&1
    systemctl start vnstat >/dev/null 2>&1
    
    log_success "依赖安装完成"
}

# 生成UUID和密码
generate_credentials() {
    log_info "生成UUID和密码..."
    
    UUID_VLESS=$(uuidgen)
    UUID_HYSTERIA2=$(uuidgen)
    UUID_TUIC=$(uuidgen)
    
    REALITY_SHORT_ID="$(openssl rand -hex 8)"
    PASSWORD_HYSTERIA2=$(openssl rand -base64 16)
    PASSWORD_TUIC=$(openssl rand -base64 16)
    
    log_success "凭证生成完成"
}

# 创建目录结构
create_directories() {
    log_info "创建完整目录结构..."
    
    mkdir -p ${INSTALL_DIR}/{cert,config,templates,scripts}
    mkdir -p ${TRAFFIC_DIR}/{logs,assets/js}
    mkdir -p ${CONFIG_DIR}/shunt
    mkdir -p ${BACKUP_DIR}
    mkdir -p /var/log/edgebox
    mkdir -p /var/log/xray
    mkdir -p /var/www/html
    
    log_success "目录结构创建完成"
}

# 检查端口占用
check_ports() {
    log_info "检查端口占用情况..."
    
    local ports=(443 2053 80)
    local occupied=false
    
    for port in "${ports[@]}"; do
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            log_warn "端口 $port 已被占用"
            occupied=true
        fi
    done
    
    if [[ "$occupied" == true ]]; then
        log_warn "某些端口已被占用，可能需要调整配置"
    else
        log_success "端口检查通过"
    fi
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙规则..."
    
    if command -v ufw &> /dev/null; then
        ufw --force disable >/dev/null 2>&1
        
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        
        ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1
        ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1
        ufw allow 443/tcp comment 'EdgeBox TCP' >/dev/null 2>&1
        ufw allow 443/udp comment 'EdgeBox Hysteria2' >/dev/null 2>&1
        ufw allow 2053/udp comment 'EdgeBox TUIC' >/dev/null 2>&1
        
        ufw --force enable >/dev/null 2>&1
        log_success "UFW防火墙规则配置完成"
    else
        log_warn "未检测到防火墙软件，请手动配置"
    fi
}

# 优化系统参数
optimize_system() {
    log_info "优化系统参数..."
    
    if [[ ! -f /etc/sysctl.conf.bak ]]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
    fi
    
    if grep -q "EdgeBox Optimizations" /etc/sysctl.conf; then
        log_info "系统参数已优化"
        return
    fi
    
    cat >> /etc/sysctl.conf << 'EOF'

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
    
    sysctl -p >/dev/null 2>&1
    log_success "系统参数优化完成"
}

# 生成自签名证书
generate_self_signed_cert() {
    log_info "生成自签名证书..."
    
    mkdir -p ${CERT_DIR}
    
    rm -f ${CERT_DIR}/self-signed.key ${CERT_DIR}/self-signed.pem
    rm -f ${CERT_DIR}/current.key ${CERT_DIR}/current.pem
    
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) \
        -keyout ${CERT_DIR}/self-signed.key \
        -out ${CERT_DIR}/self-signed.pem \
        -days 3650 \
        -subj "/C=US/ST=California/L=San Francisco/O=EdgeBox/CN=${SERVER_IP}" >/dev/null 2>&1
    
    ln -sf ${CERT_DIR}/self-signed.key ${CERT_DIR}/current.key
    ln -sf ${CERT_DIR}/self-signed.pem ${CERT_DIR}/current.pem
    
    chown root:root ${CERT_DIR}/*.key ${CERT_DIR}/*.pem
    chmod 600 ${CERT_DIR}/*.key
    chmod 644 ${CERT_DIR}/*.pem

    if openssl x509 -in ${CERT_DIR}/current.pem -noout -text >/dev/null 2>&1 && \
       openssl ec -in ${CERT_DIR}/current.key -noout -text >/dev/null 2>&1; then
        log_success "自签名证书生成完成并验证通过"
        echo "self-signed" > ${CONFIG_DIR}/cert_mode
    else
        log_error "证书验证失败"
        return 1
    fi
}

# 安装Xray
install_xray() {
    log_info "安装Xray..."

    if command -v xray &>/dev/null; then
        log_info "Xray已安装，跳过"
    else
        bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null 2>&1 || {
            log_error "Xray安装失败"
            exit 1
        }
    fi

    systemctl disable --now xray >/dev/null 2>&1 || true
    rm -rf /etc/systemd/system/xray.service.d 2>/dev/null || true

    log_success "Xray安装完成"
}

# 安装sing-box
install_sing_box() {
    log_info "安装sing-box..."

    if [[ -f /usr/local/bin/sing-box ]]; then
        log_info "sing-box已安装，跳过"
    else
        local latest ver
        latest="$(curl -sIL -o /dev/null -w '%{url_effective}' https://github.com/SagerNet/sing-box/releases/latest | awk -F/ '{print $NF}')"
        ver="$(echo "$latest" | sed 's/^v//')"
        [[ -z "$ver" ]] && ver="1.12.4"

        local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-amd64.tar.gz"
        
        if wget -q --tries=3 --timeout=25 "$url" -O "/tmp/sing-box-${ver}.tar.gz"; then 
            tar -xzf "/tmp/sing-box-${ver}.tar.gz" -C /tmp
            install -m 0755 "/tmp/sing-box-${ver}-linux-amd64/sing-box" /usr/local/bin/sing-box
            rm -rf "/tmp/sing-box-${ver}.tar.gz" "/tmp/sing-box-${ver}-linux-amd64"
        else
            log_error "下载sing-box失败"
            exit 1
        fi
    fi

    log_success "sing-box安装完成"
}

# 生成Reality密钥对
generate_reality_keys() {
    log_info "生成Reality密钥对..."

    if command -v sing-box >/dev/null 2>&1; then
        local out
        out="$(sing-box generate reality-keypair 2>/dev/null || sing-box generate reality-key 2>/dev/null || true)"
        REALITY_PRIVATE_KEY="$(echo "$out" | awk -F': ' '/Private/{print $2}')"
        REALITY_PUBLIC_KEY="$(echo "$out"  | awk -F': ' '/Public/{print  $2}')"
        if [[ -n "$REALITY_PRIVATE_KEY" && -n "$REALITY_PUBLIC_KEY" ]]; then
            log_success "Reality密钥对生成完成（sing-box）"
            return 0
        fi
    fi

    if command -v xray >/dev/null 2>&1; then
        local keys
        keys="$(xray x25519)"
        REALITY_PRIVATE_KEY="$(echo "$keys" | awk '/Private key/{print $3}')"
        REALITY_PUBLIC_KEY="$(echo  "$keys" | awk '/Public key/{print  $3}')"
        if [[ -n "$REALITY_PRIVATE_KEY" && -n "$REALITY_PUBLIC_KEY" ]]; then
            log_success "Reality密钥对生成完成（xray）"
            return 0
        fi
    fi

    log_error "生成Reality密钥失败"
    return 1
}

# 配置Nginx
configure_nginx() {
    log_info "配置 Nginx（SNI 定向 + ALPN 兜底）..."

    systemctl stop nginx >/dev/null 2>&1 || true

    if [ -f /usr/share/nginx/modules-available/mod-stream.conf ]; then
        mkdir -p /etc/nginx/modules-enabled
        ln -sf /usr/share/nginx/modules-available/mod-stream.conf \
               /etc/nginx/modules-enabled/50-mod-stream.conf 2>/dev/null || true
    fi

    if [ -f /etc/nginx/nginx.conf ] && [ ! -f /etc/nginx/nginx.conf.bak ]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    fi

    cat > /etc/nginx/nginx.conf <<'NGINX_CONF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

include /etc/nginx/modules-enabled/*.conf;

events { worker_connections 1024; use epoll; }

http {
  sendfile on; tcp_nopush on; types_hash_max_size 2048;
  include /etc/nginx/mime.types; default_type application/octet-stream;
  access_log /var/log/nginx/access.log;

  server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /etc/edgebox/traffic;
    index index.html;
    
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    
    location / { 
      try_files $uri $uri/ =404; 
    }
    
    location = /sub { 
      default_type text/plain; 
      try_files /sub.txt =404;
    }
    
    location = /api/traffic {
      default_type application/json;
      try_files /traffic-all.json =404;
    }
  }
}

stream {
  map $ssl_preread_server_name $svc {
    ~^(www\.cloudflare\.com|www\.apple\.com|www\.microsoft\.com)$  reality;
    grpc.edgebox.internal  grpc;
    ws.edgebox.internal    ws;
    default "";
  }

  map $ssl_preread_alpn_protocols $by_alpn {
    ~\bh2\b          127.0.0.1:10085;
    ~\bhttp/1\.1\b   127.0.0.1:10086;
    default          127.0.0.1:10086;
  }

  map $svc $upstream_sni {
    reality  127.0.0.1:11443;
    grpc     127.0.0.1:10085;
    ws       127.0.0.1:10086;
    default  "";
  }

  map $upstream_sni $upstream {
    ~.+     $upstream_sni;
    default $by_alpn;
  }

  server {
    listen 0.0.0.0:443;
    ssl_preread on;
    proxy_pass $upstream;
    proxy_connect_timeout 5s;
    proxy_timeout 15s;
    proxy_protocol off;
  }
}
NGINX_CONF

    if ! nginx -t >/dev/null 2>&1; then
        log_error "Nginx 配置测试失败"
        return 1
    fi

    systemctl daemon-reload
    systemctl enable nginx >/dev/null 2>&1 || true
    if systemctl restart nginx >/dev/null 2>&1; then
        log_success "Nginx 已启动"
    else
        log_error "Nginx 启动失败"
        return 1
    fi
}

# 配置Xray
configure_xray() {
    log_info "配置 Xray..."

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
      "listen": "127.0.0.1",
      "port": 11443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { 
            "id": "${UUID_VLESS}", 
            "flow": "xtls-rprx-vision", 
            "email": "reality@edgebox" 
          }
        ],
        "decryption": "none"
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
          "shortIds": ["${REALITY_SHORT_ID}"]
        }
      }
    },
    {
      "tag": "VLESS-gRPC-Internal",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "vless",
      "settings": {
        "clients": [ 
          { 
            "id": "${UUID_VLESS}", 
            "email": "grpc-internal@edgebox" 
          } 
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2"],
          "certificates": [ 
            { 
              "certificateFile": "${CERT_DIR}/current.pem", 
              "keyFile": "${CERT_DIR}/current.key" 
            } 
          ]
        },
        "grpcSettings": { 
          "serviceName": "grpc",
          "multiMode": true
        }
      }
    },
    {
      "tag": "VLESS-WS-Internal", 
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "vless",
      "settings": {
        "clients": [ 
          { 
            "id": "${UUID_VLESS}", 
            "email": "ws-internal@edgebox" 
          } 
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls", 
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [ 
            { 
              "certificateFile": "${CERT_DIR}/current.pem", 
              "keyFile": "${CERT_DIR}/current.key" 
            } 
          ]
        },
        "wsSettings": { 
          "path": "/ws"
        }
      }
    }
  ],
  "outbounds": [ 
    { 
      "protocol": "freedom", 
      "settings": {} 
    } 
  ]
}
EOF

    cat > /etc/systemd/system/xray.service << 'XRAY_SERVICE'
[Unit]
Description=Xray Service (EdgeBox)
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -c /etc/edgebox/config/xray.json
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
XRAY_SERVICE

    systemctl daemon-reload
    log_success "Xray 配置完成"
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
          "password": "${PASSWORD_HYSTERIA2}"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
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
          "uuid": "${UUID_TUIC}",
          "password": "${PASSWORD_TUIC}"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
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
    log_success "sing-box 配置完成"
}

# 保存配置信息
save_config_info() {
    log_info "保存配置信息..."
    
    cat > ${CONFIG_DIR}/server.json << EOF
{
  "server_ip": "${SERVER_IP}",
  "version": "3.0.1",
  "install_date": "$(date -Iseconds)",
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
    "private_key": "${REALITY_PRIVATE_KEY}",
    "public_key": "${REALITY_PUBLIC_KEY}",
    "short_id": "${REALITY_SHORT_ID}"
  }
}
EOF
    
    log_success "配置信息已保存"
}

# 启动服务
start_services() {
    log_info "启动服务..."
    
    for service in nginx xray sing-box; do
        systemctl enable $service >/dev/null 2>&1
        if systemctl restart $service >/dev/null 2>&1; then
            log_success "$service 启动成功"
        else
            log_error "$service 启动失败"
        fi
    done
}

# 生成订阅
generate_subscription() {
    log_info "生成订阅链接..."
    
    local HY2_PW_ENC=$(printf '%s' "$PASSWORD_HYSTERIA2" | jq -rR @uri)
    local TUIC_PW_ENC=$(printf '%s' "$PASSWORD_TUIC" | jq -rR @uri)
    
    # 生成各协议链接
    local reality_link="vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#EdgeBox-REALITY"
    local grpc_link="vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=grpc.edgebox.internal&alpn=h2&type=grpc&serviceName=grpc&fp=chrome&allowInsecure=1#EdgeBox-gRPC"
    local ws_link="vless://${UUID_VLESS}@${SERVER_IP}:443?encryption=none&security=tls&sni=ws.edgebox.internal&alpn=http%2F1.1&type=ws&path=/ws&fp=chrome&allowInsecure=1#EdgeBox-WS"
    local hy2_link="hysteria2://${HY2_PW_ENC}@${SERVER_IP}:443?sni=${SERVER_IP}&alpn=h3&insecure=1#EdgeBox-HYSTERIA2"
    local tuic_link="tuic://${UUID_TUIC}:${TUIC_PW_ENC}@${SERVER_IP}:2053?congestion_control=bbr&alpn=h3&sni=${SERVER_IP}&allowInsecure=1#EdgeBox-TUIC"
    
    # 保存所有链接
    local sub="${reality_link}
${grpc_link}
${ws_link}
${hy2_link}
${tuic_link}"
    
    echo -e "${sub}" > "${CONFIG_DIR}/subscription.txt"
    echo -e "${sub}" | base64 -w0 > "${CONFIG_DIR}/subscription.base64"
    echo -e "${sub}" > "${TRAFFIC_DIR}/sub.txt"
    
    # 保存各协议单独的Base64
    echo "${reality_link}" | base64 -w0 > "${CONFIG_DIR}/reality.base64"
    echo "${grpc_link}" | base64 -w0 > "${CONFIG_DIR}/grpc.base64"
    echo "${ws_link}" | base64 -w0 > "${CONFIG_DIR}/ws.base64"
    echo "${hy2_link}" | base64 -w0 > "${CONFIG_DIR}/hy2.base64"
    echo "${tuic_link}" | base64 -w0 > "${CONFIG_DIR}/tuic.base64"
    
    log_success "订阅链接生成完成"
}

# 设置nftables流量统计规则
setup_nftables_rules() {
    log_info "配置nftables流量统计规则..."
    
    if ! command -v nft >/dev/null 2>&1; then
        log_warn "nftables未安装，跳过流量统计规则设置"
        return
    fi
    
    # 创建nftables规则
    nft -f - <<'NFT_RULES' >/dev/null 2>&1 || true
table inet edgebox {
    counter c_tcp443 {}
    counter c_udp443 {}
    counter c_udp2053 {}
    counter c_resi_out {}
    
    set resi_addrs {
        type ipv4_addr
        flags interval
    }
    
    set resi_ports {
        type inet_service
        flags interval
    }
    
    chain input {
        type filter hook input priority 0; policy accept;
        tcp dport 443 counter name c_tcp443
        udp dport 443 counter name c_udp443
        udp dport 2053 counter name c_udp2053
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr @resi_addrs tcp dport @resi_ports counter name c_resi_out
    }
}
NFT_RULES
    
    log_success "nftables规则配置完成"
}

# 设置流量监控系统
setup_traffic_monitoring() {
    log_info "设置流量监控系统..."
    
    # 创建流量采集脚本
    cat > "${SCRIPTS_DIR}/traffic-collector.sh" << 'TRAFFIC_SCRIPT'
#!/bin/bash
# EdgeBox 流量采集脚本 - 轻量级版本

TRAFFIC_DIR="/etc/edgebox/traffic"
LOG_DIR="${TRAFFIC_DIR}/logs"
CONFIG_DIR="/etc/edgebox/config"

mkdir -p "$LOG_DIR"

# 获取当前时间
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
DATE=$(date +"%Y-%m-%d")
MONTH=$(date +"%Y-%m")
HOUR=$(date +"%H")

# 获取vnstat数据（网卡总流量）
if command -v vnstat >/dev/null 2>&1; then
    IFACE=$(ip route | awk '/default/{print $5; exit}')
    VNSTAT_DATA=$(vnstat -i "$IFACE" --oneline 2>/dev/null | tail -1)
    
    # 解析今日流量（字节）
    TODAY_RX=$(echo "$VNSTAT_DATA" | awk -F';' '{print $4}' | numfmt --from=iec 2>/dev/null || echo "0")
    TODAY_TX=$(echo "$VNSTAT_DATA" | awk -F';' '{print $5}' | numfmt --from=iec 2>/dev/null || echo "0")
    
    # 解析本月流量（字节）
    MONTH_RX=$(echo "$VNSTAT_DATA" | awk -F';' '{print $9}' | numfmt --from=iec 2>/dev/null || echo "0")
    MONTH_TX=$(echo "$VNSTAT_DATA" | awk -F';' '{print $10}' | numfmt --from=iec 2>/dev/null || echo "0")
else
    TODAY_RX=0
    TODAY_TX=0
    MONTH_RX=0
    MONTH_TX=0
fi

# 获取nftables计数器数据
if command -v nft >/dev/null 2>&1 && nft list table inet edgebox >/dev/null 2>&1; then
    TCP443=$(nft list counter inet edgebox c_tcp443 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}' || echo "0")
    UDP443=$(nft list counter inet edgebox c_udp443 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}' || echo "0")
    UDP2053=$(nft list counter inet edgebox c_udp2053 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}' || echo "0")
    RESI_OUT=$(nft list counter inet edgebox c_resi_out 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}' || echo "0")
else
    TCP443=0
    UDP443=0
    UDP2053=0
    RESI_OUT=0
fi

# 计算VPS直出流量（总流量 - 住宅IP流量）
VPS_OUT=$((TODAY_TX - RESI_OUT))
[[ $VPS_OUT -lt 0 ]] && VPS_OUT=0

# 写入daily.csv（每小时数据）
DAILY_CSV="${LOG_DIR}/daily.csv"
if [[ ! -f "$DAILY_CSV" ]]; then
    echo "timestamp,rx,tx,tcp443,udp443,udp2053,vps_out,resi_out" > "$DAILY_CSV"
fi
echo "${TIMESTAMP},${TODAY_RX},${TODAY_TX},${TCP443},${UDP443},${UDP2053},${VPS_OUT},${RESI_OUT}" >> "$DAILY_CSV"

# 保留最近90天数据
tail -n 2160 "$DAILY_CSV" > "${DAILY_CSV}.tmp" && mv "${DAILY_CSV}.tmp" "$DAILY_CSV"

# 更新monthly.csv（月累计）
MONTHLY_CSV="${LOG_DIR}/monthly.csv"
if [[ ! -f "$MONTHLY_CSV" ]]; then
    echo "month,rx,tx,tcp443,udp443,udp2053,vps_out,resi_out" > "$MONTHLY_CSV"
fi

# 检查是否已有当月记录
if grep -q "^${MONTH}," "$MONTHLY_CSV"; then
    # 更新现有记录
    sed -i "/^${MONTH},/c\\${MONTH},${MONTH_RX},${MONTH_TX},${TCP443},${UDP443},${UDP2053},${VPS_OUT},${RESI_OUT}" "$MONTHLY_CSV"
else
    # 添加新记录
    echo "${MONTH},${MONTH_RX},${MONTH_TX},${TCP443},${UDP443},${UDP2053},${VPS_OUT},${RESI_OUT}" >> "$MONTHLY_CSV"
fi

# 保留最近18个月数据
tail -n 18 "$MONTHLY_CSV" > "${MONTHLY_CSV}.tmp" && mv "${MONTHLY_CSV}.tmp" "$MONTHLY_CSV"

# 生成JSON供前端使用
cat > "${TRAFFIC_DIR}/traffic-all.json" << JSON
{
  "updated": "${TIMESTAMP}",
  "daily": $(tail -n 24 "$DAILY_CSV" | awk -F',' 'NR>1 {
    printf "{\"time\":\"%s\",\"rx\":%s,\"tx\":%s,\"tcp443\":%s,\"udp443\":%s,\"udp2053\":%s,\"vps_out\":%s,\"resi_out\":%s}",
    $1,$2,$3,$4,$5,$6,$7,$8
    if (NR < 25) printf ","
  }' | sed 's/^/{/' | sed 's/$/]/' | sed 's/}{/},{/g' | sed 's/^{/[/'),
  "monthly": $(tail -n 12 "$MONTHLY_CSV" | awk -F',' 'NR>1 {
    printf "{\"month\":\"%s\",\"rx\":%s,\"tx\":%s,\"tcp443\":%s,\"udp443\":%s,\"udp2053\":%s,\"vps_out\":%s,\"resi_out\":%s}",
    $1,$2,$3,$4,$5,$6,$7,$8
    if (NR < 13) printf ","
  }' | sed 's/^/{/' | sed 's/$/]/' | sed 's/}{/},{/g' | sed 's/^{/[/')
}
JSON
TRAFFIC_SCRIPT
    
    chmod +x "${SCRIPTS_DIR}/traffic-collector.sh"
    
    # 创建流量预警脚本
    cat > "${SCRIPTS_DIR}/traffic-alert.sh" << 'ALERT_SCRIPT'
#!/bin/bash
# EdgeBox 流量预警脚本

TRAFFIC_DIR="/etc/edgebox/traffic"
ALERT_CONFIG="${TRAFFIC_DIR}/alert.conf"
ALERT_STATE="${TRAFFIC_DIR}/alert.state"
LOG_FILE="/var/log/edgebox-alert.log"

# 创建默认配置文件
if [[ ! -f "$ALERT_CONFIG" ]]; then
    mkdir -p "$TRAFFIC_DIR"
    cat > "$ALERT_CONFIG" <<EOF
# EdgeBox 流量预警配置
ALERT_MONTHLY_GIB=100
ALERT_EMAIL=admin@example.com
ALERT_WEBHOOK=
EOF
fi

# 读取配置
source "$ALERT_CONFIG"

# 创建状态文件
[[ ! -f "$ALERT_STATE" ]] && echo "0" > "$ALERT_STATE"

# 获取当前月份和流量
CURRENT_MONTH=$(date +%Y-%m)
MONTHLY_CSV="${TRAFFIC_DIR}/logs/monthly.csv"

if [[ ! -f "$MONTHLY_CSV" ]]; then
    echo "[$(date)] 月度流量文件不存在" >> "$LOG_FILE"
    exit 0
fi

# 获取当月总流量（GB）
CURRENT_USAGE=$(awk -F',' -v month="$CURRENT_MONTH" '$1 == month {print ($2+$3)/1024/1024/1024}' "$MONTHLY_CSV" | tail -1)
CURRENT_USAGE=${CURRENT_USAGE:-0}

# 计算使用百分比
if (( $(echo "$ALERT_MONTHLY_GIB > 0" | bc -l) )); then
    USAGE_PERCENT=$(echo "scale=1; $CURRENT_USAGE * 100 / $ALERT_MONTHLY_GIB" | bc -l)
else
    exit 0
fi

# 读取已发送的警告级别
SENT_ALERTS=$(cat "$ALERT_STATE")

# 检查需要发送的警告
send_alert() {
    local threshold=$1
    local message="EdgeBox 流量警告: 本月流量使用已达 ${USAGE_PERCENT}% (${CURRENT_USAGE}GB/${ALERT_MONTHLY_GIB}GB)"
    
    # 发送邮件
    if [[ -n "$ALERT_EMAIL" ]] && command -v mail >/dev/null 2>&1; then
        echo "$message" | mail -s "EdgeBox 流量警告 ${threshold}%" "$ALERT_EMAIL"
    fi
    
    # 发送Webhook
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        curl -s -X POST "$ALERT_WEBHOOK" \
             -H "Content-Type: application/json" \
             -d "{\"text\":\"$message\"}" >/dev/null 2>&1
    fi
    
    echo "[$(date)] 已发送 ${threshold}% 警告" >> "$LOG_FILE"
}

# 检查各个阈值
for threshold in 30 60 90; do
    if (( $(echo "$USAGE_PERCENT >= $threshold" | bc -l) )) && (( $SENT_ALERTS < $threshold )); then
        send_alert $threshold
        echo "$threshold" > "$ALERT_STATE"
        break
    fi
done

# 如果进入新月份，重置状态
LAST_MONTH=$(date -d "last month" +%Y-%m)
if [[ "$CURRENT_MONTH" != "$LAST_MONTH" ]]; then
    echo "0" > "$ALERT_STATE"
fi
ALERT_SCRIPT
    
    chmod +x "${SCRIPTS_DIR}/traffic-alert.sh"
    
    # 创建预警配置
    cat > "${TRAFFIC_DIR}/alert.conf" <<EOF
# EdgeBox 流量预警配置
ALERT_MONTHLY_GIB=100
ALERT_EMAIL=admin@example.com
ALERT_WEBHOOK=
EOF
    
    log_success "流量监控系统设置完成"
}

# 创建控制面板（优化版，两列布局）
create_dashboard() {
    log_info "创建控制面板..."
    
    # 读取各协议的Base64编码
    local reality_b64=$(cat ${CONFIG_DIR}/reality.base64 2>/dev/null || echo "")
    local grpc_b64=$(cat ${CONFIG_DIR}/grpc.base64 2>/dev/null || echo "")
    local ws_b64=$(cat ${CONFIG_DIR}/ws.base64 2>/dev/null || echo "")
    local hy2_b64=$(cat ${CONFIG_DIR}/hy2.base64 2>/dev/null || echo "")
    local tuic_b64=$(cat ${CONFIG_DIR}/tuic.base64 2>/dev/null || echo "")
    local all_b64=$(cat ${CONFIG_DIR}/subscription.base64 2>/dev/null || echo "")
    
    cat > "${TRAFFIC_DIR}/index.html" << 'HTML_DASHBOARD'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EdgeBox 控制面板</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto;
        }
        .header { 
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .header h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .header p {
            color: #666;
        }
        
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        
        .card {
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .card h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .info-item {
            padding: 12px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 3px solid #667eea;
        }
        
        .info-item strong {
            color: #667eea;
            display: block;
            margin-bottom: 5px;
        }
        
        .sub-box {
            margin: 15px 0;
        }
        
        .sub-box h3 {
            color: #333;
            margin-bottom: 10px;
            font-size: 16px;
        }
        
        .sub-content {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
            max-height: 80px;
            overflow-y: auto;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .sub-content:hover {
            background: #e9ecef;
        }
        
        .protocol-grid {
            display: grid;
            gap: 10px;
        }
        
        .protocol-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #764ba2;
        }
        
        .protocol-item h4 {
            color: #764ba2;
            margin-bottom: 8px;
        }
        
        .protocol-sub {
            background: white;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 11px;
            word-break: break-all;
            cursor: pointer;
            max-height: 60px;
            overflow-y: auto;
        }
        
        .chart-container {
            margin: 20px 0;
        }
        
        canvas {
            width: 100% !important;
            height: 250px !important;
        }
        
        .commands {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        
        .cmd-group h4 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .cmd {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 8px 12px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 12px;
            margin: 5px 0;
            cursor: pointer;
        }
        
        .cmd:hover {
            background: #34495e;
        }
        
        .copy-hint {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            display: none;
            animation: slideIn 0.3s;
        }
        
        @keyframes slideIn {
            from { transform: translateX(100%); }
            to { transform: translateX(0); }
        }
        
        @media (max-width: 768px) {
            .content-grid { grid-template-columns: 1fr; }
            .info-grid { grid-template-columns: 1fr; }
            .commands { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 EdgeBox 控制面板</h1>
            <p>企业级多协议节点部署方案 v3.0.1</p>
        </div>
        
        <div class="content-grid">
            <!-- 左列：订阅和协议 -->
            <div class="card">
                <h2>📱 订阅信息</h2>
                
                <div class="info-grid">
                    <div class="info-item">
                        <strong>服务器IP</strong>
                        <span id="server-ip">加载中...</span>
                    </div>
                    <div class="info-item">
                        <strong>证书模式</strong>
                        <span id="cert-mode">加载中...</span>
                    </div>
                    <div class="info-item">
                        <strong>分流状态</strong>
                        <span id="shunt-mode">加载中...</span>
                    </div>
                    <div class="info-item">
                        <strong>协议支持</strong>
                        <span>5种协议</span>
                    </div>
                </div>
                
                <div class="sub-box">
                    <h3>聚合订阅（Base64）</h3>
                    <div class="sub-content" onclick="copyToClipboard(this)" id="sub-all">加载中...</div>
                </div>
                
                <h3 style="margin: 20px 0 15px;">单协议订阅</h3>
                <div class="protocol-grid">
                    <div class="protocol-item">
                        <h4>VLESS-Reality</h4>
                        <div class="protocol-sub" onclick="copyToClipboard(this)" id="sub-reality">加载中...</div>
                    </div>
                    <div class="protocol-item">
                        <h4>VLESS-gRPC</h4>
                        <div class="protocol-sub" onclick="copyToClipboard(this)" id="sub-grpc">加载中...</div>
                    </div>
                    <div class="protocol-item">
                        <h4>VLESS-WebSocket</h4>
                        <div class="protocol-sub" onclick="copyToClipboard(this)" id="sub-ws">加载中...</div>
                    </div>
                    <div class="protocol-item">
                        <h4>Hysteria2</h4>
                        <div class="protocol-sub" onclick="copyToClipboard(this)" id="sub-hy2">加载中...</div>
                    </div>
                    <div class="protocol-item">
                        <h4>TUIC</h4>
                        <div class="protocol-sub" onclick="copyToClipboard(this)" id="sub-tuic">加载中...</div>
                    </div>
                </div>
            </div>
            
            <!-- 右列：流量和命令 -->
            <div class="card">
                <h2>📊 流量统计</h2>
                
                <div class="chart-container">
                    <h3 style="margin-bottom: 10px;">分流出站（24小时）</h3>
                    <canvas id="chart-shunt"></canvas>
                </div>
                
                <div class="chart-container">
                    <h3 style="margin-bottom: 10px;">端口流量（24小时）</h3>
                    <canvas id="chart-ports"></canvas>
                </div>
                
                <h2 style="margin-top: 30px;">⚡ 快速操作</h2>
                <div class="commands">
                    <div class="cmd-group">
                        <h4>基础管理</h4>
                        <div class="cmd" onclick="copyToClipboard(this)">edgeboxctl status</div>
                        <div class="cmd" onclick="copyToClipboard(this)">edgeboxctl restart</div>
                        <div class="cmd" onclick="copyToClipboard(this)">edgeboxctl sub</div>
                        <div class="cmd" onclick="copyToClipboard(this)">edgeboxctl traffic show</div>
                    </div>
                    <div class="cmd-group">
                        <h4>模式切换</h4>
                        <div class="cmd" onclick="copyToClipboard(this)">edgeboxctl switch-to-domain &lt;域名&gt;</div>
                        <div class="cmd" onclick="copyToClipboard(this)">edgeboxctl switch-to-ip</div>
                        <div class="cmd" onclick="copyToClipboard(this)">edgeboxctl shunt direct-resi IP:PORT</div>
                        <div class="cmd" onclick="copyToClipboard(this)">edgeboxctl help</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="copy-hint" id="copyHint">已复制到剪贴板！</div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // 复制功能
        function copyToClipboard(element) {
            const text = element.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const hint = document.getElementById('copyHint');
                hint.style.display = 'block';
                setTimeout(() => hint.style.display = 'none', 2000);
            });
        }
        
        // 加载服务器信息
        async function loadServerInfo() {
            try {
                const response = await fetch('/api/traffic');
                const data = await response.json();
                
                // 从配置获取服务器信息
                document.getElementById('server-ip').textContent = window.location.hostname;
                document.getElementById('cert-mode').textContent = 'self-signed';
                document.getElementById('shunt-mode').textContent = 'VPS全量出';
                
                // 加载订阅
                loadSubscriptions();
                
                // 绘制图表
                drawCharts(data);
            } catch (error) {
                console.error('加载数据失败:', error);
            }
        }
        
        // 加载订阅信息
        async function loadSubscriptions() {
            // 这里应该从后端API获取，现在使用占位符
            document.getElementById('sub-all').textContent = 'SUB_ALL_BASE64';
            document.getElementById('sub-reality').textContent = 'SUB_REALITY_BASE64';
            document.getElementById('sub-grpc').textContent = 'SUB_GRPC_BASE64';
            document.getElementById('sub-ws').textContent = 'SUB_WS_BASE64';
            document.getElementById('sub-hy2').textContent = 'SUB_HY2_BASE64';
            document.getElementById('sub-tuic').textContent = 'SUB_TUIC_BASE64';
        }
        
        // 绘制图表
        function drawCharts(data) {
            // 分流图表
            const shuntCtx = document.getElementById('chart-shunt').getContext('2d');
            new Chart(shuntCtx, {
                type: 'line',
                data: {
                    labels: data.daily ? data.daily.map(d => d.time.split(' ')[1]) : [],
                    datasets: [{
                        label: 'VPS直出',
                        data: data.daily ? data.daily.map(d => d.vps_out / 1024 / 1024) : [],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4
                    }, {
                        label: '住宅IP',
                        data: data.daily ? data.daily.map(d => d.resi_out / 1024 / 1024) : [],
                        borderColor: '#764ba2',
                        backgroundColor: 'rgba(118, 75, 162, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'top' },
                        tooltip: {
                            callbacks: {
                                label: (context) => `${context.dataset.label}: ${context.parsed.y.toFixed(2)} MB`
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: { display: true, text: '流量 (MB)' }
                        }
                    }
                }
            });
            
            // 端口流量图表
            const portsCtx = document.getElementById('chart-ports').getContext('2d');
            new Chart(portsCtx, {
                type: 'bar',
                data: {
                    labels: data.daily ? data.daily.map(d => d.time.split(' ')[1]) : [],
                    datasets: [{
                        label: 'TCP/443',
                        data: data.daily ? data.daily.map(d => d.tcp443 / 1024 / 1024) : [],
                        backgroundColor: '#28a745'
                    }, {
                        label: 'UDP/443',
                        data: data.daily ? data.daily.map(d => d.udp443 / 1024 / 1024) : [],
                        backgroundColor: '#ffc107'
                    }, {
                        label: 'UDP/2053',
                        data: data.daily ? data.daily.map(d => d.udp2053 / 1024 / 1024) : [],
                        backgroundColor: '#dc3545'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'top' },
                        tooltip: {
                            callbacks: {
                                label: (context) => `${context.dataset.label}: ${context.parsed.y.toFixed(2)} MB`
                            }
                        }
                    },
                    scales: {
                        x: { stacked: true },
                        y: {
                            stacked: true,
                            beginAtZero: true,
                            title: { display: true, text: '流量 (MB)' }
                        }
                    }
                }
            });
        }
        
        // 页面加载完成后执行
        document.addEventListener('DOMContentLoaded', loadServerInfo);
        
        // 每分钟刷新数据
        setInterval(loadServerInfo, 60000);
    </script>
</body>
</html>
HTML_DASHBOARD
    
    # 替换订阅占位符
    sed -i "s|SUB_ALL_BASE64|${all_b64}|g" "${TRAFFIC_DIR}/index.html"
    sed -i "s|SUB_REALITY_BASE64|${reality_b64}|g" "${TRAFFIC_DIR}/index.html"
    sed -i "s|SUB_GRPC_BASE64|${grpc_b64}|g" "${TRAFFIC_DIR}/index.html"
    sed -i "s|SUB_WS_BASE64|${ws_b64}|g" "${TRAFFIC_DIR}/index.html"
    sed -i "s|SUB_HY2_BASE64|${hy2_b64}|g" "${TRAFFIC_DIR}/index.html"
    sed -i "s|SUB_TUIC_BASE64|${tuic_b64}|g" "${TRAFFIC_DIR}/index.html"
    
    log_success "控制面板创建完成"
}

# 设置定时任务
setup_cron_jobs() {
    log_info "设置定时任务..."
    
    # 创建新的cron任务
    (crontab -l 2>/dev/null | grep -v "edgebox"; cat <<EOF
# EdgeBox 定时任务
# 每小时采集流量数据
0 * * * * ${SCRIPTS_DIR}/traffic-collector.sh >/dev/null 2>&1

# 每小时检查流量预警
7 * * * * ${SCRIPTS_DIR}/traffic-alert.sh >/dev/null 2>&1

# 每日自动备份
30 3 * * * /usr/local/bin/edgeboxctl backup create >/dev/null 2>&1
EOF
    ) | crontab -
    
    log_success "定时任务设置完成"
}

        ls -t ${BACKUP_DIR}/edgebox_backup_*.tar.gz | tail -n +11 | xargs rm -f 2>/dev/null || true
    else
        log_error "备份失败"
    fi
}

# 备份列表
backup_list() {
    echo -e "${CYAN}备份列表：${NC}"
    ls -lh ${BACKUP_DIR}/edgebox_backup_*.tar.gz 2>/dev/null || echo "  无备份文件"
}

# 备份恢复
backup_restore() {
    local file="$1"
    [[ -z "$file" || ! -f "$file" ]] && { echo "用法: edgeboxctl backup restore <file>"; return 1; }
    
    log_info "恢复备份: $file"
    tar -xzf "$file" -C / 2>/dev/null
    
    systemctl daemon-reload
    systemctl restart nginx xray sing-box
    log_success "恢复完成"
}

# 分流管理
shunt_vps() {
    log_info "切换到VPS全量出站模式..."
    get_server_info || return 1
    
    cat > ${CONFIG_DIR}/sing-box.json << EOF
{
  "log": {"level": "warn", "timestamp": true},
  "inbounds": [
    {
      "type": "hysteria2", "tag": "hysteria2-in", "listen": "::", "listen_port": 443,
      "users": [{"password": "${PASSWORD_HYSTERIA2}"}],
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    },
    {
      "type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": 2053,
      "users": [{"uuid": "${UUID_TUIC}", "password": "${PASSWORD_TUIC}"}],
      "congestion_control": "bbr",
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
    
    echo '{"mode":"vps"}' > "$SHUNT_CONFIG"
    systemctl restart sing-box
    log_success "已切换到VPS全量出站模式"
}

shunt_resi() {
    local proxy_addr="$1"
    [[ -z "$proxy_addr" ]] && { echo "用法: edgeboxctl shunt resi IP:PORT[:USER:PASS]"; return 1; }
    
    log_info "切换到住宅IP全量出站模式..."
    get_server_info || return 1
    
    local host port user pass
    IFS=':' read -r host port user pass <<< "$proxy_addr"
    
    local auth_json=""
    [[ -n "$user" && -n "$pass" ]] && auth_json=",\"username\":\"$user\",\"password\":\"$pass\""
    
    cat > ${CONFIG_DIR}/sing-box.json << EOF
{
  "log": {"level": "warn", "timestamp": true},
  "inbounds": [
    {
      "type": "hysteria2", "tag": "hysteria2-in", "listen": "::", "listen_port": 443,
      "users": [{"password": "${PASSWORD_HYSTERIA2}"}],
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    },
    {
      "type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": 2053,
      "users": [{"uuid": "${UUID_TUIC}", "password": "${PASSWORD_TUIC}"}],
      "congestion_control": "bbr",
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    }
  ],
  "outbounds": [
    {"type": "http", "tag": "resi-proxy", "server": "${host}", "server_port": ${port}${auth_json}},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rules": [
      {"protocol": "dns", "outbound": "direct"},
      {"port": 53, "outbound": "direct"},
      {"outbound": "resi-proxy"}
    ]
  }
}
EOF
    
    echo "{\"mode\":\"resi\",\"proxy_info\":\"$proxy_addr\"}" > "$SHUNT_CONFIG"
    
    # 更新nftables
    if command -v nft >/dev/null 2>&1; then
        nft add element inet edgebox resi_addrs \{ ${host} \} 2>/dev/null || true
        nft add element inet edgebox resi_ports \{ ${port} \} 2>/dev/null || true
    fi
    
    systemctl restart sing-box
    log_success "已切换到住宅IP全量出站模式"
}

shunt_direct_resi() {
    local proxy_addr="$1"
    [[ -z "$proxy_addr" ]] && { echo "用法: edgeboxctl shunt direct-resi IP:PORT[:USER:PASS]"; return 1; }
    
    log_info "切换到智能分流模式..."
    get_server_info || return 1
    
    local host port user pass
    IFS=':' read -r host port user pass <<< "$proxy_addr"
    
    local auth_json=""
    [[ -n "$user" && -n "$pass" ]] && auth_json=",\"username\":\"$user\",\"password\":\"$pass\""
    
    # 读取白名单
    local whitelist_json='["googlevideo.com","ytimg.com","youtube.com"]'
    if [[ -f "${CONFIG_DIR}/shunt/whitelist.txt" ]]; then
        whitelist_json=$(cat "${CONFIG_DIR}/shunt/whitelist.txt" | jq -R -s 'split("\n") | map(select(length > 0))' | jq -c .)
    fi
    
    cat > ${CONFIG_DIR}/sing-box.json << EOF
{
  "log": {"level": "warn", "timestamp": true},
  "inbounds": [
    {
      "type": "hysteria2", "tag": "hysteria2-in", "listen": "::", "listen_port": 443,
      "users": [{"password": "${PASSWORD_HYSTERIA2}"}],
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    },
    {
      "type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": 2053,
      "users": [{"uuid": "${UUID_TUIC}", "password": "${PASSWORD_TUIC}"}],
      "congestion_control": "bbr",
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    }
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "http", "tag": "resi-proxy", "server": "${host}", "server_port": ${port}${auth_json}}
  ],
  "route": {
    "rules": [
      {"protocol": "dns", "outbound": "direct"},
      {"port": 53, "outbound": "direct"},
      {"domain_suffix": ${whitelist_json}, "outbound": "direct"},
      {"outbound": "resi-proxy"}
    ]
  }
}
EOF
    
    echo "{\"mode\":\"direct_resi\",\"proxy_info\":\"$proxy_addr\"}" > "$SHUNT_CONFIG"
    systemctl restart sing-box
    log_success "已切换到智能分流模式"
}

# 主命令处理
case "$1" in
    # 基础功能
    sub|subscription) show_sub ;;
    status) show_status ;;
    restart) restart_services ;;
    logs) journalctl -u "$2" -n 100 --no-pager ;;
    test) curl -s "http://$(jq -r .server_ip ${CONFIG_DIR}/server.json)/sub" >/dev/null && echo "OK" || echo "FAIL" ;;
    
    # 证书管理
    switch-to-domain) shift; switch_to_domain "$1" ;;
    switch-to-ip) switch_to_ip ;;
    
    # 配置管理
    config)
        case "$2" in
            show) jq . ${CONFIG_DIR}/server.json ;;
            regenerate-uuid)
                log_info "重新生成UUID..."
                # 实现UUID重新生成逻辑
                ;;
            *) echo "用法: edgeboxctl config [show|regenerate-uuid]" ;;
        esac
        ;;
    
    # 分流管理
    shunt)
        case "$2" in
            vps) shunt_vps ;;
            resi) shunt_resi "$3" ;;
            direct-resi) shunt_direct_resi "$3" ;;
            status)
                if [[ -f "$SHUNT_CONFIG" ]]; then
                    jq . "$SHUNT_CONFIG"
                else
                    echo "未配置分流"
                fi
                ;;
            whitelist)
                case "$3" in
                    add)
                        echo "$4" >> "${CONFIG_DIR}/shunt/whitelist.txt"
                        log_success "已添加白名单: $4"
                        ;;
                    remove)
                        sed -i "/^${4}$/d" "${CONFIG_DIR}/shunt/whitelist.txt"
                        log_success "已移除白名单: $4"
                        ;;
                    list)
                        cat "${CONFIG_DIR}/shunt/whitelist.txt" 2>/dev/null || echo "无白名单"
                        ;;
                    *) echo "用法: edgeboxctl shunt whitelist [add|remove|list] [domain]" ;;
                esac
                ;;
            *) echo "用法: edgeboxctl shunt [vps|resi|direct-resi|status|whitelist]" ;;
        esac
        ;;
    
    # 流量统计
    traffic)
        case "$2" in
            show|"") traffic_show ;;
            reset)
                if command -v nft >/dev/null 2>&1; then
                    nft reset counter inet edgebox c_tcp443 >/dev/null 2>&1
                    nft reset counter inet edgebox c_udp443 >/dev/null 2>&1
                    nft reset counter inet edgebox c_udp2053 >/dev/null 2>&1
                    nft reset counter inet edgebox c_resi_out >/dev/null 2>&1
                fi
                log_success "流量统计已重置"
                ;;
            *) echo "用法: edgeboxctl traffic [show|reset]" ;;
        esac
        ;;
    
    # 备份恢复
    backup)
        case "$2" in
            create) backup_create ;;
            list) backup_list ;;
            restore) backup_restore "$3" ;;
            *) echo "用法: edgeboxctl backup [create|list|restore <file>]" ;;
        esac
        ;;
    
    # 更新系统
    update)
        log_info "更新EdgeBox..."
        curl -fsSL https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/install.sh | bash
        ;;
    
    # 帮助信息 - 直接列出全部命令
    help|"")
        cat <<HLP
${CYAN}EdgeBox 管理工具 v${VERSION}${NC}

${YELLOW}基础操作:${NC}
  edgeboxctl status                     # 查看服务状态
  edgeboxctl restart                    # 重启所有服务
  edgeboxctl sub                        # 查看订阅链接
  edgeboxctl logs [nginx|xray|sing-box] # 查看服务日志
  edgeboxctl test                       # 测试连接

${YELLOW}证书管理:${NC}
  edgeboxctl switch-to-domain <domain>  # 切换到域名模式
  edgeboxctl switch-to-ip               # 切换到IP模式

${YELLOW}配置管理:${NC}
  edgeboxctl config show                # 显示当前配置
  edgeboxctl config regenerate-uuid     # 重新生成UUID

${YELLOW}出站分流:${NC}
  edgeboxctl shunt vps                  # VPS全量出站
  edgeboxctl shunt resi IP:PORT[:USER:PASS] # 住宅IP全量出站
  edgeboxctl shunt direct-resi IP:PORT[:USER:PASS] # 智能分流模式
  edgeboxctl shunt status               # 查看分流状态
  edgeboxctl shunt whitelist add <domain>    # 添加白名单域名
  edgeboxctl shunt whitelist remove <domain> # 移除白名单域名
  edgeboxctl shunt whitelist list       # 查看白名单

${YELLOW}流量统计:${NC}
  edgeboxctl traffic show               # 查看流量统计
  edgeboxctl traffic reset              # 重置流量计数

${YELLOW}备份恢复:${NC}
  edgeboxctl backup create              # 创建备份
  edgeboxctl backup list                # 列出备份
  edgeboxctl backup restore <file>      # 恢复备份

${YELLOW}系统:${NC}
  edgeboxctl update                     # 更新EdgeBox
  edgeboxctl help                       # 显示此帮助

${CYAN}控制面板: http://$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null || echo "YOUR_IP")/${NC}
${CYAN}订阅链接: http://$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null || echo "YOUR_IP")/sub${NC}
HLP
        ;;
    
    *)
        echo -e "${RED}未知命令: $1${NC}"
        echo "使用 'edgeboxctl help' 查看帮助"
        exit 1
        ;;
esac
EDGEBOXCTL_SCRIPT

    chmod +x /usr/local/bin/edgeboxctl
    log_success "edgeboxctl管理工具创建完成"
}dgebox_backup_*.tar.gz | tail -n +11 | xargs rm -f 2>/dev/null || true
    else
        log_error "备份失败"
    fi
}

# 备份列表
backup_list() {
    echo -e "${CYAN}备份列表：${NC}"
    ls -lh ${BACKUP_DIR}/edgebox_backup_*.tar.gz 2>/dev/null || echo "  无备份文件"
}

# 备份恢复
backup_restore() {
    local file="$1"
    [[ -z "$file" || ! -f "$file" ]] && { echo "用法: edgeboxctl backup restore <file>"; return 1; }
    
    log_info "恢复备份: $file"
    tar -xzf "$file" -C / 2>/dev/null
    
    systemctl daemon-reload
    systemctl restart nginx xray sing-box
    log_success "恢复完成"
}

# 分流管理
shunt_vps() {
    log_info "切换到VPS全量出站模式..."
    get_server_info || return 1
    
    cat > ${CONFIG_DIR}/sing-box.json << EOF
{
  "log": {"level": "warn", "timestamp": true},
  "inbounds": [
    {
      "type": "hysteria2", "tag": "hysteria2-in", "listen": "::", "listen_port": 443,
      "users": [{"password": "${PASSWORD_HYSTERIA2}"}],
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    },
    {
      "type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": 2053,
      "users": [{"uuid": "${UUID_TUIC}", "password": "${PASSWORD_TUIC}"}],
      "congestion_control": "bbr",
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
    
    echo '{"mode":"vps"}' > "$SHUNT_CONFIG"
    systemctl restart sing-box
    log_success "已切换到VPS全量出站模式"
}

shunt_resi() {
    local proxy_addr="$1"
    [[ -z "$proxy_addr" ]] && { echo "用法: edgeboxctl shunt resi IP:PORT[:USER:PASS]"; return 1; }
    
    log_info "切换到住宅IP全量出站模式..."
    get_server_info || return 1
    
    local host port user pass
    IFS=':' read -r host port user pass <<< "$proxy_addr"
    
    local auth_json=""
    [[ -n "$user" && -n "$pass" ]] && auth_json=",\"username\":\"$user\",\"password\":\"$pass\""
    
    cat > ${CONFIG_DIR}/sing-box.json << EOF
{
  "log": {"level": "warn", "timestamp": true},
  "inbounds": [
    {
      "type": "hysteria2", "tag": "hysteria2-in", "listen": "::", "listen_port": 443,
      "users": [{"password": "${PASSWORD_HYSTERIA2}"}],
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    },
    {
      "type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": 2053,
      "users": [{"uuid": "${UUID_TUIC}", "password": "${PASSWORD_TUIC}"}],
      "congestion_control": "bbr",
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    }
  ],
  "outbounds": [
    {"type": "http", "tag": "resi-proxy", "server": "${host}", "server_port": ${port}${auth_json}},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rules": [
      {"protocol": "dns", "outbound": "direct"},
      {"port": 53, "outbound": "direct"},
      {"outbound": "resi-proxy"}
    ]
  }
}
EOF
    
    echo "{\"mode\":\"resi\",\"proxy_info\":\"$proxy_addr\"}" > "$SHUNT_CONFIG"
    
    # 更新nftables
    if command -v nft >/dev/null 2>&1; then
        nft add element inet edgebox resi_addrs \{ ${host} \} 2>/dev/null || true
        nft add element inet edgebox resi_ports \{ ${port} \} 2>/dev/null || true
    fi
    
    systemctl restart sing-box
    log_success "已切换到住宅IP全量出站模式"
}

shunt_direct_resi() {
    local proxy_addr="$1"
    [[ -z "$proxy_addr" ]] && { echo "用法: edgeboxctl shunt direct-resi IP:PORT[:USER:PASS]"; return 1; }
    
    log_info "切换到智能分流模式..."
    get_server_info || return 1
    
    local host port user pass
    IFS=':' read -r host port user pass <<< "$proxy_addr"
    
    local auth_json=""
    [[ -n "$user" && -n "$pass" ]] && auth_json=",\"username\":\"$user\",\"password\":\"$pass\""
    
    # 读取白名单
    local whitelist_json='["googlevideo.com","ytimg.com","youtube.com"]'
    if [[ -f "${CONFIG_DIR}/shunt/whitelist.txt" ]]; then
        whitelist_json=$(cat "${CONFIG_DIR}/shunt/whitelist.txt" | jq -R -s 'split("\n") | map(select(length > 0))' | jq -c .)
    fi
    
    cat > ${CONFIG_DIR}/sing-box.json << EOF
{
  "log": {"level": "warn", "timestamp": true},
  "inbounds": [
    {
      "type": "hysteria2", "tag": "hysteria2-in", "listen": "::", "listen_port": 443,
      "users": [{"password": "${PASSWORD_HYSTERIA2}"}],
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    },
    {
      "type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": 2053,
      "users": [{"uuid": "${UUID_TUIC}", "password": "${PASSWORD_TUIC}"}],
      "congestion_control": "bbr",
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "${CERT_DIR}/current.pem", "key_path": "${CERT_DIR}/current.key"}
    }
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "http", "tag": "resi-proxy", "server": "${host}", "server_port": ${port}${auth_json}}
  ],
  "route": {
    "rules": [
      {"protocol": "dns", "outbound": "direct"},
      {"port": 53, "outbound": "direct"},
      {"domain_suffix": ${whitelist_json}, "outbound": "direct"},
      {"outbound": "resi-proxy"}
    ]
  }
}
EOF
    
    echo "{\"mode\":\"direct_resi\",\"proxy_info\":\"$proxy_addr\"}" > "$SHUNT_CONFIG"
    systemctl restart sing-box
    log_success "已切换到智能分流模式"
}

# 主命令处理
case "$1" in
    # 基础功能
    sub|subscription) show_sub ;;
    status) show_status ;;
    restart) restart_services ;;
    logs) journalctl -u "$2" -n 100 --no-pager ;;
    test) curl -s "http://$(jq -r .server_ip ${CONFIG_DIR}/server.json)/sub" >/dev/null && echo "OK" || echo "FAIL" ;;
    
    # 证书管理
    switch-to-domain) shift; switch_to_domain "$1" ;;
    switch-to-ip) switch_to_ip ;;
    
    # 配置管理
    config)
        case "$2" in
            show) jq . ${CONFIG_DIR}/server.json ;;
            regenerate-uuid)
                log_info "重新生成UUID..."
                # 实现UUID重新生成逻辑
                ;;
            *) echo "用法: edgeboxctl config [show|regenerate-uuid]" ;;
        esac
        ;;
    
    # 分流管理
    shunt)
        case "$2" in
            vps) shunt_vps ;;
            resi) shunt_resi "$3" ;;
            direct-resi) shunt_direct_resi "$3" ;;
            status)
                if [[ -f "$SHUNT_CONFIG" ]]; then
                    jq . "$SHUNT_CONFIG"
                else
                    echo "未配置分流"
                fi
                ;;
            whitelist)
                case "$3" in
                    add)
                        echo "$4" >> "${CONFIG_DIR}/shunt/whitelist.txt"
                        log_success "已添加白名单: $4"
                        ;;
                    remove)
                        sed -i "/^${4}$/d" "${CONFIG_DIR}/shunt/whitelist.txt"
                        log_success "已移除白名单: $4"
                        ;;
                    list)
                        cat "${CONFIG_DIR}/shunt/whitelist.txt" 2>/dev/null || echo "无白名单"
                        ;;
                    *) echo "用法: edgeboxctl shunt whitelist [add|remove|list] [domain]" ;;
                esac
                ;;
            *) echo "用法: edgeboxctl shunt [vps|resi|direct-resi|status|whitelist]" ;;
        esac
        ;;
    
    # 流量统计
    traffic)
        case "$2" in
            show|"") traffic_show ;;
            reset)
                if command -v nft >/dev/null 2>&1; then
                    nft reset counter inet edgebox c_tcp443 >/dev/null 2>&1
                    nft reset counter inet edgebox c_udp443 >/dev/null 2>&1
                    nft reset counter inet edgebox c_udp2053 >/dev/null 2>&1
                    nft reset counter inet edgebox c_resi_out >/dev/null 2>&1
                fi
                log_success "流量统计已重置"
                ;;
            *) echo "用法: edgeboxctl traffic [show|reset]" ;;
        esac
        ;;
    
    # 备份恢复
    backup)
        case "$2" in
            create) backup_create ;;
            list) backup_list ;;
            restore) backup_restore "$3" ;;
            *) echo "用法: edgeboxctl backup [create|list|restore <file>]" ;;
        esac
        ;;
    
    # 更新系统
    update)
        log_info "更新EdgeBox..."
        curl -fsSL https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/install.sh | bash
        ;;
    
    # 帮助信息 - 直接列出全部命令
    help|"")
        cat <<HLP
${CYAN}EdgeBox 管理工具 v${VERSION}${NC}

${YELLOW}基础操作:${NC}
  edgeboxctl status                     # 查看服务状态
  edgeboxctl restart                    # 重启所有服务
  edgeboxctl sub                        # 查看订阅链接
  edgeboxctl logs [nginx|xray|sing-box] # 查看服务日志
  edgeboxctl test                       # 测试连接

${YELLOW}证书管理:${NC}
  edgeboxctl switch-to-domain <domain>  # 切换到域名模式
  edgeboxctl switch-to-ip               # 切换到IP模式

${YELLOW}配置管理:${NC}
  edgeboxctl config show                # 显示当前配置
  edgeboxctl config regenerate-uuid     # 重新生成UUID

${YELLOW}出站分流:${NC}
  edgeboxctl shunt vps                  # VPS全量出站
  edgeboxctl shunt resi IP:PORT[:USER:PASS] # 住宅IP全量出站
  edgeboxctl shunt direct-resi IP:PORT[:USER:PASS] # 智能分流模式
  edgeboxctl shunt status               # 查看分流状态
  edgeboxctl shunt whitelist add <domain>    # 添加白名单域名
  edgeboxctl shunt whitelist remove <domain> # 移除白名单域名
  edgeboxctl shunt whitelist list       # 查看白名单

${YELLOW}流量统计:${NC}
  edgeboxctl traffic show               # 查看流量统计
  edgeboxctl traffic reset              # 重置流量计数

${YELLOW}备份恢复:${NC}
  edgeboxctl backup create              # 创建备份
  edgeboxctl backup list                # 列出备份
  edgeboxctl backup restore <file>      # 恢复备份

${YELLOW}系统:${NC}
  edgeboxctl update                     # 更新EdgeBox
  edgeboxctl help                       # 显示此帮助

${CYAN}控制面板: http://$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null || echo "YOUR_IP")/${NC}
${CYAN}订阅链接: http://$(jq -r .server_ip ${CONFIG_DIR}/server.json 2>/dev/null || echo "YOUR_IP")/sub${NC}
HLP
        ;;
    
    *)
        echo -e "${RED}未知命令: $1${NC}"
        echo "使用 'edgeboxctl help' 查看帮助"
        exit 1
        ;;
esac
EDGEBOXCTL_SCRIPT

    chmod +x /usr/local/bin/edgeboxctl
    log_success "edgeboxctl管理工具创建完成"
}

# 创建卸载脚本链接
create_uninstall_link() {
    log_info "创建卸载命令..."
    
    # 创建软链接到现有的卸载脚本
    cat > /usr/local/bin/edgebox-uninstall << 'UNINSTALL_WRAPPER'
#!/bin/bash
# EdgeBox 卸载脚本包装器

UNINSTALL_URL="https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/uninstall.sh"

echo -e "\033[0;36m[INFO]\033[0m 正在下载并执行卸载脚本..."

if curl -fsSL "$UNINSTALL_URL" | bash; then
    echo -e "\033[0;32m[SUCCESS]\033[0m EdgeBox已成功卸载"
else
    echo -e "\033[0;31m[ERROR]\033[0m 卸载过程中出现错误"
    echo "您可以手动执行: curl -fsSL $UNINSTALL_URL | bash"
    exit 1
fi
UNINSTALL_WRAPPER

    chmod +x /usr/local/bin/edgebox-uninstall
    log_success "卸载命令创建完成"
}

# 设置邮件系统
setup_email_system() {
    log_info "配置邮件系统..."
    
    cat > /etc/msmtprc << 'MSMTP_CONFIG'
# EdgeBox 邮件配置
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

# Gmail 示例配置（需要用户自己配置）
account        gmail
host           smtp.gmail.com
port           587
from           your-email@gmail.com
user           your-email@gmail.com
password       your-app-password

# 默认账户
account default : gmail
MSMTP_CONFIG
    
    chmod 600 /etc/msmtprc
    
    cat > ${CONFIG_DIR}/email-setup.md << 'EMAIL_GUIDE'
# EdgeBox 邮件配置说明

## 配置步骤：
1. 编辑 /etc/msmtprc
2. 替换 your-email@gmail.com 和 your-app-password
3. 测试: echo "测试" | mail -s "EdgeBox测试" your-email@gmail.com
EMAIL_GUIDE

    log_success "邮件系统配置完成"
}

# 初始化脚本
create_init_script() {
    log_info "创建初始化脚本..."
    
    cat > ${SCRIPTS_DIR}/edgebox-init.sh << 'INIT_SCRIPT'
#!/bin/bash
LOG_FILE="/var/log/edgebox-init.log"

echo "[$(date)] EdgeBox 初始化开始" >> $LOG_FILE

# 等待网络就绪
sleep 10

# 初始化nftables规则
if command -v nft >/dev/null 2>&1; then
    nft list table inet edgebox >/dev/null 2>&1 || {
        nft -f - <<'NFT' >/dev/null 2>&1
table inet edgebox {
    counter c_tcp443 {}
    counter c_udp443 {}
    counter c_udp2053 {}
    counter c_resi_out {}
    
    set resi_addrs { type ipv4_addr; flags interval; }
    set resi_ports { type inet_service; flags interval; }
    
    chain input {
        type filter hook input priority 0; policy accept;
        tcp dport 443 counter name c_tcp443
        udp dport 443 counter name c_udp443
        udp dport 2053 counter name c_udp2053
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr @resi_addrs tcp dport @resi_ports counter name c_resi_out
    }
}
NFT
    }
fi

# 启动vnstat
systemctl is-active --quiet vnstat || systemctl start vnstat

# 生成初始流量数据
if [[ -x "/etc/edgebox/scripts/traffic-collector.sh" ]]; then
    /etc/edgebox/scripts/traffic-collector.sh >> $LOG_FILE 2>&1
fi

echo "[$(date)] EdgeBox 初始化完成" >> $LOG_FILE
INIT_SCRIPT

    chmod +x ${SCRIPTS_DIR}/edgebox-init.sh
    
    cat > /etc/systemd/system/edgebox-init.service << 'INIT_SERVICE'
[Unit]
Description=EdgeBox Initialization Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/edgebox/scripts/edgebox-init.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
INIT_SERVICE

    systemctl daemon-reload
    systemctl enable edgebox-init.service >/dev/null 2>&1
    
    log_success "初始化脚本创建完成"
}

# 显示安装信息
show_installation_info() {
    clear
    print_separator
    echo -e "${GREEN}🎉 EdgeBox v3.0.1 安装完成！${NC}"
    print_separator
    
    echo -e "${CYAN}服务器信息：${NC}"
    echo -e "  IP地址: ${GREEN}${SERVER_IP}${NC}"
    echo -e "  模式: ${YELLOW}IP模式（自签名证书）${NC}"
    echo -e "  版本: ${YELLOW}EdgeBox v3.0.1 轻量级版${NC}"
    
    echo -e "\n${CYAN}协议信息：${NC}"
    echo -e "  ${PURPLE}[1] VLESS-Reality${NC}  端口: 443"
    echo -e "  ${PURPLE}[2] VLESS-gRPC${NC}     端口: 443"
    echo -e "  ${PURPLE}[3] VLESS-WS${NC}       端口: 443"
    echo -e "  ${PURPLE}[4] Hysteria2${NC}      端口: 443"
    echo -e "  ${PURPLE}[5] TUIC${NC}           端口: 2053"
    
    echo -e "\n${CYAN}访问地址：${NC}"
    echo -e "  🌐 控制面板: ${YELLOW}http://${SERVER_IP}/${NC}"
    echo -e "  📱 订阅链接: ${YELLOW}http://${SERVER_IP}/sub${NC}"
    
    echo -e "\n${YELLOW}✨ v3.0.1 优化特性：${NC}"
    echo -e "  📊 轻量级监控：vnStat + nftables采集，无Python依赖"
    echo -e "  🎨 Chart.js渲染：浏览器端动态绘制流量图表"
    echo -e "  📱 整合面板：订阅与图表同页，两列布局"
    echo -e "  🔧 完整命令：edgeboxctl help直接显示所有命令"
    
    echo -e "\n${CYAN}快速命令：${NC}"
    echo -e "  ${YELLOW}edgeboxctl status${NC}                  # 查看状态"
    echo -e "  ${YELLOW}edgeboxctl sub${NC}                     # 查看订阅"
    echo -e "  ${YELLOW}edgeboxctl switch-to-domain <域名>${NC} # 切换域名"
    echo -e "  ${YELLOW}edgeboxctl shunt direct-resi IP:PORT${NC} # 智能分流"
    echo -e "  ${YELLOW}edgeboxctl help${NC}                    # 完整帮助"
    echo -e "  ${YELLOW}edgebox-uninstall${NC}                  # 完全卸载"
    
    print_separator
    echo -e "${GREEN}🚀 EdgeBox v3.0.1 轻量级部署完成！${NC}"
    echo -e "${CYAN}控制面板: http://${SERVER_IP}/${NC}"
    print_separator
}

# 清理函数
cleanup() {
    if [ "$?" -ne 0 ]; then
        log_error "安装过程中出现错误，请检查日志: ${LOG_FILE}"
        echo -e "${YELLOW}如需重新安装，请先运行: edgebox-uninstall${NC}"
    fi
    rm -f /tmp/Xray-linux-64.zip 2>/dev/null || true
    rm -f /tmp/sing-box-*.tar.gz 2>/dev/null || true
}

# 主安装流程
main() {
    clear
    print_separator
    echo -e "${GREEN}EdgeBox 轻量级安装脚本 v3.0.1${NC}"
    echo -e "${CYAN}vnStat + nftables + Chart.js 前端渲染方案${NC}"
    print_separator
    
    # 创建日志文件
    mkdir -p $(dirname ${LOG_FILE})
    touch ${LOG_FILE}
    
    # 设置错误处理
    trap cleanup EXIT
    
    echo -e "${BLUE}正在执行安装流程...${NC}"
    
    # 基础安装步骤
    check_root
    check_system
    get_server_ip
    install_dependencies
    generate_credentials
    create_directories
    check_ports
    configure_firewall
    optimize_system
    generate_self_signed_cert
    install_sing_box
    install_xray
    generate_reality_keys
    configure_nginx
    configure_xray
    configure_sing_box
    save_config_info
    start_services
    generate_subscription
    
    # 高级功能
    setup_nftables_rules
    setup_traffic_monitoring
    create_dashboard
    setup_cron_jobs
    setup_email_system
    create_init_script
    
    # 管理工具
    create_edgeboxctl
    create_uninstall_link
    
    # 启动初始化服务
    systemctl start edgebox-init.service >/dev/null 2>&1 || true
    
    # 等待服务稳定
    sleep 3
    
    # 运行一次流量采集
    if [[ -x "${SCRIPTS_DIR}/traffic-collector.sh" ]]; then
        "${SCRIPTS_DIR}/traffic-collector.sh" >/dev/null 2>&1 || true
    fi
    
    # 更新控制面板的订阅信息
    if [[ -f "${TRAFFIC_DIR}/index.html" ]]; then
        # 重新读取Base64编码
        local all_b64=$(cat ${CONFIG_DIR}/subscription.base64 2>/dev/null || echo "")
        local reality_b64=$(cat ${CONFIG_DIR}/reality.base64 2>/dev/null || echo "")
        local grpc_b64=$(cat ${CONFIG_DIR}/grpc.base64 2>/dev/null || echo "")
        local ws_b64=$(cat ${CONFIG_DIR}/ws.base64 2>/dev/null || echo "")
        local hy2_b64=$(cat ${CONFIG_DIR}/hy2.base64 2>/dev/null || echo "")
        local tuic_b64=$(cat ${CONFIG_DIR}/tuic.base64 2>/dev/null || echo "")
        
        # 更新HTML中的占位符
        sed -i "s|SUB_ALL_BASE64|${all_b64}|g" "${TRAFFIC_DIR}/index.html"
        sed -i "s|SUB_REALITY_BASE64|${reality_b64}|g" "${TRAFFIC_DIR}/index.html"
        sed -i "s|SUB_GRPC_BASE64|${grpc_b64}|g" "${TRAFFIC_DIR}/index.html"
        sed -i "s|SUB_WS_BASE64|${ws_b64}|g" "${TRAFFIC_DIR}/index.html"
        sed -i "s|SUB_HY2_BASE64|${hy2_b64}|g" "${TRAFFIC_DIR}/index.html"
        sed -i "s|SUB_TUIC_BASE64|${tuic_b64}|g" "${TRAFFIC_DIR}/index.html"
    fi
    
    # 显示安装信息
    show_installation_info
    
    log_success "EdgeBox v3.0.1 轻量级部署完成！"
    log_info "安装日志: ${LOG_FILE}"
    echo ""
    echo -e "${GREEN}🎯 立即体验：访问 http://${SERVER_IP}/ 查看控制面板${NC}"
    echo -e "${BLUE}📚 完整文档：edgeboxctl help${NC}"
}

# 执行主函数
main "$@"
