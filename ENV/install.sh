bash -c 'cat > install.sh <<'"'"'EOF'"'"'
#!/usr/bin/env bash
# =====================================================================================
# EdgeBox - 多协议节点一键部署（轻量可视化版）
# 方案：vnStat + nftables 采集（CSV/JSON） + Chart.js 前端渲染
# 协议：VLESS-gRPC / VLESS-WS / VLESS-Reality / Hysteria2 / TUIC
# 端口：tcp/443（Reality+回落gRPC/WS），udp/443（Hysteria2），udp/2053（TUIC）
# 系统：Ubuntu 20.04+/Debian 10+
# 注意：本脚本不创建卸载脚本（沿用你现有卸载脚本）
# =====================================================================================
set -euo pipefail

# -------------------- 常量 --------------------
SB_VER="v1.11.7"
XRAY_VER="v1.8.24"
SCRIPT_VER="3.0.0-lite-vnstat-nft"

WORK_DIR="/opt/edgebox"
CERT_DIR="/etc/ssl/edgebox"
XRAY_DIR="/usr/local/etc/xray"
SBOX_DIR="/etc/sing-box"
WEB_ROOT="/etc/edgebox/traffic"
NGINX_SNIPPET="/etc/edgebox/nginx/root-site.conf"
LOG_FILE="/var/log/edgebox-install.log"

# 运行状态
SHUNT_MODE_FILE="$WORK_DIR/shunt-mode"          # direct|resi
SHUNT_PROXY_FILE="$WORK_DIR/shunt-proxy"        # ip:port[:user:pass]
DOMAIN_FILE="$WORK_DIR/domain"                  # 域名或 edgebox.local

UUID_FILE="$WORK_DIR/xray-uuid"
REALITY_PK_FILE="$WORK_DIR/reality-private-key"
REALITY_PUB_FILE="$WORK_DIR/reality-public-key"
REALITY_SID_FILE="$WORK_DIR/reality-short-id"
HY2_PWD_FILE="$WORK_DIR/hy2-password"
TUIC_UUID_FILE="$WORK_DIR/tuic-uuid"
TUIC_PWD_FILE="$WORK_DIR/tuic-password"

# 便捷函数
log(){ echo -e "[INFO] $*" | tee -a "$LOG_FILE"; }
ok(){ echo -e "[SUCCESS] $*" | tee -a "$LOG_FILE"; }
warn(){ echo -e "[WARN] $*" | tee -a "$LOG_FILE"; }
die(){ echo -e "[ERROR] $*" | tee -a "$LOG_FILE"; exit 1; }

need_root(){ [[ $EUID -ne 0 ]] && die "请以 root 身份运行"; }
server_ip(){ curl -s --connect-timeout 5 https://ipv4.icanhazip.com/ | tr -d '\n\r'; }

# -------------------- 系统/依赖 --------------------
check_os(){
  grep -qiE "ubuntu|debian" /etc/os-release || die "仅支持 Debian/Ubuntu";
}
install_deps(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends \
    ca-certificates curl wget jq tar unzip openssl uuid-runtime \
    nginx libnginx-mod-stream ufw vnstat cron logrotate \
    nftables certbot python3-certbot-nginx dnsutils
  ok "依赖安装完成"
}
optimize_sysctl(){
  cat >/etc/sysctl.d/99-edgebox-bbr.conf <<'EOF2'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
EOF2
  sysctl -p /etc/sysctl.d/99-edgebox-bbr.conf >/dev/null 2>&1 || true
}

# -------------------- 安装 Xray / sing-box --------------------
install_xray(){
  log "安装 Xray ${XRAY_VER} ..."
  local url="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip"
  local t; t=$(mktemp -d)
  cd "$t"
  curl -fsSL "$url" -o x.zip
  unzip -q x.zip
  install -m755 xray /usr/local/bin/xray
  mkdir -p "$XRAY_DIR"
  install -m644 geoip.dat geosite.dat "$XRAY_DIR"/
  cd /; rm -rf "$t"
  xray version >/dev/null || die "Xray 安装失败"
  ok "Xray 安装完成"
}
install_singbox(){
  log "安装 sing-box ${SB_VER} ..."
  local url="https://github.com/SagerNet/sing-box/releases/download/${SB_VER}/sing-box-${SB_VER#v}-linux-amd64.tar.gz"
  local t; t=$(mktemp -d)
  cd "$t"
  curl -fsSL "$url" -o s.tgz
  tar -xzf s.tgz
  install -m755 sing-box-*/sing-box /usr/local/bin/sing-box
  cd /; rm -rf "$t"
  sing-box version >/dev/null || die "sing-box 安装失败"
  ok "sing-box 安装完成"
}

# -------------------- 证书 --------------------
prepare_cert(){
  mkdir -p "$CERT_DIR"
  if [[ ! -f "$CERT_DIR/cert.pem" || ! -f "$CERT_DIR/key.pem" ]]; then
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
      -subj "/CN=edgebox.local" >/dev/null 2>&1
    ok "已生成自签名证书"
  fi
}

# -------------------- 初始化材料 --------------------
gen_materials(){
  mkdir -p "$WORK_DIR" "$WEB_ROOT" "$WEB_ROOT/logs" /etc/edgebox/nginx /etc/edgebox/scripts
  echo "edgebox.local" >"$DOMAIN_FILE"
  uuidgen >"$UUID_FILE"
  local kp; kp=$(sing-box generate reality-keypair)
  echo "$kp" | awk '/PrivateKey/{print $2}' >"$REALITY_PK_FILE"
  echo "$kp" | awk '/PublicKey/{print $2}'  >"$REALITY_PUB_FILE"
  openssl rand -hex 8 >"$REALITY_SID_FILE"
  openssl rand -hex 16 >"$HY2_PWD_FILE"
  uuidgen >"$TUIC_UUID_FILE"
  openssl rand -hex 16 >"$TUIC_PWD_FILE"
  echo "direct" >"$SHUNT_MODE_FILE"; : >"$SHUNT_PROXY_FILE"
}

# -------------------- 生成配置 --------------------
render_xray_config(){
  local uuid=$(cat "$UUID_FILE")
  local priv=$(cat "$REALITY_PK_FILE")
  local sid=$(cat "$REALITY_SID_FILE")

  local outbounds routing
  if [[ "$(cat "$SHUNT_MODE_FILE")" == "resi" && -s "$SHUNT_PROXY_FILE" ]]; then
    local hp user pass host port
    IFS=':' read -r hp user pass < <(cat "$SHUNT_PROXY_FILE")
    host="${hp%:*}"; port="${hp##*:}"
    outbounds=$(cat <<EOF3
[
  {"protocol":"freedom","tag":"direct"},
  {"protocol":"http","tag":"proxy","settings":{"servers":[{"address":"$host","port":$port$( [[ -n "${user:-}" && -n "${pass:-}" ]] && printf ', "users":[{"user":"%s","pass":"%s"}]' "$user" "$pass" )}] }}
]
EOF3
)
    routing='{"domainStrategy":"AsIs","rules":[{"type":"field","domain":["domain:googlevideo.com","domain:ytimg.com","domain:ggpht.com"],"outboundTag":"direct"},{"type":"field","outboundTag":"proxy"}]}'
  else
    outbounds='[{"protocol":"freedom","tag":"direct"}]'
    routing='{"domainStrategy":"AsIs"}'
  fi

  mkdir -p "$XRAY_DIR"
  cat >"$XRAY_DIR/config.json" <<EOF4
{
  "log":{"loglevel":"warning"},
  "inbounds":[
    {
      "tag":"VLESS-Reality","listen":"0.0.0.0","port":443,"protocol":"vless",
      "settings":{"clients":[{"id":"$uuid","flow":"xtls-rprx-vision"}],"decryption":"none","fallbacks":[{"dest":10443}]},
      "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"show":false,"dest":"www.cloudflare.com:443","xver":0,"serverNames":["www.cloudflare.com","www.microsoft.com","www.apple.com"],"privateKey":"$priv","shortIds":["$sid"]}}
    },
    {
      "tag":"VLESS-gRPC-Internal","listen":"127.0.0.1","port":10085,"protocol":"vless",
      "settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},
      "streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"alpn":["h2"],"certificates":[{"certificateFile":"$CERT_DIR/cert.pem","keyFile":"$CERT_DIR/key.pem"}]},"grpcSettings":{"serviceName":"grpc"}}
    },
    {
      "tag":"VLESS-WS-Internal","listen":"127.0.0.1","port":10086,"protocol":"vless",
      "settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},
      "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"alpn":["http/1.1"],"certificates":[{"certificateFile":"$CERT_DIR/cert.pem","keyFile":"$CERT_DIR/key.pem"}]},"wsSettings":{"path":"/ws"}}
    }
  ],
  "outbounds": $outbounds,
  "routing": $routing
}
EOF4
  /usr/local/bin/xray run -test -config "$XRAY_DIR/config.json" >/dev/null
}

render_singbox_config(){
  local hy2=$(cat "$HY2_PWD_FILE")
  local tuic_uuid=$(cat "$TUIC_UUID_FILE")
  local tuic_pwd=$(cat "$TUIC_PWD_FILE")

  local outbounds routing
  if [[ "$(cat "$SHUNT_MODE_FILE")" == "resi" && -s "$SHUNT_PROXY_FILE" ]]; then
    local hp user pass host port
    IFS=':' read -r hp user pass < <(cat "$SHUNT_PROXY_FILE")
    host="${hp%:*}"; port="${hp##*:}"
    outbounds=$(cat <<EOF5
[
  {"type":"direct","tag":"direct"},
  {"type":"http","tag":"proxy","server":{"address":"$host","port":$port$( [[ -n "${user:-}" && -n "${pass:-}" ]] && printf ', "username":"%s","password":"%s"' "$user" "$pass" )}}
]
EOF5
)
    routing='{"rules":[{"type":"logical","mode":"or","rules":[{"type":"field","domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"]}],"outbound":"direct"},{"type":"default","outbound":"proxy"}]}'
  else
    outbounds='[{"type":"direct","tag":"direct"}]'; routing='{}'
  fi

  mkdir -p "$SBOX_DIR"
  cat >"$SBOX_DIR/config.json" <<EOF6
{
  "log":{"level":"info","timestamp":true},
  "inbounds":[
    {"type":"hysteria2","tag":"hysteria2","listen":"::","listen_port":443,"users":[{"password":"$hy2"}],
     "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"$CERT_DIR/cert.pem","key_path":"$CERT_DIR/key.pem"}},
    {"type":"tuic","tag":"tuic","listen":"::","listen_port":2053,
     "users":[{"uuid":"$tuic_uuid","password":"$tuic_pwd"}],"congestion_control":"bbr","auth_timeout":"3s",
     "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"$CERT_DIR/cert.pem","key_path":"$CERT_DIR/key.pem"}}
  ],
  "outbounds": $outbounds,
  "route": $routing
}
EOF6
  /usr/local/bin/sing-box check -c "$SBOX_DIR/config.json" >/dev/null
}

render_nginx(){
  mkdir -p "$(dirname "$NGINX_SNIPPET")"
  cat >"$NGINX_SNIPPET" <<EOF7
server {
  listen 80;
  server_name _;
  root $WEB_ROOT;
  index index.html;
  add_header Cache-Control "no-store";
  location ~* \.(txt|json)$ {
    add_header Access-Control-Allow-Origin "*";
    default_type text/plain;
  }
}
EOF7

  cat >/etc/nginx/nginx.conf <<'EOF8'
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events { worker_connections 1024; }

http {
  include       /etc/nginx/mime.types;
  default_type  text/html;
  sendfile        on;
  keepalive_timeout  65;
  include /etc/nginx/conf.d/*.conf;
  include /etc/edgebox/nginx/*.conf;
}

stream {
  map $ssl_preread_alpn_protocols $upstream {
    ~h2        127.0.0.1:10085;
    ~http/1.1  127.0.0.1:10086;
    default    127.0.0.1:10086;
  }
  server {
    listen 127.0.0.1:10443 ssl_preread;
    proxy_pass $upstream;
    proxy_connect_timeout 5s;
    proxy_timeout 15s;
  }
}
EOF8
  nginx -t >/dev/null
}

# -------------------- systemd 服务 --------------------
install_services(){
  cat >/etc/systemd/system/xray.service <<EOF9
[Unit]
Description=Xray service
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config $XRAY_DIR/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF9
  cat >/etc/systemd/system/sing-box.service <<EOF10
[Unit]
Description=sing-box service
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c $SBOX_DIR/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF10
}

# -------------------- nftables 只做计数 --------------------
install_nft_counters(){
  nft list table inet edgebox >/dev/null 2>&1 && return 0
  nft -f - <<'NFT'
table inet edgebox {
  counters {
    c_tcp443 {}
    c_udp443 {}
    c_udp2053 {}
    c_resi_out {}
  }
  sets {
    resi_addr { type ipv4_addr; }
    resi_port { type inet_service; }
  }
  chain edge_input {
    type filter hook input priority 0; policy accept;
    tcp dport 443  counter name c_tcp443
    udp dport 443  counter name c_udp443
    udp dport 2053 counter name c_udp2053
  }
  chain edge_output {
    type filter hook output priority 0; policy accept;
    ip daddr @resi_addr tcp dport @resi_port counter name c_resi_out
  }
}
NFT
  ok "nftables 计数器完成"
}

# -------------------- 防火墙 --------------------
setup_firewall(){
  ufw allow 22/tcp >/dev/null 2>&1 || true
  ufw allow 80/tcp  >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw allow 443/udp >/dev/null 2>&1 || true
  ufw allow 2053/udp >/dev/null 2>&1 || true
  echo "y" | ufw enable >/dev/null 2>&1 || true
}

# -------------------- 控制面板（HTML + JS） --------------------
install_panel(){
  mkdir -p "$WEB_ROOT/assets/js"
  curl -fsSL https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js -o "$WEB_ROOT/assets/js/chart.min.js" || true

  cat >"$WEB_ROOT/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>EdgeBox 控制面板</title>
<link rel="preconnect" href="https://cdn.jsdelivr.net">
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial;background:#0f1220;margin:0}
  .wrap{max-width:1100px;margin:24px auto;background:#fff;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.2);padding:22px}
  h1{margin:0 0 12px;font-size:22px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .card{background:#f6f7fb;border-radius:12px;padding:14px}
  .muted{color:#666}
  textarea{width:100%;min-height:76px;font-family:ui-monospace,Consolas,monospace;font-size:12px}
  .row{display:flex;gap:8px;align-items:center}
  .btn{padding:6px 10px;border:0;border-radius:8px;background:#6366f1;color:#fff;cursor:pointer}
  .btn:active{transform:scale(.98)}
  .tag{display:inline-block;background:#eef;border-radius:6px;padding:2px 8px;margin-right:6px;font-size:12px}
  table{width:100%;border-collapse:collapse}
  th,td{border-bottom:1px solid #eee;padding:6px 8px;text-align:right}
  th:first-child,td:first-child{text-align:left}
  canvas{width:100%!important;height:260px!important;background:#fff;border-radius:8px}
</style>
</head>
<body>
<div class="wrap">
  <h1>🚀 EdgeBox 控制面板</h1>

  <div class="grid">
    <div class="card">
      <div class="muted">服务器信息</div>
      <div>服务器 IP/域名：<b id="host">-</b></div>
      <div>证书模式：<b id="cert">-</b></div>
      <div>分流状态：<b id="shunt">-</b></div>
      <div class="muted" style="margin-top:8px">协议支持：
        <span class="tag">Reality</span>
        <span class="tag">gRPC</span>
        <span class="tag">WS</span>
        <span class="tag">Hysteria2</span>
        <span class="tag">TUIC</span>
      </div>
    </div>

    <div class="card">
      <div class="muted">快速操作（复制到 SSH 执行）</div>
      <div class="grid" style="grid-template-columns:1fr 1fr; gap:8px; margin-top:6px">
        <textarea readonly>edgeboxctl status</textarea>
        <textarea readonly>edgeboxctl sub</textarea>
        <textarea readonly>edgeboxctl switch-to-domain your.domain.com</textarea>
        <textarea readonly>edgeboxctl switch-to-ip</textarea>
        <textarea readonly>edgeboxctl shunt apply IP:PORT[:user:pass]</textarea>
        <textarea readonly>edgeboxctl shunt clear</textarea>
        <textarea readonly>edgeboxctl traffic show</textarea>
        <textarea readonly>edgeboxctl logs</textarea>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:16px">
    <div class="muted">订阅链接</div>
    <div style="margin-top:8px"><b>聚合 Base64（五协议一体）</b></div>
    <div class="row"><textarea id="b64_all" readonly></textarea><button class="btn" onclick="copy('b64_all')">复制</button></div>

    <div style="margin-top:8px"><b>明文链接（便于检查）</b></div>
    <div class="row"><textarea id="plain" readonly></textarea><button class="btn" onclick="copy('plain')">复制</button></div>

    <div style="margin-top:8px"><b>逐协议 Base64（单条分享）</b></div>
    <div class="grid" style="grid-template-columns:1fr 1fr;gap:8px">
      <div><div class="muted">gRPC</div><textarea id="b64_grpc" readonly></textarea><button class="btn" onclick="copy('b64_grpc')">复制</button></div>
      <div><div class="muted">WS</div><textarea id="b64_ws" readonly></textarea><button class="btn" onclick="copy('b64_ws')">复制</button></div>
      <div><div class="muted">Reality</div><textarea id="b64_re" readonly></textarea><button class="btn" onclick="copy('b64_re')">复制</button></div>
      <div><div class="muted">Hysteria2</div><textarea id="b64_hy2" readonly></textarea><button class="btn" onclick="copy('b64_hy2')">复制</button></div>
      <div><div class="muted">TUIC</div><textarea id="b64_tuic" readonly></textarea><button class="btn" onclick="copy('b64_tuic')">复制</button></div>
    </div>
  </div>

  <div class="grid" style="margin-top:16px">
    <div class="card">
      <div class="muted">日曲线：分流出站口</div>
      <canvas id="dayShunt"></canvas>
    </div>
    <div class="card">
      <div class="muted">日曲线：高流量端口</div>
      <canvas id="dayPorts"></canvas>
    </div>
  </div>

  <div class="card" style="margin-top:16px">
    <div class="muted">最近 12 个月累计</div>
    <table id="mtb">
      <thead><tr><th>月份</th><th>总量 (GiB)</th><th>VPS直出</th><th>住宅直出</th><th>TCP/443</th><th>UDP/443</th><th>UDP/2053</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
</div>

<script src="/assets/js/chart.min.js"></script>
<script>
function copy(id){const t=document.getElementById(id);t.select();document.execCommand('copy');}
async function loadText(id, url){ try{ const t = await (await fetch(url,{cache:'no-store'})).text(); document.getElementById(id).value = t.trim(); }catch(e){} }
async function loadJSON(url){ try{ return await (await fetch(url,{cache:'no-store'})).json(); }catch(e){ return null; } }
(async ()=>{
  const s = await loadJSON('/status.json');
  if(s){ host.textContent=s.host; cert.textContent=s.cert_mode; shunt.textContent=s.shunt_mode; }
  await loadText('plain','/sub.txt');
  await loadText('b64_all','/sub_base64_all.txt');
  await loadText('b64_grpc','/b64_grpc.txt');
  await loadText('b64_ws','/b64_ws.txt');
  await loadText('b64_re','/b64_reality.txt');
  await loadText('b64_hy2','/b64_hy2.txt');
  await loadText('b64_tuic','/b64_tuic.txt');

  const data = await loadJSON('/traffic-all.json'); if(!data) return;

  const labels = data.day.map(d=>d.ts.slice(5,16));
  const vps_out = data.day.map(d => Math.max((d.total||0) - (d.resi_out||0), 0) / (1024*1024));
  const resi_out = data.day.map(d => (d.resi_out||0) / (1024*1024));
  new Chart(document.getElementById('dayShunt'),{
    type:'line', data:{labels,datasets:[{label:'VPS直出 (MiB)',data:vps_out},{label:'住宅直出 (MiB)',data:resi_out}]},
    options:{responsive:true,maintainAspectRatio:false}
  });

  const labels2 = data.ports.map(d=>d.ts.slice(5,16));
  const t443 = data.ports.map(d => (d.tcp443||0)/(1024*1024));
  const u443 = data.ports.map(d => (d.udp443||0)/(1024*1024));
  const u2053= data.ports.map(d => (d.udp2053||0)/(1024*1024));
  new Chart(document.getElementById('dayPorts'),{
    type:'line',
    data:{labels:labels2,datasets:[{label:'TCP/443 (MiB)',data:t443},{label:'UDP/443 (MiB)',data:u443},{label:'UDP/2053 (MiB)',data:u2053}]},
    options:{responsive:true,maintainAspectRatio:false}
  });

  const tb=document.querySelector('#mtb tbody'); tb.innerHTML='';
  for(const r of data.monthly){
    const gi=(x)=> (x/(1024*1024*1024)).toFixed(2);
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${r.ym}</td><td>${gi(r.total||0)}</td><td>${gi(r.vps_out||0)}</td><td>${gi(r.resi_out||0)}</td><td>${gi(r.tcp443||0)}</td><td>${gi(r.udp443||0)}</td><td>${gi(r.udp2053||0)}</td>`;
    tb.appendChild(tr);
  }
})();
</script>
</body>
</html>
HTML
}

# -------------------- 流量采集器 + cron --------------------
install_traffic_collector(){
  cat >/etc/edgebox/scripts/traffic-collector.sh <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
BASE="/etc/edgebox/traffic"
LOGS="$BASE/logs"
STATE="$BASE/state.json"
mkdir -p "$LOGS"

json_get(){ jq -r "$1" 2>/dev/null || echo 0; }

VN_JSON=$(vnstat --json)
TOTAL_TX=$(echo "$VN_JSON" | jq '.interfaces[0].traffic.total.tx')
TOTAL_RX=$(echo "$VN_JSON" | jq '.interfaces[0].traffic.total.rx')

NFT_JSON=$(nft -j list counters table inet edgebox || echo '{}')
C_RESI=$(echo "$NFT_JSON" | jq '.nftables[]? | select(.counter.name=="c_resi_out").counter.bytes // 0')
C_TCP443=$(echo "$NFT_JSON" | jq '.nftables[]? | select(.counter.name=="c_tcp443").counter.bytes // 0')
C_UDP443=$(echo "$NFT_JSON" | jq '.nftables[]? | select(.counter.name=="c_udp443").counter.bytes // 0')
C_UDP2053=$(echo "$NFT_JSON" | jq '.nftables[]? | select(.counter.name=="c_udp2053").counter.bytes // 0')

PRE_TX=$( [ -f "$STATE" ] && json_get '.total_tx' <"$STATE" || echo 0 )
PRE_RX=$( [ -f "$STATE" ] && json_get '.total_rx' <"$STATE" || echo 0 )
PRE_RSI=$( [ -f "$STATE" ] && json_get '.resi'     <"$STATE" || echo 0 )
PRE_T443=$( [ -f "$STATE" ] && json_get '.t443'    <"$STATE" || echo 0 )
PRE_U443=$( [ -f "$STATE" ] && json_get '.u443'    <"$STATE" || echo 0 )
PRE_U2053=$( [ -f "$STATE" ] && json_get '.u2053'  <"$STATE" || echo 0 )

d_tx=$(( TOTAL_TX - PRE_TX )); d_rx=$(( TOTAL_RX - PRE_RX ))
d_rsi=$(( C_RESI - PRE_RSI )); d_t443=$(( C_TCP443 - PRE_T443 ))
d_u443=$(( C_UDP443 - PRE_U443 )); d_u2053=$(( C_UDP2053 - PRE_U2053 ))
fix(){ [ "$1" -lt 0 ] && echo 0 || echo "$1"; }
d_tx=$(fix $d_tx); d_rx=$(fix $d_rx); d_rsi=$(fix $d_rsi)
d_t443=$(fix $d_t443); d_u443=$(fix $d_u443); d_u2053=$(fix $d_u2053)

[ -f "$LOGS/daily.csv" ] || echo "ts,total,resi_out,tcp443,udp443,udp2053" >"$LOGS/daily.csv"
echo "$(date -u +%F\ %H:00:00),$((d_tx+d_rx)),$d_rsi,$d_t443,$d_u443,$d_u2053" >>"$LOGS/daily.csv"
awk -F, -v cutoff="$(date -u -d '90 days ago' +%s)" 'NR==1{print;next}{ cmd="date -u -d \""$1"\" +%s"; cmd|getline t; close(cmd); if(t>=cutoff) print }' "$LOGS/daily.csv" >"$LOGS/daily.tmp" && mv "$LOGS/daily.tmp" "$LOGS/daily.csv"

YM=$(date -u +%Y-%m)
[ -f "$LOGS/monthly.csv" ] || echo "ym,total,resi_out,vps_out,tcp443,udp443,udp2053" >"$LOGS/monthly.csv"
line=$(awk -F, -v ym="$YM" '$1==ym{print}' "$LOGS/monthly.csv")
if [ -z "$line" ]; then
  total=$((d_tx+d_rx)); vps=$(( total - d_rsi ))
  echo "$YM,$total,$d_rsi,$vps,$d_t443,$d_u443,$d_u2053" >>"$LOGS/monthly.csv"
else
  IFS=, read -r _ t r v a b c <<<"$line"
  t=$(( t + d_tx + d_rx )); r=$(( r + d_rsi )); v=$(( t - r )); a=$(( a + d_t443 )); b=$(( b + d_u443 )); c=$(( c + d_u2053 ))
  awk -F, -v OFS=, -v ym="$YM" -v t="$t" -v r="$r" -v v="$v" -v a="$a" -v b="$b" -v c="$c" 'NR==1{print;next} $1==ym{$2=t;$3=r;$4=v;$5=a;$6=b;$7=c;done=1}{if($1!=ym)print} END{if(!done) print ym,t,r,v,a,b,c}' "$LOGS/monthly.csv" >"$LOGS/monthly.tmp" && mv "$LOGS/monthly.tmp" "$LOGS/monthly.csv"
fi

DAY_JSON=$(tail -n 24 "$LOGS/daily.csv" | awk -F, 'NR==1{next}{printf("{\"ts\":\"%s\",\"total\":%s,\"resi_out\":%s}\n",$1,$2,$3)}' | jq -s '.')
PORTS_JSON=$(tail -n 24 "$LOGS/daily.csv" | awk -F, 'NR==1{next}{printf("{\"ts\":\"%s\",\"tcp443\":%s,\"udp443\":%s,\"udp2053\":%s}\n",$1,$4,$5,$6)}' | jq -s '.')
MONTH_JSON=$(tail -n 12 "$LOGS/monthly.csv" | awk -F, 'NR==1{next}{printf("{\"ym\":\"%s\",\"total\":%s,\"resi_out\":%s,\"vps_out\":%s,\"tcp443\":%s,\"udp443\":%s,\"udp2053\":%s}\n",$1,$2,$3,$4,$5,$6,$7)}' | jq -s '.')
jq -n --arg now "$(date -u +%FT%TZ)" --argjson day "$DAY_JSON" --argjson ports "$PORTS_JSON" --argjson monthly "$MONTH_JSON" '{generated_at:$now,day:$day,ports:$ports,monthly:$monthly}' >"$BASE/traffic-all.json"

jq -n --argjson tx "$TOTAL_TX" --argjson rx "$TOTAL_RX" --argjson r "$C_RESI" --argjson t "$C_TCP443" --argjson u "$C_UDP443" --argjson w "$C_UDP2053" \
  '{total_tx:$tx,total_rx:$rx,resi:$r,t443:$t,u443:$u,u2053:$w}' >"$STATE"
EOS
  chmod +x /etc/edgebox/scripts/traffic-collector.sh

  cat >/etc/cron.d/edgebox-traffic <<'EOF11'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 * * * * root /etc/edgebox/scripts/traffic-collector.sh >/dev/null 2>&1
EOF11
}

# -------------------- edgeboxctl 管理工具 --------------------
install_edgeboxctl(){
  cat >/usr/local/bin/edgeboxctl <<'CTL'
#!/usr/bin/env bash
set -euo pipefail
WORK_DIR="/opt/edgebox"
CERT_DIR="/etc/ssl/edgebox"
XRAY_DIR="/usr/local/etc/xray"
SBOX_DIR="/etc/sing-box"
WEB_ROOT="/etc/edgebox/traffic"

SM_FILE="$WORK_DIR/shunt-mode"
SP_FILE="$WORK_DIR/shunt-proxy"
DM_FILE="$WORK_DIR/domain"
UUID_FILE="$WORK_DIR/xray-uuid"
REALITY_SID_FILE="$WORK_DIR/reality-short-id"
PUBKEY_FILE="$WORK_DIR/reality-public-key"
HY2_PWD_FILE="$WORK_DIR/hy2-password"
TUIC_UUID_FILE="$WORK_DIR/tuic-uuid"
TUIC_PWD_FILE="$WORK_DIR/tuic-password"

server_ip(){ curl -s --connect-timeout 5 https://ipv4.icanhazip.com/ | tr -d '\n\r'; }
cert_mode(){ readlink -f "$CERT_DIR/cert.pem" | grep -q letsencrypt && echo "Let's Encrypt" || echo "自签名"; }
shunt_mode(){ [[ -f "$SM_FILE" ]] && cat "$SM_FILE" || echo "direct"; }

help_all(){
cat <<'HLP'
EdgeBox 管理工具 - 全部命令
  status                         查看服务与端口
  sub                            生成/刷新订阅与面板文件
  switch-to-domain <domain>      切换域名 + 申请证书 + 重启服务
  switch-to-ip                   切回 IP 模式（自签名）
  shunt apply <ip:port[:user:pass]>  启用住宅代理出站（并写入 nft sets）
  shunt clear                    关闭住宅代理出站（清空 nft sets）
  traffic show                   显示 vnStat 摘要
  traffic export                 立即运行采集器
  traffic reset                  重置 vnStat 数据库（危险）
  restart                        重启 xray/sing-box/nginx
  logs                           查看服务日志
  help                           显示本帮助
HLP
}

status(){
  echo "=== 服务 ==="
  systemctl is-active --quiet xray     && echo "✓ xray 运行中" || echo "✗ xray 停止"
  systemctl is-active --quiet sing-box && echo "✓ sing-box 运行中" || echo "✗ sing-box 停止"
  systemctl is-active --quiet nginx    && echo "✓ nginx 运行中" || echo "✗ nginx 停止"
  echo "=== 端口 ==="
  ss -lntp | grep -E ':80|:443|:10085|:10086' || true
  echo "UDP:"; ss -lnup | grep -E ':443|:2053' || true
}

sub(){
  [[ ! -f "$DM_FILE" ]] && { echo "配置缺失"; exit 1; }
  local host=$(cat "$DM_FILE")
  [[ "$host" == "edgebox.local" ]] && host=$(server_ip)

  local uuid=$(cat "$UUID_FILE")
  local sni="www.cloudflare.com"
  local pbk=$(tr -d '\n\r ' <"$PUBKEY_FILE")
  local sid=$(tr -d '\n\r ' <"$REALITY_SID_FILE")
  local insecure=1; [[ "$(cert_mode)" == "Let's Encrypt" ]] && insecure=0

  local grpc="vless://$uuid@$host:443?encryption=none&security=tls&type=grpc&serviceName=grpc&fp=chrome"$([[ $insecure == 1 ]] && echo '&allowInsecure=1')"#EdgeBox-gRPC"
  local ws="vless://$uuid@$host:443?encryption=none&security=tls&type=ws&path=/ws&host=$host&fp=chrome"$([[ $insecure == 1 ]] && echo '&allowInsecure=1')"#EdgeBox-WS"
  local re="vless://$uuid@$host:443?security=reality&encryption=none&flow=xtls-rprx-vision&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&type=tcp#EdgeBox-Reality"
  local hy2_pass=$(cat "$HY2_PWD_FILE")
  local hy2="hysteria2://$hy2_pass@$host:443?alpn=h3"$([[ $insecure == 1 ]] && echo "&insecure=1&sni=$host")"#EdgeBox-Hysteria2"
  local tuic_uuid=$(cat "$TUIC_UUID_FILE")
  local tuic_pwd=$(cat "$TUIC_PWD_FILE")
  local tuic="tuic://$tuic_uuid:$tuic_pwd@$host:2053?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$host"$([[ $insecure == 1 ]] && echo '&allowInsecure=1')"#EdgeBox-TUIC"

  local plain=$(printf "%s\n%s\n%s\n%s\n%s\n" "$re" "$grpc" "$ws" "$hy2" "$tuic")
  echo "$plain" >"$WEB_ROOT/sub.txt"
  echo -n "$plain" | base64 -w0 >"$WEB_ROOT/sub_base64_all.txt"
  echo -n "$grpc" | base64 -w0 >"$WEB_ROOT/b64_grpc.txt"
  echo -n "$ws"   | base64 -w0 >"$WEB_ROOT/b64_ws.txt"
  echo -n "$re"   | base64 -w0 >"$WEB_ROOT/b64_reality.txt"
  echo -n "$hy2"  | base64 -w0 >"$WEB_ROOT/b64_hy2.txt"
  echo -n "$tuic" | base64 -w0 >"$WEB_ROOT/b64_tuic.txt"

  jq -n --arg host "$host" --arg cert "$(cert_mode)" --arg shunt "$(shunt_mode)" \
    '{host:$host,cert_mode:$cert,shunt_mode:$shunt}' >"$WEB_ROOT/status.json"

  echo "网页:  http://$host"
  echo "订阅:  http://$host/sub.txt"
}

switch_to_domain(){
  local d="${1:-}"; [[ -z "$d" ]] && { echo "用法: edgeboxctl switch-to-domain your.domain"; exit 1; }
  echo "$d" >"$DM_FILE"
  echo "1) 解析校验:"
  local dip=$(dig +short "$d" | tail -n1); local sip=$(server_ip)
  echo "   - $d => $dip"; echo "   - 本机 => $sip"
  [[ -z "$dip" || "$dip" != "$sip" ]] && { echo "   × 域名未指向本机"; exit 1; } || echo "   ✓ 解析正确"

  echo "2) 申请证书:"
  ufw allow 80/tcp >/dev/null 2>&1 || true
  certbot certonly --nginx --non-interactive --agree-tos --email admin@"$d" -d "$d" || { echo "   × 证书申请失败"; exit 1; }
  ln -sf "/etc/letsencrypt/live/$d/fullchain.pem" "$CERT_DIR/cert.pem"
  ln -sf "/etc/letsencrypt/live/$d/privkey.pem"  "$CERT_DIR/key.pem"
  echo "   ✓ 已切换为 Let's Encrypt"

  echo "3) 渲染与重启:"
  /usr/bin/env bash -c "$(declare -f render_xray_config render_singbox_config)" 2>/dev/null || true
  systemctl restart nginx xray sing-box
  /usr/local/bin/edgeboxctl sub >/dev/null || true
  echo "   ✓ 完成"
}

switch_to_ip(){
  echo "edgebox.local" >"$DM_FILE"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj "/CN=edgebox.local" >/dev/null 2>&1 || true
  /usr/bin/env bash -c "$(declare -f render_xray_config render_singbox_config)" 2>/dev/null || true
  systemctl restart nginx xray sing-box
  /usr/local/bin/edgeboxctl sub >/dev/null || true
  echo "已切回 IP 模式（自签名）"
}

shunt_apply(){
  local p="${1:-}"; [[ -z "$p" ]] && { echo "用法: edgeboxctl shunt apply IP:PORT[:user:pass]"; exit 1; }
  echo "resi" >"$SM_FILE"; echo "$p" >"$SP_FILE"
  local host="${p%:*}"; local port="${p##*:}"
  nft flush set inet edgebox resi_addr || true
  nft add element inet edgebox resi_addr { $host } || true
  nft flush set inet edgebox resi_port || true
  nft add element inet edgebox resi_port { $port } || true
  /usr/bin/env bash -c "$(declare -f render_xray_config render_singbox_config)" 2>/dev/null || true
  systemctl restart xray sing-box
  /usr/local/bin/edgeboxctl sub >/dev/null || true
  echo "已启用住宅代理出站：$p"
}

shunt_clear(){
  echo "direct" >"$SM_FILE"; : >"$SP_FILE"
  nft flush set inet edgebox resi_addr || true
  nft flush set inet edgebox resi_port || true
  /usr/bin/env bash -c "$(declare -f render_xray_config render_singbox_config)" 2>/dev/null || true
  systemctl restart xray sing-box
  /usr/local/bin/edgeboxctl sub >/dev/null || true
  echo "已切回 VPS 直出"
}

traffic_show(){ vnstat --json | jq '.interfaces[0] | {name:.name, today:.traffic.day[-1], month:.traffic.month[-1] }' 2>/dev/null || vnstat --json; }
traffic_export(){ /etc/edgebox/scripts/traffic-collector.sh >/dev/null 2>&1 || true; echo "已导出 /etc/edgebox/traffic/traffic-all.json"; }
traffic_reset(){
  local i=$(vnstat --json | jq -r '.interfaces[0].name'); systemctl stop vnstat || true
  rm -f /var/lib/vnstat/$i; systemctl start vnstat || true; vnstat -u -i "$i" || true
  echo "vnStat 数据已重置"
}

restart(){ systemctl restart xray sing-box nginx; echo "已重启服务"; }
logs(){
  echo "=== xray ==="; journalctl -u xray -n 50 --no-pager || true
  echo; echo "=== sing-box ==="; journalctl -u sing-box -n 50 --no-pager || true
  echo; echo "=== nginx ==="; journalctl -u nginx -n 50 --no-pager || true
}

case "${1:-help}" in
  status) status ;;
  sub) sub ;;
  switch-to-domain) shift; switch_to_domain "${1:-}" ;;
  switch-to-ip) switch_to_ip ;;
  shunt) shift; case "${1:-}" in apply) shift; shunt_apply "${1:-}";; clear) shunt_clear;; *) echo "用法: edgeboxctl shunt apply <ip:port[:user:pass]> | clear";; esac ;;
  traffic) shift; case "${1:-}" in show) traffic_show;; export) traffic_export;; reset) traffic_reset;; *) echo "用法: edgeboxctl traffic show|export|reset";; esac ;;
  restart) restart ;;
  logs) logs ;;
  help|*) help_all ;;
esac
CTL
  chmod +x /usr/local/bin/edgeboxctl
}

# -------------------- systemd/服务启用与收尾 --------------------
install_services(){
  cat >/etc/systemd/system/xray.service <<EOF12
[Unit]
Description=Xray service
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config $XRAY_DIR/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF12
  cat >/etc/systemd/system/sing-box.service <<EOF13
[Unit]
Description=sing-box service
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c $SBOX_DIR/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF13
}

start_all(){
  systemctl daemon-reload
  render_xray_config
  render_singbox_config
  render_nginx
  install_nft_counters
  install_panel
  install_traffic_collector
  install_edgeboxctl
  install_services
  setup_firewall

  systemctl enable --now nginx
  systemctl enable --now xray sing-box

  /usr/local/bin/edgeboxctl sub || true
  /etc/edgebox/scripts/traffic-collector.sh || true

  local host=$(cat "$DOMAIN_FILE"); [[ "$host" == "edgebox.local" ]] && host=$(server_ip)
  echo
  echo "================ EdgeBox 安装完成 =================="
  echo "访问面板:   http://$host"
  echo "订阅明文:   http://$host/sub.txt"
  echo "Base64聚合: http://$host/sub_base64_all.txt"
  echo "---------------------------------------------------"
  echo "管理命令：edgeboxctl help  查看全部命令"
  echo "==================================================="
}

main(){
  need_root
  mkdir -p "$(dirname "$LOG_FILE")"; : >"$LOG_FILE"
  log "EdgeBox 安装开始 - $SCRIPT_VER"
  check_os
  install_deps
  optimize_sysctl
  install_xray
  install_singbox
  prepare_cert
  gen_materials
  start_all
}
main "$@"
EOF
'"
