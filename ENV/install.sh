cat > "$TRAFFIC_DIR/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EdgeBox 控制面板</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
<style>
        :root {
            --card: #fff;
            --border: #e2e8f0;
            --bg: #f8fafc;
            --muted: #64748b;
            --shadow: 0 4px 6px -1px rgba(0,0,0,.1);
            --primary: #3b82f6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
        }

        * { box-sizing: border-box; }
        
        body {
            font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
            background: var(--bg);
            color: #334155;
            margin: 0;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .grid {
            display: grid;
            gap: 16px;
            margin-bottom: 16px;
        }

        .grid-full { grid-template-columns: 1fr; }
        .grid-4-8 { 
            grid-template-columns: 1fr 2fr;
        }
        
        @media(max-width:980px) {
            .grid-4-8 { grid-template-columns: 1fr; }
        }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: var(--shadow);
            overflow: hidden;
            position: relative;
        }

        .card h3 {
            margin: 0;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 1.5rem;
            font-weight: 700;
            color: #0f172a;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .info-block h4,
        .command-section h4,
        .chart-title {
            margin: 0 0 8px 0;
            font-size: 1.125rem;
            font-weight: 600;
            color: #1e293b;
        }

        .chart-title {
            text-align: center;
            margin: 0 0 10px 0;
        }

        .chart-title .unit {
            font-size: .875rem;
            font-weight: 400;
            color: #64748b;
        }

        .card .content { padding: 16px; }

        .table th {
            font-size: 1rem;
            font-weight: 600;
            color: #374151;
        }

        .table {
            width: 100%;
            border-collapse: collapse;
        }

        .table th {
            text-align: left;
            padding: 12px 8px;
            border-bottom: 1px solid var(--border);
        }

        .table th:last-child {
            text-align: center;
        }

        .table td {
            font-size: .875rem;
            font-weight: 400;
            color: #64748b;
            padding: 12px 8px;
            border-bottom: 1px solid #e2e8f0;
        }

        .table td:last-child {
            text-align: center;
        }

        .system-progress-bar {
            display: inline-flex;
            align-items: center;
            width: 80px;
            height: 20px;
            background: #e2e8f0;
            border-radius: 10px;
            overflow: hidden;
            margin-left: 8px;
            position: relative;
        }

        .system-progress-fill {
            height: 100%;
            background: #10b981;
            border-radius: 10px;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            min-width: 20px;
        }

        .system-progress-text {
            position: absolute;
            left: 50%;
            top: 50%;
            transform: translate(-50%, -50%);
            color: white;
            font-size: .75rem;
            font-weight: 600;
            text-shadow: 0 1px 2px rgba(0,0,0,0.3);
            z-index: 1;
        }

        .progress-bar {
            width: 100%;
            height: 20px;
            background: #e2e8f0;
            border-radius: 8px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: #10b981;
            border-radius: 8px;
            transition: width 0.3s;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .progress-percentage {
            position: absolute;
            color: white;
            font-size: .75rem;
            font-weight: 600;
            text-shadow: 0 1px 2px rgba(0,0,0,0.3);
        }

        .protocol-status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: .75rem;
            font-weight: 600;
            background: #10b981;
            color: white;
            border: none;
        }

        .service-status-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 10px;
            font-size: .75rem;
            font-weight: 600;
            background: #10b981;
            color: white;
            border: none;
        }

        .service-status-badge.inactive {
            background: #6b7280;
        }

        .status-badge {
            padding: 4px 10px;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            background: #e2e8f0;
            color: #64748b;
            white-space: nowrap;
            font-size: 1rem;
            font-weight: 600;
            height: 28px;
            display: inline-flex;
            align-items: center;
            line-height: 1;
        }

        .status-badge.active {
            background: #10b981;
            color: white;
            border-color: #10b981;
        }

        .small,
        .info-block .value,
        .btn,
        .badge,
        .notification-bell,
        .notification-item,
        .sub-label,
        .sub-input,
        .sub-copy-btn,
        .command-list,
        .config-note {
            font-size: .875rem;
            font-weight: 400;
            color: #64748b;
        }

        .detail-link {
            color: var(--primary);
            cursor: pointer;
            text-decoration: underline;
            font-size: .875rem;
            font-weight: 400;
        }

        .detail-link:hover { color: #2563eb; }

        .status-running {
            color: #10b981 !important;
            font-size: .875rem;
            font-weight: 600 !important;
        }

        .btn {
            padding: 8px 16px;
            border: 1px solid var(--border);
            background: #f1f5f9;
            border-radius: 6px;
            cursor: pointer;
            white-space: nowrap;
        }

        .btn:hover { background: #e2e8f0; }

        .info-blocks {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }

        .info-block {
            padding: 12px;
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 8px;
        }

        .info-block .value {
            margin-bottom: 2px;
        }

        .notification-bell {
            position: relative;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 4px 8px;
            border-radius: 6px;
            background: #f1f5f9;
        }

        .notification-bell:hover { background: #e2e8f0; }
        .notification-bell.has-alerts { color: var(--warning); background: #fef3c7; }

        .notification-popup {
            position: absolute;
            top: 100%;
            right: 0;
            background: white;
            border: 1px solid var(--border);
            border-radius: 8px;
            box-shadow: var(--shadow);
            width: 300px;
            max-height: 200px;
            overflow-y: auto;
            z-index: 100;
            display: none;
        }

        .notification-popup.show { display: block; }

        .notification-item {
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
        }

        .notification-item:last-child { border-bottom: none; }

        .cert-status {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }

        .network-status {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }

        .network-blocks {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 12px;
            margin-top: 12px;
        }
        
        @media(max-width:980px) {
            .network-blocks { grid-template-columns: 1fr; }
        }
        
        .network-block {
            padding: 12px;
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 8px;
        }
        
        .network-block h5 {
            margin: 0 0 8px 0;
            font-size: 1rem;
            font-weight: 600;
            color: #1e293b;
        }

        .network-note {
            margin-top: 16px;
            padding: 8px;
            border-top: 1px solid var(--border);
            background: linear-gradient(180deg, rgba(248,250,252,0.6), rgba(248,250,252,1));
            border-radius: 4px;
            font-size: .75rem;
            line-height: 1.4;
            color: #64748b;
        }

        .sub-row {
            display: flex;
            gap: 8px;
            align-items: stretch;
            margin-bottom: 8px;
            height: 32px;
        }

        .sub-input {
            flex: 1;
            height: 100%;
            padding: 6px 10px;
            box-sizing: border-box;
            border: 1px solid var(--border);
            border-radius: 4px;
            font-family: monospace;
            background: #fff;
            font-size: .875rem;
            line-height: 20px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            resize: none;
            display: inline-block;
            vertical-align: middle;
            color: #64748b;
        }

        .sub-copy-btn {
            min-width: 80px;
            padding: 6px 12px;
            border: 1px solid var(--border);
            background: #f1f5f9;
            border-radius: 4px;
            cursor: pointer;
            font-size: .875rem;
            color: #64748b;
            font-weight: 400;
            height: 100%;
            box-sizing: border-box;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }

        .sub-copy-btn:hover { 
            background: #e2e8f0; 
        }

        .traffic-card { position: relative; }

        .traffic-progress-container {
            position: absolute;
            top: 16px;
            right: 16px;
            width: 390px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .progress-wrapper {
            flex: 1;
            position: relative;
        }

        .progress-budget {
            white-space: nowrap;
            font-size: .75rem;
        }

        .progress-label {
            white-space: nowrap;
            font-size: 1rem;
            font-weight: 600;
            color: #374151;
        }

        .traffic-charts {
            display: grid;
            grid-template-columns: 1fr 400px;
            gap: 16px;
            margin-top: 50px;
        }

        @media(max-width:980px) {
            .traffic-charts { 
                grid-template-columns: 1fr; 
                margin-top: 20px;
            }
            .traffic-progress-container {
                position: static;
                width: 100%;
                margin-bottom: 16px;
            }
        }

        .chart-container {
            position: relative;
            height: 360px;
            width: 100%;
        }

        @media(max-width:768px) {
            .chart-container {
                height: 280px;
            }
        }

        .commands-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        @media(max-width:768px) {
            .commands-grid { grid-template-columns: 1fr; }
        }

        .command-section {
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
        }

        .command-section h4 {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .command-list {
            line-height: 1.6;
        }

        .command-list code {
            background: #e2e8f0;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: .75rem;
            color: #1e293b;
        }

        .command-list span {
            color: var(--muted);
            margin-left: 8px;
        }

        .command-list small {
            display: block;
            margin-top: 2px;
            color: var(--muted);
            font-style: normal;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }

        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: white;
            border-radius: 12px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1);
        }

        .modal-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h3 {
            margin: 0;
            font-size: 1.1rem;
            font-weight: 600;
            color: #374151;
        }

        .modal-close {
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--muted);
            line-height: 1;
        }

        .modal-close:hover { color: #1e293b; }

        .modal-body { padding: 20px; }

        .config-item {
            margin-bottom: 16px;
            padding: 12px;
            background: #f8fafc;
            border-radius: 8px;
        }

        .config-item h4 {
            margin: 0 0 8px 0;
            font-size: 1rem;
            font-weight: 600;
            color: #374151;
        }

        .config-item code {
            display: block;
            background: #1e293b;
            color: #10b981;
            padding: 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: .875rem;
            word-break: break-all;
            margin: 4px 0;
        }

        .config-note {
            color: var(--warning);
            margin-top: 4px;
        }

        .whitelist-content {
            max-height: 3em;
            overflow: hidden;
            position: relative;
        }

        .whitelist-content.expanded {
            max-height: none;
        }

        .whitelist-content::after {
            content: "";
            position: absolute;
            left: 0; right: 0; bottom: 0;
            height: 24px;
            background: linear-gradient(180deg, rgba(255,255,255,0), rgba(255,255,255,1));
        }

        .whitelist-content.expanded::after {
            display: none;
        }
    </style>
</head>
<body>
<div class="container">

  <!-- 第一行：概览信息 -->
  <div class="grid grid-full">
    <div class="card">
      <h3 class="main-title">
        🌐EdgeBox-企业级多协议节点 (Control Panel)
        <div class="notification-bell" id="notif-bell" onclick="toggleNotifications()">
          🔔 <span id="notif-count">0</span>
          <div class="notification-popup" id="notif-popup">
            <div id="notif-list">暂无通知</div>
          </div>
        </div>
      </h3>
      <div class="content">
        <div class="info-blocks">
          <div class="info-block">
            <h4>📊 服务器信息</h4>
            <div class="value">用户备注名: <span id="user-alias">—</span></div>
            <div class="value">云厂商/区域: <span id="cloud-provider">—</span></div>
            <div class="value">Instance ID: <span id="instance-id">—</span></div>
            <div class="value">主机名: <span id="hostname">—</span></div>
          </div>
          
          <div class="info-block">
            <h4>⚙️ 服务器配置</h4>
            <div class="value">
              CPU: 
              <span class="system-progress-bar">
                <div class="system-progress-fill" id="cpu-progress-fill" style="width: 0%"></div>
                <span class="system-progress-text" id="cpu-progress-text">0%</span>
              </span>
              <span class="small" id="cpu-detail">—</span>
            </div>
            <div class="value">
              内存: 
              <span class="system-progress-bar">
                <div class="system-progress-fill" id="mem-progress-fill" style="width: 0%"></div>
                <span class="system-progress-text" id="mem-progress-text">0%</span>
              </span>
              <span class="small" id="mem-detail">—</span>
            </div>
            <div class="value">
              磁盘: 
              <span class="system-progress-bar">
                <div class="system-progress-fill" id="disk-progress-fill" style="width: 0%"></div>
                <span class="system-progress-text" id="disk-progress-text">0%</span>
              </span>
              <span class="small" id="disk-detail">—</span>
            </div>
          </div>
          
          <div class="info-block">
            <h4>🔧 核心服务</h4>
            <div class="value">Nginx: <span id="nginx-status">—</span> <span class="small" id="nginx-version">—</span></div>
            <div class="value">Xray: <span id="xray-status">—</span> <span class="small" id="xray-version">—</span></div>
            <div class="value">Sing-box: <span id="singbox-status">—</span> <span class="small" id="singbox-version">—</span></div>
          </div>
        </div>
        <div class="small">版本号: <span id="ver">—</span> | 安装日期: <span id="inst">—</span> | 更新时间: <span id="updated">—</span></div>
      </div>
    </div>
  </div>

  <!-- 第二行：证书切换 + 网络身份配置 -->
  <div class="grid grid-4-8">
    <!-- 证书切换 -->
    <div class="card">
      <h3>🔐 证书切换</h3>
      <div class="content">
<div class="cert-status">
  <span class="status-badge active" id="cert-status-self">自签证书</span>
  <span class="status-badge" id="cert-status-ca">CA证书</span>
</div>
        <div>
          <div class="small">证书类型: <span id="cert-type">—</span></div>
          <div class="small">绑定域名: <span id="cert-domain">—</span></div>
          <div class="small">续期方式: <span id="cert-renewal">—</span></div>
          <div class="small">到期日期: <span id="cert-expire">—</span></div>
        </div>
      </div>
    </div>

    <!-- 网络身份配置 -->
    <div class="card">
      <h3>🌐 网络身份配置</h3>
      <div class="content">
<div class="network-status">
  <span class="status-badge active">VPS出站IP</span>
  <span class="status-badge">代理出站IP</span>
  <span class="status-badge">分流出站</span>
</div>
        
        <!-- 三个区块并排显示 -->
        <div class="network-blocks">
          <!-- VPS出站IP内容 -->
          <div class="network-block">
            <h5>📡 VPS出站IP</h5>
            <div class="small">公网身份: <span class="status-running">直连</span></div>
            <div class="small">VPS出站IP: <span id="vps-out-ip">—</span></div>
            <div class="small">Geo: <span id="vps-geo">—</span></div>
            <div class="small">IP质量检测: <span id="vps-quality">—</span> <span class="detail-link" onclick="showIPQDetails('vps')">详情</span></div>
          </div>
          
          <!-- 代理出站IP内容 -->
          <div class="network-block">
            <h5>🔄 代理出站IP</h5>
            <div class="small">代理身份: <span class="status-running">全代理</span></div>
            <div class="small">代理出站IP: <span id="proxy-out-ip">—</span></div>
            <div class="small">Geo: <span id="proxy-geo">—</span></div>
            <div class="small">IP质量检测: <span id="proxy-quality">—</span> <span class="detail-link" onclick="showIPQDetails('proxy')">详情</span></div>
          </div>
          
          <!-- 分流出站内容 -->
          <div class="network-block">
            <h5>🔀 分流出站</h5>
            <div class="small">混合身份: <span class="status-running">VPS直连 + 代理</span></div>
            <div class="small">白名单: 
              <div class="whitelist-content" id="whitelist-content">
                <span id="whitelist-text">—</span>
              </div>
              <span class="detail-link" id="whitelist-toggle" onclick="toggleWhitelist()">查看全部</span>
            </div>
          </div>
        </div>
        
        <div class="network-note">
          注：HY2/TUIC 为 UDP通道，VPS直连，不走代理分流
        </div>
      </div>
    </div>
  </div>

  <!-- 第三行：协议配置 -->
  <div class="grid grid-full">
    <div class="card">
      <h3>📡 协议配置</h3>
      <div class="content">
        <table class="table" id="proto">
          <thead><tr><th>协议名称</th><th>网络</th><th>伪装效果</th><th>适用场景</th><th>运行状态</th><th>客户端配置</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- 订阅链接 -->
  <div class="grid grid-full">
    <div class="card">
      <h3>📋 订阅链接</h3>
      <div class="content">
        <div class="sub-row">
          <div class="sub-label">明文链接:</div>
          <textarea id="sub-plain" class="sub-input" readonly></textarea>
          <button class="sub-copy-btn" onclick="copySub('plain')">复制</button>
        </div>
		
		<div class="sub-row">
          <div class="sub-label">B64换行:</div>
          <textarea id="sub-b64lines" class="sub-input" readonly></textarea>
          <button class="sub-copy-btn" onclick="copySub('b64lines')">复制</button>
        </div>
		
        <div class="sub-row">
          <div class="sub-label">Base64:</div>
          <textarea id="sub-b64" class="sub-input" readonly></textarea>
          <button class="sub-copy-btn" onclick="copySub('b64')">复制</button>
        </div>

      </div>
    </div>
  </div>

  <!-- 流量统计 -->
  <div class="grid grid-full">
    <div class="card traffic-card">
      <h3>📊 流量统计
        <div class="traffic-progress-container">
          <span class="progress-label">本月累计/阈值:</span>
          <div class="progress-wrapper">
            <div class="progress-bar">
              <div class="progress-fill" id="progress-fill" style="width:0%">
                <span class="progress-percentage" id="progress-percentage">0%</span>
              </div>
            </div>
          </div>
          <span class="progress-budget" id="progress-budget">0/100GiB</span>
        </div>
      </h3>
      <div class="content">
        <div class="traffic-charts">
          <div class="chart-container">
            <h4 class="chart-title">近30日出站流量 <span class="unit">(GiB)</span></h4>
            <canvas id="traffic"></canvas>
          </div>
          <div class="chart-container">
            <h4 class="chart-title">近12个月累计流量 <span class="unit">(GiB)</span></h4>
            <canvas id="monthly-chart"></canvas>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 运维管理 -->
  <div class="grid grid-full">
    <div class="card"><h3>🔧 运维管理</h3>
      <div class="content">
        <div class="commands-grid">
          <div class="command-section">
            <h4>🔧 基础操作</h4>
            <div class="command-list">
              <code>edgeboxctl sub</code> <span># 动态生成当前模式下的订阅链接</span><br>
              <code>edgeboxctl logs &lt;svc&gt;</code> <span># 查看指定服务的实时日志</span><br>
              <code>edgeboxctl status</code> <span># 查看所有核心服务运行状态</span><br>
              <code>edgeboxctl restart</code> <span># 安全地重启所有服务</span><br>
            </div>
          </div>
          
          <div class="command-section">
            <h4>🔐 证书管理</h4>
            <div class="command-list">
              <code>edgeboxctl switch-to-domain &lt;your_domain&gt;</code> <span># 切换到域名模式，申请证书</span><br>
              <code>edgeboxctl switch-to-ip</code> <span># 回退到IP模式，使用自签名证书</span><br>
              <code>edgeboxctl cert status</code> <span># 检查当前证书的到期日期和类型</span><br>
              <code>edgeboxctl cert renew</code> <span># 手动续期Let's Encrypt证书</span>
            </div>
          </div>
          
          <div class="command-section">
            <h4>🔀 出站分流</h4>
            <div class="command-list">
              <code>edgeboxctl shunt vps</code> <span> # 切换至VPS全量出站</span><br>
              <code>edgeboxctl shunt resi &lt;URL&gt;</code> <span> # 配置并切换至住宅IP全量出站</span><br>
              <code>edgeboxctl shunt direct-resi &lt;URL&gt;</code> <span> # 配置并切换至白名单智能分流状态</span><br>
              <code>edgeboxctl shunt whitelist &lt;add|remove|list&gt;</code> <span> # 管理白名单域名</span><br>
              <code>代理URL格式:</code><br>
              <code>http://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;</code><br>
              <code>https://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;?sni=</code><br>
              <code>socks5://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;</code><br>
              <code>socks5s://user:pass@&lt;IP或域名&gt;:&lt;端口&gt;?sni=</code><br>
              <code>示例：edgeboxctl shunt resi 'socks5://user:pass@111.222.333.444:11324'</code>
            </div>
          </div>
          
          <div class="command-section">
            <h4>📊 流量统计与预警</h4>
            <div class="command-list">
              <code>edgeboxctl traffic show</code> <span># 在终端中查看流量统计数据</span><br>
              <code>edgeboxctl traffic reset</code> <span># 重置流量计数器</span><br>
              <code>edgeboxctl alert &lt;command&gt;</code> <span># 管理流量预警设置</span><br>
              <code>edgeboxctl alert monthly</code> <span># 设置月度阈值</span><br>
              <code>edgeboxctl alert steps 30,60,90</code> <span># 设置预警阈值</span><br>
              <code>edgeboxctl alert telegram &lt;bot_token&gt; &lt;chat_id&gt;</code> <span># 配置Telegram机器人</span><br>
              <code>edgeboxctl alert discord &lt;webhook_url&gt;</code> <span># 配置Discord通知</span><br>
              <code>edgeboxctl alert wechat &lt;pushplus_token&gt;</code> <span># 配置微信通知</span><br>
              <code>edgeboxctl alert webhook [raw|slack|discord]</code> <span># 配置通用Webhook</span><br>
              <code>edgeboxctl alert test</code> <span># 测试预警系统</span>
            </div>
          </div>
          
          <div class="command-section">
            <h4>⚙️ 配置管理</h4>
            <div class="command-list">
              <code>edgeboxctl config show</code> <span># 显示所有服务的核心配置信息</span><br>
              <code>edgeboxctl config regenerate-uuid</code> <span># 为所有协议重新生成新的UUID</span><br>
              <code>edgeboxctl test</code> <span># 测试所有协议的连接是否正常</span><br>
              <code>edgeboxctl debug-ports</code> <span># 调试关键端口的监听状态</span>
            </div>
          </div>
          
          <div class="command-section">
            <h4>💾 系统维护</h4>
            <div class="command-list">
              <code>edgeboxctl update</code> <span># 自动更新EdgeBox脚本和核心组件</span><br>
              <code>edgeboxctl backup create</code> <span># 手动创建一个系统备份</span><br>
              <code>edgeboxctl backup list</code> <span># 列出所有可用的备份</span><br>
              <code>edgeboxctl backup restore &lt;DATE&gt;</code> <span># 恢复到指定日期的备份状态</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- 协议详情模态框 -->
<div id="protocol-modal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h3 id="modal-title">协议配置详情</h3>
      <span class="modal-close" onclick="closeModal()">&times;</span>
    </div>
    <div class="modal-body" id="modal-body">
      <!-- 动态内容 -->
    </div>
  </div>
</div>

<script>
const GiB = 1024 ** 3;

// 数据获取工具函数
async function getJSON(url) {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error(`${url} ${r.status}`);
    return r.json();
  } catch (e) {
    console.warn(`Failed to fetch ${url}:`, e);
    return null;
  }
}

async function getTEXT(url) {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error(`${url} ${r.status}`);
    return r.text();
  } catch (e) {
    console.warn(`Failed to fetch ${url}:`, e);
    return '';
  }
}

// 全局变量
let serverConfig = {};
let _chartTraffic = null;
let _chartMonthly = null;
let _sysTicker = null;

const clamp = (n, min=0, max=100) =>
  (Number.isFinite(+n) ? Math.max(min, Math.min(max, Math.round(+n))) : 0);

// 通知中心切换
function toggleNotifications() {
  const popup = document.getElementById('notif-popup');
  popup.classList.toggle('show');
}

// 关闭模态框
function closeModal() {
  document.getElementById('protocol-modal').classList.remove('show');
}

// 安全取值函数
function getSafe(obj, path, fallback = '') {
  try {
    let cur = obj;
    for (let i = 0; i < path.length; i++) {
      if (cur == null || !(path[i] in cur)) return fallback;
      cur = cur[path[i]];
    }
    return cur == null ? fallback : cur;
  } catch (_) {
    return fallback;
  }
}

// 显示协议详情
function showProtocolDetails(protocol) {
  const modal = document.getElementById('protocol-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalBody = document.getElementById('modal-body');

  const sc = window.serverConfig || {};
  const uuid = getSafe(sc, ['uuid', 'vless'], 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');
  const tuicUuid = getSafe(sc, ['uuid', 'tuic'], 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');
  const realityPK = getSafe(sc, ['reality', 'public_key'], 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
  const shortId = getSafe(sc, ['reality', 'short_id'], 'xxxxxxxxxxxxxxxx');
  const hy2Pass = getSafe(sc, ['password', 'hysteria2'], 'xxxxxxxxxxxx');
  const tuicPass = getSafe(sc, ['password', 'tuic'], 'xxxxxxxxxxxx');
  const trojanPwd = getSafe(sc, ['password', 'trojan'], 'xxxxxxxxxxxx');
  const server = getSafe(sc, ['server_ip'], window.location.hostname);

  const configs = {
    'VLESS-Reality': {
      title: 'VLESS-Reality 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: 'UUID', value: uuid },
        { label: '传输协议', value: 'tcp' },
        { label: '流控', value: 'xtls-rprx-vision' },
        { label: 'Reality配置', value: '公钥: ' + realityPK + '\nShortID: ' + shortId + '\nSNI: www.cloudflare.com', note: '支持SNI: cloudflare.com, microsoft.com, apple.com' }
      ]
    },
    'VLESS-gRPC': {
      title: 'VLESS-gRPC 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: 'UUID', value: uuid },
        { label: '传输协议', value: 'grpc' },
        { label: 'ServiceName', value: 'grpc' },
        { label: 'TLS设置', value: 'tls', note: 'IP模式需开启"跳过证书验证"' }
      ]
    },
    'VLESS-WS': {
      title: 'VLESS-WebSocket 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: 'UUID', value: uuid },
        { label: '传输协议', value: 'ws' },
        { label: 'Path', value: '/ws' },
        { label: 'TLS设置', value: 'tls', note: 'IP模式需开启"跳过证书验证"' }
      ]
    },
    'Trojan-TLS': {
      title: 'Trojan-TLS 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: '密码', value: trojanPwd },
        { label: 'SNI', value: 'trojan.edgebox.internal', note: 'IP模式需开启"跳过证书验证"' }
      ]
    },
    'Hysteria2': {
      title: 'Hysteria2 配置',
      items: [
        { label: '服务器地址', value: server + ':443' },
        { label: '密码', value: hy2Pass },
        { label: '协议', value: 'UDP/QUIC' },
        { label: '注意事项', value: '需要支持QUIC的网络环境', note: 'IP模式需开启"跳过证书验证"' }
      ]
    },
    'TUIC': {
      title: 'TUIC 配置',
      items: [
        { label: '服务器地址', value: server + ':2053' },
        { label: 'UUID', value: tuicUuid },
        { label: '密码', value: tuicPass },
        { label: '拥塞控制', value: 'bbr', note: 'IP模式需开启"跳过证书验证"' }
      ]
    }
  };

  const cfg = configs[protocol];
  if (!cfg) return;
  modalTitle.textContent = cfg.title;
  modalBody.innerHTML = cfg.items.map(function(it) {
    return '<div class="config-item"><h4>' + it.label + '</h4><code>' + it.value + '</code>' + (it.note ? '<div class="config-note">⚠️ ' + it.note + '</div>' : '') + '</div>';
  }).join('');
  modal.classList.add('show');
}

// 点击外部关闭
document.addEventListener('click', function(e) {
  if (!e.target.closest('.notification-bell')) {
    document.getElementById('notif-popup').classList.remove('show');
  }
  if (e.target.classList.contains('modal')) {
    e.target.classList.remove('show');
  }
});

// 读取服务器配置（统一从dashboard.json读取）
async function readServerConfig() {
  // 优先统一数据源：dashboard.json.secrets
  try {
    const d = await getJSON('./dashboard.json');
    if (!d) throw new Error('Dashboard data not available');
    
    const s = (d && d.secrets) || {};
    const cfg = {
      server_ip: (d && d.server && (d.server.eip || d.server.ip)) || window.location.hostname,
      uuid: {
        vless: s.vless && (s.vless.reality || s.vless.grpc || s.vless.ws) || ''
      },
      password: {
        hysteria2: (s.password && s.password.hysteria2) || '',
        tuic:      (s.password && s.password.tuic)      || '',
        trojan:    (s.password && s.password.trojan)    || ''
      },
      reality: {
        public_key: (s.reality && s.reality.public_key) || '',
        short_id:   (s.reality && s.reality.short_id)   || ''
      }
    };
    if (s.tuic_uuid) cfg.uuid.tuic = s.tuic_uuid;
    return cfg;
  } catch (_) {}

  // 兜底：从 /traffic/sub 或 /traffic/sub.txt 解析
  try {
    let txt = '';
    try { txt = await getTEXT('./sub'); } catch { txt = await getTEXT('./sub.txt'); }
    const lines = txt.split('\n').map(l => l.trim()).filter(Boolean);
    const cfg = { uuid:{}, password:{}, reality:{}, server_ip: window.location.hostname };
    const v = lines.find(l => l.startsWith('vless://'));
    if (v) {
      const m = v.match(/^vless:\/\/([^@]+)@([^:]+):\d+\?([^#]+)/i);
      if (m) {
        cfg.uuid.vless = m[1]; cfg.server_ip = m[2];
        const qs = new URLSearchParams(m[3].replace(/&amp;/g,'&'));
        cfg.reality.public_key = qs.get('pbk') || '';
        cfg.reality.short_id   = qs.get('sid') || '';
      }
    }
    for (const l of lines) {
      let m;
      if ((m = l.match(/^hysteria2:\/\/([^@]+)@/i))) cfg.password.hysteria2 = decodeURIComponent(m[1]);
      if ((m = l.match(/^tuic:\/\/([^:]+):([^@]+)@/i))) { cfg.uuid.tuic = m[1]; cfg.password.tuic = decodeURIComponent(m[2]); }
      if ((m = l.match(/^trojan:\/\/([^@]+)@/i))) cfg.password.trojan = decodeURIComponent(m[1]);
    }
    return cfg;
  } catch { 
    return {
      server_ip: window.location.hostname,
      uuid: { vless: '', tuic: '' },
      password: { hysteria2: '', tuic: '', trojan: '' },
      reality: { public_key: '', short_id: '' }
    };
  }
}

// 更新本月进度条
async function updateProgressBar() {
  try {
    const [trafficRes, alertRes] = await Promise.all([
      fetch('./traffic.json', { cache: 'no-store' }),
      fetch('./alert.conf', { cache: 'no-store' })
    ]);
    
    let budget = 100;
    if (alertRes && alertRes.ok) {
      const alertText = await alertRes.text();
      const match = alertText.match(/ALERT_MONTHLY_GIB=(\d+)/);
      if (match) budget = parseInt(match[1]);
    }
    
    if (trafficRes && trafficRes.ok) {
      const traffic = await trafficRes.json();
      if (traffic && traffic.monthly && traffic.monthly.length > 0) {
        const current = traffic.monthly[traffic.monthly.length - 1];
        const used = (current.total || 0) / GiB;
        const pct = Math.min((used / budget) * 100, 100);
        
        document.getElementById('progress-fill').style.width = pct + '%';
        document.getElementById('progress-percentage').textContent = pct.toFixed(0) + '%';
        document.getElementById('progress-budget').textContent = used.toFixed(1) + '/' + budget + 'GiB';
      }
    }
  } catch (e) {
    console.warn('进度条更新失败:', e);
  }
}

// 主数据加载函数（统一从dashboard.json读取）
async function loadData() {
  console.log('开始加载数据...');
  
  try {
    // 统一数据源：只从 dashboard.json 读取
    const [dashboard, traffic, alerts, serverJson] = await Promise.all([
      getJSON('./dashboard.json'),
      getJSON('./traffic.json'),
      getJSON('./alerts.json').then(data => data || []),
      readServerConfig()
    ]);
    
    console.log('数据加载完成:', { dashboard: !!dashboard, traffic: !!traffic, alerts: alerts.length, serverJson: !!serverJson });
    
    // 保存服务器配置供协议详情使用
    window.serverConfig = serverJson || {};

    // 统一数据模型（基于dashboard.json）
    const model = dashboard ? {
      updatedAt: dashboard.updated_at,
      server: dashboard.server || {},
      system: { cpu: null, memory: null }, // 系统信息从system.json单独获取
      protocols: dashboard.protocols || [],
      shunt: dashboard.shunt || {},
      subscription: dashboard.subscription || { plain: '', base64: '', b64_lines: '' },
      services: dashboard.services || {}
    } : {
      // 兜底数据结构
      updatedAt: new Date().toISOString(),
      server: {},
      system: { cpu: null, memory: null },
      protocols: [],
      shunt: {},
      subscription: { plain: '', base64: '', b64_lines: '' },
      services: {}
    };

    // 渲染各个模块
    renderHeader(model);
    renderProtocols(model);
    renderTraffic(traffic);
    renderAlerts(alerts);

  } catch (e) {
    console.error('loadData failed:', e);
    // 在出错时显示基本界面
    renderHeader({
      updatedAt: new Date().toISOString(),
      server: {},
      services: {}
    });
  }
}

// 渲染基本信息
function renderHeader(model) {
  const ts = model.updatedAt || new Date().toISOString();
  document.getElementById('updated').textContent = new Date(ts).toLocaleString('zh-CN');
  const s = model.server || {}, svc = model.services || {};
  
  // 基本信息 - 修正DOM元素ID
  const userAlias = document.getElementById('user-alias');
  const cloudProvider = document.getElementById('cloud-provider');
  const instanceId = document.getElementById('instance-id');
  const hostname = document.getElementById('hostname');
  
  if (userAlias) userAlias.textContent = s.user_alias || '—';
  if (cloudProvider) cloudProvider.textContent = s.cloud_provider || '—';
  if (instanceId) instanceId.textContent = s.instance_id || '—';
  if (hostname) hostname.textContent = s.hostname || '—';
 
  // 证书 / 网络模式 & 续期方式
  const mode = s.cert_mode || 'self-signed';
  const renewal = mode === 'letsencrypt' ? '自动续期' : '手动续期';

  const certType = document.getElementById('cert-type');
  const certDomain = document.getElementById('cert-domain');
  const certRenewal = document.getElementById('cert-renewal');
  const certExpire = document.getElementById('cert-expire');

  if (certType) certType.textContent = mode === 'letsencrypt' ? "Let's Encrypt" : '自签名证书';
  if (certDomain) certDomain.textContent = s.cert_domain || '无';
  if (certRenewal) certRenewal.textContent = renewal;

  // 到期日期：处理无效值
  const expStr = (s.cert_expire || '').trim();
  const expDate = expStr ? new Date(expStr) : null;
  if (certExpire) {
    certExpire.textContent = (expDate && !isNaN(expDate)) ? expDate.toLocaleDateString('zh-CN') : '无';
  }

  const verEl = document.getElementById('ver');
  const instEl = document.getElementById('inst');
  if (verEl) verEl.textContent = s.version || '—';
  if (instEl) instEl.textContent = s.install_date || '—';
  
  // CPU/内存从system.json单独获取
  loadSystemStats();
  
  // 服务状态 - 添加状态样式类
  const nginxEl = document.getElementById('nginx-status');
  const xrayEl = document.getElementById('xray-status');
  const singboxEl = document.getElementById('singbox-status');

  if (nginxEl) {
    nginxEl.innerHTML = svc.nginx === 'active' 
      ? '<span class="service-status-badge">运行中</span>'
      : '<span class="service-status-badge inactive">已停止</span>';
  }

  if (xrayEl) {
    xrayEl.innerHTML = svc.xray === 'active'
      ? '<span class="service-status-badge">运行中</span>'
      : '<span class="service-status-badge inactive">已停止</span>';
  }

  if (singboxEl) {
    singboxEl.innerHTML = svc['sing-box'] === 'active'
      ? '<span class="service-status-badge">运行中</span>'
      : '<span class="service-status-badge inactive">已停止</span>';
  }
}

// 单独加载系统状态
async function loadSystemStats() {
  try {
    const sys = await getJSON('./system.json');
    if (!sys) throw new Error('System data not available');
    
    const cpuPercent = clamp(sys.cpu);
    const memPercent = clamp(sys.memory);
    const diskPercent = clamp(sys.disk);
    
    // 更新CPU进度条
    const cpuFill = document.getElementById('cpu-progress-fill');
    const cpuText = document.getElementById('cpu-progress-text');
    const cpuDetail = document.getElementById('cpu-detail');
    if (cpuFill) cpuFill.style.width = cpuPercent + '%';
    if (cpuText) cpuText.textContent = cpuPercent + '%';
    if (cpuDetail) cpuDetail.textContent = sys.cpu_info || '—';
    
    // 更新内存进度条
    const memFill = document.getElementById('mem-progress-fill');
    const memText = document.getElementById('mem-progress-text');
    const memDetail = document.getElementById('mem-detail');
    if (memFill) memFill.style.width = memPercent + '%';
    if (memText) memText.textContent = memPercent + '%';
    if (memDetail) memDetail.textContent = sys.memory_info || '—';
    
    // 更新磁盘进度条
    const diskFill = document.getElementById('disk-progress-fill');
    const diskText = document.getElementById('disk-progress-text');
    const diskDetail = document.getElementById('disk-detail');
    if (diskFill) diskFill.style.width = diskPercent + '%';
    if (diskText) diskText.textContent = diskPercent + '%';
    if (diskDetail) diskDetail.textContent = sys.disk_info || '—';
    
  } catch(_) {
    // 错误时显示默认状态
    const elements = [
      'cpu-progress-fill', 'cpu-progress-text', 'cpu-detail',
      'mem-progress-fill', 'mem-progress-text', 'mem-detail',
      'disk-progress-fill', 'disk-progress-text', 'disk-detail'
    ];
    elements.forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        if (id.includes('fill')) el.style.width = '0%';
        else el.textContent = id.includes('text') ? '-' : '—';
      }
    });
  }
  
  // 15s轮询系统状态
  clearInterval(_sysTicker);
  _sysTicker = setInterval(loadSystemStats, 15000);
}

// 渲染协议配置
function renderProtocols(model) {
  const tb = document.querySelector('#proto tbody');
  if (!tb) return;
  
  tb.innerHTML = '';
  
  const protocols = [
    { name: 'VLESS-Reality', network: 'TCP', disguise: '极佳', scenario: '强审查环境' },
    { name: 'VLESS-gRPC', network: 'TCP/H2', disguise: '极佳', scenario: '较严审查/走CDN' },
    { name: 'VLESS-WS', network: 'TCP/WS', disguise: '良好', scenario: '常规网络更稳' },
    { name: 'Trojan-TLS', network: 'TCP', disguise: '良好', scenario: '移动网络可靠' },
    { name: 'Hysteria2', network: 'UDP/QUIC', disguise: '良好', scenario: '大带宽/低时延' },
    { name: 'TUIC', network: 'UDP/QUIC', disguise: '好', scenario: '弱网/高丢包更佳' }
  ];
  
  protocols.forEach(function(p) {
    const tr = document.createElement('tr');
    tr.innerHTML = 
      '<td>' + p.name + '</td>' +
      '<td>' + p.network + '</td>' +
      '<td>' + p.disguise + '</td>' +
      '<td>' + p.scenario + '</td>' +
      '<td><span class="protocol-status-badge">✓ 运行</span></td>' +
      '<td><span class="detail-link" onclick="showProtocolDetails(\'' + p.name + '\')">详情>></span></td>';
    tb.appendChild(tr);
  });
  
  // 网络出站状态
  const sh = model.shunt || {};
  
  // 更新网络信息
  const vpsOutIp = document.getElementById('vps-out-ip');
  const vpsGeo = document.getElementById('vps-geo');
  const vpsQuality = document.getElementById('vps-quality');
  const proxyOutIp = document.getElementById('proxy-out-ip');
  const proxyGeo = document.getElementById('proxy-geo');
  const proxyQuality = document.getElementById('proxy-quality');
  
  if (vpsOutIp) vpsOutIp.textContent = (model.server && (model.server.eip || model.server.ip)) || '—';
  if (vpsGeo) vpsGeo.textContent = sh.vps_geo || '—';
  if (vpsQuality) vpsQuality.textContent = sh.vps_quality || '—';
  if (proxyOutIp) proxyOutIp.textContent = sh.proxy_info ? '已配置' : '未配置';
  if (proxyGeo) proxyGeo.textContent = sh.proxy_geo || '—';
  if (proxyQuality) proxyQuality.textContent = sh.proxy_quality || '—';
  
  // 修复白名单显示
  const whitelist = sh.whitelist || [];
  const whitelistText = Array.isArray(whitelist) && whitelist.length > 0 
    ? whitelist.slice(0, 8).join(', ') + (whitelist.length > 8 ? '...' : '')
    : '加载中...';
  const whitelistEl = document.getElementById('whitelist-text');
  if (whitelistEl) whitelistEl.textContent = whitelistText;

  // 渲染订阅链接
  const sub = model.subscription || {};
  const subPlain = document.getElementById('sub-plain');
  const subB64 = document.getElementById('sub-b64');
  const subB64Lines = document.getElementById('sub-b64lines');
  
  if (subPlain) subPlain.value = sub.plain || '';
  if (subB64) subB64.value = sub.base64 || '';
  if (subB64Lines) subB64Lines.value = sub.b64_lines || '';
}

// 渲染流量图表
function renderTraffic(traffic) {
  if (!traffic) return;
  if (_chartTraffic) { _chartTraffic.destroy();  _chartTraffic = null; }
  if (_chartMonthly) { _chartMonthly.destroy();  _chartMonthly = null; }

  // 近30天流量图表
  if (traffic.last30d && traffic.last30d.length > 0) {
    const labels = traffic.last30d.map(function(x) { return x.date; });
    const vps = traffic.last30d.map(function(x) { return (x.vps || 0) / GiB; });
    const resi = traffic.last30d.map(function(x) { return (x.resi || 0) / GiB; });
    
    const trafficCanvas = document.getElementById('traffic');
    if (trafficCanvas) {
      _chartTraffic = new Chart(trafficCanvas, {
        type: 'line', 
        data: {
          labels: labels,
          datasets: [
            { label: 'VPS 出口', data: vps, tension: .3, borderWidth: 2, borderColor: '#3b82f6' },
            { label: '住宅出口', data: resi, tension: .3, borderWidth: 2, borderColor: '#f59e0b' }
          ]
        }, 
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: true,
              position: 'bottom',
              labels: {
                padding: 20,
                usePointStyle: true
              }
            }
          },
          scales: {
            x: { title: { display: false } },
            y: { 
              title: { display: false },
              ticks: {
                callback: function(v) { return Math.round(v * 10) / 10; }
              }
            }
          },
          layout: {
            padding: { bottom: 28 }
          }
        }
      });
    }
  }
  
  // 月累计柱形图
  if (traffic.monthly && traffic.monthly.length > 0) {
    const recentMonthly = traffic.monthly.slice(-12);
    const monthLabels = recentMonthly.map(function(item) { return item.month; });
    const vpsData = recentMonthly.map(function(item) { return (item.vps || 0) / GiB; });
    const resiData = recentMonthly.map(function(item) { return (item.resi || 0) / GiB; });
    
    const monthlyCanvas = document.getElementById('monthly-chart');
    if (monthlyCanvas) {
      _chartMonthly = new Chart(monthlyCanvas, {
        type: 'bar',
        data: {
          labels: monthLabels,
          datasets: [
            {
              label: 'VPS出口',
              data: vpsData,
              backgroundColor: '#3b82f6',
              borderColor: '#3b82f6',
              borderWidth: 1,
              stack: 'stack1'
            },
            {
              label: '住宅出口',
              data: resiData,
              backgroundColor: '#f59e0b',
              borderColor: '#f59e0b',
              borderWidth: 1,
              stack: 'stack1'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            tooltip: {
              callbacks: {
                label: function(context) {
                  const label = context.dataset.label || '';
                  const value = context.parsed.y.toFixed(2);
                  return label + ': ' + value + ' GiB';
                },
                afterLabel: function(context) {
                  const dataIndex = context.dataIndex;
                  const vpsValue = vpsData[dataIndex] || 0;
                  const resiValue = resiData[dataIndex] || 0;
                  const total = (vpsValue + resiValue).toFixed(2);
                  return '总流量: ' + total + ' GiB';
                }
              }
            },
            legend: {
              display: true,
              position: 'bottom',
              labels: {
                padding: 20,
                usePointStyle: true
              }
            }
          },
          scales: {
            x: {
              stacked: true,
              grid: { display: false }
            },
            y: {
              stacked: true,
              grid: { display: true, color: '#f1f5f9' },
              ticks: {
                callback: function(value) {
                  return Math.round(value * 10) / 10;
                }
              }
            }
          },
          layout: {
            padding: { bottom: 28 }
          },
          interaction: {
            mode: 'index',
            intersect: false
          }
        }
      });
    }
  }
  
  // 更新本月进度条
  updateProgressBar();
}

// 渲染通知中心
function renderAlerts(alerts) {
  const alertCount = (alerts || []).length;
  const notifCountEl = document.getElementById('notif-count');
  const notifBell = document.getElementById('notif-bell');
  
  if (notifCountEl) notifCountEl.textContent = alertCount;
  
  if (notifBell && alertCount > 0) {
    notifBell.classList.add('has-alerts');
    const span = notifBell.querySelector('span');
    if (span) span.textContent = alertCount + ' 条通知';
  }
  
  const notifList = document.getElementById('notif-list');
  if (notifList) {
    notifList.innerHTML = '';
    if (alertCount > 0) {
      alerts.slice(0, 10).forEach(function(a) {
        const div = document.createElement('div');
        div.className = 'notification-item';
        div.textContent = (a.ts || '') + ' ' + (a.msg || '');
        notifList.appendChild(div);
      });
    } else {
      notifList.textContent = '暂无通知';
    }
  }
}

// 复制订阅链接函数
function copySub(type) {
  const input = document.getElementById('sub-' + type);
  if (!input) return;
  
  input.select();
  document.execCommand('copy');
  
  const btn = input.nextElementSibling;
  if (btn) {
    const originalText = btn.textContent;
    btn.textContent = '已复制';
    btn.style.background = '#10b981';
    btn.style.color = 'white';
    setTimeout(function() {
      btn.textContent = originalText;
      btn.style.background = '';
      btn.style.color = '';
    }, 1000);
  }
}

// 白名单展开/收起功能
function toggleWhitelist() {
  const content = document.getElementById('whitelist-content');
  const toggle = document.getElementById('whitelist-toggle');
  
  if (content && toggle) {
    content.classList.toggle('expanded');
    toggle.textContent = content.classList.contains('expanded') ? '收起' : '查看全部';
  }
}

// IP质量详情显示功能
function showIPQDetails(type) {
  // 这里可以实现显示IP质量检测详情的功能
  alert('IP质量检测详情功能待实现 - ' + type);
}

// 白名单自动折叠功能
function initWhitelistCollapse() {
  document.querySelectorAll('.kv').forEach(function(kv){
    const v = kv.querySelector('.v');
    if(!v) return;
    
    // 检查内容是否超出3行高度
    const lineHeight = parseFloat(getComputedStyle(v).lineHeight) || 20;
    const maxHeight = lineHeight * 3;
    
    if(v.scrollHeight > maxHeight){
      kv.classList.add('v-collapsed');
      const btn = document.createElement('span');
      btn.className = 'detail-toggle';
      btn.innerText = '详情';
      btn.addEventListener('click', function(){
        kv.classList.toggle('v-collapsed');
        btn.innerText = kv.classList.contains('v-collapsed') ? '详情' : '收起';
      });
      kv.appendChild(btn);
    }
  });
}

// 启动
console.log('脚本开始执行');
document.addEventListener('DOMContentLoaded', function() {
  loadData();
  initWhitelistCollapse();
});

// 定时刷新：每5分钟刷新一次数据，每小时刷新本月进度条
setInterval(loadData, 300000);
setInterval(updateProgressBar, 3600000);
</script>
</body>
</html>
HTML
