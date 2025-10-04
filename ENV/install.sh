  # ========== 创建外置的JavaScript文件 ==========
  log_info "创建外置JavaScript文件..."

cat > "${TRAFFIC_DIR}/assets/edgebox-panel.js" <<'EXTERNAL_JS'
// =================================================================
// EdgeBox Panel v3.0 - Refactored JavaScript with Event Delegation
// =================================================================

// --- Global State ---
let dashboardData = {};
let trafficData = {};
let systemData = {};
let overviewTimer = null;
const GiB = 1024 * 1024 * 1024;

// --- Chart.js Plugin ---
const ebYAxisUnitTop = {
  id: 'ebYAxisUnitTop',
  afterDraw: (chart) => {
    const ctx = chart.ctx;
    const yAxis = chart.scales.y;
    if (!yAxis) return;
    ctx.save();
    ctx.font = '11px sans-serif';
    ctx.fillStyle = '#6b7280';
    ctx.textAlign = 'center';
    ctx.fillText('GiB', yAxis.left / 2, yAxis.top - 5);
    ctx.restore();
  }
};


async function fetchJSON(url, retries = 1, delay = 3000) {
  for (let i = 0; i <= retries; i++) {
    try {
      const response = await fetch(url, { cache: 'no-store' });
      if (!response.ok) {
        // 如果是404错误，并且还有重试机会，就等待后重试
        if (response.status === 404 && i < retries) {
          console.warn(`'${url}' not found. Retrying in ${delay / 1000}s... (${i + 1}/${retries})`);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue; // 继续下一次循环
        }
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error(`Fetch error for ${url}:`, error);
      if (i < retries) {
         console.warn(`Fetch failed. Retrying in ${delay / 1000}s... (${i + 1}/${retries})`);
         await new Promise(resolve => setTimeout(resolve, delay));
      } else {
         return null; // 所有重试都失败后返回 null
      }
    }
  }
  return null;
}

// 读取 alert.conf 配置
async function fetchAlertConfig() {
  try {
    const response = await fetch('/traffic/alert.conf', { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    const text = await response.text();
    const config = {};
    text.split('\n').forEach(line => {
      line = line.trim();
      if (line && !line.startsWith('#')) {
        const [key, value] = line.split('=');
        if (key && value !== undefined) {
          config[key.trim()] = value.trim();
        }
      }
    });
    return config;
  } catch (error) {
    console.error('Failed to fetch alert.conf:', error);
    return { ALERT_STEPS: '30,60,90' }; // 默认值
  }
}

function safeGet(obj, path, fallback = '—') {
  const value = path.split('.').reduce((acc, part) => acc && acc[part], obj);
  return value !== null && value !== undefined && value !== '' ? value : fallback;
}

function escapeHtml(s = '') {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function notify(msg, type = 'ok', ms = 1500) {
    // 优先在打开的弹窗内显示，否则在页面中央显示
    const modal = document.querySelector('.modal[style*="block"] .modal-content');
    
    if (modal) {
        // 弹窗内居中轻提示
        let toast = modal.querySelector('.modal-toast');
        if (!toast) {
            toast = document.createElement('div');
            toast.className = 'modal-toast';
            modal.appendChild(toast);
        }
        toast.textContent = msg;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 1200);
    } else {
        // 页面级提示（保持原有逻辑）
        const tip = document.createElement('div');
        tip.className = `toast toast-${type}`;
        tip.textContent = msg;
        document.body.appendChild(tip);
        requestAnimationFrame(() => tip.classList.add('show'));
        setTimeout(() => {
            tip.classList.remove('show');
            setTimeout(() => tip.remove(), 300);
        }, ms);
    }
}

async function copyTextFallbackAware(text) {
  if (!text) throw new Error('empty');
  try {
    if ((location.protocol === 'https:' || location.hostname === 'localhost') && navigator.clipboard) {
      await navigator.clipboard.writeText(text); return true;
    }
    throw new Error('insecure');
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text; ta.readOnly = true;
    ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy'); document.body.removeChild(ta);
    if (!ok) throw new Error('execCommand failed'); return true;
  }
}


// --- UI Rendering Functions ---
function renderOverview() {
  /* ========= 0) 兼容取数（优先闭包变量，取不到再用 window.*） ========= */
  const dash = (typeof dashboardData !== 'undefined' && dashboardData) ||
               (typeof window !== 'undefined' && window.dashboardData) || {};
  const sys  = (typeof systemData   !== 'undefined' && systemData)   ||
               (typeof window !== 'undefined' && window.systemData)   || {};

  /* ========= 1) 拆数据 ========= */
  const server   = dash.server   || {};
  const services = dash.services || {};

  /* ========= 2) 小工具 ========= */
  const setText = (id, text, setTitle) => {
    const el = document.getElementById(id); if (!el) return;
    el.textContent = (text === undefined || text === null || text === '') ? '—' : String(text);
    if (setTitle) el.title = el.textContent;
  };
  const setWidth = (id, pct) => { const el = document.getElementById(id); if (el) el.style.width = `${pct}%`; };
  const clamp = v => Math.max(0, Math.min(100, Number(v) || 0));
  const pick  = (...xs) => xs.find(v => v !== undefined && v !== null && v !== '') ?? 0;
  const toYMD = (v) => { if (!v) return '—'; const d = new Date(v); return isNaN(d) ? String(v).slice(0,10) : d.toISOString().slice(0,10); };
  const toggleBadge = (sel, running) => { const el = document.querySelector(sel); if (!el) return;
    el.textContent = running ? '运行中' : '已停止';
    el.classList.toggle('status-running', !!running);
    el.classList.toggle('status-stopped', !running);
  };

  /* ========= 3) 服务器信息 ========= */
  const remark   = server.user_alias ?? server.remark ?? '未备注';
  const provider = server.cloud?.provider ?? server.cloud_provider ?? 'Independent';
  const region   = server.cloud?.region   ?? server.cloud_region   ?? 'Unknown';
  setText('user-remark',  remark, true);
  setText('cloud-region', `${provider} | ${region}`, true);
  setText('instance-id',  server.instance_id ?? 'Unknown', true);
  setText('hostname',     server.hostname    ?? '-', true);

  /* ========= 4) 服务器配置（条中文本 + 百分比） ========= */
  setText('cpu-info',  server.spec?.cpu  ?? '—', true);
  setText('disk-info', server.spec?.disk ?? '—', true);

  // 内存条中文本（spec.memory 缺失或为 0 时，用 sys 组装）
  const fmtGiB = (b) => { const n = Number(b); if (!Number.isFinite(n)) return null; return Math.round((n / (1024 ** 3)) * 10) / 10; };
  let memText = server.spec?.memory ?? '';
  if (!memText || /^0\s*GiB$/i.test(memText)) {
    const totalB = pick(sys.mem_total, sys.total_mem, sys.memory_total, sys.mem?.total);
    const usedB  = pick(sys.mem_used,  sys.used_mem,  sys.memory_used,  sys.mem?.used);
    const freeB  = pick(sys.mem_free,  sys.free_mem,  sys.memory_free,  sys.mem?.free,
                        (totalB != null && usedB != null) ? (totalB - usedB) : undefined);
    const total = fmtGiB(totalB), used = fmtGiB(usedB), free = fmtGiB(freeB);
    memText = (total != null) ? (used != null && free != null ? `${total}GiB（已用: ${used}GiB, 可用: ${free}GiB）` : `${total}GiB`) : '—';
  }
  setText('mem-info', memText, true);

  // 百分比（多字段名兼容）
  const cpuPct  = clamp(pick(sys.cpu, sys.cpu_usage, sys['cpu-percent'], sys.metrics?.cpu, dash.metrics?.cpu));
  const memPct  = clamp(pick(sys.memory, sys.mem, sys['memory-percent'], sys.metrics?.memory, dash.metrics?.memory));
  const diskPct = clamp(pick(sys.disk, sys.disk_usage, sys['disk-percent'], sys.metrics?.disk, dash.metrics?.disk));

  setWidth('cpu-progress',  cpuPct);  setText('cpu-percent',  `${cpuPct}%`);
  setWidth('mem-progress',  memPct);  setText('mem-percent',  `${memPct}%`);
  setWidth('disk-progress', diskPct); setText('disk-percent', `${diskPct}%`);

  /* ========= 5) 核心服务（版本 + 状态） ========= */
  const versions = {
    nginx:   services.nginx?.version || '',
    xray:    services.xray?.version  || '',
    singbox: (services['sing-box']?.version || services.singbox?.version || '')
  };

setText('nginx-version',   versions.nginx   ? `版本 ${versions.nginx}`   : '—', true);
setText('xray-version',    versions.xray    ? `版本 ${versions.xray}`    : '—', true);
setText('singbox-version', versions.singbox ? `版本 ${versions.singbox}` : '—', true);

  toggleBadge('#system-overview .core-services .service-item:nth-of-type(1) .status-badge', services.nginx?.status === '运行中');
  toggleBadge('#system-overview .core-services .service-item:nth-of-type(2) .status-badge', services.xray?.status  === '运行中');
  toggleBadge('#system-overview .core-services .service-item:nth-of-type(3) .status-badge',
              (services['sing-box']?.status || services.singbox?.status) === '运行中');

  /* ========= 6) 顶部“版本/日期”摘要 ========= */
  const metaText = `版本号: ${server.version || '—'} | 安装日期: ${toYMD(server.install_date)} | 更新时间: ${toYMD(dash.updated_at || Date.now())}`;
  setText('sys-meta', metaText);
}


/* 仅更正“代理IP：”的显示格式，其余逻辑保持不变 */
function renderCertificateAndNetwork() {
  const data   = window.dashboardData || {};
  const server = data.server || {};
  const cert   = server.cert || {};
  const shunt  = data.shunt  || {};

  // —— 证书区（带空值保护）——
  const certMode = String(safeGet(cert, 'mode', 'self-signed'));
  document.getElementById('cert-self')?.classList.toggle('active', certMode === 'self-signed');
  document.getElementById('cert-ca')?.classList.toggle('active', certMode.startsWith('letsencrypt'));
  const certTypeEl = document.getElementById('cert-type');   if (certTypeEl) certTypeEl.textContent = certMode.startsWith('letsencrypt') ? "Let's Encrypt" : "自签名";
  const domEl = document.getElementById('cert-domain');      if (domEl) domEl.textContent = safeGet(cert, 'domain', '-');
  const rnEl  = document.getElementById('cert-renewal');     if (rnEl)  rnEl.textContent  = certMode.startsWith('letsencrypt') ? '自动' : '手动';
const exEl  = document.getElementById('cert-expiry');
if (exEl) {
  const exp = safeGet(cert, 'expires_at', null);
  // 直接显示 yyyy-mm-dd 格式，不进行本地化或其他格式转换
  exEl.textContent = exp || '—';
}

  // —— 出站模式高亮（采用你第二段的口径）——
  const shuntMode = String(safeGet(shunt, 'mode', 'vps')).toLowerCase();
  ['net-vps','net-proxy','net-shunt'].forEach(id => document.getElementById(id)?.classList.remove('active'));
  if (shuntMode.includes('direct')) {
    document.getElementById('net-shunt')?.classList.add('active');
  } else if (shuntMode.includes('resi') || shuntMode.includes('proxy')) {
    document.getElementById('net-proxy')?.classList.add('active');
  } else {
    document.getElementById('net-vps')?.classList.add('active');
  }

  // —— VPS 出站 IP（带兜底）——
  const vpsIp = safeGet(data, 'server.eip') || safeGet(data, 'server.server_ip') || '—';
  const vpsEl = document.getElementById('vps-ip'); if (vpsEl) vpsEl.textContent = vpsIp;

  // —— 代理出站 IP：仅显示 “协议//主机:端口”，自动剥离 user:pass@，兼容 IPv6 —— 
  const proxyRaw = String(safeGet(shunt, 'proxy_info', ''));
  const proxyEl  = document.getElementById('proxy-ip');

  function formatProxy(raw) {
    if (!raw) return '—';
    // 优先用 URL 解析
    try {
      // 确保有协议
      const normalized = /^[a-z][a-z0-9+.\-]*:\/\//i.test(raw) ? raw : 'socks5://' + raw;
      const u = new URL(normalized);
      const proto = u.protocol.replace(/:$/,'');     // 'socks5'
      const host  = u.hostname || '';                // 去掉了 user:pass@
      const port  = u.port || '';                    // 可能为空
      return (host && port) ? `${proto}//${host}:${port}` : (host ? `${proto}//${host}` : '—');
    } catch (_) {
      // 兜底正则：protocol://[user[:pass]@]host[:port]
      const re = /^([a-z0-9+.\-]+):\/\/(?:[^@\/\s]+@)?(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?/i;
      const m = raw.match(re);
      if (m) {
        const proto = m[1];
        const host  = m[2];
        const port  = m[3] || '';
        return port ? `${proto}//${host}:${port}` : `${proto}//${host}`;
      }
      // 再兜底一种 “proto host:port” 或 “host:port”
      const re2 = /^(?:([a-z0-9+.\-]+)\s+)?(\[[^\]]+\]|[^:\/?#\s]+)(?::(\d+))?$/i;
      const m2 = raw.match(re2);
      if (m2) {
        const proto = m2[1] || 'socks5';
        const host  = m2[2];
        const port  = m2[3] || '';
        return port ? `${proto}//${host}:${port}` : `${proto}//${host}`;
      }
      return '—';
    }
  }
  if (proxyEl) proxyEl.textContent = formatProxy(proxyRaw);
  
 /* === PATCH: 填充 Geo 与 IP质量主行分数 === */
(async () => {
  const setText = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = (val ?? '—') || '—';
  };

  // VPS 侧
  try {
    const r = await fetch('/status/ipq_vps.json', { cache: 'no-store' });
    if (r.ok) {
      const j = await r.json();
      const geo = [j.country, j.city].filter(Boolean).join(' · ');
      setText('vps-geo', geo || '—');
      // VPS IP质量显示：分数 + 等级
if (j.score != null && j.grade != null) {
  setText('vps-ipq-score', `${j.score} (${j.grade})`);
} else if (j.score != null) {
  setText('vps-ipq-score', String(j.score));
} else {
  setText('vps-ipq-score', j.grade || '—');
}
    }
  } catch (_) {}

  // 代理侧
  try {
    const r = await fetch('/status/ipq_proxy.json', { cache: 'no-store' });
    if (r.ok) {
      const j = await r.json();
      const geo = [j.country, j.city].filter(Boolean).join(' · ');
      setText('proxy-geo', geo || '—');
      // 代理IP质量显示：分数 + 等级  
if (j.score != null && j.grade != null) {
  setText('proxy-ipq-score', `${j.score} (${j.grade})`);
} else if (j.score != null) {
  setText('proxy-ipq-score', String(j.score));
} else {
  setText('proxy-ipq-score', j.grade || '—');
}
    }
  } catch (_) {}
})();

// —— 白名单预览：只显示第一个域名的前9个字符 —— 
const whitelist = data.shunt?.whitelist || [];
const preview = document.getElementById('whitelistPreview');
if (preview) {
  if (!whitelist.length) {
    preview.innerHTML = '<span class="whitelist-text">(无)</span>';
  } else {
    // 取第一个域名，显示前6个字符
    const firstDomain = whitelist[0] || '';
    const shortText = firstDomain.length > 9 ? firstDomain.substring(0, 9) + '...' : firstDomain;
    
    preview.innerHTML =
      `<span class="whitelist-text">${escapeHtml(shortText)}</span>` +
      `<button class="whitelist-more" data-action="open-modal" data-modal="whitelistModal">查看全部</button>`;
  }
}
}


function renderTrafficCharts() {
  if (!trafficData || !window.Chart) return;

  // —— 进度条（本月使用）——
  const monthly = trafficData.monthly || [];
  const currentMonthData = monthly.find(m => m.month === new Date().toISOString().slice(0, 7));
  if (currentMonthData) {
    const used = (currentMonthData.total || 0) / GiB;
    const percentage = Math.min(100, Math.round((used / 100) * 100)); // 先用默认预算100
    const fillEl   = document.getElementById('progress-fill');
    const pctEl    = document.getElementById('progress-percentage');
    const budgetEl = document.getElementById('progress-budget');
    
    if (fillEl)   fillEl.style.width = `${percentage}%`;
    if (pctEl)    pctEl.textContent  = `${percentage}%`;
    if (budgetEl) budgetEl.textContent = `阈值(100GiB)`;  // 先显示默认值
    if (pctEl) pctEl.title = `已用 ${used.toFixed(1)}GiB / 阈值 100GiB`;
    
    // 异步获取配置并更新阈值刻度线
    fetchAlertConfig().then(alertConfig => {
      const budget = parseInt(alertConfig.ALERT_MONTHLY_GIB) || 100;
      const alertSteps = (alertConfig.ALERT_STEPS || '30,60,90').split(',').map(s => parseInt(s.trim()));
      
      // 重新计算百分比（基于真实预算）
      const realPercentage = Math.min(100, Math.round((used / budget) * 100));
      
      // 更新显示
      if (fillEl) fillEl.style.width = `${realPercentage}%`;
      if (pctEl) pctEl.textContent = `${realPercentage}%`;
      if (budgetEl) budgetEl.textContent = `阈值(${budget}GiB)`;
      if (pctEl) pctEl.title = `已用 ${used.toFixed(1)}GiB / 阈值 ${budget}GiB`;
      
      // 渲染阈值刻度线
      renderTrafficProgressThresholds(alertSteps);
    }).catch(err => {
      console.warn('无法加载 alert.conf，使用默认配置:', err);
      renderTrafficProgressThresholds([30, 60, 90]); // 使用默认阈值
    });
  }
  
// 渲染流量统计进度条的阈值刻度线（只针对流量统计，不影响CPU/内存/磁盘进度条）
function renderTrafficProgressThresholds(thresholds) {
  // 特别注意：只选择流量统计卡片中的进度条
  const trafficProgressBar = document.querySelector('.traffic-card .progress-bar');
  if (!trafficProgressBar) return;
  
  // 清除现有刻度线
  const existingMarkers = trafficProgressBar.querySelectorAll('.traffic-threshold-marker');
  const existingLabels = trafficProgressBar.querySelectorAll('.traffic-threshold-label');
  existingMarkers.forEach(marker => marker.remove());
  existingLabels.forEach(label => label.remove());
  
  // 添加新的刻度线
  thresholds.forEach(threshold => {
    if (threshold > 0 && threshold <= 100) {
      // 刻度线
      const marker = document.createElement('div');
      marker.className = 'traffic-threshold-marker';
      marker.style.cssText = `
        position: absolute;
        left: ${threshold}%;
        top: 0;
        bottom: 0;
        width: 2px;
        background: #9ca3af;    /* ← 改为灰色 */
        z-index: 10;
        transform: translateX(-50%);
        border-radius: 1px;
      `;
      
      // 标签（黄色字体，无背景，放在进度条内部）
      const label = document.createElement('div');
      label.className = 'traffic-threshold-label';
      label.textContent = `${threshold}%`;
      label.style.cssText = `
        position: absolute;
        left: ${threshold}%;
        top: 50%;
        transform: translate(-50%, -50%);
        font-size: 12px;
        color: #fbbf24;         /* ← 改为黄色（预警色） */
        white-space: nowrap;
        font-weight: 600;
        pointer-events: none;
        z-index: 11;
        text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);  /* ← 添加阴影增强可读性 */
      `;
      
      trafficProgressBar.appendChild(marker);
      trafficProgressBar.appendChild(label);
    }
  });
}

  // —— 图表销毁（避免重复实例）——
  ['traffic', 'monthly-chart'].forEach(id => {
    const inst = Chart.getChart(id);
    if (inst) inst.destroy();
  });

  // —— 颜色：将原“橙色”改为“蓝色”，更贴近面板基调；绿色保留给“代理” —— 
  const vpsColor   = '#3b82f6';  // 蓝（替换原来的 #f59e0b）
  const proxyColor = '#10b981';  // 绿（保留）
  
  // —— 近30日折线 ——（去掉 y 轴顶部 GiB 插件）
  const daily = trafficData.last30d || [];
  if (daily.length) {
    const ctx = document.getElementById('traffic');
    if (ctx) {
      new Chart(ctx, {
        type: 'line',
        data: {
          labels: daily.map(d => d.date.slice(5)),
          datasets: [
            { label: 'VPS',  data: daily.map(d => d.vps  / GiB), borderColor: vpsColor,   backgroundColor: vpsColor,   tension: 0.3, pointRadius: 0, fill: false },
            { label: '代理', data: daily.map(d => d.resi / GiB), borderColor: proxyColor, backgroundColor: proxyColor, tension: 0.3, pointRadius: 0, fill: false },
          ]
        },
options: {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false } // 隐藏底部内置图例
  },
  layout: {
    padding: { bottom: 22 }    // 恢复底部留白，保证日期不被裁掉
  },
  scales: {
    x: { ticks: { padding: 6 } },
    y: { ticks: { padding: 6 } }
  }
}

      });
    }
  }

  // —— 近12个月堆叠柱 ——（同样不再用 GiB 顶部单位）
  if (monthly.length) {
    const arr = monthly.slice(-12);
    const ctx = document.getElementById('monthly-chart');
    if (ctx) {
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: arr.map(m => m.month),
          datasets: [
            { label: 'VPS',  data: arr.map(m => m.vps  / GiB), backgroundColor: vpsColor,   stack: 'a' },
            { label: '代理', data: arr.map(m => m.resi / GiB), backgroundColor: proxyColor, stack: 'a' },
          ]
        },
options: {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false } // 仍隐藏底部内置图例
  },
  layout: {
    padding: { bottom: 22 }    // 给 x 轴刻度留空间
  },
  scales: {
    x: { ticks: { padding: 6 } },
    y: { ticks: { padding: 6 } }
  }
}

      });
    }
  }
}

// --- Modal and Interaction Logic ---
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        document.body.classList.add('modal-open');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        document.body.classList.remove('modal-open');
    }
}

function showWhitelistModal() {
    const list = document.getElementById('whitelistList');
    const whitelist = dashboardData.shunt?.whitelist || [];
    if (list) {
        list.innerHTML = whitelist.length 
            ? whitelist.map(item => `<div class="whitelist-item">${escapeHtml(item)}</div>`).join('')
            : '<p>暂无白名单数据</p>';
    }
    showModal('whitelistModal');
}


// [PATCH:SHOW_CONFIG_MODAL_SAFE] —— 精准、谨慎、只改一处
// 完整的 showConfigModal 函数修改 - 修复二维码生成逻辑

function showConfigModal(protocolKey) {
  const dd = window.dashboardData;
  const modal = document.getElementById('configModal');
  if (!modal || !dd) return;

  const title = document.getElementById('configModalTitle');
  const details = document.getElementById('configDetails');
  const footer = modal.querySelector('.modal-footer');
  if (!title || !details || !footer) return;

  // 工具函数
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toB64 = s => btoa(unescape(encodeURIComponent(s)));
  const get = (o, p, fb = '') => p.split('.').reduce((a, k) => (a && a[k] !== undefined ? a[k] : undefined), o) ?? fb;

  // JSON 行尾注释对齐（仅用于 UI 展示）
  function annotateAligned(obj, comments = {}) {
    const lines = JSON.stringify(obj, null, 2).split('\n');
    const metas = lines.map(line => {
      const m = line.match(/^(\s*)"([^"]+)"\s*:\s*(.*?)(,?)$/);
      if (!m) return null;
      const [, indent, key, val, comma] = m;
      const baseLen = indent.length + 1 + key.length + 1 + 2 + 1 + String(val).length + (comma ? 1 : 0);
      return { indent, key, val, comma, baseLen };
    }).filter(Boolean);
    const maxLen = metas.length ? Math.max(...metas.map(x => x.baseLen)) : 0;

    return lines.map(line => {
      const m = line.match(/^(\s*)"([^"]+)"\s*:\s*(.*?)(,?)$/);
      if (!m) return line;
      const [, indent, key, val, comma] = m;
      const base = `${indent}"${key}": ${val}${comma}`;
      const cm = comments[key];
      if (!cm) return base;
      const thisLen = indent.length + 1 + key.length + 1 + 2 + 1 + String(val).length + (comma ? 1 : 0);
      const pad = ' '.repeat(Math.max(1, maxLen - thisLen + 1));
      return `${base}${pad}// ${cm}`;
    }).join('\n');
  }

  const usage = html => (
    `<div class="config-section">
       <h4>使用说明</h4>
       <div class="config-help" style="font-size:12px;color:#6b7280;line-height:1.6;">${html}</div>
     </div>`
  );

  // 打开弹窗并给出加载态
  details.innerHTML = '<div class="loading">正在加载配置…</div>';
  modal.style.display = 'block';
  document.body.classList.add('modal-open');

  let qrText = '';

  // ===== 整包订阅 =====
  if (protocolKey === '__SUBS__') {
    const subsUrl = get(dd, 'subscription_url', '') ||
                    (get(dd, 'server.server_ip', '') ? `http://${get(dd, 'server.server_ip')}/sub` : '');
    const plain6 = get(dd, 'subscription.plain', '');
    const base64 = get(dd, 'subscription.base64', '') || (plain6 ? toB64(plain6) : '');

    title.textContent = '订阅（整包）';
    details.innerHTML = `
      <div class="config-section">
        <h4>订阅 URL</h4>
        <div class="config-code" id="plain-link">${esc(subsUrl)}</div>
      </div>
      <div class="config-section">
        <h4>明文链接（6协议）</h4>
        <div class="config-code" id="plain-links-6" style="white-space:pre-wrap">${esc(plain6)}</div>
      </div>
      <div class="config-section">
        <h4>Base64链接（6协议）</h4>
        <div class="config-code" id="base64-link">${esc(base64)}</div>
      </div>
      <div class="config-section">
        <h4>二维码</h4>
        <div class="qr-container">
          <div id="qrcode-sub"></div>
        </div>
      </div>
      ${usage('将"订阅 URL"导入 v2rayN、Clash 等支持订阅的客户端；部分客户端也支持直接粘贴 Base64 或扫码二维码。')}
    `;
    footer.innerHTML = `
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain">复制订阅URL</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain6">复制明文(6协议)</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="base64">复制Base64</button>
      <button class="btn btn-sm btn-secondary" data-action="copy-qr">复制二维码</button>
    `;
    
    // 整包订阅的二维码应该使用订阅URL，不是明文链接
    // 客户端（如Shadowrocket）扫码后会自动获取订阅内容
    qrText = subsUrl || '';

  // ===== 单协议 =====
  } else {
    const protocols = Array.isArray(dd.protocols) ? dd.protocols : [];
    const p = protocols.find(x =>
      x && (x.name === protocolKey || x.key === protocolKey || x.id === protocolKey || x.type === protocolKey)
    );

    if (!p) {
      title.textContent = '配置详情';
      details.innerHTML = `<div class="empty">未找到协议：<code>${esc(String(protocolKey))}</code></div>`;
      footer.innerHTML = `<button class="btn btn-sm" data-action="close-config-modal">关闭</button>`;
      return;
    }

    const certMode = String(get(dd, 'server.cert.mode', 'self-signed'));
    const isLE = certMode.startsWith('letsencrypt');
    const serverIp = get(dd, 'server.server_ip', '');

    const obj = {
      protocol: p.name,
      host: serverIp,
      port: p.port ?? 443,
      uuid: get(dd, 'secrets.vless.reality', '') ||
            get(dd, 'secrets.vless.grpc', '') ||
            get(dd, 'secrets.vless.ws', ''),
      sni: isLE ? get(dd, 'server.cert.domain', '') : serverIp,
      alpn: (p.name || '').toLowerCase().includes('grpc') ? 'h2'
            : ((p.name || '').toLowerCase().includes('ws') ? 'http/1.1' : '')
    };

    const comments = {
      protocol: '协议类型（例：VLESS-Reality）',
      host: '服务器地址（IP/域名）',
      port: '端口',
      uuid: '认证 UUID / 密钥',
      sni: 'TLS/SNI（域名模式用域名）',
      alpn: 'ALPN（gRPC=h2，WS=http/1.1）'
    };
    const jsonAligned = annotateAligned(obj, comments);

    const plain = p.share_link || '';
    const base64 = plain ? toB64(plain) : '';

    title.textContent = `${p.name} 配置`;
    details.innerHTML = `
      <div class="config-section">
        <h4>JSON 配置</h4>
        <div class="config-code" id="json-code" style="white-space:pre-wrap">${esc(jsonAligned)}</div>
      </div>
      <div class="config-section">
        <h4>明文链接</h4>
        <div class="config-code" id="plain-link">${esc(plain)}</div>
      </div>
      <div class="config-section">
        <h4>Base64链接</h4>
        <div class="config-code" id="base64-link">${esc(base64)}</div>
      </div>
      <div class="config-section">
        <h4>二维码</h4>
        <div class="qr-container">
          <div id="qrcode-protocol"></div>
        </div>
      </div>
      ${usage('复制明文或 JSON 导入客户端；若客户端支持扫码添加，也可直接扫描二维码。')}
    `;
    footer.innerHTML = `
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="json">复制 JSON</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain">复制明文链接</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="base64">复制 Base64</button>
      <button class="btn btn-sm btn-secondary" data-action="copy-qr">复制二维码</button>
    `;
    
    // 单协议的二维码使用 share_link 生成（这部分是正确的）
    qrText = plain || '';
  }

  // —— 生成二维码（强制"仅一份"产物）——
  if (qrText && window.QRCode) {
    const holderId = (protocolKey === '__SUBS__') ? 'qrcode-sub' : 'qrcode-protocol';
    const holder = document.getElementById(holderId);
    if (holder) {
      // 1) 彻底清空
      holder.replaceChildren();
      // 2) 生成
      new QRCode(holder, {
        text: qrText,
        width: 200,
        height: 200,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.M
      });
      // 3) 只保留一个可见产物（优先保留 canvas）
      const kids = Array.from(holder.children);
      const keep = holder.querySelector('canvas') || kids[0] || null;
      if (keep) {
        kids.forEach(node => { if (node !== keep) node.remove(); });
      }
    }
  }
}
// [PATCH:SHOW_CONFIG_MODAL_SAFE_END]



// [PATCH:IPQ_MODAL] —— 拉不到数据也渲染结构；字段名完全兼容
let __IPQ_REQ_SEQ__ = 0; // 并发守卫：只有最新一次请求才允许更新DOM
async function showIPQDetails(which) {
  const titleEl = document.getElementById('ipqModalTitle');
  const bodyEl  = document.getElementById('ipqDetails');
  if (!titleEl || !bodyEl) return;

  const file = which === 'vps' ? '/status/ipq_vps.json' : '/status/ipq_proxy.json';
  titleEl.textContent = which === 'vps' ? 'VPS IP质量检测详情' : '代理 IP质量检测详情';
  bodyEl.innerHTML = `<div class="config-section"><div class="config-code">加载中...</div></div>`;
  showModal && showModal('ipqModal');

let data = null;
const __seq = ++__IPQ_REQ_SEQ__; // 记录本次请求序号

try {
  const r = await fetch(file, { cache: 'no-store' });
  if (__seq !== __IPQ_REQ_SEQ__) return;           // 旧请求作废，防止“失败→内容”闪烁
  if (!r.ok) throw new Error('HTTP ' + r.status);
  data = await r.json();
} catch (err) {
  if (__seq !== __IPQ_REQ_SEQ__) return;           // 旧请求作废
  // 不中断、不展示“失败”中间态；保持“加载中…”并走兜底数据渲染，用户只看到“加载中→内容”
  data = null;
}

  // —— 兜底：没有数据也给出结构（从 dashboardData 拼一些非敏感项）
  const dash = window.dashboardData || {};
  const server = dash.server || {};
  data = data || {
    score: null, grade: null, detected_at: dash.updated_at,
    ip: (which==='vps' ? server.server_ip : server.eip) || '',
    asn: '', isp: '', country: '', city: '', rdns: '',
    bandwidth: '', network_type: '', latency_p50: null,
    risk: { proxy: (which==='proxy'), hosting: true, dnsbl_hits: [] },
    conclusion: ''
  };

  // —— 兼容取值
  const pick = (o, paths, d='—')=>{
    for (const p of paths) {
      const v = p.split('.').reduce((x,k)=> x&&x[k]!=null ? x[k] : undefined, o);
      if (v!=null && v!=='') return v;
    }
    return d;
  };

  const score = pick(data,['score'], '—');
  const grade = pick(data,['grade'], null);
  const gradeStr = grade || (typeof score==='number'
                    ? (score>=80?'A':score>=60?'B':score>=40?'C':'D') : '—');
  const when = pick(data,['detected_at','updated_at','timestamp'], '—');

  const ip   = pick(data,['ip'],'—');
  const asn  = pick(data,['asn'],'');
  const isp  = pick(data,['isp'],'');
  const country = pick(data,['country','geo.country'],'');
  const city    = pick(data,['city','geo.city'],'');
  const rdns    = pick(data,['rdns','reverse_dns'],'—');

  const bwUp   = pick(data,['bandwidth_up','config.bandwidth_up'], null);
  const bwDown = pick(data,['bandwidth_down','config.bandwidth_down'], null);
  const bandwidth = (bwUp || bwDown) ? `${bwUp||'—'} / ${bwDown||'—'}` : (pick(data,['bandwidth','config.bandwidth'],'未配置'));

  const networkType = pick(data,['network_type','net_type'],'—');
  const latency = (()=>{
    const v = pick(data,['latency_p50','latency.median','latency_ms'], null);
    return v ? `${v} ms` : '—';
  })();

  const riskObj = data.risk || {};
  const flags = [
    riskObj.proxy   ? '代理标记'  : null,
    riskObj.hosting ? '数据中心'  : null,
    riskObj.mobile  ? '移动网络'  : null,
    riskObj.tor     ? 'Tor'      : null
  ].filter(Boolean).join('、') || '—';
  const hits = Array.isArray(riskObj.dnsbl_hits) ? riskObj.dnsbl_hits : [];
  const blCount = hits.length;

  const conclusion = pick(data,['conclusion'],'—');

  const EH = s => String(s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));

  bodyEl.innerHTML = `
    <div class="ipq-section">
      <h5>总览</h5>
      <div class="info-item"><label>分数:</label><value>${score} / 100</value></div>
      <div class="info-item"><label>等级:</label><value><span class="grade-badge grade-${String(gradeStr).toLowerCase()}">${EH(gradeStr)}</span></value></div>
      <div class="info-item"><label>最近检测时间:</label><value>${EH(when)}</value></div>
    </div>
    <div class="ipq-section">
      <h5>身份信息</h5>
      <div class="info-item"><label>出站IP:</label><value>${EH(ip)}</value></div>
      <div class="info-item"><label>ASN / ISP:</label><value>${EH([asn, isp].filter(Boolean).join(' / ') || '—')}</value></div>
      <div class="info-item"><label>Geo:</label><value>${EH([country, city].filter(Boolean).join(' / ') || '—')}</value></div>
      <div class="info-item"><label>rDNS:</label><value>${EH(rdns)}</value></div>
    </div>
    <div class="ipq-section">
      <h5>配置信息</h5>
      <div class="info-item"><label>带宽限制:</label><value>${EH(bandwidth)}</value></div>
    </div>
    <div class="ipq-section">
      <h5>质量细项</h5>
      <div class="info-item"><label>网络类型:</label><value>${EH(networkType)}</value></div>
      <div class="info-item"><label>时延中位数:</label><value>${EH(latency)}</value></div>
    </div>
    <div class="ipq-section">
      <h5>风险与黑名单</h5>
      <div class="info-item"><label>特征:</label><value>${EH(flags)}</value></div>
      <div class="info-item"><label>黑名单命中数:</label><value>${blCount} 个</value></div>
    </div>
    <div class="ipq-conclusion">
      <h5>结论与依据</h5>
      <p>${EH(conclusion)}</p>
      <ul style="margin-top:8px; font-size:12px; color:#6b7280; padding-left:18px; line-height:1.6;">
        <li>基础分 100 分</li>
        <li>“代理/数据中心/Tor”等标记会降低分数</li>
        <li>每命中 1 个 DNSBL 黑名单会降低分数</li>
        <li>高时延会降低分数</li>
      </ul>
    </div>`;
}

async function copyText(text) {
    if (!text || text === '—') return notify('没有可复制的内容', 'warn');
    try {
        await navigator.clipboard.writeText(text);
        notify('已复制到剪贴板');
    } catch (e) {
        notify('复制失败', 'warn');
    }
}

// --- 主应用程序逻辑 ---
// 1. 获取并渲染主仪表板数据
async function refreshDashboard() {
const dash = await fetchJSON('/traffic/dashboard.json');
if (dash) {
window.dashboardData = dash;
// 这些渲染器仅依赖于 dashboard.json
renderCertificateAndNetwork();
renderProtocolTable(); // 如果健康数据可用，现在将正确使用健康数据
}
}

// 2. 获取并渲染实时系统状态（CPU、内存、服务）
async function refreshSystemStats() {
const [sys, dash] = await Promise.all([
fetchJSON('/traffic/system.json'),
fetchJSON('/traffic/dashboard.json') // 同时获取 dash 以获取服务状态
]);

if (sys) window.systemData = sys;
if (dash) window.dashboardData = dash; // 确保 dashboardData 是最新的

// 此渲染器同时依赖于 system.json 和 dashboard.json
renderOverview();
}

// 3. 获取并渲染流量图数据
async function refreshTraffic() {
const traf = await fetchJSON('/traffic/traffic.json');
if (traf) {
window.trafficData = traf;
renderTrafficCharts();
}
}

// 更新协议健康状态显示
function updateProtocolHealthStatus(healthData) {
    if (!healthData || !healthData.protocols) return;
    
    healthData.protocols.forEach(proto => {
        // 在协议配置表格中更新状态列
        const statusCell = document.querySelector(
            `.protocol-row[data-protocol="${proto.protocol}"] .status-cell`
        );
        
        if (statusCell) {
            statusCell.innerHTML = `
                <div class="health-status-container">
                    <span class="health-status-badge ${proto.status}">
                        ${proto.status_badge}
                    </span>
                    <span class="health-detail-message">
                        ${proto.detail_message}
                    </span>
                    ${proto.repair_result ? `
                        <span class="repair-info">
                            🔧 ${proto.repair_result.includes('repaired') ? '已自动修复' : '修复失败'}
                        </span>
                    ` : ''}
                </div>
            `;
        }
    });
    
    // 更新汇总统计
    const summary = healthData.summary;
    updateHealthSummaryBadge(summary);
}

// 更新健康状态汇总徽章
function updateHealthSummaryBadge(summary) {
    const badge = document.querySelector('.health-summary-badge');
    if (!badge) return;
    
    const healthRate = summary.total > 0 
        ? Math.round((summary.healthy / summary.total) * 100) 
        : 0;
    
    let badgeClass = 'success';
    if (healthRate < 50) badgeClass = 'danger';
    else if (healthRate < 80) badgeClass = 'warning';
    
    badge.className = `health-summary-badge ${badgeClass}`;
    badge.textContent = `协议健康度: ${healthRate}% (${summary.healthy}/${summary.total})`;
}


// 这是最终的、正确的页面加载逻辑

document.addEventListener('DOMContentLoaded', async () => {
console.log('[EdgeBox Panel] 正在初始化...');

// 首先设置不需要数据的 UI 元素
setupNotificationCenter();

// 在数据加载时设置占位符
const tbody = document.getElementById('protocol-tbody');
if (tbody) {
tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:#6b7280;">正在加载节点数据...</td></tr>';
}

try {
// --- 初始加载 ---
// 一开始就加载所有内容，以便快速填充页面。
await Promise.all([
refreshDashboard(),
refreshSystemStats(),
refreshTraffic(),
initializeProtocolHealth() // 保留健康检查逻辑
]);
console.log('[Init] 初始页面渲染完成。');

} catch (error) {
console.error('[Init] 初始数据加载失败：', error);
if (tbody) {
tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:#dc2626;">错误：无法加载节点数据。</td></tr>';
}
}

// --- 设置周期性刷新定时器 ---
// 用于 CPU/内存等实时统计数据的快速计时器
setInterval(refreshSystemStats, 5000); // 每 5 秒刷新一次系统统计数据

// 用于变化频率较低的数据的较慢计时器
setInterval(async () => {
await refreshDashboard();
await refreshTraffic();
await initializeProtocolHealth();
}, 30000); // 每 30 秒刷新一次其他数据

console.log('[Init] 定期刷新计时器已启动。');
});

// ==== new11 事件委托（append-only） ====
(() => {
  if (window.__EDGEBOX_DELEGATED__) return;
  window.__EDGEBOX_DELEGATED__ = true;

  const notify = window.notify || ((msg)=>console.log(msg));
  const $ = s => document.querySelector(s);

  function showModal(id) {
    const m = document.getElementById(id);
    if (!m) return;
    m.style.display = 'block';
    document.body.classList.add('modal-open');
  }
  function closeModal(id) {
    const m = document.getElementById(id);
    if (!m) return;
    m.style.display = 'none';
    document.body.classList.remove('modal-open');
  }

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action   = btn.dataset.action;
    const modal    = btn.dataset.modal || '';
    const protocol = btn.dataset.protocol || '';
    const type     = btn.dataset.type || '';

    switch (action) {
      case 'open-modal': {
        if (modal === 'configModal') {
          if (typeof showConfigModal === 'function') showConfigModal(protocol);
          const m = document.getElementById('configModal');
          if (m && m.style.display !== 'block') showModal('configModal');
        } else if (modal === 'whitelistModal') {
          const list = (window.dashboardData?.shunt?.whitelist) || [];
          const box  = $('#whitelistList');
          if (box) box.innerHTML = list.map(d => `<div class="whitelist-item">${String(d)
            .replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}</div>`).join('');
          showModal('whitelistModal');
} else if (modal === 'ipqModal') {
  // 统一走 showIPQDetails（内部自带并发守卫），彻底避免“加载失败→内容”的闪烁
  if (typeof showIPQDetails === 'function') {
    await showIPQDetails(btn.dataset.ipq || 'vps'); // 'vps' | 'proxy'
  } else {
    showModal('ipqModal'); // 极端兜底：函数不存在时至少打开弹窗
  }
}
        break;
      }

      case 'close-modal': {
        closeModal(modal);
        break;
      }

// 事件委托中的复制分支（替换你现有的 copy 分支）
// 复制文本（JSON/明文/6协议明文/Base64）
case 'copy': {
  const host = btn.closest('.modal-content');
  const map  = { json:'#json-code', plain:'#plain-link', plain6:'#plain-links-6', base64:'#base64-link' };
  const el   = host && host.querySelector(map[btn.dataset.type]);
  const text = el ? (el.textContent || '').trim() : '';
  try { await copyTextFallbackAware(text); (window.notify||console.log)('已复制'); }
  catch { (window.notify||console.warn)('复制失败'); }
  break;
}


// 复制二维码（安全上下文优先，失败自动降级为下载 + 复制明文）
case 'copy-qr': {
  const host = btn.closest('.modal-content');
  const cvs  = host && host.querySelector('#qrcode-sub canvas, #qrcode-protocol canvas');

  if (!cvs) {
    notify('未找到二维码', 'warn');
    break;
  }

  // 小工具：下载 PNG
  const doDownload = (blob) => {
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    const name = (protocol || '__SUBS__') + '_qrcode.png';
    a.href = url; a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };

  // 小工具：复制文本兜底（订阅或明文链接）
  const doFallbackText = async () => {
    const text =
      host?.querySelector('#plain-link')?.textContent?.trim()
      || host?.querySelector('#plain-links-6')?.textContent?.trim()
      || host?.querySelector('#base64-link')?.textContent?.trim()
      || '';
    if (text) {
      try { await copyTextFallbackAware(text); } catch (_) {}
    }
  };

  // 从 canvas 拿 PNG 并尽量写入剪贴板
  cvs.toBlob(async (blob) => {
    if (!blob) {
      notify('获取二维码失败', 'warn');
      return;
    }
    try {
      // 首选：安全上下文 + 支持图片写入
      if (window.isSecureContext && navigator.clipboard?.write && window.ClipboardItem) {
        await navigator.clipboard.write([ new ClipboardItem({ 'image/png': blob }) ]);
        notify('二维码已复制到剪贴板');
      } else {
        throw new Error('insecure');
      }
    } catch (err) {
      // 降级路径：自动下载 PNG + 复制明文
      doDownload(blob);
      await doFallbackText();
      notify('图片复制受限：已自动下载二维码，并复制了明文/链接', 'warn');
    }
  }, 'image/png');

  break;
}

    }
  });
})();

// === 复制按钮（弹窗内）统一轻提示 ======================
document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-role="copy"], .copy-btn, .btn-copy');
  if (!btn) return;

  // 若你的复制逻辑已在别处执行，这里只负责提示即可。
  // 如果需要兜底复制，可取消注释：
  // const txt = btn.getAttribute('data-clipboard-text');
  // if (txt) await navigator.clipboard.writeText(txt).catch(()=>{});

  // 找到最近的弹窗容器（Ant / Element / 自研）
  const modal = btn.closest('.ant-modal, .el-dialog, .modal');
  if (!modal) return;

  // 准备/显示 toast
  let toast = modal.querySelector('.modal-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'modal-toast';
    toast.textContent = '已复制';
    modal.appendChild(toast);
  }
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 1200);
});


// =================================================================
// 通知中心功能
// =================================================================

let notificationData = { notifications: [] };

// 更新通知中心
function updateNotificationCenter(data) {
    notificationData = data || { notifications: [] };
    renderNotifications();
}

// 渲染通知列表
function renderNotifications() {
    const listEl = document.getElementById('notificationList');
    const badgeEl = document.getElementById('notificationBadge');
    
    if (!notificationData.notifications || notificationData.notifications.length === 0) {
        if (listEl) {
            listEl.innerHTML = `
                
                    🔔
                    暂无通知
                
            `;
        }
        if (badgeEl) badgeEl.style.display = 'none';
        return;
    }
    
    // 计算未读数量
    const unreadCount = notificationData.notifications.filter(n => !n.read).length;
    
    if (badgeEl) {
        if (unreadCount > 0) {
            badgeEl.textContent = unreadCount > 99 ? '99+' : unreadCount;
            badgeEl.style.display = 'inline-block';
        } else {
            badgeEl.style.display = 'none';
        }
    }
    
    // 渲染通知项
    if (listEl) {
        const html = notificationData.notifications.slice(0, 20).map(notification => {
            const iconMap = {
                alert: '⚠️',
                system: '⚙️', 
                error: '❌'
            };
            
            const timeAgo = getTimeAgo(notification.time);
            const icon = iconMap[notification.type] || iconMap[notification.level] || '📋';
            
            return `
                
                    
                        ${icon}
                    
                    
                        ${escapeHtml(notification.message)}
                        ${timeAgo}
                        ${notification.action ? `${escapeHtml(notification.action)}` : ''}
                    
                
            `;
        }).join('');
        
        listEl.innerHTML = html;
    }
}

// 时间格式化
function getTimeAgo(timeStr) {
    try {
        const time = new Date(timeStr);
        const now = new Date();
        const diff = now - time;
        
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        
        if (days > 0) return `${days}天前`;
        if (hours > 0) return `${hours}小时前`;
        if (minutes > 0) return `${minutes}分钟前`;
        return '刚刚';
    } catch (e) {
        return '未知时间';
    }
}

// 设置通知中心事件监听
function setupNotificationCenter() {
    const trigger = document.getElementById('notificationTrigger');
    const panel = document.getElementById('notificationPanel');
    
    if (!trigger || !panel) return;
    
    // 点击触发按钮
    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        panel.classList.toggle('show');
        
        if (panel.classList.contains('show')) {
            // 面板打开时延迟标记为已读
            setTimeout(markAllAsRead, 1000);
        }
    });
    
    // 点击文档其他地方关闭面板
    document.addEventListener('click', (e) => {
        if (!panel.contains(e.target) && !trigger.contains(e.target)) {
            panel.classList.remove('show');
        }
    });
    
    // 阻止面板内部点击冒泡
    panel.addEventListener('click', (e) => {
        e.stopPropagation();
    });
}

// 标记所有通知为已读
function markAllAsRead() {
    if (notificationData.notifications) {
        notificationData.notifications = notificationData.notifications.map(n => ({ ...n, read: true }));
        renderNotifications();
    }
}

// 清空通知
function clearNotifications() {
    if (confirm('确定要清空所有通知吗？')) {
        notificationData.notifications = [];
        renderNotifications();
        notify('已清空所有通知', 'ok');
    }
}

// 在现有事件委托中添加通知相关处理
document.addEventListener('click', (e) => {
    const action = e.target.closest('[data-action]')?.dataset.action;
    
    if (action === 'clear-notifications') {
        clearNotifications();
    }
});


// ========================================
// 协议健康状态渲染函数
// 添加到 edgebox-panel.js 文件中
// ========================================

/**
 * 加载协议健康数据
 */
async function loadProtocolHealth() {
    try {
        const response = await fetch('/traffic/protocol-health.json');
        if (!response.ok) {
            // 如果健康检查文件不存在，降级到旧版本显示
            console.warn('协议健康数据不可用，使用降级显示');
            return null;
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('加载协议健康数据失败:', error);
        return null;
    }
}

/**
 * 渲染协议健康状态卡片
 */
function renderProtocolHealthCard(protocol, healthData) {
    const card = document.querySelector(`[data-protocol="${protocol}"]`);
    if (!card) return;

    // 查找该协议的健康数据
    const protocolHealth = healthData?.protocols?.find(p => p.protocol === protocol);
    
    if (!protocolHealth) {
        // 如果没有健康数据，保持原有显示
        return;
    }

    // 更新状态列
    const statusCell = card.querySelector('.protocol-status');
    if (statusCell) {
        // 创建新的状态显示
        const statusHTML = `
            <div class="health-status-container">
                <div class="health-status-badge ${protocolHealth.status}">
                    ${protocolHealth.status_badge}
                </div>
                <div class="health-detail-message">
                    ${protocolHealth.detail_message}
                </div>
                ${protocolHealth.recommendation_badge ? `
                    <div class="health-recommendation-badge">
                        ${protocolHealth.recommendation_badge}
                    </div>
                ` : ''}
            </div>
        `;
        
        statusCell.innerHTML = statusHTML;
    }

    // 可选：添加健康分数显示
    const scoreCell = card.querySelector('.protocol-health-score');
    if (scoreCell) {
        scoreCell.textContent = protocolHealth.health_score;
        scoreCell.className = `protocol-health-score score-${getScoreLevel(protocolHealth.health_score)}`;
    }
}

/**
 * 获取健康分数等级
 */
function getScoreLevel(score) {
    if (score >= 85) return 'excellent';
    if (score >= 70) return 'good';
    if (score >= 50) return 'fair';
    return 'poor';
}


//名称标准化到健康数据的 protocol 键
function normalizeProtoKey(name) {
  const key = String(name || '').trim().toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[–—]/g, '-'); // 兼容不同的连字符
  const map = {
    'vless-reality': 'reality',
    'vless-grpc': 'grpc',
    'vless-websocket': 'ws',
    'trojan-tls': 'trojan',
    'hysteria2': 'hysteria2',
    'tuic': 'tuic'
  };
  return map[key] || key;
}

/*** 渲染协议表格（完整版） */

function renderProtocolTable(protocolsOpt, healthOpt) {
  // ========== 🛡️ 防御性检查 ==========
  
  // 1. 检查 DOM 元素
  const tbody = document.getElementById('protocol-tbody');
  if (!tbody) {
    console.warn('[renderProtocolTable] tbody元素不存在，跳过渲染');
    return false;
  }
  
  // 2. 获取协议数据（支持多种来源）
  let protocols = [];
  
  if (Array.isArray(protocolsOpt) && protocolsOpt.length > 0) {
    protocols = protocolsOpt;
  } else if (window.dashboardData?.protocols && Array.isArray(window.dashboardData.protocols)) {
    protocols = window.dashboardData.protocols;
  }
  
  // 3. 数据验证
  if (!protocols || protocols.length === 0) {
    console.warn('[renderProtocolTable] 协议数据为空，等待数据加载...');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:#6b7280;">正在加载协议配置...</td></tr>';
    return false;
  }
  
  console.log('[renderProtocolTable] 开始渲染，协议数量:', protocols.length);
  
  // ========== 🎨 开始渲染 ==========
  
  tbody.innerHTML = '';
  
  const health = healthOpt || window.__protocolHealth || null;
  
  protocols.forEach((p, index) => {
    try {
      const protoKey = normalizeProtoKey(p.name);
      const h = health?.protocols?.find(x => x.protocol === protoKey);

      const tr = document.createElement('tr');
      tr.dataset.protocol = protoKey;
      tr.innerHTML = `
        <td>${escapeHtml(p.name)}</td>
        <td>${escapeHtml(p.fit || p.scenario || '—')}</td>
        <td>${escapeHtml(p.effect || p.camouflage || '—')}</td>
        <td class="protocol-status">
          ${h ? `
            <div class="health-status-inline">
              <span class="health-badge ${h.status}">${h.status_badge}</span>
              <span class="health-message">${h.detail_message}</span>
            </div>
          ` : `<span class="status-badge ${p.status === '运行中' ? 'status-running' : ''}">${p.status || '—'}</span>`}
        </td>
        <td>
          <button class="btn btn-sm btn-link"
                  data-action="open-modal"
                  data-modal="configModal"
                  data-protocol="${escapeHtml(p.name)}">查看配置</button>
        </td>
      `;
      tbody.appendChild(tr);
    } catch (error) {
      console.error('[renderProtocolTable] 渲染协议失败:', p.name, error);
    }
  });

  // 添加整包协议行
  try {
    const subRow = document.createElement('tr');
    subRow.className = 'subs-row';
    subRow.innerHTML = `
      <td style="font-weight:500;">整包协议</td>
      <td></td>
      <td></td>
      <td></td>
      <td><button class="btn btn-sm btn-link" data-action="open-modal" data-modal="configModal" data-protocol="__SUBS__">查看@订阅</button></td>
    `;
    tbody.appendChild(subRow);
  } catch (error) {
    console.error('[renderProtocolTable] 添加整包协议行失败:', error);
  }
  
  console.log('[renderProtocolTable] 渲染完成，总行数:', tbody.querySelectorAll('tr').length);
  return true;
}


/**
 * 显示健康状态摘要
 */
function renderHealthSummary(healthData) {
    const summaryContainer = document.querySelector('#health-summary');
    if (!summaryContainer || !healthData) return;

    const { summary } = healthData;
    
    summaryContainer.innerHTML = `
        <div class="health-summary-card">
            <div class="summary-item">
                <span class="summary-label">总计协议</span>
                <span class="summary-value">${summary.total}</span>
            </div>
            <div class="summary-item healthy">
                <span class="summary-label">✅ 健康</span>
                <span class="summary-value">${summary.healthy}</span>
            </div>
            <div class="summary-item degraded">
                <span class="summary-label">⚠️ 降级</span>
                <span class="summary-value">${summary.degraded}</span>
            </div>
            <div class="summary-item down">
                <span class="summary-label">❌ 异常</span>
                <span class="summary-value">${summary.down}</span>
            </div>
            <div class="summary-item score">
                <span class="summary-label">平均健康分</span>
                <span class="summary-value score-${getScoreLevel(summary.avg_health_score)}">
                    ${summary.avg_health_score}
                </span>
            </div>
        </div>
        <div class="health-recommended">
            <strong>推荐协议：</strong>
            ${healthData.recommended.join(', ') || '暂无推荐'}
        </div>
        <div class="health-update-time">
            最后更新: ${new Date(healthData.updated_at).toLocaleString('zh-CN')}
        </div>
    `;
}

/*** 主初始化函数 - 在页面加载时调用 */
async function initializeProtocolHealth() {
  const healthData = await loadProtocolHealth();
  if (healthData) {
    window.__protocolHealth = healthData;
    renderHealthSummary(healthData);
    renderProtocolTable(); // ✅ 叠加健康徽章到表格
  } else {
    console.warn('健康数据加载失败，使用“运行中”降级显示');
  }
}

// ========================================
// 自动刷新逻辑
// ========================================

/**
 * 定期刷新协议健康状态
 */
function startHealthAutoRefresh(intervalSeconds = 30) {
    // 首次加载
    initializeProtocolHealth();
    
    // 定期刷新
    setInterval(() => {
        initializeProtocolHealth();
    }, intervalSeconds * 1000);
}

EXTERNAL_JS
