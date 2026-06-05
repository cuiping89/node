// =================================================================
// EdgeBox Panel v4.7.0 - 两协议架构 (Reality + Hysteria2)
// =================================================================

// ========================================
// 全局状态管理
// ========================================
let dashboardData = {};   // 仪表盘数据
let trafficData = {};     // 流量统计数据
let systemData = {};      // 系统资源数据
let notificationData = { notifications: [] }; // 通知数据
let overviewTimer = null; // 定时刷新计时器
let __IPQ_REQ_SEQ__ = 0;  // IP质量查询并发守卫

const GiB = 1024 * 1024 * 1024; // GiB 单位换算常量

// ========================================
// Chart.js 自定义插件 (已废弃,保留备用)
// ========================================
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

// ========================================
// 工具函数
// ========================================

/**
 * 异步获取 JSON 数据
 * @param {string} url - 请求地址
 * @returns {Promise<Object|null>} JSON 对象或 null
 */
async function fetchJSON(url) {
  try {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error(`Fetch error for ${url}:`, error);
    return null;
  }
}

/**
 * 读取告警公共阈值配置（v4.6.0-rc1）
 * 注: 仅含 monthly_gib + steps，不含任何 Token/Webhook 等机密
 * 机密保存在 /etc/edgebox/config/alert.env (root 600), 浏览器无法读取
 * @returns {Promise<Object>} 阈值对象，键名兼容旧版 (ALERT_STEPS / ALERT_MONTHLY_GIB)
 */
async function fetchAlertConfig() {
  try {
    const response = await fetch('/traffic/alert-public.json', { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    const data = await response.json();
    // 适配旧字段名以兼容老代码
    return {
      ALERT_STEPS: (data.steps || [30, 60, 90]).join(','),
      ALERT_MONTHLY_GIB: String(data.monthly_gib || 200),
    };
  } catch (error) {
    console.error('Failed to fetch alert-public.json:', error);
    return { ALERT_STEPS: '30,60,90', ALERT_MONTHLY_GIB: '200' };
  }
}

/**
 * 安全获取对象嵌套属性
 * @param {Object} obj - 对象
 * @param {string} path - 属性路径(用 . 分隔)
 * @param {*} fallback - 默认值
 * @returns {*} 属性值或默认值
 */
function safeGet(obj, path, fallback = '—') {
  const value = path.split('.').reduce((acc, part) => acc && acc[part], obj);
  return value !== null && value !== undefined && value !== '' ? value : fallback;
}

/**
 * HTML 转义函数
 * @param {string} s - 待转义字符串
 * @returns {string} 转义后字符串
 */
function escapeHtml(s = '') {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * 轻提示通知
 * @param {string} msg - 提示消息
 * @param {string} type - 类型: ok/warn/info
 * @param {number} ms - 显示时长(毫秒)
 */
function notify(msg, type = 'ok', ms = 1500) {
  // 优先在打开的弹窗内显示,否则在页面中央显示
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
    // 页面级提示
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

/**
 * 兼容各环境的文本复制函数
 * @param {string} text - 待复制文本
 * @returns {Promise<boolean>} 是否成功
 */
async function copyTextFallbackAware(text) {
  if (!text) throw new Error('empty');
  try {
    // 安全上下文优先使用 Clipboard API
    if ((location.protocol === 'https:' || location.hostname === 'localhost') && navigator.clipboard) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    throw new Error('insecure');
  } catch {
    // 降级使用 execCommand
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.readOnly = true;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    if (!ok) throw new Error('execCommand failed');
    return true;
  }
}

/**
 * DOM 选择器简写
 */
function $(sel, root = document) { return root.querySelector(sel); }
function $all(sel, root = document) { return [...root.querySelectorAll(sel)]; }

// ========================================
// UI 渲染函数
// ========================================

/**
 * 渲染系统概览卡片
 */
function renderOverview() {
  // 兼容取数(优先闭包变量,取不到再用 window.*)
  const dash = (typeof dashboardData !== 'undefined' && dashboardData) ||
               (typeof window !== 'undefined' && window.dashboardData) || {};
  const sys  = (typeof systemData !== 'undefined' && systemData) ||
               (typeof window !== 'undefined' && window.systemData) || {};

  // 拆解数据结构
  const server   = dash.server || {};
  const services = dash.services || {};

  // DOM 操作辅助函数
  const setText = (id, text, setTitle) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = (text === undefined || text === null || text === '') ? '—' : String(text);
    if (setTitle) el.title = el.textContent;
  };
  const setWidth = (id, pct) => {
    const el = document.getElementById(id);
    if (el) el.style.width = `${pct}%`;
  };
  const clamp = v => Math.max(0, Math.min(100, Number(v) || 0));
  const pick  = (...xs) => xs.find(v => v !== undefined && v !== null && v !== '') ?? 0;
  const toYMD = (v) => {
    if (!v) return '—';
    const d = new Date(v);
    return isNaN(d) ? String(v).slice(0, 10) : d.toISOString().slice(0, 10);
  };
  const toggleBadge = (sel, running) => {
    const el = document.querySelector(sel);
    if (!el) return;
    el.textContent = running ? '运行中 √' : '已停止';
    el.classList.toggle('status-running', !!running);
    el.classList.toggle('status-stopped', !running);
  };

  // 服务器基本信息
  const remark   = server.user_alias ?? server.remark ?? '未备注';
  const provider = server.cloud?.provider ?? server.cloud_provider ?? 'Independent';
  const region   = server.cloud?.region ?? server.cloud_region ?? 'Unknown';
  setText('user-remark',  remark, true);
  setText('cloud-region', `${provider} | ${region}`, true);
  setText('instance-id',  server.instance_id ?? 'Unknown', true);
  setText('hostname',     server.hostname ?? '-', true);

  // 服务器配置(条中文本 + 百分比)
  setText('cpu-info',  server.spec?.cpu ?? '—', true);
  setText('disk-info', server.spec?.disk ?? '—', true);

  // 内存条文本(spec.memory 缺失或为 0 时从 sys 组装)
  const fmtGiB = (b) => {
    const n = Number(b);
    if (!Number.isFinite(n)) return null;
    return Math.round((n / (1024 ** 3)) * 10) / 10;
  };
  let memText = server.spec?.memory ?? '';
  if (!memText || /^0\s*GiB$/i.test(memText)) {
    const totalB = pick(sys.mem_total, sys.total_mem, sys.memory_total, sys.mem?.total);
    const usedB  = pick(sys.mem_used, sys.used_mem, sys.memory_used, sys.mem?.used);
    const freeB  = pick(sys.mem_free, sys.free_mem, sys.memory_free, sys.mem?.free,
                        (totalB != null && usedB != null) ? (totalB - usedB) : undefined);
    const total = fmtGiB(totalB), used = fmtGiB(usedB), free = fmtGiB(freeB);
    memText = (total != null) ? (used != null && free != null ? `${total}GiB(已用: ${used}GiB, 可用: ${free}GiB)` : `${total}GiB`) : '—';
  }
  setText('mem-info', memText, true);

  // 资源使用百分比(多字段名兼容)
  const cpuPct  = clamp(pick(sys.cpu, sys.cpu_usage, sys['cpu-percent'], sys.metrics?.cpu, dash.metrics?.cpu));
  const memPct  = clamp(pick(sys.memory, sys.mem, sys['memory-percent'], sys.metrics?.memory, dash.metrics?.memory));
  const diskPct = clamp(pick(sys.disk, sys.disk_usage, sys['disk-percent'], sys.metrics?.disk, dash.metrics?.disk));

  setWidth('cpu-progress',  cpuPct);  setText('cpu-percent',  `${cpuPct}%`);
  setWidth('mem-progress',  memPct);  setText('mem-percent',  `${memPct}%`);
  setWidth('disk-progress', diskPct); setText('disk-percent', `${diskPct}%`);

  // 核心服务版本与状态
  const versions = {
    nginx:   services.nginx?.version || '',
    xray:    services.xray?.version || '',
    singbox: (services['sing-box']?.version || services.singbox?.version || '')
  };

  setText('nginx-version',   versions.nginx ? `版本 ${versions.nginx}` : '—', true);
  setText('xray-version',    versions.xray ? `版本 ${versions.xray}` : '—', true);
  setText('singbox-version', versions.singbox ? `版本 ${versions.singbox}` : '—', true);

toggleBadge('#system-overview .core-services .service-item:nth-of-type(1) .status-badge', services.nginx?.status?.includes('运行中'));
  toggleBadge('#system-overview .core-services .service-item:nth-of-type(2) .status-badge', services.xray?.status?.includes('运行中'));
  toggleBadge('#system-overview .core-services .service-item:nth-of-type(3) .status-badge',
              (services['sing-box']?.status || services.singbox?.status)?.includes('运行中'));

  // 顶部版本/日期摘要
  const metaText = `版本号: ${server.version || '—'} | 安装日期: ${toYMD(server.install_date)} | 更新时间: ${toYMD(dash.updated_at || Date.now())}`;
  setText('sys-meta', metaText);
}

/**
 * 渲染证书与网络配置卡片 (UI State Reset Fix)
 */
function renderCertificateAndNetwork() {
  const data   = window.dashboardData || {};
  const server = data.server || {};
  const cert   = server.cert || {};
  const shunt  = data.shunt || {};

  // Helper to set text content
  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text || '—';
  };

  // ... (certificate rendering part remains the same) ...
  const certMode = String(safeGet(cert, 'mode', 'self-signed'));
  document.getElementById('cert-self')?.classList.toggle('active', certMode === 'self-signed');
  document.getElementById('cert-ca')?.classList.toggle('active', certMode.startsWith('letsencrypt'));
  setText('cert-type', certMode.startsWith('letsencrypt') ? "Let's Encrypt" : "自签名");
  setText('cert-domain', safeGet(cert, 'domain', '—'));
  setText('cert-renewal', certMode.startsWith('letsencrypt') ? '自动' : '手动');
  setText('cert-expiry', safeGet(cert, 'expires_at', '—'));

  // Outbound mode highlighting
  const shuntMode = String(safeGet(shunt, 'mode', 'vps')).toLowerCase();
  ['net-vps', 'net-proxy', 'net-shunt'].forEach(id => document.getElementById(id)?.classList.remove('active'));

  const vpsIp = safeGet(data, 'server.eip') || safeGet(data, 'server.server_ip') || '—';
  setText('vps-ip', vpsIp);

  // <<< FIX: Logic to clear or populate the proxy card >>>
  if (shuntMode.includes('resi') || shuntMode.includes('direct')) {
    // Populate proxy card for resi or direct-resi modes
    if (shuntMode.includes('direct')) {
        document.getElementById('net-shunt')?.classList.add('active');
    } else {
        document.getElementById('net-proxy')?.classList.add('active');
    }

    const proxyRaw = String(safeGet(shunt, 'proxy_info', ''));
    // (formatProxy function remains the same as in your script)
    function formatProxy(raw){if(!raw)return"—";try{const o=/^[a-z][a-z0-9+.\-]*:\/\//i.test(raw)?raw:"socks5://"+raw,t=new URL(o),e=t.protocol.replace(/:$/,""),r=t.hostname||"",l=t.port||"";return r&&l?`${e}//${r}:${l}`:r?`${e}//${r}`:"—"}catch(o){const t=/^([a-z0-9+.\-]+):\/\/(?:[^@\/\s]+@)?(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?/i,e=raw.match(t);if(e){const o=e[1],t=e[2],r=e[3]||"";return r?`${o}//${t}:${r}`:`${o}//${t}`}const r=/^(?:([a-z0-9+.\-]+)\s+)?(\[[^\]]+\]|[^:\/?#\s]+)(?::(\d+))?$/i,l=raw.match(r);return l?(l[3]||""?`${l[1]||"socks5"}//${l[2]}:${l[3]}`:`${l[1]||"socks5"}//${l[2]}`):"—"}}
    setText('proxy-ip', formatProxy(proxyRaw));

    // Async fetch for proxy details
    fetch('/status/ipq_proxy.json', { cache: 'no-store' })
        .then(r => r.ok ? r.json() : null)
        .then(j => {
            if (j && j.status !== 'not_configured') {
                const geo = [j.country, j.city].filter(Boolean).join(' · ');
                setText('proxy-geo', geo);
                setText('proxy-ipq-score', j.score != null ? `${j.score} (${j.grade})` : '—');
            } else {
                setText('proxy-geo', '—');
                setText('proxy-ipq-score', '检测中...');
            }
        });
  } else {
    // Clear proxy card for VPS mode
    document.getElementById('net-vps')?.classList.add('active');
    setText('proxy-ip', '—');
    setText('proxy-geo', '—');
    setText('proxy-ipq-score', '—');
  }

  // Async fetch for VPS details (always runs)
  fetch('/status/ipq_vps.json', { cache: 'no-store' })
      .then(r => r.ok ? r.json() : null)
      .then(j => {
          if (j) {
              const geo = [j.country, j.city].filter(Boolean).join(' · ');
              setText('vps-geo', geo);
              setText('vps-ipq-score', j.score != null ? `${j.score} (${j.grade})` : '—');
          }
      });

  const whitelist = data.shunt?.whitelist || [];
  const preview = document.getElementById('whitelistPreview');
  if (preview) {
    if (!whitelist.length) {
      preview.innerHTML = '<span class="whitelist-text">(无)</span>';
    } else {
      const firstDomain = whitelist[0] || '';
      const shortText = firstDomain.length > 9 ? firstDomain.substring(0, 9) + '...' : firstDomain;
      preview.innerHTML =
        `<span class="whitelist-text">${escapeHtml(shortText)}</span>` +
        `<button class="whitelist-more" data-action="open-modal" data-modal="whitelistModal">查看全部</button>`;
    }
  }
}

/**
 * 渲染流量统计图表
 */
function renderTrafficCharts() {
  if (!trafficData || !window.Chart) return;

  // 渲染本月使用进度条
  const monthly = trafficData.monthly || [];
  const currentMonthData = monthly.find(m => m.month === new Date().toISOString().slice(0, 7));

  if (currentMonthData) {
    const used = (currentMonthData.total || 0) / GiB;
    const percentage = Math.min(100, Math.round((used / 100) * 100));
    const fillEl = document.getElementById('progress-fill');
    const pctEl = document.getElementById('progress-percentage');
    const budgetEl = document.getElementById('progress-budget');

    if (fillEl) fillEl.style.width = `${percentage}%`;
    if (pctEl) pctEl.textContent = `${percentage}%`;
    if (budgetEl) budgetEl.textContent = `阈值(100GiB)`;
    if (pctEl) pctEl.title = `已用 ${used.toFixed(1)}GiB / 阈值 100GiB`;

    // 异步获取配置并更新阈值刻度线
    fetchAlertConfig().then(alertConfig => {
      const budget = parseInt(alertConfig.ALERT_MONTHLY_GIB) || 100;
      const alertSteps = (alertConfig.ALERT_STEPS || '30,60,90').split(',').map(s => parseInt(s.trim()));

      const realPercentage = Math.min(100, Math.round((used / budget) * 100));

      if (fillEl) fillEl.style.width = `${realPercentage}%`;
      if (pctEl) pctEl.textContent = `${realPercentage}%`;
      if (budgetEl) budgetEl.textContent = `阈值(${budget}GiB)`;
      if (pctEl) pctEl.title = `已用 ${used.toFixed(1)}GiB / 阈值 ${budget}GiB`;

      renderTrafficProgressThresholds(alertSteps);
    }).catch(err => {
      console.warn('无法加载 alert.conf, 使用默认配置:', err);
      renderTrafficProgressThresholds([30, 60, 90]);
    });
  }

  function renderTrafficProgressThresholds(thresholds) {
    const trafficProgressBar = document.querySelector('.traffic-card .progress-bar');
    if (!trafficProgressBar) return;

    const existingMarkers = trafficProgressBar.querySelectorAll('.traffic-threshold-marker');
    const existingLabels = trafficProgressBar.querySelectorAll('.traffic-threshold-label');
    existingMarkers.forEach(marker => marker.remove());
    existingLabels.forEach(label => label.remove());

    thresholds.forEach(threshold => {
      if (threshold > 0 && threshold <= 100) {
        const marker = document.createElement('div');
        marker.className = 'traffic-threshold-marker';
        marker.style.cssText = `
          position: absolute;
          left: ${threshold}%;
          top: 0;
          bottom: 0;
          width: 2px;
          background: #9ca3af;
          z-index: 10;
          transform: translateX(-50%);
          border-radius: 1px;
        `;

        const label = document.createElement('div');
        label.className = 'traffic-threshold-label';
        label.textContent = `${threshold}%`;
        label.style.cssText = `
          position: absolute;
          left: ${threshold}%;
          top: 50%;
          transform: translate(-50%, -50%);
          font-size: 12px;
          color: #fbbf24;
          white-space: nowrap;
          font-weight: 600;
          pointer-events: none;
          z-index: 11;
          text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
        `;

        trafficProgressBar.appendChild(marker);
        trafficProgressBar.appendChild(label);
      }
    });
  }

  // 销毁已存在的图表实例
  ['traffic', 'monthly-chart'].forEach(id => {
    const inst = Chart.getChart(id);
    if (inst) inst.destroy();
  });

  // 颜色定义
  const vpsColor = '#3b82f6';
  const proxyColor = '#10b981';

  // 近30日流量折线图
  const daily = trafficData.last30d || [];
  if (daily.length) {
    const ctx = document.getElementById('traffic');
    if (ctx) {
      new Chart(ctx, {
        type: 'line',
        data: {
          labels: daily.map(d => d.date.slice(5)),
          datasets: [
            {
              label: 'VPS',
              data: daily.map(d => d.vps / GiB),
              borderColor: vpsColor,
              backgroundColor: vpsColor,
              tension: 0.3,
              pointRadius: 0,
              fill: false
            },
            {
              label: '代理',
              data: daily.map(d => d.resi / GiB),
              borderColor: proxyColor,
              backgroundColor: proxyColor,
              tension: 0.3,
              pointRadius: 0,
              fill: false
            },
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          layout: {
            padding: { bottom: 22 }
          },
          scales: {
            x: { ticks: { padding: 6 } },
            y: { ticks: { padding: 6 } }
          }
        }
      });
    }
  }

  // 近12个月流量堆叠柱状图
  if (monthly.length) {
    const arr = monthly.slice(-12);
    const ctx = document.getElementById('monthly-chart');
    if (ctx) {
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: arr.map(m => m.month),
          datasets: [
            {
              label: 'VPS',
              data: arr.map(m => m.vps / GiB),
              backgroundColor: vpsColor,
              stack: 'a'
            },
            {
              label: '代理',
              data: arr.map(m => m.resi / GiB),
              backgroundColor: proxyColor,
              stack: 'a'
            },
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          layout: {
            padding: { bottom: 22 }
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

// ========================================
// 弹窗交互逻辑
// ========================================

/**
 * 显示弹窗
 */
function showModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'block';
    document.body.classList.add('modal-open');
  }
}

/**
 * 关闭弹窗
 */
function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'none';
    document.body.classList.remove('modal-open');
  }
}

/**
 * 显示白名单弹窗
 */
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

/**
 * 显示配置详情弹窗
 */
/**
 * 显示配置详情弹窗 (SNI修复版)
 */
function showConfigModal(protocolKey) {
  const dd = window.dashboardData;
  const modal = document.getElementById('configModal');
  if (!modal || !dd) return;

  const title = document.getElementById('configModalTitle');
  const details = document.getElementById('configDetails');
  const footer = modal.querySelector('.modal-footer');
  if (!title || !details || !footer) return;

  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toB64 = s => btoa(unescape(encodeURIComponent(s)));
  const get = (o, p, fb = '') => p.split('.').reduce((a, k) => (a && a[k] !== undefined ? a[k] : undefined), o) ?? fb;

  const certMode = String(get(dd, 'server.cert.mode', 'self-signed'));
  const isLE = certMode.startsWith('letsencrypt');
  const serverIp = get(dd, 'server.server_ip', '');
  const domain = get(dd, 'server.cert.domain', '');
  const hostAddress = isLE && domain ? domain : serverIp;

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

  details.innerHTML = '<div class="loading">正在加载配置…</div>';
  modal.style.display = 'block';
  document.body.classList.add('modal-open');

  let qrText = '';

  if (protocolKey === '__SUBS__') {
    // v4.7.0 (前端 #3): 弹窗显示 4 种格式 URL — 不同客户端用不同后缀
    const baseUrl = get(dd, 'subscription_url', '') ||
                (get(dd, 'server.server_ip', '')
                  ? ('http://' + get(dd, 'server.server_ip') + '/' +
                     (get(dd, 'secrets.master_sub_token', '')
                       ? ('sub-' + get(dd, 'secrets.master_sub_token'))
                       : 'sub'))
                  : '');
    const urls = {
      plain:   baseUrl,                  // v2rayN / v2rayNG / Streisand
      clash:   baseUrl + '.clash',       // Clash Verge / Mihomo
      singbox: baseUrl + '.singbox',     // sing-box / NekoBox
      base64:  baseUrl + '.base64'       // 旧版 / Base64 兼容
    };

    title.textContent = '订阅(整包)';
    details.innerHTML = `
      <div class="config-section">
        <h4>🔗 订阅 URL (v2rayN / v2rayNG)</h4>
        <div class="config-code" id="plain-link">${esc(urls.plain)}</div>
      </div>
      <div class="config-section">
        <h4>🔗 订阅 URL (Clash Verge / Mihomo)</h4>
        <div class="config-code" id="clash-link">${esc(urls.clash)}</div>
      </div>
      <div class="config-section">
        <h4>🔗 订阅 URL (sing-box / NekoBox)</h4>
        <div class="config-code" id="singbox-link">${esc(urls.singbox)}</div>
      </div>
      <div class="config-section">
        <h4>🔗 订阅 URL (Base64 兼容)</h4>
        <div class="config-code" id="base64-link">${esc(urls.base64)}</div>
      </div>
      <div class="config-section">
        <h4>二维码 (默认 URL)</h4>
        <div class="qr-container">
          <div id="qrcode-sub"></div>
        </div>
      </div>
      ${usage('按客户端类型选用对应 URL：v2rayN/v2rayNG 用默认 URL；Clash Verge/Mihomo 用 <code>.clash</code>；sing-box/NekoBox 用 <code>.singbox</code>；旧版客户端用 <code>.base64</code>。二维码默认编码 v2rayN URL。')}
    `;
    footer.innerHTML = `
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain">复制 v2rayN URL</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="clash">复制 Clash URL</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="singbox">复制 sing-box URL</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="base64">复制 Base64 URL</button>
      <button class="btn btn-sm btn-secondary" data-action="copy-qr">复制二维码</button>
    `;

    qrText = urls.plain || '';

  } else {
    const protocols = Array.isArray(dd.protocols) ? dd.protocols : [];
    const p = protocols.find(x =>
      x && (x.name === protocolKey || x.protocol === protocolKey)
    );

    if (!p) {
      title.textContent = '配置详情';
      details.innerHTML = `<div class="empty">未找到协议: code>${esc(String(protocolKey))}</code></div>`;
      footer.innerHTML = `<button class="btn btn-sm" data-action="close-modal" data-modal="configModal">关闭</button>`;
      return;
    }

    // ==================== 关键修复点 START ====================
    let finalSni = isLE ? domain : hostAddress; // 默认SNI

    // Reality / Hysteria2：从 share_link 中精确提取 SNI
    if ((p.name === 'VLESS-Reality' || p.name === 'Hysteria2') && p.share_link) {
        try {
            // 对于vless链接，使用URLSearchParams
            if (p.share_link.startsWith('vless://')) {
                const url = new URL(p.share_link);
                const params = new URLSearchParams(url.search);
                if (params.has('sni')) {
                    finalSni = params.get('sni');
                }
            }
            // v4.7.0: 仅 Reality + Hysteria2 (gRPC/trojan/tuic/ws 均已移除)
        } catch (e) {
            console.warn("Could not parse share_link to extract SNI", e);
        }
    }
    // ===================== 关键修复点 END =====================

    const obj = {
      protocol: p.name,
      host: hostAddress,
      port: p.port ?? 443,
      uuid: get(dd, `secrets.vless.${p.protocol}`) || get(dd, `secrets.password.${p.protocol}`),
      sni: finalSni,
      alpn: (p.name || '').toLowerCase().includes('hysteria') ? 'h3' : ''
    };
    if (p.protocol === 'hysteria2') {
        obj.uuid = get(dd, 'secrets.password.hysteria2');
    }

    const comments = {
      protocol: '协议类型',
      host: '服务器地址(IP/域名)',
      port: '端口',
      uuid: '认证 UUID / 密码',
      sni: 'TLS/SNI',
      alpn: 'ALPN(Hysteria2=h3)'
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
      ${usage('复制明文或 JSON 导入客户端; 若客户端支持扫码添加, 也可直接扫描二维码。')}
    `;
    footer.innerHTML = `
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="json">复制 JSON</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="plain">复制明文链接</button>
      <button class="btn btn-sm btn-secondary" data-action="copy" data-type="base64">复制 Base64</button>
      <button class="btn btn-sm btn-secondary" data-action="copy-qr">复制二维码</button>
    `;

    qrText = plain || '';
  }

  // 二维码生成逻辑
  if (qrText && window.QRCode) {
    const holderId = (protocolKey === '__SUBS__') ? 'qrcode-sub' : 'qrcode-protocol';
    const holder = document.getElementById(holderId);
    if (holder) {
      holder.replaceChildren();
      new QRCode(holder, {
        text: qrText,
        width: 200,
        height: 200,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.M
      });
      const kids = Array.from(holder.children);
      const keep = holder.querySelector('canvas') || kids[0] || null;
      if (keep) {
        kids.forEach(node => { if (node !== keep) node.remove(); });
      }
    }
  }
}


/**
 * 显示 IP 质量检测详情弹窗
 */
async function showIPQDetails(which) {
  const titleEl = document.getElementById('ipqModalTitle');
  const bodyEl = document.getElementById('ipqDetails');
  if (!titleEl || !bodyEl) return;

  const file = which === 'vps' ? '/status/ipq_vps.json' : '/status/ipq_proxy.json';
  titleEl.textContent = which === 'vps' ? 'VPS IP质量检测详情' : '代理 IP质量检测详情';
  bodyEl.innerHTML = `<div class="config-section"><div class="config-code">加载中...</div></div>`;
  showModal('ipqModal');

  let data = null;
  const __seq = ++__IPQ_REQ_SEQ__;

  try {
    const r = await fetch(file, { cache: 'no-store' });
    if (__seq !== __IPQ_REQ_SEQ__) return;
    if (!r.ok) throw new Error('HTTP ' + r.status);
    data = await r.json();
  } catch (err) {
    if (__seq !== __IPQ_REQ_SEQ__) return;
    data = null;
  }

  const dash = window.dashboardData || {};
  const server = dash.server || {};
  data = data || {
    score: null, grade: null, detected_at: dash.updated_at,
    ip: (which === 'vps' ? server.server_ip : server.eip) || '',
    asn: '', isp: '', country: '', city: '', rdns: '',
    bandwidth: '', network_type: '', latency_p50: null,
    risk: { proxy: (which === 'proxy'), hosting: true, dnsbl_hits: [] },
    conclusion: ''
  };

  const pick = (o, paths, d = '—') => {
    for (const p of paths) {
      const v = p.split('.').reduce((x, k) => x && x[k] != null ? x[k] : undefined, o);
      if (v != null && v !== '') return v;
    }
    return d;
  };

  const score = pick(data, ['score'], '—');
  const grade = pick(data, ['grade'], null);
  const gradeStr = grade || (typeof score === 'number'
                    ? (score >= 80 ? 'A' : score >= 60 ? 'B' : score >= 40 ? 'C' : 'D') : '—');
  const when = pick(data, ['detected_at', 'updated_at', 'timestamp'], '—');

  const ip = pick(data, ['ip'], '—');
  const asn = pick(data, ['asn'], '');
  const isp = pick(data, ['isp'], '');
  const country = pick(data, ['country', 'geo.country'], '');
  const city = pick(data, ['city', 'geo.city'], '');
  const rdns = pick(data, ['rdns', 'reverse_dns'], '—');

  const bwUp = pick(data, ['bandwidth_up', 'config.bandwidth_up'], null);
  const bwDown = pick(data, ['bandwidth_down', 'config.bandwidth_down'], null);
  const bandwidth = (bwUp || bwDown) ? `${bwUp || '—'} / ${bwDown || '—'}` : (pick(data, ['bandwidth', 'config.bandwidth'], '未配置'));

  const networkType = pick(data, ['network_type', 'net_type'], '—');
  const latency = (() => {
    const v = pick(data, ['latency_p50', 'latency.median', 'latency_ms'], null);
    return v ? `${v} ms` : '—';
  })();

  const riskObj = data.risk || {};
  const flags = [
    riskObj.proxy ? '代理标记' : null,
    riskObj.hosting ? '数据中心' : null,
    riskObj.mobile ? '移动网络' : null,
    riskObj.tor ? 'Tor' : null
  ].filter(Boolean).join('、') || '—';
  const hits = Array.isArray(riskObj.dnsbl_hits) ? riskObj.dnsbl_hits : [];
  const blCount = hits.length;

  const conclusion = pick(data, ['conclusion'], '—');

  const EH = s => String(s || '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));

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
        <li>"代理/数据中心/Tor"等标记会降低分数</li>
        <li>每命中 1 个 DNSBL 黑名单会降低分数</li>
        <li>高时延会降低分数</li>
      </ul>
    </div>`;
}

// ========================================
// 通知中心功能
// ========================================

/**
 * 更新通知中心数据
 */
function updateNotificationCenter(data) {
  notificationData = data || { notifications: [] };
  renderNotifications();
}

/**
 * 渲染通知列表
 */
function renderNotifications() {
  const listEl = document.getElementById('notificationList');
  const badgeEl = document.getElementById('notificationBadge');

  if (!notificationData.notifications || notificationData.notifications.length === 0) {
    if (listEl) {
      listEl.innerHTML = `
        <div class="notification-empty">
          🔔
          <div>暂无通知</div>
        </div>
      `;
    }
    if (badgeEl) badgeEl.style.display = 'none';
    return;
  }

  const unreadCount = notificationData.notifications.filter(n => !n.read).length;

  if (badgeEl) {
    if (unreadCount > 0) {
      badgeEl.textContent = unreadCount > 99 ? '99+' : unreadCount;
      badgeEl.style.display = 'inline-block';
    } else {
      badgeEl.style.display = 'none';
    }
  }

  if (listEl) {
    const iconMap = {
      alert: '⚠️',
      system: '⚙️',
      error: '❌'
    };

    const html = notificationData.notifications.slice(0, 20).map(notification => {
      const timeAgo = getTimeAgo(notification.time);
      const icon = iconMap[notification.type] || iconMap[notification.level] || '📋';
      const unreadClass = notification.read ? '' : 'unread';

      return `
        <div class="notification-item ${unreadClass}">
          <div class="notification-item-icon">${icon}</div>
          <div class="notification-item-content">
            <div class="notification-item-message">${escapeHtml(notification.message)}</div>
            <div class="notification-item-time">${timeAgo}</div>
            ${notification.action ? `<a href="#" class="notification-item-action">${escapeHtml(notification.action)}</a>` : ''}
          </div>
        </div>
      `;
    }).join('');

    listEl.innerHTML = html;
  }
}

/**
 * 时间格式化为相对时间
 */
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

/**
 * 设置通知中心事件监听
 */
function setupNotificationCenter() {
  const trigger = document.getElementById('notificationTrigger');
  const panel = document.getElementById('notificationPanel');
  const clearBtn = document.querySelector('.notification-clear');

  if (!trigger || !panel) return;

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    panel.classList.toggle('show');

    if (panel.classList.contains('show')) {
      setTimeout(markAllAsRead, 1000);
    }
  });

  document.addEventListener('click', (e) => {
    if (!panel.contains(e.target) && !trigger.contains(e.target)) {
      panel.classList.remove('show');
    }
  });

  panel.addEventListener('click', (e) => {
    e.stopPropagation();
  });

  if (clearBtn) {
    clearBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      clearNotifications();
    });
  }
}

/**
 * 标记所有通知为已读
 */
function markAllAsRead() {
  if (notificationData.notifications) {
    notificationData.notifications = notificationData.notifications.map(n => ({ ...n, read: true }));
    renderNotifications();
  }
}

/**
 * 清空通知
 */
function clearNotifications() {
  if (!notificationData.notifications || notificationData.notifications.length === 0) {
    notify('暂无通知需要清空', 'info');
    return;
  }

  notificationData.notifications = [];
  renderNotifications();
  notify('已清空所有通知', 'ok');
}

// ========================================
// 协议健康监控功能
// ========================================

/**
 * 加载协议健康数据
 */
async function loadProtocolHealth() {
  try {
    const resp = await fetch('/traffic/protocol-health.json', { cache: 'no-store' });
    if (!resp.ok) return null;
    return await resp.json();
  } catch (e) {
    console.warn('加载协议健康数据失败:', e);
    return null;
  }
}

/**
 * 协议名称标准化
 */
function normalizeProtoKey(name) {
  const key = String(name || '').trim().toLowerCase().replace(/\s+/g, '-').replace(/[–—]/g, '-');
  // v4.7.0: 仅保留 2 协议架构 (Reality + Hysteria2)
  const map = {
    'vless-reality':   'reality',
    'hysteria2':       'hysteria2'
  };
  return map[key] || key;
}

/**
 * 根据分数获取等级
 */
function getScoreLevel(x) {
  const s = Number(x || 0);
  if (s >= 85) return 'excellent';
  if (s >= 70) return 'good';
  if (s >= 50) return 'fair';
  return 'poor';
}

/**
 * 推荐徽章兜底
 */
function fallbackRecBadge(recRaw) {
  const rec = String(recRaw || '').toLowerCase();
  if (!rec) return '';
  const text = rec === 'primary' ? '🏆 主推'
             : rec === 'recommended' ? '👍 推荐'
             : rec === 'backup' ? '🔄 备用'
             : rec === 'not_recommended' ? '⛔ 暂不推荐'
             : '';
  return text ? `<div class="health-recommendation-badge">${text}</div>` : '';
}

/**
 * 渲染健康摘要卡片
 */
function renderHealthSummary(health) {
  const box = $('#health-summary');
  if (!box || !health) return;

  const sum = health.summary || {};
  const avg = sum.avg_health_score ?? (Array.isArray(health.protocols)
    ? Math.round(health.protocols.map(p => Number(p.score || p.health_score || 0)).reduce((a, b) => a + b, 0) / (health.protocols.length || 1))
    : 0);

  box.innerHTML = `
    <div class="health-summary-card">
      <div class="summary-item"><span class="summary-label">总计协议</span><span class="summary-value">${sum.total ?? (health.protocols?.length || 0)}</span></div>
      <div class="summary-item healthy"><span class="summary-label">健康 √</span><span class="summary-value">${sum.healthy ?? '-'}</span></div>
      <div class="summary-item degraded"><span class="summary-label">降级 ⚠️</span><span class="summary-value">${sum.degraded ?? '-'}</span></div>
      <div class="summary-item down"><span class="summary-label">异常 ❌</span><span class="summary-value">${sum.down ?? '-'}</span></div>
      <div class="summary-item score"><span class="summary-label">平均健康分</span><span class="summary-value score-${getScoreLevel(avg)}">${avg}</span></div>
    </div>
    <div class="health-recommended"><strong>推荐协议:</strong>${(health.recommended || []).join(', ') || '暂无推荐'}</div>
    <div class="health-update-time">最后更新: ${escapeHtml(health.generated_at || health.updated_at || '')}</div>
  `;
}

/**
 * 渲染协议表格
 */
function renderProtocolTable(protocolsOpt) { // 只接收一个参数
  const protocols = Array.isArray(protocolsOpt) ? protocolsOpt : (window.dashboardData?.protocols || []);
  const tbody = $('#protocol-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  protocols.forEach(p => {
    // 直接从协议对象 p 中获取所有信息，不再需要去 health 对象里查找
    const recBadge = p.recommendation_badge || '';
    const tr = document.createElement('tr');
    // BUGFIX: 使用 p.protocol 或标准化的 p.name 作为 key
    const protocolKey = p.protocol || normalizeProtoKey(p.name);
    tr.dataset.protocol = protocolKey;

    tr.innerHTML = `
      <td>${escapeHtml(p.name)}</td>
      <td>${escapeHtml(p.scenario || '—')}</td>
      <td>${escapeHtml(p.camouflage || '—')}</td>
      <td class="protocol-status">
        <div class="health-status-container">
          <div class="health-status-badge ${escapeHtml(p.status || 'unknown')}">
            ${p.status_badge || escapeHtml(p.status || '—')}
          </div>
          <div class="health-detail-message" title="${escapeHtml(p.detail_message || '')}">
            ${escapeHtml(p.detail_message || '')}
          </div>
          ${recBadge}
        </div>
      </td>
      <td>
        <button class="btn btn-sm btn-link" data-action="open-modal" data-modal="configModal" data-protocol="${escapeHtml(p.name)}">查看配置</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // 订阅行的逻辑不变
  const subRow = document.createElement('tr');
  subRow.className = 'subs-row';
  subRow.innerHTML = `
    <td style="font-weight:500;">订阅URL | 整包链接</td><td></td><td></td><td></td>
    <td><button class="btn btn-sm btn-link" data-action="open-modal" data-modal="configModal" data-protocol="__SUBS__">查看@订阅</button></td>`;
  tbody.appendChild(subRow);
}


/**
 * 初始化协议健康监控
 */
async function initializeProtocolHealth() {
  const healthData = await loadProtocolHealth();
  if (healthData) {
    window.__protocolHealth = healthData;
    renderHealthSummary(healthData);
    renderProtocolTable();
  } else {
    console.warn('健康数据不可用, 使用"运行中"降级显示');
  }
}

/**
 * 启动健康状态自动刷新
 */
function startHealthAutoRefresh(intervalSeconds = 30) {
  initializeProtocolHealth();
  setInterval(initializeProtocolHealth, intervalSeconds * 1000);
}

// ========================================
// 主应用程序逻辑
// ========================================

/**
 * 刷新所有数据
 */
async function refreshAllData() {
  // 只请求聚合后的主要数据文件
  const [dash, sys, traf, notif] = await Promise.all([
    fetchJSON('/traffic/dashboard.json'),
    fetchJSON('/traffic/system.json'),
    fetchJSON('/traffic/traffic.json'),
    fetchJSON('/traffic/notifications.json')
  ]);

  if (dash) {
    dashboardData = dash;
    window.dashboardData = dashboardData;
    // 健康摘要数据也从 dashboard.json 中读取
    // 注意: 后端需要将健康摘要聚合到 dashboard.json 中 (当前脚本已支持)
    if(dash.health_summary) {
       renderHealthSummary(dash.health_summary);
    }
  }
  if (sys) systemData = sys;
  if (traf) trafficData = traf;
  if (notif) updateNotificationCenter(notif);

  renderOverview();
  renderCertificateAndNetwork();
  renderProtocolTable(); // 调用时不再传递 health 数据
  renderTrafficCharts();
}


/**
 * DOM 加载完成后初始化
 */
document.addEventListener('DOMContentLoaded', () => {
  refreshAllData();
  overviewTimer = setInterval(refreshAllData, 30000);
  setupNotificationCenter();
});

// ========================================
// 事件委托 (统一处理所有交互)
// ========================================
(() => {
  if (window.__EDGEBOX_DELEGATED__) return;
  window.__EDGEBOX_DELEGATED__ = true;

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;

    const action = btn.dataset.action;
    const modal = btn.dataset.modal || '';
    const protocol = btn.dataset.protocol || '';

    switch (action) {
      case 'open-modal': {
        if (modal === 'configModal') {
          if (typeof showConfigModal === 'function') showConfigModal(protocol);
          const m = document.getElementById('configModal');
          if (m && m.style.display !== 'block') showModal('configModal');
        } else if (modal === 'whitelistModal') {
          const list = (window.dashboardData?.shunt?.whitelist) || [];
          const box = $('#whitelistList');
          if (box) box.innerHTML = list.map(d => `<div class="whitelist-item">${String(d)
            .replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))}</div>`).join('');
          showModal('whitelistModal');
        } else if (modal === 'ipqModal') {
          if (typeof showIPQDetails === 'function') {
            await showIPQDetails(btn.dataset.ipq || 'vps');
          } else {
            showModal('ipqModal');
          }
        }
        break;
      }

      case 'close-modal': {
        closeModal(modal);
        break;
      }

      case 'copy': {
        const host = btn.closest('.modal-content');
        // v4.7.0 (前端 #3): + clash / singbox for the 4-format subscription popup
        const map = { json: '#json-code', plain: '#plain-link', plain6: '#plain-links-6',
                      clash: '#clash-link', singbox: '#singbox-link', base64: '#base64-link' };
        const el = host && host.querySelector(map[btn.dataset.type]);
        const text = el ? (el.textContent || '').trim() : '';
        try {
          await copyTextFallbackAware(text);
          (window.notify || console.log)('已复制');
        } catch {
          (window.notify || console.warn)('复制失败');
        }
        break;
      }

      case 'copy-qr': {
        const host = btn.closest('.modal-content');
        const cvs = host && host.querySelector('#qrcode-sub canvas, #qrcode-protocol canvas');

        if (!cvs) {
          notify('未找到二维码', 'warn');
          break;
        }

        const doDownload = (blob) => {
          const a = document.createElement('a');
          const url = URL.createObjectURL(blob);
          const name = (protocol || '__SUBS__') + '_qrcode.png';
          a.href = url;
          a.download = name;
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 2000);
        };

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

        cvs.toBlob(async (blob) => {
          if (!blob) {
            notify('获取二维码失败', 'warn');
            return;
          }
          try {
            if (window.isSecureContext && navigator.clipboard?.write && window.ClipboardItem) {
              await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
              notify('二维码已复制到剪贴板');
            } else {
              throw new Error('insecure');
            }
          } catch (err) {
            doDownload(blob);
            await doFallbackText();
            notify('图片复制受限: 已自动下载二维码, 并复制了明文/链接', 'warn');
          }
        }, 'image/png');

        break;
      }
    }
  });
})();

// ========================================
// 复制按钮统一轻提示
// ========================================
document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-role="copy"], .copy-btn, .btn-copy');
  if (!btn) return;

  const modal = btn.closest('.ant-modal, .el-dialog, .modal');
  if (!modal) return;

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

// ========================================
// 脚本加载完成标记
// ========================================
console.log('[EdgeBox Panel] JavaScript 模块已加载完成');

