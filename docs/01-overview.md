
# EdgeBox 控制面板 - V2 技术规范

本文档为 EdgeBox 控制面板 V2 版本的技术实现规范，旨在为前端开发提供清晰的布局、内容、状态及接口约定。

## 1\. 核心理念与统一口径

新版面板的核心是**信息分层**与**状态清晰**。通过模块化的卡片布局，将不同维度的数据进行逻辑隔离，为用户提供更聚焦、更有条理的视觉体验。

### 1.1 术语与命名（统一口径）

为确保前后端开发与最终用户体验的一致性，所有组件和状态的命名需严格遵守以下口径：

  * **通用术语**: 使用“出站”而非“出口”。
  * **卡片标题**:
      * `网络身份配置`
  * **出站模式枚举**:
      * `直连` (Direct)
      * `全代理` (Full-Proxy)
      * `混合` (Shunt)
  * **证书类型**:
      * `Let's Encrypt`
      * `自签名`
  * **空值显示**:
      * 数据获取中或未知: 统一显示 `—`
      * 配置未设置或不存在: 统一显示 显示 `未配置`或`无`

## 2\. 页面布局（12栅格系统）

页面采用响应式的12栅格系统进行布局，确保在不同屏幕尺寸下的兼容性。

  * **第一行: 概览信息**

      * `服务器信息` (占4列)
      * `服务器配置` (占4列)
      * `核心服务` (占4列)

  * **第二行: 核心配置**

      * `证书切换` (占4列)
      * `网络身份配置` (占8列)
          * 内部包含三个横向等分的子区块：`VPS出站IP` / `代理出站IP` / `分流出站`

  * **第三行: 协议详情**

      * `协议配置` (占12列，整行)

  * **第四行: 常用功能 (维持现状)**

      * `订阅链接` (占12列)
      * `流量统计` (占12列)

## 3\. 卡片内容与交互规范

### 3.1 服务器信息 (Card)

  * **用户备注名**: 纯文本。
  * **云厂商/区域**: 格式为 `<提供商> | <Region>` (例: `GCP | us-central1`)。
  * **Instance ID**: 纯文本。
  * **主机名 (Hostname)**: 纯文本。

### 3.2 服务器配置 (Card)

  * **CPU**: 进度条组件。显示 `已用 <pct>%`，后缀附加灰色小字说明，格式为 `<物理核心>C / <线程>T`。
  * **内存**: 进度条组件。显示 `已用 <pct>%`，后缀附加灰色小字说明，格式为 `<总内存>GiB + <虚拟内存>GiB`。
  * **磁盘**: 进度条组件。显示 `已用 <pct>%`，后缀附加灰色小字说明，格式为 `<总量>GiB`。
  * *注: 百分比取整数。*

### 3.3 核心服务 (Card)

  * **服务列表**:
      * Nginx: 显示状态 `运行中 / 已停止 / 异常 / 未安装`，并附带版本号。
      * Xray: 同上。
      * Sing-box: 同上。
  * **交互**: (可选) 点击“详情”可展开一个模态框或下拉区域，显示由后端提供的最近50行服务日志。

### 3.4 证书切换 (Card)
- 第一行放置两个标签：“自签证书”、“CA证书”，当前状态显示为绿色。
  * **证书类型**: `Let's Encrypt` / `自签名`。
  * **绑定域名**: 显示域名字符串，如 `example.com`；若无则显示 `(无)`。
  * **续期方式**: `自动` / `手动` (自签名证书默认为 `手动`)。
  * **到期日期**: 格式为 `YYYY-MM-DD`；自签名证书显示 `—`。

### 3.5 网络身份配置 (Composite Card)

- 这是一个组合卡片，内部包含三个逻辑区块。
- 第一行放置三个标签：VPS出站IP”、代理出站IP”、“混合身份”，当前状态显示为绿色。
#### a) VPS出站IP (Sub-section)

  * **公网身份**: `直连`
  * **VPS出站IP**: 显示IP地址。
  * **ASN/ISP**: 字符串 (例: `AS15169 / Google`)。
  * **Geo**: 格式为 `国家代码-城市` (例: `US-Los Angeles`)。
  * **带宽限制**: 格式为 `上行 <Mbps> / 下行 <Mbps>` (未知则显示 `— / —`)。

#### b) 代理出站IP (Sub-section)

  * **代理身份**: `全代理`
  * **数据内容**: `代理出站IP`, `ASN/ISP`, `Geo`, `带宽限制` 字段同上，但数据来源于当前所用上游代理的出口标识，由后端探活并上报。

#### c) 分流出站 (Sub-section)

  * **混合身份**: `白名单VPS直连 + 其它代理`
  * **白名单**: 列表显示域名或网段。默认显示前3条，超出部分折叠，提供“查看全部”的交互。
  * **备注**: 卡片底部需包含注释：`注：HY2/TUIC 为 UDP 通道，VPS 直连，不走代理分流`。

### 3.6 协议配置 (Card)

  * **内容**: 沿用现有版本的大表格设计，包含`客户端配置`、`伪装效果`、`适用场景`、`运行状态`等列。
  * **去重**: 此卡片专注于协议本身，不再重复显示当前的出站分流状态。

### 3.7 订阅链接 & 流量统计 (Cards)

  * **布局**: 维持现有实现，仅需确保在新的12栅格体系下宽度和对齐正常。
  * **内容**: 功能和数据来源保持不变。

## 4\. 状态与空态规范

  * **加载中**: 所有卡片或卡片内的数据区域应显示骨架屏（Skeleton Screen）或灰色加载条。
  * **加载失败**: 在对应卡片的右上角显示一个红点角标。鼠标悬浮或点击后，显示具体的错误描述。
  * **字段未知/空值**:
      * 某个数据字段后端未返回或无法获取，显示 `—`。
      * 某个配置项未设置（如绑定域名），显示 `未配置`或`无`。

## 5\. 后端 API 接口字段 (Data Contract)

前端开发应严格依据以下 JSON 结构进行数据绑定。这是后端 `dashboard-backend.sh` 脚本输出的 `dashboard.json` 文件的约定格式。

```json
{
  "serverInfo": {
    "userNote": "edge-sfo-01",
    "cloud": {
      "provider": "GCP",
      "region": "us-central1"
    },
    "instanceId": "i-2f3a...9b",
    "hostname": "edgebox-01",
    "system": {
      "distro": "Debian 12",
      "kernel": "6.1.0",
      "uptime": "12d 04:32"
    }
  },
  "serverMetrics": {
    "cpu": {
      "usedPct": 37,
      "cores": 4,
      "threads": 8
    },
    "memory": {
      "usedPct": 62,
      "totalGiB": 8,
      "swapGiB": 2
    },
    "disk": {
      "usedPct": 41,
      "totalGiB": 80
    }
  },
  "coreServices": [
    {
      "name": "nginx",
      "status": "running",
      "version": "1.24.0"
    },
    {
      "name": "xray",
      "status": "running",
      "version": "1.8.15"
    },
    {
      "name": "sing-box",
      "status": "stopped",
      "version": "1.9.6"
    }
  ],
  "certificate": {
    "type": "lets-encrypt",
    "domain": "xxx.example.com",
    "renewal": "auto",
    "expireDate": "2025-12-01"
  },
  "networkIdentity": {
    "vps": {
      "mode": "direct",
      "egressIp": "35.212.192.41",
      "asn": "AS15169",
      "isp": "Google",
      "geo": {
        "country": "US",
        "city": "Los Angeles"
      },
      "bandwidth": {
        "upMbps": 1000,
        "downMbps": 1000
      }
    },
    "proxy": {
      "mode": "full-proxy",
      "egressIp": "91.203.36.10",
      "asn": "AS9009",
      "isp": "M247",
      "geo": {
        "country": "NL",
        "city": "Amsterdam"
      },
      "bandwidth": {
        "upMbps": 200,
        "downMbps": 200
      }
    },
    "shunt": {
      "mode": "mixed",
      "whitelist": [
        "googlevideo.com",
        "ytimg.com",
        "gvt2.com"
      ],
      "note": "HY2/TUIC 为 UDP 通道，VPS 直连"
    }
  }
}
```

## 6\. V2 改动摘要 (供前端对照)

  * **[替换]** 移除旧的顶部“基本信息”卡片，替换为新的三张独立卡片：`服务器信息` / `服务器配置` / `核心服务`。
  * **[独立]** “证书信息”从原先的混合卡片中独立出来，成为新的`证书切换`卡片。
  * **[删除]** 移除旧的“出站分流状态”卡片。
  * **[新增]** 新增`网络身份配置`组合卡片，它整合并扩展了原先“出站分流”卡片的功能。
  * **[扩充]** `协议配置`卡片从半行宽度扩大为整行（12列）。
  * **[维持]** `订阅链接`和`流量统计`卡片的功能和数据源保持不变，仅需在新的栅格布局下调整宽度和样式。





# v2版：增加字段与UI

* 在 **VPS出站IP** 与 **代理出站IP** 两块中新增一行：

  * **IP质量检测**：`85 分（良好） · 详情`
  * 徽标颜色：≥90 优秀 / 70–89 良好 / 50–69 一般 / <50 较差
  * 右侧提供 `检测` 按钮（失败用“重试”），显示**上次检测时间**。
* “详情”→ 抽屉/弹窗，展示各子项评分与原始值，并可复制检测报告。

# 后端字段（示例）

```json
{
  "networkIdentity": {
    "vps": {
      "egressIp": "35.212.192.41",
      "ipQuality": {
        "score": 85,                    // 0-100
        "verdict": "good",              // excellent|good|fair|poor|unknown
        "lastCheckedAt": "2025-09-13T23:40:04Z",
        "checks": {
          "isDatacenter": true,        // DC/住宅/移动网络判定
          "blacklistHits": 0,          // 公开黑名单命中数
          "proxyVpnSignals": "low",    // 低/中/高
          "asnReputation": "ok",       // 好/一般/差
          "geoConsistency": "high",    // 多源地理一致性
          "rdnsPresent": true,         // 是否有rDNS
          "openPortsRisk": "low",      // 以22/80/443外的高风险端口为主
          "latencyMs": 180,            // 到常用服务的RTT中位数
          "packetLossPct": 0.0,
          "dnsLeak": false             // 是否泄露本地DNS
        },
        "topReasons": [
          "未命中黑名单",
          "地理信息一致",
          "数据中心IP（对部分服务可识别）"
        ]
      }
    },
    "proxy": { "egressIp": "91.203.36.10", "ipQuality": { /* 同上 */ } }
  }
}
```

# 评分模型（可实现建议）

* 0–100 加权求和（示例权重，可写入配置）

  * 黑名单命中（25%）：0 命中=满分，≥1 命中大幅扣分
  * 网络类型/可识别度（25%）：住宅/移动>商用宽带>数据中心
  * 代理/VPN信号强度（15%）：指纹/隐私字段/开放代理痕迹
  * ASN信誉（10%）：历史滥用/投诉
  * 地理一致性（10%）：多源国家/城市一致
  * rDNS（5%）：存在加分、可疑反解扣分
  * 端口风险（5%）：开放高危端口扣分
  * 时延与丢包（5%）：到常用站点（google/youtube/github）中位RTT、丢包
* 产出`verdict`映射：≥90 excellent / ≥70 good / ≥50 fair / 其余 poor。

# 交互与容错

* **首次进入**：若`lastCheckedAt`为空显示 `— · 点击检测`。
* **超时/失败**：分数显示`未知`，保留“重试”按钮与错误原因。
* **更新策略**：手动触发 + 后台定时（例如每 12h）; egress IP 变化时强制重测。
* **隐私说明**：在详情底部提示“评分基于公开信号与连通性，结果因站点策略而异，只作参考”。

# 为什么值得加

* 一眼判断“这条出口”是否容易被识别/限流，有助于**选择线路与分流策略**。
* 对比 **VPS出站IP** 与 **代理出站IP** 的分数，能直观指导“白名单直连/走代理”的划分。

总之：请配套“细项可解释 + 可重测 + 有时间戳”的设计，避免把“85分”当成黑箱结论。





# 最终版：**“方案A：静态渲染 + 详情弹窗”规范**，含数据格式、前端占位与最小 JS、crontab、以及一份可直接用的 Bash 评分脚本（每天检测 VPS 出站与代理出站各 1 次，生成 `.json` + `.txt` 两类静态文件）。

# 1) 展示与文件约定

  * **IP质量：85分（良好），详情**
* 点击“详情”弹窗，显示：

  * 分数+等级、最近检测时间
  * 出站 IP / ASN / Geo
  * 各评分子项与原始值（只读）
* 后端**每天**检测并覆盖输出到：

  * `/var/www/edgebox/status/ipq_vps.json`
  * `/var/www/edgebox/status/ipq_vps.txt`
  * `/var/www/edgebox/status/ipq_proxy.json`
  * `/var/www/edgebox/status/ipq_proxy.txt`

`.txt` 仅一行：`IP质量：<score>分（<verdict>），详情`（供前端主行直接插入）。

# 2) JSON 数据格式（详情弹窗读取）

```json
{
  "score": 85,                      // 0-100
  "verdict": "良好",                 // 优秀/良好/一般/较差/未知
  "lastCheckedAt": "2025-09-13T23:40:04Z",
  "ip": "35.212.192.41",
  "asn": "AS15169",
  "asName": "Google LLC",
  "geo": { "country": "US", "city": "Los Angeles" },
  "signals": {
    "netType": "hosting",           // hosting|residential|mobile|unknown
    "blacklistHits": 0,             // 公开RBL命中数（可为null/未知）
    "geoConsistency": "high",       // high|medium|low|unknown
    "rdns": "la21s01-in-f14.1e100.net",
    "latencyMs": 180                // 到常用站点的连接时延中位数
  },
  "reasons": [
    "未命中公开黑名单",
    "地理信息一致性高",
    "数据中心出口，部分站点可能识别"
  ],
  "source": "edgebox-ipq.sh v1"
}
```

# 3) 前端最小改动（静态页）

在“VPS出站IP”和“代理出站IP”两卡各加一行占位：

```html
<div>IP质量：<span id="ipq-vps-text">—</span>，<a href="#" id="ipq-vps-detail">详情</a></div>
<div>IP质量：<span id="ipq-proxy-text">—</span>，<a href="#" id="ipq-proxy-detail">详情</a></div>

<dialog id="ipq-dialog">
  <article id="ipq-dialog-body" style="max-width:680px;white-space:normal;"></article>
  <form method="dialog" style="text-align:right;margin-top:12px;">
    <button>关闭</button>
  </form>
</dialog>

<script>
(async function(){
  // 主行文本（直接读 .txt）
  const t1 = await fetch('/status/ipq_vps.txt').then(r=>r.ok?r.text():'—').catch(()=> '—');
  const t2 = await fetch('/status/ipq_proxy.txt').then(r=>r.ok?r.text():'—').catch(()=> '—');
  document.getElementById('ipq-vps-text').textContent   = t1.replace(/，详情.*/,'');
  document.getElementById('ipq-proxy-text').textContent = t2.replace(/，详情.*/,'');
  // 弹窗
  async function openDetail(kind){
    const data = await fetch(`/status/ipq_${kind}.json`).then(r=>r.json()).catch(()=>null);
    const el = document.getElementById('ipq-dialog-body');
    if(!data){ el.innerHTML = '<b>暂无数据</b>'; }
    else {
      el.innerHTML = `
        <h3 style="margin:0 0 4px">IP质量：${data.score}分（${data.verdict}）</h3>
        <div style="color:#666">最近检测：${data.lastCheckedAt||'—'}</div>
        <hr>
        <div>出站IP：<b>${data.ip||'—'}</b></div>
        <div>ASN/ISP：<b>${data.asn||'—'}</b> / ${data.asName||'—'}</div>
        <div>Geo：<b>${(data.geo&&data.geo.country)||'—'} - ${(data.geo&&data.geo.city)||'—'}</b></div>
        <div>网络类型：${data.signals?.netType||'—'}；rDNS：${data.signals?.rdns||'—'}</div>
        <div>黑名单命中：${data.signals?.blacklistHits ?? '未知'}；地理一致性：${data.signals?.geoConsistency||'—'}</div>
        <div>连接时延中位数：${data.signals?.latencyMs ?? '—'} ms</div>
        <hr>
        <div>判断依据：</div>
        <ul>${(data.reasons||[]).map(x=>`<li>${x}</li>`).join('')}</ul>
        <div style="color:#888;font-size:12px">提示：评分基于公开信号与连通性，仅供参考。</div>
      `;
    }
    document.getElementById('ipq-dialog').showModal();
  }
  document.getElementById('ipq-vps-detail').onclick   = (e)=>{e.preventDefault();openDetail('vps');};
  document.getElementById('ipq-proxy-detail').onclick = (e)=>{e.preventDefault();openDetail('proxy');};
})();
</script>
```

> 说明：页面仍是静态文件；只是“详情”时从同域读取静态 JSON 展示，无后端接口。

# 4) 定时任务

```bash
# 每天 02:15 运行（建议随机分钟避免同一时间拥塞）
15 2 * * * /usr/local/bin/edgebox-ipq.sh \
  --out /var/www/edgebox/status \
  --proxy 'socks5h://127.0.0.1:10808' \
  --targets vps,proxy >> /var/log/edgebox-ipq.log 2>&1
```

# 5) 依赖

* `bash`、`curl`、`jq`、`dig`（`bind9-dnsutils`）
* 允许访问公开 IP 信息源（脚本内已做多源兜底）

# 6) 评分脚本（保存为 `/usr/local/bin/edgebox-ipq.sh`）

> 设计宗旨：**稳**（超时兜底）、**简**（只依赖 curl/jq/dig）、**可解释**（输出细项）。
> 权重（可调）：黑名单 25%、网络类型 25%、ASN 信誉 20%、地理一致性 10%、rDNS 5%、连接时延 15%。

```bash
#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="/var/www/edgebox/status"
PROXY_URL=""                   # 例如 'socks5h://127.0.0.1:10808'
TARGETS="vps,proxy"            # vps|proxy|vps,proxy
USER_AGENT="edgebox-ipq/1"

# --- 解析参数 ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT_DIR="$2"; shift 2;;
    --proxy) PROXY_URL="$2"; shift 2;;
    --targets) TARGETS="$2"; shift 2;;
    *) echo "Unknown arg: $1"; exit 2;;
  esac
done
mkdir -p "$OUT_DIR"

now_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# --- 工具函数 ---
fetch_json() {
  # $1=url  $2=proxyFlag("noproxy"|"proxy")
  local url="$1" ; local flag="${2:-noproxy}"
  local extra=()
  [[ "$flag" == "proxy" && -n "$PROXY_URL" ]] && extra=(--proxy "$PROXY_URL")
  curl -m 6 -sS -A "$USER_AGENT" "${extra[@]}" "$url" || echo "{}"
}

get_ip_direct() { fetch_json "https://ipinfo.io/json" "$1"; }        # 可能返回 ip, org, asn 等
get_ip_fallback() { fetch_json "https://api.ipify.org?format=json" "$1"; }

ip_api_info() { # 取 geo/hosting 等（免费字段足够）
  local ip="$1"
  fetch_json "http://ip-api.com/json/${ip}?fields=status,message,country,city,as,asname,hosting,proxy,mobile,reverse" "noproxy"
}

rdns_lookup() {
  local ip="$1"
  (dig -x "$ip" +short 2>/dev/null | head -n1 | tr -d '\n') || echo ""
}

ms_round() { awk -v n="$1" 'BEGIN{printf "%.0f", n+0.5}'; }

tcp_connect_ms() { # 取 TCP 连接时间
  local url="$1"; local flag="$2"; local extra=()
  [[ "$flag" == "proxy" && -n "$PROXY_URL" ]] && extra=(--proxy "$PROXY_URL")
  local t; t=$(curl -m 5 -o /dev/null -sS -w '%{time_connect}' "${extra[@]}" "$url" || echo "")
  [[ -z "$t" ]] && echo "" || ms_round "$(awk "BEGIN{print $t*1000}")"
}

median_ms() {
  # 参数为若干毫秒值，返回中位数（空值忽略）
  awk 'NF{a[++i]=$1} END{if(i==0){print ""} else {asort(a); mid=int((i+1)/2); if(i%2){print a[mid]} else {print int((a[mid]+a[mid+1])/2)}}}' <<<"$(printf "%s\n" "$@")"
}

# --- 评分子项 ---
score_nettype() { # hosting|residential|mobile|unknown
  case "$1" in
    residential) echo 100;;
    mobile) echo 85;;
    hosting) echo 60;;
    *) echo 70;;
  esac
}

# 由于不同 ASN 口碑差异，这里给出一个粗略映射，可自行扩展
asn_reputation_score() {
  local asnname="$(tr '[:upper:]' '[:lower:]' <<<"${1:-unknown}")"
  if grep -Eq 'google|amazon|aws|microsoft|azure|ovh|hetzner|digitalocean|linode|vultr|leaseweb|m247|choopa|colo|data|server' <<<"$asnname"; then
    echo 65
  elif grep -Eq 'telecom|unicom|mobile|comcast|verizon|spectrum|at&t|bt|kddi|softbank|ntt|telstra|vodafone' <<<"$asnname"; then
    echo 90
  else
    echo 80
  fi
}

score_blacklist() { # 命中数 -> 分数
  local hits="${1:-0}"
  [[ -z "$hits" || "$hits" = "null" ]] && echo 80 && return
  [[ "$hits" -eq 0 ]] && echo 100 && return
  echo 20
}

score_geo() { # high|medium|low|unknown
  case "$1" in
    high) echo 100;;
    medium) echo 75;;
    low) echo 50;;
    *) echo 70;;
  esac
}

score_rdns() {
  local v="${1:-}"
  [[ -z "$v" ]] && echo 50 && return
  if grep -Eq 'static|dynamic|server|ip|cust|rev|pool|pppoe' <<<"$(tr '[:upper:]' '[:lower:]' <<<"$v")"; then
    echo 70
  else
    echo 90
  fi
}

score_latency() { # 毫秒 -> 分
  local ms="${1:-}"
  [[ -z "$ms" ]] && echo 70 && return
  if   (( ms <= 150 )); then echo 100
  elif (( ms <= 300 )); then echo 80
  elif (( ms <= 600 )); then echo 60
  else                      echo 40
  fi
}

combine_score() {
  local s_bl="$1" s_nt="$2" s_asn="$3" s_geo="$4" s_rdns="$5" s_lat="$6"
  # 权重：黑名单25、网络类型25、ASN20、地理10、rDNS5、时延15
  awk -v a="$s_bl" -v b="$s_nt" -v c="$s_asn" -v d="$s_geo" -v e="$s_rdns" -v f="$s_lat" \
      'BEGIN{printf "%.0f", a*0.25 + b*0.25 + c*0.20 + d*0.10 + e*0.05 + f*0.15}'
}

verdict_of() {
  local s="$1"
  if   (( s >= 90 )); then echo "优秀"
  elif (( s >= 70 )); then echo "良好"
  elif (( s >= 50 )); then echo "一般"
  else echo "较差"
  fi
}

# --- 黑名单命中（可选，失败不影响主流程）---
rbl_hits() {
  local ip="$1"
  # 仅做 best-effort：Spamhaus 可能限流；超时快速返回
  local rev; rev=$(awk -F. '{print $4"."$3"."$2"."$1}' <<<"$ip")
  local count=0
  for bl in "zen.spamhaus.org" "dnsbl.dronebl.org"; do
    if timeout 2 dig +short "${rev}.${bl}" A >/dev/null 2>&1; then
      # 有返回即视为命中；不取具体条目
      ((count++)) || true
    fi
  done
  echo "$count"
}

# --- 采样与评分 ---
probe_one() {
  # $1 kind: vps|proxy
  local kind="$1"
  local proxyflag="noproxy"
  [[ "$kind" == "proxy" ]] && proxyflag="proxy"

  # 1) 基础信息
  local info; info=$(get_ip_direct "$proxyflag")
  local ip; ip=$(jq -r '.ip // empty' <<<"$info")
  if [[ -z "$ip" ]]; then
    ip=$(get_ip_fallback "$proxyflag" | jq -r '.ip // empty')
  fi
  [[ -z "$ip" ]] && ip=""

  # 2) geo/hosting
  local api="{}"
  [[ -n "$ip" ]] && api=$(ip_api_info "$ip")
  local country city hosting asnName
  country=$(jq -r '.country // empty' <<<"$api")
  city=$(jq -r '.city // empty' <<<"$api")
  hosting=$(jq -r '.hosting // empty' <<<"$api")
  asnName=$(jq -r '.asname // empty' <<<"$api")

  # 3) rDNS
  local rdns=""; [[ -n "$ip" ]] && rdns=$(rdns_lookup "$ip")

  # 4) 连接时延（取三站中位数）
  local m1 m2 m3
  m1=$(tcp_connect_ms "https://www.google.com/generate_204" "$proxyflag")
  m2=$(tcp_connect_ms "https://www.youtube.com/generate_204" "$proxyflag")
  m3=$(tcp_connect_ms "https://github.com/" "$proxyflag")
  local ms; ms=$(median_ms $m1 $m2 $m3)

  # 5) 黑名单命中（可选）
  local hits=""; [[ -n "$ip" ]] && hits=$(rbl_hits "$ip")

  # 6) 归一化标签
  local netType="unknown"
  if [[ "$hosting" == "true" ]]; then netType="hosting"
  else
    # 简易判断：ASN名带 mobile/telecom/unicom 视为 residential/mobile
    if grep -Eq 'mobile' <<<"$(tr '[:upper:]' '[:lower:]' <<<"$asnName")"; then netType="mobile"
    elif grep -Eq 'telecom|unicom|comcast|spectrum|verizon|att|vodafone|bt|kddi|softbank|ntt' <<<"$(tr '[:upper:]' '[:lower:]' <<<"$asnName")"; then
      netType="residential"
    fi
  fi

  # 7) 地理一致性（这里只用单源，按是否为空做保守打分）
  local geoCons="unknown"; [[ -n "$country" ]] && geoCons="high"

  # 8) 子项分
  local s_bl s_nt s_asn s_geo s_rdns s_lat
  s_bl=$(score_blacklist "$hits")
  s_nt=$(score_nettype "$netType")
  s_asn=$(asn_reputation_score "$asnName")
  s_geo=$(score_geo "$geoCons")
  s_rdns=$(score_rdns "$rdns")
  s_lat=$(score_latency "$ms")

  local score; score=$(combine_score "$s_bl" "$s_nt" "$s_asn" "$s_geo" "$s_rdns" "$s_lat")
  local ver; ver=$(verdict_of "$score")

  # 9) 输出
  local now; now=$(now_utc)
  local json=$(jq -n \
    --arg ip "$ip" \
    --arg asnName "$asnName" \
    --arg country "$country" \
    --arg city "$city" \
    --arg rdns "$rdns" \
    --arg last "$now" \
    --arg netType "$netType" \
    --arg geoC "$geoCons" \
    --arg hits "${hits:-null}" \
    --arg ms "${ms:-}" \
    --arg ver "$ver" \
    --argjson score "$score" \
    '
    {
      score: $score,
      verdict: $ver,
      lastCheckedAt: $last,
      ip: ($ip // null),
      asn: null,
      asName: ($asnName // null),
      geo: { country: ($country // null), city: ($city // null) },
      signals: {
        netType: $netType,
        blacklistHits: ( ($hits|tonumber?) // null ),
        geoConsistency: $geoC,
        rdns: ($rdns // null),
        latencyMs: ( ($ms|tonumber?) // null )
      },
      reasons: [],
      source: "edgebox-ipq.sh v1"
    }')

  # 补 ASN 号（从 ip-api 的 AS 字段中解析）
  local asn=$(jq -r '.as // empty' <<<"$api" | awk '{print $1}')
  json=$(jq --arg asn "$asn" '.asn = ($asn // null)' <<<"$json")

  # 简易“判断依据”
  local reasons=()
  [[ -n "$hits" && "$hits" -eq 0 ]] && reasons+=("未命中公开黑名单")
  [[ "$netType" = "hosting" ]] && reasons+=("数据中心出口，部分站点可能识别")
  [[ -n "$country" ]] && reasons+=("地理信息一致性高")
  [[ -n "$rdns" ]] && reasons+=("存在rDNS")
  json=$(jq --argjson arr "$(printf '%s\n' "${reasons[@]}" | jq -R . | jq -s .)" '.reasons = $arr' <<<"$json")

  echo "$json"
}

write_outputs() {
  # $1 kind; $2 json
  local kind="$1"; local json="$2"
  local score=$(jq -r '.score' <<<"$json")
  local verdict=$(jq -r '.verdict' <<<"$json")
  echo "$json" > "${OUT_DIR}/ipq_${kind}.json"
  printf "IP质量：%s分（%s），详情" "$score" "$verdict" > "${OUT_DIR}/ipq_${kind}.txt"
}

# --- 执行 ---
if grep -q 'vps' <<<"$TARGETS"; then
  vps_json=$(probe_one "vps" || echo '{"score":0,"verdict":"未知"}')
  write_outputs "vps" "$vps_json"
fi
if grep -q 'proxy' <<<"$TARGETS"; then
  if [[ -z "$PROXY_URL" ]]; then
    # 无代理配置时仍输出占位，避免前端404
    echo '{"score":0,"verdict":"未知","lastCheckedAt":null,"signals":{}}' > "${OUT_DIR}/ipq_proxy.json"
    echo -n "IP质量：—，详情" > "${OUT_DIR}/ipq_proxy.txt"
  else
    proxy_json=$(probe_one "proxy" || echo '{"score":0,"verdict":"未知"}')
    write_outputs "proxy" "$proxy_json"
  fi
fi

echo "[$(date -Is)] ipq done -> ${OUT_DIR}"
```

**赋权并试跑**

```bash
chmod +x /usr/local/bin/edgebox-ipq.sh
/usr/local/bin/edgebox-ipq.sh --out /var/www/edgebox/status --proxy 'socks5h://127.0.0.1:10808' --targets vps,proxy
```

---

### 成功标准（用于测试/验收）

1. `/var/www/edgebox/status/` 下生成 `ipq_vps.json/.txt`、`ipq_proxy.json/.txt`；
2. 面板主行能看到：“IP质量：XX分（等级），详情”；
3. 点击“详情”弹窗内能正确显示“最近检测时间”等细项；
4. 第二天自动覆盖最新结果（看 crontab 或日志）。



您看一下上面三段


