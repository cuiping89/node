# EdgeBox 控制面板 - V2 技术规范

本文档为 EdgeBox 控制面板 V2 版本的技术实现规范，旨在为前端开发提供清晰的布局、内容、状态及接口约定。

## 1. 核心理念与统一口径

新版面板的核心是**信息分层**与**状态清晰**。通过模块化的卡片布局，将不同维度的数据进行逻辑隔离，为用户提供更聚焦、更有条理的视觉体验。

### 1.1 术语与命名（统一口径）

为确保前后端开发与最终用户体验的一致性，所有组件和状态的命名需严格遵守以下口径：

* **通用术语**: 使用“出站”而非“出口”。
* **卡片标题**: `网络身份配置`
* **出站模式枚举**: `直连` (Direct), `全代理` (Full-Proxy), `混合` (Shunt)
* **证书类型**: `Let's Encrypt`, `自签名`
* **空值显示**:
    * 数据获取中或未知: 统一显示 `—`
    * 配置未设置或不存在: 统一显示 `(无)`

## 2. 页面布局（12栅格系统）

页面采用响应式的12栅格系统进行布局。

* **第一行: 概览信息**
- 卡片标题: EdgeBox-企业级多协议节点
- 内部区块:内部整合了“服务器信息/服务器配置/核心服务”三个逻辑区块。
- 卡片底部: 版本号: 3.0.0 | 安装日期: 2025-09-11 | 更新时间: 2025/9/14 20:46:02

* **第二行: 核心配置**
    * `证书切换` (占4列)
    * `网络身份配置` (占8列)
* **第三行: 协议详情**
    * `协议配置` (占12列，整行)
* **第四行: 常用功能**
    * `订阅链接` (占12列)
    * `流量统计` (占12列)
* **第五行: 运维管理(占12列)**

## 3. 卡片内容与交互规范

### 3.1 服务器信息 (Card)
* **用户备注名**: 纯文本。
* **云厂商/区域**: 格式为 `<提供商> | <Region>` (例: `GCP | us-central1`)。
* **Instance ID**: 纯文本。
* **主机名 (Hostname)**: 纯文本。

### 3.2 服务器配置 (Card)
* **CPU**: 进度条组件。显示 `已用 <pct>%`，后缀附加灰色小字说明，格式为 `<物理核心>C / <线程>T`。
* **内存**: 进度条组件。显示 `已用 <pct>%`，后缀附加灰色小字说明，格式为 `<总内存>GiB + <虚拟内存>GiB`。
* **磁盘**: 进度条组件。显示 `已用 <pct>%`，后缀附加灰色小字说明，格式为 `<总量>GiB`。

### 3.3 核心服务 (Card)
* **服务列表**: Nginx, Xray, Sing-box 分别显示状态 `运行中 / 已停止 / 异常 / 未安装`，并附带版本号。

### 3.4 证书切换 (Card)
* **模式标签**: 卡片顶部放置两个标签：“自签证书”、“CA证书”，占满卡片顶部整行，当前模式标签显示为高亮状态（如绿色）。
* **证书类型**: `Let's Encrypt` / `自签名`。
* **绑定域名**: 显示域名字符串，如 `example.com`；若无则显示 `(无)`。
* **续期方式**: `自动` / `手动`。
* **到期日期**: 格式为 `YYYY-MM-DD`；自签名证书显示 `—`。

### 3.5 网络身份配置 (Composite Card)
- 分为三个子区块，子区块内顶部标题标签化，占满子区块内顶部整行，绿色高亮显示当前状态
- 注释“注：HY2/TUIC 为UDP通道，固定 VPS直连，不参与网络身份配置。”移到右上角与标题对齐
#### a) VPS出站IP (Sub-section)
* **公网身份**: `直连`
* **VPS出站IP**: 显示IP地址。
* **Geo**: 格式为 `国家代码-城市` (例: `US-Los Angeles`)。
* **IP质量检测**: IP质量: 85分（良好），并附带“详情”链接。

#### b) 代理出站IP (Sub-section)
* **代理身份**: `全代理`
* **公网身份**: `直连`
* **VPS出站IP**: 显示IP地址。
* **Geo**: 格式为 `国家代码-城市` (例: `US-Los Angeles`)。
* **IP质量检测**: IP质量: 85分（良好），并附带“详情”弹窗。

#### c) 分流出站 (Sub-section)
* **混合身份**: `白名单VPS直连 + 其它代理`
* **白名单**: 显示域名或网段。内容紧跟不换行，只显示两行，附带“查看全部”弹窗。

### 3.6 IP 质量检测实现规范 (方案A：静态渲染)
此功能旨在帮助用户快速判断出口IP的质量，以便更好地选择线路和分流策略。
点击“IP质量”旁的“详情”链接后，弹窗内应展示以下完整信息：
总览: 分数 + 等级、最近检测时间
身份信息:
出站IP
ASN/ISP
Geo (国家/城市全称)
配置信息:
带宽限制 (上行/下行)
质量细项:
网络类型 (住宅/IDC/移动)
rDNS
黑名单命中数
时延中位数
结论:
判断依据 (要点列表)


## 4. 数据流与口径

### 4.1 总体链路

**单向数据流**：后端定时采集 → 聚合生成 **统一 JSON** → 前端 `fetch` 渲染。

**数据源（Sources of Truth）**

* 核心配置：`/etc/edgebox/config/server.json`（含 UUID/密码/IP）。
* 分流白名单：`/etc/edgebox/config/shunt/whitelist.txt`。
* 分流模式状态：`/etc/edgebox/config/shunt/state.json`。
* 系统状态：`/proc/*` 读取 CPU/内存。
* 服务状态：`systemctl is-active`（Nginx/Xray/Sing-box）。

**后端聚合脚本（唯一）**

* `/etc/edgebox/scripts/dashboard-backend.sh` 负责采集/归一化/聚合为单一 JSON 对象。

**中心化数据接口（文件）**

* `dashboard.json`（主数据）、`traffic.json`（流量）、`system.json`（负载）— 三者为前端唯一依赖。

**刷新机制（Cron）**

* `dashboard-backend.sh`：每 **2 分钟**更新 `dashboard.json/system.json`。
* `traffic-collector.sh`：每 **小时**统计流量，计算并产出 `traffic.json`。
* `ipq`（IP 质量）：每日 **02:15** 评分，输出到 `/var/www/edgebox/status`。

**前端消费**
`index.html` 启动后以 `fetch` 读取 `/traffic/` 下三份 JSON（及按需读取 `/status/ipq_*.json`），据键路径填充各 UI 元素。

### 4.2 口径（计算与展示的一致性）

* **流量口径**：以“出站去向”拆分——`总出站 = VPS 直连 + 住宅代理`；`VPS 出站 = 总出站 - 住宅出站`（后端以 `nftables` 计数器分流累积）。
* **模式口径**：

  * `直连`：所有流量经 VPS 原生出站；
  * `全代理`：所有流量经代理出站；
  * `混合`：白名单走 VPS，其他走代理（UI 仅露出“当前是谁/从哪儿出/质量如何”，明细在弹窗）。〔最终版采用“网络身份配置”卡片并以弹窗承载明细〕。
* **空值口径**：未知 `—`，未设 `(无)`（统一到前端格式化层）。

---

## 5. 后端实现要点

### 5.1 流量采集

* `vnStat` 取网卡总出站；`nftables` 计数器统计“住宅代理”去向；产出 `daily.csv / monthly.csv → traffic.json`。

### 5.2 统一聚合

* `dashboard-backend.sh` 汇总：系统状态、服务状态、证书/模式/白名单等 → `dashboard.json`。

### 5.3 IP 质量评分（解耦）

* 由独立脚本 `edgebox-ipq.sh` 产出 `/var/www/edgebox/status/ipq_*.json`，供前端弹窗读取。

---

## 6. 前端实现要点

* **静态单页**：`index.html` 纯静态；通过 `fetch` 拉取 JSON 并渲染。
* **主要卡片**：顶部概览、模式切换、网络身份配置、协议配置、订阅链接、流量统计、运维管理。
* **订阅链接**：提供明文、B64逐行、合并Base64 三种格式。
* **图表渲染**：`traffic.json` → 近30日曲线 + 12个月柱形；本月进度条由 `alert.conf` 配置阈值。
* **IP 质量弹窗**：点击“详情”→ 读取 `/status/ipq_*.json` -> `<dialog>` 渲染。

---

## 7. 文件与目录结构（最终版）

```
/etc/edgebox/
  ├─ traffic/                 # Nginx Web 根（前端可读）
  │   ├─ logs/
  │   │   ├─ daily.csv
  │   │   └─ monthly.csv
  │   ├─ dashboard.json       # 面板主数据
  │   ├─ traffic.json         # 流量统计
  │   ├─ system.json          # 系统负载
  │   ├─ alert.conf           # 流量预警阈值
  │   └─ index.html           # 控制面板入口
  ├─ scripts/
  │   ├─ dashboard-backend.sh # 2分钟一次：聚合→dashboard/system
  │   └─ traffic-collector.sh # 1小时一次：采集→traffic
/var/www/edgebox/status/      # 新增：IP质量静态文件
  ├─ ipq_vps.json(.txt)
  └─ ipq_proxy.json(.txt)
```
---

## 8. 数据契约（Data Contract）

* **`dashboard.json`**：原有键路径（如 `shunt.whitelist`）保持不变，前端照常消费。
* **`traffic.json`**：包含 `last30d` / `monthly` 等，用于近30日曲线与12个月柱形图。
* **`system.json`**：CPU/内存等负载指标（进度条驱动）。
* **`ipq_*.json`**：由 `/var/www/edgebox/status/ipq_*.json` 提供，VPS 与代理两份评分详情，用于弹窗；字段含分数/等级/时间、IP/ASN/ISP/Geo、带宽、网络类型、rDNS、黑名单命中、时延中位数、结论与依据。

---

## 9. 定时任务（Cron）建议

```cron
*/2 * * * * /etc/edgebox/scripts/dashboard-backend.sh          # dashboard/system
15   * * * * /etc/edgebox/scripts/traffic-collector.sh         # traffic
15   2 * * * /usr/local/bin/edgebox-ipq.sh --out /var/www/edgebox/status --proxy '<proxy_url>' --targets vps,proxy  # ipq
```
---

## 10. 交付物清单

1. `index.html`（含：布局栅格、卡片组件、`fetch` 三 JSON、Chart.js、`<dialog>` 弹窗）；
2. `dashboard-backend.sh` 与 `traffic-collector.sh`（按上述目录/频率运行）；
3. `edgebox-ipq.sh`（产出 `/var/www/edgebox/status/ipq_*.json`）；
4. `alert.conf`（本月流量进度的阈值设置）。

