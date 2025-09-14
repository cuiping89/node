

# 一、术语与命名（统一口径）

* “出站”而非“出口”。
* “网络身份配置”作为卡片区标题；子区块为：**VPS出站IP / 代理出站IP / 分流出站**。
* 模式枚举：`直连`（Direct）、`全代理`（Full-Proxy）、`混合`（Shunt）。
* 证书类型：`Let's Encrypt` / `自签名`。
* 空值统一显示：`—`；无配置显示：`（无）`。

# 二、页面布局（12栅格）

**Row 1（各占 4 列）**

1. 服务器信息（span=4）
2. 服务器配置（span=4）
3. 核心服务（span=4）

**Row 2**

* 证书切换（span=4）
* 网络身份配置（span=8，内含三块：VPS出站IP / 代理出站IP / 分流出站，横向等分）

**Row 3**

* 协议配置（span=12，整行占满）

**Row 4（保持现有，不做结构性变更）**

* 订阅链接（span=12）
* 流量统计（可保持现状：两张小卡片或一整卡）

# 三、卡片内容与交互规范

### 1) 服务器信息

* **用户备注名**：文本
* **云厂商/区域**：`<提供商> | <Region>`（例：`GCP | us-central1`）
* **Instance ID**：文本
* **主机名（Hostname）**：文本

### 2) 服务器配置

* **CPU**：进度条，`已用 <pct>%`，后缀灰字：`<物理核心>C / <线程> 线程`；。
* **内存**：进度条，`已用 <pct>%`，后缀灰字：`<总内存> + <虚拟内存>`
* **磁盘**：进度条，`已用 <pct>%`，后缀灰字：`<总量>`
* 数字统一单位：GiB / MiB；百分比取整。

### 3) 核心服务

* **Nginx / Xray / Sing-box**：进度条，`运行中 / 已停止 / 异常 / 未安装` + 版本号
* 点击“详情”可展开最近 50 行日志（由后端提供）。

### 4) 证书切换（独立卡片）

* **证书类型**：`Let's Encrypt / 自签名`
* **绑定域名**：`example.com / （无）`
* **续期方式**：`自动 / 手动`（自签名默认`手动`）
* **到期日期**：`YYYY-MM-DD / —`（自签名可显示`—`）


### 5) 网络身份配置（组合卡片）

**(a) VPS出站IP**

* **公网身份**：`直连`
* **VPS出站IP**：IP + 复制按钮
* **ASN/ISP**：字符串（例：`AS15169 / Google`）
* **Geo**：`国家-城市`（例：`US-Los Angeles`）
* **带宽限制**：`上行 <Mbps> / 下行 <Mbps>`（未知显示 `— / —`）

**(b) 代理出站IP**

* **代理身份**：`全代理`
* **代理出站IP / ASN/ISP / Geo / 带宽限制**：同上
* 说明：此处为“当前所用上游代理的出口标识”，由后端上报。

**(c) 分流出站**

* **混合身份**：`白名单VPS直连 + 其它代理`
* **白名单**：域/网段列表（显示前3行，超出折叠，以详情显示）
* **注**：`HY2/TUIC 为 UDP 通道，VPS 直连，不走代理分流`

### 6) 协议配置（整行）

* 沿用现有表格与“运行状态/客户端配置/连接效果/适用场景”等列。
* 与上方“出站分流状态卡片区”**不再重复**；仅在协议说明中可添加“该协议默认走直连/代理/UDP直连”的只读提示。

### 7) 订阅链接 & 流量统计

* 保持你当前实现

# 四、状态与空态规范

* 获取中：骨架屏/灰条；
* 获取失败：卡片右上角红点 + 错误描述；
* 字段未知：`—`；未绑定：`（无）`；
* 权限不足（例如证书切换失败）：在卡片内以警告条展示“需要 sudo/提权，或后端权限不足”。

# 五、接口字段（示例 JSON）

```json
{
  "serverInfo": {
    "userNote": "edge-sfo-01",
    "cloud": {"provider": "GCP", "region": "us-central1"},
    "instanceId": "i-2f3a...9b",
    "hostname": "edgebox-01",
    "system": {"distro": "Debian 12", "kernel": "6.1.0", "uptime": "12d 04:32"}
  },
  "serverMetrics": {
    "cpu": {"usedPct": 37, "cores": 4, "threads": 8},
    "memory": {"usedPct": 62, "totalGiB": 8, "swapGiB": 2},
    "disk": {"usedPct": 41, "totalGiB": 80}
  },
  "coreServices": [
    {"name": "nginx", "status": "running", "version": "1.24.0"},
    {"name": "xray", "status": "running", "version": "1.8.15"},
    {"name": "sing-box", "status": "stopped", "version": "1.9.6"}
  ],
  "certificate": {
    "type": "lets-encrypt",         // lets-encrypt | self-signed
    "domain": "xxx.example.com",    // null 表示（无）
    "renewal": "auto",              // auto | manual
    "expireDate": "2025-12-01"      // 自签名可为 null
  },
  "networkIdentity": {
    "vps": {
      "mode": "direct",
      "egressIp": "35.212.192.41",
      "asn": "AS15169",
      "isp": "Google",
      "geo": {"country": "US", "city": "Los Angeles"},
      "bandwidth": {"upMbps": 1000, "downMbps": 1000}
    },
    "proxy": {
      "mode": "full-proxy",
      "egressIp": "91.203.36.10",
      "asn": "AS9009",
      "isp": "M247",
      "geo": {"country": "NL", "city": "Amsterdam"},
      "bandwidth": {"upMbps": 200, "downMbps": 200}
    },
    "shunt": {
      "mode": "mixed",
      "whitelist": ["googlevideo.com", "ytimg.com", "gvt2.com"],
      "note": "HY2/TUIC 为 UDP 通道，VPS 直连"
    }
  }
}
```

# 六、与现有面板的差异摘要（给前端对照改动）

* 顶部三卡：用“服务器信息 / 服务器配置 / 核心服务”**替换**现有“基本信息”里的对应块。
* “证书切换”改为**独立卡**；“出站分流状态卡片区”**删除**。
* 新增“网络身份配置”组合卡（含三子块）。
* “协议配置”扩大为**整行**。
* 订阅链接/流量统计维持现状，仅限宽优化为单行展示。


