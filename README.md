

# EdgeBox：企业级多协议节点部署方案

- EdgeBox 是一个多协议一键部署脚本，旨在提供一个**健壮灵活、一键部署、幂等卸载**的安全上网解决方案；
- 它通过**协议组合、端口分配、出站分流**等核心策略，实现深度伪装和灵活路由，以应对复杂多变的网络环境；
- 同时还内置了**模式切换、流量统计、备份恢复**等运维功能，满足日常运维需求。

-----
## 快速开始

只需连接服务器执行以下命令，即可一键部署：
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/install.sh)
```
- 浏览器访问：http://<your-ip-or-domain>/ (订阅 + 流量图表同页的静态页面)
- 命令管理：edgeboxctl help

-----

## 功能亮点

  * **一键安装**：默认非交互式“IP模式”安装。
  * **幂等卸载**：一键清理所有组件，确保幂等高效，为重装准备环境，适合自动化和故障排除。
  * **协议组合**：集成 VLESS-gRPC、VLESS-WS、VLESS-Reality、Hysteria2 和 TUIC，提供多样的协议选择。
  * **单口复用**：采用 \*\*Nginx + Xray 单端口复用（Nginx-first）\*\*架构，SNI/ALPN 定向 + 内部回环端口隔离，实现深度伪装。
  * **证书管理**：通过 `edgeboxctl` 管理工具，实现 **IP模式 ⇋ 域名模式** 双向切换，软链接契约实现“无缝切换”。
  * **灵活分流**：支持 VPS 全量 / 住宅IP 全量 / 白名单直连 + 非白名单走住宅（真正分流），并通过 `edgeboxctl` 工具轻松切换、配置白名单。
  * **全面运维**：内置 `vnStat` 和 `iptables` 流量监控，支持每日自动备份与一键恢复。

-----

## 环境要求
  * **系统**：Ubuntu 18.04+ 或 Debian 10+。
  * **硬件**：CPU 1核，内存 512MB（内存不足自动创建 2G swap），存储 10GB 可用空间，并需稳定的公网 IP。
  * **依赖**：`curl`, `wget`, `unzip`, `tar`, `nginx`, `certbot`, `vnstat`, `iftop` 等，将由安装脚本自动检测并安装。
  * **双层防火墙**：在云服务商的安全组和操作系统级防火墙（如 `ufw`）中放行 `TCP:443`、`UDP:443` 、`UDP:2053` 端口。
## 核心组件
  * **Nginx**：作为所有 TCP 协议的唯一入口，监听公网 `TCP/443`，并基于 SNI/ALPN 进行非终止 TLS 分流。
  * **Xray**：运行 Reality、VLESS-gRPC 和 VLESS-WS 协议，监听内部回环端口，负责各自协议的 TLS 终止。
  * **sing-box**：独立运行 Hysteria2 和 TUIC 协议，直接监听 UDP 端口。

## 证书管理

EdgeBox 提供全自动化的证书管理，支持两种证书类型，根据模式智能选择证书类型。

* **自签名证书（IP 模式）**
    * **生成时机**：在非交互式安装或无域名配置时自动生成。
    * **用途**：用于初始阶段，确保 VLESS-gRPC、VLESS-WS、Hysteria2 和 TUIC 协议能够立即启用并工作。这些协议在客户端连接时需要开启“跳过证书验证”或“允许不安全”。
    * **文件路径**：
        * 私钥：`/etc/edgebox/cert/self-signed.key`
        * 公钥：`/etc/edgebox/cert/self-signed.pem`

* **Let's Encrypt 证书（域名模式）**
    * **生成时机**：用户使用 `edgeboxctl change-to-domain` 命令并提供有效域名后，脚本会自动调用 Certbot 申请。
    * **用途**：提供受信任的、安全的 TLS 加密，使所有协议在客户端无需额外设置即可安全连接。
    * **文件路径**：
        * 私钥：`/etc/letsencrypt/live/<your_domain>/privkey.pem`
        * 公钥：`/etc/letsencrypt/live/<your_domain>/fullchain.pem`
    * **自动续期**：脚本将配置一个 `cron` 任务，自动执行 `certbot renew` 命令，确保证书在到期前自动续期。

* **证书在配置文件中的引用**
    * 为确保模式切换的幂等性，所有服务配置文件都将使用软链接来动态指向正确的证书文件。
 
* **Nginx、Xray、sing-box**：
    * `ssl_certificate`：指向 `/etc/edgebox/cert/current.pem`
    * `ssl_certificate_key`：指向 `/etc/edgebox/cert/current.key`
    * `edgeboxctl` 工具在切换模式时，将更新这两个软链接，使其分别指向自签名证书或 Let's Encrypt 证书的实际文件，从而实现无缝切换。

---

## 技术架构

EdgeBox 的核心在于其精巧的分层架构，实现了协议组合、端口复用、模式切换、流量分发。

### 协议组合与端口分配

本方案采用 \*\*Nginx + Xray 单端口复用（Nginx-first）\*\*架构，实现了智能分流和深度伪装。

| **协议类型** | **工作流程** |
| :--- | :--- |
| **Reality** | 客户端 → **Nginx:443** → 根据 **SNI** 转发 → **Xray Reality** (内部) |
| **gRPC** | 客户端 → **Nginx:443** → 根据 **ALPN=h2** 转发 → **Xray gRPC** (内部) |
| **WebSocket** | 客户端 → **Nginx:443** → 根据 **ALPN=http/1.1** 转发 → **Xray WS** (内部) |
| **Hysteria2/TUIC** | 客户端 → **Sing-box:443/2053** 直接处理 **UDP** 流量，与 Nginx 无关。 |

### 协议组合策略

| 矩阵协议           | 传输特征          | 行为伪装效果     | 适用场景                 |
|--------------------|-------------------|------------------|--------------------------|
| **VLESS-gRPC**     | HTTP/2 多路复用   | 极佳，类似正常网页请求 | 网络审查严格的环境   |
| **VLESS-WS**       | WebSocket 长连接  | 良好，模拟实时通信     | 一般网络环境，稳定性佳 |
| **VLESS-Reality**  | 真实 TLS 握手     | 极佳，几乎无法识别     | 最严格的网络环境     |
| **Hysteria2**      | QUIC/UDP 快速传输 | 良好，HTTP/3 伪装      | 需要高速传输的场景   |
| **TUIC**           | 轻量 QUIC 协议    | 中等，UDP 流量特征     | 移动网络和不稳定连接 |

- 默认安装：VLESS-gRPC、VLESS-WS、VLESS-Reality、Hysteria2、TUIC。
- 反探测，适用不同场景，通过多层次的伪装来模拟正常的互联网流量，高可用性，客户端可以无缝切换协议。
- **VLESS-Reality**: 通过伪装 TLS 指纹，让流量看起来像是在访问真实热门网站
- **Hysteria2**: 伪装成 HTTP/3 流量，利用 QUIC 协议的特性
- **TUIC**: 基于 QUIC 的轻量级协议，具有较好的抗检测能力

### 端口分配策略
- 本方案采用 **Nginx + Xray 单端口复用（Nginx-first）** 架构，实现了智能分流和深度伪装的完美结合。
- **核心理念：** 让 **Nginx** 成为所有 **TCP** 流量的守门员，它只监听公网 `443` 端口。Nginx根据流量类型（通过 SNI/ALPN 判断）智能地分发给后端不同功能的 **Xray** 内部服务。

| **类型** | **端口** | **功能** |
| :--- | :--- | :--- |
| **对外暴露** | TCP/443 | 所有 TCP 协议的统一入口，由 Nginx 监听。 |
| | UDP/443 | Hysteria2 使用，实现高隐蔽性。 |
| | UDP/2053 | TUIC 使用（可选）。 |
| **内部回环** | TCP/11443 | Xray Reality 服务。 |
| | TCP/10085 | Xray gRPC 服务。 |
| | TCP/10086 | Xray WebSocket 服务。 |


## 模式切换策略

本方案的核心在于 **edgeboxctl** 管理工具，它能实现两种核心模式之间的无缝切换，以适应不同的网络环境。

### 初始安装（非交互式 IP 模式）
- 安装脚本默认为非交互模式，专为无域名或非住宅 IP 的环境设计。安装后，所有协议均可立即工作，但部分协议使用自签名证书。
* **Nginx**： * 作为公网 `443/TCP` 的唯一入口，启动时将所有非 Reality 的流量转发到 Xray 的内部回环端口。
* **Reality**：* 独立启用，监听**内部回环端口**。其 `server_name` 伪装为 `www.cloudflare.com` 等常规网站，按常规生成密钥对。
* **VLESS-gRPC / VLESS-WS**：* 分别监听**内部回环端口**。后端使用 **自签名证书**，并配置各自的 `alpn`。
* **Hysteria2 / TUIC**： * 同样使用 **自签名证书** 启动，分别监听 **UDP/443** 和 **UDP/2053**。

### 模式切换（`edgeboxctl` 命令）
* **切换至域名模式**：
    * **命令**：`edgeboxctl change-to-domain <your_domain>`
    * **逻辑**：工具将检查域名解析，自动申请 Let's Encrypt 证书，并用新证书替换所有需要 TLS 的协议（VLESS-gRPC/WS、Hysteria2/TUIC）的自签名证书。Nginx、Xray 和 sing-box 的配置将被更新以使用真实域名。
* **回退至 IP 模式**：
    * **命令**：`edgeboxctl change-to-ip`
    * **逻辑**：当域名或住宅 IP 失效时，此命令将删除或禁用 Let's Encrypt 证书，重新生成并启用自签名证书，并将所有配置回退到初始的 IP 模式。

### 动态生成订阅链接

**`edgeboxctl sub`** 命令是获取订阅链接的唯一途径，它能根据当前模式动态生成一键导入的聚合链接。

* **逻辑判断**：脚本通过检查 `/etc/letsencrypt/` 目录下是否存在证书来判断当前模式。
* **IP 模式下的链接生成**：
    * `address`：使用服务器的**公网 IP**。
    * **VLESS-gRPC/WS**：SNI 使用占位符（`grpc.edgebox.local` / `www.edgebox.local`），并添加 `allowInsecure=1` 参数，以跳过自签名证书验证。
    * **Hysteria2/TUIC**：添加 `insecure=true` 或 `skip-cert-verify=true` 参数，以跳过自签名证书验证。
* **域名模式下的链接生成**：
    * `address`：使用你的**真实域名**。
    * **VLESS-gRPC/WS**：SNI 使用你的真实域名，移除 `allowInsecure=1` 参数。
    * **Hysteria2/TUIC**：移除 `insecure=true` 或 `skip-cert-verify=true` 参数。
* **聚合**：将所有协议的链接聚合，进行 Base64 编码，并在终端中**直接打印**或保存到本地文件，供客户端手动导入。

-----

## 出站分流系统
本模块提供三种互斥的出站模式。`vps` 和 `resi` 是单一出口；`direct_resi` 才是真正的分流模式。
  * **VPS 全量出 (`vps`)**：所有流量通过 VPS 出口，是默认和最稳定的模式。
  * **住宅 IP 全量出 (`resi`)**：所有流量通过配置的住宅代理 IP。
  * **白名单直连 + 其余走住宅 (`direct_resi`)**：白名单域名直连 VPS，非白名单流量走住宅 IP，兼顾成本与画像。

**文件布局与状态**
```
/etc/edgebox/shunt/
  ├─ whitelist-vps.txt   # 白名单（域名后缀匹配）
  ├─ resi.conf           # 住宅代理 <IP:PORT[:USER:PASS]>
  └─ state.json          # 当前模式/健康探活/切换时间
```

-----

## **特定环境配置**

在不同的云服务商或 VPS 环境下，虽然核心部署流程一致，但需要特别注意网络和计费策略，以优化性能并有效控制成本。

#### **GCP 环境（重点：出站成本与回源风险）**
* **流量分流实现约束**：`edgeboxctl shunt` 命令仅修改 `outbounds` 和 `route` 片段，确保变更可回退、口径一致。
* **DNS 强制直连**：在 `sing-box` 配置中将 DNS 明确 `detour` 到 `direct`，并通过路由规则强制所有 `UDP/53` 流量直出，避免 DNS 解析产生额外代理费用。
* **Cloudflare 灰云**：若域名托管在 Cloudflare，务必将 DNS 记录设置为 **DNS Only（灰云）**，而非 Proxied（橙云）。您可以通过 `dig` 或 `curl` 命令验证流量是否直连您的 VPS。
* **出站约束**：**切勿**开启 Cloudflare 的 Argo/WARP/Zero Trust 等服务，这类服务会将您的出站流量回源到 Cloudflare 边缘，从而在 GCP 上产生高额出站费用。
* **预算与阈值告警**：在「Billing → Budgets & alerts」中设置月度预算告警，并在「Monitoring → Alerting」中利用 `network/sent_bytes_count` 指标创建 **24 小时滚动阈值告警**，例如日流量超过 7 GiB 时触发邮件通知。

#### **AWS 环境（重点：免费额度与安全组）**
* **免费额度**：EC2 通常有 15 GiB 免费出站流量。将大流量（如视频）尽量留在 VPS 直出（使用 `direct_resi` 模式的白名单），以充分利用免费额度。
* **预算**：开启 AWS Budgets 服务，以便在超出免费额度时及时收到通知。

#### **阿里云（重点：区域价差与放行）**
* **费用中心**：利用阿里云的费用中心，根据地域价格差异设置预算提醒。
* **分流**：结合 `direct_resi` 模式，将需要稳定画像的登录/支付流量走住宅代理，其余流量走 VPS 直出以控制成本。

#### **其他 VPS/VM（通用做法）**
* **常看用量**：定期使用 `edgeboxctl traffic show` 命令和静态图表（网站根路径首页）核对套餐流量阈值。
* **避免“隐式代理”**：任何“智能加速/优化”开关都可能导致隐形代理或回源，建议关闭。

#### **🧪 一眼看懂：自检清单**

以下是一些快速检查项目配置状态的命令，以确保 DNS 直连、Cloudflare 灰云和出站回源策略都按预期工作。

  * **验证直连 DNS**：
    ```bash
    grep port\":\ 53.*outbound\":\ \"direct\" in config # 检查配置中是否有 DNS 强制直连规则
    ```
  * **验证 Cloudflare 灰云**：
    ```bash
    dig A yourdomain +short              # 应返回你的 VPS 真实 IP
    curl -I https://yourdomain           # 不应出现 server: cloudflare / cf-ray 头
    ```
  * **验证出站回源**：
    ```bash
    # 在 VPS 模式下，应返回你的 VPS 公网 IP
    curl -s https://ipinfo.io/ip
    # 在住宅模式/分流非白名单时，应返回住宅出口 IP
    curl -s https://ipinfo.io/ip
    ```
  * **验证分流效果**：
      * 通过浏览静态首页的日曲线图表，一段时间后可以清晰看到 VPS 和住宅代理的分摊情况。

-----

## 运维与管理

### 1.流量统计
本方案采用**轻量级采集 + 结构化存储 + Matplotlib 静态图**，并在一个浏览器页面中同时展示图表和订阅链接。
  * **数据采集**：`traffic-collector.sh` 每小时由 `cron` 触发，收集流量数据并写入 `daily.csv` 和 `monthly.csv`。
  * **图表渲染**：`generate-charts.py` 每日生成静态 `.png` 图表和 `index.html` 页面，由 Nginx 托管在站点根路径 `http://<your-ip-or-domain>/`。
  * **统计维度**：包括系统总流量、VPS 直出流量、住宅 IP 直出流量以及高流量端口。

#### 架构与流程
本方案的核心是将数据采集、图表渲染和 Web 展示紧密结合，并统一发布在站点的根路径下，实现了用户访问的零门槛。
  * **数据采集器 (`traffic-collector.sh`)**:
      * 通过 `cron` 任务每小时执行，调用 `edgeboxctl traffic show` 和 `iptables`/`nftables` 来获取流量数据。
      * 将数据按天汇总并写入 `daily.csv`，同时维护 `monthly.csv` 以保留长期趋势数据。
  * **渲染器 (`generate-charts.py`)**:
      * 这是一个 Python 脚本，每日定时执行。
      * 它负责读取 CSV 数据，使用 **Matplotlib** 生成三张静态图表（日曲线、端口曲线、月累计）。
      * 同时，脚本会调用 `edgeboxctl sub` 生成订阅文本，并最终将所有元素（订阅文本、三张图表）整合到一张 **`index.html`** 页面中。
  * **Web 展示**:
      * **Nginx** 将站点的根路径直接指向数据产出目录。
      * 用户访问 `http://<your-ip-or-domain>/` 即可查看包含所有内容的统一页面。

#### 目录结构
所有核心文件都集中在 `/etc/edgebox/` 目录下，并有清晰的职责划分。
```
/etc/edgebox/
  ├─ scripts/
  │   ├─ traffic-collector.sh        # 采集器
  │   └─ generate-charts.py          # 渲染器
  ├─ traffic/                        # Nginx 的 Web 根目录
  │   ├─ logs/
  │   │   ├─ daily.csv               # 每日流量数据 (3 个月滚动)
  │   │   └─ monthly.csv             # 月度累计数据 (18 个月滚动)
  │   ├─ charts/
  │   │   ├─ daily.png               # 最近 30 天日流量曲线
  │   │   ├─ ports.png               # 最近 30 天高流量端口曲线
  │   │   └─ monthly.png             # 最近 12 个月月累计对比图
  │   ├─ sub.txt                     # 订阅链接文本
  │   └─ index.html                  # 订阅与流量总览页面
  └─ nginx/root-site.conf            # Nginx 站点配置文件
```
#### 统计维度与数据保留
  * **时间粒度**:
      * **日维度**：按天采集，图表展示最近 30 天的趋势，数据保留 6 个月。
      * **月累计**：图表展示最近 12 个月的对比，数据保留 24 个月。
  * **统计维度**:
      * 系统总流量 (`vnStat`)
      * VPS 直出流量
      * 住宅 IP 直出流量
      * 高流量端口 (如 `TCP/443`, `UDP/443(Hysteria2)`, `UDP/2053(TUIC)`)

#### 核心脚本职责
  * **`traffic-collector.sh`**:
      * 定时由 `cron` 触发。
      * 调用 `edgeboxctl traffic show` 和 `iptables/nftables` 计数，将数据写入 `daily.csv` 和 `monthly.csv`。
  * **`generate-charts.py`**:
      * 每日定时由 `cron` 触发。
      * 读取 CSV 文件，生成三张 `.png` 格式的图表。
      * 调用 `edgeboxctl sub` 将订阅链接写入 `sub.txt`。
      * 生成包含订阅、三张图表以及更新时间的 `index.html`。

#### 定时任务 (cron)
```bash
# 数据采集：每小时
0 * * * * /etc/edgebox/scripts/traffic-collector.sh

# 图表与总览页生成：每日一次（如需更频繁，可调整）
10 0 * * * /etc/edgebox/scripts/generate-charts.py
```
#### Nginx 根路径发布
将以下配置片段保存为 `/etc/edgebox/nginx/root-site.conf`，并 `include` 到主配置中，实现根路径直出。
```nginx
server {
    listen 80;
    server_name _;

    root /etc/edgebox/traffic;
    index index.html;

    add_header Cache-Control "no-store";
}
```
好的，我已经为您将这份技术文档进行了优化和整理。我将所有关键信息和代码逻辑都归纳到清晰的板块中，同时保留了所有的细节，使其既易于理解又方便查阅和实现。

-----

### 2.流量预警功能

该功能在不引入复杂服务的情况下，在现有架构上增加一个轻量级预警脚本。它支持根据**每月总流量预算**，在达到不同百分比（例如 30%、60%、90%）时通过邮件或 Webhook（Telegram/Slack/飞书）发送告警。

#### 约定与阈值配置

所有配置都集中在 `/etc/edgebox/traffic/alert.conf` 文件中。您可以通过修改该文件来设定月度预算和通知方式。
```ini
ALERT_MONTHLY_GIB=100           # 月度总流量预算（GiB）
ALERT_EMAIL=ops@example.com     # 接收邮件的地址
ALERT_WEBHOOK=                  # 可留空；填写 Webhook URL
```
 * **告警逻辑**：脚本将自动根据 `ALERT_MONTHLY_GIB` 计算 30%、60%、90% 的阈值，并在达到这些百分比时触发告警。

#### 预警脚本（新增）

该脚本位于 `/etc/edgebox/scripts/traffic-alert.sh`，仅在每月流量数据更新后运行。当每月总流量达到配置文件中设定的任一百分比阈值时，它会发送一次告警，并在 `/etc/edgebox/traffic/alert.state` 中记录已触发的状态，避免重复发送。

**脚本核心逻辑**：
  * 读取配置文件，获取当月总预算和通知方式。
  * 从 `monthly.csv` 中获取当月总流量数据。
  * 遍历 30%、60%、90% 三个阈值，判断当前流量是否已达到。
  * 如果达到阈值，则发送告警邮件或 Webhook 通知，并在状态文件中记录已告警的百分比，防止重复触发。
**邮件发送器**：建议使用 `msmtp`，它是一个轻量且易于配置的命令行邮件客户端。您需要配置 `/etc/msmtprc` 文件来连接您的邮件服务。

#### 定时任务（`cron`）

为了确保流量统计和预警的正常运行，需要设置以下 `cron` 定时任务。
```bash
# 每小时：采集流量数据并写入日志
0 * * * * /etc/edgebox/scripts/traffic-collector.sh

# 每日：渲染首页（包含订阅与图表）
10 0 * * * /etc/edgebox/scripts/generate-charts.py

# 每小时：检查月度流量，并在达到阈值时触发预警
7 * * * * /etc/edgebox/scripts/traffic-alert.sh
```

### 3.备份与恢复

系统每日凌晨3点自动备份配置和数据到 `/root/edgebox-backup/`；可以使用 `edgeboxctl backup` 命令手动创建、列出和恢复备份。

### 4.管理工具 (`edgeboxctl`)

`edgeboxctl` 是管理 EdgeBox 的核心工具，所有操作都通过它完成。管理工具提供了丰富的功能，支持模式切换、配置更新、分流管理、流量统计、备份恢复以及证书管理等。

#### **配置与服务管理**
```bash
edgeboxctl config show               # 显示当前配置
edgeboxctl config regenerate-uuid    # 重新生成 UUID
edgeboxctl service status            # 查看服务状态
edgeboxctl service restart           # 重启服务
edgeboxctl service logs              # 查看服务日志
edgeboxctl sub                       # 动态生成订阅链接
edgeboxctl update                    # 更新 EdgeBox
```

#### **模式与证书管理**
```bash
edgeboxctl change-to-domain <your_domain>       # 切换到域名模式
edgeboxctl change-to-ip                         # 回退到 IP 模式
edgeboxctl cert status                          # 查看证书状态
edgeboxctl cert renew                           # 手动续期 Let's Encrypt 证书
edgeboxctl cert upload <fullchain> <key>        # 上传自定义证书
```

#### **出站分流管理**
```bash
edgeboxctl shunt apply <IP:PORT:USER:PASS>      # 写入/更新住宅代理配置
edgeboxctl shunt mode vps                       # 切换至 VPS 全量出
edgeboxctl shunt mode resi                      # 切换至 住宅IP 全量出
edgeboxctl shunt mode direct_resi               # 切换至 白名单 + 分流
edgeboxctl shunt whitelist add <domain_suffix>  # 配置白名单
```

#### **流量统计**
```bash
edgeboxctl traffic show                         # 查看当前流量
edgeboxctl traffic reset                        # 重置流量计数
```
**浏览器访问**：`http://<your-ip-or-domain>/` 查看静态图表。

#### **备份与恢复**
```bash
edgeboxctl backup list                          # 列出备份
edgeboxctl backup create                        # 手动创建备份
edgeboxctl backup restore <DATE>                # 恢复指定日期的备份
```
 
-----

## 常见问题

  * **Q: 连接失败，显示 -1ms？**
      * **排查步骤**：检查防火墙端口、服务运行状态、证书配置和日志。
  * **Q: Reality 协议无法连接？**
      * **解决方案**：确认伪装域名可访问、检查 SNI 配置并验证端口 443 未被占用。
  * **Q: ··· ··· ？**

-----

## **🛡️ 安全建议 & 📈 性能与限制**

  * **安全建议**：定期系统升级、SSH 加固、防火墙最小化放行、定期轮换 UUID；客户端启用“绕过大陆”、避免公开分享订阅；Reality 优先、定期更换伪装域名。
  * **性能/限制**：关注并发/内存/磁盘参考指标；注意 GCP 计费、LE 速率、Reality 兼容性与 IPv6 说明。

-----

## **📚 开发者指南**

  * **项目结构**：项目遵循模块化设计，包括 `ENV/install.sh`、`scripts/`、`configs/` 和 `edgeboxctl` 等目录，职责清晰。
  * **内核契约**：明确定义了端口契约、Nginx 回落机制、证书软链接、基础订阅契约，以及安装/卸载与测试用例。

-----

## 📈 社区特色

  * **安装友好**：一键安装、幂等卸载、文档详细。
  * **灵活运维**：模式切换、流量分流、流量统计、自动备份。

-----

## 📄 许可证

本项目采用 MIT 许可证，详见 [LICENSE](https://www.google.com/search?q=LICENSE) 文件。

-----

## 🤝 贡献与支持

欢迎提交 Issue 和 Pull Request！如果这个项目对您有帮助，请给个 Star ⭐。

