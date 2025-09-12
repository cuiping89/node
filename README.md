

# 🌐EdgeBox：企业级多协议节点部署方案

- EdgeBox 是一个企业级多协议节点部署脚本，小巧强悍，旨在提供一个**一键部署、健壮灵活、安全上网**的解决方案；
- 它通过**协议组合、端口复用、出站分流**等核心策略，实现深度伪装和灵活路由，以应对复杂多变的网络环境；
- 同时还内置了**证书切换、代理配置、控制面板、流量统计、备份恢复**等运维功能，满足日常运维需求。

-----
## 快速开始

连接服务器执行以下命令，即可一键部署：
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/install.sh)
```
- 注：Debian镜像是“最小化/新装”，一键安装会报 curl: command not found。执行`apt update && apt install -y curl`预装cur后再安装。
- - 浏览器访问：http://<your-ip-or-domain>/ (服务器、系统、协议、分流状态、订阅链接、流量预警、运维管理的静态页面)
- 命令管理：edgeboxctl help

-----

## 功能亮点

  * **一键安装**：默认非交互式“IP模式”安装。
  * **幂等卸载**：一键清理所有组件，确保幂等高效，为重装准备环境，适合自动化和故障排除。
  * **协议组合**：集成 VLESS-gRPC、VLESS-WS、VLESS-Reality、Trojan(TLS)、Hysteria2 和 TUIC，提供多种使用场景的协议选择。
  * **单口复用**：采用**Nginx + Xray 单端口复用（Nginx-first）** 架构，SNI-ALPN 定向 + 内部回环端口隔离，实现深度伪装。
  * **出站分流**：支持 VPS出站 / 住宅IP出站 / VPS + 住宅IP（真正分流），并通过 `edgeboxctl` 工具轻松切换、配置白名单。
  * **证书管理**：通过 `edgeboxctl` 管理工具，实现 **IP模式 ⇋ 域名模式** 双向切换，软链接契约实现“无缝切换”。
  * **全面运维**：内置 `vnStat` 和 `iptables` 流量监控，支持每日自动备份与一键恢复。

-----

## 环境要求
  * **系统**：Ubuntu 18.04+ 或 Debian 10+。
  * **硬件**：CPU 1核，内存 512MB（内存不足自动创建 2G swap），存储 10GB 可用空间，并需稳定的公网 IP。
  * **依赖**：curl wget unzip ca-certificates jq bc uuid-runtime dnsutils openssl vnstat nginx libnginx-mod-stream nftables certbot msmtp-mta bsd-mailx cron tar等，将由安装脚本自动检测并安装。
  * **双层防火墙**：本机防火墙（UFW）安装脚本将自动放行所用端口；**云安全组**仍需手动开放 80/tcp、443/tcp、443/udp、2053/udp（以及 SSH 的 22/tcp）。。

## 核心组件
  * **Nginx**：作为所有 TCP 协议的唯一入口，监听公网 `TCP/443`，并基于 SNI/ALPN 进行非终止 TLS 分流。
  * **Xray**：运行 Reality、VLESS-gRPC、VLESS-WS 和 Trojan(TLS) 协议，监听内部回环端口，负责各自协议的 TLS 终止。
  * **sing-box**：独立运行 Hysteria2 和 TUIC 协议，直接监听 UDP 端口。

---

## 技术架构

EdgeBox 的核心在于其精巧的分层架构，实现了协议组合、端口复用、模式切换和出站分流。

### 协议组合与端口分配

本方案采用 **Nginx + Xray 单端口复用（Nginx-first）** 架构，实现了智能分流和深度伪装。

| **协议类型** | **工作流程** |
| :--- | :--- |
| **Reality** | 客户端 → **Nginx:443** → 根据 **SNI** 转发 → **Xray Reality** (内部) |
| **gRPC** | 客户端 → **Nginx:443** → 根据 **ALPN=h2** 转发 → **Xray gRPC** (内部) |
| **WebSocket** | 客户端 → **Nginx:443** → 根据 **ALPN=http/1.1** 转发 → **Xray WS** (内部) |
| **Trojan(TLS)** | 客户端 → **Nginx:443** → 根据 **SNI** 转发 → **Xray Trojan** (内部) |
| **Hysteria2/TUIC** | 客户端 → **Sing-box:443/2053** 直接处理 **UDP** 流量，与 Nginx 无关。 |

### 协议组合策略

| 矩阵协议 | 传输特征 | 行为伪装效果 | 适用场景 |
| :--- | :--- | :--- | :--- |
| **VLESS-Reality** | 真实 TLS 握手 | 极佳，几乎无法识别 | 最严格的网络环境 |
| **VLESS-gRPC** | HTTP/2 多路复用 | 极佳，类似正常网页请求 | 网络审查严格的环境 |
| **VLESS-WS** | WebSocket 长连接 | 良好，模拟实时通信 | 一般网络环境，稳定性佳 |
| **Trojan(TLS)** | TLS 握手，无伪装 | 良好，无法被识别为代理 | 移动网络和复杂环境的可靠备选 |
| **Hysteria2** | QUIC/UDP 快速传输 | 良好，HTTP/3 伪装 | 需要高速传输的场景 |
| **TUIC** | 轻量 QUIC 协议 | 中等，UDP 流量特征 | 移动网络和不稳定连接 |

* **默认安装**：VLESS-gRPC、VLESS-WS、VLESS-Reality、Hysteria2、TUIC、Trojan(TLS)。
* **反探测**：通过多层次的伪装来模拟正常的互联网流量，高可用性，客户端可以无缝切换协议。
* **VLESS-Reality**: 通过伪装 TLS 指纹，让流量看起来像是在访问真实热门网站。
* **Trojan(TLS)**: 作为备选协议，在无法使用 Reality 等协议时，提供可靠的连接。
* **Hysteria2**: 伪装成 HTTP/3 流量，利用 QUIC 协议的特性。
* **TUIC**: 基于 QUIC 的轻量级协议，具有较好的抗检测能力。

### 端口分配策略

-   本方案采用 **Nginx + Xray 单端口复用（Nginx-first）** 架构，实现了智能分流和深度伪装的完美结合。
-   **核心理念**：让 **Nginx** 成为所有 **TCP** 流量的守门员，它只监听公网 `443` 端口。Nginx 根据流量类型（通过 SNI/ALPN 判断）智能地分发给后端不同功能的 **Xray** 内部服务。

| **类型** | **端口** | **功能** |
| :--- | :--- | :--- |
| **对外暴露** | TCP/443 | 所有 TCP 协议的统一入口，由 Nginx 监听。 |
| | UDP/443 | Hysteria2 使用，实现高隐蔽性。 |
| | UDP/2053 | TUIC 使用（可选）。 |
| **内部回环** | TCP/11443 | Xray Reality 服务。 |
| | TCP/10085 | Xray gRPC 服务。 |
| | TCP/10086 | Xray WebSocket 服务。 |
| | TCP/10143 | Xray Trojan(TLS) 服务。 |

---

## 模式切换

本方案的核心在于 **edgeboxctl** 管理工具，它能实现两种核心模式之间的无缝切换，以适应不同的网络环境。

### 初始安装（IP 模式）
 安装脚本默认为非交互模式、无域名、无住宅IP 的环境设计。安装后涉及 TLS 的协议使用自签名证书，所有协议均可立即使用。
-   **Nginx**：作为公网 `443/TCP` 的唯一入口；除 Reality 外的 SNI 流量，由 Nginx 基于 SNI 转发到后端回环端口。
-   **Reality**：独立启用，监听内部回环端口；`server_name` 伪装为常见网站（如 `www.cloudflare.com`），安装时自动生成密钥对。
-   **VLESS-gRPC / VLESS-WS**：监听内部回环端口，使用自签名证书，分别配置 `alpn=h2` / `alpn=http/1.1`。
-   **Hysteria2 / TUIC**：分别监听 `UDP/443` 与 `UDP/2053`，默认使用自签名证书。
-   **Trojan-TLS**：作为兜底协议，挂载在 Xray 入站回环端口（默认 `127.0.0.1:10143`），Nginx对 `^trojan\.`的SNI做四层预读并转发到该端口。

### 模式切换（`edgeboxctl` 命令）

**1. 切换至域名模式**
-   **命令**：`edgeboxctl change-to-domain <your_domain>`
-   **逻辑**：
    1.  检查 `<your_domain>` 的 A/AAAA 解析。
    2.  自动申请/扩展 Let’s Encrypt 证书，并替换所有需要 TLS 的后端（VLESS-gRPC/WS、Trojan-TLS、Hysteria2/TUIC）的自签名证书。
    3.  Nginx/Xray/sing-box 切换为域名化配置。
    4.  订阅与控制面板同时更新为域名模式。
-   **Trojan-TLS 特别说明**：
    -   若检测到 `trojan.<your_domain>` 已解析到本机，则证书将同时覆盖该子域。
    -   若暂未解析，Trojan 链接仍可用（订阅会自动带上 `allowInsecure=1`）。待你补齐解析后，再次执行切换命令即可自动扩展证书。

**2. 回退至 IP 模式**
-   **命令**：`edgeboxctl change-to-ip`
-   **逻辑**：
    1.  停用/清理域名证书软链，恢复自签名证书。
    2.  Nginx/Xray/sing-box 恢复 IP 模式下的回环监听与 SNI 分流。
    3.  订阅与控制面板回写为 IP 模式（Reality 继续独立伪装，Trojan-TLS 回到 `trojan.edgebox.internal` + `allowInsecure=1`）。

### 模式切换后的自动验证（验收报告）

切换完成后，`edgeboxctl` 会自动输出一份“验收报告”，覆盖以下关键项（失败项会标红）：

-   **Nginx 配置测试**：`nginx -t` 是否通过；必要时热加载 `systemctl reload nginx`。
-   **服务可用性**：`nginx` / `xray` / `sing-box` 三个服务 `systemctl is-active` 是否全部为 `active`。
-   **域名解析检查**（域名模式下）：
    -   `<your_domain>` 的 A/AAAA 是否存在且可达。
    -   `trojan.<your_domain>` 是否存在（如不存在，仅提示，不阻塞切换）。
-   **证书状态**：
    -   证书来源：自签名 / Let’s Encrypt。
    -   证书软链：`/etc/edgebox/cert/current.pem`、`current.key` 是否存在且指向正确。
    -   权限检查：`current.key` 权限是否为 `600/640`。
-   **订阅可达**：
    -   `curl http://<服务器IP或域名>/sub` 是否返回 `200`。
    -   明文链接是否包含所有协议（Reality、gRPC、WS、Hysteria2、TUIC、Trojan-TLS）。
    -   Base64 链接是否生成成功。
    -   Trojan-TLS 链接根据模式自动带/不带 `allowInsecure=1`。
-   **出站分流回显**（若当次有改动）：
    -   当前作用域与策略（`xray-only` 或 `all`；`resi` / `direct-resi` / `vps`），及连通性探测。
    -   `xray` 路由是否存在 `resi-proxy` 出站。
    -   `sing-box`（HY2/TUIC）按方案默认直连（不经上游 HTTP/SOCKS 代理）。

### 证书管理

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

-----

## 出站分流系统

本模块提供了三种互斥的出站模式：`vps`、`resi`、`direct_resi`。其中 `vps` 与 `resi` 是单一出口；`direct_resi` 才是智能分流（白名单直连，其余走住宅）。

### 最终方案要点（重要）
* **分流作用域**：`Xray-only`。分流仅在 Xray 出站上生效。`Hysteria2` 和 `TUIC`（UDP 协议）始终直连，不走上游代理。
* **分流原因**：绝大多数 HTTP/SOCKS 代理IP无法可靠地转发 UDP，分流会导致 `Hysteria2`/`TUIC` 不通或性能劣化。

### 三种出站模式
1.  **VPS 全量出** (`vps`)：所有流量都从您的 VPS 直接出网（**默认模式**，最稳定）。
2.  **住宅 IP 全量出** (`resi`)：所有流量都从您配置的住宅代理出网。
3.  **白名单直连 + 其余走住宅** (`direct_resi`)：白名单域名走 VPS，其余流量走住宅，兼顾账号画像与成本。

### 上游代理格式
* **支持格式**：`<scheme://[user:pass@]host:port[?sni=…]>`
* **支持协议**：`http://`、`https://`（可选带 `?sni=`）、`socks5://`、`socks5h://`。
* **示例**：`socks5://user:pass@111.222.333.444:11324`

### 文件布局与状态
`/etc/edgebox/shunt/`
- `whitelist-vps.txt`：白名单（域名后缀匹配，每行一个，无需开头带点）
- `resi.conf`：保存您配置的上游住宅代理 URL
- `state.json`：记录当前模式、上游健康探活状态、最近切换时间
- `resi.conf` 和 `state.json` 权限默认为 `600`，仅 `root` 可读。

### 管理命令 (`edgeboxctl`)
- `edgeboxctl shunt vps`：切换到“VPS 全量出”。
- `edgeboxctl shunt resi '<URL>'`：配置并切换到“住宅 IP 全量出”。
- `edgeboxctl shunt direct-resi '<URL>'`：配置并切换到“智能分流”。
- `edgeboxctl shunt status`：查看当前模式、上游连通性、出口 IP 变化等。
- `edgeboxctl shunt whitelist <add/remove/list/reset>`：管理白名单。

### 验收与健康检查
-   **上游连通性**：用 `curl --proxy` 探测上游代理是否可用。
-   **出口 IP 对比**：显示 VPS 本机 IP 与上游出口 IP，确认切换成功。
-   **Xray 路由**：检查 `resi-proxy` 出站规则是否存在。
-   **HY2/TUIC 提示**：明确标注“`Hysteria2`/`TUIC` 走 UDP，不参与分流，保持直连”。

### 使用建议
* **优先选择**：默认使用 **`vps`** 模式。在需要保持账号画像时，切换到 **`direct_resi`**。仅在特殊需求下使用 **`resi`** 模式。
* **协议选择**：在需要住宅画像时，请切换到 **VLESS 系列**或 **Trojan-TLS**，它们会经由 Xray 分流。`Hysteria2`/`TUIC` 继续作为高效 UDP 通道存在，不受分流影响。


-----

### **🎛️ 可视化控制面板 (Visual Control Panel)**

EdgeBox 提供了一个轻量、直观的 Web 控制面板，让您可以通过浏览器轻松掌握节点的完整状态。它是一个纯静态页面，加载迅速，所有数据一目了然。

访问地址: `http://<您的服务器IP>`

**面板核心功能包括：**

  * **实时状态一览**：在一个视图中集中展示服务器负载（CPU/内存）、核心服务（Nginx, Xray）的运行状态、证书信息以及当前出站IP。
  * **配置与订阅中心**：清晰地列出所有已部署协议的适用场景，并提供一键复制的订阅链接（支持明文、Base64等多种格式）。
  * **可视化流量监控**：以图表形式直观展示近30日的流量趋势，并精确区分“VPS出口”与“代理出口”的流量。同时提供月度流量进度条，帮助您管理流量配额。
  * **动态分流展示**：高亮显示当前的出站分流模式（如VPS直连、智能分流等），让您对流量走向了如指掌。
  * **运维命令参考**：集成了常用的 `edgeboxctl` 命令列表，方便您随时查阅和管理节点。

> 想要了解面板背后的数据流动原理？请查阅 **[控制面板技术文档]([https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/docs/02-Control-Panel.md)**。

-----

## 特定环境配置

在不同的云服务商或 VPS 环境下，虽然核心部署流程一致，但需要特别注意网络和计费策略，以优化性能并有效控制成本。

### GCP 环境（重点：出站成本与回源风险）：
* **流量分流实现约束**：`edgeboxctl shunt` 命令仅修改 `outbounds` 和 `route` 片段，确保变更可回退、口径一致。
* **DNS 强制直连**：在 `sing-box` 配置中将 DNS 明确 `detour` 到 `direct`，并通过路由规则强制所有 `UDP/53` 流量直出，避免 DNS 解析产生额外代理费用。
* **Cloudflare灰云**：若域名托管在 Cloudflare，务必将 DNS 记录设置为 **DNS Only（灰云）**，而非 Proxied（橙云）。您可以通过 `dig` 或 `curl` 命令验证流量是否直连您的 VPS。
* **出站约束**：**切勿**开启 Cloudflare 的 Argo/WARP/Zero Trust 等服务，这类服务会将您的出站流量回源到 Cloudflare 边缘，从而在 GCP 上产生高额出站费用。
* **预算与阈值告警**：在「Billing → Budgets & alerts」中设置月度预算告警，并在「Monitoring → Alerting」中利用 `network/sent_bytes_count` 指标创建 **24 小时滚动阈值告警**，例如日流量超过 7 GiB 时触发邮件通知。

### AWS 环境：
* **免费额度**：EC2 通常有 15 GiB 免费出站流量。将大流量（如视频）尽量留在 VPS 直出（使用 `direct_resi` 模式的白名单），以充分利用免费额度。
* **预算**：开启 AWS Budgets 服务，以便在超出免费额度时及时收到通知。

### 阿里云：
* **费用中心**：利用阿里云的费用中心，根据地域价格差异设置预算提醒。
* **分流**：结合 `direct_resi` 模式，将需要稳定画像的登录/支付流量走住宅代理，其余流量走 VPS 直出以控制成本。

### 其他 VPS/VM（通用做法）
* **常看用量**：定期使用 `edgeboxctl traffic show` 命令和静态图表（网站根路径首页）核对套餐流量阈值。
* **避免“隐式代理”**：任何“智能加速/优化”开关都可能导致隐形代理或回源，建议关闭。

-----

## 🧪自检清单

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
  * **验证流量统计**：
      * 检查 `/etc/edgebox/traffic/traffic-all.json` 文件是否存在且更新。
      * 在浏览器中查看图表，确认 VPS 和住宅代理的流量分摊是否可见。
  * **验证 `nftables` 计数**：
      * `nft list sets inet edgebox`：确认 `resi_addr/resi_port` 已被正确写入。
  * **验证流量预警**：
      * 检查 `alert.conf` 配置是否正确。
      * 查看 `alert.state` 文件，确认是否已记录已触发的告警状态。
    
-----

## 运维与管理 

### 3.流量预警功能

该功能使用一个轻量级脚本 `traffic-alert.sh`，根据月度总流量预算，在达到可配置的百分比（例如 30%、60%、90%）时，通过邮件或 Webhook 发送告警。

  * **约定与阈值配置**
    所有配置集中在 `/etc/edgebox/traffic/alert.conf`：
    ```ini
    ALERT_MONTHLY_GIB=100           # 月度总流量预算（GiB）
    ALERT_EMAIL=ops@example.com     # 接收邮件地址（可留空）
    ALERT_WEBHOOK=                  # Webhook URL（可留空）
    ```
  * **预警脚本**
    脚本位于 `/etc/edgebox/scripts/traffic-alert.sh`，每小时执行一次。它从 `monthly.csv` 中获取当月累计流量，并与配置的百分比阈值进行比对。一旦达到阈值，便发送告警并记录状态，避免重复触发。

### 4.备份与恢复

系统每日凌晨3点自动备份配置和数据到 `/root/edgebox-backup/`；可以使用 `edgeboxctl backup` 命令手动创建、列出和恢复备份。


-----

## **🛡️ 安全建议 & 📈 性能与限制**

  * **安全建议**：定期系统升级、SSH 加固、防火墙最小化放行、定期轮换 UUID；客户端启用“绕过大陆”、避免公开分享订阅；Reality 优先、定期更换伪装域名。
  * **性能/限制**：关注并发/内存/磁盘参考指标；注意 GCP 计费、LE 速率、Reality 兼容性与 IPv6 说明。

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

