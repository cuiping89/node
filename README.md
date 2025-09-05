

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
  * **依赖**：curl wget unzip ca-certificates jq bc uuid-runtime dnsutils openssl \
            vnstat nginx libnginx-mod-stream nftables certbot msmtp-mta bsd-mailx cron tar等，将由安装脚本自动检测并安装。
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

#### **🧪自检清单**

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

### 1.流量统计

本方案采用 **轻量级采集 (`vnStat` + `nftables`) + 结构化存储 (CSV/JSON) + `Chart.js` 前端渲染**，并在同一浏览器页面同时展示图表和订阅链接。

  * **架构与流程**
    本方案将数据采集与 Web 展示解耦：后端仅产出结构化数据 (CSV/JSON)，前端在浏览器侧渲染图表，从而避免了 Python 科学栈的重依赖，实现了轻量化。
      * **数据采集器 (`traffic-collector.sh`)**：每小时由 `cron` 触发。它通过 `vnstat` 获取网卡级总流量，并利用 `nftables` 计数器获取分流及端口维度的流量（VPS直出、住宅IP直出、高流量端口）。所有数据将写入 `daily.csv`、`monthly.csv`，并生成供前端使用的 `traffic-all.json`。
      * **渲染器 (`Chart.js`)**：取代原有的 `generate-charts.py`。`index.html` 使用 `Chart.js` (可从 CDN 或本地加载) 读取 `traffic-all.json`，在浏览器端动态绘制以下图表：
          * **日曲线 \#1**：分流出站口（VPS直出 vs 住宅直出）。
          * **日曲线 \#2**：高流量端口（TCP/443、UDP/443、UDP/2053）。
          * **月累计表格**：展示最近 12 个月的各指标累计。
  * **目录结构**
    所有核心文件都集中在 `/etc/edgebox/` 目录下，并有清晰的职责划分。
    ```
    /etc/edgebox/
      ├─ scripts/
      │   ├─ traffic-collector.sh        # 采集器
      │   └─ traffic-alert.sh            # 预警脚本（可选）
      ├─ traffic/                        # Nginx Web 根目录
      │   ├─ logs/
      │   │   ├─ daily.csv               # 每小时增量（保留 90 天）
      │   │   └─ monthly.csv             # 月累计（保留 18 个月）
      │   ├─ assets/
      │   │   └─ js/chart.min.js         # （可选）Chart.js 本地化文件
      │   ├─ traffic-all.json            # 前端渲染所需的聚合 JSON
      │   ├─ sub.txt                     # 订阅链接文本
      │   └─ index.html                  # 订阅 + 图表总览页面
      └─ nginx/root-site.conf            # Nginx 站点配置片段
    ```
  * **统计维度与数据保留**
      * **时间粒度**：按小时采集，曲线展示最近 24 小时；数据分别保留 90 天 (daily) 和 18 个月 (monthly)。
      * **统计维度**：系统总流量 (`vnStat`)、VPS 直出流量、住宅 IP 直出流量以及高流量端口。
  * **定时任务 (`cron`)**
    ```bash
    # 数据采集：每小时
    0 * * * * /etc/edgebox/scripts/traffic-collector.sh
    # 流量预警：每小时
    7 * * * * /etc/edgebox/scripts/traffic-alert.sh
    ```
  * **`nftables` 计数规则**
    用于精确统计分流和端口流量，与 `edgeboxctl shunt apply/clear` 命令联动，自动维护住宅代理上游集合。
    ```
    # nftables 规则定义 (一次性安装)
    sudo nft -f - <<'NFT'
    table inet edgebox {
      counters {
        c_tcp443 {}
        c_udp443 {}
        c_udp2053 {}
        c_resi_out {}
      }
      # ...
    }
    NFT
    ```

### 2.流量预警功能

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

