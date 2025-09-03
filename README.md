

# EdgeBox：一站式多协议节点部署方案

- EdgeBox 是一个多协议一键部署脚本，旨在提供一个**健壮灵活、一键部署、幂等卸载**的安全上网解决方案；
- 它通过**协议组合、端口分配、出站分流**等核心策略，实现深度伪装和灵活路由，以应对复杂多变的网络环境；
- 同时还内置了**模式切换、流量统计、备份恢复**等运维功能，满足日常运维需求。

-----

### **🚀 功能亮点**

  * **一键安装**：默认非交互式“IP模式”安装。
  * **幂等卸载**：一键清理所有组件，确保幂等高效，为安装失败后重装准备环境，适合自动化和故障排除
  * **协议组合**：集成 VLESS-gRPC、VLESS-WS、VLESS-Reality、Hysteria2 和 TUIC，提供多样的协议选择。
  * **深度伪装**：采用 \*\*Nginx + Xray 单端口复用（Nginx-first）\*\*架构，实现 TCP/443 和 UDP/443 的深度伪装。
  * **灵活分流**：支持 ***VPS 直出、住宅IP 直出、VPS & 住宅IP分流**，并通过 `edgeboxctl` 工具轻松切换。
  * **智能管理**：提供 `edgeboxctl` 管理工具，实现 **IP 模式 ⇋ 域名模式**和 **VPS 直出、住宅IP 直出、VPS & 住宅IP分流**的双向切换。
  * **全面运维**：内置 `vnStat` 和 `iptables` 流量监控，支持每日自动备份与一键恢复。

-----

## 快速开始

只需在服务器上执行以下命令，即可一键部署：
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/install.sh)
```
**浏览器访问**: `http://<your-ip-or-domain>/`

### 环境要求
  * **系统**：Ubuntu 18.04+ 或 Debian 10+。
  * **硬件**：CPU 1核，内存 512MB（内存不足自动创建 2G swap），存储 10GB 可用空间，并需稳定的公网 IP。
  * **依赖**：`curl`, `wget`, `unzip`, `tar`, `nginx`, `certbot`, `vnstat`, `iftop` 等，将由安装脚本自动检测并安装。

### 核心组件
  * **Nginx**：作为所有 TCP 协议的唯一入口，监听公网 `TCP/443`，并基于 SNI/ALPN 进行非终止 TLS 分流。
  * **Xray**：运行 Reality、VLESS-gRPC 和 VLESS-WS 协议，监听内部回环端口，负责各自协议的 TLS 终止。
  * **sing-box**：独立运行 Hysteria2 和 TUIC 协议，直接监听 UDP 端口。

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

---

## 技术架构

EdgeBox 的核心在于其精巧的分层架构，实现了协议组合、端口复用、模式切换、流量分发。

### 协议组合与端口分配策略

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

#### **端口分配**
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

## 出站分流策略

本模块提供三种互斥的出站模式：
  * **VPS 全量出 (`vps`)**：所有流量通过 VPS 出口，是默认和最稳定的模式。
  * **住宅 IP 全量出 (`resi`)**：所有流量通过配置的住宅代理 IP。
  * **白名单 + 分流 (`direct_resi`)**：白名单域名直连 VPS，其余流量走住宅 IP，兼顾成本与画像。

### 文件与目录布局
所有分流相关文件都统一管理在 `/etc/edgebox/shunt/` 目录下，保证清晰和原子化。
```
/etc/edgebox/shunt/
  ├─ whitelist-vps.txt   # 白名单列表
  ├─ resi.conf           # 住宅代理配置
  └─ state.json          # 记录当前状态与统计信息
```

### 路由实现
本模块通过修改 Sing-box 或 Xray 配置文件的 `outbounds` 和 `route` 片段来实现分流。
  * **出站 (`outbounds`)**: 至少包含 `direct` 和 `resi_out` 两个出站标签，分别对应 VPS 和住宅代理。
  * **路由规则 (`routing`)**: 工具根据 `SHUNT_MODE` 变量，生成不同的路由规则，决定流量的最终去向。
      * **`vps` 模式**: 最终去向 (`final`) 为 `direct`。
      * **`resi` 模式**: 最终去向 (`final`) 为 `resi_out`。
      * **`direct_resi` 模式**: 白名单流量优先去向 `direct`，非白名单流量最终去向 `resi_out`。
   
### 开发约束
- 模板幂等性：edgeboxctl shunt apply 仅修改出站与路由片段，不触碰证书、入站、fallbacks 和端口策略。这确保了分流模块是一个独立的、可控的单元，满足幂等部署的需求。
- GCP 出站约束：为避免触发 GCP 的公网出站计费，请确保您的配置遵循以下原则：CF灰云，不启用 Cloudflare 的 Argo/WARP/Zero Trust 等服务，不让任何代理“回源”到 Cloudflare 边缘节点，此策略旨在保持在 200GB 内的标准计费，避免意外产生高额费用。

-----

## 运维与管理

### 流量统计
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

### 备份与恢复
系统每日凌晨3点自动备份配置和数据到 `/root/edgebox-backup/`。你可以使用 `edgeboxctl backup` 命令手动创建、列出和恢复备份。

-----

### 管理工具 (`edgeboxctl`)

`edgeboxctl` 是管理 EdgeBox 的核心工具，所有操作都通过它完成，管理工具 [`edgeboxctl shunt`] 支持**切换模式、配置住宅代理、维护白名单**。

  * **配置与更新住宅代理**
    ```bash
    edgeboxctl shunt apply <IP:PORT[:USER:PASS]>
    ```
  - 该命令仅写入代理参数到 `/etc/edgebox/shunt/resi.conf`，不改变当前模式。
  * **出战分流切换**
    ```bash
    edgeboxctl shunt mode vps          # 切换至 VPS 全量出
    edgeboxctl shunt mode resi         # 切换至住宅 IP 全量出
    edgeboxctl shunt mode direct_resi  # 切换至白名单 + 分流
    ```
    - 注意: 切换到 `resi` 或 `direct_resi` 模式前，系统会进行健康探活。如果住宅代理不可用，将保持 `vps` 模式并给出提示。
  * **白名单维护**
    ```bash
    edgeboxctl shunt whitelist add <domain_suffix>
    edgeboxctl shunt whitelist del <domain_suffix>
    edgeboxctl shunt whitelist list
    ```
    白名单匹配采用域名后缀方式（例如 `googlevideo.com、ytimg.com、ggpht.com`），确保白名单始终优先匹配并直连 VPS。
  * **模式切换**
  * **切换至域名模式**：`edgeboxctl change-to-domain <your_domain>`
  * **回退至 IP 模式**：`edgeboxctl change-to-ip`

  * **流量统计**：`edgeboxctl traffic show` (显示流量)，或通过浏览器访问 `http://<your-ip-or-domain>/` 查看静态图表。
  * **出站分流**：`edgeboxctl shunt mode vps/resi/direct_resi`
  * **备份与恢复**：`edgeboxctl backup create/restore`

  * **常用命令：**
| **命令** | **功能** |
| :--- | :--- |
| `edgeboxctl service status` | 查看服务状态 |
| `edgeboxctl sub` | 动态生成订阅链接 |
| `edgeboxctl cert status` | 查看证书状态 |
| `edgeboxctl config regenerate-uuid` | 重新生成 UUID |
| `edgeboxctl update` | 更新 EdgeBox |
| `edgeboxctl uninstall` | 完全卸载 EdgeBox |

-----

## 安全建议与常见问题

### 客户端配置

  * 启用“绕过大陆”分流规则。
  * 配合 VPS 白名单直出策略。
  * 定期更换伪装域名。

### 服务端维护

  * 定期系统更新：`apt update && apt upgrade`。
  * 监控异常流量：`edgeboxctl traffic show`。
  * 适时轮换 UUID：`edgeboxctl config regenerate-uuid`。

### 常见问题

  * **Q: 连接失败，显示 -1ms？**
      * **排查步骤**：检查防火墙端口、服务运行状态、证书配置和日志。
  * **Q: Reality 协议无法连接？**
      * **解决方案**：确认伪装域名可访问、检查 SNI 配置并验证端口 443 未被占用。
  * **Q: GCP会因 gRPC 协议切换高级网络吗？**
      * **答案**：绝对不会。GCP 网络层级在 VM 创建时已固定，协议类型不会影响网络层级计费。

-----

## 📈 社区特色

  * **安装友好**：一键安装、幂等卸载、文档详细。
  * **GCP 优化**：针对 GCP 网络计费进行优化。
  * **灵活运维**：模式切换、流量统计、自动备份。

-----

## 📄 许可证

本项目采用 MIT 许可证，详见 [LICENSE](https://www.google.com/search?q=LICENSE) 文件。

-----

## 🤝 贡献与支持

欢迎提交 Issue 和 Pull Request！如果这个项目对您有帮助，请给个 Star ⭐。
