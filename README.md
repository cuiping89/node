
# EdgeBox：一站式多协议节点部署方案

- EdgeBox 是一个多协议一键部署脚本，旨在提供一个**健壮灵活、一键部署、幂等卸载**的安全上网解决方案，
- 核心策略：**协议组合+端口分配+出站分流**，健壮灵活、深度伪装、灵活路由，能应对复杂多变的网络环境，
- 运维功能：**模式切换+流量统计+备份恢复**。配置灵活、流量预警、安全备份，满足运维需求。

---

### **🚀 功能亮点**

* **一键安装**：默认非交互式“IP模式”安装
* **幂等卸载**：一键清理所有组件，简洁、高效、幂等、非交互，为安装失败后重装准备环境，适合自动化和故障排除
* **协议组合**：VLESS-gRPC、VLESS-WS、VLESS-Reality、Hysteria2、TUIC
* **端口分配**：**Nginx + Xray 单端口复用（Nginx-first）**，实现 TCP/443 和 UDP/443 的深度伪装。
* **出站分流**：直连白名单 与 住宅IP出站
* **模式切换**：提供管理工具 `edgeboxctl`，实现模式双向切换：IP模式 ⇋ 域名模式；VPS直出模式 ⇋ 住宅代理分流模式
* **流量统计**：内置 vnStat + iptables 流量监控
* **备份恢复**：每日自动备份，支持一键恢复

---

### **软件要求**
* 系统软件：Ubuntu 18.04+； Debian 10+
* 依赖软件：安装脚本会自动检测并安装 `curl`, `wget`, `unzip`, `tar`, **`nginx`**, `certbot`, `vnstat`, `iftop`。

#### **硬件要求**
* CPU: 1 核
* 内存: 512MB（内存不足自动创建 2G swap 补足）
* 存储: 10GB 可用空间
* 网络: 稳定的公网 IP

### **核心组件**
* **Nginx**：作为公网 `TCP/443` 的前置代理，负责基于 **SNI/ALPN** 的非终止 TLS 分流。
* **Xray**：运行 Reality、VLESS-gRPC 和 VLESS-WS 协议，监听内部回环端口，负责各自协议的 TLS 终止。
* **sing-box**：独立运行 Hysteria2 和 TUIC 协议，直接监听 UDP 端口。

### **证书管理**
EdgeBox 的证书管理模块旨在实现全自动化，根据用户是否提供域名来智能选择证书类型，并确保证书的生命周期得到妥善管理。

#### **1. 证书类型与生成流程**
EdgeBox 支持两种证书类型，它们在安装和运行的不同阶段自动生成或配置，以满足不同模式的需求。

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

#### **2. 证书在配置文件中的引用**

为确保模式切换的幂等性，所有服务配置文件都将使用软链接来动态指向正确的证书文件。

* **Nginx、Xray 和 sing-box**：
    * `ssl_certificate`：指向 `/etc/edgebox/cert/current.pem`
    * `ssl_certificate_key`：指向 `/etc/edgebox/cert/current.key`
    * `edgeboxctl` 工具在切换模式时，将更新这两个软链接，使其分别指向自签名证书或 Let's Encrypt 证书的实际文件，从而实现无缝切换。

---

## 协议组合策略

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
---

## 端口分配策略

本方案采用 **Nginx + Xray 单端口复用（Nginx-first）** 架构，实现了智能分流和深度伪装的完美结合。

**核心理念：**
- 让 **Nginx** 成为所有 **TCP** 流量的守门员，它只监听公网 `443` 端口。Nginx根据流量类型（通过 SNI/ALPN 判断）智能地分发给后端不同功能的 **Xray** 内部服务。

### **工作流**

| **协议类型** | **工作流程** |
| :--- | :--- |
| **Reality** | 客户端 → **Nginx:443** → **Nginx** 根据 **SNI 伪装域名** 转发 → **Xray Reality 入站@11443** (内部) |
| **gRPC** | 客户端 → **Nginx:443** → **Nginx** 根据 **ALPN=h2** 转发 → **Xray gRPC 入站@10085** (内部) |
| **WebSocket** | 客户端 → **Nginx:443** → **Nginx** 根据 **ALPN=http/1.1** 转发 → **Xray WS 入站@10086** (内部) |
| **Hysteria2/TUIC** | 客户端 → **Sing-box** 直接处理 **UDP** 流量（分别监听 `443/udp` 和 `2053/udp`），与 Nginx 无关。 |

### **端口分配**

| **类型** | **端口** | **功能** |
| :--- | :--- | :--- |
| **对外暴露** | TCP/443 | 所有 TCP 协议的统一入口，由 Nginx 监听。 |
| | UDP/443 | Hysteria2 使用，实现高隐蔽性。 |
| | UDP/2053 | TUIC 使用（可选）。 |
| **内部回环** | TCP/11443 | Xray Reality 服务。 |
| | TCP/10085 | Xray gRPC 服务。 |
| | TCP/10086 | Xray WebSocket 服务。 |

**重要提醒**：在你的 Nginx 配置中，请确保 **Reality** 的 `serverNames` 列表**只包含伪装域名**，这样可以防止 Reality “劫持”你真实的 gRPC 或 WS 流量。

### 部署与模式切换策略

本方案的核心在于 **edgeboxctl** 管理工具，它能实现两种核心模式之间的无缝切换，以适应不同的网络环境。

#### 初始安装（非交互式 IP 模式）
- 安装脚本默认为非交互模式，专为无域名或非住宅 IP 的环境设计。安装后，所有协议均可立即工作，但部分协议使用自签名证书。
* **Nginx**： * 作为公网 `443/TCP` 的唯一入口，启动时将所有非 Reality 的流量转发到 Xray 的内部回环端口。
* **Reality**：* 独立启用，监听**内部回环端口**。其 `server_name` 伪装为 `www.cloudflare.com` 等常规网站，按常规生成密钥对。
* **VLESS-gRPC / VLESS-WS**：* 分别监听**内部回环端口**。后端使用 **自签名证书**，并配置各自的 `alpn`。
* **Hysteria2 / TUIC**： * 同样使用 **自签名证书** 启动，分别监听 **UDP/443** 和 **UDP/2053**。

#### 模式双向切换（`edgeboxctl` 命令）
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
---

你的方案非常完善，已经考虑到了多种场景和异常处理。我将你的所有要点进行整合，使其更具逻辑性和可读性，并且语言更精炼，可以作为项目 `README` 或技术文档的核心部分。

-----

## 出站分流策略 (增强版)

本模块为 EdgeBox 节点提供灵活、高效的流量分流能力。它允许用户在三种互斥的出站模式之间自由切换，通过精细的白名单管理，在节省流量和维护账号画像之间取得平衡。

### 核心模式
该模块由 **`SHUNT_MODE`** 变量控制，并与核心的域名/IP 切换功能完全解耦。

| 模式 | `SHUNT_MODE` | 行为 | 典型用途 |
| :--- | :--- | :--- | :--- |
| **VPS 全量出** | `vps` | 所有流量通过 VPS 出口发出。 | 默认模式、零配置、排障时最稳定。 |
| **住宅 IP 全量出**| `resi` | 所有流量通过配置的住宅代理 IP 发出。 | 需稳定地域画像的场景。 |
| **白名单 + 分流** | `direct_resi`| 白名单域名直连 VPS；其余流量走住宅 IP。 | 兼顾成本与画像的平衡方案。 |

### 管理工具 (`edgeboxctl`)
所有分流管理操作均通过 `edgeboxctl` 命令完成。
  * **配置与更新住宅代理**
    ```bash
    edgeboxctl shunt apply <IP:PORT[:USER:PASS]>
    ```
  该命令仅写入代理参数到 `/etc/edgebox/shunt/resi.conf`，不改变当前模式。
  * **模式切换**
    ```bash
    edgeboxctl shunt mode vps          # 切换至 VPS 全量出
    edgeboxctl shunt mode resi         # 切换至住宅 IP 全量出
    edgeboxctl shunt mode direct_resi  # 切换至白名单 + 分流
    ```
    **注意**: 切换到 `resi` 或 `direct_resi` 模式前，系统会进行健康探活。如果住宅代理不可用，将保持 `vps` 模式并给出提示。
  * **清除代理配置**
    ```bash
    edgeboxctl shunt clear
    ```
    此命令会删除代理配置，并强制切换回 `vps` 全量出模式。
  * **白名单维护**

    ```bash
    edgeboxctl shunt whitelist add <domain_suffix>
    edgeboxctl shunt whitelist del <domain_suffix>
    edgeboxctl shunt whitelist list
    ```
    白名单匹配采用域名后缀方式（例如 `googlevideo.com`），确保白名单始终优先匹配并直连 VPS。
  * **状态与健康检查**
    ```bash
    edgeboxctl shunt test     # 立即对住宅代理进行健康探活
    edgeboxctl shunt status   # 显示当前模式、代理可用性、最后切换时间等
    ```   
### 实现细节

#### 文件与目录布局
所有分流相关文件都统一管理在 `/etc/edgebox/shunt/` 目录下，保证清晰和原子化。
```
/etc/edgebox/shunt/
  ├─ whitelist-vps.txt   # 白名单列表
  ├─ resi.conf           # 住宅代理配置
  └─ state.json          # 记录当前状态与统计信息
```
#### 路由实现
本模块通过修改 Sing-box 或 Xray 配置文件的 `outbounds` 和 `route` 片段来实现分流。
  * **出站 (`outbounds`)**: 至少包含 `direct` 和 `resi_out` 两个出站标签，分别对应 VPS 和住宅代理。
  * **路由规则 (`routing`)**: 工具根据 `SHUNT_MODE` 变量，生成不同的路由规则，决定流量的最终去向。
      * **`vps` 模式**: 最终去向 (`final`) 为 `direct`。
      * **`resi` 模式**: 最终去向 (`final`) 为 `resi_out`。
      * **`direct_resi` 模式**: 白名单流量优先去向 `direct`，非白名单流量最终去向 `resi_out`。
#### 健康探活与回退
系统在切换到 `resi` 或 `direct_resi` 模式前，会首先对住宅代理进行健康探活。若探活失败，将自动回退到 `vps` 模式，并记录告警，确保服务不中断。此外，系统可配置定时巡检，在代理故障时自动回退，并在恢复后自动切换回原模式。

### 4. 开发细节与约束

- 模板幂等性：edgeboxctl shunt apply 仅修改出站与路由片段，不触碰证书、入站、fallbacks 和端口策略。这确保了分流模块是一个独立的、可控的单元，满足幂等部署的需求。
- GCP 出站约束：为避免触发 GCP 的公网出站计费，请确保您的配置遵循以下原则：
  - 不启用 Cloudflare 的 Argo/WARP/Zero Trust 等服务。
  - 不让任何代理“回源”到 Cloudflare 边缘节点。
  - 此策略旨在保持在 200GB 内的标准计费，避免意外产生高额费用。
- 默认直连白名单：可编辑的白名单列表应在代码中清晰定义，例如：
  - googlevideo.com
  - ytimg.com
  - ggpht.com
- 健康探活：在切换到代理出站模式前，应添加简单的探活逻辑，以验证代理的可用性。如果代理不可用，应自动回退到直连模式并给出提示。

-----

## 运维与管理

### 1. 流量统计
本方案采用**轻量级采集 + 结构化存储 + Matplotlib 静态图**，并将流量图表与订阅链接集成到同一浏览器页面中。整个系统不引入复杂的依赖或前端框架，保持了极简、可维护和幂等的设计。

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
  │   │   ├─ daily.csv               # 每日流量数据 (6 个月滚动)
  │   │   └─ monthly.csv             # 月度累计数据 (24 个月滚动)
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

#### 使用方式
  * **浏览器访问**: `http://<your-ip-or-domain>/`
  * **命令行**:
      * `edgeboxctl traffic show`：查看实时流量快照。
      * `cat /etc/edgebox/traffic/sub.txt`：获取原始订阅文本。
      * `/etc/edgebox/scripts/generate-charts.py`：手动触发页面刷新。

#### 幂等性与卸载
  * **幂等性**: 脚本设计为可重复执行，`CSV` 文件会追加合并，`PNG/HTML` 文件会直接覆盖，确保系统的稳定。
  * **卸载**: `uninstall.sh` 脚本应对称删除所有相关文件和配置，包括 `/etc/edgebox/traffic/`、脚本、`cron` 任务和 Nginx 配置片段。


### 2. 备份与恢复
- 自动备份：每日凌晨3点自动备份配置、证书和用户数据到 /root/edgebox-backup/，保留最近15天的备份。
- 手动操作：
  - edgeboxctl backup list：列出所有备份。
  - edgeboxctl backup create：手动创建备份。
  - edgeboxctl backup restore <日期>：恢复指定日期的备份。

### 3. edgeboxctl 命令集

#### 配置管理

- edgeboxctl config show          # 显示当前配置
- edgeboxctl config show-sub      # 显示订阅链接
- edgeboxctl config regenerate-uuid # 重新生成 UUID

#### 服务管理

- edgeboxctl service status       # 服务状态
- edgeboxctl service restart      # 重启服务
- edgeboxctl service logs         # 查看日志

#### 出站分流

- edgeboxctl shunt apply          # 启用住宅代理分流
- edgeboxctl shunt clear          # 切换回VPS直连

#### 流量统计

- edgeboxctl traffic show         # 显示流量统计
- edgeboxctl traffic reset        # 重置流量计数

#### 证书管理

- edgeboxctl cert status	        # 查看状态：显示当前使用的证书类型、到期时间，及自动续期任务状态。
- edgeboxctl cert renew	        # 手动续期：强制执行 certbot 续期操作。通常用于测试或自动续期失败时。
- edgeboxctl cert upload <fullchain_path> <key_path>	# 上传自定义证书：允许用户使用自己的证书。脚本将把提供的证书文件软链接到 current.pem/key。

#### 系统管理

- edgeboxctl update               # 更新EdgeBox
- edgeboxctl reinstall            # 重新安装
- edgeboxctl uninstall            # 完全卸载
---

### **分模块开发**

### 模块 1 - 核心基础安装（内核契约）

**目标**：交付一个功能完整、稳定可靠的基础安装包。该模块负责所有核心服务的部署，并定义后续模块将依赖的**“内核契约”**。

**协议配置与契约定义**

* **端口契约**：
    * **公网 443/TCP 端口由 Nginx 监听**，作为所有 TCP 协议的唯一入口。
    * **Xray** 的 Reality、VLESS-gRPC 和 VLESS-WS 服务均监听**内部回环端口**，**不直接暴露在公网**。
    * VLESS-Reality 监听 127.0.0.1:11443。
    * VLESS-gRPC 监听 127.0.0.1:10085。
    * VLESS-WS 监听 127.0.0.1:10086。

* **分流机制**：
    * **Nginx 负责唯一的流量分发**：它使用 `stream` 模块的 `ssl_preread` 功能，根据流量的 **SNI** 和 **ALPN**，直接将流量转发到 Xray 对应的内部回环端口。
    * **本方案不依赖 Xray 的任何回落（fallbacks）功能**。

* **证书软链接**：
    * 确保所有服务（Nginx, Xray, sing-box）都从 `CERT_DIR/current.pem` 和 `CERT_DIR/current.key` 获取证书。这是模块 2 动态证书管理的基础。

* **基础订阅**：
    * 确保 `install.sh` 在安装完成后能生成一个基础的、硬编码的订阅链接。订阅链接的格式、字段是模块 2 动态生成订阅的契约。

**测试与验证**

* **功能测试**：在干净的虚拟机上运行 `install.sh`。
    * 验证所有服务是否正常运行：`systemctl status nginx sing-box xray`。
    * 验证监听端口：`netstat -tulnp`，确保 **Nginx 监听 443/TCP**，而 **Xray 和 sing-box 仅监听内部端口或 UDP 端口**。
    * 验证客户端能成功连接所有 5 个协议。
* **幂等卸载测试**：运行 `uninstall.sh` 并验证所有文件和服务是否被完全清除。

#### 模块 2 - edgeboxctl 管理工具

* **前置条件**：模块 1 已完成并冻结“内核契约”。模块 2 的开发必须基于这些已定义的端口、文件路径和订阅格式。
* **目标**：开发一个命令行工具，作为用户与核心服务进行交互的管理层，实现动态配置和模式切换。

##### **关键任务与交付物：**
* **命令行工具 (edgeboxctl)**：使用 Shell 脚本（或 Python/Go）开发。
* **模式切换**：实现 `edgeboxctl config switch-mode`。
    * **IP 模式 ⟶ 域名模式**：获取 Let's Encrypt 证书，并用新证书替换所有协议的自签名证书。Nginx 和 Xray 的配置将被更新以使用真实域名。
    * **域名模式 ⟶ IP 模式**：重新生成自签名证书，并将所有配置回退到初始 IP 模式。
* **证书管理**：`edgeboxctl cert renew` 和 `edgeboxctl cert upload`。
* **配置管理**：`edgeboxctl config regenerate-uuid` 和 `edgeboxctl config show`。
* **动态订阅生成**：`edgeboxctl sub` 命令应根据当前模式（IP/域名）和配置，动态生成并显示订阅链接。

### **模块 3 - 高级运维功能（可选）**

**前置条件：** 模块 1 和 2 已完成，并已建立稳定的内核和管理层。该模块将利用 `edgeboxctl` 工具提供的接口，实现自动化和高级运维功能，不影响核心服务的稳定性。

* **出站分流：**
    * **流量路由：** 在 `sing-box` 的配置中添加**出站规则**。例如，通过识别 `googlevideo.com` 等特定域名，将其流量直接路由，而将剩余的流量通过代理（如住宅代理）出站。
    * **配置管理：** 在 `edgeboxctl` 中添加 `edgeboxctl config switch-outbound <mode>` 命令，其中 `<mode>` 可以是 `direct`（所有流量直连）、`proxy`（所有流量代理）或 `smart`（按规则分流），该命令会修改 `sing-box` 的配置文件并重新加载服务。
* **流量统计：**
    * **数据收集：** 使用**`vnStat`**或**`iptables`**作为流量数据收集器。`vnStat` 是一个轻量级的网络流量监控工具，非常适合收集和记录流量数据。
    * **命令行接口：** 在 `edgeboxctl` 中添加 `edgeboxctl traffic show` 和 `edgeboxctl traffic reset` 命令。`show` 命令将调用 `vnStat` 或解析 `iptables` 规则，显示所有协议的总流量和分协议流量；`reset` 命令则清零所有计数器。
* **自动备份与恢复：**
    * **备份脚本：** 创建一个脚本，自动备份 `/etc/edgebox/`、核心配置以及**`vnStat`**的数据文件到 `/root/edgebox-backup/` 目录。
    * **定时任务：** 配置 `cron` 任务，每日自动运行备份脚本，保留最近 N 个备份版本。
    * **恢复命令：** 在 `edgeboxctl` 中添加 `edgeboxctl backup restore <timestamp>` 命令，该命令会解压指定时间戳的备份文件，覆盖现有配置文件，并重新加载所有服务。
---

## 一键安装

服务器上执行以下命令即可开始：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/install.sh)
```

### 1. 系统预检查

- ✅ 操作系统兼容性
- ✅ 网络连通性测试
- ✅ 防火墙端口检查
- ✅ 系统资源验证
- ✅ DNS解析测试

### 2. 安装后验证

- 🔍 服务状态检查
- 🔍 端口监听验证
- 🔍 证书有效性检查
- 🔍 配置文件语法验证

---

## 📱 订阅链接

- 浏览器方式：http://your-domain
- SSH方式：edgeboxctl sub

## 🔒 安全建议

### 客户端配置

- ✅ 启用"绕过大陆"分流规则
- ✅ 配合VPS白名单直出策略
- ✅ 定期更换伪装域名

### 服务端维护

- 🔄 定期系统更新：`apt update && apt upgrade`
- 📊 监控异常流量：`edgeboxctl traffic show`
- 🔑 适时轮换UUID：`edgeboxctl config regenerate-uuid`

---

## ❓ 常见问题

<details>
<summary><strong>Q: 连接失败，显示 -1ms？</strong></summary>

**排查步骤：**
1. 检查防火墙端口开放：`ufw status`
2. 验证服务运行状态：`edgeboxctl service status`
3. 检查证书配置：`edgeboxctl cert status`
4. 查看服务日志：`edgeboxctl service logs`
</details>

<details>
<summary><strong>Q: Reality 协议无法连接？</strong></summary>

**解决方案：**
1. 确认伪装域名可访问：`curl -I https://www.cloudflare.com`
2. 检查SNI配置：`edgeboxctl config show`
3. 验证端口443未被占用：`netstat -tlnp | grep :443`
</details>

<details>
<summary><strong>Q: GCP会因gRPC协议切换高级网络吗？</strong></summary>

**答案：绝对不会！**
- GCP网络层级在VM创建时固定设置
- gRPC本质是HTTP/2，使用标准TCP/443端口
- 只要VM设为"标准网络层级"，200GB内都是标准计费
- 协议类型不影响网络层级计费
</details>

---

## 📈 社区特色

- 👥 **安装友好**：一键安装、幂等卸载、文档详细
- 🎯 **GCP优化**：针对GCP网络计费进行网络优化
- 📊 **灵活运维**：模式切换、流量统计、自动备份

---

## 📄 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## ⭐ 支持项目

如果这个项目对您有帮助，请给个 Star ⭐
