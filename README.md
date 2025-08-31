# EdgeBox：一站式多协议节点部署方案

- EdgeBox 是一个多协议一键部署脚本，旨在提供一个**健壮灵活、一键部署、幂等卸载**的科学上网解决方案，
- 核心策略：**协议组合+端口分配+出站分流**，健壮灵活、深度伪装、灵活路由，能应对复杂多变的网络环境，
- 运维功能：**模式切换+流量统计+备份恢复**。配置灵活、流量预警、安全备份，满足运维需求。

---

## 🚀 功能亮点

- **一键安装**：非交互式默认“IP模式”安装
- **幂等卸载**：一键清理所有组件，简洁、高效、幂等、非交互，为安装失败后重装准备环境，适合自动化和故障排除
- **协议组合**：VLESS-gRPC、VLESS-WS、VLESS-Reality、Hysteria2、TUIC
- **端口分配**：单端口复用 + 内部回环
- **出站分流**：直连白名单 与 住宅IP出站
- **模式切换**：提供管理工具edgeboxctl，实现模式双向切换：IP模式 ⇋ 域名模式；VPS直出模式 ⇋ 住宅代理分流模式
- **流量统计**：内置 vnStat + iptables 流量监控
- **备份恢复**：每日自动备份，支持一键恢复

---

## 软件要求

- 系统软件：Ubuntu 18.04+； Debian 10+
- 依赖软件：安装脚本会自动检测并安装curl, wget, unzip, tar, certbot, vnstat, iftop。

## 硬件要求

- CPU: 1 核
- 内存: 512MB（内存不足自动创建s2G swap补足）
- 存储: 10GB 可用空间
- 网络: 稳定的公网 IP

---

## 核心组件

- **Nginx**: 前置代理，TLS终止，SNI分流
- **Xray**: VLESS-gRPC + VLESS-WS
- **sing-box**: Reality + Hysteria2 + TUIC

---

## 证书管理

EdgeBox 的证书管理模块旨在实现全自动化，根据用户是否提供域名来智能选择证书类型，并确保证书的生命周期得到妥善管理。

### 1. 证书类型与生成流程

- EdgeBox 支持两种证书类型，它们在安装和运行的不同阶段自动生成或配置。

#### 自签名证书（IP模式）

- 生成时机：在非交互式安装或无域名配置时自动生成。
- 用途：用于初始阶段，确保 VLESS-gRPC、VLESS-WS、Hysteria2 和 TUIC 协议能够立即启用并工作。这些协议在客户端连接时需要开启“跳过证书验证”或“允许不安全”。
- 文件路径：
  - 私钥：/etc/edgebox/cert/self-signed.key
  - 公钥：/etc/edgebox/cert/self-signed.pem

#### Let's Encrypt 证书（域名模式）

- 生成时机：用户使用 edgeboxctl change-to-domain 命令并提供有效域名后，脚本会自动调用 certbot 申请。
- 用途：提供受信任的、安全的TLS加密，使所有协议在客户端无需任何额外设置即可安全连接。
- 文件路径：
  - 私钥：/etc/letsencrypt/live/<your_domain>/privkey.pem
  - 公钥：/etc/letsencrypt/live/<your_domain>/fullchain.pem
- 自动续期：脚本将配置一个 cron 任务，自动执行 certbot renew 命令，确保证书在到期前自动续期。

### 2. 证书在配置文件中的引用

为了确保证书切换的幂等性，配置文件将使用变量或软链接来动态指向正确的证书文件。

#### Nginx 配置 (/etc/nginx/nginx.conf 或相关文件)

- ssl_certificate：动态指向 /etc/edgebox/cert/current.pem
- ssl_certificate_key：动态指向 /etc/edgebox/cert/current.key

#### Xray 和 sing-box 配置

- tls.certificates[0].certificate_file：指向 /etc/edgebox/cert/current.pem
- tls.certificates[0].key_file：指向 /etc/edgebox/cert/current.key
- edgeboxctl 工具在切换模式时，将更新 /etc/edgebox/cert/current.pem 和 /etc/edgebox/cert/current.key 这两个软链接，使其分别指向自签名证书或 Let's Encrypt 证书的实际文件。

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

本方案采用 **Xray单口复用、智能分流** 架构

### 1. 架构与技术原理

* **单一入口**：所有基于 TCP 的加密流量均由 **Xray** 在公网 **TCP/443** 端口接收。
* **智能分流**：
    * **Reality 协议**：如果流量匹配 Reality 特征，Xray 会直接在 `443` 端口处理。
    * **非 Reality 协议**：对于非 Reality 的 TLS 流量（如 VLESS-gRPC 或 VLESS-WS），Xray 会通过 `fallbacks` 机制，根据 ALPN 值将原始 TLS 字节流直接转发到内部端口，无需任何中间代理。
* **内部处理**：
    * **TCP/10085**（gRPC）和 **TCP/10086**（WS）端口仅监听 `127.0.0.1`，这两个端口上的 Xray 服务各自启用 TLS，在本机完成握手与解密。

### 2. 端口分配

| 类型 | 端口 | 协议/组件 | 描述 |
| :--- | :--- | :--- | :--- |
| **对外开放** | TCP/443 | Xray | 唯一入口，用于 Reality、VLESS-gRPC 和 VLESS-WS。 |
| | UDP/443 | sing-box | 用于 Hysteria2。 |
| | UDP/2053 | sing-box | 用于 TUIC。 |
| **内部回环** | TCP/10085 | Xray | VLESS-gRPC 专用，启用 TLS。 |
| | TCP/10086 | Xray | VLESS-WS 专用，启用 TLS。 |

### 3. 安全与运维

* **防火墙**：仅放行 TCP/443、UDP/443、UDP/2053 和 SSH 等管理端口，严格禁止外部访问 `10085` 和 `10086` 等内部端口。
* **证书管理**：全部服务统一使用 /etc/ssl/edgebox/cert.pem 与 /etc/ssl/edgebox/key.pem；由 edgeboxctl 统一更新与校验。
* **订阅获取**：通过 `edgeboxctl sub` 在终端获取，供客户端手动导入。
* **健康自检**：在应用配置前执行 `xray -test -config` 进行预检，并采用“生成新文件 → 预检通过 → 原子替换 → reload”的流程，失败则自动回滚。

根据您提供的文件和我们最终确定的**“极简架构”**，以下是修订和整合后的文档，使其与最终方案完全一致。

### 4. 部署与模式切换策略

本方案的关键在于 **edgeboxctl** 管理工具，它能实现两种核心模式之间的无缝切换，以适应不同的网络环境。

#### 初始安装（非交互式 IP 模式）

安装脚本默认为非交互模式，专为无域名或非住宅 IP 的环境设计。安装后，所有协议均可立即工作，但部分协议使用自签名证书。

* **Reality**：启用，`server_name` 伪装为 **`www.cloudflare.com`**，按常规生成密钥。
* **VLESS-gRPC / VLESS-WS**：
    * Xray 后端使用 **自签名证书**。
    * Reality 入站配置中设置**回落规则（fallbacks）**，当流量的 SNI 命中占位符（如 `grpc.edgebox.local` 或 `www.edgebox.local`）且 ALPN 命中 `h2` 或 `http/1.1` 时，Xray 会将流量**直接回落**至内部回环端口 `127.0.0.1:10085` 或 `127.0.0.1:10086`。
* **Hysteria2 / TUIC**：同样使用**自签名证书**启动。

#### 模式双向切换（`edgeboxctl` 命令）

* **切换至域名模式**：
    * **命令**：`edgeboxctl change-to-domain <your_domain>`
    * **逻辑**：工具将检查域名解析，自动申请 Let's Encrypt 证书，并用新证书替换**所有协议**的自签名证书。Xray 和 sing-box 的配置将被更新以使用真实域名。
* **回退至 IP 模式**：
    * **命令**：`edgeboxctl change-to-ip`
    * **逻辑**：当域名或住宅 IP 失效时，此命令将删除或禁用 Let's Encrypt 证书，重新生成并启用自签名证书，并将所有配置回退到初始 IP 模式。
  
### 5. 动态生成订阅链接

**`edgeboxctl sub`** 命令是获取订阅链接的唯一途径，它能根据当前模式动态生成一键导入的聚合链接。

* **逻辑判断**：脚本通过检查 `/etc/letsencrypt/` 目录下是否存在证书来判断当前模式。
* **IP 模式下的链接生成**：
    * `address`：使用服务器的**公网 IP**。
    * **VLESS-gRPC/WS**：SNI 使用占位符（`grpc.edgebox.local` / `www.edgebox.local`），并添加 `allowInsecure=1` 参数。
    * **Hysteria2/TUIC**：添加 `insecure=true` 或 `skip-cert-verify=true` 参数。
* **域名模式下的链接生成**：
    * `address`：使用你的**真实域名**。
    * **VLESS-gRPC/WS**：SNI 使用你的真实域名，移除 `allowInsecure=1` 参数。
    * **Hysteria2/TUIC**：移除 `insecure=true` 或 `skip-cert-verify=true` 参数。
* **聚合**：将所有协议的链接聚合，进行 Base64 编码，并在终端中**直接打印**或保存到本地文件，供客户端手动导入。本方案**不提供任何 HTTP 订阅链接**。

---

## 出站分流策略

- 本模块旨在为 EdgeBox 节点提供灵活、高效的流量分流能力。它允许用户在节省流量和保持账号画像稳定之间取得平衡，并且与核心的域名/IP 切换功能解耦。

### 1. 策略目标

- 直连白名单：将指定域名（例如 googlevideo.com 等）的流量直接通过 VPS 出口访问。这能显著节省住宅代理IP流量，并提供最佳的流媒体观看体验。
- 住宅IP出站：将所有不属于白名单的流量通过配置的静态住宅代理IP出站。这有助于稳定账号的地域画像，避免频繁变更IP地址导致的异常行为。

### 2. 模式与状态

- 本分流模块是一个独立的、支持双向切换的功能，其状态由 SHUNT_MODE 变量控制，与域名模式/IP 模式完全解耦。
  - 默认模式：VPS 直出（SHUNT_MODE=direct）
    - 行为：这是非交互式安装后的默认状态。所有流量都通过您的 VPS 服务器 IP 地址直接出站。
    - 优点：零配置，开箱即用，满足“先用后配”的要求。
  - 可选模式：住宅代理出站（SHUNT_MODE=resi）
    - 行为：当此模式启用时，除白名单流量外，其余所有流量都将通过指定的住宅代理IP出站。
    - 优点：保护账号画像，适用于需要稳定出口IP的场景。

### 3. 管理工具实现（edgeboxctl）

- 启用住宅代理出站：
  - 命令：edgeboxctl shunt apply <代理地址>
  - 代理地址格式：
    - 不带认证：<IP>:<端口>，例如 192.0.2.1:8080
    - 带认证：<IP>:<端口>:<用户名>:<密码>，例如 192.0.2.1:8080:user:pass
  - 实现逻辑：
    - 脚本解析传入的 <代理地址> 字符串，识别其格式并提取 IP、端口、用户名和密码（如果存在）。
    - 将代理信息永久保存到配置文件中。
    - 修改 sing-box 或 Xray 的核心配置文件，注入一个指向该代理的 outbound 配置。
    - 添加分流路由规则，将白名单流量路由到直连，其余流量路由到代理。
    - 执行健康探活，确保代理可用。
    - 重启 sing-box 和 Xray 服务以应用更改。
- 切换回 VPS直出模式：
  - 命令：edgeboxctl shunt clear
  - 实现逻辑：
    - 删除或清空保存代理IP和端口的配置文件。
    - 修改 sing-box 或 Xray 的核心配置文件，删除代理 outbound 和相关的分流 routing 规则。
    - 确保默认的直连 outbound 是唯一的或优先级最高的出站规则。
    - 重启 sing-box 和 Xray 服务。

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

---

## 运维与管理

### 1. 流量统计

- 命令：edgeboxctl traffic show
  - 显示内容：vnStat 系统流量、各协议端口流量、iptables/nftables 计数。
- 命令：edgeboxctl traffic reset
  - 重置流量计数。

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

## 分模块开发
### 模块 1 - 核心基础安装（内核契约）
- 目标：交付一个功能完整、稳定可靠的基础安装包。该模块负责所有核心服务的部署，并定义后续模块将依赖的**“内核契约”**。
#### 关键任务与交付物：
- 安装/卸载脚本框架 (install.sh, uninstall.sh)
- 脚本骨架： 定义全局变量、颜色、日志函数、错误处理 (set -e)。
- 核心功能函数： install_dependencies()、configure_xray()、configure_sing_box()、configure_nginx()、start_services() 等。
- 幂等卸载： uninstall.sh 脚本必须能完全清除所有文件、服务和配置，确保多次运行不会出错，为重新安装提供干净环境。
#### 协议配置与契约定义
##### 端口契约：
- 在 install.sh 中明确定义所有协议的内部端口。
- VLESS-Reality：内部回环 127.0.0.1:443
- Hysteria2：内部回环 127.0.0.1:443（避免端口冲突）
- Nginx：内部回环 127.0.0.1:10443
##### 回落机制：
- Nginx 监听 127.0.0.1:10443，并根据 ALPN 流量分发到不同的后端，这是核心路由逻辑。
##### 证书软链接：
- 确保所有服务都从 CERT_DIR/current.pem 和 CERT_DIR/current.key 获取证书。这是模块 2 动态证书管理的基础。
##### 基础订阅：
- 确保 install.sh 在安装完成后能生成一个基础的、硬编码的订阅链接。订阅链接的格式、字段是模块 2 动态生成订阅的契约。
#### 测试与验证
##### 功能测试： 在一台干净的虚拟机上运行 install.sh。
- 验证所有服务是否正常运行：systemctl status nginx sing-box xray。
- 验证所有监听端口是否正常：netstat -tulnp。
- 验证客户端能成功连接所有 5 个协议。
##### 卸载测试：
- 运行 uninstall.sh 并验证所有文件和服务是否被完全清除。

### 模块 2 - edgeboxctl 管理工具
- 前置条件：模块 1 已完成并冻结“内核契约”。模块 2 的开发必须基于这些已定义的端口、文件路径和订阅格式。
- 目标：开发一个命令行工具，作为用户与核心服务进行交互的管理层，实现动态配置和模式切换。
#### 关键任务与交付物：
#### 命令行工具 (edgeboxctl)
- 使用 Shell 脚本（或 Python/Go）开发 edgeboxctl。
##### 模式切换： 实现 edgeboxctl config switch-mode。
**IP 模式 ⟶ 域名模式：**
- 获取 Let's Encrypt 证书。
- 更新 Nginx 和 Reality/Hysteria2 的配置，将 IP 监听改为域名监听，并将自签名证书软链到新证书。
**域名模式 ⟶ IP 模式：**
- 重新生成自签名证书。
- 更新配置，将域名监听改回 IP 监听，并将软链指回自签名证书。
##### 证书管理：
- edgeboxctl cert renew：手动触发 Certbot 证书续期。
- edgeboxctl cert upload：接受用户上传自定义证书，并将其软链到 CERT_DIR/current.pem 和 CERT_DIR/current.key。
##### 配置管理：
- edgeboxctl config regenerate-uuid：重置所有 UUID，并更新所有配置文件。
- edgeboxctl config show：显示所有关键配置信息（UUID、密码、端口等）。
#### 动态订阅生成
- 订阅 API： edgeboxctl sub 命令应根据当前模式（IP/域名）和配置，动态生成并显示订阅链接。这需要工具能够读取 xray.json 和 sing-box.json 配置。

### 模块 3 - 高级运维功能（可选）
- 前置条件：模块 1 和 2 已完成，并已建立稳定的内核和管理层。
- 目标：在现有框架之上，添加运维和高级功能，不影响核心服务的稳定性。
#### 关键任务与交付物：
### 出站分流：
- 流量路由： 增加 sing-box 的出站规则，将特定流量（如 googlevideo.com）直接路由，其余流量通过住宅代理出站。
- 配置管理： 在 edgeboxctl 中添加 edgeboxctl config switch-outbound 命令，用于切换分流模式。
### 流量统计：
- 数据收集： 使用 iptables 或 vnStat 收集流量数据。
- 命令行接口： 在 edgeboxctl 中添加 edgeboxctl traffic show 和 edgeboxctl traffic reset 命令，用于显示和重置流量计数。
### 自动备份/恢复：
- 备份脚本： 创建一个脚本，自动备份 /etc/edgebox/ 目录到 /root/edgebox-backup/。
- 定时任务： 配置 cron 任务，实现每日自动备份。
- 恢复命令： 在 edgeboxctl 中添加 edgeboxctl backup restore 命令，用于恢复备份。
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

---

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
