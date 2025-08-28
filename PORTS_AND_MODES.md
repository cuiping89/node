# EdgeBox：一站式多协议节点部署方案文档

EdgeBox 是一个多协议一键部署脚本，旨在提供一个**健壮灵活、一键部署、幂等卸载**的科学上网解决方案。

- **功能齐全**：协议矩阵 + 出站分流 + 流量统计 + 聚合订阅 + 自动备份。

## 功能总览

| 功能           | 描述                                                                 |
|----------------|----------------------------------------------------------------------|
| 🚀 **一键安装**     | 自动化部署，支持非交互式安装，开箱即用。                                    |
| 🗑️ **完全卸载**     | 一键清理所有组件，为故障排除和重装准备环境。                                  |
| 🔄 **出口分流**     | `googlevideo.com` 等白名单直出，其余流量走住宅IP。                           |
| 📊 **流量统计**     | 内置 `vnStat` 和 `iptables` 监控，支持实时查看。                             |
| 🔗 **聚合订阅**     | 自动生成多协议订阅链接，支持一键导入。                                      |
| 💾 **自动备份**     | 每日备份配置，支持一键恢复。                                                |

## 核心组件

| 组件         | 功能                                       |
|--------------|--------------------------------------------|
| **Nginx**    | 前置代理，处理 TLS 终止和 SNI 分流。         |
| **Xray**     | 承载 VLESS-gRPC 和 VLESS-WS 协议。           |
| **sing-box** | 承载 Reality、Hysteria2 和 TUIC 协议。        |

## 系统与硬件要求

- **系统**：Ubuntu 18.04+ 或 Debian 10+。
- **软件依赖**：脚本自动安装 `curl`, `wget`, `unzip`, `tar`, `nginx`, `certbot`, `vnstat`, `iftop` 等。
- **硬件**：CPU 1 核，内存 512MB（内存不足自动创建 2GB Swap），存储 10GB 可用空间。
- **网络**：稳定的公网 IP。

---

## 核心策略

EdgeBox 采用**多协议组合、深度伪装、灵活路由**来应对复杂多变的网络环境。

### 协议矩阵

默认安装包含所有五种协议，通过多层次伪装模拟正常的互联网流量，有效对抗审查和探测，确保连接高可用。

| 协议              | 传输特征           | 伪装效果           | 适用场景               |
|-------------------|--------------------|--------------------|------------------------|
| **VLESS-Reality** | 真实 TLS 握手      | 极佳，几乎无法识别 | 最严格的网络环境         |
| **VLESS-gRPC**    | HTTP/2 多路复用     | 极佳，模拟网页请求 | 网络审查严格环境         |
| **VLESS-WS**      | WebSocket 长连接    | 良好，模拟实时通信 | 一般网络环境，稳定性佳   |
| **Hysteria2**     | QUIC/UDP 快速传输   | 良好，HTTP/3 伪装 | 需要高速传输的场景       |
| **TUIC**          | 轻量 QUIC 协议      | 中等，UDP 流量特征 | 移动网络和不稳定连接     |

### 端口伪装

本方案通过**单端口复用**和**内部回环**，将所有 HTTPS/QUIC 流量聚合到少数常用端口，最大化伪装效果。

**对外开放端口（GCP 防火墙配置）：**

- **TCP/443**：所有基于 TCP 的加密协议单口汇聚，模拟 HTTPS 流量
- **UDP/443**：Hysteria2 协议专用
- **UDP/2053**：TUIC 协议专用
- **重要提示**：GCP 防火墙仅开放以上端口，关闭其他未列端口（如 TCP/8443）

**不对外开放端口（仅本机回环）：**

- **TCP/8443, 10085, 10086, 10443**：仅用于内部组件通信，绝不暴露给公网

### 内部链路与流量分发

1. **流量入口**
    - 所有 **TCP/443** 流量先由 **Xray Reality** 处理。
    - **Reality (XTLS/Vision)**：主协议，流量匹配直接处理。
    - **精准回落（Fallbacks）**：不匹配流量回落到内部 Nginx Stream。

2. **Nginx Stream (监听 127.0.0.1:10443)**
    - 仅进行 TLS 预读（`ssl_preread`），不处理完整 TLS 握手。
    - 根据 **ALPN** 分流：
        - `ALPN = h2`：转发至 127.0.0.1:10085 (VLESS-gRPC)
        - 其他 ALPN（含 http/1.1）：转发至 127.0.0.1:10086 (VLESS-WS)

3. **后端服务**
    - **Xray**：在 10085 和 10086 运行 VLESS-gRPC 和 VLESS-WS
    - **sing-box**：在 udp/443 和 udp/2053 运行 Hysteria2 和 TUIC

---

## 部署与模式切换

本方案的关键在于 `edgeboxctl` 管理工具，支持两种模式无缝切换。

### A. 初始安装（无域名/IP 模式）

- 默认非交互模式，适用于无域名、无住宅 IP 环境。所有协议立即可用，部分协议使用自签名证书。
    - **Reality**：启用，`server_name` 伪装为 `www.cloudflare.com`，常规生成密钥。
    - **VLESS-gRPC / VLESS-WS**：Xray 后端用自签名证书。Reality 入站配置设回落规则：流量 SNI 命中占位符（如 `grpc.edgebox.local`/`www.edgebox.local`）即回落。
    - **Hysteria2 / TUIC**：同样使用自签名证书启动。

### B. 模式双向切换

- **切换至域名模式：**
    - **命令**：`edgeboxctl change-to-domain <your_domain>`
    - 自动申请 Let's Encrypt 证书，替换所有协议自签名证书，更新 Nginx/Xray 配置。
- **回退至 IP 模式：**
    - **命令**：`edgeboxctl change-to-ip`
    - 禁用 Let's Encrypt 证书，恢复自签名证书，配置回退到初始 IP 模式。

### C. 动态生成订阅链接

- `edgeboxctl sub` 命令根据当前模式生成一键导入聚合链接。
    - **IP 模式**：`address` 字段为公网 IP，协议链接自动带上不安全参数。
    - **域名模式**：`address` 为真实域名，移除不安全参数。

---

## 出站分流策略

本模块独立，可双向切换，和域名/IP 切换完全解耦。

### 1. 策略目标

- **直连白名单**：指定域名（如 `googlevideo.com`）流量直连，节省住宅代理流量，流媒体体验佳。
- **住宅IP代理出站**：非白名单流量通过配置的静态住宅代理 IP 出站，保持账号地域画像稳定。

### 2. 模式与状态

分流模块独立，状态由 `SHUNT_MODE` 控制，与域名/IP 模式解耦。

- **默认模式：VPS 直出（`SHUNT_MODE=direct`）**
    - 所有流量通过 VPS 服务器直接出站，零配置，开箱即用。
- **可选模式：住宅代理出站（`SHUNT_MODE=resi`）**
    - 除白名单流量外，全部通过住宅代理 IP 出站，适合需要稳定出口IP的场景。
    - 默认白名单：`googlevideo.com`, `ytimg.com`, `ggpht.com`（可编辑）

### 3. 管理工具实现（`edgeboxctl`）

- **启用住宅代理出站**：
    - **命令**：`edgeboxctl shunt apply <代理地址>`
    - 代理地址格式：
        - 不带认证：`<IP>:<端口>`，如 `192.0.2.1:8080`
        - 带认证：`<IP>:<端口>:<用户名>:<密码>`，如 `192.0.2.1:8080:user:pass`
    - 实现逻辑：
        1. 解析并保存代理信息
        2. 修改 sing-box/Xray 配置，添加指向代理的 outbound
        3. 添加分流路由，白名单直连，其余走代理
        4. 健康探活，确保代理可用
        5. 重启 sing-box 和 Xray

- **切换回 VPS 直出模式**：
    - **命令**：`edgeboxctl shunt clear`
    - 实现逻辑：
        1. 删除/清空代理配置
        2. 修改 sing-box/Xray 配置，删除代理出站和相关路由
        3. 默认直连 outbound 唯一或优先
        4. 重启 sing-box 和 Xray

---

## 运维与管理

### 1. 流量统计

- **命令**：`edgeboxctl traffic show`
- **显示内容**：`vnStat` 系统流量、各协议端口流量、`iptables/nftables` 计数

### 2. 备份与恢复

- **自动备份**：每日凌晨3点自动备份配置、证书和用户数据到 `/root/edgebox-backup/`，保留最近15天
- **手动操作**：
    - `edgeboxctl backup list`：列出所有备份
    - `edgeboxctl backup create`：手动创建备份
    - `edgeboxctl backup restore <日期>`：恢复指定日期备份

### 3. 常用 `edgeboxctl` 命令集

```bash
# 配置管理
edgeboxctl config show             # 显示当前配置
edgeboxctl config show-sub         # 显示订阅链接
edgeboxctl config regenerate-uuid  # 重新生成 UUID

# 服务管理
edgeboxctl service status          # 服务状态
edgeboxctl service restart         # 重启服务
edgeboxctl service logs            # 查看日志

# 出站分流
edgeboxctl shunt apply             # 启用住宅代理分流
edgeboxctl shunt clear             # 切换回 VPS 直连

# 流量统计
edgeboxctl traffic show            # 显示流量统计
edgeboxctl traffic reset           # 重置流量计数

# 证书管理
edgeboxctl cert status             # 证书状态
edgeboxctl cert renew              # 手动续期
edgeboxctl cert upload             # 上传自定义证书

# 系统管理
edgeboxctl update                  # 更新 EdgeBox
edgeboxctl reinstall               # 重新安装
edgeboxctl uninstall               # 完全卸载
```


EdgeBox 多协议节点部署方案文档
1. 概述
本方案旨在实现一个功能强大、灵活且高度伪装的多协议代理节点。核心思想是通过 单端口复用 和 内部回环 技术，在保证性能的同时，最大限度地提高流量的伪装性。方案支持在无域名/IP 的“IP 模式”下即时可用，并提供管理工具 edgeboxctl 实现与有域名/IP 的“域名模式”之间的双向无缝切换。

2. 端口与协议分配策略
本方案遵循简洁高效的原则，将所有协议的流量聚合到少量常用端口，以降低识别风险。

对外开放端口（GCP 防火墙配置）

TCP/443：用于所有基于 TCP 的加密协议的单口汇聚。这是 HTTPS 标准端口，能使流量看起来像正常的网页浏览。

UDP/443：专用于 Hysteria2 协议。

UDP/2053：专用于 TUIC 协议。

不对外开放端口（仅本机回环）

TCP/8443, 10085, 10086, 10443：这些端口仅用于内部组件（如 Nginx, Xray）之间的通信，绝不暴露给公网。GCP 防火墙规则中应确保这些端口处于关闭状态。

3. 内部链路与流量分发
流量在进入服务器后，将由各组件在内部进行精密处理与分发。

流量入口

所有 TCP/443 流量首先由 Xray Reality 协议处理。

Reality (XTLS/Vision)：作为 主协议，如果流量匹配其特征，将直接由 Xray 处理。

精准回落（Fallbacks）：当流量不匹配 Reality 协议时，它将根据配置被精准地回落到内部的 Nginx Stream。

Nginx Stream (监听 127.0.0.1:10443)

作为回落链路的入口，它只进行 TLS 预读（ssl_preread），不处理完整的 TLS 握手。

根据客户端的 ALPN（应用层协议协商） 值进行分流：

ALPN = h2：转发到 127.0.0.1:10085，用于 VLESS-gRPC 协议。

其余 ALPN（含 http/1.1）：转发到 127.0.0.1:10086，用于 VLESS-WS 协议。

后端服务

Xray (监听 127.0.0.1:10085/10086)

127.0.0.1:10085：运行 VLESS-gRPC，并开启 TLS。

127.0.0.1:10086：运行 VLESS-WS，并开启 TLS。

sing-box

udp/443：运行 Hysteria2 协议。

udp/2053：运行 TUIC 协议。

伪装目标（Reality）

www.cloudflare.com（默认，全球可用）

www.microsoft.com（可选，模拟 Windows 更新）

www.apple.com（可选，模拟 iOS 更新）

4. 部署与模式切换策略
本方案的关键在于 edgeboxctl 管理工具，它能实现两种模式之间的无缝切换。

4.1 初始安装（非交互式 IP 模式）
安装脚本默认为非交互模式，专为无域名、无住宅 IP 的环境设计。安装后，所有五个协议均可立即工作，但部分协议使用自签名证书。

Reality：启用，server_name 伪装为 www.cloudflare.com，按常规生成密钥。

VLESS-gRPC / VLESS-WS：

Xray 后端使用 自签名证书。

Reality 入站配置中设置 回落规则（fallbacks），以实现无域名下的流量分发。

核心回落逻辑：当流量的 SNI 命中 占位符 (grpc.edgebox.local 或 www.edgebox.local) 且 ALPN 命中 h2 或 http/1.1 时，流量将被回落至 127.0.0.1:10443。

Hysteria2 / TUIC：

同样使用 自签名证书 启动。

4.2 模式双向切换（edgeboxctl 命令）
切换至域名模式：

命令：edgeboxctl change-to-domain <your_domain>

逻辑：工具将检查域名解析，自动申请 Let's Encrypt 证书，并用新证书替换所有协议的自签名证书。Nginx 和 Xray 的配置将被更新以使用真实域名。

回退至 IP 模式：

命令：edgeboxctl change-to-ip

逻辑：当域名或住宅 IP 失效时，此命令将删除或禁用 Let's Encrypt 证书，重新生成并启用自签名证书，并将所有配置回退到初始 IP 模式。

5. 动态生成订阅链接
edgeboxctl sub 命令必须能够根据当前模式动态生成一键导入的聚合链接。

逻辑判断：脚本通过检查 /etc/letsencrypt/ 目录下是否存在证书来判断当前模式。

IP 模式下的链接生成：

address：使用服务器的公网 IP。

VLESS-gRPC/WS：SNI 使用 占位符 (grpc.edgebox.local/www.edgebox.local)，并添加 allowInsecure=1 参数。

Hysteria2/TUIC：添加 insecure=true 或 skip-cert-verify=true 参数。

域名模式下的链接生成：

address：使用你的真实域名。

VLESS-gRPC/WS：SNI 使用你的真实域名，移除 allowInsecure=1 参数。

Hysteria2/TUIC：移除 insecure=true 或 skip-cert-verify=true 参数。

聚合：将所有协议的链接聚合，进行 Base64 编码，并提供一个 HTTP 订阅链接，供客户端一键导入。
