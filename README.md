# EdgeBox：一站式多协议节点部署工具

- EdgeBox 是一个多协议一键部署脚本，旨在提供一个**健壮灵活、一键部署、幂等卸载**的科学上网解决方案。
- 功能齐全：**协议矩阵+出口分流+流量统计+聚合订阅+自动备份**。

- 🚀 **一键安装**：自动化部署
- 🗑️ **完全卸载**：一键清理所有组件，为安装失败后重装准备环境，简洁、高效、幂等、非交互式，适合自动化和故障排除。
- 🔄 **出口分流**：googlevideo.com直出；其它从住宅HTTP出
- 📊 **流量统计**：内置 vnStat + iptables 流量监控
- 🔗 **聚合订阅**：自动生成多协议订阅链接
- 💾 **自动备份**：每日备份配置，支持一键恢复

## 软件要求：
- 系统软件：Ubuntu 18.04+； Debian 10+
- 依赖软件：安装脚本会自动检测并安装curl, wget, unzip, tar, nginx, certbot, vnstat, iftop。

## 硬件要求：
- CPU: 1 核
- 内存: 512MB（内存不足自动创建s2G swap补足）
- 存储: 10GB 可用空间
- 网络: 稳定的公网 IP

## 核心组件
- **Nginx**: 前置代理，TLS终止，SNI分流
- **Xray**: VLESS-gRPC + VLESS-WS
- **sing-box**: Reality + Hysteria2 + TUIC
  
## 证书管理
```bash
# 自动化流程
域名配置 → DNS解析检查 → Let's Encrypt申请 → 自动续期
    ↓
未配置域名 → 自签名证书 → 基础功能可用
```
- **自动续期**: ACME 证书配置 cron 任务自动续期
-   在尝试申请 Let's Encrypt 证书之前，增加对 80 端口的防火墙放行检查。certbot 的 certonly --nginx 模式需要通过 80 端口验证域名所有权。如果 80 端口被 UFW 阻止，申请就会失败。对 certbot 的输出进行更详细的捕获和解析，而不仅仅是 2>/dev/null。这样在安装失败时，日志中能给出更明确的失败原因。在证书申请失败后，增加一个明确的警告或提示，告知用户证书申请失败的原因，例如“域名解析未生效”、“防火墙端口未开放”等。
 
## 核心策略
 **多协议组合、深度伪装、灵活路由** 来应对复杂多变的网络环境。

### 协议矩阵
- 默认安装：VLESS-gRPC、VLESS-WS、VLESS-Reality、Hysteria2、TUIC。
- 通过多层次的伪装来模拟正常的互联网流量，有效对抗审查和探测，适用不同场景，客户端可以无缝切换协议，确保连接的高可用性。
  
| 协议 | 传输特征 | 伪装效果 | 适用场景 |
|------|----------|----------|----------|
| **VLESS-gRPC** | HTTP/2 多路复用 | 极佳，类似正常网页请求 | 网络审查严格的环境 |
| **VLESS-WS** | WebSocket 长连接 | 良好，模拟实时通信 | 一般网络环境，稳定性佳 |
| **VLESS-Reality** | 真实 TLS 握手 | 极佳，几乎无法识别 | 最严格的网络环境 |
| **Hysteria2** | QUIC/UDP 快速传输 | 良好，HTTP/3 伪装 | 需要高速传输的场景 |
| **TUIC** | 轻量 QUIC 协议 | 中等，UDP 流量特征 | 移动网络和不稳定连接 |

### 行为伪装
- **VLESS-Reality**: 通过伪装 TLS 指纹，让流量看起来像是在访问真实热门网站
- **Hysteria2**: 伪装成 HTTP/3 流量，利用 QUIC 协议的特性
- **TUIC**: 基于 QUIC 的轻量级协议，具有较好的抗检测能力

### 端口伪装
- **TCP协议443**: 使用 HTTPS标准端口，使流量看起来像在正常浏览网页；**UDP协议443/2053**: 分散在常用端口，降低识别风险。
- **GCP防火墙**：保留开放tcp/443、udp/443、udp/2053；建议关闭tcp/8443（当前方案用不到），以及其它所有未列出的端口。

#### 1.端口分配策略（对外固定不变）
- 本方案旨在通过**单端口复用**和**内部回环**的方式，实现多个协议在同一台服务器上高效、安全地运行。
  ##### 对外开放端口（固定不变）
- TCP/443：单口汇聚
- Reality (XTLS/Vision)：作为 主协议 直连入口，不经过 Nginx
- 精准回落：当流量不匹配 Reality 协议时，将流量精确回落至内部的 Nginx Stream。
- UDP/443：Hysteria2
- UDP/2053：TUIC
  ##### 不对外开放端口（仅本机回环）
- TCP/8443, 10085, 10086, 10443：这些端口仅用于内部组件通信，不对公网开放。。

#### 2.内部链路与流量分发
- 所有流量都会在服务器内部进行处理和分发，确保链路的稳定性和隔离性。
  ##### Nginx Stream (监听 127.0.0.1:10443)
 - 作为回落链路的入口，它只做 TLS 预读（ssl_preread）。
 - 根据客户端的 ALPN（应用层协议协商） 值进行分流：
  - ALPN = h2：将流量转发到 127.0.0.1:10085，用于处理 VLESS-gRPC 协议。
  - 其余 ALPN（含 http/1.1）：将流量转发到 127.0.0.1:10086，用于处理 VLESS-WS 协议。
  ##### Xray 后端
 - 127.0.0.1:10085：运行 VLESS-gRPC，开启 TLS。
 - 127.0.0.1:10086：运行 VLESS-WS，开启 TLS。
  ##### sing-box 后端
 - udp/443：运行 Hysteria2 协议。
 - udp/2053：运行 TUIC 协议。

#### 3.伪装目标：
  - www.cloudflare.com（默认，全球可用）
  - www.microsoft.com（Windows更新流量）
  - www.apple.com（iOS更新流量）

## 灵活路由

### 分流策略
  - **直连白名单**：节省住宅IP代理流量并提升观看体验。
  - `googlevideo.com`（YouTube 视频流）
  - `ytimg.com`（YouTube 图片）
  - `ggpht.com`（Google 图片）
  - **代理出站**：其它流量通过住宅代理IP，稳定账号画像。
### GCP网络优化：
  - CF灰云、
  - 不走Argo、
  - 不让任何代理回源、
  - 不在服务器启用WARP/Zero Trust网关
  - **否则会连接CF边缘导致公网出站，触发GCP计费。确保200GB内标准计费**

## 流量统计
- 实时流量监控：edgeboxctl traffic show
- 显示内容：
- vnStat 系统流量
- 各协议端口流量
- iptables/nftables 计数
- 实时连接状态

## 备份恢复

### 自动备份
- **备份内容**：配置文件、证书、用户数据
- **备份路径**：`/root/edgebox-backup/`
- **保留策略**：最近15天
- **执行时间**：每日凌晨3点
### 手动操作
```bash
# 列出备份：edgeboxctl backup list
# 创建备份：edgeboxctl backup create
# 恢复备份：edgeboxctl backup restore 2024-01-15
```

## 一键安装（完全卸载+无损重装+出口分流+流量统计+聚合订阅+自动备份）
服务器上执行以下命令即可开始：
```bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/node/refs/heads/main/ENV/install.sh)
```

## 🔧 安装流程

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

## 📱 订阅链接

```# 浏览器方式：http://your-domain:8080/sub
```bash
```# SSH方式：edgeboxctl config show-sub
```bash

## 🛠️ 管理操作

### edgeboxctl 命令集
```bash
# 配置管理
edgeboxctl config show          # 显示当前配置
edgeboxctl config show-sub      # 显示订阅链接
edgeboxctl config backup        # 备份配置
edgeboxctl config restore       # 恢复配置

# 服务管理
edgeboxctl service status       # 服务状态
edgeboxctl service restart      # 重启服务
edgeboxctl service logs         # 查看日志

# 流量统计
edgeboxctl traffic show         # 显示流量统计
edgeboxctl traffic reset        # 重置流量计数

# 证书管理
edgeboxctl cert status          # 证书状态
edgeboxctl cert renew           # 手动续期
edgeboxctl cert upload          # 上传自定义证书

# 系统管理
edgeboxctl update               # 更新EdgeBox
edgeboxctl reinstall            # 重新安装
edgeboxctl uninstall            # 完全卸载
```

## 🔒 安全建议

### 客户端配置
- ✅ 启用"绕过大陆"分流规则
- ✅ 配合VPS白名单直出策略
- ✅ 定期更换伪装域名
### 服务端维护
- 🔄 定期系统更新：`apt update && apt upgrade`
- 📊 监控异常流量：`edgeboxctl traffic show`
- 🔑 适时轮换UUID：`edgeboxctl config regenerate-uuid`

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


## 📈 社区特色

- 👥 **安装友好**：详细文档、一键安装、内置卸载
- 🛡️ **健壮灵活**：内置防扫描、异常检测、自动防护
- 🎯 **GCP优化**：针对GCP网络计费、性能特性优化
- 📊 **智能运维**：流量统计、故障自愈、自动备份

---

## 📄 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## ⭐ 支持项目

如果这个项目对您有帮助，请给个 Star ⭐

