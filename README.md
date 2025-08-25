# EdgeBox：一站式多协议节点部署工具

- EdgeBox 是一个用于自动化部署和多种主流代理协议组合的脚本，旨在提供一个**健壮、易于部署、易于维护**的科学上网节点解决方案。
- 支持在 Debian 和 Ubuntu 系统上**一键安装、幂等更新、按需管理**，并自动生成**聚合订阅**链接。

## 软件要求：
- 系统软件：Ubuntu 18.04+； Debian 10+
- 依赖软件：安装脚本会自动检测并安装curl, wget, unzip, tar, nginx, certbot, vnstat, iftop。

## 硬件要求：
- CPU: 1 核
- 内存: 512MB（内存不足自动创建s2G swap补足）
- 存储: 10GB 可用空间
- 网络: 稳定的公网 IP

## 核心理念与策略
 **多协议组合、深度伪装、灵活路由** 来应对复杂多变的网络环境。


**协议矩阵**
- 默认安装：VLESS-gRPC、VLESS-WS、VLESS-Reality、Hysteria2、TUIC。
- 通过多层次的伪装来模拟正常的互联网流量，有效对抗审查和探测，适用不同场景，客户端可以无缝切换协议，确保连接的高可用性。
  
| 协议 | 传输特征 | 伪装效果 | 适用场景 |
|------|----------|----------|----------|
| **VLESS-gRPC** | HTTP/2 多路复用 | 极佳，类似正常网页请求 | 网络审查严格的环境 |
| **VLESS-WS** | WebSocket 长连接 | 良好，模拟实时通信 | 一般网络环境，稳定性佳 |
| **VLESS-Reality** | 真实 TLS 握手 | 极佳，几乎无法识别 | 最严格的网络环境 |
| **Hysteria2** | QUIC/UDP 快速传输 | 良好，HTTP/3 伪装 | 需要高速传输的场景 |
| **TUIC** | 轻量 QUIC 协议 | 中等，UDP 流量特征 | 移动网络和不稳定连接 |

**行为伪装**：
- **VLESS-Reality**: 通过伪装 TLS 指纹，让流量看起来像是在访问真实热门网站
- **Hysteria2**: 伪装成 HTTP/3 流量，利用 QUIC 协议的特性
- **TUIC**: 基于 QUIC 的轻量级协议，具有较好的抗检测能力

**伪装目标网站**：
- www.cloudflare.com（默认，全球可用）
- www.microsoft.com（Windows 更新流量）
- www.apple.com（iOS 更新流量）
- www.ubuntu.com（软件包更新）

**端口伪装**：
- **TCP 协议（443/8443）**: 使用 HTTPS 标准端口，使流量看起来像在正常浏览网页
- **UDP 协议（443/8443/2053）**: 分散在常用端口，降低识别风险
- **端口分配策略**：
**gRPC/WebSocket (TCP)**
- Xray 作为应用层服务
- Nginx 提供 TLS/HTTP2 反向代理
- gRPC: 127.0.0.1:10085
- WebSocket: 127.0.0.1:10086
- 外部端口策略：
  - 启用 Reality 时：Nginx 监听 **8443** 端口
  - 未启用 Reality 时：Nginx 监听 **443** 端口
**Reality (TCP)**
- sing-box 直接绑定 **tcp/443** 端口
- 默认 SNI: www.cloudflare.com（推荐伪装目标）
- 可自定义伪装域名
**Hysteria2 (UDP)**
- sing-box 监听 **udp/443** 端口（可改为 8443）
- 使用自签证书 + alpn=h3
- 伪装成 HTTP/3 流量
**TUIC (UDP)**
- sing-box 监听 **udp/2053** 端口
- 复用 Hysteria2 的证书配置

## 灵活路由
**分流策略**：
- 直连 `googlevideo.com` (YouTube 视频流，CDN 流量)、`ytimg.com` (YouTube 图片) 、`ggpht.com` (Google 图片)，节省住宅IP代理流量并提升观看体验。
- 其它全从住宅代理IP出站。
**CF灰云、路由不回源**：
- 不走Argo、不让任何代理回源、不在服务器启用WARP/Zero Trust网关，否则会连接CF边缘导致公网出站，触发GCP计费。

## 核心组件
-**Nginx**: 作为前置代理，将所有 443 端口的 TCP 流量分发到后端服务。通过 HTTP(S) 反向代理 VLESS-gRPC 和 VLESS-WS，并通过 `stream` 模块实现基于 SNI 的 VLESS-Reality 流量分流。
-**Xray & sing-box**: 脚本将通过官方安装脚本，安装 **Xray 和 sing-box 的最新相互兼容版本**。Xray 负责 VLESS-gRPC 和 VLESS-WS，而 sing-box 则承载 Reality、Hysteria2 和 TUIC。

## 证书管理
**自动化证书处理**：
- **优先方案**: 填写域名时自动通过 ACME（Let's Encrypt）申请真实证书
- **兜底方案**: 未填写域名时自动生成自签名证书
- **自定义上传**: 支持用户后期上传自定义证书
- **自动续期**: ACME 证书配置 cron 任务自动续期
   在尝试申请 Let's Encrypt 证书之前，增加对 80 端口的防火墙放行检查。certbot 的 certonly --nginx 模式需要通过 80 端口验证域名所有权。如果 80 端口被 UFW 阻止，申请就会失败。对 certbot 的输出进行更详细的捕获和解析，而不仅仅是 2>/dev/null。这样在安装失败时，日志中能给出更明确的失败原因。在证书申请失败后，增加一个明确的警告或提示，告知用户证书申请失败的原因，例如“域名解析未生效”、“防火墙端口未开放”等。
  
## 流量统计：

## 网络优化

## 安全增强

**每日自动备份**：
- 备份配置文件、证书、用户数据
- 保留最近 15 天的备份
- 备份路径：`/root/edgebox-backup/`
- 支持手动触发：`edgeboxctl backup create`
**备份恢复**：
```bash
# 列出可用备份：edgeboxctl backup list
# 恢复指定日期备份：edgeboxctl backup restore <YYYY-MM-DD>
```

## 交互式引导：

**系统预检查** 
安装前脚本会自动检查：
- 操作系统版本兼容性
- 网络连通性（DNS 解析、外网访问）
- 防火墙状态和端口占用
- 系统资源（内存、磁盘空间）

**域名与证书配置**
- 询问是否配置域名
- 域名验证和 DNS 解析检查
- 自动申请 Let's Encrypt 证书
- 证书安装和配置验证

**出站分流策略**
- 询问是否设置住宅 HTTP 代理，输入格式：`HOST:PORT:USER:PASS`
- 回车默认策略：**全直出**（跳过代理配置时）

**安装失败处理**：
- 自动检测失败原因
- 提供详细错误日志
- 支持一键回滚到安装前状态
- 清理临时文件和配置


## 一键安装
服务器上执行以下命令即可开始：
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<你的GitHub>/EdgeBox/main/install.sh)
```
## 一键卸载
简洁、高效、幂等、非交互式，适合自动化和故障排除，安装失败后的清理工具。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/EdgeBox/main/uninstall.sh)
```
## 分享建议：
- **技术小白朋友**：单个稳定协议（VLESS-Reality）
- **技术用户**：聚合订阅链接（包含所有协议，自动切换）
- **家人使用**：VLESS-WebSocket（最稳定，兼容性最好）
- **移动设备**：TUIC 协议（对不稳定网络友好）

**获取订阅链接**
- SSH 方式：显示所有订阅链接：edgeboxctl config show-sub
- 浏览器方式：访问 http://your-domain:8080/sub

## 客户端配置示例
- V2rayN (Windows)

## 安全建议

**客户端配置**
- 启用"绕过大陆"分流规则
- 配合 VPS 白名单直出策略
- 定期更换伪装域名

**服务端维护**
- 定期更新系统和软件包
- 监控异常连接和流量
- 适时轮换用户 UUID

## 常见问题解答

**Q: 连接失败，显示 -1ms？**
A: 检查端口是否正确开放，确认防火墙规则，验证证书配置。

**Q: Reality 协议无法连接？**
A: 确认伪装域名可正常访问，检查 SNI 配置是否正确。

**Q: 如何选择最适合的协议？**
A: 网络审查严格时优先 Reality > gRPC > WS；需要高速时选择 Hysteria2；移动网络推荐 TUIC。

**Q: GCP 会因为使用 gRPC 协议切换到高级网络吗？**
A: **绝对不会**！GCP 的网络层级是在 VM 实例创建时设置的，与运行的应用协议完全无关。gRPC 本质是 HTTP/2，使用标准 TCP/443 端口，只要您的 VM 设置为"标准网络层级"，200GB 内的出站流量都是标准计费，不会因为协议类型改变。

## 特别提示

**系统兼容性**: 脚本主要兼容 Debian 和 Ubuntu，它们占据了绝大多数服务器市场份额。兼容其他 Linux 发行版技术上可行，但会显著增加复杂性，因此目前并非首要目标。

**订阅链接分享**: 如需分享给朋友，**优先推荐聚合订阅链接**，它包含所有协议，提供最佳的便利性和高可用性。

**隐私保护**: 建议配置"绕过大陆"规则，结合 VPS 白名单直出策略，最大程度保障隐私和 VPS IP 安全。

## 社区定位
- 👥 **安装友好**：详细文档、一键安装、内置卸载
- 🛡️ **健壮灵活**：内置防扫描、异常检测、自动防护
- 🎯 **GCP用户专属**：针对GCP网络计费、性能特性优化
- 📊 **智能运维**：流量统计、故障自愈

- 
