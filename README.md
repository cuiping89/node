# EdgeBox：一站式多协议节点部署工具

- EdgeBox 是一个用于自动化部署和多种主流代理协议组合的脚本，旨在提供一个**健壮、易于部署、易于维护**的科学上网节点解决方案。
- 支持在 Debian 和 Ubuntu 系统上**一键安装、幂等更新、按需管理**，并自动生成**聚合订阅**链接。

## 软件要求：
- 系统软件：Ubuntu 18.04+； Debian 10+
- 依赖软件：安装脚本会自动检测并安装curl, wget, unzip, tar, nginx, certbot, vnstat, iftop。

## 最低硬件要求：
- CPU: 1 核
- 内存: 512MB（不足时自动创建 swap 虚拟内存补足）
- 存储: 10GB 可用空间
- 网络: 稳定的公网 IP

## 核心理念与策略
- **“多协议组合、深度伪装、灵活路由”** 来应对复杂多变的网络环境。

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

### 灵活路由与安全分流
节点能够根据您的需求，智能地分配流量，以平衡安全性、速度和成本。

**CF灰云、路由不回源**
不走Argo、不让任何代理回源、不在服务器启用WARP/Zero Trust网关，否则会连接CF边缘导致公网出站，触发GCP计费。

## 技术架构与协议组合

EdgeBox 采用以下技术组合，实现了多协议的完美共存：

### 核心组件

**Nginx**: 作为前置代理，将所有 443 端口的 TCP 流量分发到后端服务。通过 HTTP(S) 反向代理 VLESS-gRPC 和 VLESS-WS，并通过 `stream` 模块实现基于 SNI 的 VLESS-Reality 流量分流。

**Xray & sing-box**: 脚本将通过官方安装脚本，安装 **Xray 和 sing-box 的最新相互兼容版本**。Xray 负责 VLESS-gRPC 和 VLESS-WS，而 sing-box 则承载 Reality、Hysteria2 和 TUIC。

### 证书管理

**自动化证书处理**：
- **优先方案**: 填写域名时自动通过 ACME（Let's Encrypt）申请真实证书
- **兜底方案**: 未填写域名时自动生成自签名证书
- **自定义上传**: 支持用户后期上传自定义证书
- **自动续期**: ACME 证书配置 cron 任务自动续期

**推荐伪装目标网站**：
- www.cloudflare.com（默认，全球可用）
- www.microsoft.com（Windows 更新流量）
- www.apple.com（iOS 更新流量）
- www.ubuntu.com（软件包更新）

## 部署与管理

### 系统预检查

安装前脚本会自动检查：
- 操作系统版本兼容性
- 网络连通性（DNS 解析、外网访问）
- 防火墙状态和端口占用
- 系统资源（内存、磁盘空间）
- **内存不足处理**：自动创建 2GB swap 虚拟内存
- **依赖软件安装**：自动安装 curl、wget、nginx、certbot、vnstat 等必需组件

### 一键安装

只需在您的 Debian/Ubuntu 服务器上执行以下命令即可开始：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<你的GitHub>/EdgeBox/main/install.sh)
```

脚本将进行**交互式引导**，完成所有配置：

**域名与证书配置**
- 询问是否配置域名
- 域名验证和 DNS 解析检查
- 自动申请 Let's Encrypt 证书
- 证书安装和配置验证

**出站分流策略**
- 询问是否设置住宅 HTTP 代理
- 提示输入格式：`HOST:PORT:USER:PASS`
- 默认策略：**全直出**（跳过代理配置时）

**视频流分流优化**
- 默认配置路由规则，将以下域名设置为**直连**：
  - `googlevideo.com` (YouTube 视频流，CDN 流量)
  - `ytimg.com` (YouTube 图片)  
  - `ggpht.com` (Google 图片)
  - ⚠️ **注意**：`netflix.com` 等风险较高的流媒体域名**不建议直连**，会暴露真实 IP 给平台，影响账号安全
- 节省代理流量并提升观看体验

### 安装完成验证

安装成功后，脚本会自动执行：
- 服务状态检查
- 端口监听验证
- 证书有效性检查
- 生成聚合订阅链接
- 输出客户端配置示例

### 错误处理与回滚

**安装失败处理**：
- 自动检测失败原因
- 提供详细错误日志
- 支持一键回滚到安装前状态
- 清理临时文件和配置

**常见错误码**：
- `ERROR_001`: 系统不支持
- `ERROR_002`: 网络连接失败
- `ERROR_003`: 端口被占用
- `ERROR_004`: 证书申请失败
- `ERROR_005`: 服务启动失败

## 管理功能

### edgeboxctl 管理命令

安装完成后，脚本将自动部署管理工具 `edgeboxctl`：

**协议管理**
```bash
# 启用特定协议
edgeboxctl enable <protocol>  # gRPC|ws|reality|hy2|tuic

# 禁用特定协议
edgeboxctl disable <protocol>

# 查看所有协议状态
edgeboxctl status
```

**分流管理**
```bash
# 切换到全代理模式
edgeboxctl route proxy

# 切换到全直连模式
edgeboxctl route direct

# 查看当前路由策略
edgeboxctl route status
```

**配置管理**
```bash
# 修改域名配置
edgeboxctl config domain <new-domain>

# 更新伪装目标
edgeboxctl config reality-target <target-domain>

# 重新生成订阅链接
edgeboxctl config regenerate-sub

# 显示当前配置摘要
edgeboxctl config show
```

**用户管理**
```bash
# 添加用户
edgeboxctl user add <username>

# 删除用户
edgeboxctl user del <username>

# 列出所有用户
edgeboxctl user list

# 重置用户流量
edgeboxctl user reset <username>
```

**流量统计**
```bash
# 查看当月流量统计
edgeboxctl traffic monthly

# 查看近12个月历史流量
edgeboxctl traffic history --months 12

# 分协议流量统计
edgeboxctl traffic breakdown

# 设置月度流量预警（如 200GB）
edgeboxctl traffic alert 200GB

# 查看实时流量
edgeboxctl traffic realtime
```

**流媒体解锁检测**
```bash
# 检测流媒体解锁状态
edgeboxctl check netflix
edgeboxctl check youtube  
edgeboxctl check chatgpt
edgeboxctl check disney

# 一键检测所有平台
edgeboxctl check all
```

**网络优化**
```bash
# 启用 BBR 拥塞控制算法
edgeboxctl optimize bbr

# 优化 TCP 参数
edgeboxctl optimize tcp

# 网络速度测试
edgeboxctl speedtest

# 一键优化所有网络参数
edgeboxctl optimize all
```

**安全增强**
```bash
# 扫描异常连接
edgeboxctl security scan

# 封禁可疑 IP
edgeboxctl security block <ip>

# 查看安全报告
edgeboxctl security report

# 设置自动防护模式
edgeboxctl security autoprotect on
```

### 订阅链接获取与分享

**获取订阅链接**
```bash
# SSH 方式：显示所有订阅链接
edgeboxctl config show-sub

# 浏览器方式：访问 http://your-domain:8080/sub
# （可选开启简单 Web 面板）
```

**分享策略建议**
- **技术小白朋友**：单个稳定协议（VLESS-Reality）
- **技术用户**：聚合订阅链接（包含所有协议，自动切换）
- **家人使用**：VLESS-WebSocket（最稳定，兼容性最好）
- **移动设备**：TUIC 协议（对不稳定网络友好）

### 自动化备份

**每日自动备份**：
- 备份配置文件、证书、用户数据
- 保留最近 15 天的备份
- 备份路径：`/root/edgebox-backup/`
- 支持手动触发：`edgeboxctl backup create`

**备份恢复**：
```bash
# 列出可用备份
edgeboxctl backup list

# 恢复指定日期备份
edgeboxctl backup restore <YYYY-MM-DD>
```

## 一键卸载

如需完全移除 EdgeBox，执行以下命令：

```bash
# 下载并执行卸载脚本
bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/EdgeBox/main/uninstall.sh)

# 或使用管理工具卸载
edgeboxctl uninstall --purge
```

## 性能优化建议

**系统层面**
- 启用 BBR 拥塞控制算法
- 优化 TCP 参数
- 适当调整文件描述符限制

**应用层面**
- 根据网络环境选择合适的协议组合
- 合理配置并发连接数
- 定期清理日志文件

## 故障排除

### 常用排障命令

**端口检查**
```bash
# 检查端口占用情况
ss -lntup | egrep ':443|:8443|:2053'

# 检查防火墙规则
ufw status verbose
```

**服务状态**
```bash
# 查看所有相关服务状态
systemctl status xray sing-box nginx

# 查看 sing-box 详细日志
journalctl -u sing-box -f --no-pager -n 120

# 查看 xray 详细日志
journalctl -u xray -f --no-pager -n 120
```

**配置验证**
```bash
# 检查 Nginx 配置
nginx -t && systemctl reload nginx

# 验证 Xray 配置
xray run -test -config /usr/local/etc/xray/config.json

# 验证 sing-box 配置
sing-box check -c /usr/local/etc/sing-box/config.json
```

**证书问题**
```bash
# 检查证书有效期
openssl x509 -in /path/to/cert.crt -text -noout | grep -A2 "Validity"

# 手动续期证书
certbot renew --force-renewal

# 重新生成聚合订阅
edgeboxctl config regenerate-sub
```

### 常见问题解答

**Q: 连接失败，显示 -1ms？**
A: 检查端口是否正确开放，确认防火墙规则，验证证书配置。

**Q: Reality 协议无法连接？**
A: 确认伪装域名可正常访问，检查 SNI 配置是否正确。

**Q: 如何选择最适合的协议？**
A: 网络审查严格时优先 Reality > gRPC > WS；需要高速时选择 Hysteria2；移动网络推荐 TUIC。

**Q: GCP 会因为使用 gRPC 协议切换到高级网络吗？**
A: **绝对不会**！GCP 的网络层级是在 VM 实例创建时设置的，与运行的应用协议完全无关。gRPC 本质是 HTTP/2，使用标准 TCP/443 端口，只要您的 VM 设置为"标准网络层级"，200GB 内的出站流量都是标准计费，不会因为协议类型改变。

## 客户端配置示例

### V2rayN (Windows)
```json
{
  "v": "2",
  "ps": "EdgeBox-Reality",
  "add": "your-domain.com",
  "port": "443",
  "id": "your-uuid",
  "aid": "0",
  "net": "tcp",
  "type": "none",
  "host": "",
  "path": "",
  "tls": "reality",
  "sni": "www.cloudflare.com",
  "alpn": "",
  "fp": "chrome"
}
```

### Clash Meta
```yaml
proxies:
  - name: EdgeBox-Hysteria2
    type: hysteria2
    server: your-domain.com
    port: 443
    password: your-password
    alpn:
      - h3
    skip-cert-verify: true
```

## 安全建议

**客户端配置**
- 启用"绕过大陆"分流规则
- 配合 VPS 白名单直出策略
- 定期更换伪装域名

**服务端维护**
- 定期更新系统和软件包
- 监控异常连接和流量
- 适时轮换用户 UUID

### 与现有项目对比

**vs mack-a/v2ray-agent**
- ✅ 更精简实用：去除过时的 VMess、重复的 Trojan
- ✅ 端口策略更合理：统一标准端口，伪装效果更好  
- ✅ 管理更现代化：专业命令行工具 + 自动备份
- ❌ 社区成熟度：新项目，用户基数较小

**vs sing-box 四协议脚本**
- ✅ 架构更清晰：Nginx + Xray + sing-box 分工明确
- ✅ 功能更全面：流量统计、安全防护、性能优化
- ✅ 专为 GCP 优化：针对标准网络计费优化设计
- ❌ 复杂度稍高：功能丰富但学习成本增加

## 社区建设规划

**差异化定位**
- 🎯 **GCP 用户专属**：针对 GCP 网络计费和性能特性优化
- 🛡️ **企业级安全**：内置防扫描、异常检测、自动防护
- 📊 **智能运维**：流量统计、性能监控、故障自愈
- 👥 **用户友好**：详细文档、视频教程、社区支持

**网络安全**
- 不要在敏感网络环境下测试
- 避免大流量下载引起注意  
- 保持低调，不要分享过多细节
- 定期检查 VPS IP 是否被墙

## 特别提示

**系统兼容性**: 脚本主要兼容 Debian 和 Ubuntu，它们占据了绝大多数服务器市场份额。兼容其他 Linux 发行版技术上可行，但会显著增加复杂性，因此目前并非首要目标。

**订阅链接分享**: 如需分享给朋友，**优先推荐聚合订阅链接**，它包含所有协议，提供最佳的便利性和高可用性。

**隐私保护**: 建议配置"绕过大陆"规则，结合 VPS 白名单直出策略，最大程度保障隐私和 VPS IP 安全。

---

## 快速参考

### 安装命令
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<你的GitHub>/EdgeBox/main/install.sh)
```

### 常用管理命令
```bash
# 协议管理
edgeboxctl enable hy2
edgeboxctl disable reality
edgeboxctl status

# 路由切换
edgeboxctl route proxy
edgeboxctl route direct

# 服务重启
systemctl restart xray sing-box nginx

# 配置重载
edgeboxctl config regenerate-sub
```

### 紧急恢复
```bash
# 恢复最近备份
edgeboxctl backup restore

# 重置所有配置
edgeboxctl reset --confirm

# 完全卸载
edgeboxctl uninstall --purge
```

**支持与反馈**: 如遇问题，请查看 `/var/log/edgebox.log` 日志文件，或提交 GitHub Issue。
