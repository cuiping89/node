### 5.管理工具 (`edgeboxctl`)

`edgeboxctl` 是用于管理 EdgeBox 的核心命令行工具，它提供了丰富的功能，涵盖了从日常系统维护到高级配置的所有操作，支持订阅打印、系统维护、证书管理、模式切换、分流管理、流量统计、备份恢复等。

#### 基础操作

这些是日常使用中最高频的命令，用于管理核心服务的状态。
-   `edgeboxctl service status`：查看所有核心服务（nginx, xray, sing-box）的运行状态。
-   `edgeboxctl service restart`：安全地重启所有服务，通常在修改配置后使用。
-   `edgeboxctl sub`：动态生成并显示当前模式下的订阅链接。
-   `edgeboxctl logs <svc>`：查看指定服务的实时日志（例如 `nginx` 或 `xray`）。

#### 模式与证书管理

这些命令用于在 IP 模式和域名模式之间切换，并管理 TLS 证书。
-   `edgeboxctl change-to-domain <your_domain>`：切换到域名模式，并自动申请 Let's Encrypt 证书。
-   `edgeboxctl change-to-ip`：回退到 IP 模式，使用自签名证书。
-   `edgeboxctl cert status`：检查当前证书的到期日期和类型。
-   `edgeboxctl cert renew`：手动续期 Let's Encrypt 证书。

#### 出站分流

用于配置和管理流量的分流策略。
-   `edgeboxctl shunt mode vps`：切换至 **VPS** 全量直出模式。
-   `edgeboxctl shunt mode resi <URL>`：配置并切换至 **住宅 IP** 全量出站模式。
-   `edgeboxctl shunt mode direct-resi <URL>`：配置并切换至 **白名单智能分流** 模式。
-   `edgeboxctl shunt whitelist <add|remove|list>`：管理白名单域名。
- 代理URL 支持：
- http://user:pass@<IP或域名>:<端口>
- https://user:pass@<IP或域名>:<端口>?sni=<SNI>
- socks5://user:pass@<IP或域名>:<端口>
- socks5s://user:pass@<域名>:<端口>?sni=<SNI>
- 示例：edgeboxctl shunt resi 'socks5://14aa42d05fc94:5069856762@111.222.333.444:11324 # 全栈走住宅

#### 流量统计与预警

这些命令用于监控流量使用情况和设置预警通知。

* `edgeboxctl traffic show`: 在终端中查看流量统计数据。
* `edgeboxctl traffic reset`: 重置流量计数器。
* `edgeboxctl alert <command>`: 管理流量预警设置。
    * `edgeboxctl alert monthly <GiB>`: 设置月度流量阈值。
    * `edgeboxctl alert steps 30,60,90`: 设置预警百分比。
    * `edgeboxctl alert telegram <bot_token> <chat_id>`: 配置 Telegram 机器人通知。
    * `edgeboxctl alert discord <webhook_url>`: 配置 Discord Webhook 通知。
    * `edgeboxctl alert wechat <pushplus_token>`: 配置 Pushplus 微信通知。
    * `edgeboxctl alert webhook <url> [raw|slack|discord]`: 配置通用 Webhook 通知。
    * `edgeboxctl alert test <percent>`: 测试预警通知功能。

#### 配置管理

用于管理核心配置，如 UUID 或查看当前配置。
-   `edgeboxctl config show`：显示所有服务的核心配置信息，例如 UUID、Reality 密钥等。
-   `edgeboxctl config regenerate-uuid`：为所有协议重新生成新的 UUID。
-   `edgeboxctl test`：测试所有协议的连接是否正常。
-   `edgeboxctl debug-ports`：调试关键端口的监听状态。
 
#### 系统维护

用于系统的更新、备份与恢复。
-   `edgeboxctl update`：自动更新 EdgeBox 脚本和核心组件。
-   `edgeboxctl backup create`：手动创建一个系统备份。
-   `edgeboxctl backup list`：列出所有可用的备份。
-   `edgeboxctl backup restore <DATE>`：恢复到指定日期的备份状态。


---

## 动态生成订阅链接

**`edgeboxctl sub`** 是获取订阅链接的核心命令，它根据 EdgeBox 当前的运行模式，动态生成一个聚合了所有协议的一键导入链接。

### 技术原理

`edgeboxctl sub` 脚本通过检查 `/etc/letsencrypt/` 目录中是否存在 Let's Encrypt 证书来判断当前是**IP 模式**还是**域名模式**，并据此调整链接中的关键参数。

* **IP 模式下的链接生成**
    * `address`: 使用服务器的**公网 IP**。
    * **VLESS-gRPC/WS/Trojan-TLS**: SNI 使用占位符（如 `grpc.edgebox.local` / `trojan.edgebox.internal`），并添加 `allowInsecure=1` 参数，以跳过自签名证书验证。
    * **Hysteria2/TUIC**: 添加 `insecure=true` 或 `skip-cert-verify=true` 参数，以跳过自签名证书验证。

* **域名模式下的链接生成**
    * `address`: 使用你的**真实域名**。
    * **VLESS-gRPC/WS/Trojan-TLS**: SNI 使用你的真实域名，并移除 `allowInsecure=1` 参数。
    * **Hysteria2/TUIC**: 移除 `insecure=true` 或 `skip-cert-verify=true` 参数。

### 链接聚合与输出

脚本将所有协议的链接聚合，进行 **Base64 编码**后，直接在终端中**打印出来**，或者保存到本地文件，供客户端方便地导入使用。


