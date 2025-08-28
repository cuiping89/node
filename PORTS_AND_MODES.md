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
