EdgeBox：一站式多协议节点部署工具
EdgeBox 是一个用于自动化部署和管理多种主流代理协议的脚本，旨在提供一个健壮、灵活、易于维护的科学上网节点解决方案。它支持在 Debian 和 Ubuntu 系统上一键安装、幂等更新、按需管理，并自动生成聚合订阅链接。

核心理念与策略
一个真正强大的节点不依赖于单一协议，而是通过多协议组合、深度伪装和灵活路由来应对复杂多变的网络环境。EdgeBox 的设计正是基于此。

多协议组合与冗余：将 VLESS-gRPC、VLESS-WS、VLESS-Reality、Hysteria2 和 TUIC 集于一身。当一个协议因网络环境不佳或被封锁而失效时，客户端可以无缝切换到其他协议，确保连接的高可用性。

流量深度伪装：通过多层次的伪装来模拟正常的互联网流量，有效对抗审查和探测。

协议层面：使用通用协议（HTTP/2、WebSocket、QUIC）进行封装。

端口层面：所有 TCP 协议均使用 443 端口，这是 HTTPS 的标准端口，使流量看起来像在正常浏览网页。UDP 协议则使用 443、8443 和 2053 等常用端口，分散风险。

行为层面：VLESS-Reality 协议通过伪装 TLS 指纹，让流量看起来像是在访问一个真实的、热门网站。

灵活路由与安全分流：节点能够根据您的需求，智能地分配流量，以平衡安全性、速度和成本。

技术架构与协议组合
EdgeBox 采用以下技术组合，实现了多协议的完美共存：

Nginx：作为前置代理，将所有 443 端口的 TCP 流量分发到后端服务。通过 HTTP(S) 反向代理 VLESS-gRPC 和 VLESS-WS，并通过 stream 模块实现基于 SNI 的 VLESS-Reality 流量分流。

Xray & sing-box：脚本将通过官方安装脚本，安装 Xray 和 sing-box 的最新相互兼容版本。Xray 负责 VLESS-gRPC 和 VLESS-WS，而 sing-box 则承载 Reality、Hysteria2 和 TUIC。

证书管理：安装脚本会交互式询问用户是否填写域名，如果填写则优先使用 ACME 申请真实证书，否则退回兜底方案，自动生成自签名证书。

部署与管理
一键安装
只需在您的 Debian/Ubuntu 服务器上执行以下命令即可开始：

Bash

bash <(curl -fsSL https://raw.githubusercontent.com/<你的GitHub>/node/refs/heads/main/ENV/install.sh)
脚本将进行交互式引导，完成所有配置，包括：

域名与证书配置

出站分流策略：询问是否设置住宅 HTTP 代理，并提示输入 HOST:PORT:USER:PASS。如果跳过，则默认采用全直出策略。

视频流分流：默认在 VPS 侧配置路由规则，将 googlevideo / ytimg / ggpht 等特定视频流域名设置为直连，以节省代理流量并提升观看体验。

后期管理
安装完成后，脚本将自动部署一个名为 edgeboxctl 的管理服务，您可以使用它来轻松管理节点。

协议管理：edgeboxctl enable <protocol_name> 和 edgeboxctl disable <protocol_name>，用于按需启用或禁用协议。

分流管理：edgeboxctl route direct 和 edgeboxctl route proxy，用于随时切换出站策略（全直连或分流）。

特别提示
GCP 网络计费：VLESS-gRPC 协议本身不会导致您的 GCP 流量从标准网络切换到高级网络。GCP 的网络层级是在 VM 实例级别设置的，与协议无关。

系统兼容性：脚本主要兼容 Debian 和 Ubuntu，因为它们占据了绝大多数服务器市场份额。兼容其他 Linux 发行版（如 CentOS、Fedora）技术上可行，但会显著增加复杂性，因此目前并非首要目标。

订阅链接：如果您需要分享给朋友，优先推荐分享聚合订阅链接。它包含所有协议，提供了最佳的便利性和高可用性。

安全分流：您在客户端上可以配置**“绕过大陆”**规则，结合 VPS 上的白名单直出策略，可以最大程度地保障您的隐私和 VPS IP 的安全。

常用命令清单
安装完成后，请务必保存以下命令，它们将是您日后管理节点的核心工具。

常用管理命令
Bash

# 启用或禁用特定协议，例如启用Hysteria2
edgeboxctl enable hy2

# 切换出站分流策略到全代理
edgeboxctl route proxy

# 切换出站分流策略回全直出
edgeboxctl route direct

# 重启所有服务
systemctl restart xray sing-box nginx
常用排障命令
Bash

# 检查端口占用情况
ss -lntup | egrep ':443|:8443|:2053'

# 查看 sing-box 服务日志，了解最新120行
journalctl -u sing-box -b --no-pager -n 120

# 查看 xray 服务日志，了解最新120行
journalctl -u xray -b --no-pager -n 120

# 检查Nginx配置是否正确，并重新加载服务
nginx -t && systemctl reload nginx

# 重新生成聚合订阅链接
/root/make_sub.sh <你的域名>











Tools

Gemini can make mis
