# node
统一安装/管理 VLESS‑gRPC(443/tcp)、VLESS‑WS(+TLS)、VLESS‑Reality(443/tcp)、Hysteria2(udp/443|8443)、TUIC(udp/2053)。
可按需启用/禁用协议，支持“住宅HTTP代理直连/分流”，并输出聚合订阅。
________________________________________
1) 兼容 Debian 11/12、Ubuntu 20.04/22.04/24.04（apt 系列）；目标：在“任何 VPS/VM”上一键落地、稳定复现、方便维护。
五协议一体：VLESS-gRPC、VLESS-WS(+TLS via Nginx)、VLESS-Reality、Hysteria2、TUIC
自动：依赖安装、BBR+fq、可选创建 2GB swap、UFW 放行、Nginx 反代(8443/tcp)
出⼝分流（可选）：googlevideo/ytimg/ggpht 直出，其它走住宅 HTTP 代理；
聚合订阅：生成 /var/www/html/sub/urls.txt（也软链到 /var/lib/sb-sub/urls.txt），包含你启用的每个协议链接
幂等：多次运行不炸；错误会 exit 1，日志清晰
卸载干净：保留一份 tar 备份，选项化清理 Nginx 站点/订阅页、UFW、swap、依赖等（不强制卸 Nginx 包，防误伤）

# EdgeBox · 五协议一体节点（VLESS-gRPC/WS + VLESS-Reality + HY2 + TUIC）

> 特点：**端口最简**（443/TCP + 8443/UDP + 2053/UDP）、**幂等重装**（保 UUID 与密钥）、**聚合订阅**、**可切换分流策略**、**可管理启停协议。

## 最终方案（与本项目实现一一对齐）

### 协议与端口
- **VLESS-gRPC**：TCP/443（Nginx HTTPS → 回环 8443 → Xray 11800）
- **VLESS-WS**：TCP/443（Nginx HTTPS → 回环 8443 → Xray 11801）
- **VLESS-Reality**：TCP/443（Nginx `stream` SNI 分流 → sing-box 127.0.0.1:14443）
- **Hysteria2**：UDP/8443（主）+ UDP/443（备）
- **TUIC**：UDP/2053（DoT常用端口，穿透性好；备用 8443）

> 这样做的理由：  
> - **最像正常站点流量**：所有 TCP 走 443。  
> - **UDP 分离**：HY2 主 8443，保留 443 为兼容/隐蔽；TUIC 用 2053（常见 DoT 端口）。  
> - **不抢端口**：HY2 与 TUIC 各占一档，互不影响；Reality 与 gRPC/WS 共用 443 由 Nginx SNI 分流。

### 分流策略（出站）
- **默认**：全部直出（`direct`）。
- **可选**：仅 `googlevideo` / `ytimg` / `ggpht` 直出，其余走**住宅 HTTP 代理**（`HOST:PORT[:USER[:PASS]]`）。
- 可随时**切回直出**（用 `edgeboxctl route` 子命令）。

### 架构与组件
- **Nginx**
  - `http(s)`：本机 `127.0.0.1:8443` 终止 TLS → 反代 gRPC/WS（Xray 回环）
  - `stream`：对外 `443`，按 SNI 映射到 `8443`（站点域名）或 `127.0.0.1:14443`（Reality）
- **Xray**：只做 VLESS-gRPC 与 VLESS-WS 回环服务
- **sing-box**：承载 Reality（回环 14443）+ HY2（UDP/8443、UDP/443）+ TUIC（UDP/2053）
- **证书**：优先 ACME 真证，失败自动自签（HY2/TUIC 使用证书时，客户端需允许 **skip verify**）
- **聚合订阅**：`http://<域名或IP>/sub/urls.txt`
--
## 端口 / 防火墙

**云防火墙/安全组 + 本机 UFW**必须放行：
- TCP：`443`
- UDP：`8443`（HY2 主）、`2053`（TUIC）； `443`（HY2 备）

> 脚本会自动为 UFW 添加规则（不会强制 `ufw enable`）。云侧（如 GCP VPC 防火墙/安全组）请手工放行。

---
### 安装
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<你的GitHub>/node/refs/heads/main/ENV/install.sh)

版本策略
Xray：装最新兼容版（官方安装脚本）。
sing-box：装最新兼容版。

•	常见坑：
sing-box 新旧配置差异：旧版里 "transport":"tcp" 会让新版本报错：unknown transport type: tcp；同时用 sed/jq 误操作易造成 EOF（JSON 被截断）。
HY2/TUIC 需要 TLS 证书。脚本默认 自签证书（客户端需 allowInsecure/insecure），也留了 ACME 扩展位。
________________________________________

4) 协议使用场景与组合策略（结论）
•	主用：
o	家宽/固网：VLESS‑gRPC(443/tcp)（HTTP/2，抗 QoS、体验稳）
o	移动/热点：HY2(udp/443|8443)（基于 QUIC，弱网恢复好）
•	兜底：VLESS‑WS(+TLS)（可上橙云/Argo 隐源）
•	应急：VLESS‑Reality(443/tcp)（被动探测/强封控环境）
________________________________________

5)常用验证与排障
端口：ss -lntup | egrep ':443|:8443|:2053' || true
服务日志：
journalctl -u sing-box -b --no-pager -n 120
journalctl -u xray     -b --no-pager -n 120
Nginx：
nginx -t && systemctl reload nginx
订阅再生：/root/make_sub.sh <你的域名>
________________________________________

6) 出站流量监控 (监控指标：VM出站字节数)：保证单日不超 7 GiB → 月度基本不超 200 GiB

在 Monitoring → Alerting → Create policy → Add condition 里：
参数设置如下：
Alignment period：5m
Per-series aligner：Sum（窗口内字节数求和）
Rolling window：24h
阈值：7,500000000 B （≈ 7 GiB）
通知：邮件，Subject 建议：[GCP告警] 出站流量 > 7GiB/24h
Notification channel：Email
日度：Daily Egress > 7GiB (24h rolling)
Severity：日度阈值 → Warning

附：使用建议
客户端里建议设置优先级（主用 gRPC/HY2，备用 WS/Reality/TUIC），服务器无法强制客户端优先级。
若要用正式证书，可将 mk_self_cert 改为 ACME（比如 acme.sh），并把 Nginx/HY2/TUIC 的证书路径指向真实证书。
若所在区域 UDP 不通，关闭 HY2/TUIC，仅留 gRPC/WS/Reality。
•	可选备份：TUIC(udp/2053)（遇到 HY2 QoS/探测时切）
•	常见坑同步：
o	橙云下 HY2 不能走 CF（需灰云直连）。
o	Xray 延迟列 -1 不是不可用，只是被测拒绝；请看“右侧流量”。
o	UDP 区域性封禁：回退 gRPC/WS/Reality。
