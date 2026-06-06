# EdgeBox v4.7.0 安全审计报告 —— 抗 GFW / 大陆监控 威胁模型

> 审计范围：`ENV/` 下全部协议配置、密钥/凭据处理、管理面暴露、日志取证面。
> 威胁模型：主动探测（active probing）、被动流量分析（timing / 包长 / TLS 指纹）、
> DPI 协议指纹、SNI 审查、DNS 投毒、IP 封锁，以及**服务器被查封后的取证**。
> 部署形态：单机 GCP，VLESS-Reality(TCP/443) + Hysteria2(UDP/443),nginx stream 共用 443。

---

## 0. 先说结论 / 总体评价

**Reality 通道整体健壮**，按目前主流抗审查实践配置，没有结构性漏洞：

- 借用真实 SNI 回落（`dest=<SNI>:443`, `serverNames=[<SNI>]`），主动探测无密钥时被转发到真站点 —— 抗主动探测成立。
- `flow=xtls-rprx-vision`（抗包长/时序特征）、单一随机 `shortId`、`show:false`，均正确。
- 服务端 xray `access:none` + sing-box `level:warn`，已不记录客户端 IP/目标（前几轮已修）。

**主要风险集中在三处**：① Hysteria2 缺少混淆、易被 DPI 指纹化并封锁；② 订阅明文经 80 端口传输，在墙内拉取会把整份节点凭据暴露给 GFW；③ nginx 访问日志记录客户端 IP，服务器被查封时构成取证风险。下面按严重度排列。

---

## 1. 高危（HIGH）

### H-1　订阅明文经 HTTP/80 传输 —— 墙内拉取即向 GFW 泄露整份节点

**证据**：`scripts/edgeboxctl` show_sub 在 IP 模式下输出 `http://<IP>/sub-<token>`；nginx 80 端口提供 `/sub-*`。订阅正文是明文的 `vless://...@IP:443?...pbk=<reality公钥>&sid=<shortid>...` 和 `hysteria2://<密码>@IP:443?...`。

**为什么对 GFW 致命**：如果客户端在**墙内**用 `http://IP/sub` 拉订阅，GFW 的 DPI 能在明文 HTTP 响应里直接读到：服务器 IP、UUID、Reality 公钥与 shortId、HY2 密码、SNI。这等于把"如何识别并封锁这台节点"的全部信息白送给审查方 —— 既可直接封 IP，也可用这些参数做精准主动探测。**这是把抗审查协议的所有努力一次性绕过的旁路。**

**现状缓解**：域名模式下我们已支持 `https://<域名>:8443/sub-*`（LE 真证书，全程 TLS,GFW 读不到正文）。

**建议**（按强度递增）：
1. **最低要求**：墙内**永远不要**用 `http://IP/sub` 拉订阅；改用 `https://<域名>:8443/sub-*`,或在已有翻墙链路 / 境外网络下完成首次导入。
2. **推荐**：让 80 端口只保留 ACME 验证路径，其余 `/sub-*`、`/share/` 一律 301 跳 `https://<域名>:8443`,从机制上禁掉明文订阅（这就是上一轮提到的可选加固，从抗 GFW 角度现在值得做了）。
3. 订阅 token 可轮换；一旦怀疑曾在墙内明文拉取过，重置 token + 轮换 UUID/HY2 密码。

---

### H-2　Hysteria2 全程无 obfs（Salamander）混淆 —— QUIC 握手可被 DPI 指纹化

**证据**：全项目 `grep obfs/salamander` 为空。sing-box HY2 inbound（install.sh:4212）只有 `tls + alpn:["h3"]`,无 `obfs` 字段。

**为什么对 GFW 重要**：裸 Hysteria2 的 QUIC 初始包有可被识别的特征，GFW 历史上多次对 Hysteria 类流量做过指纹封锁/限速。Salamander 用一个预共享口令对 QUIC 包做混淆，使其不呈现 HY2 特征。缺失它意味着**HY2 是你两条通道里最容易被单独识别和封锁的一条**，尤其它跑在裸 GCP IP 的 UDP/443 上。

**建议**：服务端 HY2 inbound 增加
```json
"obfs": { "type": "salamander", "password": "<32字节随机>" }
```
并在订阅里给 HY2 链接补 `obfs=salamander&obfs-password=<同一口令>`。
**客户端影响**：obfs 口令必须两端一致 → 需重新生成订阅、客户端重新导入。建议把 obfs 口令纳入 server.json 统一管理，和 UUID/密码同等对待。

---

## 2. 中危（MEDIUM）

### M-1　HY2 无端口跳跃（port hopping）—— 单 UDP/443 易被整体限速/封锁

**证据**：`udp_ports=("443")`,HY2 固定监听 `listen_port:443`。

**说明**：GFW 对 UDP（尤其非 CDN IP 的 QUIC）限速比 TCP 激进。Hysteria2 原生支持监听端口段 + 客户端在端口段内跳跃，能显著降低被整段限速的概率。当前单端口无此能力。

**建议**：服务端放通一段 UDP（如 `20000-21000`）并用 iptables/nftables DNAT 到 443,或用 sing-box/HY2 的端口段能力；订阅 HY2 链接加 `mport=20000-21000`。**客户端影响**：需重新导入订阅；防火墙需放通该 UDP 段。

### M-2　nginx 访问日志记录客户端 IP —— 服务器被查封时的取证风险

**证据**：install.sh:3561-3562 `log_format main '$remote_addr ...'` + `access_log /var/log/nginx/access.log`；stream 日志 3686。

**说明**：Reality 流量走 stream ssl_preread、HY2 完全不经 nginx,所以代理正文不在 http 日志里 —— 这点是好的。但**订阅/面板的 HTTP 访问会带客户端 IP 落盘**。如果服务器被查封/镜像，`access.log` 能把"哪些客户端 IP 访问过这台节点"暴露出来，构成对使用者的取证关联。

**建议**：对订阅/面板 vhost 关闭或匿名化 access_log（`access_log off;`,或日志格式去掉 `$remote_addr`）；同时给 nginx/xray/sing-box 日志上 logrotate + 短保留期（如已存在则确认覆盖到这些文件）。

### M-3　HY2 masquerade 仅靠 cron 注入，存在时间窗与依赖

**证据**：基础 HY2 配置（4212）无 masquerade;由 `edgebox-traffic-randomize.sh`（44-45 行 `.masquerade = $url`）在 cron 中轮换注入,而 cron 是否安装取决于 install.sh:5346 的逻辑。

**说明**：masquerade 让 HY2 对"未认证的 HTTP/3 请求"伪装成正常网站,提升抗主动探测。但它**只在 randomize cron 跑过之后才生效** —— 安装到首次 cron 之间、或 cron 未装时,HY2 对主动探测会回落到 sing-box 默认拒绝,暴露"这不是普通 QUIC 服务"。

**建议**：把 masquerade 直接写进**基础安装配置**（不依赖 cron）,cron 仅做后续轮换;并在安装尾部验证 `jq '.inbounds[]|select(.type=="hysteria2")|.masquerade'` 非空。

---

## 3. 低危 / 信息（LOW / INFO）

### L-1　Reality SNI = IP 归属错配（Reality 固有，非本项目 bug）
SNI=`www.microsoft.com` 但服务器是 GCP IP。理论上 GFW 可校验"该 IP 是否真属于 microsoft"并标记错配。Reality 设计层面的已知权衡,目前未被系统性执法。**可选缓解**：选 Anycast/CDN 归属更模糊的 SNI,或接受该风险。

### L-2　默认 SNI 过于流行
`www.microsoft.com / www.apple.com` 是最常见的 Reality 借用目标,本身构成弱"Reality 用户"信号(不构成破解)。SNI 池里 `www.cloudflare.com`、`azure.microsoft.com` 相对均衡;可考虑换用与你 VPS 地理/网络更贴近、TLS1.3、墙内可达的站点。

### L-3　安装期未显式校验 SNI dest 可达性 + TLS1.3
`choose_initial_sni_once` 依赖 `edgeboxctl sni auto`,回落到域名池首项。若所选 dest 从该 VPS 不可达或非 TLS1.3,Reality 回落握手会异常 → 主动探测可探测到差异。**建议**：安装期对选定 SNI 做一次 `openssl s_client -tls1_3 -connect <sni>:443` 可达性 + 协议版本校验,失败则换池内下一个。

### L-4　IP 模式下 HY2 用自签证书
公网 QUIC 端点用自签证书本身是一个弱信号(正常 QUIC 服务极少自签)。**域名模式用 LE 真证书已消除此点** —— 这也是再次推荐长期跑域名模式的理由。

### L-5　Reality 未设 maxTimeDiff
未启用基于时间戳的抗重放(默认关闭)。xtls-rprx-vision + Reality 设计已覆盖多数场景,属可选增强。

---

## 4. 优先级修复清单

| 优先级 | 项 | 是否需客户端重新导入订阅 | 是否需调整防火墙 |
|---|---|---|---|
| P0 | H-1 墙内改用 HTTPS 订阅 / 80 仅留 ACME | 是(改用 8443 链接) | 否 |
| P0 | H-2 HY2 加 Salamander obfs | 是 | 否 |
| P1 | M-2 nginx 访问日志匿名化 | 否 | 否 |
| P1 | M-3 masquerade 写进基础配置 | 否 | 否 |
| P2 | M-1 HY2 端口跳跃 | 是 | 是(放通 UDP 段) |
| P2 | L-3 安装期校验 SNI 可达性/TLS1.3 | 否 | 否 |
| P3 | L-1/L-2 SNI 选择优化、L-5 maxTimeDiff | 视情况 | 否 |

**不需改动即已正确**：Reality 核心参数、服务端 xray/sing-box 日志收紧、客户端 DNS 经隧道(前几轮已修)、内网段 reject 防 SSRF。

---

## 5. 一句话总览

> Reality 这条线稳;Hysteria2 这条线"裸"(无 obfs、无端口跳跃、masquerade 靠 cron),是最易被墙单独打掉的;
> 而**最危险的不是协议本身,是订阅明文经 80 端口在墙内拉取**——它会把识别/封锁这台节点的全部信息直接交给 GFW。
> 先堵 H-1、H-2,再做日志匿名化,你这台节点的抗审查与抗取证就上一个台阶。
