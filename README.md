# node
统一安装/管理 VLESS‑gRPC(443/tcp)、VLESS‑WS(+TLS)、VLESS‑Reality(443/tcp)、Hysteria2(udp/443|8443)、TUIC(udp/2053)。
可按需启用/禁用协议，支持“住宅HTTP代理直连/分流”，并输出聚合订阅。
________________________________________
1) 兼容 Debian 11/12、Ubuntu 20.04/22.04/24.04（apt 系列）

五协议一体（可交互开/关）：VLESS-gRPC、VLESS-WS(+TLS via Nginx)、VLESS-Reality、Hysteria2、TUIC

自动：依赖安装、BBR+fq、可选创建 2GB swap、UFW 放行、Nginx 反代(8443/tcp)

出⼝分流（可选）：googlevideo/ytimg/ggpht 走你提供的住宅 HTTP 代理，其它直出

聚合订阅：生成 /var/www/html/sub/urls.txt（也软链到 /var/lib/sb-sub/urls.txt），包含你启用的每个协议链接

幂等：多次运行不炸；错误会 exit 1，日志清晰

卸载干净：保留一份 tar 备份，选项化清理 Nginx 站点/订阅页、UFW、swap、依赖等（不强制卸 Nginx 包，防误伤）

版本策略

Xray：装最新版（官方安装脚本）。

sing-box：默认装 v1.12.2（你说过这版可用）；若下载失败，自动退回官方安装脚本装最新版。

我写的 sing-box 配置不使用已弃用的 transport 字段，避免 “unknown transport type: tcp” 这类坑。


当前 VM 环境快照（体检要点）
•	系统：Ubuntu 24.04 LTS x86_64（GCP）。内核示例：6.14.0-1014-gcp。
•	已装组件（曾多次复现）：
o	nginx 1.24.x（TLS 反代 gRPC/WS）
o	jq 1.7+、curl 8.x、wget 1.21+、unzip 6.x、ufw 0.36.x
o	Xray 25.8.3（gRPC/WS）
o	sing-box 1.12.2（推荐稳定）
•	内核网络：BBR + fq（已验证可启用）
•	Swap：建议 +2GB（小内存实例更稳）
•	端口规划：
o	TCP 443（Reality）/ 或 Nginx（若无 Reality）
o	TCP 8443（Nginx：gRPC/WS；当 443 被 Reality 占用时）
o	UDP 443 或 8443（HY2）
o	UDP 2053（TUIC）
•	常见坑：
o	sing-box 新旧配置差异：旧版里 "transport":"tcp" 会让新版本报错：unknown transport type: tcp；同时用 sed/jq 误操作易造成 EOF（JSON 被截断）。
o	Reality 与 Nginx TCP/443 冲突：两者只能二选一；本方案在开 Reality 时自动把 Nginx 迁到 8443。
o	HY2/TUIC 需要 TLS 证书。脚本默认 自签证书（客户端需 allowInsecure/insecure），也留了 ACME 扩展位。
________________________________________
2) sb.sh 脚本回顾与问题定位
•	版本固定：脚本固定下载 sing-box v1.12.2（稳定，兼容 Reality/hy2/tuic 语法）。
•	报错复盘：
1.	unknown transport type: tcp → 来自旧式字段写法；已在最终版脚本彻底移除错误字段。
2.	decode config: EOF → 由不完整 here‑doc / jq 写回失败引起；最终版严格使用 完整 here‑doc + jq -e 预检。
3.	invalid private key → Reality 私钥抓取不一致/被多次生成覆盖；最终版一次生成成对密钥，并 校验非空，sing-box check 预检。
•	订阅生成：之前手工贴多段命令容易被 SSH‑Web 页面截断；最终版提供 /root/make_sub.sh 一次到位生成，并在安装结尾自动执行。
________________________________________
3) 最终整体方案与端口拓扑
•	gRPC/WS：Xray 作为应用层，Nginx(TLS/HTTP2) 反代到本地 127.0.0.1:10085(gRPC) / 10086(WS)。
o	若启用 Reality：Nginx 监听 8443；未启用 Reality 时可监听 443。
•	Reality：sing-box 直绑 tcp/443（默认 SNI www.cloudflare.com，可改）。
•	HY2：sing-box 监听 udp/443（可改 8443），自签证书 + alpn=h3。
•	TUIC：sing-box 监听 udp/2053，复用同一证书。
•	出站分流（可选）：
o	默认“全量直出（direct）”。
o	可选“住宅 HTTP 代理（host/port/user/pass）”：除 googlevideo/ytimg/ggpht 外全部经住宅代理直出；这里对 Xray 与 sing-box 各自配置相同策略。
•	订阅：聚合到 http://<你的域名>/sub/urls.txt。
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
6) 变更记录 / 与早期方案的差异

固定版本：sing-box 统一到 v1.12.2，避免语法漂移；Xray 固定 25.8.3。

彻底防 EOF：所有 JSON 用完整 here‑doc 生成，不再通过零碎 sed/jq 修改（只用于校验）。

Reality 密钥安全：同一命令一次抓取私/公钥，杜绝抓错对/变量为空。

订阅生成稳定：落地为脚本 /root/make_sub.sh，避免 WebSSH 粘贴截断。

冲突处理：启用 Reality → Nginx 自动切换 8443，避免 443/tcp 冲突。

附：使用建议

客户端里建议设置优先级（主用 gRPC/HY2，备用 WS/Reality/TUIC），服务器无法强制客户端优先级。

若要用正式证书，可将 mk_self_cert 改为 ACME（比如 acme.sh），并把 Nginx/HY2/TUIC 的证书路径指向真实证书。

若所在区域 UDP 不通，关闭 HY2/TUIC，仅留 gRPC/WS/Reality。
•	可选备份：TUIC(udp/2053)（遇到 HY2 QoS/探测时切）
•	常见坑同步：
o	橙云下 HY2 不能走 CF（需灰云直连）。
o	Xray 延迟列 -1 不是不可用，只是被测拒绝；请看“右侧流量”。
o	UDP 区域性封禁：回退 gRPC/WS/Reality。
