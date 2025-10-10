# EdgeBox 操作手册 · 流量预警与通知渠道配置指南

---

## 目录

* [概述](#概述)
* [工作原理与文件位置](#工作原理与文件位置)
* [快速入门（3 步）](#快速入门3-步)
* [命令参考](#命令参考)
* [渠道配置](#渠道配置)

  * [Telegram 机器人](#telegram-机器人)
  * [Discord Webhook](#discord-webhook)
  * [微信（PushPlus）](#微信pushplus)
  * [通用 Webhook（raw|slack|discord）](#通用-webhookrawslackdiscord)
  * [邮件（可选）](#邮件可选)
* [安全与权限](#安全与权限)
* [验证与排错](#验证与排错)
* [配置文件说明（示例）](#配置文件说明示例)
* [附：一键自检脚本](#附一键自检脚本)

---

## 概述

EdgeBox 提供基于 **月度流量预算** 的告警能力。系统按小时汇总当月出站用量，当达到设定阈值（如 50%/80%/95%）时，通过你配置的 **通知渠道**（Telegram / Discord / PushPlus / 通用 Webhook / 邮件）下发提醒，避免超量或被封顶。

> **单位说明**：采集脚本以字节（Bytes）记账，前端展示按 IEC（KiB/MiB/GiB/TiB）自适应；CLI `edgeboxctl traffic show` 也按字节换算，与你的前端图表保持同量级。

---

## 工作原理与文件位置

* **采集**：`/etc/edgebox/scripts/traffic-collector.sh`

  * 每小时写入：`/etc/edgebox/traffic/logs/monthly.csv`
  * CSV 列：`month,vps,resi,total,tx,rx`（单位：字节）
* **告警**：`/etc/edgebox/scripts/traffic-alert.sh`

  * 触发频率：每小时 **:07** 分（systemd/cron 预置）
  * 读取：`/etc/edgebox/traffic/alert.conf` 与 `logs/monthly.csv`
  * 触发后将已发送阈值记录到：`/etc/edgebox/traffic/alert.state`
* **日志**：`/var/log/edgebox-traffic-alert.log`
* **依赖**：`curl`、`jq`；若使用邮件，还需 `mail` 与已配置的 MTA/SMTP（如 `msmtp`/`postfix`）。

---

## 快速入门（3 步）

1. **设定预算与阈值**

```bash
edgeboxctl alert monthly 200        # 设置本月预算 200 GiB
edgeboxctl alert steps 50,80,95     # 在 50%、80%、95% 时各触发一次
```

2. **配置一个或多个通知渠道**（详见下文“渠道配置”）
3. **模拟触发，验证链路**

```bash
edgeboxctl alert test 80            # 模拟本月已用 80% 触发预警
edgeboxctl alert show               # 查看当前配置
sudo tail -n 20 /var/log/edgebox-traffic-alert.log
```

> 说明：`alert test` 不会消耗真实流量；它会临时构造一个 80% 用量场景，并重置 `alert.state` 以便观察告警是否能被触发。

---

## 命令参考

```text
edgeboxctl alert show                      # 查看当前告警配置
edgeboxctl alert monthly <GiB>             # 设置当月预算（单位 GiB）
edgeboxctl alert steps <p1,p2,...>         # 设置分段阈值（百分比，逗号分隔）

edgeboxctl alert telegram <token> <chat_id>        # 配置 Telegram 渠道
edgeboxctl alert discord  <webhook_url>            # 配置 Discord 渠道（专用字段）
edgeboxctl alert wechat   <pushplus_token>         # 配置 PushPlus（微信）
edgeboxctl alert webhook  <url> [raw|slack|discord]# 配置通用 Webhook（声明载荷格式）

edgeboxctl alert test [percent]            # 模拟触发告警（默认 80%）
```

---

## 渠道配置

### Telegram 机器人

**用途**：向 Telegram 个人或群组推送告警。

**准备**：

1. 与 `@BotFather` 创建机器人 → 获得 **`bot_token`**。
2. 获取 **`chat_id`**：

   * 私聊：给机器人发一句话，然后执行：

     ```bash
     TOKEN=123456:ABC-DEF_your_token
     curl -s "https://api.telegram.org/bot$TOKEN/getUpdates" | jq -r '.result[-1].message.chat.id'
     ```
   * 群聊：把机器人拉进群，群里随便发一句，再用上面命令抓取；群组 ID 一般是负号开头。
3. 若服务器直连不了 `api.telegram.org`，为 `curl` 配置代理（如 `https_proxy=http://127.0.0.1:7890`）。

**写入配置**：

```bash
edgeboxctl alert telegram <bot_token> <chat_id>
edgeboxctl alert show
```

---

### Discord Webhook

**用途**：把告警消息发到指定 Discord 频道。

**获取 Webhook**：服务器 → 频道设置 → Integrations → Webhooks → New Webhook → 复制 URL。

**写入配置**（二选一，推荐都设）：

```bash
edgeboxctl alert discord https://discord.com/api/webhooks/xxxx/xxxx
# 同时把通用 Webhook 指向 Discord，并声明格式为 discord
edgeboxctl alert webhook https://discord.com/api/webhooks/xxxx/xxxx discord
```

> 成功通常返回 `204 No Content`；看不到正文是正常现象。

---

### 微信（PushPlus）

**用途**：通过 PushPlus 触达微信。

**写入配置**：

```bash
edgeboxctl alert wechat <pushplus_token>
edgeboxctl alert show
edgeboxctl alert test 80
```

> 注意：需保证服务器可访问 PushPlus 接口；如报限流或 token 无效，请在 PushPlus 后台核对。

---

### 通用 Webhook（raw|slack|discord）

**用途**：对接 Slack / 飞书 / 自建机器人或任意 HTTP 接收端。

**写入配置**：

```bash
# raw：发送 {"text":"..."}，兼容多数简单接收端 / Slack 文本
edgeboxctl alert webhook https://example.com/hook raw

# slack：Slack 风格（与 raw 接近，细节可能有扩展）
edgeboxctl alert webhook https://hooks.slack.com/services/... slack

# discord：发送 {"content":"..."}，匹配 Discord 的推荐载荷
edgeboxctl alert webhook https://discord.com/api/webhooks/... discord
```

**兼容性提示**：

* 旧版 `traffic-alert.sh` 仅按 `raw` 发送（`{"text":"..."}`）。若你当前 Webhook 只收 `content` 字段，请：

  1. 升级到支持 `ALERT_WEBHOOK_FORMAT` 的脚本；或
  2. 直接配置 `edgeboxctl alert discord <url>` 使用专用变量；或
  3. 调整接收端以兼容 `text` 字段。

---

### 邮件（可选）

**启用**：编辑 `/etc/edgebox/traffic/alert.conf`，填写目标邮箱：

```ini
ALERT_EMAIL=me@example.com
```

确保系统 `mail` 命令可用（建议安装并配置 `msmtp` 或 `postfix`）。

**测试**：

```bash
edgeboxctl alert test 80
```

---

## 安全与权限

```bash
sudo chown root:root /etc/edgebox/traffic/alert.conf
sudo chmod 600 /etc/edgebox/traffic/alert.conf
```

* 配置文件包含令牌/密钥，仅在可信主机上执行 `edgeboxctl alert telegram|discord|wechat|webhook ...`。
* 如需代理访问第三方接口，可在服务环境为 `curl` 设置 `https_proxy`/`http_proxy`。

---

## 验证与排错

**查看配置**

```bash
edgeboxctl alert show
```

**查看告警日志**

```bash
sudo tail -n 50 /var/log/edgebox-traffic-alert.log
```

**手工执行告警脚本**

```bash
sudo bash -lc '/etc/edgebox/scripts/traffic-alert.sh'
```

**常见问题**

* **未收到消息**：检查网络连通（`curl -v <webhook_url>`）、令牌有效性、Webhook 载荷格式是否匹配。
* **Telegram 获取不到 chat_id**：先让机器人收到一条消息再 `getUpdates`；群组 ID 通常是负号开头。
* **重复轰炸**：`alert.state` 会记录已触发过的百分比。`alert test` 为测试会清空它，属正常行为。
* **大陆网络环境**：Telegram/部分 Webhook 需出站代理；确保这类域名走 VPS 出站或为 `curl` 配置代理。

---

## 配置文件说明（示例）

文件：`/etc/edgebox/traffic/alert.conf`

```ini
# 预算（单位 GiB）
ALERT_MONTHLY_GIB=200

# Telegram
ALERT_TG_BOT_TOKEN=
ALERT_TG_CHAT_ID=

# Discord 专用 Webhook
ALERT_DISCORD_WEBHOOK=

# PushPlus（微信）
ALERT_PUSHPLUS_TOKEN=

# 通用 Webhook
ALERT_WEBHOOK=
ALERT_WEBHOOK_FORMAT=raw   # raw|slack|discord（老脚本仅 raw 生效）

# 分段阈值（百分比，逗号分隔）
ALERT_STEPS=30,60,90

# 邮件（可选）
ALERT_EMAIL=
```

---

## 附：一键自检脚本

> 位置建议：`/etc/edgebox/scripts/alert-selfcheck.sh`，赋予可执行权限 `chmod +x`。运行后自动检测依赖、读取配置、连通各已启用渠道并发送一条「自检」消息。

```bash
#!/usr/bin/env bash
set -euo pipefail
CONF="/etc/edgebox/traffic/alert.conf"
LOG="/var/log/edgebox-traffic-alert.log"
[[ -f "$CONF" ]] || { echo "配置文件不存在：$CONF"; exit 1; }
command -v curl >/dev/null || { echo "缺少 curl"; exit 1; }
command -v jq   >/dev/null || { echo "缺少 jq"; exit 1; }

source "$CONF"
now() { date '+%F %T'; }
msg="[EdgeBox 自检] $(now) — 这是一次渠道连通性测试，不代表真实流量告警。"

ok(){ echo "[OK] $1"; }
ko(){ echo "[ERR] $1"; }

# Telegram
if [[ -n "${ALERT_TG_BOT_TOKEN:-}" && -n "${ALERT_TG_CHAT_ID:-}" ]]; then
  resp=$(curl -sS -X POST \
    "https://api.telegram.org/bot${ALERT_TG_BOT_TOKEN}/sendMessage" \
    -d chat_id="${ALERT_TG_CHAT_ID}" -d text="$msg") || { ko "Telegram 连接失败"; }
  [[ "$(jq -r '.ok // false' <<<"$resp")" == "true" ]] && ok "Telegram 已送达" || ko "Telegram 返回异常：$resp"
fi

# Discord 专用
if [[ -n "${ALERT_DISCORD_WEBHOOK:-}" ]]; then
  curl -sS -X POST -H 'Content-Type: application/json' \
    -d "{\"content\":\"$msg\"}" "$ALERT_DISCORD_WEBHOOK" >/dev/null \
    && ok "Discord 已提交" || ko "Discord 提交失败"
fi

# 通用 Webhook
if [[ -n "${ALERT_WEBHOOK:-}" ]]; then
  fmt="${ALERT_WEBHOOK_FORMAT:-raw}"
  case "$fmt" in
    discord) payload="{\"content\":\"$msg\"}";;
    *)       payload="{\"text\":\"$msg\"}";;
  esac
  curl -sS -X POST -H 'Content-Type: application/json' -d "$payload" "$ALERT_WEBHOOK" >/dev/null \
    && ok "通用 Webhook($fmt) 已提交" || ko "通用 Webhook 提交失败"
fi

# PushPlus
if [[ -n "${ALERT_PUSHPLUS_TOKEN:-}" ]]; then
  curl -sS -X POST -H 'Content-Type: application/json' \
    -d "{\"token\":\"$ALERT_PUSHPLUS_TOKEN\",\"title\":\"EdgeBox 自检\",\"content\":\"$msg\"}" \
    https://www.pushplus.plus/send >/dev/null \
    && ok "PushPlus 已提交" || ko "PushPlus 提交失败"
fi

echo "日志：$LOG"
```

---

> **落地建议**：
>
> * 文档保存为：`docs/guide-alerts.md`；
> * 自检脚本：`/etc/edgebox/scripts/alert-selfcheck.sh`；
> * 初次部署后：`edgeboxctl alert show && sudo /etc/edgebox/scripts/alert-selfcheck.sh`，确认所有渠道均连通。
