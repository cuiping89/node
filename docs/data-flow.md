
### 控制面板数据流与技术实现口径

为了确保控制面板（`index.html`）能够稳定、统一地展示服务器的各类状态，系统采用了一套清晰的、单向的数据流机制。理解这个机制是进行问题排查和功能扩展的关键。

整个过程可以概括为：**后端脚本定时采集 -\> 生成统一JSON文件 -\> 前端异步请求并渲染**。

#### **第一步：数据源 (Sources of Truth)**

所有前端展示的数据，其最原始的来源是服务器上的配置文件或系统命令。主要包括：

  * **核心配置**：`/etc/edgebox/config/server.json` (包含UUID、密码、IP等)。
  * **出站分流白名单**：`/etc/edge-box/config/shunt/whitelist.txt` (纯文本，每行一个域名)。
  * **分流模式状态**：`/etc/edgebox/config/shunt/state.json` (记录当前是VPS模式还是代理模式)。
  * **订阅链接缓存**：`/etc/edgebox/traffic/sub.txt`。
  * **系统实时状态**：通过 `top`, `/proc/stat`, `/proc/meminfo` 等命令获取 CPU 和内存使用率。
  * **服务运行状态**：通过 `systemctl is-active <service>` 命令获取 Nginx, Xray, Sing-box 的状态。

#### **第二步：后端聚合脚本 (The Backend Aggregator)**

这是整个数据流的核心枢纽。系统中**唯一**负责为前端生成数据的脚本是：

  * **脚本位置**：`/etc/edgebox/scripts/dashboard-backend.sh`

该脚本的主要职责是：

1.  **采集**：执行上述第一步中的所有命令和文件读取操作。
2.  **处理**：将从各处采集到的原始数据（无论是文本还是命令输出）统一处理成规范的 JSON 格式。例如，它会将 `whitelist.txt` 的多行文本转换成一个 JSON 数组。
3.  **聚合**：将所有处理后的数据，组装成一个单一、完整的 JSON 对象。

#### **第三步：中心化数据接口 (The Centralized Data "API")**

后端脚本的**唯一输出**是一个静态的 JSON 文件。这个文件扮演了前端与后端之间数据交换的“API接口”角色。

  * **接口文件**：`/etc/edgebox/traffic/dashboard.json`

这个文件包含了前端页面所需的所有动态信息。其结构经过精心设计，例如，之前出问题的白名单数据，在此文件中对应的路径是 `shunt.whitelist`。

**`dashboard.json` 结构示例：**

```json
{
  "updated_at": "2025-09-11T21:41:00Z",
  "server": {
    "ip": "35.212.192.41",
    "version": "3.0.0",
    ...
  },
  "services": {
    "nginx": "active",
    "xray": "active",
    "sing-box": "active"
  },
  "shunt": {
    "mode": "vps",
    "proxy_info": "",
    "health": "unknown",
    "whitelist": [
      "googlevideo.com",
      "ytimg.com",
      "ggpht.com",
      ...
    ]
  },
  "subscription": { ... },
  "secrets": { ... }
}
```

#### **第四步：定时刷新机制 (Automation via Cron)**

为了让前端数据能够“准实时”更新，系统通过 `cron` 定时任务来周期性地执行第二步的聚合脚本。

  * **定时任务**：`crontab -l` 中可以看到，`/etc/edgebox/scripts/dashboard-backend.sh` 脚本被设置为**每2分钟**执行一次。
  * **工作流程**：每隔2分钟，`cron` 触发脚本 -\> 脚本重新采集所有最新数据 -\> 覆盖写入 `dashboard.json` 文件。

#### **第五步：前端消费与渲染 (Frontend Consumption)**

前端 `index.html` 页面完全不关心后端的复杂逻辑。它只做一件事情：

1.  **异步请求**：页面加载后，其内置的 JavaScript 会使用 `fetch` 函数，向 `/traffic/dashboard.json` 发起一个 HTTP GET 请求。
2.  **数据驱动渲染**：获取到 JSON 数据后，JavaScript 会解析这个 JSON 对象，并将其中的值（如 `server.ip`, `services.nginx`, `shunt.whitelist` 等）填充到页面上对应的 HTML 元素中（例如 ID 为 `srv-ip`, `nginx-status`, `whitelist-text` 的元素）。

### **未来维护的核心原则与故障排查指南**

为避免再次出现类似问题，请遵循以下核心原则：

  * **单一入口原则**： **任何** 需要在前端控制面板上展示的新数据，都**必须**通过修改 `/etc/edgebox/scripts/dashboard-backend.sh` 这**唯一**的脚本来添加。严禁创建其他脚本来写入 `dashboard.json`。

  * **故障排查“倒叙法”**：如果未来发现前端某个数据显示不正确（例如显示“加载中...”或“N/A”），请严格按照以下倒叙流程进行排查：

    1.  **检查前端 (HTML/JS)**：浏览器F12查看网络请求，确认 `dashboard.json` 是否成功加载？JavaScript 代码中读取的JSON路径（如 `data.shunt.whitelist`）是否写错了？
    2.  **检查接口文件 (dashboard.json)**：直接在服务器上 `cat /etc/edgebox/traffic/dashboard.json`，查看你需要的那个字段（例如 `whitelist`）是否存在？格式是否正确？如果这里就没有数据，说明问题出在后端。
    3.  **检查后端脚本 (dashboard-backend.sh)**：检查该脚本采集数据的逻辑是否正确。是文件路径错了？还是 `jq` 命令拼错了？可以在脚本里加入 `echo` 调试语句来排查。
    4.  **检查数据源 (配置文件/系统命令)**：确认最原始的数据文件（如 `whitelist.txt`）本身是否有内容，并且格式正确。

