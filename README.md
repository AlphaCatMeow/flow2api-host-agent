# Flow2API Host Agent

> Flow2API 的 Linux 宿主机伴生服务：浏览器登录、Token 自动刷新、Web UI 与 systemd 常驻支持。

一个运行在 **Linux 宿主机** 上的独立 companion service，用来把 Google Labs / Flow 的登录态稳定同步回 **已有的 Flow2API** 实例。

适合这些场景：
- 你已经部署好了 `flow2api`
- 你不想依赖 Chrome 扩展
- 你希望在服务器上自动刷新 token
- 你需要 Web UI / systemd / 定时维护能力

---

## 界面预览

### 仪表盘

![Uploading PixPin_2026-03-09_15-22-15.png…]()


### 登录向导

![Login Guide](assets/login-guide.png)

---

## 当前版本的稳定性增强

这版重点不是“能跑”，而是**长期更稳地跑**：

- **GitHub Release 检查更新**：Web UI 可直接查看当前版本 / 最新 release / 是否可更新
- **一键更新 + 备份回滚**：拉取最新 GitHub release tarball，更新前自动备份项目目录，失败自动回滚
- **重启后本地探活**：更新完成后会自动重启 UI + daemon，并对 `http://127.0.0.1:38110/api/status` 做探活校验
- **非 root Chromium**：浏览器改为普通服务用户运行，降低 Google 登录风控敏感度
- **移除 `--no-sandbox`**：不再使用会触发 Google 登录警告的启动参数
- **browser service 托管化**：浏览器改由独立 systemd service 持续托管，不再是 oneshot 放飞子进程
- **UI 按钮统一走 systemd**：登录页中的“重新启动浏览器”改为重启 browser service，避免脚本直拉浏览器导致状态不一致
- **软预热优先（soft prewarm）**：优先复用当前浏览器中的有效登录态，不主动乱跳 Google 登录流
- **激进兜底（aggressive fallback）**：只有拿不到 `session-token` 时，才会主动打开 / 刷新 Flow 页面
- **写后强校验**：不再只看 `/api/plugin/update-token` 返回 200，而是会直接回读 Flow2API 数据库确认 ST 确实写入
- **ST 指纹比对**：记录当前 ST 指纹和库内 ST 指纹，确认不是“看起来成功”
- **异常页面告警**：如果预热后浏览器落到 `signin / accountchooser / callback error` 等页面，会在 state 和 UI 中明确标记
- **失败自动重试**：默认失败会自动重试一次，降低偶发波动影响
- **UI 可观测性增强**：仪表盘现在直接展示写后校验、页面状态、AT 过期时间、重试次数、指纹比对等关键信息
- **每日低峰自愈重启**：支持每天低峰时间自动重启 Host Agent 服务，减少长期运行累积状态
- **统一 Python 运行时**：Web UI / daemon / one-shot 命令全部走项目内 `.venv`
- **新增健康检查**：提供 `/api/health`，把 Chrome、最近刷新、Connection Token 配置分层展示
- **配置防呆**：阻止把 `Connection Token` 错填成 URL
- **日志更清晰**：Chrome 日志和 daemon 日志拆分

---

## 3 分钟上手

### 1. 克隆仓库

```bash
git clone https://github.com/muyouzhi6/flow2api-host-agent.git
cd flow2api-host-agent
```

### 2. 安装 systemd 服务

```bash
bash install-systemd.sh
```

### 3. 配置 `agent.toml`

```bash
cp agent.example.toml agent.toml
nano agent.toml
```

最关键的几项：

```toml
flow2api_url = "http://127.0.0.1:38000"
connection_token = "从 Flow2API 管理后台复制的 token 字符串"
novnc_url = "http://你的服务器IP:6080/vnc.html?autoconnect=true&resize=scale&quality=6"
listen_host = "0.0.0.0"
listen_port = 38110
```

### 4. 打开登录向导

```bash
systemctl start flow2api-host-agent-browser
systemctl start flow2api-host-agent-ui
```

然后访问：

```text
http://你的服务器IP:38110/login
```

### 5. 登录 Google Labs 并手动刷新一次

- 在登录向导页面中完成 Google 登录
- 回到仪表盘点击 **立即刷新 Token**
- 看到成功即可

### 6. 启动自动刷新 daemon

```bash
systemctl start flow2api-host-agent
```

---

## 它和 Flow2API 的关系

- **Flow2API**：主体服务，负责模型路由、token 管理、API 能力
- **Flow2API Host Agent**：宿主机侧辅助服务，负责维护浏览器登录态并把最新 session token 推回 Flow2API

也就是说：

> 如果你已经有 Flow2API，这个项目安装好以后就能直接配合使用。

它不是 Flow2API 的替代品，而是外挂式 companion service。

---

## 核心能力

- 维护 Google Labs 登录浏览器 profile
- 通过 Chrome DevTools Protocol 读取 `__Secure-next-auth.session-token`
- 调用 Flow2API 的 `/api/plugin/update-token` 自动更新 token
- **软预热优先**，避免频繁触发重新登录
- **拿不到 ST 才走激进兜底**
- **写后数据库回读校验**
- 提供 Web UI（仪表盘 / 登录向导 / 配置 / 帮助）
- 提供 `/api/status` 与 `/api/health`
- 支持 systemd 常驻
- 支持可选的每日维护性重启 timer

---

## Connection Token 怎么获取？

打开你的 Flow2API 管理后台：

1. 登录管理员账号
2. 进入 **设置**
3. 找到 **插件连接配置**
4. 复制 **连接 Token**

如果为空，就先生成一个再保存。

它的作用是：

> Host Agent 每次把 session token 推送回 Flow2API 时，Flow2API 用它验证“这个请求是不是你授权的来源”。

### 重要：这里填的是 token，不是 URL

**正确：**

```text
abc123xyz
```

**错误：**

```text
http://127.0.0.1:38000/api/plugin/update-token
```

---

## Web UI 页面说明

- **仪表盘**：看最近一次刷新结果和分层状态
- **登录向导**：首次使用 / 登录失效时用
- **配置**：修改 Flow2API 地址、Connection Token、noVNC 地址等
- **帮助 / 原理 / 稳定性**：解释它怎么工作、会不会越跑越重、为什么建议维护性重启

### 仪表盘现在会显示什么？

- 最近结果是否成功
- 写后校验是否通过
- 当前 AT 过期时间
- 页面预热是否异常
- 当前预热策略（soft / aggressive）
- 是否发生过重试
- ST 指纹与库内指纹是否一致

这意味着你看到的不再只是“HTTP 200”，而是**真正可用的成功证明**。

---

## API

### `GET /api/status`

返回当前 Chrome/CDP 状态和最近一次状态文件。

### `GET /api/health`

返回更适合排错的分层健康信息：

- Chrome / CDP 是否正常
- 最近一次刷新是否成功
- Connection Token 配置是否可疑
- Chrome binary 是否存在
- 当前运行时 Python 是哪个

---

## 可选：每日维护性重启

如果你希望进一步降低 Chrome 长时间运行的累积状态问题，可以开启：

```bash
systemctl enable --now flow2api-host-agent-selfheal.timer
```

默认计划时间：

- **每天 20:20 UTC**（约等于北京时间 04:20）

它会重启：
- `flow2api-host-agent.service`
- `flow2api-host-agent-ui.service`

这是一个偏稳妥的长期运行策略。

---

## 注意事项

### 不要把 noVNC 地址写成 localhost

如果你是用手机或另一台设备访问登录页，`novnc_url` 不能写成：

```toml
novnc_url = "http://localhost:6080/..."
```

因为这会让浏览器去访问**你自己设备的 localhost**，不是服务器。

正确方式应该是：

```toml
novnc_url = "http://你的服务器IP:6080/vnc.html?autoconnect=true&resize=scale&quality=6"
```

### 主要资源开销来自 Chrome

- Python daemon：轻
- Web UI：轻
- 大头是 Chrome / renderer / GPU 相关进程

所以如果长期运行，建议保留每日维护性重启方案。

---

## 常见问题

### 1）为什么有时会被带到 Google 登录页？

旧版预热逻辑过于激进，可能每次都主动碰 Google 登录流。

新版已经调整为：
- **默认 soft prewarm**：优先复用现有状态
- **只有拿不到 ST 才 aggressive fallback**

因此不会再动不动就要求重新登录。

### 2）什么才算真正成功？

不是只看返回 200，而是要同时满足：

- `/api/plugin/update-token` 返回成功
- 能解析出业务成功结果
- Flow2API 数据库回读成功
- 当前 ST 指纹与库内 ST 指纹一致

### 3）为什么会报 `Invalid connection token`？

通常是因为你把 `Connection Token` 填成了 URL，而不是 token 字符串。

### 4）怎么快速自检？

```bash
curl http://127.0.0.1:38110/api/health
```

---

## 适用前提

你需要先有：

1. **一台 Linux 服务器**
2. **已部署好的 Flow2API**
3. **Google Chrome / Chromium**
4. **Xvfb / noVNC**（用于服务器上的浏览器登录）

---

## 目录结构

- `scripts/`：CLI 与核心逻辑
- `web/`：Web UI
- `systemd/`：systemd service / timer 模板
- `docs/`：设计与部署文档
- `install-systemd.sh`：一键安装脚本

---

## License

MIT

## Web UI 内置更新

现在 38110 Web UI 已支持：

- `检查更新`：检查 GitHub latest release
- `一键更新`：拉取 latest release tarball 并覆盖当前项目
- `自动备份`：更新前备份到 `backups/backup-时间戳/`
- `自动回滚`：更新后如果 UI 探活失败，会自动回滚并重启服务

### 更新来源

优先读取 `agent.toml` 中的：

```toml
github_repo = "muyouzhi6/flow2api-host-agent"
```

如果未填写，会自动读取当前 git remote `origin`。

### 推荐做法

- 生产机保持代码尽量对齐正式 release，不要长期停留在 `-dirty` 状态
- 每次改动合并后发布新 tag / release，再让面板去跟最新 release
- 更新成功后观察 `/api/health` 是否保持 `ok=true`
