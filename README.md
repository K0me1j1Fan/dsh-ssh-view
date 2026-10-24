# SSH 服务器视图 · DSH 插件

在 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的 Web 界面里，通过 SSH 密码登录一台无头 Linux 服务器，用整页视图完成日常运维：

- 浏览、上传、下载、编辑服务器文件
- 查看进程、排序过滤、结束进程
- tail 任意日志文件并跟随刷新
- 连接配置可选加密落盘，密码永不下发到浏览器

插件注册在 DSH 的 `main` 主面板与 `sidebar.panellist` 侧边栏，样式只使用 DSH 主题 token，自动跟随浅色 / 深色主题。

---

## 功能

| 模块 | 能力 |
| --- | --- |
| 连接 | 主机 / 端口 / 用户名 / 密码；多套连接配置；一键重连；主机指纹 TOFU 校验 |
| 文件 | 目录浏览、面包屑与路径跳转、新建文件 / 文件夹、重命名、移动、递归删除、上传、下载 |
| 编辑 | 内置文本编辑器，`Ctrl/Cmd+S` 保存；按内容哈希检测并发修改，冲突时提示重新加载或强制覆盖；二进制与超大文件改为提示下载 |
| 进程 | `ps` 列表（PID、用户、CPU%、内存%、RSS、运行时长、状态、命令行），排序、过滤、定时刷新；SIGTERM / SIGKILL，二次确认，拒绝 PID 1 |
| 日志 | 任意日志文件 tail 末尾 N 行，可定时跟随；自动探测常见日志路径 |
| 安全 | 密码只在 Host 进程内存；凭据库 AES-256-GCM 加密；`/api` 路由走 DSH 浏览器会话鉴权；路径与命令注入防护 |

## 环境要求

- **DSH**：`0.2.0-rc.2` 上开发与验证（需要 `connection`、`webServer`、`clientModules` 等 Web 组合）
- **Node.js**：>= 20（DSH 自带 Node 22）
- **目标服务器**：
  - Linux，OpenSSH（启用 `Subsystem sftp`）
  - `procps`（提供 `ps -eo`、`kill`）；BusyBox 环境会退化为 `ps aux`
  - 不要求 systemd：日志按文件 tail，不依赖 journald
  - 需要 SSH 密码登录（支持 `password` 与 `keyboard-interactive`）
- **网络**：运行 DSH 的机器能访问目标 SSH 端口

## 安装

### 方式一：直接从 GitHub 安装（推荐）

DSH 的插件管理器支持 git 规格，无需先克隆：

```bash
dsh plugin --profile web add github:<your-name>/dsh-ssh-view

# 没有全局 dsh 时
npx @deepseek-ai/dsh plugin --profile web add github:<your-name>/dsh-ssh-view
```

> 固定版本可以写 `github:<your-name>/dsh-ssh-view#v0.1.0`。

安装完成后：

1. 刷新一次 Web 页面（新客户端插件需要重新加载）。
2. 左侧边栏出现服务器形状的「服务器视图」图标。
3. 点击图标即可打开连接页。

### 方式二：本地克隆安装（开发用）

```bash
git clone https://github.com/<your-name>/dsh-ssh-view.git
cd dsh-ssh-view
npm install                     # 安装 ssh2
dsh plugin --profile web add "$PWD"
```

也可以在 DSH 插件管理界面选择「安装本地 bundle」，指向本目录。

> 以本地目录（`link:`）方式安装时，profile 只创建软链接，不会安装本包依赖，
> 因此请保留本目录下的 `node_modules/`（由 `npm install` 生成）。

### 发布到 npm（可选）

包名已对齐为 `dsh-ssh-view`。去掉 `package.json` 的 `"private": true` 后执行 `npm publish`，
其他用户即可用包名安装：

```bash
dsh plugin --profile web add dsh-ssh-view
```

> `client.js` 中 `window.__ModuleLoader__.load({ id })` 的 id 必须与 `package.json` 的 `name` 完全一致；
> 改包名时三处要同步：`package.json`、`client.js`、`cordis.patch.yml`。

## 快速使用

1. （可选）点「设置主密码」，创建加密凭据库。
2. 填写主机 / 端口 / 用户名 / 密码；勾选「加密保存此连接」可在下次一键连接。
3. 连接成功后：
   - **文件**：双击目录进入，双击文本文件打开编辑器；工具栏可上传、下载、重命名、移动、删除。
   - **进程**：搜索框过滤，点击列头排序；行尾停止按钮选择 SIGTERM / SIGKILL 并确认。
   - **日志**：输入绝对路径或点「常用日志」，勾选「跟随刷新」每 2.5 秒重读末尾 N 行。

## 配置

`cordis.patch.yml` 中 `ssh-view` 行的 `config`（均可选）：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `dataDir` | `$DSH_HOME/storages/ssh-view` | `vault.json` 与 `hosts.json` 所在目录 |
| `connectTimeoutMs` | `20000` | SSH 连接超时（含握手） |
| `autoLockMinutes` | `15` | 凭据库闲置自动锁定；`0` 关闭 |
| `maxTextBytes` | `2097152` | 编辑器可打开 / 保存的单文件上限（2 MB） |
| `maxUploadBytes` | `1073741824` | 单次上传上限（1 GB） |
| `maxExecBytes` | `4194304` | 单条命令输出缓冲上限 |
| `maxTailBytes` | `1048576` | 日志 tail 输出上限 |
| `maxDirEntries` | `5000` | 单目录列出的最大条目数 |

示例（覆盖默认 dataDir）：

```yaml
- id: ssh-view
  config:
    dataDir: /var/lib/dsh/ssh-view
    autoLockMinutes: 30
```

## 安全模型

### 威胁边界

- 受保护：磁盘上的连接配置、浏览器侧、DSH 的 `/api` 入口、远端命令注入。
- 不在防护范围：Host 进程本身被攻破（解锁期间密钥在内存）、SSH 账号本身拥有的权限、
  DSH Web 被暴露到不可信网络。

### 凭据存储

启用主密码后，配置写入 `$DSH_HOME/storages/ssh-view/vault.json`（目录 `0700`、文件 `0600`）：

- 密钥：`scrypt(N=32768, r=8, p=1)` 派生 32 字节
- 加密：`AES-256-GCM`，随机 96-bit IV，附加认证数据绑定文件版本
- 主密码与派生密钥**不落盘**；文件里只有盐、IV、认证标签和密文
- 整份配置（主机、端口、用户名、密码）一起加密，`hosts.json` 只存主机指纹
- 主密码错误或文件被篡改时 GCM 校验失败，拒绝解锁
- 闲置超过 `autoLockMinutes` 自动锁定；手动「锁定」立即清零内存密钥；插件卸载时锁定

未创建 / 未解锁凭据库时仍可连接，但配置只存在进程内存，DSH 重启后需重新输入。

### 浏览器与 Host

- 三条 HTTP 路由都注册在 `ctx.connection.fetch` 上：
  - `POST /api/ssh-view.rpc`
  - `POST /api/ssh-view.upload`
  - `GET|HEAD /api/ssh-view.download`
- 它们继承 DSH Connection 的浏览器会话 cookie 鉴权与 Host/Origin 校验，没有额外端口。
- `state` 只返回 `hasPassword: boolean`，**密码永远不会回传给浏览器**。

### 远端操作

- 主机指纹采用 TOFU：首次连接记录 SHA256 指纹，之后不一致即中止，需在界面显式信任。
- 远端路径必须是绝对路径，统一 POSIX 归一化；删除 / 重命名禁止系统根目录与用户主目录。
- 远端命令只拼接校验过的整数（PID、行数）与 POSIX 单引号转义的路径。
- 不做 sudo / 提权：SSH 用户能做什么，这个视图就能做什么。建议使用最小权限账号。

### 使用建议

- DSH Web 只监听回环地址（默认 `127.0.0.1`），不要用 `--host 0.0.0.0` 暴露到不可信网络。
- 主密码使用独立的高强度口令，不与其他账号复用。
- 不要把 `vault.json`、`hosts.json` 复制进仓库或发给他人（`.gitignore` 已兜底忽略）。
- 不需要保存配置时，不勾选「加密保存」，连接密码只留在内存。

## 数据位置

| 文件 | 位置 | 内容 | 权限 |
| --- | --- | --- | --- |
| `vault.json` | `$DSH_HOME/storages/ssh-view/` | 加密后的连接配置（可选） | `0600` |
| `hosts.json` | `$DSH_HOME/storages/ssh-view/` | 主机指纹（非机密，用于防 MITM） | `0600` |

## 故障排查

| 现象 | 原因与处理 |
| --- | --- |
| 「端口 … 接受了 TCP 连接，但没有返回 SSH 协议标识」 | 该端口不是 SSH（例如把 Minecraft 的 25565 当成了 SSH 端口）。SSH 默认 22，或查看远端 `sshd_config` 的 `Port`。 |
| 「连接超时 / 主机不可达或端口被防火墙拦截」 | 端口被防火墙丢弃，或 Host 到目标网络不通。先用 `nc -vz <host> <port>` 验证。 |
| 「用户名或密码错误」 | 密码错误，或远端禁用了密码登录（`PasswordAuthentication no`）。 |
| 「主机指纹与已保存的不一致」 | 服务器重装或更换了密钥。确认变更属实后点「信任新指纹并重试」。 |
| 「SFTP 不可用」 | 远端未启用 SFTP 子系统。检查 `sshd_config` 中的 `Subsystem sftp /usr/lib/openssh/sftp-server`。 |
| 进程页读取失败 | 远端缺少 `procps`；安装后重试。 |
| 刷新页面后没有图标 | 首次安装客户端插件需要刷新；确认 `web` profile 的 `package.json` 中 bundles 含 `dsh-ssh-view`。 |
| 修改 Host 代码后行为未变 | Host 模块在进程内缓存，改动后需重启 DSH。 |

## 开发与测试

Host 侧逻辑有真实 OpenSSH + SFTP 的端到端测试；客户端模块有独立的注册测试。

```bash
npm install

# 1) 启动一台本地测试 SSH 服务器（Docker）
docker run -d --name dsh-ssh-test -p 127.0.0.1:2222:2222 alpine:3.20 sh -c "
  apk add --no-cache openssh procps &&
  ssh-keygen -A &&
  echo 'root:test-password-123' | chpasswd &&
  printf 'PasswordAuthentication yes\nPermitRootLogin yes\n' >> /etc/ssh/sshd_config &&
  exec /usr/sbin/sshd -D -e -p 2222"

# 2) 端到端：凭据库、指纹、SFTP、上传下载、进程、日志、路径防护、RPC 路由
node test/ssh-view.e2e.mjs

# 3) 客户端模块：能否注册主面板、侧边栏与双语文案
node test/ssh-view.client-module.mjs
```

`test/ssh-view.e2e.mjs` 默认连接 `127.0.0.1:2222`（`root` / `test-password-123`），
可用 `E2E_HOST`、`E2E_PORT`、`E2E_USER`、`E2E_PASSWORD` 覆盖。
测试只读写远端 `/tmp/dsh-view-e2e`，并只结束测试自己启动的 `sleep` 进程。

## 项目结构

```
.
├── index.js              # Host 入口：注册 /api 路由、装配服务
├── client.js             # 浏览器入口：主面板页面、侧边栏图标、双语文案
├── lib/
│   ├── vault.js          # scrypt + AES-256-GCM 凭据库
│   ├── ssh.js            # SSH 会话：探测、密码登录、主机指纹、exec、SFTP
│   └── service.js        # 连接管理、文件、进程、日志、RPC 分发
├── locale/               # 插件卡片标题与描述（en / zh）
├── cordis.patch.yml      # bundle patch：插入 ssh-view 行
├── icon.svg              # 插件图标
└── test/                 # 端到端与客户端模块测试
```

## 已知限制

- 一次只维持一条 SSH 连接，切换连接会断开上一条。
- 不支持 SSH 私钥登录、跳板机、sudo 提权、systemd / Docker 服务管理。
- 日志跟随是客户端定时重读末尾 N 行（2.5s），不是服务端流式推送。
- 单文件编辑上限 2 MB；更大的文件请下载后处理。
- 进程结束仅支持 SIGTERM / SIGKILL；受 SSH 用户权限限制。
- 未提供 AI agent 工具，所有操作只通过界面由人触发。

## License

[MIT](LICENSE) © 2026 dsh-ssh-view contributors

你可以自由使用、修改、分发和商用，只需保留版权声明与许可证文本；软件按「原样」提供，不附带担保。
