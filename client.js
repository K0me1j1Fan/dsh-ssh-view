/**
 * Browser half of the SSH server view.
 *
 * Renders a full main-panel page plus its sidebar entry. All server access goes
 * through the authenticated `/api` routes registered by the Host half; this
 * module never sees a stored password.
 */
window.__ModuleLoader__.load({
  id: 'dsh-ssh-view',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const NS = 'ssh-view'
    const PANEL_ID = 'ssh-view'
    const RPC = 'api/ssh-view.rpc'
    const UPLOAD = 'api/ssh-view.upload'
    const DOWNLOAD = 'api/ssh-view.download'

    const ZH = {
      panel: '服务器视图',
      'tab.files': '文件',
      'tab.processes': '进程',
      'tab.logs': '日志',
      'common.refresh': '刷新',
      'common.close': '关闭',
      'common.cancel': '取消',
      'common.confirm': '确认',
      'common.delete': '删除',
      'common.save': '保存',
      'common.loading': '加载中…',
      'common.retry': '重试',
      'common.unlock': '解锁',
      'common.lock': '锁定',
      'common.connect': '连接',
      'common.disconnect': '断开',
      'common.connecting': '连接中…',
      'common.connected': '已连接',
      'common.disconnected': '未连接',
      'common.search': '搜索',
      'common.optional': '可选',
      'common.busy': '处理中…',
      'conn.title': '连接到服务器',
      'conn.saved': '已保存的连接',
      'conn.empty': '还没有保存的连接。填写下面的表单即可连接。',
      'conn.name': '名称',
      'conn.host': '主机 / IP',
      'conn.port': '端口',
      'conn.user': '用户名',
      'conn.password': '密码',
      'conn.remember': '加密保存此连接',
      'conn.rememberHint': '需要先解锁或创建主密码；密码只以密文写入磁盘。',
      'conn.auth': '认证方式',
      'conn.auth.password': '密码',
      'conn.auth.agent': 'SSH 密钥',
      'conn.agentHint': '使用系统 ssh-agent 中已加载的密钥；插件不保存密码或私钥。',
      'conn.agentUnavailable': '未检测到可用的 ssh-agent 或 ~/.ssh 私钥。',
      'conn.agentReady': 'ssh-agent 就绪',
      'conn.agentReadyKey': '将使用 ~/.ssh 私钥',
      'conn.rememberAgent': '保存此连接（不含密钥）',
      'conn.rememberAgentHint': '只保存主机、端口和用户名，用于下次自动连接。',
      'conn.autoConnect': 'DSH 启动后自动连接',
      'conn.autoConnectHint': '仅对 SSH 密钥连接生效；密码连接仍需解锁凭据库。',
      'conn.autoConnectFailed': '自动连接失败',
      'conn.lastProfile': '自动连接',
      'conn.retry': '重试',
      'conn.vaultOptional': '只有密码登录需要主密码；SSH 密钥登录不需要凭据库。',
      'conn.vaultLockedHint': '凭据库已锁定，已保存的连接不可见。解锁后可一键连接。',
      'conn.memoryOnly': '仅本次运行',
      'conn.encrypted': '已加密保存',
      'conn.noPassword': '未保存密码',
      'conn.deleteProfile': '删除此连接',
      'conn.deleteConfirm': '确定删除连接「{name}」？',
      'conn.new': '新建连接',
      'conn.clear': '清空表单',
      'conn.passwordRequired': '请输入登录密码。',
      'conn.passwordHint': '留空则使用已保存的密码。',
      'conn.fingerprint': '主机指纹',
      'vault.create': '设置主密码',
      'vault.unlock': '解锁凭据库',
      'vault.passphrase': '主密码',
      'vault.confirmPassphrase': '再次输入主密码',
      'vault.hint': '主密码用于加密连接配置，不会写入磁盘；忘记后只能删除凭据库重建。',
      'vault.weak': '主密码至少需要 8 个字符。',
      'vault.mismatch': '两次输入的主密码不一致。',
      'vault.locked': '凭据库已锁定',
      'vault.unlocked': '凭据库已解锁',
      'vault.missing': '未设置主密码',
      'vault.createHint': '设置主密码后，连接配置会以 AES-256-GCM 密文保存到本机。',
      'vault.unlockedToast': '凭据库已解锁',
      'vault.createdToast': '凭据库已创建',
      'vault.lockedToast': '凭据库已锁定',
      'files.open': '打开',
      'files.download': '下载',
      'files.upload': '上传',
      'files.rename': '重命名',
      'files.move': '移动',
      'files.delete': '删除',
      'files.newFolder': '新建文件夹',
      'files.newFile': '新建文件',
      'files.name': '名称',
      'files.size': '大小',
      'files.modified': '修改时间',
      'files.mode': '权限',
      'files.path': '路径',
      'files.home': '主目录',
      'files.parent': '上一级',
      'files.empty': '空目录',
      'files.uploading': '上传中…',
      'files.renamePrompt': '新名称',
      'files.movePrompt': '目标完整路径',
      'files.folderPrompt': '文件夹名称',
      'files.filePrompt': '文件名',
      'files.deleteConfirm': '确定删除「{path}」？',
      'files.deleteDirConfirm': '目录「{path}」及其全部内容将被递归删除，确定继续？',
      'files.overwriteConfirm': '「{name}」已存在，确定覆盖？',
      'files.binary': '这是二进制文件，无法在编辑器中打开，可以下载后查看。',
      'files.tooLarge': '文件超过可编辑大小上限（{size}），可以下载后编辑。',
      'files.uploaded': '已上传 {name}',
      'files.extract': '解压',
      'files.extractTitle': '解压归档',
      'files.extractTo': '解压到',
      'files.extractOverwrite': '覆盖目标目录中的同名文件',
      'files.extracting': '解压中…',
      'files.extractDone': '已解压 {count} 个条目到 {target}',
      'files.extractHint': '默认解压到归档同目录下的同名文件夹；目标目录非空时需要勾选覆盖。',
      'files.saved': '文件已保存',
      'editor.title': '编辑文件',
      'editor.save': '保存',
      'editor.revert': '重新加载',
      'editor.overwrite': '覆盖保存',
      'editor.dirty': '有未保存的修改',
      'editor.conflict': '文件在打开后已被修改。可以重新加载，或确认覆盖保存。',
      'editor.closeConfirm': '有未保存的修改，确定关闭？',
      'editor.download': '下载',
      'proc.pid': 'PID',
      'proc.user': '用户',
      'proc.cpu': 'CPU%',
      'proc.mem': '内存%',
      'proc.rss': 'RSS',
      'proc.elapsed': '运行时长',
      'proc.stat': '状态',
      'proc.command': '命令',
      'proc.kill': '结束进程',
      'proc.killConfirm': '确定向进程 {pid} 发送 SIG{signal}？',
      'proc.filter': '过滤 PID、用户或命令',
      'proc.interval': '刷新间隔',
      'proc.off': '不自动刷新',
      'proc.load': '负载',
      'proc.uptime': '运行时间',
      'proc.memory': '内存',
      'proc.count': '进程数',
      'proc.signal.term': 'SIGTERM（请求退出）',
      'proc.signal.kill': 'SIGKILL（强制结束）',
      'proc.killed': '已向进程 {pid} 发送 SIG{signal}',
      'logs.path': '日志文件路径',
      'logs.lines': '行数',
      'logs.follow': '跟随刷新',
      'logs.load': '读取',
      'logs.presets': '常用日志',
      'logs.empty': '输入日志路径或选择常用日志后读取。',
      'logs.truncated': '输出已截断，只保留了末尾部分。',
      'logs.noPresets': '未发现常用日志文件。',
      'logs.updated': '更新于 {time}',
      'logs.size': '大小 {size}',
      'host.mismatch': '主机指纹不一致',
      'host.forget': '信任新指纹并重试',
      'host.forgotten': '已清除旧指纹，正在重试…',
      'error.title': '操作失败',
      'error.unauthorized': '浏览器会话已失效，请刷新页面。',
    }

    const EN = {
      panel: 'Server view',
      'tab.files': 'Files',
      'tab.processes': 'Processes',
      'tab.logs': 'Logs',
      'common.refresh': 'Refresh',
      'common.close': 'Close',
      'common.cancel': 'Cancel',
      'common.confirm': 'Confirm',
      'common.delete': 'Delete',
      'common.save': 'Save',
      'common.loading': 'Loading…',
      'common.retry': 'Retry',
      'common.unlock': 'Unlock',
      'common.lock': 'Lock',
      'common.connect': 'Connect',
      'common.disconnect': 'Disconnect',
      'common.connecting': 'Connecting…',
      'common.connected': 'Connected',
      'common.disconnected': 'Disconnected',
      'common.search': 'Search',
      'common.optional': 'optional',
      'common.busy': 'Working…',
      'conn.title': 'Connect to a server',
      'conn.saved': 'Saved connections',
      'conn.empty': 'No saved connections yet. Fill in the form below to connect.',
      'conn.name': 'Name',
      'conn.host': 'Host / IP',
      'conn.port': 'Port',
      'conn.user': 'Username',
      'conn.password': 'Password',
      'conn.remember': 'Encrypt and save this connection',
      'conn.rememberHint': 'Requires an unlocked master passphrase; the password is written only as ciphertext.',
      'conn.auth': 'Authentication',
      'conn.auth.password': 'Password',
      'conn.auth.agent': 'SSH key',
      'conn.agentHint': 'Uses a key already loaded in the system ssh-agent; no password or private key is stored.',
      'conn.agentUnavailable': 'No usable ssh-agent or ~/.ssh private key was found.',
      'conn.agentReady': 'ssh-agent ready',
      'conn.agentReadyKey': 'Falls back to the ~/.ssh key',
      'conn.rememberAgent': 'Save this connection (no secret)',
      'conn.rememberAgentHint': 'Stores only host, port and username for the next automatic connection.',
      'conn.autoConnect': 'Reconnect when DSH starts',
      'conn.autoConnectHint': 'Applies to SSH-key connections only; password connections still need the vault.',
      'conn.autoConnectFailed': 'Automatic connection failed',
      'conn.lastProfile': 'Auto',
      'conn.retry': 'Retry',
      'conn.vaultOptional': 'Only password logins need the master passphrase; SSH-key logins do not.',
      'conn.vaultLockedHint': 'The credential vault is locked, so saved connections are hidden. Unlock it to connect in one click.',
      'conn.memoryOnly': 'This run only',
      'conn.encrypted': 'Encrypted',
      'conn.noPassword': 'No saved password',
      'conn.deleteProfile': 'Delete connection',
      'conn.deleteConfirm': 'Delete the connection "{name}"?',
      'conn.new': 'New connection',
      'conn.clear': 'Clear form',
      'conn.passwordRequired': 'Enter the login password.',
      'conn.passwordHint': 'Leave blank to use the saved password.',
      'conn.fingerprint': 'Host fingerprint',
      'vault.create': 'Set master passphrase',
      'vault.unlock': 'Unlock vault',
      'vault.passphrase': 'Master passphrase',
      'vault.confirmPassphrase': 'Repeat master passphrase',
      'vault.hint': 'The master passphrase encrypts the connection profiles. It is never written to disk; if lost, the vault must be deleted and rebuilt.',
      'vault.weak': 'The master passphrase needs at least 8 characters.',
      'vault.mismatch': 'The two passphrases do not match.',
      'vault.locked': 'Vault locked',
      'vault.unlocked': 'Vault unlocked',
      'vault.missing': 'No master passphrase',
      'vault.createHint': 'With a master passphrase, connection profiles are stored on this machine as AES-256-GCM ciphertext.',
      'vault.unlockedToast': 'Vault unlocked',
      'vault.createdToast': 'Vault created',
      'vault.lockedToast': 'Vault locked',
      'files.open': 'Open',
      'files.download': 'Download',
      'files.upload': 'Upload',
      'files.rename': 'Rename',
      'files.move': 'Move',
      'files.delete': 'Delete',
      'files.newFolder': 'New folder',
      'files.newFile': 'New file',
      'files.name': 'Name',
      'files.size': 'Size',
      'files.modified': 'Modified',
      'files.mode': 'Mode',
      'files.path': 'Path',
      'files.home': 'Home',
      'files.parent': 'Up',
      'files.empty': 'Empty directory',
      'files.uploading': 'Uploading…',
      'files.renamePrompt': 'New name',
      'files.movePrompt': 'Full destination path',
      'files.folderPrompt': 'Folder name',
      'files.filePrompt': 'File name',
      'files.deleteConfirm': 'Delete "{path}"?',
      'files.deleteDirConfirm': 'The directory "{path}" and everything inside it will be deleted. Continue?',
      'files.overwriteConfirm': '"{name}" already exists. Overwrite it?',
      'files.binary': 'This is a binary file. Download it to inspect it.',
      'files.tooLarge': 'The file exceeds the editable size limit ({size}). Download it to edit it.',
      'files.uploaded': 'Uploaded {name}',
      'files.extract': 'Extract',
      'files.extractTitle': 'Extract archive',
      'files.extractTo': 'Extract to',
      'files.extractOverwrite': 'Overwrite existing files in the target',
      'files.extracting': 'Extracting…',
      'files.extractDone': 'Extracted {count} entries to {target}',
      'files.extractHint': 'Defaults to a folder named after the archive next to it; a non-empty target needs the overwrite option.',
      'files.saved': 'File saved',
      'editor.title': 'Edit file',
      'editor.save': 'Save',
      'editor.revert': 'Reload',
      'editor.overwrite': 'Overwrite',
      'editor.dirty': 'Unsaved changes',
      'editor.conflict': 'The file changed after it was opened. Reload it, or overwrite it deliberately.',
      'editor.closeConfirm': 'Discard unsaved changes and close?',
      'editor.download': 'Download',
      'proc.pid': 'PID',
      'proc.user': 'User',
      'proc.cpu': 'CPU%',
      'proc.mem': 'MEM%',
      'proc.rss': 'RSS',
      'proc.elapsed': 'Elapsed',
      'proc.stat': 'State',
      'proc.command': 'Command',
      'proc.kill': 'Kill',
      'proc.killConfirm': 'Send SIG{signal} to process {pid}?',
      'proc.filter': 'Filter PID, user or command',
      'proc.interval': 'Refresh interval',
      'proc.off': 'No auto refresh',
      'proc.load': 'Load',
      'proc.uptime': 'Uptime',
      'proc.memory': 'Memory',
      'proc.count': 'Processes',
      'proc.signal.term': 'SIGTERM (graceful)',
      'proc.signal.kill': 'SIGKILL (force)',
      'proc.killed': 'Sent SIG{signal} to process {pid}',
      'logs.path': 'Log file path',
      'logs.lines': 'Lines',
      'logs.follow': 'Follow',
      'logs.load': 'Read',
      'logs.presets': 'Common logs',
      'logs.empty': 'Enter a log path or pick a common log, then read it.',
      'logs.truncated': 'Output was truncated; only the tail is shown.',
      'logs.noPresets': 'No common log files found.',
      'logs.updated': 'Updated {time}',
      'logs.size': 'Size {size}',
      'host.mismatch': 'Host fingerprint mismatch',
      'host.forget': 'Trust the new fingerprint and retry',
      'host.forgotten': 'Old fingerprint cleared, retrying…',
      'error.title': 'Operation failed',
      'error.unauthorized': 'The browser session expired. Reload the page.',
    }

    const TContext = React.createContext((key) => key)

    function useT() {
      return React.useContext(TContext)
    }

    /** Interpolate `{name}` placeholders. */
    function tf(t, key, vars) {
      let text = t(key)
      if (vars) {
        for (const name of Object.keys(vars)) text = text.split(`{${name}}`).join(String(vars[name]))
      }
      return text
    }

    class ApiError extends Error {
      constructor(code, message, details) {
        super(message)
        this.name = 'ApiError'
        this.code = code
        this.details = details
      }
    }

    function endpoint(path) {
      return new URL(path, document.baseURI)
    }

    async function readJson(response) {
      let data = null
      try {
        data = await response.json()
      } catch {
        data = null
      }
      if (!response.ok) {
        if (response.status === 401) throw new ApiError('unauthorized', '浏览器会话已失效，请刷新页面。')
        const error = data && data.error ? data.error : {}
        throw new ApiError(error.code || 'http', error.message || `HTTP ${response.status}`, error.details)
      }
      if (!data || data.ok !== true) {
        const error = data && data.error ? data.error : {}
        throw new ApiError(error.code || 'error', error.message || '操作失败。', error.details)
      }
      return data.value
    }

    async function rpc(op, params) {
      const response = await fetch(endpoint(RPC), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ op, params: params || {} }),
        credentials: 'same-origin',
      })
      return readJson(response)
    }

    async function uploadFile(path, file, overwrite) {
      const url = endpoint(UPLOAD)
      url.searchParams.set('path', path)
      if (overwrite) url.searchParams.set('overwrite', 'true')
      const response = await fetch(url, { method: 'POST', body: file, credentials: 'same-origin' })
      return readJson(response)
    }

    function downloadFile(path) {
      const url = endpoint(DOWNLOAD)
      url.searchParams.set('path', path)
      const anchor = document.createElement('a')
      anchor.href = url.href
      anchor.download = path.split('/').pop() || 'download'
      anchor.rel = 'noopener'
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
    }

    const ARCHIVE_SUFFIXES = ['.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tbz', '.tar.xz', '.txz', '.tar', '.zip', '.gz', '.bz2', '.xz']

    function isArchiveName(name) {
      const lower = String(name).toLowerCase()
      return ARCHIVE_SUFFIXES.some((suffix) => lower.endsWith(suffix))
    }

    function archiveStemName(name) {
      const lower = String(name).toLowerCase()
      for (const suffix of ARCHIVE_SUFFIXES) {
        if (lower.endsWith(suffix)) return name.slice(0, name.length - suffix.length) || 'extracted'
      }
      return name
    }

    function formatSize(bytes) {
      const value = Number(bytes) || 0
      if (value < 1024) return `${value} B`
      const units = ['KB', 'MB', 'GB', 'TB']
      let scaled = value / 1024
      let index = 0
      while (scaled >= 1024 && index < units.length - 1) {
        scaled /= 1024
        index += 1
      }
      return `${scaled >= 100 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[index]}`
    }

    function formatDuration(seconds) {
      if (seconds === null || seconds === undefined || !Number.isFinite(Number(seconds))) return '—'
      let rest = Math.max(0, Math.trunc(Number(seconds)))
      const days = Math.floor(rest / 86400)
      rest %= 86400
      const hours = Math.floor(rest / 3600)
      rest %= 3600
      const minutes = Math.floor(rest / 60)
      const secs = rest % 60
      if (days > 0) return `${days}d ${hours}h`
      if (hours > 0) return `${hours}h ${minutes}m`
      if (minutes > 0) return `${minutes}m ${secs}s`
      return `${secs}s`
    }

    function formatTime(seconds) {
      if (!seconds) return '—'
      try {
        return new Date(Number(seconds) * 1000).toLocaleString()
      } catch {
        return '—'
      }
    }

    function formatClock(ms) {
      if (!ms) return '—'
      try {
        return new Date(Number(ms)).toLocaleTimeString()
      } catch {
        return '—'
      }
    }

    function parentOf(path) {
      if (!path || path === '/') return null
      const index = path.replace(/\/+$/, '').lastIndexOf('/')
      if (index <= 0) return '/'
      return path.slice(0, index)
    }

    function joinPath(dir, name) {
      if (dir.endsWith('/')) return `${dir}${name}`
      return `${dir}/${name}`
    }

    function baseName(path) {
      if (!path) return ''
      const trimmed = path.replace(/\/+$/, '')
      return trimmed.slice(trimmed.lastIndexOf('/') + 1) || '/'
    }

    function crumbs(path) {
      if (!path || path === '/') return [{ label: '/', path: '/' }]
      const parts = path.split('/').filter(Boolean)
      const rows = [{ label: '/', path: '/' }]
      let current = ''
      for (const part of parts) {
        current += `/${part}`
        rows.push({ label: part, path: current })
      }
      return rows
    }

    function cx() {
      return Array.prototype.filter.call(arguments, Boolean).join(' ')
    }

    function icon(paths, size) {
      return h(
        'svg',
        {
          viewBox: '0 0 16 16',
          width: size || 16,
          height: size || 16,
          fill: 'none',
          stroke: 'currentColor',
          strokeWidth: 1.3,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
          'aria-hidden': 'true',
          focusable: 'false',
        },
        paths.map((d, index) => h('path', { key: index, d })),
      )
    }

    const IconFolder = () => icon(['M1.8 4.2a1 1 0 0 1 1-1h3l1.4 1.6h5a1 1 0 0 1 1 1v5.6a1 1 0 0 1-1 1h-9.4a1 1 0 0 1-1-1z'])
    const IconFile = () => icon(['M4 1.8h4.6L12.2 5.4v8.8H4z', 'M8.6 1.8v3.6h3.6'])
    const IconServer = () => icon(['M2 3h12v4H2z', 'M2 9h12v4H2z', 'M4.2 5h.01', 'M4.2 11h.01'])
    const IconRefresh = () => icon(['M13 8a5 5 0 1 1-1.5-3.6', 'M13 2.5V5h-2.5'])
    const IconUpload = () => icon(['M8 11.5V2.8', 'M4.6 6.2 8 2.8l3.4 3.4', 'M2.5 13.2h11'])
    const IconDownload = () => icon(['M8 2.8v8.7', 'M4.6 8.1 8 11.5l3.4-3.4', 'M2.5 13.2h11'])
    const IconTrash = () => icon(['M2.8 4.2h10.4', 'M6 4.2V2.6h4v1.6', 'M4.2 4.2l.6 9h6.4l.6-9', 'M6.6 6.8v4.4', 'M9.4 6.8v4.4'])
    const IconEdit = () => icon(['M10.8 2.6 13.4 5.2 5.8 12.8H3.2v-2.6z', 'M9.6 3.8 12.2 6.4'])
    const IconX = () => icon(['M3.4 3.4l9.2 9.2', 'M12.6 3.4l-9.2 9.2'])
    const IconChevron = () => icon(['M6 3.6 10.4 8 6 12.4'])
    const IconLock = () => icon(['M4 7.2h8v6.2H4z', 'M5.8 7.2V5a2.2 2.2 0 0 1 4.4 0v2.2'])
    const IconUnlock = () => icon(['M4 7.2h8v6.2H4z', 'M5.8 7.2V5a2.2 2.2 0 0 1 4.3-.7'])
    const IconSearch = () => icon(['M7.2 2.6a4.6 4.6 0 1 0 0 9.2 4.6 4.6 0 0 0 0-9.2z', 'M10.6 10.6 13.6 13.6'])
    const IconAlert = () => icon(['M8 2.4 14 13H2z', 'M8 6.2v3.2', 'M8 11.2h.01'])
    const IconPlus = () => icon(['M8 3.2v9.6', 'M3.2 8h9.6'])
    const IconPlay = () => icon(['M5 3.4 12.2 8 5 12.6z'])
    const IconStop = () => icon(['M4.2 4.2h7.6v7.6H4.2z'])
    const IconArchive = () => icon(['M2.5 5.2h11v8.3h-11z', 'M2.5 8.3h11', 'M6.4 3.2h3.2', 'M6.6 11h2.8'])

    const CSS = `
.dsv_page{position:relative;box-sizing:border-box;width:100%;height:100%;min-width:0;min-height:0;display:flex;flex-direction:column;overflow:hidden;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-size:14px;line-height:1.6}
.dsv_header{flex:none;display:flex;flex-direction:column;gap:8px;padding:16px clamp(20px,3vw,36px) 10px;border-bottom:.5px solid var(--dsw-alias-border-l1)}
.dsv_headerRow{display:flex;align-items:center;gap:10px;flex-wrap:wrap;min-width:0}
.dsv_headerTitle{display:flex;align-items:center;gap:8px;min-width:0}
.dsv_headerTitle h1{margin:0;font-size:17px;font-weight:500;line-height:24px;white-space:nowrap}
.dsv_glyph{color:var(--dsw-alias-label-tertiary);display:inline-flex}
.dsv_meta{color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.dsv_meta strong{color:var(--dsw-alias-label-secondary);font-weight:500}
.dsv_spacer{flex:1;min-width:8px}
.dsv_dot{width:8px;height:8px;border-radius:50%;background:var(--dsw-alias-state-idle-primary);flex:none}
.dsv_dotOn{background:var(--dsw-alias-state-success-primary)}
.dsv_dotError{background:var(--dsw-alias-state-error-primary)}
.dsv_status{display:inline-flex;align-items:center;gap:6px;color:var(--dsw-alias-label-secondary);font-size:12px;white-space:nowrap}
.dsv_badge{display:inline-flex;align-items:center;gap:4px;height:20px;padding:0 8px;border-radius:10px;font-size:11px;line-height:20px;background:var(--dsw-alias-bg-module-platform);color:var(--dsw-alias-label-secondary);white-space:nowrap}
.dsv_badgeOn{background:var(--dsw-alias-state-success-tertiary);color:var(--dsw-alias-state-success-primary)}
.dsv_badgeWarn{background:var(--dsw-alias-state-warn-tertiary);color:var(--dsw-alias-state-warn-label)}
.dsv_btn{height:30px;padding:0 12px;border:none;border-radius:15px;background:transparent;color:var(--dsw-alias-label-primary);font:inherit;font-size:13px;line-height:20px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.dsv_btn:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}
.dsv_btn:disabled{color:var(--dsw-alias-label-caption);cursor:default}
.dsv_btnPrimary{background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground)}
.dsv_btnPrimary:hover:not(:disabled){background:var(--dsw-alias-button-primary-hover)}
.dsv_btnDanger{color:var(--dsw-alias-state-error-primary)}
.dsv_btnDanger:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover-danger)}
.dsv_iconBtn{width:28px;height:28px;padding:0;justify-content:center;border-radius:8px;flex:none}
.dsv_tabs{display:flex;align-items:center;gap:2px;flex-wrap:wrap}
.dsv_tab{height:30px;padding:0 12px;border:none;border-radius:15px;background:transparent;color:var(--dsw-alias-label-tertiary);font:inherit;font-size:13px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.dsv_tab:hover{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-secondary)}
.dsv_tabActive{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary)}
.dsv_body{flex:1;min-height:0;display:flex;flex-direction:column;padding:12px clamp(20px,3vw,36px) 14px;gap:8px}
.dsv_scroll{flex:1;min-height:0;overflow:auto;scrollbar-gutter:stable;--dsh-scrollbar-width:9px;--dsh-scrollbar-thumb-border:2px}
.dsv_content{max-width:1080px;margin:0 auto;padding:20px clamp(20px,3vw,36px) 48px}
.dsv_narrow{max-width:760px}
.dsv_card{border:.5px solid var(--dsw-alias-border-l2);border-radius:16px;padding:14px 16px;margin-bottom:14px;background:var(--dsw-alias-bg-base)}
.dsv_card h2{margin:0 0 10px;font-size:14px;font-weight:500;line-height:22px}
.dsv_cardHead{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.dsv_cardHead h2{margin:0;flex:1;min-width:0}
.dsv_fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}
.dsv_field{display:flex;flex-direction:column;gap:4px;min-width:0}
.dsv_fieldWide{grid-column:1/-1}
.dsv_label{font-size:12px;color:var(--dsw-alias-label-tertiary);line-height:18px}
.dsv_input,.dsv_select{box-sizing:border-box;height:32px;min-width:0;border:.5px solid var(--dsw-alias-border-l3);border-radius:10px;background:transparent;color:var(--dsw-alias-label-primary);font:inherit;font-size:13px;padding:0 10px}
.dsv_input:hover,.dsv_select:hover{border-color:var(--dsw-alias-border-l2)}
.dsv_input:focus,.dsv_select:focus{outline:none;border-color:var(--dsw-alias-state-business-primary)}
.dsv_input::placeholder{color:var(--dsw-alias-label-caption)}
.dsv_check{display:flex;align-items:flex-start;gap:8px;font-size:13px;line-height:20px;color:var(--dsw-alias-label-secondary);cursor:pointer;max-width:560px}
.dsv_check input{margin:3px 0 0;accent-color:var(--dsw-alias-state-business-primary);flex:none}
.dsv_checkText{display:flex;flex-direction:column;gap:2px;min-width:0}
.dsv_seg{display:inline-flex;align-items:center;gap:2px;padding:2px;border-radius:12px;background:var(--dsw-alias-bg-module-platform);flex-wrap:wrap}
.dsv_segBtn{height:26px;padding:0 10px;border:none;border-radius:10px;background:transparent;color:var(--dsw-alias-label-tertiary);font:inherit;font-size:12px;cursor:pointer;display:inline-flex;align-items:center;gap:5px}
.dsv_segBtn:hover:not(:disabled){color:var(--dsw-alias-label-primary)}
.dsv_segBtn:disabled{color:var(--dsw-alias-label-caption);cursor:default}
.dsv_segActive{background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);box-shadow:var(--dsw-elevation-soft)}
.dsv_hint{font-size:12px;line-height:18px;color:var(--dsw-alias-label-caption)}
.dsv_actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:12px}
.dsv_notice{display:flex;align-items:flex-start;gap:8px;border-radius:10px;padding:9px 12px;margin-bottom:12px;background:var(--dsw-alias-bg-module-platform);color:var(--dsw-alias-label-secondary);font-size:12px;line-height:20px}
.dsv_noticeIcon{flex:none;margin-top:2px;color:var(--dsw-alias-label-tertiary)}
.dsv_noticeError{background:var(--dsw-alias-interactive-bg-hover-danger);color:var(--dsw-alias-state-error-primary)}
.dsv_noticeError .dsv_noticeIcon{color:var(--dsw-alias-state-error-primary)}
.dsv_noticeWarn{color:var(--dsw-alias-state-warn-label)}
.dsv_noticeBody{flex:1;min-width:0;overflow-wrap:anywhere}
.dsv_noticeBody pre{white-space:pre-wrap;margin:4px 0 0;font-family:var(--ds-font-family-code);font-size:11px;line-height:17px}
.dsv_profile{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:12px;flex-wrap:wrap}
.dsv_profile:hover{background:var(--dsw-alias-interactive-bg-hover)}
.dsv_profileMain{display:flex;flex-direction:column;gap:1px;min-width:0;flex:1}
.dsv_profileName{font-size:13px;line-height:20px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dsv_profileHost{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary);font-family:var(--ds-font-family-code);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dsv_profileActions{display:flex;align-items:center;gap:4px;flex:none}
.dsv_toolbar{display:flex;align-items:center;gap:4px;flex-wrap:wrap;flex:none}
.dsv_toolbarSep{width:1px;height:18px;background:var(--dsw-alias-border-l2);margin:0 4px}
.dsv_crumbs{display:flex;align-items:center;gap:1px;flex-wrap:wrap;min-width:0;font-size:12px;color:var(--dsw-alias-label-tertiary)}
.dsv_crumb{border:none;background:none;color:var(--dsw-alias-label-secondary);font:inherit;font-size:12px;line-height:20px;cursor:pointer;padding:1px 5px;border-radius:6px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dsv_crumb:hover{background:var(--dsw-alias-interactive-bg-hover)}
.dsv_crumbSep{color:var(--dsw-alias-label-caption);padding:0 1px}
.dsv_pathRow{display:flex;align-items:center;gap:6px;flex:none}
.dsv_pathRow .dsv_input{flex:1}
.dsv_tableWrap{flex:1;min-height:0;overflow:auto;border:.5px solid var(--dsw-alias-border-l1);border-radius:12px;scrollbar-gutter:stable}
.dsv_table{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto}
.dsv_th{position:sticky;top:0;z-index:1;text-align:left;font-weight:500;font-size:12px;color:var(--dsw-alias-label-tertiary);background:var(--dsw-alias-bg-base);padding:7px 10px;border-bottom:.5px solid var(--dsw-alias-border-l2);white-space:nowrap;user-select:none}
.dsv_thBtn{border:none;background:none;font:inherit;font-size:12px;color:inherit;cursor:pointer;padding:0;display:inline-flex;align-items:center;gap:4px}
.dsv_thBtn:hover{color:var(--dsw-alias-label-primary)}
.dsv_td{padding:5px 10px;border-bottom:.5px solid var(--dsw-alias-border-l1);vertical-align:middle;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dsv_tr:hover .dsv_td{background:var(--dsw-alias-interactive-bg-hover)}
.dsv_trSelected .dsv_td{background:var(--dsw-alias-interactive-bg-hover)}
.dsv_rowName{display:flex;align-items:center;gap:7px;min-width:200px;max-width:460px}
.dsv_rowNameText{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dsv_rowIcon{color:var(--dsw-alias-label-tertiary);display:inline-flex;flex:none}
.dsv_rowIconDir{color:var(--dsw-alias-state-business-primary)}
.dsv_mono{font-family:var(--ds-font-family-code);font-size:12px;color:var(--dsw-alias-label-secondary)}
.dsv_numeric{text-align:right;font-variant-numeric:tabular-nums}
.dsv_th.dsv_numeric{text-align:right}
.dsv_empty{padding:36px 16px;text-align:center;color:var(--dsw-alias-label-tertiary);font-size:13px}
.dsv_logWrap{flex:1;min-height:0;display:flex;flex-direction:column;gap:8px}
.dsv_log{flex:1;min-height:0;overflow:auto;margin:0;padding:10px 12px;border:.5px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-base);font-family:var(--ds-font-family-code);font-size:12px;line-height:18px;white-space:pre-wrap;word-break:break-all;tab-size:2;color:var(--dsw-alias-label-secondary);scrollbar-gutter:stable}
.dsv_chips{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.dsv_chip{height:24px;padding:0 9px;border-radius:12px;border:none;background:var(--dsw-alias-bg-module-platform);color:var(--dsw-alias-label-secondary);font:inherit;font-size:11px;line-height:24px;cursor:pointer;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dsv_chip:hover{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary)}
.dsv_chipActive{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary)}
.dsv_summary{display:flex;align-items:center;gap:14px;flex-wrap:wrap;flex:none;font-size:12px;color:var(--dsw-alias-label-tertiary);line-height:18px}
.dsv_summary strong{color:var(--dsw-alias-label-secondary);font-weight:500}
.dsv_search{position:relative;flex:1;min-width:160px;max-width:360px;display:flex;align-items:center}
.dsv_search .dsv_input{width:100%;padding-left:28px}
.dsv_searchIcon{position:absolute;left:8px;color:var(--dsw-alias-label-caption);display:inline-flex;pointer-events:none}
.dsv_select{height:30px;font-size:12px;padding:0 6px;border-radius:10px}
.dsv_backdrop{position:absolute;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;padding:24px;background:var(--dsw-alias-bg-mask-1)}
.dsv_modal{width:min(480px,100%);max-height:100%;min-height:0;display:flex;flex-direction:column;overflow:hidden;border:.5px solid var(--dsw-alias-border-l2);border-radius:16px;background:var(--dsw-alias-bg-layer-1);box-shadow:var(--dsw-elevation-prominent)}
.dsv_modalWide{width:min(1100px,100%);height:min(820px,100%)}
.dsv_modalHead{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:.5px solid var(--dsw-alias-border-l1);flex:none}
.dsv_modalHead h2{margin:0;flex:1;min-width:0;font-size:14px;font-weight:500;line-height:22px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dsv_modalHeadMeta{font-family:var(--ds-font-family-code);font-size:11px;color:var(--dsw-alias-label-tertiary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:45%}
.dsv_modalBody{padding:16px;overflow:auto;min-height:0;flex:1;display:flex;flex-direction:column;gap:10px}
.dsv_modalFoot{display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:10px 16px;border-top:.5px solid var(--dsw-alias-border-l1);flex:none;flex-wrap:wrap}
.dsv_modalFootInfo{margin-right:auto;font-size:12px;color:var(--dsw-alias-label-tertiary);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dsv_textarea{flex:1;min-height:0;width:100%;box-sizing:border-box;resize:none;border:.5px solid var(--dsw-alias-border-l3);border-radius:10px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-family:var(--ds-font-family-code);font-size:12px;line-height:19px;padding:10px 12px;tab-size:2}
.dsv_textarea:focus{outline:none;border-color:var(--dsw-alias-state-business-primary)}
.dsv_toast{position:absolute;right:20px;bottom:20px;z-index:70;max-width:min(460px,80%);padding:9px 14px;border-radius:12px;background:var(--dsw-alias-toast-bg);color:var(--dsw-alias-toast-label);font-size:13px;line-height:20px;box-shadow:var(--dsw-elevation-prominent);overflow-wrap:anywhere}
.dsv_crash{padding:24px;color:var(--dsw-alias-state-error-primary);font-size:13px;line-height:1.6}
.dsv_spin{display:inline-block;width:12px;height:12px;border:1.5px solid currentColor;border-right-color:transparent;border-radius:50%;animation:dsv-spin .8s linear infinite;flex:none}
@keyframes dsv-spin{to{transform:rotate(360deg)}}
.dsv_fill{flex:1;min-height:0;display:flex;flex-direction:column;gap:8px}
.dsv_fillCenter{flex:1;min-height:0;display:flex;align-items:center;justify-content:center;color:var(--dsw-alias-label-tertiary);font-size:13px;gap:8px}
.dsv_kv{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:12px;color:var(--dsw-alias-label-tertiary);min-width:0}
.dsv_kv code{font-family:var(--ds-font-family-code);font-size:11px;color:var(--dsw-alias-label-secondary)}
@media (max-width:760px){
  .dsv_meta{display:none}
  .dsv_td.dsv_hideNarrow,.dsv_th.dsv_hideNarrow{display:none}
}
`

    class ErrorBoundary extends React.Component {
      constructor(props) {
        super(props)
        this.state = { error: null }
      }
      static getDerivedStateFromError(error) {
        return { error }
      }
      componentDidCatch(error, info) {
        try {
          console.error('[ssh-view] render failed', error, info)
        } catch {
          /* no console */
        }
      }
      render() {
        if (this.state.error) {
          return h('div', { className: 'dsv_crash' }, `SSH 服务器视图渲染失败：${String((this.state.error && this.state.error.message) || this.state.error)}`)
        }
        return this.props.children
      }
    }

    function Notice({ kind, children, action }) {
      return h('div', { className: cx('dsv_notice', kind === 'error' && 'dsv_noticeError', kind === 'warn' && 'dsv_noticeWarn') },
        h('span', { className: 'dsv_noticeIcon' }, h(IconAlert, { size: 14 })),
        h('div', { className: 'dsv_noticeBody' }, children),
        action || null)
    }

    function Field({ label, hint, wide, children }) {
      return h('label', { className: cx('dsv_field', wide && 'dsv_fieldWide') },
        h('span', { className: 'dsv_label' }, label),
        children,
        hint ? h('span', { className: 'dsv_hint' }, hint) : null)
    }

    function Modal({ title, meta, onClose, children, footer, wide }) {
      const t = useT()
      React.useEffect(() => {
        const onKey = (event) => {
          if (event.key !== 'Escape') return
          event.preventDefault()
          event.stopPropagation()
          onClose()
        }
        document.addEventListener('keydown', onKey, true)
        return () => document.removeEventListener('keydown', onKey, true)
      }, [onClose])
      return h('div', {
        className: 'dsv_backdrop',
        onMouseDown: (event) => {
          if (event.target === event.currentTarget) onClose()
        },
      }, h('div', {
        className: cx('dsv_modal', wide && 'dsv_modalWide'),
        role: 'dialog',
        'aria-modal': 'true',
        'aria-label': title,
      },
      h('div', { className: 'dsv_modalHead' },
        h('h2', null, title),
        meta ? h('span', { className: 'dsv_modalHeadMeta' }, meta) : null,
        h('button', { type: 'button', className: 'dsv_iconBtn dsv_btn', onClick: onClose, 'aria-label': t('common.close') }, h(IconX, { size: 14 }))),
      h('div', { className: 'dsv_modalBody' }, children),
      footer ? h('div', { className: 'dsv_modalFoot' }, footer) : null))
    }

    function ConfirmDialog({ title, message, danger, confirmLabel, onCancel, onConfirm }) {
      const t = useT()
      const [busy, setBusy] = React.useState(false)
      const [error, setError] = React.useState('')
      const run = async () => {
        setBusy(true)
        setError('')
        try {
          await onConfirm()
        } catch (failure) {
          setError(failure.message || String(failure))
        } finally {
          setBusy(false)
        }
      }
      return h(Modal, {
        title,
        onClose: busy ? () => {} : onCancel,
        footer: [
          h('button', { key: 'cancel', type: 'button', className: 'dsv_btn', onClick: onCancel, disabled: busy }, t('common.cancel')),
          h('button', {
            key: 'confirm',
            type: 'button',
            className: cx('dsv_btn', danger ? 'dsv_btnDanger' : 'dsv_btnPrimary'),
            onClick: run,
            disabled: busy,
          }, busy ? h('span', { className: 'dsv_spin' }) : null, confirmLabel || t('common.confirm')),
        ],
      },
      message ? h('div', { className: 'dsv_hint' }, message) : null,
      error ? h(Notice, { kind: 'error' }, error) : null)
    }

    function PromptDialog({ title, label, initialValue, confirmLabel, onCancel, onSubmit }) {
      const t = useT()
      const [value, setValue] = React.useState(initialValue || '')
      const [busy, setBusy] = React.useState(false)
      const [error, setError] = React.useState('')
      const inputRef = React.useRef(null)
      React.useEffect(() => {
        if (inputRef.current) {
          inputRef.current.focus()
          try {
            inputRef.current.select()
          } catch {
            /* selection is best effort */
          }
        }
      }, [])
      const submit = async (event) => {
        event.preventDefault()
        if (busy) return
        setBusy(true)
        setError('')
        try {
          await onSubmit(value)
        } catch (failure) {
          setError(failure.message || String(failure))
        } finally {
          setBusy(false)
        }
      }
      return h(Modal, {
        title,
        onClose: busy ? () => {} : onCancel,
        footer: [
          h('button', { key: 'cancel', type: 'button', className: 'dsv_btn', onClick: onCancel, disabled: busy }, t('common.cancel')),
          h('button', { key: 'ok', type: 'submit', form: 'dsv-prompt-form', className: 'dsv_btn dsv_btnPrimary', disabled: busy }, busy ? h('span', { className: 'dsv_spin' }) : null, confirmLabel || t('common.confirm')),
        ],
      },
      h('form', { id: 'dsv-prompt-form', onSubmit: submit, style: { display: 'flex', flexDirection: 'column', gap: '6px' } },
        h('span', { className: 'dsv_label' }, label),
        h('input', {
          ref: inputRef,
          className: 'dsv_input',
          value,
          onChange: (event) => setValue(event.target.value),
          spellCheck: false,
          autoComplete: 'off',
        })),
      error ? h(Notice, { kind: 'error' }, error) : null)
    }

    function VaultDialog({ mode, onClose, onDone }) {
      const t = useT()
      const [passphrase, setPassphrase] = React.useState('')
      const [confirmation, setConfirmation] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [error, setError] = React.useState('')
      const submit = async (event) => {
        event.preventDefault()
        if (busy) return
        if (mode === 'create') {
          if (passphrase.length < 8) return setError(t('vault.weak'))
          if (passphrase !== confirmation) return setError(t('vault.mismatch'))
        }
        setBusy(true)
        setError('')
        try {
          const result = mode === 'create' ? await rpc('vault.create', { passphrase }) : await rpc('vault.unlock', { passphrase })
          onDone(result, mode)
        } catch (failure) {
          setError(failure.message || String(failure))
        } finally {
          setBusy(false)
        }
      }
      return h(Modal, {
        title: mode === 'create' ? t('vault.create') : t('vault.unlock'),
        onClose: busy ? () => {} : onClose,
        footer: [
          h('button', { key: 'cancel', type: 'button', className: 'dsv_btn', onClick: onClose, disabled: busy }, t('common.cancel')),
          h('button', { key: 'ok', type: 'submit', form: 'dsv-vault-form', className: 'dsv_btn dsv_btnPrimary', disabled: busy }, busy ? h('span', { className: 'dsv_spin' }) : null, mode === 'create' ? t('vault.create') : t('common.unlock')),
        ],
      },
      h('form', { id: 'dsv-vault-form', onSubmit: submit, style: { display: 'flex', flexDirection: 'column', gap: '10px' } },
        h(Field, { label: t('vault.passphrase') },
          h('input', {
            className: 'dsv_input',
            type: 'password',
            value: passphrase,
            onChange: (event) => setPassphrase(event.target.value),
            autoComplete: 'new-password',
            autoFocus: true,
          })),
        mode === 'create'
          ? h(Field, { label: t('vault.confirmPassphrase') },
            h('input', {
              className: 'dsv_input',
              type: 'password',
              value: confirmation,
              onChange: (event) => setConfirmation(event.target.value),
              autoComplete: 'new-password',
            }))
          : null,
        h('p', { className: 'dsv_hint', style: { margin: 0 } }, t('vault.hint'))),
      error ? h(Notice, { kind: 'error' }, error) : null)
    }

    // ── connection view ───────────────────────────────────────────────────────

    function ConnectionView({ state, form, setForm, busy, error, onConnect, onSelectProfile, onDeleteProfile, onOpenVault, onLockVault, onToggleAutoConnect, onRetryAuto }) {
      const t = useT()
      const vault = state.vault
      const agent = state.agent || { available: false, socket: false, privateKey: false }
      const isAgent = form.auth === 'agent'
      const agentReady = agent.available
        ? `${t('conn.agentReady')}${agent.socket ? '' : ` · ${t('conn.agentReadyKey')}`}`
        : t('conn.agentUnavailable')

      const vaultCard = vault.unlocked
        ? h('div', { className: 'dsv_card' },
          h('div', { className: 'dsv_cardHead' },
            h('h2', null, t('vault.unlocked')),
            h('span', { className: 'dsv_badge dsv_badgeOn' }, h(IconUnlock, { size: 11 }), t('vault.unlocked')),
            h('button', { type: 'button', className: 'dsv_btn', onClick: onLockVault }, h(IconLock, { size: 13 }), t('common.lock'))),
          h('p', { className: 'dsv_hint', style: { margin: 0 } }, t('conn.vaultOptional')))
        : vault.exists
          ? h('div', { className: 'dsv_card' },
            h('div', { className: 'dsv_cardHead' }, h('h2', null, t('vault.locked')), h('span', { className: 'dsv_badge' }, h(IconLock, { size: 11 }), t('vault.locked'))),
            h('p', { className: 'dsv_hint', style: { margin: '0 0 10px' } }, t('conn.vaultLockedHint')),
            h('p', { className: 'dsv_hint', style: { margin: '0 0 10px' } }, t('conn.vaultOptional')),
            h('button', { type: 'button', className: 'dsv_btn dsv_btnPrimary', onClick: onOpenVault }, h(IconUnlock, { size: 13 }), t('common.unlock')))
          : h('div', { className: 'dsv_card' },
            h('div', { className: 'dsv_cardHead' }, h('h2', null, t('vault.missing'))),
            h('p', { className: 'dsv_hint', style: { margin: '0 0 10px' } }, t('vault.createHint')),
            h('p', { className: 'dsv_hint', style: { margin: '0 0 10px' } }, t('conn.vaultOptional')),
            h('button', { type: 'button', className: 'dsv_btn dsv_btnPrimary', onClick: onOpenVault }, h(IconLock, { size: 13 }), t('vault.create')))

      const autoError = state.autoConnectError
        ? h(Notice, { kind: 'error' },
          h('strong', null, t('conn.autoConnectFailed')),
          h('pre', null, state.autoConnectError),
          h('div', { style: { marginTop: '8px' } },
            h('button', { type: 'button', className: 'dsv_btn', onClick: onRetryAuto }, t('conn.retry'))))
        : null

      const errorNotice = error
        ? h(Notice, { kind: 'error' },
          h('strong', null, t('error.title')),
          h('pre', null, error.message),
          error.code === 'host-key-mismatch'
            ? h('div', { style: { marginTop: '8px' } },
              h('button', { type: 'button', className: 'dsv_btn', onClick: () => onConnect(null, true) }, t('host.forget')))
            : null)
        : null

      const nameField = h(Field, { label: t('conn.name') },
        h('input', { className: 'dsv_input', value: form.name, onChange: (event) => setForm({ ...form, name: event.target.value }), placeholder: t('common.optional'), spellCheck: false }))
      const hostField = h(Field, { label: t('conn.host') },
        h('input', { className: 'dsv_input', value: form.host, onChange: (event) => setForm({ ...form, host: event.target.value }), placeholder: '10.0.0.10', spellCheck: false, autoComplete: 'off' }))
      const portField = h(Field, { label: t('conn.port') },
        h('input', { className: 'dsv_input', value: form.port, onChange: (event) => setForm({ ...form, port: event.target.value.replace(/[^0-9]/g, '') }), inputMode: 'numeric', spellCheck: false }))
      const userField = h(Field, { label: t('conn.user') },
        h('input', { className: 'dsv_input', value: form.username, onChange: (event) => setForm({ ...form, username: event.target.value }), placeholder: 'root', spellCheck: false, autoComplete: 'off' }))

      const authField = h(Field, { label: t('conn.auth'), wide: true, hint: isAgent ? agentReady : t('conn.rememberHint') },
        h('div', { className: 'dsv_seg', role: 'group', 'aria-label': t('conn.auth') },
          h('button', {
            type: 'button',
            className: cx('dsv_segBtn', form.auth === 'password' && 'dsv_segActive'),
            'aria-pressed': form.auth === 'password',
            onClick: () => setForm({ ...form, auth: 'password', remember: false }),
          }, h(IconLock, { size: 12 }), t('conn.auth.password')),
          h('button', {
            type: 'button',
            className: cx('dsv_segBtn', form.auth === 'agent' && 'dsv_segActive'),
            'aria-pressed': form.auth === 'agent',
            disabled: !agent.available,
            onClick: () => setForm({ ...form, auth: 'agent', remember: true }),
          }, h(IconServer, { size: 12 }), t('conn.auth.agent'))))

      const passwordField = !isAgent
        ? h(Field, { label: t('conn.password'), wide: true },
          h('input', {
            className: 'dsv_input',
            type: 'password',
            value: form.password,
            onChange: (event) => setForm({ ...form, password: event.target.value }),
            placeholder: '••••••••',
            autoComplete: 'new-password',
          }))
        : null
      const savedPasswordHint = !isAgent && form.id && !form.password
        ? h('span', { className: 'dsv_hint', style: { gridColumn: '1 / -1' } }, t('conn.passwordHint'))
        : null

      const fields = h('div', { className: 'dsv_fields' }, nameField, hostField, portField, userField, authField, passwordField, savedPasswordHint)

      const rememberRow = h('div', { className: 'dsv_actions', style: { marginTop: '10px', flexDirection: 'column', alignItems: 'flex-start', gap: '8px' } },
        h('label', { className: 'dsv_check' },
          h('input', {
            type: 'checkbox',
            checked: form.remember,
            onChange: (event) => setForm({ ...form, remember: event.target.checked }),
          }),
          h('span', { className: 'dsv_checkText' },
            h('span', null, isAgent ? t('conn.rememberAgent') : t('conn.remember')),
            h('span', { className: 'dsv_hint' }, isAgent ? t('conn.rememberAgentHint') : t('conn.rememberHint')))),
        h('label', { className: 'dsv_check' },
          h('input', {
            type: 'checkbox',
            checked: state.autoConnect === true,
            onChange: (event) => onToggleAutoConnect(event.target.checked),
          }),
          h('span', { className: 'dsv_checkText' },
            h('span', null, t('conn.autoConnect')),
            h('span', { className: 'dsv_hint' }, t('conn.autoConnectHint')))))

      const submitRow = h('div', { className: 'dsv_actions' },
        h('button', {
          type: 'submit',
          className: 'dsv_btn dsv_btnPrimary',
          disabled: busy || (isAgent && !agent.available),
        },
        busy ? h('span', { className: 'dsv_spin' }) : h(IconPlay, { size: 13 }),
        busy ? t('common.connecting') : t('common.connect')),
        h('button', {
          type: 'button',
          className: 'dsv_btn',
          onClick: () => setForm({ id: '', name: '', host: '', port: '22', username: '', password: '', remember: true, auth: agent.available ? 'agent' : 'password' }),
        }, t('conn.clear')))

      const formNode = h('form', {
        onSubmit: (event) => {
          event.preventDefault()
          onConnect()
        },
      }, fields, rememberRow, submitRow)

      const profileRows = state.profiles.length === 0
        ? h('p', { className: 'dsv_hint', style: { margin: 0 } }, t('conn.empty'))
        : state.profiles.map((profile) => h('div', { key: profile.id, className: 'dsv_profile' },
          h('span', { className: 'dsv_glyph' }, h(IconServer, { size: 16 })),
          h('div', { className: 'dsv_profileMain' },
            h('span', { className: 'dsv_profileName' }, profile.name),
            h('span', { className: 'dsv_profileHost' }, `${profile.username}@${profile.host}:${profile.port}`)),
          h('span', { className: cx('dsv_badge', profile.auth === 'agent' && 'dsv_badgeOn') },
            profile.auth === 'agent' ? t('conn.auth.agent') : t('conn.auth.password')),
          profile.id === state.lastProfileId
            ? h('span', { className: 'dsv_badge dsv_badgeOn' }, t('conn.lastProfile'))
            : null,
          profile.auth === 'password' && !profile.hasPassword
            ? h('span', { className: 'dsv_badge' }, t('conn.noPassword'))
            : null,
          h('div', { className: 'dsv_profileActions' },
            h('button', { type: 'button', className: 'dsv_btn', onClick: () => onSelectProfile(profile) }, h(IconPlay, { size: 12 }), t('common.connect')),
            h('button', {
              type: 'button',
              className: 'dsv_btn dsv_iconBtn',
              onClick: () => onDeleteProfile(profile),
              title: t('conn.deleteProfile'),
              'aria-label': t('conn.deleteProfile'),
            }, h(IconTrash, { size: 14 })))))

      return h('div', { className: 'dsv_scroll' },
        h('div', { className: 'dsv_content dsv_narrow' },
          vaultCard,
          autoError,
          errorNotice,
          h('section', { className: 'dsv_card' }, h('h2', null, t('conn.new')), formNode),
          h('section', { className: 'dsv_card' }, h('h2', null, t('conn.saved')), profileRows)))
    }

    // ── files ─────────────────────────────────────────────────────────────────

    function ExtractDialog({ state, onChange, onCancel, onDone }) {
      const t = useT()
      const [busy, setBusy] = React.useState(false)
      const [error, setError] = React.useState('')
      const submit = async (event) => {
        event.preventDefault()
        if (busy) return
        setBusy(true)
        setError('')
        try {
          const result = await rpc('fs.extract', {
            path: state.path,
            target: state.target,
            overwrite: state.overwrite === true,
          })
          onDone(result)
        } catch (failure) {
          setError(failure.message || String(failure))
        } finally {
          setBusy(false)
        }
      }
      return h(Modal, {
        title: t('files.extractTitle'),
        meta: state.name,
        onClose: busy ? () => {} : onCancel,
        footer: [
          h('button', { key: 'cancel', type: 'button', className: 'dsv_btn', onClick: onCancel, disabled: busy }, t('common.cancel')),
          h('button', {
            key: 'ok',
            type: 'submit',
            form: 'dsv-extract-form',
            className: 'dsv_btn dsv_btnPrimary',
            disabled: busy || !state.target.trim().startsWith('/'),
          }, busy ? h('span', { className: 'dsv_spin' }) : null, busy ? t('files.extracting') : t('files.extract')),
        ],
      },
      h('form', { id: 'dsv-extract-form', onSubmit: submit, style: { display: 'flex', flexDirection: 'column', gap: '10px' } },
        h('span', { className: 'dsv_hint' }, t('files.extractHint')),
        h(Field, { label: t('files.extractTo') },
          h('input', {
            className: 'dsv_input',
            value: state.target,
            onChange: (event) => onChange({ ...state, target: event.target.value }),
            spellCheck: false,
          })),
        h('label', { className: 'dsv_check' },
          h('input', {
            type: 'checkbox',
            checked: state.overwrite === true,
            onChange: (event) => onChange({ ...state, overwrite: event.target.checked }),
          }),
          h('span', null, t('files.extractOverwrite')))),
      error ? h(Notice, { kind: 'error' }, error) : null)
    }

    function FilesTab({ session, limits, notify }) {
      const t = useT()
      const [listing, setListing] = React.useState(null)
      const [loading, setLoading] = React.useState(false)
      const [failure, setFailure] = React.useState('')
      const [pathInput, setPathInput] = React.useState('')
      const [selected, setSelected] = React.useState('')
      const [editor, setEditor] = React.useState(null)
      const [prompt, setPrompt] = React.useState(null)
      const [confirm, setConfirm] = React.useState(null)
      const [extract, setExtract] = React.useState(null)
      const [uploading, setUploading] = React.useState('')
      const uploadRef = React.useRef(null)
      const editorRef = React.useRef(null)

      const currentPath = listing ? listing.path : ''
      const home = (listing && listing.home) || (session.server && session.server.home) || '/'

      const load = React.useCallback(async (path) => {
        setLoading(true)
        setFailure('')
        try {
          const value = await rpc('fs.list', { path })
          setListing(value)
          setPathInput(value.path)
          setSelected('')
        } catch (error) {
          setFailure(error.message || String(error))
        } finally {
          setLoading(false)
        }
      }, [])

      const initialPathRef = React.useRef((session.server && session.server.home) || '/')
      React.useEffect(() => {
        void load(initialPathRef.current)
      }, [load])

      const entry = React.useMemo(() => {
        if (!listing) return null
        return listing.entries.find((row) => row.path === selected) || null
      }, [listing, selected])

      const startRename = () => {
        if (!entry) return
        setPrompt({
          title: t('files.rename'),
          label: t('files.renamePrompt'),
          initialValue: entry.name,
          onSubmit: async (value) => {
            const name = String(value || '').trim()
            if (!name || name.includes('/')) throw new Error('名称不能为空且不能包含 /')
            await rpc('fs.rename', { from: entry.path, to: joinPath(currentPath, name) })
            setPrompt(null)
            await load(currentPath)
          },
        })
      }

      const startMove = () => {
        if (!entry) return
        setPrompt({
          title: t('files.move'),
          label: t('files.movePrompt'),
          initialValue: entry.path,
          onSubmit: async (value) => {
            const target = String(value || '').trim()
            if (!target.startsWith('/')) throw new Error('目标路径必须是绝对路径')
            await rpc('fs.rename', { from: entry.path, to: target })
            setPrompt(null)
            await load(currentPath)
          },
        })
      }

      const startFolder = () => {
        setPrompt({
          title: t('files.newFolder'),
          label: t('files.folderPrompt'),
          initialValue: '',
          onSubmit: async (value) => {
            const name = String(value || '').trim()
            if (!name || name.includes('/')) throw new Error('名称不能为空且不能包含 /')
            await rpc('fs.mkdir', { path: joinPath(currentPath, name) })
            setPrompt(null)
            await load(currentPath)
          },
        })
      }

      const startTouch = () => {
        setPrompt({
          title: t('files.newFile'),
          label: t('files.filePrompt'),
          initialValue: '',
          onSubmit: async (value) => {
            const name = String(value || '').trim()
            if (!name || name.includes('/')) throw new Error('名称不能为空且不能包含 /')
            await rpc('fs.touch', { path: joinPath(currentPath, name) })
            setPrompt(null)
            await load(currentPath)
          },
        })
      }

      const startExtract = () => {
        if (!entry || !isArchiveName(entry.name)) return
        setExtract({
          path: entry.path,
          name: entry.name,
          target: joinPath(currentPath, archiveStemName(entry.name)),
          overwrite: false,
        })
      }

      const startDelete = () => {
        if (!entry) return
        setConfirm({
          title: t('files.delete'),
          message: entry.type === 'dir'
            ? tf(t, 'files.deleteDirConfirm', { path: entry.path })
            : tf(t, 'files.deleteConfirm', { path: entry.path }),
          danger: true,
          confirmLabel: t('common.delete'),
          onConfirm: async () => {
            await rpc('fs.remove', { path: entry.path, recursive: entry.type === 'dir' })
            setConfirm(null)
            await load(currentPath)
          },
        })
      }

      const openEntry = async (row) => {
        if (!row) return
        if (row.type === 'dir') {
          await load(row.path)
          return
        }
        try {
          const value = await rpc('fs.read', { path: row.path })
          if (value.binary) {
            notify(t('files.binary'), 'warn')
            return
          }
          if (value.tooLarge) {
            notify(tf(t, 'files.tooLarge', { size: formatSize(value.size) }), 'warn')
            return
          }
          setEditor({
            path: value.path,
            content: value.content,
            original: value.content,
            mtime: value.mtime,
            version: value.version,
            size: value.size,
            saving: false,
            error: '',
            conflict: false,
          })
        } catch (error) {
          if (error.code === 'is-directory') {
            await load(row.path)
            return
          }
          notify(error.message || String(error), 'error')
        }
      }

      const saveEditor = async (force) => {
        if (!editor) return
        setEditor((current) => (current ? { ...current, saving: true, error: '', conflict: false } : current))
        try {
          const value = await rpc('fs.write', {
            path: editor.path,
            content: editor.content,
            mtime: editor.mtime,
            version: editor.version,
            force: force === true,
          })
          setEditor((current) => current ? {
            ...current,
            saving: false,
            mtime: value.mtime,
            version: value.version,
            original: editor.content,
            size: value.size,
            error: '',
            conflict: false,
          } : current)
          notify(t('files.saved'), 'info')
          if (currentPath) void load(currentPath)
        } catch (error) {
          setEditor((current) => current ? {
            ...current,
            saving: false,
            conflict: error.code === 'conflict',
            error: error.code === 'conflict' ? t('editor.conflict') : (error.message || String(error)),
          } : current)
        }
      }

      const reloadEditor = async () => {
        if (!editor) return
        try {
          const value = await rpc('fs.read', { path: editor.path })
          if (value.binary || value.tooLarge) {
            setEditor(null)
            notify(value.binary ? t('files.binary') : tf(t, 'files.tooLarge', { size: formatSize(value.size) }), 'warn')
            return
          }
          setEditor({
            path: value.path,
            content: value.content,
            original: value.content,
            mtime: value.mtime,
            version: value.version,
            size: value.size,
            saving: false,
            error: '',
            conflict: false,
          })
        } catch (error) {
          notify(error.message || String(error), 'error')
        }
      }

      const closeEditor = () => {
        if (!editor) return
        if (editor.content !== editor.original) {
          setConfirm({
            title: t('common.close'),
            message: t('editor.closeConfirm'),
            danger: true,
            confirmLabel: t('common.close'),
            onConfirm: async () => {
              setConfirm(null)
              setEditor(null)
            },
          })
          return
        }
        setEditor(null)
      }

      React.useEffect(() => {
        const onKey = (event) => {
          const meta = event.metaKey || event.ctrlKey
          if (meta && event.key.toLowerCase() === 's' && editor) {
            event.preventDefault()
            void saveEditor(false)
          }
        }
        window.addEventListener('keydown', onKey)
        return () => window.removeEventListener('keydown', onKey)
      })

      React.useEffect(() => {
        if (editor && editorRef.current) editorRef.current.focus()
      }, [editor && editor.path])

      const handleUpload = async (fileList) => {
        const files = Array.from(fileList || [])
        if (!files.length || !currentPath) return
        for (const file of files) {
          const target = joinPath(currentPath, file.name)
          const exists = listing && listing.entries.some((row) => row.name === file.name)
          const confirmed = await new Promise((resolve) => {
            if (!exists) return resolve(true)
            setConfirm({
              title: t('files.upload'),
              message: tf(t, 'files.overwriteConfirm', { name: file.name }),
              danger: true,
              confirmLabel: t('files.upload'),
              onConfirm: async () => {
                setConfirm(null)
                resolve(true)
              },
              onCancel: () => {
                setConfirm(null)
                resolve(false)
              },
            })
          })
          if (!confirmed) continue
          setUploading(file.name)
          try {
            await uploadFile(target, file, true)
            notify(tf(t, 'files.uploaded', { name: file.name }), 'info')
          } catch (error) {
            notify(error.message || String(error), 'error')
          } finally {
            setUploading('')
          }
        }
        await load(currentPath)
      }

      const rows = listing ? listing.entries : []
      const breadcrumb = crumbs(currentPath || '/')

      return h('div', { className: 'dsv_fill' },
        failure ? h(Notice, { kind: 'error' }, failure) : null,
        h('div', { className: 'dsv_toolbar' },
          h('button', { type: 'button', className: 'dsv_btn dsv_iconBtn', title: t('files.parent'), 'aria-label': t('files.parent'), disabled: !currentPath || currentPath === '/', onClick: () => load(parentOf(currentPath)) }, icon(['M10.4 3.6 6 8l4.4 4.4'])),
          h('button', { type: 'button', className: 'dsv_btn dsv_iconBtn', title: t('files.home'), 'aria-label': t('files.home'), onClick: () => load(home) }, icon(['M2.4 7.4 8 2.4l5.6 5', 'M4 6.6v7h8v-7'])),
          h('button', { type: 'button', className: 'dsv_btn dsv_iconBtn', title: t('common.refresh'), 'aria-label': t('common.refresh'), disabled: loading, onClick: () => load(currentPath || '/') }, loading ? h('span', { className: 'dsv_spin' }) : h(IconRefresh, { size: 14 })),
          h('span', { className: 'dsv_toolbarSep' }),
          h('button', { type: 'button', className: 'dsv_btn', disabled: !entry, onClick: () => openEntry(entry) }, h(IconPlay, { size: 12 }), t('files.open')),
          h('button', { type: 'button', className: 'dsv_btn', disabled: !entry || entry.type === 'dir', onClick: () => entry && downloadFile(entry.path) }, h(IconDownload, { size: 13 }), t('files.download')),
          h('button', { type: 'button', className: 'dsv_btn', disabled: !entry || !isArchiveName(entry.name), onClick: startExtract }, h(IconArchive, { size: 13 }), t('files.extract')),
          h('button', { type: 'button', className: 'dsv_btn', disabled: !entry, onClick: startRename }, h(IconEdit, { size: 13 }), t('files.rename')),
          h('button', { type: 'button', className: 'dsv_btn', disabled: !entry, onClick: startMove }, t('files.move')),
          h('button', { type: 'button', className: 'dsv_btn dsv_btnDanger', disabled: !entry, onClick: startDelete }, h(IconTrash, { size: 13 }), t('files.delete')),
          h('span', { className: 'dsv_spacer' }),
          h('button', { type: 'button', className: 'dsv_btn', onClick: startFolder }, h(IconPlus, { size: 12 }), t('files.newFolder')),
          h('button', { type: 'button', className: 'dsv_btn', onClick: startTouch }, h(IconPlus, { size: 12 }), t('files.newFile')),
          h('button', { type: 'button', className: 'dsv_btn', disabled: Boolean(uploading), onClick: () => uploadRef.current && uploadRef.current.click() }, h(IconUpload, { size: 13 }), uploading ? `${t('files.uploading')} ${uploading}` : t('files.upload')),
          h('input', {
            ref: uploadRef,
            type: 'file',
            multiple: true,
            style: { display: 'none' },
            onChange: (event) => {
              const files = event.target.files
              event.target.value = ''
              void handleUpload(files)
            },
          })),
        h('div', { className: 'dsv_pathRow' },
          h('div', { className: 'dsv_crumbs' },
            breadcrumb.map((crumb, index) => h(React.Fragment, { key: crumb.path },
              index > 0 ? h('span', { className: 'dsv_crumbSep' }, h(IconChevron, { size: 10 })) : null,
              h('button', { type: 'button', className: 'dsv_crumb', onClick: () => load(crumb.path), title: crumb.path }, crumb.label)))),
          h('button', { type: 'button', className: 'dsv_btn dsv_iconBtn', title: t('common.refresh'), 'aria-label': t('common.refresh'), onClick: () => load(currentPath || '/') }, h(IconRefresh, { size: 13 }))),
        h('div', { className: 'dsv_pathRow' },
          h('input', {
            className: 'dsv_input',
            style: { flex: 1 },
            value: pathInput,
            onChange: (event) => setPathInput(event.target.value),
            onKeyDown: (event) => {
              if (event.key === 'Enter') {
                event.preventDefault()
                if (pathInput.trim().startsWith('/')) void load(pathInput.trim())
              }
            },
            placeholder: t('files.path'),
            spellCheck: false,
            'aria-label': t('files.path'),
          }),
          h('button', { type: 'button', className: 'dsv_btn', disabled: !pathInput.trim().startsWith('/'), onClick: () => load(pathInput.trim()) }, t('files.open'))),
        h('div', { className: 'dsv_tableWrap' },
          h('table', { className: 'dsv_table' },
            h('thead', null, h('tr', null,
              h('th', { className: 'dsv_th' }, t('files.name')),
              h('th', { className: 'dsv_th dsv_numeric' }, t('files.size')),
              h('th', { className: 'dsv_th dsv_hideNarrow' }, t('files.modified')),
              h('th', { className: 'dsv_th dsv_hideNarrow' }, t('files.mode')),
              h('th', { className: 'dsv_th dsv_numeric' }, ''))),
            h('tbody', null,
              rows.length === 0
                ? h('tr', null, h('td', { className: 'dsv_td dsv_empty', colSpan: 5 }, loading ? t('common.loading') : t('files.empty')))
                : rows.map((row) => h('tr', {
                  key: row.path,
                  className: cx('dsv_tr', selected === row.path && 'dsv_trSelected'),
                  onClick: () => setSelected(row.path),
                  onDoubleClick: () => openEntry(row),
                  tabIndex: 0,
                  onKeyDown: (event) => {
                    if (event.key === 'Enter') {
                      event.preventDefault()
                      openEntry(row)
                    }
                  },
                },
                h('td', { className: 'dsv_td' }, h('div', { className: 'dsv_rowName' },
                  h('span', { className: cx('dsv_rowIcon', row.type === 'dir' && 'dsv_rowIconDir') }, row.type === 'dir' ? h(IconFolder, { size: 15 }) : h(IconFile, { size: 15 })),
                  h('span', { className: 'dsv_rowNameText', title: row.name }, row.name))),
                h('td', { className: 'dsv_td dsv_numeric dsv_mono' }, row.type === 'dir' ? '—' : formatSize(row.size)),
                h('td', { className: 'dsv_td dsv_hideNarrow dsv_mono' }, formatTime(row.mtime)),
                h('td', { className: 'dsv_td dsv_hideNarrow dsv_mono' }, row.mode),
                h('td', { className: 'dsv_td dsv_numeric' },
                  h('button', {
                    type: 'button',
                    className: 'dsv_btn dsv_iconBtn',
                    title: t('files.download'),
                    'aria-label': t('files.download'),
                    disabled: row.type === 'dir',
                    onClick: (event) => {
                      event.stopPropagation()
                      downloadFile(row.path)
                    },
                  }, h(IconDownload, { size: 13 })))))))),
        editor ? h(Modal, {
          title: t('editor.title'),
          meta: editor.path,
          wide: true,
          onClose: closeEditor,
          footer: [
            h('span', { key: 'info', className: 'dsv_modalFootInfo' },
              editor.content !== editor.original ? t('editor.dirty') : formatSize(new Blob([editor.content]).size)),
            h('button', { key: 'download', type: 'button', className: 'dsv_btn', onClick: () => downloadFile(editor.path) }, h(IconDownload, { size: 13 }), t('editor.download')),
            h('button', { key: 'reload', type: 'button', className: 'dsv_btn', onClick: () => { void reloadEditor() } }, t('editor.revert')),
            editor.conflict ? h('button', {
              key: 'overwrite',
              type: 'button',
              className: 'dsv_btn dsv_btnDanger',
              disabled: editor.saving,
              onClick: () => { void saveEditor(true) },
            }, t('editor.overwrite')) : null,
            h('button', {
              key: 'save',
              type: 'button',
              className: 'dsv_btn dsv_btnPrimary',
              disabled: editor.saving || editor.content === editor.original,
              onClick: () => { void saveEditor(false) },
            }, editor.saving ? h('span', { className: 'dsv_spin' }) : null, t('editor.save')),
          ],
        },
        editor.error ? h(Notice, { kind: 'error' }, editor.error) : null,
        h('textarea', {
          ref: editorRef,
          className: 'dsv_textarea',
          value: editor.content,
          spellCheck: false,
          onChange: (event) => setEditor((current) => current ? { ...current, content: event.target.value } : current),
          onKeyDown: (event) => {
            if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 's') {
              event.preventDefault()
              void saveEditor(false)
            }
            if (event.key === 'Tab') {
              event.preventDefault()
              const target = event.target
              const start = target.selectionStart
              const end = target.selectionEnd
              const next = `${editor.content.slice(0, start)}  ${editor.content.slice(end)}`
              setEditor((current) => current ? { ...current, content: next } : current)
              requestAnimationFrame(() => {
                target.selectionStart = start + 2
                target.selectionEnd = start + 2
              })
            }
          },
        })) : null,
        extract ? h(ExtractDialog, {
          key: 'extract',
          state: extract,
          onChange: setExtract,
          onCancel: () => setExtract(null),
          onDone: (result) => {
            setExtract(null)
            notify(tf(t, 'files.extractDone', { count: result.entries, target: result.target }), 'info')
            void load(currentPath)
          },
        }) : null,
        prompt ? h(PromptDialog, {
          title: prompt.title,
          label: prompt.label,
          initialValue: prompt.initialValue,
          onCancel: () => setPrompt(null),
          onSubmit: prompt.onSubmit,
        }) : null,
        confirm ? h(ConfirmDialog, {
          title: confirm.title,
          message: confirm.message,
          danger: confirm.danger,
          confirmLabel: confirm.confirmLabel,
          onCancel: () => {
            const cancel = confirm.onCancel
            setConfirm(null)
            if (cancel) cancel()
          },
          onConfirm: confirm.onConfirm,
        }) : null)
    }

    // ── processes ─────────────────────────────────────────────────────────────

    function ProcessesTab({ notify }) {
      const t = useT()
      const [data, setData] = React.useState(null)
      const [failure, setFailure] = React.useState('')
      const [loading, setLoading] = React.useState(false)
      const [filter, setFilter] = React.useState('')
      const [intervalMs, setIntervalMs] = React.useState(5000)
      const [sort, setSort] = React.useState({ key: 'cpu', dir: 'desc' })
      const [target, setTarget] = React.useState(null)
      const [signal, setSignal] = React.useState('TERM')

      const load = React.useCallback(async () => {
        setLoading(true)
        try {
          const value = await rpc('proc.list')
          setData(value)
          setFailure('')
        } catch (error) {
          setFailure(error.message || String(error))
        } finally {
          setLoading(false)
        }
      }, [])

      React.useEffect(() => {
        void load()
      }, [load])

      React.useEffect(() => {
        if (!intervalMs) return undefined
        const timer = setInterval(() => { void load() }, intervalMs)
        return () => clearInterval(timer)
      }, [intervalMs, load])

      const rows = React.useMemo(() => {
        if (!data || !Array.isArray(data.procs)) return []
        const needle = filter.trim().toLowerCase()
        const list = needle
          ? data.procs.filter((row) => String(row.pid).includes(needle) || String(row.user).toLowerCase().includes(needle) || String(row.args).toLowerCase().includes(needle))
          : data.procs.slice()
        const key = sort.key
        const direction = sort.dir === 'asc' ? 1 : -1
        list.sort((a, b) => {
          const left = a[key]
          const right = b[key]
          if (typeof left === 'number' && typeof right === 'number') return (left - right) * direction
          return String(left).localeCompare(String(right)) * direction
        })
        return list
      }, [data, filter, sort])

      const toggleSort = (key) => {
        setSort((current) => current.key === key ? { key, dir: current.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'args' || key === 'user' ? 'asc' : 'desc' })
      }

      const header = (key, label, extra) => h('th', { className: cx('dsv_th', extra) },
        h('button', { type: 'button', className: 'dsv_thBtn', onClick: () => toggleSort(key) },
          label,
          sort.key === key ? h('span', { className: 'dsv_mono' }, sort.dir === 'asc' ? '↑' : '↓') : null))

      const memory = data && data.mem ? data.mem : null
      const memUsed = memory && memory.MemTotal ? Math.max(0, memory.MemTotal - (memory.MemAvailable || memory.MemFree || 0)) : null

      return h('div', { className: 'dsv_fill' },
        failure ? h(Notice, { kind: 'error' }, failure) : null,
        h('div', { className: 'dsv_summary' },
          data
            ? h(React.Fragment, null,
              h('span', null, t('proc.load'), ' ', h('strong', null, (data.load || []).join(' ') || '—')),
              h('span', null, t('proc.uptime'), ' ', h('strong', null, formatDuration(data.uptimeSec))),
              memUsed !== null
                ? h('span', null, t('proc.memory'), ' ', h('strong', null, `${formatSize(memUsed * 1024)} / ${formatSize((memory.MemTotal || 0) * 1024)}`))
                : null,
              h('span', null, t('proc.count'), ' ', h('strong', null, String(data.count || 0))),
              h('span', { className: 'dsv_meta' }, formatClock(data.at)))
            : h('span', null, loading ? t('common.loading') : t('common.disconnected'))),
        h('div', { className: 'dsv_toolbar' },
          h('div', { className: 'dsv_search' },
            h('span', { className: 'dsv_searchIcon' }, h(IconSearch, { size: 13 })),
            h('input', {
              className: 'dsv_input',
              value: filter,
              placeholder: t('proc.filter'),
              onChange: (event) => setFilter(event.target.value),
              'aria-label': t('proc.filter'),
              spellCheck: false,
            })),
          h('select', {
            className: 'dsv_select',
            value: String(intervalMs),
            onChange: (event) => setIntervalMs(Number(event.target.value)),
            'aria-label': t('proc.interval'),
          },
          h('option', { value: '0' }, t('proc.off')),
          h('option', { value: '2000' }, '2 s'),
          h('option', { value: '5000' }, '5 s'),
          h('option', { value: '10000' }, '10 s')),
          h('button', { type: 'button', className: 'dsv_btn', disabled: loading, onClick: () => { void load() } }, loading ? h('span', { className: 'dsv_spin' }) : h(IconRefresh, { size: 13 }), t('common.refresh'))),
        h('div', { className: 'dsv_tableWrap' },
          h('table', { className: 'dsv_table' },
            h('thead', null, h('tr', null,
              header('pid', t('proc.pid'), 'dsv_numeric'),
              header('user', t('proc.user')),
              header('cpu', t('proc.cpu'), 'dsv_numeric'),
              header('mem', t('proc.mem'), 'dsv_numeric'),
              header('rssKb', t('proc.rss'), 'dsv_numeric dsv_hideNarrow'),
              header('elapsedSec', t('proc.elapsed')),
              h('th', { className: 'dsv_th dsv_hideNarrow' }, t('proc.stat')),
              header('args', t('proc.command')),
              h('th', { className: 'dsv_th' }, ''))),
            h('tbody', null,
              rows.length === 0
                ? h('tr', null, h('td', { className: 'dsv_td dsv_empty', colSpan: 9 }, loading ? t('common.loading') : '—'))
                : rows.map((row) => h('tr', { key: row.pid, className: 'dsv_tr' },
                  h('td', { className: 'dsv_td dsv_numeric dsv_mono' }, String(row.pid)),
                  h('td', { className: 'dsv_td' }, row.user),
                  h('td', { className: 'dsv_td dsv_numeric dsv_mono' }, Number(row.cpu).toFixed(1)),
                  h('td', { className: 'dsv_td dsv_numeric dsv_mono' }, Number(row.mem).toFixed(1)),
                  h('td', { className: 'dsv_td dsv_numeric dsv_mono dsv_hideNarrow' }, formatSize((Number(row.rssKb) || 0) * 1024)),
                  h('td', { className: 'dsv_td dsv_mono' }, formatDuration(row.elapsedSec)),
                  h('td', { className: 'dsv_td dsv_mono dsv_hideNarrow' }, row.stat || '—'),
                  h('td', { className: 'dsv_td dsv_mono', style: { maxWidth: '520px' }, title: row.args }, row.args),
                  h('td', { className: 'dsv_td dsv_numeric' },
                    h('button', {
                      type: 'button',
                      className: 'dsv_btn dsv_btnDanger dsv_iconBtn',
                      title: t('proc.kill'),
                      'aria-label': t('proc.kill'),
                      disabled: row.pid <= 1,
                      onClick: () => {
                        setSignal('TERM')
                        setTarget(row)
                      },
                    }, h(IconStop, { size: 13 })))))))),
        target ? h(ConfirmDialog, {
          title: t('proc.kill'),
          message: h('div', { style: { display: 'flex', flexDirection: 'column', gap: '8px' } },
            h('span', null, tf(t, 'proc.killConfirm', { pid: target.pid, signal: 'TERM' === signal ? 'TERM' : 'KILL' })),
            h('code', { className: 'dsv_mono', style: { overflowWrap: 'anywhere' } }, target.args),
            h('select', {
              className: 'dsv_select',
              value: signal,
              onChange: (event) => setSignal(event.target.value),
              'aria-label': 'signal',
            },
            h('option', { value: 'TERM' }, t('proc.signal.term')),
            h('option', { value: 'KILL' }, t('proc.signal.kill')))),
          danger: signal === 'KILL',
          confirmLabel: t('proc.kill'),
          onCancel: () => setTarget(null),
          onConfirm: async () => {
            setTarget(null)
            try {
              await rpc('proc.kill', { pid: target.pid, signal })
              notify(tf(t, 'proc.killed', { pid: target.pid, signal }), 'info')
              await load()
            } catch (error) {
              notify(error.message || String(error), 'error')
            }
          },
        }) : null)
    }

    // ── logs ─────────────────────────────────────────────────────────────────

    function LogsTab({ notify }) {
      const t = useT()
      const [path, setPath] = React.useState('')
      const [lines, setLines] = React.useState(200)
      const [follow, setFollow] = React.useState(true)
      const [data, setData] = React.useState(null)
      const [failure, setFailure] = React.useState('')
      const [presets, setPresets] = React.useState([])
      const [loading, setLoading] = React.useState(false)
      const logRef = React.useRef(null)
      const pathRef = React.useRef(path)
      pathRef.current = path

      React.useEffect(() => {
        let alive = true
        rpc('logs.presets').then((value) => {
          if (alive && value && Array.isArray(value.presets)) setPresets(value.presets)
        }).catch(() => {})
        return () => { alive = false }
      }, [])

      const load = React.useCallback(async () => {
        const target = pathRef.current.trim()
        if (!target.startsWith('/')) return
        setLoading(true)
        try {
          const value = await rpc('logs.tail', { path: target, lines })
          setData(value)
          setFailure('')
        } catch (error) {
          setFailure(error.message || String(error))
        } finally {
          setLoading(false)
        }
      }, [lines])

      React.useEffect(() => {
        if (!follow) return undefined
        if (!path.trim().startsWith('/')) return undefined
        void load()
        const timer = setInterval(() => { void load() }, 2500)
        return () => clearInterval(timer)
      }, [follow, path, load])

      React.useEffect(() => {
        const node = logRef.current
        if (!node || !follow) return
        node.scrollTop = node.scrollHeight
      }, [data, follow])

      return h('div', { className: 'dsv_fill' },
        failure ? h(Notice, { kind: 'error' }, failure) : null,
        h('div', { className: 'dsv_toolbar' },
          h('div', { className: 'dsv_search', style: { maxWidth: '520px' } },
            h('input', {
              className: 'dsv_input',
              style: { paddingLeft: '10px' },
              value: path,
              placeholder: t('logs.path'),
              onChange: (event) => setPath(event.target.value),
              onKeyDown: (event) => {
                if (event.key === 'Enter') {
                  event.preventDefault()
                  void load()
                }
              },
              'aria-label': t('logs.path'),
              spellCheck: false,
            })),
          h('button', { type: 'button', className: 'dsv_btn dsv_btnPrimary', disabled: loading || !path.trim().startsWith('/'), onClick: () => { void load() } }, loading ? h('span', { className: 'dsv_spin' }) : h(IconPlay, { size: 12 }), t('logs.load')),
          h('label', { className: 'dsv_check', style: { margin: 0, flex: 'none' } },
            h('input', { type: 'checkbox', checked: follow, onChange: (event) => setFollow(event.target.checked) }),
            h('span', null, t('logs.follow'))),
          h('select', {
            className: 'dsv_select',
            value: String(lines),
            onChange: (event) => setLines(Number(event.target.value)),
            'aria-label': t('logs.lines'),
          },
          [100, 200, 500, 1000, 2000, 5000].map((value) => h('option', { key: value, value: String(value) }, `${value}`))),
          data ? h('span', { className: 'dsv_meta', style: { marginLeft: 'auto' } }, `${t('logs.size')} ${formatSize(data.size)} · ${tf(t, 'logs.updated', { time: formatClock(data.at) })}`) : null),
        h('div', { className: 'dsv_chips' },
          h('span', { className: 'dsv_label' }, t('logs.presets')),
          presets.length === 0
            ? h('span', { className: 'dsv_hint' }, t('logs.noPresets'))
            : presets.map((preset) => h('button', {
              key: preset.path,
              type: 'button',
              className: cx('dsv_chip', path === preset.path && 'dsv_chipActive'),
              title: preset.path,
              onClick: () => {
                setPath(preset.path)
                pathRef.current = preset.path
                setTimeout(() => { void load() }, 0)
              },
            }, preset.path))),
        data && data.truncated ? h(Notice, { kind: 'warn' }, t('logs.truncated')) : null,
        h('pre', { ref: logRef, className: 'dsv_log' }, data ? data.text : t('logs.empty')))
    }

    // ── connected shell ──────────────────────────────────────────────────────

    function ConnectedView({ state, tab, setTab, notify, onRefresh, onDisconnect }) {
      const t = useT()
      const session = state.session
      const server = session.server || {}
      const [refreshing, setRefreshing] = React.useState(false)

      const refresh = async () => {
        setRefreshing(true)
        try {
          await onRefresh()
        } finally {
          setRefreshing(false)
        }
      }

      return h(React.Fragment, null,
        h('div', { className: 'dsv_toolbar', style: { padding: '0 clamp(20px,3vw,36px)' } },
          h('div', { className: 'dsv_kv' },
            h('span', { className: 'dsv_mono' }, `${session.username}@${session.host}:${session.port}`),
            server.hostname ? h('span', null, `· ${server.hostname}`) : null,
            server.os ? h('span', null, `· ${server.os}`) : null,
            h('span', null, `· ${session.auth === 'agent' ? t('conn.auth.agent') : t('conn.auth.password')}${session.keySource === 'private-key' ? ' (~/.ssh)' : ''}`),
            h('span', { title: String(session.fingerprint || '') }, `· ${t('conn.fingerprint')} ${String(session.fingerprint || '').replace('SHA256:', '').slice(0, 16)}…`)),
          h('span', { className: 'dsv_spacer' }),
          h('button', { type: 'button', className: 'dsv_btn', onClick: () => { void refresh() } }, refreshing ? h('span', { className: 'dsv_spin' }) : h(IconRefresh, { size: 13 }), t('common.refresh')),
          h('button', { type: 'button', className: 'dsv_btn dsv_btnDanger', onClick: onDisconnect }, h(IconStop, { size: 12 }), t('common.disconnect'))),
        h('div', { className: 'dsv_tabs', style: { padding: '0 clamp(20px,3vw,36px)' } },
          h('button', { type: 'button', className: cx('dsv_tab', tab === 'files' && 'dsv_tabActive'), onClick: () => setTab('files'), 'aria-pressed': tab === 'files' }, h(IconFolder, { size: 14 }), t('tab.files')),
          h('button', { type: 'button', className: cx('dsv_tab', tab === 'processes' && 'dsv_tabActive'), onClick: () => setTab('processes'), 'aria-pressed': tab === 'processes' }, h(IconServer, { size: 14 }), t('tab.processes')),
          h('button', { type: 'button', className: cx('dsv_tab', tab === 'logs' && 'dsv_tabActive'), onClick: () => setTab('logs'), 'aria-pressed': tab === 'logs' }, h(IconFile, { size: 14 }), t('tab.logs'))),
        h('div', { className: 'dsv_body' },
          tab === 'files' ? h(FilesTab, { session, limits: state.limits, notify }) : null,
          tab === 'processes' ? h(ProcessesTab, { notify }) : null,
          tab === 'logs' ? h(LogsTab, { notify }) : null))
    }

    // ── root view ────────────────────────────────────────────────────────────

    function View() {
      const t = useT()
      const [state, setState] = React.useState(null)
      const [loading, setLoading] = React.useState(true)
      const [error, setError] = React.useState(null)
      const [busy, setBusy] = React.useState(false)
      const [toast, setToast] = React.useState(null)
      const [tab, setTab] = React.useState('files')
      const [dialog, setDialog] = React.useState(null)
      const [form, setForm] = React.useState({ id: '', name: '', host: '', port: '22', username: '', password: '', remember: true, auth: '' })
      const lastAttempt = React.useRef(null)
      const previousSession = React.useRef(null)

      const notify = React.useCallback((message, kind) => {
        setToast({ message: String(message), kind: kind || 'info' })
      }, [])

      const refresh = React.useCallback(async () => {
        try {
          const value = await rpc('state')
          setState(value)
          setError(null)
        } catch (failure) {
          setError(failure)
        } finally {
          setLoading(false)
        }
      }, [])

      React.useEffect(() => {
        void refresh()
        const timer = setInterval(() => { void refresh() }, 15000)
        return () => clearInterval(timer)
      }, [refresh])

      React.useEffect(() => {
        const had = previousSession.current
        previousSession.current = state ? state.session : null
        if (had && state && !state.session) {
          setToast({ message: t('common.disconnected'), kind: 'warn' })
        }
      }, [state, t])

      React.useEffect(() => {
        if (!toast) return undefined
        const timer = setTimeout(() => setToast(null), 5000)
        return () => clearTimeout(timer)
      }, [toast])

      const agentAvailable = Boolean(state && state.agent && state.agent.available)
      React.useEffect(() => {
        if (!state || form.auth !== '') return
        setForm((current) => (current.auth !== '' ? current : { ...current, auth: agentAvailable ? 'agent' : 'password' }))
      }, [state, form.auth, agentAvailable])

      const connect = React.useCallback(async (input) => {
        const effectiveAuth = form.auth || (agentAvailable ? 'agent' : 'password')
        const payload = input || {
          profileId: form.id || undefined,
          host: form.host.trim(),
          port: Number(form.port) || 22,
          username: form.username.trim(),
          name: form.name.trim() || undefined,
          auth: effectiveAuth,
          remember: form.remember === true,
          ...(effectiveAuth === 'password' && form.password !== '' ? { password: form.password } : {}),
        }
        setBusy(true)
        setError(null)
        lastAttempt.current = payload
        try {
          const result = await rpc('connect', payload)
          setState(result.state)
          if (result.warning) setToast({ message: result.warning, kind: 'warn' })
          setForm((current) => ({ ...current, password: '' }))
        } catch (failure) {
          setError(failure)
        } finally {
          setBusy(false)
        }
      }, [form, agentAvailable])

      const applyControl = (result) => {
        if (result && result.state) setState(result.state)
      }

      const openVault = async () => {
        const exists = state && state.vault && state.vault.exists
        setDialog({ kind: exists ? 'unlock' : 'create' })
      }

      const deleteProfile = (profile) => {
        setDialog({
          kind: 'confirm',
          title: t('conn.deleteProfile'),
          message: tf(t, 'conn.deleteConfirm', { name: profile.name }),
          danger: true,
          confirmLabel: t('common.delete'),
          onConfirm: async () => {
            applyControl(await rpc('profile.delete', { id: profile.id }))
            setDialog(null)
          },
        })
      }

      const trustHost = async () => {
        if (!error || !error.details) return
        try {
          await rpc('host.forget', { host: error.details.host, port: error.details.port })
          notify(t('host.forgotten'), 'info')
          if (lastAttempt.current) await connect(lastAttempt.current)
        } catch (failure) {
          setError(failure)
        }
      }

      const header = h('header', { className: 'dsv_header' },
        h('div', { className: 'dsv_headerRow' },
          h('div', { className: 'dsv_headerTitle' }, h('span', { className: 'dsv_glyph' }, h(IconServer, { size: 18 })), h('h1', null, t('panel'))),
          state
            ? h('span', { className: 'dsv_status' }, h('span', { className: cx('dsv_dot', state.session ? 'dsv_dotOn' : '') }), state.session ? t('common.connected') : t('common.disconnected'))
            : null,
          state && state.session
            ? h('span', { className: 'dsv_badge' }, `${state.session.username}@${state.session.host}`)
            : null,
          state ? h('span', { className: cx('dsv_badge', state.vault.unlocked ? 'dsv_badgeOn' : '') },
            state.vault.unlocked ? h(IconUnlock, { size: 11 }) : h(IconLock, { size: 11 }),
            state.vault.unlocked ? t('vault.unlocked') : state.vault.exists ? t('vault.locked') : t('vault.missing')) : null,
          h('span', { className: 'dsv_spacer' }),
          state && !state.vault.unlocked && state.vault.exists
            ? h('button', { type: 'button', className: 'dsv_btn', onClick: openVault }, h(IconUnlock, { size: 13 }), t('common.unlock'))
            : null,
          state && state.vault.unlocked
            ? h('button', {
              type: 'button',
              className: 'dsv_btn',
              onClick: async () => {
                try {
                  applyControl(await rpc('vault.lock'))
                  notify(t('vault.lockedToast'), 'info')
                } catch (failure) {
                  notify(failure.message || String(failure), 'error')
                }
              },
            }, h(IconLock, { size: 13 }), t('common.lock'))
            : null),
        state && state.session
          ? h('div', { className: 'dsv_headerRow' },
            h('div', { className: 'dsv_meta' },
              `${state.session.username}@${state.session.host}:${state.session.port}`,
              state.session.server && state.session.server.hostname ? ` · ${state.session.server.hostname}` : '',
              state.session.server && state.session.server.os ? ` · ${state.session.server.os}` : ''))
          : h('div', { className: 'dsv_meta' }, t('conn.title')))

      let content = null
      if (loading && !state) {
        content = h('div', { className: 'dsv_fillCenter' }, h('span', { className: 'dsv_spin' }), t('common.loading'))
      } else if (!state) {
        content = h('div', { className: 'dsv_scroll' }, h('div', { className: 'dsv_content dsv_narrow' },
          h(Notice, { kind: 'error' }, error ? (error.code === 'unauthorized' ? t('error.unauthorized') : error.message) : t('error.title')),
          h('button', { type: 'button', className: 'dsv_btn dsv_btnPrimary', onClick: () => { void refresh() } }, t('common.retry'))))
      } else if (state.session) {
        content = h(ConnectedView, {
          state,
          tab,
          setTab,
          notify,
          onRefresh: refresh,
          onDisconnect: async () => {
            try {
              applyControl(await rpc('disconnect'))
            } catch (failure) {
              notify(failure.message || String(failure), 'error')
            }
          },
        })
      } else {
        content = h(ConnectionView, {
          state,
          form,
          setForm,
          busy,
          error,
          onConnect: (input, retry) => {
            if (retry) return trustHost()
            return connect(input)
          },
          onSelectProfile: (profile) => {
            const authMode = profile.auth === 'agent' ? 'agent' : 'password'
            setForm({
              id: profile.id,
              name: profile.name,
              host: profile.host,
              port: String(profile.port),
              username: profile.username,
              password: '',
              remember: true,
              auth: authMode,
            })
            if (authMode === 'agent') {
              void connect({ profileId: profile.id, auth: 'agent', remember: true })
            } else if (profile.hasPassword && state.vault.unlocked) {
              void connect({ profileId: profile.id, auth: 'password', remember: true })
            }
          },
          onDeleteProfile: deleteProfile,
          onOpenVault: openVault,
          onToggleAutoConnect: async (autoConnect) => {
            try {
              applyControl(await rpc('settings.save', { autoConnect }))
            } catch (failure) {
              notify(failure.message || String(failure), 'error')
            }
          },
          onRetryAuto: () => {
            if (!state.lastProfileId) return undefined
            return connect({ profileId: state.lastProfileId, auth: 'agent', remember: true })
          },
          onLockVault: async () => {
            try {
              applyControl(await rpc('vault.lock'))
              notify(t('vault.lockedToast'), 'info')
            } catch (failure) {
              notify(failure.message || String(failure), 'error')
            }
          },
        })
      }

      const dialogs = []
      if (dialog && (dialog.kind === 'unlock' || dialog.kind === 'create')) {
        dialogs.push(h(VaultDialog, {
          key: 'vault',
          mode: dialog.kind,
          onClose: () => setDialog(null),
          onDone: (result) => {
            applyControl(result)
            setDialog(null)
            notify(dialog.kind === 'create' ? t('vault.createdToast') : t('vault.unlockedToast'), 'info')
          },
        }))
      }
      if (dialog && dialog.kind === 'confirm') {
        dialogs.push(h(ConfirmDialog, {
          key: 'confirm',
          title: dialog.title,
          message: dialog.message,
          danger: dialog.danger,
          confirmLabel: dialog.confirmLabel,
          onCancel: () => setDialog(null),
          onConfirm: dialog.onConfirm,
        }))
      }

      return h('div', { className: 'dsv_page' },
        header,
        content,
        toast ? h('div', { className: 'dsv_toast' }, toast.message) : null,
        dialogs)
    }

    function ServerViewPage(props) {
      const t = typeof props.t === 'function' ? props.t : (key) => key
      return h(TContext.Provider, { value: t },
        h('style', null, CSS),
        h(ErrorBoundary, null, h(View, null)))
    }

    function PanelIcon(props) {
      const size = (props && props.size) || 18
      return h('span', { style: { display: 'inline-flex', color: 'currentColor' } }, h(IconServer, { size }))
    }

    const dictionaries = { zh: ZH, en: EN }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        ctx.effect(() => ctx.locale.register(NS, dictionaries), 'ssh-view: dictionaries')
        const t = ctx.locale.bind(NS)
        ctx.slots.inject('main', () => ctx.slots.register({
          name: 'main',
          key: PANEL_ID,
          locale: NS,
        }, ServerViewPage))
        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
          name: 'sidebar.panellist',
          id: PANEL_ID,
          order: 20,
          locale: NS,
          label: () => t('panel'),
        }, PanelIcon))
      },
    }
  },
})
