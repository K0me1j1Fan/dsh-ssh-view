/**
 * Host-side service behind the SSH server view.
 *
 * Owns the credential vault, the known-host table, the live SSH session, and
 * every operation the authenticated /api routes expose. All remote paths are
 * normalized to absolute POSIX paths; every shell command interpolates only
 * validated integers or single-quoted strings.
 */
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join, posix } from 'node:path'
import { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { Vault, VaultError } from './vault.js'
import { SshError, SshSession } from './ssh.js'

const DEFAULTS = {
  connectTimeoutMs: 20000,
  autoLockMinutes: 15,
  maxTextBytes: 2 * 1024 * 1024,
  maxUploadBytes: 1024 * 1024 * 1024,
  maxExecBytes: 4 * 1024 * 1024,
  maxTailBytes: 1024 * 1024,
  maxTailLines: 5000,
  maxDirEntries: 5000,
}

const SIGNALS = new Set(['TERM', 'KILL'])

/** Paths that may never be removed or renamed by this view. */
const PROTECTED_PATHS = new Set([
  '/',
  '/bin',
  '/boot',
  '/dev',
  '/etc',
  '/home',
  '/lib',
  '/lib32',
  '/lib64',
  '/media',
  '/mnt',
  '/opt',
  '/proc',
  '/root',
  '/run',
  '/sbin',
  '/srv',
  '/sys',
  '/tmp',
  '/usr',
  '/var',
])

const LOG_PRESETS = [
  '/var/log/syslog',
  '/var/log/messages',
  '/var/log/auth.log',
  '/var/log/secure',
  '/var/log/kern.log',
  '/var/log/dpkg.log',
  '/var/log/nginx/access.log',
  '/var/log/nginx/error.log',
  '/var/log/apache2/access.log',
  '/var/log/apache2/error.log',
  '/var/log/mysql/error.log',
  '/var/log/cloud-init.log',
]

export class ViewError extends Error {
  /**
   * @param {string} code stable client-facing code.
   * @param {string} message human text.
   * @param {object} [details] structured payload for the client.
   */
  constructor(code, message, details) {
    super(message)
    this.name = 'ViewError'
    this.code = code
    if (details !== undefined) this.details = details
  }
}

function clampInt(value, min, max, fallback) {
  const number = Number(value)
  if (!Number.isFinite(number)) return fallback
  const integer = Math.trunc(number)
  if (integer < min) return min
  if (integer > max) return max
  return integer
}

/** Normalize and validate an absolute remote path. */
export function remotePath(input) {
  if (typeof input !== 'string' || input.trim() === '') throw new ViewError('bad-path', '路径不能为空。')
  if (input.length > 4096) throw new ViewError('bad-path', '路径过长。')
  if (!input.startsWith('/')) throw new ViewError('bad-path', '路径必须是绝对路径。')
  if (/[\0\r\n]/.test(input)) throw new ViewError('bad-path', '路径包含非法字符。')
  return posix.normalize(input)
}

/** POSIX single-quote escaping for shell interpolation. */
export function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`
}

function modeString(mode) {
  const type = mode & 0o170000
  const lead = type === 0o040000 ? 'd' : type === 0o120000 ? 'l' : type === 0o140000 ? 's' : type === 0o010000 ? 'p' : '-'
  const bits = ['r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x']
  let out = lead
  for (let index = 0; index < 9; index += 1) {
    const mask = 1 << (8 - index)
    out += mode & mask ? bits[index] : '-'
  }
  if (mode & 0o4000) out = `${out.slice(0, 3)}${out[3] === 'x' ? 's' : 'S'}${out.slice(4)}`
  if (mode & 0o2000) out = `${out.slice(0, 6)}${out[6] === 'x' ? 's' : 'S'}${out.slice(7)}`
  if (mode & 0o1000) out = `${out.slice(0, 9)}${out[9] === 'x' ? 't' : 'T'}`
  return out
}

function fileType(attrs) {
  if (attrs.isDirectory()) return 'dir'
  if (attrs.isSymbolicLink()) return 'symlink'
  if (attrs.isFile()) return 'file'
  return 'other'
}

function contentVersion(buffer) {
  return createHash('sha256').update(buffer).digest('hex').slice(0, 32)
}

function looksBinary(buffer) {
  const limit = Math.min(buffer.length, 8192)
  for (let index = 0; index < limit; index += 1) if (buffer[index] === 0) return true
  return false
}

function publicProfile(row, saved) {
  return {
    id: row.id,
    name: row.name || `${row.username}@${row.host}`,
    host: row.host,
    port: row.port,
    username: row.username,
    hasPassword: typeof row.password === 'string' && row.password.length > 0,
    saved,
    updatedAt: row.updatedAt || 0,
  }
}

function hostKeyOf(host, port) {
  return `${host}:${port}`
}

function text(value, limit = 4096) {
  if (typeof value !== 'string') return ''
  return value.slice(0, limit)
}

export class ServerViewService {
  /**
   * @param {object} options
   * @param {Record<string, unknown>} [options.config]
   * @param {{warn?: Function, info?: Function, debug?: Function}} [options.logger]
   */
  constructor({ config = {}, logger } = {}) {
    this.config = {
      ...DEFAULTS,
      ...Object.fromEntries(Object.entries(config || {}).filter(([, value]) => value !== undefined && value !== null)),
    }
    this.logger = logger
    const root =
      typeof config?.dataDir === 'string' && config.dataDir.trim() !== ''
        ? config.dataDir
        : join(process.env.DSH_HOME || join(homedir(), '.dsh'), 'storages', 'ssh-view')
    this.dataDir = root
    this.vault = new Vault(join(root, 'vault.json'))
    this.hostFile = join(root, 'hosts.json')
    /** @type {Record<string, {fingerprint: string, firstSeen: number, lastSeen: number}>} */
    this.knownHosts = this.#loadKnownHosts()
    /** @type {Map<string, object>} */
    this.memoryProfiles = new Map()
    /** @type {SshSession | null} */
    this.session = null
    this.sessionInfo = null
    this.lastVaultUse = 0
    this.lockedNotice = ''
    this.idleTimer = setInterval(() => this.#autoLock(), 60_000)
    this.idleTimer.unref?.()
  }

  // ── known hosts ────────────────────────────────────────────────────────────

  #loadKnownHosts() {
    try {
      const parsed = JSON.parse(readFileSync(this.hostFile, 'utf8'))
      if (parsed && typeof parsed === 'object') {
        const rows = {}
        for (const [key, entry] of Object.entries(parsed)) {
          if (entry && typeof entry === 'object' && typeof entry.fingerprint === 'string') {
            rows[key] = {
              fingerprint: entry.fingerprint,
              firstSeen: Number(entry.firstSeen) || Date.now(),
              lastSeen: Number(entry.lastSeen) || Date.now(),
            }
          }
        }
        return rows
      }
    } catch {
      /* absent or unreadable: start with an empty table */
    }
    return {}
  }

  async #saveKnownHosts() {
    try {
      await mkdir(this.dataDir, { recursive: true, mode: 0o700 })
      const temp = `${this.hostFile}.${randomBytes(4).toString('hex')}.tmp`
      await writeFile(temp, JSON.stringify(this.knownHosts, null, 2), { mode: 0o600 })
      await rename(temp, this.hostFile)
    } catch (error) {
      this.logger?.warn?.(`ssh-view: 无法保存主机指纹表 (${error && error.message ? error.message : error})`)
    }
  }

  // ── vault ──────────────────────────────────────────────────────────────────

  async createVault(passphrase) {
    await this.vault.create(passphrase)
    this.lastVaultUse = Date.now()
    return { state: this.controlState() }
  }

  async unlockVault(passphrase) {
    await this.vault.unlock(passphrase)
    this.lastVaultUse = Date.now()
    return { state: this.controlState() }
  }

  lockVault() {
    this.vault.lock()
    this.lastVaultUse = 0
    this.lockedNotice = ''
    return { state: this.controlState() }
  }

  #autoLock() {
    const minutes = Number(this.config.autoLockMinutes) || 0
    if (minutes <= 0 || !this.vault.unlocked) return
    if (Date.now() - this.lastVaultUse < minutes * 60_000) return
    this.lockVault()
    this.logger?.info?.('ssh-view: 凭据库因闲置已自动锁定')
  }

  // ── profiles ───────────────────────────────────────────────────────────────

  /** @returns {object[]} client-safe profile rows (never includes passwords) */
  listProfiles() {
    const rows = []
    const seen = new Set()
    if (this.vault.unlocked) {
      for (const row of this.vault.profiles) {
        seen.add(row.id)
        rows.push(publicProfile(row, true))
      }
    }
    for (const [id, row] of this.memoryProfiles) {
      if (seen.has(id)) continue
      rows.push(publicProfile(row, false))
    }
    rows.sort((a, b) => String(a.name).localeCompare(String(b.name)))
    return rows
  }

  #findProfile(id) {
    if (typeof id !== 'string' || id === '') return undefined
    if (this.vault.unlocked) {
      const row = this.vault.profile(id)
      if (row) return { ...row, saved: true }
    }
    const row = this.memoryProfiles.get(id)
    return row ? { ...row, saved: false } : undefined
  }

  async saveProfile(input) {
    const profile = this.#validateProfileInput(input)
    if (!this.vault.unlocked) {
      this.memoryProfiles.set(profile.id, { ...profile, saved: false })
      return { state: this.controlState(), warning: '凭据库未解锁，连接只保存在本次运行的内存中。' }
    }
    await this.vault.putProfile(profile)
    this.memoryProfiles.delete(profile.id)
    this.lastVaultUse = Date.now()
    return { state: this.controlState() }
  }

  async deleteProfile(id) {
    if (typeof id !== 'string' || id === '') throw new ViewError('bad-request', '缺少连接 id。')
    let removed = false
    if (this.vault.unlocked) removed = (await this.vault.removeProfile(id)) || removed
    removed = this.memoryProfiles.delete(id) || removed
    if (removed) this.lastVaultUse = Date.now()
    return { state: this.controlState() }
  }

  #validateProfileInput(input) {
    const source = input && typeof input === 'object' ? input : {}
    const host = text(source.host, 255).trim()
    if (!host || /[\s\0]/.test(host)) throw new ViewError('bad-host', '请输入有效的主机地址。')
    const port = clampInt(source.port, 1, 65535, 22)
    const username = text(source.username, 128).trim()
    if (!username || /[\s\0]/.test(username)) throw new ViewError('bad-username', '请输入有效的用户名。')
    const password = typeof source.password === 'string' ? source.password : ''
    if (password.length > 4096) throw new ViewError('bad-password', '密码过长。')
    const id = typeof source.id === 'string' && /^[a-f0-9-]{8,64}$/i.test(source.id) ? source.id : randomBytes(8).toString('hex')
    return {
      id,
      name: text(source.name, 120).trim() || `${username}@${host}`,
      host,
      port,
      username,
      password,
      updatedAt: Date.now(),
    }
  }

  // ── session ────────────────────────────────────────────────────────────────

  async connect(input = {}) {
    const source = input && typeof input === 'object' ? input : {}
    const base = this.#findProfile(source.profileId)
    const host = text(source.host ?? base?.host, 255).trim()
    const port = clampInt(source.port ?? base?.port, 1, 65535, 22)
    const username = text(source.username ?? base?.username, 128).trim()
    if (!host || /[\s\0]/.test(host)) throw new ViewError('bad-host', '请输入有效的主机地址。')
    if (!username || /[\s\0]/.test(username)) throw new ViewError('bad-username', '请输入有效的用户名。')
    const suppliedPassword = typeof source.password === 'string' ? source.password : ''
    const password = suppliedPassword !== '' ? suppliedPassword : base?.password || ''
    if (!password) throw new ViewError('password-required', '请输入登录密码。')

    if (this.session) {
      this.session.dispose()
      this.session = null
      this.sessionInfo = null
    }

    const profile = {
      id: base?.id || randomBytes(8).toString('hex'),
      name: text(source.name ?? base?.name, 120).trim() || `${username}@${host}`,
      host,
      port,
      username,
    }
    const key = hostKeyOf(host, port)
    const known = this.knownHosts[key]
    const session = new SshSession({
      profile,
      connectTimeoutMs: Number(this.config.connectTimeoutMs) || DEFAULTS.connectTimeoutMs,
      maxExecBytes: Number(this.config.maxExecBytes) || DEFAULTS.maxExecBytes,
      onClosed: () => {
        if (this.session === session) {
          this.session = null
        }
      },
    })

    try {
      await session.connect(password, { knownFingerprint: known ? known.fingerprint : '' })
    } catch (error) {
      session.dispose()
      if (error instanceof SshError && error.code === 'host-key-mismatch') {
        throw new ViewError(
          'host-key-mismatch',
          `主机 ${key} 的指纹与已保存的不一致，连接已中止。\n已保存：${known ? known.fingerprint : '无'}\n本次：${session.observedFingerprint}`,
          {
            host,
            port,
            knownFingerprint: known ? known.fingerprint : '',
            observedFingerprint: session.observedFingerprint,
          },
        )
      }
      throw error instanceof ViewError ? error : new ViewError(error.code || 'connect-failed', error.message)
    }

    if (!known || known.fingerprint !== session.fingerprint) {
      this.knownHosts[key] = {
        fingerprint: session.fingerprint,
        firstSeen: known ? known.firstSeen : Date.now(),
        lastSeen: Date.now(),
      }
      void this.#saveKnownHosts()
    } else {
      known.lastSeen = Date.now()
    }

    this.session = session
    let facts = { hostname: '', kernel: '', os: '', user: username, load: [], uptimeSec: 0, mem: null, disk: null, home: '' }
    try {
      facts = await session.readServerFacts()
    } catch (error) {
      this.logger?.warn?.(`ssh-view: 读取服务器信息失败 (${error && error.message ? error.message : error})`)
    }
    this.sessionInfo = {
      profileId: profile.id,
      name: profile.name,
      host,
      port,
      username,
      connectedAt: Date.now(),
      fingerprint: session.fingerprint,
      server: facts,
    }

    const warnings = []
    if (source.remember === true) {
      if (this.vault.unlocked) {
        const row = {
          id: profile.id,
          name: profile.name,
          host,
          port,
          username,
          password,
          updatedAt: Date.now(),
        }
        try {
          await this.vault.putProfile(row)
          this.memoryProfiles.delete(profile.id)
          this.lastVaultUse = Date.now()
        } catch (error) {
          warnings.push(`连接成功，但凭据保存失败：${error && error.message ? error.message : error}`)
        }
      } else {
        warnings.push('连接成功，但凭据库未解锁，密码只保存在本次运行的内存中。')
        this.memoryProfiles.set(profile.id, { ...profile, password, updatedAt: Date.now() })
      }
    } else if (source.save === true) {
      // Save host/user metadata without the password when the caller asked to
      // remember the connection but not its secret.
      const row = { id: profile.id, name: profile.name, host, port, username, password: '', updatedAt: Date.now() }
      if (this.vault.unlocked) {
        await this.vault.putProfile(row)
      } else {
        this.memoryProfiles.set(profile.id, { ...row, saved: false })
      }
    }
    return { state: this.controlState(), warning: warnings.length ? warnings.join(' ') : undefined }
  }

  disconnect() {
    if (this.session) {
      this.session.dispose()
      this.session = null
    }
    this.sessionInfo = null
    return { state: this.controlState() }
  }

  #requireSession() {
    if (!this.session || !this.session.connected) throw new ViewError('not-connected', 'SSH 连接已断开，请重新连接。')
    return this.session
  }

  #sessionPayload() {
    if (!this.sessionInfo || !this.session || !this.session.connected) return null
    return this.sessionInfo
  }

  /** State every control operation returns so the client can re-render. */
  controlState() {
    return {
      vault: {
        exists: this.vault.exists,
        unlocked: this.vault.unlocked,
        autoLockMinutes: Number(this.config.autoLockMinutes) || 0,
      },
      profiles: this.listProfiles(),
      session: this.#sessionPayload(),
      limits: {
        maxTextBytes: Number(this.config.maxTextBytes) || DEFAULTS.maxTextBytes,
        maxUploadBytes: Number(this.config.maxUploadBytes) || DEFAULTS.maxUploadBytes,
        maxTailLines: DEFAULTS.maxTailLines,
      },
      now: Date.now(),
    }
  }

  // ── SFTP helpers ───────────────────────────────────────────────────────────

  async #sftp() {
    const session = this.#requireSession()
    try {
      return await session.sftp()
    } catch (error) {
      throw error instanceof ViewError ? error : new ViewError(error.code || 'sftp-unavailable', error.message)
    }
  }

  #mapSftpError(error) {
    // ssh2 reports SFTP protocol failures as a numeric status code in `code`
    // (2 = no such file, 3 = permission denied, 7 = connection lost, ...),
    // while local errors use errno strings.
    const numeric = typeof error?.code === 'number' ? error.code : 0
    const code = typeof error?.code === 'string' ? error.code : ''
    const message = String(error?.message || error || '')
    const map = {
      ENOENT: ['not-found', '文件或目录不存在。'],
      EACCES: ['permission-denied', '没有权限访问该路径。'],
      EPERM: ['permission-denied', '没有权限访问该路径。'],
      EEXIST: ['exists', '目标已存在。'],
      ENOTDIR: ['not-directory', '该路径不是目录。'],
      EISDIR: ['is-directory', '该路径是一个目录。'],
      ENOTEMPTY: ['not-empty', '目录不为空。'],
      EROFS: ['read-only', '目标文件系统是只读的。'],
      ENOSPC: ['no-space', '目标磁盘空间不足。'],
      ENAMETOOLONG: ['bad-path', '路径过长。'],
    }
    let row = map[code]
    if (!row && numeric === 2) row = ['not-found', '文件或目录不存在。']
    if (!row && numeric === 3) row = ['permission-denied', '没有权限访问该路径。']
    if (!row && numeric === 7) row = ['disconnected', 'SFTP 连接已断开。']
    if (!row && numeric === 8) row = ['unsupported', '服务器不支持该 SFTP 操作。']
    if (!row && /no such file/i.test(message)) row = ['not-found', '文件或目录不存在。']
    if (!row && /permission denied/i.test(message)) row = ['permission-denied', '没有权限访问该路径。']
    return new ViewError(row ? row[0] : 'sftp-error', row ? row[1] : `SFTP 操作失败：${message}`)
  }

  async #call(sftp, method, ...args) {
    try {
      return await new Promise((resolve, reject) => {
        sftp[method](...args, (error, result) => (error ? reject(this.#mapSftpError(error)) : resolve(result)))
      })
    } catch (error) {
      throw error instanceof ViewError ? error : this.#mapSftpError(error)
    }
  }

  async #stat(sftp, path) {
    try {
      return await this.#call(sftp, 'stat', path)
    } catch (error) {
      if (error.code === 'not-found') return null
      throw error
    }
  }

  async #readdir(sftp, path) {
    const entries = await this.#call(sftp, 'readdir', path)
    if (!Array.isArray(entries)) return []
    return entries
      .filter((entry) => entry && entry.filename !== '.' && entry.filename !== '..')
      .sort((a, b) => {
        const aDir = a.attrs && a.attrs.isDirectory() ? 0 : 1
        const bDir = b.attrs && b.attrs.isDirectory() ? 0 : 1
        if (aDir !== bDir) return aDir - bDir
        return String(a.filename).localeCompare(String(b.filename), undefined, { numeric: true })
      })
      .slice(0, Number(this.config.maxDirEntries) || DEFAULTS.maxDirEntries)
  }

  async #deleteTree(sftp, path, budget) {
    if (budget.count > 20000) throw new ViewError('too-many', '目录条目过多，已停止递归删除。')
    const attrs = await this.#stat(sftp, path)
    if (!attrs) return
    if (!attrs.isDirectory()) {
      await this.#call(sftp, 'unlink', path)
      return
    }
    const entries = await this.#readdir(sftp, path)
    for (const entry of entries) {
      budget.count += 1
      await this.#deleteTree(sftp, posix.join(path, entry.filename), budget)
    }
    await this.#call(sftp, 'rmdir', path)
  }

  #homePath() {
    const home = this.sessionInfo?.server?.home
    return typeof home === 'string' && home.startsWith('/') ? home : ''
  }

  // ── filesystem ops ─────────────────────────────────────────────────────────

  async listDir(rawPath) {
    const path = remotePath(rawPath)
    const sftp = await this.#sftp()
    const attrs = await this.#stat(sftp, path)
    if (!attrs) throw new ViewError('not-found', `目录不存在：${path}`)
    if (!attrs.isDirectory()) throw new ViewError('not-directory', `不是目录：${path}`)
    const entries = await this.#readdir(sftp, path)
    return {
      path,
      parent: path === '/' ? null : posix.dirname(path),
      home: this.#homePath(),
      entries: entries.map((entry) => ({
        name: entry.filename,
        path: posix.join(path, entry.filename),
        type: fileType(entry.attrs),
        size: Number(entry.attrs.size) || 0,
        mtime: Number(entry.attrs.mtime) || 0,
        mode: modeString(entry.attrs.mode || 0),
      })),
    }
  }

  async readFile(rawPath) {
    const path = remotePath(rawPath)
    const sftp = await this.#sftp()
    const attrs = await this.#stat(sftp, path)
    if (!attrs) throw new ViewError('not-found', `文件不存在：${path}`)
    if (attrs.isDirectory()) throw new ViewError('is-directory', '该路径是一个目录。')
    const maxBytes = Number(this.config.maxTextBytes) || DEFAULTS.maxTextBytes
    if (Number(attrs.size) > maxBytes) {
      return { path, tooLarge: true, size: Number(attrs.size) || 0, mtime: Number(attrs.mtime) || 0, maxBytes }
    }
    const buffer = await this.#call(sftp, 'readFile', path)
    if (looksBinary(buffer)) {
      return { path, binary: true, size: Number(attrs.size) || 0, mtime: Number(attrs.mtime) || 0 }
    }
    return {
      path,
      binary: false,
      content: buffer.toString('utf8'),
      size: Number(attrs.size) || 0,
      mtime: Number(attrs.mtime) || 0,
      version: contentVersion(buffer),
      mode: modeString(attrs.mode || 0),
    }
  }

  async writeFile(rawPath, content, options = {}) {
    const path = remotePath(rawPath)
    if (typeof content !== 'string') throw new ViewError('bad-request', '缺少文件内容。')
    const maxBytes = Number(this.config.maxTextBytes) || DEFAULTS.maxTextBytes
    if (Buffer.byteLength(content, 'utf8') > maxBytes) throw new ViewError('too-large', '文件内容超过可编辑大小上限。')
    const sftp = await this.#sftp()
    const current = await this.#stat(sftp, path)
    if (current && current.isDirectory()) throw new ViewError('is-directory', '该路径是一个目录。')
    const buffer = Buffer.from(content, 'utf8')
    const expectedVersion = typeof options.expectedVersion === 'string' ? options.expectedVersion : ''
    const expected = Number(options.expectedMtime)
    if (options.force !== true) {
      if (expectedVersion) {
        // Content hash beats mtime granularity: two writes inside the same
        // second would otherwise look identical to the conflict check.
        if (!current) {
          throw new ViewError('conflict', '文件已被删除，请重新加载。')
        }
        const existing = await this.#call(sftp, 'readFile', path)
        if (contentVersion(existing) !== expectedVersion) {
          throw new ViewError('conflict', '文件在打开后已被修改，请先重新加载。', {
            currentMtime: Number(current.mtime) || 0,
            size: Number(current.size) || 0,
          })
        }
      } else if (current && Number.isFinite(expected) && expected > 0 && Number(current.mtime) !== expected) {
        throw new ViewError('conflict', '文件在打开后已被修改，请先重新加载。', {
          currentMtime: Number(current.mtime) || 0,
          size: Number(current.size) || 0,
        })
      }
    }
    await this.#call(sftp, 'writeFile', path, buffer)
    const after = await this.#stat(sftp, path)
    return {
      path,
      mtime: Number(after?.mtime) || 0,
      size: Number(after?.size) || 0,
      version: contentVersion(buffer),
    }
  }

  async makeDir(rawPath) {
    const path = remotePath(rawPath)
    const sftp = await this.#sftp()
    if (await this.#stat(sftp, path)) throw new ViewError('exists', '目标已存在。')
    await this.#call(sftp, 'mkdir', path, { mode: 0o755 })
    return { path }
  }

  async touchFile(rawPath) {
    const path = remotePath(rawPath)
    const sftp = await this.#sftp()
    if (await this.#stat(sftp, path)) throw new ViewError('exists', '目标已存在。')
    await this.#call(sftp, 'writeFile', path, Buffer.alloc(0))
    return { path }
  }

  async renamePath(rawFrom, rawTo) {
    const from = remotePath(rawFrom)
    const to = remotePath(rawTo)
    if (from === to) throw new ViewError('bad-request', '源路径与目标路径相同。')
    if (PROTECTED_PATHS.has(from)) throw new ViewError('protected', `不允许移动系统路径：${from}`)
    if (PROTECTED_PATHS.has(to)) throw new ViewError('protected', `不允许覆盖系统路径：${to}`)
    if (this.#homePath() && from === this.#homePath()) throw new ViewError('protected', '不允许移动用户主目录。')
    const sftp = await this.#sftp()
    if (!(await this.#stat(sftp, from))) throw new ViewError('not-found', `源路径不存在：${from}`)
    if (await this.#stat(sftp, to)) throw new ViewError('exists', `目标已存在：${to}`)
    await this.#call(sftp, 'rename', from, to)
    return { from, to }
  }

  async removePath(rawPath, options = {}) {
    const path = remotePath(rawPath)
    if (path === '/' || PROTECTED_PATHS.has(path)) throw new ViewError('protected', `不允许删除系统路径：${path}`)
    if (this.#homePath() && path === this.#homePath()) throw new ViewError('protected', '不允许删除用户主目录。')
    const sftp = await this.#sftp()
    const attrs = await this.#stat(sftp, path)
    if (!attrs) throw new ViewError('not-found', `路径不存在：${path}`)
    if (attrs.isDirectory()) {
      if (options.recursive !== true) throw new ViewError('is-directory', '这是一个目录，需要确认递归删除。')
      await this.#deleteTree(sftp, path, { count: 0 })
    } else {
      await this.#call(sftp, 'unlink', path)
    }
    return { path }
  }

  /** Stream `path` to the response body. */
  async openDownload(rawPath) {
    const path = remotePath(rawPath)
    const sftp = await this.#sftp()
    const attrs = await this.#stat(sftp, path)
    if (!attrs) throw new ViewError('not-found', `文件不存在：${path}`)
    if (attrs.isDirectory()) throw new ViewError('is-directory', '目录不能下载。')
    return {
      path,
      name: posix.basename(path),
      size: Number(attrs.size) || 0,
      mtime: Number(attrs.mtime) || 0,
      stream: sftp.createReadStream(path),
    }
  }

  /** Stream an uploaded request body into `path` through a temporary file. */
  async uploadStream(rawPath, webStream, options = {}) {
    const path = remotePath(rawPath)
    const sftp = await this.#sftp()
    const existing = await this.#stat(sftp, path)
    if (existing && existing.isDirectory()) throw new ViewError('is-directory', '目标是一个目录。')
    if (existing && options.overwrite !== true) throw new ViewError('exists', '目标已存在。')
    const directory = posix.dirname(path)
    const temp = posix.join(directory, `.dsh-upload-${randomBytes(6).toString('hex')}`)
    const maxBytes = Number(this.config.maxUploadBytes) || DEFAULTS.maxUploadBytes
    const nodeStream = Readable.fromWeb(webStream)
    let measured = 0
    let oversized = false
    nodeStream.on('data', (chunk) => {
      measured += chunk.length
      if (measured > maxBytes) {
        oversized = true
        nodeStream.destroy(new ViewError('too-large', '上传内容超过大小上限。'))
      }
    })
    try {
      await pipeline(nodeStream, sftp.createWriteStream(temp))
    } catch (error) {
      await this.#call(sftp, 'unlink', temp).catch(() => {})
      if (oversized) throw new ViewError('too-large', '上传内容超过大小上限。')
      throw error instanceof ViewError ? error : this.#mapSftpError(error)
    }
    const total = measured
    await this.#call(sftp, 'rename', temp, path)
    const attrs = await this.#stat(sftp, path)
    return { path, size: Number(attrs?.size) || total, mtime: Number(attrs?.mtime) || 0 }
  }

  // ── processes ──────────────────────────────────────────────────────────────

  async listProcesses() {
    const session = this.#requireSession()
    let result = await session.exec(
      'ps -eo pid=,ppid=,user=,pcpu=,pmem=,rss=,etimes=,stat=,args= --no-headers',
      { timeoutMs: 20000, maxBytes: Number(this.config.maxExecBytes) || DEFAULTS.maxExecBytes },
    )
    let rows = result.stdout
    let parsed = result.code === 0 ? parseProcps(rows) : []
    if (!parsed.length) {
      const fallback = await session.exec('ps aux', { timeoutMs: 20000, maxBytes: Number(this.config.maxExecBytes) || DEFAULTS.maxExecBytes })
      if (fallback.code !== 0 && fallback.stderr.trim()) {
        throw new ViewError('ps-failed', `无法读取进程列表：${fallback.stderr.trim().slice(0, 300)}`)
      }
      rows = fallback.stdout
      parsed = parsePsAux(rows)
    }
    const facts = await session.readServerFacts()
    return {
      at: Date.now(),
      procs: parsed,
      load: facts.load,
      uptimeSec: facts.uptimeSec,
      mem: facts.mem,
      count: parsed.length,
    }
  }

  async killProcess(pidValue, signalValue) {
    const pid = clampInt(pidValue, 0, 4_194_304, 0)
    if (pid <= 1) throw new ViewError('bad-request', '拒绝结束该进程（PID 必须大于 1）。')
    const signal = String(signalValue || 'TERM').toUpperCase()
    if (!SIGNALS.has(signal)) throw new ViewError('bad-request', '只支持 TERM 与 KILL 信号。')
    const session = this.#requireSession()
    const result = await session.exec(`kill -${signal} ${pid}`, { timeoutMs: 15000, maxBytes: 16 * 1024 })
    if (result.code !== 0) {
      throw new ViewError('kill-failed', (result.stderr.trim() || `kill 返回 ${result.code}`).slice(0, 300))
    }
    return { pid, signal }
  }

  // ── logs ───────────────────────────────────────────────────────────────────

  async tailLog(rawPath, options = {}) {
    const path = remotePath(rawPath)
    const lines = clampInt(options.lines, 1, DEFAULTS.maxTailLines, 200)
    const session = this.#requireSession()
    const result = await session.exec(`tail -n ${lines} ${shellQuote(path)}`, {
      timeoutMs: 20000,
      maxBytes: Number(this.config.maxTailBytes) || DEFAULTS.maxTailBytes,
      keep: 'tail',
    })
    if (result.code !== 0) {
      const detail = result.stderr.trim() || `tail 返回 ${result.code}`
      throw new ViewError('tail-failed', detail.slice(0, 300))
    }
    let size = 0
    let mtime = 0
    try {
      const sftp = await this.#sftp()
      const attrs = await this.#stat(sftp, path)
      if (attrs) {
        size = Number(attrs.size) || 0
        mtime = Number(attrs.mtime) || 0
      }
    } catch {
      /* size is advisory */
    }
    return {
      path,
      text: result.stdout,
      lines,
      truncated: result.truncated,
      size,
      mtime,
      at: Date.now(),
    }
  }

  async logPresets() {
    const sftp = await this.#sftp()
    const found = []
    for (const path of LOG_PRESETS) {
      try {
        const attrs = await this.#stat(sftp, path)
        if (attrs && attrs.isFile()) found.push({ path, size: Number(attrs.size) || 0, mtime: Number(attrs.mtime) || 0 })
      } catch {
        /* unreadable preset: skip */
      }
    }
    return { presets: found }
  }

  // ── dispatch ───────────────────────────────────────────────────────────────

  async dispatch(op, params = {}) {
    const input = params && typeof params === 'object' ? params : {}
    switch (op) {
      case 'state':
        return this.controlState()
      case 'vault.create':
        return this.createVault(input.passphrase)
      case 'vault.unlock':
        return this.unlockVault(input.passphrase)
      case 'vault.lock':
        return this.lockVault()
      case 'profile.save':
        return this.saveProfile(input.profile || input)
      case 'profile.delete':
        return this.deleteProfile(input.id)
      case 'connect':
        return this.connect(input)
      case 'disconnect':
        return this.disconnect()
      case 'fs.list':
        return this.listDir(input.path)
      case 'fs.read':
        return this.readFile(input.path)
      case 'fs.write':
        return this.writeFile(input.path, input.content, {
          expectedMtime: input.mtime,
          expectedVersion: input.version,
          force: input.force === true,
        })
      case 'fs.mkdir':
        return this.makeDir(input.path)
      case 'fs.touch':
        return this.touchFile(input.path)
      case 'fs.rename':
        return this.renamePath(input.from, input.to)
      case 'fs.remove':
        return this.removePath(input.path, { recursive: input.recursive === true })
      case 'fs.home':
        return { home: this.#homePath() }
      case 'proc.list':
        return this.listProcesses()
      case 'proc.kill':
        return this.killProcess(input.pid, input.signal)
      case 'logs.tail':
        return this.tailLog(input.path, { lines: input.lines })
      case 'logs.presets':
        return this.logPresets()
      case 'host.forget':
        return this.forgetHost(input.host, input.port)
      case 'ping':
        return { ok: true, at: Date.now() }
      default:
        throw new ViewError('unknown-op', `未知操作：${String(op).slice(0, 80)}`)
    }
  }

  async forgetHost(hostValue, portValue) {
    const host = text(hostValue, 255).trim()
    const port = clampInt(portValue, 1, 65535, 22)
    if (!host) throw new ViewError('bad-request', '缺少主机地址。')
    const key = hostKeyOf(host, port)
    delete this.knownHosts[key]
    await this.#saveKnownHosts()
    return { host, port, forgotten: true }
  }

  dispose() {
    if (this.idleTimer) clearInterval(this.idleTimer)
    if (this.session) this.session.dispose()
    this.session = null
    this.sessionInfo = null
    this.vault.lock()
  }
}

// ── ps parsers ─────────────────────────────────────────────────────────────

/** Parse `ps -eo pid=,ppid=,user=,pcpu=,pmem=,rss=,etimes=,stat=,args=`. */
export function parseProcps(stdout) {
  const rows = []
  for (const line of String(stdout).split('\n')) {
    const text = line.trim()
    if (!text) continue
    const fields = text.split(/\s+/)
    if (fields.length < 8) continue
    const pid = Number(fields[0])
    if (!Number.isInteger(pid) || pid <= 0) continue
    rows.push({
      pid,
      ppid: Number(fields[1]) || 0,
      user: fields[2],
      cpu: Number(fields[3]) || 0,
      mem: Number(fields[4]) || 0,
      rssKb: Number(fields[5]) || 0,
      elapsedSec: Number(fields[6]),
      stat: fields[7],
      args: fields.slice(8).join(' '),
    })
  }
  return rows
}

/** Fallback parser for BusyBox-style `ps aux`. */
export function parsePsAux(stdout) {
  const rows = []
  for (const line of String(stdout).split('\n')) {
    if (!line.trim()) continue
    const fields = line.trim().split(/\s+/)
    if (fields.length < 11) continue
    const pid = Number(fields[1])
    if (!Number.isInteger(pid) || pid <= 0) continue
    rows.push({
      pid,
      ppid: 0,
      user: fields[0],
      cpu: Number(fields[2]) || 0,
      mem: Number(fields[3]) || 0,
      rssKb: Number(fields[5]) || 0,
      elapsedSec: null,
      stat: fields[7],
      args: fields.slice(10).join(' '),
    })
  }
  return rows
}
