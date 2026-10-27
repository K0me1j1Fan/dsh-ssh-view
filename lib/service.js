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
import { SshError, SshSession, defaultAgentSocket, defaultPrivateKey } from './ssh.js'

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

const MAX_ARCHIVE_ENTRIES = 100_000

/** Archive suffixes in longest-first order, so .tar.gz wins over .gz. */
const ARCHIVE_SUFFIXES = [
  ['.tar.gz', 'tar.gz'],
  ['.tgz', 'tar.gz'],
  ['.tar.bz2', 'tar.bz2'],
  ['.tbz2', 'tar.bz2'],
  ['.tbz', 'tar.bz2'],
  ['.tar.xz', 'tar.xz'],
  ['.txz', 'tar.xz'],
  ['.tar', 'tar'],
  ['.zip', 'zip'],
  ['.gz', 'gz'],
  ['.bz2', 'bz2'],
  ['.xz', 'xz'],
]

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

/** Archive type by suffix, or '' for a non-archive name. */
export function archiveType(path) {
  const lower = String(path).toLowerCase()
  for (const [suffix, type] of ARCHIVE_SUFFIXES) if (lower.endsWith(suffix)) return type
  return ''
}

/** File name without its archive suffix, used as the default target directory. */
export function archiveStem(path) {
  const name = posix.basename(String(path))
  const lower = name.toLowerCase()
  for (const [suffix] of ARCHIVE_SUFFIXES) {
    if (lower.endsWith(suffix)) return name.slice(0, name.length - suffix.length) || 'extracted'
  }
  return name
}

/** Reject entries that would escape the target directory or write through a drive path. */
export function unsafeArchiveEntry(name) {
  if (typeof name !== 'string' || name === '') return true
  if (name.includes('\0')) return true
  const normalized = name.replace(/\\/g, '/')
  if (normalized.startsWith('/')) return true
  if (/^[A-Za-z]:/.test(normalized)) return true
  return normalized.split('/').some((part) => part === '..')
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
    auth: row.auth === 'agent' ? 'agent' : 'password',
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
    this.profilesFile = join(root, 'profiles.json')
    /** @type {Record<string, {fingerprint: string, firstSeen: number, lastSeen: number}>} */
    this.knownHosts = this.#loadKnownHosts()
    /** Non-secret connection profiles used for startup auto-connect. */
    this.store = this.#loadProfileStore()
    /** @type {Map<string, object>} */
    this.memoryProfiles = new Map()
    /** @type {SshSession | null} */
    this.session = null
    this.sessionInfo = null
    this.lastVaultUse = 0
    this.lockedNotice = ''
    this.autoConnectError = ''
    this.autoConnectTimer = null
    this.idleTimer = setInterval(() => this.#autoLock(), 60_000)
    this.idleTimer.unref?.()
    this.#scheduleAutoConnect(1200, 0)
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

  // ── profile store (non-secret, auto-connect) ───────────────────────────────

  #loadProfileStore() {
    const fallback = { version: 1, autoConnect: true, lastProfileId: '', profiles: [] }
    try {
      const parsed = JSON.parse(readFileSync(this.profilesFile, 'utf8'))
      if (!parsed || typeof parsed !== 'object') return fallback
      const profiles = []
      for (const row of Array.isArray(parsed.profiles) ? parsed.profiles : []) {
        if (!row || typeof row !== 'object') continue
        if (typeof row.id !== 'string' || typeof row.host !== 'string' || typeof row.username !== 'string') continue
        profiles.push({
          id: row.id,
          name: typeof row.name === 'string' && row.name !== '' ? row.name : `${row.username}@${row.host}`,
          host: row.host,
          port: Number.isInteger(row.port) ? row.port : 22,
          username: row.username,
          auth: 'agent',
          updatedAt: Number(row.updatedAt) || 0,
        })
      }
      const lastProfileId =
        typeof parsed.lastProfileId === 'string' && profiles.some((row) => row.id === parsed.lastProfileId)
          ? parsed.lastProfileId
          : ''
      return { version: 1, autoConnect: parsed.autoConnect !== false, lastProfileId, profiles }
    } catch {
      return fallback
    }
  }

  async #saveProfileStore() {
    try {
      await mkdir(this.dataDir, { recursive: true, mode: 0o700 })
      const temp = `${this.profilesFile}.${randomBytes(4).toString('hex')}.tmp`
      await writeFile(temp, JSON.stringify(this.store, null, 2), { mode: 0o600 })
      await rename(temp, this.profilesFile)
    } catch (error) {
      this.logger?.warn?.(`ssh-view: 无法保存连接配置 (${error && error.message ? error.message : error})`)
    }
  }

  #agentAvailable() {
    return defaultAgentSocket() !== '' || defaultPrivateKey() !== null
  }

  async #rememberAgentProfile(profile) {
    const row = {
      id: profile.id,
      name: profile.name,
      host: profile.host,
      port: profile.port,
      username: profile.username,
      auth: 'agent',
      updatedAt: Date.now(),
    }
    const rows = this.store.profiles
    const index = rows.findIndex((current) => current.id === row.id)
    if (index >= 0) rows[index] = row
    else rows.push(row)
    this.store.lastProfileId = row.id
    await this.#saveProfileStore()
  }

  #scheduleAutoConnect(delay, attempt) {
    if (this.config.autoConnect === false) return
    if (!this.store.autoConnect) return
    const id = this.store.lastProfileId
    if (!id) return
    if (!this.store.profiles.some((row) => row.id === id)) return
    if (this.autoConnectTimer) clearTimeout(this.autoConnectTimer)
    this.autoConnectTimer = setTimeout(async () => {
      this.autoConnectTimer = null
      if (this.session) return
      try {
        await this.connect({ profileId: id, auth: 'agent', remember: true })
        this.autoConnectError = ''
        this.logger?.info?.(`ssh-view: 已自动连接到 ${id}`)
      } catch (error) {
        this.autoConnectError = error && error.message ? error.message : String(error)
        this.logger?.warn?.(`ssh-view: 自动连接失败 (${this.autoConnectError})`)
        const retryable = error && error.code !== 'auth-failed' && error.code !== 'ssh-key-rejected' && error.code !== 'host-key-mismatch'
        if (retryable && attempt < 2) this.#scheduleAutoConnect(attempt === 0 ? 5000 : 15000, attempt + 1)
      }
    }, delay)
    this.autoConnectTimer.unref?.()
  }

  async saveSettings(input = {}) {
    if (typeof input.autoConnect === 'boolean') this.store.autoConnect = input.autoConnect
    await this.#saveProfileStore()
    if (this.store.autoConnect) {
      if (!this.session) this.#scheduleAutoConnect(200, 0)
    } else if (this.autoConnectTimer) {
      clearTimeout(this.autoConnectTimer)
      this.autoConnectTimer = null
    }
    return { state: this.controlState() }
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
    for (const row of this.store.profiles) {
      seen.add(row.id)
      rows.push(publicProfile(row, true))
    }
    if (this.vault.unlocked) {
      for (const row of this.vault.profiles) {
        if (seen.has(row.id)) continue
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
    const stored = this.store.profiles.find((row) => row.id === id)
    if (stored) return { ...stored, auth: 'agent', saved: true }
    if (this.vault.unlocked) {
      const row = this.vault.profile(id)
      if (row) return { ...row, auth: 'password', saved: true }
    }
    const row = this.memoryProfiles.get(id)
    return row ? { ...row, saved: false } : undefined
  }

  async saveProfile(input) {
    const profile = this.#validateProfileInput(input)
    if (profile.auth === 'agent') {
      await this.#rememberAgentProfile(profile)
      return { state: this.controlState() }
    }
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
    const before = this.store.profiles.length
    this.store.profiles = this.store.profiles.filter((row) => row.id !== id)
    if (this.store.profiles.length !== before) {
      removed = true
      if (this.store.lastProfileId === id) this.store.lastProfileId = ''
      await this.#saveProfileStore()
    }
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
    const auth = source.auth === 'agent' ? 'agent' : 'password'
    const id = typeof source.id === 'string' && /^[a-f0-9-]{8,64}$/i.test(source.id) ? source.id : randomBytes(8).toString('hex')
    return {
      id,
      name: text(source.name, 120).trim() || `${username}@${host}`,
      host,
      port,
      username,
      auth,
      password: auth === 'agent' ? '' : password,
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

    const requested = source.auth === 'agent' || source.auth === 'password' ? source.auth : base?.auth
    const authMode = requested || (typeof source.password === 'string' && source.password !== '' ? 'password' : this.#agentAvailable() ? 'agent' : 'password')
    const suppliedPassword = typeof source.password === 'string' ? source.password : ''
    let password = ''
    let agent = ''
    let privateKey
    if (authMode === 'password') {
      password = suppliedPassword !== '' ? suppliedPassword : base?.password || ''
      if (!password) throw new ViewError('password-required', '请输入登录密码。')
    } else {
      agent = defaultAgentSocket()
      if (agent === '') {
        const fallback = defaultPrivateKey()
        if (!fallback) {
          throw new ViewError('agent-unavailable', '未找到可用的 ssh-agent 或 ~/.ssh 私钥。请先运行 ssh-add 加载密钥，或改用密码登录。')
        }
        privateKey = fallback.key
      }
    }

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
      auth: authMode,
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
      const credentials = authMode === 'password' ? { password } : agent !== '' ? { agent } : { privateKey }
      await session.connect(credentials, { knownFingerprint: known ? known.fingerprint : '' })
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
      if (authMode === 'agent' && error instanceof SshError && error.code === 'auth-failed') {
        throw new ViewError('ssh-key-rejected', '服务器没有接受这把 SSH 密钥。请确认本机公钥已加入服务器 ~/.ssh/authorized_keys。', { host, port })
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
      auth: authMode,
      keySource: authMode === 'password' ? 'password' : agent !== '' ? 'agent' : 'private-key',
      connectedAt: Date.now(),
      fingerprint: session.fingerprint,
      server: facts,
    }

    const warnings = []
    if (authMode === 'agent') {
      if (source.remember !== false) {
        try {
          await this.#rememberAgentProfile(profile)
        } catch (error) {
          warnings.push(`连接成功，但连接配置保存失败：${error && error.message ? error.message : error}`)
        }
      }
    } else if (source.remember === true) {
      if (this.vault.unlocked) {
        const row = {
          id: profile.id,
          name: profile.name,
          host,
          port,
          username,
          auth: 'password',
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
      const row = { id: profile.id, name: profile.name, host, port, username, auth: 'password', password: '', updatedAt: Date.now() }
      if (this.vault.unlocked) {
        await this.vault.putProfile(row)
      } else {
        this.memoryProfiles.set(profile.id, { ...row, saved: false })
      }
    }
    this.autoConnectError = ''
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
      agent: {
        available: this.#agentAvailable(),
        socket: defaultAgentSocket() !== '',
        privateKey: defaultPrivateKey() !== null,
      },
      autoConnect: this.store.autoConnect,
      lastProfileId: this.store.lastProfileId,
      autoConnectError: this.autoConnectError,
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

  async #shell(command, options = {}) {
    const session = this.#requireSession()
    return session.exec(command, {
      timeoutMs: options.timeoutMs ?? 20000,
      maxBytes: options.maxBytes ?? 256 * 1024,
    })
  }

  async #assertTool(session, tool) {
    const probe = await session.exec(`command -v ${tool}`, { timeoutMs: 10000, maxBytes: 8 * 1024 })
    if (probe.code !== 0) {
      throw new ViewError(
        'tool-missing',
        `服务器未安装 ${tool}，无法处理该归档。请先安装（例如 apt install ${tool} / apk add ${tool}）。`,
      )
    }
  }

  /** Listed entry names, with a symlink/hardlink rejection where it can be detected. */
  async #listArchive(session, path, type) {
    const quoted = shellQuote(path)
    if (type === 'zip') {
      await this.#assertTool(session, 'unzip')
      const listing = await session.exec(`unzip -Z1 ${quoted}`, { timeoutMs: 60000, maxBytes: 8 * 1024 * 1024 })
      if (listing.code !== 0) {
        throw new ViewError('archive-list-failed', (listing.stderr || listing.stdout || '无法读取 zip 目录').slice(0, 300))
      }
      const probe = await session.exec('command -v zipinfo', { timeoutMs: 10000, maxBytes: 8 * 1024 })
      if (probe.code === 0) {
        const verbose = await session.exec(`zipinfo -l ${quoted}`, { timeoutMs: 60000, maxBytes: 8 * 1024 * 1024 })
        if (verbose.code === 0 && verbose.stdout.split('\n').some((line) => /^[lhbc]/.test(line))) {
          throw new ViewError('unsafe-archive', '归档包含符号链接，已拒绝解压。')
        }
      }
      return listing.stdout.split('\n').map((line) => line.trim()).filter(Boolean)
    }
    if (type === 'gz' || type === 'bz2' || type === 'xz') return []
    const flag = type === 'tar.gz' ? 'z' : type === 'tar.bz2' ? 'j' : type === 'tar.xz' ? 'J' : ''
    await this.#assertTool(session, 'tar')
    const verbose = await session.exec(`tar -tv${flag}f ${quoted}`, { timeoutMs: 60000, maxBytes: 8 * 1024 * 1024 })
    if (verbose.code !== 0) {
      throw new ViewError('archive-list-failed', (verbose.stderr || verbose.stdout || '无法读取 tar 目录').slice(0, 300))
    }
    const lines = verbose.stdout.split('\n').filter((line) => line.trim() !== '')
    if (lines.some((line) => /^[lhbc]/.test(line))) {
      throw new ViewError('unsafe-archive', '归档包含符号链接或硬链接，已拒绝解压。')
    }
    const names = await session.exec(`tar -t${flag}f ${quoted}`, { timeoutMs: 60000, maxBytes: 8 * 1024 * 1024 })
    if (names.code !== 0) {
      throw new ViewError('archive-list-failed', (names.stderr || names.stdout || '无法读取 tar 目录').slice(0, 300))
    }
    return names.stdout.split('\n').map((line) => line.trim()).filter(Boolean)
  }

  /** Extract an archive on the remote host into a validated target directory. */
  async extractArchive(rawPath, options = {}) {
    const path = remotePath(rawPath)
    const type = archiveType(path)
    if (!type) {
      throw new ViewError('unsupported-archive', '不支持的归档格式（支持 zip / tar / tar.gz / tgz / tar.bz2 / tar.xz / gz / bz2 / xz）。')
    }
    const sftp = await this.#sftp()
    const attrs = await this.#stat(sftp, path)
    if (!attrs) throw new ViewError('not-found', `归档不存在：${path}`)
    if (attrs.isDirectory()) throw new ViewError('is-directory', '该路径是一个目录。')
    const overwrite = options.overwrite === true
    const target = remotePath(options.target || posix.join(posix.dirname(path), archiveStem(path)))
    if (target === '/' || PROTECTED_PATHS.has(target)) throw new ViewError('protected', `不允许解压到系统路径：${target}`)

    const existing = await this.#stat(sftp, target)
    if (existing) {
      if (!existing.isDirectory()) throw new ViewError('not-directory', `目标不是目录：${target}`)
      const rows = await this.#readdir(sftp, target)
      if (rows.length > 0 && !overwrite) {
        throw new ViewError('target-exists', `目标目录非空：${target}。勾选「覆盖」后再试。`)
      }
    } else {
      const made = await this.#shell(`mkdir -p ${shellQuote(target)}`)
      if (made.code !== 0) throw new ViewError('extract-failed', `无法创建目标目录：${(made.stderr || '').slice(0, 200)}`)
    }

    const session = this.#requireSession()
    const entries = await this.#listArchive(session, path, type)
    if (entries.length > MAX_ARCHIVE_ENTRIES) {
      throw new ViewError('too-many', `归档条目过多（${entries.length}），已停止。`)
    }
    const unsafe = entries.find((name) => unsafeArchiveEntry(name))
    if (unsafe) throw new ViewError('unsafe-archive', `归档包含不安全的路径：${String(unsafe).slice(0, 160)}`)

    const tool = type === 'zip' ? 'unzip' : type === 'gz' ? 'gzip' : type === 'bz2' ? 'bzip2' : type === 'xz' ? 'xz' : 'tar'
    await this.#assertTool(session, tool)
    const quoted = shellQuote(path)
    const dest = shellQuote(target)
    let command
    if (type === 'zip') {
      command = `unzip -q ${overwrite ? '-o ' : ''}${quoted} -d ${dest}`
    } else if (type === 'tar' || type.startsWith('tar.')) {
      const flag = type === 'tar.gz' ? 'z' : type === 'tar.bz2' ? 'j' : type === 'tar.xz' ? 'J' : ''
      command = `tar -x${flag}f ${quoted} -C ${dest}`
    } else {
      const outName = posix.join(target, posix.basename(path).replace(/\.(gz|bz2|xz)$/i, '') || 'extracted')
      if (!overwrite && (await this.#stat(sftp, outName))) {
        throw new ViewError('target-exists', `目标文件已存在：${outName}`)
      }
      const decompress = type === 'gz' ? 'gzip -dc' : type === 'bz2' ? 'bzip2 -dc' : 'xz -dc'
      command = `${decompress} ${quoted} > ${shellQuote(outName)}`
    }
    const result = await session.exec(command, { timeoutMs: 300000, maxBytes: 2 * 1024 * 1024 })
    if (result.code !== 0) {
      throw new ViewError('extract-failed', (result.stderr || result.stdout || `解压命令返回 ${result.code}`).slice(0, 500))
    }
    const extracted = entries.length > 0 ? entries.length : 1
    return { path, target, type, entries: extracted, overwrite }
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
      case 'settings.save':
        return this.saveSettings(input)
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
      case 'fs.extract':
        return this.extractArchive(input.path, { target: input.target, overwrite: input.overwrite === true })
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
    if (this.autoConnectTimer) {
      clearTimeout(this.autoConnectTimer)
      this.autoConnectTimer = null
    }
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
