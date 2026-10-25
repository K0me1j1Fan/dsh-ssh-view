/**
 * One SSH session: password authentication, trust-on-first-use host key
 * verification, remote command execution, and an SFTP channel.
 *
 * Nothing in this module writes to disk; the caller owns the known-hosts table
 * and persists fingerprints after a successful handshake.
 */
import ssh2 from 'ssh2'
import net from 'node:net'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const { Client } = ssh2

/** The live ssh-agent socket, or '' when none is advertised. */
export function defaultAgentSocket() {
  const socket = process.env.SSH_AUTH_SOCK
  return typeof socket === 'string' && socket !== '' && existsSync(socket) ? socket : ''
}

/** First standard private key under ~/.ssh, for hosts without a live agent. */
export function defaultPrivateKey() {
  for (const name of ['id_ed25519', 'id_rsa', 'id_ecdsa']) {
    const path = join(homedir(), '.ssh', name)
    if (!existsSync(path)) continue
    try {
      return { path, key: readFileSync(path) }
    } catch {
      return null
    }
  }
  return null
}

export class SshError extends Error {
  /** @param {string} code stable client-facing code. @param {string} message human text. */
  constructor(code, message) {
    super(message)
    this.name = 'SshError'
    this.code = code
  }
}

/** `SHA256:<base64 without padding>` for a raw host-key blob. */
export function fingerprintOf(keyBlob) {
  return `SHA256:${createHash('sha256').update(keyBlob).digest('base64').replace(/=+$/, '')}`
}

function connectFailure(error) {
  const text = error && typeof error.message === 'string' ? error.message : String(error)
  if (/host key verification failed|verification failed|host key/i.test(text)) {
    return new SshError('host-key-mismatch', text)
  }
  if (/all configured authentication methods failed|authentication failure|permission denied/i.test(text)) {
    return new SshError('auth-failed', '用户名或密码错误，或服务器拒绝了密码登录。')
  }
  if (error && error.code === 'ECONNREFUSED') return new SshError('connect-refused', '目标端口拒绝连接。')
  if (error && error.code === 'ENOTFOUND') return new SshError('dns', '无法解析主机名。')
  if (error && error.code === 'ETIMEDOUT') return new SshError('timeout', '连接超时。')
  if (/timed out|timeout/i.test(text)) return new SshError('timeout', '连接超时。')
  return new SshError('connect-failed', text)
}

export class SshSession {
  /**
   * @param {object} options
   * @param {{id: string, host: string, port: number, username: string}} options.profile
   * @param {number} options.connectTimeoutMs
   * @param {number} options.maxExecBytes
   * @param {(error: Error) => void} [options.onClosed]
   */
  constructor({ profile, connectTimeoutMs, maxExecBytes, onClosed }) {
    this.profile = profile
    this.hostKey = `${profile.host}:${profile.port}`
    this.connectTimeoutMs = connectTimeoutMs
    this.maxExecBytes = maxExecBytes
    this.onClosed = onClosed
    /** @type {InstanceType<typeof Client> | null} */
    this.client = null
    this.connected = false
    this.lastError = ''
    this.connectedAt = 0
    this.fingerprint = ''
    this.observedFingerprint = ''
    this.knownFingerprint = ''
    this._sftp = null
    this._sftpPromise = null
    this._expectedHostFingerprint = ''
  }

  /**
   * Cheap reachability probe: open one TCP connection and require an SSH
   * identification string. This turns a silent handshake timeout into a
   * precise diagnosis (wrong port, filtered port, unreachable host).
   */
  async #preflight() {
    const host = this.profile.host
    const port = this.profile.port
    const timeoutMs = Math.max(3000, Math.min(8000, this.connectTimeoutMs))
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host, port })
      let settled = false
      let banner = ''
      const done = (error) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        socket.removeAllListeners()
        socket.destroy()
        if (error) reject(error)
        else resolve()
      }
      const timer = setTimeout(() => {
        done(new SshError('connect-timeout', `连接 ${host}:${port} 超时：主机不可达或端口被防火墙拦截。`))
      }, timeoutMs)
      socket.setNoDelay(true)
      socket.once('connect', () => {
        // An SSH server sends its identification string unprompted; a service
        // that stays silent after accepting the socket is not SSH.
        socket.setTimeout(4000, () => {
          done(new SshError(
            'not-ssh',
            `端口 ${port} 接受了 TCP 连接，但没有返回 SSH 协议标识。这通常说明该端口不是 SSH 服务（SSH 默认端口是 22）。`,
          ))
        })
      })
      socket.on('data', (chunk) => {
        banner += chunk.toString('latin1')
        if (banner.length > 1024) {
          done(new SshError('not-ssh', `端口 ${port} 返回了非 SSH 数据，可能不是 SSH 服务。`))
          return
        }
        const newline = banner.indexOf('\n')
        if (newline < 0) return
        const line = banner.slice(0, newline).replace(/\r$/, '')
        if (/^SSH-\d/.test(line)) {
          done()
          return
        }
        done(new SshError(
          'not-ssh',
          `端口 ${port} 返回的不是 SSH 协议（"${line.slice(0, 60).trim()}"），请确认 SSH 端口。`,
        ))
      })
      socket.once('error', (error) => {
        if (error.code === 'ECONNREFUSED') {
          done(new SshError('connect-refused', `连接被拒绝：${host}:${port} 上没有服务监听。`))
        } else if (error.code === 'EHOSTUNREACH' || error.code === 'ENETUNREACH') {
          done(new SshError('unreachable', `无法到达 ${host}:${port}：网络不可达。`))
        } else if (error.code === 'ENOTFOUND') {
          done(new SshError('dns', `无法解析主机名 ${host}。`))
        } else {
          done(new SshError('connect-failed', `TCP 连接失败：${error.message}`))
        }
      })
    })
  }

  /**
   * @param {string | {password?: string, agent?: string, privateKey?: Buffer}} credentials
   * @param {{knownFingerprint?: string}} [options]
   */
  async connect(credentials = {}, options = {}) {
    if (this.connected) return this
    const auth = typeof credentials === 'string' ? { password: credentials } : (credentials || {})
    const password = typeof auth.password === 'string' ? auth.password : ''
    const agent = typeof auth.agent === 'string' ? auth.agent : ''
    const privateKey = Buffer.isBuffer(auth.privateKey) ? auth.privateKey : undefined
    if (password === '' && agent === '' && privateKey === undefined) {
      throw new SshError('auth-required', '缺少可用的登录凭据。')
    }
    this.auth = password !== '' ? 'password' : agent !== '' ? 'agent' : 'private-key'
    this._expectedHostFingerprint = options.knownFingerprint || ''
    await this.#preflight()
    const client = new Client()
    this.client = client
    const timeout = Math.max(3000, this.connectTimeoutMs)
    await new Promise((resolve, reject) => {
      let settled = false
      const timer = setTimeout(() => {
        try {
          client.end()
        } catch {
          /* already gone */
        }
        settle(new SshError('timeout', '连接超时。'))
      }, timeout)
      const settle = (error) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (error) reject(error)
        else resolve()
      }
      if (password !== '') {
        client.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
          finish(prompts.map(() => password))
        })
      }
      client.once('ready', () => settle())
      client.once('error', (error) => settle(connectFailure(error)))
      client.once('close', () => {
        if (!settled) settle(new SshError('connect-failed', '连接在完成握手前被关闭。'))
      })
      try {
        client.connect({
          host: this.profile.host,
          port: this.profile.port,
          username: this.profile.username,
          ...(password !== '' ? { password } : {}),
          ...(agent !== '' ? { agent } : {}),
          ...(privateKey !== undefined ? { privateKey } : {}),
          readyTimeout: timeout,
          keepaliveInterval: 15000,
          keepaliveCountMax: 3,
          tryKeyboard: password !== '',
          hostVerifier: (key) => {
            const observed = fingerprintOf(key)
            this.observedFingerprint = observed
            // Unknown host: accept for trust-on-first-use; the caller pins it
            // only after the handshake and authentication both succeed.
            this.fingerprint = observed
            return !this._expectedHostFingerprint || this._expectedHostFingerprint === observed
          },
        })
      } catch (error) {
        settle(connectFailure(error))
      }
    })
    this.connected = true
    this.connectedAt = Date.now()
    this.lastError = ''
    client.on('close', () => {
      const wasConnected = this.connected
      this.connected = false
      this._sftp = null
      this._sftpPromise = null
      if (wasConnected) this.onClosed?.(new SshError('disconnected', 'SSH 连接已断开。'))
    })
    client.on('error', (error) => {
      this.lastError = error && error.message ? error.message : String(error)
    })
    return this
  }

  /** Open (and cache) the SFTP channel. */
  async sftp() {
    if (!this.connected || !this.client) throw new SshError('not-connected', '尚未连接到服务器。')
    if (this._sftp) return this._sftp
    if (!this._sftpPromise) {
      this._sftpPromise = new Promise((resolve, reject) => {
        this.client.sftp((error, sftp) => {
          if (error) {
            this._sftpPromise = null
            reject(new SshError('sftp-unavailable', `SFTP 不可用：${error.message}`))
            return
          }
          this._sftp = sftp
          sftp.on('close', () => {
            this._sftp = null
            this._sftpPromise = null
          })
          resolve(sftp)
        })
      })
    }
    return this._sftpPromise
  }

  /**
   * Run one command through the remote login shell.
   * @param {string} command
   * @param {{timeoutMs?: number, maxBytes?: number, keep?: 'head'|'tail'}} [options]
   * @returns {Promise<{stdout: string, stderr: string, code: number | null, signal: string | undefined, truncated: boolean}>}
   */
  async exec(command, options = {}) {
    const client = this.client
    if (!this.connected || !client) throw new SshError('not-connected', '尚未连接到服务器。')
    const timeoutMs = options.timeoutMs ?? 30000
    const maxBytes = options.maxBytes ?? this.maxExecBytes
    const keep = options.keep ?? 'head'
    return new Promise((resolve, reject) => {
      let settled = false
      let timer = null
      const finish = (error, value) => {
        if (settled) return
        settled = true
        if (timer) clearTimeout(timer)
        if (error) reject(error)
        else resolve(value)
      }
      client.exec(command, { env: { LC_ALL: 'C', LANG: 'C' } }, (error, stream) => {
        if (error) {
          finish(new SshError('exec-failed', `命令执行失败：${error.message}`))
          return
        }
        const out = []
        const err = []
        let outBytes = 0
        let errBytes = 0
        let truncated = false
        timer = setTimeout(() => {
          try {
            stream.close()
          } catch {
            /* already closed */
          }
          finish(new SshError('exec-timeout', `命令执行超时（${Math.round(timeoutMs / 1000)} 秒）。`))
        }, timeoutMs)
        stream.on('data', (chunk) => {
          let piece = chunk
          if (outBytes + piece.length > maxBytes) {
            truncated = true
            if (keep === 'tail') {
              // Drop buffered chunks from the front until this one fits.
              while (out.length > 0 && outBytes + piece.length > maxBytes) {
                outBytes -= out.shift().length
              }
              if (piece.length > maxBytes) piece = piece.subarray(piece.length - maxBytes)
            } else {
              const room = Math.max(0, maxBytes - outBytes)
              if (room === 0) return
              piece = piece.subarray(0, room)
            }
          }
          out.push(piece)
          outBytes += piece.length
        })
        stream.stderr.on('data', (chunk) => {
          if (errBytes >= 256 * 1024) return
          const room = 256 * 1024 - errBytes
          const piece = chunk.length > room ? chunk.subarray(0, room) : chunk
          err.push(piece)
          errBytes += piece.length
        })
        stream.on('error', (streamError) => {
          finish(new SshError('exec-failed', streamError.message))
        })
        stream.on('close', (code, signal) => {
          finish(null, {
            stdout: Buffer.concat(out).toString('utf8'),
            stderr: Buffer.concat(err).toString('utf8'),
            code: typeof code === 'number' ? code : null,
            signal: signal || undefined,
            truncated,
          })
        })
      })
    })
  }

  /** Collect a compact system summary for the connection header. */
  async readServerFacts() {
    const script = [
      'printf "__hostname__%s\\n" "$(hostname 2>/dev/null)"',
      'printf "__kernel__%s\\n" "$(uname -sr 2>/dev/null)"',
      'printf "__os__%s\\n" "$(. /etc/os-release 2>/dev/null; printf "%s" "${PRETTY_NAME:-}")"',
      'printf "__user__%s\\n" "$(id -un 2>/dev/null)"',
      'printf "__load__%s\\n" "$(cut -d" " -f1-3 /proc/loadavg 2>/dev/null)"',
      'printf "__uptime__%s\\n" "$(cut -d. -f1 /proc/uptime 2>/dev/null)"',
      'printf "__mem__%s\\n" "$(awk \'/^MemTotal:|^MemFree:|^MemAvailable:/{v=$2; sub(/:$/,"",$1); printf "%s=%s ", $1, v}\' /proc/meminfo 2>/dev/null)"',
      'printf "__disk__%s\\n" "$(df -P -k / 2>/dev/null | awk \'NR==2{printf "%s %s %s %s", $2, $3, $4, $6}\')"',
    ].join('\n')
    let stdout = ''
    try {
      const result = await this.exec(script, { timeoutMs: 15000, maxBytes: 64 * 1024 })
      stdout = result.stdout
    } catch {
      stdout = ''
    }
    const facts = { hostname: '', kernel: '', os: '', user: this.profile.username, load: [], uptimeSec: 0, mem: null, disk: null, home: '' }
    for (const line of stdout.split('\n')) {
      const match = /^__(hostname|kernel|os|user|load|uptime|mem|disk)__(.*)$/.exec(line.trimEnd())
      if (!match) continue
      const value = match[2]
      switch (match[1]) {
        case 'hostname':
          facts.hostname = value
          break
        case 'kernel':
          facts.kernel = value
          break
        case 'os':
          facts.os = value
          break
        case 'user':
          if (value) facts.user = value
          break
        case 'load':
          facts.load = value
            .trim()
            .split(/\s+/)
            .map(Number)
            .filter((n) => Number.isFinite(n))
          break
        case 'uptime':
          facts.uptimeSec = Number(value) || 0
          break
        case 'mem': {
          const mem = {}
          for (const token of value.trim().split(/\s+/)) {
            const [key, raw] = token.split('=')
            const kv = Number(raw)
            if (key && Number.isFinite(kv)) mem[key] = kv
          }
          facts.mem = Object.keys(mem).length ? mem : null
          break
        }
        case 'disk': {
          const [total, used, avail, mount] = value.trim().split(/\s+/)
          if (mount) {
            facts.disk = {
              totalKb: Number(total) || 0,
              usedKb: Number(used) || 0,
              availKb: Number(avail) || 0,
              mount,
            }
          }
          break
        }
      }
    }
    try {
      const sftp = await this.sftp()
      facts.home = await new Promise((resolve, reject) => {
        sftp.realpath('.', (error, resolved) => (error ? reject(error) : resolve(resolved)))
      })
    } catch {
      facts.home = ''
    }
    return facts
  }

  dispose() {
    this.connected = false
    this._sftp = null
    this._sftpPromise = null
    const client = this.client
    this.client = null
    if (!client) return
    try {
      client.end()
    } catch {
      /* already closed */
    }
    setTimeout(() => {
      try {
        client.destroy()
      } catch {
        /* already closed */
      }
    }, 500).unref?.()
  }
}
