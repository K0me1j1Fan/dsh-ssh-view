/**
 * Encrypted credential vault.
 *
 * The file on disk holds only ciphertext: a scrypt-derived key (never stored)
 * encrypts the profile list and the known-host fingerprints with AES-256-GCM.
 * The passphrase and the derived key live in memory while the vault is
 * unlocked; `lock()` zeroes the key before dropping it.
 *
 * File shape (JSON, mode 0600 under a mode 0700 directory):
 *   { version: 1,
 *     kdf: { name, salt, N, r, p },
 *     cipher: { name, iv, tag },
 *     payload: <base64 ciphertext> }
 */
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto'
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { dirname } from 'node:path'

/** Bound into every ciphertext so a vault file cannot be replayed elsewhere. */
const AAD = Buffer.from('dsh-ssh-view/vault/v1', 'utf8')
const VERSION = 1
const KDF = { name: 'scrypt', N: 32768, r: 8, p: 1 }
const KEY_BYTES = 32
const MIN_PASSPHRASE = 8
const MAX_PASSPHRASE = 1024

export class VaultError extends Error {
  /** @param {string} code stable client-facing code. @param {string} message human text. */
  constructor(code, message) {
    super(message)
    this.name = 'VaultError'
    this.code = code
  }
}

function assertPassphrase(passphrase) {
  if (typeof passphrase !== 'string') throw new VaultError('bad-passphrase', '主密码必须是字符串。')
  if (passphrase.length < MIN_PASSPHRASE) {
    throw new VaultError('weak-passphrase', `主密码至少需要 ${MIN_PASSPHRASE} 个字符。`)
  }
  if (passphrase.length > MAX_PASSPHRASE) throw new VaultError('bad-passphrase', '主密码过长。')
}

function deriveKey(passphrase, salt, params) {
  const { N, r, p } = params
  // scrypt needs 128 * N * r bytes; leave headroom for the allocator.
  const maxmem = Math.max(64 * 1024 * 1024, 256 * N * r)
  return scryptSync(Buffer.from(passphrase.normalize('NFKC'), 'utf8'), salt, KEY_BYTES, {
    N,
    r,
    p,
    maxmem,
  })
}

function encrypt(key, plaintext) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  cipher.setAAD(AAD)
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return { iv, tag: cipher.getAuthTag(), data }
}

function decrypt(key, iv, tag, data) {
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAAD(AAD)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(data), decipher.final()])
}

function emptyPayload() {
  return { profiles: [], knownHosts: {} }
}

function normalizePayload(value) {
  const payload = emptyPayload()
  if (value && typeof value === 'object') {
    if (Array.isArray(value.profiles)) {
      payload.profiles = value.profiles.filter((row) => row && typeof row === 'object' && typeof row.id === 'string')
    }
    if (value.knownHosts && typeof value.knownHosts === 'object') {
      for (const [key, entry] of Object.entries(value.knownHosts)) {
        if (entry && typeof entry === 'object' && typeof entry.fingerprint === 'string') {
          payload.knownHosts[key] = {
            fingerprint: entry.fingerprint,
            firstSeen: typeof entry.firstSeen === 'number' ? entry.firstSeen : Date.now(),
            lastSeen: typeof entry.lastSeen === 'number' ? entry.lastSeen : Date.now(),
          }
        }
      }
    }
  }
  return payload
}

export class Vault {
  /** @param {string} file absolute path of vault.json */
  constructor(file) {
    this.file = file
    /** @type {Buffer | null} */
    this.key = null
    /** @type {{profiles: object[], knownHosts: Record<string, object>} | null} */
    this.payload = null
    this.params = { ...KDF }
  }

  get exists() {
    return existsSync(this.file)
  }

  get unlocked() {
    return this.key !== null && this.payload !== null
  }

  get profiles() {
    return this.payload ? this.payload.profiles : []
  }

  /** @returns {object | undefined} */
  profile(id) {
    return this.profiles.find((row) => row.id === id)
  }

  /** @returns {{fingerprint: string, firstSeen: number, lastSeen: number} | undefined} */
  knownHost(key) {
    return this.payload ? this.payload.knownHosts[key] : undefined
  }

  /** Create the vault with an empty payload. */
  async create(passphrase) {
    assertPassphrase(passphrase)
    if (this.exists) throw new VaultError('vault-exists', '凭据库已经存在。')
    const salt = randomBytes(16)
    this.key = deriveKey(passphrase, salt, this.params)
    this.salt = salt
    this.payload = emptyPayload()
    await this.write()
  }

  /** Unlock an existing vault. Wrong passphrases fail the GCM tag check. */
  async unlock(passphrase) {
    assertPassphrase(passphrase)
    if (!this.exists) throw new VaultError('vault-missing', '尚未创建凭据库。')
    let doc
    try {
      doc = JSON.parse(await readFile(this.file, 'utf8'))
    } catch {
      throw new VaultError('vault-corrupt', '凭据库文件无法解析。')
    }
    if (!doc || doc.version !== VERSION || !doc.kdf || !doc.cipher || typeof doc.payload !== 'string') {
      throw new VaultError('vault-corrupt', '凭据库文件格式不受支持。')
    }
    const kdf = {
      name: 'scrypt',
      salt: Buffer.from(String(doc.kdf.salt ?? ''), 'base64'),
      N: Number(doc.kdf.N),
      r: Number(doc.kdf.r),
      p: Number(doc.kdf.p),
    }
    if (!kdf.salt.length || !Number.isInteger(kdf.N) || kdf.N < 16384 || kdf.N > 1048576) {
      throw new VaultError('vault-corrupt', '凭据库的密钥参数无效。')
    }
    const key = deriveKey(passphrase, kdf.salt, kdf)
    let plaintext
    try {
      plaintext = decrypt(
        key,
        Buffer.from(String(doc.cipher.iv ?? ''), 'base64'),
        Buffer.from(String(doc.cipher.tag ?? ''), 'base64'),
        Buffer.from(doc.payload, 'base64'),
      )
    } catch {
      key.fill(0)
      throw new VaultError('vault-bad-passphrase', '主密码不正确。')
    }
    let parsed
    try {
      parsed = JSON.parse(plaintext.toString('utf8'))
    } catch {
      key.fill(0)
      throw new VaultError('vault-corrupt', '凭据库内容已损坏。')
    }
    if (this.key) this.key.fill(0)
    this.key = key
    this.salt = kdf.salt
    this.params = { N: kdf.N, r: kdf.r, p: kdf.p }
    this.payload = normalizePayload(parsed)
  }

  /** Drop the in-memory key and decrypted payload. */
  lock() {
    if (this.key) this.key.fill(0)
    this.key = null
    this.payload = null
    this.salt = undefined
  }

  /** Replace one profile and persist. Requires an unlocked vault. */
  async putProfile(profile) {
    if (!this.unlocked) throw new VaultError('vault-locked', '凭据库已锁定。')
    const rows = this.payload.profiles
    const index = rows.findIndex((row) => row.id === profile.id)
    if (index >= 0) rows[index] = profile
    else rows.push(profile)
    await this.write()
  }

  /** Remove a profile and persist. Requires an unlocked vault. */
  async removeProfile(id) {
    if (!this.unlocked) throw new VaultError('vault-locked', '凭据库已锁定。')
    const rows = this.payload.profiles
    const next = rows.filter((row) => row.id !== id)
    if (next.length === rows.length) return false
    this.payload.profiles = next
    await this.write()
    return true
  }

  /** Record a host fingerprint after a successful handshake. */
  async rememberHost(key, fingerprint) {
    if (!this.unlocked) return false
    const known = this.payload.knownHosts[key]
    if (known && known.fingerprint === fingerprint) {
      known.lastSeen = Date.now()
    } else {
      this.payload.knownHosts[key] = { fingerprint, firstSeen: Date.now(), lastSeen: Date.now() }
    }
    await this.write()
    return true
  }

  /** Forget a host fingerprint so the next connection re-pins it. */
  async forgetHost(key) {
    if (!this.unlocked) return false
    if (!this.payload.knownHosts[key]) return false
    delete this.payload.knownHosts[key]
    await this.write()
    return true
  }

  /** Re-encrypt the payload under a new passphrase. */
  async changePassphrase(current, next) {
    await this.unlock(current)
    assertPassphrase(next)
    const salt = randomBytes(16)
    const key = deriveKey(next, salt, this.params)
    if (this.key) this.key.fill(0)
    this.key = key
    this.salt = salt
    await this.write()
  }

  /** Encrypt the current payload with a fresh IV and replace the file atomically. */
  async write() {
    if (!this.unlocked) throw new VaultError('vault-locked', '凭据库已锁定。')
    const { iv, tag, data } = encrypt(this.key, Buffer.from(JSON.stringify(this.payload), 'utf8'))
    const doc = {
      version: VERSION,
      kdf: {
        name: 'scrypt',
        salt: this.salt.toString('base64'),
        N: this.params.N,
        r: this.params.r,
        p: this.params.p,
      },
      cipher: { name: 'aes-256-gcm', iv: iv.toString('base64'), tag: tag.toString('base64') },
      payload: data.toString('base64'),
    }
    const dir = dirname(this.file)
    await mkdir(dir, { recursive: true, mode: 0o700 })
    const temp = `${this.file}.${randomBytes(6).toString('hex')}.tmp`
    try {
      await writeFile(temp, JSON.stringify(doc), { mode: 0o600 })
      await rename(temp, this.file)
    } catch (error) {
      await rm(temp, { force: true }).catch(() => {})
      throw error
    }
  }
}
