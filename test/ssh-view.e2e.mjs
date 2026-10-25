/**
 * End-to-end check of the Host half against a real OpenSSH/SFTP server.
 *
 *   node test/ssh-view.e2e.mjs
 *
 * Expects an SSH server reachable at E2E_HOST:E2E_PORT (default
 * 127.0.0.1:2222) with E2E_USER / E2E_PASSWORD (default root /
 * test-password-123). The test writes only below its own .tmp directory and
 * /tmp/dsh-view-e2e on the server.
 */
import assert from 'node:assert/strict'
import { readFile, rm, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Readable } from 'node:stream'
import { ServerViewService, ViewError, remotePath } from '../lib/service.js'
import { apply } from '../index.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '.tmp', `run-${process.pid}`)
const REMOTE = '/tmp/dsh-view-e2e'
const HOST = process.env.E2E_HOST || '127.0.0.1'
const PORT = Number(process.env.E2E_PORT || 2222)
const USER = process.env.E2E_USER || 'root'
const PASSWORD = process.env.E2E_PASSWORD || 'test-password-123'
const MASTER = 'master-passphrase-123'

const results = []
let failures = 0

async function test(name, fn) {
  try {
    await fn()
    results.push({ name, ok: true })
    console.log(`ok   ${name}`)
  } catch (error) {
    failures += 1
    results.push({ name, ok: false, error })
    console.error(`FAIL ${name}`)
    console.error(error && error.stack ? error.stack : error)
  }
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function assertCode(promise, codes) {
  return promise.then(
    () => {
      throw new Error(`expected rejection with ${codes.join('/')}`)
    },
    (error) => {
      assert.ok(codes.includes(error.code), `unexpected code ${error.code}: ${error.message}`)
    },
  )
}

async function main() {
  await rm(ROOT, { recursive: true, force: true })

  const service = new ServerViewService({
    config: { dataDir: ROOT, autoLockMinutes: 0, connectTimeoutMs: 12000 },
    logger: { warn() {}, info() {} },
  })

  let profileId = ''

  await test('vault: create, encrypt on disk, wrong passphrase, unlock', async () => {
    await service.createVault(MASTER)
    await service.saveProfile({ name: 'e2e', host: HOST, port: PORT, username: USER, password: PASSWORD })
    const unlocked = service.listProfiles()
    assert.equal(unlocked.length, 1)
    profileId = unlocked[0].id
    assert.equal(unlocked[0].password, undefined, 'profiles never expose the password')

    const raw = await readFile(join(ROOT, 'vault.json'), 'utf8')
    assert.ok(!raw.includes(MASTER), 'master passphrase must not be on disk')
    assert.ok(!raw.includes(PASSWORD), 'password must not be on disk')
    assert.ok(!raw.includes(HOST), 'host must be encrypted')

    const locked = service.lockVault()
    assert.equal(locked.state.vault.unlocked, false)
    assert.equal(service.listProfiles().length, 0, 'locked vault hides profiles')

    await assertCode(service.unlockVault('definitely-wrong-pass'), ['vault-bad-passphrase'])
    await service.unlockVault(MASTER)
    assert.equal(service.listProfiles().length, 1)
    assert.equal(service.listProfiles()[0].hasPassword, true)
  })

  await test('connect: wrong password is rejected', async () => {
    await assertCode(
      service.connect({ host: HOST, port: PORT, username: USER, password: 'wrong-password' }),
      ['auth-failed', 'connect-failed'],
    )
  })

  await test('connect: password login and server facts', async () => {
    const result = await service.connect({ profileId, remember: true })
    const state = result.state
    assert.ok(state.session, 'session is present')
    assert.equal(state.session.host, HOST)
    assert.match(state.session.fingerprint, /^SHA256:/)
    assert.ok(state.session.server.home.startsWith('/'), 'home directory resolved over SFTP')
    const hosts = await readFile(join(ROOT, 'hosts.json'), 'utf8')
    assert.ok(hosts.includes('SHA256:'), 'host fingerprint pinned after first handshake')
  })

  await test('connect: a mismatched host fingerprint aborts', async () => {
    const key = `${HOST}:${PORT}`
    const entry = service.knownHosts[key]
    assert.ok(entry, 'known host entry exists')
    entry.fingerprint = 'SHA256:definitely-not-the-server-key'
    service.disconnect()
    await assertCode(service.connect({ profileId, remember: true }), ['host-key-mismatch'])
    await service.dispatch('host.forget', { host: HOST, port: PORT })
    const reconnected = await service.connect({ profileId, remember: true })
    assert.match(reconnected.state.session.fingerprint, /^SHA256:/)
  })

  await test('connect: ssh-agent key authentication and non-secret profile store', async () => {
    if (process.env.E2E_AGENT !== '1') {
      console.log('     skipped: set E2E_AGENT=1 and authorize ~/.ssh/id_ed25519.pub on the test server')
      return
    }
    const result = await service.connect({ host: HOST, port: PORT, username: USER, auth: 'agent', remember: true })
    assert.equal(result.state.session.auth, 'agent')
    const storePath = join(ROOT, 'profiles.json')
    const raw = await readFile(storePath, 'utf8')
    assert.ok(!/password/i.test(raw), 'profile store must not contain a password')
    assert.equal((await stat(storePath)).mode & 0o777, 0o600)
    const store = JSON.parse(raw)
    assert.equal(store.autoConnect, true)
    assert.ok(store.lastProfileId, 'last profile recorded')
    assert.equal(store.profiles[0].auth, 'agent')
  })

  await test('fs: mkdir, write, read, conflict, force, rename, remove', async () => {
    await service.dispatch('fs.remove', { path: REMOTE, recursive: true }).catch(() => {})
    await service.makeDir(REMOTE)
    const file = `${REMOTE}/notes.txt`
    await service.touchFile(file)
    const written = await service.writeFile(file, 'first line\nsecond line\n', {})
    assert.ok(written.size > 0)
    const first = await service.readFile(file)
    assert.equal(first.content, 'first line\nsecond line\n')
    assert.equal(first.binary, false)
    assert.match(first.version, /^[a-f0-9]{32}$/)

    // Another writer changes the file between read and save.
    await service.writeFile(file, 'external change', {})
    await assertCode(service.writeFile(file, 'mine', { expectedVersion: first.version }), ['conflict'])
    const current = await service.readFile(file)
    await service.writeFile(file, 'mine', { expectedVersion: current.version })
    assert.equal((await service.readFile(file)).content, 'mine')

    // Two saves inside the same second still conflict: the check hashes content.
    const sameSecond = await service.readFile(file)
    await service.writeFile(file, 'one', { expectedVersion: sameSecond.version })
    await assertCode(service.writeFile(file, 'two', { expectedVersion: sameSecond.version }), ['conflict'])
    await service.writeFile(file, 'two', { expectedVersion: sameSecond.version, force: true })
    assert.equal((await service.readFile(file)).content, 'two')

    await service.renamePath(file, `${REMOTE}/renamed.txt`)
    const listing = await service.listDir(REMOTE)
    assert.deepEqual(listing.entries.map((row) => row.name), ['renamed.txt'])
    assert.equal(listing.entries[0].type, 'file')
    await service.removePath(`${REMOTE}/renamed.txt`)
    assert.equal((await service.listDir(REMOTE)).entries.length, 0)
    await service.removePath(REMOTE, { recursive: true })
  })

  await test('fs: upload stream and download stream', async () => {
    await service.dispatch('fs.remove', { path: REMOTE, recursive: true }).catch(() => {})
    await service.makeDir(REMOTE)
    const file = `${REMOTE}/uploaded.bin`
    const payload = Buffer.from('uploaded-content-0123456789')
    await service.uploadStream(file, Readable.toWeb(Readable.from([payload])), { overwrite: true })
    const readBack = await service.readFile(file)
    assert.equal(readBack.content, payload.toString())
    const download = await service.openDownload(file)
    assert.equal(download.size, payload.length)
    const chunks = []
    for await (const chunk of download.stream) chunks.push(chunk)
    assert.equal(Buffer.concat(chunks).toString(), payload.toString())
    await service.removePath(file)
  })

  await test('proc: list processes and kill a spawned one', async () => {
    await service.session.exec('nohup sleep 300 >/dev/null 2>&1 & echo started', { timeoutMs: 5000 })
    await delay(600)
    const list = await service.listProcesses()
    assert.ok(list.procs.length > 3, 'process list has rows')
    assert.ok(Number.isFinite(list.uptimeSec) && list.uptimeSec > 0)
    const sleepProc = list.procs.find((row) => /sleep 300/.test(row.args))
    assert.ok(sleepProc, 'spawned sleep process is visible')
    await service.killProcess(sleepProc.pid, 'TERM')
    await delay(600)
    const after = await service.listProcesses()
    assert.ok(!after.procs.some((row) => row.pid === sleepProc.pid), 'killed process is gone')
  })

  await test('logs: tail an arbitrary file and list presets', async () => {
    await service.dispatch('fs.remove', { path: REMOTE, recursive: true }).catch(() => {})
    await service.makeDir(REMOTE)
    const log = `${REMOTE}/app.log`
    const text = Array.from({ length: 10 }, (_, index) => `line-${index + 1}`).join('\n') + '\n'
    await service.writeFile(log, text, {})
    const tail = await service.tailLog(log, { lines: 4 })
    assert.equal(tail.text.trim().split('\n').join('|'), 'line-7|line-8|line-9|line-10')
    const presets = await service.logPresets()
    assert.ok(Array.isArray(presets.presets))
    await service.removePath(log)
    await service.removePath(REMOTE, { recursive: true })
  })

  await test('guards: system paths, pid 1 and relative paths are refused', async () => {
    assertCode(Promise.resolve().then(() => remotePath('relative/path')), ['bad-path'])
    await assertCode(service.removePath('/etc', { recursive: true }), ['protected'])
    await assertCode(service.renamePath('/etc', '/tmp/whatever'), ['protected'])
    await assertCode(service.killProcess(1, 'TERM'), ['bad-request'])
    await assertCode(service.removePath('/'), ['protected'])
  })

  await test('rpc: authenticated route layer answers ping/state and rejects junk', async () => {
    const routes = new Map()
    const disposers = []
    const fakeCtx = {
      logger: { warn() {}, info() {}, debug() {} },
      effect(fn) {
        const disposer = fn()
        disposers.push(disposer)
        return disposer
      },
      connection: {
        fetch: {
          register(route) {
            routes.set(route.path, route)
            return async () => routes.delete(route.path)
          },
        },
      },
    }
    apply(fakeCtx, { dataDir: join(ROOT, 'rpc') })
    assert.deepEqual([...routes.keys()].sort(), [
      '/api/ssh-view.download',
      '/api/ssh-view.rpc',
      '/api/ssh-view.upload',
    ])
    const route = routes.get('/api/ssh-view.rpc')
    const call = async (body) => {
      const response = await route.fetch(new Request('http://local/api/ssh-view.rpc', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: typeof body === 'string' ? body : JSON.stringify(body),
      }))
      return { status: response.status, data: await response.json() }
    }
    const ping = await call({ op: 'ping' })
    assert.equal(ping.data.ok, true)
    const state = await call({ op: 'state' })
    assert.equal(state.data.ok, true)
    assert.equal(state.data.value.vault.exists, false)
    assert.deepEqual(state.data.value.profiles, [])
    const unknown = await call({ op: 'nope' })
    assert.equal(unknown.data.ok, false)
    assert.equal(unknown.data.error.code, 'unknown-op')
    const junk = await call('{not json')
    assert.equal(junk.data.ok, false)
    assert.equal(junk.data.error.code, 'bad-request')
    for (const disposer of disposers.reverse()) {
      if (typeof disposer === 'function') await disposer()
    }
  })

  await test('auto-connect: a fresh service reconnects from profiles.json', async () => {
    if (process.env.E2E_AGENT !== '1') {
      console.log('     skipped: set E2E_AGENT=1 and authorize ~/.ssh/id_ed25519.pub on the test server')
      return
    }
    service.dispose()
    const restarted = new ServerViewService({
      config: { dataDir: ROOT, connectTimeoutMs: 10000 },
      logger: { warn() {}, info() {} },
    })
    try {
      for (let attempt = 0; attempt < 40 && !restarted.controlState().session; attempt += 1) await delay(250)
      const state = restarted.controlState()
      assert.ok(state.session, `auto-connect failed: ${state.autoConnectError}`)
      assert.equal(state.session.auth, 'agent')
    } finally {
      restarted.dispose()
    }
  })

  service.dispose()
  await rm(ROOT, { recursive: true, force: true })
  await rm(join(HERE, '.tmp'), { recursive: true, force: true }).catch(() => {})

  const passed = results.filter((row) => row.ok).length
  console.log(`\n${passed}/${results.length} checks passed`)
  if (failures > 0) process.exitCode = 1
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
