/**
 * Host half of the SSH server view.
 *
 * Registers three authenticated routes on the shared `/api` channel:
 *   POST /api/ssh-view.rpc       JSON control + file/process/log operations
 *   POST /api/ssh-view.upload    raw request body streamed to a remote file
 *   GET  /api/ssh-view.download  remote file streamed to the browser
 *
 * Every route sits behind Connection's browser-session cookie check and its
 * Host/Origin trust fence, so only the authenticated operator can reach the
 * SSH session. Passwords never leave this process.
 */
import { Readable } from 'node:stream'
import { ServerViewService, ViewError } from './lib/service.js'

export const name = 'ssh-view'
export const inject = ['connection']

const RPC_PATH = '/api/ssh-view.rpc'
const UPLOAD_PATH = '/api/ssh-view.upload'
const DOWNLOAD_PATH = '/api/ssh-view.download'
const MAX_RPC_BODY = 4 * 1024 * 1024

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

function errorBody(error) {
  const code = error && typeof error.code === 'string' && error.code ? error.code : 'error'
  let message = error && typeof error.message === 'string' && error.message ? error.message : '操作失败。'
  if (message.length > 2000) message = `${message.slice(0, 2000)}…`
  const body = { code, message }
  if (error && error.details && typeof error.details === 'object') body.details = error.details
  return body
}

function ok(value) {
  return jsonResponse({ ok: true, value })
}

function fail(error, logger) {
  if (!(error instanceof ViewError) && !(error && typeof error.code === 'string' && error.code)) {
    logger?.warn?.(error instanceof Error ? error : new Error(String(error)))
  }
  return jsonResponse({ ok: false, error: errorBody(error) })
}

function statusFor(error) {
  const code = error && error.code
  if (code === 'not-found' || code === 'not-directory') return 404
  if (code === 'permission-denied' || code === 'protected') return 403
  return 400
}

async function handleRpc(service, request, logger) {
  try {
    const raw = await request.text()
    if (raw.length > MAX_RPC_BODY) throw new ViewError('too-large', '请求体过大。')
    let body
    try {
      body = JSON.parse(raw)
    } catch {
      throw new ViewError('bad-request', '请求体不是合法 JSON。')
    }
    if (!body || typeof body !== 'object' || typeof body.op !== 'string') {
      throw new ViewError('bad-request', '缺少操作名。')
    }
    const value = await service.dispatch(body.op, body.params)
    return ok(value)
  } catch (error) {
    return fail(error, logger)
  }
}

function contentDisposition(name) {
  const fallback = String(name).replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_') || 'download'
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(name)}`
}

async function handleUpload(service, request, logger) {
  try {
    const url = new URL(request.url)
    const path = url.searchParams.get('path') || ''
    const overwrite = url.searchParams.get('overwrite') === 'true'
    if (!request.body) throw new ViewError('bad-request', '缺少上传内容。')
    const value = await service.uploadStream(path, request.body, { overwrite })
    return ok(value)
  } catch (error) {
    return fail(error, logger)
  }
}

async function handleDownload(service, request, logger) {
  try {
    const url = new URL(request.url)
    const path = url.searchParams.get('path') || ''
    const file = await service.openDownload(path)
    const headers = {
      'content-type': 'application/octet-stream',
      'content-length': String(file.size),
      'content-disposition': contentDisposition(file.name),
      'cache-control': 'no-store',
    }
    if (request.method === 'HEAD') {
      file.stream.destroy()
      return new Response(null, { status: 200, headers })
    }
    return new Response(Readable.toWeb(file.stream), { status: 200, headers })
  } catch (error) {
    if (error && error.code === 'not-connected') return fail(error, logger)
    return jsonResponse({ ok: false, error: errorBody(error) }, statusFor(error))
  }
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {Record<string, unknown>} config
 */
export function apply(ctx, config = {}) {
  const logger = ctx.logger
  const service = new ServerViewService({ config: config || {}, logger })
  ctx.effect(() => () => service.dispose(), 'ssh-view: dispose session and vault')

  const register = (route) =>
    ctx.effect(
      () => ctx.connection.fetch.register(route),
      `ssh-view: ${route.path} route`,
    )

  register({
    path: RPC_PATH,
    methods: ['POST'],
    requestBody: 'buffered',
    fetch: (request) => handleRpc(service, request, logger),
  })
  register({
    path: UPLOAD_PATH,
    methods: ['POST'],
    requestBody: 'streaming',
    fetch: (request) => handleUpload(service, request, logger),
  })
  register({
    path: DOWNLOAD_PATH,
    methods: ['GET', 'HEAD'],
    requestBody: 'buffered',
    fetch: (request) => handleDownload(service, request, logger),
  })
}
