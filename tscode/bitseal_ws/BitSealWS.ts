// @ts-nocheck
// BitSeal-WS TypeScript helper – compose Web (handshake) + RTC (BST2)

import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import PublicKey from '@bsv/sdk/primitives/PublicKey'
import BigNumber from '@bsv/sdk/primitives/BigNumber'
import Random from '@bsv/sdk/primitives/Random'
import { toHex, toArray } from '@bsv/sdk/primitives/utils'
import { signRequest, BitSealHeaders, verifyRequest } from '../bitseal_web/BitSeal'
import { Session } from '../bitseal_rtc/BitSealRTC.js'
import { sha256 } from '@bsv/sdk/primitives/Hash'
import { sign as brc77Sign, verify as brc77Verify } from '@bsv/sdk/messages/SignedMessage'
import { createToken as createSimpleToken, verifyToken } from './SimpleToken'

/** Generate a 4-byte random salt in hex */
const randomSalt4 = (): string => toHex(Random(4))

/** Step-1: build POST /ws/handshake body + headers */
export function buildHandshakeRequest (
  clientPriv: PrivateKey,
  serverPub: PublicKey,
  opts: Partial<{ ts: string, nonce: string }> = {}
): { body: string, headers: BitSealHeaders, salt: string } {
  const salt = randomSalt4()
  const bodyObj = {
    proto: 'BitSeal-WS.1',
    pk: clientPriv.toPublicKey().encode(true, 'hex'),
    salt,
    nonce: opts.nonce ?? toHex(Random(16))
  }
  const body = JSON.stringify(bodyObj)
  const headers = signRequest('POST', '/ws/handshake', '', body, clientPriv, serverPub, {
    timestamp: opts.ts,
    nonce: bodyObj.nonce
  })
  return { body, headers, salt }
}

/** Step-1 server-side verification helper */
export function verifyHandshakeRequest (
  body: string,
  method: string,
  uriPath: string,
  headers: Record<string, string>,
  serverPriv: PrivateKey
): { ok: boolean, clientPub?: PublicKey, salt?: string, nonce?: string } {
  const ok = verifyRequest(method, uriPath, '', body, headers, serverPriv)
  if (!ok) return { ok: false }
  const obj = JSON.parse(body)
  return {
    ok: true,
    clientPub: PublicKey.fromString(obj.pk),
    salt: obj.salt,
    nonce: obj.nonce
  }
}

/** @deprecated 改用 WebSocket(url, ['BitSeal-WS/1.0', token]) */
export function buildUpgradeHeaders (_jwt: string): Record<string, string> {
  throw new Error('buildUpgradeHeaders deprecated; use sub-protocol array instead.')
}

/** Create BST2 session (client side) from own priv key and data in JWT */
export function sessionFromJwt (
  clientPriv: PrivateKey,
  serverPub: PublicKey,
  jwtPayload: Record<string, any>,
  saltClientHex: string
): Session {
  const saltClient = toArray(saltClientHex, 'hex')
  const saltServer = toArray(jwtPayload.salt_s as string, 'hex')
  const sess = Session.create(clientPriv, serverPub, saltClient, saltServer)
  return sess
}

// --- Internal light-weight WebSocket interface（最小依赖 send/close/on*） ------------------------
export interface WebSocketLike {
  send(data: string | ArrayBufferLike | Blob | ArrayBufferView): void
  close(code?: number, reason?: string): void
  onopen: ((ev: any) => any) | null
  onerror: ((ev: any) => any) | null
  onmessage: ((ev: { data: ArrayBuffer | ArrayBufferView | Blob | string }) => any) | null
}

// 构造函数类型：与浏览器/isomorphic-ws 一致
export type WebSocketConstructor = new (
  url: string | URL,
  protocols?: string | string[]
) => WebSocketLike

// --- New high-level client helper -------------------------------------------------
/** Options for connectBitSealWS */
export interface ConnectOptions {
  /** HTTP origin, default derives from wsUrl if omitted */
  httpBase?: string
  /** custom fetch implementation */
  fetchImpl?: typeof fetch
  /** extra headers to append to POST /ws/handshake */
  extraHeaders?: Record<string, string>
  /** supply a preconstructed salt (hex) – mainly for tests */
  clientSaltHex?: string
  /** WebSocket 构造函数（默认使用 isomorphic-ws） */
  WebSocketImpl?: WebSocketConstructor
  /** timeout ms for HTTP handshake */
  timeoutMs?: number
  /**
   * 业务回调：当收到一条解密后的明文时触发。
   *
   * plain       – 解密后的明文字节
   * session     – 当前 BST2 Session，可用于 encode / decode
   * ws          – WebSocket 对象，方便额外操作
   * peerPub     – 对方公钥（服务器）
   * selfPriv    – 自己的私钥
   *
   * 返回值：若返回 Uint8Array | string，则自动 encodeRecord 并通过 ws 发送；
   *           返回 null/undefined 则表示无需回复。
   */
  onMessage?: (
    plain: Uint8Array,
    session: Session,
    ws: WebSocketLike,
    peerPub: PublicKey,
    selfPriv: PrivateKey
  ) => Uint8Array | string | null | undefined | Promise<Uint8Array | string | null | undefined>

  /** 成功建立 BST2 Session 后回调，可用于保存 session、读取 peerPub 等。*/
  onSession?: (session: Session, ws: WebSocketLike, peerPub: PublicKey, selfPriv: PrivateKey) => void | Promise<void>
}

/** Result of connectBitSealWS() */
export interface ConnectResult {
  ws: WebSocketLike
  session: Session
  jwtPayload: Record<string, any>
  clientSaltHex: string
  token: string
  /** 服务端额外返回字段（respJson 去除 token / salt_s 后剩余部分） */
  extra: Record<string, any>
  /** 发送明文，内部自动 encodeRecord */
  send: (plain: Uint8Array | string) => void
}

/**
 * Complete client-side flow:
 * 1. POST /ws/handshake 进行 BitSeal-WEB 签名握手，验证服务器回签。
 * 2. 根据返回的 JWT、salt 等派生 BST2 Session。
 * 3. 带 sub-protocol 与 Authorization 头发起 WebSocket Upgrade。
 * 返回 {ws, session} 供上层读写（发送前 encodeRecord，收到后 decodeRecord）。
 */
export async function connectBitSealWS (
  clientPriv: PrivateKey,
  serverPub: PublicKey,
  wsUrl: string,
  opts: ConnectOptions = {}
): Promise<ConnectResult> {
  // 优先使用调用方指定，其次检测全局 WebSocket（浏览器/Bun），最后回退 isomorphic-ws
  let WebSocketCtor: WebSocketConstructor | undefined = opts.WebSocketImpl as WebSocketConstructor | undefined
  if (!WebSocketCtor && typeof (globalThis as any).WebSocket === 'function') {
    WebSocketCtor = (globalThis as any).WebSocket as WebSocketConstructor
  }
  if (!WebSocketCtor) {
    WebSocketCtor = (await import('isomorphic-ws')).default as unknown as WebSocketConstructor
  }
  const fetcher: typeof fetch = opts.fetchImpl ?? (globalThis as any).fetch
  if (!fetcher) throw new Error('fetch implementation not found')

  // Derive HTTP base from wsUrl if not provided
  let httpBase = opts.httpBase
  if (!httpBase) {
    const u = new URL(wsUrl)
    u.protocol = u.protocol.startsWith('wss') ? 'https:' : 'http:'
    httpBase = u.origin
  }

  // ---------- Step-1 POST /ws/handshake ----------
  const { body, headers: signedHeaders, salt: saltClientHex } = buildHandshakeRequest(
    clientPriv,
    serverPub,
    opts.clientSaltHex ? { nonce: undefined } : {}
  )
  if (opts.clientSaltHex) {
    // override generated salt if provided
    const bodyObj = JSON.parse(body)
    bodyObj.salt = opts.clientSaltHex
    const newBody = JSON.stringify(bodyObj)
    // need to resign
    Object.assign(signedHeaders, signRequest('POST', '/ws/handshake', '', newBody, clientPriv, serverPub))
  }

  const reqHeaders: Record<string, string> = { ...signedHeaders, ...(opts.extraHeaders ?? {}) }
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15000)
  const res = await fetcher(`${httpBase}/ws/handshake`, {
    method: 'POST',
    headers: reqHeaders,
    body,
    signal: controller.signal
  })
  clearTimeout(timeout)
  if (!res.ok) throw new Error(`handshake HTTP ${res.status}`)
  const respText = await res.text()
  const respJson: Record<string, any> = JSON.parse(respText)

  // collect headers into simple map
  const respHeaders: Record<string, string> = {}
  res.headers.forEach((v, k) => { respHeaders[k] = v })

  // verify server signature (BitSeal-WEB)
  const ok = verifyRequest('POST', '/ws/handshake', '', respText, respHeaders, clientPriv)
  if (!ok) throw new Error('server BitSeal signature invalid')

  const token = respJson.token as string
  const jwtPayload = verifyToken(token, serverPub)

  console.log('[handshake] clientSalt', saltClientHex, 'serverSalt from resp', respJson.salt_s)

  // derive extra payload (copy then delete known keys)
  const extraPayload: Record<string, any> = { ...respJson }
  delete extraPayload.token
  delete extraPayload.salt_s

  // ---------- Step-2 WebSocket Upgrade (sub-protocol carries JWT) ----------
  const protocols = ['BitSeal-WS.1', token]
  const ws = new WebSocketCtor(wsUrl, protocols)

  // wait until open
  await new Promise((resolve, reject) => {
    ws.onopen = () => resolve(undefined)
    ws.onerror = (ev: any) => reject((ev as any).error ?? new Error('ws error'))
  })

  const session = sessionFromJwt(clientPriv, serverPub, jwtPayload, saltClientHex)

  // 业务回调：会话已建立
  if (opts.onSession) {
    try {
      await opts.onSession(session, ws, serverPub, clientPriv)
    } catch (err) {
      console.error('onSession handler error', err)
    }
  }

  // 封装 send() – 隐藏 encodeRecord
  const send = (plain: Uint8Array | string): void => {
    const bytes = typeof plain === 'string' ? new TextEncoder().encode(plain) : plain
    const arr = Uint8Array.from(session.encode(bytes))
    console.log('[debug] send len', arr.length, 'first16', toHex(arr.subarray(0, 16)))
    ws.send(arr.buffer) // send ArrayBuffer for binary frame
  }

  // 自动封装 onmessage，若业务方提供了回调
  if (opts.onMessage) {
    ws.onmessage = async (ev) => {
      try {
        let raw: Uint8Array
        if (typeof ev.data === 'string') {
          raw = new TextEncoder().encode(ev.data as string)
        } else if (ev.data instanceof ArrayBuffer || ArrayBuffer.isView(ev.data)) {
          raw = ev.data instanceof Uint8Array ? ev.data : new Uint8Array(ev.data as ArrayBuffer)
        } else if (globalThis.Blob && ev.data instanceof Blob) {
          // Node-undici 在 binaryType=undefined 时默认返回 Blob
          const ab = await ev.data.arrayBuffer()
          raw = new Uint8Array(ab)
        } else {
          console.error('[debug] unsupported ev.data type', typeof ev.data, ev.data)
          return
        }

        console.log('[debug] recv typeof', typeof ev.data, 'len', raw.length, 'first16', toHex(raw.subarray(0, 16)))

        const plain = session.decode(raw)
        const resp = await opts.onMessage!(plain, session, ws, serverPub, clientPriv)
        if (resp != null) {
          send(resp)
        }
      } catch (err) {
        console.error('onMessage handler error', err)
      }
    }
  }

  return { ws, session, jwtPayload, clientSaltHex: saltClientHex, token, extra: extraPayload, send }
}

// ---------------------------------------------------------------------------------
// Server-side helper: build handshake response JSON & headers
// ---------------------------------------------------------------------------------

export interface HandshakeResponseOptions {
  /** override expire seconds for SimpleToken, default 60 */
  expSec?: number
  /** 业务扩展回调：返回要合并进响应 JSON 的键值对（同键覆盖）。*/
  onHandshakeResponse?: (req: {
    clientPub: PublicKey
    nonce: string
  }) => Record<string, any> | undefined
}

/**
 * 根据已通过 verifyHandshakeRequest() 的信息，生成返回给客户端的 JSON body 与签名头。
 *
 * @param serverPriv   服务器私钥
 * @param clientPub    客户端公钥
 * @param nonce        verifyHandshakeRequest 返回的 nonce
 * @param opts         可选：token 过期秒数、业务回调合并额外字段
 */
export function buildHandshakeResponse (
  serverPriv: PrivateKey,
  clientPub: PublicKey,
  nonce: string,
  opts: HandshakeResponseOptions = {}
): { body: string, headers: BitSealHeaders, token: string, saltS: string } {
  const saltS = randomSalt4()

  // Build SimpleToken payload
  const claims = {
    addr: `pk:${clientPub.encode(true, 'hex')}`,
    salt_s: saltS,
    nonce
  }
  const token = createSimpleToken(claims, serverPriv, opts.expSec ?? 60)

  // default response object
  const respObj: Record<string, any> = {
    token,
    salt_s: saltS,
    ts: Date.now(),
    nonce
  }

  // merge business extras
  if (opts.onHandshakeResponse) {
    const extra = opts.onHandshakeResponse({ clientPub, nonce }) ?? {}
    Object.assign(respObj, extra)
  }

  const body = JSON.stringify(respObj)

  // Sign headers using BitSeal-WEB helper (same algorithm as Go version)
  const headers = signRequest('POST', '/ws/handshake', '', body, serverPriv, clientPub)

  return { body, headers, token, saltS }
}

// --------------------------------------------------------------------------------- 