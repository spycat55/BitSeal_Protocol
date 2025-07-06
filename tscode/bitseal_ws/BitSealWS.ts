// @ts-nocheck
// BitSeal-WS TypeScript helper – compose Web (handshake) + RTC (BST2)

import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import PublicKey from '@bsv/sdk/primitives/PublicKey'
import BigNumber from '@bsv/sdk/primitives/BigNumber'
import { randomBytes } from 'crypto'
import { toHex } from '@bsv/sdk/primitives/utils'
import { signRequest, BitSealHeaders, verifyRequest } from '../bitseal_web/BitSeal'
import { Session } from '../bitseal_rtc/BitSealRTC.js'
import { sha256 } from '@bsv/sdk/primitives/Hash'
import { sign as brc77Sign, verify as brc77Verify } from '@bsv/sdk/messages/SignedMessage'
import { createToken as createSimpleToken, verifyToken } from './SimpleToken'

/** Generate a 4-byte random salt in hex */
const randomSalt4 = (): string => toHex(Array.from(randomBytes(4)))

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
    nonce: opts.nonce ?? randomBytes(16).toString('hex')
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
  const saltClient = Array.from(Buffer.from(saltClientHex, 'hex'))
  const saltServer = Array.from(Buffer.from(jwtPayload.salt_s as string, 'hex'))
  const sess = Session.create(clientPriv, serverPub, saltClient, saltServer)
  return sess
}

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
  /** isomorphic-ws constructor (for dependency injection / tests) */
  WebSocketImpl?: any
  /** timeout ms for HTTP handshake */
  timeoutMs?: number
}

/** Result of connectBitSealWS() */
export interface ConnectResult {
  ws: any /* WebSocket */
  session: Session
  jwtPayload: Record<string, any>
  clientSaltHex: string
  token: string
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
  const WebSocketCtor = opts.WebSocketImpl ?? (await import('isomorphic-ws')).default
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
  const respJson = JSON.parse(respText)

  // collect headers into simple map
  const respHeaders: Record<string, string> = {}
  res.headers.forEach((v, k) => { respHeaders[k] = v })

  // verify server signature (BitSeal-WEB)
  const ok = verifyRequest('POST', '/ws/handshake', '', respText, respHeaders, clientPriv)
  if (!ok) throw new Error('server BitSeal signature invalid')

  const token = respJson.token as string
  const jwtPayload = verifyToken(token, serverPub)

  // ---------- Step-2 WebSocket Upgrade (sub-protocol carries JWT) ----------
  const protocols = ['BitSeal-WS.1', token]
  const ws = new WebSocketCtor(wsUrl, protocols)

  // wait until open
  await new Promise((resolve, reject) => {
    ws.onopen = () => resolve(undefined)
    ws.onerror = (ev: any) => reject(ev.error ?? new Error('ws error'))
  })

  const session = sessionFromJwt(clientPriv, serverPub, jwtPayload, saltClientHex)

  return { ws, session, jwtPayload, clientSaltHex: saltClientHex, token }
}

// --------------------------------------------------------------------------------- 