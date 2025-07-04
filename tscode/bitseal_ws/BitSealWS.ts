// @ts-nocheck
// BitSeal-WS TypeScript helper – compose Web (handshake) + RTC (BST2)

import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import PublicKey from '@bsv/sdk/primitives/PublicKey'
import { randomBytes } from 'crypto'
import { toHex } from '@bsv/sdk/primitives/utils'
import { signRequest, BitSealHeaders, verifyRequest } from '../bitseal_web/BitSeal'
import { Session } from '../bitseal_rtc/BitSealRTC.js'
import { sha256 } from '@bsv/sdk/primitives/Hash'
import { sign as brc77Sign, verify as brc77Verify } from '@bsv/sdk/messages/SignedMessage'
import * as jose from 'jose' // ES256K JWT (assumes jose >=5)

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
    proto: 'BitSeal-WS/1.0',
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

/** Create JWT token signed by server private key (ES256K low-s) */
export async function createJwtToken (
  payload: Record<string, any>,
  serverPriv: PrivateKey,
  expSec = 60
): Promise<string> {
  const pkJwk = await jose.exportJWK(serverPriv.toPublicKey().toRaw()) // placeholder; adjust conversion
  const privJwk = await jose.exportJWK(serverPriv.toRaw())
  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256K' })
    .setIssuedAt()
    .setExpirationTime(`${expSec}s`)
    .sign(jose.importJWK(privJwk, 'ES256K'))
  return jwt
}

/** Verify JWT using server public key */
export async function verifyJwt (token: string, serverPub: PublicKey): Promise<Record<string, any>> {
  const pubJwk = await jose.exportJWK(serverPub.toRaw())
  const { payload } = await jose.jwtVerify(token, await jose.importJWK(pubJwk, 'ES256K'))
  return payload as Record<string, any>
}

/** Step-2: build Upgrade headers */
export function buildUpgradeHeaders (jwtToken: string): Record<string, string> {
  return {
    'Sec-WebSocket-Protocol': 'BitSeal-WS/1.0',
    'Authorization': `BitSeal ${jwtToken}`
  }
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