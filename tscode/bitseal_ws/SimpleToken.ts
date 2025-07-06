import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import PublicKey from '@bsv/sdk/primitives/PublicKey'
import Signature from '@bsv/sdk/primitives/Signature'
import { toArray } from '@bsv/sdk/primitives/utils'
import { base64url } from 'jose'

export function createToken (payload: Record<string, any>, priv: PrivateKey, expSec: number = 60): string {
  const now = Math.floor(Date.now() / 1000)
  payload = { ...payload, iat: now, exp: now + expSec }
  const jsonStr = JSON.stringify(payload)
  const sig = priv.sign(jsonStr, 'utf8', true)
  const der = sig.toDER() as number[]
  const token = `${base64url.encode(new Uint8Array(toArray(jsonStr, 'utf8')))}.${base64url.encode(new Uint8Array(der))}`
  return token
}

export function verifyToken (token: string, pub: PublicKey): Record<string, any> {
  const parts = token.split('.')
  if (parts.length !== 2) throw new Error('token parts')
  const payloadStr = new TextDecoder().decode(base64url.decode(parts[0]))
  const sigDer = toArray(base64url.decode(parts[1]))
  const sig = Signature.fromDER(sigDer)
  const ok = pub.verify(payloadStr, sig, 'utf8')
  if (!ok) throw new Error('sig invalid')
  const payload = JSON.parse(payloadStr)
  if (typeof payload.exp === 'number' && payload.exp < Date.now() / 1000) {
    throw new Error('token expired')
  }
  return payload
} 