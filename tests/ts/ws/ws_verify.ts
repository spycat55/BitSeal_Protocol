// @ts-nocheck
import { readFileSync } from 'fs'
import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import { verifyHandshakeRequest } from '../../../tscode/bitseal_ws/BitSealWS.ts'

const inPath = process.argv[2] || 'ws_go_sign.json'
const data = JSON.parse(readFileSync(inPath, 'utf8'))

function privFromHex(hex: string) {
  return PrivateKey.fromHex(hex)
}

const serverPriv = privFromHex(data.serverPriv)

const res = verifyHandshakeRequest(data.body, data.method, data.uriPath, data.headers, serverPriv)
if (!res.ok) {
  console.error('verify failed')
  process.exit(1)
}
console.log('verify ok salt', res.salt, 'nonce', res.nonce) 