// @ts-nocheck
import { writeFileSync } from 'fs'
import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import { buildHandshakeRequest } from '../../../tscode/bitseal_ws/BitSealWS.ts'
import PublicKey from '@bsv/sdk/primitives/PublicKey'

function fixedPriv(b: number) {
  return new PrivateKey(Array(31).fill(0).concat([b]))
}

const outPath = process.argv[2] || 'ws_ts_sign.json'
const clientPriv = fixedPriv(0x11)
const serverPriv = fixedPriv(0x22)

const { body, headers, salt } = buildHandshakeRequest(clientPriv, serverPriv.toPublicKey(), {
  nonce: 'deadbeefdeadbeefdeadbeefdeadbeef'
})

const obj = {
  method: 'POST',
  uriPath: '/ws/handshake',
  body,
  headers,
  serverPriv: serverPriv.toHex()
}
writeFileSync(outPath, JSON.stringify(obj))
console.log('wrote', outPath) 