// @ts-nocheck
import fs from 'node:fs'
import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import { buildHandshake } from '../../../tscode/bitseal_rtc/BitSealRTC.js'
import { toHex } from '@bsv/sdk/primitives/utils'

function key(byteVal: number): PrivateKey {
  const bytes = new Array(32).fill(0)
  bytes[31] = byteVal
  return new PrivateKey(bytes)
}

const self = key(5)
const peer = key(6)

const { raw, sig, salt } = buildHandshake(self, peer.toPublicKey())

const out = {
  handshake_raw: toHex(raw),
  handshake_sig: toHex(sig),
  salt: toHex(salt)
}
const file = process.argv[2] || 'ts_rtc_sign.json'
fs.writeFileSync(file, JSON.stringify(out, null, 2))
console.log('TS sign ok') 