// @ts-nocheck
import { writeFileSync } from 'fs'
import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import { createToken } from '../../../tscode/bitseal_ws/SimpleToken.ts'

function fixedPriv(b: number) {
  return new PrivateKey(Array(31).fill(0).concat([b]))
}

const outPath = process.argv[2] || 'token_ts.json'
const priv = fixedPriv(0x44)
const pub = priv.toPublicKey()

const token = createToken({ hello: 'world' }, priv, 300)
const obj = {
  token,
  pub: pub.encode(true, 'hex')
}
writeFileSync(outPath, JSON.stringify(obj))
console.log('wrote', outPath) 