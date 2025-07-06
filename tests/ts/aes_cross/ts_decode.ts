#!/usr/bin/env bun
// ts-node / tsx 可直接运行
import { readFileSync } from 'fs'
import { createDecipheriv } from 'crypto'
import { AESGCMDecrypt } from '@bsv/sdk/primitives/AESGCM'

if (process.argv.length < 3) {
  console.error('Usage: ts_decode.ts data.json')
  process.exit(1)
}

const data = JSON.parse(readFileSync(process.argv[2], 'utf8')) as {
  key_hex: string
  nonce_hex: string
  ad_hex: string
  plain_hex: string
  cipher_hex: string
  tag_hex: string
}

function hexToBuf(h: string) { return Buffer.from(h, 'hex') }

const key = hexToBuf(data.key_hex)
const nonce = hexToBuf(data.nonce_hex)
const ad = hexToBuf(data.ad_hex)
const plainExp = hexToBuf(data.plain_hex)
const cipher = hexToBuf(data.cipher_hex)
const tag = hexToBuf(data.tag_hex)

// ---- Node crypto decrypt ----
let nodeOk = false
try {
  const dec = createDecipheriv('aes-256-gcm', key, nonce)
  dec.setAuthTag(tag)
  dec.setAAD(ad)
  const plainBuf = Buffer.concat([dec.update(cipher), dec.final()])
  nodeOk = plainBuf.equals(plainExp)
  console.log('[node-crypto] decrypt ok', nodeOk)
} catch (e) {
  console.error('[node-crypto] decrypt threw', e)
  process.exit(1)
}

// ---- SDK decrypt ----
let sdkOk = false
try {
  let recovered: Uint8Array | null = null
  if (AESGCMDecrypt.length === 4) {
    // Legacy ts-sdk signature: decrypt(cipher || tag, key, nonce, ad)
    const combo = Buffer.concat([cipher, tag])
    recovered = (AESGCMDecrypt as any)(Array.from(combo), Array.from(key), Array.from(nonce), Array.from(ad))
  } else {
    // Newer signature: decrypt(cipher, ad, nonce, tag, key)
    recovered = (AESGCMDecrypt as any)(Array.from(cipher), Array.from(ad), Array.from(nonce), Array.from(tag), Array.from(key))
  }
  sdkOk = recovered !== null && Buffer.from(recovered as any).equals(plainExp)
  console.log('[sdk] decrypt ok', sdkOk)
} catch (e) {
  console.log('[sdk] decrypt threw', (e as Error).message)
}

if (nodeOk && sdkOk) {
  // 双端均成功，测试通过
  process.exit(0)
}

console.error('Decrypt mismatch: nodeOk=', nodeOk, ' sdkOk=', sdkOk)
process.exit(1) 