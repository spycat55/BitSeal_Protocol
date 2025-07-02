// @ts-nocheck
// bun run tscode/cross/ts_verify.ts <jsonFilePath>
import { readFileSync } from 'fs'
import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import { verifyRequest, buildCanonicalString, bodyHashHex, canonicalQueryString } from '../../../tscode/bitseal_web/BitSeal.ts'
import { verify as brc77Verify } from '@bsv/sdk/messages/SignedMessage'
import { toArray } from '@bsv/sdk/primitives/utils'
import { sha256 } from '@bsv/sdk/primitives/Hash'

function fixedPrivKey(byteVal: number): PrivateKey {
  return new PrivateKey(Array(31).fill(0).concat([byteVal]))
}

const path = process.argv[2]
if (!path) {
  console.error('usage: bun run ts_verify.ts <json-file>')
  process.exit(1)
}

const data = JSON.parse(readFileSync(path, 'utf8'))
const { method, uriPath, query, body, headers, serverPriv } = data
const serverPrivKey = PrivateKey.fromHex(serverPriv as string)
const ok = verifyRequest(method, uriPath, query, body, headers, serverPrivKey)

// extra direct check
let direct = true
try {
  const sigBytes = toArray(headers['X-BKSA-Sig'], 'base64')
  const canonical = buildCanonicalString(
    method,
    uriPath,
    query,
    body,
    headers['X-BKSA-Timestamp'],
    headers['X-BKSA-Nonce']
  )
  const digest = sha256(toArray(canonical, 'utf8'))
  direct = brc77Verify(digest, sigBytes, serverPrivKey)
} catch (e) {
  console.error('Direct brc77Verify error', e)
  direct = false
}

console.log('direct verify result', direct)

if (!ok) {
  const canonical = buildCanonicalString(
    method,
    uriPath,
    query,
    body,
    headers['X-BKSA-Timestamp'],
    headers['X-BKSA-Nonce']
  )
  const digestHex = bodyHashHex(canonical)
  console.error('TS verify FAILED')
  console.error('Canonical String:\n' + canonical)
  console.error('Digest(hex):', digestHex)
  console.error('Headers:', headers)
  process.exit(1)
}

console.log('TS verify success') 