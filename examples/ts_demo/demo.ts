import {
  Fragmenter,
  Reassembler,
  signRequest,
  verifyRequest,
  randomNonce
} from 'bitseal'

/* ───────────── Dummy Session ─────────────
   仅用于展示分片流程：encode / decode 不做加密，
   直接把数据原样变成 Uint8Array 往返。                */
class DummySession {
  encode (plaintext: number[] | Uint8Array, _flags = 0): Uint8Array {
    return Uint8Array.from(plaintext)
  }
  decode (frame: Uint8Array): Uint8Array {
    return frame
  }
}
const sess = new DummySession()

// ===== 1) BitSeal-RTC Fragment Demo =====
const payload = new TextEncoder().encode(
  'Hello BitSeal 👋 – 这是一段需要传输的超长数据，演示分片与重组…'
)

const fragger = new Fragmenter(sess)
const frames = fragger.encode(payload)
console.log(
  `原始长度 ${payload.length} bytes => 分成 ${frames.length} 片:`,
  frames.map(f => f.length)
)

// 乱序递送
const shuffled = [...frames].sort(() => Math.random() - 0.5)
const reassembler = new Reassembler(sess)

for (const f of shuffled) {
  const { done, msg } = reassembler.push(f)
  if (done && msg) {
    console.log('重组结果:', new TextDecoder().decode(msg))
  }
}

// ===== 2) BitSeal-Web Request-Sign Demo =====
import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
const clientPriv = PrivateKey.fromRandom()
const serverPriv = PrivateKey.fromRandom()
const serverPub = serverPriv.toPublicKey()

const headers = signRequest(
  'POST',
  '/api/upload',
  '?q=test',
  '{"foo":1}',
  clientPriv,
  serverPub,
  { nonce: randomNonce() }
)
console.log('\n生成的签名头:', headers)

const ok = verifyRequest(
  'POST',
  '/api/upload',
  '?q=test',
  '{"foo":1}',
  headers,
  serverPriv
)
console.log('服务器验签结果 ->', ok)