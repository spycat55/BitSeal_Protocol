// @ts-nocheck
import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import PublicKey from '@bsv/sdk/primitives/PublicKey'
import { sha256 } from '@bsv/sdk/primitives/Hash'
import { toHex, toArray, toUTF8 } from '@bsv/sdk/primitives/utils'
import { sign as brc77Sign, verify as brc77Verify } from '@bsv/sdk/messages/SignedMessage'
import { AESGCM, AESGCMDecrypt } from '@bsv/sdk/primitives/AESGCM'
import { randomBytes } from 'crypto'

const PROTO = 'BitSeal-RTC/1.0'
const TAG_SIZE = 16

export const buildHandshake = (selfPriv, peerPub) => {
  const salt = Array.from(randomBytes(4))
  const ts = Date.now()
  const pkHex = selfPriv.toPublicKey().encode(true, 'hex')
  const saltHex = toHex(salt)
  const rawStr = `{"proto":"${PROTO}","pk":"${pkHex}","salt":"${saltHex}","ts":${ts}}`
  const raw = toArray(rawStr, 'utf8')
  const sig = brc77Sign(raw, selfPriv, peerPub)
  return { raw, sig, salt }
}

export const verifyHandshake = (raw, sig, selfPriv) => {
  const json = JSON.parse(toUTF8(raw))
  if (json.proto !== PROTO) throw new Error('proto mismatch')
  const peerPub = PublicKey.fromString(json.pk)
  const ok = brc77Verify(raw, sig, selfPriv)
  if (!ok) throw new Error('sig invalid')
  const salt = toArray(json.salt, 'hex')
  return { peerPub, salt }
}

const deriveKey = (shared, saltA, saltB) => {
  // 确保双方拼接顺序一致：按字典序排序 salt
  const cmp = (a, b) => {
    for (let i = 0; i < 4; i++) {
      if (a[i] !== b[i]) return a[i] - b[i]
    }
    return 0
  }
  if (cmp(saltA, saltB) > 0) {
    [saltA, saltB] = [saltB, saltA]
  }
  const data = [...shared, ...saltA, ...saltB]
  return sha256(data)
}

export class Session {
  constructor (key, saltSend, saltRecv) {
    this.key = key
    this.saltSend = saltSend  // 用于本端发送
    this.saltRecv = saltRecv  // 用于解密对端数据
    this.seq = 0n
    this.windowSize = 64n
    this.maxSeq = 0n
    this.bitmap = 0n
  }

  static create (selfPriv, peerPub, saltSelf, saltPeer) {
    const shared = selfPriv.deriveSharedSecret(peerPub).encode(true)
    console.log('[derive] saltA', Buffer.from(saltSelf).toString('hex'),
                'saltB', Buffer.from(saltPeer).toString('hex'),
                'shared', Buffer.from(shared).subarray(0, 16).toString('hex'))
    const key = deriveKey(shared, saltSelf, saltPeer)
    console.log('[derive] key', Buffer.from(key).subarray(0, 16).toString('hex'))
    const rand = randomBytes(8)
    let init = 0n
    for (const b of rand) init = (init << 8n) + BigInt(b)
    const sess = new Session(key, saltSelf, saltPeer)
    sess.seq = init
    return sess
  }

  encode (plaintext, flags = 0) {
    this.seq += 1n
    const seqBytes = bigIntToBytes(this.seq, 8)
    const nonce = [...this.saltSend, ...seqBytes]
    const ad = [flags, ...seqBytes]
    const { result: cipher, authenticationTag: tag } = AESGCM(plaintext, ad, nonce, this.key)
    const len = 1 + 8 + cipher.length + TAG_SIZE
    return [...u32be(len), flags, ...seqBytes, ...cipher, ...tag]
  }

  decode (frame) {
    if (frame.length < 4 + 1 + 8 + TAG_SIZE) throw new Error('short')
    const len = u32beToInt(frame.slice(0, 4))
    if (len !== frame.length - 4) throw new Error('len mismatch')
    const flags = frame[4]
    const seq = bytesToBigInt(frame.slice(5, 13))
    if (!this.accept(seq)) throw new Error('replay')
    const cipher = frame.slice(13, frame.length - TAG_SIZE)
    const tag    = frame.slice(frame.length - TAG_SIZE)
    const seqBytes = frame.slice(5, 13)
    const nonce = [...this.saltRecv, ...seqBytes]
    const ad = [flags, ...seqBytes]
    // DEBUG
    console.log('[rtc.decode] saltRecv', Buffer.from(this.saltRecv).toString('hex'), 'seq', Buffer.from(seqBytes).toString('hex'))
    console.log('[rtc.decode] ad', Buffer.from(ad).toString('hex'))
    let plain
    if (AESGCMDecrypt.length === 4) {
      // library expects cipher||tag combined (array)
      const combo = new Uint8Array(cipher.length + TAG_SIZE)
      combo.set(cipher)
      combo.set(tag, cipher.length)
      plain = AESGCMDecrypt(Array.from(combo), ad, nonce, Array.from(this.key))
    } else {
      // 5-param signature (cipher, ad, nonce, tag, key) – all params should be array<number>
      plain = AESGCMDecrypt(
        Array.from(cipher),
        ad,
        nonce,
        Array.from(tag),
        Array.from(this.key)
      )
    }
    if (plain == null) throw new Error('decrypt fail')
    return plain instanceof Uint8Array ? plain : Uint8Array.from(plain)
  }

  accept (seq) {
    if (seq > this.maxSeq) {
      const shift = seq - this.maxSeq
      if (shift >= this.windowSize) {
        this.bitmap = 0n
      } else {
        this.bitmap <<= shift
      }
      this.bitmap |= 1n
      this.maxSeq = seq
      return true
    }
    const offset = this.maxSeq - seq
    if (offset >= this.windowSize) return false
    if ((this.bitmap >> offset) & 1n) return false
    this.bitmap |= 1n << offset
    return true
  }
}

// helpers
const u32be = (n) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
const u32beToInt = (b) => (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
const bigIntToBytes = (n, len) => {
  const arr = new Array(len).fill(0)
  for (let i = len - 1; i >= 0; i--) {
    arr[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return arr
}
const bytesToBigInt = (b) => b.reduce((acc, v) => (acc << 8n) + BigInt(v), 0n) 