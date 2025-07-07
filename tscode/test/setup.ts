import { randomBytes } from 'crypto'

// Vitest 运行于 Node 环境时，globalThis 可能没有 WebCrypto
// 这里注入一个仅包含 getRandomValues 的简易 polyfill，满足 @bsv/sdk 依赖
if (typeof globalThis.crypto === 'undefined') {
  // 定义最小化的 Crypto 接口，当前只实现 getRandomValues
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  globalThis.crypto = {
    getRandomValues<T extends ArrayBufferView | null>(array: T): T {
      if (array === null) {
        throw new TypeError('Expected input to be an ArrayBufferView')
      }
      const bytes = randomBytes((array as ArrayBufferView).byteLength)
      new Uint8Array(array!.buffer, array!.byteOffset, array!.byteLength).set(bytes)
      return array
    },
  } as Crypto
}

// 始终让 self 指向 globalThis，便于浏览器/Node 共享的第三方库检测
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
if (typeof globalThis.self === 'undefined') globalThis.self = globalThis

// 如果 self.crypto 或其 getRandomValues 缺失，填充前面定义的 polyfill
if (!globalThis.self.crypto || typeof globalThis.self.crypto.getRandomValues !== 'function') {
  // 若之前 crypto 已被填充，直接使用；否则重用上方 polyfill
  if (typeof globalThis.crypto !== 'undefined') {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    globalThis.self.crypto = globalThis.crypto
  }
} 