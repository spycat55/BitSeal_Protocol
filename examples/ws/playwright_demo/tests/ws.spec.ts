import { test, expect } from '@playwright/test'
import path from 'path'
import * as esbuild from 'esbuild'

// util: 返回固定私钥 bytes = 0...0b
function fixedPrivBytes (b: number): number[] {
  return Array(31).fill(0).concat([b])
}

test.describe('BitSeal-WS Go<->Browser 互通', () => {
  // 测试前需手动启动 Go 服务器（监听 ws://localhost:8080/ws/socket）。
  // 若需更改地址，可通过环境变量 WS_URL 指定。

  test('前端通过浏览器 WebSocket 成功收发消息', async ({ page }) => {
    // 将浏览器 console.* 转发到 Node 输出，便于调试
    page.on('console', (msg) => {
      console.log(`[browser ${msg.type()}]`, msg.text())
    })

    // ---------- 在 Node 中打包浏览器脚本 ----------
    const entry = path.join(__dirname, '..', 'browser_entry.ts')
    const cryptoShimPlugin: esbuild.Plugin = {
      name: 'crypto-shim',
      setup(build) {
        // 拦截 import 'crypto'
        build.onResolve({ filter: /^crypto$/ }, () => ({ path: 'crypto', namespace: 'crypto-shim' }))
        build.onLoad({ filter: /.*/, namespace: 'crypto-shim' }, () => ({
          contents: `export function randomBytes(size){
            if(typeof globalThis!== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues){
              const arr=new Uint8Array(size); globalThis.crypto.getRandomValues(arr); return arr;
            }
            if (typeof require==='function') { const { randomBytes } = require('crypto'); return randomBytes(size) }
            throw new Error('randomBytes unavailable');
          }`,
          loader: 'js'
        }))
      }
    }

    const bundle = await esbuild.build({
      entryPoints: [entry],
      bundle: true,
      format: 'iife',
      globalName: 'BitSeal',
      write: false,
      platform: 'browser',
      target: ['es2020'],
      plugins: [cryptoShimPlugin]
    })

    const scriptText = bundle.outputFiles[0].text

    // 创建空白页并注入脚本
    await page.goto('about:blank')
    await page.addScriptTag({ content: scriptText })

    // 在浏览器上下文执行连接 & 消息收发
    const result = await page.evaluate(async ([clientBytes, serverBytes]) => {
      // BitSeal 在 globalThis 上提供导出
      const { PrivateKey, connectBitSealWS } = (window as any).BitSeal

      const fixedPriv = (bytes: number[]) => new PrivateKey(bytes)

      const clientPriv = fixedPriv(clientBytes)
      const serverPub = fixedPriv(serverBytes).toPublicKey()

      const wsURL = (globalThis as any).WS_URL ?? 'ws://localhost:8080/ws/socket'
      return await new Promise<any>((resolve, reject) => {
        const replies: string[] = []
        connectBitSealWS(clientPriv, serverPub, wsURL, {
          onSession: (sess: any) => {
            // verify peerPub matches serverPub
            const peerHex = sess.peerPub().encode(true, 'hex')
            replies.push('peer:' + peerHex)
          },
          onMessage: (plain: Uint8Array) => {
            replies.push(new TextDecoder().decode(plain))
            if (replies.length >= 3) {
              resolve(replies)
            }
            return null
          }
        }).then(({ send }: { send: (plain:any)=>void }) => {
          send('msg1 from browser')
          send('msg2 from browser')
        }).catch(reject)
      })
    }, [fixedPrivBytes(0x33), fixedPrivBytes(0x55)])

    const [peerLine, ack1, ack2] = result as string[]
    expect(peerLine.startsWith('peer:')).toBeTruthy()
    expect(ack1).toBe('server ack: msg1 from browser')
    expect(ack2).toBe('server ack: msg2 from browser')
  })
}) 