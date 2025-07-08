import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import { connectBitSealWS, WebSocketLike } from '../../../tscode/bitseal_ws/BitSealWS.ts'

function fixedPriv(b: number): PrivateKey {
  return new PrivateKey(Array(31).fill(0).concat([b]))
}

(async () => {
  const clientPriv = fixedPriv(0x33)
  const serverPub = fixedPriv(0x55).toPublicKey()

  let resolveDone!: () => void
  const done = new Promise<void>((r) => { resolveDone = r })

  console.log('script start')

  try {
    const { ws, send, session, extra, jwtPayload, clientSaltHex, token } = await connectBitSealWS(clientPriv, serverPub, 'ws://localhost:8080/ws/socket', {
      WebSocketImpl: WebSocket as unknown as any,
      onSession: (sess, _ws, peerPub, _selfPriv) => {
        console.log('[onSession] peerPub(hex)=', peerPub.encode(true, 'hex'))
        console.log('[onSession] sess.peerPub() ==', sess.peerPub().encode(true, 'hex'))
      },
      onMessage: (plain: Uint8Array, _sess, _ws: WebSocketLike, _peerPub, _selfPriv) => {
        console.log('got reply:', new TextDecoder().decode(plain))
        _ws.close()
        resolveDone()
        return null // 不再回复
      }
    })

    console.log('connected, extra fields =', extra)
    console.log('jwtPayload', jwtPayload)
    console.log('clientSaltHex', clientSaltHex)
    console.log('token', token)
    console.log('ws.readyState =', (ws as any).readyState, 'sending hello via send()')

    ;(ws as any).onopen = () => console.log('[debug] ws onopen')
    ;(ws as any).onerror = (e: any) => console.log('[debug] ws onerror', e)
    ;(ws as any).onclose = (e: any) => console.log('[debug] ws onclose', e.code, e.reason)

    send('hello BitSeal-WS')

    console.log('after send, awaiting reply …')

    // wait until reply received
    await done

    console.log('after connect, session.peerPub() =', session.peerPub().encode(true, 'hex'))

    console.log('script end')
  } catch (err) {
    console.error('connectBitSealWS failed', err)
  }
})(); 