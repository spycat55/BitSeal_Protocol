// @ts-nocheck
import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import PublicKey from '@bsv/sdk/primitives/PublicKey'
import { connectBitSealWS } from '../../../tscode/bitseal_ws/BitSealWS.ts'

function fixedPriv(b:number){return new PrivateKey(Array(31).fill(0).concat([b]))}

(async()=>{
  const clientPriv=fixedPriv(0x33)
  const serverPub=fixedPriv(0x55).toPublicKey()

  const {ws,session}=await connectBitSealWS(clientPriv,serverPub,'ws://localhost:8080/ws/socket')
  console.log('connected, sending hello')
  const payload=new TextEncoder().encode('hello BitSeal-WS')
  ws.send(Buffer.from(session.encode(payload)))
  ws.onmessage=(ev:any)=>{
    const plain=session.decode(new Uint8Array(ev.data))
    console.log('echo:',new TextDecoder().decode(plain))
    ws.close()
  }
})(); 