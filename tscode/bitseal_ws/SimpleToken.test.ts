import { describe, it, expect } from 'vitest'
import PrivateKey from '@bsv/sdk/primitives/PrivateKey'
import { createToken, verifyToken } from './SimpleToken'

function priv(byteVal:number){
  const arr = new Array(32).fill(0); arr[31]=byteVal; return new PrivateKey(arr)
}

describe('SimpleToken', () => {
  it('roundtrip', () => {
    const p = priv(5)
    const token = createToken({foo:'bar'}, p, 120)
    const claims = verifyToken(token, p.toPublicKey())
    expect(claims.foo).toBe('bar')
  })
}) 