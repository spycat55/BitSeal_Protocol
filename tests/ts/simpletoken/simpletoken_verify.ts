// @ts-nocheck
import { readFileSync } from 'fs'
import PublicKey from '@bsv/sdk/primitives/PublicKey'
import { verifyToken } from '../../../tscode/bitseal_ws/SimpleToken.ts'

const file = process.argv[2] || 'token_go.json'
const data = JSON.parse(readFileSync(file, 'utf8'))

const pub = PublicKey.fromString(data.pub)
const claims = verifyToken(data.token, pub)
console.log('TS verify OK', claims) 