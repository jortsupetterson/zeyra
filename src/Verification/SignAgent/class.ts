import { toBufferSource } from '@z-base/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertEd25519PrivateKey } from '../../.helpers/assertEd25519PrivateKey.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { SignJWK } from '../index.js'

export class SignAgent {
  private keyPromise: Promise<CryptoKey>

  constructor(signJwk: SignJWK) {
    assertEd25519PrivateKey(signJwk, 'SignAgent')
    assertSubtleAvailable('SignAgent')
    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          signJwk,
          { name: 'Ed25519' },
          false,
          ['sign']
        )
      } catch {
        throw new CryptosuiteError(
          'ED25519_UNSUPPORTED',
          'SignAgent: Ed25519 is not supported.'
        )
      }
    })()
  }

  async sign(bytes: Uint8Array): Promise<ArrayBuffer> {
    const key = await this.keyPromise
    return crypto.subtle.sign('Ed25519', key, toBufferSource(bytes))
  }
}
