import { toBufferSource } from '@z-base/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertEd25519PublicKey } from '../../.helpers/assertEd25519PublicKey.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { VerifyJWK } from '../index.js'

export class VerifyAgent {
  private keyPromise: Promise<CryptoKey>

  constructor(verifyJwk: VerifyJWK) {
    assertEd25519PublicKey(verifyJwk, 'VerifyAgent')
    assertSubtleAvailable('VerifyAgent')
    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          verifyJwk,
          { name: 'Ed25519' },
          false,
          ['verify']
        )
      } catch {
        throw new CryptosuiteError(
          'ED25519_UNSUPPORTED',
          'VerifyAgent: Ed25519 is not supported.'
        )
      }
    })()
  }

  async verify(bytes: Uint8Array, signature: ArrayBuffer): Promise<boolean> {
    const key = await this.keyPromise
    return crypto.subtle.verify(
      'Ed25519',
      key,
      signature,
      toBufferSource(bytes)
    )
  }
}
