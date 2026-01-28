import { fromBase64UrlString } from '@z-base/bytecodec'
import { CryptosuiteError } from '../.errors/class.js'
import {
  ED25519_ALG,
  ED25519_CURVE,
  ED25519_USE,
  ED25519_BYTES,
  ED25519_PRIVATE_OPS,
} from './shared.js'

export function assertEd25519PrivateKey(
  jwk: JsonWebKey,
  context = 'key'
): void {
  if (!jwk || typeof jwk !== 'object') {
    throw new CryptosuiteError(
      'ED25519_PRIVATE_KEY_EXPECTED',
      `${context}: expected an Ed25519 private JWK.`
    )
  }

  if (jwk.kty !== 'OKP') {
    throw new CryptosuiteError(
      'ED25519_PRIVATE_KEY_EXPECTED',
      `${context}: expected kty OKP.`
    )
  }

  if (jwk.crv !== ED25519_CURVE) {
    throw new CryptosuiteError(
      'ED25519_CURVE_INVALID',
      `${context}: expected curve ${ED25519_CURVE}.`
    )
  }

  if (jwk.alg && jwk.alg !== ED25519_ALG) {
    throw new CryptosuiteError(
      'ED25519_ALG_INVALID',
      `${context}: expected alg ${ED25519_ALG}.`
    )
  }

  if (jwk.use && jwk.use !== ED25519_USE) {
    throw new CryptosuiteError(
      'ED25519_USE_INVALID',
      `${context}: expected use ${ED25519_USE}.`
    )
  }

  if (jwk.key_ops) {
    if (!Array.isArray(jwk.key_ops)) {
      throw new CryptosuiteError(
        'ED25519_KEY_OPS_INVALID',
        `${context}: key_ops must be an array.`
      )
    }
    const ops = new Set(jwk.key_ops)
    if (!ops.has('sign')) {
      throw new CryptosuiteError(
        'ED25519_KEY_OPS_INVALID',
        `${context}: key_ops must include sign.`
      )
    }
    for (const op of ops) {
      if (
        !ED25519_PRIVATE_OPS.includes(
          op as (typeof ED25519_PRIVATE_OPS)[number]
        )
      ) {
        throw new CryptosuiteError(
          'ED25519_KEY_OPS_INVALID',
          `${context}: unexpected key_ops value.`
        )
      }
    }
  }

  if (typeof jwk.x !== 'string') {
    throw new CryptosuiteError(
      'ED25519_PRIVATE_KEY_EXPECTED',
      `${context}: missing public key.`
    )
  }

  if (typeof jwk.d !== 'string') {
    throw new CryptosuiteError(
      'ED25519_PRIVATE_KEY_EXPECTED',
      `${context}: missing private key.`
    )
  }

  let x: Uint8Array
  let d: Uint8Array
  try {
    x = fromBase64UrlString(jwk.x)
    d = fromBase64UrlString(jwk.d)
  } catch {
    throw new CryptosuiteError(
      'BASE64URL_INVALID',
      `${context}: invalid base64url key material.`
    )
  }
  if (x.byteLength !== ED25519_BYTES || d.byteLength !== ED25519_BYTES) {
    throw new CryptosuiteError(
      'ED25519_KEY_SIZE_INVALID',
      `${context}: expected 32-byte key material.`
    )
  }
}
