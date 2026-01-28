import { fromBase64UrlString } from '@z-base/bytecodec'
import { CryptosuiteError } from '../.errors/class.js'
import { HMAC_ALG, HMAC_USE, HMAC_KEY_BYTES, HMAC_KEY_OPS } from './shared.js'

export function assertHmacSha256Key(jwk: JsonWebKey, context = 'key'): void {
  if (!jwk || typeof jwk !== 'object') {
    throw new CryptosuiteError(
      'HMAC_KEY_EXPECTED',
      `${context}: expected an HMAC JWK.`
    )
  }

  if (jwk.kty !== 'oct') {
    throw new CryptosuiteError(
      'HMAC_KEY_EXPECTED',
      `${context}: expected an octet JWK for HMAC.`
    )
  }

  if (jwk.alg && jwk.alg !== HMAC_ALG) {
    throw new CryptosuiteError(
      'HMAC_ALG_INVALID',
      `${context}: expected alg ${HMAC_ALG}.`
    )
  }

  if (jwk.use && jwk.use !== HMAC_USE) {
    throw new CryptosuiteError(
      'HMAC_USE_INVALID',
      `${context}: expected use ${HMAC_USE}.`
    )
  }

  if (jwk.key_ops) {
    if (!Array.isArray(jwk.key_ops)) {
      throw new CryptosuiteError(
        'HMAC_KEY_OPS_INVALID',
        `${context}: key_ops must be an array.`
      )
    }
    const ops = new Set(jwk.key_ops)
    for (const op of ops) {
      if (!HMAC_KEY_OPS.includes(op as (typeof HMAC_KEY_OPS)[number])) {
        throw new CryptosuiteError(
          'HMAC_KEY_OPS_INVALID',
          `${context}: unexpected key_ops value.`
        )
      }
    }
    for (const required of HMAC_KEY_OPS) {
      if (!ops.has(required)) {
        throw new CryptosuiteError(
          'HMAC_KEY_OPS_INVALID',
          `${context}: key_ops must include ${required}.`
        )
      }
    }
  }

  if (typeof jwk.k !== 'string') {
    throw new CryptosuiteError(
      'HMAC_KEY_EXPECTED',
      `${context}: missing key material.`
    )
  }

  let keyBytes: Uint8Array
  try {
    keyBytes = fromBase64UrlString(jwk.k)
  } catch {
    throw new CryptosuiteError(
      'BASE64URL_INVALID',
      `${context}: invalid base64url key material.`
    )
  }
  if (keyBytes.byteLength !== HMAC_KEY_BYTES) {
    throw new CryptosuiteError(
      'HMAC_KEY_SIZE_INVALID',
      `${context}: expected 256-bit key material.`
    )
  }
}
