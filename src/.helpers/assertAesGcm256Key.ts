import { fromBase64UrlString } from '@z-base/bytecodec'
import { CryptosuiteError } from '../.errors/class.js'
import {
  AES_GCM_ALG,
  AES_GCM_USE,
  AES_GCM_KEY_BYTES,
  AES_GCM_KEY_OPS,
} from './shared.js'

export function assertAesGcm256Key(jwk: JsonWebKey, context = 'key'): void {
  if (!jwk || typeof jwk !== 'object') {
    throw new CryptosuiteError(
      'AES_GCM_KEY_EXPECTED',
      `${context}: expected an AES-GCM JWK.`
    )
  }

  if (jwk.kty !== 'oct') {
    throw new CryptosuiteError(
      'AES_GCM_KEY_EXPECTED',
      `${context}: expected an octet JWK for AES-GCM.`
    )
  }

  if (jwk.alg && jwk.alg !== AES_GCM_ALG) {
    throw new CryptosuiteError(
      'AES_GCM_ALG_INVALID',
      `${context}: expected alg ${AES_GCM_ALG}.`
    )
  }

  if (jwk.use && jwk.use !== AES_GCM_USE) {
    throw new CryptosuiteError(
      'AES_GCM_USE_INVALID',
      `${context}: expected use ${AES_GCM_USE}.`
    )
  }

  if (jwk.key_ops) {
    if (!Array.isArray(jwk.key_ops)) {
      throw new CryptosuiteError(
        'AES_GCM_KEY_OPS_INVALID',
        `${context}: key_ops must be an array.`
      )
    }
    const ops = new Set(jwk.key_ops)
    for (const op of ops) {
      if (!AES_GCM_KEY_OPS.includes(op as (typeof AES_GCM_KEY_OPS)[number])) {
        throw new CryptosuiteError(
          'AES_GCM_KEY_OPS_INVALID',
          `${context}: unexpected key_ops value.`
        )
      }
    }
    for (const required of AES_GCM_KEY_OPS) {
      if (!ops.has(required)) {
        throw new CryptosuiteError(
          'AES_GCM_KEY_OPS_INVALID',
          `${context}: key_ops must include ${required}.`
        )
      }
    }
  }

  if (typeof jwk.k !== 'string') {
    throw new CryptosuiteError(
      'AES_GCM_KEY_EXPECTED',
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
  if (keyBytes.byteLength !== AES_GCM_KEY_BYTES) {
    throw new CryptosuiteError(
      'AES_GCM_KEY_SIZE_INVALID',
      `${context}: expected 256-bit key material.`
    )
  }
}
