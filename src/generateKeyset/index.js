/**
 * Generates a cryptographic keyset for a single resource.
 *
 * Returned keys:
 * - symmetricJwk: AES-GCM 256-bit key (JWK, kty:"oct") for encrypt/decrypt
 * - publicJwk: ECDSA P-256 public key (JWK) for verify
 * - privateJwk: ECDSA P-256 private key (JWK) for sign
 *
 * All keys are extractable and intended to be stored encrypted
 * or transported as data. Type definitions are expected to live
 * in a separate TypeScript types file.
 *
 * @returns {Promise<{
 *   symmetricJwk: JsonWebKey,
 *   publicJwk: JsonWebKey,
 *   privateJwk: JsonWebKey
 * }>}
 */
export async function generateKeyset() {
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const symmetricJwk = await crypto.subtle.exportKey("jwk", aesKey);

  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  return { symmetricJwk, publicJwk, privateJwk };
}
