export async function generateHmacKey(): Promise<JsonWebKey> {
  const hmacKey = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign", "verify"]
  );
  return await crypto.subtle.exportKey("jwk", hmacKey);
}
