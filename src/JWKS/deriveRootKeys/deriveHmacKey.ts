export async function deriveHmacKey(first: BufferSource): Promise<JsonWebKey> {
  const key = await crypto.subtle.importKey(
    "raw",
    first,
    { name: "HMAC", hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );

  return await crypto.subtle.exportKey("jwk", key);
}
