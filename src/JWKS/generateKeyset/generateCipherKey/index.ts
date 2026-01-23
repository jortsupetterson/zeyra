export async function generateCipherKey(): Promise<JsonWebKey> {
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return await crypto.subtle.exportKey("jwk", aesKey);
}
