export async function deriveCipherKey(
  second: BufferSource
): Promise<JsonWebKey> {
  const key = await crypto.subtle.importKey(
    "raw",
    second,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
  return await crypto.subtle.exportKey("jwk", key);
}
