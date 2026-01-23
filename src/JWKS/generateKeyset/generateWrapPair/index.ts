export async function generateWrapPair(): Promise<{
  wrappingJwk: JsonWebKey;
  unwrappingJwk: JsonWebKey;
}> {
  const wrapPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["wrapKey", "unwrapKey"]
  );
  const wrappingJwk = await crypto.subtle.exportKey("jwk", wrapPair.publicKey);
  const unwrappingJwk = await crypto.subtle.exportKey(
    "jwk",
    wrapPair.privateKey
  );
  return { wrappingJwk, unwrappingJwk };
}
