export async function generateSignPair(): Promise<{
  signingJwk: JsonWebKey;
  verificationJwk: JsonWebKey;
}> {
  const signPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const verificationJwk = await crypto.subtle.exportKey(
    "jwk",
    signPair.publicKey
  );
  const signingJwk = await crypto.subtle.exportKey("jwk", signPair.privateKey);
  return { signingJwk, verificationJwk };
}
