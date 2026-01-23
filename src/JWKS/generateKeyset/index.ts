import { generateCipherKey } from "./generateCipherKey/index.js";
import { generateHmacKey } from "./generateHmacKey/index.js";
import { generateSignPair } from "./generateSignPair/index.js";
import { generateWrapPair } from "./generateWrapPair/index.js";
export async function generateKeyset(): Promise<{
  cipherJwk: JsonWebKey;
  verificationJwk: JsonWebKey;
  signingJwk: JsonWebKey;
  wrappingJwk: JsonWebKey;
  unwrappingJwk: JsonWebKey;
  hmacJwk: JsonWebKey;
}> {
  const { signingJwk, verificationJwk } = await generateSignPair();
  const { wrappingJwk, unwrappingJwk } = await generateWrapPair();
  const hmacJwk = await generateHmacKey();
  const cipherJwk = await generateCipherKey();
  return {
    cipherJwk,
    verificationJwk,
    signingJwk,
    wrappingJwk,
    unwrappingJwk,
    hmacJwk,
  };
}
