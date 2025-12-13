# Zeyra

WebCrypto helpers for zero-knowledge–friendly flows: generate AES-GCM + ECDSA keysets as JWKs and wrap them with tiny agent classes for encrypt, decrypt, sign, and verify.

## Features
- AES-GCM 256 encryption/decryption via `CipherAgent`
- ECDSA P-256 signing/verification via `SigningAgent` and `VerificationAgent`
- `generateKeyset()` produces an exportable JWK bundle you can store or transport
- Pure WebCrypto, no native add-ons; ships as ESM
- Plays nicely with `bytecodec` for UTF-8 and base64url conversions

## Requirements
- Node.js 18+ (global `crypto.subtle`)
- ESM environment (`"type": "module"` in `package.json`)

## Installation
```bash
npm install zeyra
```

## Quickstart
```js
import { Bytes } from "bytecodec";
import {
  generateKeyset,
  CipherAgent,
  SigningAgent,
  VerificationAgent,
} from "zeyra";

// One-time key material for a resource
const { symmetricJwk, privateJwk, publicJwk } = await generateKeyset();

// Writers: encrypt + sign
const cipher = new CipherAgent(symmetricJwk);
const signer = new SigningAgent(privateJwk);
const payload = await cipher.encrypt(Bytes.fromString("hello world"));
const signature = await signer.sign(payload.ciphertext);

// Readers / servers: verify ownership + decrypt
const verifier = new VerificationAgent(publicJwk);
const authorized = await verifier.verify(payload.ciphertext, signature);
const plaintext = Bytes.toString(await cipher.decrypt(payload));
```

## API
- `generateKeyset()` -> `{ symmetricJwk, publicJwk, privateJwk }` (all exportable JWKs)
- `new CipherAgent(symmetricJwk)`  
  - `.encrypt(Uint8Array)` -> `{ iv: Uint8Array, ciphertext: ArrayBuffer }`  
  - `.decrypt({ iv, ciphertext })` -> `Uint8Array`
- `new SigningAgent(privateJwk)`  
  - `.sign(Uint8Array | ArrayBuffer)` -> `ArrayBuffer` (ECDSA P-256 / SHA-256)
- `new VerificationAgent(publicJwk)`  
  - `.verify(Uint8Array | ArrayBuffer, ArrayBuffer)` -> `boolean`

See the implementations in `src/index.js` and friends for details.

## Testing and benchmarks
- Run tests: `npm test` (uses Node’s built-in `node:test` runner against `test.js`)
- Run microbenchmarks (skipped by default): `npm run bench`  
  - Pass iterations: `npm run bench -- --iterations=500`
  - Reports ops/sec for encryption and the full encrypt/sign/verify/decrypt pipeline.

## Notes
- Keys are intentionally exportable to move them between client/storage; encrypt them at rest according to your threat model.
- AES-GCM already authenticates ciphertext/IV; ECDSA signatures add an explicit ownership check for multi-party flows.

## License
MIT
