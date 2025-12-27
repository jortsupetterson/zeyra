# Zeyra

Managed WebCrypto helpers for storage-ready AES-GCM + ECDSA keysets, with lightweight agents and weakly cached clusters.

## Features

- AES-GCM 256 encryption/decryption via `CipherAgent`
- ECDSA P-256 signing/verification via `SigningAgent` and `VerificationAgent`
- Managed clusters (`CipherCluster`, `SigningCluster`, `VerificationCluster`) cache agents with WeakRef for large keysets
- `generateKeyset()` produces an exportable JWK bundle you can store or transport
- Storage/transport-ready artifacts with base64url payloads and SHA-256 digests
- Pure WebCrypto, no native add-ons; ships as ESM
- Works with `bytecodec` for UTF-8, compression, and base64url conversions

## Requirements

- Node.js 18+ (global `crypto.subtle`)
- ESM environment (`"type": "module"` in `package.json`)

## Installation

```bash
npm install zeyra
```

## Quickstart (agents)

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

## Managed cluster flow

```js
import {
  generateKeyset,
  CipherCluster,
  SigningCluster,
  VerificationCluster,
} from "zeyra";

const { symmetricJwk, privateJwk, publicJwk } = await generateKeyset();

const resource = { id: "file-123", body: "hello world" };
const artifact = await CipherCluster.encrypt(symmetricJwk, resource);
const signature = await SigningCluster.sign(privateJwk, resource.id);

// VerificationCluster is designed to run on a per-resource server node.
const authorized = await VerificationCluster.verify(
  publicJwk,
  resource.id,
  signature
);

const decrypted = await CipherCluster.decrypt(symmetricJwk, artifact);
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
- `CipherCluster.encrypt(symmetricJwk, resource)`
  - -> `{ digest, ciphertext, iv }` (all base64url strings; digest is SHA-256 of JSON bytes, pre-encryption, useful for version checks)
- `CipherCluster.decrypt(symmetricJwk, artifact)`
  - -> `{ digest, ...resource }` (resource object restored from compressed JSON)
- `SigningCluster.sign(privateJwk, value)` -> `Base64URLString`
- `VerificationCluster.verify(publicJwk, value, signature)` -> `boolean`

See the implementations in `src/index.js` and friends for details.

## Testing and benchmarks

- Run tests: `npm test` (uses Node's built-in `node:test` runner against `test.js`)
- Run microbenchmarks (skipped by default): `npm run bench`
  - Pass iterations: `npm run bench -- --iterations=500`
  - Reports ops/sec for encryption and the full encrypt/sign/verify/decrypt pipeline.

## Notes

- CipherCluster assumes one unique random key per resource (no derivations or shared usage).
- Cluster classes are intended for client-side usage; `VerificationCluster`/`VerificationAgent` can be hosted per-resource to pre-verify access before downstream identity or ACL checks.
- Cluster serialization uses JSON and adds a `digest` field; avoid using `digest` in resource objects.
- WeakRef caching keeps memory usage loose and GC-friendly by design.

## License

MIT
