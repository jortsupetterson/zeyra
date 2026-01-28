[![npm version](https://img.shields.io/npm/v/@z-base/cryptosuite)](https://www.npmjs.com/package/@z-base/cryptosuite)
[![CI](https://github.com/z-base/cryptosuite/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/z-base/cryptosuite/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/z-base/cryptosuite/branch/master/graph/badge.svg)](https://codecov.io/gh/z-base/cryptosuite)
[![license](https://img.shields.io/npm/l/@z-base/cryptosuite)](LICENSE)

# cryptosuite

Developer-experience-first cryptography toolkit that lets you powerfully express cryptographic intentions through a semantic and declarative API surface.

## Compatibility

- Runtimes: Modern JavaScript hosts with WebCrypto.
- Module format: ESM-only (no CJS build).
- Required globals / APIs: `crypto`, `crypto.subtle`, `crypto.getRandomValues`.
- TypeScript: bundled types.

## Goals

- Consistent JWK validation for AES-GCM, HMAC, Ed25519, and RSA-OAEP.
- Byte-oriented APIs (`Uint8Array` and `ArrayBuffer`) to avoid ambiguous inputs.
- No side effects on import; all work happens per call.
- Clean separation between agents (stateful) and clusters (cached).
- Minimal, but strict WebCrypto wrappers with explicit `CryptosuiteError` codes.

## Installation

```sh
npm install @z-base/cryptosuite
# or
pnpm add @z-base/cryptosuite
# or
yarn add @z-base/cryptosuite
```

## Usage

### Cryptosuite wrapper

```ts
import { Cryptosuite } from '@z-base/cryptosuite'
// The `Cryptosuite` convenience class wraps classes and functions into an intuitive structure.
const cipherJwk = await Cryptosuite.cipher.generateKey()
const payload = new Uint8Array([1, 2, 3])
const artifact = await Cryptosuite.cipher.encrypt(cipherJwk, payload)
const roundtrip = await Cryptosuite.cipher.decrypt(cipherJwk, artifact)
```

### OpaqueIdentifier

```ts
import {
  deriveOID,
  generateOID,
  validateOID,
  type OpaqueIdentifier,
} from '@z-base/cryptosuite'

const oid = await generateOID() // 43 random base64url chars
const derived = await deriveOID(idBytesFromSomewhere) // 43 deterministic base64url chars
const valid = validateOID(uncontrolledOID) // 43 base64url chars | false
if (!valid) return
```

### Cipher

```ts
import { fromJSON, toJSON } from '@z-base/bytecodec'
import {
  deriveCipherKey,
  CipherCluster,
  CipherAgent,
  type CipherJWK,
} from '@z-base/cryptosuite'

const cipherJwk = await deriveCipherKey(deterministicBytes)

const state = { name: 'Bob', email: 'bob@email.com' }
const enc = await CipherCluster.encrypt(cipherJwk, fromJSON(state)) // {iv, ciphertext}
const dec = await CipherCluster.decrypt(cipherJwk, enc)

const restored = toJSON(dec)
console.log(restored.name) // "Bob"
```

### Exchange

```ts
import { fromString, toString } from '@z-base/bytecodec'
import {
  generateCipherKey,
  generateExchangePair,
  ExchangeCluster,
  WrapAgent,
  type WrapJWK,
  UnwrapAgent,
  type UnwrapJWK,
  CipherAgent,
  type CipherJWK,
} from '@z-base/cryptosuite'

const { wrapJwk, unwrapJwk } = await generateExchangePair()
const encryptJwk = await generateCipherKey()
const encryptAgent = new CipherAgent(encryptJwk)
const body = await encryptAgent.encrypt(fromString('Hello world!')) // {iv, ciphertext}
const header = await ExchangeCluster.wrap(wrapJwk, encryptJwk) // ArrayBuffer
const message = { header, body }
const decryptJwk = (await ExchangeCluster.unwrap(
  unwrapJwk,
  message.header
)) as CipherJWK
const decryptAgent = new CipherAgent(decryptJwk)
const decryptedBody = await decryptAgent.decrypt(message.body)
const messageText = toString(decryptedBody) // "Hello world!"
```

### HMAC

```ts
import { fromString } from '@z-base/bytecodec'
import {
  generateHMACKey,
  HMACCluster,
  HMACAgent,
  type HMACJWK,
} from '@z-base/cryptosuite'

const hmacJwk = await generateHMACKey()

const challenge = crypto.getRandomValues(new Uint8Array(32))
const sig = await HMACCluster.sign(hmacJwk, challenge) // ArrayBuffer
const ok = await HMACCluster.verify(hmacJwk, challenge, sig) // true | false
```

### Verification

```ts
import {
  generateVerificationPair,
  VerificationCluster,
  SignAgent,
  type SignJWK,
  VerifyAgent,
  type VerifyJWK,
} from '@z-base/cryptosuite'

const { signJwk, verifyJwk } = await generateVerificationPair()
const payload = new Uint8Array([9, 8, 7])
const sig = await VerificationCluster.sign(signJwk, payload) // ArrayBuffer
const ok = await VerificationCluster.verify(verifyJwk, payload, sig) // true | false
```

## Runtime behavior

### Node

Uses Node's global WebCrypto (`globalThis.crypto`) when available. Node is not the primary target, but tests and benchmarks run on Node 18+.

### Browsers / Edge runtimes

Uses `crypto.subtle` and `crypto.getRandomValues`. Ed25519 and RSA-OAEP support vary by engine; unsupported operations throw `CryptosuiteError` codes.

### Validation & errors

Validation failures throw `CryptosuiteError` with a `code` string (for example `AES_GCM_KEY_EXPECTED`, `RSA_OAEP_UNSUPPORTED`, `ED25519_ALG_INVALID`). Cryptographic failures (e.g., decrypt with the wrong key) bubble the underlying WebCrypto error.

### Security considerations

- Keep `{iv, ciphertext}` together and never mix IVs across messages or keys.
- Treat all JWKs and raw key bytes as secrets; never log them and rotate on exposure.
- Always sign a canonical byte serialization so verifiers see identical bytes.
- Ciphertext length leaks; add padding at your protocol layer if size is sensitive.
- Handle decrypt/verify failures uniformly; don't leak which check failed.

## Tests

Suite: unit + integration (Node), E2E (Playwright)
Matrix: Chromium / Firefox / WebKit + mobile emulation (Pixel 5, iPhone 12)
Coverage: c8 — 100% statements/branches/functions/lines (Node)

## Benchmarks

How it was run: `node benchmark/bench.js`
Environment: Node v22.14.0 (win32 x64)
Results:

| Benchmark            | Result                    |
| -------------------- | ------------------------- |
| AES-GCM encrypt      | 30.41ms (6575.9 ops/sec)  |
| HMAC sign+verify     | 29.95ms (6678.1 ops/sec)  |
| Ed25519 sign+verify  | 76.45ms (2616.0 ops/sec)  |
| RSA-OAEP wrap+unwrap | 1224.07ms (163.4 ops/sec) |

Results vary by machine.

## License

MIT
