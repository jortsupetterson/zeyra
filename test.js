import assert from "node:assert/strict";
import test from "node:test";
import { performance } from "node:perf_hooks";
import { Bytes } from "bytecodec";
import {
  generateKeyset,
  SigningAgent,
  VerificationAgent,
  CipherAgent,
  CipherCluster,
  SigningCluster,
  VerificationCluster,
} from "./src/index.js";

const PLAINTEXT = "mustan kissan paksut posket";
const plainBytes = Bytes.fromString(PLAINTEXT);

const keyset = await generateKeyset();

test("generateKeyset produces AES-GCM and ECDSA keys", () => {
  assert.equal(keyset.symmetricJwk.kty, "oct");
  assert.equal(keyset.publicJwk.kty, "EC");
  assert.equal(keyset.privateJwk.kty, "EC");
  assert.ok(keyset.symmetricJwk.k, "AES key material missing");
});

test("encrypt/decrypt round trip", async () => {
  const cipherAgent = new CipherAgent(keyset.symmetricJwk);
  const encrypted = await cipherAgent.encrypt(plainBytes);
  const decrypted = await cipherAgent.decrypt(encrypted);
  assert.equal(Bytes.toString(decrypted), PLAINTEXT);
});

test("sign/verify ciphertext integrity", async () => {
  const cipherAgent = new CipherAgent(keyset.symmetricJwk);
  const signingAgent = new SigningAgent(keyset.privateJwk);
  const verificationAgent = new VerificationAgent(keyset.publicJwk);

  const payload = await cipherAgent.encrypt(plainBytes);
  const signature = await signingAgent.sign(payload.ciphertext);

  const authorized = await verificationAgent.verify(
    payload.ciphertext,
    signature
  );
  assert.equal(authorized, true);

  const tampered = new Uint8Array(payload.ciphertext.slice(0));
  tampered[0] ^= 1;
  const shouldFail = await verificationAgent.verify(tampered, signature);
  assert.equal(shouldFail, false);

  const decrypted = await cipherAgent.decrypt(payload);
  assert.equal(Bytes.toString(decrypted), PLAINTEXT);
});

test("CipherCluster encrypt/decrypt round trip", async () => {
  const resource = {
    id: "resource-1",
    kind: "note",
    body: PLAINTEXT,
    count: 3,
  };
  const artifact = await CipherCluster.encrypt(keyset.symmetricJwk, resource);
  assert.equal(typeof artifact.ciphertext, "string");
  assert.equal(typeof artifact.iv, "string");
  assert.equal(typeof artifact.digest, "string");

  const expectedDigest = Bytes.toBase64UrlString(
    await crypto.subtle.digest("SHA-256", Bytes.fromJSON(resource))
  );
  assert.equal(artifact.digest, expectedDigest);

  const decrypted = await CipherCluster.decrypt(keyset.symmetricJwk, artifact);
  assert.equal(decrypted.digest, artifact.digest);
  assert.equal(decrypted.id, resource.id);
  assert.equal(decrypted.kind, resource.kind);
  assert.equal(decrypted.body, resource.body);
  assert.equal(decrypted.count, resource.count);
});

test("SigningCluster/VerificationCluster sign and verify JSON values", async () => {
  const value = { id: "resource-1", action: "read", nonce: 1 };
  const signature = await SigningCluster.sign(keyset.privateJwk, value);
  assert.equal(typeof signature, "string");

  const authorized = await VerificationCluster.verify(
    keyset.publicJwk,
    value,
    signature
  );
  assert.equal(authorized, true);

  const tampered = { ...value, nonce: 2 };
  const shouldFail = await VerificationCluster.verify(
    keyset.publicJwk,
    tampered,
    signature
  );
  assert.equal(shouldFail, false);
});

function formatOps(durationMs, iterations) {
  const opsPerSec = iterations / (durationMs / 1000);
  return `${durationMs.toFixed(2)}ms (${opsPerSec.toFixed(1)} ops/sec)`;
}

async function runBenchmark(iterations = 200) {
  const cipherAgent = new CipherAgent(keyset.symmetricJwk);
  const signingAgent = new SigningAgent(keyset.privateJwk);
  const verificationAgent = new VerificationAgent(keyset.publicJwk);

  const encryptStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    await cipherAgent.encrypt(plainBytes);
  }
  const encryptDuration = performance.now() - encryptStart;

  const fullStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    const payload = await cipherAgent.encrypt(plainBytes);
    const signature = await signingAgent.sign(payload.ciphertext);
    await verificationAgent.verify(payload.ciphertext, signature);
    await cipherAgent.decrypt(payload);
  }
  const fullDuration = performance.now() - fullStart;

  return {
    encryptDuration,
    fullDuration,
    iterations,
  };
}

const shouldBenchmark =
  process.env.BENCHMARK === "1" ||
  process.env.BENCHMARK?.toLowerCase() === "true" ||
  process.argv.includes("--bench");

const iterationsFlag = process.argv
  .find((arg) => arg.startsWith("--iterations="))
  ?.split("=")[1];

const parsedIterations = iterationsFlag ? Number(iterationsFlag) : undefined;
const benchmarkIterations =
  Number.isFinite(parsedIterations) && parsedIterations > 0
    ? parsedIterations
    : 200;

test(
  "benchmark encrypt/sign/verify/decrypt",
  { skip: !shouldBenchmark },
  async (t) => {
    const { encryptDuration, fullDuration, iterations } = await runBenchmark(
      benchmarkIterations
    );
    t.diagnostic(`encrypt only: ${formatOps(encryptDuration, iterations)}`);
    t.diagnostic(`full pipeline: ${formatOps(fullDuration, iterations)}`);
  }
);
