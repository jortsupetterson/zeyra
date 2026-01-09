export class HmacAgent {
  private keyPromise: Promise<CryptoKey>;

  constructor(hmacJwk: JsonWebKey) {
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      hmacJwk,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  }

  async sign(value: BufferSource): Promise<ArrayBuffer> {
    const key = await this.keyPromise;
    return crypto.subtle.sign("HMAC", key, value);
  }

  async verify(value: BufferSource, signature: BufferSource): Promise<boolean> {
    const key = await this.keyPromise;
    return crypto.subtle.verify("HMAC", key, signature, value);
  }
}
