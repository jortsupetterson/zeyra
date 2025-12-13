export class SigningAgent {
  /**
   * @param {JsonWebKey} privateJwk // ECDSA P-256 private key
   */
  constructor(privateJwk) {
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      privateJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
  }

  /**
   * @param {Uint8Array} bytes
   * @returns {Promise<ArrayBuffer>}
   */
  async sign(bytes) {
    const key = await this.keyPromise;
    return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, bytes);
  }
}
