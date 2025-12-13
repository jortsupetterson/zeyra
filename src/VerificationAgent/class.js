export class VerificationAgent {
  /**
   * @param {JsonWebKey} publicJwk // ECDSA P-256 public key
   */
  constructor(publicJwk) {
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  }

  /**
   * @param {Uint8Array} bytes
   * @param {ArrayBuffer} signature
   * @returns {Promise<boolean>}
   */
  async verify(bytes, signature) {
    const key = await this.keyPromise;
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signature,
      bytes
    );
  }
}
