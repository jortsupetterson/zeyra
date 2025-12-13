export class CipherAgent {
  /**
   * @param {JsonWebKey} symmetricJwk  // AES-GCM (kty:"oct", alg:"A256GCM")
   */
  constructor(symmetricJwk) {
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      symmetricJwk,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * @param {Uint8Array} plaintext
   * @returns {Promise<{ iv: Uint8Array, ciphertext: ArrayBuffer }>}
   */
  async encrypt(plaintext) {
    const key = await this.keyPromise;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      plaintext
    );
    return { iv, ciphertext };
  }

  /**
   * @param {{ iv: Uint8Array, ciphertext: ArrayBuffer }} payload
   * @returns {Promise<Uint8Array>}
   */
  async decrypt({ iv, ciphertext }) {
    const key = await this.keyPromise;
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    return new Uint8Array(plaintext);
  }
}
