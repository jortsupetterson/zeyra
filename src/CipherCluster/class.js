import { Bytes } from "bytecodec";
import { CipherAgent } from "../CipherAgent/class.js";

export class CipherCluster {
  /** @type {WeakMap<JsonWebKey, WeakRef<CipherAgent>>} */
  static #agents = new WeakMap();

  /**
   * @param {JsonWebKey} symmetricJwk
   * @returns {CipherAgent}
   */
  static #loadAgent(symmetricJwk) {
    const weakRef = CipherCluster.#agents.get(symmetricJwk);
    /** @type {CipherAgent | undefined} */
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new CipherAgent(symmetricJwk);
      CipherCluster.#agents.set(symmetricJwk, new WeakRef(agent));
    }
    return agent;
  }

  /**
   * @param {JsonWebKey} symmetricJwk
   * @param {any} resource
   * @returns {Promise<{ digest: Base64URLString, ciphertext: Base64URLString, iv: Base64URLString }>}
   */
  static async encrypt(symmetricJwk, resource) {
    const agent = CipherCluster.#loadAgent(symmetricJwk);
    const bytes = Bytes.fromJSON(resource);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const compressed = await Bytes.toCompressed(bytes);
    const envelope = await agent.encrypt(compressed);
    return {
      digest: Bytes.toBase64UrlString(digest),
      ciphertext: Bytes.toBase64UrlString(envelope.ciphertext),
      iv: Bytes.toBase64UrlString(envelope.iv),
    };
  }

  /**
   * @param {JsonWebKey} symmetricJwk
   * @param {{ digest: Base64URLString, ciphertext: Base64URLString, iv: Base64URLString }} artifact
   * @returns {Promise<any>}
   */
  static async decrypt(symmetricJwk, artifact) {
    const envelope = {
      ciphertext: Bytes.fromBase64UrlString(artifact.ciphertext),
      iv: Bytes.fromBase64UrlString(artifact.iv),
    };
    const agent = CipherCluster.#loadAgent(symmetricJwk);
    const bytes = await agent.decrypt(envelope);
    const decompressed = await Bytes.fromCompressed(bytes);
    const resource = Bytes.toJSON(decompressed);
    return { digest: artifact.digest, ...resource };
  }
}
