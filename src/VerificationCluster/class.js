import { Bytes } from "bytecodec";
import { VerificationAgent } from "../VerificationAgent/class.js";

export class VerificationCluster {
  /** @type {WeakMap<JsonWebKey, WeakRef<VerificationAgent>>} */
  static #agents = new WeakMap();

  /**
   * @param {JsonWebKey} publicJwk
   * @returns {VerificationAgent}
   */
  static #loadAgent(publicJwk) {
    const weakRef = VerificationCluster.#agents.get(publicJwk);
    /** @type {VerificationAgent | undefined} */
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new VerificationAgent(publicJwk);
      VerificationCluster.#agents.set(publicJwk, new WeakRef(agent));
    }
    return agent;
  }

  /**
   * @param {JsonWebKey} publicJwk
   * @param {any} value
   * @param {Base64URLString} signature
   * @returns {Promise<boolean>}
   */
  static async verify(publicJwk, value, signature) {
    const agent = VerificationCluster.#loadAgent(publicJwk);
    const valueBytes = Bytes.fromJSON(value);
    const signatureBytes = Bytes.fromBase64UrlString(signature);
    return await agent.verify(valueBytes, signatureBytes);
  }
}
