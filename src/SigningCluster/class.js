import { Bytes } from "bytecodec";
import { SigningAgent } from "../SigningAgent/class.js";

export class SigningCluster {
  /** @type {WeakMap<JsonWebKey, WeakRef<SigningAgent>>} */
  static #agents = new WeakMap();

  /**
   * @param {JsonWebKey} privateJwk
   * @returns {SigningAgent}
   */
  static #loadAgent(privateJwk) {
    const weakRef = SigningCluster.#agents.get(privateJwk);
    /** @type {SigningAgent | undefined} */
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new SigningAgent(privateJwk);
      SigningCluster.#agents.set(privateJwk, new WeakRef(agent));
    }
    return agent;
  }

  /**
   * @param {JsonWebKey} privateJwk
   * @param {any} value
   * @returns {Promise<Base64URLString>}
   */
  static async sign(privateJwk, value) {
    const agent = SigningCluster.#loadAgent(privateJwk);
    const bytes = Bytes.fromJSON(value);
    const signature = await agent.sign(bytes);
    return Bytes.toBase64UrlString(signature);
  }
}
