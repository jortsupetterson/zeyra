import { Bytes } from "bytecodec";
import { HmacAgent } from "../HmacAgent/class.js";

export class HmacCluster {
  static #agents = new WeakMap<JsonWebKey, WeakRef<HmacAgent>>();

  static #loadAgent(hmacJwk: JsonWebKey): HmacAgent {
    const weakRef = HmacCluster.#agents.get(hmacJwk);
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new HmacAgent(hmacJwk);
      HmacCluster.#agents.set(hmacJwk, new WeakRef(agent));
    }
    return agent;
  }

  static async sign(hmacJwk: JsonWebKey, value: any): Promise<ArrayBuffer> {
    const agent = HmacCluster.#loadAgent(hmacJwk);
    const bytes = Bytes.toBufferSource(Bytes.fromJSON(value));
    return await agent.sign(bytes);
  }

  static async verify(
    hmacJwk: JsonWebKey,
    value: any,
    signature: ArrayBuffer
  ): Promise<boolean> {
    const agent = HmacCluster.#loadAgent(hmacJwk);
    const bytes = Bytes.toBufferSource(Bytes.fromJSON(value));
    return await agent.verify(bytes, signature);
  }
}
