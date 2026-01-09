export class HmacAgent {
    keyPromise;
    constructor(hmacJwk) {
        this.keyPromise = crypto.subtle.importKey("jwk", hmacJwk, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    }
    async sign(value) {
        const key = await this.keyPromise;
        return crypto.subtle.sign("HMAC", key, value);
    }
    async verify(value, signature) {
        const key = await this.keyPromise;
        return crypto.subtle.verify("HMAC", key, signature, value);
    }
}
//# sourceMappingURL=class.js.map