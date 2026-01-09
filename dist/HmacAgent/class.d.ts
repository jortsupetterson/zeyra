export declare class HmacAgent {
    private keyPromise;
    constructor(hmacJwk: JsonWebKey);
    sign(value: BufferSource): Promise<ArrayBuffer>;
    verify(value: BufferSource, signature: BufferSource): Promise<boolean>;
}
//# sourceMappingURL=class.d.ts.map