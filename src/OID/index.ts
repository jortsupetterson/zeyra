import { toBase64UrlString, toBufferSource type ByteSource } from "bytecodec";

export type OpaqueIdentifier = Base64URLString;

export async function deriveOID(source: ByteSource): Promise<OpaqueIdentifier> {
const hash = await crypto.subtle.digest("SHA-256", toBufferSource(source)) 
  return toBase64UrlString(hash)
}


export async function generateOID(): Promise<OpaqueIdentifier> {
  return toBase64UrlString(crypto.getRandomValues(new Uint8Array(32)));
}

export function validateOID(id: string): OpaqueIdentifier | false {
    if (typeof id !== "string") return false
    if(id.length !== 43) return false
    return id as OpaqueIdentifier
}