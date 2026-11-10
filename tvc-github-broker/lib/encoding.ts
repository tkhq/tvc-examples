/** ArrayBuffer-backed bytes. */
export type Bytes = Uint8Array<ArrayBuffer>;

/** Byte and encoding helpers shared by the client, admin tool, and tests. */

export const te = new TextEncoder();
export const td = new TextDecoder();

export function b64url(bytes: Bytes | string): string {
  const b = typeof bytes === "string" ? te.encode(bytes) : bytes;
  return Buffer.from(b).toString("base64url");
}

/** Strict unpadded base64url decode. */
export function fromB64url(s: string): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url");
  const out = new Uint8Array(Buffer.from(s, "base64url"));
  if (b64url(out) !== s) throw new Error("non-canonical base64url");
  return out;
}

export function hex(bytes: Bytes): string {
  return Buffer.from(bytes).toString("hex");
}

export async function sha256(data: Bytes | string): Promise<Bytes> {
  const b = typeof data === "string" ? te.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}

/** Unpadded base64url SHA-256. */
export async function sha256b64url(data: Bytes | string): Promise<string> {
  return b64url(await sha256(data));
}
