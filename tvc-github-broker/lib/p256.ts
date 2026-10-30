/**
 * P-256 helpers on WebCrypto: key generation in Turnkey API-key file format,
 * compressed and uncompressed points, and DER/raw ECDSA signature conversion.
 */
import { type Bytes, b64url, concat, fromB64url, fromHex, hex } from "./encoding.ts";

/** P-256 group order. */
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export type ApiKeyFile = { publicKey: string; privateKey: string };

export function bytesToBig(b: Bytes): bigint {
  return BigInt("0x" + (hex(b) || "0"));
}

export function bigToBytes(n: bigint, len = 32): Bytes {
  return fromHex(n.toString(16).padStart(len * 2, "0"));
}

export function compressPoint(x: Bytes, y: Bytes): Bytes {
  return concat(new Uint8Array([0x02 | (y[31]! & 1)]), x);
}

/** Generate a P-256 key in Turnkey API-key file format (hex scalar, compressed public key). */
export async function generateApiKey(): Promise<ApiKeyFile & { jwk: JsonWebKey }> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const x = fromB64url(jwk.x!);
  const y = fromB64url(jwk.y!);
  return {
    publicKey: hex(compressPoint(x, y)),
    privateKey: hex(fromB64url(jwk.d!)),
    jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
  };
}

/** Import a public JWK for ECDSA verification. */
export function importVerifyKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

/** Uncompressed SEC1 point for a public JWK. */
export function jwkToUncompressed(jwk: JsonWebKey): Bytes {
  return concat(new Uint8Array([4]), fromB64url(jwk.x!), fromB64url(jwk.y!));
}

/** Raw r||s to DER, with s normalized to low-S (some verifiers require it). */
export function rawToDer(raw: Bytes): Bytes {
  let s = bytesToBig(raw.slice(32));
  if (s > N / 2n) s = N - s;
  const int = (b: Bytes) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const body = concat(int(raw.slice(0, 32)), int(bigToBytes(s)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

/** DER to raw r||s. */
export function derToRaw(der: Bytes): Bytes {
  if (der[0] !== 0x30 || der[1] !== der.length - 2) throw new Error("bad DER signature");
  let o = 2;
  const read = () => {
    if (der[o] !== 0x02) throw new Error("bad DER integer");
    const len = der[o + 1]!;
    const v = der.slice(o + 2, o + 2 + len);
    o += 2 + len;
    const n = bytesToBig(v);
    if (n >= 1n << 256n) throw new Error("DER integer too large");
    return bigToBytes(n);
  };
  const r = read();
  const s = read();
  if (o !== der.length) throw new Error("trailing DER bytes");
  return concat(r, s);
}

/** ECDSA P-256 SHA-256 signature, DER-encoded, low-S. */
export async function signDer(key: CryptoKey, data: Bytes): Promise<Bytes> {
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data));
  return rawToDer(raw);
}

export async function verifyDer(key: CryptoKey, der: Bytes, data: Bytes): Promise<boolean> {
  try {
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(der), data);
  } catch {
    return false;
  }
}

export { b64url };
