/**
 * http-authz/v1 digest format. Must match
 * the `turnkey_jwt_profiles` crate (`rfc9530`); both run the vectors in
 * testdata/digests.json.
 *
 * A digest is exactly one RFC 9530 dictionary member, `sha-256=:<b64>:`, with
 * standard padded base64 (44 characters). No other algorithm, no parameters,
 * no whitespace, no second member. The body digest equals a valid
 * `Content-Digest` value for the body bytes as sent.
 */
import { type Bytes, sha256 } from "./encoding.ts";

const DIGEST = /^sha-256=:([A-Za-z0-9+/]{43}=):$/;

export async function sha256Digest(data: Bytes | string): Promise<string> {
  return `sha-256=:${Buffer.from(await sha256(data)).toString("base64")}:`;
}

export function isDigest(s: string): boolean {
  const m = DIGEST.exec(s);
  if (!m) return false;
  const raw = Buffer.from(m[1]!, "base64");
  return raw.toString("base64") === m[1];
}
