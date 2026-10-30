/**
 * http-authz/v1 header binding. Must match
 * the `turnkey_jwt_profiles` crate (`http_authz::headers`); both run the
 * `headers` and `header_names` vectors in testdata/digests.json.
 *
 * `header_names`: lowercase tokens, unique, in any order, at most 32, never
 * `authorization`. `header_digest[i]`: the digest of the value of
 * `header_names[i]`: every field line for that name in order, trimmed of
 * spaces and tabs, joined with `", "`. A bound header that is absent fails.
 */
import { sha256Digest } from "./digest.ts";

export const MAX_HEADER_NAMES = 32;
/** Never bound. HTTP/2 pseudo-headers (leading `:`) are also refused. */
export const FORBIDDEN_HEADER_NAMES = [
  "authorization",
  "connection",
  "host",
  "keep-alive",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];
/** RFC 9110 tchar symbols, escaped for a regex character class. */
export const TCHAR_SYMBOLS = "!#$%&'*+\\-.^_`|~";
const TOKEN = new RegExp(`^[${TCHAR_SYMBOLS}0-9a-z]+$`);
const VALUE = /^[\t\x20-\x7e]*$/;

export function checkHeaderNames(names: string[]): void {
  if (names.length > MAX_HEADER_NAMES) throw new Error(`at most ${MAX_HEADER_NAMES} header names`);
  names.forEach((n, i) => {
    if (n.startsWith(":") || FORBIDDEN_HEADER_NAMES.includes(n)) throw new Error(`header ${JSON.stringify(n)} must not be bound`);
    if (!TOKEN.test(n)) throw new Error(`header name ${JSON.stringify(n)} is not a lowercase token`);
    if (names.indexOf(n) !== i) throw new Error(`header name ${JSON.stringify(n)} is repeated`);
  });
}

/**
 * The normalized value of header `name` over the fields as sent or received,
 * in order. Names in `fields` are compared without case.
 */
export function headerValue(name: string, fields: [string, string][]): string {
  const lines: string[] = [];
  for (const [rawName, value] of fields) {
    if (rawName.toLowerCase() !== name) continue;
    if (!VALUE.test(value)) throw new Error(`header ${name} has a byte outside visible ASCII, space, and tab`);
    lines.push(value.replace(/^[ \t]+|[ \t]+$/g, ""));
  }
  if (lines.length === 0) throw new Error(`bound header ${name} is absent`);
  return lines.join(", ");
}

export function headerDigest(name: string, fields: [string, string][]): Promise<string> {
  return sha256Digest(headerValue(name, fields));
}

/** One digest per name, in order. */
export function headerDigests(names: string[], fields: [string, string][]): Promise<string[]> {
  checkHeaderNames(names);
  return Promise.all(names.map((n) => headerDigest(n, fields)));
}
