/**
 * The github-broker's canonical query form for its token route. This is an
 * app rule, not part of http-authz/v1 (the profile compares the raw query
 * byte for byte): the broker accepts only this form, so each scope has one
 * query string and an exact-query policy cannot be sidestepped by reordering.
 * Must match src/github-broker/src/query.rs; both run the vectors in
 * src/github-broker/testdata/scope-query.json.
 */
import { type Bytes, te } from "./encoding.ts";

const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

export function percentEncode(bytes: Bytes): string {
  let out = "";
  for (const b of bytes) {
    const c = String.fromCharCode(b);
    out += UNRESERVED.test(c) ? c : "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

/** Decode %XX escapes only; `+` is literal. Operates on the string's UTF-8 bytes. */
export function percentDecode(s: string): Bytes {
  const src = te.encode(s);
  const out: number[] = [];
  for (let i = 0; i < src.length; ) {
    if (src[i] === 0x25) {
      const h = String.fromCharCode(src[i + 1] ?? 0, src[i + 2] ?? 0);
      if (!/^[0-9A-Fa-f]{2}$/.test(h)) throw new Error("bad percent-encoding");
      out.push(parseInt(h, 16));
      i += 3;
    } else {
      out.push(src[i]!);
      i += 1;
    }
  }
  return new Uint8Array(out);
}

function cmpBytes(a: Bytes, b: Bytes): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}

function decodedPairs(raw: string): [Bytes, Bytes][] {
  if (raw === "") return [];
  const pairs: [Bytes, Bytes][] = [];
  for (const c of raw.split("&")) {
    if (c === "") throw new Error("empty query component");
    const i = c.indexOf("=");
    const [k, v] = i < 0 ? [c, ""] : [c.slice(0, i), c.slice(i + 1)];
    const kb = percentDecode(k);
    if (kb.length === 0) throw new Error("empty query key");
    pairs.push([kb, percentDecode(v)]);
  }
  pairs.sort((a, b) => cmpBytes(a[0], b[0]) || cmpBytes(a[1], b[1]));
  return pairs;
}

export function canonicalQuery(raw: string): string {
  return decodedPairs(raw)
    .map(([k, v]) => `${percentEncode(k)}=${percentEncode(v)}`)
    .join("&");
}

export function queryPairs(raw: string): [string, string][] {
  const dec = new TextDecoder("utf-8", { fatal: true });
  return decodedPairs(raw).map(([k, v]) => [dec.decode(k), dec.decode(v)]);
}

/**
 * The scope-canonical query for the broker's token endpoint: one
 * `permissions=<name>:<level>` pair per permission and one
 * `repositories=<name>` pair per repository, in canonical order.
 */
export function scopeQuery(repositories: string[], permissions: Record<string, string>): string {
  const pairs = [
    ...Object.entries(permissions).map(([k, l]) => `permissions=${percentEncode(te.encode(`${k}:${l}`))}`),
    ...repositories.map((r) => `repositories=${percentEncode(te.encode(r))}`),
  ];
  return canonicalQuery(pairs.join("&"));
}
