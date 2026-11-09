import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { exportJWK, calculateJwkThumbprint } from "jose";
import { exportPolicy } from "../admin/src/appkey.ts";
import { callBroker } from "../client/src/broker.ts";
import { sha256b64url } from "../lib/encoding.ts";
import { canonicalQuery, scopeQuery } from "../lib/canonical.ts";
import { isDigest, sha256Digest } from "../lib/digest.ts";
import { checkHeaderNames, headerDigest, headerValue } from "../lib/headers.ts";
import { generateRecipient } from "../lib/hpke.ts";

const readJson = (f: string) => JSON.parse(fs.readFileSync(path.join(import.meta.dir, f.startsWith("../") ? "" : "../src", f), "utf8"));
const digestVectors = readJson("../testdata/digests.json");
const scopeVectors = readJson("github-broker/testdata/scope-query.json");

describe("shared digest vectors", () => {
  for (const c of digestVectors.body) test(`body: ${c.name}`, async () => expect(await sha256Digest(c.body)).toBe(c.digest));
  for (const c of digestVectors.format) test(`format: ${c.name}`, () => expect(isDigest(c.value)).toBe(c.ok));
});

describe("shared header-binding vectors", () => {
  for (const c of digestVectors.headers) {
    test(c.name, async () => {
      if (c.value === undefined) {
        expect(() => headerValue(c.header, c.received)).toThrow();
      } else {
        expect(headerValue(c.header, c.received)).toBe(c.value);
        expect(await headerDigest(c.header, c.received)).toBe(c.digest);
      }
    });
  }
  for (const c of digestVectors.header_names) {
    test(`names: ${c.name}`, () => {
      if (c.ok) expect(() => checkHeaderNames(c.names)).not.toThrow();
      else expect(() => checkHeaderNames(c.names)).toThrow();
    });
  }
  test("fetch-style names are matched without case", () => expect(headerValue("accept", [["Accept", "a"]])).toBe("a"));
});

describe("broker scope query vectors", () => {
  for (const c of scopeVectors.query) {
    test(`query ${JSON.stringify(c.raw)}`, () => {
      if (c.canonical === undefined) expect(() => canonicalQuery(c.raw)).toThrow();
      else expect(canonicalQuery(c.raw)).toBe(c.canonical);
    });
  }
  test("repeated keys in canonical order", () => {
    expect(scopeQuery(["frontend", "backend"], { pull_requests: "write", contents: "read" })).toBe(
      "permissions=contents%3Aread&permissions=pull_requests%3Awrite&repositories=backend&repositories=frontend",
    );
  });
});

describe("keys", () => {
  test("RFC 7638 thumbprint matches jose", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])) as CryptoKeyPair;
    const jwk = await exportJWK(kp.publicKey);
    expect(await sha256b64url(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`)).toBe(await calculateJwkThumbprint(jwk, "sha256"));
    // A fixed RFC 7638 vector, also used by the Rust verifier.
    expect(await calculateJwkThumbprint({ kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" }, "sha256")).toBe(
      "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U",
    );
  });
});

describe("token delivery HPKE", () => {
  test("seal/open round trip, aad = tk_body_digest", async () => {
    const { DELIVERY_INFO, open, seal } = await import("../lib/hpke.ts");
    const r = await generateRecipient();
    const aad = new TextEncoder().encode(await sha256Digest("a"));
    const { enc, ct } = await seal(r.publicKey, new TextEncoder().encode("ghs_x"), DELIVERY_INFO, aad);
    expect(new TextDecoder().decode(await open(r, enc, ct, DELIVERY_INFO, aad))).toBe("ghs_x");
    await expect(open(r, enc, ct, DELIVERY_INFO, new TextEncoder().encode(await sha256Digest("b")))).rejects.toThrow();
  });
});

describe("export policy", () => {
  const fp = "SHA256:" + "A".repeat(43) + "=";
  test("names one user and one key fingerprint", () => {
    const p = exportPolicy("user-1", fp);
    expect(p.consensus).toContain("user-1");
    expect(p.condition).toContain(`secret.static_properties['github:key_sha256'] == '${fp}'`);
  });
  test("rejects a malformed fingerprint", () => {
    expect(() => exportPolicy("user-1", "x' || true || '")).toThrow();
  });
});

describe("callBroker", () => {
  test("sends one content-type even when the request binds one", async () => {
    const real = globalThis.fetch;
    let seen: Headers | undefined;
    globalThis.fetch = (async (_u: unknown, init: RequestInit) => {
      seen = new Headers(init.headers);
      return new Response("{}");
    }) as typeof fetch;
    try {
      const r = { method: "POST", path: "/p", query: "", headers: { "content-type": "application/json" }, body: new Uint8Array() } as any;
      await callBroker("http://x", r, "jwt");
      expect(seen?.get("content-type")).toBe("application/json");
      expect(seen?.get("authorization")).toBe("Bearer jwt");
    } finally {
      globalThis.fetch = real;
    }
  });
});
