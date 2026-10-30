import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { exportJWK, importJWK, jwtVerify, calculateJwkThumbprint } from "jose";
import { canonicalQuery, scopeQuery } from "../lib/canonical.ts";
import { isDigest, sha256Digest } from "../lib/digest.ts";
import type { HttpAuthzV1 } from "../lib/mint.ts";
import { checkHeaderNames, headerDigest, headerValue } from "../lib/headers.ts";
import { derToRaw, rawToDer } from "../lib/p256.ts";
import { generateRecipient, turnkeyOpen, turnkeySeal } from "../lib/hpke.ts";
import { evaluate, mintValues } from "../shim/src/policy.ts";
import { buildClaims, IntentError, validateIntent, type MintJwtIntent } from "../shim/src/profile.ts";
import { examplePolicy, futureQuerySubsetPolicy, thumbprint, USER_IDS } from "../shim/src/state.ts";

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
    expect(await thumbprint(jwk)).toBe(await calculateJwkThumbprint(jwk, "sha256"));
    // A fixed RFC 7638 vector, also used by the Rust verifier.
    expect(await calculateJwkThumbprint({ kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" }, "sha256")).toBe(
      "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U",
    );
  });

  test("DER round trip normalizes to low-S and still verifies", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const msg = new TextEncoder().encode("hello");
    for (let i = 0; i < 16; i++) {
      const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, msg));
      const back = derToRaw(rawToDer(raw));
      expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, kp.publicKey, back, msg)).toBe(true);
    }
  });

  test("shim-minted ES256 JWTs verify with jose", async () => {
    const { startShim } = await import("../shim/src/server.ts");
    const { initState, DEMO_PARENT_ORG_ID } = await import("../shim/src/state.ts");
    const os = await import("node:os");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shim-unit-"));
    await initState({ dir, audience: "https://broker.example" });
    const shim = await startShim({ stateDir: dir, log: () => {} });
    try {
      const { mintJwt, readKeyFile, whoami } = await import("../client/src/turnkey.ts");
      const key = readKeyFile(path.join(dir, "keys/alice.json"));
      const organizationId = shim.state.org.organizationId;
      expect(await whoami(shim.url, key, organizationId)).toBe(USER_IDS.alice);
      const body = await sha256Digest("{}");
      const httpAuthzV1 = {
        method: "POST",
        path: "/v1/installations/12345/tokens",
        query: "permissions=contents%3Aread&repositories=demo",
        headerNames: [],
        headerDigest: [],
        bodyDigest: body,
        subject: USER_IDS.alice,
        timeToLiveSeconds: "300",
        issuedAt: String(Math.floor(Date.now() / 1000)),
      };
      const jwk = await importJWK(shim.state.jwks.keys[0]!, "ES256");
      const mint = (intent: HttpAuthzV1) => mintJwt(shim.url, key, { organizationId, audience: "https://broker.example", httpAuthzV1: intent });
      const mintAndVerify = async (intent: HttpAuthzV1) => {
        const m = await mint(intent);
        if (!m.ok) throw new Error(m.message);
        return jwtVerify(m.jwt, jwk, {
          algorithms: ["ES256"],
          typ: "application/vnd.turnkey.http-authz-v1+jwt",
          audience: "https://broker.example",
          issuer: `https://id.turnkey.com/t/${DEMO_PARENT_ORG_ID}`,
          maxTokenAge: 300,
        });
      };
      const { payload, protectedHeader } = await mintAndVerify(httpAuthzV1);
      expect(Object.keys(protectedHeader).sort()).toEqual(["alg", "kid", "typ"]);
      expect(protectedHeader.kid).toBe(shim.state.mintKid);
      expect(payload.sub).toBe(`urn:turnkey:user:${USER_IDS.alice}`);
      expect(payload.org).toBe(`urn:turnkey:org:${organizationId}`);
      expect(payload.iat).toBe(Number(httpAuthzV1.issuedAt));
      expect(payload.exp! - payload.iat!).toBe(300);
      expect(payload.jti).toBeUndefined();
      expect(payload.tk_body_digest).toBe(body);
      expect(payload.tk_header_digest).toBeUndefined();
      expect(payload.tk_request).toEqual({ method: "POST", path: httpAuthzV1.path, query: httpAuthzV1.query });
      const unbound = (await mintAndVerify({ ...httpAuthzV1, bodyDigest: "" })).payload;
      expect(Object.keys(unbound).sort()).toEqual(["aud", "exp", "iat", "iss", "org", "sub", "tk_request"]);
      expect(unbound.aud).toBe("https://broker.example");
      expect(unbound.exp! - unbound.iat!).toBe(300);
      expect(unbound.tk_body_digest).toBeUndefined();
      expect(unbound.tk_request).toEqual({ method: "POST", path: httpAuthzV1.path, query: httpAuthzV1.query });
      const boundDigests = [body, await sha256Digest("")];
      const bound = (await mintAndVerify({ ...httpAuthzV1, headerNames: ["x-b", "accept"], headerDigest: boundDigests })).payload;
      expect((bound.tk_request as { headers?: string[] }).headers).toEqual(["x-b", "accept"]);
      expect(bound.tk_header_digest).toEqual(boundDigests);
      expect(bound.tk_body_digest).toBe(body);
      expect(await mint({ ...httpAuthzV1, query: "a=%ZZ" })).toMatchObject({ ok: false, status: 400 });
      expect(await mint({ ...httpAuthzV1, query: "constructor=x" })).toMatchObject({ ok: true });
      const headerNames = Array.from({ length: 33 }, (_, i) => `x-${i}`);
      expect(await mint({ ...httpAuthzV1, headerNames, headerDigest: headerNames.map(() => body) })).toMatchObject({ ok: false, status: 400 });
    } finally {
      shim.stop();
      fs.rmSync(dir, { recursive: true });
    }
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

describe("Turnkey enclave-encrypt HPKE", () => {
  test("seal/open round trip, aad bound to the recipient", async () => {
    const r = await generateRecipient();
    const other = await generateRecipient();
    const { enc, ct } = await turnkeySeal(r.publicKey, new TextEncoder().encode("pem"));
    expect(new TextDecoder().decode(await turnkeyOpen(r, enc, ct))).toBe("pem");
    expect(turnkeyOpen(other, enc, ct)).rejects.toThrow();
  });
});

const NOW = 1_800_000_000;
const digest = await sha256Digest("x");
const base: MintJwtIntent = {
  profile: "JWT_PROFILE_HTTP_AUTHZ_V1",
  audience: "https://broker.example",
  httpAuthzV1: {
    method: "POST",
    path: "/v1/installations/1/tokens",
    query: "a=1",
    headerNames: [],
    headerDigest: [],
    bodyDigest: "",
    subject: "user_1",
    timeToLiveSeconds: "60",
    issuedAt: String(NOW),
  },
};
const withFields = (f: Record<string, unknown>) => ({ ...base, httpAuthzV1: { ...base.httpAuthzV1, ...f } });

describe("profile validation", () => {
  const good: [string, unknown][] = [
    ["a minimal intent", base],
    ["bound headers in any order", withFields({ headerNames: ["x-github-api-version", "accept"], headerDigest: [digest, digest] })],
    ["a body digest", withFields({ bodyDigest: digest })],
    ["an unsorted raw query (no canonicalization)", withFields({ query: "b=1&a=%7e" })],
    ["an empty query", withFields({ query: "" })],
    ["a query up to 2 KiB", withFields({ query: "a=" + "x".repeat(2046) })],
    ["TTL 1", withFields({ timeToLiveSeconds: "1" })],
    ["TTL 300", withFields({ timeToLiveSeconds: "300" })],
    ["issuedAt a day ahead", withFields({ issuedAt: String(NOW + 86_400) })],
    ["issuedAt a day behind", withFields({ issuedAt: String(NOW - 86_400) })],
    ["any uppercase method token", withFields({ method: "M-SEARCH" })],
  ];
  for (const [name, intent] of good) test(`accepts ${name}`, () => expect(() => validateIntent(intent, NOW)).not.toThrow());

  const formatCases = digestVectors.format.filter((c: { ok: boolean }) => !c.ok) as { name: string; value: string }[];
  const bad: [string, unknown][] = [
    ["unknown profile", { ...base, profile: "turnkey.io/http-authz/v1" }],
    ["http audience", { ...base, audience: "http://broker.example" }],
    ["audience with path", { ...base, audience: "https://broker.example/x" }],
    ["uppercase host", { ...base, audience: "https://Broker.example" }],
    ["default port", { ...base, audience: "https://broker.example:443" }],
    ["unknown intent field", { ...base, signingKeyId: "pk_1" }],
    ["the old fields map", { profile: base.profile, audience: base.audience, fields: { method: "POST" } }],
    ["unknown httpAuthzV1 field", withFields({ nonce: "n" })],
    ["missing subject", withFields({ subject: undefined })],
    ["missing headerDigest", withFields({ headerDigest: undefined })],
    ["lowercase method", withFields({ method: "post" })],
    ["relative path", withFields({ path: "v1/x" })],
    ["path with a query", withFields({ path: "/v1?x=1" })],
    ["path with a space", withFields({ path: "/v1/a b" })],
    ["query with a leading ?", withFields({ query: "?a=1" })],
    ["query with a fragment", withFields({ query: "a=1#f" })],
    ["query over 2 KiB", withFields({ query: "a=" + "x".repeat(2047) })],
    ["TTL 0", withFields({ timeToLiveSeconds: "0" })],
    ["TTL 301", withFields({ timeToLiveSeconds: "301" })],
    ["fractional TTL", withFields({ timeToLiveSeconds: "1.5" })],
    ["numeric TTL", withFields({ timeToLiveSeconds: 60 })],
    ["missing issuedAt", withFields({ issuedAt: undefined })],
    ["numeric issuedAt", withFields({ issuedAt: NOW })],
    ["issuedAt not a number", withFields({ issuedAt: "now" })],
    ["issuedAt over a day ahead", withFields({ issuedAt: String(NOW + 86_401) })],
    ["issuedAt over a day behind", withFields({ issuedAt: String(NOW - 86_401) })],
    ["empty subject", withFields({ subject: "" })],
    ["headerNames longer than headerDigest", withFields({ headerNames: ["accept", "x-a"], headerDigest: [digest] })],
    ["headerDigest without headerNames", withFields({ headerDigest: [digest] })],
    ["authorization header", withFields({ headerNames: ["authorization"], headerDigest: [digest] })],
    ["pseudo-header", withFields({ headerNames: [":path"], headerDigest: [digest] })],
    ["repeated header name", withFields({ headerNames: ["accept", "accept"], headerDigest: [digest, digest] })],
    ["uppercase header name", withFields({ headerNames: ["Accept"], headerDigest: [digest] })],
    ["33 header names", withFields({ headerNames: Array.from({ length: 33 }, (_, i) => `x-${i}`), headerDigest: Array(33).fill(digest) })],
    ["headerNames as a string", withFields({ headerNames: "accept", headerDigest: [digest] })],
    ...formatCases.flatMap((c): [string, unknown][] => [
      [`bodyDigest: ${c.name}`, withFields({ bodyDigest: c.value || " " })],
      [`headerDigest: ${c.name}`, withFields({ headerNames: ["accept"], headerDigest: [c.value] })],
    ]),
  ];
  for (const [name, intent] of bad) test(`rejects ${name}`, () => expect(() => validateIntent(intent, NOW)).toThrow(IntentError));
});

describe("claims", () => {
  const organizationId = "7b9c1d52-3e48-4a07-9c3d-5e8a2f6b0c44";
  const topLevelOrganizationId = "4f0a3a8e-9d2b-4c61-8f57-2b1c6d0e7a11";
  test("iss names the top-level organization and org the minting one", () => {
    const claims = buildClaims({ intent: base, organizationId, topLevelOrganizationId });
    expect(claims.iss).toBe(`https://id.turnkey.com/t/${topLevelOrganizationId}`);
    expect(claims.org).toBe(`urn:turnkey:org:${organizationId}`);
    expect(claims.sub).toBe("urn:turnkey:user:user_1");
    expect([claims.iat, claims.exp]).toEqual([NOW, NOW + 60]);
  });
  test("a top-level organization mints as itself", () => {
    const claims = buildClaims({ intent: base, organizationId: topLevelOrganizationId, topLevelOrganizationId });
    expect(claims.iss).toBe(`https://id.turnkey.com/t/${topLevelOrganizationId}`);
    expect(claims.org).toBe(`urn:turnkey:org:${topLevelOrganizationId}`);
  });
  test("the same intent gives the same claims", () => {
    expect(buildClaims({ intent: base, organizationId, topLevelOrganizationId })).toEqual(buildClaims({ intent: base, organizationId, topLevelOrganizationId }));
  });
});

describe("policy evaluation (default)", () => {
  const p = examplePolicy({ audience: "https://b", installationId: "1" });
  const values = (query: string, path = "/v1/installations/1/tokens") =>
    mintValues({ ...base, audience: "https://b", httpAuthzV1: { ...base.httpAuthzV1, path, query, bodyDigest: digest, headerDigest: [digest], headerNames: ["accept"], subject: USER_IDS.alice } });
  const alice = { userId: USER_IDS.alice, isRoot: false };
  test("allows any query on the approved path; the broker allowlist narrows it", () => {
    expect(evaluate(p, alice, values(scopeQuery(["demo"], { contents: "read" }))).outcome).toBe("ALLOW");
    expect(evaluate(p, alice, values(scopeQuery(["secret"], { administration: "write" }))).outcome).toBe("ALLOW");
  });
  test("denies no query", () => expect(evaluate(p, alice, values("")).outcome).toBe("DENY"));
  test("denies another path", () => expect(evaluate(p, alice, values("a=1", "/v1/installations/2/tokens")).outcome).toBe("DENY"));
  test("denies other users", () => expect(evaluate(p, { userId: USER_IDS.bob, isRoot: false }, values("a=1")).outcome).toBe("DENY"));
  test("root bypasses", () => expect(evaluate(p, { userId: USER_IDS.root, isRoot: true }, values("x=1")).outcome).toBe("ALLOW"));
  test("exact queries with `in`", () => {
    const exact = examplePolicy({ audience: "https://b", installationId: "1", queries: [scopeQuery(["demo"], { contents: "read" })] });
    expect(evaluate(exact, alice, values("permissions=contents%3Aread&repositories=demo")).outcome).toBe("ALLOW");
    expect(evaluate(exact, alice, values("permissions=contents%3Aread&repositories=demo&repositories=demo-2")).outcome).toBe("DENY");
    expect(evaluate(exact, alice, values("repositories=demo&permissions=contents%3Aread")).outcome).toBe("DENY");
  });
  test("policy sees header names and subject but no digests or TTL", () => {
    const v = values("a=1");
    expect(v["activity.type"]).toBe("ACTIVITY_TYPE_MINT_JWT");
    expect(v["activity.params.httpAuthzV1.headerNames"]).toEqual(["accept"]);
    expect(v["activity.params.httpAuthzV1.subject"]).toBe(USER_IDS.alice);
    expect(v["activity.params.httpAuthzV1.bodyDigest"]).toBeUndefined();
    expect(v["activity.params.httpAuthzV1.headerDigest"]).toBeUndefined();
    expect(v["activity.params.httpAuthzV1.timeToLiveSeconds"]).toBeUndefined();
  });
});

describe("policy evaluation (FUTURE query subset extension, not in policy today)", () => {
  const p = futureQuerySubsetPolicy({ audience: "https://b", installationId: "1", repositories: ["demo", "demo-2"], permissions: ["contents:read", "workflows:write"] });
  const values = (query: string) => mintValues({ ...base, audience: "https://b", httpAuthzV1: { ...base.httpAuthzV1, query } });
  const alice = { userId: USER_IDS.alice, isRoot: false };
  test("repeated keys project as a list", () => expect(values("repositories=a&repositories=b")["http.query['repositories']"]).toEqual(["a", "b"]));
  test("allows a subset", () => expect(evaluate(p, alice, values(scopeQuery(["demo", "demo-2"], { contents: "read" }))).outcome).toBe("ALLOW"));
  test("denies a repository outside the subset", () => expect(evaluate(p, alice, values(scopeQuery(["demo", "secret"], { contents: "read" }))).outcome).toBe("DENY"));
  test("explicit DENY wins", () => expect(evaluate(p, alice, values(scopeQuery(["demo"], { workflows: "write" }))).outcome).toBe("DENY"));
});
