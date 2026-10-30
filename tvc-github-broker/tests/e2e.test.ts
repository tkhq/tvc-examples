/**
 * End-to-end tests: Turnkey shim + mock GitHub + the real broker binary.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { scopeQuery } from "../lib/canonical.ts";
import { b64url, canonicalJson, te } from "../lib/encoding.ts";
import { TYP } from "../shim/src/profile.ts";
import { DEMO_PARENT_ORG_ID, examplePolicy, futureQuerySubsetPolicy, USER_IDS } from "../shim/src/state.ts";
import { buildTokenRequest, callBroker, decryptToken, intentFor, mintFor as mintForUser, type Scope, type TokenRequest } from "../client/src/broker.ts";
import { type HttpAuthzV1, mintJwt, readKeyFile } from "../client/src/turnkey.ts";
import { APP_CLIENT_ID, INSTALLATION_ID, OWNER, startStack, type Stack } from "./harness.ts";

let s: Stack;
const scope: Scope = { installationId: INSTALLATION_ID, repositories: ["demo"], permissions: { contents: "read", metadata: "read" } };
const alice = () => readKeyFile(s.keys.alice);
const policy = () => examplePolicy({ audience: s.audience, installationId: INSTALLATION_ID });
/** Mint with alice's key and alice as the subject (the user whose policy allows the mint). */
const mintAlice = (req: TokenRequest, aud = s.audience) => mintForUser(s.shim.url, alice(), s.organizationId, aud, USER_IDS.alice, req);
const mintAliceWith = (req: TokenRequest, over: Partial<HttpAuthzV1>) =>
  mintJwt(s.shim.url, alice(), { organizationId: s.organizationId, audience: s.audience, httpAuthzV1: { ...intentFor(req, USER_IDS.alice), ...over } });

beforeAll(async () => {
  s = await startStack();
}, 120_000);
afterAll(() => s?.stop());
beforeEach(() => {
  s.shim.setPolicy(policy());
  s.github.setMode("normal");
});

async function mintAndBuild(sc: Scope = scope) {
  const req = await buildTokenRequest(sc);
  const m = await mintAlice(req);
  if (!m.ok) throw new Error(`mint failed: ${m.message}`);
  return { req, jwt: m.jwt };
}

/** Sign arbitrary claims with the trusted mint key, to test verifier rules the shim would never produce. */
async function craft(req: TokenRequest, over: { header?: Record<string, unknown>; claims?: Record<string, unknown>; drop?: string[] } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    aud: s.audience,
    exp: now + 60,
    iat: now,
    iss: `https://id.turnkey.com/t/${DEMO_PARENT_ORG_ID}`,
    org: `urn:turnkey:org:${s.organizationId}`,
    sub: `urn:turnkey:user:${USER_IDS.alice}`,
    tk_request: { method: "POST", path: req.path, query: req.query, headers: req.headerNames },
    tk_body_digest: req.bodyDigest,
    tk_header_digest: req.headerDigests,
    ...over.claims,
  };
  for (const k of over.drop ?? []) delete claims[k];
  const header = { alg: "ES256", kid: s.shim.state.mintKid, typ: TYP, ...over.header };
  const input = `${b64url(canonicalJson(header))}.${b64url(canonicalJson(claims))}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, s.shim.state.mintKey, te.encode(input)));
  return `${input}.${b64url(sig)}`;
}

describe("happy path", () => {
  test("mint, broker, decrypt, narrowed GitHub call", async () => {
    const before = s.github.tokenRequests.length;
    const { req, jwt } = await mintAndBuild();
    const r = await callBroker(s.broker.url, req, jwt);
    expect(r.status).toBe(201);
    expect(r.json.repositories).toEqual(["demo"]);
    expect(r.json.repository_selection).toBe("selected");
    expect(r.json.authorization.sub).toBe(`urn:turnkey:user:${USER_IDS.alice}`);
    expect(r.json.authorization.iss).toBe(`https://id.turnkey.com/t/${DEMO_PARENT_ORG_ID}`);
    expect(r.json.authorization.org).toBe(`urn:turnkey:org:${s.organizationId}`);
    expect(r.json.encrypted_token.aad).toBe("tk_body_digest");
    const token = await decryptToken(req, r.json);
    expect(token.startsWith("ghs_mock")).toBe(true);

    // The App JWT was verified by jose in the mock; check its shape here too.
    const tr = s.github.tokenRequests.at(-1)!;
    expect(s.github.tokenRequests.length).toBe(before + 1);
    expect(tr.jwtHeader).toEqual({ alg: "RS256", typ: "JWT" });
    const now = Math.floor(Date.now() / 1000);
    expect(tr.jwtClaims.iss).toBe(APP_CLIENT_ID);
    expect(Math.abs(tr.jwtClaims.iat - (now - 30))).toBeLessThanOrEqual(3);
    expect(Math.abs(tr.jwtClaims.exp - (now + 120))).toBeLessThanOrEqual(3);
    expect(tr.body).toEqual({ repositories: ["demo"], permissions: { contents: "read", metadata: "read" } });

    const repo = await fetch(`${s.github.url}/repos/${OWNER}/demo`, { headers: { Authorization: `Bearer ${token}` } });
    expect(repo.status).toBe(200);
    const other = await fetch(`${s.github.url}/repos/${OWNER}/secret-repo`, { headers: { Authorization: `Bearer ${token}` } });
    expect(other.status).toBe(404);
  });

  test("the token and JWTs never appear in broker logs", async () => {
    const { req, jwt } = await mintAndBuild();
    const r = await callBroker(s.broker.url, req, jwt);
    const token = await decryptToken(req, r.json);
    const logs = s.broker.logs();
    expect(logs).not.toContain(token);
    expect(logs).not.toContain(jwt.split(".")[2]!);
    expect(logs).not.toContain("BEGIN RSA PRIVATE KEY");
    expect(logs).toContain(r.json.token_sha256);
  });
});

describe("policy at the shim", () => {
  test("policy gates the path; the broker allowlist gates repositories and permissions", async () => {
    const m = await mintAlice(await buildTokenRequest({ ...scope, installationId: "999" }));
    expect(m.ok).toBe(false);
    if (!m.ok) expect(m.status).toBe(403);
    const before = s.github.tokenRequests.length;
    for (const sc of [
      { ...scope, permissions: { contents: "write" } },
      { ...scope, repositories: ["demo", "secret-repo"] },
    ]) {
      // Policy cannot express a subset of the query, so it allows these.
      const { req, jwt } = await mintAndBuild(sc);
      const r = await callBroker(s.broker.url, req, jwt);
      expect(r.status).toBe(403);
      expect(r.json.error).toBe("scope_not_allowed");
    }
    expect(s.github.tokenRequests.length).toBe(before);
  });

  test("a mint without a query is denied", async () => {
    const req = await buildTokenRequest(scope);
    const m = await mintAliceWith(req, { query: "" });
    expect(m.ok).toBe(false);
    if (!m.ok) expect(m.status).toBe(403);
  });

  test("an exact-query policy (`in`) denies other scopes at the shim", async () => {
    s.shim.setPolicy(examplePolicy({ audience: s.audience, installationId: INSTALLATION_ID, queries: [scopeQuery(scope.repositories, scope.permissions)] }));
    expect((await mintAlice(await buildTokenRequest(scope))).ok).toBe(true);
    const m = await mintAlice(await buildTokenRequest({ ...scope, repositories: ["demo", "demo-2"] }));
    expect(m.ok).toBe(false);
  });

  test("explicit DENY on an exact query wins over ALLOW", async () => {
    const p = policy();
    const denied = scopeQuery(["demo"], { workflows: "write" });
    p.policies.unshift({
      policyName: "nobody may mint this exact workflows scope",
      effect: "EFFECT_DENY",
      condition: { "activity.type": { eq: "ACTIVITY_TYPE_MINT_JWT" }, "activity.params.httpAuthzV1.query": { in: [denied] } },
    });
    s.shim.setPolicy(p);
    const m = await mintAlice(await buildTokenRequest({ ...scope, permissions: { workflows: "write" } }));
    expect(m.ok).toBe(false);
    if (!m.ok) expect(m.message).toContain("explicit deny");
  });

  test("FUTURE (not in policy today): the shim's parsed query subset matcher denies at the shim", async () => {
    s.shim.setPolicy(futureQuerySubsetPolicy({ audience: s.audience, installationId: INSTALLATION_ID, repositories: ["demo", "demo-2"], permissions: ["contents:read", "metadata:read"] }));
    expect((await mintAlice(await buildTokenRequest(scope))).ok).toBe(true);
    const m = await mintAlice(await buildTokenRequest({ ...scope, repositories: ["demo", "secret-repo"] }));
    expect(m.ok).toBe(false);
  });

  test("another user is denied", async () => {
    const m = await mintForUser(s.shim.url, readKeyFile(s.keys.bob), s.organizationId, s.audience, USER_IDS.bob, await buildTokenRequest(scope));
    expect(m.ok).toBe(false);
  });

  test("an unregistered audience is refused by the destination filter", async () => {
    const m = await mintAlice(await buildTokenRequest(scope), "https://other.example");
    expect(m.ok).toBe(false);
    if (!m.ok) expect(m.message).toContain("not a registered destination");
  });

  test("the 2 KiB query bound caps the scope size", async () => {
    const many = Array.from({ length: 100 }, (_, i) => `repository-${String(i).padStart(3, "0")}`);
    const m = await mintAlice(await buildTokenRequest({ ...scope, repositories: many }));
    expect(m.ok).toBe(false);
    if (!m.ok) {
      expect(m.status).toBe(400);
      expect(m.message).toContain("at most 2048");
    }
    // 60 repositories fit.
    const ok = await mintAlice(await buildTokenRequest({ ...scope, repositories: many.slice(0, 60) }));
    expect(ok.ok).toBe(true);
  });

  test("the shim mints a non-canonical query as is; the broker refuses it", async () => {
    const req = await buildTokenRequest(scope);
    const query = "repositories=demo&permissions=contents%3Aread&permissions=metadata%3Aread";
    const m = await mintAlice({ ...req, query });
    if (!m.ok) throw new Error(m.message);
    const r = await callBroker(s.broker.url, req, m.jwt, { query });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("invalid_scope");
  });

  test("a subject that is not a user of the organization is refused", async () => {
    const m = await mintForUser(s.shim.url, alice(), s.organizationId, s.audience, "00000000-0000-4000-8000-0000000000ff", await buildTokenRequest(scope));
    expect(m.ok).toBe(false);
    if (!m.ok) expect(m.status).toBe(400);
    if (!m.ok) expect(m.message).toContain("subject is not a user of the organization");
  });

  test("a TTL above 300 s is refused, not clamped", async () => {
    const m = await mintForUser(s.shim.url, alice(), s.organizationId, s.audience, USER_IDS.alice, await buildTokenRequest(scope), 301);
    expect(m.ok).toBe(false);
    if (!m.ok) expect(m.status).toBe(400);
    if (!m.ok) expect(m.message).toContain("timeToLiveSeconds");
  });
});

describe("request binding and replay at the broker", () => {
  test("tampered query fails and never reaches GitHub", async () => {
    const before = s.github.tokenRequests.length;
    const { req, jwt } = await mintAndBuild();
    for (const query of [
      scopeQuery(["demo", "demo-2"], scope.permissions),
      scopeQuery(["demo"], { contents: "write", metadata: "read" }),
      "repositories=demo&permissions=contents%3Aread&permissions=metadata%3Aread",
      "",
    ]) {
      const r = await callBroker(s.broker.url, req, jwt, { query });
      expect(r.status).toBe(401);
      expect(r.json.error).toBe("request_mismatch");
    }
    const path = await callBroker(s.broker.url, req, jwt, { path: "/v1/installations/999/tokens" });
    expect(path.json.error).toBe("request_mismatch");
    const body = await callBroker(s.broker.url, req, jwt, { body: (await buildTokenRequest(scope)).body });
    expect(body.json.error).toBe("request_mismatch");
    expect(s.github.tokenRequests.length).toBe(before);
    expect((await callBroker(s.broker.url, req, jwt)).status).toBe(201);
  });

  test("a replay before exp succeeds, sealed to the same key", async () => {
    const { req, jwt } = await mintAndBuild();
    const first = await callBroker(s.broker.url, req, jwt);
    expect(first.status).toBe(201);
    const again = await callBroker(s.broker.url, req, jwt);
    expect(again.status).toBe(201);
    expect(await decryptToken(req, again.json)).not.toBe(await decryptToken(req, first.json));
    // A replay with another HPKE key is a different request.
    const thief = await callBroker(s.broker.url, req, jwt, { body: (await buildTokenRequest(scope)).body });
    expect(thief.json.error).toBe("request_mismatch");
  });

  test("a failed GitHub call can be retried with the same token", async () => {
    s.github.setMode("error-500");
    const { req, jwt } = await mintAndBuild();
    expect((await callBroker(s.broker.url, req, jwt)).status).toBe(502);
    s.github.setMode("normal");
    expect((await callBroker(s.broker.url, req, jwt)).status).toBe(201);
  });

  test("a replay at or after exp fails (no skew on exp)", async () => {
    const req = await buildTokenRequest(scope);
    const m = await mintForUser(s.shim.url, alice(), s.organizationId, s.audience, USER_IDS.alice, req, 3);
    if (!m.ok) throw new Error(m.message);
    expect((await callBroker(s.broker.url, req, m.jwt)).status).toBe(201);
    await Bun.sleep(3_500);
    const r = await callBroker(s.broker.url, req, m.jwt);
    expect(r.status).toBe(401);
    expect(r.json.error).toBe("expired");
  }, 15_000);

  test("/v1/info reports the issuer and the token route", async () => {
    const info = await (await fetch(`${s.broker.url}/v1/info`)).json();
    expect(info.issuer).toBe(`https://id.turnkey.com/t/${DEMO_PARENT_ORG_ID}`);
    expect(info.profile).toBe("JWT_PROFILE_HTTP_AUTHZ_V1");
    expect(info.token_route).toEqual({ required_headers: ["accept", "x-github-api-version"] });
  });

  test("the broker refuses the removed config fields", async () => {
    for (const extra of [{ single_use_token_route: true }, { allowed_issuers: [`urn:turnkey:org:${s.organizationId}`] }]) {
      const r = await s.startBroker({ ...s.config, ...extra });
      expect(r.exitCode).toBe(1);
      expect(r.logs).toContain("unknown field");
    }
  });
});

describe("header binding at the broker", () => {
  test("a changed or dropped bound header fails (Rust tests cover repeated fields)", async () => {
    const { req, jwt } = await mintAndBuild();
    for (const headers of [
      { ...req.headers, "x-github-api-version": "2026-03-10" },
      { ...req.headers, accept: "application/json" },
      { "x-github-api-version": req.headers["x-github-api-version"]! },
    ]) {
      const r = await callBroker(s.broker.url, req, jwt, { headers });
      expect(r.status).toBe(401);
      expect(r.json.error).toBe("request_mismatch");
    }
    // Surrounding whitespace and unbound headers do not matter.
    const r = await callBroker(s.broker.url, req, jwt, { headers: { ...req.headers, accept: `  ${req.headers.accept}\t`, "user-agent": "other" } });
    expect(r.status).toBe(201);
  });

  test("a token that does not bind the route's required headers is refused", async () => {
    const req = await buildTokenRequest(scope);
    const none = await craft(req, { claims: { tk_request: { method: "POST", path: req.path, query: req.query } }, drop: ["tk_header_digest"] });
    const r = await callBroker(s.broker.url, req, none);
    expect(r.status).toBe(401);
    expect(r.json.error).toBe("header_binding_required");
    expect(r.json.message).toContain("accept");

    const onlyAccept = await buildTokenRequest(scope, { accept: "application/vnd.github+json" });
    const m = await mintAlice(onlyAccept);
    if (!m.ok) throw new Error(m.message);
    const r2 = await callBroker(s.broker.url, onlyAccept, m.jwt, { headers: { ...onlyAccept.headers, "x-github-api-version": "2022-11-28" } });
    expect(r2.json.error).toBe("header_binding_required");
    expect(r2.json.message).toContain("x-github-api-version");
  });

  test("binding extra headers is allowed", async () => {
    const req = await buildTokenRequest(scope, { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "x-request-id": "r-1" });
    expect(req.headerNames).toEqual(["accept", "x-github-api-version", "x-request-id"]);
    const m = await mintAlice(req);
    if (!m.ok) throw new Error(m.message);
    expect((await callBroker(s.broker.url, req, m.jwt)).status).toBe(201);
    expect((await callBroker(s.broker.url, req, m.jwt, { headers: { ...req.headers, "x-request-id": "r-2" } })).json.error).toBe("request_mismatch");
  });

  test("the shim refuses forbidden header names", async () => {
    const req = await buildTokenRequest(scope);
    const m = await mintAliceWith(req, { headerNames: ["accept", "host"] });
    expect(m.ok).toBe(false);
    if (!m.ok) expect(m.status).toBe(400);
  });
});

describe("JWT verification at the broker", () => {
  const now = () => Math.floor(Date.now() / 1000);
  const cases: [string, (r: TokenRequest) => Promise<string>, string][] = [
    ["wrong aud", (r) => craft(r, { claims: { aud: "https://other.example" } }), "wrong_aud"],
    ["aud with trailing slash", (r) => craft(r, { claims: { aud: `${s.audience}/` } }), "wrong_aud"],
    ["wrong typ JWT", (r) => craft(r, { header: { typ: "JWT" } }), "wrong_typ"],
    ["dpop typ", (r) => craft(r, { header: { typ: "dpop+jwt" } }), "wrong_typ"],
    ["alg HS256", (r) => craft(r, { header: { alg: "HS256" } }), "unsupported_alg"],
    ["unknown kid", (r) => craft(r, { header: { kid: "not-a-trusted-kid" } }), "unknown_kid"],
    ["embedded jwk", (r) => craft(r, { header: { jwk: { kty: "EC" } } }), "malformed_token"],
    ["expired", (r) => craft(r, { claims: { iat: now() - 120, exp: now() - 60 } }), "expired"],
    ["lifetime over 300 s", (r) => craft(r, { claims: { exp: now() + 301 } }), "lifetime_too_long"],
    ["future iat beyond skew", (r) => craft(r, { claims: { iat: now() + 30, exp: now() + 60 } }), "not_yet_valid"],
    ["another top-level organization", (r) => craft(r, { claims: { iss: "https://id.turnkey.com/t/9a1e4d7c-2b58-4f03-8c6a-1d7e5b3f0a92" } }), "wrong_iss"],
    ["iss on another host", (r) => craft(r, { claims: { iss: `https://auth.turnkey.com/t/${DEMO_PARENT_ORG_ID}` } }), "bad_claim"],
    ["iss that is not a UUID", (r) => craft(r, { claims: { iss: "https://id.turnkey.com/t/parent_org" } }), "bad_claim"],
    ["org without the urn prefix", (r) => craft(r, { claims: { org: s.organizationId } }), "bad_claim"],
    ["missing org", (r) => craft(r, { drop: ["org"] }), "bad_claim"],
    ["unknown claim", (r) => craft(r, { claims: { admin: true } }), "bad_claim"],
    ["jti claim", (r) => craft(r, { claims: { jti: "j1" } }), "bad_claim"],
    ["missing sub", (r) => craft(r, { drop: ["sub"] }), "bad_claim"],
    ["no body digest", (r) => craft(r, { drop: ["tk_body_digest"] }), "body_digest_required"],
    ["old tk_body_sha256 name", (r) => craft(r, { claims: { tk_body_sha256: "x" }, drop: ["tk_body_digest"] }), "bad_claim"],
    ["body digest without padding", (r) => craft(r, { claims: { tk_body_digest: r.bodyDigest.replace("=:", ":") } }), "bad_claim"],
    ["sha-512 body digest", (r) => craft(r, { claims: { tk_body_digest: `sha-512=:${Buffer.alloc(64).toString("base64")}:` } }), "bad_claim"],
    ["canonical_query name", (r) => craft(r, { claims: { tk_request: { method: "POST", path: r.path, canonical_query: r.query, headers: r.headerNames } } }), "bad_claim"],
    ["nonce in tk_request", (r) => craft(r, { claims: { tk_request: { method: "POST", path: r.path, query: r.query, headers: r.headerNames, nonce: "n" } } }), "bad_claim"],
    ["sub without urn prefix", (r) => craft(r, { claims: { sub: USER_IDS.alice } }), "bad_claim"],
    ["headers without digests", (r) => craft(r, { drop: ["tk_header_digest"] }), "bad_claim"],
    ["fewer digests than headers", (r) => craft(r, { claims: { tk_header_digest: r.headerDigests.slice(1) } }), "bad_claim"],
    ["authorization bound", (r) => craft(r, { claims: { tk_request: { method: "POST", path: r.path, query: r.query, headers: [...r.headerNames, "authorization"] }, tk_header_digest: [...r.headerDigests, r.bodyDigest] } }), "bad_claim"],
  ];
  for (const [name, make, code] of cases) {
    test(name, async () => {
      const req = await buildTokenRequest(scope);
      const r = await callBroker(s.broker.url, req, await make(req));
      expect(r.status).toBe(401);
      expect(r.json.error).toBe(code);
    });
  }

  test("a signature from an untrusted key is refused", async () => {
    const req = await buildTokenRequest(scope);
    const good = await craft(req);
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])) as CryptoKeyPair;
    const input = good.split(".").slice(0, 2).join(".");
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, te.encode(input)));
    const r = await callBroker(s.broker.url, req, `${input}.${b64url(sig)}`);
    expect(r.json.error).toBe("bad_signature");
  });
});

describe("scope checks at the broker", () => {
  test("admin permission is refused even with a valid JWT", async () => {
    const req = await buildTokenRequest({ ...scope, permissions: { administration: "admin" } });
    const r = await callBroker(s.broker.url, req, await craft(req));
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("invalid_scope");
  });

  test("app allowlist blocks a scope that policy allowed", async () => {
    const before = s.github.tokenRequests.length;
    const { req, jwt } = await mintAndBuild({ ...scope, repositories: ["secret-repo"] });
    const r = await callBroker(s.broker.url, req, jwt);
    expect(r.status).toBe(403);
    expect(r.json.error).toBe("scope_not_allowed");
    expect(s.github.tokenRequests.length).toBe(before);
  });

  test("the comma-joined scope format is refused", async () => {
    const req = await buildTokenRequest(scope);
    const commas = "permissions=contents%3Aread%2Cmetadata%3Aread&repositories=demo";
    const r = await callBroker(s.broker.url, { ...req, query: commas }, await craft({ ...req, query: commas }));
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("invalid_scope");
  });
});

describe("GitHub response checks", () => {
  for (const mode of ["overbroad-repo", "overbroad-permission", "selection-all"] as const) {
    test(`${mode} response is revoked and refused`, async () => {
      s.github.setMode(mode);
      const revokedBefore = s.github.revocations.length;
      const { req, jwt } = await mintAndBuild();
      const r = await callBroker(s.broker.url, req, jwt);
      expect(r.status).toBe(502);
      expect(r.json.error).toBe("github_grant_too_broad");
      expect(r.json.message).toContain("revoked=true");
      expect(r.json.encrypted_token).toBeUndefined();
      expect(s.github.revocations.length).toBe(revokedBefore + 1);
      const t = s.github.issued.get(s.github.revocations.at(-1)!)!;
      expect(t.revoked).toBe(true);
    });
  }
});

describe("broker startup: App key export", () => {
  test("refuses to start when EXPORT_SECRETS is denied", async () => {
    const p = policy();
    p.policies = p.policies.filter((x) => !x.policyName.includes("export"));
    s.shim.setPolicy(p);
    const r = await s.startBroker();
    expect(r.broker).toBeUndefined();
    expect(r.exitCode).toBe(1);
    expect(r.logs).toContain("refusing to start");
    expect(r.logs).toContain("policy denied ACTIVITY_TYPE_EXPORT_SECRETS");
  });

  test("refuses to start when EXPORT_SECRETS needs consensus", async () => {
    const p = policy();
    p.policies = p.policies.map((x) => (x.policyName.includes("export") ? { ...x, consensus: { allOf: [USER_IDS.broker, USER_IDS.root] } } : x));
    s.shim.setPolicy(p);
    const r = await s.startBroker();
    expect(r.exitCode).toBe(1);
    expect(r.logs).toContain("ACTIVITY_STATUS_CONSENSUS_NEEDED");
  });

  test("refuses a bundle signed by an unpinned Signer key", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])) as CryptoKeyPair;
    const raw = Buffer.from(await crypto.subtle.exportKey("raw", kp.publicKey)).toString("hex");
    const r = await s.startBroker({ ...s.config, turnkey: { ...s.config.turnkey, signer_public_key: raw } });
    expect(r.exitCode).toBe(1);
    expect(r.logs).toContain("export bundle");
  });

  test("refuses a key whose fingerprint is not the expected one", async () => {
    const r = await s.startBroker({ ...s.config, github: { ...s.config.github, expected_key_sha256: "SHA256:AAAA" } });
    expect(r.exitCode).toBe(1);
    expect(r.logs).toContain("does not match expected_key_sha256");
  });

  test("starts with a matching policy", async () => {
    const r = await s.startBroker();
    expect(r.broker).toBeDefined();
    r.broker?.stop();
  });
});
