/**
 * SHIM: local state for the Turnkey stand-in. Everything lives in one state
 * directory (default `.shim/`, git-ignored):
 *
 *   mint-signer.private.jwk.json    ES256 key that signs http-authz JWTs (stands in for the Signer quorum key)
 *   enclave-signer.private.jwk.json P-256 key that signs Secrets bundles (stands in for the Signer enclave key)
 *   jwks.json                       public JWK Set for the broker to pin
 *   org.json                        organization (a sub-org), its parent, users, API public keys, destination filter
 *   policy.json                     policies (see policy.ts)
 *   keys/<user>.json                demo users' API keys, Turnkey key-file format (0600)
 */
import fs from "node:fs";
import path from "node:path";
import { scopeQuery } from "../../lib/canonical.ts";
import { b64url, fromB64url, hex, sha256b64url } from "../../lib/encoding.ts";
import { generateApiKey, jwkToUncompressed } from "../../lib/p256.ts";
import type { Matcher, Policy, PolicyFile } from "./policy.ts";
import { ACTIVITY_TYPE, PROFILE } from "./profile.ts";

export type User = { userId: string; userName: string; isRoot: boolean; apiKeys: { publicKey: string; jwk: JsonWebKey }[] };
export type Org = {
  organizationId: string;
  /** Set when the organization is a sub-org. The token's `iss` names the top-level organization. */
  parentOrganizationId?: string;
  organizationName: string;
  users: User[];
  /** Coordinator destination filter: audiences allowed to mint for (default deny). */
  allowedAudiences: string[];
};

export type LoadedState = {
  dir: string;
  org: Org;
  policy: PolicyFile;
  mintKey: CryptoKey;
  mintKid: string;
  jwks: { keys: (JsonWebKey & { kid: string })[] };
  enclaveKey: CryptoKey;
  /** SEC1 uncompressed hex; pass as `dangerouslyOverrideSignerPublicKey` / `signer_public_key`. */
  enclaveSignerPublicKey: string;
};

export const DEMO_ORG_ID = "7d5d7f4e-0b0e-4c1a-9a51-6f0d3c1e2a10";
/** The demo org is a sub-org of this parent; the broker pins the parent. */
export const DEMO_PARENT_ORG_ID = "3f1c9a2e-6b4d-4e8a-9c07-5a2b8d1e0f34";
export const USER_IDS = {
  root: "00000000-0000-4000-8000-00000000000a",
  broker: "00000000-0000-4000-8000-00000000000b",
  alice: "00000000-0000-4000-8000-0000000000a1",
  bob: "00000000-0000-4000-8000-0000000000b0",
};

/** RFC 7638 thumbprint of a P-256 JWK. */
export function thumbprint(jwk: JsonWebKey): Promise<string> {
  return sha256b64url(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`);
}

function writeSecret(file: string, data: unknown) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
}

async function genSigningJwk(): Promise<JsonWebKey> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const j = await crypto.subtle.exportKey("jwk", kp.privateKey);
  return { kty: "EC", crv: "P-256", x: j.x, y: j.y, d: j.d };
}

export type InitOptions = {
  dir: string;
  audience: string;
  installationId?: string;
  repositories?: string[];
  permissions?: string[];
};

/** Create a fresh state directory. Overwrites existing keys. */
export async function initState(o: InitOptions): Promise<void> {
  fs.mkdirSync(o.dir, { recursive: true });
  writeSecret(path.join(o.dir, "mint-signer.private.jwk.json"), await genSigningJwk());
  writeSecret(path.join(o.dir, "enclave-signer.private.jwk.json"), await genSigningJwk());
  const users: User[] = [];
  for (const [name, userId] of Object.entries(USER_IDS)) {
    const k = await generateApiKey();
    writeSecret(path.join(o.dir, "keys", `${name}.json`), { publicKey: k.publicKey, privateKey: k.privateKey });
    users.push({ userId, userName: name, isRoot: name === "root", apiKeys: [{ publicKey: k.publicKey, jwk: k.jwk }] });
  }
  const org: Org = { organizationId: DEMO_ORG_ID, parentOrganizationId: DEMO_PARENT_ORG_ID, organizationName: "tvc-github-broker (shim)", users, allowedAudiences: [o.audience] };
  fs.writeFileSync(path.join(o.dir, "org.json"), JSON.stringify(org, null, 2) + "\n");
  // With an explicit scope, policy lists that one exact query (`in`).
  // Without one, policy leaves the scope to the broker's allowlist.
  const queries =
    o.repositories && o.permissions ? [scopeQuery(o.repositories, Object.fromEntries(o.permissions.map((p) => p.split(":") as [string, string])))] : undefined;
  const policy = examplePolicy({ audience: o.audience, installationId: o.installationId ?? "12345", queries });
  fs.writeFileSync(path.join(o.dir, "policy.json"), JSON.stringify(policy, null, 2) + "\n");
  const st = await loadState(o.dir);
  fs.writeFileSync(path.join(o.dir, "jwks.json"), JSON.stringify(st.jwks, null, 2) + "\n");
}

function exportPolicy(): Policy {
  return {
    policyName: "the broker's API user may export the GitHub App key",
    effect: "EFFECT_ALLOW",
    consensus: { anyOf: [USER_IDS.broker] },
    condition: {
      "activity.type": { eq: "ACTIVITY_TYPE_EXPORT_SECRETS" },
      "secret.static_properties['demo:schema']": { eq: "github-app-key-v1" },
    },
    turnkeyConsensus: `approvers.any(user, user.id == '${USER_IDS.broker}')`,
    turnkeyCondition: "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['demo:schema'] == 'github-app-key-v1'",
    notes: "Policy cannot bind the export target key to the enclave's attested key. See README gaps.",
  };
}

const quote = (s: string) => `'${s}'`;

function mintCondition(audience: string, path: string): Record<string, Matcher> {
  return {
    "activity.type": { eq: ACTIVITY_TYPE },
    "activity.params.profile": { eq: PROFILE },
    "activity.params.audience": { eq: audience },
    "activity.params.httpAuthzV1.method": { eq: "POST" },
    "activity.params.httpAuthzV1.path": { eq: path },
  };
}

/**
 * The default demo policy. It uses only what Turnkey policy can express: the
 * principal, audience, method, and path, and the query as one string
 * (`queries` given: an exact `in` list; otherwise: a query must be present).
 * The broker's per-installation allowlist enforces the repository and
 * permission subset.
 */
export function examplePolicy(p: { audience: string; installationId: string; queries?: string[] }): PolicyFile {
  const path = `/v1/installations/${p.installationId}/tokens`;
  const queryCondition: Record<string, Matcher> = p.queries ? { "activity.params.httpAuthzV1.query": { in: p.queries } } : { "activity.params.httpAuthzV1.query": { ne: "" } };
  const queryExpr = p.queries ? `activity.params.httpAuthzV1.query in [${p.queries.map(quote).join(", ")}]` : "activity.params.httpAuthzV1.query != ''";
  return {
    policies: [
      {
        policyName: `alice may mint GitHub tokens for installation ${p.installationId}`,
        effect: "EFFECT_ALLOW",
        consensus: { anyOf: [USER_IDS.alice] },
        condition: {
          ...mintCondition(p.audience, path),
          ...queryCondition,
        },
        turnkeyConsensus: `approvers.any(user, user.id == '${USER_IDS.alice}')`,
        turnkeyCondition:
          `activity.type == '${ACTIVITY_TYPE}' && ` +
          `activity.params.profile == '${PROFILE}' && ` +
          `activity.params.audience == '${p.audience}' && ` +
          "activity.params.httpAuthzV1.method == 'POST' && " +
          `activity.params.httpAuthzV1.path == '${path}' && ` +
          queryExpr,
        notes: p.queries
          ? "Policy compares the whole query string, so it lists each allowed scope exactly. The broker accepts only its canonical query form, so a reordered query cannot sidestep the list."
          : "Policy cannot express a subset over query parameters, so it only requires a query. The broker's installations allowlist enforces the repository and permission subset.",
      },
      exportPolicy(),
    ],
  };
}

/**
 * FUTURE POLICY-LANGUAGE EXTENSION, NOT IN TURNKEY POLICY TODAY. The same
 * grant written with a parsed query subset matcher (`http.query[...]`). The
 * shim evaluates it so tests can show the intended behavior; real Turnkey
 * policy cannot express it today.
 */
export function futureQuerySubsetPolicy(p: { audience: string; installationId: string; repositories: string[]; permissions: string[] }): PolicyFile {
  const path = `/v1/installations/${p.installationId}/tokens`;
  return {
    policies: [
      {
        policyName: `FUTURE (not in policy today): alice may mint a subset of the allowed scope for installation ${p.installationId}`,
        effect: "EFFECT_ALLOW",
        consensus: { anyOf: [USER_IDS.alice] },
        condition: {
          ...mintCondition(p.audience, path),
          "http.query['repositories']": { subsetOf: p.repositories },
          "http.query['permissions']": { subsetOf: p.permissions },
        },
        notes: "Shim-only parsed query subset matcher. Not in Turnkey policy today.",
      },
      {
        policyName: "FUTURE (not in policy today): nobody may mint tokens that can change workflows",
        effect: "EFFECT_DENY",
        condition: {
          "activity.type": { eq: ACTIVITY_TYPE },
          "http.query['permissions']": { containsAny: ["workflows:write"] },
        },
        notes: "Shim-only parsed query matcher. Not in Turnkey policy today.",
      },
      exportPolicy(),
    ],
  };
}

export async function loadState(dir: string): Promise<LoadedState> {
  const read = (f: string) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
  const mintJwk = read("mint-signer.private.jwk.json") as JsonWebKey;
  const encJwk = read("enclave-signer.private.jwk.json") as JsonWebKey;
  const importSign = (j: JsonWebKey) => crypto.subtle.importKey("jwk", j, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const pub = { kty: "EC", crv: "P-256", x: mintJwk.x, y: mintJwk.y };
  const mintKid = await thumbprint(pub);
  // Sanity: the JWK coordinates decode to 32 bytes.
  fromB64url(mintJwk.x!);
  return {
    dir,
    org: read("org.json"),
    policy: read("policy.json"),
    mintKey: await importSign(mintJwk),
    mintKid,
    jwks: { keys: [{ ...pub, kid: mintKid, alg: "ES256", use: "sig" }] },
    enclaveKey: await importSign(encJwk),
    enclaveSignerPublicKey: hex(jwkToUncompressed(encJwk)),
  };
}

export { b64url };
