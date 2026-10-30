/**
 * Demo client. One command:
 *
 * 1. asks the MINT_JWT shim for an http-authz/v1 JWT for the exact request
 *    (subject: the caller, from whoami);
 * 2. calls the TVC broker with it;
 * 3. decrypts the installation token (HPKE) and checks token_sha256;
 * 4. makes one narrowed GitHub API call (GET /repos/{owner}/{repo});
 * 5. shows a scope outside what the org allows failing (at the shim when
 *    policy lists exact queries, else at the broker's allowlist), a replay
 *    before exp (sealed to the original key), and altered
 *    requests failing at the broker;
 * 6. revokes the tokens (unless KEEP_TOKEN=1).
 *
 * Environment (defaults suit `bun run demo:local`):
 *   SHIM_URL, BROKER_URL, AUDIENCE (defaults to BROKER_URL), ORG_ID,
 *   USER_KEY (API key file of the allowed user), OTHER_USER_KEY (optional),
 *   INSTALLATION_ID, REPOS (comma-separated list), PERMISSIONS (comma-separated
 *   name:level list), GITHUB_API_BASE (default https://api.github.com), GITHUB_OWNER.
 */
import { scopeQuery } from "../../lib/canonical.ts";
import { buildTokenRequest, callBroker, decryptToken, mintFor, type Scope, type TokenRequest } from "./broker.ts";
import { readKeyFile, whoami } from "./turnkey.ts";

const env = (k: string, d?: string) => {
  const v = process.env[k] ?? d;
  if (v === undefined) throw new Error(`missing env ${k}`);
  return v;
};

const shimUrl = env("SHIM_URL", "http://127.0.0.1:8081");
const brokerUrl = env("BROKER_URL", "http://127.0.0.1:44020");
const audience = env("AUDIENCE", brokerUrl);
const org = env("ORG_ID");
const user = readKeyFile(env("USER_KEY"));
const otherUserKey = process.env.OTHER_USER_KEY;
const subject = await whoami(shimUrl, user, org);
const githubApi = env("GITHUB_API_BASE", "https://api.github.com");
const owner = env("GITHUB_OWNER");
const scope: Scope = {
  installationId: env("INSTALLATION_ID", "12345"),
  repositories: env("REPOS", "demo").split(","),
  permissions: Object.fromEntries(env("PERMISSIONS", "contents:read,metadata:read").split(",").map((p) => p.split(":") as [string, string])),
};

let failures = 0;
const step = (n: string) => console.log(`\n== ${n}`);
const expect = (ok: boolean, what: string) => {
  console.log(`   ${ok ? "PASS" : "FAIL"}  ${what}`);
  if (!ok) failures++;
};

step(`1. Mint an http-authz/v1 JWT for POST /v1/installations/${scope.installationId}/tokens?${scopeQuery(scope.repositories, scope.permissions)}`);
const req = await buildTokenRequest(scope);
const minted = await mintFor(shimUrl, user, org, audience, subject, req);
if (!minted.ok) {
  console.error(`   mint failed: ${minted.message}`);
  process.exit(1);
}
const claims = JSON.parse(Buffer.from(minted.jwt.split(".")[1]!, "base64url").toString());
console.log(`   activity ${minted.activityId}; iss ${claims.iss}; org ${claims.org}; sub ${claims.sub}; exp-iat ${claims.exp - claims.iat}s`);

step("2. Call the TVC broker with the JWT");
const resp = await callBroker(brokerUrl, req, minted.jwt);
expect(resp.status === 201, `broker returned ${resp.status} ${resp.status === 201 ? "" : JSON.stringify(resp.json)}`);
if (resp.status !== 201) process.exit(1);
console.log(`   granted repositories ${JSON.stringify(resp.json.repositories)}, permissions ${JSON.stringify(resp.json.permissions)}, expires ${resp.json.expires_at}`);

step("3. Decrypt the token (HPKE, aad = tk_body_digest) and check token_sha256");
const token = await decryptToken(req, resp.json);
expect(token.length > 0, `decrypted a ${token.length}-character token; sha256 ${resp.json.token_sha256}`);

step(`4. Narrowed GitHub call: GET /repos/${owner}/${scope.repositories[0]}`);
const gh = (path: string, method = "GET", bearer = token) =>
  fetch(`${githubApi}${path}`, { method, headers: { Authorization: `Bearer ${bearer}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "tkhq-demo-tvc-github" } });
const repo = await gh(`/repos/${owner}/${scope.repositories[0]}`);
const repoJson: any = await repo.json().catch(() => ({}));
expect(repo.status === 200, `GET /repos/${owner}/${scope.repositories[0]} -> ${repo.status} ${repoJson.full_name ?? ""}`);
const outside = process.env.OUTSIDE_REPO;
if (outside) {
  const r = await gh(`/repos/${owner}/${outside}`);
  expect(r.status === 404 || r.status === 403, `GET /repos/${owner}/${outside} (not in the token) -> ${r.status}`);
}

step("5a. A scope outside what the org allows fails");
{
  // Turnkey policy gates who, which method and path, and whether a query
  // is present. It cannot express a subset of repositories, so the broker's
  // allowlist enforces the scope (unless policy lists exact queries).
  const outsideScope = async (label: string, r: TokenRequest) => {
    const m = await mintFor(shimUrl, user, org, audience, subject, r);
    if (!m.ok) return expect(m.status === 403, `${label} -> shim ${m.status} ${m.message}`);
    const b = await callBroker(brokerUrl, r, m.jwt);
    expect(b.status === 403 && b.json.error === "scope_not_allowed", `${label} -> policy allowed it; broker ${b.status} ${b.json.error}: ${b.json.message}`);
  };
  await outsideScope("contents:write", await buildTokenRequest({ ...scope, permissions: { ...scope.permissions, contents: "write" } }));
  await outsideScope("extra repository", await buildTokenRequest({ ...scope, repositories: [...scope.repositories, "not-allowed-repo"] }));
  const m = await mintFor(shimUrl, user, org, audience, subject, await buildTokenRequest({ ...scope, installationId: "999" }));
  expect(!m.ok && m.status === 403, `another installation (path) -> ${m.ok ? "minted!" : `shim ${m.status} ${m.message}`}`);
  if (otherUserKey) {
    const other = readKeyFile(otherUserKey);
    const m3 = await mintFor(shimUrl, other, org, audience, await whoami(shimUrl, other, org), await buildTokenRequest(scope));
    expect(!m3.ok && m3.status === 403, `another user -> ${m3.ok ? "minted!" : `shim ${m3.status} ${m3.message}`}`);
  }
}

const extraTokens: string[] = [];
step("5b. Replay of the same request");
{
  const r = await callBroker(brokerUrl, req, minted.jwt);
  expect(r.status === 201, `replay before exp -> ${r.status} (a new token, sealed to the original caller's key)`);
  if (r.status === 201) extraTokens.push(await decryptToken(req, r.json));
}

step("5c. Altered request fails at the broker (descriptor mismatch)");
{
  const fresh = await buildTokenRequest(scope);
  const m = await mintFor(shimUrl, user, org, audience, subject, fresh);
  if (!m.ok) throw new Error(m.message);
  const altered = scopeQuery([...scope.repositories, "other"].sort(), scope.permissions);
  const r = await callBroker(brokerUrl, fresh, m.jwt, { query: altered });
  expect(r.status === 401 && r.json.error === "request_mismatch", `query changed after minting -> ${r.status} ${r.json.error}`);
  const other = await buildTokenRequest(scope);
  const r2 = await callBroker(brokerUrl, fresh, m.jwt, { body: other.body });
  expect(r2.status === 401 && r2.json.error === "request_mismatch", `HPKE key swapped -> ${r2.status} ${r2.json.error}`);
  const r3 = await callBroker(brokerUrl, fresh, m.jwt, { headers: { ...fresh.headers, "x-github-api-version": "2026-03-10" } });
  expect(r3.status === 401 && r3.json.error === "request_mismatch", `bound header changed -> ${r3.status} ${r3.json.error}`);
}

if (process.env.KEEP_TOKEN !== "1") {
  step("6. Revoke the installation tokens");
  for (const t of [token, ...extraTokens]) {
    const r = await gh("/installation/token", "DELETE", t);
    expect(r.status === 204, `DELETE /installation/token -> ${r.status}`);
  }
}

console.log(failures === 0 ? "\nAll demo checks passed." : `\n${failures} demo check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
