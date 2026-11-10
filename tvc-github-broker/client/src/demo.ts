/**
 * Demo client. One command:
 *
 * 1. asks Turnkey for an http-authz/v1 JWT for the exact request (subject: the
 *    caller, from whoami);
 * 2. calls the TVC broker with it;
 * 3. decrypts the installation token (HPKE) and checks it with one narrowed
 *    GitHub call;
 * 4. shows a scope outside the allowlist and an altered request failing;
 * 5. revokes the token.
 *
 * Environment: TURNKEY_API_BASE_URL (default https://api.turnkey.com),
 * TURNKEY_ORGANIZATION_ID (the minting user's organization), USER_KEY_FILE,
 * BROKER_URL, AUDIENCE (default BROKER_URL), INSTALLATION_ID, REPOS
 * (comma-separated), PERMISSIONS (comma-separated name:level), GITHUB_OWNER.
 */
import { scopeQuery } from "../../lib/canonical.ts";
import { buildTokenRequest, callBroker, decryptToken, mintFor, type Scope } from "./broker.ts";
import { readKeyFile, whoami } from "./turnkey.ts";

const env = (k: string, d?: string) => {
  const v = process.env[k] ?? d;
  if (v === undefined) throw new Error(`missing env ${k}`);
  return v;
};

const apiBaseUrl = env("TURNKEY_API_BASE_URL", "https://api.turnkey.com");
const org = env("TURNKEY_ORGANIZATION_ID");
const user = readKeyFile(env("USER_KEY_FILE"));
const brokerUrl = env("BROKER_URL");
const audience = env("AUDIENCE", brokerUrl);
const owner = env("GITHUB_OWNER");
const scope: Scope = {
  installationId: env("INSTALLATION_ID"),
  repositories: env("REPOS").split(","),
  permissions: Object.fromEntries(env("PERMISSIONS", "contents:read,metadata:read").split(",").map((p) => p.split(":") as [string, string])),
};
const repoName = scope.repositories[0]!;
const subject = await whoami(apiBaseUrl, user, org);

let failures = 0;
const step = (n: string) => console.log(`\n== ${n}`);
const expect = (ok: boolean, what: string) => {
  console.log(`   ${ok ? "PASS" : "FAIL"}  ${what}`);
  if (!ok) failures++;
};

step(`1. Mint a JWT for POST /v1/installations/${scope.installationId}/tokens?${scopeQuery(scope.repositories, scope.permissions)}`);
const req = await buildTokenRequest(scope);
const minted = await mintFor(apiBaseUrl, user, org, audience, subject, req);
if (!minted.ok) {
  console.error(`   mint failed: ${minted.message}`);
  process.exit(1);
}
const claims = JSON.parse(Buffer.from(minted.jwt.split(".")[1]!, "base64url").toString());
console.log(`   activity ${minted.activityId}; iss ${claims.iss}; org ${claims.org}; sub ${claims.sub}`);

step("2. Call the TVC broker with the JWT");
const resp = await callBroker(brokerUrl, req, minted.jwt);
expect(resp.status === 201, `broker returned ${resp.status} ${resp.status === 201 ? "" : JSON.stringify(resp.json)}`);
if (resp.status !== 201) process.exit(1);

step("3. Decrypt the token and make one narrowed GitHub call");
const token = await decryptToken(req, resp.json);
const gh = (path: string, method = "GET") =>
  fetch(`https://api.github.com${path}`, { method, headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "tvc-github-broker" } });
try {
  const repo = await gh(`/repos/${owner}/${repoName}`);
  expect(repo.status === 200, `GET /repos/${owner}/${repoName} -> ${repo.status}`);

  step("4. A scope outside the allowlist, and an altered request, fail");
  const wider = await buildTokenRequest({ ...scope, permissions: { ...scope.permissions, contents: "write" } });
  const widerJwt = await mintFor(apiBaseUrl, user, org, audience, subject, wider);
  if (widerJwt.ok) {
    const r = await callBroker(brokerUrl, wider, widerJwt.jwt);
    expect(r.status === 403 && r.json.error === "scope_not_allowed", `contents:write -> ${r.status} ${r.json.error}`);
  }
  const altered = await callBroker(brokerUrl, req, minted.jwt, { query: scopeQuery([...scope.repositories, "other"].sort(), scope.permissions) });
  expect(altered.status === 401, `query changed after minting -> ${altered.status} ${altered.json.error}`);
} finally {
  step("5. Revoke the installation token");
  const revoked = await gh("/installation/token", "DELETE");
  expect(revoked.status === 204, `DELETE /installation/token -> ${revoked.status}`);
}

console.log(failures === 0 ? "\nAll demo checks passed." : `\n${failures} demo check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
