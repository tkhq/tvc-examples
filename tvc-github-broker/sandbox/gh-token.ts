/**
 * Print a narrowed GitHub installation token from the TVC broker on stdout.
 * Logs go to stderr. Uses the same environment as client/src/demo.ts:
 * TURNKEY_API_BASE_URL (default https://api.turnkey.com), TURNKEY_ORGANIZATION_ID,
 * USER_KEY_FILE, BROKER_URL, AUDIENCE (default BROKER_URL), INSTALLATION_ID,
 * REPOS (comma-separated), PERMISSIONS (comma-separated name:level).
 */
import { buildTokenRequest, callBroker, decryptToken, mintFor, type Scope } from "../client/src/broker.ts";
import { readKeyFile, whoami } from "../client/src/turnkey.ts";

const env = (k: string, d?: string) => {
  const v = process.env[k] ?? d;
  if (v === undefined) throw new Error(`missing env ${k}`);
  return v;
};

const apiBaseUrl = env("TURNKEY_API_BASE_URL", "https://api.turnkey.com");
const org = env("TURNKEY_ORGANIZATION_ID");
const user = readKeyFile(env("USER_KEY_FILE"));
const brokerUrl = env("BROKER_URL");
const scope: Scope = {
  installationId: env("INSTALLATION_ID"),
  repositories: env("REPOS").split(","),
  permissions: Object.fromEntries(env("PERMISSIONS", "contents:read,metadata:read").split(",").map((p) => p.split(":") as [string, string])),
};

const req = await buildTokenRequest(scope);
const minted = await mintFor(apiBaseUrl, user, org, env("AUDIENCE", brokerUrl), await whoami(apiBaseUrl, user, org), req);
if (!minted.ok) {
  console.error(`mint failed: ${minted.message}`);
  process.exit(1);
}
const resp = await callBroker(brokerUrl, req, minted.jwt);
if (resp.status !== 201) {
  console.error(`broker refused: ${resp.status} ${JSON.stringify(resp.json)}`);
  process.exit(1);
}
console.error(`token for installation ${scope.installationId}: repos=${scope.repositories.join(",")} permissions=${JSON.stringify(scope.permissions)}`);
process.stdout.write(await decryptToken(req, resp.json));
