/**
 * Live demo: the broker mints an installation token from a test GitHub App,
 * using the App key stored in Turnkey and a JWT minted by Turnkey.
 *
 * Setup: see the README. Environment:
 *
 *   TURNKEY_API_BASE_URL         default https://api.turnkey.com
 *   TURNKEY_ORGANIZATION_ID      top-level organization that holds the secret
 *   TURNKEY_SIGNER_PUBLIC_KEY    Signer public key (hex) that signs Secrets exports
 *   SECRET_ID                    the imported App key
 *   BROKER_API_KEY_FILE          API key file of the broker's Turnkey user
 *   MINTER_ORGANIZATION_ID       organization the minting user belongs to (default: the top-level one)
 *   MINTER_API_KEY_FILE          API key file of the user who mints the JWT
 *   MINT_JWT_JWKS                JWK Set file with the MINT_JWT signing key to trust
 *   GITHUB_APP_CLIENT_ID, GITHUB_INSTALLATION_ID, GITHUB_OWNER, GITHUB_REPO
 *   GITHUB_APP_KEY_SHA256        optional: the fingerprint GitHub shows for the key
 *
 *   bun scripts/demo.ts
 */
import fs from "node:fs";
import path from "node:path";
import { ROOT, ensureBrokerBuilt, freePort, spawnBroker } from "./broker.ts";

const need = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`missing env ${k}`);
  return v;
};
const repo = need("GITHUB_REPO");
if (repo !== repo.toLowerCase()) throw new Error("GITHUB_REPO must be lowercase");
const installationId = need("GITHUB_INSTALLATION_ID");
const topLevelOrganizationId = need("TURNKEY_ORGANIZATION_ID");
const apiBaseUrl = process.env.TURNKEY_API_BASE_URL ?? "https://api.turnkey.com";

ensureBrokerBuilt();
const dir = path.join(ROOT, ".demo");
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
const port = await freePort();
const audience = `http://127.0.0.1:${port}`;
const configPath = path.join(dir, "broker-config.json");
fs.writeFileSync(
  configPath,
  JSON.stringify(
    {
      audience,
      organization_id: topLevelOrganizationId,
      detailed_auth_errors: true,
      trusted_jwks_path: need("MINT_JWT_JWKS"),
      github: {
        app_client_id: need("GITHUB_APP_CLIENT_ID"),
        ...(process.env.GITHUB_APP_KEY_SHA256 ? { expected_key_sha256: process.env.GITHUB_APP_KEY_SHA256 } : {}),
      },
      turnkey: { api_base_url: apiBaseUrl, organization_id: topLevelOrganizationId, secret_id: need("SECRET_ID"), signer_public_key: need("TURNKEY_SIGNER_PUBLIC_KEY") },
      installations: { [installationId]: { repositories: [repo], permissions: { contents: "read", metadata: "read" } } },
    },
    null,
    2,
  ),
  { mode: 0o600 },
);

const broker = await spawnBroker(configPath, need("BROKER_API_KEY_FILE"), port);
const demo = Bun.spawn(["bun", "client/src/demo.ts"], {
  cwd: ROOT,
  stdout: "inherit",
  stderr: "inherit",
  env: {
    ...process.env,
    TURNKEY_API_BASE_URL: apiBaseUrl,
    TURNKEY_ORGANIZATION_ID: process.env.MINTER_ORGANIZATION_ID ?? topLevelOrganizationId,
    USER_KEY_FILE: need("MINTER_API_KEY_FILE"),
    BROKER_URL: broker.url,
    INSTALLATION_ID: installationId,
    REPOS: repo,
    PERMISSIONS: "contents:read,metadata:read",
  },
});
const code = await demo.exited;
broker.stop();
process.exit(code);
