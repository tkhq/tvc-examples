/**
 * Live GitHub demo: the broker mints a real installation token from a real
 * (test) GitHub App. MINT_JWT still comes from the shim.
 *
 * The App key reaches the broker only through a Secrets export:
 * - default: this script imports the PEM into the local shim's Secrets API
 *   (the PEM is read by this process only and never printed);
 * - `--live-secrets`: the key is already in real Turnkey (see README); set
 *   TURNKEY_ORGANIZATION_ID, LIVE_SECRET_ID, TURNKEY_SIGNER_PUBLIC_KEY,
 *   LIVE_BROKER_API_KEY, and optionally TURNKEY_API_BASE_URL.
 *
 * Required env:
 *   GITHUB_APP_CLIENT_ID    App client ID (Iv23li...) or numeric App ID
 *   GITHUB_INSTALLATION_ID  installation ID on the test account
 *   GITHUB_OWNER            test account or org login
 *   GITHUB_REPO             the one test repository (lowercase)
 *   GITHUB_APP_PEM          path to the downloaded PEM (not needed with --live-secrets)
 *
 *   bun scripts/demo-github.ts [--live-secrets]
 */
import fs from "node:fs";
import path from "node:path";
import { Turnkey } from "@turnkey/sdk-server";
import { importAppKey, keyFingerprint } from "../admin/src/appkey.ts";
import { readApiKeyFile } from "../admin/src/turnkey.ts";
import { startShim } from "../shim/src/server.ts";
import { initState } from "../shim/src/state.ts";
import { ROOT, ensureBrokerBuilt, freePort, spawnBroker } from "../tests/harness.ts";

const need = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`missing env ${k}`);
  return v;
};
const live = process.argv.includes("--live-secrets");
const clientId = need("GITHUB_APP_CLIENT_ID");
const installationId = need("GITHUB_INSTALLATION_ID");
const owner = need("GITHUB_OWNER");
const repo = need("GITHUB_REPO");
if (repo !== repo.toLowerCase()) throw new Error("GITHUB_REPO must be lowercase (GitHub matches names without case; the broker requires lowercase)");

ensureBrokerBuilt();
const dir = path.join(ROOT, ".demo", "github");
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
const stateDir = path.join(dir, "shim");
const port = await freePort();
const audience = `http://127.0.0.1:${port}`;
await initState({ dir: stateDir, audience, installationId, repositories: [repo], permissions: ["contents:read", "metadata:read"] });
const shim = await startShim({ stateDir });
const org = shim.state.org.organizationId;

let turnkey: Record<string, string>;
let brokerKey: string;
let fingerprint: string;
if (live) {
  turnkey = {
    api_base_url: process.env.TURNKEY_API_BASE_URL ?? "https://api.turnkey.com",
    organization_id: need("TURNKEY_ORGANIZATION_ID"),
    secret_id: need("LIVE_SECRET_ID"),
    signer_public_key: need("TURNKEY_SIGNER_PUBLIC_KEY"),
  };
  brokerKey = need("LIVE_BROKER_API_KEY");
  fingerprint = process.env.LIVE_KEY_SHA256 ?? "";
} else {
  const pemPath = need("GITHUB_APP_PEM");
  fingerprint = keyFingerprint(fs.readFileSync(pemPath, "utf8"));
  const root = readApiKeyFile(path.join(stateDir, "keys/root.json"));
  const client = new Turnkey({ apiBaseUrl: shim.url, apiPublicKey: root.publicKey, apiPrivateKey: root.privateKey, defaultOrganizationId: org }).apiClient();
  const { secretId } = await importAppKey({ client, organizationId: org, pemPath, appClientId: clientId, signerPublicKey: shim.state.enclaveSignerPublicKey });
  turnkey = { api_base_url: shim.url, organization_id: org, secret_id: secretId, signer_public_key: shim.state.enclaveSignerPublicKey };
  brokerKey = path.join(stateDir, "keys/broker.json");
}
console.log(`App key fingerprint ${fingerprint || "(not checked)"}: compare with the one in the GitHub App settings.`);

const topLevelOrganizationId = shim.state.org.parentOrganizationId;
if (topLevelOrganizationId === undefined) {
  shim.stop();
  throw new Error("shim org has no parentOrganizationId; the broker config needs organization_id");
}
const jwksPath = path.join(dir, "jwks.json");
fs.writeFileSync(jwksPath, JSON.stringify(shim.state.jwks));
const configPath = path.join(dir, "broker-config.json");
fs.writeFileSync(
  configPath,
  JSON.stringify(
    {
      audience,
      organization_id: topLevelOrganizationId,
      detailed_auth_errors: true,
      trusted_jwks_path: jwksPath,
      github: { api_base_url: "https://api.github.com", app_client_id: clientId, ...(fingerprint ? { expected_key_sha256: fingerprint } : {}) },
      turnkey,
      installations: { [installationId]: { repositories: [repo], permissions: { contents: "read", metadata: "read" } } },
    },
    null,
    2,
  ),
);
const started = await spawnBroker(configPath, brokerKey, port, false);
if (!started.broker) {
  shim.stop();
  throw new Error(`broker did not start (exit ${started.exitCode})`);
}
const proc = Bun.spawn(["bun", "client/src/demo.ts"], {
  cwd: ROOT,
  stdout: "inherit",
  stderr: "inherit",
  env: {
    ...process.env,
    SHIM_URL: shim.url,
    BROKER_URL: started.broker.url,
    ORG_ID: org,
    USER_KEY: path.join(stateDir, "keys/alice.json"),
    OTHER_USER_KEY: path.join(stateDir, "keys/bob.json"),
    INSTALLATION_ID: installationId,
    REPOS: repo,
    PERMISSIONS: "contents:read,metadata:read",
    GITHUB_API_BASE: "https://api.github.com",
    GITHUB_OWNER: owner,
  },
});
const code = await proc.exited;
started.broker.stop();
shim.stop();
process.exit(code);
