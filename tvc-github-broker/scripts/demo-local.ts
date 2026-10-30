/**
 * One-command local demo: Turnkey shim + mock GitHub + broker, then the demo
 * client. `bun run demo:local`
 */
import fs from "node:fs";
import { OWNER, INSTALLATION_ID, ROOT, startStack, type LiveSecrets } from "../tests/harness.ts";

/**
 * `--live-secrets`: export the App key from real Turnkey Secret Storage (the
 * API). MINT_JWT still comes from the local stand-in and GitHub is still the
 * mock. Env: TURNKEY_ORGANIZATION_ID, LIVE_SECRET_ID,
 * TURNKEY_SIGNER_PUBLIC_KEY, LIVE_BROKER_API_KEY (the broker user's key file),
 * APP_PUBLIC_KEY_PEM (public half of the throwaway key), LIVE_KEY_SHA256.
 */
let liveSecrets: LiveSecrets | undefined;
if (process.argv.includes("--live-secrets")) {
  const need = (k: string) => {
    const v = process.env[k];
    if (!v) throw new Error(`--live-secrets needs ${k}`);
    return v;
  };
  liveSecrets = {
    apiBaseUrl: process.env.TURNKEY_API_BASE_URL ?? "https://api.turnkey.com",
    organizationId: need("TURNKEY_ORGANIZATION_ID"),
    secretId: need("LIVE_SECRET_ID"),
    signerPublicKey: need("TURNKEY_SIGNER_PUBLIC_KEY"),
    brokerApiKeyPath: need("LIVE_BROKER_API_KEY"),
    appPublicKeyPem: fs.readFileSync(need("APP_PUBLIC_KEY_PEM"), "utf8"),
    keyFingerprint: need("LIVE_KEY_SHA256"),
  };
}

const s = await startStack({ quiet: process.env.VERBOSE !== "1", liveSecrets });
if (liveSecrets) console.log(`Turnkey     ${liveSecrets.apiBaseUrl} org ${liveSecrets.organizationId} (live Secrets export)`);
console.log(`shim        ${s.shim.url}  (MINT_JWT + Secrets stand-in)`);
console.log(`mock GitHub ${s.github.url}`);
console.log(`broker      ${s.broker.url}  App key exported from secret ${s.secretId} (${s.keyFingerprint})`);
const proc = Bun.spawn(["bun", "client/src/demo.ts"], {
  cwd: ROOT,
  stdout: "inherit",
  stderr: "inherit",
  env: {
    ...process.env,
    SHIM_URL: s.shim.url,
    BROKER_URL: s.broker.url,
    ORG_ID: s.organizationId,
    USER_KEY: s.keys.alice,
    OTHER_USER_KEY: s.keys.bob,
    INSTALLATION_ID,
    REPOS: "demo",
    PERMISSIONS: "contents:read,metadata:read",
    GITHUB_API_BASE: s.github.url,
    GITHUB_OWNER: OWNER,
    OUTSIDE_REPO: "secret-repo",
  },
});
const code = await proc.exited;
console.log(`\nApp JWTs verified by jose in the mock: ${s.github.tokenRequests.length}; revoked tokens: ${s.github.revocations.length}`);
s.stop();
process.exit(code);
