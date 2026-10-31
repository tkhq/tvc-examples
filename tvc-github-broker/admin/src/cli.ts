/**
 * Admin tool for a Turnkey organization.
 *
 * Environment: TURNKEY_ORGANIZATION_ID, TURNKEY_API_KEY_FILE (an admin or root
 * API key, read only by this process), TURNKEY_API_BASE_URL (default
 * https://api.turnkey.com), and TURNKEY_SIGNER_PUBLIC_KEY (hex; needed outside
 * production, where the SDK's pinned production key does not apply).
 *
 * Commands:
 *   gen-test-key --out <pem>                     throwaway RSA-2048 PKCS#1 (never a real App key)
 *   import-app-key --pem <pem> --app-client-id <id> [--name <n>]
 *   create-broker-user (--public-key <hex> | --out <keyfile>) [--name <n>]
 *   create-export-policy --broker-user-id <id>
 *   list-secrets
 *   probe
 */
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { Turnkey } from "@turnkey/sdk-server";
import { generateApiKey } from "../../lib/p256.ts";
import { exportPolicy, generateThrowawayPem, importAppKey, keyFingerprint, SECRET_SCHEMA } from "./appkey.ts";
import { DEFAULT_API_BASE_URL, readApiKeyFile, requireEnv } from "./turnkey.ts";

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    out: { type: "string" },
    pem: { type: "string" },
    "app-client-id": { type: "string" },
    name: { type: "string" },
    "broker-user-id": { type: "string" },
    "public-key": { type: "string" },
  },
});

async function connect() {
  const organizationId = requireEnv("TURNKEY_ORGANIZATION_ID");
  const apiBaseUrl = process.env.TURNKEY_API_BASE_URL ?? DEFAULT_API_BASE_URL;
  const k = readApiKeyFile(requireEnv("TURNKEY_API_KEY_FILE"));
  const client = new Turnkey({ apiBaseUrl, apiPublicKey: k.publicKey, apiPrivateKey: k.privateKey, defaultOrganizationId: organizationId }).apiClient();
  return { client, organizationId, apiBaseUrl, signerPublicKey: process.env.TURNKEY_SIGNER_PUBLIC_KEY };
}

const need = (k: keyof typeof values) => {
  const v = values[k];
  if (typeof v !== "string" || !v) throw new Error(`--${k} is required`);
  return v;
};
const print = (v: unknown) => console.log(JSON.stringify(v, null, 2));

switch (positionals[0]) {
  case "gen-test-key": {
    const out = need("out");
    const { pem, publicSpkiPem } = generateThrowawayPem();
    fs.writeFileSync(out, pem, { mode: 0o600 });
    fs.writeFileSync(`${out}.pub`, publicSpkiPem);
    print({ wrote: out, publicKey: `${out}.pub`, fingerprint: keyFingerprint(pem), note: "throwaway test key; not registered with GitHub" });
    break;
  }
  case "import-app-key": {
    const c = await connect();
    const r = await importAppKey({ client: c.client, organizationId: c.organizationId, pemPath: need("pem"), appClientId: need("app-client-id"), name: values.name, signerPublicKey: c.signerPublicKey });
    print({ api: c.apiBaseUrl, organizationId: c.organizationId, ...r, staticProperties: { "demo:schema": SECRET_SCHEMA,"github:app_client_id": values["app-client-id"], "github:key_sha256": r.fingerprint } });
    console.error("Delete the PEM file now if it is a real App key. Compare the fingerprint with the one GitHub shows.");
    break;
  }
  case "create-broker-user": {
    const c = await connect();
    // In an enclave the broker derives its API key from the quorum seed, so
    // register the public key it prints. Otherwise make a key file for local runs.
    const registered = values["public-key"];
    const k = registered ? undefined : await generateApiKey();
    const publicKey = registered ?? k!.publicKey;
    const res = await c.client.createUsers({
      organizationId: c.organizationId,
      users: [
        {
          userName: values.name ?? `tvc-github-broker-${Date.now().toString(36)}`,
          apiKeys: [{ apiKeyName: "tvc-broker", publicKey, curveType: "API_KEY_CURVE_P256" }],
          authenticators: [],
          oauthProviders: [],
          userTags: [],
        },
      ],
    } as any);
    let keyFile: string | undefined;
    if (k) {
      keyFile = need("out");
      fs.mkdirSync(path.dirname(keyFile), { recursive: true });
      fs.writeFileSync(keyFile, JSON.stringify({ publicKey: k.publicKey, privateKey: k.privateKey }, null, 2) + "\n", { mode: 0o600 });
    }
    print({ organizationId: c.organizationId, userId: (res as any).userIds?.[0], apiPublicKey: publicKey, keyFile, activityId: (res as any).activity?.id });
    break;
  }
  case "create-export-policy": {
    const c = await connect();
    const res = await c.client.createPolicy({ organizationId: c.organizationId, ...exportPolicy(need("broker-user-id")) });
    print({ policyId: (res as any).policyId, activityId: (res as any).activity?.id, status: (res as any).activity?.status });
    break;
  }
  case "list-secrets": {
    const c = await connect();
    print(await c.client.getSecrets({ organizationId: c.organizationId }));
    break;
  }
  case "probe":
    await import("./probe.ts");
    break;
  default:
    console.error("usage: bun admin/src/cli.ts gen-test-key|import-app-key|create-broker-user|create-export-policy|list-secrets|probe");
    process.exit(2);
}
