/**
 * Read-only probe: does the Secrets API work for this organization?
 * Runs whoami, list_secrets, and init_import_secrets (which only mints a
 * single-use ingress key). Prints the enclave signer public key so the app can
 * pin it. Prints no key material.
 */
import { client, requireEnv, DEFAULT_API_BASE_URL } from "./turnkey.ts";

const org = requireEnv("TURNKEY_ORGANIZATION_ID");
const base = process.env.TURNKEY_API_BASE_URL ?? DEFAULT_API_BASE_URL;
const c = client(requireEnv("TURNKEY_API_KEY_FILE"), org, base);
const out = (k: string, v: unknown) => console.log(k, JSON.stringify(v));
out("env", { base, org });
const who = await c.getWhoami({ organizationId: org });
out("whoami", { userId: who.userId, username: who.username, orgName: who.organizationName });
try {
  const secrets = await c.getSecrets({ organizationId: org });
  out("listSecrets", { count: secrets.length, names: secrets.map((s) => s.name) });
} catch (e) {
  out("listSecrets.error", String((e as Error).message).slice(0, 400));
}
try {
  const init = await (c as any).command(
    "/public/v1/submit/init_import_secrets",
    {
      type: "ACTIVITY_TYPE_INIT_IMPORT_SECRETS",
      timestampMs: String(Date.now()),
      organizationId: org,
      parameters: { encryptionSuite: "TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V1", numSecrets: 1 },
    },
    "initImportSecretsResult",
  );
  const bundle = init?.enclaveTargetMessages?.[0];
  const outer = bundle ? JSON.parse(bundle) : null;
  out("initImport", { status: init?.activity?.status, enclaveQuorumPublic: outer?.enclaveQuorumPublic });
} catch (e) {
  out("initImport.error", String((e as Error).message).slice(0, 400));
}
