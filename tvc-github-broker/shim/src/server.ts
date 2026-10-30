/**
 * A local stand-in for the Turnkey public API. NOT Turnkey.
 *
 * It serves two activities with Turnkey's wire shapes and API-key stamps:
 *
 * 1. `ACTIVITY_TYPE_MINT_JWT` with profile `JWT_PROFILE_HTTP_AUTHZ_V1`. One
 *    process plays the coordinator (stamp check, destination filter), the
 *    policy engine (intent validation, policy), and the Signer (claims and
 *    ES256 signing). Turnkey splits those across services, and only the
 *    Signer, which holds the quorum key, builds and signs the JWT. The
 *    stand-in's key is a local file.
 *
 * 2. The Secrets API (`INIT_IMPORT_SECRETS`, `IMPORT_SECRETS`,
 *    `EXPORT_SECRETS`, `list_secrets`) with the enclave-encrypt transport,
 *    so the tests run without a Turnkey organization. Secrets are held in
 *    memory only. The same client code runs against real Turnkey with
 *    `--live-secrets`.
 */
import { turnkeyOpen, turnkeySeal, generateRecipient, type RecipientKey } from "../../lib/hpke.ts";
import { type Bytes, b64url, canonicalJson, fromB64url, fromHex, hex, sha256, te, td } from "../../lib/encoding.ts";
import { importVerifyKey, signDer, verifyDer } from "../../lib/p256.ts";
import { evaluate, mintValues, secretValues, type Outcome, type PolicyFile, type Values } from "./policy.ts";
import { ACTIVITY_TYPE, buildClaims, IntentError, TYP, validateIntent } from "./profile.ts";
import { loadState, type LoadedState, type User } from "./state.ts";

type Activity = {
  id: string;
  organizationId: string;
  type: string;
  status: string;
  fingerprint: string;
  timestampMs: string;
  result?: Record<string, unknown>;
  failure?: { message: string };
};

type Secret = { secretId: string; name?: string; staticProperties: Record<string, string>; plaintext: Bytes; createdAtUnixMs: string };

class ApiError extends Error {
  constructor(
    readonly http: number,
    readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

export type ShimOptions = { stateDir: string; port?: number; hostname?: string; log?: (msg: string, data?: unknown) => void };

export type Shim = {
  url: string;
  state: LoadedState;
  stop: () => void;
  setPolicy: (p: PolicyFile) => void;
  /** Mint counters for tests. */
  counters: { mint: number; mintDenied: number; export: number; exportDenied: number };
};

const MAX_SKEW_MS = 5 * 60_000;

export async function startShim(o: ShimOptions): Promise<Shim> {
  const state = await loadState(o.stateDir);
  const log = o.log ?? ((m: string, d?: unknown) => console.log(`[shim] ${m}`, d === undefined ? "" : JSON.stringify(d)));
  const activities = new Map<string, Activity>();
  const byFingerprint = new Map<string, string>();
  const targets = new Map<string, RecipientKey>();
  const secrets = new Map<string, Secret>();
  const counters = { mint: 0, mintDenied: 0, export: 0, exportDenied: 0 };

  async function authenticate(req: Request, body: string): Promise<User> {
    const header = req.headers.get("X-Stamp");
    if (!header) throw new ApiError(401, 16, "missing X-Stamp");
    let stamp: { publicKey: string; scheme: string; signature: string };
    try {
      stamp = JSON.parse(td.decode(fromB64url(header)));
    } catch {
      throw new ApiError(401, 16, "malformed X-Stamp");
    }
    if (stamp.scheme !== "SIGNATURE_SCHEME_TK_API_P256") throw new ApiError(401, 16, "unsupported stamp scheme");
    const user = state.org.users.find((u) => u.apiKeys.some((k) => k.publicKey === stamp.publicKey.toLowerCase()));
    const key = user?.apiKeys.find((k) => k.publicKey === stamp.publicKey.toLowerCase());
    if (!user || !key) throw new ApiError(401, 16, "unknown API key");
    const ok = await verifyDer(await importVerifyKey(key.jwk), fromHex(stamp.signature), te.encode(body));
    if (!ok) throw new ApiError(401, 16, "stamp signature does not verify");
    return user;
  }

  function checkEnvelope(b: any, type: string) {
    if (b?.type !== type) throw new ApiError(400, 3, `expected type ${type}`);
    if (b.organizationId !== state.org.organizationId) throw new ApiError(403, 7, "organization not found or not accessible");
    const ts = Number(b.timestampMs);
    if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > MAX_SKEW_MS) throw new ApiError(400, 3, "timestampMs is not fresh");
  }

  function record(type: string, fingerprint: string, status: string, result?: Record<string, unknown>): Activity {
    const a: Activity = { id: crypto.randomUUID(), organizationId: state.org.organizationId, type, status, fingerprint, timestampMs: String(Date.now()), ...(result ? { result } : {}) };
    activities.set(a.id, a);
    byFingerprint.set(fingerprint, a.id);
    return a;
  }

  function outcomeToActivity(type: string, fp: string, out: Outcome): Activity | undefined {
    if (out.outcome === "DENY") throw new ApiError(403, 7, `policy denied ${type}: ${out.reason}`);
    if (out.outcome === "CONSENSUS_NEEDED") return record(type, fp, "ACTIVITY_STATUS_CONSENSUS_NEEDED");
    return undefined;
  }

  /** Signer enclave signature over a bundle's data, as in ServerTargetMsgV1 / ServerSendMsgV1. */
  async function signedBundle(data: Record<string, unknown>): Promise<string> {
    const bytes = te.encode(JSON.stringify(data));
    return JSON.stringify({
      version: "v1.0.0",
      data: hex(bytes),
      dataSignature: hex(await signDer(state.enclaveKey, bytes)),
      enclaveQuorumPublic: state.enclaveSignerPublicKey,
    });
  }

  async function mintJwt(user: User, b: any, fp: string): Promise<Activity> {
    checkEnvelope(b, ACTIVITY_TYPE);
    const intent: unknown = b.parameters;
    let values: Values;
    let claims: ReturnType<typeof buildClaims>;
    try {
      const now = Math.floor(Date.now() / 1000);
      validateIntent(intent, now);
      values = mintValues(intent);
      // Signer: iss and org come from the organization, never from the intent.
      claims = buildClaims({
        intent,
        organizationId: state.org.organizationId,
        topLevelOrganizationId: state.org.parentOrganizationId ?? state.org.organizationId,
      });
    } catch (e) {
      if (e instanceof IntentError) throw new ApiError(400, 3, `invalid MINT_JWT intent: ${e.message}`);
      throw e;
    }
    if (!state.org.users.some((u) => u.userId === intent.httpAuthzV1.subject)) throw new ApiError(400, 3, "invalid MINT_JWT intent: subject is not a user of the organization");
    // Coordinator admission: default-deny destination filter.
    if (!state.org.allowedAudiences.includes(intent.audience)) throw new ApiError(403, 7, `audience ${intent.audience} is not a registered destination`);
    // Policy.
    const out = evaluate(state.policy, user, values);
    log("mint_jwt policy", { user: user.userName, outcome: out.outcome, policy: "policyName" in out ? out.policyName : undefined });
    if (out.outcome !== "ALLOW") counters.mintDenied++;
    const pending = outcomeToActivity(b.type, fp, out);
    if (pending) return pending;
    const header = { alg: "ES256", kid: state.mintKid, typ: TYP };
    const input = `${b64url(canonicalJson(header))}.${b64url(canonicalJson(claims))}`;
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, state.mintKey, te.encode(input)));
    counters.mint++;
    return record(b.type, fp, "ACTIVITY_STATUS_COMPLETED", { mintJwtResult: { jwt: `${input}.${b64url(sig)}` } });
  }

  async function initImport(user: User, b: any, fp: string): Promise<Activity> {
    checkEnvelope(b, "ACTIVITY_TYPE_INIT_IMPORT_SECRETS");
    if (b.parameters?.encryptionSuite !== "TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V1") throw new ApiError(400, 3, "unsupported encryption suite");
    const n = Number(b.parameters?.numSecrets);
    if (!Number.isInteger(n) || n < 1 || n > 10) throw new ApiError(400, 3, "numSecrets must be 1-10");
    const pending = outcomeToActivity(b.type, fp, evaluate(state.policy, user, { "activity.type": b.type }));
    if (pending) return pending;
    const msgs: string[] = [];
    for (let i = 0; i < n; i++) {
      const t = await generateRecipient();
      targets.set(hex(t.publicKey), t);
      msgs.push(await signedBundle({ targetPublic: hex(t.publicKey), organizationId: state.org.organizationId, userId: user.userId }));
    }
    return record(b.type, fp, "ACTIVITY_STATUS_COMPLETED", { initImportSecretsResult: { enclaveTargetMessages: msgs } });
  }

  async function importSecrets(user: User, b: any, fp: string): Promise<Activity> {
    checkEnvelope(b, "ACTIVITY_TYPE_IMPORT_SECRETS");
    const pending = outcomeToActivity(b.type, fp, evaluate(state.policy, user, { "activity.type": b.type }));
    if (pending) return pending;
    const ids: string[] = [];
    for (const s of b.parameters?.secrets ?? []) {
      const target = targets.get(String(s.targetPublicKey).toLowerCase());
      if (!target) throw new ApiError(400, 3, "unknown or already used ingress target key");
      targets.delete(String(s.targetPublicKey).toLowerCase());
      const payload = JSON.parse(s.secretPayload) as { encappedPublic: string; ciphertext: string };
      let plaintext: Bytes;
      try {
        plaintext = await turnkeyOpen(target, fromHex(payload.encappedPublic), fromHex(payload.ciphertext));
      } catch {
        throw new ApiError(400, 3, "could not decrypt secret payload");
      }
      if (s.name && [...secrets.values()].some((x) => x.name === s.name)) throw new ApiError(400, 3, "secret name already exists");
      const secretId = crypto.randomUUID();
      const staticProperties = Object.fromEntries((s.staticProperties ?? []).map((kv: { key: string; value: string }) => [kv.key, kv.value]));
      secrets.set(secretId, { secretId, name: s.name, staticProperties, plaintext, createdAtUnixMs: String(Date.now()) });
      ids.push(secretId);
      log("import_secrets", { secretId, name: s.name, staticProperties });
    }
    return record(b.type, fp, "ACTIVITY_STATUS_COMPLETED", { importSecretsResult: { secretIds: ids } });
  }

  async function exportSecrets(user: User, b: any, fp: string): Promise<Activity> {
    checkEnvelope(b, "ACTIVITY_TYPE_EXPORT_SECRETS");
    const params = (b.parameters?.secrets ?? []) as { secretId: string; targetPublicKey: string; encryptionSuite: string }[];
    if (params.length === 0) throw new ApiError(400, 3, "no secrets");
    const loaded = params.map((p) => {
      const s = secrets.get(p.secretId);
      if (!s) throw new ApiError(404, 5, `secret ${p.secretId} not found`);
      if (p.encryptionSuite !== "TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V1") throw new ApiError(400, 3, "unsupported encryption suite");
      return { p, s };
    });
    // One policy unit per secret; every unit must allow.
    const outcomes = loaded.map(({ s }) => evaluate(state.policy, user, secretValues(s)));
    const deny = outcomes.find((x) => x.outcome === "DENY");
    const out: Outcome = deny ?? outcomes.find((x) => x.outcome === "CONSENSUS_NEEDED") ?? outcomes[0]!;
    log("export_secrets policy", { user: user.userName, outcome: out.outcome, secrets: params.map((p) => p.secretId) });
    if (out.outcome !== "ALLOW") counters.exportDenied++;
    const pending = outcomeToActivity(b.type, fp, out);
    if (pending) return pending;
    const payloads: string[] = [];
    for (const { p, s } of loaded) {
      const target = fromHex(p.targetPublicKey);
      if (target.length !== 65 || target[0] !== 4) throw new ApiError(400, 3, "targetPublicKey must be an uncompressed P-256 key");
      const { enc, ct } = await turnkeySeal(target, s.plaintext);
      payloads.push(await signedBundle({ encappedPublic: hex(enc), ciphertext: hex(ct), organizationId: state.org.organizationId }));
    }
    counters.export++;
    return record(b.type, fp, "ACTIVITY_STATUS_COMPLETED", { exportSecretsResult: { secretPayloads: payloads } });
  }

  const submit: Record<string, (u: User, b: any, fp: string) => Promise<Activity>> = {
    "/public/v1/submit/mint_jwt": mintJwt,
    "/public/v1/submit/init_import_secrets": initImport,
    "/public/v1/submit/import_secrets": importSecrets,
    "/public/v1/submit/export_secrets": exportSecrets,
  };

  async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "GET" && url.pathname === "/.well-known/jwks.json") return Response.json(state.jwks);
    if (req.method !== "POST") return Response.json({ code: 12, message: "not found" }, { status: 404 });
    const body = await req.text();
    const user = await authenticate(req, body);
    let b: any;
    try {
      b = JSON.parse(body);
    } catch {
      throw new ApiError(400, 3, "body is not JSON");
    }
    const handler = submit[url.pathname];
    if (handler) {
      const fp = "sha256:" + hex(await sha256(body));
      const existing = byFingerprint.get(fp);
      const activity = existing ? activities.get(existing)! : await handler(user, b, fp);
      return Response.json({ activity });
    }
    switch (url.pathname) {
      case "/public/v1/query/get_activity": {
        const a = activities.get(b.activityId);
        if (!a || b.organizationId !== state.org.organizationId) throw new ApiError(404, 5, "activity not found");
        return Response.json({ activity: a });
      }
      case "/public/v1/query/whoami":
        return Response.json({ organizationId: state.org.organizationId, organizationName: state.org.organizationName, userId: user.userId, username: user.userName });
      case "/public/v1/query/list_secrets":
        return Response.json({
          secrets: [...secrets.values()].reverse().map((s) => ({
            secretId: s.secretId,
            ...(s.name ? { name: s.name } : {}),
            staticProperties: Object.entries(s.staticProperties).map(([key, value]) => ({ key, value })),
            createdAtUnixMs: s.createdAtUnixMs,
          })),
        });
    }
    throw new ApiError(404, 12, `unknown endpoint ${url.pathname}`);
  }

  const server = Bun.serve({
    port: o.port ?? 0,
    hostname: o.hostname ?? "127.0.0.1",
    async fetch(req) {
      try {
        return await handle(req);
      } catch (e) {
        if (e instanceof ApiError) {
          log("error", { path: new URL(req.url).pathname, code: e.code, message: e.message });
          return Response.json({ code: e.code, message: e.message, details: [] }, { status: e.http });
        }
        log("internal error", { message: String((e as Error).message) });
        return Response.json({ code: 13, message: "internal error", details: [] }, { status: 500 });
      }
    },
  });

  return {
    url: `http://${server.hostname}:${server.port}`,
    state,
    stop: () => server.stop(true),
    setPolicy: (p) => {
      state.policy = p;
    },
    counters,
  };
}

if (import.meta.main) {
  const dir = process.env.SHIM_STATE_DIR ?? ".shim";
  const port = Number(process.env.SHIM_PORT ?? 8081);
  const shim = await startShim({ stateDir: dir, port });
  console.log(`[shim] local Turnkey shim (MINT_JWT + Secrets) on ${shim.url}`);
  console.log(`[shim] mint signer kid ${shim.state.mintKid}; enclave signer ${shim.state.enclaveSignerPublicKey}`);
}
