/**
 * Client side of MINT_JWT. Builds and stamps the activity with the Turnkey
 * API-key stamper. The organization must allow the user to mint.
 */
import fs from "node:fs";
import { ApiKeyStamper } from "@turnkey/api-key-stamper";
import { ACTIVITY_TYPE, type HttpAuthzV1, PROFILE } from "../../lib/mint.ts";

export type { HttpAuthzV1 };

export type ApiKeyFile = { publicKey: string; privateKey: string };

export function readKeyFile(file: string): ApiKeyFile {
  const d = JSON.parse(fs.readFileSync(file, "utf8"));
  return { publicKey: d.publicKey ?? d.public_key, privateKey: d.privateKey ?? d.private_key };
}

type MintRequest = {
  organizationId: string;
  audience: string;
  httpAuthzV1: HttpAuthzV1;
};

export type MintResult =
  | { ok: true; jwt: string; activityId: string; fingerprint: string }
  | { ok: false; status: number; activityStatus?: string; message: string };

async function submit(baseUrl: string, key: ApiKeyFile, path: string, body: unknown): Promise<{ status: number; json: any }> {
  const text = JSON.stringify(body);
  const stamp = await new ApiKeyStamper({ apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey }).stamp(text);
  const resp = await fetch(baseUrl + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", [stamp.stampHeaderName]: stamp.stampHeaderValue },
    body: text,
  });
  return { status: resp.status, json: await resp.json().catch(() => ({})) };
}

export async function mintJwt(apiBaseUrl: string, key: ApiKeyFile, r: MintRequest): Promise<MintResult> {
  const { status, json } = await submit(apiBaseUrl, key, "/public/v1/submit/mint_jwt", {
    type: ACTIVITY_TYPE,
    timestampMs: String(Date.now()),
    organizationId: r.organizationId,
    parameters: {
      profile: PROFILE,
      audience: r.audience,
      httpAuthzV1: r.httpAuthzV1,
    },
  });
  if (status !== 200) return { ok: false, status, message: json.message ?? `HTTP ${status}` };
  const a = json.activity;
  if (typeof a !== "object" || a === null) throw new Error("mint_jwt: response has no activity");
  if (a.status !== "ACTIVITY_STATUS_COMPLETED") return { ok: false, status, activityStatus: a.status, message: `activity ${a.id} is ${a.status}` };
  const jwt = a.result?.mintJwtResult?.jwt;
  if (typeof jwt !== "string" || jwt === "") throw new Error("mint_jwt: completed activity has no jwt");
  return { ok: true, jwt, activityId: a.id, fingerprint: a.fingerprint };
}

/** The caller's user ID (`whoami`), the usual `subject` of a mint. */
export async function whoami(baseUrl: string, key: ApiKeyFile, organizationId: string): Promise<string> {
  const { status, json } = await submit(baseUrl, key, "/public/v1/query/whoami", { organizationId });
  if (status !== 200) throw new Error(`whoami: ${json.message ?? `HTTP ${status}`}`);
  if (typeof json.userId !== "string" || json.userId === "") throw new Error("whoami: response has no userId");
  return json.userId;
}
