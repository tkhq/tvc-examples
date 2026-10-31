/**
 * Client for the TVC broker: build the exact request, mint a JWT for it,
 * call the broker, decrypt the token.
 */
import { scopeQuery } from "../../lib/canonical.ts";
import { sha256Digest } from "../../lib/digest.ts";
import { type Bytes, b64url, fromB64url, sha256, te, td } from "../../lib/encoding.ts";
import { headerDigests } from "../../lib/headers.ts";
import { DELIVERY_INFO, generateRecipient, open, type RecipientKey } from "../../lib/hpke.ts";
import { mintJwt, type ApiKeyFile, type HttpAuthzV1, type MintResult } from "./turnkey.ts";

export type Scope = { installationId: string; repositories: string[]; permissions: Record<string, string> };

/**
 * Headers the broker's token route requires to be bound. The client sends
 * each once, exactly as listed, so the value it hashes is the value the
 * broker rebuilds. (fetch joins repeated values into one line with ", ",
 * which hashes the same as separate lines.)
 */
const BOUND_HEADERS: Record<string, string> = {
  accept: "application/vnd.github+json",
  "x-github-api-version": "2022-11-28",
};

type TokenRequest = {
  method: "POST";
  path: string;
  query: string;
  /** Bound headers, sent as-is. */
  headers: Record<string, string>;
  headerNames: string[];
  headerDigests: string[];
  body: Bytes;
  bodyDigest: string;
  recipient: RecipientKey;
};

/** Default token lifetime the client asks for. The profile allows up to 300 s. */
const DEFAULT_TTL_SECS = 60;

export async function buildTokenRequest(scope: Scope, headers: Record<string, string> = BOUND_HEADERS): Promise<TokenRequest> {
  const recipient = await generateRecipient();
  const body = te.encode(JSON.stringify({ hpke_public_key: b64url(recipient.publicKey) }));
  const headerNames = Object.keys(headers).map((n) => n.toLowerCase());
  return {
    method: "POST",
    path: `/v1/installations/${scope.installationId}/tokens`,
    query: scopeQuery(scope.repositories, scope.permissions),
    headers,
    headerNames,
    headerDigests: await headerDigests(headerNames, Object.entries(headers)),
    body,
    bodyDigest: await sha256Digest(body),
    recipient,
  };
}

/** The `httpAuthzV1` intent for a request. */
function intentFor(r: TokenRequest, subject: string, ttl = DEFAULT_TTL_SECS): HttpAuthzV1 {
  return {
    method: r.method,
    path: r.path,
    query: r.query,
    headerNames: r.headerNames,
    headerDigest: r.headerDigests,
    bodyDigest: r.bodyDigest,
    subject,
    timeToLiveSeconds: String(ttl),
    issuedAt: String(Math.floor(Date.now() / 1000)),
  };
}

export function mintFor(apiBaseUrl: string, key: ApiKeyFile, organizationId: string, audience: string, subject: string, r: TokenRequest, ttl?: number): Promise<MintResult> {
  return mintJwt(apiBaseUrl, key, { organizationId, audience, httpAuthzV1: intentFor(r, subject, ttl) });
}

type BrokerResponse ={ status: number; json: any };

export async function callBroker(
  brokerUrl: string,
  r: TokenRequest,
  jwt: string,
  overrides: { path?: string; query?: string; body?: Bytes; headers?: Record<string, string> } = {},
): Promise<BrokerResponse> {
  const q = overrides.query ?? r.query;
  const resp = await fetch(`${brokerUrl}${overrides.path ?? r.path}${q ? `?${q}` : ""}`, {
    method: r.method,
    headers: { ...(overrides.headers ?? r.headers), Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
    body: overrides.body ?? r.body,
  });
  return { status: resp.status, json: await resp.json().catch(() => ({})) };
}

/** Decrypt the sealed token and check its hash. aad is the request's body digest (the JWT's tk_body_digest). */
export async function decryptToken(r: TokenRequest, json: unknown): Promise<string> {
  const { encrypted_token: e, token_sha256 } = (json ?? {}) as { encrypted_token?: { encapsulated_key?: unknown; ciphertext?: unknown }; token_sha256?: unknown };
  if (typeof e?.encapsulated_key !== "string" || typeof e.ciphertext !== "string" || typeof token_sha256 !== "string") throw new Error("broker response has no encrypted_token");
  const pt = await open(r.recipient, fromB64url(e.encapsulated_key), fromB64url(e.ciphertext), DELIVERY_INFO, te.encode(r.bodyDigest));
  const token = td.decode(pt);
  const digest = Buffer.from(await sha256(token)).toString("base64");
  if (digest !== token_sha256) throw new Error("token_sha256 does not match the decrypted token");
  return token;
}
