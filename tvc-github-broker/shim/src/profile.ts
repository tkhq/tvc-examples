/**
 * Local stand-in for the http-authz/v1 profile of `MINT_JWT`.
 *
 * In Turnkey, validation runs before policy and the claims are built inside
 * the Signer enclave. Here `validateIntent` and `buildClaims` do both so the
 * demo and its tests run without a Turnkey organization.
 */
import { isDigest } from "../../lib/digest.ts";
import { checkHeaderNames, TCHAR_SYMBOLS } from "../../lib/headers.ts";
import { type HttpAuthzV1, PROFILE } from "../../lib/mint.ts";

export { ACTIVITY_TYPE, PROFILE } from "../../lib/mint.ts";

export const TYP = "application/vnd.turnkey.http-authz-v1+jwt";
const MAX_TTL_SECS = 300;
const ORG_URN_PREFIX = "urn:turnkey:org:";
const USER_URN_PREFIX = "urn:turnkey:user:";

/** `MintJwtIntent`, JSON form. */
export type MintJwtIntent = {
  profile: typeof PROFILE;
  audience: string;
  httpAuthzV1: HttpAuthzV1;
};

export class IntentError extends Error {}

const INTENT_KEYS = ["profile", "audience", "httpAuthzV1"];
const PROFILE_KEYS = ["method", "path", "query", "headerNames", "headerDigest", "bodyDigest", "subject", "timeToLiveSeconds", "issuedAt"];
const MAX_PATH = 2048;
const MAX_QUERY = 2048;
const MAX_ISSUED_AT_SKEW_SECS = 24 * 60 * 60;
const ISSUER_PREFIX = "https://id.turnkey.com/t/";
const DECIMAL = /^[0-9]{1,18}$/;
const VISIBLE = /^[\x21-\x7e]*$/;
const METHOD = new RegExp(`^[${TCHAR_SYMBOLS}0-9A-Z]{1,32}$`);

/**
 * Exact canonical HTTPS origin. DEVIATION: the shim also accepts http on
 * loopback so the demo runs without TLS.
 */
export function isCanonicalOrigin(s: string): boolean {
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return false;
  }
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname);
  if (!(u.protocol === "https:" || (u.protocol === "http:" && loopback))) return false;
  if (u.username || u.password || u.search || u.hash) return false;
  // URL normalizes; the canonical form must round-trip exactly (lowercase host, no default port, no path).
  return u.origin === s;
}

function closed(o: unknown, keys: string[], what: string): Record<string, unknown> {
  if (o === null || typeof o !== "object" || Array.isArray(o)) throw new IntentError(`${what} must be an object`);
  const rec = o as Record<string, unknown>;
  for (const k of Object.keys(rec)) if (!keys.includes(k)) throw new IntentError(`unknown ${what} field ${k}`);
  for (const k of keys) if (rec[k] === undefined || rec[k] === null) throw new IntentError(`missing ${what} field ${k}`);
  return rec;
}

function str(v: unknown, name: string): string {
  if (typeof v !== "string") throw new IntentError(`${name} must be a string`);
  return v;
}

function strings(v: unknown, name: string): string[] {
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) throw new IntentError(`${name} must be an array of strings`);
  return v;
}

/**
 * Validate an intent against the rules the minter owns. `subject` must also
 * be a user of the organization; the caller checks that (it needs the org).
 */
export function validateIntent(intent: unknown, now: number): asserts intent is MintJwtIntent {
  const i = closed(intent, INTENT_KEYS, "intent");
  if (i.profile !== PROFILE) throw new IntentError(`unknown profile ${String(i.profile)}`);
  if (!isCanonicalOrigin(str(i.audience, "audience"))) throw new IntentError("audience must be an exact canonical HTTPS origin");
  const p = closed(i.httpAuthzV1, PROFILE_KEYS, "httpAuthzV1");
  if (!METHOD.test(str(p.method, "method"))) throw new IntentError("method must be an uppercase HTTP method token");
  const path = str(p.path, "path");
  if (!path.startsWith("/") || path.length > MAX_PATH || !VISIBLE.test(path) || /[?#]/.test(path)) {
    throw new IntentError(`path must be an absolute request path of at most ${MAX_PATH} visible ASCII characters, without ? or #`);
  }
  const query = str(p.query, "query");
  if (query.length > MAX_QUERY || !VISIBLE.test(query) || query.startsWith("?") || query.includes("#")) {
    throw new IntentError(`query must be the raw query (no leading ?, no #) of at most ${MAX_QUERY} visible ASCII characters`);
  }
  const names = strings(p.headerNames, "headerNames");
  const digests = strings(p.headerDigest, "headerDigest");
  try {
    checkHeaderNames(names);
  } catch (e) {
    throw new IntentError(`headerNames: ${(e as Error).message}`);
  }
  if (digests.length !== names.length) throw new IntentError("headerNames and headerDigest must have the same length");
  digests.forEach((d, n) => {
    if (!isDigest(d)) throw new IntentError(`headerDigest[${n}] must be sha-256=:<padded base64>:`);
  });
  const body = str(p.bodyDigest, "bodyDigest");
  if (body !== "" && !isDigest(body)) throw new IntentError("bodyDigest must be empty or sha-256=:<padded base64>:");
  const subject = str(p.subject, "subject");
  if (subject === "" || subject.length > 128 || !VISIBLE.test(subject)) throw new IntentError("subject must be a user ID");
  const ttl = str(p.timeToLiveSeconds, "timeToLiveSeconds");
  if (!DECIMAL.test(ttl) || Number(ttl) < 1 || Number(ttl) > MAX_TTL_SECS) {
    throw new IntentError(`timeToLiveSeconds must be a decimal string from 1 to ${MAX_TTL_SECS}`);
  }
  const issuedAt = str(p.issuedAt, "issuedAt");
  if (!DECIMAL.test(issuedAt)) throw new IntentError("issuedAt must be a decimal Unix timestamp in seconds");
  if (Math.abs(Number(issuedAt) - now) > MAX_ISSUED_AT_SKEW_SECS) throw new IntentError("issuedAt must be within 24 hours of the current time");
}

/**
 * Build the wire claims. `iss` names the top-level organization and `org` the
 * organization that minted the token; both come from authenticated context,
 * never from the intent. The same intent always yields the same claims.
 */
export function buildClaims(p: { intent: MintJwtIntent; organizationId: string; topLevelOrganizationId: string }) {
  const a = p.intent.httpAuthzV1;
  const iat = Number(a.issuedAt);
  const claims: Record<string, unknown> = {
    aud: p.intent.audience,
    exp: iat + Number(a.timeToLiveSeconds),
    iat,
    iss: ISSUER_PREFIX + p.topLevelOrganizationId,
    org: ORG_URN_PREFIX + p.organizationId,
    sub: USER_URN_PREFIX + a.subject,
    tk_request: {
      method: a.method,
      path: a.path,
      query: a.query,
      ...(a.headerNames.length > 0 ? { headers: a.headerNames } : {}),
    },
    ...(a.headerNames.length > 0 ? { tk_header_digest: a.headerDigest } : {}),
    ...(a.bodyDigest !== "" ? { tk_body_digest: a.bodyDigest } : {}),
  };
  return claims;
}
