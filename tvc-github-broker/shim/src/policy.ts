/**
 * A small stand-in for Turnkey policy evaluation.
 *
 * A policy file mirrors Turnkey policies: `effect`, a `condition`, and a
 * `consensus`. Real Turnkey policies are expressions; the shim uses a JSON
 * form of the same shape and keeps the real expression next to it in
 * `turnkeyCondition` / `turnkeyConsensus` for readers.
 *
 * Condition keys are policy value names:
 * - `activity.type`
 * - `activity.params.profile`, `activity.params.audience`,
 *   `activity.params.httpAuthzV1.<field>` (MINT_JWT projection: `method`,
 *   `path`, `query`, and `subject` as strings, `headerNames` as a list; no
 *   digests)
 * - `secret.id`, `secret.static_properties['<name>']` (Secrets export)
 * - `http.query['<param>']`: FUTURE POLICY-LANGUAGE EXTENSION, NOT IN
 *   TURNKEY POLICY TODAY (a parsed query subset matcher). The list of every
 *   percent-decoded value of that repeated query parameter. The default demo
 *   policy does not use it; see `futureQuerySubsetPolicy` in state.ts.
 *
 * Matchers (string comparison): `{"eq": s}`, `{"ne": s}`, `{"in": [..]}`.
 * List values (`headerNames` and the FUTURE `http.query[...]` lists) match
 * only `{"subsetOf": [..]}` and `{"containsAny": [..]}`. A missing value
 * never matches.
 *
 * Evaluation: an explicit DENY that matches wins. Otherwise an ALLOW whose
 * condition matches and whose consensus is met allows. An ALLOW that matches
 * but needs more approvers gives CONSENSUS_NEEDED. Otherwise DENY. Root users
 * bypass policy, as a root quorum does in Turnkey.
 */
import { queryPairs } from "../../lib/canonical.ts";
import { ACTIVITY_TYPE, IntentError, type MintJwtIntent } from "./profile.ts";

export type Matcher = { eq: string } | { ne: string } | { in: string[] } | { subsetOf: string[] } | { containsAny: string[] };
export type Policy = {
  policyName: string;
  effect: "EFFECT_ALLOW" | "EFFECT_DENY";
  /** `anyOf`: the proposer alone satisfies it if listed. `allOf`: every listed user must approve. */
  consensus?: { anyOf: string[] } | { allOf: string[] };
  condition: Record<string, Matcher>;
  turnkeyCondition?: string;
  turnkeyConsensus?: string;
  notes?: string;
};
export type PolicyFile = { policies: Policy[] };
export type Values = Record<string, string | string[] | undefined>;
export type Outcome =
  | { outcome: "ALLOW"; policyName: string }
  | { outcome: "CONSENSUS_NEEDED"; policyName: string }
  | { outcome: "DENY"; policyName?: string; reason: string };

function matches(m: Matcher, v: string | string[] | undefined): boolean {
  if (v === undefined) return false;
  const list = Array.isArray(v) ? v : [v];
  if ("eq" in m) return !Array.isArray(v) && v === m.eq;
  if ("ne" in m) return !Array.isArray(v) && v !== m.ne;
  if ("in" in m) return !Array.isArray(v) && m.in.includes(v);
  if ("subsetOf" in m) return list.length > 0 && list.every((x) => m.subsetOf.includes(x));
  if ("containsAny" in m) return list.some((x) => m.containsAny.includes(x));
  return false;
}

function conditionMatches(p: Policy, values: Values): boolean {
  return Object.entries(p.condition).every(([k, m]) => matches(m, values[k]));
}

export function evaluate(file: PolicyFile, proposer: { userId: string; isRoot: boolean }, values: Values): Outcome {
  if (proposer.isRoot) return { outcome: "ALLOW", policyName: "(root quorum)" };
  const deny = file.policies.find((p) => p.effect === "EFFECT_DENY" && conditionMatches(p, values));
  if (deny) return { outcome: "DENY", policyName: deny.policyName, reason: `explicit deny: ${deny.policyName}` };
  let needsConsensus: Policy | undefined;
  for (const p of file.policies) {
    if (p.effect !== "EFFECT_ALLOW" || !conditionMatches(p, values)) continue;
    const c = p.consensus;
    if (!c) return { outcome: "ALLOW", policyName: p.policyName };
    if ("anyOf" in c && c.anyOf.includes(proposer.userId)) return { outcome: "ALLOW", policyName: p.policyName };
    if ("allOf" in c) {
      if (c.allOf.length === 1 && c.allOf[0] === proposer.userId) return { outcome: "ALLOW", policyName: p.policyName };
      if (c.allOf.includes(proposer.userId)) needsConsensus ??= p;
    }
  }
  if (needsConsensus) return { outcome: "CONSENSUS_NEEDED", policyName: needsConsensus.policyName };
  return { outcome: "DENY", reason: "no ALLOW policy matched (default deny)" };
}

/** The intent fields policy may see. Digests and the TTL are not projected. */
const PROJECTED_FIELDS = ["method", "path", "query", "headerNames", "subject"] as const;

/**
 * Policy values for a MINT_JWT intent, plus the FUTURE `http.query[...]`
 * extension (not in Turnkey policy today).
 */
export function mintValues(intent: MintJwtIntent): Values {
  const v: Values = {
    "activity.type": ACTIVITY_TYPE,
    "activity.params.profile": intent.profile,
    "activity.params.audience": intent.audience,
  };
  for (const k of PROJECTED_FIELDS) v[`activity.params.httpAuthzV1.${k}`] = intent.httpAuthzV1[k];
  // FUTURE extension: each repeated parameter as a list.
  let pairs: [string, string][];
  try {
    pairs = queryPairs(intent.httpAuthzV1.query);
  } catch {
    throw new IntentError("query is not a parseable query");
  }
  const lists: Record<string, string[]> = Object.create(null);
  for (const [k, val] of pairs) (lists[k] ??= []).push(val);
  for (const [k, list] of Object.entries(lists)) v[`http.query['${k}']`] = list;
  return v;
}

export function secretValues(secret: { secretId: string; staticProperties: Record<string, string> }): Values {
  const v: Values = { "activity.type": "ACTIVITY_TYPE_EXPORT_SECRETS", "secret.id": secret.secretId };
  for (const [k, val] of Object.entries(secret.staticProperties)) v[`secret.static_properties['${k}']`] = val;
  return v;
}
