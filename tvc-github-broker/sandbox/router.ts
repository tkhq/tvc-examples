/**
 * Host-side model router for the demo. Holds the provider key in memory and
 * forwards chat completions for callers that present a session token.
 * For the demo only: this process holds the key, so it does not prove enclave custody.
 *
 *   KEY_FILE=...  SESSION_OUT=...  bun router.ts
 *
 * Environment: KEY_FILE (provider key, read once), SESSION_OUT (file that
 * receives the session token), PORT (default 8787), UPSTREAM (default
 * https://openrouter.ai/api), ALLOWED_MODELS (comma-separated),
 * MAX_REQUESTS (default 40), TTL_SECONDS (default 1800).
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";

const need = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`missing env ${k}`);
  return v;
};
const providerKey = fs.readFileSync(need("KEY_FILE"), "utf8").trim();
const upstream = (process.env.UPSTREAM ?? "https://openrouter.ai/api").replace(/\/$/, "");
const port = Number(process.env.PORT ?? 8787);
const allowedModels = need("ALLOWED_MODELS").split(",");
const maxRequests = Number(process.env.MAX_REQUESTS ?? 40);
const ttl = Number(process.env.TTL_SECONDS ?? 1800);

const secret = randomBytes(32);
const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
const mac = (body: string) => createHmac("sha256", secret).update(body).digest();

type Claims = { sid: string; exp: number; models: string[]; max: number };
const used = new Map<string, number>();

function mint(c: Claims): string {
  const body = b64u(JSON.stringify(c));
  return `rt.${body}.${b64u(mac(body))}`;
}

function verify(header: string | null): Claims | null {
  const m = /^Bearer rt\.([\w-]+)\.([\w-]+)$/.exec(header ?? "");
  if (!m) return null;
  const given = Buffer.from(m[2]!, "base64url");
  const want = mac(m[1]!);
  if (given.length !== want.length || !timingSafeEqual(given, want)) return null;
  const c = JSON.parse(Buffer.from(m[1]!, "base64url").toString()) as Claims;
  return c.exp > Date.now() / 1000 ? c : null;
}

const json = (status: number, error: string) => Response.json({ error }, { status });

const server = Bun.serve({
  hostname: process.env.HOST ?? "127.0.0.1",
  port,
  async fetch(req) {
    const url = new URL(req.url);
    const log = (status: number, model = "-") =>
      console.error(`${new Date().toISOString()} ${req.method} ${url.pathname} model=${model} -> ${status}`);
    if (url.pathname === "/health") return new Response("ok");
    if (req.method !== "POST" || url.pathname !== "/v1/chat/completions") {
      log(404);
      return json(404, "not_found");
    }
    const claims = verify(req.headers.get("authorization"));
    if (!claims) {
      log(401);
      return json(401, "invalid_session");
    }
    const body = await req.text();
    let model = "-";
    try {
      const parsed = JSON.parse(body);
      model = parsed.model;
      // OpenRouter also routes on `models` (fallbacks), which would skip the allowlist.
      if ("models" in parsed) {
        log(400, String(model));
        return json(400, "models_not_supported");
      }
    } catch {
      log(400);
      return json(400, "bad_json");
    }
    if (typeof model !== "string" || !claims.models.includes(model)) {
      log(403, model);
      return json(403, "model_not_allowed");
    }
    const n = (used.get(claims.sid) ?? 0) + 1;
    used.set(claims.sid, n);
    if (n > claims.max) {
      log(429, model);
      return json(429, "session_budget_exhausted");
    }
    const resp = await fetch(`${upstream}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: req.headers.get("accept") ?? "application/json", authorization: `Bearer ${providerKey}` },
      body,
    });
    log(resp.status, model);
    const headers = new Headers();
    for (const h of ["content-type", "cache-control"]) {
      const v = resp.headers.get(h);
      if (v) headers.set(h, v);
    }
    return new Response(resp.body, { status: resp.status, headers });
  },
});

const token = mint({ sid: b64u(randomBytes(8)), exp: Math.floor(Date.now() / 1000) + ttl, models: allowedModels, max: maxRequests });
fs.writeFileSync(need("SESSION_OUT"), token, { mode: 0o600 });
console.error(`router on ${server.hostname}:${server.port}, models=${allowedModels.join(",")}, max=${maxRequests}, ttl=${ttl}s`);
