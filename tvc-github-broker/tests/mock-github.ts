/**
 * Mock GitHub API for the e2e tests and `demo:local`.
 *
 * It verifies the broker's RS256 App JWT with `jose`, an implementation
 * independent of the broker's `ring` signer, against the App public key.
 *
 * Endpoints:
 *   POST   /app/installations/:id/access_tokens
 *   DELETE /installation/token
 *   GET    /repos/:owner/:repo
 */
import { importSPKI, jwtVerify, decodeProtectedHeader } from "jose";

export type MockMode = "normal" | "overbroad-repo" | "overbroad-permission" | "selection-all" | "error-500";

export type MockOptions = {
  publicKeyPem: string;
  appClientId: string;
  owner: string;
  installations: Record<string, { repositories: string[] }>;
  port?: number;
};

type Issued = { token: string; installationId: string; repositories: string[]; permissions: Record<string, string>; revoked: boolean };

export type MockGitHub = {
  url: string;
  stop: () => void;
  mode: MockMode;
  setMode: (m: MockMode) => void;
  tokenRequests: { installationId: string; body: any; jwtHeader: unknown; jwtClaims: any }[];
  jwtFailures: string[];
  revocations: string[];
  issued: Map<string, Issued>;
};

export async function startMockGitHub(o: MockOptions): Promise<MockGitHub> {
  const key = await importSPKI(o.publicKeyPem, "RS256");
  const state: MockGitHub = {
    url: "",
    stop: () => {},
    mode: "normal",
    setMode: (m) => {
      state.mode = m;
    },
    tokenRequests: [],
    jwtFailures: [],
    revocations: [],
    issued: new Map(),
  };
  const json = (status: number, body: unknown) => Response.json(body, { status });
  const bearer = (req: Request) => req.headers.get("authorization")?.match(/^Bearer (.+)$/)?.[1];

  const server = Bun.serve({
    port: o.port ?? 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url);
      const m = url.pathname.match(/^\/app\/installations\/(\d+)\/access_tokens$/);
      if (m && req.method === "POST") {
        const jwt = bearer(req) ?? "";
        let claims: any;
        try {
          const r = await jwtVerify(jwt, key, { algorithms: ["RS256"], issuer: o.appClientId });
          claims = r.payload;
          const now = Math.floor(Date.now() / 1000);
          if (claims.exp - claims.iat > 600) throw new Error("JWT lifetime over 10 minutes");
          if (claims.iat > now + 60) throw new Error("iat in the future");
        } catch (e) {
          state.jwtFailures.push(String((e as Error).message));
          return json(401, { message: "A JSON web token could not be decoded" });
        }
        const installationId = m[1]!;
        const inst = o.installations[installationId];
        const body = await req.json();
        state.tokenRequests.push({ installationId, body, jwtHeader: decodeProtectedHeader(jwt), jwtClaims: claims });
        if (!inst) return json(404, { message: "Not Found" });
        if (state.mode === "error-500") return json(500, { message: "Server Error" });
        const repos: string[] = body.repositories ?? inst.repositories;
        if (repos.some((r) => !inst.repositories.includes(r.toLowerCase()))) return json(422, { message: "There is at least one repository that does not exist or is not accessible to the parent installation." });
        const permissions: Record<string, string> = { ...(body.permissions ?? { contents: "write", metadata: "read" }) };
        permissions.metadata ??= "read";
        let grantedRepos = repos;
        if (state.mode === "overbroad-repo") grantedRepos = [...repos, "secret-repo"];
        if (state.mode === "overbroad-permission") permissions.administration = "write";
        const token = "ghs_mock" + Buffer.from(crypto.getRandomValues(new Uint8Array(18))).toString("hex");
        state.issued.set(token, { token, installationId, repositories: grantedRepos, permissions, revoked: false });
        return json(201, {
          token,
          expires_at: new Date(Date.now() + 3600_000).toISOString().replace(/\.\d+Z$/, "Z"),
          permissions,
          repository_selection: state.mode === "selection-all" ? "all" : "selected",
          repositories: grantedRepos.map((name, i) => ({ id: 1000 + i, name, full_name: `${o.owner}/${name}`, private: true })),
        });
      }
      if (url.pathname === "/installation/token" && req.method === "DELETE") {
        const t = state.issued.get(bearer(req) ?? "");
        if (!t || t.revoked) return json(401, { message: "Bad credentials" });
        t.revoked = true;
        state.revocations.push(t.token);
        return new Response(null, { status: 204 });
      }
      const r = url.pathname.match(/^\/repos\/([^/]+)\/([^/]+)$/);
      if (r && req.method === "GET") {
        const t = state.issued.get(bearer(req) ?? "");
        if (!t || t.revoked) return json(401, { message: "Bad credentials" });
        if (r[1] !== o.owner || !t.repositories.includes(r[2]!.toLowerCase())) return json(404, { message: "Not Found" });
        return json(200, { name: r[2], full_name: `${o.owner}/${r[2]}`, private: true });
      }
      return json(404, { message: "Not Found" });
    },
  });
  state.url = `http://127.0.0.1:${server.port}`;
  state.stop = () => server.stop(true);
  return state;
}

if (import.meta.main) {
  const fs = await import("node:fs");
  const m = await startMockGitHub({
    publicKeyPem: fs.readFileSync(process.env.APP_PUBLIC_KEY_PEM!, "utf8"),
    appClientId: process.env.APP_CLIENT_ID ?? "Iv23liMockDemo",
    owner: process.env.GITHUB_OWNER ?? "demo-owner",
    installations: { [process.env.INSTALLATION_ID ?? "12345"]: { repositories: (process.env.REPOS ?? "demo,demo-2").split(",") } },
    port: Number(process.env.MOCK_GITHUB_PORT ?? 0),
  });
  console.log(`[mock-github] ${m.url}`);
}
