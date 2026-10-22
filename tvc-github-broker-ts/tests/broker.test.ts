import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { jwtVerify } from "jose";
import * as z from "zod/v4";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { GitHubBroker } from "../src/broker.js";
import { createBrokerServer } from "../src/server.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const config = {
  GITHUB_APP_ID: "123",
  GITHUB_REPOSITORY: "example/demo",
  GITHUB_PRIVATE_KEY: privateKey.export({ type: "pkcs1", format: "pem" }).toString(),
};

function github() {
  const state = { issued: 0, deleted: [] as string[], deleteStatus: 204, lifetime: 3600, failCreate: false };
  const request: typeof fetch = async (url, init) => {
    const authorization = new Headers(init?.headers).get("Authorization")!;
    if (init?.method === "DELETE") {
      state.deleted.push(authorization);
      return new Response(null, { status: state.deleteStatus });
    }
    const { payload } = await jwtVerify(authorization.slice(7), publicKey, { issuer: "123", algorithms: ["RS256"] });
    assert.ok(payload.exp! - payload.iat! <= 600);
    if (String(url).endsWith("/installation")) {
      assert.equal(String(url), "https://api.github.com/repos/example/demo/installation");
      return Response.json({ id: 456 });
    }
    assert.equal(String(url), "https://api.github.com/app/installations/456/access_tokens");
    const body = JSON.parse(String(init?.body));
    assert.deepEqual(body.repositories, ["demo"]);
    assert.deepEqual(Object.keys(body.permissions).sort(), ["contents", "metadata"]);
    assert.equal(body.permissions.metadata, "read");
    assert.ok(["read", "write"].includes(body.permissions.contents));
    if (state.failCreate) return Response.json({ secret: "do-not-leak" }, { status: 403 });
    return Response.json({
      token: `fake-${++state.issued}`,
      expires_at: new Date(Date.now() + state.lifetime * 1000).toISOString(),
    }, { status: 201 });
  };
  return { state, broker: new GitHubBroker(config, request) };
}

test("fresh scoped tokens, bounded lifetime, failed revocation retries, and native expiry", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const { state, broker } = github();
  const read = await broker.issue({ access: "read", ttl_seconds: 20 });
  const write = await broker.issue({ access: "write", ttl_seconds: 30 });
  assert.notEqual(read.token, write.token);
  assert.equal(Date.parse(read.expires_at) - Date.now(), 20_000);
  await broker.revokeExpired();
  assert.equal(state.deleted.length, 0);
  t.mock.timers.tick(20_000);
  state.deleteStatus = 503;
  await broker.revokeExpired();
  assert.deepEqual(state.deleted, ["Bearer fake-1"]);
  state.deleteStatus = 204;
  await broker.revokeExpired();
  assert.equal(state.deleted.length, 2);
  await broker.revokeExpired(true);
  assert.equal(state.deleted.at(-1), "Bearer fake-2");

  state.lifetime = 5;
  const short = await broker.issue({ ttl_seconds: 30 });
  assert.equal(short.expires_at, short.github_expires_at);
  t.mock.timers.tick(5_000);
  const count = state.deleted.length;
  await broker.revokeExpired();
  assert.equal(state.deleted.length, count);
});

test("reject invalid TTL and permissions before contacting GitHub", async () => {
  const { state, broker } = github();
  for (const ttl_seconds of [0, -1, 3601, 1.5, NaN]) {
    await assert.rejects(broker.issue({ ttl_seconds }));
  }
  assert.equal(state.issued, 0);
});

test("real MCP 2026-07-28 client: auth, discovery, issuance, automatic expiry, shutdown", async () => {
  const { state, broker } = github();
  const secret = "test-broker-secret-32-characters-long";
  const app = createBrokerServer(broker, secret, "localhost");
  app.server.listen(0, "127.0.0.1");
  await once(app.server, "listening");
  const address = app.server.address();
  assert.ok(address && typeof address !== "string");
  const url = new URL(`http://127.0.0.1:${address.port}/mcp`);
  const client = new Client({ name: "test", version: "1" }, {
    versionNegotiation: { mode: { pin: "2026-07-28" } },
  });
  try {
    assert.equal((await fetch(url)).status, 401);
    assert.equal((await fetch(new URL("/health", url))).status, 200);
    assert.equal((await fetch(url, { headers: { Authorization: `Bearer ${secret}`, Origin: "https://evil.example" } })).status, 403);
    await client.connect(new StreamableHTTPClientTransport(url, {
      requestInit: { headers: { Authorization: `Bearer ${secret}` } },
    }));
    const listed = await client.listTools();
    assert.deepEqual(listed.tools.map((tool) => tool.name), ["issue_token"]);
    for (const input of [{ access: "admin" }, { ttl_seconds: 3601 }, { ttl_seconds: 1.5 }]) {
      const rejected = await client.callTool({ name: "issue_token", arguments: input });
      assert.equal(rejected.isError, true);
    }
    assert.equal(state.issued, 0);
    const result = await client.callTool({ name: "issue_token", arguments: { access: "read", ttl_seconds: 1 } });
    assert.equal(result.isError, undefined);
    assert.equal(z.object({ token: z.string() }).parse(result.structuredContent).token, "fake-1");
    for (let i = 0; i < 30 && state.deleted.length === 0; i++) await delay(100);
    assert.deepEqual(state.deleted, ["Bearer fake-1"]);

    state.failCreate = true;
    const failure = await client.callTool({ name: "issue_token", arguments: {} });
    assert.equal(failure.isError, true);
    assert.ok(!JSON.stringify(failure).includes("do-not-leak"));
    state.failCreate = false;
    await client.callTool({ name: "issue_token", arguments: { access: "write" } });
  } finally {
    await client.close();
    await app.close();
  }
  assert.equal(state.deleted.at(-1), "Bearer fake-2");
});
