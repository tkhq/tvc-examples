import assert from "node:assert/strict";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

// Read-only check, suitable for either language's packaged server. Never mint or
// print credentials here; use client.ts for the explicit issuance walkthrough.
const secret = process.env.BROKER_TOKEN;
if (!secret) throw new Error("Set BROKER_TOKEN");
for (const endpoint of process.argv.slice(2)) {
  const url = new URL(endpoint);
  const health = await fetch(new URL("/health", url));
  assert.equal(health.status, 200);
  assert.equal((await fetch(url)).status, 401);
  const client = new Client({ name: "packaged-smoke", version: "1" }, {
    versionNegotiation: { mode: { pin: "2026-07-28" } },
  });
  try {
    await client.connect(new StreamableHTTPClientTransport(url, {
      requestInit: { headers: { Authorization: `Bearer ${secret}` } },
    }));
    assert.deepEqual((await client.listTools()).tools.map((tool) => tool.name), ["issue_token"]);
    console.log(`${url.origin}: health, auth, MCP 2026-07-28 discovery OK`);
  } finally {
    await client.close();
  }
}
