import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { hostHeaderValidation, originValidation, toNodeHandler } from "@modelcontextprotocol/node";
import { GitHubBroker, requestSchema } from "./broker.js";

export function createBrokerServer(broker: GitHubBroker, bearerToken: string, hostname: string) {
  const handler = createMcpHandler(() => {
    const mcp = new McpServer({ name: "tvc-github-broker", version: "1.0.0" });
    mcp.registerTool("issue_token", {
      description: "Issue a fresh GitHub token for the configured repository. 'write' allows reading and writing contents. expires_at is the broker's revocation deadline; github_expires_at is GitHub's hard expiry.",
      inputSchema: requestSchema,
    }, async (input) => {
      try {
        const result = await broker.issue(input);
        return { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result };
      } catch {
        return { isError: true, content: [{ type: "text", text: "Unable to issue a GitHub token. Check the App installation and permissions." }] };
      }
    });
    return mcp;
  }, { responseMode: "json" });

  const nodeHandler = toNodeHandler(handler);
  const validateHost = hostHeaderValidation([hostname, "localhost", "127.0.0.1"]);
  const validateOrigin = originValidation([hostname, "localhost", "127.0.0.1"]);
  const expected = Buffer.from(`Bearer ${bearerToken}`);
  const server = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" }).end('{"status":"ok"}');
      return;
    }
    if (req.url !== "/mcp") {
      res.writeHead(404).end();
      return;
    }
    if (!validateHost(req, res) || !validateOrigin(req, res)) return;

    // Here's where you could use OAuth to authenticate agents, using the SDK's
    // bearer-auth middleware and a real identity provider. This demo shares a key.
    const supplied = Buffer.from(req.headers.authorization ?? "");
    res.setHeader("Cache-Control", "no-store");
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
      res.writeHead(401, { "WWW-Authenticate": "Bearer" }).end();
      return;
    }
    void nodeHandler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });

  // One loop, so a slow GitHub request cannot create overlapping cleanup jobs.
  const stop = new AbortController();
  const cleanup = (async () => {
    while (!stop.signal.aborted) {
      await broker.revokeExpired();
      await delay(1000, undefined, { signal: stop.signal }).catch(() => {});
    }
  })();

  return {
    server,
    async close() {
      // Stop accepting requests and finish existing calls before draining leases.
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await handler.close();
      stop.abort();
      await cleanup;
      await broker.revokeExpired(true);
    },
  };
}
