import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { requestSchema } from "./src/broker.js";

const input = requestSchema.parse({
  access: process.argv[2] ?? "read",
  ttl_seconds: Number(process.argv[3] ?? 900),
});
if (!process.env.BROKER_TOKEN) throw new Error("Set BROKER_TOKEN");
const client = new Client({ name: "broker-example", version: "1.0.0" }, {
  versionNegotiation: { mode: { pin: "2026-07-28" } },
});
try {
  await client.connect(new StreamableHTTPClientTransport(
    new URL(process.env.MCP_URL ?? "http://127.0.0.1:3000/mcp"),
    { requestInit: { headers: { Authorization: `Bearer ${process.env.BROKER_TOKEN}` } } },
  ));
  const result = await client.callTool({ name: "issue_token", arguments: input });
  if (result.isError) throw new Error("Broker could not issue the token");
  // This command intentionally prints a credential. Send stdout to a protected file.
  console.log(JSON.stringify(result.structuredContent));
} finally {
  await client.close();
}
