// tvc-counterparty-check: a compliance rule the Turnkey policy engine cannot
// express, because the data lives with you.
//
//   GET  /health   -> {"status":"ok"}                       (TVC's health check)
//   POST /check    -> is this payout recipient a verified counterparty?
//                     Answer signed by the enclave's Ephemeral Key.
//
// Run with plain Node 24 (TypeScript is stripped at load):
//   node src/server.ts --port 3000 --database-url postgres://...

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { parseArgs } from "node:util";
import { connect, findCounterparty } from "./db.ts";
import { loadEnclaveKeys, signPayload, EPHEMERAL_KEY_FILE } from "./enclave.ts";

// What precedes the flags in argv depends on how the app was started: a script
// path under plain Node, or runtime placeholders in the single-executable build.
// Start at the first flag so both work.
const firstFlag = process.argv.findIndex((a, i) => i > 0 && a.startsWith("--"));
const { values: args } = parseArgs({
  args: firstFlag === -1 ? [] : process.argv.slice(firstFlag),
  options: {
    port: { type: "string", default: "3000" },
    "database-url": { type: "string", default: process.env.DATABASE_URL },
    "database-driver": { type: "string", default: "pg" },
    "database-ca-file": { type: "string" },
    "insecure-database": { type: "boolean", default: false },
  },
});
if (args["database-driver"] !== "pg" && args["database-driver"] !== "neon-serverless") {
  console.error("--database-driver must be pg or neon-serverless");
  process.exit(2);
}
if (!args["database-url"]) {
  console.error("--database-url (or DATABASE_URL) is required");
  process.exit(2);
}

const pool = connect({
  connectionString: args["database-url"],
  driver: args["database-driver"],
  caFile: args["database-ca-file"],
  insecure: args["insecure-database"],
});

// Inside an enclave this loads the Ephemeral Key; elsewhere it is null and
// verdicts simply carry no appProof.
const keys = loadEnclaveKeys();
console.log(
  keys
    ? `ephemeral key loaded from ${EPHEMERAL_KEY_FILE}; verdicts will be signed`
    : `no ephemeral key at ${EPHEMERAL_KEY_FILE}; verdicts will be unsigned (expected outside an enclave)`,
);

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");

  if (req.method === "GET" && url.pathname === "/health") {
    return json(res, 200, { status: "ok" });
  }

  if (req.method === "POST" && url.pathname === "/check") {
    let body: { to?: unknown; from?: unknown; valueWei?: unknown; chainId?: unknown };
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      return json(res, 400, { error: "invalid JSON body" });
    }
    if (typeof body.to !== "string" || !EVM_ADDRESS.test(body.to)) {
      return json(res, 400, { error: "to must be a 0x-prefixed EVM address" });
    }
    const to = body.to.toLowerCase();

    // The rule. Any database problem is a 500, never an "allowed": a compliance
    // check must fail closed.
    let counterparty;
    try {
      counterparty = await findCounterparty(pool, to);
    } catch (err) {
      console.error("database lookup failed:", err);
      return json(res, 500, { error: "counterparty lookup failed" });
    }

    const allowed = counterparty?.kybStatus === "verified";
    const reason =
      counterparty === null
        ? "recipient is not an onboarded counterparty"
        : allowed
          ? "recipient is a verified counterparty"
          : `recipient KYB status is ${counterparty.kybStatus}`;

    // Everything the verdict depends on goes into the signed payload, so a
    // verifier can see exactly which transaction was judged and why.
    const payload = {
      type: "counterparty_check",
      timestampMs: String(Date.now()),
      transaction: {
        to,
        from: typeof body.from === "string" ? body.from.toLowerCase() : null,
        valueWei: typeof body.valueWei === "string" ? body.valueWei : null,
        chainId: typeof body.chainId === "number" ? body.chainId : null,
      },
      allowed,
      reason,
      counterparty,
    };

    return json(res, 200, {
      allowed,
      reason,
      counterparty,
      appProof: keys ? signPayload(keys, payload) : null,
      bootEphemeralKey: keys?.bootEphemeralKey ?? null,
    });
  }

  json(res, 404, { error: "not found" });
});

const port = Number(args.port);
server.listen(port, "0.0.0.0", () => {
  console.log(`tvc-counterparty-check listening on 0.0.0.0:${port}`);
});

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body) + "\n");
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}
