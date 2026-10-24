// Postgres access. The enclave is a read-only consumer of the counterparties
// table; nothing here writes.

import { readFileSync } from "node:fs";
import { Pool as NeonPool } from "@neondatabase/serverless";
import pg from "pg";

export interface Counterparty {
  address: string;
  name: string;
  kybStatus: "pending" | "verified" | "rejected";
  verifiedAt: string | null;
}

export type DbDriver = "pg" | "neon-serverless";

export interface DbOptions {
  connectionString: string;
  /**
   * "pg" speaks the Postgres wire protocol on the URL's port (5432 by default).
   * "neon-serverless" carries the same protocol over a WebSocket on port 443,
   * for Neon databases when only HTTPS egress is available.
   */
  driver?: DbDriver;
  /** Path to a PEM CA certificate to trust instead of Node's built-in roots. */
  caFile?: string;
  /** Plain TCP, no TLS. Only for a local database you fully control. */
  insecure?: boolean;
}

export function connect(opts: DbOptions): pg.Pool {
  // TLS is on by default and verifies the server certificate. Without caFile,
  // Node verifies against the root store compiled into the node binary, which
  // is part of the pivot that TVC pins. With caFile, only that CA is trusted,
  // which is the right setting for a database you run yourself.
  const ssl = opts.insecure
    ? false
    : { rejectUnauthorized: true, ca: opts.caFile ? readFileSync(opts.caFile, "utf8") : undefined };

  const config = {
    connectionString: opts.connectionString,
    ssl,
    max: 4,
    connectionTimeoutMillis: 5_000,
    query_timeout: 5_000,
  };
  // Neon's Pool is API-compatible with pg's; only the transport differs.
  const pool: pg.Pool =
    opts.driver === "neon-serverless" ? (new NeonPool(config) as unknown as pg.Pool) : new pg.Pool(config);

  // An idle connection that drops (database restart, network blip) emits
  // "error" on the pool. Without a listener Node treats that as an unhandled
  // error and exits the process. Log it and let the next query reconnect.
  pool.on("error", (err) => {
    console.error("idle database connection error:", err.message);
  });

  return pool;
}

/** Look up one counterparty by address. Returns null when it is not onboarded. */
export async function findCounterparty(pool: pg.Pool, address: string): Promise<Counterparty | null> {
  const { rows } = await pool.query<{
    address: string;
    name: string;
    kyb_status: Counterparty["kybStatus"];
    verified_at: Date | null;
  }>(
    "SELECT address, name, kyb_status, verified_at FROM counterparties WHERE address = $1",
    [address],
  );
  const row = rows[0];
  if (!row) return null;
  return {
    address: row.address,
    name: row.name,
    kybStatus: row.kyb_status,
    verifiedAt: row.verified_at ? row.verified_at.toISOString() : null,
  };
}
