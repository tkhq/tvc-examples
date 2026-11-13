// Postgres access. The enclave is a read-only consumer of the counterparties
// table; nothing here writes.

import tls from "node:tls";
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
  /**
   * PEM CA certificate(s). Becomes the only trust store for every TLS
   * connection this process makes, whichever driver is in use.
   */
  ca?: string;
  /** Plain TCP, no TLS. Only for a local database you fully control. pg driver only. */
  insecure?: boolean;
}

export function connect(opts: DbOptions): pg.Pool {
  // The Neon driver disables Postgres-protocol TLS and relies on the WebSocket's
  // own TLS, so an ssl: false here would change nothing while the flag claims
  // TLS is off. Refuse it rather than let the flag lie.
  if (opts.driver === "neon-serverless" && opts.insecure) {
    throw new Error("--insecure-database is only supported with --database-driver pg");
  }

  // TLS is on by default and verifies the server certificate. Without ca,
  // Node verifies against the root store compiled into the node binary, which
  // is part of the pivot that TVC pins but still spans well over a hundred
  // public CAs. With ca, that store is replaced process-wide so only those
  // CAs are trusted. Process-wide matters: the Neon driver's WebSocket TLS
  // never sees the ssl object below and would otherwise keep using the full
  // store. The database is this app's only outbound TLS, so nothing else is
  // affected.
  if (opts.ca) {
    const certs = opts.ca.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (!certs) throw new Error("database CA is not a PEM certificate");
    tls.setDefaultCACertificates(certs);
  }
  const ssl = opts.insecure ? false : { rejectUnauthorized: true, ca: opts.ca };

  // pg merges parameters parsed from the URL over the explicit config, so
  // ?sslmode=disable or ?sslrootcert=... in the URL would silently replace the
  // ssl object above. Reject them so the flags stay the only TLS knobs.
  for (const parameter of new URL(opts.connectionString).searchParams.keys()) {
    if (parameter.startsWith("ssl") || parameter === "uselibpqcompat") {
      throw new Error(
        `database URL parameter "${parameter}" is not supported; use --database-ca-file or --insecure-database instead`,
      );
    }
  }

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
