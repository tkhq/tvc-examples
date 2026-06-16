import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import * as schema from "./schema";
import path from "path";

function createDb() {
  const sqlite = new Database(process.env.DB_PATH ?? path.join(process.cwd(), "local.db"));
  sqlite.pragma("journal_mode = WAL");
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      turnkey_user_id TEXT NOT NULL UNIQUE,
      turnkey_sub_org_id TEXT NOT NULL UNIQUE,
      turnkey_wallet_id TEXT NOT NULL UNIQUE,
      wallet_address TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      from_address TEXT NOT NULL,
      to_address TEXT NOT NULL,
      value_wei TEXT NOT NULL,
      data TEXT NOT NULL DEFAULT '0x',
      chain_id INTEGER NOT NULL,
      tx_hash TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      submitted_at TEXT,
      confirmed_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS screenings (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      transaction_id TEXT NOT NULL REFERENCES transactions(id),
      address TEXT NOT NULL,
      is_sanctioned INTEGER NOT NULL DEFAULT 0,
      identifications TEXT NOT NULL,
      proof_scheme TEXT,
      proof_public_key TEXT,
      proof_payload TEXT,
      proof_signature TEXT,
      boot_proof TEXT,
      outcome TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  return drizzle(sqlite, { schema });
}

let _instance: ReturnType<typeof createDb> | undefined;

// Proxy defers DB initialization to first request so the file path
// is not opened at build time (when the /data volume isn't mounted).
export const db = new Proxy({} as ReturnType<typeof createDb>, {
  get(_target, prop) {
    if (!_instance) _instance = createDb();
    return Reflect.get(_instance, prop);
  },
});
