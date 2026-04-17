import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import * as schema from "./schema";
import path from "path";

// SQLite database file lives at apps/web/local.db.
// Add local.db to .gitignore — it contains address screening records and boot proofs.
const sqlite = new Database(path.join(process.cwd(), "local.db"));

// Enable WAL mode for better concurrent read performance.
sqlite.pragma("journal_mode = WAL");

export const db = drizzle(sqlite, { schema });
