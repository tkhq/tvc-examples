import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { sql } from "drizzle-orm";

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  turnkeyUserId: text("turnkey_user_id").notNull().unique(),
  turnkeySubOrgId: text("turnkey_sub_org_id").notNull().unique(),
  turnkeyWalletId: text("turnkey_wallet_id").notNull().unique(),
  walletAddress: text("wallet_address").notNull().unique(),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
  updatedAt: text("updated_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export const transactions = sqliteTable("transactions", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id),
  fromAddress: text("from_address").notNull(),
  toAddress: text("to_address").notNull(),
  valueWei: text("value_wei").notNull(),
  data: text("data").notNull().default("0x"),
  chainId: integer("chain_id").notNull(),
  txHash: text("tx_hash"),
  status: text("status", {
    enum: ["pending", "submitted", "confirmed", "blocked"],
  })
    .notNull()
    .default("pending"),
  submittedAt: text("submitted_at"),
  confirmedAt: text("confirmed_at"),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

// Screenings audit log — one row per Hermod check.
//
// The columns capture the enriched Hermod verdict alongside the enclave
// proofs. `isThreat` is the top-line hit/miss signal (Hermod 200 vs 404).
// `threatLevel`, `hitUuid`, `hashedInvestigation`, and `sanctionedList` are
// only meaningful on a hit; on a miss they are stored as their zero values.
//
// IMPORTANT: A stored miss is a point-in-time record. It is NOT a durable
// "safe" verdict. Consumers must not query this table to short-circuit
// future screens for the same address.
export const screenings = sqliteTable("screenings", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id),
  transactionId: text("transaction_id")
    .notNull()
    .references(() => transactions.id),
  address: text("address").notNull(),
  isThreat: integer("is_threat", { mode: "boolean" })
    .notNull()
    .default(false),
  threatLevel: integer("threat_level").notNull().default(0),
  hitUuid: text("hit_uuid"),
  hashedAddress: text("hashed_address"),
  hashedInvestigation: text("hashed_investigation"),
  // Sanctions program string from Hermod (e.g. "OFAC"). Empty when not set.
  sanctionedList: text("sanctioned_list"),
  proofScheme: text("proof_scheme"),
  proofPublicKey: text("proof_public_key"),
  proofPayload: text("proof_payload"),
  proofSignature: text("proof_signature"),
  bootProof: text("boot_proof"),
  outcome: text("outcome", { enum: ["allowed", "blocked"] }).notNull(),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Transaction = typeof transactions.$inferSelect;
export type NewTransaction = typeof transactions.$inferInsert;
export type Screening = typeof screenings.$inferSelect;
export type NewScreening = typeof screenings.$inferInsert;
