import { sqliteTable, text, integer, uniqueIndex } from "drizzle-orm/sqlite-core";
import { sql } from "drizzle-orm";

// One row per (user, wallet address) pair. orgId is the Turnkey sub-org ID
// and userId is the Turnkey user ID — together they identify the authenticated user.
export const userWallets = sqliteTable(
  "user_wallets",
  {
    id: text("id").primaryKey(),
    orgId: text("org_id").notNull(),
    userId: text("user_id").notNull(),
    address: text("address").notNull(),
    createdAt: text("created_at")
      .notNull()
      .default(sql`(datetime('now'))`),
  },
  (table) => ({
    orgAddressUniq: uniqueIndex("user_wallets_org_address_uniq").on(
      table.orgId,
      table.address
    ),
  })
);

// One row per address screening. userWalletId links back to the user wallet
// that initiated the check. destinationAddress is the address being screened,
// kept denormalized for simple audit log queries without joins.
export const screenings = sqliteTable("screenings", {
  id: text("id").primaryKey(),
  userWalletId: text("user_wallet_id")
    .notNull()
    .references(() => userWallets.id),
  destinationAddress: text("destination_address").notNull(),
  sanctioned: integer("sanctioned", { mode: "boolean" }).notNull(),
  // JSON: Identification[]
  identifications: text("identifications").notNull(),
  // JSON: BootProofSummary | null — TVC attestation at time of check
  bootProof: text("boot_proof"),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export type UserWallet = typeof userWallets.$inferSelect;
export type NewUserWallet = typeof userWallets.$inferInsert;
export type Screening = typeof screenings.$inferSelect;
export type NewScreening = typeof screenings.$inferInsert;
