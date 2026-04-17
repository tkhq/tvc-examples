import { Turnkey } from "@turnkey/sdk-server";

// Singleton Turnkey server client. Uses the parent org API key.
// This key is used for:
//   - Creating sub-orgs per user (first login)
//   - Initiating email auth activities
//   - Fetching boot proofs from the TVC app
export const turnkey = new Turnkey({
  apiBaseUrl: "https://api.turnkey.com",
  apiPublicKey: process.env.TURNKEY_API_PUBLIC_KEY!,
  apiPrivateKey: process.env.TURNKEY_API_PRIVATE_KEY!,
  defaultOrganizationId: process.env.TURNKEY_ORG_ID!,
});
