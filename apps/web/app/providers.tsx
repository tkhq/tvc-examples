"use client";

import type { ReactNode } from "react";
import { TurnkeyProvider, type TurnkeyProviderConfig } from "@turnkey/react-wallet-kit";

const turnkeyConfig: TurnkeyProviderConfig = {
  organizationId: process.env.NEXT_PUBLIC_TURNKEY_ORG_ID!,
  // Auth Proxy Config ID from https://app.turnkey.com/dashboard/auth
  // Enables client-side initOtp / completeOtp without exposing parent API keys.
  authProxyConfigId: process.env.NEXT_PUBLIC_AUTH_PROXY_CONFIG_ID!,
};

console.log("🆔:", process.env.NEXT_PUBLIC_AUTH_PROXY_CONFIG_ID!)

export function Providers({ children }: { children: ReactNode }) {
  return <TurnkeyProvider config={turnkeyConfig}>{children}</TurnkeyProvider>;
}
