"use client";

import type { ReactNode } from "react";
import { TurnkeyProvider, type TurnkeyProviderConfig } from "@turnkey/react-wallet-kit";

const turnkeyConfig: TurnkeyProviderConfig = {
  organizationId: process.env.NEXT_PUBLIC_TURNKEY_ORG_ID!,
  authProxyConfigId: process.env.NEXT_PUBLIC_AUTH_PROXY_CONFIG_ID!,
  auth: {
    methods: {
      passkeyAuthEnabled: true,
      emailOtpAuthEnabled: true,
      smsOtpAuthEnabled: false,
      walletAuthEnabled: false,
      googleOauthEnabled: false,
      appleOauthEnabled: false,
      xOauthEnabled: false,
      discordOauthEnabled: false,
      facebookOauthEnabled: false,
    },
  },
};

export function Providers({ children }: { children: ReactNode }) {
  return <TurnkeyProvider config={turnkeyConfig}>{children}</TurnkeyProvider>;
}
