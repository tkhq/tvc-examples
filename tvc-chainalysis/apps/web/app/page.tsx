"use client";

import { useEffect } from "react";
import { useTurnkey, AuthState } from "@turnkey/react-wallet-kit";
import Header from "@/components/Header";
import LoginPrompt from "@/components/LoginPrompt";
import SendETH from "@/components/SendETH";
import ScreeningHistory from "@/components/ScreeningHistory";

export default function Home() {
  const { authState, createWallet, refreshWallets } = useTurnkey();

  useEffect(() => {
    if (authState !== AuthState.Authenticated) return;

    async function ensureWallet() {
      const current = await refreshWallets();
      if (current.length > 0) return;
      await createWallet({
        walletName: "Default",
        accounts: ["ADDRESS_FORMAT_ETHEREUM"],
      });
      await refreshWallets();
    }

    ensureWallet().catch(console.error);
  }, [authState, createWallet, refreshWallets]);

  if (authState !== AuthState.Authenticated) {
    return <LoginPrompt />;
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <main className="flex-1 max-w-3xl mx-auto w-full px-4 py-10 space-y-8">
        <SendETH />
        <ScreeningHistory />
      </main>
    </div>
  );
}
