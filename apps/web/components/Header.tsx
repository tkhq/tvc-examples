"use client";

import WalletAddress from "./WalletAddress";
import LogoutButton from "./LogoutButton";

export default function Header() {
  return (
    <header className="border-b border-surface-border">
      <div className="max-w-3xl mx-auto px-4 h-14 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-accent font-bold tracking-tight">TVC</span>
          <span className="text-muted text-sm hidden sm:inline">
            Sanctions Screener
          </span>
        </div>

        <div className="flex items-center gap-3">
          <WalletAddress />
          <LogoutButton />
        </div>
      </div>
    </header>
  );
}
