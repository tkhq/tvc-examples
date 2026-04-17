"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTurnkey } from "@turnkey/react-wallet-kit";

export default function Header() {
  const router = useRouter();
  const { logout, user } = useTurnkey();
  const [loggingOut, setLoggingOut] = useState(false);

  async function handleLogout() {
    setLoggingOut(true);
    await logout();
    router.refresh(); // re-evaluates authState, showing the login prompt
  }

  return (
    <header className="border-b border-surface-border">
      <div className="max-w-3xl mx-auto px-4 h-14 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-accent font-bold tracking-tight">TVC</span>
          <span className="text-muted text-sm hidden sm:inline">Sanctions Screener</span>
        </div>

        <div className="flex items-center gap-3">
          {user?.userName && (
            <span className="text-xs text-muted hidden sm:inline">{user.userName}</span>
          )}
          <button
            onClick={handleLogout}
            disabled={loggingOut}
            className="btn-ghost text-xs"
          >
            {loggingOut ? "Signing out…" : "Sign out"}
          </button>
        </div>
      </div>
    </header>
  );
}
