"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTurnkey } from "@turnkey/react-wallet-kit";

export default function LogoutButton() {
  const router = useRouter();
  const { logout } = useTurnkey();
  const [loggingOut, setLoggingOut] = useState(false);

  async function handleLogout() {
    setLoggingOut(true);
    await logout();
    router.refresh();
  }

  return (
    <button
      onClick={handleLogout}
      disabled={loggingOut}
      className="btn-ghost text-xs"
    >
      {loggingOut ? "Signing out…" : "Sign out"}
    </button>
  );
}
