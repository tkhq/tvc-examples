"use client";

import { useTurnkey } from "@turnkey/react-wallet-kit";

export default function WalletAddress() {
  const { wallets } = useTurnkey();

  const address =
    wallets
      .flatMap((w) => w.accounts)
      .find((a) => a.addressFormat === "ADDRESS_FORMAT_ETHEREUM")?.address ??
    null;

  if (!address) return null;

  const display = `${address.slice(0, 6)}…${address.slice(-4)}`;

  return (
    <span className="text-xs text-muted font-mono hidden sm:inline">
      {display}
    </span>
  );
}
