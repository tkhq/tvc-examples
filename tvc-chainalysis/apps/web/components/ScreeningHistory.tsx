"use client";

import { useState } from "react";
import { useTurnkey } from "@turnkey/react-wallet-kit";
import ScreenedTransaction, { type ScreenedTransaction as ScreenedTransactionType } from "./ScreenedTransaction";

export default function ScreeningHistory() {
  const { session } = useTurnkey();
  const orgId = session?.organizationId;

  const [history, setHistory] = useState<ScreenedTransactionType[] | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(false);

  async function loadHistory() {
    setLoadingHistory(true);
    try {
      const res = await fetch(
        `/api/screen?orgId=${encodeURIComponent(orgId ?? "")}`
      );
      const { screenings } = await res.json();
      setHistory(screenings);
    } catch (err) {
      console.log("Error loading transaction history.");

      console.error(err);
    } finally {
      setLoadingHistory(false);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted uppercase tracking-wide">
          Screening history
        </h3>
        <button
          onClick={loadHistory}
          disabled={loadingHistory}
          className="btn-ghost text-xs"
        >
          {loadingHistory ? "Loading…" : history ? "Refresh" : "Load history"}
        </button>
      </div>

      {history && history.length === 0 && (
        <p className="text-sm text-muted">No screenings yet.</p>
      )}

      {history && history.length > 0 && (
        <div className="space-y-2">
          {[...history].reverse().map((item) => (
            <ScreenedTransaction key={item.id} item={item} />
          ))}
        </div>
      )}
    </div>
  );
}
