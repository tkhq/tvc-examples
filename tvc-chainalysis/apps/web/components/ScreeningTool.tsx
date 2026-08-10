"use client";

import { useState } from "react";
import { useTurnkey } from "@turnkey/react-wallet-kit";
import ProofBadge from "./ProofBadge";
import { type AppProof, type BootProof } from "@/lib/tvc-app";

interface ScreenResult {
  address: string;
  isThreat: boolean;
  threatLevel: number;
  hitUuid: string;
  hashedAddress: string;
  hashedInvestigation: string;
  sanctioned: string;
  appProof: AppProof | null;
  bootProof: BootProof | null;
}

interface HistoryItem extends ScreenResult {
  id: string;
  createdAt: string;
}

export default function ScreeningTool() {
  const { session } = useTurnkey();
  const orgId = session?.organizationId;
  const userId = session?.userId;

  const [address, setAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScreenResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[] | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(false);

  async function handleScreen(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const res = await fetch("/api/screen", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: address.trim(), orgId, userId }),
      });

      if (!res.ok) {
        const { error } = await res.json();
        throw new Error(error ?? `Error ${res.status}`);
      }

      const data: ScreenResult = await res.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Screening failed");
    } finally {
      setLoading(false);
    }
  }

  async function loadHistory() {
    setLoadingHistory(true);
    try {
      const res = await fetch(`/api/screen?orgId=${encodeURIComponent(orgId ?? "")}`);
      const { screenings } = await res.json();
      setHistory(screenings);
    } catch {
      // silent
    } finally {
      setLoadingHistory(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Screen form */}
      <div className="card space-y-4">
        <div>
          <h2 className="font-semibold text-lg">Screen an address</h2>
          <p className="text-sm text-muted mt-1">
            Check any crypto address against zeroShadow&apos;s Hermod
            threat-intel graph — running inside a TVC enclave.
          </p>
        </div>

        <form onSubmit={handleScreen} className="flex gap-2">
          <input
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="0x… or a Bitcoin / Solana address"
            className="input flex-1"
            required
          />
          <button
            type="submit"
            disabled={loading || !address.trim()}
            className="btn-primary whitespace-nowrap"
          >
            {loading ? "Checking…" : "Screen"}
          </button>
        </form>

        {error && <p className="text-sm text-danger">{error}</p>}
      </div>

      {/* Result */}
      {result && (
        <div className="space-y-4">
          {/* Verdict */}
          <div
            className={`card flex items-start gap-4 border ${
              result.isThreat
                ? "border-danger/40 bg-danger/5"
                : "border-success/30 bg-success/5"
            }`}
          >
            <div
              className={`w-10 h-10 rounded-full flex-shrink-0 flex items-center justify-center text-lg ${
                result.isThreat ? "bg-danger/20" : "bg-success/20"
              }`}
            >
              {result.isThreat ? "🚫" : "✅"}
            </div>
            <div>
              <p
                className={`font-semibold ${
                  result.isThreat ? "text-danger" : "text-success"
                }`}
              >
                {result.isThreat
                  ? `Threat detected (level ${result.threatLevel}${result.sanctioned ? " · " + result.sanctioned : ""})`
                  : "No known threat"}
              </p>
              <p className="text-xs font-mono text-muted mt-0.5 break-all">
                {result.address}
              </p>
            </div>
          </div>

          {/* Miss disclaimer — Hermod misses are point-in-time, never durable */}
          {!result.isThreat && (
            <div className="card border border-yellow-800/40 bg-yellow-900/10">
              <p className="text-xs text-yellow-400 leading-relaxed">
                <strong>Point-in-time result.</strong> Hermod did not flag this
                address at the moment of this screen. Threat intel changes
                continuously — this is not evidence of future safety. Screen
                again before every transaction.
              </p>
            </div>
          )}

          {/* Hit details */}
          {result.isThreat && (
            <div className="card space-y-3">
              <h3 className="text-sm font-medium text-muted uppercase tracking-wide">
                Hermod hit details
              </h3>
              <div className="border border-surface-border rounded-lg p-3 space-y-1 text-sm font-mono">
                <DetailRow label="Threat level" value={`${result.threatLevel} / 10`} />
                {result.sanctioned && (
                  <DetailRow label="Sanctions" value={result.sanctioned} />
                )}
                {result.hitUuid && <DetailRow label="Hit UUID" value={result.hitUuid} />}
                {result.hashedInvestigation && (
                  <DetailRow label="Investigation" value={result.hashedInvestigation} />
                )}
              </div>
            </div>
          )}

          {/* Boot proof */}
          <ProofBadge appProof={result.appProof} bootProof={result.bootProof} />
        </div>
      )}

      {/* History */}
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
              <div
                key={item.id}
                className="card flex items-center justify-between gap-4 py-3"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span
                    className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      item.isThreat ? "bg-danger" : "bg-success"
                    }`}
                  />
                  <span className="text-xs font-mono text-gray-300 truncate">
                    {item.address}
                  </span>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  {item.appProof && (
                    <span className="text-xs text-success hidden sm:inline">
                      ✓ attested
                    </span>
                  )}
                  <span className="text-xs text-muted">
                    {new Date(item.createdAt).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2 text-xs">
      <span className="text-muted w-28 flex-shrink-0">{label}</span>
      <span className="text-gray-300 break-all">{value}</span>
    </div>
  );
}
