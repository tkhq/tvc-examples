"use client";

import { useState } from "react";
import { useTurnkey } from "@turnkey/react-wallet-kit";
import ProofBadge from "./ProofBadge";

interface Identification {
  category: string | null;
  name: string | null;
  description: string | null;
  url: string | null;
}

interface ScreenResult {
  address: string;
  sanctioned: boolean;
  identifications: Identification[];
  proof: {
    deploymentLabel?: string | null;
    enclaveApp?: string | null;
    owner?: string | null;
    checkedAt: string;
  } | null;
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
            Check any crypto address against OFAC sanctions lists via the
            Chainalysis API, running inside a TVC enclave.
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
              result.sanctioned
                ? "border-danger/40 bg-danger/5"
                : "border-success/30 bg-success/5"
            }`}
          >
            <div
              className={`w-10 h-10 rounded-full flex-shrink-0 flex items-center justify-center text-lg ${
                result.sanctioned ? "bg-danger/20" : "bg-success/20"
              }`}
            >
              {result.sanctioned ? "🚫" : "✅"}
            </div>
            <div>
              <p
                className={`font-semibold ${
                  result.sanctioned ? "text-danger" : "text-success"
                }`}
              >
                {result.sanctioned ? "Sanctioned address" : "No sanctions found"}
              </p>
              <p className="text-xs font-mono text-muted mt-0.5 break-all">
                {result.address}
              </p>
            </div>
          </div>

          {/* Identifications */}
          {result.identifications.length > 0 && (
            <div className="card space-y-3">
              <h3 className="text-sm font-medium text-muted uppercase tracking-wide">
                Sanctions details
              </h3>
              {result.identifications.map((id, i) => (
                <div
                  key={i}
                  className="border border-surface-border rounded-lg p-3 space-y-1 text-sm"
                >
                  {id.name && <p className="font-medium">{id.name}</p>}
                  {id.description && (
                    <p className="text-muted text-xs leading-relaxed">
                      {id.description}
                    </p>
                  )}
                  {id.url && (
                    <a
                      href={id.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-accent text-xs hover:underline"
                    >
                      Source ↗
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Boot proof */}
          <ProofBadge proof={result.proof} />
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
                      item.sanctioned ? "bg-danger" : "bg-success"
                    }`}
                  />
                  <span className="text-xs font-mono text-gray-300 truncate">
                    {item.address}
                  </span>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  {item.proof && (
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
