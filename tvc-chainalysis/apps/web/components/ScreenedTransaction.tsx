"use client";

import { useState } from "react";
import ProofBadge from "./ProofBadge";
import { type AppProof, type BootProof } from "@/lib/tvc-app";

export interface ScreenedTransaction {
  id: string;
  fromAddress: string;
  toAddress: string;
  valueWei: string;
  isThreat: boolean;
  threatLevel: number;
  hitUuid: string | null;
  hashedAddress: string | null;
  hashedInvestigation: string | null;
  sanctioned: string;
  appProof: AppProof | null;
  bootProof: BootProof | null;
  outcome: "allowed" | "blocked";
  createdAt: string;
}

export default function ScreenedTransaction({ item }: { item: ScreenedTransaction }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="card overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between gap-4 py-3 text-left"
      >
        <div className="flex items-center gap-3 min-w-0">
          <span
            className={`w-2 h-2 rounded-full flex-shrink-0 ${item.isThreat ? "bg-danger" : "bg-success"
              }`}
          />
          <span className="text-xs font-mono text-gray-300 truncate">
            {item.toAddress}
          </span>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          {item.isThreat ? (
            <span className="text-xs text-danger hidden sm:inline">blocked</span>
          ) : (
            item.appProof && (
              <span className="text-xs text-success hidden sm:inline">
                ✓ attested
              </span>
            )
          )}
          <span className="text-xs text-muted">
            {new Date(item.createdAt).toLocaleDateString()}
          </span>
          <span className="text-muted text-xs">{open ? "▲" : "▼"}</span>
        </div>
      </button>

      {open && (
        <div className="border-t border-surface-border pt-4 pb-2 space-y-4">
          <div className="grid grid-cols-1 gap-1">
            <DetailRow label="From" value={item.fromAddress} mono />
            <DetailRow label="To" value={item.toAddress} mono />
            <DetailRow label="Value" value={item.valueWei} mono />
            <DetailRow
              label="Time"
              value={new Date(item.createdAt).toLocaleString()}
            />
            <DetailRow
              label="Status"
              value={item.isThreat ? "Threat detected" : "No known threat"}
              valueClassName={item.isThreat ? "text-danger" : "text-success"}
            />
          </div>

          {item.isThreat && (
            <div className="space-y-2">
              <p className="text-xs font-medium text-muted uppercase tracking-wide">
                Hermod hit details
              </p>
              <div className="border border-surface-border rounded-lg p-3 space-y-1 text-xs">
                <DetailRow label="Threat level" value={`${item.threatLevel} / 10`} valueClassName="text-danger font-medium" />
                {item.sanctioned && (
                  <DetailRow label="Sanctions" value={item.sanctioned} valueClassName="text-danger font-medium" />
                )}
                {item.hitUuid && <DetailRow label="Hit UUID" value={item.hitUuid} mono />}
                {item.hashedInvestigation && (
                  <DetailRow label="Investigation" value={item.hashedInvestigation} mono />
                )}
              </div>
            </div>
          )}

          {!item.isThreat && (
            <p className="text-xs text-muted italic leading-relaxed">
              Point-in-time result. Hermod did not flag this address when the
              screen ran; that is not evidence of future safety. Each transaction
              should be screened again before it is submitted.
            </p>
          )}

          <ProofBadge appProof={item.appProof} bootProof={item.bootProof} />
        </div>
      )}
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono,
  valueClassName,
}: {
  label: string;
  value: string;
  mono?: boolean;
  valueClassName?: string;
}) {
  return (
    <div className="flex gap-2 text-xs">
      <span className="text-muted w-24 flex-shrink-0">{label}</span>
      <span
        className={`break-all ${mono ? "font-mono" : ""} ${valueClassName ?? "text-gray-300"}`}
      >
        {value}
      </span>
    </div>
  );
}
