"use client";

import { useState } from "react";
import ProofBadge from "./ProofBadge";
import { type AppProof, type BootProof, type Identification } from "@/lib/tvc";

export interface ScreenedTransaction {
  id: string;
  fromAddress: string;
  toAddress: string;
  valueWei: string;
  isSanctioned: boolean;
  identifications: Identification[];
  appProof: AppProof | null;
  bootProof: BootProof | null;
  outcome: "allowed" | "blocked";
  createdAt: string;
}

export default function ScreenedTransaction({ item }: { item: ScreenedTransaction }) {
  const [open, setOpen] = useState(false);
  console.log("ITEM VALUE 👉", Number(item.valueWei) / 1e18);

  return (
    <div className="card overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between gap-4 py-3 text-left"
      >
        <div className="flex items-center gap-3 min-w-0">
          <span
            className={`w-2 h-2 rounded-full flex-shrink-0 ${item.isSanctioned ? "bg-danger" : "bg-success"
              }`}
          />
          <span className="text-xs font-mono text-gray-300 truncate">
            {item.toAddress}
          </span>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          {item.isSanctioned ? (
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
              value={item.isSanctioned ? "Blocked" : "Cleared"}
              valueClassName={item.isSanctioned ? "text-danger" : "text-success"}
            />
          </div>

          {item.isSanctioned && item.identifications.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-medium text-muted uppercase tracking-wide">
                Sanctions details
              </p>
              {item.identifications.map((id, i) => (
                <div
                  key={i}
                  className="border border-surface-border rounded-lg p-3 space-y-1 text-xs"
                >
                  {id.name && <p className="font-medium">{id.name}</p>}
                  {id.category && <p className="text-muted">{id.category}</p>}
                  {id.description && (
                    <p className="text-muted leading-relaxed">{id.description}</p>
                  )}
                  {id.url && (
                    <a
                      href={id.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-accent hover:underline"
                    >
                      Source ↗
                    </a>
                  )}
                </div>
              ))}
            </div>
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
      <span className="text-muted w-16 flex-shrink-0">{label}</span>
      <span
        className={`break-all ${mono ? "font-mono" : ""} ${valueClassName ?? "text-gray-300"}`}
      >
        {value}
      </span>
    </div>
  );
}
