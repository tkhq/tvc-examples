"use client";

import { useState } from "react";
import { useTurnkey, TurnkeyRequestError } from "@turnkey/react-wallet-kit";
import ProofBadge from "./ProofBadge";
import { type BootProof } from "@/lib/tvc";

type EthTransaction = {
  from: string;
  to: string;
  caip2: string;
  value?: string;
  data?: string;
  nonce?: string;
  gasLimit?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
};

const CHAIN_ID = parseInt(process.env.NEXT_PUBLIC_CHAIN_ID ?? "11155111");
const CHAIN_CAIP2 = `eip155:${CHAIN_ID}`;

interface Identification {
  category: string | null;
  name: string | null;
  description: string | null;
  url: string | null;
}

interface ScreenResult {
  address: string;
  isSanctioned: boolean;
  identifications: Identification[];
  appProof: {
    scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
    publicKey: string;
    proofPayload: string;
    signature: string;
  } | null;
  bootProof: BootProof | null;
}

type Status = "idle" | "screening" | "sanctioned" | "sending" | "sent";

function ethToHexWei(eth: string): string {
  const [whole = "0", frac = ""] = eth.split(".");
  const fracPadded = frac.padEnd(18, "0").slice(0, 18);
  const wei =
    BigInt(whole) * BigInt("1000000000000000000") + BigInt(fracPadded);
  return "0x" + wei.toString(16);
}

export default function SendETH() {
  const { session, handleSendTransaction, wallets } = useTurnkey();

  const orgId = session?.organizationId;
  const userId = session?.userId;

  // Derive the user's EVM address from the first embedded wallet account.
  const walletAddress =
    wallets
      .flatMap((w) => w.accounts)
      .find((a) => a.addressFormat === "ADDRESS_FORMAT_ETHEREUM")?.address ??
    null;

  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [screenResult, setScreenResult] = useState<ScreenResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isReady = !!walletAddress && !!orgId;
  const isSubmitting = status === "screening" || status === "sending";

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setScreenResult(null);
    setStatus("screening");

    const destination = to.trim();

    try {
      // Step 1 — screen the destination address via the TVC enclave.
      const res = await fetch("/api/screen", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: destination,
          orgId,
          userId,
          walletAddress,
          walletId: wallets[0]?.walletId,
          valueWei: ethToHexWei(amount),
          chainId: CHAIN_ID,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? `Error ${res.status}`);

      const result = data as ScreenResult;

      setScreenResult(result);

      if (result.isSanctioned) {
        setStatus("sanctioned");
        return;
      }

      // Step 2 — address is not sanctioned, submit the transaction via Turnkey.
      setStatus("sending");

      const tx: EthTransaction = {
        from: walletAddress!,
        to: destination,
        caip2: CHAIN_CAIP2,
        value: ethToHexWei(amount),
      };

      await handleSendTransaction({ transaction: tx, successPageDuration: 3000 });

      setStatus("sent");
      setTo("");
      setAmount("");
      setScreenResult(null);
    } catch (err: any) {
      if (err.cause?.toString().includes("insufficient funds")) {
        console.log("🚱 insufficient funds")
        setError("Insufficient funds");
      } else {
        setError("Unknown error");
      }

      setStatus("idle");
    }
  }

  function resetToIdle() {
    setStatus("idle");
    setScreenResult(null);
    setError(null);
  }

  return (
    <div className="card space-y-4">
      <div>
        <h2 className="font-semibold text-lg">Send ETH</h2>
        <p className="text-sm text-muted mt-1">
          Destination addresses are screened against OFAC sanctions via a TVC
          enclave before the transaction is sent.
        </p>
      </div>

      {/* Input form — hide while showing sanction block or sent confirmation */}
      {status !== "sanctioned" && status !== "sent" && (
        <form onSubmit={handleSubmit} className="space-y-3">
          <input
            type="text"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            placeholder="Destination address (0x…)"
            className="input"
            required
            disabled={isSubmitting}
          />
          <div className="flex gap-2">
            <input
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="Amount (ETH)"
              className="input flex-1"
              step="any"
              min="0"
              required
              disabled={isSubmitting}
            />
            <button
              type="submit"
              disabled={isSubmitting || !isReady || !to.trim() || !amount}
              className="btn-primary whitespace-nowrap"
            >
              {status === "screening"
                ? "Screening…"
                : status === "sending"
                  ? "Sending…"
                  : isReady
                    ? "Send"
                    : "Loading wallet…"}
            </button>
          </div>
        </form>
      )}

      {error && <p className="text-sm text-danger">{error}</p>}

      {/* Sanctions block */}
      {status === "sanctioned" && screenResult && (
        <div className="space-y-4">
          <div className="card flex items-start gap-4 border border-danger/40 bg-danger/5">
            <div className="w-10 h-10 rounded-full flex-shrink-0 flex items-center justify-center text-lg bg-danger/20">
              🚫
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-semibold text-danger">Transaction blocked</p>
              <p className="text-xs font-mono text-muted mt-0.5 break-all">
                {screenResult.address}
              </p>
              <p className="text-xs text-muted mt-1">
                This address appears on OFAC sanctions lists.
              </p>
            </div>
          </div>

          {screenResult.identifications.length > 0 && (
            <div className="card space-y-3">
              <h3 className="text-sm font-medium text-muted uppercase tracking-wide">
                Sanctions details
              </h3>
              {screenResult.identifications.map((id, i) => (
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

          <ProofBadge appProof={screenResult.appProof} bootProof={screenResult.bootProof} />

          <button onClick={resetToIdle} className="btn-ghost text-sm">
            ← Try a different address
          </button>
        </div>
      )}

      {/* Sent confirmation */}
      {status === "sent" && (
        <div className="card flex items-center gap-4 border border-success/30 bg-success/5">
          <div className="w-10 h-10 rounded-full flex-shrink-0 flex items-center justify-center text-lg bg-success/20">
            ✅
          </div>
          <div>
            <p className="font-semibold text-success">Transaction submitted</p>
            <p className="text-xs text-muted mt-0.5">
              Destination passed sanctions screening and the transaction was sent.
            </p>
          </div>
          <button onClick={resetToIdle} className="btn-ghost text-xs ml-auto">
            Send again
          </button>
        </div>
      )}
    </div>
  );
}
