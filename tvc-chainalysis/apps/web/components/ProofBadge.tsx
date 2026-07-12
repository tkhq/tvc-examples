"use client";

import { useEffect, useState } from "react";
import { type AppProof, type BootProof } from "@/lib/tvc-app";

interface ProofBadgeProps {
  appProof: AppProof | null;
  bootProof: BootProof | null;
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(hex.length / 2);
  const arr = new Uint8Array(buf);
  for (let i = 0; i < arr.length; i++)
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

function derToRaw(der: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  let offset = 2;
  const rLen = der[offset + 1]; offset += 2;
  const rBytes = der.slice(offset, offset + rLen); offset += rLen;
  const sLen = der[offset + 1]; offset += 2;
  const sBytes = der.slice(offset, offset + sLen);
  const raw = new Uint8Array(new ArrayBuffer(64));
  const r = rBytes[0] === 0 ? rBytes.slice(1) : rBytes;
  const s = sBytes[0] === 0 ? sBytes.slice(1) : sBytes;
  raw.set(r, 32 - r.length);
  raw.set(s, 64 - s.length);
  return raw;
}

async function verifySignature(appProof: AppProof): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    hexToBytes(appProof.publicKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    derToRaw(hexToBytes(appProof.signature)),
    new TextEncoder().encode(appProof.proofPayload)
  );
}

export default function ProofBadge({ appProof, bootProof }: ProofBadgeProps) {
  const [sigValid, setSigValid] = useState<boolean | null>(null);

  useEffect(() => {
    if (!appProof) return;
    verifySignature(appProof)
      .then(setSigValid)
      .catch(() => setSigValid(false));
  }, [appProof]);

  if (!appProof && !bootProof) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-yellow-800/50 bg-yellow-900/10">
        <span className="w-2 h-2 rounded-full bg-yellow-500 flex-shrink-0" />
        <span className="text-xs text-yellow-400">App proof unavailable</span>
      </div>
    );
  }

  const keysMatch =
    appProof &&
    bootProof &&
    bootProof.ephemeralPublicKeyHex.toLowerCase().endsWith(appProof.publicKey.toLowerCase());

  return (
    <div className="rounded-lg border border-success/20 bg-success/5 p-4 space-y-4">
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-success flex-shrink-0 animate-pulse" />
        <span className="text-sm font-medium text-success">
          Verified by Turnkey Verifiable Cloud
        </span>
      </div>

      <p className="text-xs text-muted leading-relaxed">
        This result was produced inside an AWS Nitro Enclave running the
        exact binary committed in the QOS manifest. The app proof is a
        signature by the enclave ephemeral key over the screening result.
        The boot proof is a cryptographic attestation from Turnkey confirming
        the enclave identity and deployment.
      </p>

      {/* App Proof */}
      {appProof && (
        <section className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-gray-200 uppercase tracking-wide">App Proof</span>
            <span className="text-xs text-muted">— signed by the enclave ephemeral key</span>
            {sigValid === null && <span className="text-xs text-muted">Verifying…</span>}
            {sigValid === true && <span className="text-xs text-success font-medium">✓ Signature valid</span>}
            {sigValid === false && <span className="text-xs text-danger font-medium">✗ Signature invalid</span>}
          </div>
          <div className="grid grid-cols-1 gap-1 font-mono">
            <Row label="Scheme" value={appProof.scheme} />
            <CopyRow label="Public key" value={appProof.publicKey} />
            <CopyRow label="Proof payload" value={appProof.proofPayload} />
            <CopyRow label="Signature" value={appProof.signature} />
          </div>
        </section>
      )}

      {/* Key linkage */}
      {appProof && bootProof && (
        <div className={`text-xs px-3 py-2 rounded-lg border ${keysMatch ? "border-success/30 bg-success/5 text-success" : "border-yellow-800/40 bg-yellow-900/10 text-yellow-400"}`}>
          {keysMatch
            ? "✓ App proof key matches boot proof ephemeral key"
            : "! App proof key differs from boot proof ephemeral key — may be a different replica"}
        </div>
      )}

      {/* Boot Proof */}
      {bootProof && (
        <section className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-gray-200 uppercase tracking-wide">Boot Proof</span>
            <span className="text-xs text-muted">— attests the enclave and binary</span>
          </div>
          <p className="text-xs text-muted leading-relaxed">
            Verify: decode <code className="text-gray-300">awsAttestationDoc</code> (COSE Sign1) → check AWS signature → confirm PCR3 = Turnkey&apos;s AWS account → parse QOS manifest → confirm binary hash matches your deployed digest.
          </p>
          <div className="grid grid-cols-1 gap-1 font-mono">
            <Row label="App" value={bootProof.enclaveApp} />
            <Row label="Label" value={bootProof.deploymentLabel} />
            <CopyRow label="Ephemeral key" value={bootProof.ephemeralPublicKeyHex} />
            <CopyRow label="Attestation doc" value={bootProof.awsAttestationDocB64} />
            <CopyRow label="QOS manifest" value={bootProof.qosManifestB64} />
          </div>
        </section>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2 text-xs">
      <span className="text-muted w-28 flex-shrink-0">{label}</span>
      <span className="text-gray-300 break-all">{value}</span>
    </div>
  );
}

function CopyRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="flex gap-2 text-xs items-start">
      <span className="text-muted w-28 flex-shrink-0">{label}</span>
      <span className="text-gray-300">{value.slice(0, 20)}…</span>
      <button
        onClick={copy}
        className="ml-auto flex-shrink-0 text-muted hover:text-gray-300 transition-colors"
        title="Copy full value"
      >
        {copied ? <CheckIcon /> : <CopyIcon />}
      </button>
    </div>
  );
}

function CopyIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}
