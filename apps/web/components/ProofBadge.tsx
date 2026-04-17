interface BootProof {
  deploymentLabel?: string | null;
  enclaveApp?: string | null;
  owner?: string | null;
  checkedAt: string;
}

interface ProofBadgeProps {
  proof: BootProof | null;
}

export default function ProofBadge({ proof }: ProofBadgeProps) {
  if (!proof) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-yellow-800/50 bg-yellow-900/10">
        <span className="w-2 h-2 rounded-full bg-yellow-500 flex-shrink-0" />
        <span className="text-xs text-yellow-400">Boot proof unavailable</span>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-success/20 bg-success/5 p-4 space-y-3">
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-success flex-shrink-0 animate-pulse" />
        <span className="text-sm font-medium text-success">
          Verified by Turnkey Verifiable Cloud
        </span>
      </div>

      <p className="text-xs text-muted leading-relaxed">
        This result was produced inside an AWS Nitro Enclave running the
        exact binary committed in the QOS manifest. The boot proof below is
        a cryptographic attestation from Turnkey confirming the enclave
        identity and deployment.
      </p>

      <div className="grid grid-cols-1 gap-1 text-xs font-mono">
        {proof.deploymentLabel && (
          <Row label="Deployment" value={proof.deploymentLabel} />
        )}
        {proof.enclaveApp && (
          <Row label="Enclave app" value={proof.enclaveApp} />
        )}
        {proof.owner && (
          <Row label="Owner" value={proof.owner} />
        )}
        <Row
          label="Attested at"
          value={new Date(proof.checkedAt).toLocaleString()}
        />
      </div>
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
