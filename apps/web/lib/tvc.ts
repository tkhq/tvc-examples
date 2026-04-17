export interface Identification {
  category: string | null;
  name: string | null;
  description: string | null;
  url: string | null;
}

export interface ScreeningResult {
  address: string;
  sanctioned: boolean;
  identifications: Identification[];
}

export interface BootProofSummary {
  deploymentLabel: string | null;
  enclaveApp: string | null;
  checkedAt: string;
}

export interface ScreenResponse extends ScreeningResult {
  proof: BootProofSummary | null;
}

// screenAddress calls the TVC app's POST /screen endpoint.
// This runs inside the Nitro enclave — the result is covered by the boot proof.
export async function screenAddress(address: string): Promise<ScreeningResult> {
  const tvcUrl = process.env.TVC_APP_URL;
  if (!tvcUrl) {
    throw new Error("TVC_APP_URL is not configured");
  }

  const res = await fetch(`${tvcUrl}/screen`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address }),
    // Next.js: don't cache sanctions results
    cache: "no-store",
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`TVC app error ${res.status}: ${text}`);
  }

  return res.json();
}
