export interface AppProof {
  scheme: string;
  publicKey: string;
  proofPayload: string;
  signature: string;
}

export interface BootProof {
  ephemeralPublicKeyHex: string;
  awsAttestationDocB64: string;
  qosManifestB64: string;
  qosManifestEnvelopeB64: string;
  deploymentLabel: string;
  enclaveApp: string;
  owner: string;
  createdAt: { seconds: string; nanos: string };
}

// ScreeningResult mirrors the enriched Hermod result returned by the TVC
// Go app. `isThreat` is the top-line signal (Hermod 200 = true, 404 = false).
// The remaining fields are only populated on a hit; consumers must not
// interpret zero/empty values as meaningful on a miss.
export interface ScreeningResult {
  address: string;
  isThreat: boolean;
  threatLevel: number;
  hitUuid: string;
  hashedAddress: string;
  hashedInvestigation: string;
  sanctioned: string;
  appProof: AppProof | null;
  bootEphemeralKey: string | null;
}

// screenAddress calls the TVC app's POST /screen endpoint.
// The TVC app runs inside a Nitro Enclave and returns the Hermod verdict
// plus an app proof signed by the enclave ephemeral key.
export async function screenAddress(address: string): Promise<ScreeningResult> {
  const tvcUrl = process.env.TVC_APP_URL;

  const res = await fetch(`${tvcUrl}/screen`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address }),
    cache: "no-store",
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`TVC app error ${res.status}: ${text}`);
  }

  const data = await res.json();

  const appProof = data.appProof
    ? {
        scheme: data.appProof.scheme,
        publicKey: data.appProof.publicKey,
        proofPayload: data.appProof.proofPayload,
        signature: data.appProof.signature,
      }
    : null;

  return {
    address: data.address,
    isThreat: Boolean(data.isThreat),
    threatLevel: Number(data.threatLevel ?? 0),
    hitUuid: data.hitUuid ?? "",
    hashedAddress: data.hashedAddress ?? "",
    hashedInvestigation: data.hashedInvestigation ?? "",
    sanctioned: data.sanctioned ?? "",
    appProof,
    bootEphemeralKey: data.bootEphemeralKey ?? null,
  };
}
