export interface Identification {
  category: string | null;
  name: string | null;
  description: string | null;
  url: string | null;
}

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

export interface ScreeningResult {
  address: string;
  isSanctioned: boolean;
  identifications: Identification[];
  appProof: AppProof | null;
  bootEphemeralKey: string | null;
}

// screenAddress calls the TVC app's POST /screen endpoint.
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
    isSanctioned: data.sanctioned,
    identifications: data.identifications,
    appProof,
    bootEphemeralKey: data.bootEphemeralKey ?? null,
  };
}
