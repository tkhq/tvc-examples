/**
 * GitHub App key helpers for the admin tool. The PEM is read by this process
 * and handed to the SDK, which HPKE-encrypts it to the Signer's ingress
 * target key. The PEM is never printed.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import type { TurnkeyApiClient } from "@turnkey/sdk-server";

export const SECRET_SCHEMA = "github-app-key-v1";

/** `SHA256:<base64>` of the SPKI DER: the fingerprint GitHub shows in App settings. */
export function keyFingerprint(pem: string): string {
  const der = crypto.createPublicKey(pem).export({ type: "spki", format: "der" });
  return "SHA256:" + crypto.createHash("sha256").update(der).digest("base64");
}

/** Validate that a PEM is a PKCS#1 RSA-2048 private key, as GitHub issues. */
export function checkGitHubPem(pem: string): void {
  if (!pem.includes("-----BEGIN RSA PRIVATE KEY-----")) throw new Error("expected a PKCS#1 'RSA PRIVATE KEY' PEM (GitHub's download format)");
  const k = crypto.createPrivateKey(pem);
  if (k.asymmetricKeyType !== "rsa" || k.asymmetricKeyDetails?.modulusLength !== 2048) throw new Error("expected an RSA-2048 key");
}

/** A throwaway RSA-2048 key in GitHub's format, for tests and dev-environment proofs. Never a real App key. */
export function generateThrowawayPem(): { pem: string; publicSpkiPem: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 65537,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return { pem: privateKey, publicSpkiPem: publicKey };
}

export async function importAppKey(p: {
  client: TurnkeyApiClient;
  organizationId: string;
  pemPath: string;
  appClientId: string;
  name?: string;
  signerPublicKey?: string;
}): Promise<{ secretId: string; fingerprint: string }> {
  const pem = fs.readFileSync(p.pemPath, "utf8");
  checkGitHubPem(pem);
  const fingerprint = keyFingerprint(pem);
  const secretId = await p.client.importSecret({
    organizationId: p.organizationId,
    plaintext: pem,
    name: p.name ?? `github-app-${p.appClientId}-${Date.now().toString(36)}`,
    staticProperties: {
      "demo:schema": SECRET_SCHEMA,
      "github:app_client_id": p.appClientId,
      "github:key_sha256": fingerprint,
    },
    ...(p.signerPublicKey ? { dangerouslyOverrideSignerPublicKey: p.signerPublicKey } : {}),
  });
  return { secretId, fingerprint };
}

export function exportPolicy(brokerUserId: string) {
  return {
    policyName: "tvc-github-broker: broker may export the GitHub App key",
    effect: "EFFECT_ALLOW" as const,
    consensus: `approvers.any(user, user.id == '${brokerUserId}')`,
    condition: `activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['demo:schema'] == '${SECRET_SCHEMA}'`,
    notes: "tvc-github-broker: lets the TVC broker's API user export github-app-key-v1 secrets without other approvers. Remove after the demo.",
  };
}
