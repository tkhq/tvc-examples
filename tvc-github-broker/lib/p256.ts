/** P-256 key generation in the Turnkey API-key file format. */
import { fromB64url, hex } from "./encoding.ts";

type ApiKeyFile ={ publicKey: string; privateKey: string };

/** Generate a P-256 key as a hex scalar and a compressed public key. */
export async function generateApiKey(): Promise<ApiKeyFile> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const x = fromB64url(jwk.x!);
  const y = fromB64url(jwk.y!);
  const prefix = new Uint8Array([0x02 | (y[31]! & 1)]);
  return { publicKey: hex(Uint8Array.from([...prefix, ...x])), privateKey: hex(fromB64url(jwk.d!)) };
}
