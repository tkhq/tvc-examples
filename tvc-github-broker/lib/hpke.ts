/**
 * HPKE (RFC 9180, base mode) with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
 * AES-256-GCM, via @hpke/core.
 *
 * Broker token delivery: info = "tkhq/tvc-github-broker/installation-token/v1",
 * aad = the request's `tk_body_digest`.
 */
import { Aes256Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { type Bytes, te } from "./encoding.ts";

const suite =new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
export const DELIVERY_INFO = te.encode("tkhq/tvc-github-broker/installation-token/v1");

/** @hpke/core takes ArrayBuffer inputs. */
const ab = (b: Bytes): ArrayBuffer => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);

export type RecipientKey = { keyPair: CryptoKeyPair; publicKey: Bytes };

export async function generateRecipient(): Promise<RecipientKey> {
  const keyPair = await suite.kem.generateKeyPair();
  const publicKey = new Uint8Array(await suite.kem.serializePublicKey(keyPair.publicKey));
  return { keyPair, publicKey };
}

export async function seal(recipientPublic: Bytes, plaintext: Bytes, info: Bytes, aad: Bytes): Promise<{ enc: Bytes; ct: Bytes }> {
  const pk = await suite.kem.deserializePublicKey(ab(recipientPublic));
  const r = await suite.seal({ recipientPublicKey: pk, info: ab(info) }, ab(plaintext), ab(aad));
  return { enc: new Uint8Array(r.enc), ct: new Uint8Array(r.ct) };
}

export async function open(recipient: RecipientKey, enc: Bytes, ct: Bytes, info: Bytes, aad: Bytes): Promise<Bytes> {
  return new Uint8Array(await suite.open({ recipientKey: recipient.keyPair, enc: ab(enc), info: ab(info) }, ab(ct), ab(aad)));
}
