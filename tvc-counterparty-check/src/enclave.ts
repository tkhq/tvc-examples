// Everything that touches the enclave's Ephemeral Key lives here.
//
// When a TVC enclave boots, QOS writes a 32-byte master seed (hex) to
// /qos.ephemeral.key. That seed never leaves the enclave and is different for
// every boot. From it we derive the same two P-256 keys QOS does
// (https://github.com/tkhq/qos/blob/main/src/qos_p256/SPEC.md):
//
//   signing key    = HKDF-SHA512(seed, salt = "qos_p256_sign")
//   encryption key = HKDF-SHA512(seed, salt = "qos_p256_encrypt")
//
// A signature by the signing key is an "App Proof": proof that this exact
// enclave produced a payload. The two public keys concatenated form the
// "boot ephemeral key", which is what Turnkey uses to look up the Boot Proof
// (the AWS Nitro attestation) for the same enclave.

import {
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

// Override for local testing (see README). Inside TVC the default is correct.
export const EPHEMERAL_KEY_FILE =
  process.env.EPHEMERAL_KEY_FILE ?? "/qos.ephemeral.key";

const SIGN_DERIVE_PATH = "qos_p256_sign";
const ENCRYPT_DERIVE_PATH = "qos_p256_encrypt";

export interface EnclaveKeys {
  signingKey: KeyObject;
  /** Uncompressed SEC1 public key, hex: 04 || X || Y (65 bytes). */
  signingPublicKeyHex: string;
  /** encryptPub || signPub, hex (130 bytes). Used to fetch the Boot Proof. */
  bootEphemeralKey: string;
}

export interface AppProof {
  scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
  publicKey: string;
  proofPayload: string;
  signature: string;
}

/**
 * Load the master seed and derive the enclave keys.
 * Returns null when the key file does not exist, which is the normal case when
 * running outside an enclave: the app still works, it just cannot sign.
 */
export function loadEnclaveKeys(): EnclaveKeys | null {
  if (!existsSync(EPHEMERAL_KEY_FILE)) return null;

  const seedHex = readFileSync(EPHEMERAL_KEY_FILE, "utf8").trim();
  const masterSeed = Buffer.from(seedHex, "hex");
  if (masterSeed.length !== 32) {
    throw new Error(
      `${EPHEMERAL_KEY_FILE}: expected a 32-byte hex master seed, got ${masterSeed.length} bytes`,
    );
  }

  const signingKey = p256KeyFromSeed(masterSeed, SIGN_DERIVE_PATH);
  const encryptionKey = p256KeyFromSeed(masterSeed, ENCRYPT_DERIVE_PATH);

  const signPub = uncompressedPublicKeyHex(signingKey);
  const encryptPub = uncompressedPublicKeyHex(encryptionKey);

  return {
    signingKey,
    signingPublicKeyHex: signPub,
    bootEphemeralKey: encryptPub + signPub,
  };
}

/** Sign a JSON-serializable payload with the enclave signing key. */
export function signPayload(keys: EnclaveKeys, payload: unknown): AppProof {
  const proofPayload = JSON.stringify(payload);
  const signature = sign("sha256", Buffer.from(proofPayload), {
    key: keys.signingKey,
    dsaEncoding: "der",
  });
  return {
    scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
    publicKey: keys.signingPublicKeyHex,
    proofPayload,
    signature: signature.toString("hex"),
  };
}

/** Derive a P-256 private key from the master seed for one QOS derive path. */
function p256KeyFromSeed(masterSeed: Buffer, derivePath: string): KeyObject {
  const secret = Buffer.from(hkdfSync("sha512", masterSeed, derivePath, "", 32));

  // Node has no "private key from raw scalar" API, so wrap the 32-byte scalar
  // in a minimal SEC1 ECPrivateKey DER structure:
  //   SEQUENCE { INTEGER 1, OCTET STRING secret, [0] OID prime256v1 }
  // The public key is optional in SEC1; Node computes it from the scalar.
  const der = Buffer.concat([
    Buffer.from("30310201010420", "hex"), // SEQUENCE(49) INTEGER(1) OCTET STRING(32)
    secret,
    Buffer.from("a00a06082a8648ce3d030107", "hex"), // [0] OID 1.2.840.10045.3.1.7
  ]);
  return createPrivateKey({ key: der, format: "der", type: "sec1" });
}

/** Export a key's public half as uncompressed SEC1 hex (04 || X || Y). */
function uncompressedPublicKeyHex(key: KeyObject): string {
  const jwk = createPublicKey(key).export({ format: "jwk" });
  const x = Buffer.from(jwk.x!, "base64url");
  const y = Buffer.from(jwk.y!, "base64url");
  return "04" + x.toString("hex") + y.toString("hex");
}
