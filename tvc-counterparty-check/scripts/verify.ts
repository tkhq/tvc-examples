// Verify the appProof in a /check response, offline, with only node:crypto.
//
//   curl -s -X POST https://<app-domain>/check -d '{"to":"0x..."}' | node scripts/verify.ts
//   node scripts/verify.ts response.json
//
// This checks step 1 of the TVC verification flow (the App Proof signature).
// Steps 2 and 3, verifying the Boot Proof and matching its ephemeral key to the
// publicKey below, are described in the README.

import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const source = process.argv[2] ?? 0; // 0 = stdin
const response = JSON.parse(readFileSync(source, "utf8"));

const proof = response.appProof;
if (!proof) {
  fail("response has no appProof (the app is not running inside an enclave, or EPHEMERAL_KEY_FILE is unset)");
}
if (proof.scheme !== "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256") {
  fail(`unexpected scheme ${proof.scheme}`);
}

// publicKey is uncompressed SEC1: 04 || X (32 bytes) || Y (32 bytes).
const pub = Buffer.from(proof.publicKey, "hex");
if (pub.length !== 65 || pub[0] !== 0x04) {
  fail("publicKey is not a 65-byte uncompressed P-256 point");
}
const key = createPublicKey({
  key: {
    kty: "EC",
    crv: "P-256",
    x: pub.subarray(1, 33).toString("base64url"),
    y: pub.subarray(33, 65).toString("base64url"),
  },
  format: "jwk",
});

// The signature is ECDSA (DER) over SHA-256(proofPayload).
const ok = verify(
  "sha256",
  Buffer.from(proof.proofPayload),
  { key, dsaEncoding: "der" },
  Buffer.from(proof.signature, "hex"),
);
if (!ok) fail("signature does NOT verify");

const payload = JSON.parse(proof.proofPayload);
console.log("app proof signature: OK");
console.log(`verdict:              ${payload.allowed ? "ALLOWED" : "DENIED"} (${payload.reason})`);
console.log("signed payload:      ", proof.proofPayload);
console.log("ephemeral public key:", proof.publicKey);
if (response.bootEphemeralKey) {
  console.log("boot ephemeral key:  ", response.bootEphemeralKey);
  console.log(
    "\nnext: fetch the Boot Proof for this boot ephemeral key and confirm its\n" +
      "ephemeralPublicKeyHex matches the ephemeral public key above (see README).",
  );
}

function fail(message: string): never {
  console.error(`verification failed: ${message}`);
  process.exit(1);
}
