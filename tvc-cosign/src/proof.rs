//! App Proof over the cosign decision — the verifiability story.
//!
//! Stamping (see `stamp.rs`) authenticates the request to Turnkey as an API user.
//! An *App Proof* proves something stronger and orthogonal: that *this enclave*,
//! running *this attested code*, classified *this transaction* *this way*. It is
//! a statement signed by the enclave's Ephemeral Key — a per-boot P-256 key whose
//! public half is pinned in the enclave's Boot Proof. A verifier fetches the Boot
//! Proof from Turnkey by that public key, confirms it against the expected code
//! manifest, then verifies this signature — linking the decision to the code.
//!
//! Envelope matches Turnkey's standardized App Proof:
//!
//!   { scheme, publicKey, proofPayload (stringified JSON), signature }
//!
//!   signature = ECDSA-P256 over SHA-256(proofPayload bytes), DER-encoded, hex.
//!
//! `proofPayload` is a strictly-typed JSON string. We define one proof type,
//! `APP_PROOF_TYPE_COSIGN_DECISION`, committing to the facts a verifier cares
//! about: which wallet, which transaction, the classification, the stamping key,
//! and a digest binding the proof to the exact request that was stamped.

use p256::ecdsa::Signature;
use p256::ecdsa::signature::Signer;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::keys::EphemeralKey;
use crate::rules::Classification;

/// Turnkey's signature-scheme identifier for Ephemeral-Key App Proofs.
const APP_PROOF_SCHEME: &str = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";

/// This application's proof type. Turnkey's own proof types (e.g.
/// `APP_PROOF_TYPE_POLICY_OUTCOME`) are reserved; TVC apps define their own.
const COSIGN_PROOF_TYPE: &str = "APP_PROOF_TYPE_COSIGN_DECISION";

/// The facts this proof commits to. Serialized (as a string) into `proofPayload`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CosignDecision<'a> {
    /// The (sub-)organization the request targets.
    organization_id: &'a str,
    /// The wallet the transaction would be signed by (`signWith`).
    signer_address: &'a str,
    /// The unsigned transaction, normalized to no-`0x` lowercase hex — the exact
    /// form that appears in the stamped activity body.
    unsigned_transaction: &'a str,
    /// How the enclave routed it: `PROGRAMMATIC` or `ADMIN`.
    classification: Classification,
    /// Compressed-SEC1 hex of the derived API key that stamped the request. Lets a
    /// verifier confirm which Turnkey user (and thus which policy path) applies.
    stamped_with: &'a str,
    /// SHA-256 (hex) of the exact stamped activity body. Binds this proof to the
    /// precise bytes the customer submits to Turnkey — re-serialize and it breaks.
    activity_body_sha256: String,
}

/// The typed proof payload: `{ type, timestampMs, cosignDecision }`, matching the
/// shape of Turnkey's own App Proof payloads.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofPayload<'a> {
    #[serde(rename = "type")]
    proof_type: &'static str,
    timestamp_ms: String,
    cosign_decision: CosignDecision<'a>,
}

/// A finished App Proof, ready to embed in the `/cosign` response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProof {
    scheme: &'static str,
    public_key: String,
    /// The JSON proof payload, serialized to a string (verifiers hash these bytes).
    proof_payload: String,
    /// ECDSA-P256/SHA-256/DER signature over `proof_payload`, hex.
    signature: String,
}

/// Everything needed to build a cosign App Proof.
pub struct ProofInputs<'a> {
    pub organization_id: &'a str,
    pub signer_address: &'a str,
    pub unsigned_transaction: &'a str,
    pub classification: Classification,
    /// Compressed-SEC1 hex of the key that stamped the request.
    pub stamped_with: &'a str,
    /// The exact stamped activity body (bound into the proof via its digest).
    pub activity_body: &'a str,
    pub timestamp_ms: u64,
}

/// Build and sign an App Proof over a cosign decision, using the enclave's
/// ephemeral key.
pub fn app_proof(ephemeral: &EphemeralKey, inputs: &ProofInputs) -> AppProof {
    let activity_body_sha256 = hex::encode(Sha256::digest(inputs.activity_body.as_bytes()));

    let payload = ProofPayload {
        proof_type: COSIGN_PROOF_TYPE,
        timestamp_ms: inputs.timestamp_ms.to_string(),
        cosign_decision: CosignDecision {
            organization_id: inputs.organization_id,
            signer_address: inputs.signer_address,
            unsigned_transaction: inputs.unsigned_transaction,
            classification: inputs.classification,
            stamped_with: inputs.stamped_with,
            activity_body_sha256,
        },
    };

    // Serialize once — this exact string is both signed and returned. A verifier
    // re-hashes these bytes, so they must not be re-serialized downstream.
    let proof_payload = serde_json::to_string(&payload).expect("proof payload serializes");

    // RustCrypto's `Signer` for P-256 hashes with SHA-256 and low-S–normalizes —
    // the construction Turnkey verifies App Proofs against.
    let sig: Signature = ephemeral.signing_key().sign(proof_payload.as_bytes());

    AppProof {
        scheme: APP_PROOF_SCHEME,
        public_key: ephemeral.public_key_hex().to_string(),
        proof_payload,
        signature: hex::encode(sig.to_der().as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;
    use serde_json::Value;

    fn ephemeral() -> EphemeralKey {
        EphemeralKey::derive(&[0x42; 32])
    }

    fn inputs<'a>() -> ProofInputs<'a> {
        ProofInputs {
            organization_id: "org-123",
            signer_address: "0xabc0000000000000000000000000000000000001",
            unsigned_transaction: "deadbeef",
            classification: Classification::Programmatic,
            stamped_with: "02aaaa",
            activity_body: r#"{"type":"ACTIVITY_TYPE_SIGN_TRANSACTION_V2"}"#,
            timestamp_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn envelope_has_expected_shape() {
        let key = ephemeral();
        let proof = app_proof(&key, &inputs());
        let v: Value = serde_json::to_value(&proof).unwrap();

        assert_eq!(v["scheme"], APP_PROOF_SCHEME);
        assert_eq!(v["publicKey"], key.public_key_hex());
        assert!(!v["signature"].as_str().unwrap().is_empty());

        // proofPayload is a JSON *string*; parse it and check the typed schema.
        let payload: Value = serde_json::from_str(v["proofPayload"].as_str().unwrap()).unwrap();
        assert_eq!(payload["type"], COSIGN_PROOF_TYPE);
        assert_eq!(payload["timestampMs"], "1700000000000");
        assert_eq!(payload["cosignDecision"]["classification"], "PROGRAMMATIC");
        assert_eq!(
            payload["cosignDecision"]["signerAddress"],
            inputs().signer_address
        );
    }

    #[test]
    fn payload_commits_to_the_activity_body() {
        let proof = app_proof(&ephemeral(), &inputs());
        let payload: Value = serde_json::from_str(&proof.proof_payload).unwrap();
        let expected = hex::encode(Sha256::digest(inputs().activity_body.as_bytes()));
        assert_eq!(payload["cosignDecision"]["activityBodySha256"], expected);
    }

    #[test]
    fn signature_verifies_against_the_ephemeral_key() {
        let key = ephemeral();
        let proof = app_proof(&key, &inputs());

        let vk = VerifyingKey::from_sec1_bytes(&hex::decode(&proof.public_key).unwrap()).unwrap();
        let sig = Signature::from_der(&hex::decode(&proof.signature).unwrap()).unwrap();

        vk.verify(proof.proof_payload.as_bytes(), &sig)
            .expect("app proof signature verifies over its payload");
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = ephemeral();
        let proof = app_proof(&key, &inputs());

        let vk = VerifyingKey::from_sec1_bytes(&hex::decode(&proof.public_key).unwrap()).unwrap();
        let sig = Signature::from_der(&hex::decode(&proof.signature).unwrap()).unwrap();

        let tampered = proof.proof_payload.replace("PROGRAMMATIC", "ADMIN");
        assert_ne!(tampered, proof.proof_payload);
        assert!(
            vk.verify(tampered.as_bytes(), &sig).is_err(),
            "a proof must not verify after its decision is altered"
        );
    }
}
