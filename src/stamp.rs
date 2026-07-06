//! Turnkey request stamping.
//!
//! A "stamp" is how a request authenticates itself to Turnkey as a given API
//! user. We sign the exact request body with a derived P-256 key and wrap the
//! signature in the envelope Turnkey expects:
//!
//!   signature = ECDSA-P256 over SHA-256(body), DER-encoded, hex.
//!   envelope  = base64url(JSON { publicKey, scheme, signature }).
//!
//! The envelope string is sent as the `X-Stamp` HTTP header alongside the
//! unmodified body. Turnkey recomputes SHA-256(body) and verifies the signature
//! against the registered public key.

use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use serde::Serialize;

use crate::keys::ApiKey;

/// Turnkey's signature-scheme identifier for P-256 API-key stamps.
const STAMP_SCHEME: &str = "SIGNATURE_SCHEME_TK_API_P256";

/// The stamp envelope. Field names are camelCase to match Turnkey's JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StampEnvelope {
    public_key: String,
    scheme: &'static str,
    signature: String,
}

/// A signed request, ready to POST to Turnkey.
#[allow(dead_code)] // consumed once POST /cosign is wired up
pub struct Stamped {
    /// The exact body bytes that were signed — send these unmodified.
    pub body: String,
    /// Value for the `X-Stamp` header.
    pub x_stamp: String,
}

/// Sign `body` with `key` and produce the `X-Stamp` header value.
#[allow(dead_code)] // consumed once POST /cosign is wired up
pub fn stamp(key: &ApiKey, body: &str) -> Stamped {
    // RustCrypto's `Signer` for P-256 hashes the message with SHA-256 and emits
    // a low-S–normalized signature — the same construction Turnkey verifies.
    let sig: Signature = key.signing_key().sign(body.as_bytes());
    let signature_hex = hex::encode(sig.to_der().as_bytes());

    let envelope = StampEnvelope {
        public_key: key.public_key_hex(),
        scheme: STAMP_SCHEME,
        signature: signature_hex,
    };
    let json = serde_json::to_string(&envelope).expect("stamp envelope serializes");
    let x_stamp = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);

    Stamped {
        body: body.to_string(),
        x_stamp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeySet;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;
    use serde_json::Value;

    const SEED: [u8; 32] = [0x42; 32];
    const BODY: &str = r#"{"type":"ACTIVITY_TYPE_SIGN_TRANSACTION_V2","hello":"world"}"#;

    /// Decode the base64url X-Stamp back into its JSON envelope.
    fn decode_stamp(x_stamp: &str) -> Value {
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x_stamp)
            .expect("x_stamp is valid base64url");
        serde_json::from_slice(&json).expect("x_stamp decodes to JSON")
    }

    #[test]
    fn envelope_has_expected_shape() {
        let keys = KeySet::derive(&SEED);
        let stamped = stamp(&keys.programmatic, BODY);
        let env = decode_stamp(&stamped.x_stamp);

        assert_eq!(env["scheme"], STAMP_SCHEME);
        assert_eq!(env["publicKey"], keys.programmatic.public_key_hex());
        assert!(env["signature"].as_str().unwrap().len() > 0);
        assert_eq!(stamped.body, BODY, "body is returned unmodified");
    }

    #[test]
    fn signature_verifies_against_the_public_key() {
        let keys = KeySet::derive(&SEED);
        let stamped = stamp(&keys.admin, BODY);
        let env = decode_stamp(&stamped.x_stamp);

        // Reconstruct the verifying key from the compressed SEC1 hex in the stamp.
        let pk_bytes = hex::decode(env["publicKey"].as_str().unwrap()).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&pk_bytes).expect("valid SEC1 pubkey");

        // Parse the DER signature and verify it over the body (SHA-256 internally).
        let sig_bytes = hex::decode(env["signature"].as_str().unwrap()).unwrap();
        let sig = Signature::from_der(&sig_bytes).expect("valid DER signature");

        vk.verify(BODY.as_bytes(), &sig)
            .expect("stamp signature verifies against its own public key");
    }

    #[test]
    fn wrong_body_fails_verification() {
        let keys = KeySet::derive(&SEED);
        let stamped = stamp(&keys.programmatic, BODY);
        let env = decode_stamp(&stamped.x_stamp);

        let pk_bytes = hex::decode(env["publicKey"].as_str().unwrap()).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&pk_bytes).unwrap();
        let sig_bytes = hex::decode(env["signature"].as_str().unwrap()).unwrap();
        let sig = Signature::from_der(&sig_bytes).unwrap();

        assert!(
            vk.verify(b"tampered body", &sig).is_err(),
            "a signature must not verify over a different body"
        );
    }
}
