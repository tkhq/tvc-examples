//! Build a Turnkey `SIGN_TRANSACTION_V2` activity request body.
//!
//! This JSON is what we stamp and the customer submits to Turnkey. The shape and
//! field names are verified against Turnkey's API reference
//! (`POST /public/v1/submit/sign_transaction`):
//!
//!   { type, timestampMs, organizationId,
//!     parameters: { signWith, unsignedTransaction, type } }
//!
//! `unsignedTransaction` is the raw Ethereum transaction as hex WITHOUT a `0x`
//! prefix (matching Turnkey's SDKs). We accept either form on input and
//! normalize to no-prefix lowercase so the stamped bytes are deterministic.

use serde::Serialize;

const ACTIVITY_TYPE_SIGN_TRANSACTION: &str = "ACTIVITY_TYPE_SIGN_TRANSACTION_V2";
const TRANSACTION_TYPE_ETHEREUM: &str = "TRANSACTION_TYPE_ETHEREUM";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Parameters {
    sign_with: String,
    unsigned_transaction: String,
    #[serde(rename = "type")]
    tx_type: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignTransactionActivity {
    #[serde(rename = "type")]
    activity_type: &'static str,
    timestamp_ms: String,
    organization_id: String,
    parameters: Parameters,
}

/// Inputs needed to build a sign-transaction request.
pub struct SignTransaction<'a> {
    /// The customer's (sub-)organization id.
    pub organization_id: &'a str,
    /// Wallet account address / private key address / id to sign with.
    pub sign_with: &'a str,
    /// Raw unsigned Ethereum transaction, hex (with or without `0x`).
    pub unsigned_transaction: &'a str,
    /// Request timestamp in milliseconds (Turnkey uses it for liveness).
    pub timestamp_ms: u64,
}

/// Serialize a `SIGN_TRANSACTION_V2` activity to its exact JSON body.
///
/// The returned string is both stamped and sent — Turnkey re-hashes these exact
/// bytes, so it must be produced once and used for both.
pub fn build_sign_transaction(req: &SignTransaction) -> String {
    let activity = SignTransactionActivity {
        activity_type: ACTIVITY_TYPE_SIGN_TRANSACTION,
        timestamp_ms: req.timestamp_ms.to_string(),
        organization_id: req.organization_id.to_string(),
        parameters: Parameters {
            sign_with: req.sign_with.to_string(),
            unsigned_transaction: strip_0x(req.unsigned_transaction).to_ascii_lowercase(),
            tx_type: TRANSACTION_TYPE_ETHEREUM,
        },
    };
    serde_json::to_string(&activity).expect("activity serializes")
}

/// Strip a leading `0x`/`0X` if present.
fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn sample() -> SignTransaction<'static> {
        SignTransaction {
            organization_id: "org-123",
            sign_with: "0xabc0000000000000000000000000000000000001",
            unsigned_transaction: "0xDEADBEEF",
            timestamp_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn body_matches_turnkey_shape() {
        let body = build_sign_transaction(&sample());
        let v: Value = serde_json::from_str(&body).unwrap();

        assert_eq!(v["type"], "ACTIVITY_TYPE_SIGN_TRANSACTION_V2");
        assert_eq!(v["timestampMs"], "1700000000000"); // string, not number
        assert_eq!(v["organizationId"], "org-123");
        assert_eq!(v["parameters"]["signWith"], sample().sign_with);
        assert_eq!(v["parameters"]["type"], "TRANSACTION_TYPE_ETHEREUM");
    }

    #[test]
    fn unsigned_transaction_is_normalized() {
        let body = build_sign_transaction(&sample());
        let v: Value = serde_json::from_str(&body).unwrap();
        // 0x stripped, lowercased.
        assert_eq!(v["parameters"]["unsignedTransaction"], "deadbeef");
    }

    #[test]
    fn accepts_input_without_0x() {
        let mut req = sample();
        req.unsigned_transaction = "deadbeef";
        let body = build_sign_transaction(&req);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["parameters"]["unsignedTransaction"], "deadbeef");
    }

    #[test]
    fn build_is_deterministic() {
        assert_eq!(
            build_sign_transaction(&sample()),
            build_sign_transaction(&sample())
        );
    }

    /// The whole point: an activity body can be stamped and the stamp verifies.
    #[test]
    fn activity_body_can_be_stamped_and_verified() {
        use crate::keys::KeySet;
        use crate::stamp::stamp;
        use base64::Engine;
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};

        let body = build_sign_transaction(&sample());
        let keys = KeySet::derive(&[7u8; 32]);
        let stamped = stamp(&keys.programmatic, &body);

        let env: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&stamped.x_stamp)
                .unwrap(),
        )
        .unwrap();

        let vk = VerifyingKey::from_sec1_bytes(
            &hex::decode(env["publicKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let sig =
            Signature::from_der(&hex::decode(env["signature"].as_str().unwrap()).unwrap()).unwrap();

        vk.verify(stamped.body.as_bytes(), &sig)
            .expect("stamp over the activity body verifies");
    }
}
