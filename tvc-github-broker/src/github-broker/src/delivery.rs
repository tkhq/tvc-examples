//! HPKE delivery of the installation token to the caller.
//!
//! HPKE delivery is **required**. The request body is
//! `{"hpke_public_key":"<base64url SEC1 uncompressed P-256 point>"}`. The body
//! digest is in the authorization JWT, so nobody between the caller and the
//! app can swap the key. The token is encrypted inside the app, so the TVC
//! host, the ingress, and any TLS terminator in front of the enclave see only
//! ciphertext.
//!
//! Suite (RFC 9180, base mode): DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
//! AES-256-GCM. `info` is [`INFO`]. `aad` is the authorization JWT's
//! `tk_body_digest`, which binds the ciphertext to the request body that
//! produced it.

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeS, Serializable};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::b64;

type Kem = DhP256HkdfSha256;

/// HPKE `info` for token delivery.
pub const INFO: &[u8] = b"tkhq/tvc-github-broker/installation-token/v1";
/// Human-readable suite name, returned to the caller.
pub const SUITE: &str = "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM";

/// The request body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequestBody {
    /// Caller's HPKE public key, base64url SEC1 uncompressed.
    pub hpke_public_key: String,
}

/// The sealed token.
#[derive(Serialize, Debug)]
pub struct SealedToken {
    /// Suite name.
    pub suite: &'static str,
    /// base64url encapsulated key.
    pub encapsulated_key: String,
    /// base64url ciphertext (AES-GCM output with tag).
    pub ciphertext: String,
    /// What the AAD is.
    pub aad: &'static str,
}

/// A delivery failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryError(pub &'static str);

/// Parse and validate the request body.
///
/// # Errors
///
/// Returns an error for malformed JSON, unknown fields, or a bad key.
pub fn parse_recipient(body: &[u8]) -> Result<<Kem as hpke::Kem>::PublicKey, DeliveryError> {
    let req: TokenRequestBody = serde_json::from_slice(body)
        .map_err(|_| DeliveryError("body must be {\"hpke_public_key\": \"<base64url>\"}"))?;
    let bytes = b64::url_decode(&req.hpke_public_key)
        .filter(|b| b.len() == 65)
        .ok_or(DeliveryError(
            "hpke_public_key must be a 65-byte uncompressed P-256 point",
        ))?;
    <Kem as hpke::Kem>::PublicKey::from_bytes(&bytes)
        .map_err(|_| DeliveryError("hpke_public_key is not a valid P-256 point"))
}

/// Seal `plaintext` to `recipient` with `aad`.
///
/// # Errors
///
/// Returns an error if HPKE fails.
pub fn seal(
    recipient: &<Kem as hpke::Kem>::PublicKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedToken, DeliveryError> {
    let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        recipient,
        INFO,
        plaintext,
        aad,
        &mut OsRng,
    )
    .map_err(|_| DeliveryError("HPKE seal failed"))?;
    Ok(SealedToken {
        suite: SUITE,
        encapsulated_key: b64::url_encode(&enc.to_bytes()),
        ciphertext: b64::url_encode(&ct),
        aad: "tk_body_digest",
    })
}

/// Generate a recipient key pair (tests and tools).
#[must_use]
pub fn generate() -> (
    <Kem as hpke::Kem>::PrivateKey,
    <Kem as hpke::Kem>::PublicKey,
) {
    Kem::gen_keypair(&mut OsRng)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use hpke::OpModeR;

    #[test]
    fn round_trip_and_aad_binding() {
        let (sk, pk) = generate();
        let body = format!(
            r#"{{"hpke_public_key":"{}"}}"#,
            b64::url_encode(&pk.to_bytes())
        );
        let recipient = parse_recipient(body.as_bytes()).unwrap();
        let sealed = seal(&recipient, b"ghs_token", b"sha-256=:a:").unwrap();
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(
            &b64::url_decode(&sealed.encapsulated_key).unwrap(),
        )
        .unwrap();
        let ct = b64::url_decode(&sealed.ciphertext).unwrap();
        let open = |aad: &[u8]| {
            hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
                &OpModeR::Base,
                &sk,
                &enc,
                INFO,
                &ct,
                aad,
            )
        };
        assert_eq!(open(b"sha-256=:a:").unwrap(), b"ghs_token");
        assert!(open(b"sha-256=:b:").is_err());
    }

    #[test]
    fn rejects_bad_bodies() {
        assert!(parse_recipient(b"").is_err());
        assert!(parse_recipient(br#"{"hpke_public_key":"AA"}"#).is_err());
        assert!(parse_recipient(br#"{"hpke_public_key":"AA","x":1}"#).is_err());
        let off_curve = b64::url_encode(&[4u8; 65]);
        assert!(
            parse_recipient(format!(r#"{{"hpke_public_key":"{off_curve}"}}"#).as_bytes()).is_err()
        );
    }
}
