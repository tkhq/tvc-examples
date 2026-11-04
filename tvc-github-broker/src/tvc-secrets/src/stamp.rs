//! Turnkey API request stamping with a P-256 API key
//! (`X-Stamp`, `SIGNATURE_SCHEME_TK_API_P256`).
//!
//! The key material is parsed from bytes the caller already loaded. This
//! module never reads files.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::json;
use zeroize::Zeroizing;

use crate::SecretsError;

/// The stamp scheme for P-256 API keys.
pub const STAMP_SCHEME: &str = "SIGNATURE_SCHEME_TK_API_P256";
/// The request header that carries the stamp.
pub const STAMP_HEADER: &str = "X-Stamp";

/// A Turnkey P-256 API key.
pub struct ApiKey {
    signing: SigningKey,
    public_hex: String,
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKey({})", self.public_hex)
    }
}

impl ApiKey {
    /// Parse `{"publicKey": <compressed hex>, "privateKey": <hex>}` (SDK
    /// style) or the `public_key`/`private_key` form. The derived public key
    /// must match.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::InvalidApiKey`] for a malformed document or
    /// mismatched keys.
    pub fn from_json(bytes: &[u8]) -> Result<Self, SecretsError> {
        #[derive(serde::Deserialize)]
        struct KeyFile {
            #[serde(alias = "public_key", rename = "publicKey")]
            public: String,
            #[serde(alias = "private_key", rename = "privateKey")]
            private: String,
        }
        let file: KeyFile = serde_json::from_slice(bytes)
            .map_err(|_| SecretsError::InvalidApiKey("expected {publicKey, privateKey}".into()))?;
        let private = Zeroizing::new(file.private);
        let key = Self::from_private_hex(&private)?;
        if !key.public_hex.eq_ignore_ascii_case(&file.public) {
            return Err(SecretsError::InvalidApiKey(
                "publicKey does not match privateKey".into(),
            ));
        }
        Ok(key)
    }

    /// Build a key from the hex-encoded P-256 scalar.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::InvalidApiKey`] if the value is not a valid
    /// scalar.
    pub fn from_private_hex(private_hex: &str) -> Result<Self, SecretsError> {
        let scalar = Zeroizing::new(
            hex::decode(private_hex)
                .map_err(|_| SecretsError::InvalidApiKey("privateKey is not hex".into()))?,
        );
        let signing = SigningKey::from_slice(&scalar)
            .map_err(|_| SecretsError::InvalidApiKey("privateKey is not a P-256 scalar".into()))?;
        let public_hex = hex::encode(
            VerifyingKey::from(&signing)
                .to_encoded_point(true)
                .as_bytes(),
        );
        Ok(Self {
            signing,
            public_hex,
        })
    }

    /// Compressed public key, hex. This is the value registered with Turnkey.
    #[must_use]
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    /// The `X-Stamp` header value for `body`: base64url JSON with the
    /// compressed public key, the scheme, and a DER ECDSA signature (hex) over
    /// the exact body bytes.
    #[must_use]
    pub fn stamp(&self, body: &[u8]) -> String {
        let sig: Signature = self.signing.sign(body);
        let stamp = json!({
            "publicKey": self.public_hex,
            "scheme": STAMP_SCHEME,
            "signature": hex::encode(sig.to_der().as_bytes()),
        });
        URL_SAFE_NO_PAD.encode(stamp.to_string().as_bytes())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use serde_json::Value;

    // A throwaway key generated for this test only.
    const PRIV: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn key_json() -> String {
        let sk = SigningKey::from_slice(&hex::decode(PRIV).unwrap()).unwrap();
        let pk = hex::encode(VerifyingKey::from(&sk).to_encoded_point(true).as_bytes());
        format!(r#"{{"publicKey":"{pk}","privateKey":"{PRIV}"}}"#)
    }

    #[test]
    fn stamp_verifies_over_exact_body() {
        let k = ApiKey::from_json(key_json().as_bytes()).unwrap();
        let stamp: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(k.stamp(b"{\"a\":1}")).unwrap())
                .unwrap();
        assert_eq!(stamp["scheme"], STAMP_SCHEME);
        let vk = VerifyingKey::from_sec1_bytes(
            &hex::decode(stamp["publicKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let sig = Signature::from_der(&hex::decode(stamp["signature"].as_str().unwrap()).unwrap())
            .unwrap();
        assert!(vk.verify(b"{\"a\":1}", &sig).is_ok());
        assert!(vk.verify(b"{\"a\":2}", &sig).is_err());
    }

    #[test]
    fn rejects_mismatched_key_file() {
        let bad = key_json().replace("\"publicKey\":\"0", "\"publicKey\":\"1");
        assert!(ApiKey::from_json(bad.as_bytes()).is_err());
        assert!(
            format!("{:?}", ApiKey::from_json(key_json().as_bytes()).unwrap())
                .starts_with("ApiKey(0")
        );
        assert!(ApiKey::from_private_hex("zz").is_err());
        assert_eq!(
            ApiKey::from_private_hex(PRIV).unwrap().public_hex(),
            ApiKey::from_json(key_json().as_bytes())
                .unwrap()
                .public_hex()
        );
    }
}
