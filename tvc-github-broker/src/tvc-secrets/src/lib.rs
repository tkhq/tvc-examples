//! Turnkey Secrets export client for TVC apps.
//!
//! [`SecretsClient::export_secret`] runs the whole export in process:
//!
//! 1. picks a P-256 HPKE target key: the enclave's ephemeral encrypt key when
//!    the config has the ephemeral seed ([`SecretsConfig::with_target_seed`]),
//!    otherwise a fresh in-memory key (`turnkey_enclave_encrypt`);
//! 2. submits `ACTIVITY_TYPE_EXPORT_SECRETS` for the secret, stamped with the
//!    app user's API key, with that target public key;
//! 3. polls the activity while it is `CREATED` or `PENDING`, and maps
//!    `CONSENSUS_NEEDED` and `REJECTED` to typed errors;
//! 4. verifies the Signer enclave signature on the returned `ServerSendMsgV1`
//!    against the pinned Signer public key and checks the organization ID;
//! 5. decrypts in process and returns the plaintext as [`SecretBytes`], which
//!    zeroizes on drop.
//!
//! The plaintext is never written to disk or logged. The API key material is
//! parsed from bytes the caller loaded ([`ApiKey::from_json`]); this crate
//! never reads files.
//!
//! ```no_run
//! use tvc_secrets::{ApiKey, SecretsClient, SecretsConfig, SignerPublicKey};
//!
//! # async fn run(api_key_json: &[u8]) -> Result<(), tvc_secrets::SecretsError> {
//! let config = SecretsConfig::new(
//!     "https://api.turnkey.com",
//!     "<organization id>",
//!     ApiKey::from_json(api_key_json)?,
//!     SignerPublicKey::from_hex("04...")?,
//! );
//! let client = SecretsClient::new(config)?;
//! let secret = client.export_secret("<secret id>").await?;
//! let _bytes: &[u8] = secret.expose();
//! # Ok(())
//! # }
//! ```

mod qos;
mod secret;
mod stamp;

use std::fmt;
use std::time::Duration;

use p256::ecdsa::VerifyingKey;
use serde_json::{Value, json};
use turnkey_enclave_encrypt::client::EnclaveEncryptClient;
use turnkey_enclave_encrypt::errors::EnclaveEncryptError;

pub use qos::{Seed, seed_from_hex};

pub use secret::{SecretBytes, SecretString};
pub use stamp::{ApiKey, STAMP_HEADER, STAMP_SCHEME};

/// Transport suite for the export.
pub const ENCRYPTION_SUITE: &str = "TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V1";
/// The activity type this client submits.
pub const ACTIVITY_TYPE: &str = "ACTIVITY_TYPE_EXPORT_SECRETS";
/// Default longest wait for a pending activity.
pub const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(30);
/// Default per-request HTTP timeout.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Time between activity polls.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Longest error message kept from a Turnkey response.
const MAX_MESSAGE_CHARS: usize = 300;

/// A failure of the export. Never contains secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsError {
    /// The configuration is unusable.
    InvalidConfig(String),
    /// The API key material is unusable.
    InvalidApiKey(String),
    /// Network or HTTP client failure.
    Transport(String),
    /// Turnkey refused the request (HTTP 401 or 403, for example a policy
    /// denial) or an approver rejected the activity.
    Denied {
        /// The activity, when one was created.
        activity_id: Option<String>,
        /// Turnkey's message, truncated.
        message: String,
    },
    /// Turnkey returned another HTTP error.
    Api {
        /// HTTP status.
        status: u16,
        /// Turnkey message, truncated.
        message: String,
    },
    /// The export needs more approvals.
    ConsensusNeeded {
        /// Activity to approve.
        activity_id: String,
    },
    /// The activity ended in another status, or did not finish in time.
    ActivityFailed {
        /// Activity ID.
        activity_id: String,
        /// Last observed status.
        status: String,
    },
    /// The response could not be used.
    BadResponse(String),
    /// The bundle names a Signer key other than the pinned one.
    UnpinnedSignerKey,
    /// Signature verification, organization check, or decryption of the
    /// export bundle failed.
    Verification(String),
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(e) => write!(f, "Turnkey Secrets configuration: {e}"),
            Self::InvalidApiKey(e) => write!(f, "Turnkey API key: {e}"),
            Self::Transport(e) => write!(f, "Turnkey transport error: {e}"),
            Self::Denied {
                activity_id: Some(id),
                message,
            } => write!(f, "{ACTIVITY_TYPE} denied (activity {id}): {message}"),
            Self::Denied {
                activity_id: None,
                message,
            } => write!(f, "{ACTIVITY_TYPE} denied: {message}"),
            Self::Api { status, message } => write!(f, "Turnkey returned {status}: {message}"),
            Self::ConsensusNeeded { activity_id } => write!(
                f,
                "{ACTIVITY_TYPE} needs consensus (activity {activity_id}, status \
                 ACTIVITY_STATUS_CONSENSUS_NEEDED). Approve the activity and retry, or give \
                 the app user an ALLOW policy that needs no other approvers"
            ),
            Self::ActivityFailed {
                activity_id,
                status,
            } => write!(
                f,
                "{ACTIVITY_TYPE} activity {activity_id} ended with {status}"
            ),
            Self::BadResponse(e) => write!(f, "Turnkey response: {e}"),
            Self::UnpinnedSignerKey => f.write_str(
                "export bundle: the enclave quorum key in the bundle is not the pinned Signer key",
            ),
            Self::Verification(e) => write!(f, "export bundle: {e}"),
        }
    }
}

impl std::error::Error for SecretsError {}

/// The pinned Signer enclave signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerPublicKey(VerifyingKey);

impl SignerPublicKey {
    /// Parse a hex Signer key: a 65-byte SEC1 uncompressed signing key, or a
    /// 130-byte quorum key (encryption key then signing key).
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::InvalidConfig`] for any other form.
    pub fn from_hex(hex_key: &str) -> Result<Self, SecretsError> {
        let bytes = hex::decode(hex_key)
            .map_err(|_| SecretsError::InvalidConfig("signer_public_key is not hex".into()))?;
        let signing = match bytes.len() {
            65 => &bytes[..],
            130 => &bytes[65..],
            _ => {
                return Err(SecretsError::InvalidConfig(
                    "signer_public_key must be 65 or 130 bytes".into(),
                ));
            }
        };
        VerifyingKey::from_sec1_bytes(signing)
            .map(Self)
            .map_err(|_| {
                SecretsError::InvalidConfig("signer_public_key is not a P-256 point".into())
            })
    }

    /// The verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }
}

/// Connection settings and credentials for the export.
pub struct SecretsConfig {
    /// API base URL, no trailing slash.
    pub api_base_url: String,
    /// Organization that owns the secrets. The bundle's organization must
    /// match.
    pub organization_id: String,
    /// The app user's API key, for stamping.
    pub api_key: ApiKey,
    /// Pinned Signer enclave signing key.
    pub signer_public_key: SignerPublicKey,
    /// Longest wait for a pending activity.
    pub poll_timeout: Duration,
    /// Per-request HTTP timeout.
    pub request_timeout: Duration,
    /// The enclave's ephemeral seed. When set, the export target is the encrypt
    /// key derived from it, not a fresh random key.
    target_seed: Option<Seed>,
}

impl SecretsConfig {
    /// Settings with the default timeouts.
    pub fn new(
        api_base_url: impl Into<String>,
        organization_id: impl Into<String>,
        api_key: ApiKey,
        signer_public_key: SignerPublicKey,
    ) -> Self {
        Self {
            api_base_url: api_base_url.into(),
            organization_id: organization_id.into(),
            api_key,
            signer_public_key,
            poll_timeout: DEFAULT_POLL_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            target_seed: None,
        }
    }

    /// Export to the encrypt key derived from the enclave's ephemeral seed.
    /// QOS attests that key's public half in the Boot Proof, so the exported
    /// secret can only be read inside that enclave.
    #[must_use]
    pub fn with_target_seed(mut self, seed: Seed) -> Self {
        self.target_seed = Some(seed);
        self
    }
}

/// A client for `EXPORT_SECRETS`.
pub struct SecretsClient {
    cfg: SecretsConfig,
    http: reqwest::Client,
}

impl fmt::Debug for SecretsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretsClient")
            .field("api_base_url", &self.cfg.api_base_url)
            .field("organization_id", &self.cfg.organization_id)
            .field("api_key", &self.cfg.api_key)
            .finish_non_exhaustive()
    }
}

fn now_ms() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
        .to_string()
}

fn truncate(message: &str) -> String {
    message.chars().take(MAX_MESSAGE_CHARS).collect()
}

fn activity_status(v: &Value) -> Result<(String, String), SecretsError> {
    let a = v
        .get("activity")
        .ok_or_else(|| SecretsError::BadResponse("no activity".into()))?;
    let id = a.get("id").and_then(Value::as_str).unwrap_or("").to_owned();
    let status = a
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| SecretsError::BadResponse("no activity status".into()))?
        .to_owned();
    Ok((id, status))
}

fn map_decrypt_error(e: &EnclaveEncryptError) -> SecretsError {
    match e {
        EnclaveEncryptError::InvalidEnclaveQuorumPublicKey => SecretsError::UnpinnedSignerKey,
        other => SecretsError::Verification(other.to_string()),
    }
}

impl SecretsClient {
    /// Build a client.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::InvalidConfig`] for a base URL that is not
    /// `http(s)://`, an empty organization ID, or an HTTP client that cannot
    /// be built.
    pub fn new(cfg: SecretsConfig) -> Result<Self, SecretsError> {
        if !(cfg.api_base_url.starts_with("https://") || cfg.api_base_url.starts_with("http://")) {
            return Err(SecretsError::InvalidConfig(
                "api_base_url must start with https:// or http://".into(),
            ));
        }
        if cfg.organization_id.is_empty() {
            return Err(SecretsError::InvalidConfig(
                "organization_id must not be empty".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(cfg.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| SecretsError::InvalidConfig(format!("HTTP client: {e}")))?;
        Ok(Self { cfg, http })
    }

    /// The settings.
    #[must_use]
    pub fn config(&self) -> &SecretsConfig {
        &self.cfg
    }

    /// The compressed public key of the stamping API key, hex.
    #[must_use]
    pub fn api_key_public_hex(&self) -> &str {
        self.cfg.api_key.public_hex()
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value, SecretsError> {
        let base = self.cfg.api_base_url.trim_end_matches('/');
        let bytes = body.to_string();
        let resp = self
            .http
            .post(format!("{base}{path}"))
            .header("Content-Type", "application/json")
            .header(STAMP_HEADER, self.cfg.api_key.stamp(bytes.as_bytes()))
            .body(bytes)
            .send()
            .await
            .map_err(|e| SecretsError::Transport(e.without_url().to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| SecretsError::Transport(e.without_url().to_string()))?;
        if !(200..300).contains(&status) {
            let message = truncate(
                serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_owned))
                    .unwrap_or_default()
                    .as_str(),
            );
            return Err(match status {
                401 | 403 => SecretsError::Denied {
                    activity_id: None,
                    message: format!("HTTP {status}: {message}"),
                },
                _ => SecretsError::Api { status, message },
            });
        }
        serde_json::from_str(&text).map_err(|_| SecretsError::BadResponse("not JSON".into()))
    }

    /// Export `secret_id` to a fresh in-memory target key and decrypt it.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretsError`] for a denial, a consensus requirement, a
    /// failed activity, an unpinned Signer key, a bad signature, or a
    /// decryption failure.
    pub async fn export_secret(&self, secret_id: &str) -> Result<SecretBytes, SecretsError> {
        let signer = *self.cfg.signer_public_key.verifying_key();
        let mut target = match &self.cfg.target_seed {
            Some(seed) => {
                let (public, private) = qos::target_key_pair(seed)?;
                EnclaveEncryptClient::from_enclave_auth_key_and_target_key(signer, public, private)
            }
            None => EnclaveEncryptClient::from_enclave_auth_key(signer),
        };
        let target_public = hex::encode(
            target
                .target_bytes()
                .map_err(|e| SecretsError::Verification(e.to_string()))?,
        );

        let body = json!({
            "type": ACTIVITY_TYPE,
            "timestampMs": now_ms(),
            "organizationId": self.cfg.organization_id,
            "parameters": {
                "secrets": [{
                    "secretId": secret_id,
                    "targetPublicKey": target_public,
                    "encryptionSuite": ENCRYPTION_SUITE,
                }]
            }
        });
        let mut resp = self.post("/public/v1/submit/export_secrets", &body).await?;
        let (activity_id, mut status) = activity_status(&resp)?;
        tracing::info!(activity_id, status, secret_id, "EXPORT_SECRETS submitted");

        let deadline = tokio::time::Instant::now() + self.cfg.poll_timeout;
        while matches!(
            status.as_str(),
            "ACTIVITY_STATUS_CREATED" | "ACTIVITY_STATUS_PENDING"
        ) {
            if tokio::time::Instant::now() >= deadline {
                return Err(SecretsError::ActivityFailed {
                    activity_id,
                    status,
                });
            }
            tokio::time::sleep(POLL_INTERVAL).await;
            let q = json!({"organizationId": self.cfg.organization_id, "activityId": activity_id});
            resp = self.post("/public/v1/query/get_activity", &q).await?;
            status = activity_status(&resp)?.1;
        }
        match status.as_str() {
            "ACTIVITY_STATUS_COMPLETED" => {}
            "ACTIVITY_STATUS_CONSENSUS_NEEDED" => {
                return Err(SecretsError::ConsensusNeeded { activity_id });
            }
            "ACTIVITY_STATUS_REJECTED" => {
                return Err(SecretsError::Denied {
                    activity_id: Some(activity_id),
                    message: "an approver rejected the activity".into(),
                });
            }
            _ => {
                return Err(SecretsError::ActivityFailed {
                    activity_id,
                    status,
                });
            }
        }
        let payload = resp
            .pointer("/activity/result/exportSecretsResult/secretPayloads/0")
            .and_then(Value::as_str)
            .ok_or_else(|| SecretsError::BadResponse("no secretPayloads[0]".into()))?;
        // Verifies the Signer signature over the encapsulated key, checks that
        // the bundle's quorum key is the pinned one and that the organization
        // matches, then decrypts.
        let plaintext = target
            .decrypt(payload.as_bytes(), &self.cfg.organization_id)
            .map_err(|e| map_decrypt_error(&e))?;
        tracing::info!(
            activity_id,
            "EXPORT_SECRETS completed; bundle verified and decrypted"
        );
        Ok(SecretBytes::new(plaintext))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    const PRIV: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn signer_key_forms() {
        let sk = SigningKey::from_slice(&hex::decode(PRIV).unwrap()).unwrap();
        let unc = hex::encode(VerifyingKey::from(&sk).to_encoded_point(false).as_bytes());
        assert!(SignerPublicKey::from_hex(&unc).is_ok());
        assert!(SignerPublicKey::from_hex(&format!("{unc}{unc}")).is_ok());
        assert!(SignerPublicKey::from_hex("04").is_err());
    }

    #[test]
    fn config_is_validated() {
        let sk = SigningKey::from_slice(&hex::decode(PRIV).unwrap()).unwrap();
        let signer = SignerPublicKey(VerifyingKey::from(&sk));
        let key = || ApiKey::from_private_hex(PRIV).unwrap();
        assert!(matches!(
            SecretsClient::new(SecretsConfig::new("ftp://x", "org", key(), signer)),
            Err(SecretsError::InvalidConfig(_))
        ));
        assert!(matches!(
            SecretsClient::new(SecretsConfig::new("https://x", "", key(), signer)),
            Err(SecretsError::InvalidConfig(_))
        ));
        let c = SecretsClient::new(SecretsConfig::new("https://x", "org", key(), signer)).unwrap();
        assert_eq!(c.api_key_public_hex(), key().public_hex());
        assert!(format!("{c:?}").contains("org"));
    }

    #[test]
    fn decrypt_errors_map_to_typed_variants() {
        assert_eq!(
            map_decrypt_error(&EnclaveEncryptError::InvalidEnclaveQuorumPublicKey),
            SecretsError::UnpinnedSignerKey
        );
        assert!(matches!(
            map_decrypt_error(&EnclaveEncryptError::InvalidOrganization),
            SecretsError::Verification(_)
        ));
        assert!(matches!(
            map_decrypt_error(&EnclaveEncryptError::ServerEncappedKeySignatureVerificationFail),
            SecretsError::Verification(_)
        ));
    }

    #[test]
    fn activity_status_shape() {
        let v = json!({"activity": {"id": "a1", "status": "ACTIVITY_STATUS_PENDING"}});
        assert_eq!(
            activity_status(&v).unwrap(),
            ("a1".to_owned(), "ACTIVITY_STATUS_PENDING".to_owned())
        );
        assert!(activity_status(&json!({})).is_err());
        assert!(activity_status(&json!({"activity": {"id": "a1"}})).is_err());
    }
}
