//! Verify exact webhook bytes and discover Turnkey signing keys.

use crate::client::HttpClient;
use axum::http::HeaderMap;
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

pub(super) const SIGNATURE_ALGORITHM: &str = "ed25519";
pub(super) const SIGNATURE_VERSION: &str = "v1";
pub(super) const WEBHOOK_VERSION: &str = "1";
const MAX_TIMESTAMP_AGE_MS: u64 = 5 * 60 * 1_000;
const DEFAULT_JWKS_CACHE_LIFETIME: Duration = Duration::from_secs(5 * 60);
pub(super) const JWKS_PATH: &str = "/public/v1/discovery/webhooks/jwks";

pub(super) const ORGANIZATION_ID_HEADER: &str = "x-turnkey-organization-id";
pub(super) const EVENT_TYPE_HEADER: &str = "x-turnkey-event-type";
pub(super) const TIMESTAMP_HEADER: &str = "x-turnkey-timestamp";
pub(super) const WEBHOOK_VERSION_HEADER: &str = "x-turnkey-webhook-version";
pub(super) const EVENT_ID_HEADER: &str = "x-turnkey-event-id";
pub(super) const SIGNATURE_KEY_ID_HEADER: &str = "x-turnkey-signature-key-id";
pub(super) const SIGNATURE_ALGORITHM_HEADER: &str = "x-turnkey-signature-algorithm";
pub(super) const SIGNATURE_VERSION_HEADER: &str = "x-turnkey-signature-version";
pub(super) const SIGNATURE_HEADER: &str = "x-turnkey-signature";

/// A verified delivery's metadata.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct VerifiedDelivery {
    pub(super) organization_id: String,
    pub(super) event_type: String,
}

/// Authentication or key-discovery failure.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum WebhookVerificationError {
    MissingHeader(&'static str),
    InvalidHeader(&'static str),
    StaleTimestamp,
    InvalidSignature,
    UnknownKey,
    KeyDiscovery(String),
}

impl WebhookVerificationError {
    pub(super) fn is_retryable(&self) -> bool {
        matches!(self, Self::KeyDiscovery(_))
    }
}

impl fmt::Display for WebhookVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHeader(header) => write!(formatter, "missing {header} header"),
            Self::InvalidHeader(header) => write!(formatter, "invalid {header} header"),
            Self::StaleTimestamp => {
                formatter.write_str("webhook timestamp is outside the freshness window")
            }
            Self::InvalidSignature => formatter.write_str("webhook signature is invalid"),
            Self::UnknownKey => formatter.write_str("webhook signing key is unknown"),
            Self::KeyDiscovery(message) => {
                write!(formatter, "webhook key discovery failed: {message}")
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct WebhookVerifier {
    http_client: HttpClient,
    jwks_url: String,
    cache: Arc<RwLock<CachedVerificationKeys>>,
}

struct CachedVerificationKeys {
    keys: HashMap<String, VerifyingKey>,
    expires_at: Instant,
}

impl WebhookVerifier {
    pub(crate) fn new(http_client: HttpClient, turnkey_api_base_url: &str) -> Self {
        Self {
            http_client,
            jwks_url: format!("{}{JWKS_PATH}", turnkey_api_base_url.trim_end_matches('/')),
            cache: Arc::new(RwLock::new(CachedVerificationKeys {
                keys: HashMap::new(),
                expires_at: Instant::now(),
            })),
        }
    }

    pub(super) async fn verify(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
    ) -> Result<VerifiedDelivery, WebhookVerificationError> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| WebhookVerificationError::KeyDiscovery(error.to_string()))?
            .as_millis();
        self.verify_at(headers, raw_body, now_ms).await
    }

    async fn verify_at(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now_ms: u128,
    ) -> Result<VerifiedDelivery, WebhookVerificationError> {
        let organization_id = required_header(headers, ORGANIZATION_ID_HEADER)?;
        let event_type = required_header(headers, EVENT_TYPE_HEADER)?;
        let timestamp = required_header(headers, TIMESTAMP_HEADER)?;
        let webhook_version = required_header(headers, WEBHOOK_VERSION_HEADER)?;
        let event_id = required_header(headers, EVENT_ID_HEADER)?;
        let key_id = required_header(headers, SIGNATURE_KEY_ID_HEADER)?;
        let signature_algorithm = required_header(headers, SIGNATURE_ALGORITHM_HEADER)?;
        let signature_version = required_header(headers, SIGNATURE_VERSION_HEADER)?;
        let signature_hex = required_header(headers, SIGNATURE_HEADER)?;

        if webhook_version != WEBHOOK_VERSION {
            return Err(WebhookVerificationError::InvalidHeader(
                WEBHOOK_VERSION_HEADER,
            ));
        }
        if signature_algorithm != SIGNATURE_ALGORITHM {
            return Err(WebhookVerificationError::InvalidHeader(
                SIGNATURE_ALGORITHM_HEADER,
            ));
        }
        if signature_version != SIGNATURE_VERSION {
            return Err(WebhookVerificationError::InvalidHeader(
                SIGNATURE_VERSION_HEADER,
            ));
        }
        if organization_id.is_empty() || event_id.is_empty() || key_id.is_empty() {
            return Err(WebhookVerificationError::InvalidSignature);
        }

        let timestamp_ms = timestamp
            .parse::<u128>()
            .map_err(|_| WebhookVerificationError::InvalidHeader(TIMESTAMP_HEADER))?;
        if now_ms.abs_diff(timestamp_ms) > u128::from(MAX_TIMESTAMP_AGE_MS) {
            return Err(WebhookVerificationError::StaleTimestamp);
        }

        let signature_bytes = qos_hex::decode(&signature_hex)
            .map_err(|_| WebhookVerificationError::InvalidSignature)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| WebhookVerificationError::InvalidSignature)?;
        let verification_key = self.verification_key(&key_id).await?;

        // The raw body is appended byte-for-byte. Parsing or re-serializing it before this point
        // would invalidate the security contract even if the resulting JSON were equivalent.
        let mut signed_message =
            format!("{SIGNATURE_VERSION}.{SIGNATURE_ALGORITHM}.{key_id}.{timestamp}.{event_id}.")
                .into_bytes();
        signed_message.extend_from_slice(raw_body);
        verification_key
            .verify(&signed_message, &signature)
            .map_err(|_| WebhookVerificationError::InvalidSignature)?;

        Ok(VerifiedDelivery {
            organization_id,
            event_type,
        })
    }

    async fn verification_key(
        &self,
        key_id: &str,
    ) -> Result<VerifyingKey, WebhookVerificationError> {
        let cache = self.cache.read().await;
        if Instant::now() < cache.expires_at
            && let Some(key) = cache.keys.get(key_id)
        {
            return Ok(*key);
        }
        drop(cache);

        self.refresh_keys().await?;
        self.cache
            .read()
            .await
            .keys
            .get(key_id)
            .copied()
            .ok_or(WebhookVerificationError::UnknownKey)
    }

    async fn refresh_keys(&self) -> Result<(), WebhookVerificationError> {
        let response = self
            .http_client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|error| WebhookVerificationError::KeyDiscovery(error.to_string()))?;
        if !response.status().is_success() {
            return Err(WebhookVerificationError::KeyDiscovery(format!(
                "JWKS endpoint returned {}",
                response.status()
            )));
        }
        let cache_lifetime = cache_lifetime(response.headers());
        let jwks: Jwks = response
            .json()
            .await
            .map_err(|error| WebhookVerificationError::KeyDiscovery(error.to_string()))?;
        let keys = parse_jwks(jwks)?;
        let now = Instant::now();
        let expires_at = now.checked_add(cache_lifetime).unwrap_or(now);
        *self.cache.write().await = CachedVerificationKeys { keys, expires_at };
        Ok(())
    }
}

fn required_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<String, WebhookVerificationError> {
    headers
        .get(name)
        .ok_or(WebhookVerificationError::MissingHeader(name))?
        .to_str()
        .map(str::to_owned)
        .map_err(|_| WebhookVerificationError::InvalidHeader(name))
}

fn cache_lifetime(headers: &HeaderMap) -> Duration {
    headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find_map(|directive| directive.strip_prefix("max-age="))
        })
        .and_then(|seconds| seconds.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_JWKS_CACHE_LIFETIME)
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    crv: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
    x: String,
    turnkey_signature_algorithm: String,
    turnkey_signature_version: String,
}

fn parse_jwks(jwks: Jwks) -> Result<HashMap<String, VerifyingKey>, WebhookVerificationError> {
    jwks.keys
        .into_iter()
        .map(|jwk| {
            if jwk.kid.is_empty()
                || jwk.kty != "OKP"
                || jwk.crv != "Ed25519"
                || jwk.alg != "EdDSA"
                || jwk.key_use != "sig"
                || jwk.turnkey_signature_algorithm != SIGNATURE_ALGORITHM
                || jwk.turnkey_signature_version != SIGNATURE_VERSION
            {
                return Err(WebhookVerificationError::KeyDiscovery(
                    "JWKS contains an invalid Ed25519 key".to_owned(),
                ));
            }
            let key_bytes = BASE64_URL_SAFE_NO_PAD.decode(&jwk.x).map_err(|_| {
                WebhookVerificationError::KeyDiscovery(
                    "JWKS contains an invalid public key encoding".to_owned(),
                )
            })?;
            let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
                WebhookVerificationError::KeyDiscovery(
                    "JWKS contains a public key with the wrong length".to_owned(),
                )
            })?;
            let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
                WebhookVerificationError::KeyDiscovery(
                    "JWKS contains an invalid Ed25519 public key".to_owned(),
                )
            })?;
            Ok((jwk.kid, key))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::super::test_support::{jwks, signed_headers, spawn_jwks_server};
    use super::*;
    use crate::webhook::ACTIVITY_UPDATES;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::Ordering;
    #[test]
    fn parses_cache_control_max_age() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CACHE_CONTROL,
            "public, max-age=42".parse().expect("header should parse"),
        );
        assert_eq!(cache_lifetime(&headers), Duration::from_secs(42));
        assert_eq!(
            cache_lifetime(&HeaderMap::new()),
            DEFAULT_JWKS_CACHE_LIFETIME
        );
    }
    #[tokio::test]
    async fn verifies_exact_body_and_rejects_missing_stale_and_future_headers() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let (base_url, request_count) =
            spawn_jwks_server(vec![jwks(&signing_key, "key-1")], "max-age=300").await;
        let verifier = WebhookVerifier::new(
            HttpClient::new().expect("HTTP client should build"),
            &base_url,
        );
        let now_ms = 1_800_000_000_000_u128;
        let body = br#"{"organizationId":"organization-id"}"#;
        let headers = signed_headers(&signing_key, "key-1", now_ms, "event-1", body);

        assert_eq!(
            verifier.verify_at(&headers, body, now_ms).await,
            Ok(VerifiedDelivery {
                organization_id: "organization-id".to_owned(),
                event_type: ACTIVITY_UPDATES.to_owned(),
            })
        );
        assert_eq!(
            verifier.verify_at(&headers, b"tampered", now_ms).await,
            Err(WebhookVerificationError::InvalidSignature)
        );

        let mut missing = headers.clone();
        missing.remove(SIGNATURE_HEADER);
        assert_eq!(
            verifier.verify_at(&missing, body, now_ms).await,
            Err(WebhookVerificationError::MissingHeader(SIGNATURE_HEADER))
        );
        let stale = signed_headers(
            &signing_key,
            "key-1",
            now_ms - u128::from(MAX_TIMESTAMP_AGE_MS) - 1,
            "event-2",
            body,
        );
        assert_eq!(
            verifier.verify_at(&stale, body, now_ms).await,
            Err(WebhookVerificationError::StaleTimestamp)
        );
        let future = signed_headers(
            &signing_key,
            "key-1",
            now_ms + u128::from(MAX_TIMESTAMP_AGE_MS) + 1,
            "event-3",
            body,
        );
        assert_eq!(
            verifier.verify_at(&future, body, now_ms).await,
            Err(WebhookVerificationError::StaleTimestamp)
        );
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refreshes_for_unknown_keys_and_after_cache_expiry() {
        let old_key = SigningKey::from_bytes(&[1; 32]);
        let new_key = SigningKey::from_bytes(&[2; 32]);
        let (base_url, request_count) = spawn_jwks_server(
            vec![jwks(&old_key, "old-key"), jwks(&new_key, "new-key")],
            "max-age=300",
        )
        .await;
        let verifier = WebhookVerifier::new(
            HttpClient::new().expect("HTTP client should build"),
            &base_url,
        );
        let now_ms = 1_800_000_000_000_u128;
        let body = b"{}";
        let old_headers = signed_headers(&old_key, "old-key", now_ms, "event-1", body);
        verifier
            .verify_at(&old_headers, body, now_ms)
            .await
            .expect("old key should verify");
        let new_headers = signed_headers(&new_key, "new-key", now_ms, "event-2", body);
        verifier
            .verify_at(&new_headers, body, now_ms)
            .await
            .expect("unknown key should trigger one refresh");
        assert_eq!(request_count.load(Ordering::SeqCst), 2);

        let (base_url, request_count) =
            spawn_jwks_server(vec![jwks(&old_key, "old-key")], "max-age=0").await;
        let verifier = WebhookVerifier::new(
            HttpClient::new().expect("HTTP client should build"),
            &base_url,
        );
        verifier
            .verify_at(&old_headers, body, now_ms)
            .await
            .expect("first signature should verify");
        verifier
            .verify_at(&old_headers, body, now_ms)
            .await
            .expect("expired cache should refresh");
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn rejects_malformed_jwks() {
        let malformed: Jwks = serde_json::from_value(serde_json::json!({
            "keys": [{
                "kid": "key-1",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "x": "not-a-key",
                "turnkey_signature_algorithm": "ed25519",
                "turnkey_signature_version": "v1"
            }]
        }))
        .expect("JWKS DTO should deserialize");
        assert!(matches!(
            parse_jwks(malformed),
            Err(WebhookVerificationError::KeyDiscovery(_))
        ));
    }
}
