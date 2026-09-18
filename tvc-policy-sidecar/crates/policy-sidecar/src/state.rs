//! Shared server state.

use crate::{client::HttpClient, turnkey_voter::TurnkeyVoter, webhook::WebhookVerifier};
use qos_p256::P256Pair;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub(crate) turnkey_api_public_key: String,
    pub(crate) turnkey_organization_id: String,
    pub(crate) turnkey_voter: TurnkeyVoter,
    pub(crate) webhook_verifier: WebhookVerifier,
}

impl AppState {
    /// Create a new application state value.
    pub fn new(
        quorum_key: P256Pair,
        turnkey_organization_id: String,
        turnkey_api_base_url: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if turnkey_organization_id.is_empty() {
            return Err("Turnkey organization ID must not be empty".into());
        }
        let quorum_private_key = quorum_key.signing_key().to_bytes();
        let api_key = TurnkeyP256ApiKey::from_bytes(quorum_private_key, None)?;
        // Publish the key belonging to the same stamper moved into the voting client.
        let turnkey_api_public_key = qos_hex::encode(&api_key.compressed_public_key());
        let http_client = HttpClient::new()?;
        let turnkey_voter = TurnkeyVoter::new(api_key, &turnkey_api_base_url)?;
        let webhook_verifier = WebhookVerifier::new(http_client, &turnkey_api_base_url);

        Ok(Self {
            turnkey_api_public_key,
            turnkey_organization_id,
            turnkey_voter,
            webhook_verifier,
        })
    }
}
