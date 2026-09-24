//! Shared server state.

use crate::client::HttpClient;
use crate::oracle_status::OracleRuntimeStatus;
use qos_p256::P256Pair;
use std::sync::Arc;
use tokio::sync::RwLock;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::TurnkeyClient;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub(crate) ephemeral_key: Arc<P256Pair>,
    pub(crate) turnkey_client: Arc<TurnkeyClient<TurnkeyP256ApiKey>>,
    pub(crate) turnkey_organization_id: String,
    pub(crate) http_client: HttpClient,
    pub(crate) sepolia_rpc_url: String,
    pub(crate) oracle_status: Arc<RwLock<OracleRuntimeStatus>>,
}

impl AppState {
    /// Create a new application state value.
    pub fn new(
        ephemeral_key: P256Pair,
        quorum_key: P256Pair,
        turnkey_organization_id: String,
        turnkey_api_base_url: String,
        sepolia_rpc_url: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if turnkey_organization_id.is_empty() {
            return Err("Turnkey organization ID must not be empty".into());
        }
        if sepolia_rpc_url.is_empty() {
            return Err("Sepolia RPC URL must not be empty".into());
        }
        let turnkey_api_key =
            TurnkeyP256ApiKey::from_bytes(quorum_key.signing_key().to_bytes(), None)?;
        let turnkey_client = TurnkeyClient::builder()
            .api_key(turnkey_api_key)
            .base_url(turnkey_api_base_url)
            .build()?;

        Ok(Self {
            ephemeral_key: Arc::new(ephemeral_key),
            turnkey_client: Arc::new(turnkey_client),
            turnkey_organization_id,
            http_client: HttpClient::new()?,
            sepolia_rpc_url,
            oracle_status: Arc::new(RwLock::new(OracleRuntimeStatus::new(false, 0))),
        })
    }

    /// Configure the operational status before starting the updater task.
    pub async fn configure_oracle_updates(&self, enabled: bool, interval_seconds: u64) {
        *self.oracle_status.write().await = OracleRuntimeStatus::new(enabled, interval_seconds);
    }
}
