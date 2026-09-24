//! Runtime status shared by the updater and the public status endpoint.

use serde::Serialize;

/// In-memory operational state for this enclave process.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleRuntimeStatus {
    /// Whether autonomous updates were enabled at process startup.
    pub enabled: bool,
    /// Configured interval between successful updates.
    pub update_interval_seconds: u64,
    /// Unix timestamp of the most recent attempt.
    pub last_attempt_at: Option<u64>,
    /// Unix timestamp of the most recent successful or unnecessary cycle.
    pub last_success_at: Option<u64>,
    /// Most recently submitted transaction hash observed by this process.
    pub last_transaction_hash: Option<String>,
    /// Most recent failure, cleared after a successful cycle.
    pub last_error: Option<String>,
    /// Human-readable description of the current updater phase.
    pub phase: String,
}

impl OracleRuntimeStatus {
    /// Construct the initial status value.
    #[must_use]
    pub fn new(enabled: bool, update_interval_seconds: u64) -> Self {
        Self {
            enabled,
            update_interval_seconds,
            last_attempt_at: None,
            last_success_at: None,
            last_transaction_hash: None,
            last_error: None,
            phase: if enabled { "starting" } else { "disabled" }.to_owned(),
        }
    }
}
