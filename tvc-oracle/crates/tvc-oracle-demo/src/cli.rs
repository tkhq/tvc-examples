//! CLI argument parsing for the TVC signed ETH/USD oracle server.
use clap::Parser;

use crate::config::{DEFAULT_SEPOLIA_RPC_URL, DEFAULT_TURNKEY_API_BASE_URL};

/// TVC signed ETH/USD oracle server.
#[derive(Parser, Debug)]
#[command(name = "tvc-oracle-demo", version, about = "TVC signed ETH/USD oracle")]
pub struct Cli {
    /// IP address to listen on
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to listen on
    #[arg(long, default_value = "44020")]
    pub port: u16,

    /// Path to the quorum key file
    #[arg(long, default_value = qos_core::QUORUM_FILE)]
    pub quorum_file: String,

    /// Path to the ephemeral key file used for app proofs
    #[arg(long, default_value = qos_core::EPHEMERAL_KEY_FILE)]
    pub ephemeral_file: String,

    /// Turnkey organization containing the policy-constrained updater account.
    #[arg(long)]
    pub turnkey_organization_id: String,

    /// Base URL for the Turnkey API.
    #[arg(long, default_value = DEFAULT_TURNKEY_API_BASE_URL)]
    pub turnkey_api_base_url: String,

    /// Ethereum Sepolia JSON-RPC endpoint.
    #[arg(long, default_value = DEFAULT_SEPOLIA_RPC_URL)]
    pub sepolia_rpc_url: String,

    /// Run the non-broadcast Turnkey policy matrix once before serving traffic.
    #[arg(long, default_value_t = false)]
    pub policy_preflight: bool,

    /// Fetch, sign, and publish an ETH/USD update immediately and then periodically.
    #[arg(long, default_value_t = false)]
    pub oracle_updates: bool,

    /// Seconds between successful oracle updates.
    #[arg(long, default_value_t = 86_400)]
    pub oracle_update_interval_seconds: u64,
}
