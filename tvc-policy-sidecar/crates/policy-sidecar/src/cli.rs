//! CLI argument parsing for the TVC policy sidecar
use clap::Parser;

/// TVC policy sidecar
#[derive(Parser, Debug)]
#[command(name = "policy-sidecar", version, about = "TVC policy sidecar")]
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

    /// Path to the ephemeral key file loaded for QOS startup compatibility
    #[arg(long, default_value = qos_core::EPHEMERAL_KEY_FILE)]
    pub ephemeral_file: String,

    /// Turnkey organization served by this deployment
    #[arg(long)]
    pub turnkey_organization_id: String,

    /// Base URL for the Turnkey API and webhook JWKS
    #[arg(long, default_value = "https://api.turnkey.com")]
    pub turnkey_api_base_url: String,
}
