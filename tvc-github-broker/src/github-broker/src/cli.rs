//! CLI arguments.
use std::path::PathBuf;

use clap::Parser;

/// GitHub App installation-token broker (TVC app)
#[derive(Parser, Debug)]
#[command(name = "github-broker", version, about)]
pub struct Cli {
    /// IP address to listen on
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to listen on
    #[arg(long, default_value = "44020")]
    pub port: u16,

    /// Path to the JSON configuration file
    #[arg(long, env = "BROKER_CONFIG")]
    pub config: PathBuf,

    /// Path to the app user's Turnkey API key JSON. The value is a path, but
    /// the environment value is hidden from --help anyway.
    #[arg(long, env = "TURNKEY_API_KEY_PATH", hide_env_values = true)]
    pub turnkey_api_key_path: PathBuf,
}
