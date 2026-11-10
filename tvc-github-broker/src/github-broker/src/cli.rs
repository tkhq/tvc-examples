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
    #[arg(long, env = "BROKER_CONFIG", conflicts_with = "config_json")]
    pub config: Option<PathBuf>,

    /// The JSON configuration itself, for an enclave where the image has no
    /// config file. Pass it as a pivot argument so the manifest covers it.
    #[arg(long, env = "BROKER_CONFIG_JSON", conflicts_with = "config")]
    pub config_json: Option<String>,

    /// QOS quorum seed. In an enclave, the Turnkey API key is derived from it.
    #[arg(long, default_value = "/qos.quorum.key")]
    pub quorum_key_path: PathBuf,

    /// QOS ephemeral seed. In an enclave, the export target is derived from it.
    #[arg(long, default_value = "/qos.ephemeral.key")]
    pub ephemeral_key_path: PathBuf,

    /// Turnkey API key JSON, for runs outside an enclave only. The value is a
    /// path, but the environment value is hidden from --help anyway.
    #[arg(long, env = "TURNKEY_API_KEY_PATH", hide_env_values = true)]
    pub turnkey_api_key_path: Option<PathBuf>,

    /// Print the Turnkey API public key to register as the broker's user, then
    /// exit.
    #[arg(long)]
    pub print_api_public_key: bool,

    /// Serve only `/health` and `/v1/api-public-key`, with no config and no
    /// export. Use it for a first deployment: an enclave's API key is derived
    /// from its quorum seed, so this is how you read the key to register.
    #[arg(long, conflicts_with_all = ["config", "config_json"])]
    pub bootstrap: bool,
}
