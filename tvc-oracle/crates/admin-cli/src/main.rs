//! Local, explicit administrator actions using the API key configured by the TVC CLI.

use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::{
    collections::HashMap,
    env, fs, io,
    io::Read,
    path::{Path, PathBuf},
};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::{
    TurnkeyClient,
    generated::immutable::{activity::v1::SignTransactionIntentV2, common::v1::TransactionType},
};

#[derive(Parser)]
#[command(about = "Explicit local administrator actions through the Turnkey API")]
struct Cli {
    /// TVC CLI configuration file. Defaults to ~/.config/turnkey/tvc.config.toml.
    #[arg(long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ask Turnkey to sign an already prepared unsigned Ethereum transaction.
    Sign {
        /// Turnkey Ethereum address that should sign the transaction.
        #[arg(long)]
        sign_with: String,

        /// RLP-encoded unsigned Ethereum transaction, with or without a 0x prefix. Use - for stdin.
        #[arg(long)]
        unsigned_transaction: String,
    },
}

#[derive(Deserialize)]
struct TvcConfig {
    active_org: String,
    orgs: HashMap<String, OrganizationConfig>,
}

#[derive(Deserialize)]
struct OrganizationConfig {
    id: String,
    api_key_path: PathBuf,
    api_base_url: String,
}

#[derive(Deserialize)]
struct ApiKeyFile {
    curve: String,
    private_key: String,
    public_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or(default_config_path()?);
    let tvc_config = load_tvc_config(&config_path)?;
    let organization = tvc_config.orgs.get(&tvc_config.active_org).ok_or_else(|| {
        invalid_data(format!(
            "active organization '{}' is missing from {}",
            tvc_config.active_org,
            config_path.display()
        ))
    })?;
    let api_key = load_api_key(&organization.api_key_path)?;
    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(&organization.api_base_url)
        .build()?;

    match cli.command {
        Command::Sign {
            sign_with,
            unsigned_transaction,
        } => {
            let unsigned_transaction = read_unsigned_transaction(&unsigned_transaction)?;
            let result = client
                .sign_transaction(
                    organization.id.clone(),
                    client.current_timestamp(),
                    SignTransactionIntentV2 {
                        sign_with,
                        unsigned_transaction,
                        r#type: TransactionType::Ethereum,
                    },
                )
                .await?;

            println!("Turnkey activity: {}", result.activity_id);
            println!("Signed transaction: {}", result.result.signed_transaction);
            println!("The transaction is signed but has not been broadcast.");
        }
    }

    Ok(())
}

fn default_config_path() -> Result<PathBuf, io::Error> {
    let home = env::var_os("HOME")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config/turnkey/tvc.config.toml"))
}

fn load_tvc_config(path: &Path) -> Result<TvcConfig, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    Ok(toml::from_str(&contents)?)
}

fn load_api_key(path: &Path) -> Result<TurnkeyP256ApiKey, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    let key: ApiKeyFile = serde_json::from_str(&contents)?;
    if key.curve != "p256" {
        return Err(invalid_data(format!(
            "unsupported API key curve '{}'; expected p256",
            key.curve
        ))
        .into());
    }

    Ok(TurnkeyP256ApiKey::from_strings(
        key.private_key,
        Some(key.public_key),
    )?)
}

fn normalize_hex(value: &str) -> Result<String, io::Error> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_data(
            "unsigned transaction must be non-empty, even-length hexadecimal",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn read_unsigned_transaction(value: &str) -> Result<String, io::Error> {
    if value != "-" {
        return normalize_hex(value);
    }

    let mut transaction = String::new();
    io::stdin().read_to_string(&mut transaction)?;
    normalize_hex(transaction.trim())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::normalize_hex;

    #[test]
    fn normalizes_optional_prefix_and_case() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(normalize_hex("0x02AB")?, "02ab");
        assert_eq!(normalize_hex("02ab")?, "02ab");
        Ok(())
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!(normalize_hex("").is_err());
        assert!(normalize_hex("0x123").is_err());
        assert!(normalize_hex("0xzz").is_err());
    }
}
