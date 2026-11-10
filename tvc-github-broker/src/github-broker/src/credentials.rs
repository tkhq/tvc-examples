//! The broker's Turnkey credentials.
//!
//! In a TVC enclave, QOS exposes two seeds. The Turnkey API key is derived
//! from the quorum seed, so only the enclave can stamp with it. The export
//! target is the encrypt key derived from the ephemeral seed, so the secret can
//! only be read inside the enclave. Outside an enclave the quorum seed file is
//! absent, and the broker falls back to an API key file and a random target,
//! which is for local runs only.

use std::path::{Path, PathBuf};

use tvc_secrets::{ApiKey, Seed, seed_from_hex};
use zeroize::Zeroizing;

use crate::cli::Cli;

/// What the broker stamps with, and where the export goes.
pub struct Credentials {
    /// The Turnkey API key.
    pub api_key: ApiKey,
    /// The ephemeral seed, when running in an enclave.
    pub ephemeral_seed: Option<Seed>,
}

fn read_seed(path: &Path) -> Result<Option<Seed>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let text = Zeroizing::new(text);
            seed_from_hex(&text)
                .map(Some)
                .map_err(|e| format!("{}: {e}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// Load the credentials the CLI points at.
///
/// # Errors
///
/// Returns a message when a key file is unreadable or malformed, when the
/// quorum seed exists but the ephemeral seed does not, or when there is
/// neither a quorum seed nor an API key file.
pub fn load(cli: &Cli) -> Result<Credentials, String> {
    if let Some(quorum) = read_seed(&cli.quorum_key_path)? {
        let ephemeral = read_seed(&cli.ephemeral_key_path)?.ok_or_else(|| {
            format!(
                "{} exists but {} does not",
                cli.quorum_key_path.display(),
                cli.ephemeral_key_path.display()
            )
        })?;
        return Ok(Credentials {
            api_key: ApiKey::from_quorum_seed(&quorum).map_err(|e| e.to_string())?,
            ephemeral_seed: Some(ephemeral),
        });
    }
    let path: &PathBuf = cli.turnkey_api_key_path.as_ref().ok_or_else(|| {
        format!(
            "{} not found: not in an enclave, so pass --turnkey-api-key-path",
            cli.quorum_key_path.display()
        )
    })?;
    tracing::warn!(
        "not running in an enclave: using an API key file and a random export target; \
         do not do this in production"
    );
    let bytes =
        Zeroizing::new(std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?);
    Ok(Credentials {
        api_key: ApiKey::from_json(&bytes).map_err(|e| e.to_string())?,
        ephemeral_seed: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use clap::Parser;

    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("credentials-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cli(d: &Path, extra: &[&str]) -> Cli {
        let mut args = vec![
            "github-broker".to_owned(),
            "--config".to_owned(),
            "c.json".to_owned(),
            "--quorum-key-path".to_owned(),
            d.join("quorum").display().to_string(),
            "--ephemeral-key-path".to_owned(),
            d.join("ephemeral").display().to_string(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        Cli::parse_from(args)
    }

    #[test]
    fn in_an_enclave_both_seeds_are_used() {
        let d = dir("both");
        std::fs::write(d.join("quorum"), "ab".repeat(32)).unwrap();
        std::fs::write(d.join("ephemeral"), format!("{}\n", "cd".repeat(32))).unwrap();
        let c = load(&cli(&d, &[])).unwrap();
        assert!(c.ephemeral_seed.is_some());
        assert_eq!(c.api_key.public_hex().len(), 66);
    }

    #[test]
    fn a_quorum_seed_without_an_ephemeral_seed_is_refused() {
        let d = dir("half");
        std::fs::write(d.join("quorum"), "ab".repeat(32)).unwrap();
        assert!(load(&cli(&d, &[])).is_err());
    }

    #[test]
    fn a_malformed_seed_is_refused() {
        let d = dir("bad");
        std::fs::write(d.join("quorum"), "not hex").unwrap();
        assert!(load(&cli(&d, &[])).is_err());
    }

    #[test]
    fn outside_an_enclave_an_api_key_file_is_required() {
        let d = dir("none");
        assert!(load(&cli(&d, &[])).is_err());
        let private = "01".repeat(32);
        let key = d.join("key.json");
        std::fs::write(
            &key,
            serde_json::json!({
                "publicKey": ApiKey::from_private_hex(&private).unwrap().public_hex(),
                "privateKey": private,
            })
            .to_string(),
        )
        .unwrap();
        let c = load(&cli(
            &d,
            &["--turnkey-api-key-path", &key.display().to_string()],
        ))
        .unwrap();
        assert!(c.ephemeral_seed.is_none());
    }
}
