use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use qos_p256::P256Pair;
use std::{fs, io};

#[derive(Parser)]
#[command(about = "TVC worker for synthetic MPP eligibility computations")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 44020)]
    port: u16,
    #[arg(long, default_value = "/qos.ephemeral.key")]
    ephemeral_file: String,
    #[arg(long, default_value = "/qos.quorum.key")]
    quorum_file: String,
    #[arg(
        long,
        required_unless_present = "jwks_base64",
        conflicts_with = "jwks_base64"
    )]
    jwks_file: Option<String>,
    #[arg(
        long,
        required_unless_present = "jwks_file",
        conflicts_with = "jwks_file"
    )]
    jwks_base64: Option<String>,
    #[arg(long)]
    audience: String,
    #[arg(long)]
    issuer: String,
    #[arg(long)]
    client_id: String,
    #[arg(long, default_value = "evaluate")]
    required_scope: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let ephemeral = P256Pair::from_hex_file(&cli.ephemeral_file)
        .map_err(|_| io::Error::other("failed to load QOS ephemeral key"))?;
    // Fail startup when QOS has not provisioned this deployment. The quorum
    // key is not used to sign application results.
    let _quorum = P256Pair::from_hex_file(&cli.quorum_file)
        .map_err(|_| io::Error::other("failed to load QOS quorum key"))?;
    let jwks = match (&cli.jwks_file, &cli.jwks_base64) {
        (Some(path), None) => fs::read(path)?,
        (None, Some(value)) if value.len() <= 87_384 => STANDARD.decode(value)?,
        _ => return Err("provide exactly one bounded JWKS file or base64 value".into()),
    };
    if jwks.len() > 64 * 1024 {
        return Err("JWKS file exceeds 64 KiB".into());
    }
    let state = tvc_mpp::AppState::new(
        ephemeral,
        &jwks,
        &cli.issuer,
        &cli.audience,
        &cli.client_id,
        &cli.required_scope,
    )?;
    let listener = tokio::net::TcpListener::bind((cli.host.as_str(), cli.port)).await?;
    axum::serve(listener, tvc_mpp::router(state)).await?;
    Ok(())
}
