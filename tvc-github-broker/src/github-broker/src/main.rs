//! github-broker binary.

use std::process::ExitCode;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use github_broker::appkey::AppKey;
use github_broker::cli::Cli;
use github_broker::config::Config;
use github_broker::credentials;
use github_broker::github::GitHubClient;
use github_broker::router::{self, AppState};
use serde_json::json;
use tracing_subscriber::EnvFilter;
use turnkey_jwt_profiles::http_authz::Verifier;
use turnkey_jwt_profiles::http_authz::jwks::PinnedKeySet;
use tvc_secrets::{SecretsClient, SecretsConfig, SignerPublicKey};

/// The `kid` (RFC 7638 thumbprint) of each key in a JWK Set the key set already
/// accepted.
fn trusted_kids(jwks: &[u8]) -> Result<Vec<String>, String> {
    #[derive(serde::Deserialize)]
    struct Set {
        keys: Vec<Key>,
    }
    #[derive(serde::Deserialize)]
    struct Key {
        x: String,
        y: String,
    }
    let set: Set = serde_json::from_slice(jwks).map_err(|e| format!("jwks: {e}"))?;
    Ok(set
        .keys
        .iter()
        .map(|k| turnkey_jwt_profiles::http_authz::jwks::thumbprint_p256(&k.x, &k.y))
        .collect())
}

/// Serve the API public key and a health check, and nothing else.
async fn bootstrap(cli: &Cli, api_public_key: String) -> Result<(), String> {
    let app = Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"status": "healthy"})) }),
        )
        .route(
            "/v1/api-public-key",
            get(move || async move { Json(json!({"api_public_key": api_public_key})) }),
        );
    let addr = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    tracing::info!("bootstrap mode: serving the API public key on {addr}");
    axum::serve(listener, app).await.map_err(|e| e.to_string())
}

async fn run(cli: Cli) -> Result<(), String> {
    let credentials = credentials::load(&cli)?;
    if cli.print_api_public_key {
        println!("{}", credentials.api_key.public_hex());
        return Ok(());
    }
    if cli.bootstrap {
        return bootstrap(&cli, credentials.api_key.public_hex().to_owned()).await;
    }
    let config_bytes = match (&cli.config, &cli.config_json) {
        (Some(path), None) => {
            std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?
        }
        (None, Some(json)) => json.clone().into_bytes(),
        _ => return Err("pass --config or --config-json".into()),
    };
    let config = Config::from_json(&config_bytes)?;
    let allowlist = config.allowlist()?;
    let jwks = match (&config.trusted_jwks_path, &config.trusted_jwks) {
        (Some(path), _) => {
            std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?
        }
        (None, Some(jwks)) => jwks.to_string().into_bytes(),
        (None, None) => return Err("no trusted JWK Set".into()),
    };
    let keys = PinnedKeySet::from_jwks_json(&jwks).map_err(|e| e.to_string())?;
    let trusted_kids = trusted_kids(&jwks)?;

    // Load the App key: EXPORT_SECRETS to the enclave's ephemeral key, decrypt
    // in process, parse, zeroize.
    let mut secrets_config = SecretsConfig::new(
        config.turnkey.api_base_url.clone(),
        config.turnkey.organization_id.clone(),
        credentials.api_key,
        SignerPublicKey::from_hex(&config.turnkey.signer_public_key).map_err(|e| e.to_string())?,
    );
    if let Some(seed) = credentials.ephemeral_seed {
        secrets_config = secrets_config.with_target_seed(seed);
    }
    let secrets = SecretsClient::new(secrets_config).map_err(|e| e.to_string())?;
    tracing::info!(
        api = config.turnkey.api_base_url,
        organization_id = config.turnkey.organization_id,
        secret_id = config.turnkey.secret_id,
        api_key = secrets.api_key_public_hex(),
        "exporting the GitHub App key from Turnkey Secret Storage"
    );
    let pem = secrets
        .export_secret(&config.turnkey.secret_id)
        .await
        .map_err(|e| e.to_string())?;
    drop(secrets);
    let app_key = AppKey::from_pkcs1_pem(pem.expose()).map_err(|e| e.to_string())?;
    drop(pem);
    let fingerprint = app_key.fingerprint();
    if let Some(want) = &config.github.expected_key_sha256 {
        if *want != fingerprint {
            return Err(format!(
                "exported App key fingerprint {fingerprint} does not match expected_key_sha256 {want}"
            ));
        }
    }
    tracing::info!(fingerprint, "GitHub App key loaded into memory");

    let github = GitHubClient::new(
        &config.github.api_base_url,
        &config.github.app_client_id,
        app_key,
    )
    .map_err(|e| e.to_string())?;
    let state = Arc::new(AppState {
        audience: config.audience.clone(),
        organization_id: config.organization_id.clone(),
        detailed_auth_errors: config.detailed_auth_errors,
        verifier: Arc::new(
            Verifier::new(config.verifier_config(), Arc::new(keys)).map_err(|e| e.to_string())?,
        ),
        allowlist,
        allow_admin: config.allow_admin_permissions,
        github,
        app_client_id: config.github.app_client_id.clone(),
        trusted_kids,
    });

    let app = router::router(state);

    let addr = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    tracing::info!(
        audience = config.audience,
        organization_id = config.organization_id,
        "listening on {addr}"
    );
    axum::serve(listener, app).await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("refusing to start: {e}");
            ExitCode::FAILURE
        }
    }
}
