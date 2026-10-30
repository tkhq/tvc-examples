//! github-broker binary.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use github_broker::appkey::AppKey;
use github_broker::cli::Cli;
use github_broker::config::Config;
use github_broker::github::GitHubClient;
use github_broker::router::{self, AppState};
use metrics::MetricsLayer;
use tracing_subscriber::EnvFilter;
use turnkey_jwt_profiles::http_authz::Verifier;
use turnkey_jwt_profiles::http_authz::jwks::PinnedKeySet;
use tvc_secrets::{ApiKey, SecretsClient, SecretsConfig, SignerPublicKey};
use zeroize::Zeroizing;

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

async fn run(cli: Cli) -> Result<(), String> {
    let config = Config::from_json(
        &std::fs::read(&cli.config).map_err(|e| format!("read {}: {e}", cli.config.display()))?,
    )?;
    let allowlist = config.allowlist()?;
    let jwks = std::fs::read(&config.trusted_jwks_path)
        .map_err(|e| format!("read {}: {e}", config.trusted_jwks_path.display()))?;
    let keys = PinnedKeySet::from_jwks_json(&jwks).map_err(|e| e.to_string())?;
    let trusted_kids = trusted_kids(&jwks)?;

    // Load the App key: EXPORT_SECRETS to an in-memory HPKE key, decrypt in
    // process, parse, zeroize.
    let api_key = {
        let bytes = Zeroizing::new(
            std::fs::read(&cli.turnkey_api_key_path)
                .map_err(|e| format!("read {}: {e}", cli.turnkey_api_key_path.display()))?,
        );
        ApiKey::from_json(&bytes).map_err(|e| e.to_string())?
    };
    let secrets_config = SecretsConfig::new(
        config.turnkey.api_base_url.clone(),
        config.turnkey.organization_id.clone(),
        api_key,
        SignerPublicKey::from_hex(&config.turnkey.signer_public_key).map_err(|e| e.to_string())?,
    );
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

    let metrics_layer = MetricsLayer::builder()
        .namespace("tvc")
        .build()
        .map_err(|e| e.to_string())?;
    let collector = metrics_layer.collector();
    let app = router::router(state)
        .layer(metrics_layer)
        .route("/metrics", metrics::handler(collector));

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
