//! TVC signed ETH/USD oracle server binary.

use clap::Parser;
use metrics::MetricsLayer;
use qos_p256::P256Pair;
use std::io;
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use tvc_oracle_demo::cli::Cli;
use tvc_oracle_demo::router::{self, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let metrics_layer = MetricsLayer::builder().namespace("tvc").build()?;
    let collector = metrics_layer.collector();

    let ephemeral_key = P256Pair::from_hex_file(cli.ephemeral_file)
        .map_err(|e| io::Error::other(format!("failed to load ephemeral key: {e:?}")))?;
    let quorum_key = P256Pair::from_hex_file(cli.quorum_file)
        .map_err(|e| io::Error::other(format!("failed to load quorum key: {e:?}")))?;
    let app_state = AppState::new(ephemeral_key, quorum_key)?;
    if cli.oracle_update_interval_seconds == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--oracle-update-interval-seconds must be greater than zero",
        )
        .into());
    }
    app_state
        .configure_oracle_updates(cli.oracle_updates, cli.oracle_update_interval_seconds)
        .await;
    if cli.policy_preflight {
        tvc_oracle_demo::policy_preflight::run(&app_state).await?;
    }
    if cli.oracle_updates {
        tokio::spawn(tvc_oracle_demo::oracle_updater::run_forever(
            app_state.clone(),
            Duration::from_secs(cli.oracle_update_interval_seconds),
        ));
    }
    let app = router::router_with_state(app_state)
        .layer(metrics_layer)
        .route("/metrics", metrics::handler(collector));

    let addr = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
