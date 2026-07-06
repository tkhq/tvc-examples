//! TVC `/cosign` POC — an enclave pivot binary that stamps Turnkey activity
//! requests with quorum-key-derived P-256 keys.
//!
//! Exposes `GET /health` today; `GET /pubkeys` and `POST /cosign` are wired in
//! as the rules engine and stamping land.

mod keys;
mod stamp;

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};

use keys::KeySet;

/// Address the enclave listens on. TVC pivots serve plain HTTP inside the
/// enclave; the host proxies to them.
const LISTEN_ADDR: &str = "0.0.0.0:3000";

#[tokio::main]
async fn main() {
    // Derive the enclave's two API keys once at boot. Enclave stdout is not
    // observable in production, so these prints are only a local-dev aid; the
    // pubkeys are exposed over HTTP for registration.
    let keyset = KeySet::load();
    println!("keys: programmatic pubkey = {}", keyset.programmatic.public_key_hex());
    println!("keys: admin pubkey        = {}", keyset.admin.public_key_hex());

    let app = router();

    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR)
        .await
        .expect("bind listener");
    println!("tvc-cosign listening on {LISTEN_ADDR}");

    axum::serve(listener, app).await.expect("serve");
}

/// Builds the app router. Kept separate from `main` so tests can exercise it.
fn router() -> Router {
    Router::new().route("/health", get(health))
}

/// TVC liveness probe. Must return `200`.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
