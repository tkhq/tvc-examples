//! TVC `/cosign` POC — an enclave pivot binary that stamps Turnkey activity
//! requests with quorum-key-derived P-256 keys.
//!
//! Endpoints:
//!   GET  /health   — liveness probe.
//!   GET  /pubkeys  — the derived programmatic + admin public keys (register these
//!                    as Turnkey API users).
//!   POST /cosign   — classify an unsigned tx and return a stamped
//!                    SIGN_TRANSACTION_V2 request for the customer to submit.

mod activity;
mod config;
mod keys;
mod rules;
mod stamp;
mod tx;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use activity::{build_sign_transaction, SignTransaction};
use config::Config;
use keys::KeySet;
use rules::{classify, Classification};

/// Address the enclave listens on. TVC pivots serve plain HTTP inside the
/// enclave; the host proxies to them.
const LISTEN_ADDR: &str = "0.0.0.0:3000";

/// Shared, read-only application state.
struct AppState {
    keys: KeySet,
    config: Config,
}

#[tokio::main]
async fn main() {
    // Derive the enclave's two API keys once at boot. Enclave stdout is not
    // observable in production, so these prints are only a local-dev aid; the
    // pubkeys are exposed over GET /pubkeys for registration.
    let keys = KeySet::load();
    println!("keys: programmatic pubkey = {}", keys.programmatic.public_key_hex());
    println!("keys: admin pubkey        = {}", keys.admin.public_key_hex());

    let config = Config::from_env();
    let state = Arc::new(AppState { keys, config });

    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR)
        .await
        .expect("bind listener");
    println!("tvc-cosign listening on {LISTEN_ADDR}");

    axum::serve(listener, router(state)).await.expect("serve");
}

/// Builds the app router. Takes state so tests can construct it independently.
fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/pubkeys", get(pubkeys))
        .route("/cosign", post(cosign))
        .with_state(state)
}

/// TVC liveness probe. Must return `200`.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PubkeysResponse {
    programmatic: String,
    admin: String,
}

/// Serve the derived public keys so an operator can register them as API users.
async fn pubkeys(State(state): State<Arc<AppState>>) -> Json<PubkeysResponse> {
    Json(PubkeysResponse {
        programmatic: state.keys.programmatic.public_key_hex(),
        admin: state.keys.admin.public_key_hex(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CosignRequest {
    unsigned_transaction: String,
    signer_address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CosignResponse {
    /// Exact JSON bytes to POST to Turnkey — send verbatim; the stamp covers
    /// these exact bytes, so re-serializing would break it.
    activity_body: String,
    x_stamp: String,
    classification: Classification,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CosignError {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<Classification>,
}

/// Parse an unsigned tx, classify it, then build + stamp a `SIGN_TRANSACTION_V2`.
async fn cosign(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CosignRequest>,
) -> Result<Json<CosignResponse>, (StatusCode, Json<CosignError>)> {
    // Decode + parse the unsigned transaction. A malformed tx is a client error.
    let raw = decode_hex(&req.unsigned_transaction)
        .map_err(|e| bad_request(format!("invalid unsignedTransaction hex: {e}"), None))?;
    let parsed = tx::parse_unsigned(&raw)
        .map_err(|e| bad_request(format!("could not parse transaction: {e}"), None))?;

    let classification = classify(&parsed, &state.config.ruleset);

    let key = match classification {
        Classification::Programmatic => &state.keys.programmatic,
        Classification::Admin => &state.keys.admin,
        Classification::Reject => {
            return Err(bad_request(
                "transaction rejected by ruleset".to_string(),
                Some(Classification::Reject),
            ));
        }
    };

    let body = build_sign_transaction(&SignTransaction {
        organization_id: &state.config.organization_id,
        sign_with: &req.signer_address,
        unsigned_transaction: &req.unsigned_transaction,
        timestamp_ms: now_ms(),
    });
    let stamped = stamp::stamp(key, &body);

    Ok(Json(CosignResponse {
        activity_body: stamped.body,
        x_stamp: stamped.x_stamp,
        classification,
    }))
}

/// Current time in milliseconds since the Unix epoch (Turnkey liveness stamp).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_millis() as u64
}

/// Hex-decode, tolerating an optional `0x` prefix.
fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    hex::decode(s)
}

/// Build a `400` response with an error message and optional classification.
fn bad_request(
    error: String,
    classification: Option<Classification>,
) -> (StatusCode, Json<CosignError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(CosignError {
            error,
            classification,
        }),
    )
}
