//! TVC `/cosign` POC — an enclave pivot binary that stamps Turnkey activity
//! requests with quorum-key-derived P-256 keys.
//!
//! Endpoints:
//!   GET  /health   — liveness probe.
//!   GET  /pubkeys  — the derived programmatic + admin public keys (register these
//!                    as Turnkey API users).
//!   POST /cosign   — classify an unsigned tx and return a stamped
//!                    SIGN_TRANSACTION_V2 request for the customer to submit.
//!
//! Runtime config comes from CLI arguments (`pivotArgs` in a TVC deployment):
//!   --organization-id <id>   the (sub-)org to stamp requests for (attested)
//!   --rules-path <path>      ruleset TOML (default `rules.toml`; baked image
//!                            deployments pass `/rules.toml`)
//!   --port <n>               listen port (default 3000)

mod activity;
mod config;
mod keys;
mod proof;
mod rules;
mod stamp;
mod tx;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::Address;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use activity::{SignTransaction, build_sign_transaction};
use config::Config;
use keys::{EphemeralKey, KeySet};
use proof::{AppProof, ProofInputs, app_proof};
use rules::{Classification, classify};

/// Default listen port when `--port` is not supplied.
const DEFAULT_PORT: u16 = 3000;

/// Usage text printed by `--help` / `-h`.
const HELP: &str = "\
tvc-cosign — TVC /cosign pivot binary

USAGE:
    tvc-cosign [OPTIONS]

OPTIONS:
    --organization-id <id>   (sub-)org to stamp requests for (attested)
    --rules-path <path>      ruleset TOML override (local dev only; default: embedded)
    --port <n>               listen port (default: 3000)
    -h, --help               print this help and exit
";

/// Parsed command-line arguments (a TVC deployment supplies these as `pivotArgs`).
struct Args {
    organization_id: Option<String>,
    rules_path: Option<String>,
    port: u16,
}

/// Minimal hand-rolled arg parsing — avoids a CLI dependency for three flags.
/// TVC pivots serve plain HTTP inside the enclave and bind all interfaces.
fn parse_args() -> Args {
    let mut args = Args {
        organization_id: None,
        rules_path: None,
        port: DEFAULT_PORT,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--help" | "-h" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "--organization-id" => args.organization_id = iter.next(),
            "--rules-path" => args.rules_path = iter.next(),
            "--port" => {
                if let Some(v) = iter.next() {
                    match v.parse() {
                        Ok(p) => args.port = p,
                        Err(_) => {
                            eprintln!("args: WARNING invalid --port {v:?}, using {DEFAULT_PORT}")
                        }
                    }
                }
            }
            other => eprintln!("args: WARNING ignoring unknown argument {other:?}"),
        }
    }
    args
}

/// Shared, read-only application state.
struct AppState {
    keys: KeySet,
    /// Per-boot ephemeral key that signs App Proofs (see `proof.rs`).
    ephemeral: EphemeralKey,
    config: Config,
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    // Derive the enclave's two API keys once at boot. Enclave stdout is not
    // observable in production, so these prints are only a local-dev aid; the
    // pubkeys are exposed over GET /pubkeys for registration.
    let keys = KeySet::load();
    println!(
        "keys: programmatic pubkey = {}",
        keys.programmatic.public_key_hex()
    );
    println!(
        "keys: admin pubkey        = {}",
        keys.admin.public_key_hex()
    );

    // The ephemeral key is per-boot (one per replica); its public half is pinned
    // in this replica's Boot Proof.
    let ephemeral = EphemeralKey::load();
    println!(
        "keys: boot ephemeral key  = {}",
        ephemeral.boot_ephemeral_key_hex()
    );

    let config = Config::load(args.organization_id, args.rules_path);
    let state = Arc::new(AppState {
        keys,
        ephemeral,
        config,
    });

    let listen_addr = format!("0.0.0.0:{}", args.port);
    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .expect("bind listener");
    println!("tvc-cosign listening on {listen_addr}");

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

/// Serve the quorum-derived stamping keys so an operator can register them as the
/// two Turnkey API users. These are stable across the TVC's replicas (the quorum
/// key is shared), so they only need to be fetched and registered once. The
/// per-replica ephemeral/Boot-Proof key is NOT here — it rides on each `/cosign`
/// response instead (see [`CosignResponse::boot_ephemeral_key`]).
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
    /// Enclave-signed proof committing to this decision (see `proof.rs`).
    app_proof: AppProof,
    /// The QOS KeySet of the replica that produced `app_proof`. Pass it to
    /// `get_boot_proof` to fetch the Boot Proof and verify the proof against this
    /// enclave's attested code. Per-replica, so it must come from this response.
    boot_ephemeral_key: String,
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

    // The wallet to sign with is a global gate — it must be an allowlisted signer.
    let signer = req
        .signer_address
        .parse::<Address>()
        .map_err(|e| bad_request(format!("invalid signerAddress: {e}"), None))?;

    let classification = classify(signer, &parsed, &state.config.ruleset);

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

    // One timestamp shared by the activity body and the proof for this request.
    let timestamp_ms = now_ms();
    let body = build_sign_transaction(&SignTransaction {
        organization_id: &state.config.organization_id,
        sign_with: &req.signer_address,
        unsigned_transaction: &req.unsigned_transaction,
        timestamp_ms,
    });
    let stamped = stamp::stamp(key, &body);

    // Attach an App Proof committing to this decision. `raw` re-encoded is the
    // same normalized (no-`0x`, lowercase) form the activity body carries.
    let proof = app_proof(
        &state.ephemeral,
        &ProofInputs {
            organization_id: &state.config.organization_id,
            signer_address: &req.signer_address,
            unsigned_transaction: &hex::encode(&raw),
            classification,
            stamped_with: &key.public_key_hex(),
            activity_body: &stamped.body,
            timestamp_ms,
        },
    );

    Ok(Json(CosignResponse {
        activity_body: stamped.body,
        x_stamp: stamped.x_stamp,
        classification,
        app_proof: proof,
        boot_ephemeral_key: state.ephemeral.boot_ephemeral_key_hex().to_string(),
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
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
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
