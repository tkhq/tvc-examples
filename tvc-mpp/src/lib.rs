//! Fixed synthetic-data evaluation, protected by OAuth access tokens.

mod auth;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use qos_p256::P256Pair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use turnkey_jwt_verify::unix_now;

pub const MAX_BODY_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct AppState {
    ephemeral_key: Arc<P256Pair>,
    policy: Arc<auth::AccessPolicy>,
}

impl AppState {
    pub fn new(
        ephemeral_key: P256Pair,
        jwks: &[u8],
        issuer: &str,
        audience: &str,
        client_id: &str,
        required_scope: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let policy = auth::AccessPolicy::new(jwks, issuer, audience, client_id, required_scope)?;
        Ok(Self {
            ephemeral_key: Arc::new(ephemeral_key),
            policy: Arc::new(policy),
        })
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"status":"healthy"})) }),
        )
        .route("/v1/evaluate", post(evaluate_request))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub age_years: u8,
    pub country: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Context {
    pub mpp_challenge_id: String,
    pub bot_key_id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionRequest {
    pub job_id: String,
    pub record: Record,
    pub context: Context,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub eligible: bool,
    pub reasons: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofPayload<'a> {
    r#type: &'static str,
    timestamp_ms: String,
    job_id: &'a str,
    input_digest: String,
    result: &'a EvaluationResult,
    mpp_challenge_id: &'a str,
    bot_key_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProof {
    pub scheme: &'static str,
    pub public_key: String,
    pub proof_payload: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct EvaluationResponse {
    pub result: EvaluationResult,
    pub proof: AppProof,
}

pub fn evaluate(record: &Record) -> EvaluationResult {
    let mut reasons = vec![];
    if record.age_years < 18 {
        reasons.push("under_age".into());
    }
    if record.country != "US" {
        reasons.push("unsupported_country".into());
    }
    EvaluationResult {
        eligible: reasons.is_empty(),
        reasons,
    }
}

pub fn validate(request: &ExecutionRequest) -> bool {
    !request.job_id.is_empty()
        && request.job_id.len() <= 64
        && request
            .job_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && request.record.age_years <= 130
        && request.record.country.len() == 2
        && request
            .record
            .country
            .bytes()
            .all(|b| b.is_ascii_uppercase())
        && !request.context.mpp_challenge_id.is_empty()
        && request.context.mpp_challenge_id.len() <= 512
        && !request.context.bot_key_id.is_empty()
        && request.context.bot_key_id.len() <= 128
}

/// Sign the exact serialized application claim using the QOS ephemeral pair.
/// `P256Pair::sign` hashes these bytes once with SHA-256.
pub fn create_app_proof(
    ephemeral_key: &P256Pair,
    request: &ExecutionRequest,
    body: &[u8],
    result: &EvaluationResult,
    timestamp_ms: String,
) -> Result<AppProof, Box<dyn std::error::Error>> {
    let payload = ProofPayload {
        r#type: "APP_PROOF_TYPE_MPP_EVALUATION_V1",
        timestamp_ms,
        job_id: &request.job_id,
        input_digest: qos_hex::encode(&Sha256::digest(body)),
        result,
        mpp_challenge_id: &request.context.mpp_challenge_id,
        bot_key_id: &request.context.bot_key_id,
    };
    let proof_payload = serde_json::to_string(&payload)?;
    let signature = ephemeral_key
        .sign(proof_payload.as_bytes())
        .map_err(|_| "App Proof signing failed")?;
    Ok(AppProof {
        scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
        public_key: qos_hex::encode(&ephemeral_key.public_key().to_bytes()),
        proof_payload,
        signature: qos_hex::encode(&signature),
    })
}

async fn evaluate_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let tokens: Vec<_> = headers.get_all(header::AUTHORIZATION).iter().collect();
    let token = match tokens.as_slice() {
        [value] => value
            .to_str()
            .ok()
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|token| !token.is_empty()),
        _ => None,
    };
    let Some(token) = token else {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    if state.policy.authorize(token, unix_now()).is_err() {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim)
        != Some("application/json")
    {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application_json_required",
        );
    }
    let request: ExecutionRequest = match serde_json::from_slice(&body) {
        Ok(request) if validate(&request) => request,
        _ => return error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let result = evaluate(&request.record);
    let timestamp_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => now.as_millis().to_string(),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable"),
    };
    let proof = match create_app_proof(&state.ephemeral_key, &request, &body, &result, timestamp_ms)
    {
        Ok(proof) => proof,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "proof_signing_failed"),
    };
    Json(EvaluationResponse { result, proof }).into_response()
}

fn error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({"error":code}))).into_response()
}
