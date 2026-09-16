//! Shared test fixtures and local Turnkey mock servers.
#![allow(clippy::expect_used)]

use super::verification::*;
use crate::aptos_policy::tests::{sender, signing_message, transaction};
use axum::{
    Json, Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use std::{
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const ACTIVITY_UPDATES: &str = "ACTIVITY_UPDATES";
const CONSENSUS_NEEDED: &str = "ACTIVITY_STATUS_CONSENSUS_NEEDED";
const SIGN_RAW_PAYLOAD_V2: &str = "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2";
#[derive(Debug)]
pub(super) struct CapturedVote {
    pub(super) path: &'static str,
    body: serde_json::Value,
    x_stamp: String,
    raw_body: Vec<u8>,
}

pub(super) async fn spawn_jwks_server(
    responses: Vec<serde_json::Value>,
    cache_control: &'static str,
) -> (String, Arc<AtomicUsize>) {
    let responses = Arc::new(StdMutex::new(responses));
    let request_count = Arc::new(AtomicUsize::new(0));
    let response_values = Arc::clone(&responses);
    let response_count = Arc::clone(&request_count);
    let app = Router::new().route(
        JWKS_PATH,
        get(move || {
            let response_values = Arc::clone(&response_values);
            let response_count = Arc::clone(&response_count);
            async move {
                let index = response_count.fetch_add(1, Ordering::SeqCst);
                let values = response_values
                    .lock()
                    .expect("JWKS responses lock poisoned");
                let selected = index.min(values.len().saturating_sub(1));
                (
                    [(reqwest::header::CACHE_CONTROL.as_str(), cache_control)],
                    Json(values[selected].clone()),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test JWKS listener should bind");
    let address = listener.local_addr().expect("listener has an address");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test JWKS server should run");
    });
    (format!("http://{address}"), request_count)
}

pub(super) fn jwks(signing_key: &SigningKey, key_id: &str) -> serde_json::Value {
    serde_json::json!({
        "keys": [{
            "kid": key_id,
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "x": BASE64_URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            "turnkey_signature_algorithm": SIGNATURE_ALGORITHM,
            "turnkey_signature_version": SIGNATURE_VERSION
        }]
    })
}

pub(super) fn signed_headers(
    signing_key: &SigningKey,
    key_id: &str,
    timestamp_ms: u128,
    event_id: &str,
    body: &[u8],
) -> HeaderMap {
    let timestamp = timestamp_ms.to_string();
    let mut signed_message =
        format!("{SIGNATURE_VERSION}.{SIGNATURE_ALGORITHM}.{key_id}.{timestamp}.{event_id}.")
            .into_bytes();
    signed_message.extend_from_slice(body);
    let signature = signing_key.sign(&signed_message);

    let mut headers = HeaderMap::new();
    let values = [
        (ORGANIZATION_ID_HEADER, "organization-id"),
        (EVENT_TYPE_HEADER, ACTIVITY_UPDATES),
        (TIMESTAMP_HEADER, timestamp.as_str()),
        (WEBHOOK_VERSION_HEADER, WEBHOOK_VERSION),
        (EVENT_ID_HEADER, event_id),
        (SIGNATURE_KEY_ID_HEADER, key_id),
        (SIGNATURE_ALGORITHM_HEADER, SIGNATURE_ALGORITHM),
        (SIGNATURE_VERSION_HEADER, SIGNATURE_VERSION),
    ];
    for (name, value) in values {
        headers.insert(name, value.parse().expect("test header value should parse"));
    }
    headers.insert(
        SIGNATURE_HEADER,
        qos_hex::encode(&signature.to_bytes())
            .parse()
            .expect("signature header should parse"),
    );
    headers
}

pub(super) async fn spawn_turnkey_server(
    webhook_signing_key: SigningKey,
) -> (String, Arc<StdMutex<Vec<CapturedVote>>>) {
    spawn_turnkey_server_with_vote_statuses(webhook_signing_key, vec![StatusCode::OK]).await
}

pub(super) async fn spawn_turnkey_server_with_vote_statuses(
    webhook_signing_key: SigningKey,
    statuses: Vec<StatusCode>,
) -> (String, Arc<StdMutex<Vec<CapturedVote>>>) {
    assert!(!statuses.is_empty());
    let statuses = Arc::new(statuses);
    let attempts = Arc::new(AtomicUsize::new(0));
    let votes = Arc::new(StdMutex::new(Vec::new()));
    let approve_votes = Arc::clone(&votes);
    let reject_votes = Arc::clone(&votes);
    let jwks_value = jwks(&webhook_signing_key, "webhook-key");
    let app = Router::new()
        .route(
            JWKS_PATH,
            get(move || {
                let jwks_value = jwks_value.clone();
                async move {
                    (
                        [(reqwest::header::CACHE_CONTROL.as_str(), "max-age=300")],
                        Json(jwks_value),
                    )
                }
            }),
        )
        .route(
            "/public/v1/submit/approve_activity",
            post(move |headers: HeaderMap, body: Bytes| {
                let votes = Arc::clone(&approve_votes);
                let statuses = Arc::clone(&statuses);
                let attempts = Arc::clone(&attempts);
                async move {
                    capture_vote(&votes, "approve", &headers, &body);
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                    let status = statuses[attempt.min(statuses.len() - 1)];
                    (
                        status,
                        Json(completed_vote_activity("ACTIVITY_TYPE_APPROVE_ACTIVITY")),
                    )
                }
            }),
        )
        .route(
            "/public/v1/submit/reject_activity",
            post(move |headers: HeaderMap, body: Bytes| {
                let votes = Arc::clone(&reject_votes);
                async move {
                    capture_vote(&votes, "reject", &headers, &body);
                    Json(completed_vote_activity("ACTIVITY_TYPE_REJECT_ACTIVITY"))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test Turnkey listener should bind");
    let address = listener.local_addr().expect("listener has an address");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test Turnkey server should run");
    });
    (format!("http://{address}"), votes)
}

fn capture_vote(
    votes: &StdMutex<Vec<CapturedVote>>,
    path: &'static str,
    headers: &HeaderMap,
    body: &[u8],
) {
    let raw_body = body.to_vec();
    let body = serde_json::from_slice(body).expect("vote request should be JSON");
    let x_stamp = headers
        .get("x-stamp")
        .expect("vote should have X-Stamp")
        .to_str()
        .expect("X-Stamp should be text")
        .to_owned();
    votes
        .lock()
        .expect("captured votes lock poisoned")
        .push(CapturedVote {
            path,
            body,
            x_stamp,
            raw_body,
        });
}

pub(super) fn verify_vote(vote: &CapturedVote, expected_type: &str, expected_public_key: &str) {
    let timestamp = vote.body["timestampMs"]
        .as_str()
        .expect("vote timestamp is a string");
    assert!(
        timestamp
            .parse::<u128>()
            .expect("vote timestamp is numeric")
            > 0
    );
    assert_eq!(
        vote.body,
        serde_json::json!({
            "type": expected_type,
            "generateAppProofs": null,
            "timestampMs": timestamp,
            "organizationId": "organization-id",
            "parameters": { "fingerprint": "fingerprint" },
        })
    );
    let stamp_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(&vote.x_stamp)
        .expect("stamp is base64url");
    let stamp: serde_json::Value = serde_json::from_slice(&stamp_bytes).expect("stamp is JSON");
    assert_eq!(stamp["publicKey"], expected_public_key);
    assert_eq!(stamp["scheme"], "SIGNATURE_SCHEME_TK_API_P256");
    let public_key = qos_hex::decode(expected_public_key).expect("public key is hex");
    let verifying_key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key).expect("public key is P256");
    let signature = qos_hex::decode(stamp["signature"].as_str().expect("signature is string"))
        .expect("signature is hex");
    let signature = p256::ecdsa::Signature::from_der(&signature).expect("signature is DER");
    assert!(verifying_key.verify(&vote.raw_body, &signature).is_ok());
}

fn completed_vote_activity(activity_type: &str) -> serde_json::Value {
    serde_json::json!({
        "activity": {
            "id": "vote-activity-id",
            "organizationId": "organization-id",
            "status": "ACTIVITY_STATUS_COMPLETED",
            "type": activity_type,
            "fingerprint": "fingerprint",
            "votes": [],
            "appProofs": []
        }
    })
}

pub(super) fn valid_aptos_transaction() -> String {
    qos_hex::encode(&signing_message(&transaction()))
}

pub(super) fn webhook_body(payload: Option<&str>) -> Vec<u8> {
    let mut intent = serde_json::json!({
        "signWith": sender().to_string(),
        "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
        "hashFunction": "HASH_FUNCTION_NOT_APPLICABLE"
    });
    if let Some(payload) = payload {
        intent["payload"] = serde_json::Value::String(payload.to_owned());
    }
    serde_json::to_vec(&serde_json::json!({
        "id": "activity-id",
        "organizationId": "organization-id",
        "status": CONSENSUS_NEEDED,
        "type": SIGN_RAW_PAYLOAD_V2,
        "fingerprint": "fingerprint",
        "intent": { "signRawPayloadIntentV2": intent }
    }))
    .expect("webhook body should serialize")
}

pub(super) fn webhook_request(
    signing_key: &SigningKey,
    event_id: &str,
    body: Vec<u8>,
) -> axum::http::Request<axum::body::Body> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock should be valid")
        .as_millis();
    let headers = signed_headers(signing_key, "webhook-key", timestamp_ms, event_id, &body);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/webhooks/turnkey/activity")
        .body(axum::body::Body::from(body))
        .expect("webhook request should build");
    *request.headers_mut() = headers;
    request
}
pub(super) fn activity_fixture() -> serde_json::Value {
    serde_json::from_slice(&webhook_body(Some(&valid_aptos_transaction())))
        .expect("fixture should be JSON")
}
