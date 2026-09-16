//! Authenticate, evaluate, and submit a vote for one Turnkey activity delivery.

mod activity;
mod delivery;
#[cfg(test)]
mod test_support;
mod verification;

use crate::{response::AppError, state::AppState, turnkey_voter::Vote};
use activity::{ActivityDecision, ActivityPayloadError, ActivityWebhookPayload, evaluate_activity};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
pub(crate) use delivery::DeliveryTracker;
use std::time::{SystemTime, UNIX_EPOCH};
pub(crate) use verification::WebhookVerifier;

const ACTIVITY_UPDATES: &str = "ACTIVITY_UPDATES";

/// Handle one signed Turnkey activity update.
pub(crate) async fn turnkey_activity_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<StatusCode, AppError> {
    let delivery = state
        .webhook_verifier
        .verify(&headers, &raw_body)
        .await
        .map_err(|error| {
            if error.is_retryable() {
                AppError::service_unavailable(error.to_string())
            } else {
                AppError::unauthorized(error.to_string())
            }
        })?;
    if delivery.event_type != ACTIVITY_UPDATES {
        return Err(AppError::bad_request(
            "unexpected Turnkey webhook event type",
        ));
    }

    // JSON is deliberately parsed only after signature verification over the exact bytes.
    let activity: ActivityWebhookPayload = serde_json::from_slice(&raw_body)
        .map_err(|error| AppError::bad_request(format!("invalid activity payload: {error}")))?;
    if delivery.organization_id != state.turnkey_organization_id
        || activity.organization_id != state.turnkey_organization_id
    {
        return Err(AppError::unauthorized(
            "webhook organization does not match this deployment",
        ));
    }

    let event_lock = state.delivery_tracker.lock_for(&delivery.event_id).await;
    let _event_guard = event_lock.lock().await;
    if state
        .delivery_tracker
        .is_completed(&delivery.event_id)
        .await
    {
        return Ok(StatusCode::NO_CONTENT);
    }

    let decision = evaluate_activity(&activity)
        .map_err(|error| AppError::bad_request(format!("invalid activity payload: {error}")))?;
    let vote = match &decision {
        ActivityDecision::Approve(reason) => {
            tracing::info!(activity_id = %activity.id, reason = %reason, "approving Turnkey activity");
            Some(Vote::Approve)
        }
        ActivityDecision::Reject(reason) => {
            tracing::info!(activity_id = %activity.id, reason = %reason, "rejecting Turnkey activity");
            Some(Vote::Reject)
        }
        ActivityDecision::Ignore(reason) => {
            tracing::info!(activity_id = %activity.id, reason = %reason, "ignoring Turnkey activity");
            None
        }
    };
    if let Some(vote) = vote {
        let fingerprint = activity
            .fingerprint
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AppError::bad_request(format!(
                    "invalid activity payload: {}",
                    ActivityPayloadError::MissingFingerprint
                ))
            })?;
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| AppError::service_unavailable(format!("system clock error: {error}")))?
            .as_millis();
        state
            .turnkey_voter
            .submit(
                &state.turnkey_organization_id,
                fingerprint,
                timestamp_ms,
                vote,
            )
            .await
            .map_err(|error| {
                if error.is_retryable() {
                    AppError::service_unavailable(error.to_string())
                } else {
                    AppError::bad_request(error.to_string())
                }
            })?;
    }

    state.delivery_tracker.complete(&delivery.event_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::test_support::*;
    use super::verification::ORGANIZATION_ID_HEADER;
    use super::*;
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt as _;
    use qos_p256::P256Pair;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn endpoint_votes_with_quorum_key_and_suppresses_duplicates() {
        let webhook_signing_key = SigningKey::from_bytes(&[4; 32]);
        let (base_url, captured_votes) = spawn_turnkey_server(webhook_signing_key.clone()).await;
        let quorum_key = P256Pair::generate().expect("quorum key should generate");
        let expected_public_key = qos_hex::encode(
            quorum_key
                .public_key()
                .signing_key()
                .to_encoded_point(true)
                .as_bytes(),
        );
        let state = AppState::new(quorum_key, "organization-id".to_owned(), base_url)
            .expect("app state should build");
        let app = crate::router::router_with_state(state);
        let public_key_response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/turnkey/api_public_key")
                    .body(axum::body::Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should execute");
        assert_eq!(public_key_response.status(), StatusCode::OK);
        let public_key_body = public_key_response
            .into_body()
            .collect()
            .await
            .expect("response should collect")
            .to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&public_key_body)
                .expect("public key is JSON"),
            serde_json::json!({"publicKey": expected_public_key, "curveType": "API_KEY_CURVE_P256"})
        );
        let body = webhook_body(Some(&valid_aptos_transaction()));

        let response = app
            .clone()
            .oneshot(webhook_request(
                &webhook_signing_key,
                "event-1",
                body.clone(),
            ))
            .await
            .expect("webhook request should execute");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let duplicate = app
            .oneshot(webhook_request(&webhook_signing_key, "event-1", body))
            .await
            .expect("duplicate request should execute");
        assert_eq!(duplicate.status(), StatusCode::NO_CONTENT);

        let votes = captured_votes.lock().expect("captured votes lock poisoned");
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].path, "approve");
        verify_vote(
            &votes[0],
            "ACTIVITY_TYPE_APPROVE_ACTIVITY",
            &expected_public_key,
        );
    }

    #[tokio::test]
    async fn endpoint_rejects_aptos_missing_payload_and_enforces_body_limit() {
        let webhook_signing_key = SigningKey::from_bytes(&[5; 32]);
        let (base_url, captured_votes) = spawn_turnkey_server(webhook_signing_key.clone()).await;
        let quorum_key = P256Pair::generate().expect("quorum key should generate");
        let expected_public_key = qos_hex::encode(
            quorum_key
                .public_key()
                .signing_key()
                .to_encoded_point(true)
                .as_bytes(),
        );
        let state = AppState::new(quorum_key, "organization-id".to_owned(), base_url)
            .expect("app state should build");
        let app = crate::router::router_with_state(state);
        let response = app
            .clone()
            .oneshot(webhook_request(
                &webhook_signing_key,
                "event-2",
                webhook_body(None),
            ))
            .await
            .expect("webhook request should execute");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        for activity_type in [
            "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
            "ACTIVITY_TYPE_SIGN_TRANSACTION",
            "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD",
            "ACTIVITY_TYPE_SIGN_RAW_PAYLOADS",
            "ACTIVITY_TYPE_EXPORT_WALLET",
            "ACTIVITY_TYPE_UPDATE_ROOT_QUORUM",
        ] {
            let mut ignored = activity_fixture();
            ignored["type"] = serde_json::json!(activity_type);
            let response = app
                .clone()
                .oneshot(webhook_request(
                    &webhook_signing_key,
                    activity_type,
                    serde_json::to_vec(&ignored).expect("activity serializes"),
                ))
                .await
                .expect("request should execute");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        let mut wrong_organization = webhook_request(
            &webhook_signing_key,
            "event-wrong-organization",
            webhook_body(Some(&valid_aptos_transaction())),
        );
        wrong_organization.headers_mut().insert(
            ORGANIZATION_ID_HEADER,
            "different-organization"
                .parse()
                .expect("organization header should parse"),
        );
        let response = app
            .clone()
            .oneshot(wrong_organization)
            .await
            .expect("wrong-organization request should execute");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut tampered = webhook_request(
            &webhook_signing_key,
            "event-tampered",
            webhook_body(Some(&valid_aptos_transaction())),
        );
        *tampered.body_mut() = axum::body::Body::from("{}");
        let response = app
            .clone()
            .oneshot(tampered)
            .await
            .expect("tampered request should execute");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        {
            let votes = captured_votes.lock().expect("captured votes lock poisoned");
            assert_eq!(votes.len(), 1);
            assert_eq!(votes[0].path, "reject");
            verify_vote(
                &votes[0],
                "ACTIVITY_TYPE_REJECT_ACTIVITY",
                &expected_public_key,
            );
        }

        let oversized = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/webhooks/turnkey/activity")
                    .body(axum::body::Body::from(vec![0; 1024 * 1024 + 1]))
                    .expect("oversized request should build"),
            )
            .await
            .expect("oversized request should execute");
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let _ = oversized
            .into_body()
            .collect()
            .await
            .expect("response body should collect");
    }

    fn app_for_test(base_url: String) -> axum::Router {
        crate::router::router_with_state(
            AppState::new(
                P256Pair::generate().expect("quorum key should generate"),
                "organization-id".to_owned(),
                base_url,
            )
            .expect("state should build"),
        )
    }

    #[tokio::test]
    async fn concurrent_duplicates_submit_one_vote() {
        let key = SigningKey::from_bytes(&[6; 32]);
        let (base_url, votes) = spawn_turnkey_server(key.clone()).await;
        let app = app_for_test(base_url);
        let body = webhook_body(Some(&valid_aptos_transaction()));
        let first = app
            .clone()
            .oneshot(webhook_request(&key, "concurrent", body.clone()));
        let second = app.oneshot(webhook_request(&key, "concurrent", body));
        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            first.expect("first delivery should execute").status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            second.expect("second delivery should execute").status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(votes.lock().expect("votes lock should succeed").len(), 1);
    }

    #[tokio::test]
    async fn failed_vote_is_retried_before_marking_delivery_complete() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let (base_url, votes) = spawn_turnkey_server_with_vote_statuses(
            key.clone(),
            vec![StatusCode::SERVICE_UNAVAILABLE, StatusCode::OK],
        )
        .await;
        let app = app_for_test(base_url);
        let body = webhook_body(Some(&valid_aptos_transaction()));
        for (expected_status, expected_attempts) in [
            (StatusCode::SERVICE_UNAVAILABLE, 1),
            (StatusCode::NO_CONTENT, 2),
            (StatusCode::NO_CONTENT, 2),
        ] {
            let response = app
                .clone()
                .oneshot(webhook_request(&key, "retry", body.clone()))
                .await
                .expect("delivery should execute");
            assert_eq!(response.status(), expected_status);
            assert_eq!(
                votes.lock().expect("votes lock should succeed").len(),
                expected_attempts
            );
        }
    }

    #[tokio::test]
    async fn upstream_vote_status_controls_webhook_retryability() {
        for (upstream, expected) in [
            (StatusCode::BAD_REQUEST, StatusCode::BAD_REQUEST),
            (StatusCode::UNAUTHORIZED, StatusCode::BAD_REQUEST),
            (StatusCode::FORBIDDEN, StatusCode::BAD_REQUEST),
            (StatusCode::NOT_FOUND, StatusCode::BAD_REQUEST),
            (StatusCode::CONFLICT, StatusCode::BAD_REQUEST),
            (StatusCode::UNPROCESSABLE_ENTITY, StatusCode::BAD_REQUEST),
            (StatusCode::REQUEST_TIMEOUT, StatusCode::SERVICE_UNAVAILABLE),
            (
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (StatusCode::BAD_GATEWAY, StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let key = SigningKey::from_bytes(&[11; 32]);
            let (base_url, votes) =
                spawn_turnkey_server_with_vote_statuses(key.clone(), vec![upstream]).await;
            let response = app_for_test(base_url)
                .oneshot(webhook_request(
                    &key,
                    "vote-status",
                    webhook_body(Some(&valid_aptos_transaction())),
                ))
                .await
                .expect("delivery should execute");
            assert_eq!(response.status(), expected, "upstream status: {upstream}");
            assert_eq!(votes.lock().expect("votes lock should succeed").len(), 1);
        }
    }

    #[tokio::test]
    async fn jwks_failure_returns_retryable_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener has an address");
        let server = axum::Router::new().route(
            "/public/v1/discovery/webhooks/jwks",
            axum::routing::get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, server)
                .await
                .expect("server should run");
        });
        let key = SigningKey::from_bytes(&[8; 32]);
        let response = app_for_test(format!("http://{address}"))
            .oneshot(webhook_request(
                &key,
                "jwks-failure",
                webhook_body(Some(&valid_aptos_transaction())),
            ))
            .await
            .expect("delivery should execute");
        task.abort();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn signed_body_organization_mismatch_and_missing_fingerprint_do_not_vote() {
        let key = SigningKey::from_bytes(&[10; 32]);
        let (base_url, votes) = spawn_turnkey_server(key.clone()).await;
        let app = app_for_test(base_url);
        let mut wrong_org = activity_fixture();
        wrong_org["organizationId"] = serde_json::json!("different-organization");
        let mut missing_fingerprint = activity_fixture();
        missing_fingerprint
            .as_object_mut()
            .expect("fixture is an object")
            .remove("fingerprint");
        let mut empty_fingerprint = activity_fixture();
        empty_fingerprint["fingerprint"] = serde_json::json!("");
        for (id, body, status) in [
            ("body-org-mismatch", wrong_org, StatusCode::UNAUTHORIZED),
            (
                "missing-fingerprint",
                missing_fingerprint,
                StatusCode::BAD_REQUEST,
            ),
            (
                "empty-fingerprint",
                empty_fingerprint,
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(webhook_request(
                    &key,
                    id,
                    serde_json::to_vec(&body).expect("fixture should serialize"),
                ))
                .await
                .expect("delivery should execute");
            assert_eq!(response.status(), status);
        }
        assert!(votes.lock().expect("votes lock should succeed").is_empty());
    }
}
