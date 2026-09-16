//! Router for the TVC policy sidecar
use crate::handlers::{health, hello_world, time, turnkey_api_public_key};
use crate::webhook::turnkey_activity_webhook;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

pub use crate::state::AppState;

/// Build the application router with the given state.
pub fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/hello_world", get(hello_world))
        .route("/time", get(time))
        .route("/turnkey/api_public_key", get(turnkey_api_public_key))
        .route(
            "/webhooks/turnkey/activity",
            post(turnkey_activity_webhook).layer(DefaultBodyLimit::max(1024 * 1024)),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use qos_p256::{P256Pair, P256Public};
    use tower::ServiceExt;

    async fn body_string(body: Body) -> String {
        let bytes = body
            .collect()
            .await
            .expect("failed to read body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("invalid utf8")
    }

    fn router_with_generated_keys() -> Router {
        router_with_generated_keys_and_quorum_public().0
    }

    fn router_with_generated_keys_and_quorum_public() -> (Router, P256Public) {
        let quorum_key = P256Pair::generate().expect("failed to generate quorum key");
        let quorum_public = quorum_key.public_key();

        (
            router_with_state(
                AppState::new(
                    quorum_key,
                    "organization-id".to_owned(),
                    "http://127.0.0.1:1".to_owned(),
                )
                .expect("failed to build app state"),
            ),
            quorum_public,
        )
    }

    #[tokio::test]
    async fn turnkey_api_public_key_matches_quorum_key() {
        let (app, quorum_public) = router_with_generated_keys_and_quorum_public();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/turnkey/api_public_key")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response.into_body()).await;
        let response_json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");
        let compressed_public = quorum_public
            .signing_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        assert_eq!(
            response_json,
            serde_json::json!({
                "publicKey": qos_hex::encode(&compressed_public),
                "curveType": "API_KEY_CURVE_P256"
            })
        );
    }

    #[tokio::test]
    async fn test_health() {
        let app = router_with_generated_keys();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");

        assert_eq!(response.status(), 200);
        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");
        assert_eq!(json["status"], "healthy");
    }

    #[tokio::test]
    async fn test_hello_world() {
        let app = router_with_generated_keys();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/hello_world")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");

        assert_eq!(response.status(), 200);
        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");
        assert_eq!(json["message"], "hello world");
    }

    #[tokio::test]
    async fn test_time() {
        let app = router_with_generated_keys();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/time")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");

        assert_eq!(response.status(), 200);
        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");
        assert!(json["time"].is_u64(), "time field should be a number");
    }

    #[tokio::test]
    async fn removed_endpoints_return_not_found() {
        let app = router_with_generated_keys();
        for (method, path) in [
            ("POST", "/turnkey/sign_transaction"),
            ("POST", "/echo"),
            ("GET", "/btc_price"),
            ("GET", "/download"),
            ("POST", "/quorum_key/encrypt"),
            ("POST", "/quorum_key/decrypt"),
            ("GET", "/random_app_proof"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .expect("request should build"),
                )
                .await
                .expect("request should execute");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        }
    }
}
