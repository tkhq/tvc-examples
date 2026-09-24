//! Router for the signed ETH/USD oracle service.

use crate::handlers::{
    dashboard, health, oracle_status, random_app_proof, signed_eth_usd_observation,
};
use axum::{Router, routing::get};
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

pub use crate::state::AppState;

/// Build the application router with the given state.
pub fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/oracle/observation", get(signed_eth_usd_observation))
        .route("/oracle/status", get(oracle_status))
        .route("/app-proof", get(random_app_proof))
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
    use axum::{body::Body, http::StatusCode};
    use http_body_util::BodyExt;
    use qos_p256::{P256Pair, P256Public};
    use tower::ServiceExt;

    fn router_with_generated_keys() -> Router {
        let ephemeral_key = P256Pair::generate().expect("failed to generate ephemeral key");
        let quorum_key = P256Pair::generate().expect("failed to generate quorum key");
        router_with_state(
            AppState::new(ephemeral_key, quorum_key).expect("failed to build app state"),
        )
    }

    async fn body_string(body: Body) -> String {
        let bytes = body
            .collect()
            .await
            .expect("failed to read body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("invalid UTF-8")
    }

    #[tokio::test]
    async fn health_is_available() {
        let response = router_with_generated_keys()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dashboard_explains_the_oracle() {
        let response = router_with_generated_keys()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response.into_body()).await;
        assert!(body.contains("A signed price, carried on-chain."));
        assert!(body.contains("/oracle/status"));
    }

    #[tokio::test]
    async fn app_proof_signature_verifies() {
        let response = router_with_generated_keys()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/app-proof")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");
        assert_eq!(response.status(), StatusCode::OK);

        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");
        let payload = json["proof"]["payload"]
            .as_str()
            .expect("proof payload should be a string");
        let public_key = P256Public::from_bytes(
            &qos_hex::decode(
                json["proof"]["public_key"]
                    .as_str()
                    .expect("public key should be a string"),
            )
            .expect("public key should hex decode"),
        )
        .expect("public key should decode");
        let signature = qos_hex::decode(
            json["proof"]["signature"]
                .as_str()
                .expect("signature should be a string"),
        )
        .expect("signature should hex decode");
        public_key
            .verify(payload.as_bytes(), &signature)
            .expect("proof signature should verify");
    }

    #[tokio::test]
    async fn template_routes_are_not_exposed() {
        for path in ["/hello_world", "/time", "/download", "/quorum_key/decrypt"] {
            let response = router_with_generated_keys()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("failed to build request"),
                )
                .await
                .expect("failed to execute request");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }
}
