//! HTTP surface.
//!
//! - `POST /v1/installations/{installation_id}/tokens?permissions=..&repositories=..`
//!   behind the http-authz/v1 middleware (`token_route_rule`).
//! - `GET /v1/info`: audience, App client ID, key fingerprint, trusted kids.
//! - `GET /health`

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, OriginalUri, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;
use tower_http::trace::TraceLayer;

use turnkey_jwt_profiles::http_authz::middleware::{Verified, route_layer};
use turnkey_jwt_profiles::http_authz::{RouteRule, Verifier};

use crate::delivery;
use crate::github::{GitHubClient, GitHubError};
use crate::scope::{Allowlist, parse_scope};

pub use turnkey_jwt_profiles::http_authz::middleware::DEFAULT_MAX_BODY_BYTES as MAX_BODY_BYTES;

/// The profile name in the `MINT_JWT` intent.
const PROFILE: &str = "JWT_PROFILE_HTTP_AUTHZ_V1";
/// The JOSE `typ` of the profile's tokens.
const TYP: &str = "application/vnd.turnkey.http-authz-v1+jwt";

/// Headers that a token for the token route must bind. They name the GitHub
/// API version and media type the caller expects. Binding them means a host
/// cannot change them after policy ran. This broker always calls GitHub
/// with API version 2022-11-28; a broker that forwarded them would depend on
/// them.
pub const TOKEN_ROUTE_REQUIRED_HEADERS: [&str; 2] = ["accept", "x-github-api-version"];

/// The http-authz/v1 rule for the token route.
///
/// Tokens are not single-use: a token works any number of times until `exp`.
/// A replay repeats only the exact approved request, and the new installation
/// token is sealed to the HPKE key in the bound body, so only the original
/// caller can read it. The cost is extra GitHub tokens.
#[must_use]
fn token_route_rule() -> RouteRule {
    RouteRule {
        required_headers: TOKEN_ROUTE_REQUIRED_HEADERS
            .iter()
            .map(|h| (*h).to_owned())
            .collect(),
        require_body_digest: true,
    }
}

/// Shared application state.
pub struct AppState {
    /// Verifier settings and keys.
    pub verifier: Arc<Verifier>,
    /// The app's exact origin, for `/v1/info`.
    pub audience: String,
    /// The top-level organization ID, for `/v1/info`.
    pub organization_id: String,
    /// Whether a rejected request says which check failed.
    pub detailed_auth_errors: bool,
    /// App-side allowlist.
    pub allowlist: Allowlist,
    /// Whether `admin` levels are accepted.
    pub allow_admin: bool,
    /// GitHub client, holding the App key.
    pub github: GitHubClient,
    /// App client ID, for `/v1/info`.
    pub app_client_id: String,
    /// Trusted kids, for `/v1/info`.
    pub trusted_kids: Vec<String>,
}

/// Build the router.
pub fn router(state: Arc<AppState>) -> Router {
    let token_route = post(issue_token).route_layer(
        route_layer(Arc::clone(&state.verifier), token_route_rule())
            .with_detailed_errors(state.detailed_auth_errors),
    );
    Router::new()
        .route(
            "/health",
            get(|| async { axum::Json(json!({"status": "healthy"})) }),
        )
        .route("/v1/info", get(info))
        .route("/v1/installations/{installation_id}/tokens", token_route)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn error(status: StatusCode, code: &str, message: impl std::fmt::Display) -> Response {
    (
        status,
        axum::Json(json!({"error": code, "message": message.to_string()})),
    )
        .into_response()
}

async fn info(State(st): State<Arc<AppState>>) -> Response {
    axum::Json(json!({
        "audience": st.audience,
        "profile": PROFILE,
        "typ": TYP,
        "issuer": format!("https://id.turnkey.com/t/{}", st.organization_id),
        "token_route": {
            "required_headers": TOKEN_ROUTE_REQUIRED_HEADERS,
        },
        "trusted_kids": st.trusted_kids,
        "github_app_client_id": st.app_client_id,
        "github_app_key_sha256": st.github.key_fingerprint(),
        "token_delivery": delivery::SUITE,
    }))
    .into_response()
}

async fn issue_token(
    State(st): State<Arc<AppState>>,
    Extension(Verified(claims)): Extension<Verified>,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    // The middleware already verified the JWT, checked its parent
    // organization, and bound it to this exact request (method, path, query,
    // required headers, body).
    let now = crate::unix_now();

    // 1. Scope bounds, then the app-side allowlist. Turnkey policy cannot
    //    express "a subset of these repositories", so this allowlist is the
    //    scope enforcement.
    let scope = match parse_scope(uri.path(), uri.query().unwrap_or(""), st.allow_admin) {
        Ok(s) => s,
        Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_scope", e),
    };
    if let Err(e) = st.allowlist.check(&scope, &claims.org) {
        return error(StatusCode::FORBIDDEN, "scope_not_allowed", e);
    }
    let Some(body_digest) = claims.tk_body_digest.as_deref() else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "verified claims have no tk_body_digest",
        );
    };
    let recipient = match delivery::parse_recipient(&body) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_body", e.0),
    };

    // 2. GitHub.
    let issued = match st.github.create_installation_token(&scope, now).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(org = claims.org, sub = claims.sub, error = %e, "GitHub token request failed");
            let code = match e {
                GitHubError::GrantMismatch { .. } => "github_grant_too_broad",
                _ => "github_error",
            };
            return error(StatusCode::BAD_GATEWAY, code, e);
        }
    };

    // 3. Seal to the caller. The plaintext token leaves this function only
    //    as HPKE ciphertext.
    let token_sha256 = crate::b64::std_encode(
        ring::digest::digest(&ring::digest::SHA256, issued.token.expose().as_bytes()).as_ref(),
    );
    let sealed = match delivery::seal(
        &recipient,
        issued.token.expose().as_bytes(),
        body_digest.as_bytes(),
    ) {
        Ok(s) => s,
        Err(e) => {
            let revoked = st.github.revoke(issued.token.expose()).await;
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "delivery_failed",
                format!("{} (revoked={revoked})", e.0),
            );
        }
    };
    tracing::info!(
        org = claims.org,
        sub = claims.sub,
        installation_id = scope.installation_id,
        repositories = ?issued.grant.repositories,
        permissions = ?issued.grant.permissions,
        expires_at = issued.grant.expires_at,
        token_sha256,
        "issued installation token"
    );
    (
        StatusCode::CREATED,
        axum::Json(json!({
            "installation_id": scope.installation_id,
            "repositories": issued.grant.repositories,
            "permissions": issued.grant.permissions,
            "repository_selection": issued.grant.repository_selection,
            "expires_at": issued.grant.expires_at,
            "token_sha256": token_sha256,
            "encrypted_token": sealed,
            "authorization": {
                "iss": claims.iss,
                "org": claims.org,
                "sub": claims.sub,
                "iat": claims.iat,
                "exp": claims.exp,
            },
        })),
    )
        .into_response()
}
