//! GitHub installation-token request, grant checks, and revocation.
//!
//! The request and response rules:
//!
//! - `POST {api}/app/installations/{id}/access_tokens` with a body that the
//!   app builds from the validated scope. The caller never supplies it.
//! - The response must be `201`, `repository_selection == "selected"`, the
//!   granted repositories must be a subset of the requested ones, and each
//!   granted permission must be requested at the same or a higher level.
//! - Otherwise the app revokes the token with `DELETE /installation/token`
//!   and fails.
//!
//! Nothing here logs a JWT, a token, or a response body. A GitHub error is
//! reduced to its status and at most 200 characters of `message`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Deserialize;

use crate::appkey::AppKey;
use crate::scope::{Level, Scope};
use tvc_secrets::SecretString;

const ACCEPT: &str = "application/vnd.github+json";
const API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "tkhq-tvc-github-broker";
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// `metadata: read` is part of every installation token that has repository
/// access. GitHub may return it even when it was not requested. This is the
/// only permission the grant check accepts without a request.
pub const IMPLICIT_PERMISSION: (&str, Level) = ("metadata", Level::Read);

/// A GitHub-side failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHubError {
    /// Network or TLS failure.
    Transport(String),
    /// GitHub returned a non-201 status.
    Status {
        /// HTTP status.
        status: u16,
        /// GitHub `message`, truncated.
        message: String,
        /// Whether a token in the response was revoked.
        revoked: bool,
    },
    /// The response could not be parsed.
    BadResponse(&'static str),
    /// The grant is broader than the request. The token was revoked if
    /// `revoked` is true.
    GrantMismatch {
        /// The check that failed.
        reason: String,
        /// Whether revocation succeeded.
        revoked: bool,
    },
    /// JWT signing failed.
    Signing,
}

impl fmt::Display for GitHubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "GitHub transport error: {e}"),
            Self::Status {
                status,
                message,
                revoked,
            } => write!(f, "GitHub returned {status}: {message} (revoked={revoked})"),
            Self::BadResponse(r) => write!(f, "GitHub response: {r}"),
            Self::GrantMismatch { reason, revoked } => {
                write!(
                    f,
                    "GitHub grant is broader than requested: {reason} (revoked={revoked})"
                )
            }
            Self::Signing => f.write_str("App JWT signing failed"),
        }
    }
}

#[derive(Deserialize)]
struct RepoObject {
    name: String,
}

/// The fields of the token response that the app reads.
#[derive(Deserialize)]
pub struct TokenResponse {
    token: String,
    /// ISO 8601 expiry.
    pub expires_at: String,
    /// Granted permissions.
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
    /// `selected` or `all`.
    #[serde(default)]
    pub repository_selection: Option<String>,
    #[serde(default)]
    repositories: Option<Vec<RepoObject>>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// What GitHub granted, after the checks passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Granted repository names, as GitHub returned them.
    pub repositories: Vec<String>,
    /// Granted permissions, as GitHub returned them.
    pub permissions: BTreeMap<String, String>,
    /// Always `selected`.
    pub repository_selection: String,
    /// ISO 8601 expiry.
    pub expires_at: String,
}

/// An issued, checked token.
pub struct IssuedToken {
    /// The installation token.
    pub token: SecretString,
    /// The checked grant.
    pub grant: Grant,
}

/// Check a grant against the requested scope.
///
/// # Errors
///
/// Returns the reason the grant is broader than the request.
pub fn check_grant(scope: &Scope, resp: &TokenResponse) -> Result<Grant, String> {
    if resp.repository_selection.as_deref() != Some("selected") {
        return Err(format!(
            "repository_selection is {:?}, not \"selected\"",
            resp.repository_selection
        ));
    }
    let Some(repos) = resp.repositories.as_ref() else {
        return Err("response has no repositories list".into());
    };
    if repos.is_empty() {
        return Err("response repositories list is empty".into());
    }
    let requested: BTreeSet<&str> = scope.repositories.iter().map(String::as_str).collect();
    for r in repos {
        // GitHub repository names are case-insensitive; requests are lowercase.
        if !requested.contains(r.name.to_ascii_lowercase().as_str()) {
            return Err(format!("repository {} was not requested", r.name));
        }
    }
    for (name, level) in &resp.permissions {
        let Some(granted) = Level::parse(level) else {
            return Err(format!("permission {name} has unknown level {level}"));
        };
        match scope.permissions.get(name) {
            Some(asked) if granted <= *asked => {}
            None if (name.as_str(), granted) == IMPLICIT_PERMISSION => {}
            Some(asked) => {
                return Err(format!(
                    "permission {name} granted {level}, requested {}",
                    asked.as_str()
                ));
            }
            None => return Err(format!("permission {name}:{level} was not requested")),
        }
    }
    if resp.token.is_empty() {
        return Err("empty token".into());
    }
    if resp.expires_at.is_empty() || resp.expires_at.len() > 64 {
        return Err("bad expires_at".into());
    }
    Ok(Grant {
        repositories: repos.iter().map(|r| r.name.clone()).collect(),
        permissions: resp.permissions.clone(),
        repository_selection: "selected".into(),
        expires_at: resp.expires_at.clone(),
    })
}

/// A GitHub App client for one app.
pub struct GitHubClient {
    base_url: String,
    client_id: String,
    key: AppKey,
    http: reqwest::Client,
}

async fn read_limited(resp: reqwest::Response) -> Result<Vec<u8>, GitHubError> {
    let mut resp = resp;
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| GitHubError::Transport(e.without_url().to_string()))?
    {
        if out.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(GitHubError::BadResponse("response too large"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn github_message(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_owned))
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}

impl GitHubClient {
    /// Build a client. `base_url` has no trailing slash.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(base_url: &str, client_id: &str, key: AppKey) -> Result<Self, GitHubError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            // The App JWT must never follow a redirect to another host.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| GitHubError::Transport(e.to_string()))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client_id: client_id.to_owned(),
            key,
            http,
        })
    }

    /// The App key fingerprint.
    #[must_use]
    pub fn key_fingerprint(&self) -> String {
        self.key.fingerprint()
    }

    /// Request a narrowed installation token, check the grant, and revoke it
    /// if the grant is broader than the request.
    ///
    /// # Errors
    ///
    /// Returns a [`GitHubError`]. No token is returned on error.
    pub async fn create_installation_token(
        &self,
        scope: &Scope,
        now: u64,
    ) -> Result<IssuedToken, GitHubError> {
        let jwt = self
            .key
            .app_jwt(&self.client_id, now)
            .map_err(|_| GitHubError::Signing)?;
        let permissions: BTreeMap<&str, &str> = scope
            .permissions
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let body = serde_json::json!({
            "repositories": scope.repositories,
            "permissions": permissions,
        });
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.base_url, scope.installation_id
        );
        let resp = self
            .http
            .post(url)
            .bearer_auth(jwt.expose())
            .header("Accept", ACCEPT)
            .header("X-GitHub-Api-Version", API_VERSION)
            .json(&body)
            .send()
            .await
            .map_err(|e| GitHubError::Transport(e.without_url().to_string()))?;
        drop(jwt);
        let status = resp.status().as_u16();
        let bytes = read_limited(resp).await?;
        let parsed = serde_json::from_slice::<TokenResponse>(&bytes);

        if status != 201 {
            // A token in a non-201 response is still a live credential, even
            // if the rest of the body does not match the schema.
            let revoked = match raw_token(&bytes) {
                Some(t) => self.revoke(&t).await,
                None => false,
            };
            return Err(GitHubError::Status {
                status,
                message: github_message(&bytes),
                revoked,
            });
        }
        let Ok(resp) = parsed else {
            // The token may be live even when the grant cannot be checked.
            if let Some(t) = raw_token(&bytes) {
                self.revoke(&t).await;
            }
            return Err(GitHubError::BadResponse("token response schema"));
        };
        match check_grant(scope, &resp) {
            Ok(grant) => Ok(IssuedToken {
                token: SecretString::new(resp.token),
                grant,
            }),
            Err(reason) => {
                let revoked = self.revoke(&resp.token).await;
                Err(GitHubError::GrantMismatch { reason, revoked })
            }
        }
    }

    /// `DELETE /installation/token`. Returns whether GitHub answered 204.
    pub async fn revoke(&self, token: &str) -> bool {
        let url = format!("{}/installation/token", self.base_url);
        let ok = self
            .http
            .delete(url)
            .bearer_auth(token)
            .header("Accept", ACCEPT)
            .header("X-GitHub-Api-Version", API_VERSION)
            .send()
            .await
            .is_ok_and(|r| r.status().as_u16() == 204);
        if ok {
            tracing::warn!("revoked an installation token after a failed check");
        } else {
            tracing::error!("failed to revoke an installation token after a failed check");
        }
        ok
    }
}

/// The `token` string of a response body, read without checking the rest of
/// the schema, so a rejected response can still have its token revoked.
fn raw_token(bytes: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    v.get("token")?.as_str().filter(|t| !t.is_empty()).map(str::to_owned)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::scope::{parse_scope, scope_query};

    #[test]
    fn raw_token_ignores_the_rest_of_the_schema() {
        assert_eq!(raw_token(br#"{"token":"ghs_x","permissions":7}"#).as_deref(), Some("ghs_x"));
        assert_eq!(raw_token(br#"{"token":""}"#), None);
        assert_eq!(raw_token(br#"{"message":"no"}"#), None);
        assert_eq!(raw_token(b"not json"), None);
    }

    fn scope() -> Scope {
        parse_scope(
            "/v1/installations/1/tokens",
            &scope_query(
                &["demo", "demo-2"],
                &[("contents", "read"), ("issues", "write")],
            ),
            false,
        )
        .unwrap()
    }

    fn resp(v: serde_json::Value) -> TokenResponse {
        serde_json::from_value(v).unwrap()
    }

    fn base() -> serde_json::Value {
        serde_json::json!({
            "token": "ghs_x", "expires_at": "2026-09-23T12:00:00Z",
            "repository_selection": "selected",
            "repositories": [{"name": "demo", "full_name": "o/demo"}],
            "permissions": {"contents": "read", "issues": "read", "metadata": "read"}
        })
    }

    #[test]
    fn accepts_narrower_grant_and_implicit_metadata() {
        let g = check_grant(&scope(), &resp(base())).unwrap();
        assert_eq!(g.repositories, vec!["demo"]);
    }

    #[test]
    fn repository_names_compare_without_case() {
        let mut v = base();
        v["repositories"] = serde_json::json!([{"name": "Demo"}]);
        assert!(check_grant(&scope(), &resp(v)).is_ok());
    }

    #[test]
    fn rejects_broader_grants() {
        let cases = [
            ("repository_selection", serde_json::json!("all")),
            (
                "repositories",
                serde_json::json!([{"name": "demo"}, {"name": "secret"}]),
            ),
            ("repositories", serde_json::json!([])),
            ("permissions", serde_json::json!({"contents": "write"})),
            (
                "permissions",
                serde_json::json!({"contents": "read", "actions": "read"}),
            ),
            ("permissions", serde_json::json!({"metadata": "write"})),
            ("permissions", serde_json::json!({"contents": "maintain"})),
            ("token", serde_json::json!("")),
        ];
        for (k, v) in cases {
            let mut r = base();
            r[k] = v.clone();
            assert!(check_grant(&scope(), &resp(r)).is_err(), "{k}={v}");
        }
        let mut r = base();
        r.as_object_mut().unwrap().remove("repositories");
        assert!(check_grant(&scope(), &resp(r)).is_err());
    }

    #[test]
    fn debug_redacts_token() {
        assert!(!format!("{:?}", resp(base())).contains("ghs_x"));
    }
}
