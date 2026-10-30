//! Broker configuration file (JSON).
//!
//! The file holds no secrets. The Turnkey API key path comes from the CLI or
//! the environment.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::Deserialize;

use crate::scope::{Allowlist, InstallationPolicy, Level, valid_repository_name};

/// Largest accepted clock skew.
pub const MAX_CLOCK_SKEW_SECS: u64 = turnkey_jwt_profiles::http_authz::jwt::MAX_CLOCK_SKEW_SECS;

fn default_skew() -> u64 {
    5
}

fn default_github_api() -> String {
    "https://api.github.com".into()
}

/// Top-level configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The app's exact origin. Must equal `aud` and the mint audience.
    pub audience: String,
    /// The app's top-level organization ID, a lowercase UUID without a prefix.
    /// A token's `iss` must name this organization.
    pub organization_id: String,
    /// Pinned JWK Set with the trusted Signer key(s).
    pub trusted_jwks_path: PathBuf,
    /// Clock skew in seconds (at most 30).
    #[serde(default = "default_skew")]
    pub clock_skew_seconds: u64,
    /// Allow `admin` permission levels. Off by default.
    #[serde(default)]
    pub allow_admin_permissions: bool,
    /// Put the specific check that failed in the body of a rejected request.
    /// Off by default, so a rejection does not tell the caller which check
    /// failed. Turn it on for debugging only.
    #[serde(default)]
    pub detailed_auth_errors: bool,
    /// GitHub App settings.
    pub github: GitHubConfig,
    /// Where the App key comes from.
    pub turnkey: TurnkeyConfig,
    /// Installation ID (decimal string) to allowlist entry.
    pub installations: BTreeMap<String, InstallationConfig>,
}

/// GitHub App settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubConfig {
    /// API base URL, for example `https://api.github.com` or a mock.
    #[serde(default = "default_github_api")]
    pub api_base_url: String,
    /// App client ID (or numeric app ID); the App JWT `iss`.
    pub app_client_id: String,
    /// If set, the exported key must have this `SHA256:` fingerprint.
    #[serde(default)]
    pub expected_key_sha256: Option<String>,
}

/// Turnkey Secret Storage settings for the App key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyConfig {
    /// Turnkey API base URL.
    pub api_base_url: String,
    /// Organization that owns the secret.
    pub organization_id: String,
    /// Secret ID of the App PEM.
    pub secret_id: String,
    /// Pinned Signer enclave signing key, hex (65 or 130 bytes).
    pub signer_public_key: String,
}

/// One allowlisted installation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationConfig {
    /// Allowed repositories (lowercase).
    pub repositories: Vec<String>,
    /// Allowed permissions and their highest level.
    pub permissions: BTreeMap<String, String>,
    /// Organizations (`urn:turnkey:org:<uuid>`, the token's `org` claim)
    /// allowed to use this installation. Omit for any.
    #[serde(default)]
    pub organizations: Option<Vec<String>>,
}

/// Is `url` an origin (`scheme://host[:port]`, no path) that is HTTPS, or
/// HTTP on a loopback host?
#[must_use]
pub fn valid_origin(url: &str) -> bool {
    let (scheme, rest) = match url.split_once("://") {
        Some(p) => p,
        None => return false,
    };
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return false;
    }
    match scheme {
        "https" => true,
        "http" => {
            let host = rest.rsplit_once(':').map_or(rest, |(h, _)| h);
            matches!(host, "127.0.0.1" | "localhost" | "[::1]")
        }
        _ => false,
    }
}

/// Is `url` HTTPS, or HTTP on loopback? A path is allowed.
#[must_use]
pub fn valid_base_url(url: &str) -> bool {
    let origin_end = url
        .find("://")
        .and_then(|i| url[i + 3..].find('/').map(|j| i + 3 + j))
        .unwrap_or(url.len());
    valid_origin(&url[..origin_end])
}

impl Config {
    /// Parse and validate.
    ///
    /// # Errors
    ///
    /// Returns a message for the first invalid setting.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let c: Self = serde_json::from_slice(bytes).map_err(|e| format!("config: {e}"))?;
        if !valid_origin(&c.audience) {
            return Err("audience must be an https origin (http only on loopback), no path".into());
        }
        if c.clock_skew_seconds > MAX_CLOCK_SKEW_SECS {
            return Err(format!(
                "clock_skew_seconds must be at most {MAX_CLOCK_SKEW_SECS}"
            ));
        }
        if !turnkey_jwt_profiles::ids::is_uuid(&c.organization_id) {
            return Err("organization_id must be a lowercase UUID with no prefix".into());
        }
        if !valid_base_url(&c.github.api_base_url) {
            return Err("github.api_base_url must be https (http only on loopback)".into());
        }
        let id = &c.github.app_client_id;
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err("github.app_client_id must be 1-64 characters of [A-Za-z0-9._-]".into());
        }
        if !valid_base_url(&c.turnkey.api_base_url) {
            return Err("turnkey.api_base_url must be https (http only on loopback)".into());
        }
        if c.installations.is_empty() {
            return Err("installations must not be empty".into());
        }
        Ok(c)
    }

    /// The token verifier settings.
    #[must_use]
    pub fn verifier_config(&self) -> turnkey_jwt_profiles::http_authz::VerifierConfig {
        turnkey_jwt_profiles::http_authz::VerifierConfig {
            clock_skew_secs: self.clock_skew_seconds,
            ..turnkey_jwt_profiles::http_authz::VerifierConfig::new(
                self.audience.clone(),
                self.organization_id.clone(),
            )
        }
    }

    /// The allowlist from the `installations` section.
    ///
    /// # Errors
    ///
    /// Returns a message for an invalid entry.
    pub fn allowlist(&self) -> Result<Allowlist, String> {
        let mut out = Allowlist::default();
        for (id, inst) in &self.installations {
            let n =
                crate::scope::parse_installation_path(&format!("/v1/installations/{id}/tokens"))
                    .map_err(|e| format!("installations.{id}: {e}"))?;
            if let Some(r) = inst.repositories.iter().find(|r| !valid_repository_name(r)) {
                return Err(format!(
                    "installations.{id}: bad repository {r:?} (lowercase)"
                ));
            }
            if let Some(i) = inst.organizations.iter().flatten().find(|i| {
                turnkey_jwt_profiles::ids::urn_uuid(
                    i,
                    turnkey_jwt_profiles::http_authz::jwt::ORG_URN_PREFIX,
                )
                .is_none()
            }) {
                return Err(format!(
                    "installations.{id}: organization {i:?} is not {}<uuid>",
                    turnkey_jwt_profiles::http_authz::jwt::ORG_URN_PREFIX
                ));
            }
            let mut permissions = BTreeMap::new();
            for (name, level) in &inst.permissions {
                let l = Level::parse(level)
                    .ok_or_else(|| format!("installations.{id}: bad level {level}"))?;
                if l == Level::Admin && !self.allow_admin_permissions {
                    return Err(format!(
                        "installations.{id}: {name}:admin needs allow_admin_permissions"
                    ));
                }
                permissions.insert(name.clone(), l);
            }
            out.installations.insert(
                n,
                InstallationPolicy {
                    repositories: inst.repositories.iter().cloned().collect(),
                    permissions,
                    organizations: inst
                        .organizations
                        .as_ref()
                        .map(|i| i.iter().cloned().collect::<BTreeSet<_>>()),
                },
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests panic on a failed setup step")]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert!(valid_origin("https://broker.example"));
        assert!(valid_origin("https://broker.example:8443"));
        assert!(valid_origin("http://127.0.0.1:44020"));
        assert!(!valid_origin("http://broker.example"));
        assert!(!valid_origin("https://broker.example/"));
        assert!(!valid_origin("https://u@broker.example"));
        assert!(valid_base_url("http://127.0.0.1:1/api"));
        assert!(!valid_base_url("http://evil.example/api"));
    }

    fn config(organization: &str, organizations: &str) -> serde_json::Value {
        serde_json::json!({
            "audience": "https://broker.example",
            "organization_id": organization,
            "trusted_jwks_path": "/dev/null",
            "github": {"app_client_id": "Iv23li"},
            "turnkey": {
                "api_base_url": "https://api.turnkey.com",
                "organization_id": "o",
                "secret_id": "s",
                "signer_public_key": "04",
            },
            "installations": {"1": {
                "repositories": ["demo"],
                "permissions": {"contents": "read"},
                "organizations": serde_json::from_str::<serde_json::Value>(organizations).unwrap(),
            }},
        })
    }

    fn parse(v: &serde_json::Value) -> Result<Config, String> {
        let c = Config::from_json(v.to_string().as_bytes())?;
        c.allowlist()?;
        Ok(c)
    }

    #[test]
    fn rejects_a_bad_organization_id_and_bad_organization_urns() {
        const ORG: &str = "4f0a3a8e-9d2b-4c61-8f57-2b1c6d0e7a11";
        const SUB: &str = "7b9c1d52-3e48-4a07-9c3d-5e8a2f6b0c44";
        assert!(parse(&config(ORG, &format!(r#"["urn:turnkey:org:{SUB}"]"#))).is_ok());
        assert!(parse(&config(ORG, "null")).is_ok());
        assert!(parse(&config("", "null")).is_err());
        assert!(parse(&config("parent_1", "null")).is_err());
        assert!(parse(&config(&ORG.to_uppercase(), "null")).is_err());
        assert!(parse(&config(&format!("urn:turnkey:org:{ORG}"), "null")).is_err());
        assert!(
            parse(&config(
                ORG,
                &format!(r#"["urn:turnkey:organization:{SUB}"]"#)
            ))
            .is_err()
        );
        assert!(parse(&config(ORG, r#"["urn:turnkey:org:"]"#)).is_err());
        assert!(parse(&config(ORG, r#"["urn:turnkey:org:sub_1"]"#)).is_err());
    }
}
