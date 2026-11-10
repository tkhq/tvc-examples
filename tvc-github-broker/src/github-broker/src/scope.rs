//! Token scope: parsing, bounds, and the app-side allowlist.
//!
//! The scope lives in the path and query so that Turnkey policy can inspect
//! it through the http-authz/v1 fields:
//!
//! ```text
//! POST /v1/installations/{installation_id}/tokens?permissions=<name:level>&...&repositories=<name>&...
//! ```
//!
//! Each permission and each repository is its own query parameter (repeated
//! keys, not commas). For example:
//!
//! ```text
//! permissions=contents%3Aread&permissions=pull_requests%3Awrite&repositories=backend&repositories=frontend
//! ```
//!
//! The query must already be in the broker's canonical form
//! (`query`), so each scope has exactly one query string. On top of
//! that the app requires:
//!
//! - only the keys `permissions` and `repositories`, each at least once;
//! - repository names lowercase and unique;
//! - permission names unique (one level per name).
//!
//! Turnkey policy can compare the query string, but it cannot express
//! "any subset of these repositories". The [`Allowlist`] is therefore the
//! scope enforcement: Turnkey policy decides who may call which method and
//! path, and this app decides which repositories and permissions an organization
//! can get.
//!
//! Lowercase matters for policy. GitHub matches repository names without
//! regard to case. If `Secret` and `secret` were both accepted, a policy that
//! denies `secret` by string comparison could be bypassed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::query::{BytePairs, decoded_pairs, encode_pairs, utf8_pairs};

/// Most repositories per token. GitHub allows more; this app caps the list at 100.
pub const MAX_REPOSITORIES: usize = 100;
/// Most permissions per token.
pub const MAX_PERMISSIONS: usize = 32;

/// A GitHub permission level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// `read`
    Read,
    /// `write`
    Write,
    /// `admin`
    Admin,
}

impl Level {
    /// Parse a GitHub level string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// The GitHub level string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
}

/// A requested token scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// GitHub installation ID.
    pub installation_id: u64,
    /// Repository names, lowercase and sorted.
    pub repositories: Vec<String>,
    /// Permission name to level.
    pub permissions: BTreeMap<String, Level>,
}

/// A scope validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeError(pub String);

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(s: impl Into<String>) -> Result<T, ScopeError> {
    Err(ScopeError(s.into()))
}

/// Parse `/v1/installations/{id}/tokens`. The ID is a positive decimal
/// integer without leading zeros.
///
/// # Errors
///
/// Returns an error for any other path shape.
pub fn parse_installation_path(path: &str) -> Result<u64, ScopeError> {
    let Some(id) = path
        .strip_prefix("/v1/installations/")
        .and_then(|r| r.strip_suffix("/tokens"))
    else {
        return err("path must be /v1/installations/{installation_id}/tokens");
    };
    if id.is_empty()
        || id.len() > 19
        || !id.bytes().all(|b| b.is_ascii_digit())
        || id.starts_with('0')
    {
        return err("installation_id must be a positive decimal integer");
    }
    match id.parse::<u64>() {
        Ok(n) if n > 0 => Ok(n),
        _ => err("installation_id must be a positive decimal integer"),
    }
}

/// Whether `name` is a repository name that this app accepts: 1 to 100
/// characters of `[a-z0-9._-]`, not `.` or `..`.
#[must_use]
pub fn valid_repository_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

fn valid_permission_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    !name.is_empty()
        && name.len() <= 64
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Parse and validate the scope from a verified path and query.
///
/// # Errors
///
/// Returns the first rule the scope breaks.
pub fn parse_scope(path: &str, query: &str, allow_admin: bool) -> Result<Scope, ScopeError> {
    let installation_id = parse_installation_path(path)?;
    let pairs = match decoded_pairs(query) {
        Some(p) if encode_pairs(&p) == query => p,
        _ => return err("query must be canonical"),
    };
    let pairs = utf8_pairs(pairs)
        .ok_or_else(|| ScopeError("query: query key or value is not UTF-8".into()))?;

    let mut repositories: Vec<String> = Vec::new();
    let mut permissions = BTreeMap::new();
    for (key, value) in pairs {
        match key.as_str() {
            "repositories" => {
                if !valid_repository_name(&value) {
                    return err(format!(
                        "invalid repository name {value:?} (lowercase [a-z0-9._-], 1-100 characters)"
                    ));
                }
                // Canonical order sorts values, so a duplicate is adjacent.
                if repositories.last() == Some(&value) {
                    return err(format!("repository {value} is repeated"));
                }
                repositories.push(value);
            }
            "permissions" => {
                let Some((name, level)) = value.split_once(':') else {
                    return err(format!("permission {value:?} must be name:level"));
                };
                if !valid_permission_name(name) {
                    return err(format!("invalid permission name {name:?}"));
                }
                let level = match Level::parse(level) {
                    Some(Level::Admin) if !allow_admin => {
                        return err(format!("permission {name}:admin is not allowed"));
                    }
                    Some(l) => l,
                    None => {
                        return err(format!("permission level {level:?} must be read or write"));
                    }
                };
                if permissions.insert(name.to_owned(), level).is_some() {
                    return err(format!("permission {name} is repeated"));
                }
            }
            _ => {
                return err(format!(
                    "unknown query parameter {key:?}; only permissions and repositories"
                ));
            }
        }
    }
    if repositories.is_empty() {
        return err("at least one repositories parameter is required");
    }
    if repositories.len() > MAX_REPOSITORIES {
        return err(format!("at most {MAX_REPOSITORIES} repositories"));
    }
    if permissions.is_empty() {
        return err("at least one permissions parameter is required");
    }
    if permissions.len() > MAX_PERMISSIONS {
        return err(format!("at most {MAX_PERMISSIONS} permissions"));
    }

    Ok(Scope {
        installation_id,
        repositories,
        permissions,
    })
}

/// Build the scope-canonical query for a scope: one `permissions` pair per
/// permission and one `repositories` pair per repository, in canonical order.
#[must_use]
pub fn scope_query(repositories: &[&str], permissions: &[(&str, &str)]) -> String {
    let mut pairs: BytePairs = permissions
        .iter()
        .map(|(n, l)| (b"permissions".to_vec(), format!("{n}:{l}").into_bytes()))
        .chain(
            repositories
                .iter()
                .map(|r| (b"repositories".to_vec(), r.as_bytes().to_vec())),
        )
        .collect();
    pairs.sort();
    encode_pairs(&pairs)
}

/// What the app permits for one installation.
#[derive(Debug, Clone)]
pub struct InstallationPolicy {
    /// Allowed repositories (lowercase).
    pub repositories: BTreeSet<String>,
    /// Allowed permissions and their highest level.
    pub permissions: BTreeMap<String, Level>,
    /// Organizations (`urn:turnkey:org:<uuid>`) that may use this
    /// installation. `None` means any organization under the configured
    /// top-level organization.
    pub organizations: Option<BTreeSet<String>>,
}

/// The app-side allowlist. Turnkey policy is the primary control; this is
/// defense in depth against a policy mistake.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    /// Installation ID to policy. Installations not listed are refused.
    pub installations: BTreeMap<u64, InstallationPolicy>,
}

impl Allowlist {
    /// Check a scope against the allowlist for the minting organization `org`.
    ///
    /// # Errors
    ///
    /// Returns the first entry that the allowlist does not permit.
    pub fn check(&self, scope: &Scope, org: &str) -> Result<(), ScopeError> {
        let Some(p) = self.installations.get(&scope.installation_id) else {
            return err(format!(
                "installation {} is not allowed",
                scope.installation_id
            ));
        };
        if p.organizations.as_ref().is_some_and(|o| !o.contains(org)) {
            return err(format!(
                "organization may not use installation {}",
                scope.installation_id
            ));
        }
        if let Some(r) = scope
            .repositories
            .iter()
            .find(|r| !p.repositories.contains(*r))
        {
            return err(format!("repository {r} is not allowed"));
        }
        for (name, level) in &scope.permissions {
            match p.permissions.get(name) {
                Some(max) if level <= max => {}
                _ => {
                    return err(format!(
                        "permission {name}:{} is not allowed",
                        level.as_str()
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const PATH: &str = "/v1/installations/12345/tokens";

    fn q(repos: &[&str], perms: &[(&str, &str)]) -> String {
        scope_query(repos, perms)
    }

    #[test]
    fn parses_valid_scope() {
        let s = parse_scope(
            PATH,
            &q(
                &["demo", "demo-2"],
                &[("contents", "read"), ("issues", "write")],
            ),
            false,
        )
        .unwrap();
        assert_eq!(s.installation_id, 12345);
        assert_eq!(s.repositories, vec!["demo", "demo-2"]);
        assert_eq!(s.permissions.get("issues"), Some(&Level::Write));
    }

    #[test]
    fn installation_id_rules() {
        for p in [
            "/v1/installations/0/tokens",
            "/v1/installations/012/tokens",
            "/v1/installations/-1/tokens",
            "/v1/installations/1e3/tokens",
            "/v1/installations//tokens",
            "/v1/installations/99999999999999999999/tokens",
            "/v1/installations/1/token",
        ] {
            assert!(parse_installation_path(p).is_err(), "{p}");
        }
        assert_eq!(parse_installation_path("/v1/installations/1/tokens"), Ok(1));
    }

    #[test]
    fn repeated_key_format() {
        assert_eq!(
            q(
                &["frontend", "backend"],
                &[("pull_requests", "write"), ("contents", "read")]
            ),
            "permissions=contents%3Aread&permissions=pull_requests%3Awrite&repositories=backend&repositories=frontend"
        );
        let s = parse_scope(
            PATH,
            "permissions=contents%3Aread&permissions=pull_requests%3Awrite&repositories=backend&repositories=frontend",
            false,
        )
        .unwrap();
        assert_eq!(s.repositories, vec!["backend", "frontend"]);
        assert_eq!(s.permissions.get("pull_requests"), Some(&Level::Write));
        // The comma-joined format is gone: a comma is not a valid name byte.
        assert!(
            parse_scope(
                PATH,
                "permissions=contents%3Aread&repositories=backend%2Cfrontend",
                false
            )
            .is_err()
        );
        assert!(
            parse_scope(
                PATH,
                "permissions=contents%3Aread%2Cmetadata%3Aread&repositories=demo",
                false
            )
            .is_err()
        );
        // Canonical order for names where digits sort before ':'.
        let s = parse_scope(PATH, &q(&["a"], &[("a", "read"), ("a1", "read")]), false).unwrap();
        assert_eq!(s.permissions.len(), 2);
    }

    #[test]
    fn repository_rules() {
        let perm = [("contents", "read")];
        let bad = |repos: &[&str]| parse_scope(PATH, &q(repos, &perm), false).is_err();
        assert!(bad(&[]));
        assert!(bad(&["Demo"]), "uppercase is refused");
        assert!(bad(&["a", "a"]), "duplicate");
        assert!(
            parse_scope(
                PATH,
                "permissions=contents%3Aread&repositories=b&repositories=a",
                false
            )
            .is_err(),
            "not canonical"
        );
        assert!(bad(&[".."]));
        assert!(bad(&["a/b"]));
        assert!(bad(&["owner/repo"]));
        let long = "a".repeat(101);
        assert!(bad(&[long.as_str()]));
        let many: Vec<String> = (0..101).map(|i| format!("r{i:03}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(bad(&many));
        let hundred = &many[..100];
        assert!(!bad(hundred));
    }

    #[test]
    fn permission_rules() {
        let bad = |perms: &[(&str, &str)], admin: bool| {
            parse_scope(PATH, &q(&["demo"], perms), admin).is_err()
        };
        assert!(bad(&[], false));
        assert!(bad(&[("contents", "admin")], false));
        assert!(!bad(&[("contents", "admin")], true));
        assert!(bad(&[("contents", "none")], false));
        assert!(bad(&[("Contents", "read")], false));
        assert!(
            bad(&[("contents", "read"), ("contents", "write")], false),
            "duplicate"
        );
        let many: Vec<String> = (0..33).map(|i| format!("p{i:02}")).collect();
        let many: Vec<(&str, &str)> = many.iter().map(|n| (n.as_str(), "read")).collect();
        assert!(bad(&many, false));
    }

    #[test]
    fn query_shape_rules() {
        assert!(parse_scope(PATH, "repositories=demo", false).is_err());
        assert!(parse_scope(PATH, "permissions=contents%3Aread", false).is_err());
        assert!(parse_scope(PATH, "", false).is_err());
        assert!(
            parse_scope(
                PATH,
                "permissions=contents%3Aread&permissions=x%3Aread&repositories=demo",
                false
            )
            .is_ok()
        );
        assert!(
            parse_scope(
                PATH,
                "extra=1&permissions=contents%3Aread&repositories=demo",
                false
            )
            .is_err()
        );
    }

    #[test]
    fn allowlist() {
        let mut a = Allowlist::default();
        a.installations.insert(
            12345,
            InstallationPolicy {
                repositories: ["demo".to_owned()].into_iter().collect(),
                permissions: [
                    ("contents".to_owned(), Level::Read),
                    ("issues".to_owned(), Level::Write),
                ]
                .into_iter()
                .collect(),
                organizations: Some(["urn:turnkey:org:o".to_owned()].into_iter().collect()),
            },
        );
        let org = "urn:turnkey:org:o";
        let s = |repos: &[&str], perms: &[(&str, &str)]| {
            parse_scope(PATH, &q(repos, perms), false).unwrap()
        };
        assert!(
            a.check(
                &s(&["demo"], &[("contents", "read"), ("issues", "read")]),
                org
            )
            .is_ok()
        );
        assert!(
            a.check(&s(&["demo"], &[("contents", "write")]), org)
                .is_err()
        );
        assert!(
            a.check(&s(&["other"], &[("contents", "read")]), org)
                .is_err()
        );
        assert!(a.check(&s(&["demo"], &[("actions", "read")]), org).is_err());
        assert!(
            a.check(&s(&["demo"], &[("contents", "read")]), "urn:turnkey:org:x")
                .is_err()
        );
        let other = parse_scope(
            "/v1/installations/9/tokens",
            &q(&["demo"], &[("contents", "read")]),
            false,
        )
        .unwrap();
        assert!(a.check(&other, org).is_err());
    }
}
