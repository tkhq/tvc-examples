//! Runtime configuration (non-secret), supplied at deploy time.
//!
//! The only secret this app uses is the quorum seed, which is read from
//! `/qos.quorum.key` — never from here. Everything in `Config` is safe to pass
//! as a plain deploy-time argument or as a file baked into the image, and is not
//! secret.
//!
//! In a TVC deployment there is no way to inject environment variables: runtime
//! config arrives through the pivot binary's CLI arguments (`pivotArgs`), which are
//! recorded in the QOS manifest and therefore attested. The organization id is
//! passed as `--organization-id`; the ruleset is compiled into the binary (see
//! [`crate::rules::Ruleset::embedded`]). `--rules-path` / `TVC_RULES_PATH` remain a
//! local-dev override only.

use crate::rules::Ruleset;

/// Environment variable holding the customer's (sub-)organization id (dev only;
/// in a deployment this comes from `--organization-id`).
const ORGANIZATION_ID_ENV: &str = "TVC_ORGANIZATION_ID";
/// Environment variable pointing at a ruleset TOML file (dev-only override).
const RULES_PATH_ENV: &str = "TVC_RULES_PATH";

/// Non-secret configuration loaded once at startup.
pub struct Config {
    /// The `organizationId` placed in every `SIGN_TRANSACTION_V2` body.
    pub organization_id: String,
    /// The active classification ruleset.
    pub ruleset: Ruleset,
}

impl Config {
    /// Resolve config. The `organizationId` comes from `--organization-id` (or env
    /// var for dev); if unset it falls back to an empty placeholder and warns.
    ///
    /// The ruleset is the one compiled into the binary ([`Ruleset::embedded`]). A
    /// `--rules-path` / `TVC_RULES_PATH` override is honored for local dev only, and
    /// if it fails to load falls back to the embedded ruleset (never deny-all).
    pub fn load(cli_organization_id: Option<&str>, cli_rules_path: Option<&str>) -> Self {
        let organization_id = cli_organization_id
            .map(str::to_string)
            .or_else(|| std::env::var(ORGANIZATION_ID_ENV).ok())
            .unwrap_or_else(|| {
                eprintln!(
                    "config: WARNING organization id not set (--organization-id / \
                     {ORGANIZATION_ID_ENV}) — using empty placeholder; set it to submit real \
                     requests"
                );
                String::new()
            });

        let ruleset = match cli_rules_path
            .map(str::to_string)
            .or_else(|| std::env::var(RULES_PATH_ENV).ok())
        {
            Some(path) => Ruleset::load(&path).unwrap_or_else(|e| {
                eprintln!(
                    "config: WARNING could not load --rules-path {path} ({e}); using the \
                     embedded ruleset"
                );
                Ruleset::embedded().expect("embedded ruleset (rules.toml) is valid")
            }),
            None => Ruleset::embedded().expect("embedded ruleset (rules.toml) is valid"),
        };

        Config {
            organization_id,
            ruleset,
        }
    }
}
