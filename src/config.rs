//! Runtime configuration (non-secret), supplied at deploy time.
//!
//! The only secret this app uses is the quorum seed, which is read from
//! `/qos.quorum.key` — never from here. Everything in `Config` is safe to pass
//! as a plain deploy-time argument or as a file baked into the image, and is not
//! secret.
//!
//! In a TVC deployment there is no way to inject environment variables — runtime
//! config arrives through the pivot binary's CLI arguments (`pivotArgs`), which
//! are recorded in the QOS manifest and therefore attested. So the organization
//! id is passed as `--organization-id`, and the ruleset is baked into the image
//! at `--rules-path` (covered by the image digest). Environment variables are
//! still honored as a convenience for local development.

use crate::rules::Ruleset;

/// Environment variable holding the customer's (sub-)organization id (dev only;
/// in a deployment this comes from `--organization-id`).
const ORGANIZATION_ID_ENV: &str = "TVC_ORGANIZATION_ID";
/// Environment variable pointing at the ruleset TOML file (dev-only fallback).
const RULES_PATH_ENV: &str = "TVC_RULES_PATH";
/// Default ruleset path when neither `--rules-path` nor `TVC_RULES_PATH` is set.
const DEFAULT_RULES_PATH: &str = "rules.toml";

/// Non-secret configuration loaded once at startup.
pub struct Config {
    /// The `organizationId` placed in every `SIGN_TRANSACTION_V2` body.
    pub organization_id: String,
    /// The active classification ruleset.
    pub ruleset: Ruleset,
}

impl Config {
    /// Resolve config with precedence CLI argument > environment variable >
    /// default. A missing `organizationId` or ruleset file is tolerated so the
    /// app still boots for local inspection: the org id falls back to an empty
    /// placeholder, and the ruleset falls back to deny-all (every transaction is
    /// REJECTed). Both warn loudly.
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

        let rules_path = cli_rules_path
            .map(str::to_string)
            .or_else(|| std::env::var(RULES_PATH_ENV).ok())
            .unwrap_or_else(|| DEFAULT_RULES_PATH.to_string());
        let ruleset = Ruleset::load(&rules_path).unwrap_or_else(|e| {
            eprintln!("config: WARNING could not load ruleset ({e}) — using deny-all");
            Ruleset::deny_all()
        });

        Config {
            organization_id,
            ruleset,
        }
    }
}
