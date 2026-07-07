//! Runtime configuration (non-secret), supplied at deploy time.
//!
//! The only secret this app uses is the quorum seed, which is read from
//! `/qos.quorum.key` — never from here. Everything in `Config` is safe to pass
//! as a plain deploy-time argument / environment variable or as a file baked
//! into the image, and is not secret.

use crate::rules::Ruleset;

/// Environment variable holding the customer's (sub-)organization id.
const ORGANIZATION_ID_ENV: &str = "TVC_ORGANIZATION_ID";
/// Environment variable pointing at the ruleset TOML file.
const RULES_PATH_ENV: &str = "TVC_RULES_PATH";
/// Default ruleset path if `TVC_RULES_PATH` is unset.
const DEFAULT_RULES_PATH: &str = "rules.toml";

/// Non-secret configuration loaded once at startup.
pub struct Config {
    /// The `organizationId` placed in every `SIGN_TRANSACTION_V2` body.
    pub organization_id: String,
    /// The active classification ruleset.
    pub ruleset: Ruleset,
}

impl Config {
    /// Load config from the environment. A missing `organizationId` or ruleset
    /// file is tolerated so the app still boots for local inspection: the org id
    /// falls back to an empty placeholder, and the ruleset falls back to
    /// deny-all (every transaction is REJECTed). Both warn loudly.
    pub fn from_env() -> Self {
        let organization_id = std::env::var(ORGANIZATION_ID_ENV).unwrap_or_else(|_| {
            eprintln!(
                "config: WARNING {ORGANIZATION_ID_ENV} not set — using empty placeholder; \
                 set it to submit real requests"
            );
            String::new()
        });

        let rules_path =
            std::env::var(RULES_PATH_ENV).unwrap_or_else(|_| DEFAULT_RULES_PATH.to_string());
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
