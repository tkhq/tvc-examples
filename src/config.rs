//! Runtime configuration (non-secret), supplied at deploy time.
//!
//! The only secret this app uses is the quorum seed, which is read from
//! `/qos.quorum.key` — never from here. Everything in `Config` is safe to pass
//! as a plain deploy-time argument / environment variable and is not baked into
//! the image.

/// Environment variable holding the customer's (sub-)organization id.
const ORGANIZATION_ID_ENV: &str = "TVC_ORGANIZATION_ID";

/// Non-secret configuration loaded once at startup.
pub struct Config {
    /// The `organizationId` placed in every `SIGN_TRANSACTION_V2` body.
    pub organization_id: String,
}

impl Config {
    /// Load config from the environment. A missing `organizationId` is tolerated
    /// (empty placeholder + warning) so the app still boots for local inspection;
    /// it must be set to submit real requests to Turnkey.
    pub fn from_env() -> Self {
        let organization_id = std::env::var(ORGANIZATION_ID_ENV).unwrap_or_else(|_| {
            eprintln!(
                "config: WARNING {ORGANIZATION_ID_ENV} not set — using empty placeholder; \
                 set it to submit real requests"
            );
            String::new()
        });
        Config { organization_id }
    }
}
