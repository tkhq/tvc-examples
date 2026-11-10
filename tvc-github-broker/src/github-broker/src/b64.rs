//! Base64 helpers. The base64url forms come from `turnkey_jwt_profiles`; GitHub's
//! padded standard form is local.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub use turnkey_jwt_profiles::http_authz::b64::{url_decode, url_encode};

/// Padded standard base64 encoding. GitHub uses this form for token hashes.
#[must_use]
pub fn std_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn std_is_padded() {
        assert_eq!(std_encode(b"a"), "YQ==");
        assert_eq!(url_encode(b"a"), "YQ");
    }
}
