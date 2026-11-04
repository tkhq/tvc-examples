//! Wrappers for secret material that zeroize on drop and never print.

use std::fmt;

use zeroize::Zeroizing;

/// Exported secret bytes (the plaintext of one Turnkey secret).
///
/// `Debug` prints `[redacted]`. The buffer is zeroized on drop. Callers that
/// parse the bytes into another key type should zeroize their own copies.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wrap plaintext.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the plaintext. Callers must not log the returned value.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the plaintext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// A credential string (an API token, a JWT, a password).
///
/// `Debug` and `Display` print `[redacted]`, so the value cannot reach logs
/// through formatting. The buffer is zeroized on drop.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wrap a credential.
    #[must_use]
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// Borrow the credential. Callers must not log the returned value.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_formats_the_value() {
        let s = SecretString::new("ghs_supersecret".to_owned());
        assert_eq!(format!("{s:?} {s}"), "[redacted] [redacted]");
        assert_eq!(s.expose(), "ghs_supersecret");
        let b = SecretBytes::new(b"-----BEGIN".to_vec());
        assert_eq!(format!("{b:?}"), "[redacted]");
        assert_eq!(b.expose(), b"-----BEGIN");
        assert_eq!(b.len(), 10);
        assert!(!b.is_empty());
    }
}
