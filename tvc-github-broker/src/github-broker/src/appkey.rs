//! GitHub App private key: PKCS#1 PEM to a `ring` RSA key.
//!
//! GitHub downloads App keys as PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`).
//! This module decodes the PEM itself so that every intermediate buffer is a
//! `Zeroizing` value. `ring` then holds the key; `ring` uses constant-time
//! RSA code. The `rsa` crate is not used (RUSTSEC-2023-0071).

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use zeroize::Zeroizing;

use crate::b64;
use tvc_secrets::SecretString;

const BEGIN: &str = "-----BEGIN RSA PRIVATE KEY-----";
const END: &str = "-----END RSA PRIVATE KEY-----";

/// A key loading or signing failure. Never contains key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppKeyError(pub &'static str);

impl fmt::Display for AppKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitHub App key: {}", self.0)
    }
}

impl std::error::Error for AppKeyError {}

/// The GitHub App signing key.
pub struct AppKey {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl fmt::Debug for AppKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AppKey({})", self.fingerprint())
    }
}

/// Wrap a DER length.
fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(u8::try_from(n).unwrap_or(0));
    } else {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let len = bytes.len() - skip;
        out.push(0x80 | u8::try_from(len).unwrap_or(0));
        out.extend_from_slice(&bytes[skip..]);
    }
}

impl AppKey {
    /// Parse a PKCS#1 PEM. Accepts only an unencrypted 2048-bit RSA key.
    ///
    /// # Errors
    ///
    /// Returns an error for any other PEM type, an encrypted PEM, bad base64,
    /// an invalid key, or a key size other than 2048 bits.
    pub fn from_pkcs1_pem(pem: &[u8]) -> Result<Self, AppKeyError> {
        let text = std::str::from_utf8(pem).map_err(|_| AppKeyError("PEM is not UTF-8"))?;
        let start = text
            .find(BEGIN)
            .ok_or(AppKeyError("expected a PKCS#1 'RSA PRIVATE KEY' PEM"))?;
        let body_start = start + BEGIN.len();
        let end = text
            .get(body_start..)
            .and_then(|t| t.find(END))
            .ok_or(AppKeyError("PEM has no END line"))?;
        let body = text
            .get(body_start..body_start + end)
            .ok_or(AppKeyError("PEM body"))?;
        if body.contains(':') {
            return Err(AppKeyError("encrypted PEM keys are not supported"));
        }
        let mut b64 = Zeroizing::new(String::with_capacity(body.len()));
        b64.extend(body.chars().filter(|c| !c.is_ascii_whitespace()));
        let mut der = Zeroizing::new(Vec::new());
        STANDARD
            .decode_vec(b64.as_bytes(), &mut der)
            .map_err(|_| AppKeyError("PEM base64"))?;
        let key = RsaKeyPair::from_der(&der).map_err(|_| AppKeyError("invalid PKCS#1 RSA key"))?;
        if key.public().modulus_len() != 256 {
            return Err(AppKeyError("GitHub App keys are RSA-2048"));
        }
        Ok(Self {
            key,
            rng: SystemRandom::new(),
        })
    }

    /// The public key as SubjectPublicKeyInfo DER.
    #[must_use]
    pub fn public_spki_der(&self) -> Vec<u8> {
        // AlgorithmIdentifier { rsaEncryption, NULL }
        const ALG: &[u8] = &[
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        let pkcs1 = self.key.public_key().as_ref();
        let mut bit_string = vec![0x03];
        der_len(pkcs1.len() + 1, &mut bit_string);
        bit_string.push(0x00);
        bit_string.extend_from_slice(pkcs1);
        let mut out = vec![0x30];
        der_len(ALG.len() + bit_string.len(), &mut out);
        out.extend_from_slice(ALG);
        out.extend_from_slice(&bit_string);
        out
    }

    /// `SHA256:<base64>` over the SPKI DER. This is the value of
    /// `openssl rsa -in key.pem -pubout -outform DER | openssl sha256 -binary | openssl base64`,
    /// the fingerprint GitHub shows in the App settings.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let d = ring::digest::digest(&ring::digest::SHA256, &self.public_spki_der());
        format!("SHA256:{}", b64::std_encode(d.as_ref()))
    }

    /// Sign a compact JWS input with RSASSA-PKCS1-v1_5 and SHA-256.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_rs256(&self, signing_input: &[u8]) -> Result<Vec<u8>, AppKeyError> {
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &self.rng, signing_input, &mut sig)
            .map_err(|_| AppKeyError("RS256 signing failed"))?;
        Ok(sig)
    }

    /// Build the GitHub App JWT: `iat` 30 s in the past, `exp` 120 s ahead.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn app_jwt(&self, client_id: &str, now: u64) -> Result<SecretString, AppKeyError> {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let claims = serde_json::json!({
            "iat": now.saturating_sub(30),
            "exp": now + 120,
            "iss": client_id,
        });
        let input = format!(
            "{}.{}",
            b64::url_encode(header.as_bytes()),
            b64::url_encode(claims.to_string().as_bytes())
        );
        let sig = self.sign_rs256(input.as_bytes())?;
        Ok(SecretString::new(format!(
            "{input}.{}",
            b64::url_encode(&sig)
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_pem_types() {
        let pkcs8 = b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n";
        assert!(AppKey::from_pkcs1_pem(pkcs8).is_err());
        let enc = b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nMIIB\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(
            AppKey::from_pkcs1_pem(enc).unwrap_err(),
            AppKeyError("encrypted PEM keys are not supported")
        );
        let junk = b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(AppKey::from_pkcs1_pem(junk).is_err());
    }

    #[test]
    fn der_lengths() {
        let mut v = Vec::new();
        der_len(0x7f, &mut v);
        der_len(0x80, &mut v);
        der_len(0x10f, &mut v);
        assert_eq!(v, vec![0x7f, 0x81, 0x80, 0x82, 0x01, 0x0f]);
    }
}
